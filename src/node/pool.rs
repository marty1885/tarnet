//! Node-level resource-pool operations: join/leave/list local memberships, and
//! register/withdraw/resolve endpoint claims. Thin orchestration over `crate::pool`
//! (the publish/resolve logic) plus the local pool store and the active-claim
//! registry that the lease-refresh timer drives. See memory `project_resource_pool.md`.

use std::time::Duration;

use tarnet_api::service::{PoolClaim, PoolEndpoint, PoolKind, PoolRegisterOptions};
use tarnet_api::types::ServiceId;

use crate::identity::Keypair;
use crate::pool;
use crate::types::{Error, Result};

use super::Node;

/// A claim this node is advertising into a pool; refreshed by the lease loop.
#[derive(Clone)]
pub struct ActiveClaim {
    pub pool: String,
    pub service: String,
    pub identity_label: Option<String>,
    pub port: String,
    pub weight: u16,
    pub meta: Vec<u8>,
    pub ttl_secs: u32,
}

/// TTL for the per-member catalog contribution.
const CATALOG_TTL_SECS: u32 = 120;

impl Node {
    /// Resolve an identity label (or default) to its keypair.
    async fn pool_keypair(&self, identity: Option<&str>) -> Option<Keypair> {
        let store = self.identity_store.lock().await;
        let id = match identity {
            Some(l) if !l.is_empty() && l != "default" => store.resolve_label_or_sid(l)?,
            _ => store.default_identity(),
        };
        // Keypair is not Clone (holds secret material); reconstruct from bytes.
        Keypair::from_full_bytes(&id.keypair.to_full_bytes()).ok()
    }

    /// Import a pool under a local name (persisted). Returns the pool root.
    pub async fn pool_join(&self, name: &str, kind: PoolKind) -> ServiceId {
        if let Some(db) = &self.db {
            match &kind {
                PoolKind::Closed { key } => {
                    let _ = db.save_pool(name, 0, key);
                }
            }
        }
        self.pool_store.lock().await.join(name, kind)
    }

    /// Forget a pool by local name; also drops any active claims for it.
    pub async fn pool_leave(&self, name: &str) -> bool {
        if let Some(db) = &self.db {
            let _ = db.delete_pool(name);
        }
        self.pool_claims.lock().await.retain(|k, _| k.0 != name);
        self.pool_store.lock().await.leave(name)
    }

    /// (local name, pool root) for every joined pool.
    pub async fn pool_list(&self) -> Vec<(String, ServiceId)> {
        self.pool_store.lock().await.list()
    }

    /// The derived root for a joined pool, by local name.
    pub async fn pool_root_for(&self, name: &str) -> Option<ServiceId> {
        self.pool_store.lock().await.get(name).map(|e| e.root)
    }

    /// Advertise an endpoint claim for `service` into the pool and track it for
    /// lease refresh. Returns a handle for later withdrawal.
    pub async fn pool_register(
        &self,
        pool_name: &str,
        service: &str,
        identity: Option<&str>,
        port: &str,
        opts: PoolRegisterOptions,
    ) -> Result<PoolClaim> {
        let root = self
            .pool_root_for(pool_name)
            .await
            .ok_or_else(|| Error::Protocol(format!("not a member of pool '{}'", pool_name)))?;
        let keypair = self
            .pool_keypair(identity)
            .await
            .ok_or_else(|| Error::Protocol("pool register: identity not found".into()))?;
        let signer = keypair.identity.service_id();

        pool::publish_claim(
            self,
            &root,
            &keypair,
            service,
            port,
            opts.weight,
            opts.meta.clone(),
            opts.ttl_secs,
        )
        .await?;

        self.pool_claims.lock().await.insert(
            (pool_name.to_string(), service.to_string()),
            ActiveClaim {
                pool: pool_name.to_string(),
                service: service.to_string(),
                identity_label: identity.map(|s| s.to_string()),
                port: port.to_string(),
                weight: opts.weight,
                meta: opts.meta,
                ttl_secs: opts.ttl_secs,
            },
        );

        self.republish_pool_catalog(pool_name, &root, &keypair).await;

        Ok(PoolClaim {
            pool: pool_name.to_string(),
            service: service.to_string(),
            signer,
        })
    }

    /// Withdraw a claim: publish a tombstone and stop refreshing it.
    pub async fn pool_withdraw(&self, claim: &PoolClaim) -> Result<()> {
        let root = self
            .pool_root_for(&claim.pool)
            .await
            .ok_or_else(|| Error::Protocol(format!("not a member of pool '{}'", claim.pool)))?;
        let key = (claim.pool.clone(), claim.service.clone());
        let identity_label = self
            .pool_claims
            .lock()
            .await
            .get(&key)
            .and_then(|c| c.identity_label.clone());
        let keypair = self
            .pool_keypair(identity_label.as_deref())
            .await
            .ok_or_else(|| Error::Protocol("pool withdraw: identity not found".into()))?;

        pool::withdraw_claim(self, &root, &keypair, &claim.service).await?;
        self.pool_claims.lock().await.remove(&key);
        self.republish_pool_catalog(&claim.pool, &root, &keypair).await;
        Ok(())
    }

    /// Discover the live endpoint set for a pool service (one per member).
    pub async fn pool_resolve(
        &self,
        pool_name: &str,
        service: &str,
        timeout_secs: u32,
    ) -> Result<Vec<PoolEndpoint>> {
        let root = self
            .pool_root_for(pool_name)
            .await
            .ok_or_else(|| Error::Protocol(format!("not a member of pool '{}'", pool_name)))?;
        Ok(pool::resolve_endpoints(
            self,
            &root,
            service,
            Duration::from_secs(timeout_secs.max(1) as u64),
        )
        .await)
    }

    /// Browse the pool catalog: union of service names members advertise.
    pub async fn pool_catalog(&self, pool_name: &str, timeout_secs: u32) -> Result<Vec<String>> {
        let root = self
            .pool_root_for(pool_name)
            .await
            .ok_or_else(|| Error::Protocol(format!("not a member of pool '{}'", pool_name)))?;
        Ok(pool::resolve_catalog(self, &root, Duration::from_secs(timeout_secs.max(1) as u64)).await)
    }

    /// Refresh all active pool claims (driven by the lease timer). Returns count refreshed.
    pub async fn refresh_pool_claims(&self) -> usize {
        let claims: Vec<ActiveClaim> =
            self.pool_claims.lock().await.values().cloned().collect();
        let mut refreshed = 0;
        for c in claims {
            let Some(root) = self.pool_root_for(&c.pool).await else {
                continue;
            };
            let Some(kp) = self.pool_keypair(c.identity_label.as_deref()).await else {
                continue;
            };
            if pool::publish_claim(
                self, &root, &kp, &c.service, &c.port, c.weight, c.meta.clone(), c.ttl_secs,
            )
            .await
            .is_ok()
            {
                refreshed += 1;
            }
        }
        refreshed
    }

    /// (Re)publish this node's catalog contribution for the pool: the services it offers.
    /// Phase 1: published under `keypair`, listing all of this node's claims in the pool.
    async fn republish_pool_catalog(&self, pool_name: &str, root: &ServiceId, keypair: &Keypair) {
        let services: Vec<String> = self
            .pool_claims
            .lock()
            .await
            .keys()
            .filter(|k| k.0 == pool_name)
            .map(|k| k.1.clone())
            .collect();
        let _ = pool::publish_catalog(self, root, keypair, &services, CATALOG_TTL_SECS).await;
    }
}
