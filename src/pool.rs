//! Resource pool (virtual cluster) local membership store + key derivation.
//!
//! A pool is a shared, multi-writer TNS zone: trusted machines join, each claims
//! a named service it owns, and consumers discover the endpoint set and round-robin.
//! See memory `project_resource_pool.md` for the full design.
//!
//! Phase 1 implements the **closed** pool: keyed by a symmetric key `K` distributed
//! out-of-band. `pool_root = ServiceId(derive_key("tarnet pool root", K))` is
//! unguessable to non-members, so the registry is both unlistable and unreadable
//! without `K`. Per-member authenticity comes from each member signing its own claim.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tarnet_api::service::{PoolEndpoint, PoolKind, TnsRecord};
use tarnet_api::types::{PeerId, ServiceId};

use crate::identity::Keypair;
use crate::node::Node;
use crate::tns::{build_bundle, build_peer_record, disposable_record_key, open_bundle, seal, tns_dht_key, unseal};
use crate::types::Result;

/// Reserved label carrying the list of service names members offer (browse/enumerate).
pub const CATALOG_LABEL: &str = "_catalog";

/// BLAKE3 derive_key context for the closed-pool root identifier.
const POOL_ROOT_CONTEXT: &str = "tarnet pool root v1";

/// Derive the pool root ServiceId for a closed pool from its shared key.
pub fn closed_pool_root(key: &[u8; 32]) -> ServiceId {
    ServiceId(crate::crypto::kdf(key, POOL_ROOT_CONTEXT))
}

/// Derive the pool root for any pool kind.
pub fn pool_root(kind: &PoolKind) -> ServiceId {
    match kind {
        PoolKind::Closed { key } => closed_pool_root(key),
    }
}

/// A pool this node participates in, keyed by a local name.
#[derive(Clone)]
pub struct PoolEntry {
    pub name: String,
    pub kind: PoolKind,
    /// Cached derived root (namespace identifier and, for open pools, trust root).
    pub root: ServiceId,
}

/// Local name → pool membership. Sibling to the identity store; persisted to the DB.
pub struct PoolStore {
    pools: HashMap<String, PoolEntry>,
}

impl PoolStore {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    /// Import a pool under a local name (idempotent on name). Returns the pool root.
    pub fn join(&mut self, name: &str, kind: PoolKind) -> ServiceId {
        let root = pool_root(&kind);
        self.pools.insert(
            name.to_string(),
            PoolEntry {
                name: name.to_string(),
                kind,
                root,
            },
        );
        root
    }

    /// Remove a pool by local name. Returns true if it existed.
    pub fn leave(&mut self, name: &str) -> bool {
        self.pools.remove(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<&PoolEntry> {
        self.pools.get(name)
    }

    /// Look up a pool by its derived root (used to recognize pool zones on resolve).
    pub fn get_by_root(&self, root: &ServiceId) -> Option<&PoolEntry> {
        self.pools.values().find(|e| &e.root == root)
    }

    /// (local name, pool root) for every joined pool.
    pub fn list(&self) -> Vec<(String, ServiceId)> {
        self.pools
            .values()
            .map(|e| (e.name.clone(), e.root))
            .collect()
    }

    /// All entries, for persistence.
    pub fn entries(&self) -> impl Iterator<Item = &PoolEntry> {
        self.pools.values()
    }
}

impl Default for PoolStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Claim publish / resolve (closed pool) ──
//
// A claim is published at `tns_dht_key(pool_root, service)` as a SignedContent
// record carrying a TNS authenticity bundle: the record SET is sealed under the
// pool-root-derived key (so only members holding K, from which the unguessable
// pool_root is derived, can locate and read it) and the bundle is signed by the
// member's own master identity key (so claims are attributable). The DHT record
// is signed by the member's disposable per-label key, so members never expose
// their master pubkey on the DHT. Consumers authenticate via `open_bundle` with
// `require_owner = false`: any member's signature is accepted, bound to pool_root.

/// Assemble a claim record set: Identity(owner) + Peer{owner→peer} + Service{..}.
fn build_claim_records(
    member_keypair: &Keypair,
    port: &str,
    weight: u16,
    meta: Vec<u8>,
) -> Vec<TnsRecord> {
    let owner = member_keypair.identity.service_id();
    let peer_id = member_keypair.peer_id();
    vec![
        TnsRecord::Identity(owner),
        build_peer_record(member_keypair, &peer_id),
        TnsRecord::Service {
            port: port.to_string(),
            weight,
            meta,
        },
    ]
}

/// Publish (or refresh) this member's endpoint claim for `service` into the pool.
pub async fn publish_claim(
    node: &Node,
    pool_root: &ServiceId,
    member_keypair: &Keypair,
    service: &str,
    port: &str,
    weight: u16,
    meta: Vec<u8>,
    ttl_secs: u32,
) -> Result<()> {
    let records = build_claim_records(member_keypair, port, weight, meta);
    publish_record_set(node, pool_root, member_keypair, service, &records, ttl_secs).await
}

/// Withdraw this member's claim by publishing an empty (tombstone) record set with a
/// fresh (higher) sequence and short TTL, so consumers drop it immediately.
pub async fn withdraw_claim(
    node: &Node,
    pool_root: &ServiceId,
    member_keypair: &Keypair,
    service: &str,
) -> Result<()> {
    publish_record_set(node, pool_root, member_keypair, service, &[], 1).await
}

/// Low-level: seal a member's authenticity bundle under the pool key and put it
/// signed by the member's disposable per-label key. The bundle is signed by the
/// member's own master key and bound to `pool_root`; consumers authenticate it
/// with [`open_bundle`] (any member who knows the pool key may write — confidentiality
/// is K-gated because the pool root is unguessable without K).
async fn publish_record_set(
    node: &Node,
    pool_root: &ServiceId,
    member_keypair: &Keypair,
    label: &str,
    records: &[TnsRecord],
    ttl_secs: u32,
) -> Result<()> {
    let dht_key = tns_dht_key(pool_root, label);
    let sequence = node.next_dht_sequence().await;
    let bundle = build_bundle(member_keypair, pool_root, label, sequence, records);
    let value = seal(pool_root, label, &bundle);
    let record_key = disposable_record_key();
    node.dht_put_signed_at_key(&record_key, dht_key, &value, sequence, ttl_secs)
        .await
}

/// Decrypt and authenticate every member's record set at the pool key, one per
/// member. `require_owner` is false: any member's master signature is accepted,
/// since pool authority is membership (knowing K), bound to `pool_root`.
///
/// Records are signed by disposable (random, non-deterministic) DHT keys, so a
/// member's republishes appear as distinct slots until they expire; we dedup by
/// author (the member's master identity), keeping each member's highest-sequence
/// set, so a stale slot can't shadow a fresh one or double-count an endpoint.
fn decrypt_all_sets(node_records: &[crate::dht::DhtRecord], pool_root: &ServiceId, label: &str)
    -> Vec<Vec<TnsRecord>>
{
    let mut latest: HashMap<ServiceId, (u64, Vec<TnsRecord>)> = HashMap::new();
    for record in node_records {
        if record.record_type != crate::types::RecordType::SignedContent {
            continue;
        }
        let plaintext = match unseal(pool_root, label, &record.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some((set, seq, author)) = open_bundle(pool_root, label, &plaintext, false) {
            match latest.get(&author) {
                Some((best_seq, _)) if *best_seq >= seq => {}
                _ => {
                    latest.insert(author, (seq, set));
                }
            }
        }
    }
    latest.into_values().map(|(_, set)| set).collect()
}

/// Turn one member's decrypted record set into a routable endpoint, if it is one.
fn record_set_to_endpoint(set: &[TnsRecord]) -> Option<PoolEndpoint> {
    let mut owner: Option<ServiceId> = None;
    let mut peer_id: Option<PeerId> = None;
    let mut svc: Option<(String, u16, Vec<u8>)> = None;
    for rec in set {
        match rec {
            TnsRecord::Identity(sid) => owner = Some(*sid),
            TnsRecord::Peer { peer_id: pid, .. } => peer_id = Some(*pid),
            TnsRecord::Service { port, weight, meta } => {
                svc = Some((port.clone(), *weight, meta.clone()))
            }
            _ => {}
        }
    }
    let owner = owner?;
    let (port, weight, meta) = svc?;
    Some(PoolEndpoint {
        owner,
        port,
        weight,
        meta,
        peer_id,
    })
}

/// Resolve the live endpoint set for `service` in the pool. One endpoint per member.
/// Issues a DHT GET and polls the local store until something arrives or `timeout`.
pub async fn resolve_endpoints(
    node: &Node,
    pool_root: &ServiceId,
    service: &str,
    timeout: Duration,
) -> Vec<PoolEndpoint> {
    let dht_key = tns_dht_key(pool_root, service);

    // Fast path: already in the local store.
    let local = node.dht_get_records_at_key(&dht_key).await;
    let mut sets = decrypt_all_sets(&local, pool_root, service);
    if sets.is_empty() {
        // Search the network, re-reading the store as records stream back.
        let mut search = node.dht_search(dht_key, Instant::now() + timeout).await;
        loop {
            let recs = node.dht_get_records_at_key(&dht_key).await;
            sets = decrypt_all_sets(&recs, pool_root, service);
            if !sets.is_empty() || search.next().await.is_none() {
                break;
            }
        }
    }

    sets.iter().filter_map(|s| record_set_to_endpoint(s)).collect()
}

/// Resolve the pool catalog: the union of service names members have published.
pub async fn resolve_catalog(node: &Node, pool_root: &ServiceId, timeout: Duration) -> Vec<String> {
    let dht_key = tns_dht_key(pool_root, CATALOG_LABEL);
    let mut search = node.dht_search(dht_key, Instant::now() + timeout).await;
    let mut names: Vec<String> = Vec::new();
    loop {
        let recs = node.dht_get_records_at_key(&dht_key).await;
        for set in decrypt_all_sets(&recs, pool_root, CATALOG_LABEL) {
            for rec in set {
                if let TnsRecord::Text(name) = rec {
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
            }
        }
        if !names.is_empty() || search.next().await.is_none() {
            break;
        }
    }
    names
}

/// Publish this member's catalog contribution: the list of service names it offers.
pub async fn publish_catalog(
    node: &Node,
    pool_root: &ServiceId,
    member_keypair: &Keypair,
    services: &[String],
    ttl_secs: u32,
) -> Result<()> {
    let records: Vec<TnsRecord> = services
        .iter()
        .map(|s| TnsRecord::Text(s.clone()))
        .collect();
    publish_record_set(node, pool_root, member_keypair, CATALOG_LABEL, &records, ttl_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_root_is_deterministic_and_key_dependent() {
        let a = closed_pool_root(&[1u8; 32]);
        let b = closed_pool_root(&[1u8; 32]);
        let c = closed_pool_root(&[2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn join_list_leave() {
        let mut store = PoolStore::new();
        let root = store.join("mycluster", PoolKind::Closed { key: [9u8; 32] });
        assert_eq!(store.list(), vec![("mycluster".to_string(), root)]);
        assert!(store.get("mycluster").is_some());
        assert_eq!(store.get_by_root(&root).map(|e| e.name.as_str()), Some("mycluster"));
        assert!(store.leave("mycluster"));
        assert!(!store.leave("mycluster"));
        assert!(store.list().is_empty());
    }
}
