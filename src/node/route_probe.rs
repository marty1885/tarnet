use super::*;
use crate::wire::{RouteProbeFoundMsg, RouteProbeMsg};

/// Maximum TTL for route probes (prevents amplification).
const PROBE_MAX_TTL: u16 = 1000;

/// How long to keep probe nonces for duplicate suppression / reverse-path routing.
const PROBE_NONCE_EXPIRY: Duration = Duration::from_secs(60);

/// Default initial TTL for probes we originate.
const PROBE_INITIAL_TTL: u16 = 64;

/// Expanding ring multiplier.
const PROBE_TTL_MULTIPLIER: u16 = 4;

/// Maximum attempts for expanding ring search.
const PROBE_MAX_ATTEMPTS: usize = 5;

impl Node {
    /// Handle an incoming RouteProbe message.
    pub(super) async fn handle_route_probe(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let probe = RouteProbeMsg::from_bytes(payload)?;

        // Duplicate suppression: drop if we've seen this nonce.
        {
            let mut seen = self.probe_seen.lock().await;
            if seen.contains_key(&probe.nonce) {
                return Ok(());
            }
            seen.insert(probe.nonce, Instant::now());
        }

        // Record reverse path for RouteProbeFound routing.
        self.probe_reverse
            .lock()
            .await
            .insert(probe.nonce, (from, Instant::now()));

        // Check if WE are the target.
        if probe.target == self.peer_id() {
            let reply = RouteProbeFoundMsg {
                nonce: probe.nonce,
                target: probe.target,
                cost: 0,
            };
            self.send_to_peer(&from, &reply.to_wire().encode()).await?;
            return Ok(());
        }

        // Check our routing table for the target.
        let route_cost = {
            let rt = self.routing_table.lock().await;
            rt.lookup(&probe.target).map(|r| r.cost)
        };

        if let Some(cost) = route_cost {
            // We know this destination — send RouteProbeFound back.
            // Also insert a route entry from the discovered direction so
            // subsequent EXTENDs can follow the cached path.
            let reply = RouteProbeFoundMsg {
                nonce: probe.nonce,
                target: probe.target,
                cost: cost.min(u16::MAX as u32) as u16,
            };
            self.send_to_peer(&from, &reply.to_wire().encode()).await?;
            return Ok(());
        }

        // Not found. Forward if TTL allows.
        if probe.ttl == 0 {
            return Ok(()); // TTL expired, drop silently.
        }

        let capped_ttl = probe.ttl.min(PROBE_MAX_TTL);

        // Forward to best candidate: prefer DV next_hop, fall back to random neighbor.
        let forward_to = {
            let links = self.links.lock().await;
            let candidates: Vec<PeerId> = links
                .keys()
                .filter(|p| **p != from) // don't send back
                .copied()
                .collect();
            if candidates.is_empty() {
                return Ok(()); // dead end
            }
            // On a line: only one option. On a mesh: random among non-sender neighbors.
            use rand::seq::SliceRandom;
            *candidates.choose(&mut rand::thread_rng()).unwrap()
        };

        let forwarded = RouteProbeMsg {
            nonce: probe.nonce,
            target: probe.target,
            ttl: capped_ttl - 1,
            hops: probe.hops.saturating_add(1),
        };
        self.send_to_peer(&forward_to, &forwarded.to_wire().encode())
            .await?;

        Ok(())
    }

    /// Handle an incoming RouteProbeFound message.
    pub(super) async fn handle_route_probe_found(
        &self,
        from: PeerId,
        payload: &[u8],
    ) -> Result<()> {
        let found = RouteProbeFoundMsg::from_bytes(payload)?;

        // Cache the discovered route: target is reachable through `from` at cost+1.
        {
            let mut rt = self.routing_table.lock().await;
            rt.update_with_source(
                found.target,
                from,
                (found.cost as u32).saturating_add(1),
                crate::routing::RouteSource::Local,
            );
        }

        // Check if we have a pending probe for this target.
        {
            let mut pending = self.pending_probes.lock().await;
            if let Some(waiters) = pending.remove(&found.target) {
                for tx in waiters {
                    let _ = tx.send(found.cost);
                }
                return Ok(());
            }
        }

        // Not ours — forward along reverse path.
        let next = self
            .probe_reverse
            .lock()
            .await
            .get(&found.nonce)
            .map(|(p, _)| *p);
        if let Some(next_peer) = next {
            let forwarded = RouteProbeFoundMsg {
                nonce: found.nonce,
                target: found.target,
                cost: found.cost.saturating_add(1),
            };
            self.send_to_peer(&next_peer, &forwarded.to_wire().encode())
                .await?;
        }

        Ok(())
    }

    /// Initiate a route probe for `target`. Uses expanding ring search.
    /// Returns the cost if found, or None if all attempts failed.
    pub async fn route_probe(&self, target: PeerId) -> Option<u16> {
        let cutoff = Instant::now() - PROBE_NONCE_EXPIRY;
        self.probe_seen.lock().await.retain(|_, t| *t > cutoff);
        self.probe_reverse
            .lock()
            .await
            .retain(|_, (_, t)| *t > cutoff);

        let mut ttl = PROBE_INITIAL_TTL;

        for _attempt in 0..PROBE_MAX_ATTEMPTS {
            // Register a waiter.
            let (tx, rx) = oneshot::channel();
            {
                let mut pending = self.pending_probes.lock().await;
                pending.entry(target).or_default().push(tx);
            }

            // Generate nonce and send probe to all neighbors.
            let nonce: [u8; 16] = rand::random();
            {
                let mut seen = self.probe_seen.lock().await;
                seen.insert(nonce, Instant::now());
            }

            let probe = RouteProbeMsg {
                nonce,
                target,
                ttl,
                hops: 0,
            };

            // Send to all neighbors (expanding ring — all directions).
            let links = self.links.lock().await;
            let peers: Vec<(PeerId, Arc<PeerLink>)> =
                links.iter().map(|(p, l)| (*p, l.clone())).collect();
            drop(links);

            for (peer, link) in &peers {
                if let Err(e) = link.send_message(&probe.to_wire().encode()).await {
                    log::debug!("Failed to send RouteProbe to {:?}: {}", peer, e);
                }
            }

            // Wait for reply with timeout proportional to TTL.
            let timeout_ms = 2000 + (ttl as u64) * 20; // base + ~20ms per hop
            match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
                Ok(Ok(cost)) => return Some(cost),
                _ => {
                    // Clean up any remaining waiter for this attempt.
                    let mut pending = self.pending_probes.lock().await;
                    if let Some(waiters) = pending.get_mut(&target) {
                        waiters.retain(|_| true); // dropped senders are already gone
                        if waiters.is_empty() {
                            pending.remove(&target);
                        }
                    }
                }
            }

            // Expand ring.
            ttl = ttl.saturating_mul(PROBE_TTL_MULTIPLIER).min(PROBE_MAX_TTL);
        }

        None
    }
}
