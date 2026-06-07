use crate::identity::{self, Keypair};
use crate::pubkey_cache::PubkeyCache;
use crate::types::{Error, PeerId, Result};
use crate::wire::{RouteAdvertisement, RouteEntry};
use tarnet_api::types::SigningAlgo;

use super::{RouteSource, RoutingTable};

/// Wire size of a single `RouteEntry` (destination(32) || cost(4)).
const ROUTE_ENTRY_BYTES: usize = 36;
/// Bytes an advertisement spends on everything *except* its entries: wire
/// header(5) + advertiser(32) + entry_count(2) + sig_len(2) + signature. The
/// signature reserve (1024) comfortably covers a Falcon-512 + Ed25519 hybrid
/// (~750 B, and variable-length) with margin, so a chunk never overruns the
/// size budget even when the next signature is slightly larger than the last.
const AD_OVERHEAD_RESERVE: usize = 5 + 32 + 2 + 2 + 1024;

/// Build the (destination, cost) entry list to advertise to `exclude_next_hop`,
/// applying split horizon with poison reverse. Entry 0 is always ourselves at
/// cost 0.
fn advertisement_entries(
    identity: &Keypair,
    table: &RoutingTable,
    exclude_next_hop: &PeerId,
) -> Vec<RouteEntry> {
    let mut entries: Vec<RouteEntry> = vec![RouteEntry {
        destination: identity.peer_id(),
        cost: 0,
    }];

    for (dest, cost) in table.entries_for_advertisement() {
        // Split horizon: skip routes whose best path goes through the recipient
        if let Some(routes) = table.lookup_all(&dest) {
            if routes.first().map(|r| r.next_hop) == Some(*exclude_next_hop) {
                // Poison reverse: advertise with infinite cost
                entries.push(RouteEntry {
                    destination: dest,
                    cost: u32::MAX,
                });
                continue;
            }
        }
        entries.push(RouteEntry {
            destination: dest,
            cost,
        });
    }

    entries
}

/// Generate signed route advertisements from our routing table, split into as
/// many messages as needed so each fits `max_message_bytes` (the recipient
/// link's per-frame budget — see [`PeerLink::max_wire_message`]).
///
/// This is safe to split because `process_advertisement` is pure soft state:
/// each entry is an independent (dest, cost) refresh with no snapshot/replace
/// semantics, and routes age out via expiry. As long as every chunk ships
/// within one advertisement cycle (well inside `ROUTE_EXPIRY`), splitting is
/// indistinguishable from one large advertisement. Each chunk is a complete,
/// independently-signed advertisement.
pub fn generate_advertisements(
    identity: &Keypair,
    table: &RoutingTable,
    exclude_next_hop: &PeerId,
    max_message_bytes: usize,
) -> Vec<RouteAdvertisement> {
    let entries = advertisement_entries(identity, table, exclude_next_hop);

    // Entries that fit one message under the size budget (at least one, so we
    // always make progress even with a pathologically small MTU).
    let per_chunk = max_message_bytes
        .saturating_sub(AD_OVERHEAD_RESERVE)
        / ROUTE_ENTRY_BYTES;
    let per_chunk = per_chunk.max(1);

    entries
        .chunks(per_chunk)
        .map(|chunk| {
            let mut ad = RouteAdvertisement {
                advertiser: identity.peer_id(),
                entries: chunk.to_vec(),
                signature: Vec::new(),
            };
            ad.signature = identity.sign(&ad.signable_bytes());
            ad
        })
        .collect()
}

/// Single-message convenience wrapper (no size limit). Test-only — production
/// senders use [`generate_advertisements`] with the link's frame budget.
#[cfg(test)]
pub fn generate_advertisement(
    identity: &Keypair,
    table: &RoutingTable,
    exclude_next_hop: &PeerId,
) -> RouteAdvertisement {
    generate_advertisements(identity, table, exclude_next_hop, usize::MAX)
        .pop()
        .expect("at least the self-route entry is always present")
}

/// Process a received route advertisement. Returns true if routing table changed.
/// Verifies the signature using the advertiser's cached pubkey.
pub fn process_advertisement(
    table: &mut RoutingTable,
    ad: &RouteAdvertisement,
    pubkey_cache: &mut PubkeyCache,
) -> Result<bool> {
    // Look up advertiser's signing pubkey from cache (populated during link handshake)
    let cached = pubkey_cache.get(&ad.advertiser).ok_or_else(|| {
        Error::Crypto(format!(
            "no cached pubkey for advertiser {:?}",
            ad.advertiser
        ))
    })?;
    let algo = SigningAlgo::from_u8(cached.signing_algo as u8)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let signing_pk = cached.signing_pk.clone();

    let signable = ad.signable_bytes();
    if !identity::verify(algo, &signing_pk, &signable, &ad.signature) {
        return Err(Error::Crypto(
            "invalid route advertisement signature".into(),
        ));
    }

    let mut changed = false;
    for entry in &ad.entries {
        if entry.cost == u32::MAX {
            continue; // poison reverse — skip infinite cost
        }
        // Cost to reach destination through advertiser = entry.cost + 1 (link cost)
        let total_cost = entry.cost.saturating_add(1);
        if table.update_with_source(
            entry.destination,
            ad.advertiser,
            total_cost,
            RouteSource::Advertisement,
        ) {
            changed = true;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn advertisement_roundtrip() {
        let kp = Keypair::generate();
        let mut table = RoutingTable::new(kp.peer_id());
        table.add_neighbor(pid(1));
        table.update(pid(2), pid(1), 2);

        let ad = generate_advertisement(&kp, &table, &pid(99));
        let bytes = ad.to_bytes();
        let parsed = RouteAdvertisement::from_bytes(&bytes).unwrap();

        // Verify signature using the Ed25519 pubkey directly
        let signable = parsed.signable_bytes();
        let pubkey = kp.identity.signing.signing_pubkey_bytes();
        assert!(identity::verify(
            kp.identity.signing_algo(),
            &pubkey,
            &signable,
            &parsed.signature
        ));
    }

    fn make_cache_for(kp: &Keypair) -> PubkeyCache {
        use crate::pubkey_cache::CachedPubkey;
        let mut cache = PubkeyCache::new(100);
        cache.insert(
            kp.peer_id(),
            CachedPubkey {
                signing_algo: kp.identity.signing_algo(),
                signing_pk: kp.identity.signing.signing_pubkey_bytes(),
                kem_algo: kp.identity.kem_algo(),
                kem_pk: kp.identity.kem.kem_pubkey_bytes(),
            },
        );
        cache
    }

    #[test]
    fn process_updates_table() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        // B advertises that it knows C at cost 1
        let mut table_b = RoutingTable::new(kp_b.peer_id());
        table_b.add_neighbor(PeerId([3u8; 32]));
        let ad = generate_advertisement(&kp_b, &table_b, &kp_a.peer_id());

        // A processes B's advertisement
        let mut table_a = RoutingTable::new(kp_a.peer_id());
        table_a.add_neighbor(kp_b.peer_id());
        let mut cache = make_cache_for(&kp_b);
        let changed = process_advertisement(&mut table_a, &ad, &mut cache).unwrap();
        assert!(changed);

        // A should know C through B at cost 2
        let route = table_a.lookup(&PeerId([3u8; 32])).unwrap();
        assert_eq!(route.next_hop, kp_b.peer_id());
        assert_eq!(route.cost, 2);
    }

    #[test]
    fn chunks_to_fit_budget_and_reassemble_via_processing() {
        // A large table must split into multiple frame-sized advertisements,
        // each independently valid, and applying all chunks reproduces the full
        // routing knowledge (soft-state: order/splitting-independent).
        let kp_b = Keypair::generate();
        let mut table_b = RoutingTable::with_capacity(kp_b.peer_id(), 10_000, 200);
        for i in 0..300u32 {
            let mut d = [0u8; 32];
            d[0..4].copy_from_slice(&i.to_be_bytes());
            table_b.update_with_source(PeerId(d), pid(200), i + 1, RouteSource::Advertisement);
        }

        // Budget that forces several chunks (room for ~ a dozen entries each).
        let budget = AD_OVERHEAD_RESERVE + 12 * ROUTE_ENTRY_BYTES;
        let ads = generate_advertisements(&kp_b, &table_b, &pid(99), budget);
        assert!(ads.len() > 1, "expected multiple chunks, got {}", ads.len());

        // Every chunk fits the budget once wrapped for the wire.
        for ad in &ads {
            assert!(ad.to_wire().encode().len() <= budget);
        }

        // Applying all chunks teaches a fresh table every destination.
        let kp_a = Keypair::generate();
        let mut table_a = RoutingTable::with_capacity(kp_a.peer_id(), 10_000, 200);
        table_a.add_neighbor(kp_b.peer_id());
        let mut cache = make_cache_for(&kp_b);
        for ad in &ads {
            process_advertisement(&mut table_a, ad, &mut cache).unwrap();
        }
        for (dest, _) in table_b.entries_for_advertisement() {
            assert!(table_a.lookup(&dest).is_some(), "missing dest after chunked apply");
        }
    }

    #[test]
    fn split_horizon() {
        let kp = Keypair::generate();
        let mut table = RoutingTable::new(kp.peer_id());
        table.update(pid(2), pid(1), 2); // reach 2 via 1

        // Advertisement to peer 1 should poison-reverse the route to 2
        let ad = generate_advertisement(&kp, &table, &pid(1));
        let entry = ad.entries.iter().find(|e| e.destination == pid(2));
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().cost, u32::MAX);
    }
}
