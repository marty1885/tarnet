use crate::identity::{self, Keypair};
use crate::pubkey_cache::PubkeyCache;
use crate::types::{Error, PeerId, Result};
use crate::wire::{RouteAdvertisement, RouteEntry};
use tarnet_api::types::SigningAlgo;

use super::RoutingTable;

/// Generate a signed route advertisement from our routing table.
pub fn generate_advertisement(
    identity: &Keypair,
    table: &RoutingTable,
    exclude_next_hop: &PeerId,
) -> RouteAdvertisement {
    // Split horizon: don't advertise routes learned through the peer we're
    // sending to. Also include ourselves at cost 0.
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

    let mut ad = RouteAdvertisement {
        advertiser: identity.peer_id(),
        entries,
        signature: Vec::new(),
    };
    let signable = ad.signable_bytes();
    ad.signature = identity.sign(&signable);
    ad
}

/// Process a received route advertisement. Returns true if routing table changed.
/// Verifies the signature using the advertiser's cached pubkey.
pub fn process_advertisement(table: &mut RoutingTable, ad: &RouteAdvertisement, pubkey_cache: &mut PubkeyCache) -> Result<bool> {
    // Look up advertiser's signing pubkey from cache (populated during link handshake)
    let cached = pubkey_cache.get(&ad.advertiser).ok_or_else(|| {
        Error::Crypto(format!("no cached pubkey for advertiser {:?}", ad.advertiser))
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
        if table.update(entry.destination, ad.advertiser, total_cost) {
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
        cache.insert(kp.peer_id(), CachedPubkey {
            signing_algo: kp.identity.signing_algo(),
            signing_pk: kp.identity.signing.signing_pubkey_bytes(),
            kem_algo: kp.identity.kem_algo(),
            kem_pk: kp.identity.kem.kem_pubkey_bytes(),
        });
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
