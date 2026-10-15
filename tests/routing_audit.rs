use tarnet::routing::{LandmarkLimits, RoutingTable, COST_FAST};
use tarnet::types::PeerId;
use tarnet::wire::*;

fn peer(n: u8) -> PeerId {
    PeerId([n; 32])
}
fn entry(n: u8, metric: u16) -> RouteEntry {
    RouteEntry {
        dest: peer(n),
        seqno: 1,
        metric,
        eflags: 0,
    }
}
fn update(flags: u8, dump_id: u16, entries: Vec<RouteEntry>) -> RouteUpdateMsg {
    RouteUpdateMsg {
        flags,
        dump_id,
        entries,
        degree: 1,
    }
}

#[test]
fn audit_dump_preserves_interleaved_withdrawal() {
    let mut rt = RoutingTable::new(peer(1));
    rt.neighbour_up(peer(2), COST_FAST);
    rt.apply_update(
        &peer(2),
        &update(
            ROUTE_FULL | ROUTE_FULL_START | ROUTE_FULL_END,
            1,
            vec![entry(3, 1)],
        ),
    );
    rt.apply_update(
        &peer(2),
        &update(ROUTE_FULL | ROUTE_FULL_START, 2, vec![entry(3, 1)]),
    );
    rt.apply_update(&peer(2), &update(0, 0, vec![entry(3, ROUTE_INFINITY)]));
    assert!(rt.lookup(&peer(3)).is_none());
    rt.apply_update(&peer(2), &update(ROUTE_FULL | ROUTE_FULL_END, 2, vec![]));
    assert!(
        rt.lookup(&peer(3)).is_none(),
        "dump resurrected a withdrawn route"
    );
}

#[test]
fn audit_dump_commit_preserves_rib_capacity() {
    let mut rt = RoutingTable::with_budget(peer(1), 1);
    rt.set_landmark_limits(LandmarkLimits {
        max: 0,
        ..LandmarkLimits::default()
    });
    rt.neighbour_up(peer(2), COST_FAST);
    rt.apply_update(
        &peer(2),
        &update(ROUTE_FULL | ROUTE_FULL_START | ROUTE_FULL_END, 1, vec![]),
    );
    // With these limits advertised_capacity = 2 and RIB capacity = 4.
    let snapshot: Vec<_> = (10..14).map(|n| entry(n, 1)).collect();
    let changes: Vec<_> = (20..24).map(|n| entry(n, 1)).collect();
    rt.apply_update(
        &peer(2),
        &update(ROUTE_FULL | ROUTE_FULL_START, 2, snapshot.clone()),
    );
    rt.apply_update(&peer(2), &update(0, 0, changes.clone()));
    rt.apply_update(&peer(2), &update(ROUTE_FULL | ROUTE_FULL_END, 2, vec![]));
    let union: Vec<_> = snapshot.into_iter().chain(changes).collect();
    assert!(
        !rt.digest_matches(&peer(2), &RouteDigestMsg::of_with_degree(union.iter(), 1)),
        "RIB accepted all eight entries despite a four-entry cap"
    );
    // Overflow retains the live deltas and forces repair, even if the sender
    // happens to advertise exactly that retained set.
    let retained: Vec<_> = (20..24).map(|n| entry(n, 1)).collect();
    let digest = RouteDigestMsg::of_with_degree(retained.iter(), 1);
    assert!(!rt.digest_matches(&peer(2), &digest));
    rt.apply_update(
        &peer(2),
        &update(ROUTE_FULL | ROUTE_FULL_START | ROUTE_FULL_END, 3, retained),
    );
    assert!(rt.digest_matches(&peer(2), &digest));
}

#[test]
fn audit_degree_change_reaches_existing_neighbours() {
    let mut a = RoutingTable::new(peer(1));
    let mut b = RoutingTable::new(peer(2));
    a.neighbour_up(peer(2), COST_FAST);
    b.neighbour_up(peer(1), COST_FAST);
    for msg in a.take_pending(&peer(2)) {
        b.apply_update(&peer(1), &msg);
    }
    assert_eq!(b.neighbour_degree(&peer(1)), Some(1));
    a.neighbour_up(peer(3), COST_FAST);
    for msg in a.take_pending(&peer(2)) {
        b.apply_update(&peer(1), &msg);
    }
    assert_eq!(
        b.neighbour_degree(&peer(1)),
        Some(2),
        "degree change was not queued"
    );
    a.neighbour_down(&peer(3));
    // Drop the metadata-only update: digest repair must detect it.
    assert_eq!(a.take_pending(&peer(2)).len(), 1);
    assert!(!b.digest_matches(&peer(1), &a.digest_for(&peer(2)).unwrap()));
    a.request_full_dump(&peer(2));
    for msg in a.take_pending(&peer(2)) {
        b.apply_update(&peer(1), &msg);
    }
    assert_eq!(b.neighbour_degree(&peer(1)), Some(1));
    assert!(b.digest_matches(&peer(1), &a.digest_for(&peer(2)).unwrap()));
}

#[test]
fn audit_admission_checks_final_batch_not_entry_order() {
    let mut rt = RoutingTable::with_budget(peer(1), 1);
    rt.set_landmark_limits(LandmarkLimits {
        max: 0,
        ..LandmarkLimits::default()
    });
    rt.neighbour_up(peer(2), COST_FAST);
    rt.apply_update(
        &peer(2),
        &update(0, 0, (10..14).map(|n| entry(n, 1)).collect()),
    );
    // Addition comes before the withdrawal which makes room for it.
    rt.apply_update(
        &peer(2),
        &update(0, 0, vec![entry(20, 1), entry(10, ROUTE_INFINITY)]),
    );
    let expected: Vec<_> = [11, 12, 13, 20].into_iter().map(|n| entry(n, 1)).collect();
    assert!(rt.digest_matches(
        &peer(2),
        &RouteDigestMsg::of_with_degree(expected.iter(), 1)
    ));
    // An oversized ordinary batch must not partially change the live set.
    rt.apply_update(&peer(2), &update(0, 0, vec![entry(21, 1)]));
    rt.apply_update(
        &peer(2),
        &update(
            ROUTE_FULL | ROUTE_FULL_START | ROUTE_FULL_END,
            1,
            expected.clone(),
        ),
    );
    assert!(rt.digest_matches(
        &peer(2),
        &RouteDigestMsg::of_with_degree(expected.iter(), 1)
    ));
}

#[test]
fn audit_overflowing_first_dump_can_be_replaced() {
    let mut rt = RoutingTable::with_budget(peer(1), 1);
    rt.set_landmark_limits(LandmarkLimits {
        max: 0,
        ..LandmarkLimits::default()
    });
    rt.neighbour_up(peer(2), COST_FAST);
    rt.apply_update(
        &peer(2),
        &update(
            ROUTE_FULL | ROUTE_FULL_START,
            1,
            (10..14).map(|n| entry(n, 1)).collect(),
        ),
    );
    rt.apply_update(
        &peer(2),
        &update(ROUTE_FULL | ROUTE_FULL_END, 1, vec![entry(14, 1)]),
    );
    let repaired: Vec<_> = (20..24).map(|n| entry(n, 1)).collect();
    rt.apply_update(
        &peer(2),
        &update(
            ROUTE_FULL | ROUTE_FULL_START | ROUTE_FULL_END,
            2,
            repaired.clone(),
        ),
    );
    assert!(rt.digest_matches(
        &peer(2),
        &RouteDigestMsg::of_with_degree(repaired.iter(), 1)
    ));
}
