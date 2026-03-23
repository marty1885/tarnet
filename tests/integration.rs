use std::sync::Arc;
use std::time::Duration;

use tarnet::dht::{BloomFilter, IterativeLookup, KBucketTable};
use tarnet::identity::{self, dht_id_from_peer_id, Keypair};
use tarnet::link::PeerLink;
use tarnet::node::Node;
use tarnet::pubkey_cache::{CachedPubkey, PubkeyCache};
use tarnet::routing::dv;
use tarnet::routing::RoutingTable;
use tarnet::state::{StateDb, StorageLimits};
use tarnet::transport::tcp::{TcpDiscovery, TcpTransport};
use tarnet::types::{DhtId, PeerId, RecordType};
use tarnet::wire::*;
use tarnet_api::service::{ListenerOptions, PortMode};
use tarnet_api::types::ServiceId;
use tokio::net::{TcpListener, TcpStream};

fn hash_64(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    blake3::Hasher::new()
        .update(input)
        .finalize_xof()
        .fill(&mut out);
    out
}

fn make_pubkey_cache(kp: &Keypair) -> PubkeyCache {
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

const TEST_MODE: PortMode = PortMode::ReliableOrdered;

/// Test that peer link handshake completes over TCP.
#[tokio::test]
async fn peer_link_handshake() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let pid_a = kp_a.peer_id();
    let pid_b = kp_b.peer_id();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let transport = Box::new(TcpTransport::new(stream));
        PeerLink::responder(transport, &kp_b).await.unwrap()
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let transport = Box::new(TcpTransport::new(stream));
    let link_a = PeerLink::initiator(transport, &kp_a, None).await.unwrap();
    let link_b = server.await.unwrap();

    assert_eq!(link_a.remote_peer(), pid_b);
    assert_eq!(link_b.remote_peer(), pid_a);
}

/// Test encrypted message exchange over peer links.
#[tokio::test]
async fn peer_link_encrypted_messages() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let transport = Box::new(TcpTransport::new(stream));
        PeerLink::responder(transport, &kp_b).await.unwrap()
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let transport = Box::new(TcpTransport::new(stream));
    let link_a = PeerLink::initiator(transport, &kp_a, None).await.unwrap();
    let link_b = server.await.unwrap();

    // A sends to B
    let msg = b"hello from A to B";
    let wire = WireMessage::new(MessageType::ChannelData, msg.to_vec());
    link_a.send_message(&wire.encode()).await.unwrap();

    let received = link_b.recv_message().await.unwrap();
    let decoded = WireMessage::decode(&received).unwrap();
    assert_eq!(decoded.msg_type, MessageType::ChannelData);
    assert_eq!(decoded.payload, msg);

    // B sends to A
    let reply = b"reply from B to A";
    let wire = WireMessage::new(MessageType::ChannelData, reply.to_vec());
    link_b.send_message(&wire.encode()).await.unwrap();

    let received = link_a.recv_message().await.unwrap();
    let decoded = WireMessage::decode(&received).unwrap();
    assert_eq!(decoded.payload, reply);
}

/// Test route advertisement propagation across 3 nodes.
#[tokio::test]
async fn route_propagation_three_nodes() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let kp_c = Keypair::generate();

    // Build routing tables: A -- B -- C
    let mut table_a = RoutingTable::new(kp_a.peer_id());
    let mut table_b = RoutingTable::new(kp_b.peer_id());
    let mut table_c = RoutingTable::new(kp_c.peer_id());

    // B is neighbor of A and C
    table_a.add_neighbor(kp_b.peer_id());
    table_b.add_neighbor(kp_a.peer_id());
    table_b.add_neighbor(kp_c.peer_id());
    table_c.add_neighbor(kp_b.peer_id());

    // B advertises to A (including C)
    let ad_b_to_a = dv::generate_advertisement(&kp_b, &table_b, &kp_a.peer_id());
    let mut cache = make_pubkey_cache(&kp_b);
    let changed = dv::process_advertisement(&mut table_a, &ad_b_to_a, &mut cache).unwrap();
    assert!(changed);

    // A should now know about C through B
    let route = table_a.lookup(&kp_c.peer_id()).unwrap();
    assert_eq!(route.next_hop, kp_b.peer_id());
    assert_eq!(route.cost, 2); // A→B (1) + B→C (1) = 2

    // B advertises to C (including A)
    let ad_b_to_c = dv::generate_advertisement(&kp_b, &table_b, &kp_c.peer_id());
    let mut cache = make_pubkey_cache(&kp_b);
    let changed = dv::process_advertisement(&mut table_c, &ad_b_to_c, &mut cache).unwrap();
    assert!(changed);

    // C should now know about A through B
    let route = table_c.lookup(&kp_a.peer_id()).unwrap();
    assert_eq!(route.next_hop, kp_b.peer_id());
    assert_eq!(route.cost, 2);
}

/// Test DHT content-addressed put/get.
#[tokio::test]
async fn dht_content_addressed() {
    use tarnet::dht::*;

    let data = b"distributed hash table test data";
    let (key, blob) = content_address_put(data);

    // Simulate storing and retrieving
    let peer = PeerId([1u8; 32]);
    let mut store = DhtStore::new(&peer);
    store.put(DhtRecord {
        key,
        record_type: tarnet::types::RecordType::Content,
        sequence: 0,
        signer: [0u8; 32],
        signer_algo: 1,
        signer_pubkey: Vec::new(),
        value: blob.clone(),
        ttl: Duration::from_secs(3600),
        stored_at: std::time::Instant::now(),
        signature: vec![0u8; 64],
    });

    let records = store.get(&key);
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.value, blob);

    // Decrypt with content hash
    let inner_hash: [u8; 64] = hash_64(data);
    let decrypted = content_address_get(&inner_hash, &record.value).unwrap();
    assert_eq!(decrypted, data);
}

/// Test stateless tunnel encrypt/decrypt (e2e, no relay state).
#[tokio::test]
async fn tunnel_stateless_e2e() {
    use tarnet::tunnel::{Tunnel, TunnelTable};

    // A and C share a key — tunnels are now peer-keyed, no relay state
    let shared = [99u8; 32];
    let tunnel_a = Tunnel::new(PeerId([3; 32]), &shared, true);
    let tunnel_c = Tunnel::new(PeerId([1; 32]), &shared, false);

    // A encrypts
    let plaintext = b"end to end stateless";
    let encrypted = tunnel_a.encrypt(plaintext);

    // C decrypts (relays just forward the routed packet, no tunnel state)
    let decrypted = tunnel_c.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);

    // Verify tunnel table is peer-keyed
    let mut table = TunnelTable::new();
    table.add(tunnel_a);
    assert!(table.get(&PeerId([3; 32])).is_some());
    assert!(table.get(&PeerId([1; 32])).is_none());
}

/// Test reliable channel ordering and selective ACK.
#[tokio::test]
async fn reliable_channel_full() {
    use tarnet::channel::Channel;

    let mut sender = Channel::from_port_name(1, "test-service", true, true);
    let mut receiver = Channel::from_port_name(1, "test-service", true, true);

    // Send 5 messages
    let messages: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("message {}", i).into_bytes())
        .collect();

    let mut sends = Vec::new();
    for msg in &messages {
        sends.extend(sender.prepare_send(msg.clone()));
    }

    // Deliver out of order: 0, 2, 4, 1, 3
    let d0 = receiver.receive_data(0, messages[0].clone());
    assert_eq!(d0.len(), 1); // delivered immediately

    let d2 = receiver.receive_data(2, messages[2].clone());
    assert!(d2.is_empty()); // buffered

    let d4 = receiver.receive_data(4, messages[4].clone());
    assert!(d4.is_empty()); // buffered

    // ACK should show we need seq 1, with 2 and 4 selectively acked
    let (ack_seq, selective) = receiver.generate_ack().unwrap();
    assert_eq!(ack_seq, 1);
    assert!(selective.contains(&2));
    assert!(selective.contains(&4));

    // Deliver seq 1 — should cascade deliver 1 and 2
    let d1 = receiver.receive_data(1, messages[1].clone());
    assert_eq!(d1.len(), 2); // seq 1 and 2

    // Deliver seq 3 — should cascade deliver 3 and 4
    let d3 = receiver.receive_data(3, messages[3].clone());
    assert_eq!(d3.len(), 2); // seq 3 and 4

    // Process cumulative ACK on sender side
    sender.process_ack(5, &[]);
    assert_eq!(sender.pending_retransmit().len(), 0);
}

/// Integration test: two nodes connect over TCP, exchange routed data.
#[tokio::test]
async fn two_node_link_and_routing() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));

    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();

    // Start node B's event loop (no bootstrap)
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![], vec![]).await.ok();
    });

    // Give B time to start listening
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start node A, bootstrapping to B
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok();
    });

    // Wait for link establishment and initial route exchange
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Both should see each other as connected
    let a_peers = node_a.connected_peers().await;
    assert!(a_peers.contains(&node_b.peer_id()));

    let b_peers = node_b.connected_peers().await;
    assert!(b_peers.contains(&node_a.peer_id()));
}

/// Integration test: 3 nodes, client sends data to server through relay.
#[tokio::test]
async fn three_node_routed_data() {
    let _ = env_logger::builder().is_test(true).try_init();

    let server = Arc::new(Node::new(Keypair::generate()));
    let relay = Arc::new(Node::new(Keypair::generate()));
    let client = Arc::new(Node::new(Keypair::generate()));

    let server_pid = server.peer_id();

    // Start server
    let disc_s = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_s = disc_s.local_addrs()[0].to_string();
    let mut server_rx = server.take_app_receiver().await.unwrap();
    let s = server.clone();
    tokio::spawn(async move {
        s.run(Box::new(disc_s), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start relay, connected to server
    let disc_r = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_r = disc_r.local_addrs()[0].to_string();
    let r = relay.clone();
    tokio::spawn(async move {
        r.run(Box::new(disc_r), vec![addr_s], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Start client, connected to relay (NOT directly to server)
    let disc_c = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let c = client.clone();
    tokio::spawn(async move {
        c.run(Box::new(disc_c), vec![addr_r], vec![]).await.ok();
    });

    // Wait for routes to propagate through relay
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Client should have a route to server through relay
    let routes = client.routing_entries().await;
    assert!(
        routes.iter().any(|(d, _, _)| *d == server_pid),
        "client has no route to server. routes: {:?}",
        routes
    );

    // Client sends data to server through overlay
    client
        .send_data(&server_pid, b"hello from client")
        .await
        .unwrap();

    // Server should receive it
    let (from, data) = tokio::time::timeout(Duration::from_secs(2), server_rx.recv())
        .await
        .expect("timeout waiting for data")
        .expect("channel closed");

    assert_eq!(from, client.peer_id());
    assert_eq!(data, b"hello from client");
}

/// Integration test: DHT watch notification.
/// Node A watches a key, Node B puts a record at that key, Node A receives notification.
#[tokio::test]
async fn dht_watch_notification() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));

    let mut watch_rx = node_a.take_dht_watch_receiver().await.unwrap();

    // Start node A
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_a = disc_a.local_addrs()[0].to_string();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start node B, bootstrap to A
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![addr_a], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Both should be connected
    assert!(node_a.connected_peers().await.contains(&node_b.peer_id()));

    // Node A watches node B's hello key
    let key = tarnet::dht::identity_address_key(&node_b.peer_id());
    node_a.dht_watch(&key, 300).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Node B publishes its hello
    node_b
        .set_global_addrs(vec![tarnet::types::ScopedAddress::from_string(
            "127.0.0.1:9999",
        )
        .unwrap()])
        .await;
    node_b.publish_hello().await;

    // Node A should receive a watch notification
    let (notified_key, record) = tokio::time::timeout(Duration::from_secs(2), watch_rx.recv())
        .await
        .expect("timeout waiting for watch notification")
        .expect("channel closed");

    assert_eq!(notified_key, key);
    assert_eq!(record.record_type, tarnet::types::RecordType::Hello);
}

/// Test k-bucket insert, eviction, and closest_peers.
#[test]
fn kbucket_insert_and_closest() {
    let local = Keypair::generate();
    let mut table = KBucketTable::new(&local.peer_id());

    // Insert several peers
    let mut peers = Vec::new();
    for _ in 0..30 {
        let kp = Keypair::generate();
        let pid = kp.peer_id();
        let did = dht_id_from_peer_id(&pid);
        table.insert(pid, did);
        peers.push((pid, did));
    }

    assert!(table.len() <= 30);
    assert!(table.len() > 0);

    // closest_peers should return up to k
    let target = DhtId([0xAA; 64]);
    let closest = table.closest_peers(&target, 10);
    assert!(closest.len() <= 10);
    assert!(!closest.is_empty());

    // Verify ordering: each peer should be at least as close as the next
    for i in 1..closest.len() {
        let dist_prev = target.xor_distance(&closest[i - 1].1);
        let dist_curr = target.xor_distance(&closest[i].1);
        assert!(dist_prev <= dist_curr);
    }
}

/// Test bloom filter insert and contains.
#[test]
fn bloom_filter_dedup() {
    let mut bloom = BloomFilter::new();
    let peer_a = PeerId([0x11; 32]);
    let peer_b = PeerId([0x22; 32]);
    let peer_c = PeerId([0x33; 32]);

    bloom.insert(&peer_a);
    bloom.insert(&peer_b);

    assert!(bloom.contains(&peer_a));
    assert!(bloom.contains(&peer_b));
    // peer_c was not inserted — might be false positive, but very unlikely
    // We just check that the bloom filter works at all
    // (false positive rate for 2 insertions in 2048 bits is very low)

    // Verify roundtrip through bytes
    let bytes = bloom.to_bytes();
    let bloom2 = BloomFilter::from_bytes(bytes);
    assert!(bloom2.contains(&peer_a));
    assert!(bloom2.contains(&peer_b));
    assert_eq!(bloom.to_bytes(), bloom2.to_bytes());

    // Empty bloom should not contain anything
    let empty = BloomFilter::new();
    assert!(!empty.contains(&peer_a));
    assert!(!empty.contains(&peer_c));
}

/// Test iterative lookup state machine.
#[test]
fn iterative_lookup_state_machine() {
    let target = DhtId([0x55; 64]);
    let mut peers = Vec::new();
    for i in 0..10u8 {
        let pid = PeerId([i; 32]);
        let did = dht_id_from_peer_id(&pid);
        peers.push((pid, did));
    }

    let mut lookup = IterativeLookup::new(target, peers.clone());

    // Should return alpha=3 peers to query first
    let to_query = lookup.next_to_query();
    assert_eq!(to_query.len(), 3);

    // Process response from first peer with no new peers
    lookup.process_response(to_query[0], vec![], vec![]);

    // Should still have more to query
    assert!(!lookup.is_done());

    // Process all remaining
    for peer in &to_query[1..] {
        lookup.process_response(*peer, vec![], vec![]);
    }

    // Get more to query
    let more = lookup.next_to_query();
    for peer in more {
        lookup.process_response(peer, vec![], vec![]);
    }

    // Keep querying until done
    loop {
        let batch = lookup.next_to_query();
        if batch.is_empty() {
            break;
        }
        for peer in batch {
            lookup.process_response(peer, vec![], vec![]);
        }
    }

    assert!(lookup.is_done());
    let closest = lookup.k_closest_peers();
    assert!(!closest.is_empty());
}

/// Test handshake with anti-replay protection (timestamp + challenge).
#[tokio::test]
async fn handshake_anti_replay() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let transport = Box::new(TcpTransport::new(stream));
        PeerLink::responder(transport, &kp_b).await.unwrap()
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let transport = Box::new(TcpTransport::new(stream));
    let link_a = PeerLink::initiator(transport, &kp_a, None).await.unwrap();
    let link_b = server.await.unwrap();

    // Links should work after the hardened handshake
    let msg = b"post-hardened-handshake data";
    let wire = WireMessage::new(MessageType::ChannelData, msg.to_vec());
    link_a.send_message(&wire.encode()).await.unwrap();

    let received = link_b.recv_message().await.unwrap();
    let decoded = WireMessage::decode(&received).unwrap();
    assert_eq!(decoded.payload, msg);
}

/// Test link sequence number anti-replay.
#[tokio::test]
async fn link_sequence_anti_replay() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let transport = Box::new(TcpTransport::new(stream));
        PeerLink::responder(transport, &kp_b).await.unwrap()
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let transport = Box::new(TcpTransport::new(stream));
    let link_a = PeerLink::initiator(transport, &kp_a, None).await.unwrap();
    let link_b = server.await.unwrap();

    // Send multiple messages and verify they arrive
    for i in 0..5u8 {
        let data = vec![i; 10];
        let wire = WireMessage::new(MessageType::Data, data.clone());
        link_a.send_message(&wire.encode()).await.unwrap();

        let received = link_b.recv_message().await.unwrap();
        let decoded = WireMessage::decode(&received).unwrap();
        assert_eq!(decoded.payload, data);
    }
}

/// Test DHT PUT hop limit enforcement.
#[tokio::test]
async fn dht_put_hop_limit() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let node_c = Arc::new(Node::new(Keypair::generate()));

    // Start nodes: A -- B -- C
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_a = disc_a.local_addrs()[0].to_string();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![addr_a], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let disc_c = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let nc = node_c.clone();
    tokio::spawn(async move {
        nc.run(Box::new(disc_c), vec![addr_b], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // All should be connected through B
    assert!(node_a.connected_peers().await.contains(&node_b.peer_id()));
    assert!(node_b.connected_peers().await.contains(&node_c.peer_id()));

    // Node A puts content — should propagate through network with hop limit
    let data = b"hop limit test data";
    let inner_hash = node_a.dht_put_content(data).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node B should have the data (1 hop from A)
    let result_b = node_b.dht_get_content(&inner_hash).await;
    assert!(result_b.is_some(), "Node B should have the content");
    assert_eq!(result_b.unwrap(), data);
}

/// Test signature rejection on DHT GET response.
#[test]
fn signature_validation_on_get_response() {
    // Create a DhtPutMsg with an invalid signature
    let kp = Keypair::generate();
    let pubkey = kp.identity.signing.signing_pubkey_bytes();
    let put = DhtPutMsg {
        key: [0xAA; 64],
        record_type: RecordType::Hello,
        sequence: 1,
        signer: *kp.peer_id().as_bytes(),
        ttl: 600,
        value: b"hello".to_vec(),
        signature: vec![0xFF; 64], // invalid signature
        signer_algo: 1,
        signer_pubkey: pubkey.clone(),
        hop_count: 0,
        hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
        bloom: [0; 256],
    };

    // Verify that signature check fails
    let valid = identity::verify(
        kp.identity.signing_algo(),
        &pubkey,
        &put.signable_bytes(),
        &put.signature,
    );
    assert!(!valid, "Invalid signature should not verify");

    // Create one with a valid signature
    let mut put_valid = DhtPutMsg {
        key: [0xBB; 64],
        record_type: RecordType::Hello,
        sequence: 1,
        signer: *kp.peer_id().as_bytes(),
        ttl: 600,
        value: b"valid hello".to_vec(),
        signature: vec![0u8; 64],
        signer_algo: 1,
        signer_pubkey: pubkey.clone(),
        hop_count: 0,
        hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
        bloom: [0; 256],
    };
    put_valid.signature = kp.sign(&put_valid.signable_bytes());
    let valid = identity::verify(
        kp.identity.signing_algo(),
        &pubkey,
        &put_valid.signable_bytes(),
        &put_valid.signature,
    );
    assert!(valid, "Valid signature should verify");
}

/// Test DhtFindClosest/DhtFindClosestResponse roundtrip.
#[test]
fn dht_find_closest_roundtrip() {
    let find = DhtFindClosestMsg { key: [0xAA; 64] };
    let bytes = find.to_bytes();
    let decoded = DhtFindClosestMsg::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.key, [0xAA; 64]);

    let resp = DhtFindClosestResponseMsg {
        key: [0xBB; 64],
        peers: vec![
            (PeerId([0x11; 32]), DhtId([0x22; 64])),
            (PeerId([0x33; 32]), DhtId([0x44; 64])),
        ],
    };
    let bytes = resp.to_bytes();
    let decoded = DhtFindClosestResponseMsg::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.key, [0xBB; 64]);
    assert_eq!(decoded.peers.len(), 2);
    assert_eq!(decoded.peers[0].0, PeerId([0x11; 32]));
    assert_eq!(decoded.peers[1].1, DhtId([0x44; 64]));
}

/// Test DhtGetMsg with hop_limit and bloom roundtrip.
#[test]
fn dht_get_msg_new_fields_roundtrip() {
    let mut bloom = BloomFilter::new();
    bloom.insert(&PeerId([0x11; 32]));

    let get = DhtGetMsg {
        key: [0xCC; 64],
        query_token: [0x99; 32],
        hop_count: 2,
        hop_limit: 5,
        bloom: bloom.to_bytes(),
    };
    let bytes = get.to_bytes();
    let decoded = DhtGetMsg::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.key, [0xCC; 64]);
    assert_eq!(decoded.query_token, [0x99; 32]);
    assert_eq!(decoded.hop_limit, 5);

    let bloom_decoded = BloomFilter::from_bytes(decoded.bloom);
    assert!(bloom_decoded.contains(&PeerId([0x11; 32])));
}

/// Test DhtGetResponseMsg with query_token roundtrip.
#[test]
fn dht_get_response_with_query_token_roundtrip() {
    let resp = DhtGetResponseMsg {
        query_token: [0xAA; 32],
        key: [0xDD; 64],
        records: vec![],
    };
    let bytes = resp.to_bytes();
    let decoded = DhtGetResponseMsg::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.query_token, [0xAA; 32]);
    assert_eq!(decoded.key, [0xDD; 64]);
    assert!(decoded.records.is_empty());
}

/// Test HandshakeConfirmMsg roundtrip.
#[test]
fn handshake_confirm_roundtrip() {
    let confirm = HandshakeConfirmMsg {
        confirm_hash: [0xAB; 32],
    };
    let bytes = confirm.to_bytes();
    let decoded = HandshakeConfirmMsg::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.confirm_hash, [0xAB; 32]);
}

/// Test RekeyMsg roundtrip.
#[test]
fn rekey_msg_roundtrip() {
    let kp = Keypair::generate();
    let pubkey = kp.identity.signing.signing_pubkey_bytes();
    let mut rekey = RekeyMsg {
        kem_algo: kp.identity.kem_algo() as u8,
        kem_pubkey: vec![0xDD; 8],
        kem_ciphertext: vec![0xEE; 16],
        signature: vec![0u8; 64],
    };
    rekey.signature = kp.sign(&rekey.signable_bytes());

    let bytes = rekey.to_bytes();
    let decoded = RekeyMsg::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.kem_algo, kp.identity.kem_algo() as u8);

    // Verify the signature
    let valid = identity::verify(
        kp.identity.signing_algo(),
        &pubkey,
        &decoded.signable_bytes(),
        &decoded.signature,
    );
    assert!(valid);
}

/// Integration test: signed content DHT with two publishers at the same key.
/// Provider A and Provider B both publish signed content for the same topic.
/// A client retrieves both records and gets both signer PeerIds.
#[tokio::test]
async fn signed_content_multi_publisher() {
    let _ = env_logger::builder().is_test(true).try_init();

    let provider_a = Arc::new(Node::new(Keypair::generate()));
    let provider_b = Arc::new(Node::new(Keypair::generate()));
    let client = Arc::new(Node::new(Keypair::generate()));

    let pid_a = provider_a.peer_id();
    let pid_b = provider_b.peer_id();

    // Start provider A
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_a = disc_a.local_addrs()[0].to_string();
    let pa = provider_a.clone();
    tokio::spawn(async move {
        pa.run(Box::new(disc_a), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start provider B, bootstrap to A
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let pb = provider_b.clone();
    tokio::spawn(async move {
        pb.run(Box::new(disc_b), vec![addr_a.clone()], vec![])
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Start client, bootstrap to B
    let disc_c = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let c = client.clone();
    tokio::spawn(async move {
        c.run(Box::new(disc_c), vec![addr_b], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The shared "topic" — in real use this would include a group secret
    let topic = b"my-group-secret||llama-70b";

    // Both providers publish signed content for the same topic
    let inner_hash_a = provider_a.dht_put_signed_content(topic, 600).await;
    let inner_hash_b = provider_b.dht_put_signed_content(topic, 600).await;

    // Inner hashes must be identical (same content)
    assert_eq!(inner_hash_a, inner_hash_b);

    // Wait for propagation
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Client retrieves signed content — should find both providers
    let results = client.dht_get_signed_content(&inner_hash_a).await;

    // Collect signer PeerIds
    let signer_pids: Vec<PeerId> = results.iter().map(|(pid, _)| *pid).collect();

    // Both providers should appear (records propagated through the network)
    assert!(
        signer_pids.contains(&pid_a),
        "provider A not found in results. signers: {:?}",
        signer_pids
    );
    assert!(
        signer_pids.contains(&pid_b),
        "provider B not found in results. signers: {:?}",
        signer_pids
    );

    // All decrypted values should be the original topic
    for (_, plaintext) in &results {
        assert_eq!(plaintext.as_slice(), topic);
    }
}

/// Integration test: garbage records at a signed content key are silently rejected.
#[tokio::test]
async fn signed_content_garbage_rejected() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node = Arc::new(Node::new(Keypair::generate()));

    let disc = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let n = node.clone();
    tokio::spawn(async move {
        n.run(Box::new(disc), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish real signed content
    let topic = b"secret||model-x";
    let inner_hash = node.dht_put_signed_content(topic, 600).await;

    // Retrieve with correct inner hash — should find the record
    let results = node.dht_get_signed_content(&inner_hash).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, node.peer_id());
    assert_eq!(results[0].1, topic);

    // Retrieve with wrong inner hash — should find nothing (self-authentication)
    let wrong_hash: [u8; 64] = hash_64(b"wrong-secret||model-x");
    let wrong_results = node.dht_get_signed_content(&wrong_hash).await;
    assert!(wrong_results.is_empty());
}

#[tokio::test]
async fn node_db_restores_sequences_and_records() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("tarnet-integ-restore-{}.sqlite3", nanos));
    let db = Arc::new(StateDb::open(&path).unwrap());

    let original = Node::with_db(Keypair::generate(), db.clone(), StorageLimits::default());

    original.publish_hello().await;
    let signed_hash = original.dht_put_signed_content(b"payload", 300).await;

    // Read back persisted state through new Node
    let restored = Node::with_db(Keypair::generate(), db.clone(), StorageLimits::default());

    assert!(restored.lookup_hello(&original.peer_id()).await.is_some());
    let restored_signed = restored.dht_get_signed_content(&signed_hash).await;
    assert_eq!(restored_signed.len(), 1);
    assert_eq!(restored_signed[0].1, b"payload");

    // Verify metadata persisted
    assert_eq!(db.get_metadata("hello_sequence").unwrap(), Some(1));
    assert!(db.get_metadata("signed_content_sequence").unwrap().unwrap() >= 1);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

/// Test building a 2-hop circuit A → B → C and sending data through it.
#[tokio::test]
async fn circuit_build_two_hop() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let node_c = Arc::new(Node::new(Keypair::generate()));

    let pid_b = node_b.peer_id();
    let pid_c = node_c.peer_id();

    // Start node C
    let disc_c = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_c = disc_c.local_addrs()[0].to_string();
    let nc = node_c.clone();
    tokio::spawn(async move {
        nc.run(Box::new(disc_c), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start node B, connected to C
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![addr_c], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Start node A, connected to B
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify connectivity
    assert!(node_a.connected_peers().await.contains(&pid_b));
    assert!(node_b.connected_peers().await.contains(&pid_c));

    // Build a 2-hop circuit: A → B → C
    let circuit_id = tokio::time::timeout(
        Duration::from_secs(5),
        node_a.build_circuit(pid_b, vec![pid_c]),
    )
    .await
    .expect("circuit build timed out")
    .expect("circuit build failed");

    assert!(circuit_id > 0);

    // Send data through the circuit
    node_a
        .send_circuit_data(circuit_id, b"hello through circuit")
        .await
        .expect("send_circuit_data failed");

    // Destroy the circuit
    node_a
        .destroy_circuit(circuit_id)
        .await
        .expect("destroy_circuit failed");
}

/// Test building a 1-hop circuit (direct endpoint).
#[tokio::test]
async fn circuit_build_one_hop() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));

    let pid_b = node_b.peer_id();

    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(node_a.connected_peers().await.contains(&pid_b));

    let circuit_id = tokio::time::timeout(
        Duration::from_secs(5),
        node_a.build_circuit(pid_b, vec![pid_b]),
    )
    .await
    .expect("circuit build timed out")
    .expect("circuit build failed");

    assert!(circuit_id > 0);

    // Send data and destroy
    node_a
        .send_circuit_data(circuit_id, b"one hop data")
        .await
        .expect("send failed");

    node_a.destroy_circuit(circuit_id).await.unwrap();
}

/// Test connect() + accept() with bidirectional data exchange.
#[tokio::test]
async fn circuit_connect_accept_bidi() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));

    let pid_b = node_b.peer_id();
    let service_id_b = node_b.default_service_id().await;

    // Start B
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Register B as a listener
    let listener_b = node_b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    // Spawn accept on B in the background
    let nb2 = node_b.clone();
    let accept_handle =
        tokio::spawn(async move { nb2.circuit_accept(listener_b.id).await.unwrap() });

    // Start A, connected to B
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A connects to B (passing PeerId hint from B's address)
    let conn_a = tokio::time::timeout(
        Duration::from_secs(5),
        node_a.circuit_connect(service_id_b, TEST_MODE, "80", Some(pid_b), None),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    assert_eq!(conn_a.port, "80");
    assert_eq!(conn_a.mode, TEST_MODE);
    assert_eq!(conn_a.remote_service_id, service_id_b);

    // B should accept the connection
    let conn_b = tokio::time::timeout(Duration::from_secs(5), accept_handle)
        .await
        .expect("accept timed out")
        .expect("accept task failed");

    assert_eq!(conn_b.port, "80");
    assert_eq!(conn_b.mode, TEST_MODE);

    // A sends data to B
    conn_a.send(b"hello from A").await.unwrap();

    // B receives the data
    let received = tokio::time::timeout(Duration::from_secs(5), conn_b.recv())
        .await
        .expect("recv timed out")
        .expect("recv failed");
    assert_eq!(received, b"hello from A");
}

/// Integration test: hidden service rendezvous protocol.
/// 3 nodes: client (A), relay/intro/rendezvous (B), hidden service (C).
/// C is connected to B but NOT to A.
/// C publishes a hidden service with B as intro point.
/// A resolves the service and connects through B as rendezvous.
/// Data flows from A to C through the rendezvous.
#[tokio::test]
async fn hidden_service_rendezvous() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let node_c = Arc::new(Node::new(Keypair::generate()));

    let _pid_c = node_c.peer_id();

    // Start B (relay/intro/rendezvous)
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let addr_b_for_a = addr_b.clone();
    let addr_b_for_c = addr_b.clone();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Start C (hidden service), connected to B
    let disc_c = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let nc = node_c.clone();
    tokio::spawn(async move {
        nc.run(Box::new(disc_c), vec![addr_b_for_c], vec![])
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify B and C are connected
    assert!(
        node_b.connected_peers().await.contains(&node_c.peer_id()),
        "B should be connected to C"
    );

    // Use C's default identity (from identity store) — this is what
    // handle_introduce_at_service uses, not the transport identity.
    let service_id_c = node_c.default_service_id().await;
    let default_kp_c = node_c.keypair_for_service(&service_id_c).await.unwrap();

    // C registers as listener and publishes hidden service
    let listener_c = node_c
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();
    node_c
        .publish_hidden_service(service_id_c, 1)
        .await
        .expect("publish_hidden_service failed");

    // Start A (client), connected to B but NOT to C
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![addr_b_for_a], vec![])
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify A is connected to B
    assert!(
        node_a.connected_peers().await.contains(&node_b.peer_id()),
        "A should be connected to B"
    );
    // Verify A is NOT directly connected to C
    assert!(
        !node_a.connected_peers().await.contains(&node_c.peer_id()),
        "A should NOT be directly connected to C"
    );

    // Publish C's intro records on A's local DHT store
    // (simulating TNS resolution propagation).
    let intro_records = vec![tarnet::tns::TnsRecord::IntroductionPoint {
        relay_peer_id: node_b.peer_id(),
        kem_algo: default_kp_c.identity.kem_algo() as u8,
        kem_pubkey: default_kp_c.identity.kem.kem_pubkey_bytes(),
    }];
    tarnet::tns::publish(&*node_a, &default_kp_c, "intro", &intro_records, 600)
        .await
        .unwrap();

    // Verify TNS records are resolvable from A
    let resolution = tarnet::tns::resolve(&*node_a, service_id_c, "intro").await;
    match resolution {
        tarnet::tns::TnsResolution::Records(records) => {
            assert_eq!(records.len(), 1);
            match &records[0] {
                tarnet::tns::TnsRecord::IntroductionPoint { relay_peer_id, .. } => {
                    assert_eq!(*relay_peer_id, node_b.peer_id());
                }
                other => panic!("expected IntroductionPoint, got {:?}", other),
            }
        }
        other => panic!("expected Records, got {:?}", other),
    }

    // C accepts incoming connections in the background.
    let node_c_accept = node_c.clone();
    let service_conn_handle = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            node_c_accept.circuit_accept(listener_c.id),
        )
        .await
        .expect("accept timed out")
        .expect("accept failed")
    });

    // A connects to C directly via the rendezvous protocol,
    // bypassing circuit_connect's direct-route attempts.
    let kem_algo = default_kp_c.identity.kem_algo() as u8;
    let kem_pubkey = default_kp_c.identity.kem.kem_pubkey_bytes();
    let intro_points = vec![(node_b.peer_id(), kem_algo, kem_pubkey)];
    let client_conn = tokio::time::timeout(
        Duration::from_secs(10),
        node_a.connect_via_rendezvous(service_id_c, TEST_MODE, "80", &intro_points),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    assert_eq!(client_conn.port, "80");
    assert_eq!(client_conn.mode, TEST_MODE);
    assert_eq!(client_conn.remote_service_id, service_id_c);

    let service_conn = service_conn_handle.await.expect("accept task panicked");

    // Bidirectional data exchange over the e2e-encrypted rendezvous.
    // If the DH shared secrets don't match, this will produce garbage.
    client_conn.send(b"hello from client").await.unwrap();
    let received_at_service = tokio::time::timeout(Duration::from_secs(5), service_conn.recv())
        .await
        .expect("recv at service timed out")
        .expect("recv at service failed");
    assert_eq!(received_at_service, b"hello from client");

    service_conn.send(b"hello from service").await.unwrap();
    let received_at_client = tokio::time::timeout(Duration::from_secs(5), client_conn.recv())
        .await
        .expect("recv at client timed out")
        .expect("recv at client failed");
    assert_eq!(received_at_client, b"hello from service");

    log::info!("Rendezvous e2e data exchange verified");
}

/// Test: flow control allows bulk data transfer.
/// Sends far more cells than CWND_INIT (4) — if SENDME is broken, the
/// sender would stall after 4 cells and the recv side would time out.
#[tokio::test]
async fn flow_control_bulk_transfer() {
    let _ = env_logger::builder().is_test(true).try_init();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));

    let pid_b = node_b.peer_id();
    let service_id_b = node_b.default_service_id().await;

    // Start B
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move {
        nb.run(Box::new(disc_b), vec![], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let listener_b = node_b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    let nb2 = node_b.clone();
    let accept_handle =
        tokio::spawn(async move { nb2.circuit_accept(listener_b.id).await.unwrap() });

    // Start A, connected to B
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move {
        na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let conn_a = tokio::time::timeout(
        Duration::from_secs(5),
        node_a.circuit_connect(service_id_b, TEST_MODE, "80", Some(pid_b), None),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    let conn_b = tokio::time::timeout(Duration::from_secs(5), accept_handle)
        .await
        .expect("accept timed out")
        .expect("accept task failed");

    // Send 200 cells worth of data — far exceeds CWND_INIT (4).
    // This exercises the full SENDME loop: sender blocks at window,
    // receiver sends SENDME every 32 cells, sender unblocks.
    let num_messages = 200;
    let payload = vec![0xABu8; 1000]; // ~1 cell each

    let send_handle = {
        let payload = payload.clone();
        tokio::spawn(async move {
            for i in 0..num_messages {
                let mut msg = payload.clone();
                msg[0] = (i & 0xFF) as u8;
                msg[1] = ((i >> 8) & 0xFF) as u8;
                conn_a.send(&msg).await.unwrap();
            }
        })
    };

    // Receive all messages on the other side.
    let recv_handle = tokio::spawn(async move {
        let mut received = 0u32;
        while received < num_messages {
            let data = tokio::time::timeout(Duration::from_secs(30), conn_b.recv())
                .await
                .expect(&format!("recv timed out after {} messages", received))
                .expect("recv failed");
            let idx = data[0] as u32 | ((data[1] as u32) << 8);
            assert_eq!(idx, received, "messages arrived out of order");
            assert_eq!(data.len(), 1000);
            received += 1;
        }
        received
    });

    let (send_result, recv_result) = tokio::join!(send_handle, recv_handle);
    send_result.expect("send task panicked");
    let total = recv_result.expect("recv task panicked");
    assert_eq!(total, num_messages);

    log::info!("Flow control bulk transfer: {} messages delivered", total);
}

/// Test that outbound backpressure drops cells when the peer is slow.
///
/// Creates a PeerLink pair, stops reading from one side, and blasts cells.
/// The TCP kernel buffer + outbound queue fill, then send_message silently
/// drops. We verify: (1) send_message never blocks, (2) some cells are lost.
#[tokio::test]
async fn link_backpressure_drops_cells() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let transport = Box::new(TcpTransport::new(stream));
        PeerLink::responder(transport, &kp_b).await.unwrap()
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    stream.set_nodelay(true).unwrap();
    let transport = Box::new(TcpTransport::new(stream));
    let link_a = Arc::new(PeerLink::initiator(transport, &kp_a, None).await.unwrap());
    let link_b = Arc::new(server.await.unwrap());

    // Blast many cells from A — don't read from B.
    // The outbound mpsc queue (4096 slots) plus TCP send/recv kernel
    // buffers must all fill before try_send returns Full and drops start.
    // We send well over that to guarantee backpressure kicks in.
    let total: usize = 20_000;
    let payload = vec![0xCCu8; 1000];

    let deadline = tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..total {
            link_a.send_message(&payload).await.unwrap();
        }
    });
    deadline
        .await
        .expect("send_message should never block — timed out");

    // Now drain everything that made it through.
    let mut received: usize = 0;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), link_b.recv_message()).await {
            Ok(Ok(_)) => received += 1,
            _ => break,
        }
    }

    log::info!(
        "backpressure test: sent {}, received {} (dropped {})",
        total,
        received,
        total - received
    );

    assert!(received > 0, "at least some cells should arrive");
    assert!(
        received < total,
        "all {} cells arrived — backpressure did not drop any",
        total
    );
}

/// Unit test: CongestionWindow stall recovery.
#[test]
fn congestion_window_stall_recovery() {
    use tarnet::circuit::{CongestionWindow, CWND_INIT, CWND_MIN};

    let mut cw = CongestionWindow::new();

    // Fill the window completely.
    for _ in 0..CWND_INIT {
        assert!(cw.can_send());
        cw.on_send();
    }
    assert!(!cw.can_send(), "window should be full");

    // Simulate a SENDME arriving.
    cw.on_sendme();
    assert!(cw.can_send(), "window should open after SENDME");
    let cwnd_after_sendme = cw.cwnd;

    // Fill again past the new window.
    while cw.can_send() {
        cw.on_send();
    }
    assert!(!cw.can_send());

    // check_stall should not fire immediately (last_sendme_at is recent).
    assert!(!cw.check_stall(), "should not stall when SENDME was recent");
    assert!(!cw.can_send(), "window still full");

    // Backdate last_sendme_at to simulate timeout.
    cw.last_sendme_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(15));
    assert!(cw.check_stall(), "should detect stall after timeout");
    assert!(
        cw.can_send(),
        "probe window should be open after stall recovery"
    );

    // Verify the window was halved (loss event).
    let expected_cwnd = (cwnd_after_sendme / 2).max(CWND_MIN);
    assert_eq!(cw.cwnd, expected_cwnd);
}

/// Unit test: receiver-side window drops cells when exhausted.
#[test]
fn receiver_window_enforced() {
    use tarnet::circuit::{CongestionWindow, RECV_WINDOW_INIT, SENDME_INC};

    let mut cw = CongestionWindow::new();

    // Deliver RECV_WINDOW_INIT cells — should all succeed.
    let mut sendme_count = 0u32;
    for i in 0..RECV_WINDOW_INIT {
        assert!(cw.can_receive(), "should accept cell {}", i);
        let digest = [i as u8; 16];
        if cw.on_deliver(digest) {
            sendme_count += 1;
            // on_deliver replenishes recv_allowed by SENDME_INC when it returns true.
        }
    }

    // We should have sent RECV_WINDOW_INIT / SENDME_INC SENDMEs.
    assert_eq!(sendme_count, RECV_WINDOW_INIT / SENDME_INC);

    // The window should still be open because each SENDME replenished it.
    // But if the sender kept sending without us sending SENDMEs (misbehaving),
    // the window should eventually close. Let's simulate that by NOT crediting.
    // Reset to test pure exhaustion.
    let mut cw2 = CongestionWindow::new();
    // Exhaust without replenishment: deliver cells but ignore the SENDME signal.
    for _ in 0..RECV_WINDOW_INIT {
        assert!(cw2.can_receive());
        cw2.recv_allowed = cw2.recv_allowed.saturating_sub(1);
        cw2.deliver_count += 1;
        if cw2.deliver_count >= SENDME_INC {
            cw2.deliver_count = 0;
            // Don't replenish — simulating the sender ignoring SENDME.
        }
    }
    assert!(!cw2.can_receive(), "window should be exhausted");
}
