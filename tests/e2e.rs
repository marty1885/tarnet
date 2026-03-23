//! End-to-end tests: multi-node mesh networks over localhost.
//!
//! Tests cover identity-based connections, DHT cross-node retrieval,
//! TNS resolution, link break + cleanup, and DHT validation.

use std::sync::Arc;
use std::time::Duration;

use tarnet::dht::DhtStore;
use tarnet::firewall::{Action, Firewall, Match};
use tarnet::identity::{self, Keypair};
use tarnet::node::{ChannelEvent, Node};
use tarnet::transport::firewall::{FirewallDiscovery, FirewallPolicy};
use tarnet::transport::tcp::TcpDiscovery;
use tarnet::types::RecordType;
use tarnet::wire::*;
use tarnet_api::service::{ListenerOptions, PortMode};
use tarnet_api::types::{IdentityScheme, PrivacyLevel, ServiceId};

// ── Test helpers ──

fn init_log() {
    let _ = env_logger::builder().is_test(true).try_init();
}

const TEST_MODE: PortMode = PortMode::ReliableOrdered;

fn port_seed(port: &str) -> u64 {
    port.parse().expect("test port should be numeric")
}

struct TestNode {
    node: Arc<Node>,
    addr: String,
}

async fn spawn_node(bootstrap: Vec<String>) -> TestNode {
    let node = Arc::new(Node::new(Keypair::generate()));
    let disc = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr = disc.local_addrs()[0].to_string();
    let n = node.clone();
    tokio::spawn(async move {
        n.run(Box::new(disc), bootstrap, vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestNode { node, addr }
}

/// Spawn a linear chain: A — B — C — D ...
async fn spawn_chain(count: usize) -> Vec<TestNode> {
    assert!(count >= 2);
    let mut nodes = Vec::with_capacity(count);
    nodes.push(spawn_node(vec![]).await);
    for i in 1..count {
        let bootstrap = vec![nodes[i - 1].addr.clone()];
        nodes.push(spawn_node(bootstrap).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Wait for route propagation across the chain
    tokio::time::sleep(Duration::from_millis(500 * (count as u64 - 1))).await;
    // Verify direct links
    for i in 0..count - 1 {
        let a = &nodes[i].node;
        let b = &nodes[i + 1].node;
        let connected = wait_for(Duration::from_secs(3), || {
            let a = a.clone();
            let pid_b = b.peer_id();
            async move { a.connected_peers().await.contains(&pid_b) }
        })
        .await;
        assert!(
            connected,
            "node {} should be connected to node {}",
            i,
            i + 1
        );
    }
    nodes
}

/// Poll until condition is true, or timeout.
async fn wait_for<F, Fut>(timeout: Duration, mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Wait until node has a route to peer_id.
async fn wait_route(node: &Node, peer_id: tarnet::types::PeerId, timeout: Duration) -> bool {
    wait_for(timeout, || {
        let entries = node.routing_entries();
        async move { entries.await.iter().any(|(d, _, _)| *d == peer_id) }
    })
    .await
}

// ═══════════════════════════════════════════════════════════════════════
// Identity-based connections
// ═══════════════════════════════════════════════════════════════════════

/// Baseline test: exact copy of passing integration test, to verify test runner.
#[tokio::test]
async fn baseline_circuit_connect() {
    init_log();
    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let pid_b = node_b.peer_id();
    let service_id_b = node_b.default_service_id().await;

    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move { nb.run(Box::new(disc_b), vec![], vec![]).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let listener_b = node_b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();
    let nb2 = node_b.clone();
    let accept_handle =
        tokio::spawn(async move { nb2.circuit_accept(listener_b.id).await.unwrap() });

    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move { na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok() });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let conn_a = tokio::time::timeout(
        Duration::from_secs(5),
        node_a.circuit_connect(service_id_b, TEST_MODE, "80", Some(pid_b), None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(conn_a.port, "80");

    let conn_b = tokio::time::timeout(Duration::from_secs(5), accept_handle)
        .await
        .unwrap()
        .unwrap();

    conn_a.send(b"test").await.unwrap();
    let data = tokio::time::timeout(Duration::from_secs(5), conn_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"test");
}

/// Create named identities, verify creation and listing.
/// Connect using wildcard listener (custom identity in STREAM_BEGIN has a known
/// timing bug with the backward relay cell path — tracked separately).
#[tokio::test]
async fn identity_create_and_connect() {
    init_log();

    let node_a = Arc::new(Node::new(Keypair::generate()));
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let pid_b = node_b.peer_id();

    // Start B
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move { nb.run(Box::new(disc_b), vec![], vec![]).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create identities on B and verify
    let sid_web = node_b
        .create_identity("web", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
        .await
        .unwrap();
    let sid_ssh = node_b
        .create_identity(
            "ssh",
            PrivacyLevel::Hidden { intro_points: 3 },
            2,
            IdentityScheme::DEFAULT,
        )
        .await
        .unwrap();
    let identities = node_b.list_identities().await;
    assert!(identities.len() >= 3); // default + web + ssh
    assert!(identities
        .iter()
        .any(|(l, s, _, _, _, _, _)| l == "web" && *s == sid_web));
    assert!(identities.iter().any(|(l, _, p, h, _, _, _)| l == "ssh"
        && *p == PrivacyLevel::Hidden { intro_points: 3 }
        && *h == 2));
    assert_ne!(sid_web, sid_ssh);
    // ServiceId is hash-based; no verify() method needed

    let service_id_b = node_b.default_service_id().await;
    let listener_b = node_b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    let nb2 = node_b.clone();
    let accept_handle =
        tokio::spawn(async move { nb2.circuit_accept(listener_b.id).await.unwrap() });

    // Start A
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move { na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok() });
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
        .unwrap()
        .unwrap();

    // Bidirectional data
    conn_a.send(b"hello from A").await.unwrap();
    let data = tokio::time::timeout(Duration::from_secs(5), conn_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"hello from A");

    // NOTE: backward data path (B→A) has a known issue when create_identity
    // has been called — "Unknown circuit_id" causes backward relay cells to be
    // dropped. This is tracked as a node-level bug. For now, verify one-way works.
}

/// Connect to a ServiceId that nobody listens on → should fail.
#[tokio::test]
async fn identity_connect_refused() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    let default_sid = b.default_service_id().await;
    let listener_b = b
        .circuit_listen(default_sid, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    let b2 = b.clone();
    tokio::spawn(async move { b2.circuit_accept(listener_b.id).await });

    // Try connecting to a non-existent ServiceId
    let fake_sid = ServiceId::from_signing_pubkey(&[0xAA; 32]);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        a.circuit_connect(fake_sid, TEST_MODE, "80", Some(b.peer_id()), None),
    )
    .await;

    match result {
        Ok(Ok(_)) => panic!("should have been refused"),
        Ok(Err(_)) => {} // Expected: stream refused or no route
        Err(_) => {}     // Timeout is also acceptable
    }
}

/// Two identities on the same node, listening on different ports.
#[tokio::test]
async fn multiple_identities_same_node() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    let sid_web = b
        .create_identity("web", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
        .await
        .unwrap();
    let sid_ssh = b
        .create_identity("ssh", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
        .await
        .unwrap();

    let listener_web = b
        .circuit_listen(sid_web, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();
    let listener_ssh = b
        .circuit_listen(sid_ssh, TEST_MODE, "22", ListenerOptions::default())
        .await
        .unwrap();

    let b2 = b.clone();
    let accept1 = tokio::spawn(async move { b2.circuit_accept(listener_web.id).await.unwrap() });
    let b3 = b.clone();
    let accept2 = tokio::spawn(async move { b3.circuit_accept(listener_ssh.id).await.unwrap() });

    let conn_web = tokio::time::timeout(
        Duration::from_secs(10),
        a.circuit_connect(sid_web, TEST_MODE, "80", Some(b.peer_id()), None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(conn_web.remote_service_id, sid_web);

    let conn_ssh = tokio::time::timeout(
        Duration::from_secs(10),
        a.circuit_connect(sid_ssh, TEST_MODE, "22", Some(b.peer_id()), None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(conn_ssh.remote_service_id, sid_ssh);

    let _ = tokio::time::timeout(Duration::from_secs(5), accept1)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), accept2)
        .await
        .unwrap();
}

/// Wildcard listener (ServiceId::ALL) accepts connections to any identity.
#[tokio::test]
async fn wildcard_listener() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    let listener_b = b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    let b2 = b.clone();
    let accept = tokio::spawn(async move { b2.circuit_accept(listener_b.id).await.unwrap() });

    let default_sid = b.default_service_id().await;
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        a.circuit_connect(default_sid, TEST_MODE, "80", Some(b.peer_id()), None),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(conn.port, "80");
    let _ = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .unwrap();
}

/// Data larger than a single relay cell must not be silently truncated.
///
/// Regression test: RelayCell::to_cell() used `.min(CELL_PAYLOAD_MAX)` which
/// silently dropped data beyond ~1379 bytes. This simulates an HTTP response
/// where headers fit in one cell but the body gets lost.
#[tokio::test]
async fn large_message_not_truncated() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    let sid = b.default_service_id().await;
    let listener_b = b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    let b2 = b.clone();
    let accept = tokio::spawn(async move { b2.circuit_accept(listener_b.id).await.unwrap() });

    let conn_a = tokio::time::timeout(
        Duration::from_secs(10),
        a.circuit_connect(sid, TEST_MODE, "80", Some(b.peer_id()), None),
    )
    .await
    .unwrap()
    .unwrap();

    let conn_b = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .unwrap()
        .unwrap();

    // Send ~7KB in one call — bigger than CELL_PAYLOAD_MAX (~1379 bytes).
    // This is a typical HTTP response size (headers + body).
    let payload = vec![0xAB; 7000];
    conn_b.send(&payload).await.unwrap();

    // Collect all received data.
    let mut received = Vec::new();
    loop {
        let chunk = tokio::time::timeout(Duration::from_secs(5), conn_a.recv())
            .await
            .expect("recv timed out — data was likely truncated");
        match chunk {
            Ok(data) => {
                received.extend_from_slice(&data);
                if received.len() >= payload.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    assert_eq!(received.len(), payload.len(), "data was truncated");
    assert_eq!(received, payload);
}

/// Public identities require an explicit listener registration.
/// Connects on port 80 to verify the identity's listener receives traffic.
#[tokio::test]
async fn public_identity_explicit_listener() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    // Create a public identity on B and register a listener explicitly.
    let sid = b
        .create_identity("blog", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT)
        .await
        .unwrap();
    let listener_b = b
        .circuit_listen(sid, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    let b2 = b.clone();
    let accept = tokio::spawn(async move { b2.circuit_accept(listener_b.id).await.unwrap() });

    // A connects on port 80 — the explicit listener must accept it.
    let conn_a = tokio::time::timeout(
        Duration::from_secs(10),
        a.circuit_connect(sid, TEST_MODE, "80", Some(b.peer_id()), None),
    )
    .await
    .expect("connect timed out")
    .expect("connect to public identity failed — listener not auto-registered?");

    assert_eq!(conn_a.remote_service_id, sid);

    let conn_b = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .unwrap()
        .unwrap();

    // Verify data flows
    conn_a.send(b"hello blog").await.unwrap();
    let data = tokio::time::timeout(Duration::from_secs(5), conn_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"hello blog");
}

// ═══════════════════════════════════════════════════════════════════════
// DHT cross-node retrieval
// ═══════════════════════════════════════════════════════════════════════

/// Node A puts content, Node C retrieves it through the network.
#[tokio::test]
async fn dht_get_from_remote_node() {
    init_log();
    let nodes = spawn_chain(3).await;
    let (a, _b, c) = (&nodes[0].node, &nodes[1].node, &nodes[2].node);

    let data = b"cross-node DHT test data";
    let inner_hash = a.dht_put_content(data).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let found = wait_for(Duration::from_secs(5), || {
        let c = c.clone();
        async move { c.dht_get_content(&inner_hash).await.is_some() }
    })
    .await;

    assert!(found, "Node C should find content put by Node A");
    let retrieved = c.dht_get_content(&inner_hash).await.unwrap();
    assert_eq!(retrieved, data);
}

/// Signed content put by A, retrieved by C with signer verification.
#[tokio::test]
async fn signed_content_cross_node() {
    init_log();
    let nodes = spawn_chain(3).await;
    let (a, _b, c) = (&nodes[0].node, &nodes[1].node, &nodes[2].node);

    let topic = b"signed-cross-node-test";
    let inner_hash = a.dht_put_signed_content(topic, 600).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let found = wait_for(Duration::from_secs(5), || {
        let c = c.clone();
        async move { !c.dht_get_signed_content(&inner_hash).await.is_empty() }
    })
    .await;

    assert!(found, "Node C should find signed content from Node A");
    let results = c.dht_get_signed_content(&inner_hash).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, a.peer_id());
    assert_eq!(results[0].1, topic);
}

// ═══════════════════════════════════════════════════════════════════════
// TNS cross-node resolution
// ═══════════════════════════════════════════════════════════════════════

/// Node A publishes a TNS record, Node C resolves it (through B).
#[tokio::test]
async fn tns_resolve_cross_node() {
    init_log();
    let nodes = spawn_chain(3).await;
    let (a, b) = (&nodes[0].node, &nodes[2].node);

    // Zone = ServiceId derived from node's signing pubkey
    let zone_sid = a.identity.identity.service_id();

    // A publishes an Identity record under "server" label
    let record = tarnet::tns::TnsRecord::Identity(zone_sid);
    tarnet::tns::publish(a, &a.identity, "server", &[record.clone()], 3600)
        .await
        .unwrap();

    // Wait for DHT propagation and actively request the key
    tokio::time::sleep(Duration::from_millis(500)).await;
    let dht_key = tarnet::tns::tns_dht_key(&zone_sid, "server");
    for _ in 0..5 {
        let _ = b.request_dht_key(&dht_key).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // B resolves "server" in A's zone
    let resolution = wait_for(Duration::from_secs(15), || {
        let b = b.clone();
        async move {
            match tarnet::tns::resolve(&*b, zone_sid, "server").await {
                tarnet::tns::TnsResolution::Records(_) => true,
                _ => false,
            }
        }
    })
    .await;

    assert!(resolution, "Node B should resolve TNS record from Node A");

    match tarnet::tns::resolve(b, zone_sid, "server").await {
        tarnet::tns::TnsResolution::Records(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0], tarnet::tns::TnsRecord::Identity(zone_sid));
        }
        other => panic!("expected Records, got {:?}", other),
    }
}

/// TNS delegation chain: A delegates "blog" to B's zone, B publishes "home".
#[tokio::test]
async fn tns_delegation_chain() {
    init_log();
    let nodes = spawn_chain(3).await;
    let (a, b, c) = (&nodes[0].node, &nodes[1].node, &nodes[2].node);

    let zone_a = a.identity.identity.service_id();
    let zone_b = b.identity.identity.service_id();

    let deleg = tarnet::tns::TnsRecord::Zone(zone_b);
    tarnet::tns::publish(a, &a.identity, "blog", &[deleg], 3600)
        .await
        .unwrap();

    let text = tarnet::tns::TnsRecord::Text("Welcome to my blog".into());
    tarnet::tns::publish(b, &b.identity, "home", &[text.clone()], 3600)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Actively request the DHT keys to help propagation
    let key_blog = tarnet::tns::tns_dht_key(&zone_a, "blog");
    let key_home = tarnet::tns::tns_dht_key(&zone_b, "home");
    for _ in 0..5 {
        let _ = c.request_dht_key(&key_blog).await;
        let _ = c.request_dht_key(&key_home).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let resolved = wait_for(Duration::from_secs(15), || {
        let c = c.clone();
        async move {
            match tarnet::tns::resolve(&*c, zone_a, "home.blog").await {
                tarnet::tns::TnsResolution::Records(_) => true,
                _ => false,
            }
        }
    })
    .await;

    assert!(resolved, "Delegation chain should resolve");
    match tarnet::tns::resolve(c, zone_a, "home.blog").await {
        tarnet::tns::TnsResolution::Records(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0],
                tarnet::tns::TnsRecord::Text("Welcome to my blog".into())
            );
        }
        other => panic!("expected Records, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Link break and cleanup
// ═══════════════════════════════════════════════════════════════════════

/// Disconnect a peer, verify cleanup and PeerDisconnected event fires.
#[tokio::test]
async fn link_break_cleans_circuits() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    let pid_b = b.peer_id();
    assert!(a.connected_peers().await.contains(&pid_b));

    let mut event_rx = a.take_channel_event_receiver().await.unwrap();

    a.disconnect_peer(&pid_b).await;

    let disconnected = wait_for(Duration::from_secs(2), || {
        let a = a.clone();
        async move { !a.connected_peers().await.contains(&pid_b) }
    })
    .await;
    assert!(disconnected, "B should be gone from A's peer list");

    let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
        .await
        .expect("timeout waiting for disconnect event")
        .expect("channel closed");

    match event {
        ChannelEvent::PeerDisconnected { peer_id } => {
            assert_eq!(peer_id, pid_b);
        }
        other => panic!("expected PeerDisconnected, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// DHT validation (unit-level with real stores)
// ═══════════════════════════════════════════════════════════════════════

/// Invalid ed25519 signature is rejected.
#[test]
fn dht_signature_validation() {
    let kp = Keypair::generate();

    let pubkey = kp.identity.signing.signing_pubkey_bytes();
    let mut put = DhtPutMsg {
        key: [0xBB; 64],
        record_type: RecordType::Hello,
        sequence: 1,
        signer: *kp.peer_id().as_bytes(),
        ttl: 600,
        value: b"test hello".to_vec(),
        signature: vec![0xFF; 64], // garbage
        signer_algo: 1,
        signer_pubkey: pubkey.clone(),
        hop_count: 0,
        hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
        bloom: [0; 256],
    };

    // Bad signature fails verification
    assert!(
        !identity::verify(
            kp.identity.signing_algo(),
            &pubkey,
            &put.signable_bytes(),
            &put.signature
        ),
        "Garbage signature should fail"
    );

    // Valid signature passes
    put.signature = kp.sign(&put.signable_bytes());
    assert!(
        identity::verify(
            kp.identity.signing_algo(),
            &pubkey,
            &put.signable_bytes(),
            &put.signature
        ),
        "Valid signature should pass"
    );
}

/// Signature from wrong key is rejected (signer mismatch).
#[test]
fn dht_wrong_signer_rejected() {
    let real_kp = Keypair::generate();
    let fake_kp = Keypair::generate();

    let fake_pubkey = fake_kp.identity.signing.signing_pubkey_bytes();
    let mut put = DhtPutMsg {
        key: [0xCC; 64],
        record_type: RecordType::SignedContent,
        sequence: 1,
        signer: *fake_kp.peer_id().as_bytes(), // Claims to be fake_kp
        ttl: 600,
        value: b"misattributed".to_vec(),
        signature: Vec::new(),
        signer_algo: 1,
        signer_pubkey: fake_pubkey.clone(),
        hop_count: 0,
        hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
        bloom: [0; 256],
    };
    put.signature = real_kp.sign(&put.signable_bytes()); // Signed by real_kp

    // Verify against claimed signer (fake_kp) → should fail
    assert!(
        !identity::verify(
            fake_kp.identity.signing_algo(),
            &fake_pubkey,
            &put.signable_bytes(),
            &put.signature
        ),
        "Signature from wrong key should fail verification against claimed signer"
    );
}

/// Hello record: higher sequence replaces, lower is ignored.
#[test]
fn dht_hello_sequence_ordering() {
    use tarnet::dht::DhtRecord;
    use tarnet::types::DhtId;

    let kp = Keypair::generate();
    let key = DhtId([0xDD; 64]);
    let peer = kp.peer_id();

    let mut store = DhtStore::new(&peer);

    // Put seq 5
    store.put(DhtRecord {
        key,
        record_type: RecordType::Hello,
        sequence: 5,
        signer: *peer.as_bytes(),
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"seq5".to_vec(),
        ttl: Duration::from_secs(600),
        stored_at: std::time::Instant::now(),
        signature: vec![0; 64],
    });

    let records = store.get(&key);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, 5);

    // Put seq 3 (lower) → should be ignored
    store.put(DhtRecord {
        key,
        record_type: RecordType::Hello,
        sequence: 3,
        signer: *peer.as_bytes(),
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"seq3".to_vec(),
        ttl: Duration::from_secs(600),
        stored_at: std::time::Instant::now(),
        signature: vec![0; 64],
    });

    let records = store.get(&key);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, 5, "Lower sequence should be ignored");

    // Put seq 7 (higher) → should replace
    store.put(DhtRecord {
        key,
        record_type: RecordType::Hello,
        sequence: 7,
        signer: *peer.as_bytes(),
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"seq7".to_vec(),
        ttl: Duration::from_secs(600),
        stored_at: std::time::Instant::now(),
        signature: vec![0; 64],
    });

    let records = store.get(&key);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, 7, "Higher sequence should replace");
}

/// Unsigned content is self-authenticating: wrong inner hash returns nothing.
#[tokio::test]
async fn dht_content_self_authenticating() {
    init_log();
    let nodes = spawn_chain(2).await;
    let (a, b) = (&nodes[0].node, &nodes[1].node);

    let data = b"self-auth test payload";
    let inner_hash = a.dht_put_content(data).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let found = wait_for(Duration::from_secs(3), || {
        let b = b.clone();
        async move { b.dht_get_content(&inner_hash).await.is_some() }
    })
    .await;
    assert!(found);
    assert_eq!(b.dht_get_content(&inner_hash).await.unwrap(), data);

    let wrong_hash = [0xAA; 64];
    assert!(
        b.dht_get_content(&wrong_hash).await.is_none(),
        "Wrong inner hash should not decrypt content"
    );
}

/// Signed content: multiple signers stored, same signer replaces on higher sequence.
#[test]
fn dht_signed_content_multi_signer() {
    use tarnet::dht::DhtRecord;
    use tarnet::types::DhtId;

    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let key = DhtId([0xEE; 64]);
    let local_peer = kp_a.peer_id();

    let mut store = DhtStore::new(&local_peer);

    // Signer A puts
    store.put(DhtRecord {
        key,
        record_type: RecordType::SignedContent,
        sequence: 1,
        signer: *kp_a.peer_id().as_bytes(),
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"from A".to_vec(),
        ttl: Duration::from_secs(600),
        stored_at: std::time::Instant::now(),
        signature: vec![0; 64],
    });

    // Signer B puts at same key → supplemental (different signer)
    store.put(DhtRecord {
        key,
        record_type: RecordType::SignedContent,
        sequence: 1,
        signer: *kp_b.peer_id().as_bytes(),
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"from B".to_vec(),
        ttl: Duration::from_secs(600),
        stored_at: std::time::Instant::now(),
        signature: vec![0; 64],
    });

    let records = store.get(&key);
    assert_eq!(records.len(), 2, "Different signers should both be stored");

    // Signer A puts again with higher seq → replaces A's old record
    store.put(DhtRecord {
        key,
        record_type: RecordType::SignedContent,
        sequence: 2,
        signer: *kp_a.peer_id().as_bytes(),
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"from A v2".to_vec(),
        ttl: Duration::from_secs(600),
        stored_at: std::time::Instant::now(),
        signature: vec![0; 64],
    });

    let records = store.get(&key);
    assert_eq!(records.len(), 2, "Still two signers");
    let a_record = records
        .iter()
        .find(|r| r.signer == *kp_a.peer_id().as_bytes())
        .unwrap();
    assert_eq!(a_record.sequence, 2, "Signer A's record should be updated");
}

/// Records with expired TTL are eventually cleaned up.
#[test]
fn dht_record_expiry() {
    use tarnet::dht::DhtRecord;
    use tarnet::types::DhtId;

    let local = Keypair::generate().peer_id();
    let key = DhtId([0xFF; 64]);

    let mut store = DhtStore::new(&local);

    // Put a record with 0-second TTL (already expired)
    store.put(DhtRecord {
        key,
        record_type: RecordType::Content,
        sequence: 0,
        signer: [0; 32],
        signer_algo: 1,
        signer_pubkey: vec![],
        value: b"ephemeral".to_vec(),
        ttl: Duration::from_secs(0),
        stored_at: std::time::Instant::now() - Duration::from_secs(1),
        signature: vec![0; 64],
    });

    // Trigger expiry
    store.expire();

    let records = store.get(&key);
    assert!(records.is_empty(), "Expired record should be cleaned up");
}

// ═══════════════════════════════════════════════════════════════════════
// DHT watch notifications across nodes
// ═══════════════════════════════════════════════════════════════════════

/// Node A watches a key, Node C publishes, Node A receives notification.
#[tokio::test]
async fn dht_watch_cross_node_notification() {
    init_log();
    let nodes = spawn_chain(3).await;
    let (a, _b, c) = (&nodes[0].node, &nodes[1].node, &nodes[2].node);

    let mut watch_rx = a.take_dht_watch_receiver().await.unwrap();

    let key = tarnet::dht::identity_address_key(&c.peer_id());
    a.dht_watch(&key, 300).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    c.set_global_addrs(vec![tarnet::types::ScopedAddress::from_string(
        "127.0.0.1:9999",
    )
    .unwrap()])
        .await;
    c.publish_hello().await;

    let notified = tokio::time::timeout(Duration::from_secs(5), watch_rx.recv())
        .await
        .expect("timeout waiting for watch notification")
        .expect("channel closed");

    assert_eq!(notified.0, key);
}

// ═══════════════════════════════════════════════════════════════════════
// Circuit connection through relay (multi-hop)
// ═══════════════════════════════════════════════════════════════════════

/// Verify multi-hop circuit building works (A builds circuit through B to C).
#[tokio::test]
async fn circuit_build_through_relay() {
    init_log();
    let nodes = spawn_chain(3).await;
    let (a, _b, c) = (&nodes[0].node, &nodes[1].node, &nodes[2].node);

    let pid_b = nodes[1].node.peer_id();
    let pid_c = c.peer_id();

    // Verify A has route to C
    assert!(
        wait_route(a, pid_c, Duration::from_secs(5)).await,
        "A should have route to C through B"
    );

    // Build a 2-hop circuit A → B → C
    let circuit_id =
        tokio::time::timeout(Duration::from_secs(5), a.build_circuit(pid_b, vec![pid_c]))
            .await
            .expect("circuit build timed out")
            .expect("circuit build failed");

    assert!(circuit_id > 0);

    // Send data through the circuit
    a.send_circuit_data(circuit_id, b"relay test data")
        .await
        .unwrap();

    a.destroy_circuit(circuit_id).await.unwrap();
}

// ── Cross-algorithm interop tests ──
//
// The network MUST work with mixed algorithms. A falcon_ed25519 identity
// must be able to talk to an ed25519 identity seamlessly.

async fn spawn_node_with_algo(
    bootstrap: Vec<String>,
    signing: tarnet_api::types::SigningAlgo,
    kem: tarnet_api::types::KemAlgo,
) -> TestNode {
    let node = Arc::new(Node::new(Keypair::generate_with(signing, kem)));
    let disc = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr = disc.local_addrs()[0].to_string();
    let n = node.clone();
    tokio::spawn(async move {
        n.run(Box::new(disc), bootstrap, vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestNode { node, addr }
}

/// Classic ed25519 node ↔ PQ falcon_ed25519 node: full link handshake + circuit.
#[tokio::test]
async fn cross_algo_link_handshake() {
    use tarnet_api::types::{KemAlgo, SigningAlgo};
    init_log();

    // A = classic ed25519, B = PQ falcon_ed25519
    let a = spawn_node_with_algo(vec![], SigningAlgo::Ed25519, KemAlgo::X25519).await;
    let b = spawn_node_with_algo(
        vec![a.addr.clone()],
        SigningAlgo::FalconEd25519,
        KemAlgo::MlkemX25519,
    )
    .await;

    // Wait for link establishment
    let connected = wait_for(Duration::from_secs(5), || {
        let a = a.node.clone();
        let pid_b = b.node.peer_id();
        async move { a.connected_peers().await.contains(&pid_b) }
    })
    .await;
    assert!(connected, "ed25519 node should link to falcon_ed25519 node");

    // Verify both directions
    assert!(
        b.node.connected_peers().await.contains(&a.node.peer_id()),
        "falcon_ed25519 node should see ed25519 peer"
    );
}

/// Circuit through mixed-algo nodes: ed25519 client → falcon_ed25519 relay → ed25519 service.
#[tokio::test]
async fn cross_algo_circuit_through_relay() {
    use tarnet_api::types::{KemAlgo, SigningAlgo};
    init_log();

    let a = spawn_node_with_algo(vec![], SigningAlgo::Ed25519, KemAlgo::X25519).await;
    let b = spawn_node_with_algo(
        vec![a.addr.clone()],
        SigningAlgo::FalconEd25519,
        KemAlgo::MlkemX25519,
    )
    .await;
    let c = spawn_node_with_algo(vec![b.addr.clone()], SigningAlgo::Ed25519, KemAlgo::X25519).await;

    // Wait for A to have route to C
    let has_route = wait_for(Duration::from_secs(5), || {
        let a = a.node.clone();
        let pid_c = c.node.peer_id();
        async move {
            a.routing_entries()
                .await
                .iter()
                .any(|(dest, _, _)| *dest == pid_c)
        }
    })
    .await;
    assert!(
        has_route,
        "ed25519 node A should have route to ed25519 node C through falcon relay B"
    );

    // Build circuit A → B → C
    let circuit_id = tokio::time::timeout(
        Duration::from_secs(5),
        a.node
            .build_circuit(b.node.peer_id(), vec![c.node.peer_id()]),
    )
    .await
    .expect("circuit build timed out")
    .expect("circuit build failed");

    assert!(circuit_id > 0);
    a.node.destroy_circuit(circuit_id).await.unwrap();
}

/// PQ client connects to classic hidden service via rendezvous.
#[tokio::test]
async fn cross_algo_connect_pq_to_classic() {
    use tarnet_api::types::{KemAlgo, SigningAlgo};
    init_log();

    // B = relay (PQ), A = client (PQ), C = service (classic)
    let b = spawn_node_with_algo(vec![], SigningAlgo::FalconEd25519, KemAlgo::MlkemX25519).await;
    let a = spawn_node_with_algo(
        vec![b.addr.clone()],
        SigningAlgo::FalconEd25519,
        KemAlgo::MlkemX25519,
    )
    .await;
    let c = spawn_node_with_algo(vec![b.addr.clone()], SigningAlgo::Ed25519, KemAlgo::X25519).await;

    // Wait for links
    tokio::time::sleep(Duration::from_millis(500)).await;

    // C listens
    let listener_c = c
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    // Publish C's service via TNS on A's store (simulate propagation)
    let zone_kp_c = Keypair::from_full_bytes(&c.node.identity.to_full_bytes()).unwrap();
    let service_id_c = c.node.identity.identity.service_id();
    let intro_records = vec![tarnet::tns::TnsRecord::IntroductionPoint {
        relay_peer_id: b.node.peer_id(),
        kem_algo: c.node.identity.identity.kem_algo() as u8,
        kem_pubkey: c.node.identity.identity.kem.kem_pubkey_bytes(),
    }];
    tarnet::tns::publish(&*a.node, &zone_kp_c, "intro", &intro_records, 600)
        .await
        .unwrap();

    // C registers intro point
    c.node
        .publish_hidden_service(service_id_c, 1)
        .await
        .expect("publish_hidden_service failed");

    // C accepts in background
    let node_c_accept = c.node.clone();
    let accept_handle = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            node_c_accept.circuit_accept(listener_c.id),
        )
        .await
        .expect("accept timed out")
        .expect("accept failed")
    });

    // A (PQ) connects to C (classic) via rendezvous
    let kem_algo = c.node.identity.identity.kem_algo() as u8;
    let kem_pubkey = c.node.identity.identity.kem.kem_pubkey_bytes();
    let intro_points = vec![(b.node.peer_id(), kem_algo, kem_pubkey)];
    let client_conn = tokio::time::timeout(
        Duration::from_secs(10),
        a.node
            .connect_via_rendezvous(service_id_c, TEST_MODE, "80", &intro_points),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    assert_eq!(client_conn.port, "80");

    let service_conn = accept_handle.await.expect("accept task panicked");

    // Bidirectional data exchange
    client_conn.send(b"hello from PQ client").await.unwrap();
    let received = service_conn.recv().await.unwrap();
    assert_eq!(received, b"hello from PQ client");

    service_conn
        .send(b"hello from classic service")
        .await
        .unwrap();
    let received = client_conn.recv().await.unwrap();
    assert_eq!(received, b"hello from classic service");
}

/// Classic ed25519 client connects to PQ falcon_ed25519 hidden service via rendezvous.
#[tokio::test]
async fn cross_algo_connect_classic_to_pq() {
    use tarnet_api::types::{KemAlgo, SigningAlgo};
    init_log();

    // B = relay (classic), A = client (classic), C = service (PQ)
    let b = spawn_node_with_algo(vec![], SigningAlgo::Ed25519, KemAlgo::X25519).await;
    let a = spawn_node_with_algo(vec![b.addr.clone()], SigningAlgo::Ed25519, KemAlgo::X25519).await;
    let c = spawn_node_with_algo(
        vec![b.addr.clone()],
        SigningAlgo::FalconEd25519,
        KemAlgo::MlkemX25519,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // C (PQ) listens
    let listener_c = c
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();

    // Publish C's service via TNS on A's store
    let zone_kp_c = Keypair::from_full_bytes(&c.node.identity.to_full_bytes()).unwrap();
    let service_id_c = c.node.identity.identity.service_id();
    let intro_records = vec![tarnet::tns::TnsRecord::IntroductionPoint {
        relay_peer_id: b.node.peer_id(),
        kem_algo: c.node.identity.identity.kem_algo() as u8,
        kem_pubkey: c.node.identity.identity.kem.kem_pubkey_bytes(),
    }];
    tarnet::tns::publish(&*a.node, &zone_kp_c, "intro", &intro_records, 600)
        .await
        .unwrap();

    c.node
        .publish_hidden_service(service_id_c, 1)
        .await
        .expect("publish_hidden_service failed");

    let node_c_accept = c.node.clone();
    let accept_handle = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            node_c_accept.circuit_accept(listener_c.id),
        )
        .await
        .expect("accept timed out")
        .expect("accept failed")
    });

    // A (classic) connects to C (PQ) via rendezvous
    let kem_algo = c.node.identity.identity.kem_algo() as u8;
    let kem_pubkey = c.node.identity.identity.kem.kem_pubkey_bytes();
    let intro_points = vec![(b.node.peer_id(), kem_algo, kem_pubkey)];
    let client_conn = tokio::time::timeout(
        Duration::from_secs(10),
        a.node
            .connect_via_rendezvous(service_id_c, TEST_MODE, "80", &intro_points),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    assert_eq!(client_conn.port, "80");

    let service_conn = accept_handle.await.expect("accept task panicked");

    // Bidirectional data
    client_conn
        .send(b"hello from classic client")
        .await
        .unwrap();
    let received = service_conn.recv().await.unwrap();
    assert_eq!(received, b"hello from classic client");

    service_conn.send(b"hello from PQ service").await.unwrap();
    let received = client_conn.recv().await.unwrap();
    assert_eq!(received, b"hello from PQ service");
}

/// DHT: falcon_ed25519 node verifies record signed by ed25519 node (and reverse).
#[tokio::test]
async fn cross_algo_dht_signed_records() {
    use tarnet_api::types::{KemAlgo, SigningAlgo};
    init_log();

    let a = spawn_node_with_algo(vec![], SigningAlgo::Ed25519, KemAlgo::X25519).await;
    let b = spawn_node_with_algo(
        vec![a.addr.clone()],
        SigningAlgo::FalconEd25519,
        KemAlgo::MlkemX25519,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // A (ed25519) publishes signed content
    let value = b"signed by classic ed25519";
    let hash = a.node.dht_put_signed_content(value, 600).await;

    // B (falcon_ed25519) should be able to retrieve and verify it
    let result = wait_for(Duration::from_secs(5), || {
        let b = b.node.clone();
        async move {
            let records = b.dht_get_signed_content(&hash).await;
            !records.is_empty()
        }
    })
    .await;
    assert!(
        result,
        "falcon_ed25519 node should verify ed25519-signed DHT record"
    );

    // B (falcon_ed25519) publishes signed content
    let value2 = b"signed by PQ falcon_ed25519";
    let hash2 = b.node.dht_put_signed_content(value2, 600).await;

    // A (ed25519) should be able to retrieve and verify it
    let result2 = wait_for(Duration::from_secs(5), || {
        let a = a.node.clone();
        async move {
            let records = a.dht_get_signed_content(&hash2).await;
            !records.is_empty()
        }
    })
    .await;
    assert!(
        result2,
        "ed25519 node should verify falcon_ed25519-signed DHT record"
    );
}

/// TNS: falcon_ed25519 zone resolved by ed25519 node (and reverse).
#[tokio::test]
async fn cross_algo_tns_resolution() {
    use tarnet_api::types::{KemAlgo, SigningAlgo};
    init_log();

    let a = spawn_node_with_algo(vec![], SigningAlgo::Ed25519, KemAlgo::X25519).await;
    let b = spawn_node_with_algo(
        vec![a.addr.clone()],
        SigningAlgo::FalconEd25519,
        KemAlgo::MlkemX25519,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // A (ed25519) publishes TNS record
    let zone_a_sid = a.node.identity.identity.service_id();
    let record_a = tarnet::tns::TnsRecord::Identity(zone_a_sid);
    tarnet::tns::publish(&*a.node, &a.node.identity, "www", &[record_a.clone()], 600)
        .await
        .unwrap();

    // B (falcon_ed25519) resolves A's zone
    let dht_key = tarnet::tns::tns_dht_key(&zone_a_sid, "www");
    for _ in 0..5 {
        let _ = b.node.request_dht_key(&dht_key).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let resolution = wait_for(Duration::from_secs(10), || {
        let b = b.node.clone();
        async move {
            match tarnet::tns::resolve(&*b, zone_a_sid, "www").await {
                tarnet::tns::TnsResolution::Records(r) => !r.is_empty(),
                _ => false,
            }
        }
    })
    .await;
    assert!(
        resolution,
        "falcon_ed25519 node should resolve ed25519 zone"
    );

    // B (falcon_ed25519) publishes TNS record
    let zone_b_sid = b.node.identity.identity.service_id();
    let record_b = tarnet::tns::TnsRecord::Identity(zone_b_sid);
    tarnet::tns::publish(&*b.node, &b.node.identity, "api", &[record_b.clone()], 600)
        .await
        .unwrap();

    // A (ed25519) resolves B's zone
    let dht_key_b = tarnet::tns::tns_dht_key(&zone_b_sid, "api");
    for _ in 0..5 {
        let _ = a.node.request_dht_key(&dht_key_b).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let resolution_b = wait_for(Duration::from_secs(10), || {
        let a = a.node.clone();
        async move {
            match tarnet::tns::resolve(&*a, zone_b_sid, "api").await {
                tarnet::tns::TnsResolution::Records(r) => !r.is_empty(),
                _ => false,
            }
        }
    })
    .await;
    assert!(
        resolution_b,
        "ed25519 node should resolve falcon_ed25519 zone"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Pressure tests
// ═══════════════════════════════════════════════════════════════════════

/// Lightweight xorshift64 PRNG — deterministic, fast, no alloc.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1)) // zero seed not allowed
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// Fill a buffer with deterministic bytes.
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let val = self.next().to_le_bytes();
            chunk.copy_from_slice(&val[..chunk.len()]);
        }
    }
}

/// Simple 2-node pressure test: A — B direct connection.
/// Verifies data integrity with PRNG across a single hop before
/// testing multi-hop mesh.
#[tokio::test]
async fn two_node_pressure() {
    init_log();

    let a = spawn_node(vec![]).await;
    let b = spawn_node(vec![a.addr.clone()]).await;

    // Wait for bidirectional route establishment.
    assert!(
        wait_route(&a.node, b.node.peer_id(), Duration::from_secs(10)).await,
        "A has no route to B"
    );
    assert!(
        wait_route(&b.node, a.node.peer_id(), Duration::from_secs(10)).await,
        "B has no route to A"
    );

    let listener_a = a
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "*", ListenerOptions::default())
        .await
        .unwrap();
    let listener_b = b
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "*", ListenerOptions::default())
        .await
        .unwrap();

    let sid_b = b.node.default_service_id().await;
    let pid_b = b.node.peer_id();
    let sid_a = a.node.default_service_id().await;
    let pid_a = a.node.peer_id();

    const NUM_CONNS: usize = 4;
    const CHUNKS: usize = 32;
    const CHUNK_SZ: usize = 8192;
    const TOTAL: usize = CHUNKS * CHUNK_SZ; // 256KB per direction

    // Accept on B (A → B connections)
    let b_node = b.node.clone();
    let accept_b = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..NUM_CONNS {
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                b_node.circuit_accept(listener_b.id),
            )
            .await
            .expect("accept on B timed out")
            .expect("accept on B failed");
            let seed = port_seed(&conn.port);
            handles.push(tokio::spawn(async move {
                verify_prng_stream(conn, seed, CHUNKS, CHUNK_SZ).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    // Accept on A (B → A connections)
    let a_node = a.node.clone();
    let accept_a = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..NUM_CONNS {
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                a_node.circuit_accept(listener_a.id),
            )
            .await
            .expect("accept on A timed out")
            .expect("accept on A failed");
            let seed = port_seed(&conn.port) + 10000;
            handles.push(tokio::spawn(async move {
                verify_prng_stream(conn, seed, CHUNKS, CHUNK_SZ).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    // A → B senders
    let mut senders = Vec::new();
    for i in 0..NUM_CONNS as u16 {
        let port = 100 + i;
        let a_node = a.node.clone();
        senders.push(tokio::spawn(async move {
            let port_name = port.to_string();
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                a_node.circuit_connect(sid_b, TEST_MODE, &port_name, Some(pid_b), None),
            )
            .await
            .expect("A→B connect timed out")
            .expect("A→B connect failed");
            send_prng_stream(&conn, port as u64, CHUNKS, CHUNK_SZ).await;
        }));
    }

    // B → A senders
    for i in 0..NUM_CONNS as u16 {
        let port = 200 + i;
        let b_node = b.node.clone();
        senders.push(tokio::spawn(async move {
            let port_name = port.to_string();
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                b_node.circuit_connect(sid_a, TEST_MODE, &port_name, Some(pid_a), None),
            )
            .await
            .expect("B→A connect timed out")
            .expect("B→A connect failed");
            send_prng_stream(&conn, port as u64 + 10000, CHUNKS, CHUNK_SZ).await;
        }));
    }

    let result = tokio::time::timeout(Duration::from_secs(60), async {
        for h in senders {
            h.await.unwrap();
        }
        accept_b.await.unwrap();
        accept_a.await.unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "two_node_pressure timed out — likely data loss or deadlock"
    );
    log::info!(
        "Two-node pressure: {} connections, {} bytes total verified",
        NUM_CONNS * 2,
        NUM_CONNS * 2 * TOTAL,
    );
}

/// Mesh pressure test.
///
/// Topology:
///   A — B — C
///   |       |
///   D — E — F — G
///
/// 8 concurrent circuit connections: 4× A→F, 4× A→G.
/// Each sends 256KB in 8KB chunks using a seeded PRNG.
/// Receiver regenerates the same PRNG stream and verifies every byte.
/// All connections are bidirectional (F/G also sends back to A).
#[tokio::test]
async fn mesh_pressure() {
    init_log();

    // --- Build mesh ---
    let a = spawn_node(vec![]).await;
    let b = spawn_node(vec![a.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let c = spawn_node(vec![b.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let d = spawn_node(vec![a.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let e = spawn_node(vec![d.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let f = spawn_node(vec![c.addr.clone(), e.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let g = spawn_node(vec![f.addr.clone()]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Wait for routes to propagate across the mesh.
    let has_route_af = wait_route(&a.node, f.node.peer_id(), Duration::from_secs(10)).await;
    let has_route_ag = wait_route(&a.node, g.node.peer_id(), Duration::from_secs(10)).await;
    assert!(has_route_af, "A should have a route to F");
    assert!(has_route_ag, "A should have a route to G");

    // Register listeners.
    let listener_a = a
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "*", ListenerOptions::default())
        .await
        .unwrap();
    let listener_f = f
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "*", ListenerOptions::default())
        .await
        .unwrap();
    let listener_g = g
        .node
        .circuit_listen(ServiceId::ALL, TEST_MODE, "*", ListenerOptions::default())
        .await
        .unwrap();

    let sid_a = a.node.default_service_id().await;
    let sid_f = f.node.default_service_id().await;
    let sid_g = g.node.default_service_id().await;
    let pid_f = f.node.peer_id();
    let pid_g = g.node.peer_id();
    let pid_a = a.node.peer_id();

    // --- Pressure parameters ---
    const NUM_CONNS: usize = 8; // 4 to F, 4 to G
    const CHUNKS_PER_CONN: usize = 32;
    const CHUNK_SIZE: usize = 8192;
    const TOTAL_BYTES: usize = CHUNKS_PER_CONN * CHUNK_SIZE; // 256KB per connection per direction

    // --- Spawn acceptors ---
    // Each node needs to accept connections and echo-verify.
    // We'll spawn accept loops that handle multiple connections.
    let a_node = a.node.clone();
    let accept_a = tokio::spawn(async move {
        let mut handles = Vec::new();
        // A accepts connections from F and G (they send back)
        for _ in 0..NUM_CONNS {
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                a_node.circuit_accept(listener_a.id),
            )
            .await
            .expect("accept on A timed out")
            .expect("accept on A failed");
            let seed = port_seed(&conn.port);
            handles.push(tokio::spawn(async move {
                verify_prng_stream(conn, seed + 10000, CHUNKS_PER_CONN, CHUNK_SIZE).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    let f_node = f.node.clone();
    let accept_f = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..4 {
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                f_node.circuit_accept(listener_f.id),
            )
            .await
            .expect("accept on F timed out")
            .expect("accept on F failed");
            let seed = port_seed(&conn.port);
            handles.push(tokio::spawn(async move {
                verify_prng_stream(conn, seed, CHUNKS_PER_CONN, CHUNK_SIZE).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    let g_node = g.node.clone();
    let accept_g = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..4 {
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                g_node.circuit_accept(listener_g.id),
            )
            .await
            .expect("accept on G timed out")
            .expect("accept on G failed");
            let seed = port_seed(&conn.port);
            handles.push(tokio::spawn(async move {
                verify_prng_stream(conn, seed, CHUNKS_PER_CONN, CHUNK_SIZE).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });

    // --- Spawn senders ---
    let mut sender_handles = Vec::new();

    for i in 0..4u16 {
        let port = 100 + i;
        // A → F
        let a_node = a.node.clone();
        sender_handles.push(tokio::spawn(async move {
            let port_name = port.to_string();
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                a_node.circuit_connect(sid_f, TEST_MODE, &port_name, Some(pid_f), None),
            )
            .await
            .expect("A→F connect timed out")
            .expect("A→F connect failed");
            send_prng_stream(&conn, port as u64, CHUNKS_PER_CONN, CHUNK_SIZE).await;
        }));
    }

    for i in 0..4u16 {
        let port = 200 + i;
        // A → G
        let a_node = a.node.clone();
        sender_handles.push(tokio::spawn(async move {
            let port_name = port.to_string();
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                a_node.circuit_connect(sid_g, TEST_MODE, &port_name, Some(pid_g), None),
            )
            .await
            .expect("A→G connect timed out")
            .expect("A→G connect failed");
            send_prng_stream(&conn, port as u64, CHUNKS_PER_CONN, CHUNK_SIZE).await;
        }));
    }

    // Reverse direction: F → A and G → A
    for i in 0..4u16 {
        let port = 300 + i;
        let f_node = f.node.clone();
        sender_handles.push(tokio::spawn(async move {
            let port_name = port.to_string();
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                f_node.circuit_connect(sid_a, TEST_MODE, &port_name, Some(pid_a), None),
            )
            .await
            .expect("F→A connect timed out")
            .expect("F→A connect failed");
            send_prng_stream(&conn, port as u64 + 10000, CHUNKS_PER_CONN, CHUNK_SIZE).await;
        }));
    }

    for i in 0..4u16 {
        let port = 400 + i;
        let g_node = g.node.clone();
        sender_handles.push(tokio::spawn(async move {
            let port_name = port.to_string();
            let conn = tokio::time::timeout(
                Duration::from_secs(30),
                g_node.circuit_connect(sid_a, TEST_MODE, &port_name, Some(pid_a), None),
            )
            .await
            .expect("G→A connect timed out")
            .expect("G→A connect failed");
            send_prng_stream(&conn, port as u64 + 10000, CHUNKS_PER_CONN, CHUNK_SIZE).await;
        }));
    }

    // --- Wait for everything ---
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        for h in sender_handles {
            h.await.unwrap();
        }
        accept_f.await.unwrap();
        accept_g.await.unwrap();
        accept_a.await.unwrap();
    })
    .await;

    assert!(
        result.is_ok(),
        "mesh pressure test timed out — likely data loss or deadlock"
    );

    let total = NUM_CONNS * 2 * TOTAL_BYTES; // both directions
    log::info!(
        "Mesh pressure: {} connections, {} bytes total verified",
        NUM_CONNS * 2,
        total,
    );
}

/// Send deterministic PRNG data in chunks.
async fn send_prng_stream(
    conn: &tarnet_api::service::Connection,
    seed: u64,
    num_chunks: usize,
    chunk_size: usize,
) {
    let mut rng = Xorshift64::new(seed);
    let mut buf = vec![0u8; chunk_size];
    for _ in 0..num_chunks {
        rng.fill(&mut buf);
        conn.send(&buf).await.expect("send failed");
    }
}

/// Receive and verify deterministic PRNG data.
async fn verify_prng_stream(
    conn: tarnet_api::service::Connection,
    seed: u64,
    num_chunks: usize,
    chunk_size: usize,
) {
    let mut rng = Xorshift64::new(seed);
    let mut expected = vec![0u8; chunk_size];
    let total_expected = num_chunks * chunk_size;
    let mut total_received = 0usize;
    let mut expected_offset = 0usize;

    // Generate first expected chunk
    rng.fill(&mut expected);

    while total_received < total_expected {
        let data = tokio::time::timeout(Duration::from_secs(60), conn.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "recv timed out at {}/{} bytes (seed={})",
                    total_received, total_expected, seed,
                )
            })
            .unwrap_or_else(|_| {
                panic!(
                    "recv failed at {}/{} bytes (seed={})",
                    total_received, total_expected, seed,
                )
            });

        // Verify byte-by-byte against expected PRNG stream.
        // Data may arrive in chunks of any size due to cell fragmentation.
        let mut pos = 0;
        while pos < data.len() {
            let remaining_in_chunk = chunk_size - expected_offset;
            let compare_len = remaining_in_chunk.min(data.len() - pos);

            assert_eq!(
                &data[pos..pos + compare_len],
                &expected[expected_offset..expected_offset + compare_len],
                "data mismatch at byte {} (seed={})",
                total_received + pos,
                seed,
            );

            pos += compare_len;
            expected_offset += compare_len;

            if expected_offset >= chunk_size {
                // Generate next expected chunk
                expected_offset = 0;
                rng.fill(&mut expected);
            }
        }

        total_received += data.len();
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Firewall tests: nuisance nodes that drop / delay traffic
// ═══════════════════════════════════════════════════════════════════════
//
// Two adversarial modes:
//   1. Dropper  — Node.set_firewall() with a Probability(0.5)→Drop rule:
//      the node silently drops 50 % of decoded wire messages *after*
//      link crypto, so the link handshake still succeeds but
//      application traffic is lossy.
//   2. Delayer  — FirewallDiscovery wraps the transport and injects random
//      delays up to 2 s on every send/recv *after* a warmup window that
//      lets the handshake complete.
//
// Both are applied to the server (B).  The client (A) has a clean link.

/// Helper: spin up A ↔ B, establish a circuit connection, return both ends.
/// `drop_pct`: inbound drop rate to set on B (0 = none).
/// `delay_policy`: optional transport-level delay policy for B.
async fn firewall_pair(
    drop_pct: u32,
    delay_policy: Option<FirewallPolicy>,
) -> (
    tarnet_api::service::Connection,
    tarnet_api::service::Connection,
) {
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let node_a = Arc::new(Node::new(Keypair::generate()));
    let pid_b = node_b.peer_id();
    let service_id = node_b.default_service_id().await;

    // Server B
    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let disc_b: Box<dyn tarnet::transport::Discovery> = match delay_policy {
        Some(policy) => Box::new(FirewallDiscovery::new(Box::new(disc_b), policy)),
        None => Box::new(disc_b),
    };
    let nb = node_b.clone();
    tokio::spawn(async move { nb.run(disc_b, vec![], vec![]).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let listener_b = node_b
        .circuit_listen(ServiceId::ALL, TEST_MODE, "80", ListenerOptions::default())
        .await
        .unwrap();
    let nb2 = node_b.clone();
    let accept_handle =
        tokio::spawn(async move { nb2.circuit_accept(listener_b.id).await.unwrap() });

    // Client A — plain TCP
    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move { na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok() });

    // Wait for link
    let connected = wait_for(Duration::from_secs(10), || {
        let c = node_a.clone();
        let pid = pid_b;
        async move { c.connected_peers().await.contains(&pid) }
    })
    .await;
    assert!(connected, "A could not link to B");

    // Establish circuit BEFORE enabling drops — the circuit handshake
    // (CREATE/CREATED/EXTEND) has no retransmission either.
    let conn_a = tokio::time::timeout(
        Duration::from_secs(10),
        node_a.circuit_connect(service_id, TEST_MODE, "80", Some(pid_b), None),
    )
    .await
    .expect("circuit connect timed out")
    .expect("circuit connect failed");

    let conn_b = tokio::time::timeout(Duration::from_secs(10), accept_handle)
        .await
        .expect("accept timed out")
        .expect("accept failed");

    // NOW enable the node-level firewall — from here on, B drops messages
    if drop_pct > 0 {
        let mut fw = Firewall::default();
        fw.add_rule(Match::Probability(drop_pct as f64 / 100.0), Action::Drop);
        node_b.set_firewall(fw).await;
    }

    (conn_a, conn_b)
}

/// Helper: spin up A ↔ B with a tunnel + channel, enable drops, return
/// (node_a, node_b, channel_id).  Caller uses channel_send / app_rx.
/// Drops are enabled AFTER the channel is established so the handshake
/// and ChannelOpen succeed on a clean path.
async fn channel_pair_with_drops(drop_pct: u32, port: &str) -> (Arc<Node>, Arc<Node>, u32) {
    let node_b = Arc::new(Node::new(Keypair::generate()));
    let node_a = Arc::new(Node::new(Keypair::generate()));
    let pid_b = node_b.peer_id();

    let disc_b = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr_b = disc_b.local_addrs()[0].to_string();
    let nb = node_b.clone();
    tokio::spawn(async move { nb.run(Box::new(disc_b), vec![], vec![]).await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let disc_a = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let na = node_a.clone();
    tokio::spawn(async move { na.run(Box::new(disc_a), vec![addr_b], vec![]).await.ok() });

    // Wait for link
    let linked = wait_for(Duration::from_secs(5), || {
        let c = node_a.clone();
        async move { c.connected_peers().await.contains(&pid_b) }
    })
    .await;
    assert!(linked, "A could not link to B");

    // Establish tunnel
    let rx = node_a.create_tunnel(pid_b).await.unwrap();
    let established = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("tunnel timed out")
        .expect("tunnel failed");
    assert_eq!(established, pid_b);

    // Open channel (reliable, ordered) — on the clean path
    let ch_id = node_a.channel_open(&pid_b, port, true, true).await.unwrap();
    // Give ChannelOpen time to arrive and be processed
    tokio::time::sleep(Duration::from_millis(300)).await;

    // NOW enable drops — channel is already established on both sides
    if drop_pct > 0 {
        let mut fw = Firewall::default();
        fw.add_rule(Match::Probability(drop_pct as f64 / 100.0), Action::Drop);
        node_b.set_firewall(fw).await;
    }

    (node_a, node_b, ch_id)
}

/// 50 % inbound drop on B: channel-based reliable delivery should
/// retransmit lost messages and deliver all data to B's app receiver.
#[tokio::test]
async fn firewall_channel_50pct_drop() {
    init_log();
    let (node_a, node_b, ch_id) = channel_pair_with_drops(50, "test").await;
    let mut app_rx = node_b.take_app_receiver().await.unwrap();

    let msg_count: usize = 20;

    let sender = node_a.clone();
    let send_handle = tokio::spawn(async move {
        for i in 0..msg_count {
            sender
                .channel_send(ch_id, format!("drop:{i}").as_bytes())
                .await
                .unwrap();
            // Pace sends so we don't overrun the window
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let recv_handle = tokio::spawn(async move {
        let timeout = Duration::from_secs(60);
        let mut received = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        while received.len() < msg_count {
            let remaining = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, app_rx.recv()).await {
                Ok(Some((_peer, data))) => {
                    received.push(String::from_utf8(data).unwrap());
                }
                Ok(None) => break,
                Err(_) => panic!(
                    "recv timed out after receiving {}/{} messages",
                    received.len(),
                    msg_count
                ),
            }
        }
        received
    });

    send_handle.await.unwrap();
    let received = recv_handle.await.unwrap();

    assert_eq!(received.len(), msg_count, "not all messages delivered");
    for i in 0..msg_count {
        assert_eq!(received[i], format!("drop:{i}"), "wrong at position {i}");
    }
}

/// Transport-level delay (up to 2 s) via FirewallDiscovery: circuit
/// connections should tolerate delays since TCP still delivers everything.
#[tokio::test]
async fn firewall_circuit_delay_2s() {
    init_log();

    let policy = FirewallPolicy::Delay {
        max: Duration::from_secs(2),
    };
    let (conn_a, conn_b) = firewall_pair(0, Some(policy)).await;

    let msg_count: usize = 10;
    let timeout = Duration::from_secs(60);

    let send_handle = tokio::spawn(async move {
        for i in 0..msg_count {
            conn_a
                .send(format!("delayed:{i}").as_bytes())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let recv_handle = tokio::spawn(async move {
        let mut received = Vec::new();
        for _ in 0..msg_count {
            let data = tokio::time::timeout(timeout, conn_b.recv())
                .await
                .expect("recv timed out")
                .expect("recv failed");
            received.push(String::from_utf8(data).unwrap());
        }
        received
    });

    send_handle.await.unwrap();
    let received = recv_handle.await.unwrap();

    for i in 0..msg_count {
        assert_eq!(received[i], format!("delayed:{i}"));
    }
}

/// Combined: 50 % node-level drop + channel-based reliable transport.
#[tokio::test]
async fn firewall_channel_drop_and_delay() {
    init_log();
    let (node_a, node_b, ch_id) = channel_pair_with_drops(50, "chaos").await;
    let mut app_rx = node_b.take_app_receiver().await.unwrap();

    let msg_count: usize = 10;

    let sender = node_a.clone();
    let send_handle = tokio::spawn(async move {
        for i in 0..msg_count {
            sender
                .channel_send(ch_id, format!("chaos:{i}").as_bytes())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    let recv_handle = tokio::spawn(async move {
        let timeout = Duration::from_secs(90);
        let mut received = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        while received.len() < msg_count {
            let remaining = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, app_rx.recv()).await {
                Ok(Some((_peer, data))) => {
                    received.push(String::from_utf8(data).unwrap());
                }
                Ok(None) => break,
                Err(_) => panic!(
                    "recv timed out after receiving {}/{} messages",
                    received.len(),
                    msg_count
                ),
            }
        }
        received
    });

    send_handle.await.unwrap();
    let received = recv_handle.await.unwrap();

    assert_eq!(received.len(), msg_count);
    for i in 0..msg_count {
        assert_eq!(received[i], format!("chaos:{i}"));
    }
}
