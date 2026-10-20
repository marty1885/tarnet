//! Landmarks, the address directory and forwarding with hints, at small N:
//! every node's table budget is forced far below the network size, so the
//! machinery that normally switches on beyond `B_MIN` runs here.

use std::sync::Arc;
use std::time::Duration;

use tarnet::identity::Keypair;
use tarnet::node::{LandmarkConfig, Node};
use tarnet::transport::firewall::{FirewallDiscovery, FirewallPolicy, LinkCut};
use tarnet::transport::tcp::TcpDiscovery;
use tarnet::types::PeerId;
use tarnet_api::service::{Connection, ListenerOptions, PortMode};
use tarnet_api::types::ServiceId;

const MODE: PortMode = PortMode::ReliableOrdered;

fn init_log() {
    let _ = env_logger::builder().is_test(true).try_init();
}

/// Election and publishing fast enough for a test.
fn fast_landmarks() -> LandmarkConfig {
    LandmarkConfig {
        promote_delay_max: Duration::from_secs(3),
        min_tenure: Duration::from_secs(600),
        hysteresis: Duration::from_secs(30),
        publish_gap: Duration::from_secs(1),
        ..LandmarkConfig::default()
    }
}

struct Spawned {
    node: Arc<Node>,
    addr: String,
}

#[derive(Default)]
struct Opts {
    policy: Option<FirewallPolicy>,
    cut: Option<Arc<LinkCut>>,
    client_only: bool,
    no_landmarks: bool,
    landmarks: Option<LandmarkConfig>,
}

async fn spawn(budget: usize, bootstrap: Vec<String>, opts: Opts) -> Spawned {
    let node = Arc::new(Node::new(Keypair::generate()));
    node.set_route_budget(budget).await;
    let mut config = opts.landmarks.unwrap_or_else(fast_landmarks);
    if opts.no_landmarks {
        config.mode = tarnet::node::LandmarkMode::Never;
    }
    node.set_landmark_config(config).await;
    node.set_client_only(opts.client_only);
    let disc = TcpDiscovery::bind(&["127.0.0.1:0".into()]).await.unwrap();
    let addr = disc.local_addrs()[0].to_string();
    let disc: Box<dyn tarnet::transport::Discovery> = if opts.policy.is_some() || opts.cut.is_some() {
        let policy = opts.policy.unwrap_or(FirewallPolicy::Drop { rate: 0.0 });
        let mut fw = FirewallDiscovery::new(Box::new(disc), policy);
        if let Some(cut) = opts.cut {
            fw = fw.with_cut(cut);
        }
        Box::new(fw)
    } else {
        Box::new(disc)
    };
    let n = node.clone();
    tokio::spawn(async move {
        n.run(disc, bootstrap, vec![]).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Spawned { node, addr }
}

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
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Wait until every node is covered by a landmark and every node that
/// publishes has an address.
async fn wait_directory(nodes: &[Arc<Node>], timeout: Duration) {
    let ok = wait_for(timeout, || async {
        for n in nodes {
            if !n.is_landmark().await && n.landmarks().await.is_empty() {
                return false;
            }
            if !n.is_client_only() && n.own_address().await.is_none() {
                return false;
            }
        }
        true
    })
    .await;
    if !ok {
        for (i, n) in nodes.iter().enumerate() {
            eprintln!(
                "node {}: landmark {}, sees {} landmarks, address {:?}",
                i,
                n.is_landmark().await,
                n.landmarks().await.len(),
                n.own_address().await.map(|a| a.entries.len())
            );
        }
        panic!("directory did not settle within {:?}", timeout);
    }
}

/// A node of `from` and a node of `to` it has no route to (neither is a
/// landmark, which everyone keeps a route to).
async fn far_pair(from: &[Arc<Node>], to: &[Arc<Node>]) -> (Arc<Node>, Arc<Node>) {
    // Nodes elected at about the same moment are all landmarks, which every
    // table keeps, until the crowded ones step down: wait for that.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        for a in from.iter().rev() {
            for z in to.iter().rev() {
                if a.peer_id() != z.peer_id() && a.route_cost(&z.peer_id()).await.is_none() {
                    return (a.clone(), z.clone());
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut landmarks = 0;
    for n in from.iter().chain(to) {
        landmarks += n.is_landmark().await as usize;
    }
    panic!(
        "every node routes to every other: tables are not scoped ({} landmarks)",
        landmarks
    );
}

async fn landmark_count(nodes: &[Arc<Node>]) -> usize {
    let mut n = 0;
    for node in nodes {
        n += node.is_landmark().await as usize;
    }
    n
}

/// `server` listens on `port`; `client` connects by peer id. Both ends of
/// the connection, after a round trip.
async fn connect(client: &Arc<Node>, server: &Arc<Node>, port: &str, timeout: Duration) -> (Connection, Connection) {
    let listener = server
        .circuit_listen(ServiceId::ALL, MODE, port, ListenerOptions::default())
        .await
        .unwrap();
    let s = server.clone();
    let accept = tokio::spawn(async move { s.circuit_accept(listener.id).await.unwrap() });
    let sid = server.default_service_id().await;
    let conn = tokio::time::timeout(
        timeout,
        client.circuit_connect(sid, MODE, port, Some(server.peer_id()), None),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    let served = tokio::time::timeout(Duration::from_secs(30), accept)
        .await
        .expect("accept timed out")
        .unwrap();
    conn.send(b"ping").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(30), served.recv())
        .await
        .expect("ping lost")
        .unwrap();
    assert_eq!(got, b"ping");
    served.send(b"pong").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(30), conn.recv())
        .await
        .expect("pong lost")
        .unwrap();
    assert_eq!(got, b"pong");
    (conn, served)
}

/// A tunnel from `a` to `b` and raw tunnel data both ways.
async fn tunnel_round_trip(a: &Arc<Node>, b: &Arc<Node>) {
    let mut b_rx = b.take_app_receiver().await.expect("app receiver taken");
    let mut a_rx = a.take_app_receiver().await.expect("app receiver taken");
    let done = a.create_tunnel(b.peer_id()).await.expect("tunnel start failed");
    tokio::time::timeout(Duration::from_secs(45), done)
        .await
        .expect("tunnel timed out")
        .unwrap();
    a.send_tunnel_data(&b.peer_id(), b"over the tunnel").await.unwrap();
    let (from, data) = tokio::time::timeout(Duration::from_secs(20), b_rx.recv())
        .await
        .expect("tunnel data lost")
        .unwrap();
    assert_eq!((from, data.as_slice()), (a.peer_id(), &b"over the tunnel"[..]));
    // The responder reaches the initiator by its address too.
    let reply = wait_for(Duration::from_secs(20), || async {
        b.send_tunnel_data(&a.peer_id(), b"and back").await.is_ok()
    })
    .await;
    assert!(reply, "responder has no tunnel back");
    let (from, data) = tokio::time::timeout(Duration::from_secs(20), a_rx.recv())
        .await
        .expect("tunnel reply lost")
        .unwrap();
    assert_eq!((from, data.as_slice()), (b.peer_id(), &b"and back"[..]));
}

/// Spawn a chain, each node bootstrapping to the one before.
async fn chain(count: usize, budget: usize) -> Vec<Arc<Node>> {
    // Short tenure and hysteresis: landmarks elected at once crowd a short
    // chain, and the extra ones should step down within the test.
    let config = LandmarkConfig {
        min_tenure: Duration::from_secs(5),
        hysteresis: Duration::from_secs(10),
        ..fast_landmarks()
    };
    let mut nodes: Vec<Spawned> = Vec::new();
    for i in 0..count {
        let bootstrap = if i == 0 { vec![] } else { vec![nodes[i - 1].addr.clone()] };
        let opts = Opts {
            landmarks: Some(config.clone()),
            ..Opts::default()
        };
        nodes.push(spawn(budget, bootstrap, opts).await);
    }
    nodes.into_iter().map(|s| s.node).collect()
}

/// An 8-node chain where every table keeps 3 destinations: landmarks get
/// elected, everyone publishes an address, and the far end is reached by
/// resolving its address, not by a route.
#[tokio::test]
async fn scoped_chain_resolves_far_nodes_through_the_directory() {
    init_log();
    let nodes = chain(8, 3).await;
    wait_directory(&nodes, Duration::from_secs(60)).await;

    let landmarks = landmark_count(&nodes).await;
    assert!(
        (1..nodes.len()).contains(&landmarks),
        "{} landmarks among {}",
        landmarks,
        nodes.len()
    );
    let mut stored = 0;
    for n in &nodes {
        stored += n.directory_size().await;
    }
    assert!(stored >= nodes.len(), "landmarks store only {} records", stored);

    // Any pair without a route between them (landmarks are routed to by
    // everyone, so this depends on which nodes were elected).
    let (a, z) = far_pair(&nodes, &nodes).await;
    let (a, z) = (&a, &z);
    let rec = a.lookup_address(&z.peer_id()).await.expect("lookup failed");
    assert_eq!(rec.peer, z.peer_id());
    assert!(rec.verify());
    assert!(!rec.entries.is_empty());

    connect(a, z, "80", Duration::from_secs(60)).await;
    connect(z, a, "81", Duration::from_secs(60)).await;
    tunnel_round_trip(a, z).await;
}

/// A client-only node publishes nothing and is never a landmark, but still
/// reaches far nodes: replies come back over its circuits.
#[tokio::test]
async fn client_only_node_publishes_nothing_and_still_connects() {
    init_log();
    let mut spawned: Vec<Spawned> = Vec::new();
    for i in 0..7 {
        let bootstrap = if i == 0 { vec![] } else { vec![spawned[i - 1].addr.clone()] };
        spawned.push(spawn(3, bootstrap, Opts::default()).await);
    }
    let client = spawn(
        3,
        vec![spawned[0].addr.clone()],
        Opts {
            client_only: true,
            ..Opts::default()
        },
    )
    .await
    .node;
    let nodes: Vec<Arc<Node>> = spawned.iter().map(|s| s.node.clone()).collect();
    let mut all = nodes.clone();
    all.push(client.clone());
    wait_directory(&all, Duration::from_secs(60)).await;

    assert!(client.own_address().await.is_none());
    assert!(!client.is_landmark().await);
    // Nobody finds an address for it.
    let far = &nodes[6];
    assert!(far.lookup_address(&client.peer_id()).await.is_none());

    connect(&client, far, "80", Duration::from_secs(60)).await;
}

/// Two clusters joined by a fast link through one gateway and by a 5-hop
/// chain of slow, lossy links. Every table keeps 4 destinations, so
/// landmarks, addresses, hints and sampling all run.
struct Barbell {
    left: Vec<Arc<Node>>,
    right: Vec<Arc<Node>>,
    chain: Vec<Arc<Node>>,
    gateway: Arc<Node>,
    gateway_cut: Arc<LinkCut>,
    chain_cut: Arc<LinkCut>,
}

impl Barbell {
    fn all(&self) -> Vec<Arc<Node>> {
        let mut all = self.left.clone();
        all.extend(self.right.iter().cloned());
        all.extend(self.chain.iter().cloned());
        all.push(self.gateway.clone());
        all
    }
}

const SLOW: FirewallPolicy = FirewallPolicy::RateLimit {
    bytes_per_sec: 16_000,
    drop_rate: 0.02,
};

/// A cluster of 5: a hub and four nodes, each linked to the hub and to the
/// previous one.
async fn cluster(budget: usize) -> Vec<Spawned> {
    let mut nodes = vec![spawn(budget, vec![], Opts::default()).await];
    for i in 1..5 {
        let mut bootstrap = vec![nodes[0].addr.clone()];
        if i > 1 {
            bootstrap.push(nodes[i - 1].addr.clone());
        }
        nodes.push(spawn(budget, bootstrap, Opts::default()).await);
    }
    nodes
}

async fn barbell() -> Barbell {
    const BUDGET: usize = 4;
    let left = cluster(BUDGET).await;
    let right = cluster(BUDGET).await;
    // left[0] — c1 — c2 — c3 — c4 — right[0], every chain link slow. c3's
    // links can be cut to split the network.
    let chain_cut = LinkCut::new();
    let mut chain: Vec<Spawned> = Vec::new();
    for i in 0..4 {
        let prev = if i == 0 { left[0].addr.clone() } else { chain[i - 1].addr.clone() };
        let mut bootstrap = vec![prev];
        if i == 3 {
            bootstrap.push(right[0].addr.clone());
        }
        chain.push(
            spawn(
                BUDGET,
                bootstrap,
                Opts {
                    policy: Some(SLOW),
                    cut: (i == 2).then(|| chain_cut.clone()),
                    ..Opts::default()
                },
            )
            .await,
        );
    }
    // The fast path: left[1] — gateway — right[1].
    let gateway_cut = LinkCut::new();
    let gateway = spawn(
        BUDGET,
        vec![left[1].addr.clone(), right[1].addr.clone()],
        Opts {
            cut: Some(gateway_cut.clone()),
            ..Opts::default()
        },
    )
    .await
    .node;
    Barbell {
        left: left.into_iter().map(|s| s.node).collect(),
        right: right.into_iter().map(|s| s.node).collect(),
        chain: chain.into_iter().map(|s| s.node).collect(),
        gateway,
        gateway_cut,
        chain_cut,
    }
}

/// Across the barbell: circuits and tunnels to the far cluster resolve
/// through the directory. Then the fast path dies ("school down"): a new
/// circuit across succeeds over the slow chain well inside a TCP connect
/// timeout.
#[tokio::test]
async fn barbell_reaches_across_and_survives_school_down() {
    init_log();
    let net = barbell().await;
    let all = net.all();
    wait_directory(&all, Duration::from_secs(90)).await;
    let landmarks = landmark_count(&all).await;
    assert!((1..all.len()).contains(&landmarks), "{} landmarks", landmarks);
    for c in &net.chain {
        assert!(!c.is_landmark().await, "a node on slow links only became a landmark");
    }

    let (a, z) = far_pair(&net.left, &net.right).await;
    connect(&a, &z, "80", Duration::from_secs(60)).await;
    tunnel_round_trip(&a, &z).await;

    // School down: the fast path goes away. A new connection, made once the
    // links have died, gets across over the chain.
    net.gateway_cut.cut();
    let started = std::time::Instant::now();
    let (a, b) = far_pair(&net.left, &net.right).await;
    connect(&a, &b, "81", Duration::from_secs(100)).await;
    let took = started.elapsed();
    log::info!("new circuit across after school down: {:?}", took);
    assert!(took < Duration::from_secs(100), "recovery took {:?}", took);
}

/// Island: cut the barbell in two. Each side keeps resolving and
/// connecting to its own nodes beyond its local area, electing its own
/// landmarks if it lost them.
#[tokio::test]
async fn island_keeps_resolving_inside() {
    init_log();
    let net = barbell().await;
    let all = net.all();
    wait_directory(&all, Duration::from_secs(90)).await;

    net.gateway_cut.cut();
    net.chain_cut.cut();
    let island: Vec<Arc<Node>> = net
        .left
        .iter()
        .cloned()
        .chain(net.chain[..2].iter().cloned())
        .collect();
    let island_ids: Vec<PeerId> = island.iter().map(|n| n.peer_id()).collect();
    // Every island node is covered by a landmark inside the island.
    let covered = wait_for(Duration::from_secs(90), || async {
        for n in &island {
            if n.is_landmark().await {
                continue;
            }
            let ls = n.landmarks().await;
            if !ls.iter().any(|l| island_ids.contains(l)) {
                return false;
            }
        }
        true
    })
    .await;
    assert!(covered, "island has no landmark of its own");

    // A pair inside the island beyond each other's local area.
    let (a, z) = far_pair(&island, &island).await;
    connect(&a, &z, "80", Duration::from_secs(90)).await;
}

/// A hidden service in a scoped network: intro point, rendezvous point and
/// waypoints are sampled relays, possibly beyond either side's local area,
/// reached through their addresses. The client uses a single hop, so it has
/// no waypoint with a route to lean on.
#[tokio::test]
async fn hidden_service_across_a_scoped_chain() {
    use tarnet_api::types::{IdentityScheme, PrivacyLevel};
    init_log();
    let nodes = chain(8, 3).await;
    wait_directory(&nodes, Duration::from_secs(60)).await;
    let (client, host) = (&nodes[0], &nodes[7]);

    let sid = host
        .create_identity(
            "hidden",
            PrivacyLevel::Hidden { intro_points: 1 },
            2,
            IdentityScheme::DEFAULT,
        )
        .await
        .unwrap();
    let listener = host
        .circuit_listen(sid, MODE, "80", ListenerOptions::default())
        .await
        .unwrap();
    if host.hidden_intro_peers(&sid).await.is_empty() {
        host.publish_hidden_service(sid, 1)
            .await
            .expect("publish_hidden_service failed");
    }
    let kp = host.keypair_for_service(&sid).await.unwrap();
    let intro_points: Vec<_> = host
        .hidden_intro_peers(&sid)
        .await
        .into_iter()
        .map(|p| (p, kp.identity.kem_algo() as u8, kp.identity.kem.kem_pubkey_bytes()))
        .collect();
    assert!(!intro_points.is_empty());

    let accepting = host.clone();
    let accept = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(90), accepting.circuit_accept(listener.id))
            .await
            .expect("accept timed out")
            .expect("accept failed")
    });
    let conn = tokio::time::timeout(
        Duration::from_secs(90),
        client.connect_via_rendezvous(sid, MODE, "80", &intro_points, 1),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");
    let served = accept.await.unwrap();
    conn.send(b"to the service").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(20), served.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"to the service");
    served.send(b"to the client").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(20), conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"to the client");
}

/// A scoped chain where no node may be a landmark: there is no directory,
/// so the far end is found by route search alone.
async fn chain_without_landmarks(count: usize, budget: usize) -> Vec<Arc<Node>> {
    let mut nodes: Vec<Spawned> = Vec::new();
    for i in 0..count {
        let bootstrap = if i == 0 { vec![] } else { vec![nodes[i - 1].addr.clone()] };
        let opts = Opts {
            no_landmarks: true,
            ..Opts::default()
        };
        nodes.push(spawn(budget, bootstrap, opts).await);
    }
    let nodes: Vec<Arc<Node>> = nodes.into_iter().map(|s| s.node).collect();
    // Wait for the tables to settle at their budget.
    let settled = wait_for(Duration::from_secs(20), || async {
        nodes[0].route_cost(&nodes[1].peer_id()).await.is_some()
            && nodes[count - 1].route_cost(&nodes[count - 2].peer_id()).await.is_some()
    })
    .await;
    assert!(settled);
    tokio::time::sleep(Duration::from_secs(2)).await;
    nodes
}

#[tokio::test]
async fn route_search_reaches_nodes_the_directory_cannot() {
    init_log();
    let nodes = chain_without_landmarks(8, 3).await;
    for n in &nodes {
        assert!(!n.is_landmark().await);
        assert!(n.own_address().await.is_none());
    }
    let (a, z) = far_pair(&nodes[..1], &nodes[5..]).await;
    let hints = a.route_search(&z.peer_id()).await.expect("search found nothing");
    assert!(!hints.is_empty());
    assert!(hints.len() <= tarnet::wire::MAX_HINTS);

    // Connections find it the same way, without being told.
    let (a, z) = far_pair(&nodes[1..2], &nodes[6..]).await;
    connect(&a, &z, "80", Duration::from_secs(90)).await;
    tunnel_round_trip(&a, &z).await;
}

#[tokio::test]
async fn route_search_for_a_missing_node_ends() {
    init_log();
    let nodes = chain_without_landmarks(6, 3).await;
    let nobody = PeerId([0x5A; 32]);
    let started = std::time::Instant::now();
    assert!(nodes[0].route_search(&nobody).await.is_none());
    let took = started.elapsed();
    // Rings of 4, 8 and 16 hops: 2 + 4 + 8 s.
    assert!(took < Duration::from_secs(20), "search took {:?}", took);
    // At most one search per target per 30 s.
    let started = std::time::Instant::now();
    assert!(nodes[0].route_search(&nobody).await.is_none());
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// Two halves joined through a bridge node that can be cut. Each half is its
/// landmark-eligible node next to the bridge, a chain of four, and four
/// leaves on the chain's end:
///
/// ```text
/// a5..a8 ┐                        ┌ b5..b8
///        a4 — a3 — a2 — a1 — a0 — x — b0 — b1 — b2 — b3 — b4
/// ```
///
/// Joined, a0 and b0 lie within half of each other's radius, so only one of
/// them stays a landmark; every node stays within an address path's length
/// of either.
struct Halves {
    a: Vec<Arc<Node>>,
    b: Vec<Arc<Node>>,
    x: Arc<Node>,
    cut: Arc<LinkCut>,
}

const MERGE_HYSTERESIS: Duration = Duration::from_secs(15);

async fn halves() -> Halves {
    const BUDGET: usize = 8;
    const LEN: usize = 9;
    let config = LandmarkConfig {
        min_tenure: Duration::from_secs(5),
        hysteresis: MERGE_HYSTERESIS,
        ..fast_landmarks()
    };
    let opts = |eligible: bool| Opts {
        no_landmarks: !eligible,
        landmarks: Some(config.clone()),
        ..Opts::default()
    };
    let half = || async {
        let mut h: Vec<Spawned> = vec![spawn(BUDGET, vec![], opts(true)).await];
        for i in 1..LEN {
            let to = if i <= 4 { i - 1 } else { 4 };
            h.push(spawn(BUDGET, vec![h[to].addr.clone()], opts(false)).await);
        }
        h
    };
    let a = half().await;
    let b = half().await;
    let cut = LinkCut::new();
    let x = spawn(
        BUDGET,
        vec![a[0].addr.clone(), b[0].addr.clone()],
        Opts {
            cut: Some(cut.clone()),
            ..opts(false)
        },
    )
    .await
    .node;
    Halves {
        a: a.into_iter().map(|s| s.node).collect(),
        b: b.into_iter().map(|s| s.node).collect(),
        x,
        cut,
    }
}

impl Halves {
    fn all(&self) -> Vec<Arc<Node>> {
        self.a.iter().chain(&self.b).chain([&self.x]).cloned().collect()
    }

    /// The two landmark-eligible nodes, next to the bridge.
    fn candidates(&self) -> (Arc<Node>, Arc<Node>) {
        (self.a[0].clone(), self.b[0].clone())
    }

    async fn landmarks(&self) -> (bool, bool) {
        let (la, lb) = self.candidates();
        (la.is_landmark().await, lb.is_landmark().await)
    }

    async fn joined(&self) -> bool {
        let (la, lb) = self.candidates();
        la.route_cost(&lb.peer_id()).await.is_some() && lb.route_cost(&la.peer_id()).await.is_some()
    }
}

/// Separation and merge. Joined, the two crowded candidates settle on one
/// landmark. Split, the side without it elects its own. A brief merge
/// changes nothing. A lasting merge leaves one landmark again, though
/// neither saw the other promote, and the far ends reach each other.
#[tokio::test]
async fn split_halves_elect_and_merged_halves_thin_out() {
    init_log();
    let net = halves().await;
    let all = net.all();
    wait_directory(&all, Duration::from_secs(120)).await;
    let one = || async {
        let (a, b) = net.landmarks().await;
        a != b
    };
    assert!(
        wait_for(Duration::from_secs(90), one).await,
        "joined halves did not settle on one landmark: {:?}",
        net.landmarks().await
    );
    assert_eq!(landmark_count(&all).await, 1);

    // Split: each half has a landmark of its own.
    net.cut.cut();
    let both = || async { net.landmarks().await == (true, true) };
    assert!(
        wait_for(Duration::from_secs(60), both).await,
        "a half without a landmark did not elect one: {:?}",
        net.landmarks().await
    );

    // A brief merge: both stay.
    net.cut.restore();
    assert!(
        wait_for(Duration::from_secs(120), || net.joined()).await,
        "halves did not rejoin"
    );
    tokio::time::sleep(Duration::from_secs(5)).await;
    net.cut.cut();
    let (la, lb) = net.candidates();
    let gone = wait_for(Duration::from_secs(30), || async {
        la.route_cost(&lb.peer_id()).await.is_none()
    })
    .await;
    assert!(gone, "halves did not split again");
    tokio::time::sleep(MERGE_HYSTERESIS * 2 + Duration::from_secs(5)).await;
    assert_eq!(net.landmarks().await, (true, true), "a brief merge moved landmarks");

    // A lasting merge: one of them steps down.
    net.cut.restore();
    assert!(
        wait_for(Duration::from_secs(120), || net.joined()).await,
        "halves did not rejoin"
    );
    let merged = std::time::Instant::now();
    assert!(
        wait_for(MERGE_HYSTERESIS * 2 + Duration::from_secs(45), one).await,
        "merged halves kept both landmarks: {:?}",
        net.landmarks().await
    );
    log::info!("one landmark again {:?} after the merge", merged.elapsed());
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(one().await, "landmarks flapped after the merge: {:?}", net.landmarks().await);

    // The far ends reach each other across the merged network.
    let (a, z) = far_pair(&net.a[5..], &net.b[5..]).await;
    connect(&a, &z, "80", Duration::from_secs(90)).await;
    connect(&z, &a, "81", Duration::from_secs(90)).await;
}
