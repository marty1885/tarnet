use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::link::PeerLink;
use crate::types::{LinkId, PeerId};

/// Score for a link, used to rank links to the same peer.
/// Lower total score = better link.
#[derive(Debug, Clone)]
struct LinkScore {
    /// Exponentially weighted moving average RTT in microseconds.
    ewma_rtt_us: u64,
    /// Loss rate as 0..255 (0 = no loss, 255 = total loss).
    loss_rate: u8,
    /// Monotonic timestamp of last successful send/recv.
    last_active: Instant,
}

impl LinkScore {
    fn new() -> Self {
        Self {
            ewma_rtt_us: 0,
            loss_rate: 0,
            last_active: Instant::now(),
        }
    }

    /// Compute a comparable score. Lower is better.
    fn score(&self) -> u64 {
        self.ewma_rtt_us + (self.loss_rate as u64 * 10_000)
    }
}

/// State of a link within the transport manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    Active,
    Standby,
}

/// A scored link to a peer.
struct ScoredLink {
    link: Arc<PeerLink>,
    score: LinkScore,
    state: LinkState,
    /// Last time we received any message on this link.
    last_recv: Instant,
    /// Whether this side initiated the connection (outbound).
    is_outbound: bool,
    /// Whether this link can be evicted when at capacity.
    /// Currently always true. Future: false for scarce/irreplaceable transports
    /// (e.g. RS232, dedicated LAN) — based on replaceability, not trust, since
    /// any physical link can be MITM'd.
    evictable: bool,
    /// When this link was created (for age-based eviction scoring).
    created_at: Instant,
}

/// Manages multiple links to a single peer with scored failover.
///
/// Tracks all links, picks the best one as active, and promotes the next-best
/// when the active link dies. Hysteresis prevents flapping: a standby link
/// must beat the active link's score by >20% to trigger promotion.
struct PeerTransport {
    links: BTreeMap<LinkId, ScoredLink>,
    active: Option<LinkId>,
    next_id: LinkId,
}

impl PeerTransport {
    fn new() -> Self {
        Self {
            links: BTreeMap::new(),
            active: None,
            next_id: 0,
        }
    }

    /// Insert a new link. Returns (assigned LinkId, whether the active link changed).
    fn add_link(&mut self, link: Arc<PeerLink>) -> (LinkId, bool) {
        let id = self.next_id;
        self.next_id += 1;

        let is_outbound = link.is_initiator();
        self.links.insert(
            id,
            ScoredLink {
                link,
                score: LinkScore::new(),
                state: LinkState::Standby,
                last_recv: Instant::now(),
                is_outbound,
                evictable: true,
                created_at: Instant::now(),
            },
        );

        let active_changed = self.recompute_active();
        (id, active_changed)
    }

    /// Remove a link by id. If it was active, promotes the next-best.
    fn remove_link(&mut self, id: LinkId) {
        self.links.remove(&id);
        if self.active == Some(id) {
            self.active = None;
            self.recompute_active();
        }
    }

    /// Get the currently active (best) link for sending.
    fn active_link(&self) -> Option<&Arc<PeerLink>> {
        self.active
            .and_then(|id| self.links.get(&id))
            .map(|sl| &sl.link)
    }

    /// Number of links to this peer.
    fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Update scoring metrics for a link after keepalive pong.
    fn update_score(&mut self, id: LinkId, rtt_us: u64, loss_rate: u8) {
        if let Some(sl) = self.links.get_mut(&id) {
            // EWMA with alpha=0.25: new = 0.75*old + 0.25*sample
            sl.score.ewma_rtt_us = (sl.score.ewma_rtt_us * 3 + rtt_us) / 4;
            sl.score.loss_rate = loss_rate;
            sl.score.last_active = Instant::now();
        }
        self.recompute_active();
    }

    /// Mark a specific link as having received a message.
    fn touch_recv(&mut self, id: LinkId) {
        if let Some(sl) = self.links.get_mut(&id) {
            sl.last_recv = Instant::now();
        }
    }

    /// Return link IDs that haven't received any message within `timeout`.
    fn dead_links(&self, timeout: Duration) -> Vec<LinkId> {
        let cutoff = Instant::now() - timeout;
        self.links
            .iter()
            .filter(|(_, sl)| sl.last_recv < cutoff)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Return link IDs that have been idle (no recv) for longer than `idle_threshold`.
    fn idle_links(&self, idle_threshold: Duration) -> Vec<(LinkId, Arc<PeerLink>)> {
        let cutoff = Instant::now() - idle_threshold;
        self.links
            .iter()
            .filter(|(_, sl)| sl.last_recv < cutoff)
            .map(|(&id, sl)| (id, sl.link.clone()))
            .collect()
    }

    /// True when no links remain (triggers full peer removal).
    fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Recompute which link should be active. Returns true if active changed.
    fn recompute_active(&mut self) -> bool {
        if self.links.is_empty() {
            let changed = self.active.is_some();
            self.active = None;
            return changed;
        }

        // Find the best (lowest score) link
        let best_id = *self
            .links
            .iter()
            .min_by_key(|(_, sl)| sl.score.score())
            .unwrap()
            .0;

        let old_active = self.active;

        match old_active {
            None => {
                // No current active — just pick the best
                self.active = Some(best_id);
            }
            Some(current_id) if current_id == best_id => {
                // Already the best, no change needed
                return false;
            }
            Some(current_id) => {
                // Hysteresis: standby must beat active by >20% to trigger promotion
                let current_score = self
                    .links
                    .get(&current_id)
                    .map(|sl| sl.score.score())
                    .unwrap_or(u64::MAX);
                let best_score = self.links.get(&best_id).unwrap().score.score();

                // If current link is gone (score=MAX), always switch.
                // Otherwise require 20% improvement.
                if current_score == u64::MAX || best_score * 5 < current_score * 4 {
                    self.active = Some(best_id);
                } else {
                    return false;
                }
            }
        }

        // Update states
        for (&id, sl) in self.links.iter_mut() {
            sl.state = if Some(id) == self.active {
                LinkState::Active
            } else {
                LinkState::Standby
            };
        }

        self.active != old_active
    }
}

// ── Status snapshot types ──

/// Per-link status snapshot for display.
#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub link_id: LinkId,
    pub state: &'static str,     // "active" | "standby"
    pub direction: &'static str, // "outbound" | "inbound"
    pub rtt_us: u64,
    pub loss_rate: u8,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub transport: &'static str,
}

/// Per-peer status snapshot with all its links.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub links: Vec<LinkInfo>,
}

// ── LinkTable: drop-in replacement for HashMap<PeerId, Arc<PeerLink>> ──

/// Multi-link-per-peer table that presents the same API shape as the old
/// `HashMap<PeerId, Arc<PeerLink>>`. Callers get/iterate the *best* link
/// per peer transparently. Only `insert` and `remove_link` differ.
pub struct LinkTable {
    peers: HashMap<PeerId, PeerTransport>,
}

impl LinkTable {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Add a link to a peer. Returns (LinkId, is_first_link_for_peer).
    pub fn insert(&mut self, peer: PeerId, link: Arc<PeerLink>) -> (LinkId, bool) {
        let pt = self.peers.entry(peer).or_insert_with(PeerTransport::new);
        let is_first = pt.is_empty();
        let (link_id, _active_changed) = pt.add_link(link);
        (link_id, is_first)
    }

    /// Remove a specific link. Returns true if the peer has no links left
    /// (caller should clean up routing state).
    pub fn remove_link(&mut self, peer: &PeerId, link_id: LinkId) -> bool {
        if let Some(pt) = self.peers.get_mut(peer) {
            pt.remove_link(link_id);
            if pt.is_empty() {
                self.peers.remove(peer);
                return true;
            }
        }
        false
    }

    /// Get the best link to a peer (same signature as HashMap::get).
    pub fn get(&self, peer: &PeerId) -> Option<&Arc<PeerLink>> {
        self.peers.get(peer).and_then(|pt| pt.active_link())
    }

    /// Iterate (peer_id, best_link) for all connected peers.
    /// Same shape as HashMap::iter() — callers don't change.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Arc<PeerLink>)> {
        self.peers
            .iter()
            .filter_map(|(pid, pt)| pt.active_link().map(|link| (pid, link)))
    }

    /// Check if we have any link to a peer.
    pub fn contains_key(&self, peer: &PeerId) -> bool {
        self.peers
            .get(peer)
            .map(|pt| !pt.is_empty())
            .unwrap_or(false)
    }

    /// Get all connected peer IDs.
    pub fn keys(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.keys()
    }

    /// Number of connected peers (not links).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// How many links exist to a given peer.
    #[allow(dead_code)]
    pub fn link_count(&self, peer: &PeerId) -> usize {
        self.peers.get(peer).map(|pt| pt.link_count()).unwrap_or(0)
    }

    /// Record that we received a message on a specific link.
    pub fn touch_recv(&mut self, peer: &PeerId, link_id: LinkId) {
        if let Some(pt) = self.peers.get_mut(peer) {
            pt.touch_recv(link_id);
        }
    }

    /// Update RTT scoring for a link (from keepalive pong).
    pub fn update_link_score(&mut self, peer: &PeerId, link_id: LinkId, rtt_us: u64) {
        if let Some(pt) = self.peers.get_mut(peer) {
            pt.update_score(link_id, rtt_us, 0);
        }
    }

    /// Return all (peer, link_id) pairs that haven't received anything within `timeout`.
    pub fn dead_links(&self, timeout: Duration) -> Vec<(PeerId, LinkId)> {
        let mut result = Vec::new();
        for (&peer, pt) in &self.peers {
            for id in pt.dead_links(timeout) {
                result.push((peer, id));
            }
        }
        result
    }

    /// Return all idle links (no recv within threshold) with their PeerLink handles for sending keepalives.
    pub fn idle_links(&self, idle_threshold: Duration) -> Vec<(PeerId, LinkId, Arc<PeerLink>)> {
        let mut result = Vec::new();
        for (&peer, pt) in &self.peers {
            for (id, link) in pt.idle_links(idle_threshold) {
                result.push((peer, id, link));
            }
        }
        result
    }

    /// Count total inbound (responder) links across all peers.
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .flat_map(|pt| pt.links.values())
            .filter(|sl| !sl.is_outbound)
            .count()
    }

    /// Snapshot all peers with their link details for status display.
    pub fn peer_info_snapshot(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .map(|(&peer_id, pt)| {
                let links = pt
                    .links
                    .iter()
                    .map(|(&lid, sl)| LinkInfo {
                        link_id: lid,
                        state: match sl.state {
                            LinkState::Active => "active",
                            LinkState::Standby => "standby",
                        },
                        direction: if sl.is_outbound {
                            "outbound"
                        } else {
                            "inbound"
                        },
                        rtt_us: sl.score.ewma_rtt_us,
                        loss_rate: sl.score.loss_rate,
                        age_secs: sl.created_at.elapsed().as_secs(),
                        idle_secs: sl.last_recv.elapsed().as_secs(),
                        transport: sl.link.transport_name(),
                    })
                    .collect();
                PeerInfo { peer_id, links }
            })
            .collect()
    }

    /// Count total outbound (initiator) links across all peers.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .flat_map(|pt| pt.links.values())
            .filter(|sl| sl.is_outbound)
            .count()
    }

    /// Pick the best eviction candidate among links matching `outbound`.
    ///
    /// Eviction score = `circuit_count_for_peer + age_bucket`. Lower score = more evictable.
    /// Only considers links with `evictable = true`. Returns None if no evictable link exists.
    ///
    /// `circuit_counts`: number of circuit table entries involving each peer (from CircuitTable).
    pub fn pick_eviction_candidate(
        &self,
        outbound: bool,
        circuit_counts: &HashMap<PeerId, usize>,
    ) -> Option<(PeerId, LinkId)> {
        let mut best: Option<(PeerId, LinkId, u64)> = None;

        for (&peer, pt) in &self.peers {
            let peer_circuits = circuit_counts.get(&peer).copied().unwrap_or(0) as u64;

            for (&link_id, sl) in &pt.links {
                if sl.is_outbound != outbound || !sl.evictable {
                    continue;
                }

                let age_secs = sl.created_at.elapsed().as_secs();
                let age_bucket = match age_secs {
                    0..60 => 0u64,
                    60..600 => 1,
                    600..3600 => 2,
                    _ => 3,
                };

                let score = peer_circuits + age_bucket;

                if best.is_none() || score < best.unwrap().2 {
                    best = Some((peer, link_id, score));
                }
            }
        }

        best.map(|(peer, link_id, _)| (peer, link_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;
    use crate::transport::Transport;
    use async_trait::async_trait;
    use tokio::sync::Mutex as TokioMutex;

    /// In-memory bidirectional transport for testing PeerLink handshakes.
    struct MemTransport {
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        rx: TokioMutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    }

    fn mem_transport_pair() -> (MemTransport, MemTransport) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(64);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(64);
        (
            MemTransport {
                tx: tx_a,
                rx: TokioMutex::new(rx_b),
            },
            MemTransport {
                tx: tx_b,
                rx: TokioMutex::new(rx_a),
            },
        )
    }

    #[async_trait]
    impl Transport for MemTransport {
        async fn send(&self, data: &[u8]) -> crate::types::Result<()> {
            self.tx
                .send(data.to_vec())
                .await
                .map_err(|_| crate::types::Error::Io(std::io::Error::other("send failed")))
        }
        async fn recv(&self, buf: &mut [u8]) -> crate::types::Result<usize> {
            let data = self
                .rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| crate::types::Error::Io(std::io::Error::other("recv failed")))?;
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        }
        fn mtu(&self) -> usize {
            65536
        }
        fn is_reliable(&self) -> bool {
            true
        }
        fn name(&self) -> &'static str {
            "mem"
        }
    }

    /// Create a pair of linked PeerLinks via in-memory transport for testing.
    async fn make_test_link_pair() -> (Arc<PeerLink>, Arc<PeerLink>) {
        let id_a = Keypair::generate();
        let id_b = Keypair::generate();

        let (a_transport, b_transport) = mem_transport_pair();

        let (link_a, link_b) = tokio::join!(
            PeerLink::initiator(Box::new(a_transport), &id_a, None),
            PeerLink::responder(Box::new(b_transport), &id_b),
        );

        (Arc::new(link_a.unwrap()), Arc::new(link_b.unwrap()))
    }

    // ── PeerTransport unit tests ──

    #[tokio::test]
    async fn add_two_links_first_is_active() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let (id0, changed0) = pt.add_link(link_a.clone());
        assert!(changed0); // first link becomes active
        assert_eq!(id0, 0);

        let (id1, changed1) = pt.add_link(link_b.clone());
        assert!(!changed1); // equal score, no promotion (hysteresis)
        assert_eq!(id1, 1);

        // Active should still be the first link
        assert!(Arc::ptr_eq(pt.active_link().unwrap(), &link_a));
    }

    #[tokio::test]
    async fn remove_active_promotes_standby() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let (id0, _) = pt.add_link(link_a);
        let (_id1, _) = pt.add_link(link_b.clone());

        pt.remove_link(id0);

        // link_b should now be active
        assert!(Arc::ptr_eq(pt.active_link().unwrap(), &link_b));
    }

    #[tokio::test]
    async fn hysteresis_prevents_flapping() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let (id0, _) = pt.add_link(link_a.clone());
        let (id1, _) = pt.add_link(link_b);

        // Converge both links to similar scores via multiple rounds.
        // Update id1 first each round (it starts at 0, so giving it a high
        // score first ensures it never steals active from id0).
        for _ in 0..20 {
            pt.update_score(id1, 900, 0);
            pt.update_score(id0, 1000, 0);
        }
        // After convergence: id0 ≈ 1000, id1 ≈ 900.
        // link_b is 10% better — within hysteresis band (needs >20%).
        assert!(Arc::ptr_eq(pt.active_link().unwrap(), &link_a));
    }

    #[tokio::test]
    async fn significant_score_difference_triggers_promotion() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let (id0, _) = pt.add_link(link_a);
        let (id1, _) = pt.add_link(link_b.clone());

        // Give link_b a much better score (>20% better)
        pt.update_score(id0, 10000, 0);
        pt.update_score(id1, 1000, 0);

        // Now link_b should be promoted
        assert!(Arc::ptr_eq(pt.active_link().unwrap(), &link_b));
    }

    #[tokio::test]
    async fn remove_all_links_is_empty() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let (id0, _) = pt.add_link(link_a);
        let (id1, _) = pt.add_link(link_b);

        assert!(!pt.is_empty());
        pt.remove_link(id0);
        assert!(!pt.is_empty());
        pt.remove_link(id1);
        assert!(pt.is_empty());
        assert!(pt.active_link().is_none());
    }

    // ── LinkTable unit tests ──

    #[tokio::test]
    async fn link_table_insert_and_get() {
        let (link_a, _) = make_test_link_pair().await;
        let peer = link_a.remote_peer();

        let mut table = LinkTable::new();
        let (_, is_first) = table.insert(peer, link_a.clone());
        assert!(is_first);
        assert!(Arc::ptr_eq(table.get(&peer).unwrap(), &link_a));
    }

    #[tokio::test]
    async fn link_table_second_link_not_first() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;
        let peer = link_a.remote_peer();

        let mut table = LinkTable::new();
        let (_, is_first) = table.insert(peer, link_a);
        assert!(is_first);
        let (_, is_first) = table.insert(peer, link_b);
        assert!(!is_first);
        assert_eq!(table.link_count(&peer), 2);
    }

    #[tokio::test]
    async fn link_table_remove_link_failover() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;
        let peer = link_a.remote_peer();

        let mut table = LinkTable::new();
        let (id_a, _) = table.insert(peer, link_a);
        let (_id_b, _) = table.insert(peer, link_b.clone());

        // Remove first link — second should take over
        let peer_gone = table.remove_link(&peer, id_a);
        assert!(!peer_gone);
        assert!(table.get(&peer).is_some());
        assert!(Arc::ptr_eq(table.get(&peer).unwrap(), &link_b));
    }

    #[tokio::test]
    async fn link_table_remove_all_links() {
        let (link_a, _) = make_test_link_pair().await;
        let peer = link_a.remote_peer();

        let mut table = LinkTable::new();
        let (id_a, _) = table.insert(peer, link_a);

        let peer_gone = table.remove_link(&peer, id_a);
        assert!(peer_gone);
        assert!(table.get(&peer).is_none());
        assert!(!table.contains_key(&peer));
    }

    #[tokio::test]
    async fn link_table_iter_returns_best_links() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;
        let peer = link_a.remote_peer();

        let mut table = LinkTable::new();
        table.insert(peer, link_a.clone());
        table.insert(peer, link_b);

        let entries: Vec<_> = table.iter().collect();
        assert_eq!(entries.len(), 1); // one peer, one best link
        assert!(Arc::ptr_eq(entries[0].1, &link_a)); // first-added wins at equal score
    }
}
