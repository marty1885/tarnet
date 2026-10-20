use std::collections::{BTreeMap, HashMap, HashSet};
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
}

impl LinkScore {
    fn new() -> Self {
        Self {
            ewma_rtt_us: 0,
            loss_rate: 0,
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
    /// The task reading this link: stopped when the link leaves the table,
    /// so a removed link delivers nothing more and its transport closes.
    recv_task: Option<tokio::task::AbortHandle>,
    /// When the next heartbeat / cover-traffic packet should fire on this
    /// link. Drawn from a Poisson process so an observer can't distinguish
    /// heartbeats from real traffic by timing alone.
    next_heartbeat_at: Instant,
}

/// Heartbeat scheduling parameters. Mean interval ~60s, clamped to
/// [HEARTBEAT_MIN, HEARTBEAT_MAX] so a draw is always in a sane range.
///
/// This is well below `node::KEEPALIVE_DEAD_TIMEOUT` so a healthy link sees
/// ~3 heartbeats per dead-timeout window — enough that the probability of
/// 3 consecutive losses on a genuinely live link is small.
pub const HEARTBEAT_MEAN: Duration = Duration::from_secs(60);
pub const HEARTBEAT_MIN: Duration = Duration::from_secs(20);
pub const HEARTBEAT_MAX: Duration = Duration::from_secs(120);

/// A link that has received nothing for this long is probed: its heartbeats
/// come every [PROBE_MIN, PROBE_MAX] instead of on the slow Poisson schedule,
/// so lost heartbeats (or lost replies) can't add up to a false link death.
/// Probing starts well before `node::KEEPALIVE_DEAD_TIMEOUT`.
pub const PROBE_AFTER: Duration = Duration::from_secs(60);
pub const PROBE_MIN: Duration = Duration::from_secs(3);
pub const PROBE_MAX: Duration = Duration::from_secs(6);

fn next_probe_delay() -> Duration {
    use rand::Rng;
    rand::thread_rng().gen_range(PROBE_MIN..=PROBE_MAX)
}

/// Draw the next heartbeat delay from an exponential distribution clamped to
/// [HEARTBEAT_MIN, HEARTBEAT_MAX].
fn next_heartbeat_delay() -> Duration {
    use rand::Rng;
    // Inverse-CDF: -mean * ln(1 - U) for U in (0, 1).
    let u: f64 = rand::thread_rng().gen_range(0.0_f64..1.0_f64);
    // Guard against u=0 (would yield ln(1)=0, fine) and u→1 (ln(0)=-inf).
    let u = u.min(0.999_999);
    let secs = -(HEARTBEAT_MEAN.as_secs_f64()) * (1.0 - u).ln();
    let d = Duration::from_secs_f64(secs);
    if d < HEARTBEAT_MIN {
        HEARTBEAT_MIN
    } else if d > HEARTBEAT_MAX {
        HEARTBEAT_MAX
    } else {
        d
    }
}

/// Manages multiple links to a single peer with scored failover.
///
/// Tracks all links, picks the best one as active, and promotes the next-best
/// when the active link dies. Hysteresis prevents flapping: a standby link
/// must beat the active link's score by >20% to trigger promotion.
struct PeerTransport {
    links: BTreeMap<LinkId, ScoredLink>,
    active: Option<LinkId>,
}

impl Drop for ScoredLink {
    fn drop(&mut self) {
        if let Some(task) = &self.recv_task {
            task.abort();
        }
    }
}

impl PeerTransport {
    fn new() -> Self {
        Self {
            links: BTreeMap::new(),
            active: None,
        }
    }

    /// Insert a new link under `id`. Returns whether the active link changed.
    fn add_link(&mut self, id: LinkId, link: Arc<PeerLink>) -> bool {

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
                next_heartbeat_at: Instant::now() + next_heartbeat_delay(),
                recv_task: None,
            },
        );

        self.recompute_active()
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
    // Observed RTT is display-only: peer batching/delay must not drive selection.
    // Only tests feed scores; loss measurement is not implemented.
    #[cfg(test)]
    fn update_score(&mut self, id: LinkId, rtt_us: u64, loss_rate: u8) {
        if let Some(sl) = self.links.get_mut(&id) {
            // EWMA with alpha=0.25: new = 0.75*old + 0.25*sample
            sl.score.ewma_rtt_us = (sl.score.ewma_rtt_us * 3 + rtt_us) / 4;
            sl.score.loss_rate = loss_rate;
        }
        self.recompute_active();
    }

    /// Mark a specific link as having received a message.
    fn touch_recv(&mut self, id: LinkId) {
        if let Some(sl) = self.links.get_mut(&id) {
            sl.last_recv = Instant::now();
        }
        // This link may just have been confirmed by the peer; if the active
        // one still isn't, switch.
        if self.active != Some(id) && self.active_link().is_some_and(|l| l.awaiting_peer()) {
            self.recompute_active();
        }
    }

    /// Links the peer never confirmed within `timeout` of the handshake.
    fn unconfirmed_links(&self, timeout: Duration) -> Vec<LinkId> {
        self.links
            .iter()
            .filter(|(_, sl)| sl.created_at.elapsed() >= timeout && sl.link.awaiting_peer()
                && sl.link.receive_activity().map_or(true, |at| at.elapsed() >= timeout))
            .map(|(&id, _)| id)
            .collect()
    }

    /// Return link IDs that haven't received any message within `timeout`.
    fn dead_links(&self, timeout: Duration) -> Vec<LinkId> {
        let now = Instant::now();
        self.links
            .iter()
            .filter(|(_, sl)| now.saturating_duration_since(sl.link.receive_activity().unwrap_or(sl.last_recv).max(sl.last_recv)) >= timeout)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Return links whose next heartbeat is due, bumping their schedule to a
    /// fresh draw from the Poisson process. Drains all currently-due links in
    /// one shot; callers should send a heartbeat on each.
    fn heartbeat_due(&mut self) -> Vec<(LinkId, Arc<PeerLink>)> {
        let now = Instant::now();
        let mut out = Vec::new();
        for (&id, sl) in self.links.iter_mut() {
            let received = sl.link.receive_activity().unwrap_or(sl.last_recv).max(sl.last_recv);
            let quiet = now.saturating_duration_since(received) >= PROBE_AFTER;
            if quiet {
                // Pull a far-off heartbeat in to probing cadence.
                sl.next_heartbeat_at = sl.next_heartbeat_at.min(now + PROBE_MAX);
            }
            if sl.next_heartbeat_at <= now {
                sl.next_heartbeat_at = now
                    + if quiet {
                        next_probe_delay()
                    } else {
                        next_heartbeat_delay()
                    };
                out.push((id, sl.link.clone()));
            }
        }
        out
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

        // Find the best (lowest score) link. A link the peer hasn't confirmed
        // yet (see `PeerLink::awaiting_peer`) ranks behind every confirmed one.
        let best_id = *self
            .links
            .iter()
            .min_by_key(|(_, sl)| (sl.link.awaiting_peer(), sl.score.score()))
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
                // An unconfirmed active link yields to any confirmed one.
                let current_score = self
                    .links
                    .get(&current_id)
                    .filter(|sl| {
                        !sl.link.awaiting_peer()
                            || self.links[&best_id].link.awaiting_peer()
                    })
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
    /// Observed response time, including peer batching/delay; zero if unknown/stale.
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
    maintenance_changed: Arc<tokio::sync::Notify>,
    routing_changed: Arc<tokio::sync::Notify>,
    peers: HashMap<PeerId, PeerTransport>,
    /// Link ids are never reused, whatever peer they belong to: an event
    /// naming a link that is gone can't be mistaken for a newer link.
    next_id: LinkId,
}

/// What [`LinkTable::remove_link`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removed {
    /// No such link (already removed): nothing changed.
    Unknown,
    /// The link is gone; the peer has others.
    Link,
    /// The link was the peer's last.
    Peer,
}

impl LinkTable {
    pub fn new() -> Self {
        Self {
            maintenance_changed: Arc::new(tokio::sync::Notify::new()),
            routing_changed: Arc::new(tokio::sync::Notify::new()),
            peers: HashMap::new(),
            next_id: 0,
        }
    }

    /// Add a link to a peer. Returns (LinkId, is_first_link_for_peer).
    pub fn insert(&mut self, peer: PeerId, link: Arc<PeerLink>) -> (LinkId, bool) {
        let link_id = self.next_id;
        self.next_id += 1;
        let pt = self.peers.entry(peer).or_insert_with(PeerTransport::new);
        let is_first = pt.is_empty();
        pt.add_link(link_id, link);
        self.maintenance_changed.notify_one();
        self.routing_changed.notify_one();
        (link_id, is_first)
    }

    /// Tie the task reading a link to the link's place in the table.
    pub fn set_recv_task(&mut self, peer: &PeerId, link_id: LinkId, task: tokio::task::AbortHandle) {
        match self.peers.get_mut(peer).and_then(|pt| pt.links.get_mut(&link_id)) {
            Some(sl) => sl.recv_task = Some(task),
            None => task.abort(),
        }
    }

    /// Remove a specific link (stopping its reader).
    pub fn remove_link(&mut self, peer: &PeerId, link_id: LinkId) -> Removed {
        let Some(pt) = self.peers.get_mut(peer) else {
            return Removed::Unknown;
        };
        if !pt.links.contains_key(&link_id) {
            return Removed::Unknown;
        }
        pt.remove_link(link_id);
        self.maintenance_changed.notify_one();
        self.routing_changed.notify_one();
        if pt.is_empty() {
            self.peers.remove(peer);
            return Removed::Peer;
        }
        Removed::Link
    }

    /// The ids of every link to `peer`.
    pub fn link_ids(&self, peer: &PeerId) -> Vec<LinkId> {
        self.peers
            .get(peer)
            .map(|pt| pt.links.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Get the best link to a peer (same signature as HashMap::get).
    pub fn get(&self, peer: &PeerId) -> Option<&Arc<PeerLink>> {
        self.peers.get(peer).and_then(|pt| pt.active_link())
    }

    /// Get a specific link to a peer by id. Needed when a reply must go out on
    /// the exact link a message arrived on (e.g. a rekey), not merely the
    /// currently-active one.
    pub fn get_link(&self, peer: &PeerId, link_id: LinkId) -> Option<Arc<PeerLink>> {
        self.peers
            .get(peer)
            .and_then(|pt| pt.links.get(&link_id))
            .map(|sl| sl.link.clone())
    }

    /// Every link across all peers (not just the active one per peer).
    pub fn all_links(&self) -> Vec<Arc<PeerLink>> {
        self.peers
            .values()
            .flat_map(|pt| pt.links.values().map(|sl| sl.link.clone()))
            .collect()
    }

    /// Iterate (peer_id, best_link) for all connected peers.
    /// Same shape as HashMap::iter() — callers don't change.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Arc<PeerLink>)> {
        self.peers
            .iter()
            .filter_map(|(pid, pt)| pt.active_link().map(|link| (pid, link)))
    }

    /// True when no peers are connected at all.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
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

    /// Record that we received a message on a specific link. False if the
    /// link is no longer in the table (its message is stale).
    pub fn touch_recv(&mut self, peer: &PeerId, link_id: LinkId) -> bool {
        match self.peers.get_mut(peer) {
            Some(pt) if pt.links.contains_key(&link_id) => {
                let active = pt.active;
                pt.touch_recv(link_id);
                if pt.active != active { self.routing_changed.notify_one(); }
                true
            }
            _ => false,
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

    /// Links whose handshake the peer never confirmed within `timeout`: the
    /// peer gave up on them, so they only black-hole traffic.
    pub fn unconfirmed_links(&self, timeout: Duration) -> Vec<(PeerId, LinkId)> {
        let mut result = Vec::new();
        for (&peer, pt) in &self.peers {
            for id in pt.unconfirmed_links(timeout) {
                result.push((peer, id));
            }
        }
        result
    }

    /// Drain all links whose next heartbeat is due. Each returned link gets
    /// its next-fire time rescheduled to a fresh exponential draw.
    pub fn heartbeat_due(&mut self) -> Vec<(PeerId, LinkId, Arc<PeerLink>)> {
        let mut result = Vec::new();
        for (&peer, pt) in self.peers.iter_mut() {
            for (id, link) in pt.heartbeat_due() {
                result.push((peer, id, link));
            }
        }
        result
    }

    pub(crate) fn maintenance_notify(&self) -> Arc<tokio::sync::Notify> {
        self.maintenance_changed.clone()
    }

    #[cfg(test)]
    pub(crate) fn reschedule_heartbeat_for_test(&mut self, peer: &PeerId, id: LinkId, at: Instant) {
        self.peers.get_mut(peer).unwrap().links.get_mut(&id).unwrap().next_heartbeat_at = at;
        self.maintenance_changed.notify_one();
    }

    pub(crate) fn routing_notify(&self) -> Arc<tokio::sync::Notify> {
        self.routing_changed.clone()
    }

    /// Earliest heartbeat, quiet-to-probing transition, or liveness expiry.
    /// Activity only postpones these deadlines, so traffic need not wake the
    /// scheduler: it can recompute when its previously scheduled timer fires.
    pub(crate) fn next_maintenance_at(
        &self,
        dead_timeout: Duration,
        unconfirmed_timeout: Duration,
        reported: &HashSet<(PeerId, LinkId)>,
    ) -> Option<Instant> {
        let now = Instant::now();
        self.peers.iter().flat_map(|(peer, pt)| {
            pt.links.iter().filter_map(|(id, sl)| {
                if reported.contains(&(*peer, *id)) { return None; }
                let activity = sl.link.receive_activity();
                let received = activity.unwrap_or(sl.last_recv).max(sl.last_recv);
                let mut at = sl.next_heartbeat_at.min(received + dead_timeout);
                let probe_at = received + PROBE_AFTER;
                if probe_at > now { at = at.min(probe_at); }
                if sl.link.awaiting_peer() {
                    let expires = (sl.created_at + unconfirmed_timeout)
                        .max(activity.map_or(sl.created_at, |at| at) + unconfirmed_timeout);
                    at = at.min(expires);
                }
                Some(at)
            })
        }).min()
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
                        rtt_us: sl.link.observed_rtt_us(),
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

    #[tokio::test]
    async fn maintenance_deadlines_cover_probe_transition_and_reported_links() {
        let mut table = LinkTable::new();
        let mut reported = HashSet::new();
        let dead = Duration::from_secs(180);
        let unconfirmed = Duration::from_secs(3600);
        assert!(table.next_maintenance_at(dead, unconfirmed, &reported).is_none());
        let (link, _remote) = make_test_link_pair().await;
        let peer = link.remote_peer();
        let (id, _) = table.insert(peer, link);
        let now = Instant::now();
        let sl = table.peers.get_mut(&peer).unwrap().links.get_mut(&id).unwrap();
        sl.last_recv = now;
        sl.next_heartbeat_at = now + HEARTBEAT_MAX;
        assert_eq!(table.next_maintenance_at(dead, unconfirmed, &reported), Some(now + PROBE_AFTER));
        table.peers.get_mut(&peer).unwrap().links.get_mut(&id).unwrap().last_recv = now - PROBE_AFTER;
        table.heartbeat_due();
        let next = table.next_maintenance_at(dead, unconfirmed, &reported).unwrap();
        assert!(next > now);
        assert!(next <= Instant::now() + PROBE_MAX);
        reported.insert((peer, id));
        assert!(table.next_maintenance_at(dead, unconfirmed, &reported).is_none());
    }

    /// Drive a full in-band rekey end-to-end over a real link pair and confirm
    /// traffic keeps flowing both ways under the rotated keys. Mirrors what the
    /// node receive loop does: shuttle the Rekey frames to `handle_rekey_msg`.
    #[tokio::test]
    async fn in_band_rekey_end_to_end() {
        use crate::wire::{KeepaliveMsg, MessageType, RekeyMsg, WireMessage};

        let (a, b) = make_test_link_pair().await; // a = initiator, b = responder

        // a initiates: sends its ephemeral KEM pubkey as a Rekey frame.
        a.rekey_initiate().await.unwrap();

        // b receives the request and answers with the ciphertext.
        let req = b.recv_message().await.unwrap();
        let req = WireMessage::decode(&req).unwrap();
        assert_eq!(req.msg_type, MessageType::Rekey);
        b.handle_rekey_msg(&RekeyMsg::from_bytes(&req.payload).unwrap())
            .await
            .unwrap();

        // a receives the response and completes the rekey.
        let resp = a.recv_message().await.unwrap();
        let resp = WireMessage::decode(&resp).unwrap();
        assert_eq!(resp.msg_type, MessageType::Rekey);
        a.handle_rekey_msg(&RekeyMsg::from_bytes(&resp.payload).unwrap())
            .await
            .unwrap();

        // Post-rekey: a→b and b→a both decrypt under the new keys. (Frames are
        // padded before encryption, so decode rather than compare raw bytes.)
        let frame = KeepaliveMsg {
            ping_id: None,
            probe_nonce: None,
            padding: Vec::new(),
        }
        .to_wire()
        .encode();
        a.send_message(&frame).await.unwrap();
        let got = WireMessage::decode(&b.recv_message().await.unwrap()).unwrap();
        assert_eq!(got.msg_type, MessageType::Keepalive);
        b.send_message(&frame).await.unwrap();
        let got = WireMessage::decode(&a.recv_message().await.unwrap()).unwrap();
        assert_eq!(got.msg_type, MessageType::Keepalive);
    }

    /// A rekey whose request and reply are each lost once still completes,
    /// and the link carries traffic both ways throughout.
    #[tokio::test]
    async fn rekey_survives_lost_request_and_reply() {
        use crate::wire::{KeepaliveMsg, MessageType, RekeyMsg, WireMessage};

        let (a, b) = make_test_link_pair().await; // a = initiator
        let frame = KeepaliveMsg {
            ping_id: None,
            probe_nonce: None,
            padding: Vec::new(),
        }
        .to_wire()
        .encode();
        async fn recv_type(l: &PeerLink) -> WireMessage {
            WireMessage::decode(&l.recv_message().await.unwrap()).unwrap()
        }

        // Request lost.
        a.rekey_initiate().await.unwrap();
        assert_eq!(recv_type(&b).await.msg_type, MessageType::Rekey);
        // Too early to retry: no new request goes out.
        a.rekey_initiate().await.unwrap();
        a.send_message(&frame).await.unwrap();
        assert_eq!(recv_type(&b).await.msg_type, MessageType::Keepalive);

        // Retry after the interval: the identical request; b answers, but the
        // reply is lost.
        tokio::time::sleep(crate::link::REKEY_RETRY_INTERVAL).await;
        a.rekey_initiate().await.unwrap();
        let req = recv_type(&b).await;
        let req = RekeyMsg::from_bytes(&req.payload).unwrap();
        b.handle_rekey_msg(&req).await.unwrap();
        assert_eq!(recv_type(&a).await.msg_type, MessageType::Rekey);

        // b is still sending under the old key, so a hears it fine.
        b.send_message(&frame).await.unwrap();
        assert_eq!(recv_type(&a).await.msg_type, MessageType::Keepalive);
        a.send_message(&frame).await.unwrap();
        assert_eq!(recv_type(&b).await.msg_type, MessageType::Keepalive);

        // Next retry: b resends the same reply, a installs.
        tokio::time::sleep(crate::link::REKEY_RETRY_INTERVAL).await;
        a.rekey_initiate().await.unwrap();
        b.handle_rekey_msg(&RekeyMsg::from_bytes(&recv_type(&b).await.payload).unwrap())
            .await
            .unwrap();
        let resp = recv_type(&a).await;
        a.handle_rekey_msg(&RekeyMsg::from_bytes(&resp.payload).unwrap())
            .await
            .unwrap();
        assert_eq!(a.key_epoch().await, 1);
        assert!(!a.needs_rekey().await);

        // A duplicate reply is ignored.
        a.handle_rekey_msg(&RekeyMsg::from_bytes(&resp.payload).unwrap())
            .await
            .unwrap();

        // a's first new-key frame switches b over; both directions work.
        a.send_message(&frame).await.unwrap();
        assert_eq!(recv_type(&b).await.msg_type, MessageType::Keepalive);
        assert_eq!(b.key_epoch().await, 1);
        b.send_message(&frame).await.unwrap();
        assert_eq!(recv_type(&a).await.msg_type, MessageType::Keepalive);

        // A late copy of the request is ignored, not re-answered.
        b.handle_rekey_msg(&req).await.unwrap();
        assert_eq!(b.key_epoch().await, 1);
    }

    #[tokio::test]
    async fn local_download_pause_does_not_reap_a_live_or_unconfirmed_link() {
        use crate::{bandwidth::BandwidthLimiter, stats::StatsRegistry, transport::metered::MeteredTransport};
        use crate::wire::KeepaliveMsg;
        let (a, b) = mem_transport_pair();
        let budget = Arc::new(BandwidthLimiter::new(0, 0));
        let b = MeteredTransport::wrap(Box::new(b), budget.clone(), Arc::new(StatsRegistry::new()));
        let ka = Keypair::generate();
        let kb = Keypair::generate();
        let (a, b) = tokio::join!(PeerLink::initiator(Box::new(a), &ka, None), PeerLink::responder(b, &kb));
        let a = a.unwrap();
        let b = Arc::new(b.unwrap());
        let mut pt = PeerTransport::new();
        pt.add_link(0, b.clone());
        let timeout = Duration::from_millis(2);
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(pt.dead_links(timeout), vec![0]);
        budget.set_rates(0, 1);
        budget.acquire_download(1).await;
        let msg = KeepaliveMsg {
            ping_id: None,
            probe_nonce: None,
            padding: vec![0; 8],
        }
        .to_wire()
        .encode();
        a.send_message(&msg).await.unwrap();
        {
            let receive = b.recv_message();
            tokio::pin!(receive);
            tokio::select! {
                _ = &mut receive => panic!("download did not throttle"),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            assert!(pt.dead_links(timeout).is_empty());
            assert!(pt.unconfirmed_links(timeout).is_empty());
        }
        // Cancelling a local wait resumes the clock from the authenticated
        // frame, rather than from the earlier period of silence.
        assert!(pt.dead_links(timeout).is_empty());
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(pt.dead_links(timeout), vec![0]);
    }

    // ── PeerTransport unit tests ──

    /// A responder link the initiator never confirmed must not stay the way
    /// we reach the peer once a working link exists, and gets reaped.
    #[tokio::test]
    async fn unconfirmed_link_yields_and_is_reaped() {
        let (_, half_open) = make_test_link_pair().await;
        let (_, second) = make_test_link_pair().await;
        half_open.set_awaiting_peer(true);
        second.set_awaiting_peer(true);

        let mut pt = PeerTransport::new();
        let id0 = 0;
        pt.add_link(id0, half_open.clone());
        let id1 = 1;
        pt.add_link(id1, second.clone());
        assert_eq!(pt.active, Some(id0));

        // The redialled link hears from the peer: it takes over at once.
        second.set_awaiting_peer(false);
        pt.touch_recv(id1);
        assert_eq!(pt.active, Some(id1));

        // A confirmed link is preferred from the start over an unconfirmed one.
        let mut pt2 = PeerTransport::new();
        pt2.add_link(0, half_open.clone());
        assert!(pt2.add_link(1, second.clone()));
        assert_eq!(pt2.active, Some(1));

        assert_eq!(pt.unconfirmed_links(Duration::ZERO), vec![id0]);
        assert!(pt.unconfirmed_links(Duration::from_secs(3600)).is_empty());
    }

    #[tokio::test]
    async fn quiet_link_is_probed_quickly() {
        let (link, _) = make_test_link_pair().await;
        let mut pt = PeerTransport::new();
        let id = 0;
        pt.add_link(id, link);
        let now = Instant::now();

        // A link that just heard from its peer keeps its slow schedule.
        pt.links.get_mut(&id).unwrap().next_heartbeat_at = now + HEARTBEAT_MAX;
        assert!(pt.heartbeat_due().is_empty());
        assert!(pt.links[&id].next_heartbeat_at > now + PROBE_MAX);

        // Quiet past PROBE_AFTER: the next heartbeat is pulled in...
        let Some(quiet_since) = now.checked_sub(PROBE_AFTER + Duration::from_secs(1)) else {
            return; // monotonic clock too young to back-date
        };
        pt.links.get_mut(&id).unwrap().last_recv = quiet_since;
        assert!(pt.heartbeat_due().is_empty());
        assert!(pt.links[&id].next_heartbeat_at <= Instant::now() + PROBE_MAX);

        // ...and once due, the following one is a probe interval away too.
        pt.links.get_mut(&id).unwrap().next_heartbeat_at = Instant::now();
        assert_eq!(pt.heartbeat_due().len(), 1);
        assert!(pt.links[&id].next_heartbeat_at <= Instant::now() + PROBE_MAX);
    }

    #[tokio::test]
    async fn add_two_links_first_is_active() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        assert!(pt.add_link(0, link_a.clone())); // first link becomes active
        assert!(!pt.add_link(1, link_b.clone())); // equal score, no promotion (hysteresis)

        // Active should still be the first link
        assert!(Arc::ptr_eq(pt.active_link().unwrap(), &link_a));
    }

    #[tokio::test]
    async fn remove_active_promotes_standby() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let id0 = 0;
        pt.add_link(id0, link_a);
        let _id1 = 1;
        pt.add_link(_id1, link_b.clone());

        pt.remove_link(id0);

        // link_b should now be active
        assert!(Arc::ptr_eq(pt.active_link().unwrap(), &link_b));
    }

    #[tokio::test]
    async fn hysteresis_prevents_flapping() {
        let (link_a, _) = make_test_link_pair().await;
        let (link_b, _) = make_test_link_pair().await;

        let mut pt = PeerTransport::new();
        let id0 = 0;
        pt.add_link(id0, link_a.clone());
        let id1 = 1;
        pt.add_link(id1, link_b);

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
        let id0 = 0;
        pt.add_link(id0, link_a);
        let id1 = 1;
        pt.add_link(id1, link_b.clone());

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
        let id0 = 0;
        pt.add_link(id0, link_a);
        let id1 = 1;
        pt.add_link(id1, link_b);

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
        assert_eq!(table.remove_link(&peer, id_a), Removed::Link);
        assert!(table.get(&peer).is_some());
        assert!(Arc::ptr_eq(table.get(&peer).unwrap(), &link_b));
    }

    #[tokio::test]
    async fn link_table_remove_all_links() {
        let (link_a, _) = make_test_link_pair().await;
        let peer = link_a.remote_peer();

        let mut table = LinkTable::new();
        let (id_a, _) = table.insert(peer, link_a);

        assert_eq!(table.remove_link(&peer, id_a), Removed::Peer);
        assert_eq!(table.remove_link(&peer, id_a), Removed::Unknown);
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
