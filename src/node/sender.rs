//! The one way a node puts a message on a link.
//!
//! Every send, from the node or from a task holding only a clone of this,
//! picks its next hop by the same rule, is accounted to the same bandwidth
//! limit and statistics (unless it is link upkeep, explicitly), and never
//! holds the link table locked while it waits on a link.

use super::*;

/// Which queue of the link a message goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Queue {
    /// High priority; dropped if the link is congested (channels recover).
    Data,
    /// High priority; waits for room instead of being dropped (one-shot
    /// control cells with no retransmission).
    Critical,
    /// Background; may wait to share a frame.
    Deferred,
}

/// Whether a message counts against the node's upload limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Budget {
    /// Overlay traffic: limited and counted.
    Limited,
    /// Keeping links and routing alive (keepalives, route updates, padding):
    /// counted, but never held back by the upload limit, which would starve
    /// the network of its own upkeep.
    Upkeep,
}

#[derive(Clone)]
pub(crate) struct Sender {
    links: Arc<Mutex<LinkTable>>,
    routing: Arc<Mutex<RoutingTable>>,
    bandwidth: Arc<crate::bandwidth::BandwidthLimiter>,
    stats: Arc<crate::stats::StatsRegistry>,
}

impl Sender {
    pub(crate) fn new(
        links: Arc<Mutex<LinkTable>>,
        routing: Arc<Mutex<RoutingTable>>,
        bandwidth: Arc<crate::bandwidth::BandwidthLimiter>,
        stats: Arc<crate::stats::StatsRegistry>,
    ) -> Self {
        Self {
            links,
            routing,
            bandwidth,
            stats,
        }
    }

    /// Send to a neighbour.
    pub(crate) async fn to_peer(&self, peer: &PeerId, data: &[u8], queue: Queue, budget: Budget) -> Result<()> {
        if budget == Budget::Limited {
            self.bandwidth.acquire_upload(data.len()).await;
        }
        // Clone the link out: the table is never locked across a send.
        let link = self
            .links
            .lock()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("no link to {:?}", peer)))?;
        self.stats.record_send(peer, data.len() as u64);
        match queue {
            Queue::Data => link.send_message(data).await,
            Queue::Critical => link.send_message_critical(data).await,
            Queue::Deferred => link.send_deferred(data).await,
        }
    }

    /// The next hop toward `dest` by the forwarding rule (a link to it, its
    /// routes, then `hints`), never back to `from`.
    pub(crate) async fn next_hop(&self, dest: &PeerId, hints: &[PeerId], from: Option<&PeerId>) -> Option<PeerId> {
        let linked: HashSet<PeerId> = self.links.lock().await.keys().copied().collect();
        self.routing
            .lock()
            .await
            .next_hop_hinted(dest, hints, |p| linked.contains(p) && Some(p) != from)
    }

    /// Send an overlay message toward `dest`, over the link if we have one,
    /// else by the forwarding rule with `hints`.
    pub(crate) async fn routed(&self, dest: &PeerId, hints: &[PeerId], data: &[u8]) -> Result<()> {
        let next = self.next_hop(dest, hints, None).await.ok_or(Error::NotFound)?;
        self.to_peer(&next, data, Queue::Data, Budget::Limited).await
    }
}
