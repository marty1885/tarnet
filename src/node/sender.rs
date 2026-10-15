//! The one way a node puts a message on a link.
//!
//! Every send, from the node or from a task holding only a clone of this,
//! picks its next hop by the same rule and never holds the link table locked
//! while it waits on a link. Accounting and throttling belong to link I/O.

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

#[derive(Clone)]
pub(crate) struct Sender {
    links: Arc<Mutex<LinkTable>>,
    routing: Arc<Mutex<RoutingTable>>,
}

impl Sender {
    /// One lifetime for outbound admission and the response. Dropping the
    /// caller cancels both; the caller's request guard owns registration.
    pub(super) async fn request_until<T>(
        &self,
        peers: &[PeerId],
        bytes: &[u8],
        response: oneshot::Receiver<T>,
        deadline: Instant,
    ) -> Option<T> {
        if deadline <= Instant::now() {
            return None;
        }
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let mut response = response;
            let send = async {
                for peer in peers {
                    let _ = self.to_peer(peer, bytes, Queue::Deferred).await;
                }
            };
            tokio::select! {
                result = &mut response => result.ok(),
                _ = send => response.await.ok(),
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// A batch may never outlive the state authorizing its replies.
    pub(super) async fn batch_until(&self, messages: Vec<(PeerId, Vec<u8>)>, deadline: Instant) {
        if deadline <= Instant::now() {
            return;
        }
        let _ = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            for (peer, bytes) in messages {
                let _ = self.to_peer(&peer, &bytes, Queue::Deferred).await;
            }
        })
        .await;
    }

    pub(crate) fn new(links: Arc<Mutex<LinkTable>>, routing: Arc<Mutex<RoutingTable>>) -> Self {
        Self { links, routing }
    }

    /// Send to a neighbour.
    pub(crate) async fn to_peer(&self, peer: &PeerId, data: &[u8], queue: Queue) -> Result<()> {
        // Clone the link out: the table is never locked across a send.
        let link = self
            .links
            .lock()
            .await
            .get(peer)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("no link to {:?}", peer)))?;
        match queue {
            Queue::Data => link.send_message(data).await,
            Queue::Critical => link.send_message_critical(data).await,
            Queue::Deferred => link.send_deferred(data).await,
        }
    }

    /// The next hop toward `dest` by the forwarding rule (a link to it, its
    /// routes, then `hints`), never back to `from`.
    pub(crate) async fn next_hop(
        &self,
        dest: &PeerId,
        hints: &[PeerId],
        from: Option<&PeerId>,
    ) -> Option<PeerId> {
        let linked: HashSet<PeerId> = self.links.lock().await.keys().copied().collect();
        self.routing
            .lock()
            .await
            .next_hop_hinted(dest, hints, |p| linked.contains(p) && Some(p) != from)
    }

    /// Send an overlay message toward `dest`, over the link if we have one,
    /// else by the forwarding rule with `hints`.
    pub(crate) async fn routed(&self, dest: &PeerId, hints: &[PeerId], data: &[u8]) -> Result<()> {
        let next = self
            .next_hop(dest, hints, None)
            .await
            .ok_or(Error::NotFound)?;
        self.to_peer(&next, data, Queue::Data).await
    }
}
