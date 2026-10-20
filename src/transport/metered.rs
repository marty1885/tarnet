//! Shared node I/O policy, independent of the physical transport.
//!
//! Counts transport message bytes (including link encryption, padding and
//! handshake/repair traffic). TCP/WebSocket/IP framing below Transport is not
//! included. Unauthenticated handshake traffic is counted globally only.
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;

use super::{Discovery, Transport};
use crate::{
    bandwidth::BandwidthLimiter,
    stats::StatsRegistry,
    types::{PeerId, Result},
};

struct Activity {
    last: Instant,
    paused: Option<Instant>,
}

pub(crate) struct MeteredTransport {
    inner: Box<dyn Transport>,
    budget: Arc<BandwidthLimiter>,
    stats: Arc<StatsRegistry>,
    peer: Mutex<Option<PeerId>>,
    activity: Mutex<Activity>,
}

impl MeteredTransport {
    pub(crate) fn wrap(
        inner: Box<dyn Transport>,
        budget: Arc<BandwidthLimiter>,
        stats: Arc<StatsRegistry>,
    ) -> Box<dyn Transport> {
        Box::new(Self {
            inner,
            budget,
            stats,
            peer: Mutex::new(None),
            activity: Mutex::new(Activity {
                last: Instant::now(),
                paused: None,
            }),
        })
    }

    async fn received(&self, bytes: usize) {
        self.stats
            .record_link_recv(self.peer.lock().unwrap().as_ref(), bytes as u64);
        self.activity.lock().unwrap().paused = Some(Instant::now());
        let _pause = ReceivePause(&self.activity);
        self.budget.acquire_download(bytes).await;
    }

    async fn transmit(&self, data: &[u8], control: bool) -> Result<()> {
        self.budget.acquire_frame(data.len(), control).await;
        self.inner.send(data).await?;
        self.stats
            .record_link_send(self.peer.lock().unwrap().as_ref(), data.len() as u64);
        Ok(())
    }
}

/// Cancelling a receive must also release its local liveness pause.
struct ReceivePause<'a>(&'a Mutex<Activity>);
impl Drop for ReceivePause<'_> {
    fn drop(&mut self) {
        let mut activity = self.0.lock().unwrap();
        if let Some(start) = activity.paused.take() {
            activity.last += start.elapsed();
        }
    }
}

#[async_trait]
impl Transport for MeteredTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.transmit(data, true).await
    }
    async fn send_frame(&self, data: &[u8], control: bool) -> Result<()> {
        self.transmit(data, control).await
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.recv(buf).await?;
        self.received(n).await;
        Ok(n)
    }
    fn authenticated(&self, peer: PeerId) {
        *self.peer.lock().unwrap() = Some(peer);
        self.activity.lock().unwrap().last = Instant::now();
    }
    fn authenticated_frame(&self) {
        self.activity.lock().unwrap().last = Instant::now();
    }
    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.recv_frame(buf).await?;
        self.stats
            .record_link_recv(self.peer.lock().unwrap().as_ref(), n as u64);
        Ok(n)
    }
    async fn deliver_frame(&self, bytes: usize, authenticated: bool) {
        if authenticated {
            self.activity.lock().unwrap().paused = Some(Instant::now());
            let _pause = ReceivePause(&self.activity);
            self.budget.acquire_download(bytes).await;
        } else {
            self.budget.acquire_download(bytes).await;
        }
    }
    fn receive_activity(&self) -> Option<Instant> {
        let activity = self.activity.lock().unwrap();
        Some(if activity.paused.is_some() {
            Instant::now()
        } else {
            activity.last
        })
    }
    fn mtu(&self) -> usize {
        self.inner.mtu()
    }
    fn is_reliable(&self) -> bool {
        self.inner.is_reliable()
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn bandwidth_hint(&self) -> Option<u64> {
        match (self.inner.bandwidth_hint(), self.budget.rate_hint()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

pub(crate) struct MeteredDiscovery {
    inner: Box<dyn Discovery>,
    budget: Arc<BandwidthLimiter>,
    stats: Arc<StatsRegistry>,
}
impl MeteredDiscovery {
    pub(crate) fn new(
        inner: Box<dyn Discovery>,
        budget: Arc<BandwidthLimiter>,
        stats: Arc<StatsRegistry>,
    ) -> Self {
        Self {
            inner,
            budget,
            stats,
        }
    }
    fn wrap(&self, transport: Box<dyn Transport>) -> Box<dyn Transport> {
        MeteredTransport::wrap(transport, self.budget.clone(), self.stats.clone())
    }
}
#[async_trait]
impl Discovery for MeteredDiscovery {
    fn supports_address(&self, addr: &str) -> bool {
        self.inner.supports_address(addr)
    }
    async fn accept(&self) -> Result<Box<dyn Transport>> {
        Ok(self.wrap(self.inner.accept().await?))
    }
    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        Ok(self.wrap(self.inner.connect(addr).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Error;
    use std::time::Duration;
    use tokio::sync::mpsc;

    struct Memory {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }
    fn pair() -> (Box<dyn Transport>, Box<dyn Transport>) {
        let (a, ar) = mpsc::unbounded_channel();
        let (b, br) = mpsc::unbounded_channel();
        (
            Box::new(Memory {
                tx: a,
                rx: tokio::sync::Mutex::new(br),
            }),
            Box::new(Memory {
                tx: b,
                rx: tokio::sync::Mutex::new(ar),
            }),
        )
    }
    #[async_trait]
    impl Transport for Memory {
        async fn send(&self, data: &[u8]) -> Result<()> {
            self.tx.send(data.to_vec()).map_err(|_| Error::NotFound)
        }
        async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            let bytes = self.rx.lock().await.recv().await.ok_or(Error::NotFound)?;
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
        fn mtu(&self) -> usize {
            65536
        }
        fn is_reliable(&self) -> bool {
            true
        }
        fn name(&self) -> &'static str {
            "memory"
        }
    }

    #[tokio::test]
    async fn links_share_one_total_budget_and_control_does_not_bypass_it() {
        let budget = Arc::new(BandwidthLimiter::new(1000, 0));
        let stats = Arc::new(StatsRegistry::new());
        let (a, _ar) = pair();
        let (b, _br) = pair();
        let a = MeteredTransport::wrap(a, budget.clone(), stats.clone());
        let b = MeteredTransport::wrap(b, budget, stats.clone());
        a.send_frame(&[0; 900], false).await.unwrap();
        // Data cannot spend the 100-byte control reserve.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), b.send_frame(&[0; 100], false))
                .await
                .is_err()
        );
        b.send_frame(&[0; 100], true).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), b.send_frame(&[0; 100], true))
                .await
                .is_err()
        );
        assert_eq!(stats.traffic_summary().bytes_up.total, 1000);
    }

    #[tokio::test]
    async fn rate_reload_wakes_a_blocked_frame() {
        let budget = Arc::new(BandwidthLimiter::new(1, 0));
        let stats = Arc::new(StatsRegistry::new());
        let (a, _b) = pair();
        let a = MeteredTransport::wrap(a, budget.clone(), stats);
        a.send(&[0]).await.unwrap();
        let send = tokio::spawn(async move { a.send_frame(&[0; 256], false).await });
        tokio::task::yield_now().await;
        assert!(!send.is_finished());
        budget.set_rates(0, 0);
        tokio::time::timeout(Duration::from_millis(100), send)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn received_bytes_are_counted_before_delivery_and_local_pause_is_cancel_safe() {
        let budget = Arc::new(BandwidthLimiter::new(0, 1));
        budget.acquire_download(1).await;
        let stats = Arc::new(StatsRegistry::new());
        let (a, b) = pair();
        let b = MeteredTransport::wrap(b, budget, stats.clone());
        let peer = PeerId([3; 32]);
        b.authenticated(peer);
        a.send(&[7; 64]).await.unwrap();
        let mut buf = [0; 128];
        let before = b.receive_activity().unwrap();
        let n = b.recv_frame(&mut buf).await.unwrap();
        assert_eq!(n, 64);
        {
            let delivery = b.deliver_frame(n, true);
            tokio::pin!(delivery);
            tokio::select! {
                _ = &mut delivery => panic!("download escaped the total limit"),
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            assert_eq!(stats.peer_traffic(&peer).bytes_down.total, 64);
            assert!(b.receive_activity().unwrap() > before);
        }
        // Cancelling a delivery releases its local pause.
        let resumed = b.receive_activity().unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(b.receive_activity().unwrap(), resumed);
    }

    #[tokio::test]
    async fn rejected_frame_does_not_extend_authenticated_liveness() {
        let budget = Arc::new(BandwidthLimiter::new(0, 1));
        budget.acquire_download(1).await;
        let (a, b) = pair();
        let b = MeteredTransport::wrap(b, budget, Arc::new(StatsRegistry::new()));
        b.authenticated(PeerId([3; 32]));
        let before = b.receive_activity().unwrap();
        a.send(&[7; 64]).await.unwrap();
        let mut buf = [0; 128];
        let n = b.recv_frame(&mut buf).await.unwrap();
        let delivery = b.deliver_frame(n, false);
        tokio::pin!(delivery);
        tokio::select! {
            _ = &mut delivery => panic!("invalid frame unexpectedly cleared the limit"),
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        assert_eq!(b.receive_activity().unwrap(), before);
    }

    #[tokio::test]
    async fn handshake_padding_and_encrypted_frames_are_accounted_once() {
        use crate::{identity::Keypair, link::PeerLink, wire::KeepaliveMsg};
        let stats_a = Arc::new(StatsRegistry::new());
        let stats_b = Arc::new(StatsRegistry::new());
        let (a, b) = pair();
        let a = MeteredTransport::wrap(a, Arc::new(BandwidthLimiter::new(0, 0)), stats_a.clone());
        let b = MeteredTransport::wrap(b, Arc::new(BandwidthLimiter::new(0, 0)), stats_b.clone());
        let ka = Keypair::generate();
        let kb = Keypair::generate();
        let (a, b) = tokio::join!(
            PeerLink::initiator(a, &ka, None),
            PeerLink::responder(b, &kb)
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let handshake = stats_a.traffic_summary().bytes_up.total;
        assert!(handshake > 0);
        let msg = KeepaliveMsg {
            ping_id: None,
            probe_nonce: None,
            padding: vec![4; 73],
        }
        .to_wire()
        .encode();
        a.send_message(&msg).await.unwrap();
        assert_eq!(b.recv_message().await.unwrap(), msg);
        let sent = stats_a.traffic_summary().bytes_up.total - handshake;
        assert!(
            sent > msg.len() as u64,
            "frame padding/encryption were omitted"
        );
        assert_eq!(stats_a.peer_traffic(&kb.peer_id()).bytes_up.total, sent);
        assert_eq!(stats_b.peer_traffic(&ka.peer_id()).bytes_down.total, sent);
        let before = stats_a.traffic_summary().bytes_up.total;
        stats_a.record_relay();
        assert_eq!(
            stats_a.traffic_summary().bytes_up.total,
            before,
            "relay bytes counted twice"
        );
    }
}
