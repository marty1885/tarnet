//! Adversarial transport wrapper for testing.
//!
//! Wraps any `Transport` + `Discovery` and applies configurable packet-level
//! disruption: random drops, random per-packet delays (which reorder), or
//! both.  Sits below the link crypto layer so the disruption looks like a
//! flaky network to the node.
//!
//! The policy applies from the first packet: the link handshake retransmits
//! on unreliable transports and must survive it like everything else.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::prelude::*;
use rand::rngs::StdRng;
use tokio::sync::{mpsc, Mutex};

use super::{Discovery, Transport};
use crate::types::{Error, Result};

/// A switch that cuts every link of a `FirewallDiscovery`, as if its cable
/// were pulled with connection resets: open transports fail, and new ones
/// can't be made until it is restored.
#[derive(Default)]
pub struct LinkCut {
    cut: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl LinkCut {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn restore(&self) {
        self.cut.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cut(&self) -> bool {
        self.cut.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn check(&self) -> Result<()> {
        if self.is_cut() {
            return Err(Error::Wire("link cut".into()));
        }
        Ok(())
    }
}

/// What the firewall does to each packet.
#[derive(Clone, Debug)]
pub enum FirewallPolicy {
    /// Drop each packet independently with this probability.
    Drop { rate: f64 },
    /// Delay each packet by a random duration up to `max`.
    Delay { max: Duration },
    /// Combine drop + delay: surviving packets get a random delay.
    DropAndDelay { drop_rate: f64, max_delay: Duration },
    /// A slow serial line (HC-12-class radio): each packet occupies the line
    /// for `len / bytes_per_sec` before it arrives, packets queue behind each
    /// other, and each is lost with `drop_rate` after its airtime. The
    /// transport reports the rate as its bandwidth hint.
    RateLimit { bytes_per_sec: u64, drop_rate: f64 },
}

/// Wraps a `Transport`, applying a `FirewallPolicy` to both send and recv.
///
/// Every packet is delayed independently (its own timer), so packets overtake
/// each other the way they do on a real multi-path network: delays reorder,
/// they don't just add latency.
pub struct FirewallTransport {
    inner: Arc<dyn Transport>,
    shared: Arc<Shared>,
    cut: Option<Arc<LinkCut>>,
    /// Packets received from `inner` that survived the policy, in the order
    /// their delays expired.
    inbound: Mutex<mpsc::Receiver<Result<Vec<u8>>>>,
    pump: tokio::task::JoinHandle<()>,
}

struct Shared {
    policy: FirewallPolicy,
    rng: std::sync::Mutex<StdRng>,
    /// Held while a packet is on a rate-limited line.
    line: Mutex<()>,
}

/// Largest packet the recv pump will read from the wrapped transport.
const PUMP_BUFFER: usize = 1 << 20;

impl Shared {
    /// `None` to drop the packet, else how long to hold it.
    fn verdict(&self) -> Option<Duration> {
        let (rate, max) = match &self.policy {
            FirewallPolicy::Drop { rate } => (*rate, Duration::ZERO),
            FirewallPolicy::Delay { max } => (0.0, *max),
            FirewallPolicy::DropAndDelay {
                drop_rate,
                max_delay,
            } => (*drop_rate, *max_delay),
            FirewallPolicy::RateLimit { drop_rate, .. } => (*drop_rate, Duration::ZERO),
        };
        let mut rng = self.rng.lock().unwrap();
        if rate > 0.0 && rng.gen::<f64>() < rate {
            return None;
        }
        if max.is_zero() {
            return Some(Duration::ZERO);
        }
        Some(Duration::from_millis(
            rng.gen_range(0..=max.as_millis() as u64),
        ))
    }
}

impl FirewallTransport {
    pub fn new(inner: Box<dyn Transport>, policy: FirewallPolicy, seed: u64) -> Self {
        Self::with_cut(inner, policy, seed, None)
    }

    pub fn with_cut(
        inner: Box<dyn Transport>,
        policy: FirewallPolicy,
        seed: u64,
        cut: Option<Arc<LinkCut>>,
    ) -> Self {
        let inner: Arc<dyn Transport> = Arc::from(inner);
        let shared = Arc::new(Shared {
            policy,
            rng: std::sync::Mutex::new(StdRng::seed_from_u64(seed)),
            line: Mutex::new(()),
        });
        let (tx, rx) = mpsc::channel(1024);
        let pump = tokio::spawn(Self::pump(inner.clone(), shared.clone(), tx, cut.clone()));
        Self {
            inner,
            shared,
            cut,
            inbound: Mutex::new(rx),
            pump,
        }
    }

    /// Read from the wrapped transport and release each surviving packet
    /// after its own delay.
    async fn pump(
        inner: Arc<dyn Transport>,
        shared: Arc<Shared>,
        tx: mpsc::Sender<Result<Vec<u8>>>,
        cut: Option<Arc<LinkCut>>,
    ) {
        let mut buf = vec![0u8; PUMP_BUFFER];
        loop {
            let received = match &cut {
                Some(cut) => {
                    let cut_now = cut.notify.notified();
                    if let Err(e) = cut.check() {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                    tokio::select! {
                        r = inner.recv(&mut buf) => r,
                        _ = cut_now => Err(Error::Wire("link cut".into())),
                    }
                }
                None => inner.recv(&mut buf).await,
            };
            let n = match received {
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };
            // A rate-limited line loses packets on the sending side only.
            let verdict = match shared.policy {
                FirewallPolicy::RateLimit { .. } => Some(Duration::ZERO),
                _ => shared.verdict(),
            };
            let Some(delay) = verdict else {
                continue; // dropped
            };
            let packet = buf[..n].to_vec();
            if delay.is_zero() {
                if tx.send(Ok(packet)).await.is_err() {
                    return;
                }
            } else {
                let tx = tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx.send(Ok(packet)).await;
                });
            }
        }
    }
}

impl Drop for FirewallTransport {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[async_trait]
impl Transport for FirewallTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        if let Some(cut) = &self.cut {
            cut.check()?;
        }
        if let FirewallPolicy::RateLimit { bytes_per_sec, .. } = self.shared.policy {
            let _line = self.shared.line.lock().await;
            let airtime = Duration::from_secs_f64(data.len() as f64 / bytes_per_sec.max(1) as f64);
            tokio::time::sleep(airtime).await;
            if self.shared.verdict().is_none() {
                return Ok(());
            }
            return self.inner.send(data).await;
        }
        let Some(delay) = self.shared.verdict() else {
            // Silently eat the packet — looks like network loss
            return Ok(());
        };
        if delay.is_zero() {
            return self.inner.send(data).await;
        }
        let inner = self.inner.clone();
        let data = data.to_vec();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = inner.send(&data).await;
        });
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let packet = self
            .inbound
            .lock()
            .await
            .recv()
            .await
            .unwrap_or_else(|| Err(Error::Wire("firewall transport closed".into())))?;
        if packet.len() > buf.len() {
            return Err(Error::Wire(format!(
                "message {} bytes exceeds buffer {}",
                packet.len(),
                buf.len()
            )));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn mtu(&self) -> usize {
        self.inner.mtu()
    }

    fn is_reliable(&self) -> bool {
        // The wrapped transport might be TCP (reliable), but the firewall
        // makes it unreliable from the node's perspective.
        false
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn bandwidth_hint(&self) -> Option<u64> {
        match self.shared.policy {
            FirewallPolicy::RateLimit { bytes_per_sec, .. } => Some(bytes_per_sec),
            _ => self.inner.bandwidth_hint(),
        }
    }
}

/// Wraps a `Discovery`, applying a `FirewallPolicy` to every transport
/// it produces (both accepted and connected).
pub struct FirewallDiscovery {
    inner: Box<dyn Discovery>,
    policy: FirewallPolicy,
    seed_counter: Mutex<u64>,
    cut: Option<Arc<LinkCut>>,
}

impl FirewallDiscovery {
    pub fn new(inner: Box<dyn Discovery>, policy: FirewallPolicy) -> Self {
        Self {
            inner,
            policy,
            seed_counter: Mutex::new(0),
            cut: None,
        }
    }

    /// Every link this discovery makes can be cut with `cut`.
    pub fn with_cut(mut self, cut: Arc<LinkCut>) -> Self {
        self.cut = Some(cut);
        self
    }

    async fn next_seed(&self) -> u64 {
        let mut c = self.seed_counter.lock().await;
        let seed = *c;
        *c = c.wrapping_add(1);
        seed
    }
}

#[async_trait]
impl Discovery for FirewallDiscovery {
    fn supports_address(&self, addr: &str) -> bool {
        self.inner.supports_address(addr)
    }

    async fn accept(&self) -> Result<Box<dyn Transport>> {
        loop {
            let transport = self.inner.accept().await?;
            // While cut, connections are reset as they arrive.
            if self.cut.as_ref().is_some_and(|c| c.is_cut()) {
                continue;
            }
            let seed = self.next_seed().await;
            return Ok(Box::new(FirewallTransport::with_cut(
                transport,
                self.policy.clone(),
                seed,
                self.cut.clone(),
            )));
        }
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        if let Some(cut) = &self.cut {
            cut.check()?;
        }
        let transport = self.inner.connect(addr).await?;
        let seed = self.next_seed().await;
        Ok(Box::new(FirewallTransport::with_cut(
            transport,
            self.policy.clone(),
            seed,
            self.cut.clone(),
        )))
    }
}
