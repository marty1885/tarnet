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

/// What the firewall does to each packet.
#[derive(Clone, Debug)]
pub enum FirewallPolicy {
    /// Drop each packet independently with this probability.
    Drop { rate: f64 },
    /// Delay each packet by a random duration up to `max`.
    Delay { max: Duration },
    /// Combine drop + delay: surviving packets get a random delay.
    DropAndDelay { drop_rate: f64, max_delay: Duration },
}

/// Wraps a `Transport`, applying a `FirewallPolicy` to both send and recv.
///
/// Every packet is delayed independently (its own timer), so packets overtake
/// each other the way they do on a real multi-path network: delays reorder,
/// they don't just add latency.
pub struct FirewallTransport {
    inner: Arc<dyn Transport>,
    shared: Arc<Shared>,
    /// Packets received from `inner` that survived the policy, in the order
    /// their delays expired.
    inbound: Mutex<mpsc::Receiver<Result<Vec<u8>>>>,
    pump: tokio::task::JoinHandle<()>,
}

struct Shared {
    policy: FirewallPolicy,
    rng: std::sync::Mutex<StdRng>,
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
        let inner: Arc<dyn Transport> = Arc::from(inner);
        let shared = Arc::new(Shared {
            policy,
            rng: std::sync::Mutex::new(StdRng::seed_from_u64(seed)),
        });
        let (tx, rx) = mpsc::channel(1024);
        let pump = tokio::spawn(Self::pump(inner.clone(), shared.clone(), tx));
        Self {
            inner,
            shared,
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
    ) {
        let mut buf = vec![0u8; PUMP_BUFFER];
        loop {
            let n = match inner.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };
            let Some(delay) = shared.verdict() else {
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
}

/// Wraps a `Discovery`, applying a `FirewallPolicy` to every transport
/// it produces (both accepted and connected).
pub struct FirewallDiscovery {
    inner: Box<dyn Discovery>,
    policy: FirewallPolicy,
    seed_counter: Mutex<u64>,
}

impl FirewallDiscovery {
    pub fn new(inner: Box<dyn Discovery>, policy: FirewallPolicy) -> Self {
        Self {
            inner,
            policy,
            seed_counter: Mutex::new(0),
        }
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
        let transport = self.inner.accept().await?;
        let seed = self.next_seed().await;
        Ok(Box::new(FirewallTransport::new(
            transport,
            self.policy.clone(),
            seed,
        )))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        let transport = self.inner.connect(addr).await?;
        let seed = self.next_seed().await;
        Ok(Box::new(FirewallTransport::new(
            transport,
            self.policy.clone(),
            seed,
        )))
    }
}
