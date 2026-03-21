//! Adversarial transport wrapper for testing.
//!
//! Wraps any `Transport` + `Discovery` and applies configurable packet-level
//! disruption: random drops, random delays, or both.  Sits below the link
//! crypto layer so the disruption looks like a flaky network to the node.
//!
//! A warmup period lets the initial handshake complete undisturbed — the
//! link handshake has no retransmission and cannot survive packet loss.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rand::prelude::*;
use rand::rngs::StdRng;
use tokio::sync::Mutex;

use super::{Discovery, Transport};
use crate::types::Result;

/// Number of send/recv calls to let through unmolested so the link
/// handshake can complete.  The handshake is ~3-4 messages per direction;
/// 20 gives comfortable margin for keepalives and route advertisements.
const DEFAULT_WARMUP: u64 = 20;

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
/// The first `warmup` send+recv calls pass through unmodified.
pub struct FirewallTransport {
    inner: Box<dyn Transport>,
    policy: FirewallPolicy,
    rng: Mutex<StdRng>,
    /// Counts down to zero; policy kicks in once this reaches 0.
    warmup_remaining: AtomicU64,
}

impl FirewallTransport {
    pub fn new(inner: Box<dyn Transport>, policy: FirewallPolicy, seed: u64) -> Self {
        Self {
            inner,
            policy,
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            warmup_remaining: AtomicU64::new(DEFAULT_WARMUP),
        }
    }

    /// Check (and decrement) warmup counter. Returns true if still warming up.
    fn is_warming_up(&self) -> bool {
        let prev = self.warmup_remaining.load(Ordering::Relaxed);
        if prev == 0 {
            return false;
        }
        // Best-effort decrement; races are fine — worst case a few extra
        // messages get through, which is harmless.
        self.warmup_remaining
            .compare_exchange(prev, prev - 1, Ordering::Relaxed, Ordering::Relaxed)
            .ok();
        true
    }

    /// Returns true if this packet should be dropped.
    async fn should_drop(&self) -> bool {
        let rate = match &self.policy {
            FirewallPolicy::Drop { rate } => *rate,
            FirewallPolicy::DropAndDelay { drop_rate, .. } => *drop_rate,
            FirewallPolicy::Delay { .. } => 0.0,
        };
        if rate <= 0.0 {
            return false;
        }
        self.rng.lock().await.gen::<f64>() < rate
    }

    /// Returns the delay to apply (zero if none).
    async fn pick_delay(&self) -> Duration {
        let max = match &self.policy {
            FirewallPolicy::Delay { max } => *max,
            FirewallPolicy::DropAndDelay { max_delay, .. } => *max_delay,
            FirewallPolicy::Drop { .. } => return Duration::ZERO,
        };
        if max.is_zero() {
            return Duration::ZERO;
        }
        let ms = self.rng.lock().await.gen_range(0..=max.as_millis() as u64);
        Duration::from_millis(ms)
    }
}

#[async_trait]
impl Transport for FirewallTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        if self.is_warming_up() {
            return self.inner.send(data).await;
        }
        if self.should_drop().await {
            // Silently eat the packet — looks like network loss
            return Ok(());
        }
        let delay = self.pick_delay().await;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.inner.send(data).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let n = self.inner.recv(buf).await?;
            if self.is_warming_up() {
                return Ok(n);
            }
            if self.should_drop().await {
                continue; // dropped — wait for next
            }
            let delay = self.pick_delay().await;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            return Ok(n);
        }
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
