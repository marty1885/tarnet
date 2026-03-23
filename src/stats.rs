//! Lock-free statistics collection with time-windowed aggregation.
//!
//! Subsystems submit timestamped samples via [`StatsRegistry::record`].
//! The registry uses [`DashMap`] for concurrent access and per-metric
//! [`RollingCounter`]s backed by atomic bucket rings.
//!
//! Read path (status queries) sums buckets for 5-minute, 1-hour, and
//! 1-day windows plus an all-time total.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use crate::types::PeerId;

// ── Bucket ring ──

/// Fixed-size ring of atomic counters, each covering a time slice.
///
/// Writes are lock-free (`fetch_add`). When the head advances past old
/// buckets they are lazily zeroed on the next write to that slot.
struct BucketRing<const N: usize> {
    buckets: Box<[AtomicU64; N]>,
    /// Timestamp (ms) of the last write — used to detect bucket rollover.
    last_write_ms: AtomicU64,
    bucket_duration_ms: u64,
}

impl<const N: usize> BucketRing<N> {
    fn new(bucket_duration_ms: u64) -> Self {
        Self {
            buckets: Box::new(std::array::from_fn(|_| AtomicU64::new(0))),
            last_write_ms: AtomicU64::new(0),
            bucket_duration_ms,
        }
    }

    /// Record `value` at `timestamp_ms`. Lock-free.
    fn record(&self, timestamp_ms: u64, value: u64) {
        let idx = self.bucket_index(timestamp_ms);
        let prev_ms = self.last_write_ms.swap(timestamp_ms, Ordering::Relaxed);

        // If we skipped buckets, zero them so stale data doesn't pollute sums.
        if prev_ms > 0 {
            let prev_idx = self.bucket_index(prev_ms);
            let elapsed_buckets = (timestamp_ms / self.bucket_duration_ms)
                .wrapping_sub(prev_ms / self.bucket_duration_ms);

            if elapsed_buckets > 0 && elapsed_buckets <= N as u64 {
                // Clear buckets between prev and current (exclusive of current,
                // which we're about to write to).
                for offset in 1..=elapsed_buckets.min(N as u64) {
                    let clear_idx = (prev_idx + offset as usize) % N;
                    if clear_idx != idx {
                        self.buckets[clear_idx].store(0, Ordering::Relaxed);
                    }
                }
            } else if elapsed_buckets > N as u64 {
                // Too many buckets elapsed — clear everything.
                for b in self.buckets.iter() {
                    b.store(0, Ordering::Relaxed);
                }
            }

            // If this is a new bucket (not the same as prev), zero it before adding.
            if idx != prev_idx {
                self.buckets[idx].store(0, Ordering::Relaxed);
            }
        }

        self.buckets[idx].fetch_add(value, Ordering::Relaxed);
    }

    /// Sum the most recent `window_buckets` buckets from `now_ms`.
    fn sum(&self, now_ms: u64, window_buckets: usize) -> u64 {
        let head = self.bucket_index(now_ms);
        let count = window_buckets.min(N);
        let mut total = 0u64;
        for i in 0..count {
            let idx = (head + N - i) % N;
            total = total.wrapping_add(self.buckets[idx].load(Ordering::Relaxed));
        }
        total
    }

    fn bucket_index(&self, timestamp_ms: u64) -> usize {
        ((timestamp_ms / self.bucket_duration_ms) % N as u64) as usize
    }
}

// ── Rolling counter (multi-resolution) ──

/// Three-tier rolling counter: fine (1s buckets, 5min), medium (1min, 1h),
/// coarse (1h, 1d). All tiers are written on every `record()` call so
/// reads are simple sums — no downsampling needed.
pub struct RollingCounter {
    /// 1-second buckets, 300 of them → covers 5 minutes.
    fine: BucketRing<300>,
    /// 1-minute buckets, 60 of them → covers 1 hour.
    medium: BucketRing<60>,
    /// 1-hour buckets, 24 of them → covers 1 day.
    coarse: BucketRing<24>,
    /// All-time total.
    total: AtomicU64,
}

impl RollingCounter {
    pub fn new() -> Self {
        Self {
            fine: BucketRing::new(1_000),       // 1s
            medium: BucketRing::new(60_000),    // 1min
            coarse: BucketRing::new(3_600_000), // 1h
            total: AtomicU64::new(0),
        }
    }

    /// Record a value. Lock-free: three atomic adds + one total add.
    pub fn record(&self, timestamp_ms: u64, value: u64) {
        self.fine.record(timestamp_ms, value);
        self.medium.record(timestamp_ms, value);
        self.coarse.record(timestamp_ms, value);
        self.total.fetch_add(value, Ordering::Relaxed);
    }

    /// Read all windows at `now_ms`.
    pub fn read(&self, now_ms: u64) -> WindowedStats {
        WindowedStats {
            total: self.total.load(Ordering::Relaxed),
            last_5min: self.fine.sum(now_ms, 300),
            last_1hr: self.medium.sum(now_ms, 60),
            last_1day: self.coarse.sum(now_ms, 24),
        }
    }
}

// ── Stat key ──

/// Metric identifier. Cheap to hash and compare.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StatKey {
    // Global traffic
    BytesUp,
    BytesDown,
    PacketsUp,
    PacketsDown,
    CellsRelayed,
    // Per-peer traffic (only direct links)
    PeerBytesUp(PeerId),
    PeerBytesDown(PeerId),
    PeerPacketsUp(PeerId),
    PeerPacketsDown(PeerId),
}

// ── Windowed stats ──

/// Statistics for a single metric across time windows.
#[derive(Debug, Clone, Default)]
pub struct WindowedStats {
    pub total: u64,
    pub last_5min: u64,
    pub last_1hr: u64,
    pub last_1day: u64,
}

// ── Stats registry ──

/// Central lock-free statistics sink. Shared across all subsystems via `Arc`.
///
/// Write path: one `DashMap` shard lock (very brief) + three atomic adds.
/// Read path: iterate relevant entries, sum bucket rings.
pub struct StatsRegistry {
    counters: DashMap<StatKey, RollingCounter>,
}

impl StatsRegistry {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Record a metric sample. Called on hot paths — lock-free per shard.
    pub fn record(&self, key: StatKey, timestamp_ms: u64, value: u64) {
        self.counters
            .entry(key)
            .or_insert_with(RollingCounter::new)
            .record(timestamp_ms, value);
    }

    /// Read windowed stats for a single metric.
    pub fn read(&self, key: &StatKey) -> WindowedStats {
        let now_ms = now_millis();
        match self.counters.get(key) {
            Some(counter) => counter.read(now_ms),
            None => WindowedStats::default(),
        }
    }

    /// Convenience: record bytes + packet count on send.
    pub fn record_send(&self, peer: &PeerId, bytes: u64) {
        let ts = now_millis();
        self.record(StatKey::BytesUp, ts, bytes);
        self.record(StatKey::PacketsUp, ts, 1);
        self.record(StatKey::PeerBytesUp(*peer), ts, bytes);
        self.record(StatKey::PeerPacketsUp(*peer), ts, 1);
    }

    /// Convenience: record bytes + packet count on recv.
    pub fn record_recv(&self, peer: &PeerId, bytes: u64) {
        let ts = now_millis();
        self.record(StatKey::BytesDown, ts, bytes);
        self.record(StatKey::PacketsDown, ts, 1);
        self.record(StatKey::PeerBytesDown(*peer), ts, bytes);
        self.record(StatKey::PeerPacketsDown(*peer), ts, 1);
    }

    /// Convenience: record a relayed cell.
    pub fn record_relay(&self, bytes: u64) {
        let ts = now_millis();
        self.record(StatKey::CellsRelayed, ts, 1);
        // Relayed bytes count as both up and down for the relay node.
        self.record(StatKey::BytesUp, ts, bytes);
        self.record(StatKey::BytesDown, ts, bytes);
        self.record(StatKey::PacketsUp, ts, 1);
        self.record(StatKey::PacketsDown, ts, 1);
    }

    /// Read traffic summary (global).
    pub fn traffic_summary(&self) -> TrafficSummary {
        TrafficSummary {
            bytes_up: self.read(&StatKey::BytesUp),
            bytes_down: self.read(&StatKey::BytesDown),
            packets_up: self.read(&StatKey::PacketsUp),
            packets_down: self.read(&StatKey::PacketsDown),
            cells_relayed: self.read(&StatKey::CellsRelayed),
        }
    }

    /// Read per-peer stats for a specific peer.
    pub fn peer_traffic(&self, peer: &PeerId) -> PeerTraffic {
        PeerTraffic {
            bytes_up: self.read(&StatKey::PeerBytesUp(*peer)),
            bytes_down: self.read(&StatKey::PeerBytesDown(*peer)),
            packets_up: self.read(&StatKey::PeerPacketsUp(*peer)),
            packets_down: self.read(&StatKey::PeerPacketsDown(*peer)),
        }
    }
}

/// Global traffic summary.
#[derive(Debug, Clone)]
pub struct TrafficSummary {
    pub bytes_up: WindowedStats,
    pub bytes_down: WindowedStats,
    pub packets_up: WindowedStats,
    pub packets_down: WindowedStats,
    pub cells_relayed: WindowedStats,
}

/// Per-peer traffic.
#[derive(Debug, Clone)]
pub struct PeerTraffic {
    pub bytes_up: WindowedStats,
    pub bytes_down: WindowedStats,
    pub packets_up: WindowedStats,
    pub packets_down: WindowedStats,
}

/// Current UNIX time in milliseconds.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_counter_basic() {
        let counter = RollingCounter::new();
        let base = 1_000_000_000u64; // arbitrary epoch

        counter.record(base, 100);
        counter.record(base + 500, 200);
        counter.record(base + 1_500, 50);

        let stats = counter.read(base + 2_000);
        assert_eq!(stats.total, 350);
        assert!(stats.last_5min >= 350); // all within 5min
    }

    #[test]
    fn rolling_counter_window_expiry() {
        let counter = RollingCounter::new();
        let base = 1_000_000_000u64;

        // Record at base
        counter.record(base, 100);

        // Record 6 minutes later — first record should fall out of 5min window
        let later = base + 6 * 60 * 1_000;
        counter.record(later, 50);

        let stats = counter.read(later);
        assert_eq!(stats.total, 150);
        assert_eq!(stats.last_5min, 50); // only the recent one
        assert_eq!(stats.last_1hr, 150); // both in 1hr window
    }

    #[test]
    fn registry_send_recv() {
        let reg = StatsRegistry::new();
        let peer = PeerId([0u8; 32]);

        reg.record_send(&peer, 1024);
        reg.record_recv(&peer, 2048);

        let summary = reg.traffic_summary();
        assert_eq!(summary.bytes_up.total, 1024);
        assert_eq!(summary.bytes_down.total, 2048);
        assert_eq!(summary.packets_up.total, 1);
        assert_eq!(summary.packets_down.total, 1);

        let pt = reg.peer_traffic(&peer);
        assert_eq!(pt.bytes_up.total, 1024);
        assert_eq!(pt.bytes_down.total, 2048);
    }
}
