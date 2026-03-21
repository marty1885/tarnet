use tokio::sync::Mutex;

/// Global bandwidth limiter using a refill-on-check token bucket.
///
/// A single instance is shared across all peer links. Upload and download
/// limits are independent. A rate of 0 means unlimited — `acquire` returns
/// immediately without touching any state.
///
/// Refill-on-check avoids periodic background ticks that would create
/// observable burst patterns useful for traffic analysis.
pub struct BandwidthLimiter {
    upload: TokenBucket,
    download: TokenBucket,
}

struct BucketState {
    tokens: f64,
    rate: f64,   // bytes/sec, 0 = unlimited
    burst: f64,  // max token accumulation
    last_refill: tokio::time::Instant,
}

struct TokenBucket {
    state: Mutex<BucketState>,
}

impl TokenBucket {
    fn new(rate: u64) -> Self {
        let rate_f = rate as f64;
        let burst = if rate > 0 { rate_f } else { 0.0 };
        Self {
            state: Mutex::new(BucketState {
                tokens: burst, // start with a full burst
                rate: rate_f,
                burst,
                last_refill: tokio::time::Instant::now(),
            }),
        }
    }

    async fn acquire(&self, nbytes: usize) {
        let nbytes = nbytes as f64;
        loop {
            let sleep_dur = {
                let mut s = self.state.lock().await;

                // rate == 0 means unlimited
                if s.rate == 0.0 {
                    return;
                }

                // Refill based on elapsed time
                let now = tokio::time::Instant::now();
                let elapsed = now.duration_since(s.last_refill).as_secs_f64();
                s.tokens = (s.tokens + elapsed * s.rate).min(s.burst);
                s.last_refill = now;

                if s.tokens >= nbytes {
                    s.tokens -= nbytes;
                    return;
                }

                // Not enough tokens — compute how long to wait
                let deficit = nbytes - s.tokens;
                std::time::Duration::from_secs_f64(deficit / s.rate)
            };
            // Sleep outside the lock so other tasks can proceed
            tokio::time::sleep(sleep_dur).await;
        }
    }

    async fn update_rate(&self, rate: u64) {
        let mut s = self.state.lock().await;
        let rate_f = rate as f64;
        s.rate = rate_f;
        s.burst = rate_f;
        // When switching to unlimited, leave tokens as-is (harmless).
        // When switching to limited, clamp tokens to new burst.
        if rate > 0 && s.tokens > s.burst {
            s.tokens = s.burst;
        }
    }
}

impl BandwidthLimiter {
    /// Create a new limiter. Rates are in bytes/sec; 0 means unlimited.
    pub fn new(upload_rate: u64, download_rate: u64) -> Self {
        Self {
            upload: TokenBucket::new(upload_rate),
            download: TokenBucket::new(download_rate),
        }
    }

    /// Wait until `nbytes` worth of upload capacity is available.
    pub async fn acquire_upload(&self, nbytes: usize) {
        self.upload.acquire(nbytes).await;
    }

    /// Wait until `nbytes` worth of download capacity is available.
    pub async fn acquire_download(&self, nbytes: usize) {
        self.download.acquire(nbytes).await;
    }

    /// Update rates at runtime (e.g. on config reload). 0 = unlimited.
    /// Seamlessly transitions between unlimited and limited in either direction.
    pub async fn update_rates(&self, upload_rate: u64, download_rate: u64) {
        self.upload.update_rate(upload_rate).await;
        self.download.update_rate(download_rate).await;
    }
}

/// Parse a human-readable bandwidth string into bytes per second.
///
/// Supported formats:
///   - `"0"` or `""` → 0 (unlimited)
///   - Bare number: `"1000000"` → 1_000_000 B/s
///   - Bits per second: `"10Mbps"`, `"500kbps"`, `"1Gbps"`, `"8000bps"`
///   - Bytes per second: `"1MB/s"`, `"500KB/s"`, `"1GB/s"`, `"1000B/s"`
///
/// SI prefixes (powers of 1000) are used throughout.
pub fn parse_bandwidth(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Ok(0);
    }

    // Try suffixed formats
    let lower = s.to_ascii_lowercase();

    // Bytes per second: GB/s, MB/s, KB/s, B/s
    if let Some(val) = try_parse_bytes_per_sec(&lower, s) {
        return val;
    }

    // Bits per second: Gbps, Mbps, kbps/Kbps, bps
    if let Some(val) = try_parse_bits_per_sec(&lower, s) {
        return val;
    }

    // Bare number = bytes/sec
    s.parse::<u64>()
        .map_err(|_| format!("invalid bandwidth value: {:?}", s))
}

fn try_parse_bytes_per_sec(lower: &str, original: &str) -> Option<Result<u64, String>> {
    let suffixes: &[(&str, f64)] = &[
        ("gb/s", 1_000_000_000.0),
        ("mb/s", 1_000_000.0),
        ("kb/s", 1_000.0),
        ("b/s", 1.0),
    ];

    for (suffix, multiplier) in suffixes {
        if lower.ends_with(suffix) {
            let num_part = &original[..original.len() - suffix.len()].trim();
            return Some(
                num_part
                    .parse::<f64>()
                    .map(|n| (n * multiplier) as u64)
                    .map_err(|_| format!("invalid bandwidth value: {:?}", original)),
            );
        }
    }
    None
}

fn try_parse_bits_per_sec(lower: &str, original: &str) -> Option<Result<u64, String>> {
    let suffixes: &[(&str, f64)] = &[
        ("gbps", 1_000_000_000.0 / 8.0),
        ("mbps", 1_000_000.0 / 8.0),
        ("kbps", 1_000.0 / 8.0),
        ("bps", 1.0 / 8.0),
    ];

    for (suffix, multiplier) in suffixes {
        if lower.ends_with(suffix) {
            let num_part = &original[..original.len() - suffix.len()].trim();
            return Some(
                num_part
                    .parse::<f64>()
                    .map(|n| (n * multiplier) as u64)
                    .map_err(|_| format!("invalid bandwidth value: {:?}", original)),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn parse_empty_and_zero() {
        assert_eq!(parse_bandwidth("").unwrap(), 0);
        assert_eq!(parse_bandwidth("0").unwrap(), 0);
        assert_eq!(parse_bandwidth("  0  ").unwrap(), 0);
    }

    #[test]
    fn parse_bare_number() {
        assert_eq!(parse_bandwidth("1000000").unwrap(), 1_000_000);
    }

    #[test]
    fn parse_bits_per_sec() {
        assert_eq!(parse_bandwidth("8000bps").unwrap(), 1_000);
        assert_eq!(parse_bandwidth("1Mbps").unwrap(), 125_000);
        assert_eq!(parse_bandwidth("10Mbps").unwrap(), 1_250_000);
        assert_eq!(parse_bandwidth("100Mbps").unwrap(), 12_500_000);
        assert_eq!(parse_bandwidth("1Gbps").unwrap(), 125_000_000);
        assert_eq!(parse_bandwidth("500kbps").unwrap(), 62_500);
    }

    #[test]
    fn parse_bytes_per_sec() {
        assert_eq!(parse_bandwidth("1B/s").unwrap(), 1);
        assert_eq!(parse_bandwidth("500KB/s").unwrap(), 500_000);
        assert_eq!(parse_bandwidth("1MB/s").unwrap(), 1_000_000);
        assert_eq!(parse_bandwidth("1GB/s").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(parse_bandwidth("10mbps").unwrap(), 1_250_000);
        assert_eq!(parse_bandwidth("10MBPS").unwrap(), 1_250_000);
        assert_eq!(parse_bandwidth("1mb/s").unwrap(), 1_000_000);
    }

    #[test]
    fn parse_fractional() {
        assert_eq!(parse_bandwidth("1.5Mbps").unwrap(), 187_500);
        assert_eq!(parse_bandwidth("2.5MB/s").unwrap(), 2_500_000);
    }

    #[test]
    fn parse_invalid() {
        assert!(parse_bandwidth("abc").is_err());
        assert!(parse_bandwidth("10xyz").is_err());
    }

    #[tokio::test]
    async fn unlimited_is_noop() {
        let limiter = Arc::new(BandwidthLimiter::new(0, 0));
        // Should return instantly
        limiter.acquire_upload(1_000_000).await;
        limiter.acquire_download(1_000_000).await;
    }

    #[tokio::test]
    async fn limiter_throttles() {
        let limiter = Arc::new(BandwidthLimiter::new(10_000, 0));
        let start = tokio::time::Instant::now();
        // Drain the initial burst (10_000 tokens)
        limiter.acquire_upload(10_000).await;
        // Next chunk should take ~1 second
        limiter.acquire_upload(10_000).await;
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() >= 900, "expected ~1s delay, got {:?}", elapsed);
    }

    #[tokio::test]
    async fn switch_unlimited_to_limited() {
        let limiter = Arc::new(BandwidthLimiter::new(0, 0));
        // Unlimited — should be instant
        limiter.acquire_upload(1_000_000).await;

        // Switch to 10KB/s
        limiter.update_rates(10_000, 0).await;

        let start = tokio::time::Instant::now();
        limiter.acquire_upload(10_000).await;
        // Should now throttle on the next call
        limiter.acquire_upload(10_000).await;
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() >= 900, "expected ~1s delay, got {:?}", elapsed);
    }

    #[tokio::test]
    async fn switch_limited_to_unlimited() {
        let limiter = Arc::new(BandwidthLimiter::new(10_000, 0));
        // Drain burst
        limiter.acquire_upload(10_000).await;

        // Switch to unlimited
        limiter.update_rates(0, 0).await;

        // Should be instant now
        let start = tokio::time::Instant::now();
        limiter.acquire_upload(1_000_000).await;
        assert!(start.elapsed().as_millis() < 50, "should be instant after switching to unlimited");
    }
}
