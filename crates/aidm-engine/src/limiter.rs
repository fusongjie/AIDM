//! 全局令牌桶限速（§3.3）：跨全部任务 / 分段 / 连接共享。
//! `0` = 不限。`set_limit_kbps` 立即对后续 `take` 生效。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct TokenBucket {
    rate_bps: AtomicU64,
    state: Mutex<BucketState>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
    capacity: f64,
}

impl TokenBucket {
    pub fn new(limit_kbps: u64) -> Arc<Self> {
        let bps = kbps_to_bps(limit_kbps);
        Arc::new(Self {
            rate_bps: AtomicU64::new(bps),
            state: Mutex::new(BucketState {
                tokens: capacity_for(bps),
                last: Instant::now(),
                capacity: capacity_for(bps),
            }),
        })
    }

    pub fn set_limit_kbps(&self, kbps: u64) {
        let bps = kbps_to_bps(kbps);
        self.rate_bps.store(bps, Ordering::Relaxed);
        let mut st = self.state.lock().unwrap();
        st.capacity = capacity_for(bps);
        if bps == 0 {
            st.tokens = st.capacity;
        } else if st.tokens > st.capacity {
            st.tokens = st.capacity;
        }
    }

    /// 当前全局限速（B/s）；0 = 不限。
    pub fn limit_bps(&self) -> u64 {
        self.rate_bps.load(Ordering::Relaxed)
    }

    /// 消费 `n` 字节；桶空时阻塞直到补齐。限速为 0 时立即返回。
    /// 单次 `n` 可以大于桶容量（按可用代币分多次扣）。
    pub fn take(&self, n: u64) {
        self.take_until(n, || false);
    }

    /// 多源传输暂停时及时退出限速等待，避免一个大块在低速配置下阻塞退出。
    pub fn take_until(&self, mut n: u64, stop: impl Fn() -> bool) -> bool {
        while n > 0 {
            if stop() {
                return false;
            }
            let sleep_for = {
                let rate = self.rate_bps.load(Ordering::Relaxed);
                if rate == 0 {
                    return true;
                }
                let mut st = self.state.lock().unwrap();
                refill(&mut st, rate);
                if st.tokens >= 1.0 {
                    let take = st.tokens.min(n as f64);
                    st.tokens -= take;
                    n = n.saturating_sub(take as u64);
                    if n == 0 {
                        return true;
                    }
                }
                let want = (n as f64).min(st.capacity);
                let missing = (want - st.tokens).max(0.0);
                Duration::from_secs_f64((missing / rate as f64).max(0.001))
            };
            std::thread::sleep(sleep_for.min(Duration::from_millis(20)));
        }
        true
    }
}

fn kbps_to_bps(kbps: u64) -> u64 {
    kbps.saturating_mul(1024)
}

fn capacity_for(bps: u64) -> f64 {
    if bps == 0 {
        return f64::MAX / 4.0;
    }
    // 约 1 秒突发，避免把短读放大成不限速。
    bps as f64
}

fn refill(st: &mut BucketState, rate: u64) {
    let now = Instant::now();
    let dt = now.saturating_duration_since(st.last).as_secs_f64();
    st.last = now;
    if rate == 0 {
        st.tokens = st.capacity;
        return;
    }
    st.tokens = (st.tokens + dt * rate as f64).min(st.capacity);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_is_instant() {
        let b = TokenBucket::new(0);
        let t0 = Instant::now();
        b.take(10 * 1024 * 1024);
        assert!(t0.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn low_rate_large_block_can_be_cancelled_promptly() {
        let bucket = TokenBucket::new(1);
        let start = Instant::now();
        assert!(!bucket.take_until(184_320, || start.elapsed() >= Duration::from_millis(30)));
        assert!(start.elapsed() < Duration::from_millis(300));
    }

    #[test]
    fn rough_accuracy_50kbps() {
        let b = TokenBucket::new(50); // 50 KiB/s，约 1s 突发
        b.take(50 * 1024); // 吃掉突发
        let t0 = Instant::now();
        // 再取 100 KiB ≈ 2s
        b.take(100 * 1024);
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1400) && elapsed <= Duration::from_millis(4000),
            "elapsed={elapsed:?}"
        );
    }

    #[test]
    fn set_limit_takes_effect() {
        let b = TokenBucket::new(0);
        b.take(64 * 1024);
        b.set_limit_kbps(40);
        let t0 = Instant::now();
        b.take(80 * 1024);
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1000) && elapsed <= Duration::from_millis(5000),
            "elapsed={elapsed:?}"
        );
    }
}
