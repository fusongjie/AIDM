//! 速度测量：1 秒桶 + 5 秒固定窗口（开发文档 §3.3 的简化实现）。
//! 突发字节先并入当前桶，窗口平均后输出，避免瞬时尖峰。
//!
//! 线程安全：内部用 Mutex，适合在工作线程与 IPC 查询线程之间共享。

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

const WINDOW: std::time::Duration = std::time::Duration::from_secs(5);
/// 速率按 1 秒桶聚合：突发流量先落到当前桶，再由 5 秒窗口平均，
/// 避免“单个样本 / 200ms”这种短分母造成的尖峰。
const BUCKET: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Default)]
pub struct SpeedWindow {
    /// (桶开始时刻, 该桶累计字节)；只保留最近 5 秒。
    samples: Mutex<VecDeque<(Instant, u64)>>,
}

impl SpeedWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录新增字节。同一秒内的多次上报合并到同一个桶。
    pub fn add(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap();
        match samples.back_mut() {
            Some((at, total)) if now.duration_since(*at) < BUCKET => {
                *total = total.saturating_add(bytes);
            }
            _ => samples.push_back((now, bytes)),
        }
        Self::evict(&mut samples, now);
    }

    /// 最近 5 秒的平均速度（B/s）。
    /// 分母至少 1 秒：启动后的第一个桶不会被放大成瞬时尖峰；
    /// 超过 5 秒没有新数据时，旧桶全部淘汰，结果自然回到 0。
    pub fn bytes_per_sec(&self) -> u64 {
        let now = Instant::now();
        let mut samples = self.samples.lock().unwrap();
        Self::evict(&mut samples, now);
        let total: u64 = samples.iter().map(|(_, b)| b).sum();
        if total == 0 {
            return 0;
        }
        let span = samples
            .front()
            .map(|(t, _)| now.duration_since(*t))
            .unwrap_or(std::time::Duration::ZERO);
        let denom = span.clamp(BUCKET, WINDOW);
        (total as f64 / denom.as_secs_f64()).round() as u64
    }

    fn evict(samples: &mut VecDeque<(Instant, u64)>, now: Instant) {
        while let Some((t, _)) = samples.front() {
            if now.duration_since(*t) > WINDOW {
                samples.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_window_is_zero() {
        let w = SpeedWindow::new();
        assert_eq!(w.bytes_per_sec(), 0);
    }

    #[test]
    fn measures_rate() {
        let w = SpeedWindow::new();
        w.add(1000);
        // 启动后的第一个桶分母至少为 1 秒：1000B / 1s = 1000 B/s。
        assert_eq!(w.bytes_per_sec(), 1000);
    }

    #[test]
    fn same_second_samples_are_merged() {
        let w = SpeedWindow::new();
        w.add(1000);
        w.add(2000);
        assert_eq!(w.bytes_per_sec(), 3000);
    }

    #[test]
    fn stale_samples_decay_to_zero() {
        let w = SpeedWindow::new();
        w.samples
            .lock()
            .unwrap()
            .push_back((Instant::now() - std::time::Duration::from_secs(6), 1000));
        assert_eq!(w.bytes_per_sec(), 0);
    }
}
