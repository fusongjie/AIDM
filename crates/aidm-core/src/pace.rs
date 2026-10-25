//! 「持续慢」判定：给段级换源（规则 `05-download-correctness.md` R-DL-14）用的纯逻辑。
//!
//! # 规格
//!
//! 某个分段**持续 `alt.measure_window_s` 秒**的实测速率低于**已完成分段的平均速率**时，
//! 允许把**该段**换到来源池里实测最快的来源。`alt.measure_min_bps` 是**绝对下限**的
//! 第二判据（两者都配才完整，见 `setting_spec.rs` 里这两个键的注释）。
//!
//! # 为什么单独成模块
//!
//! 判定必须能在测试里把「5 秒窗口」完整走一遍，而不是真的睡 5 秒。所以这里**不碰时钟**：
//! 调用方把「本段已经跑了多久」和「本次尝试已经收了多少字节」喂进来，判定只做算术。
//! 网络、文件、数据库都在调用方（`aidm-engine` 的段循环）那一侧。
//!
//! # 「持续」是怎么实现的
//!
//! 按期采样：每跨过一个完整窗口结算一次，任何一个窗口不达标就触发。这对"持续 N 秒都慢"
//! 是等价的说法，而且不需要记录"从哪一刻开始慢"这种会随抖动来回翻转的状态。

use std::time::Duration;

/// 触发换源的原因（写进 `segment_src_switch` 的 `reason=`，R-DL-14 要求留痕）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowReason {
    /// 窗口内速率低于**已完成分段的平均速率**（相对判据）。
    SlowerThanDone,
    /// 窗口内速率低于 `alt.measure_min_bps`（绝对下限）。
    BelowMinBps,
}

impl SlowReason {
    /// 事件里的稳定字符串。改名等于改可观测契约，所以集中在这里。
    pub fn as_str(self) -> &'static str {
        match self {
            SlowReason::SlowerThanDone => "slow_vs_done",
            SlowReason::BelowMinBps => "below_min_bps",
        }
    }
}

/// 一次观察的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    /// 继续当前连接。
    Keep,
    /// 触发「换源 / 换连接」，并带上原因。
    Switch(SlowReason),
}

/// 段级「持续慢」闸门。
///
/// 只在**跨过一个完整窗口**时判定；触发后窗口照常重新计时（调用方自己决定还要不要继续观察，
/// 例如已经换过 `N` 次就不再观察 —— 那是防死循环的策略，不属于这里）。
#[derive(Debug, Clone)]
pub struct SlowGate {
    window: Duration,
    min_bps: u64,
    /// 当前窗口的起点（相对本段本次尝试开始）。
    window_at: Duration,
    /// 当前窗口起点时的累计字节数。
    window_bytes: u64,
    /// 已经触发过几次（调用方可用它设上限）。
    fired: u32,
}

impl SlowGate {
    /// `window_s == 0` 回 `None` —— **没有窗口就不观察**，这正是
    /// `alt.measure_window_s` 默认 `0` 的语义（保持既有行为，绝不"默认开启"）。
    pub fn new(window_s: u64, min_bps: u64) -> Option<Self> {
        if window_s == 0 {
            return None;
        }
        Some(Self {
            window: Duration::from_secs(window_s),
            min_bps,
            window_at: Duration::ZERO,
            window_bytes: 0,
            fired: 0,
        })
    }

    /// 已经触发过几次。
    pub fn fired(&self) -> u32 {
        self.fired
    }

    /// 窗口长度（诊断用）。
    pub fn window(&self) -> Duration {
        self.window
    }

    /// 观察一次。
    ///
    /// - `at`：本段**本次尝试**已经跑了多久
    /// - `bytes`：本次尝试已经收到的字节数（不是整段进度：换源后重新计数）
    /// - `done_avg_bps`：已完成分段的平均速率；`None` = 还没有任何段完成，
    ///   此时**只有绝对下限判据**可用（拿不存在的平均值去比等于无中生有）
    pub fn observe(&mut self, at: Duration, bytes: u64, done_avg_bps: Option<f64>) -> Pace {
        if at.saturating_sub(self.window_at) < self.window {
            return Pace::Keep;
        }
        let dt = at.saturating_sub(self.window_at);
        let delta = bytes.saturating_sub(self.window_bytes);
        self.window_at = at;
        self.window_bytes = bytes;
        let bps = if dt.is_zero() {
            0.0
        } else {
            delta as f64 / dt.as_secs_f64()
        };
        // 绝对下限优先报：它是用户显式给的门槛，比"和已完成段比"更能解释现场。
        if self.min_bps > 0 && bps < self.min_bps as f64 {
            self.fired += 1;
            return Pace::Switch(SlowReason::BelowMinBps);
        }
        if let Some(avg) = done_avg_bps {
            // `avg <= 0` 说明"平均速率"这个参照本身不可用（例如 0 字节的完成段），
            // 拿它当门槛会把每一个源都判成慢。
            if avg > 0.0 && bps < avg {
                self.fired += 1;
                return Pace::Switch(SlowReason::SlowerThanDone);
            }
        }
        Pace::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(v: f64) -> Duration {
        Duration::from_secs_f64(v)
    }

    /// `window_s = 0` 就是关闭：这正是该键默认 0 的语义，不能"默认开启"。
    #[test]
    fn a_zero_window_means_no_observation_at_all() {
        assert!(SlowGate::new(0, 0).is_none());
        assert!(
            SlowGate::new(0, 1024).is_none(),
            "只设下限、没设窗口 = 没有判据"
        );
    }

    /// 窗口没满就不判定 —— 哪怕这一窗口一个字节都没收到。
    #[test]
    fn nothing_is_decided_before_the_window_closes() {
        let mut g = SlowGate::new(5, 0).unwrap();
        assert_eq!(g.observe(secs(0.5), 0, Some(1_000_000.0)), Pace::Keep);
        assert_eq!(g.observe(secs(4.9), 0, Some(1_000_000.0)), Pace::Keep);
        assert_eq!(g.fired(), 0, "窗口未满不该计入触发");
    }

    /// 满窗口且低于「已完成段平均速率」→ 触发，原因可区分。
    #[test]
    fn a_window_below_the_average_of_finished_segments_fires() {
        let mut g = SlowGate::new(5, 0).unwrap();
        // 5 秒收了 100 KiB ≈ 20 KiB/s，远低于已完成段的 1 MiB/s
        let p = g.observe(secs(5.0), 100 * 1024, Some(1024.0 * 1024.0));
        assert_eq!(p, Pace::Switch(SlowReason::SlowerThanDone));
        assert_eq!(g.fired(), 1);
        assert_eq!(SlowReason::SlowerThanDone.as_str(), "slow_vs_done");
    }

    /// 达标就继续：比已完成段快，绝不换。
    #[test]
    fn a_window_at_or_above_the_average_keeps_the_connection() {
        let mut g = SlowGate::new(5, 0).unwrap();
        // 5 秒 10 MiB = 2 MiB/s > 1 MiB/s
        assert_eq!(
            g.observe(secs(5.0), 10 * 1024 * 1024, Some(1024.0 * 1024.0)),
            Pace::Keep
        );
        // 正好等于平均：不算低于
        assert_eq!(
            g.observe(secs(10.0), 20 * 1024 * 1024, Some(2.0 * 1024.0 * 1024.0)),
            Pace::Keep
        );
        assert_eq!(g.fired(), 0);
    }

    /// 绝对下限优先：用户显式设的门槛比"和已完成段比"更能解释现场。
    #[test]
    fn the_absolute_floor_wins_and_works_without_finished_segments() {
        let mut g = SlowGate::new(5, 256 * 1024).unwrap();
        // 5 秒 100 KiB ≈ 20 KiB/s < 256 KiB/s。完全没有已完成段（None）也要能判。
        let p = g.observe(secs(5.0), 100 * 1024, None);
        assert_eq!(p, Pace::Switch(SlowReason::BelowMinBps));
        assert_eq!(SlowReason::BelowMinBps.as_str(), "below_min_bps");

        // 只设窗口、不设下限（0）时，没有参照就不能凭空判慢
        let mut g2 = SlowGate::new(5, 0).unwrap();
        assert_eq!(g2.observe(secs(5.0), 0, None), Pace::Keep);
        // 参照为 0（比如 0 字节的"完成段"）同样不能判慢
        assert_eq!(g2.observe(secs(10.0), 0, Some(0.0)), Pace::Keep);
    }

    /// 窗口是**逐窗结算**的：一个窗口达标、下一个窗口慢下来，仍然要能抓到。
    #[test]
    fn each_window_is_settled_on_its_own() {
        let mut g = SlowGate::new(2, 0).unwrap();
        // 第 1 窗：2 秒 4 MiB = 2 MiB/s，高于 1 MiB/s → 继续
        assert_eq!(
            g.observe(secs(2.0), 4 * 1024 * 1024, Some(1024.0 * 1024.0)),
            Pace::Keep
        );
        // 第 2 窗：又一个 2 秒只多了 64 KiB ≈ 32 KiB/s → 触发
        assert_eq!(
            g.observe(
                secs(4.0),
                4 * 1024 * 1024 + 64 * 1024,
                Some(1024.0 * 1024.0)
            ),
            Pace::Switch(SlowReason::SlowerThanDone)
        );
        assert_eq!(g.fired(), 1);
        assert_eq!(g.window(), Duration::from_secs(2));
    }

    /// 窗口内速率按**本窗增量**算，不受窗口起点之前的累计影响。
    #[test]
    fn the_rate_is_measured_within_the_window_only() {
        let mut g = SlowGate::new(1, 0).unwrap();
        // 第 1 窗飞快（10 MiB/s）
        assert_eq!(
            g.observe(secs(1.0), 10 * 1024 * 1024, Some(1024.0 * 1024.0)),
            Pace::Keep
        );
        // 第 2 窗几乎不动：累计很大，但增量≈0 → 必须判慢（拿累计算就会漏掉）
        assert_eq!(
            g.observe(secs(2.0), 10 * 1024 * 1024 + 1024, Some(1024.0 * 1024.0)),
            Pace::Switch(SlowReason::SlowerThanDone)
        );
    }
}
