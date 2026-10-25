//! 调度纯逻辑：连接数闸门、网络重试退避、主机提取、cron 资格、
//! 运行时段、流量配额、完成后动作、主机模式匹配。
//!
//! 这里把时段开关 / 时段表 / 流量配额 / 超限提示，以及"队列处理完之后
//! 退出/关机/休眠/断开"这组能力做成**可测的纯函数**，读写设置的那一层
//! 只负责解析一次。

use crate::cron::CronExpr;

/// 指数退避上限 60s。
pub const RETRY_CAP_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gates {
    /// 全局连接闸门：**唯一**的连接数硬约束（每任务连接数不设限）。
    pub max_conns_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct GateSnapshot {
    pub reserved_conns: u64,
}

/// 第 `retry_count` 次重试（1-based）的等待毫秒：`base * 2^(n-1)`，封顶 60s。
pub fn retry_backoff_ms(base_ms: u64, retry_count: u32) -> u64 {
    let exp = retry_count.saturating_sub(1).min(16);
    base_ms.saturating_mul(1u64 << exp).min(RETRY_CAP_MS)
}

pub fn is_network_error(code: &str) -> bool {
    crate::error::is_retryable_network(code)
}

/// 从 URL 取主机名（小写，不含端口）。
pub fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = if let Some(inner) = hostport.strip_prefix('[') {
        inner
            .split_once(']')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| hostport.to_string())
    } else {
        hostport.split(':').next().unwrap_or(hostport).to_string()
    };
    host.to_ascii_lowercase()
}

/// 队列处理完之后要做什么（退出 / 关机 / 休眠 / 待机 / 断开）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterDone {
    None,
    Exit,
    Shutdown,
    Hibernate,
    Sleep,
    Disconnect,
}

impl AfterDone {
    pub fn parse(raw: &str) -> Self {
        match raw.trim() {
            "exit" => AfterDone::Exit,
            "shutdown" => AfterDone::Shutdown,
            "hibernate" => AfterDone::Hibernate,
            "sleep" => AfterDone::Sleep,
            "disconnect" => AfterDone::Disconnect,
            _ => AfterDone::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AfterDone::None => "none",
            AfterDone::Exit => "exit",
            AfterDone::Shutdown => "shutdown",
            AfterDone::Hibernate => "hibernate",
            AfterDone::Sleep => "sleep",
            AfterDone::Disconnect => "disconnect",
        }
    }

    pub fn is_action(self) -> bool {
        !matches!(self, AfterDone::None)
    }
}

/// 允许下载的时间窗。
///
/// 跨午夜（`22:00`–`06:00`）是合法的：起点大于终点时按"跨越子夜"处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunWindow {
    pub enabled: bool,
    pub start_min: u16,
    pub end_min: u16,
    /// ISO 星期（1=周一 … 7=周日）
    pub days: Vec<u8>,
}

impl Default for RunWindow {
    fn default() -> Self {
        Self {
            enabled: false,
            start_min: 0,
            end_min: 23 * 60 + 59,
            days: vec![1, 2, 3, 4, 5, 6, 7],
        }
    }
}

impl RunWindow {
    pub fn parse(enabled: bool, start: &str, end: &str, days: &str) -> Self {
        let d = Self::default();
        Self {
            enabled,
            start_min: parse_clock_minutes(start).unwrap_or(d.start_min),
            end_min: parse_clock_minutes(end).unwrap_or(d.end_min),
            days: crate::settings::parse_weekdays(days).unwrap_or(d.days),
        }
    }

    /// `iso_weekday` 取 1..=7，`minute` 取 0..=1439（本地时间）。
    pub fn is_open(&self, iso_weekday: u8, minute: u16) -> bool {
        if !self.enabled {
            return true;
        }
        if !self.days.contains(&iso_weekday) {
            return false;
        }
        if self.start_min <= self.end_min {
            minute >= self.start_min && minute <= self.end_min
        } else {
            // 跨午夜：要么在起点之后，要么在终点之前
            minute >= self.start_min || minute <= self.end_min
        }
    }
}

/// 流量配额。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quota {
    pub enabled: bool,
    pub mb: u64,
    pub period: QuotaPeriod,
    pub action: QuotaAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaPeriod {
    Hour,
    Day,
    Week,
}

impl QuotaPeriod {
    pub fn parse(raw: &str) -> Self {
        match raw.trim() {
            "hour" => QuotaPeriod::Hour,
            "week" => QuotaPeriod::Week,
            _ => QuotaPeriod::Day,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            QuotaPeriod::Hour => "hour",
            QuotaPeriod::Day => "day",
            QuotaPeriod::Week => "week",
        }
    }

    /// 当前时刻落在哪个周期桶里（用于按周期累计字节）。
    pub fn bucket_start_secs(self, now_secs: i64) -> i64 {
        const HOUR: i64 = 3600;
        match self {
            QuotaPeriod::Hour => now_secs - now_secs.rem_euclid(HOUR),
            // 以 UTC 日界为准：跨时区漂移一天不影响"限流量"的语义，
            // 但换来完全可测的纯函数。
            QuotaPeriod::Day => now_secs - now_secs.rem_euclid(24 * HOUR),
            QuotaPeriod::Week => {
                // 1970-01-01 是周四：偏移 3 天让周一成为一周之始
                let weeks = (now_secs + 3 * 24 * HOUR).div_euclid(7 * 24 * HOUR);
                weeks * 7 * 24 * HOUR - 3 * 24 * HOUR
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaAction {
    /// 暂停（保留进度，下个周期自动续）
    Pause,
    /// 停止（列为 error/quota，等用户手动继续）
    Stop,
}

impl QuotaAction {
    pub fn parse(raw: &str) -> Self {
        match raw.trim() {
            "stop" => QuotaAction::Stop,
            _ => QuotaAction::Pause,
        }
    }
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            enabled: false,
            mb: 200,
            period: QuotaPeriod::Day,
            action: QuotaAction::Pause,
        }
    }
}

impl Quota {
    pub fn parse(enabled: bool, mb: u64, period: &str, action: &str) -> Self {
        Self {
            enabled,
            mb: mb.max(1),
            period: QuotaPeriod::parse(period),
            action: QuotaAction::parse(action),
        }
    }

    pub fn limit_bytes(&self) -> u64 {
        self.mb.saturating_mul(1024 * 1024)
    }

    /// 本周期已用 + 本次要新增是否会超限。
    pub fn exceeded(&self, used_bytes: u64, add_bytes: u64) -> bool {
        self.enabled && used_bytes.saturating_add(add_bytes) > self.limit_bytes()
    }

    pub fn bucket_start_secs(&self, now_secs: i64) -> i64 {
        self.period.bucket_start_secs(now_secs)
    }
}

/// `HH:MM` -> 当日分钟数。
pub fn parse_clock_minutes(raw: &str) -> Option<u16> {
    let (h, m) = crate::settings::parse_clock(raw).ok()?;
    Some(u16::from(h) * 60 + u16::from(m))
}

/// 主机是否命中模式表。模式可以是精确主机、`*.example.com` 后缀、
/// 或任何大小写混写（统一按小写比较）。
pub fn host_matches_any(patterns: &[String], host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    patterns.iter().any(|p| host_matches(p, &host))
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == p
}

/// 全局连接闸门：只限制连接数，不再限制同时下载的任务数。
///
/// 每任务连接数不再有独立上限，所以这里按**全局闸门**夹取：
/// 一个任务最多也只能占满整个全局预算。
pub fn can_start(gates: &Gates, snap: &GateSnapshot, _host: &str, task_conns: u64) -> bool {
    let conns = task_conns.clamp(1, gates.max_conns_total.max(1));
    snap.reserved_conns.saturating_add(conns) <= gates.max_conns_total
}

/// `start=now` 立即具备资格；`start=queue` 且 cron 开启时等到 `created_at` 之后的下一次 cron。
pub fn is_eligible(
    start_mode: &str,
    cron: Option<&CronExpr>,
    created_at_secs: i64,
    now_ms: i64,
) -> bool {
    if start_mode != "queue" {
        return true;
    }
    let Some(expr) = cron else {
        return true;
    };
    let created_ms = created_at_secs.saturating_mul(1000);
    match crate::cron::next_fire_ms(expr, created_ms) {
        Some(t) => now_ms >= t,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cron;
    use chrono::TimeZone;

    #[test]
    fn backoff_exponential_capped() {
        assert_eq!(retry_backoff_ms(1000, 1), 1000);
        assert_eq!(retry_backoff_ms(1000, 2), 2000);
        assert_eq!(retry_backoff_ms(1000, 3), 4000);
        assert_eq!(retry_backoff_ms(1000, 7), 60_000);
        assert_eq!(retry_backoff_ms(2000, 6), 60_000);
    }

    #[test]
    fn network_error_codes() {
        assert!(is_network_error("connect: Connection refused"));
        assert!(is_network_error("read: timeout"));
        assert!(is_network_error("http_503"));
        assert!(is_network_error("http_429"));
        assert!(is_network_error("network"));
        assert!(!is_network_error("http_404"));
        assert!(!is_network_error("size_mismatch 1/2"));
        assert!(!is_network_error("mkdir: denied"));
    }

    #[test]
    fn host_from_url() {
        assert_eq!(
            url_host("https://CDN.Example.com:8443/a.bin"),
            "cdn.example.com"
        );
        assert_eq!(url_host("http://127.0.0.1/x"), "127.0.0.1");
    }

    #[test]
    fn gates_only_limit_total_connections() {
        let gates = Gates {
            max_conns_total: 32,
        };
        let snap = GateSnapshot {
            reserved_conns: 24,
        };
        assert!(can_start(&gates, &snap, "a.com", 8));
        // 同一主机不再有任务数/连接数上限：只看全局预算。
        assert!(can_start(&gates, &snap, "a.com", 8));
        let busy = GateSnapshot {
            reserved_conns: 28,
        };
        assert!(!can_start(&gates, &busy, "a.com", 8));
        assert!(can_start(&gates, &busy, "b.com", 4));
    }

    #[test]
    fn a_single_task_may_claim_the_whole_global_budget() {
        // 每任务连接数不设限：一个任务要 1000 根，也不因为"超过每任务上限"被拒，
        // 只看全局预算够不够。这里全局 256 是空的，所以放行。
        let gates = Gates {
            max_conns_total: 256,
        };
        let snap = GateSnapshot {
            reserved_conns: 0,
        };
        assert!(can_start(&gates, &snap, "a.com", 1000));
        // 全局已被占满时仍然拒绝（唯一硬约束）。
        let busy = GateSnapshot {
            reserved_conns: 256,
        };
        assert!(!can_start(&gates, &busy, "a.com", 1));
    }

    #[test]
    fn run_window_handles_midnight_and_weekdays() {
        // 关闭 = 永远允许
        let w = RunWindow::parse(false, "22:00", "06:00", "1,2,3");
        assert!(w.is_open(7, 12 * 60));
        // 跨午夜：22:00–06:00 只在 1/2/3 开放
        let w = RunWindow::parse(true, "22:00", "06:00", "1,2,3");
        assert!(w.is_open(1, 0));
        assert!(w.is_open(1, 22 * 60));
        assert!(w.is_open(3, 5 * 60 + 59));
        assert!(!w.is_open(3, 6 * 60 + 1));
        assert!(!w.is_open(4, 23 * 60)); // 周四不在允许的日子
        assert!(!w.is_open(2, 12 * 60));
        // 同日窗口
        let w = RunWindow::parse(true, "09:00", "17:30", "5");
        assert!(w.is_open(5, 9 * 60));
        assert!(w.is_open(5, 17 * 60 + 30));
        assert!(!w.is_open(5, 8 * 60 + 59));
        assert!(!w.is_open(5, 17 * 60 + 31));
        // 非法输入回落到默认（全天/全周）
        let w = RunWindow::parse(true, "9:0", "25:00", "0");
        assert_eq!(w.start_min, 0);
        assert_eq!(w.end_min, 23 * 60 + 59);
        assert_eq!(w.days.len(), 7);
    }

    #[test]
    fn quota_periods_and_exceeded() {
        assert_eq!(QuotaPeriod::Hour.bucket_start_secs(3600 * 5 + 61), 3600 * 5);
        let day = QuotaPeriod::Day.bucket_start_secs(86_400 * 3 + 500);
        assert_eq!(day, 86_400 * 3);
        let w1 = QuotaPeriod::Week.bucket_start_secs(0);
        assert_eq!(w1, -3 * 86_400, "1970-01-01 是周四，周一为周首");
        assert_eq!(
            QuotaPeriod::Week.bucket_start_secs(86_400 * 4),
            -3 * 86_400 + 7 * 86_400
        );

        let q = Quota::parse(true, 10, "day", "pause");
        assert_eq!(q.limit_bytes(), 10 * 1024 * 1024);
        assert!(!q.exceeded(9 * 1024 * 1024, 1024 * 1024));
        assert!(q.exceeded(9 * 1024 * 1024, 2 * 1024 * 1024));
        let off = Quota::parse(false, 1, "day", "stop");
        assert!(!off.exceeded(u64::MAX, u64::MAX));
        assert_eq!(QuotaAction::parse("stop"), QuotaAction::Stop);
        assert_eq!(QuotaAction::parse("whatever"), QuotaAction::Pause);
    }

    #[test]
    fn after_done_parsing() {
        assert_eq!(AfterDone::parse("shutdown"), AfterDone::Shutdown);
        assert_eq!(AfterDone::parse("hibernate"), AfterDone::Hibernate);
        assert_eq!(AfterDone::parse("sleep"), AfterDone::Sleep);
        assert_eq!(AfterDone::parse("disconnect"), AfterDone::Disconnect);
        assert_eq!(AfterDone::parse("exit"), AfterDone::Exit);
        assert_eq!(AfterDone::parse(""), AfterDone::None);
        assert_eq!(AfterDone::parse("reboot"), AfterDone::None);
        assert!(!AfterDone::None.is_action());
        assert!(AfterDone::Shutdown.is_action());
    }

    #[test]
    fn host_pattern_matching() {
        let pats = vec!["example.com".to_string(), "*.internal.test".to_string()];
        assert!(host_matches_any(&pats, "EXAMPLE.com"));
        assert!(host_matches_any(&pats, "internal.test"));
        assert!(host_matches_any(&pats, "a.b.internal.test"));
        assert!(!host_matches_any(&pats, "notinternal.test"));
        assert!(!host_matches_any(&pats, "example.com.evil.net"));
        assert!(!host_matches_any(&pats, ""));
        assert!(host_matches_any(&[], "x.com") == false);
    }

    #[test]
    fn queue_waits_for_cron_now_does_not() {
        let expr = cron::parse("0 2 * * *").unwrap().unwrap();
        let created = chrono::Local
            .with_ymd_and_hms(2024, 6, 15, 1, 0, 0)
            .single()
            .unwrap()
            .timestamp();
        let before = chrono::Local
            .with_ymd_and_hms(2024, 6, 15, 1, 30, 0)
            .single()
            .unwrap()
            .timestamp_millis();
        let after = chrono::Local
            .with_ymd_and_hms(2024, 6, 15, 2, 0, 0)
            .single()
            .unwrap()
            .timestamp_millis();
        assert!(is_eligible("now", Some(&expr), created, before));
        assert!(!is_eligible("queue", Some(&expr), created, before));
        assert!(is_eligible("queue", Some(&expr), created, after));
        assert!(is_eligible("queue", None, created, before));
    }
}
