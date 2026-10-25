//! 调度 / 队列展示纯逻辑（无 IO）。与 `ui/app.js` 对齐。

// 本模块是 `ui/app.js` 对应逻辑的 Rust 规格镜像：二进制只消费其中少数入口
// （见 `main.rs` 的模块注释），其余条目只被本文件的 `#[cfg(test)] mod tests`
// 使用。这里显式声明，避免每条规格都报 `never used` 把真正的告警淹掉。
#![allow(dead_code)]

pub const CRON_HINT: &str = "按 分 时 日 月 周 填写，例如 0 2 * * * 表示每天 2:00";
pub const CRON_INVALID: &str = "定时格式不对，例如 0 2 * * *";
pub const SCHED_HELP: &str = "开启后，加入队列的任务会等到点再开始；立即下载不受影响";
pub const AFTER_DONE_LABEL: &str = "全部完成后关机（暂未开放）";
pub const AFTER_DONE_VALUE: &str = "none";
pub const RETRY_ALL_TOAST_PREFIX: &str = "已重新排队";
pub const RETRY_ALL_FAIL: &str = "重试失败，请稍后再试";
pub const RETRY_ALL_TIP: &str = "把所有失败的任务重新排队";

pub const CONN_GLOBAL_RANGE: &str = "请输入 1–1024 之间的整数";
pub const CONN_RETRY_MAX_RANGE: &str = "请输入 0–20 之间的整数";
pub const CONN_BACKOFF_SEC_RANGE: &str = "请输入 0.1–60 秒";
pub const RETRY_BACKOFF_NOTE: &str = "之后每次加倍，最长 60 秒";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    /// 0 = 周日 … 6 = 周六（与 JS `Date.getDay()` 一致）。
    pub weekday: u32,
}

pub fn format_next_start(at: CivilTime, now: CivilTime) -> String {
    let hm = format!("{:02}:{:02}", at.hour, at.minute);
    if at.year == now.year && at.month == now.month && at.day == now.day {
        return format!("今天 {hm}");
    }
    let tom = add_days(now, 1);
    if at.year == tom.year && at.month == tom.month && at.day == tom.day {
        return format!("明天 {hm}");
    }
    if at.year != now.year {
        return format!("{}年{}月{}日 {hm}", at.year, at.month, at.day);
    }
    format!("{}月{}日 {hm}", at.month, at.day)
}

pub fn format_retry_countdown(remain_ms: i64) -> String {
    if remain_ms <= 0 {
        return "即将重试".into();
    }
    let sec = ((remain_ms + 999) / 1000) as u64;
    if sec < 60 {
        return format!("{sec} 秒后");
    }
    let m = sec / 60;
    let s = sec % 60;
    if m < 60 {
        if s == 0 {
            format!("{m} 分钟后")
        } else {
            format!("{m} 分 {:02} 秒后", s)
        }
    } else {
        let h = m / 60;
        let mm = m % 60;
        format!("{h} 小时 {mm} 分钟后")
    }
}

/// 排队状态文案：退避中显示倒计时，否则就是"排队中"。
///
/// 刻意**不**显示"第 N 位"：派发顺序只有一套权威 —— 入队先后（id）。
pub fn format_queue_status(retry_at_ms: Option<u64>, now_ms: u64) -> String {
    if let Some(at) = retry_at_ms {
        let remain = at as i64 - now_ms as i64;
        return format!("等待重试 · {}", format_retry_countdown(remain));
    }
    "排队中".into()
}

pub fn retry_tooltip(retries: Option<u32>, retry_max: u32) -> Option<String> {
    let n = retries?;
    if n == 0 {
        return None;
    }
    Some(format!("第 {n}/{retry_max} 次重试"))
}

/// `ok=false` → 失败 toast；成功且 `count==0` → 不 toast；`count>0` → 重新排队文案。
pub fn retry_all_toast(ok: bool, count: u64) -> Option<String> {
    if !ok {
        return Some(RETRY_ALL_FAIL.into());
    }
    if count == 0 {
        return None;
    }
    Some(format!("{RETRY_ALL_TOAST_PREFIX} {count} 个任务"))
}

pub fn queue_start_hint(next_label: &str) -> String {
    format!("将于 {next_label} 开始")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedMode {
    Off,
    Daily,
    Weekdays,
    Custom,
}

pub fn cron_from_preset(mode: SchedMode, hour: u32, minute: u32, custom: &str) -> String {
    match mode {
        SchedMode::Off => String::new(),
        SchedMode::Daily => format!("{minute} {hour} * * *"),
        SchedMode::Weekdays => format!("{minute} {hour} * * 1-5"),
        SchedMode::Custom => custom.trim().to_string(),
    }
}

/// 展示用 5 段拆分（不依赖引擎内部 cron 解析器）。
fn cron_parts(expr: &str) -> Option<[&str; 5]> {
    let mut it = expr.trim().split_whitespace();
    let a = it.next()?;
    let b = it.next()?;
    let c = it.next()?;
    let d = it.next()?;
    let e = it.next()?;
    if it.next().is_some() {
        return None;
    }
    Some([a, b, c, d, e])
}

fn is_valid_cron_5(expr: &str) -> bool {
    aidm_core::cron::parse(expr).is_ok()
}

fn cron_field_ok(field: &str, min: i32, max: i32) -> bool {
    !field.is_empty() && field.split(',').all(|atom| cron_atom_ok(atom, min, max))
}

fn cron_atom_ok(atom: &str, min: i32, max: i32) -> bool {
    let parts: Vec<&str> = atom.split('/').collect();
    if parts.len() > 2 {
        return false;
    }
    if parts.len() == 2 {
        let Ok(step) = parts[1].parse::<i32>() else {
            return false;
        };
        if step <= 0 {
            return false;
        }
    }
    let range = parts[0];
    if range == "*" {
        return true;
    }
    if let Some((a, b)) = range.split_once('-') {
        let (Ok(lo), Ok(hi)) = (a.parse::<i32>(), b.parse::<i32>()) else {
            return false;
        };
        return lo >= min && hi <= max && lo <= hi;
    }
    let Ok(n) = range.parse::<i32>() else {
        return false;
    };
    n >= min && n <= max
}

fn cron_field_matches(field: &str, value: i32, min: i32, max: i32) -> bool {
    cron_field_ok(field, min, max)
        && field
            .split(',')
            .any(|atom| cron_atom_matches(atom, value, min, max))
}

fn cron_atom_matches(atom: &str, value: i32, min: i32, max: i32) -> bool {
    let slash: Vec<&str> = atom.split('/').collect();
    let range = slash[0];
    let step = if slash.len() > 1 {
        slash[1].parse::<i32>().unwrap_or(1)
    } else {
        1
    };
    if range == "*" {
        return (value - min) % step == 0;
    }
    if let Some((a, b)) = range.split_once('-') {
        let lo = a.parse::<i32>().unwrap_or(0);
        let hi = b.parse::<i32>().unwrap_or(0);
        return value >= lo && value <= hi && (value - lo) % step == 0;
    }
    let n = range.parse::<i32>().unwrap_or(i32::MIN);
    if slash.len() > 1 {
        return value >= n && value <= max && (value - n) % step == 0;
    }
    n == value
}

pub fn parse_sched_mode(cron: &str) -> (SchedMode, Option<(u32, u32)>) {
    let t = cron.trim();
    if t.is_empty() {
        return (SchedMode::Off, None);
    }
    let Some(parts) = cron_parts(t) else {
        return (SchedMode::Custom, None);
    };
    let (Ok(minute), Ok(hour)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) else {
        return (SchedMode::Custom, None);
    };
    if hour > 23 || minute > 59 {
        return (SchedMode::Custom, None);
    }
    if parts[2] == "*" && parts[3] == "*" && parts[4] == "*" {
        return (SchedMode::Daily, Some((hour, minute)));
    }
    if parts[2] == "*" && parts[3] == "*" && parts[4] == "1-5" {
        return (SchedMode::Weekdays, Some((hour, minute)));
    }
    (SchedMode::Custom, None)
}

pub fn cron_error_text(expr: &str) -> Option<&'static str> {
    if is_valid_cron_5(expr) {
        None
    } else {
        Some(CRON_INVALID)
    }
}

pub fn next_cron_civil(cron: &str, mut now: CivilTime) -> Option<CivilTime> {
    if cron.trim().is_empty() || !is_valid_cron_5(cron) {
        return None;
    }
    let parts = cron_parts(cron.trim())?;
    add_minute(&mut now);
    for _ in 0..(366 * 24 * 60) {
        if civil_matches(parts, now) {
            return Some(now);
        }
        add_minute(&mut now);
    }
    None
}

fn civil_matches(parts: [&str; 5], t: CivilTime) -> bool {
    let dow_cron = t.weekday as i32; // 0=Sun
    cron_field_matches(parts[0], t.minute as i32, 0, 59)
        && cron_field_matches(parts[1], t.hour as i32, 0, 23)
        && cron_field_matches(parts[2], t.day as i32, 1, 31)
        && cron_field_matches(parts[3], t.month as i32, 1, 12)
        && (cron_field_matches(parts[4], dow_cron, 0, 7)
            || (dow_cron == 0 && cron_field_matches(parts[4], 7, 0, 7)))
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

fn add_days(mut t: CivilTime, days: u32) -> CivilTime {
    for _ in 0..days {
        t.weekday = (t.weekday + 1) % 7;
        t.day += 1;
        let dim = days_in_month(t.year, t.month);
        if t.day > dim {
            t.day = 1;
            t.month += 1;
            if t.month > 12 {
                t.month = 1;
                t.year += 1;
            }
        }
    }
    t
}

fn add_minute(t: &mut CivilTime) {
    t.minute += 1;
    if t.minute < 60 {
        return;
    }
    t.minute = 0;
    t.hour += 1;
    if t.hour < 24 {
        return;
    }
    t.hour = 0;
    *t = add_days(*t, 1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnField {
    pub key: &'static str,
    pub min: i64,
    pub max: i64,
    pub default: &'static str,
    pub range_msg: &'static str,
}

pub const CONN_FIELDS: &[ConnField] = &[
    ConnField {
        key: "conn.global_conn_cap",
        min: 1,
        max: 1024,
        default: "256",
        range_msg: CONN_GLOBAL_RANGE,
    },
    ConnField {
        key: "conn.retry_max",
        min: 0,
        max: 20,
        default: "5",
        range_msg: CONN_RETRY_MAX_RANGE,
    },
];

pub fn conn_field(key: &str) -> Option<&'static ConnField> {
    CONN_FIELDS.iter().find(|f| f.key == key)
}

pub fn parse_int_in_range(raw: &str, min: i64, max: i64) -> Result<i64, ()> {
    let n: i64 = raw.trim().parse().map_err(|_| ())?;
    if n < min || n > max {
        return Err(());
    }
    Ok(n)
}

/// 界面秒 → `conn.retry_backoff_ms`（引擎范围 100–60000 ms）。
pub fn backoff_ms_from_seconds(raw: &str) -> Result<u64, &'static str> {
    let secs: f64 = raw.trim().parse().map_err(|_| CONN_BACKOFF_SEC_RANGE)?;
    if !secs.is_finite() || secs < 0.1 || secs > 60.0 {
        return Err(CONN_BACKOFF_SEC_RANGE);
    }
    Ok((secs * 1000.0).round() as u64)
}

pub fn seconds_from_backoff_ms(ms: &str) -> String {
    let n: f64 = ms.trim().parse().unwrap_or(1000.0);
    format_seconds_label(n / 1000.0)
}

fn format_seconds_label(secs: f64) -> String {
    if (secs - secs.round()).abs() < 1e-9 {
        format!("{}", secs.round() as i64)
    } else {
        let s = format!("{secs}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

fn format_ms_as_seconds(ms: i64) -> String {
    format_seconds_label(ms as f64 / 1000.0)
}

/// 设置项校验失败：只认 `invalid_value`（带 min/max）与 `invalid_cron`。
pub fn settings_set_user_error(
    key: &str,
    code: &str,
    min: Option<i64>,
    max: Option<i64>,
) -> String {
    let code = code.trim();
    if code == "invalid_cron" {
        return CRON_INVALID.into();
    }
    if code == "invalid_value" {
        if let (Some(min), Some(max)) = (min, max) {
            if key == "conn.retry_backoff_ms" {
                return format!(
                    "请输入 {}–{} 秒",
                    format_ms_as_seconds(min),
                    format_ms_as_seconds(max)
                );
            }
            return format!("请输入 {min}–{max} 之间的整数");
        }
    }
    crate::logic::SETTINGS_SAVE_FAILED.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_display::{EXT_AUTH_EXPIRED, FAIL_GENERIC, FAIL_HTTP_403};

    #[test]
    fn cron_preset_generation_and_parse() {
        assert_eq!(cron_from_preset(SchedMode::Off, 2, 0, ""), "");
        assert_eq!(cron_from_preset(SchedMode::Daily, 2, 0, ""), "0 2 * * *");
        assert_eq!(
            cron_from_preset(SchedMode::Weekdays, 8, 30, ""),
            "30 8 * * 1-5"
        );
        assert_eq!(
            cron_from_preset(SchedMode::Custom, 0, 0, "  */5 * * * * "),
            "*/5 * * * *"
        );
        assert_eq!(parse_sched_mode(""), (SchedMode::Off, None));
        assert_eq!(
            parse_sched_mode("0 2 * * *"),
            (SchedMode::Daily, Some((2, 0)))
        );
        assert_eq!(
            parse_sched_mode("30 8 * * 1-5"),
            (SchedMode::Weekdays, Some((8, 30)))
        );
        assert_eq!(parse_sched_mode("*/5 * * * *"), (SchedMode::Custom, None));
        assert_eq!(cron_error_text(""), None);
        assert_eq!(cron_error_text("0 2 * * *"), None);
        assert_eq!(cron_error_text("0 2 * *"), Some(CRON_INVALID));
        assert_eq!(
            CRON_HINT,
            "按 分 时 日 月 周 填写，例如 0 2 * * * 表示每天 2:00"
        );
        assert_eq!(
            SCHED_HELP,
            "开启后，加入队列的任务会等到点再开始；立即下载不受影响"
        );
        assert_eq!(AFTER_DONE_LABEL, "全部完成后关机（暂未开放）");
        assert_eq!(AFTER_DONE_VALUE, "none");
    }

    #[test]
    fn next_start_label_today_tomorrow() {
        let now = CivilTime {
            year: 2026,
            month: 10,
            day: 11,
            hour: 14,
            minute: 0,
            weekday: 0,
        };
        let today = CivilTime {
            hour: 16,
            minute: 5,
            ..now
        };
        assert_eq!(format_next_start(today, now), "今天 16:05");
        let tom = CivilTime {
            year: 2026,
            month: 10,
            day: 12,
            hour: 2,
            minute: 0,
            weekday: 1,
        };
        assert_eq!(format_next_start(tom, now), "明天 02:00");
        let later = CivilTime {
            year: 2026,
            month: 11,
            day: 1,
            hour: 9,
            minute: 0,
            weekday: 0,
        };
        assert_eq!(format_next_start(later, now), "11月1日 09:00");
    }

    #[test]
    fn next_cron_daily_rolls_to_tomorrow() {
        let now = CivilTime {
            year: 2026,
            month: 10,
            day: 11,
            hour: 3,
            minute: 0,
            weekday: 0,
        };
        let next = next_cron_civil("0 2 * * *", now).unwrap();
        assert_eq!(format_next_start(next, now), "明天 02:00");
        let morning = CivilTime {
            hour: 1,
            minute: 10,
            ..now
        };
        let next = next_cron_civil("0 2 * * *", morning).unwrap();
        assert_eq!(format_next_start(next, morning), "今天 02:00");
    }

    #[test]
    fn countdown_and_queue_status() {
        assert_eq!(format_retry_countdown(12_000), "12 秒后");
        assert_eq!(format_retry_countdown(0), "即将重试");
        assert_eq!(format_retry_countdown(-5), "即将重试");
        assert_eq!(format_retry_countdown(65_000), "1 分 05 秒后");
        assert_eq!(format_retry_countdown(120_000), "2 分钟后");
        assert_eq!(format_queue_status(None, 0), "排队中");
        assert_eq!(
            format_queue_status(Some(1_000 + 12_000), 1_000),
            "等待重试 · 12 秒后"
        );
        assert_eq!(retry_tooltip(Some(2), 5).as_deref(), Some("第 2/5 次重试"));
        assert_eq!(retry_tooltip(None, 5), None);
        assert_eq!(retry_tooltip(Some(0), 5), None);
        assert_eq!(queue_start_hint("明天 02:00"), "将于 明天 02:00 开始");
    }

    #[test]
    fn retry_all_toast_only_when_count_positive_or_request_failed() {
        assert_eq!(
            retry_all_toast(true, 3).as_deref(),
            Some("已重新排队 3 个任务")
        );
        assert_eq!(retry_all_toast(true, 0), None);
        assert_eq!(retry_all_toast(false, 0).as_deref(), Some(RETRY_ALL_FAIL));
        assert_eq!(retry_all_toast(false, 5).as_deref(), Some(RETRY_ALL_FAIL));
        assert_eq!(RETRY_ALL_TIP, "把所有失败的任务重新排队");
    }

    #[test]
    fn settings_key_mapping_and_backoff() {
        assert_eq!(parse_int_in_range("3", 1, 16), Ok(3));
        assert_eq!(parse_int_in_range("17", 1, 16), Err(()));
        assert_eq!(backoff_ms_from_seconds("1").unwrap(), 1000);
        assert_eq!(backoff_ms_from_seconds("0.1").unwrap(), 100);
        assert_eq!(
            backoff_ms_from_seconds("0").unwrap_err(),
            CONN_BACKOFF_SEC_RANGE
        );
        assert_eq!(
            backoff_ms_from_seconds("61").unwrap_err(),
            CONN_BACKOFF_SEC_RANGE
        );
        assert_eq!(seconds_from_backoff_ms("1000"), "1");
        assert_eq!(seconds_from_backoff_ms("100"), "0.1");
        assert_eq!(RETRY_BACKOFF_NOTE, "之后每次加倍，最长 60 秒");
        assert_eq!(
            settings_set_user_error(
                "conn.retry_backoff_ms",
                "invalid_value",
                Some(100),
                Some(60_000)
            ),
            "请输入 0.1–60 秒"
        );
        assert_eq!(
            settings_set_user_error("sched.start_cron", "invalid_cron", None, None),
            CRON_INVALID
        );
        assert_eq!(
            settings_set_user_error("sched.start_cron", "cron_invalid", None, None),
            crate::logic::SETTINGS_SAVE_FAILED
        );
        assert_eq!(
            settings_set_user_error(
                "sched.start_cron",
                "定时格式不对，例如 0 2 * * *",
                None,
                None
            ),
            crate::logic::SETTINGS_SAVE_FAILED
        );
        assert_eq!(
            settings_set_user_error("proxy.mode", "proxy_mode_invalid", None, None),
            crate::logic::SETTINGS_SAVE_FAILED
        );
    }

    #[test]
    fn error_code_not_error_text_for_401_403() {
        assert_eq!(
            crate::error_display::task_fail_reason(Some("http_401"), Some("ext"), None),
            EXT_AUTH_EXPIRED
        );
        assert_eq!(
            crate::error_display::task_fail_reason(Some("http_403"), Some("manual"), None),
            FAIL_HTTP_403
        );
        assert_eq!(
            crate::error_display::task_fail_reason(None, Some("ext"), Some("http_401")),
            FAIL_GENERIC
        );
        assert_eq!(
            crate::error_display::task_fail_reason(None, Some("ext"), Some("401")),
            FAIL_GENERIC
        );
    }
}
