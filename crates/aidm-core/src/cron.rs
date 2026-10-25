//! 5 段 cron（分 时 日 月 周），按**本地时区**解释。空串表示关闭。

use std::collections::BTreeSet;

use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};

const MINUTE: FieldSpec = FieldSpec {
    min: 0,
    max: 59,
    names: &[],
};
const HOUR: FieldSpec = FieldSpec {
    min: 0,
    max: 23,
    names: &[],
};
const DOM: FieldSpec = FieldSpec {
    min: 1,
    max: 31,
    names: &[],
};
const MONTH: FieldSpec = FieldSpec {
    min: 1,
    max: 12,
    names: &[
        ("JAN", 1),
        ("FEB", 2),
        ("MAR", 3),
        ("APR", 4),
        ("MAY", 5),
        ("JUN", 6),
        ("JUL", 7),
        ("AUG", 8),
        ("SEP", 9),
        ("OCT", 10),
        ("NOV", 11),
        ("DEC", 12),
    ],
};
const DOW: FieldSpec = FieldSpec {
    min: 0,
    max: 7,
    names: &[
        ("SUN", 0),
        ("MON", 1),
        ("TUE", 2),
        ("WED", 3),
        ("THU", 4),
        ("FRI", 5),
        ("SAT", 6),
    ],
};

struct FieldSpec {
    min: u8,
    max: u8,
    names: &'static [(&'static str, u8)],
}

/// 已解析的 5 段 cron。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    minutes: Vec<u8>,
    hours: Vec<u8>,
    dom: Vec<u8>,
    months: Vec<u8>,
    dow: Vec<u8>,
    dom_star: bool,
    dow_star: bool,
}

/// 本地时间的 `(ISO 星期 1..=7, 当日分钟 0..=1439)`。
///
/// 运行时段用它判断"现在是否允许下载"；引擎进程不直接依赖
/// chrono，所以放在这里。
pub fn local_weekday_minute(now_secs: i64) -> (u8, u16) {
    let dt = Local
        .timestamp_opt(now_secs, 0)
        .single()
        .or_else(|| Local.timestamp_opt(0, 0).single());
    match dt {
        Some(dt) => (
            dt.weekday().number_from_monday() as u8,
            (dt.hour() * 60 + dt.minute()) as u16,
        ),
        None => (1, 0),
    }
}

/// 解析 5 段 cron。空 / 空白 → `Ok(None)`（关闭）。非法 → `Err`。
pub fn parse(s: &str) -> Result<Option<CronExpr>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 5 {
        return Err("invalid_cron".into());
    }
    let minutes = parse_field(parts[0], MINUTE).map_err(|_| "invalid_cron".to_string())?;
    let hours = parse_field(parts[1], HOUR).map_err(|_| "invalid_cron".to_string())?;
    let dom = parse_field(parts[2], DOM).map_err(|_| "invalid_cron".to_string())?;
    let months = parse_field(parts[3], MONTH).map_err(|_| "invalid_cron".to_string())?;
    let mut dow = parse_field(parts[4], DOW).map_err(|_| "invalid_cron".to_string())?;
    for v in &mut dow {
        if *v == 7 {
            *v = 0;
        }
    }
    dow.sort_unstable();
    dow.dedup();
    Ok(Some(CronExpr {
        minutes,
        hours,
        dom,
        months,
        dow,
        dom_star: parts[2] == "*",
        dow_star: parts[4] == "*",
    }))
}

/// 当前这一分钟是否命中表达式（队列时间窗用）。
///
/// 定义：把"上一分钟的起点"当作搜索起点，若下一次触发落在 `now_ms` 之前或正好，
/// 就说明**包含 now 的那一分钟**命中。用 `next_fire_ms`（严格取下一分钟）实现，
/// 避免为"当前分钟"另写一套匹配规则而与触发逻辑分叉。
pub fn matches_now(expr: &CronExpr, now_ms: i64) -> bool {
    match next_fire_ms(expr, now_ms.saturating_sub(60_000)) {
        Some(t) => t <= now_ms,
        None => false,
    }
}

/// `from_ms` 之后（不含该分钟）下一次触发的 unix 毫秒。最多向前搜 366 天。
pub fn next_fire_ms(expr: &CronExpr, from_ms: i64) -> Option<i64> {
    let from = Local.timestamp_millis_opt(from_ms).single()?;
    let start = from + chrono::Duration::try_minutes(1)?;
    let start = start.with_second(0)?.with_nanosecond(0)?;
    let mut dt = start;
    for _ in 0..(366 * 24 * 60) {
        if matches_cron(expr, dt) {
            return Some(dt.timestamp_millis());
        }
        dt += chrono::Duration::try_minutes(1)?;
    }
    None
}

fn matches_cron(expr: &CronExpr, dt: DateTime<Local>) -> bool {
    if !expr.minutes.contains(&(dt.minute() as u8)) {
        return false;
    }
    if !expr.hours.contains(&(dt.hour() as u8)) {
        return false;
    }
    if !expr.months.contains(&(dt.month() as u8)) {
        return false;
    }
    let dom_ok = expr.dom.contains(&(dt.day() as u8));
    let dow_ok = expr
        .dow
        .contains(&(dt.weekday().num_days_from_sunday() as u8));
    if expr.dom_star || expr.dow_star {
        (expr.dom_star || dom_ok) && (expr.dow_star || dow_ok)
    } else {
        dom_ok || dow_ok
    }
}

fn parse_field(raw: &str, spec: FieldSpec) -> Result<Vec<u8>, ()> {
    let mut out = BTreeSet::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(());
        }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u8>().map_err(|_| ())?),
            None => (part, 1u8),
        };
        if step == 0 {
            return Err(());
        }
        let (lo, hi) = if range == "*" {
            (spec.min, spec.max)
        } else if let Some((a, b)) = range.split_once('-') {
            (parse_atom(a, spec.names)?, parse_atom(b, spec.names)?)
        } else {
            let v = parse_atom(range, spec.names)?;
            (v, v)
        };
        if lo < spec.min || hi > spec.max || lo > hi {
            return Err(());
        }
        let mut v = lo;
        while v <= hi {
            if (v - lo) % step == 0 {
                let mut store = v;
                if spec.max == 7 && store == 7 {
                    store = 0;
                }
                if store >= spec.min && (store <= spec.max || store == 0) {
                    out.insert(store);
                }
            }
            if v == u8::MAX {
                break;
            }
            v += 1;
        }
    }
    if out.is_empty() {
        return Err(());
    }
    Ok(out.into_iter().collect())
}

fn parse_atom(s: &str, names: &[(&str, u8)]) -> Result<u8, ()> {
    let t = s.trim();
    if let Ok(n) = t.parse::<u8>() {
        return Ok(n);
    }
    let up = t.to_ascii_uppercase();
    names
        .iter()
        .find(|(n, _)| *n == up)
        .map(|(_, v)| *v)
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_off() {
        assert_eq!(parse("").unwrap(), None);
        assert_eq!(parse("   ").unwrap(), None);
    }

    #[test]
    fn reject_malformed() {
        assert!(parse("not-a-cron").is_err());
        assert!(parse("* * *").is_err());
        assert!(parse("* * * * * *").is_err());
        assert!(parse("60 * * * *").is_err());
        assert!(parse("* 24 * * *").is_err());
        assert!(parse("1-70 * * * *").is_err());
        assert!(parse("*/0 * * * *").is_err());
        assert!(parse("-1 * * * *").is_err());
    }

    #[test]
    fn parse_every_minute_and_lists() {
        let every = parse("* * * * *").unwrap().unwrap();
        assert_eq!(every.minutes.len(), 60);
        let hourly = parse("0 * * * *").unwrap().unwrap();
        assert_eq!(hourly.minutes, vec![0]);
        let list = parse("0,15,30,45 1-2 * * 1-5").unwrap().unwrap();
        assert_eq!(list.minutes, vec![0, 15, 30, 45]);
        assert_eq!(list.hours, vec![1, 2]);
    }

    #[test]
    fn matches_now_is_true_only_inside_the_matching_minute() {
        let expr = parse("30 14 * * *").unwrap().unwrap();
        // 用**本地时间**构造：cron 段按本地时间解释（`local_weekday_minute`）。
        let base = Local
            .with_ymd_and_hms(2026, 10, 15, 14, 30, 0)
            .unwrap()
            .timestamp_millis();
        assert!(matches_now(&expr, base));
        assert!(matches_now(&expr, base + 59_000));
        assert!(!matches_now(&expr, base - 1_000));
        assert!(!matches_now(&expr, base + 60_000));
        assert!(!matches_now(&expr, base - 3_600_000));
    }

    #[test]
    fn next_fire_hourly() {
        let expr = parse("0 * * * *").unwrap().unwrap();
        // 2024-06-15 10:07:30 local
        let from = Local
            .with_ymd_and_hms(2024, 6, 15, 10, 7, 30)
            .single()
            .unwrap()
            .timestamp_millis();
        let next = next_fire_ms(&expr, from).unwrap();
        let dt = Local.timestamp_millis_opt(next).single().unwrap();
        assert_eq!(dt.hour(), 11);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn next_fire_daily_2am() {
        let expr = parse("0 2 * * *").unwrap().unwrap();
        let from = Local
            .with_ymd_and_hms(2024, 6, 15, 3, 0, 0)
            .single()
            .unwrap()
            .timestamp_millis();
        let next = next_fire_ms(&expr, from).unwrap();
        let dt = Local.timestamp_millis_opt(next).single().unwrap();
        assert_eq!(
            (dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute()),
            (2024, 6, 16, 2, 0)
        );
    }

    #[test]
    fn names_and_dow_7_is_sunday() {
        let a = parse("0 0 1 JAN SUN").unwrap().unwrap();
        let b = parse("0 0 1 1 7").unwrap().unwrap();
        assert_eq!(a.months, vec![1]);
        assert_eq!(b.dow, vec![0]);
        assert_eq!(a.dow, vec![0]);
    }
}
