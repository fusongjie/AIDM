//! 按服务器（主机）覆盖的设置。
//!
//! 全局有一个默认连接数，某些服务器需要单独调大或调小。
//! 主机名存成一张表，主机模式（精确 / `*.example.com`）由
//! [`crate::sched::host_matches`] 统一匹配，并允许在下载途中热应用
//! （`Apply::LiveLimits`）。

use rusqlite::Connection;

use crate::sched;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOverride {
    pub host: String,
    /// `None` = 不覆盖全局值
    pub max_conns: Option<i64>,
    pub speed_limit_kbps: Option<i64>,
    pub updated_at: i64,
}

/// 全部覆盖项（按主机名排序，便于 UI 稳定展示）。
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<HostOverride>> {
    let mut stmt = conn.prepare(
        "SELECT host, max_conns, speed_limit_kbps, updated_at
         FROM host_settings ORDER BY host",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(HostOverride {
            host: r.get(0)?,
            max_conns: r.get(1)?,
            speed_limit_kbps: r.get(2)?,
            updated_at: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// 写入/更新一项。`max_conns` 与 `speed_limit_kbps` 都为 `None` 时等价于删除。
pub fn set(
    conn: &Connection,
    host: &str,
    max_conns: Option<i64>,
    speed_limit_kbps: Option<i64>,
) -> rusqlite::Result<Option<HostOverride>> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Ok(None);
    }
    if max_conns.is_none() && speed_limit_kbps.is_none() {
        remove(conn, &host)?;
        return Ok(None);
    }
    let now = crate::model::now_secs();
    conn.execute(
        "INSERT INTO host_settings(host, max_conns, speed_limit_kbps, updated_at)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(host) DO UPDATE SET
            max_conns = excluded.max_conns,
            speed_limit_kbps = excluded.speed_limit_kbps,
            updated_at = excluded.updated_at",
        rusqlite::params![host, max_conns, speed_limit_kbps, now],
    )?;
    Ok(Some(HostOverride {
        host,
        max_conns,
        speed_limit_kbps,
        updated_at: now,
    }))
}

pub fn remove(conn: &Connection, host: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM host_settings WHERE host = ?1",
        [normalize_host(host)],
    )
}

/// 命中该主机的覆盖项；精确匹配优先，其次是最具体的 `*.` 通配。
pub fn lookup(conn: &Connection, host: &str) -> rusqlite::Result<Option<HostOverride>> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Ok(None);
    }
    let all = list(conn)?;
    if let Some(exact) = all.iter().find(|o| o.host == host) {
        return Ok(Some(exact.clone()));
    }
    // 通配按后缀长度降序，保证 `*.a.b` 比 `*.b` 更优先
    let mut wild: Vec<&HostOverride> = all
        .iter()
        .filter(|o| o.host.starts_with("*.") && sched::host_matches(&o.host, &host))
        .collect();
    wild.sort_by_key(|o| std::cmp::Reverse(o.host.len()));
    Ok(wild.first().map(|o| (*o).clone()))
}

/// 该主机最终生效的最大连接数：覆盖项优先，否则用任务/全局值。
///
/// `global`（任务侧的值）与覆盖项都可以是 **0 = 不限**；不限原样返回 0，
/// 由调用方按全局闸门收窄。正数则夹到 `cap`（= 全局闸门）。
pub fn effective_max_conns(conn: &Connection, host: &str, global: i64, cap: i64) -> i64 {
    let all = list(conn).unwrap_or_default();
    effective_with(&all, host, global, cap)
}

/// 同上，但覆盖项由调用方一次查好（列表 / 快照循环里避免逐行查库）。
pub fn effective_with(overrides: &[HostOverride], host: &str, global: i64, cap: i64) -> i64 {
    let host = normalize_host(host);
    let hit = overrides.iter().find(|o| o.host == host).or_else(|| {
        // 通配按后缀长度降序，保证 `*.a.b` 比 `*.b` 更优先
        let mut wild: Vec<&HostOverride> = overrides
            .iter()
            .filter(|o| o.host.starts_with("*.") && sched::host_matches(&o.host, &host))
            .collect();
        wild.sort_by_key(|o| std::cmp::Reverse(o.host.len()));
        wild.first().copied()
    });
    let raw = hit.and_then(|o| o.max_conns).unwrap_or(global);
    if raw <= 0 {
        return 0;
    }
    raw.min(cap.max(1))
}

/// 任务实际生效的连接预算（**唯一解析器**，恒 ≥ 1）。
///
/// 优先级只有两级：每服务器例外（`host_settings.max_conns`）> 全局闸门
/// （`conn.global_conn_cap`）。
///
/// 任务行里那份 `downloads.max_conns` 是**派生值**（每次派发写回解析结果），
/// 它**不参与解析**：派生值一旦落库，用户改设置就永远不生效。
pub fn task_conns(conn: &Connection, url: &str) -> u32 {
    let cap = crate::settings::sched_gates(conn).max_conns_total.max(1);
    let host = crate::sched::url_host(url);
    let effective = effective_max_conns(conn, &host, 0, cap as i64);
    crate::segment::desired_conns(effective, cap)
}

/// 该主机最终生效的每任务限速（kbps）：覆盖项优先，否则用全局默认。
pub fn effective_speed_limit_kbps(conn: &Connection, host: &str, global: i64) -> i64 {
    lookup(conn, host)
        .ok()
        .flatten()
        .and_then(|o| o.speed_limit_kbps)
        .unwrap_or(global)
        .max(0)
}

/// 主机名归一：小写、去空白；保留 `*.` 通配前缀。
pub fn normalize_host(host: &str) -> String {
    let h = host.trim().to_ascii_lowercase();
    let h = h
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let h = h.split('/').next().unwrap_or(h);
    let h = h.split(':').next().unwrap_or(h);
    h.trim_end_matches('.').to_string()
}

/// 校验主机模式（UI/IPC 写入前调用）。
pub fn validate_pattern(host: &str) -> Result<String, String> {
    let h = normalize_host(host);
    if h.is_empty() || h.len() > 253 {
        return Err("host_invalid".into());
    }
    let body = h.trim_start_matches("*.");
    if body.is_empty() {
        return Err("host_invalid".into());
    }
    let ok = body.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    if !ok {
        return Err("host_invalid".into());
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db;
    use std::path::Path;

    fn mem() -> Connection {
        open_db(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn set_lookup_and_effective() {
        let conn = mem();
        assert!(list(&conn).unwrap().is_empty());
        set(&conn, "CDN.Example.com", Some(16), None).unwrap();
        set(&conn, "*.mirror.test", Some(4), Some(512)).unwrap();

        let o = lookup(&conn, "cdn.example.com").unwrap().unwrap();
        assert_eq!(o.max_conns, Some(16));
        // 精确匹配优先
        assert_eq!(effective_max_conns(&conn, "cdn.example.com", 8, 32), 16);
        // 未命中的主机用全局值
        assert_eq!(effective_max_conns(&conn, "other.com", 8, 32), 8);
        // 通配
        assert_eq!(effective_max_conns(&conn, "a.mirror.test", 8, 32), 4);
        assert_eq!(effective_max_conns(&conn, "mirror.test", 8, 32), 4);
        assert_eq!(effective_max_conns(&conn, "notmirror.test", 8, 32), 8);
        assert_eq!(effective_speed_limit_kbps(&conn, "x.mirror.test", 0), 512);
        assert_eq!(effective_speed_limit_kbps(&conn, "other.com", 0), 0);
        // 覆盖值仍受全局上限夹紧
        assert_eq!(effective_max_conns(&conn, "cdn.example.com", 8, 12), 12);
    }

    #[test]
    fn most_specific_wildcard_wins() {
        let conn = mem();
        set(&conn, "*.example.com", Some(4), None).unwrap();
        set(&conn, "*.a.example.com", Some(12), None).unwrap();
        assert_eq!(effective_max_conns(&conn, "x.a.example.com", 8, 32), 12);
        assert_eq!(effective_max_conns(&conn, "x.b.example.com", 8, 32), 4);
    }

    /// 唯一解析器：只有「每服务器例外 → 全局闸门」两级，任务行里的派生值不参与。
    #[test]
    fn task_conns_follows_the_global_cap_and_host_exceptions() {
        use crate::settings;
        let conn = mem();
        settings::ensure_defaults(&conn).unwrap();
        settings::set(&conn, "conn.global_conn_cap", "64").unwrap();
        // 没有例外：完全跟随设置（历史遗留的 32 不会再盖住它）
        assert_eq!(task_conns(&conn, "https://cdn.example.com/a.bin"), 64);
        // 例外优先
        set(&conn, "cdn.example.com", Some(16), None).unwrap();
        assert_eq!(task_conns(&conn, "https://cdn.example.com/a.bin"), 16);
        assert_eq!(task_conns(&conn, "https://other.com/a.bin"), 64);
        // 例外比全局大时仍夹到全局
        set(&conn, "big.example.com", Some(999), None).unwrap();
        assert_eq!(task_conns(&conn, "https://big.example.com/a.bin"), 64);
        // 改设置立刻生效
        settings::set(&conn, "conn.global_conn_cap", "8").unwrap();
        assert_eq!(task_conns(&conn, "https://other.com/a.bin"), 8);
        assert_eq!(task_conns(&conn, "https://cdn.example.com/a.bin"), 8);
    }

    #[test]
    fn clearing_and_normalizing() {
        let conn = mem();
        set(&conn, "https://Host.Example.com:8443/path", Some(6), None).unwrap();
        assert_eq!(list(&conn).unwrap()[0].host, "host.example.com");
        // 两个字段都为空 = 删除
        set(&conn, "host.example.com", None, None).unwrap();
        assert!(list(&conn).unwrap().is_empty());
        assert!(set(&conn, "   ", Some(1), None).unwrap().is_none());
        assert_eq!(remove(&conn, "nope").unwrap(), 0);
    }

    #[test]
    fn pattern_validation() {
        assert_eq!(validate_pattern("*.Example.com").unwrap(), "*.example.com");
        assert_eq!(
            validate_pattern("a-b.example.com").unwrap(),
            "a-b.example.com"
        );
        assert!(validate_pattern("").is_err());
        assert!(validate_pattern("*. ").is_err());
        assert!(validate_pattern("bad host").is_err());
        assert!(validate_pattern("..").is_err());
    }
}
