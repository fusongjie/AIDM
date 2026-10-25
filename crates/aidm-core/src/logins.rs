//! 站点凭据：按主机存用户名/密码，401 挑战时自动带上重试。
//!
//! 密码用 [`crate::secret`]（Windows 上 DPAPI）保护后存储，
//! **永不进日志、不进 TaskView**。
//!
//! 与浏览器的 cookie 数据库完全无关：这里只存用户自己为某个站点填的凭据。

use rusqlite::{params, Connection};

use crate::secret;

/// 一条站点凭据（密码已解密，仅内存里短暂存在）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteLogin {
    pub host: String,
    pub username: String,
    pub password: String,
}

/// 主机名归一：小写、去空白、去端口。`Example.COM:8080` → `example.com`。
pub fn normalize_host(raw: &str) -> String {
    let s = raw.trim().to_ascii_lowercase();
    // 允许直接粘 URL：先剥 scheme（`https://host/path` → `host/path`）
    let s = match s.split_once("://") {
        Some((_, rest)) => rest.to_string(),
        None => s,
    };
    let s = s.split('/').next().unwrap_or("").to_string();
    // IPv6 字面量形如 [::1]:8080，先取括号内
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    match s.rsplit_once(':') {
        // 只剥掉"看起来像端口"的尾巴，避免把裸 IPv6 切断
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            host.to_string()
        }
        _ => s,
    }
}

/// 列出全部站点凭据（密码解密；解不开的条目跳过并保持不删）。
pub fn list(conn: &Connection) -> rusqlite::Result<Vec<SiteLogin>> {
    let mut stmt = conn.prepare(
        "SELECT host, username, password_enc FROM site_logins ORDER BY host COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (host, username, enc) = row?;
        let password = match enc.as_deref() {
            Some(v) if !v.is_empty() => secret::unprotect(v).unwrap_or_default(),
            _ => String::new(),
        };
        out.push(SiteLogin {
            host,
            username,
            password,
        });
    }
    Ok(out)
}

/// 写入/覆盖一条站点凭据（密码受保护后存储）。
pub fn set(conn: &Connection, host: &str, username: &str, password: &str) -> Result<(), String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Err("host_empty".into());
    }
    if host.len() > 255 {
        return Err("host_too_long".into());
    }
    if username.chars().any(|c| c.is_control()) || password.chars().any(|c| c.is_control()) {
        return Err("credential_control_char".into());
    }
    if username.len() > 255 || password.len() > 1024 {
        return Err("credential_too_long".into());
    }
    let enc = if password.is_empty() {
        String::new()
    } else {
        secret::protect(password).map_err(|e| format!("secret_protect: {e}"))?
    };
    conn.execute(
        "INSERT INTO site_logins(host, username, password_enc, updated_at)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(host) DO UPDATE SET
            username = excluded.username,
            password_enc = excluded.password_enc,
            updated_at = excluded.updated_at",
        params![host, username, enc, crate::model::now_secs()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 删除一条站点凭据。返回是否真的删掉了。
pub fn remove(conn: &Connection, host: &str) -> rusqlite::Result<bool> {
    let host = normalize_host(host);
    let n = conn.execute("DELETE FROM site_logins WHERE host = ?1", params![host])?;
    Ok(n > 0)
}

/// 查一条凭据（密码已解密）。主机名精确匹配、大小写不敏感。
pub fn lookup(conn: &Connection, host: &str) -> rusqlite::Result<Option<SiteLogin>> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Ok(None);
    }
    let row = conn
        .query_row(
            "SELECT host, username, password_enc FROM site_logins
             WHERE host = ?1 COLLATE NOCASE",
            params![host],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;
    Ok(row.map(|(host, username, enc)| {
        let password = match enc.as_deref() {
            Some(v) if !v.is_empty() => secret::unprotect(v).unwrap_or_default(),
            _ => String::new(),
        };
        SiteLogin {
            host,
            username,
            password,
        }
    }))
}

/// `host` 是否有可用凭据（密码非空）。
pub fn has_credentials(conn: &Connection, host: &str) -> bool {
    lookup(conn, host)
        .ok()
        .flatten()
        .map(|l| !l.password.is_empty())
        .unwrap_or(false)
}

/// 生成 `Authorization: Basic ...` 的值（不含头名）。
///
/// 只做 Base64，不做任何转义：用户名/密码里的冒号按 RFC 7617 允许，
/// 冒号在用户名中属于非法但服务端自会拒绝。
pub fn basic_authorization(username: &str, password: &str) -> String {
    let raw = format!("{username}:{password}");
    format!("Basic {}", base64(&raw.into_bytes()))
}

/// 最小 Base64 编码（避免为一行功能引入依赖；标准字母表带 `=` 填充）。
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn mem() -> Connection {
        crate::open_db(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn normalizes_hosts() {
        assert_eq!(normalize_host("Example.COM"), "example.com");
        assert_eq!(normalize_host(" example.com:8080 "), "example.com");
        assert_eq!(normalize_host("https://example.com/a/b"), "example.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host("::1"), "::1");
        assert_eq!(normalize_host(""), "");
    }

    #[test]
    fn crud_roundtrip_and_password_not_plaintext() {
        let conn = mem();
        set(&conn, "Example.com", "alice", "s3cret").unwrap();
        let got = lookup(&conn, "example.COM:443").unwrap().unwrap();
        assert_eq!(got.username, "alice");
        assert_eq!(got.password, "s3cret");
        assert!(has_credentials(&conn, "example.com"));

        // 库里必须是受保护形态，不能是明文
        let raw: String = conn
            .query_row(
                "SELECT password_enc FROM site_logins WHERE host='example.com'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(raw, "s3cret");
        assert!(secret::is_protected(&raw), "应为受保护值: {raw}");

        // 覆盖
        set(&conn, "example.com", "bob", "pw2").unwrap();
        let got2 = lookup(&conn, "example.com").unwrap().unwrap();
        assert_eq!(got2.username, "bob");
        assert_eq!(got2.password, "pw2");
        assert_eq!(list(&conn).unwrap().len(), 1);

        // 删除
        assert!(remove(&conn, "EXAMPLE.com").unwrap());
        assert!(!remove(&conn, "example.com").unwrap());
        assert!(lookup(&conn, "example.com").unwrap().is_none());
    }

    #[test]
    fn rejects_bad_inputs() {
        let conn = mem();
        assert_eq!(set(&conn, "  ", "u", "p").unwrap_err(), "host_empty");
        assert_eq!(
            set(&conn, "a.com", "u\u{1}", "p").unwrap_err(),
            "credential_control_char"
        );
        assert_eq!(
            set(&conn, "a.com", "u", "p\u{7f}").unwrap_err(),
            "credential_control_char"
        );
    }

    #[test]
    fn basic_authorization_matches_rfc7617_examples() {
        // RFC 7617 的经典例子
        assert_eq!(
            basic_authorization("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(basic_authorization("", ""), "Basic Og==");
        assert_eq!(basic_authorization("a", "b"), "Basic YTpi");
        assert_eq!(basic_authorization("user", "pass"), "Basic dXNlcjpwYXNz");
        // 需要填充的两种长度
        assert_eq!(basic_authorization("u", "p"), "Basic dTpw");
        assert_eq!(basic_authorization("uu", "pp"), "Basic dXU6cHA=");
        assert_eq!(basic_authorization("uuu", "pp"), "Basic dXV1OnBw");
    }
}
