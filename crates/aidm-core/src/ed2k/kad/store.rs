//! Kad bootstrap 节点列表（`nodes.dat`）的持久化与新鲜度。
//!
//! 背景：`nodes.dat` 里装的是别人公网 IP + UDP key，**会随时间失效**。此前只有
//! 编译期 `include_bytes!` 的内嵌样本，等于"发货那天就冻结"。这里让刷新下来的
//! 原始文件能落库，读取顺序是「库里的最新一份 → 内嵌兜底」。
//!
//! 存**原始字节**而不是解析结果：`nodes.dat` 有 v0/v1/v2/v3 四种布局，保存原文
//! 才能无损重解析，也便于用文件 SHA-256 复盘"当时刷的是哪一份"。

use rusqlite::{Connection, OptionalExtension};

use super::{parse_nodes_dat, KadNode};

/// 默认刷新来源。实测：HTTP 200 / 6030 B / v2 / 177 节点；
/// 同一地址的 https 亦可用。`gruk.org` 没有 `nodes.dat`（实测 404）。
pub const DEFAULT_NODES_URL: &str = "http://upd.emule-security.org/nodes.dat";

/// 默认新鲜期：超过就认为该刷新了。节点是别人的公网地址，会更替。
pub const DEFAULT_MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// 单份 `nodes.dat` 的读取上限。正常约 6 KB：给足余量，但不接受超大响应。
pub const MAX_DOC_BYTES: u64 = 256 * 1024;

/// 一次成功刷新后的记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNodes {
    pub source_url: String,
    /// 原始文件字节（`nodes.dat` 原文）。
    pub doc: Vec<u8>,
    /// 原始文件的 SHA-256（小写 hex），用于复盘刷的是哪一份。
    pub sha256: String,
    pub node_count: u32,
    /// unix 毫秒。
    pub fetched_at: i64,
}

impl StoredNodes {
    /// 按原文重新解析。落库时已经解析过一次，所以这里失败只可能是库被外部改坏。
    pub fn nodes(&self) -> Result<Vec<KadNode>, String> {
        parse_nodes_dat(&self.doc).map_err(|e| format!("{}: {}", e.code(), e.message()))
    }
}

/// 校验并落库。**先解析再写**：畸形、截断或计数不符的响应绝不进库，
/// 否则下一次启动会拿一份坏文件去 bootstrap。
pub fn store(
    conn: &Connection,
    source_url: &str,
    doc: &[u8],
    fetched_at: i64,
) -> Result<StoredNodes, String> {
    if doc.is_empty() {
        return Err("nodes_dat_empty".into());
    }
    if doc.len() as u64 > MAX_DOC_BYTES {
        return Err("nodes_dat_too_large".into());
    }
    let nodes = parse_nodes_dat(doc).map_err(|e| format!("nodes_dat_invalid: {}", e.code()))?;
    // 空节点列表能解析但没有任何用处，等于没刷新。
    if nodes.is_empty() {
        return Err("nodes_dat_empty".into());
    }
    let sha256 = crate::hash::sha256_reader(doc).map_err(|e| format!("nodes_dat_hash: {e}"))?;
    let node_count = nodes.len() as u32;
    conn.execute(
        "INSERT INTO kad_bootstrap(source_url, doc, sha256, node_count, fetched_at)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(source_url) DO UPDATE SET
            doc = excluded.doc, sha256 = excluded.sha256,
            node_count = excluded.node_count, fetched_at = excluded.fetched_at",
        rusqlite::params![source_url, doc, sha256, node_count, fetched_at],
    )
    .map_err(|e| format!("nodes_dat_store: {e}"))?;
    Ok(StoredNodes {
        source_url: source_url.to_string(),
        doc: doc.to_vec(),
        sha256,
        node_count,
        fetched_at,
    })
}

/// 最近一次成功刷新（按 `fetched_at` 取最新一条）。库里没有时 `None`。
pub fn load(conn: &Connection) -> Result<Option<StoredNodes>, String> {
    conn.query_row(
        "SELECT source_url, doc, sha256, node_count, fetched_at
           FROM kad_bootstrap ORDER BY fetched_at DESC, source_url LIMIT 1",
        [],
        |r| {
            Ok(StoredNodes {
                source_url: r.get(0)?,
                doc: r.get(1)?,
                sha256: r.get(2)?,
                node_count: r.get(3)?,
                fetched_at: r.get(4)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("nodes_dat_load: {e}"))
}

/// 某来源是否已过期。没有记录（`None`）视为过期 —— 调用方才该去刷。
pub fn is_stale(fetched_at: Option<i64>, now: i64, max_age_ms: i64) -> bool {
    match fetched_at {
        None => true,
        Some(t) => {
            // 时钟回拨（fetched_at 在未来）时不当作过期，避免反复刷新。
            let age = now.saturating_sub(t);
            age >= max_age_ms.max(0)
        }
    }
}

/// 丢弃某来源的缓存（刷新失败后想回到内嵌兜底时用）。
pub fn clear(conn: &Connection, source_url: &str) -> Result<bool, String> {
    let n = conn
        .execute(
            "DELETE FROM kad_bootstrap WHERE source_url = ?1",
            [source_url],
        )
        .map_err(|e| format!("nodes_dat_clear: {e}"))?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db;
    use std::path::Path;

    /// 采集的**第二份**真实文件（6030 B / v2 / 177 节点）。
    /// 与既有夹具（6234 B / 183 节点）计数不同，正好证明解析器不是靠单一样本自洽。
    fn fresh_doc() -> Vec<u8> {
        let p =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ed2k/nodes-20261018.dat");
        std::fs::read(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    fn conn() -> Connection {
        open_db(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn fresh_fixture_parses_to_its_declared_count() {
        let doc = fresh_doc();
        // 12 B 头 + 177 × 34 B = 6030 B，与文件长度严格吻合
        assert_eq!(doc.len(), 6030);
        let nodes = parse_nodes_dat(&doc).expect("第二份真实文件也要能解析");
        assert_eq!(nodes.len(), 177);
    }

    #[test]
    fn store_validates_then_persists() {
        let conn = conn();
        let doc = fresh_doc();
        let want_sha = crate::hash::sha256_reader(&doc[..]).unwrap();
        let saved = store(&conn, DEFAULT_NODES_URL, &doc, 1_700_000_000_000).unwrap();
        assert_eq!(saved.node_count, 177);
        assert_eq!(saved.sha256, want_sha);
        assert!(saved.nodes().unwrap().len() == 177);

        let back = load(&conn).unwrap().expect("应能读回");
        assert_eq!(back, saved);
    }

    #[test]
    fn store_refuses_malformed_before_writing() {
        let conn = conn();
        // 计数与长度不符：解析器要求精确吻合
        let mut bad = fresh_doc();
        bad.truncate(bad.len() - 1);
        let err = store(&conn, DEFAULT_NODES_URL, &bad, 1).unwrap_err();
        assert!(err.starts_with("nodes_dat_invalid:"), "{err}");
        // 坏响应绝不入库，否则下次启动会拿它去 bootstrap
        assert!(load(&conn).unwrap().is_none());

        assert_eq!(
            store(&conn, DEFAULT_NODES_URL, &[], 1).unwrap_err(),
            "nodes_dat_empty"
        );
        let huge = vec![0u8; (MAX_DOC_BYTES + 1) as usize];
        assert_eq!(
            store(&conn, DEFAULT_NODES_URL, &huge, 1).unwrap_err(),
            "nodes_dat_too_large"
        );
    }

    #[test]
    fn load_prefers_the_most_recent_refresh() {
        let conn = conn();
        let doc = fresh_doc();
        store(&conn, "http://a.test/nodes.dat", &doc, 100).unwrap();
        store(&conn, "http://b.test/nodes.dat", &doc, 200).unwrap();
        let back = load(&conn).unwrap().unwrap();
        assert_eq!(back.source_url, "http://b.test/nodes.dat");
        assert_eq!(back.fetched_at, 200);
        // 同一来源重复刷新是覆盖而不是新增
        store(&conn, "http://b.test/nodes.dat", &doc, 300).unwrap();
        let back = load(&conn).unwrap().unwrap();
        assert_eq!(back.fetched_at, 300);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM kad_bootstrap", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn emptiness_is_stale_and_clock_skew_is_not() {
        let now = 1_700_000_000_000i64;
        let day = 24 * 60 * 60 * 1000;
        assert!(is_stale(None, now, day), "没有记录就该去刷");
        assert!(is_stale(Some(now - day), now, day), "刚好到期算过期");
        assert!(!is_stale(Some(now - day + 1), now, day));
        // 时钟回拨：fetched_at 在未来时不要反复刷新
        assert!(!is_stale(Some(now + 10 * day), now, day));
        assert!(is_stale(Some(now), now, 0), "新鲜期为 0 表示每次都算过期");
    }

    #[test]
    fn clear_drops_only_that_source() {
        let conn = conn();
        let doc = fresh_doc();
        store(&conn, "http://a.test/nodes.dat", &doc, 100).unwrap();
        store(&conn, "http://b.test/nodes.dat", &doc, 200).unwrap();
        assert!(clear(&conn, "http://b.test/nodes.dat").unwrap());
        assert!(!clear(&conn, "http://b.test/nodes.dat").unwrap());
        let back = load(&conn).unwrap().unwrap();
        assert_eq!(back.source_url, "http://a.test/nodes.dat");
    }
}
