//! Kad bootstrap 节点列表（`nodes.dat`）的取用与刷新。
//!
//! 为什么单独一个模块：`kad_session.rs` 会被几个测试用 `#[path]` 单独编进测试二进制
//! （见 `tests/kad_session_udp.rs`），在那里 `worker` 不存在，放进 `kad_session`
//! 的新函数会被判成死代码。
//!
//! 职责边界：
//! - 「库里有刷新过的就用它，否则退回编译期内嵌样本」= [`bootstrap_nodes`]
//! - 「取一份新的、校验后落库」= [`refresh_nodes_dat`]；落库时**先解析再写**，
//!   畸形响应既不会入库也不会覆盖已有好缓存（由 `aidm_core::ed2k::kad::store` 保证）
//! - 「过期才刷」= [`refresh_if_stale`]

use std::io::Read;

use aidm_core::ed2k::kad::store as kad_store;
use aidm_core::ed2k::kad::KadNode;
use rusqlite::Connection;

use super::kad_session::default_bootstrap_nodes;

/// Bootstrap 节点：优先用**刷新过的**（库里最新一份），退回内嵌样本。
///
/// 库里没有记录、或记录已损坏时用内嵌样本 —— 因此"从没刷新过"的行为与从前完全一致。
/// 返回空 Vec 只可能是内嵌样本也坏了（构建期字节被改），调用方按"没有种子"处理。
pub fn bootstrap_nodes(conn: &Connection) -> Vec<KadNode> {
    match kad_store::load(conn) {
        Ok(Some(stored)) => match stored.nodes() {
            Ok(nodes) if !nodes.is_empty() => {
                log::debug!(
                    "kad bootstrap: 用库里的 nodes.dat（{} 节点，刷于 {}，sha256={}）",
                    nodes.len(),
                    stored.fetched_at,
                    stored.sha256
                );
                return nodes;
            }
            Ok(_) => log::warn!("kad bootstrap: 库里的 nodes.dat 解析出 0 个节点，回退内嵌样本"),
            Err(e) => log::warn!("kad bootstrap: 库里的 nodes.dat 无法解析（{e}），回退内嵌样本"),
        },
        Ok(None) => {}
        Err(e) => log::warn!("kad bootstrap: 读取节点缓存失败（{e}），回退内嵌样本"),
    }
    default_bootstrap_nodes().unwrap_or_default()
}

/// 只做网络取回：GET 一份 `nodes.dat` 原始字节（含状态码与长度上限校验）。
///
/// 与 [`refresh_nodes_dat`] 拆开是为了让调用方能**先取回、再持锁落库**：
/// 取回可能耗时数秒，握着数据库锁去等 HTTP 会挡住整个引擎。
pub fn fetch_nodes_dat(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
    // ureq 把 >=400 当 `Err(Status)`：状态码是可预期的结果，给稳定错误码
    // （供 IPC/界面映射），不要把引擎的 Debug 文本透出去。
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => return Err(format!("nodes_dat_http_{code}")),
        Err(e) => return Err(format!("nodes_dat_http: {e}")),
    };
    if resp.status() != 200 {
        return Err(format!("nodes_dat_http_{}", resp.status()));
    }
    let mut doc = Vec::new();
    resp.into_reader()
        .take(kad_store::MAX_DOC_BYTES + 1)
        .read_to_end(&mut doc)
        .map_err(|e| format!("nodes_dat_read: {e}"))?;
    Ok(doc)
}

/// 刷新 `nodes.dat`：取一份新的、校验后落库。
///
/// 只接受 HTTP 200；正文有上限；**先解析再写**，因此畸形、截断或计数不符的响应
/// 既不会落库，也不会覆盖已有的好缓存。
pub fn refresh_nodes_dat(
    agent: &ureq::Agent,
    conn: &Connection,
    url: &str,
    now_ms: i64,
) -> Result<kad_store::StoredNodes, String> {
    let doc = fetch_nodes_dat(agent, url)?;
    let saved = kad_store::store(conn, url, &doc, now_ms)?;
    log::info!(
        "kad bootstrap: 刷新成功，{} 节点 / {} B / sha256={}",
        saved.node_count,
        saved.doc.len(),
        saved.sha256
    );
    Ok(saved)
}

/// 当前缓存的抓取时间（unix 毫秒；库里没有则为 `None`）。
///
/// 单独暴露是为了让调用方能**只查新鲜度**，把"取回"和"落库"分开加锁。
pub fn cached_at(conn: &Connection) -> Option<i64> {
    kad_store::load(conn).ok().flatten().map(|s| s.fetched_at)
}

/// 过期才刷。返回 `Ok(None)` 表示"还新鲜，没动"；`Err` 表示想刷但失败，
/// 调用方应当按"继续用旧的"处理，而不是把 bootstrap 置空。
pub fn refresh_if_stale(
    agent: &ureq::Agent,
    conn: &Connection,
    url: &str,
    now_ms: i64,
    max_age_ms: i64,
) -> Result<Option<kad_store::StoredNodes>, String> {
    let current = kad_store::load(conn).unwrap_or(None);
    let fetched_at = current.as_ref().map(|s| s.fetched_at);
    if !kad_store::is_stale(fetched_at, now_ms, max_age_ms) {
        return Ok(None);
    }
    refresh_nodes_dat(agent, conn, url, now_ms).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k::kad_session::default_bootstrap_nodes;
    use aidm_core::db::open_db;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::Arc;

    fn conn() -> Connection {
        open_db(Path::new(":memory:")).unwrap()
    }

    /// 第二份真实文件：6030 B / v2 / **177** 节点；内嵌样本是 183 节点。
    /// 两者节点数不同，正好用来判定"到底用了哪一份"。
    fn fresh_doc() -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../aidm-core/tests/fixtures/ed2k/nodes-20261018.dat");
        std::fs::read(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    /// 一次性 HTTP 服务：给每个连接回同一份固定响应，够本模块的用例用。
    fn serve_once(
        status: &'static str,
        body: Vec<u8>,
    ) -> (String, Arc<std::thread::JoinHandle<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            // 只服务一个连接：`accept` 一次就够。写成
            // `for stream in listener.incoming() { …; break }` 会触发 clippy 的
            // `never_loop`（错误级），而这里本来也没有"循环"这回事。
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            // 读掉请求头就够（本用例不关心请求内容）
            let mut buf = [0u8; 2048];
            let _ = std::io::Read::read(&mut s, &mut buf);
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
            let _ = s.flush();
        });
        (format!("http://{addr}/nodes.dat"), Arc::new(handle))
    }

    #[test]
    fn bootstrap_falls_back_to_the_embedded_sample_when_nothing_was_refreshed() {
        let conn = conn();
        let nodes = bootstrap_nodes(&conn);
        let embedded = default_bootstrap_nodes().unwrap();
        assert_eq!(nodes.len(), embedded.len());
        assert_eq!(nodes.len(), 183, "内嵌样本是 183 节点");
    }

    #[test]
    fn bootstrap_prefers_the_refreshed_document() {
        let conn = conn();
        let doc = fresh_doc();
        kad_store::store(&conn, "http://a.test/nodes.dat", &doc, 1_000).unwrap();
        let nodes = bootstrap_nodes(&conn);
        assert_eq!(
            nodes.len(),
            177,
            "应当用库里的那份（177），而不是内嵌的 183"
        );
    }

    #[test]
    fn bootstrap_falls_back_when_the_cached_document_is_corrupt() {
        let conn = conn();
        // 绕过 store 的校验直接塞坏数据：模拟库被外部改坏
        conn.execute(
            "INSERT INTO kad_bootstrap(source_url, doc, sha256, node_count, fetched_at)
             VALUES('http://a.test/nodes.dat', ?1, 'x', 1, 1)",
            rusqlite::params![vec![0u8; 32]],
        )
        .unwrap();
        let nodes = bootstrap_nodes(&conn);
        assert_eq!(nodes.len(), 183, "坏缓存必须退回内嵌样本，而不是返回空");
    }

    #[test]
    fn refresh_stores_a_valid_document() {
        let conn = conn();
        let doc = fresh_doc();
        let (url, _srv) = serve_once("200 OK", doc.clone());
        let agent = ureq::AgentBuilder::new().build();
        let saved = refresh_nodes_dat(&agent, &conn, &url, 5_000).unwrap();
        assert_eq!(saved.node_count, 177);
        assert_eq!(saved.doc, doc);
        // 落库之后 bootstrap 就该用它
        assert_eq!(bootstrap_nodes(&conn).len(), 177);
    }

    #[test]
    fn refresh_rejects_garbage_without_touching_the_cache() {
        let conn = conn();
        // 先有一份好的
        kad_store::store(&conn, "http://good.test/nodes.dat", &fresh_doc(), 1_000).unwrap();
        // 服务端回一份长度与计数不符的坏文件
        let mut bad = fresh_doc();
        bad.truncate(bad.len() - 1);
        let (url, _srv) = serve_once("200 OK", bad);
        let agent = ureq::AgentBuilder::new().build();
        let err = refresh_nodes_dat(&agent, &conn, &url, 6_000).unwrap_err();
        assert!(err.starts_with("nodes_dat_invalid:"), "{err}");
        // 坏响应既不入库，也不影响已有缓存
        let back = kad_store::load(&conn).unwrap().unwrap();
        assert_eq!(back.source_url, "http://good.test/nodes.dat");
        assert_eq!(bootstrap_nodes(&conn).len(), 177);
    }

    #[test]
    fn refresh_surfaces_http_failures() {
        let conn = conn();
        let (url, _srv) = serve_once("404 Not Found", b"nope".to_vec());
        let agent = ureq::AgentBuilder::new().build();
        assert_eq!(
            refresh_nodes_dat(&agent, &conn, &url, 1).unwrap_err(),
            "nodes_dat_http_404"
        );
        assert!(kad_store::load(&conn).unwrap().is_none());
    }

    #[test]
    fn refresh_if_stale_only_fetches_when_needed() {
        let conn = conn();
        let (url, _srv) = serve_once("200 OK", fresh_doc());
        let agent = ureq::AgentBuilder::new().build();
        let day = 24 * 60 * 60 * 1000;

        // 库里没有 → 过期 → 刷
        let first = refresh_if_stale(&agent, &conn, &url, 10_000, day).unwrap();
        assert!(first.is_some());
        assert_eq!(first.unwrap().fetched_at, 10_000);

        // 还新鲜 → 不动（服务端只接受一个连接，若它被再次访问就会失败）
        let again = refresh_if_stale(&agent, &conn, &url, 11_000, day).unwrap();
        assert!(again.is_none(), "新鲜期内不应再刷");
    }
}
