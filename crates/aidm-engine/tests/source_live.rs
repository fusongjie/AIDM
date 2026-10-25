//! 找源外网烟测（默认 `#[ignore]`，只有显式 `--ignored` + `AIDM_LIVE_FIND=1` 才跑）。
//!
//! 目的不是证明"全网可用"，而是证明适配器在真实响应上的**最小成功路径**：
//! Wayback CDX 能返回捕获、地址被改写成 `web/<ts>id_/<url>`、且不把 CDX 的
//! 压缩记录长度当文件大小。
//!
//! 这里不跑 archive.org 的按文件名搜索：结果依赖归档内容，容易随时间漂移。

use std::sync::Mutex;

use aidm_core::source::{SourceKind, SourceQuery};
use aidm_engine::source::{PlatformAdapter, SearchBudget, WaybackAdapter};
use aidm_engine::HttpRuntime;
use rusqlite::Connection;

fn live_enabled() -> bool {
    std::env::var("AIDM_LIVE_FIND").as_deref() == Ok("1")
}

fn http() -> std::sync::Arc<HttpRuntime> {
    HttpRuntime::from_db(&Mutex::new(Connection::open_in_memory().unwrap()))
}

#[test]
#[ignore = "live: 需要公网；运行方式 AIDM_LIVE_FIND=1 cargo test -p aidm-engine --test source_live -- --ignored"]
fn wayback_cdx_finds_example_com_capture() {
    if !live_enabled() {
        eprintln!("AIDM_LIVE_FIND != 1，跳过外网用例");
        return;
    }
    let adapter = WaybackAdapter::new(http());
    let query = SourceQuery {
        file_name: "index.html".into(),
        size: None,
        hashes: Vec::new(),
        version: None,
        orig_url: Some("http://example.com/".into()),
        source_hint: None,
    };
    let budget = SearchBudget::new(aidm_engine::source_registry::now_ms(), 15_000, 5);
    let got = adapter
        .search(&query, budget)
        .expect("Wayback CDX 查询应成功（HTTP/解析错误会返回 Err）");
    assert!(!got.is_empty(), "example.com 应该有可用的 Wayback 捕获");
    let first = &got[0];
    assert_eq!(first.platform, aidm_core::source::Platform::Wayback);
    assert_eq!(first.kind, SourceKind::File);
    assert!(
        first.url.contains("/web/") && first.url.contains("id_/"),
        "应使用 id_ 原始字节地址: {}",
        first.url
    );
    assert!(
        first.size.is_none(),
        "CDX length 是压缩记录长度，不能当文件大小"
    );
    assert!(first.evidence.allows_multi_source() == false);
}
