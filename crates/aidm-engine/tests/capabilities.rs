//! 能力查询（`capabilities`）的契约测试。
//!
//! 这里守的是**跨层不变量**：`aidm-ipc` 的 `CapabilityView` 与 `aidm-core` 的
//! `ProtocolProfile` 是两套刻意分开的类型（契约层不依赖实现层），所以它们的
//! 字段对应关系没有任何编译期保障 —— 只能靠这组测试。谁改了 `capabilities_for`
//! 的判据却忘了同步契约层，或者漏映射了 `note`（把"下不了"谎报成"能下"），
//! 都必须在这里红。

mod common;

use std::sync::{Arc, Mutex};

use aidm_core::{open_db, settings};

struct TestEnv {
    manager: aidm_engine::DownloadManager,
    /// 库文件路径。测试需要改写 `url_final` 时自己开一条连接 —— 这样不必给
    /// `DownloadManager` 增加只为测试存在的访问器（那会扩大公开接口面）。
    db_path: std::path::PathBuf,
    /// 持有 tempdir：Drop 时自动删除。目录落在
    /// `%TEMP%\aidm-tests\aidm-caps-<tag>-XXXXXX`（见 `tests/common`）。
    _tmp: tempfile::TempDir,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let tmp = common::tempdir(&format!("caps-{tag}"));
        let root = tmp.path().to_path_buf();
        let db_path = root.join("db.sqlite");
        let db = open_db(&db_path).unwrap();
        settings::ensure_defaults(&db).unwrap();
        let manager = aidm_engine::DownloadManager::new(Arc::new(Mutex::new(db)), root.join("dl"));
        Self {
            manager,
            db_path,
            _tmp: tmp,
        }
    }
}

/// 代表每个传输层各一条，外加清单型与封装型。
const SAMPLES: &[&str] = &[
    "https://mirrors.example/a.iso",
    "http://mirrors.example/a.iso",
    "ftp://ftp.example/pub/a.iso",
    "ftps://ftp.example/pub/a.iso",
    "sftp://host.example/pub/a.iso",
    "quic://host.example/a.bin",
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
    "https://host.example/seed.torrent",
    "ed2k://|file|a.iso|1024|E7C526499308841A4A6D116C857DB669|/",
    "https://host.example/stream.m3u8",
    "https://host.example/stream.mpd",
    "https://host.example/a.iso.metalink",
    "https://mirrors.example/a.iso.zsync",
    "https://host.example/dav/a.iso",
    "https://bucket.s3.example/a.iso",
    // 五类封装：载荷各自不同，验证"剥壳后才判协议"。
    "thunder://aHR0cHM6Ly9taXJyb3JzLmV4YW1wbGUvYS5pc28=",
    "qqdl://aHR0cHM6Ly9taXJyb3JzLmV4YW1wbGUvYS5pc28=",
    "flashget://W0ZMQVNIR0VUXWh0dHBzOi8vbWlycm9ycy5leGFtcGxlL2EuaXNvW0ZMQVNIR0VUXQ==",
    // 网盘资源标识必须在这里：它是**唯一** `note` 非 None 的样本（能识别、但服务已停运）。
    "fs2you://YWJjMTIzaGFzaHxtb3ZpZS5ta3Z8MTA3Mzc0MTgyNA==",
];

/// 契约层视图必须与实现层结论逐字段一致 —— 这是本文件存在的理由。
#[test]
fn capabilities_view_matches_core_for_every_sample() {
    let env = TestEnv::new("parity");
    for raw in SAMPLES {
        let view = env
            .manager
            .capabilities(None, Some(raw))
            .unwrap_or_else(|e| panic!("{raw} 应当可识别，却回 {e}"));

        // 实现层的真值。两者都是纯字符串判定，所以可以直接比。
        let core = aidm_core::capability::detect(raw)
            .unwrap_or_else(|| panic!("{raw} 在 core 侧不可识别"));

        assert_eq!(
            view.transport,
            core.transport.as_str(),
            "{raw} transport 漂移"
        );
        assert_eq!(view.resource, core.resource.as_str(), "{raw} resource 漂移");
        assert_eq!(
            view.manifest.as_deref(),
            core.manifest.map(|m| m.as_str()),
            "{raw} manifest 漂移"
        );
        assert_eq!(
            view.wrapper.as_deref(),
            core.wrapper.map(|w| w.as_str()),
            "{raw} wrapper 漂移"
        );
        // 八个能力位逐位比：漏映射一个就会被这里抓住。
        let (a, b) = (view.capabilities, core.capabilities);
        assert_eq!(
            (
                a.pause,
                a.resume,
                a.segment,
                a.seek,
                a.multi_source,
                a.manifest,
                a.verify,
                a.seed
            ),
            (
                b.pause,
                b.resume,
                b.segment,
                b.seek,
                b.multi_source,
                b.manifest,
                b.verify,
                b.seed
            ),
            "{raw} 能力位漂移"
        );
        // `note` 最容易在映射时被漏掉，而漏掉就等于把不可用谎报成可用。
        assert_eq!(
            view.note, core.note,
            "{raw} note 漂移（漏了它就会谎报可用）"
        );
    }
}

/// 未知 scheme 必须**明确回绝**，而不是给个兜底协议。
///
/// 猜一个协议出来只会把失败推后到下载时，而且会让界面显示一个并不存在的"支持"。
#[test]
fn unknown_scheme_is_refused_not_guessed() {
    let env = TestEnv::new("unknown");
    for raw in [
        "gopher://old.example/1/a.txt",
        "tftp://host.example/a.bin",
        "not-a-url-at-all",
        "",
    ] {
        let err = env
            .manager
            .capabilities(None, Some(raw))
            .expect_err("{raw} 不该被识别");
        assert_eq!(err, "unsupported_scheme", "{raw} 的错误码应当稳定");
    }
}

/// 两个目标都不给是调用错误，要有独立错误码（调用方能据此区分"用错接口"）。
#[test]
fn missing_target_is_a_distinct_error() {
    let env = TestEnv::new("missing");
    assert_eq!(
        env.manager.capabilities(None, None).unwrap_err(),
        "missing_target"
    );
}

/// 给 `id` 时必须用任务**生效的**地址（`url_final` 优先），否则界面看到的能力
/// 会与实际走的路径不一致。
#[test]
fn task_query_prefers_the_effective_url() {
    let env = TestEnv::new("effective");
    // 新建一个普通 HTTP 任务，然后把它的生效地址改写成 m3u8（模拟 302 跳转后
    // 落到分片清单的情形）。
    let id = env
        .manager
        .add("http://origin.example/watch", None, Some("a.bin"), None, 0)
        .unwrap();
    {
        // 另开一条连接改同一个库文件（SQLite 支持多连接；manager 持有的那条
        // 不暴露给测试）。
        let conn = open_db(&env.db_path).unwrap();
        conn.execute(
            "UPDATE downloads SET url_final=?1 WHERE id=?2",
            rusqlite::params!["https://cdn.example/stream.m3u8", id],
        )
        .unwrap();
    }
    let view = env.manager.capabilities(Some(id as u64), None).unwrap();
    assert_eq!(view.transport, "https", "应当按生效地址判定传输层");
    assert_eq!(
        view.resource, "hls",
        "url_final 指向 m3u8 ⇒ 资源层应当是 hls"
    );
    assert_eq!(view.manifest.as_deref(), Some("m3u8"));
    assert!(!view.capabilities.seek, "HLS 没有跨分片随机读");
    assert!(!view.capabilities.multi_source, "HLS 的来源由清单唯一确定");
}

/// `note` 必须穿过契约映射活下来 —— 单独钉一条，不依赖"通用比对恰好抽到了
/// 一个 note 非空的样本"。
///
/// 这条是变异验证逼出来的：先前把映射里的 `note` 改成 `None`，整套测试仍然全绿，
/// 因为样本集里没有 `fs2you`（其余封装的载荷都是能下的直链，`note` 恒为 `None`）。
/// 而 `note` 恰恰是**唯一**能表达"识别得出、但其实下不了"的字段，漏掉它
/// 就等于把不可用谎报成可用。
#[test]
fn note_survives_the_contract_mapping() {
    let env = TestEnv::new("note");
    let view = env
        .manager
        .capabilities(
            None,
            Some("fs2you://YWJjMTIzaGFzaHxtb3ZpZS5ta3Z8MTA3Mzc0MTgyNA=="),
        )
        .expect("fs2you 应当可识别（只是下不了）");

    assert_eq!(view.wrapper.as_deref(), Some("fs2you"), "应当认出封装类型");
    let note = view
        .note
        .as_deref()
        .expect("note 不能丢：它是'下不了'的唯一载体");
    assert!(note.contains("abc123hash"), "note 应当带出资源哈希: {note}");
    assert!(note.contains("movie.mkv"), "note 应当带出文件名: {note}");
    assert!(note.contains("已停运"), "note 应当说明服务不可用: {note}");
}

/// 不存在的任务 id 与"地址不认识"是两回事，错误码必须分开。
#[test]
fn unknown_task_id_is_not_found() {
    let env = TestEnv::new("notfound");
    assert_eq!(
        env.manager.capabilities(Some(999_999), None).unwrap_err(),
        "not_found"
    );
}
