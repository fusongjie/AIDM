//! 统一下载视图与 `task_snapshot` 的跨层集成测试。
//!
//! 守的不变量：
//! - **真实**旧执行器状态能输出正确快照，不是空壳：切片来自 `segments`，
//!   闭区间 `pos_end` 转成左闭右开。
//! - 0 个切片是合法状态，不是错误。
//! - 无内容摘要的 HTTP 任务不得把 `verified_unique_bytes` 伪造成文件长度。
//! - 分页游标绑定版本；进度变化后旧游标必须失效，不能拼出混合版本。
//! - 旧 IPC 载荷（无新字段）仍能解析；新字段缺失不崩。
//!
//! 不覆盖：真实公网下载、长跑与崩溃注入（按项目规则显式跳过）。

mod common;

use std::sync::{Arc, Mutex};

use aidm_core::{model, open_db, settings};
use aidm_ipc::{FEATURE_UNIFIED_DOWNLOAD_V1, UNIFIED_SCHEMA_VERSION};
use rusqlite::params;

struct TestEnv {
    manager: Arc<aidm_engine::DownloadManager>,
    db: Arc<Mutex<rusqlite::Connection>>,
    _tmp: tempfile::TempDir,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let tmp = common::tempdir(&format!("unified-{tag}"));
        let root = tmp.path().to_path_buf();
        let db = open_db(&root.join("db.sqlite")).unwrap();
        settings::ensure_defaults(&db).unwrap();
        let db = Arc::new(Mutex::new(db));
        let manager = Arc::new(aidm_engine::DownloadManager::new(db.clone(), root.join("dl")));
        Self {
            manager,
            db,
            _tmp: tmp,
        }
    }

    /// 建一条任务，返回 `downloads.id`。
    fn add_task(&self, url: &str, size: Option<i64>, status: model::Status) -> i64 {
        let conn = self.db.lock().unwrap();
        let id = model::insert_download(&conn, url, "a.bin", "/tmp/dl", 0, 4).unwrap();
        conn.execute(
            "UPDATE downloads SET size_total = ?1, status = ?2 WHERE id = ?3",
            params![size, status.as_str(), id],
        )
        .unwrap();
        id
    }

    /// 直接插一行分段（`pos_end` 为闭区间，与 legacy 语义一致）。
    fn add_segment(
        &self,
        download_id: i64,
        idx: i32,
        pos_start: i64,
        pos_end: Option<i64>,
        done_bytes: i64,
        status: &str,
    ) {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO segments(download_id, idx, pos_start, pos_end, done_bytes, part_path, status, retries)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
            params![
                download_id,
                idx,
                pos_start,
                pos_end,
                done_bytes,
                format!(".aidm/{download_id}/{idx}.part"),
                status
            ],
        )
        .unwrap();
    }

    fn set_ed2k_hash(&self, download_id: i64) {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE downloads SET ed2k_hash = ?1 WHERE id = ?2",
            params!["e7c526499308841a4a6d116c857db669", download_id],
        )
        .unwrap();
    }

    fn set_sha256(&self, download_id: i64) {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE downloads SET sha256_expected = ?1 WHERE id = ?2",
            params!["a".repeat(64), download_id],
        )
        .unwrap();
    }
}

#[test]
fn legacy_segments_project_to_slices_with_open_interval() {
    let env = TestEnv::new("slices");
    let id = env.add_task("https://example.com/a.bin", Some(1000), model::Status::Downloading);
    // 三段覆盖 0..=999，等价于左闭右开 0..1000。
    env.add_segment(id, 0, 0, Some(299), 150, "running");
    env.add_segment(id, 1, 300, Some(599), 300, "running");
    env.add_segment(id, 2, 600, Some(999), 0, "pending");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_eq!(view.schema_version, UNIFIED_SCHEMA_VERSION);
    assert_eq!(view.identity.task_id, id.to_string());
    assert_eq!(view.slices.len(), 3, "每个 segments 行一个切片");

    // 闭区间 → 左闭右开：299 → 300，999 → 1000。
    assert_eq!(view.slices[0].range.start, "0");
    assert_eq!(view.slices[0].range.end_exclusive.as_deref(), Some("300"));
    assert_eq!(view.slices[2].range.start, "600");
    assert_eq!(view.slices[2].range.end_exclusive.as_deref(), Some("1000"));

    // 有效覆盖是真实 done_bytes，不是段长度。
    assert_eq!(view.slices[0].progress.stored_unique_bytes, "150");
    assert_eq!(view.slices[1].progress.stored_unique_bytes, "300");
    assert_eq!(view.progress.stored_unique_bytes, "450");
    assert_eq!(view.progress.required_bytes.as_deref(), Some("1000"));
    assert_eq!(view.status, "downloading");
}

#[test]
fn no_segments_is_legal_and_not_an_error() {
    let env = TestEnv::new("empty");
    let id = env.add_task("https://example.com/a.bin", None, model::Status::Queued);
    let view = env.manager.unified_summary(id).expect("summary");
    assert!(view.slices.is_empty(), "0 个切片是合法初始态");
    assert!(view.completeness.complete);
    assert_eq!(view.completeness.total_count, 0);
    assert!(view.error.is_none(), "没有切片不等于错误");
    assert_eq!(view.progress.required_bytes, None, "未知总量不能填 0");
}

#[test]
fn http_without_digest_does_not_fake_verified_bytes() {
    let env = TestEnv::new("http-verify");
    let id = env.add_task("https://example.com/a.bin", Some(100), model::Status::Done);
    env.add_segment(id, 0, 0, Some(99), 100, "done");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_eq!(
        view.progress.stored_unique_bytes, "100",
        "已落盘字节要如实显示"
    );
    assert_eq!(
        view.progress.verified_unique_bytes, "0",
        "无内容摘要的 HTTP 任务不得伪造已验证覆盖"
    );
    // 资源侧明确校验等级，而不是让调用方猜。
    assert_eq!(view.resources[0].verification, "length_only");
}

#[test]
fn http_with_digest_counts_verified_after_done() {
    let env = TestEnv::new("http-sha256");
    let id = env.add_task("https://example.com/a.bin", Some(100), model::Status::Done);
    env.set_sha256(id);
    env.add_segment(id, 0, 0, Some(99), 100, "done");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_eq!(view.resources[0].verification, "whole_file");
    assert_eq!(
        view.progress.verified_unique_bytes, "100",
        "有整文件摘要且已完成，才能计入已验证"
    );
}

#[test]
fn ed2k_without_part_observation_does_not_fake_coverage() {
    // 复核修正：eD2k 的 segments 只存聚合完成量（idx 0），不能据此断定
    // “文件开头已完成同等长度”。没有 part 事实时必须显示未知。
    let env = TestEnv::new("ed2k-no-obs");
    let size = 9_728_000i64 * 2;
    let id = env.add_task(
        "ed2k://|file|a.iso|19456000|E7C526499308841A4A6D116C857DB669|/",
        Some(size),
        model::Status::Downloading,
    );
    env.set_ed2k_hash(id);
    // idx 0 存“累计已收 600 字节”，跨越 part 边界但位置未知。
    env.add_segment(id, 0, 0, Some(size - 1), 600, "running");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_eq!(
        view.progress.stored_unique_bytes, "0",
        "没有 part 事实时不得把聚合字节数铺成从文件头开始的覆盖"
    );
    // 无 part 事实时仍保留切片条目（由 total + budget 确定性推导，暂停/重启后同一 ID），
    // 避免详情面板“暂停一下整段消失”；但不得附带任何伪造的覆盖。
    assert!(
        !view.slices.is_empty(),
        "无 part 事实时应保留占位切片，只把覆盖留空"
    );
    for slice in &view.slices {
        assert_eq!(slice.progress.stored_unique_bytes, "0");
        assert_eq!(slice.progress.verified_unique_bytes, "0");
        assert_eq!(slice.state, "pending");
    }
    assert_eq!(
        view.resources[0].verification, "native_block",
        "校验策略仍如实标注，不因无观测而降低"
    );
}

#[test]
fn unknown_size_segment_is_open_ended() {
    let env = TestEnv::new("open");
    let id = env.add_task("https://example.com/a.bin", None, model::Status::Downloading);
    env.add_segment(id, 0, 0, None, 10, "running");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_eq!(view.slices.len(), 1);
    assert_eq!(
        view.slices[0].range.end_exclusive, None,
        "总长未知必须表达为缺失，而不是编一个终点"
    );
}

#[test]
fn snapshot_paginates_slices_and_keeps_true_total() {
    let env = TestEnv::new("page");
    let id = env.add_task("https://example.com/a.bin", Some(500), model::Status::Downloading);
    for idx in 0..5i32 {
        let start = idx as i64 * 100;
        env.add_segment(id, idx, start, Some(start + 99), 0, "pending");
    }

    let first = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(2))
        .expect("page1");
    assert_eq!(first.section, "slices");
    assert_eq!(first.items.as_ref().expect("items").len(), 2);
    assert_eq!(first.total_count, 5, "总数不因分页变小");
    assert!(!first.complete);
    let cursor = first.next_cursor.expect("cursor");

    let second = env
        .manager
        .unified_snapshot(id, Some("slices"), Some(&cursor), Some(2))
        .expect("page2");
    assert_eq!(second.items.as_ref().expect("items").len(), 2);
    assert_eq!(second.total_count, 5);
}

#[test]
fn snapshot_cursor_goes_stale_when_progress_changes() {
    let env = TestEnv::new("stale");
    let id = env.add_task("https://example.com/a.bin", Some(500), model::Status::Downloading);
    for idx in 0..4i32 {
        let start = idx as i64 * 100;
        env.add_segment(id, idx, start, Some(start + 99), 0, "pending");
    }
    let first = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(2))
        .expect("page1");
    let cursor = first.next_cursor.expect("cursor");

    // 进度推进 → 兼容投影的 state_revision 随之变化 → 旧游标必须失效。
    // 用 UPDATE 而不是再插一行：segments 对 (download_id, idx) 有唯一约束。
    {
        let conn = env.db.lock().unwrap();
        conn.execute(
            "UPDATE segments SET done_bytes = 50, status = 'running' WHERE download_id = ?1 AND idx = 0",
            params![id],
        )
        .unwrap();
    }
    let err = env
        .manager
        .unified_snapshot(id, Some("slices"), Some(&cursor), Some(2))
        .expect_err("旧游标必须被拒收");
    assert_eq!(err.code(), aidm_ipc::snapshot_error::SNAPSHOT_STALE);
}

#[test]
fn snapshot_errors_have_stable_codes() {
    let env = TestEnv::new("errors");
    let id = env.add_task("https://example.com/a.bin", Some(100), model::Status::Queued);

    let missing = env
        .manager
        .unified_snapshot(999_999, None, None, None)
        .expect_err("不存在的任务");
    assert_eq!(missing.code(), aidm_ipc::snapshot_error::NO_SUCH_TASK);

    let bad_limit = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(0))
        .expect_err("limit=0 非法");
    assert_eq!(bad_limit.code(), aidm_ipc::snapshot_error::INVALID_LIMIT);

    let bad_section = env
        .manager
        .unified_snapshot(id, Some("bogus"), None, None)
        .expect_err("未知 section");
    assert_eq!(
        bad_section.code(),
        aidm_ipc::snapshot_error::INVALID_SECTION
    );

    let too_big = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(257))
        .expect_err("超过上限必须报错而不是截断");
    assert_eq!(too_big.code(), aidm_ipc::snapshot_error::INVALID_LIMIT);
}

#[test]
fn completed_length_only_slice_is_done_not_verifying() {
    // 复核反例：无内容摘要的 HTTP 任务已完成，切片却能停在 verifying。
    let env = TestEnv::new("length-only-done");
    let id = env.add_task("https://example.com/a.bin", Some(100), model::Status::Done);
    env.add_segment(id, 0, 0, Some(99), 100, "done");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_eq!(view.resources[0].verification, "length_only");
    assert_eq!(
        view.slices[0].state, "done",
        "长度校验完成即应判完成，不能因无摘要永远停在 verifying"
    );
    assert_eq!(
        view.progress.verified_unique_bytes, "0",
        "但不得把长度校验冒充为内容已验证"
    );
    assert_eq!(view.counts.done_slices, 1);
    assert!(view.error.is_none());
}

#[test]
fn partly_downloaded_length_only_slice_is_not_done() {
    // 与上一条成对：长度校验也不能把“只下了一半”当成完成。
    let env = TestEnv::new("length-only-partial");
    let id = env.add_task("https://example.com/a.bin", Some(100), model::Status::Downloading);
    env.add_segment(id, 0, 0, Some(99), 40, "running");

    let view = env.manager.unified_summary(id).expect("summary");
    assert_ne!(view.slices[0].state, "done");
    assert_eq!(view.progress.stored_unique_bytes, "40");
}

#[test]
fn snapshot_cursor_invalidates_when_only_state_changes() {
    // 复核反例：切片从 pending 变 error 时字节数不变，旧游标却仍有效。
    let env = TestEnv::new("stale-state-only");
    let id = env.add_task("https://example.com/a.bin", Some(300), model::Status::Downloading);
    for idx in 0..3i32 {
        let start = idx as i64 * 100;
        env.add_segment(id, idx, start, Some(start + 99), 0, "pending");
    }
    let first = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(2))
        .expect("page1");
    let cursor = first.next_cursor.expect("cursor");

    // 只改状态，**不改任何字节数**：pending → error。
    {
        let conn = env.db.lock().unwrap();
        conn.execute(
            "UPDATE segments SET status = 'error' WHERE download_id = ?1 AND idx = 1",
            params![id],
        )
        .unwrap();
    }

    let err = env
        .manager
        .unified_snapshot(id, Some("slices"), Some(&cursor), Some(2))
        .expect_err("仅状态变化也必须让旧游标失效");
    assert_eq!(err.code(), aidm_ipc::snapshot_error::SNAPSHOT_STALE);
}

#[test]
fn cursor_stays_valid_when_nothing_visible_changed() {
    // 指纹版本不能过度敏感：状态未变时同一游标应继续可用。
    let env = TestEnv::new("stable-cursor");
    let id = env.add_task("https://example.com/a.bin", Some(300), model::Status::Downloading);
    for idx in 0..3i32 {
        let start = idx as i64 * 100;
        env.add_segment(id, idx, start, Some(start + 99), 0, "pending");
    }
    let first = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(2))
        .expect("page1");
    let cursor = first.next_cursor.expect("cursor");

    let second = env
        .manager
        .unified_snapshot(id, Some("slices"), Some(&cursor), Some(2))
        .expect("无变化时游标应继续有效");
    assert_eq!(second.items.as_ref().expect("items").len(), 1);
}

#[test]
fn legacy_task_view_json_still_parses() {
    // 旧引擎的载荷：没有 unified_download 字段。
    let raw = r#"{
        "id": 1,
        "name": "a.bin",
        "state": "downloading",
        "done": 10,
        "speed": 0,
        "save_path": "/tmp/a.bin"
    }"#;
    let view: aidm_ipc::TaskView = serde_json::from_str(raw).expect("旧载荷必须可解析");
    assert!(view.unified_download.is_none());
    assert_eq!(view.done, 10);
}

#[test]
fn new_unified_payload_omits_unknown_and_keeps_precision() {
    let env = TestEnv::new("payload");
    let id = env.add_task("https://example.com/a.bin", Some(100), model::Status::Downloading);
    env.add_segment(id, 0, 0, Some(99), 100, "running");

    let view = env.manager.unified_summary(id).expect("summary");
    let json = serde_json::to_value(&view).expect("serialize");
    assert_eq!(json["schema_version"], 1);
    // 可选字段缺失时不出现在 JSON 里（旧客户端噪声最小化）。
    assert!(json.get("error").is_none());
    assert!(json.get("sources").is_none());
    // 字节计数以十进制字符串出现，避免 JS 精度丢失。
    assert!(json["progress"]["stored_unique_bytes"].is_string());
}

#[test]
fn feature_flag_name_is_stable() {
    // 功能协商靠这个名字，改名等于破坏兼容。
    assert_eq!(FEATURE_UNIFIED_DOWNLOAD_V1, "unified_download_v1");
    // 旧的 EngineRequest 仍能解析 ping。
    let req: aidm_ipc::EngineRequest = serde_json::from_str(r#"{"op":"ping"}"#).expect("ping");
    assert_eq!(req, aidm_ipc::EngineRequest::Ping);
    // 新请求形状可解析。
    let req: aidm_ipc::EngineRequest =
        serde_json::from_str(r#"{"op":"task_snapshot","id":7,"section":"slices","limit":16}"#)
            .expect("task_snapshot");
    assert!(matches!(
        req,
        aidm_ipc::EngineRequest::TaskSnapshot { id: 7, .. }
    ));
}

#[test]
fn engine_instance_id_is_stable_within_process() {
    let env = TestEnv::new("engine-id");
    let a = env.manager.engine_instance_id().to_owned();
    let b = env.manager.engine_instance_id().to_owned();
    assert_eq!(a, b, "同一进程内实例标识不变");
    assert_eq!(a.len(), 36, "UUIDv4 字面量");
}

// ---------------------------------------------------------------- 真实链路

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 最小 HTTP/1.1 服务：每个连接返回一次 200 + 完整 body。
///
/// 只为验证“真实执行器 → 落盘 → 快照”链路，不复现生产 HTTP 特性
/// （分片、重定向、鉴权）。那些在 `integration.rs` 里已有独立覆盖。
struct OneShotHttp {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OneShotHttp {
    fn spawn(body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test http");
        let addr = listener.local_addr().expect("local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).expect("nonblocking");
            let len = body.len();
            loop {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let body = body.clone();
                        std::thread::spawn(move || {
                            let mut buf = [0u8; 8192];
                            let _ = stream.read(&mut buf);
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\
                                 Content-Type: application/octet-stream\r\n\
                                 Accept-Ranges: bytes\r\nConnection: close\r\n\r\n"
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(&body);
                            let _ = stream.flush();
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for OneShotHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn real_http_download_snapshot_is_consistent() {
    // 用户验收要求：不能只有“数据库夹具 → 快照”，必须跑一次真实下载再核对。
    let body: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    let server = OneShotHttp::spawn(body.clone());
    let env = TestEnv::new("real-http");
    let dir = env._tmp.path().join("dl");
    std::fs::create_dir_all(&dir).expect("create dl dir");

    let id = env
        .manager
        .add(
            &server.url("/a.bin"),
            Some(dir.to_str().expect("utf8 path")),
            Some("a.bin"),
            None,
            0,
        )
        .expect("add task");

    let mut status = model::Status::Queued;
    for _ in 0..600 {
        env.manager.tick();
        std::thread::sleep(Duration::from_millis(10));
        {
            let conn = env.db.lock().unwrap();
            if let Ok(Some(row)) = model::get_download(&conn, id) {
                status = row.status;
            }
        }
        if matches!(status, model::Status::Done | model::Status::Error) {
            break;
        }
    }
    assert_eq!(status, model::Status::Done, "本地 HTTP 下载必须完成");

    // 经 IPC 契约层核对（`task_snapshot` 的 summary），不是直接读内部结构。
    let resp = env
        .manager
        .unified_snapshot(id, None, None, None)
        .expect("snapshot");
    let view = resp.summary.expect("summary section");
    assert_eq!(view.status, "done");
    assert!(!view.slices.is_empty(), "真实下载必须产生切片");

    let stored: u64 = view.progress.stored_unique_bytes.parse().expect("stored");
    assert_eq!(
        stored,
        body.len() as u64,
        "有效覆盖必须等于真实落盘字节数"
    );
    assert!(
        view.slices.iter().all(|s| s.state == "done"),
        "完成后所有切片都应为 done"
    );
    assert_eq!(
        view.resources[0].verification, "length_only",
        "无内容摘要按长度校验"
    );
    // 磁盘上的最终文件也要与源一致（链路真的走完了）。
    let written = std::fs::read(dir.join("a.bin")).expect("final file");
    assert_eq!(written, body, "最终文件内容必须与源一致");
}

#[test]
fn real_http_download_snapshot_pagination_matches_slice_count() {
    let body: Vec<u8> = (0..64 * 1024).map(|i| (i % 253) as u8).collect();
    let server = OneShotHttp::spawn(body);
    let env = TestEnv::new("real-http-page");
    let dir = env._tmp.path().join("dl");
    std::fs::create_dir_all(&dir).expect("create dl dir");

    let id = env
        .manager
        .add(
            &server.url("/b.bin"),
            Some(dir.to_str().expect("utf8 path")),
            Some("b.bin"),
            None,
            0,
        )
        .expect("add task");

    for _ in 0..600 {
        env.manager.tick();
        std::thread::sleep(Duration::from_millis(10));
        let done = {
            let conn = env.db.lock().unwrap();
            model::get_download(&conn, id)
                .ok()
                .flatten()
                .is_some_and(|r| matches!(r.status, model::Status::Done | model::Status::Error))
        };
        if done {
            break;
        }
    }

    let all = env
        .manager
        .unified_snapshot(id, Some("slices"), None, Some(256))
        .expect("all slices");
    let total = all.total_count;
    assert!(total > 0, "必须有切片");

    // 逐页收集，数量与 total_count 一致，且每页不超过 limit。
    let mut seen = 0u32;
    let mut cursor: Option<String> = None;
    loop {
        let page = env
            .manager
            .unified_snapshot(id, Some("slices"), cursor.as_deref(), Some(1))
            .expect("page");
        let items = page.items.expect("items").len() as u32;
        assert!(items <= 1, "limit 必须被遵守");
        seen += items;
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, total, "分页必须覆盖全部切片，不多不少");
}

// ---------------------------------------------------------------- IPC 服务链路

#[test]
fn ipc_service_advertises_feature_and_serves_snapshot() {
    // 用户验收要求：不能只调内存方法，必须经运行中的回环 IPC 服务查询。
    let env = TestEnv::new("ipc");
    let id = env.add_task("https://example.com/a.bin", Some(600), model::Status::Downloading);
    env.add_segment(id, 0, 0, Some(299), 100, "running");
    env.add_segment(id, 1, 300, Some(599), 0, "pending");

    let port = aidm_engine::server::serve_ephemeral(env.manager.clone()).expect("serve ipc");
    let timeout = Duration::from_secs(5);

    // 1) `ping` 必须声明支持统一视图（旧的 `{"op":"ping"}` 请求形状不变）。
    let pong = aidm_ipc::engine_roundtrip(port, &aidm_ipc::EngineRequest::Ping, timeout)
        .expect("ping");
    assert!(pong.ok);
    let features = pong.features.expect("features");
    assert!(
        features.iter().any(|f| f == aidm_ipc::FEATURE_UNIFIED_DOWNLOAD_V1),
        "引擎必须声明 unified_download_v1，实际 {features:?}"
    );

    // 2) `task_snapshot` summary 走完整 IPC 编解码。
    let resp = aidm_ipc::engine_roundtrip(
        port,
        &aidm_ipc::EngineRequest::TaskSnapshot {
            id: id as u64,
            section: None,
            cursor: None,
            limit: None,
        },
        timeout,
    )
    .expect("task_snapshot");
    assert!(resp.ok, "快照查询应成功：{:?}", resp.error);
    let snapshot = resp.snapshot.expect("snapshot payload");
    assert_eq!(snapshot.schema_version, UNIFIED_SCHEMA_VERSION);
    assert_eq!(snapshot.section, "summary");
    let summary = snapshot.summary.expect("summary");
    assert_eq!(summary.identity.task_id, id.to_string());
    assert_eq!(summary.status, "downloading");
    assert_eq!(summary.slices.len(), 2);
    assert_eq!(summary.progress.stored_unique_bytes, "100");

    // 3) 分页 section 也经 IPC 可达。
    let page = aidm_ipc::engine_roundtrip(
        port,
        &aidm_ipc::EngineRequest::TaskSnapshot {
            id: id as u64,
            section: Some("slices".into()),
            cursor: None,
            limit: Some(1),
        },
        timeout,
    )
    .expect("slices page");
    let snapshot = page.snapshot.expect("page payload");
    assert_eq!(snapshot.items.as_ref().expect("items").len(), 1);
    assert_eq!(snapshot.total_count, 2);
    assert!(!snapshot.complete);

    // 4) 未知任务回结构化错误码，不是自由文本。
    let missing = aidm_ipc::engine_roundtrip(
        port,
        &aidm_ipc::EngineRequest::TaskSnapshot {
            id: 999_999,
            section: None,
            cursor: None,
            limit: None,
        },
        timeout,
    )
    .expect("missing task");
    assert!(!missing.ok);
    assert_eq!(
        missing.code.as_deref(),
        Some(aidm_ipc::snapshot_error::NO_SUCH_TASK)
    );
}
