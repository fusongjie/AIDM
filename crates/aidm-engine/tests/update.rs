//! 应用内更新：清单校验、已是最新、SHA256 不符、网络失败、下载应用（假包）。
//! 真实 Release URL 不进本测试；只用本地夹具 + 测试 HTTP 服务器。

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aidm_core::db::open_db;
use aidm_core::hash::sha256_reader;
use aidm_core::settings;
use aidm_engine::manager::DownloadManager;
use aidm_engine::server;
use aidm_ipc::{
    engine_roundtrip, engine_subscribe, EngineEvent, EngineRequest, ERR_CHECKSUM_MISMATCH,
    ERR_CHECK_FAILED, ERR_NETWORK, ERR_UPDATE_FAILED, UPDATE_PHASE_AVAILABLE, UPDATE_PHASE_DONE,
    UPDATE_PHASE_ERROR, UPDATE_PHASE_UP_TO_DATE,
};

const FAKE_PKG: &[u8] = include_bytes!("fixtures/update/fake-package.bin");
const INVALID_MANIFEST: &str = include_str!("fixtures/update/version-invalid.json");

struct Req {
    path: String,
}

struct TestServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn new(handler: Arc<dyn Fn(&Req) -> (u16, &'static str, Vec<u8>) + Send + Sync>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            for stream in listener.incoming() {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(mut stream) => {
                        let _ = stream.set_nonblocking(false);
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            continue;
                        }
                        let path = line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("/")
                            .split('?')
                            .next()
                            .unwrap_or("/")
                            .to_string();
                        let mut rest = String::new();
                        loop {
                            rest.clear();
                            if reader.read_line(&mut rest).is_err()
                                || rest == "\r\n"
                                || rest == "\n"
                            {
                                break;
                            }
                        }
                        let (status, ctype, body) = handler(&Req { path });
                        let _ = write!(
                            stream,
                            "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(&body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
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
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct Env {
    dir: PathBuf,
    /// 持有 tempdir 保证目录在整个用例期间存在（Drop 时自动删除）。
    _tmp: tempfile::TempDir,
    manager: Arc<DownloadManager>,
}

fn temp_env(_tag: &str) -> Env {
    let tmp = common::tempdir("upd");
    let dir = tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        dir.join("downloads"),
    ));
    manager.set_update_staging_dir(dir.join("staging"));
    Env {
        dir,
        _tmp: tmp,
        manager,
    }
}

fn wait_update(rx: &std::sync::mpsc::Receiver<EngineEvent>, timeout: Duration) -> Vec<EngineEvent> {
    let mut out = Vec::new();
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(ev) => {
                if matches!(ev, EngineEvent::Update { .. }) {
                    let terminal = matches!(
                        &ev,
                        EngineEvent::Update { phase, .. }
                            if phase == UPDATE_PHASE_AVAILABLE
                                || phase == UPDATE_PHASE_UP_TO_DATE
                                || phase == UPDATE_PHASE_DONE
                                || phase == UPDATE_PHASE_ERROR
                    );
                    out.push(ev);
                    if terminal {
                        break;
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => break,
        }
    }
    out
}

fn last_update(events: &[EngineEvent]) -> &EngineEvent {
    events
        .iter()
        .rev()
        .find(|e| matches!(e, EngineEvent::Update { .. }))
        .expect("update event")
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256_reader(std::io::Cursor::new(bytes)).unwrap()
}

fn set_base(manager: &DownloadManager, url: &str) {
    manager
        .settings_set("update.manifest_base_url", url)
        .unwrap();
}

#[test]
fn invalid_manifest_is_check_failed() {
    let env = temp_env("invalid");
    let server = TestServer::new(Arc::new(|req: &Req| match req.path.as_str() {
        "/stable/version.json" => (
            200,
            "application/json",
            INVALID_MANIFEST.as_bytes().to_vec(),
        ),
        _ => (404, "text/plain", b"no".to_vec()),
    }));
    set_base(&env.manager, &server.url(""));
    let rx = env.manager.events().subscribe();
    env.manager.update_check();
    let evs = wait_update(&rx, Duration::from_secs(5));
    match last_update(&evs) {
        EngineEvent::Update {
            phase,
            code,
            current_version,
            ..
        } => {
            assert_eq!(phase, UPDATE_PHASE_ERROR);
            assert_eq!(code.as_deref(), Some(ERR_CHECK_FAILED));
            assert_eq!(
                current_version.as_deref(),
                Some(aidm_engine::update::current_app_version())
            );
        }
        other => panic!("{other:?}"),
    }
    let map = env.manager.settings_get().unwrap();
    let last = map
        .get("update.last_check_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(!last.is_empty(), "engine must write last_check_at");
}

#[test]
fn already_latest_is_up_to_date() {
    let env = temp_env("latest");
    let current = aidm_engine::update::current_app_version().to_string();
    let hex = sha256_hex(FAKE_PKG);
    let server = TestServer::new(Arc::new({
        let current = current.clone();
        let hex = hex.clone();
        move |req: &Req| match req.path.as_str() {
            "/stable/version.json" => {
                let body = format!(
                    r#"{{"version":"{current}","url":"http://127.0.0.1/pkg.bin","sha256":"{hex}","notes":"same"}}"#
                );
                (200, "application/json", body.into_bytes())
            }
            _ => (404, "text/plain", b"no".to_vec()),
        }
    }));
    set_base(&env.manager, &server.url(""));
    let rx = env.manager.events().subscribe();
    env.manager.update_check();
    let evs = wait_update(&rx, Duration::from_secs(5));
    match last_update(&evs) {
        EngineEvent::Update {
            phase,
            version,
            current_version,
            ..
        } => {
            assert_eq!(phase, UPDATE_PHASE_UP_TO_DATE);
            assert_eq!(version.as_deref(), Some(current.as_str()));
            assert_eq!(current_version.as_deref(), Some(current.as_str()));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn sha256_mismatch_does_not_apply() {
    let env = temp_env("mismatch");
    let applied = Arc::new(AtomicBool::new(false));
    env.manager.set_update_apply_hook(Some(Arc::new({
        let applied = applied.clone();
        move |_| {
            applied.store(true, Ordering::SeqCst);
            Ok(())
        }
    })));
    let wrong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let host_holder: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let server = TestServer::new(Arc::new({
        let host_holder = host_holder.clone();
        let pkg = FAKE_PKG.to_vec();
        move |req: &Req| match req.path.as_str() {
            "/stable/version.json" => {
                let host = host_holder.lock().unwrap().clone().unwrap_or_default();
                let body = format!(
                    r#"{{"version":"99.0.0","url":"{host}/pkg.bin","sha256":"{wrong}","notes":"bad hash"}}"#
                );
                (200, "application/json", body.into_bytes())
            }
            "/pkg.bin" => (200, "application/octet-stream", pkg.clone()),
            _ => (404, "text/plain", b"no".to_vec()),
        }
    }));
    *host_holder.lock().unwrap() = Some(server.url(""));
    set_base(&env.manager, &server.url(""));
    let rx = env.manager.events().subscribe();
    env.manager.update_check();
    let evs = wait_update(&rx, Duration::from_secs(5));
    match last_update(&evs) {
        EngineEvent::Update { phase, version, .. } => {
            assert_eq!(phase, UPDATE_PHASE_AVAILABLE);
            assert_eq!(version.as_deref(), Some("99.0.0"));
        }
        other => panic!("{other:?}"),
    }
    env.manager.update_download_apply().unwrap();
    let evs = wait_update(&rx, Duration::from_secs(5));
    match last_update(&evs) {
        EngineEvent::Update { phase, code, .. } => {
            assert_eq!(phase, UPDATE_PHASE_ERROR);
            assert_eq!(code.as_deref(), Some(ERR_CHECKSUM_MISMATCH));
        }
        other => panic!("{other:?}"),
    }
    assert!(
        !applied.load(Ordering::SeqCst),
        "must not apply on checksum mismatch"
    );
}

#[test]
fn download_apply_fake_package() {
    let env = temp_env("apply");
    let marker = env.dir.join("applied");
    env.manager.set_update_apply_hook(Some(Arc::new({
        let marker = marker.clone();
        move |path| {
            assert!(path.exists(), "package missing: {}", path.display());
            std::fs::write(&marker, path.to_string_lossy().as_bytes()).unwrap();
            Ok(())
        }
    })));
    let hex = sha256_hex(FAKE_PKG);
    let host_holder: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let server = TestServer::new(Arc::new({
        let host_holder = host_holder.clone();
        let pkg = FAKE_PKG.to_vec();
        let hex = hex.clone();
        move |req: &Req| match req.path.as_str() {
            "/beta/version.json" => {
                let host = host_holder.lock().unwrap().clone().unwrap_or_default();
                let body = format!(
                    r#"{{"version":"99.0.0","url":"{host}/fake-package.bin","sha256":"{hex}","notes":"fixture"}}"#
                );
                (200, "application/json", body.into_bytes())
            }
            "/fake-package.bin" => (200, "application/octet-stream", pkg.clone()),
            _ => (404, "text/plain", b"no".to_vec()),
        }
    }));
    *host_holder.lock().unwrap() = Some(server.url(""));
    env.manager.settings_set("update.channel", "beta").unwrap();
    set_base(&env.manager, &server.url(""));
    let rx = env.manager.events().subscribe();
    env.manager.update_check();
    let evs = wait_update(&rx, Duration::from_secs(5));
    match last_update(&evs) {
        EngineEvent::Update { phase, notes, .. } => {
            assert_eq!(phase, UPDATE_PHASE_AVAILABLE);
            assert_eq!(notes.as_deref(), Some("fixture"));
        }
        other => panic!("{other:?}"),
    }
    env.manager.update_download_apply().unwrap();
    let evs = wait_update(&rx, Duration::from_secs(5));
    match last_update(&evs) {
        EngineEvent::Update {
            phase,
            version,
            current_version,
            ..
        } => {
            assert_eq!(phase, UPDATE_PHASE_DONE);
            assert_eq!(version.as_deref(), Some("99.0.0"));
            assert_eq!(
                current_version.as_deref(),
                Some(aidm_engine::update::current_app_version())
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(marker.exists(), "apply hook not invoked");
}

#[test]
fn check_network_failure() {
    let env = temp_env("net");
    env.manager
        .settings_set("update.manifest_base_url", "http://127.0.0.1:1")
        .unwrap();
    let rx = env.manager.events().subscribe();
    env.manager.update_check();
    let evs = wait_update(&rx, Duration::from_secs(8));
    match last_update(&evs) {
        EngineEvent::Update { phase, code, .. } => {
            assert_eq!(phase, UPDATE_PHASE_ERROR);
            assert_eq!(code.as_deref(), Some(ERR_NETWORK));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn apply_without_check_fails() {
    let env = temp_env("nocheck");
    let rx = env.manager.events().subscribe();
    let err = env.manager.update_download_apply().unwrap_err();
    assert_eq!(err, "no_update_available");
    let evs = wait_update(&rx, Duration::from_secs(2));
    match last_update(&evs) {
        EngineEvent::Update { phase, code, .. } => {
            assert_eq!(phase, UPDATE_PHASE_ERROR);
            assert_eq!(code.as_deref(), Some(ERR_UPDATE_FAILED));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn settings_get_exposes_app_version_and_update_keys() {
    let env = temp_env("settings");
    let map = env.manager.settings_get().unwrap();
    assert_eq!(
        map.get("app.version").and_then(|v| v.as_str()),
        Some(aidm_engine::update::current_app_version())
    );
    assert_eq!(
        map.get("update.channel").and_then(|v| v.as_str()),
        Some("stable")
    );
    assert_eq!(
        map.get("update.auto_check").and_then(|v| v.as_str()),
        Some("true")
    );
    assert_eq!(
        map.get("update.last_check_at").and_then(|v| v.as_str()),
        Some("")
    );
}

#[test]
fn ipc_update_check_returns_ok_quickly() {
    let env = temp_env("ipc");
    let current = aidm_engine::update::current_app_version().to_string();
    let hex = sha256_hex(FAKE_PKG);
    let server = TestServer::new(Arc::new({
        let current = current.clone();
        let hex = hex.clone();
        move |req: &Req| match req.path.as_str() {
            "/stable/version.json" => {
                let body = format!(
                    r#"{{"version":"{current}","url":"http://127.0.0.1/x.bin","sha256":"{hex}"}}"#
                );
                (200, "application/json", body.into_bytes())
            }
            _ => (404, "text/plain", b"no".to_vec()),
        }
    }));
    set_base(&env.manager, &server.url(""));
    let port = server::serve_ephemeral(env.manager.clone()).expect("listen");
    let mut sub = engine_subscribe(port, Duration::from_secs(3)).unwrap();
    sub.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let start = std::time::Instant::now();
    let resp =
        engine_roundtrip(port, &EngineRequest::UpdateCheck, Duration::from_secs(15)).unwrap();
    assert!(resp.ok);
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "update_check must return quickly"
    );
    let mut saw = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match sub.read_event() {
            Ok(EngineEvent::Update { phase, .. })
                if phase == UPDATE_PHASE_UP_TO_DATE || phase == UPDATE_PHASE_ERROR =>
            {
                saw = true;
                break;
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    assert!(saw, "expected update event on subscribe");
}
