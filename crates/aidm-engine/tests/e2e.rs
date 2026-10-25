//! 引擎进程 + 原生消息宿主端到端。
//!
//! 隔离 `XDG_DATA_HOME` / `LOCALAPPDATA`，不写系统代理或浏览器策略键。

mod common;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aidm_ipc::{
    engine_roundtrip, read_nmh_message, write_nmh_message, EngineRequest, EngineResponse,
    ExtResponse, AIDM_EXT_ID, HOST_NAME, PORT_FILE,
};

/// 每个 e2e 进程内唯一的数据根。`Instant::now().elapsed()` 几乎总是 0，
/// Windows 上并行用例会撞上同一 `%TEMP%\aidm-e2e-{pid}-0`，Drop 删库后
/// Status 就会拿到空 task。
fn isolated_data_home() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join("aidm-tests").join(format!(
        "aidm-e2e-{}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn spawn_engine_process(data_home: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_aidm-engine"))
        .env("XDG_DATA_HOME", data_home)
        .env("LOCALAPPDATA", data_home)
        .env("HOME", data_home)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn engine")
}


/// 等待预算缩放：CI 的 2 vCPU runner 上启动进程/握手更慢，用环境变量放大。
/// 本地默认 1.0（行为不变），CI 设 3.0。
fn budget(d: Duration) -> Duration {
    let scale = std::env::var("AIDM_TEST_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v >= 1.0)
        .unwrap_or(1.0);
    d.mul_f64(scale)
}

fn wait_instance_lock_free(data_dir: &Path, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(lock) = aidm_core::try_acquire_instance_lock(data_dir) {
            drop(lock);
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "engine.lock still held after crash at {}",
        data_dir.display()
    );
}

fn wait_task_status(port: u16, id: u64, timeout: Duration) -> EngineResponse {
    let start = Instant::now();
    let mut last: Option<Result<EngineResponse, String>> = None;
    while start.elapsed() < timeout {
        match engine_roundtrip(port, &EngineRequest::Status { id }, budget(Duration::from_secs(15))) {
            Ok(st) if st.ok && st.task.is_some() => return st,
            other => last = Some(other),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    match last {
        Some(Ok(st)) => st,
        Some(Err(e)) => panic!("status after crash+restart failed: {e}"),
        None => panic!("status after crash+restart: no response"),
    }
}

fn workspace_bin(name: &str) -> PathBuf {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let engine = PathBuf::from(env!("CARGO_BIN_EXE_aidm-engine"));
    let sibling = engine.with_file_name(&exe);
    if sibling.exists() {
        return sibling;
    }
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    for profile in ["debug", "release"] {
        let cand = root.join("target").join(profile).join(&exe);
        if cand.exists() {
            return cand;
        }
    }
    sibling
}

fn ensure_host_bin() -> PathBuf {
    let p = workspace_bin("aidm-ext-host");
    if p.exists() {
        return p;
    }
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "aidm-ext-host"])
        .status()
        .expect("build aidm-ext-host");
    assert!(status.success(), "aidm-ext-host build failed");
    workspace_bin("aidm-ext-host")
}

struct Isolated {
    dir: PathBuf,
    child: Child,
    /// 持有 tempdir：字段先于 `child` 之后 drop，`Drop` 里先杀子进程再删。
    _tmp: tempfile::TempDir,
}

impl Isolated {
    fn spawn_engine() -> Self {
        let tmp = common::tempdir("e2e");
        let dir = tmp.path().to_path_buf();
        Self {
            child: spawn_engine_process(&dir),
            dir,
            _tmp: tmp,
        }
    }

    fn data_dir(&self) -> PathBuf {
        if cfg!(windows) {
            self.dir.join("AIDM")
        } else {
            self.dir.join("aidm")
        }
    }

    fn wait_port(&self, timeout: Duration) -> u16 {
        let port_file = self.data_dir().join(PORT_FILE);
        let start = Instant::now();
        while start.elapsed() < timeout {
            if let Ok(s) = std::fs::read_to_string(&port_file) {
                if let Ok(p) = s.trim().parse::<u16>() {
                    if engine_roundtrip(p, &EngineRequest::Ping, Duration::from_millis(300))
                        .map(|r| r.ok)
                        .unwrap_or(false)
                    {
                        return p;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("engine port not ready at {}", port_file.display());
    }
}

impl Drop for Isolated {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn nmh_roundtrip(host: &Path, data_home: &Path, json: &str) -> ExtResponse {
    let mut child = Command::new(host)
        .arg(format!("chrome-extension://{AIDM_EXT_ID}/"))
        .env("XDG_DATA_HOME", data_home)
        .env("LOCALAPPDATA", data_home)
        .env("HOME", data_home)
        .env("AIDM_HOST_ALLOW_NON_BROWSER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn host");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        write_nmh_message(&mut stdin, json.as_bytes()).expect("write frame");
    }
    let mut stdout = child.stdout.take().expect("stdout");
    let bytes = read_nmh_message(&mut stdout).expect("read frame");
    let _ = child.kill();
    let _ = child.wait();
    serde_json::from_slice(&bytes).expect("ext json")
}

#[test]
fn engine_and_native_host_e2e() {
    let mut env = Isolated::spawn_engine();
    let port = env.wait_port(budget(Duration::from_secs(8)));
    let ping = engine_roundtrip(port, &EngineRequest::Ping, budget(Duration::from_secs(15))).unwrap();
    assert!(ping.ok);

    let host = ensure_host_bin();
    let pong = nmh_roundtrip(&host, &env.dir, r#"{"v":1,"op":"ping"}"#);
    assert!(pong.ok, "host ping: {pong:?}");

    let status = nmh_roundtrip(&host, &env.dir, r#"{"v":1,"op":"status"}"#);
    assert_eq!(status.engine_online, Some(true));
    assert!(status.active.unwrap_or(0) < 100);

    // FTP 现在由引擎实现：宿主转发后应当被接受
    let ftp = nmh_roundtrip(
        &host,
        &env.dir,
        r#"{"v":1,"op":"add","url":"ftp://example.com/a.bin"}"#,
    );
    assert!(ftp.ok, "FTP 应被接受: {ftp:?}");
    // 仍然拒绝不支持的 scheme
    let file = nmh_roundtrip(
        &host,
        &env.dir,
        r#"{"v":1,"op":"add","url":"file:///tmp/a.bin"}"#,
    );
    assert!(!file.ok);
    assert_eq!(file.code.as_deref(), Some("bad_url"));

    let _ = env.child.kill();
    let _ = HOST_NAME;
}

#[test]
fn engine_process_crash_restart_requeues() {
    let mut env = Isolated::spawn_engine();
    let port = env.wait_port(budget(Duration::from_secs(8)));
    let add = engine_roundtrip(
        port,
        &EngineRequest::Add {
            url: "http://127.0.0.1:1/never.bin".into(),
            dir: Some(env.dir.join("dl").to_string_lossy().into_owned()),
            filename: Some("never.bin".into()),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            source: None,
            speed_limit_kbps: 0,
            start: Some("now".into()),
        },
        budget(Duration::from_secs(15)),
    )
    .unwrap();
    assert!(add.ok);
    let id = add.id.expect("id");

    std::thread::sleep(Duration::from_millis(400));
    let _ = env.child.kill();
    env.child.wait().ok();
    // 避免 wait_port 误连已死进程留下的端口文件。
    let _ = std::fs::remove_file(env.data_dir().join(PORT_FILE));
    wait_instance_lock_free(&env.data_dir(), budget(Duration::from_secs(5)));

    let db = env.data_dir().join("db.sqlite");
    let start = Instant::now();
    while start.elapsed() < budget(Duration::from_secs(3)) {
        if db.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        db.exists(),
        "engine must persist db.sqlite before crash at {}",
        db.display()
    );
    {
        let conn = aidm_core::open_db(&db).unwrap();
        aidm_core::model::get_download(&conn, id as i64)
            .expect("read download")
            .expect("add must persist a downloads row");
        aidm_core::model::set_status(&conn, id as i64, aidm_core::Status::Downloading, None)
            .expect("mark downloading so recover_on_startup requeues");
    }

    env.child = spawn_engine_process(&env.dir);
    let port = env.wait_port(budget(Duration::from_secs(8)));
    let st = wait_task_status(port, id, budget(Duration::from_secs(5)));
    assert!(st.ok, "status after crash+restart must succeed: {st:?}");
    assert!(
        st.task.is_some(),
        "status.task missing after crash+restart: {st:?}"
    );
    let task = st.task.unwrap();
    assert_ne!(task.state, "error", "crash recovery must not fail the task");
    assert!(
        task.state == "queued"
            || task.state == "connecting"
            || task.state == "downloading"
            || task.error_code.as_deref() == Some("interrupted"),
        "expected requeue/interrupted, got {task:?}"
    );
    if task.state == "queued" {
        assert_eq!(task.error_code.as_deref(), Some("interrupted"));
    }
}

#[test]
fn isolated_data_homes_are_unique() {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for _ in 0..32 {
        assert!(
            seen.insert(isolated_data_home()),
            "parallel e2e cases must not share a data home"
        );
    }
}

#[test]
fn installer_config_never_writes_proxy_or_policy() {
    let conf = include_str!("../../aidm-ui/tauri.conf.json");
    assert!(!conf.contains("Policies"));
    assert!(!conf.contains("ProxyEnable"));
    assert!(!conf.contains("Internet Settings"));
    assert!(!conf.contains("ExtensionInstallForcelist"));
    let ci = include_str!("../../../.github/workflows/aidm-ci.yml");
    assert!(
        ci.contains("intentionally not run"),
        "CI must keep verify_1gb.sh out of executed steps"
    );
    assert!(!ci.contains("./scripts/verify_1gb"));
    assert!(!ci.contains("one_gb_sha256_offline"));
}

#[allow(dead_code)]
fn _touch_read(p: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut f = std::fs::File::open(p)?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    Ok(b)
}

#[allow(dead_code)]
fn _touch_write(p: &Path, b: &[u8]) -> Result<(), std::io::Error> {
    let mut f = std::fs::File::create(p)?;
    f.write_all(b)
}
