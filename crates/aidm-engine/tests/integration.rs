//! 集成测试：本地测试 HTTP 服务器 + 引擎管理器端到端。
//!
//! 覆盖：Range 支持 / 不支持、多连接分段、暂停后续传不重下已完成段、
//! 取消/删除无残留 part、合并 SHA256、ETag 变化拒续、段级 503 Retry-After、
//! 崩溃恢复（缺失 part / 未合并 verifying）。单线程路径保持回归。

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aidm_core::db::open_db;
use aidm_core::hash::sha256_reader;
use aidm_core::model;
use aidm_core::secret;
use aidm_core::settings;
use aidm_core::Status;
use aidm_engine::manager::{DownloadManager, IoFault, Progress};
use aidm_engine::server;
use aidm_ipc::{
    engine_roundtrip, engine_subscribe, EngineEvent, EngineRequest, OfferItem, OfferKind,
};

mod common;

// ---------- 测试 HTTP 服务器 ----------

#[derive(Debug)]
struct Req {
    path: String,
    headers: HashMap<String, String>,
}

enum BodySrc {
    Mem(Vec<u8>),
    File {
        path: PathBuf,
        offset: u64,
        len: u64,
    },
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: BodySrc,
    chunk: usize,
    chunk_delay: Duration,
    /// 写出这么多字节后关连接，模拟断流。
    drop_after: Option<u64>,
    /// 用 `Transfer-Encoding: chunked` 且**不写** `Content-Length`。
    ///
    /// 这是“未知长度下载”的夹具：客户端拿不到总长，只能靠连接结束定界。
    chunked: bool,
}

impl Resp {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: BodySrc::Mem(body),
            chunk: 16 * 1024,
            chunk_delay: Duration::ZERO,
            drop_after: None,
            chunked: false,
        }
    }

    /// 分块传输、不给长度：模拟 chunked / 无 `Content-Length` 的响应。
    fn chunked(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: BodySrc::Mem(body),
            chunk: 16 * 1024,
            chunk_delay: Duration::ZERO,
            drop_after: None,
            chunked: true,
        }
    }

    fn file(path: PathBuf, offset: u64, len: u64) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: BodySrc::File { path, offset, len },
            chunk: 64 * 1024,
            chunk_delay: Duration::ZERO,
            drop_after: None,
            chunked: false,
        }
    }

    fn empty(status: u16) -> Self {
        let mut r = Self::ok(vec![]);
        r.status = status;
        r
    }

    fn slow(mut self, chunk: usize, delay: Duration) -> Self {
        self.chunk = chunk;
        self.chunk_delay = delay;
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn drop_after(mut self, n: u64) -> Self {
        self.drop_after = Some(n);
        self
    }

    fn len(&self) -> u64 {
        match &self.body {
            BodySrc::Mem(b) => b.len() as u64,
            BodySrc::File { len, .. } => *len,
        }
    }
}

#[derive(Debug)]
struct Recorded {
    path: String,
    range: Option<String>,
    ua: Option<String>,
    referer: Option<String>,
    cookie: Option<String>,
    accept_encoding: Option<String>,
    /// 全部请求头（小写名）：用于断言自定义头等任意头
    all_headers: HashMap<String, String>,
    #[allow(dead_code)]
    bytes_out: u64,
}

type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

struct TestServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn new(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (reqs, stop2) = (requests.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(true).expect("set nonblocking");
            for stream in listener.incoming() {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => {
                        let _ = stream.set_nonblocking(false);
                        let handler = handler.clone();
                        let reqs = reqs.clone();
                        std::thread::spawn(move || serve_conn(stream, handler, reqs));
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
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
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

fn serve_conn(stream: std::net::TcpStream, handler: Handler, requests: Arc<Mutex<Vec<Recorded>>>) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() {
            return;
        }
        let h = h.trim();
        if h.is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let req = Req {
        path: path.clone(),
        headers: headers.clone(),
    };
    let resp = handler(&req);
    let bytes_out = resp.len();
    requests.lock().unwrap().push(Recorded {
        path,
        range: headers.get("range").cloned(),
        ua: headers.get("user-agent").cloned(),
        referer: headers.get("referer").cloned(),
        cookie: headers.get("cookie").cloned(),
        accept_encoding: headers.get("accept-encoding").cloned(),
        all_headers: headers.clone(),
        bytes_out,
    });
    let mut out = stream;
    let status_text = match resp.status {
        206 => "Partial Content",
        302 | 301 => "Found",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, status_text);
    if resp.chunked {
        // 故意不给 Content-Length：客户端只能靠分块编码/连接结束定界。
        head.push_str("Transfer-Encoding: chunked\r\n");
    } else {
        head.push_str(&format!("Content-Length: {}\r\n", resp.len()));
    }
    for (name, value) in &resp.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    if out.write_all(head.as_bytes()).is_err() {
        return;
    }
    let chunk = resp.chunk.max(1);
    let mut sent = 0u64;
    let drop_after = resp.drop_after;
    match resp.body {
        BodySrc::Mem(body) => {
            for part in body.chunks(chunk) {
                let ok = if resp.chunked {
                    out.write_all(format!("{:x}\r\n", part.len()).as_bytes())
                        .and_then(|_| out.write_all(part))
                        .and_then(|_| out.write_all(b"\r\n"))
                        .and_then(|_| out.flush())
                } else {
                    out.write_all(part).and_then(|_| out.flush())
                };
                if ok.is_err() {
                    return;
                }
                sent += part.len() as u64;
                if drop_after.is_some_and(|n| sent >= n) {
                    return;
                }
                if !resp.chunk_delay.is_zero() {
                    std::thread::sleep(resp.chunk_delay);
                }
            }
            // 分块编码的终止块：缺了它客户端会一直等下一块。
            if resp.chunked && out.write_all(b"0\r\n\r\n").is_err() {
                return;
            }
        }
        BodySrc::File { path, offset, len } => {
            let Ok(mut f) = std::fs::File::open(&path) else {
                return;
            };
            if f.seek(SeekFrom::Start(offset)).is_err() {
                return;
            }
            let mut left = len;
            let mut buf = vec![0u8; chunk];
            while left > 0 {
                let n = left.min(chunk as u64) as usize;
                if f.read_exact(&mut buf[..n]).is_err() {
                    return;
                }
                if out.write_all(&buf[..n]).and_then(|_| out.flush()).is_err() {
                    return;
                }
                sent += n as u64;
                left -= n as u64;
                if drop_after.is_some_and(|lim| sent >= lim) {
                    return;
                }
                if !resp.chunk_delay.is_zero() {
                    std::thread::sleep(resp.chunk_delay);
                }
            }
        }
    }
}

fn parse_range(h: &str, total: usize) -> (usize, usize) {
    let s = h.strip_prefix("bytes=").unwrap_or(h);
    let (a, b) = s.split_once('-').unwrap_or((s, ""));
    let start = a.parse::<usize>().unwrap_or(0).min(total);
    let end = if b.is_empty() {
        total.saturating_sub(1)
    } else {
        b.parse::<usize>()
            .unwrap_or(total.saturating_sub(1))
            .min(total.saturating_sub(1))
    };
    (start, end)
}

fn ranged_mem(body: &[u8], req: &Req, support: bool) -> Resp {
    if !support {
        return Resp::ok(body.to_vec());
    }
    let Some(range) = req.headers.get("range") else {
        return Resp::ok(body.to_vec());
    };
    let total = body.len();
    let (start, end) = parse_range(range, total);
    if start >= total {
        return Resp::empty(416);
    }
    let slice = body[start..=end].to_vec();
    let mut r = Resp::ok(slice);
    r.status = 206;
    r.headers.push((
        "Content-Range".into(),
        format!("bytes {start}-{end}/{total}"),
    ));
    r
}

fn ranged_file(path: &Path, total: u64, req: &Req) -> Resp {
    let Some(range) = req.headers.get("range") else {
        return Resp::file(path.to_path_buf(), 0, total);
    };
    let (start, end) = parse_range(range, total as usize);
    let start = start as u64;
    let end = end as u64;
    let mut r = Resp::file(path.to_path_buf(), start, end.saturating_sub(start) + 1);
    r.status = 206;
    r.headers.push((
        "Content-Range".into(),
        format!("bytes {start}-{end}/{total}"),
    ));
    r
}

// ---------- 测试脚手架 ----------

/// `DownloadManager` 的持有槽：存在的唯一目的是让 [`Env`] 能在 `Drop` 里**提前**释放它。
///
/// 为什么需要：Windows 上只要 sqlite 连接还开着，`remove_dir_all` 就删不掉目录，
/// 临时目录会一直堆在 `%TEMP%`。`Deref` 让 300 多处 `env.manager.xxx()` 保持原样。
struct ManagerSlot(Option<DownloadManager>);

impl std::ops::Deref for ManagerSlot {
    type Target = DownloadManager;
    fn deref(&self) -> &DownloadManager {
        self.0.as_ref().expect("manager 已被释放")
    }
}

impl std::ops::DerefMut for ManagerSlot {
    fn deref_mut(&mut self) -> &mut DownloadManager {
        self.0.as_mut().expect("manager 已被释放")
    }
}

struct Env {
    dir: PathBuf,
    manager: ManagerSlot,
    _tmp: tempfile::TempDir,
}

impl Drop for Env {
    fn drop(&mut self) {
        // 先放掉 manager（关闭 sqlite 连接），再删临时目录。worker 线程可能还握着
        // 句柄，所以重试几次；删不掉也不影响测试结论（TempDir 随后还会再试一次）。
        let _ = self.manager.0.take();
        for _ in 0..20 {
            if std::fs::remove_dir_all(self._tmp.path()).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

fn temp_env(tag: &str) -> Env {
    temp_env_conns(tag, None)
}

fn temp_env_conns(tag: &str, max_conns: Option<i64>) -> Env {
    // 目录落在 `%TEMP%\aidm-tests\aidm-m2-{tag}-XXXXXX`（见 `tests/common`），
    // 进程内首次建目录时顺手清掉 1 小时前的旧目录 —— Windows 上 worker 线程可能
    // 比用例活得久，`TempDir::drop` 的一次删除会失败。
    let tmp = common::tempdir(&format!("m2-{tag}"));
    let dir = tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    // 普通集成用例仅访问其本地服务；公网 Kad 单独由 ignored 探针验收。
    settings::set(&db, "ed2k.kad_enabled", "false").unwrap();
    if let Some(n) = max_conns {
        // 每任务连接数不设限（设置里没有这个键）：用全局闸门表达"这个用例要几根连接"。
        settings::set(&db, "conn.global_conn_cap", &n.to_string()).unwrap();
    }
    let manager = DownloadManager::new(Arc::new(Mutex::new(db)), dir.join("downloads"));
    Env {
        dir,
        manager: ManagerSlot(Some(manager)),
        _tmp: tmp,
    }
}

/// 等待窗口的可缩放倍数。CI 的 2 vCPU runner 上，慢速滴灌 + 并行用例会让
/// 状态推进明显变慢；用环境变量放大等待预算，避免把「环境慢」误报成功能回归。
/// 本地默认 1.0（行为不变），CI 设 3.0。
fn timeout_scale() -> f64 {
    std::env::var("AIDM_TEST_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v >= 1.0)
        .unwrap_or(1.0)
}

fn until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    let timeout = timeout.mul_f64(timeout_scale());
    while start.elapsed() < timeout {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    pred()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn pattern_sha256(len: usize) -> String {
    sha256_reader(std::io::Cursor::new(pattern(len))).unwrap()
}

fn event_kinds(db_path: &Path, id: i64) -> Vec<String> {
    let conn = open_db(db_path).unwrap();
    model::list_events(&conn, id)
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect()
}

/// 事件时间线：`(相对秒, kind, detail)`，按写入顺序。
///
/// 探测阶段的耗时不能靠 curl 反推（上一轮的教训）：库里每条事件都有 unix 秒时间戳，
/// 直接读出来就是 AIDM **自己**花在每个候选上的时间。
fn timeline(db_path: &Path, id: i64) -> Vec<(i64, String, Option<String>)> {
    let conn = open_db(db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT ts, kind, detail FROM events WHERE download_id=?1 ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap();
    let mut out: Vec<(i64, String, Option<String>)> = rows.filter_map(|r| r.ok()).collect();
    if let Some(base) = out.first().map(|r| r.0) {
        for r in out.iter_mut() {
            r.0 -= base;
        }
    }
    out
}

fn event_details(db_path: &Path, id: i64, kind: &str) -> Vec<String> {
    let conn = open_db(db_path).unwrap();
    model::list_events(&conn, id)
        .unwrap()
        .into_iter()
        .filter(|(k, _)| k == kind)
        .filter_map(|(_, d)| d)
        .collect()
}

fn leftover_parts(dir: &Path, id: i64) -> Vec<PathBuf> {
    let part_dir = dir.join("downloads").join(".aidm").join(id.to_string());
    if !part_dir.exists() {
        return Vec::new();
    }
    std::fs::read_dir(&part_dir)
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default()
}

// ---------- 单连接回归 ----------

#[test]
fn redirect_headers_and_full_download() {
    let server = TestServer::new(Arc::new(|req: &Req| match req.path.as_str() {
        "/redir/pkg" => {
            let mut r = Resp::ok(vec![]);
            r.status = 302;
            r.headers = vec![("Location".into(), "/final/real.bin".into())];
            r
        }
        p if p.starts_with("/final/") => {
            let body = pattern(300 * 1024);
            Resp::ok(body)
                .header(
                    "Content-Disposition",
                    "attachment; filename=\"renamed.bin\"",
                )
                .header("ETag", "\"abc123\"")
                .header("Content-Type", "application/octet-stream")
        }
        _ => Resp::ok(b"not found".to_vec()),
    }));

    let env = temp_env("redirect");
    let (tx, rx) = std::sync::mpsc::channel();
    env.manager
        .set_progress_callback(Arc::new(move |p: Progress| {
            let _ = tx.send(p);
        }));
    let id = env
        .manager
        .add(
            &server.url("/redir/pkg"),
            None,
            None,
            Some("https://ref.example/page"),
            0,
        )
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "task should finish"
    );

    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.url.as_deref(), Some(server.url("/redir/pkg").as_str()));
    assert_ne!(
        task.url.as_deref(),
        Some(server.url("/final/real.bin").as_str())
    );
    assert_eq!(task.name, "renamed.bin");
    assert_eq!(task.done, 300 * 1024);
    assert_eq!(task.total, Some(300 * 1024));
    assert!((task.pct.unwrap() - 100.0).abs() < 0.01);
    assert_eq!(task.state, "done");
    assert_eq!(task.mode.as_deref(), Some("single"));

    let data = std::fs::read(&task.save_path).unwrap();
    assert_eq!(data, pattern(300 * 1024));

    let conn_path = env.dir.join("db.sqlite");
    let conn = open_db(&conn_path).unwrap();
    let row = model::get_download(&conn, id as i64).unwrap().unwrap();
    assert_eq!(row.status, Status::Done);
    assert_eq!(row.url_final, Some(server.url("/final/real.bin")));
    assert_eq!(row.size_total, Some(300 * 1024));

    let kinds = event_kinds(&conn_path, id as i64);
    assert!(kinds.contains(&"created".into()));
    assert!(kinds.contains(&"range_probe".into()));
    assert!(kinds.contains(&"degrade_single".into()));
    assert!(kinds.contains(&"start".into()));
    assert!(kinds.contains(&"done".into()));
    assert!(kinds.contains(&"sha256".into()));

    let reqs = server.requests.lock().unwrap();
    assert!(
        reqs.len() >= 2,
        "expect at least probe+download hops: {:?}",
        &*reqs
    );
    assert!(reqs.iter().any(|r| r.path == "/redir/pkg"));
    assert!(reqs.iter().any(|r| r.path == "/final/real.bin"));
    for r in reqs.iter() {
        // UA 使用默认值（见 docs/http-profile.md），不自报客户端标识
        assert_eq!(
            r.ua.as_deref(),
            Some(aidm_core::setting_spec::DEFAULT_USER_AGENT),
            "UA 应为默认值: {:?}",
            r.ua
        );
        assert_eq!(r.accept_encoding.as_deref(), Some("identity"));
        // 显式给了 Referer 就必须用它，不能被站点根兜底覆盖
        assert_eq!(r.referer.as_deref(), Some("https://ref.example/page"));
    }

    drop(reqs);
    let mut last = 0u64;
    while let Ok(p) = rx.try_recv() {
        assert!(p.done_bytes >= last);
        assert_eq!(p.total, Some(300 * 1024));
        last = p.done_bytes;
    }
    assert_eq!(last, 300 * 1024);
}

#[test]
fn cancel_mid_download_stops_and_cleans() {
    let server = TestServer::new(Arc::new(|_req: &Req| {
        Resp::ok(pattern(2 * 1024 * 1024)).slow(16 * 1024, Duration::from_millis(30))
    }));

    let env = temp_env("cancel");
    let id = env
        .manager
        .add(&server.url("/big.bin"), None, None, None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager
                .status(id)
                .unwrap()
                .map(|t| t.done > 0)
                .unwrap_or(false)
        }),
        "should have partial progress"
    );

    env.manager.cancel(id).unwrap();
    assert!(until(Duration::from_secs(10), || env
        .manager
        .list()
        .unwrap()
        .is_empty()));
    assert!(
        env.manager.list().unwrap().is_empty(),
        "task row removed after cancel"
    );
    assert!(
        !env.dir.join("downloads/big.bin").exists(),
        "partial file removed"
    );
    assert!(
        leftover_parts(&env.dir, id as i64).is_empty(),
        "no residual .aidm parts"
    );
}

#[test]
fn pause_resume_with_single_range() {
    let total = 240 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        let base = if let Some(range) = req.headers.get("range") {
            let start: usize = range
                .strip_prefix("bytes=")
                .and_then(|s| s.split('-').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let slice = server_body[start.min(total)..].to_vec();
            let mut r = Resp::ok(slice);
            r.status = 206;
            r.headers = vec![(
                "Content-Range".into(),
                format!("bytes {start}-{}/{total}", total - 1),
            )];
            r
        } else {
            Resp::ok(server_body.to_vec())
        };
        base.slow(8 * 1024, Duration::from_millis(20))
    }));

    let env = temp_env("pause_resume");
    let id = env
        .manager
        .add(&server.url("/data.bin"), None, Some("data.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager
                .status(id)
                .unwrap()
                .map(|t| t.done > 64 * 1024)
                .unwrap_or(false)
        }),
        "partial progress expected"
    );
    env.manager.pause(id).unwrap();
    assert!(
        until(Duration::from_secs(10), || {
            env.manager.status(id).unwrap().unwrap().state == "paused"
        }),
        "should reach paused"
    );
    let paused = env.manager.status(id).unwrap().unwrap();
    let partial_len = std::fs::metadata(&paused.save_path).unwrap().len();
    assert_eq!(partial_len, paused.done, "file len matches persisted done");

    env.manager.resume(id).unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "resume should finish"
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.done, total as u64);
    let data = std::fs::read(&task.save_path).unwrap();
    assert_eq!(data, pattern(total));

    let reqs = server.requests.lock().unwrap();
    assert!(
        reqs.iter().any(|r| r
            .range
            .as_deref()
            .and_then(|s| s.strip_prefix("bytes="))
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|start| start > 0)
            .unwrap_or(false)),
        "expected a ranged request: {:?}",
        &*reqs
    );
}

#[test]
fn http_error_becomes_error_status() {
    let server = TestServer::new(Arc::new(|_req: &Req| Resp::empty(404)));
    let env = temp_env("err404");
    let id = env
        .manager
        .add(&server.url("/missing.bin"), None, None, None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(15), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "should reach error state"
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.error_code.as_deref(), Some("http_404"));
    assert_eq!(task.http_status, Some(404));
    assert!(
        task.error.as_deref().unwrap_or("").contains("404"),
        "error must stay human-readable: {:?}",
        task.error
    );
    env.manager.resume(id).unwrap();
    assert!(
        until(Duration::from_secs(15), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "retryable after resume"
    );
}

#[test]
fn startup_recovery_requeues_running_as_interrupted() {
    let env = temp_env("recovery");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let conn = aidm_core::open_db(&db_path).unwrap();
        model::insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 1).unwrap()
    };
    {
        let conn = aidm_core::open_db(&db_path).unwrap();
        model::set_status(&conn, id, Status::Downloading, None).unwrap();
    }
    env.manager.recover_on_startup();
    let conn = aidm_core::open_db(&db_path).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.status, Status::Queued);
    assert_eq!(row.error_code.as_deref(), Some("interrupted"));
    assert_ne!(
        row.status,
        Status::Error,
        "interrupted must not fail the task"
    );
    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(view.state, "queued");
    assert_eq!(view.error_code.as_deref(), Some("interrupted"));
    assert!(view.error.as_deref().unwrap_or("").contains("重新排队"));
}

// ---------- 分段续传 ----------

#[test]
fn range_supported_multi_segment_sha256() {
    let total = 2 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let expect = pattern_sha256(total);
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true).header("ETag", "\"v1\"")
    }));

    let env = temp_env_conns("multi_hash", Some(8));
    let id = env
        .manager
        .add(&server.url("/multi.bin"), None, Some("multi.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(40), || {
            env.manager
                .status(id)
                .unwrap()
                .and_then(|t| t.segments)
                .map(|s| {
                    s.len() >= 2
                        && s.windows(2).all(|w| w[1].idx == w[0].idx + 1)
                        && s.iter().any(|seg| seg.done_bytes > 0)
                })
                .unwrap_or(false)
        }),
        "status JSON should expose ordered segments while running: {:?}",
        env.manager.status(id)
    );
    assert!(
        until(Duration::from_secs(40), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "multi download should finish: {:?}",
        env.manager.status(id)
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.mode.as_deref(), Some("multi"));
    assert_eq!(task.done, total as u64);
    let ipc_segs = task.segments.as_ref().expect("TaskView.segments");
    assert!(ipc_segs.len() >= 2);
    for (i, s) in ipc_segs.iter().enumerate() {
        assert_eq!(s.idx, i as u32, "segments must be idx-ordered");
        let end = s.pos_end.expect("multi segment has pos_end");
        assert_eq!(s.status, "done");
        assert_eq!(s.done_bytes, end - s.pos_start + 1);
    }
    let listed = env.manager.list().unwrap();
    assert_eq!(
        listed[0].segments.as_ref().map(|s| s.len()),
        Some(ipc_segs.len())
    );
    let wire = serde_json::to_value(&task).unwrap();
    assert!(
        wire.get("segments").and_then(|v| v.as_array()).is_some(),
        "status JSON must include segments: {wire}"
    );
    let data = std::fs::read(&task.save_path).unwrap();
    assert_eq!(
        aidm_core::hash::sha256_reader(std::io::Cursor::new(&data)).unwrap(),
        expect
    );
    assert_eq!(data, pattern(total));
    assert!(
        leftover_parts(&env.dir, id as i64).is_empty(),
        "part dir cleared after merge"
    );

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let segs = model::list_segments(&conn, id as i64).unwrap();
    assert!(
        segs.len() >= 2,
        "expected multiple segments, got {}",
        segs.len()
    );
    assert!(segs.iter().all(|s| s.is_done()));
    let kinds = event_kinds(&env.dir.join("db.sqlite"), id as i64);
    assert!(kinds.contains(&"range_probe".into()));
    assert!(kinds.contains(&"verifying".into()));
    assert!(kinds.contains(&"sha256".into()));
    let hashes = event_details(&env.dir.join("db.sqlite"), id as i64, "sha256");
    assert_eq!(hashes.last().map(String::as_str), Some(expect.as_str()));
}

#[test]
fn range_not_supported_degrades_single() {
    let total = 512 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, false)
    }));
    let env = temp_env_conns("no_range", Some(8));
    let id = env
        .manager
        .add(&server.url("/full.bin"), None, Some("full.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.mode.as_deref(), Some("single"));
    assert_eq!(std::fs::read(&task.save_path).unwrap(), pattern(total));
    let details = event_details(&env.dir.join("db.sqlite"), id as i64, "degrade_single");
    assert!(
        details.iter().any(|d| d.contains("no_range")),
        "expected degrade_single no_range, got {details:?}"
    );

    // 能力模型的两层不能混：**同一个地址**，预检（无观测）给协议上界"能分片"，
    // 按任务查则要如实收窄成"这次不能分片"，并说清为什么。少了这层收窄，界面就会
    // 一边显示"支持分段"、一边跑着单连接。
    let upper = env
        .manager
        .capabilities(None, Some(&server.url("/full.bin")))
        .unwrap();
    assert!(
        upper.capabilities.segment,
        "预检只有协议上界：HTTP 上界允许分片"
    );
    assert!(
        upper.note.is_none(),
        "预检没有观测，不该凭空给解释: {upper:?}"
    );

    let observed = env.manager.capabilities(Some(id as u64), None).unwrap();
    assert!(
        !observed.capabilities.segment,
        "按任务查必须用实测收窄掉分片: {observed:?}"
    );
    assert!(
        !observed.capabilities.seek,
        "同一份观测也砍掉随机定位（两者都依赖按范围取）: {observed:?}"
    );
    assert!(
        observed.capabilities.resume && observed.capabilities.pause,
        "收窄只砍与观测直接相关的位，不该误伤暂停/续传: {observed:?}"
    );
    assert!(
        observed
            .note
            .as_deref()
            .is_some_and(|n| n.contains("不支持按范围取")),
        "比上界弱就必须说得清为什么: {observed:?}"
    );
}

#[test]
fn pause_resume_skips_completed_segments() {
    let total = 2 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        let resp = ranged_mem(&server_body, req, true);
        // 第一段（start=0 且非探测 0-0）快速完成，其余段故意拖慢，便于中途暂停。
        if let Some(range) = req.headers.get("range") {
            let (start, end) = parse_range(range, total);
            if start == 0 && end > 0 {
                return resp;
            }
        }
        resp.slow(8 * 1024, Duration::from_millis(25))
    }));

    let env = temp_env_conns("pause_multi", Some(4));
    let id = env
        .manager
        .add(&server.url("/seg.bin"), None, Some("seg.bin"), None, 0)
        .unwrap();

    let db_path = env.dir.join("db.sqlite");
    assert!(
        until(Duration::from_secs(40), || {
            let conn = open_db(&db_path).unwrap();
            model::list_segments(&conn, id as i64)
                .map(|segs| {
                    let any_done = segs.iter().any(|s| s.is_done());
                    let any_open = segs.iter().any(|s| !s.is_done());
                    any_done && any_open
                })
                .unwrap_or(false)
        }),
        "need a mix of completed and unfinished segments before pause"
    );

    env.manager.pause(id).unwrap();
    assert!(until(Duration::from_secs(15), || {
        env.manager.status(id).unwrap().unwrap().state == "paused"
    }));

    let completed: Vec<(i32, String)> = {
        let conn = open_db(&db_path).unwrap();
        model::list_segments(&conn, id as i64)
            .unwrap()
            .into_iter()
            .filter(|s| s.is_done())
            .map(|s| {
                (
                    s.idx,
                    format!("bytes={}-{}", s.pos_start, s.pos_end.unwrap_or(0)),
                )
            })
            .collect()
    };
    assert!(
        !completed.is_empty(),
        "need a completed segment to assert no re-fetch"
    );
    let completed_ranges: Vec<String> = completed.iter().map(|(_, r)| r.clone()).collect();

    env.manager.resume(id).unwrap();
    assert!(
        until(Duration::from_secs(40), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "resume should finish"
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(std::fs::read(&task.save_path).unwrap(), pattern(total));

    let reqs = server.requests.lock().unwrap();
    let resume_hits: Vec<&Recorded> = reqs
        .iter()
        .filter(|r| {
            r.range
                .as_deref()
                .is_some_and(|rg| completed_ranges.iter().any(|c| c == rg))
        })
        .collect();
    // 探测 bytes=0-0 可能与第 0 段区间不同；已完成段的精确 Range 只应在 pause 前出现一次。
    for (_, rg) in &completed {
        let count = reqs
            .iter()
            .filter(|r| r.range.as_deref() == Some(rg.as_str()))
            .count();
        assert_eq!(
            count,
            1,
            "completed range {rg} re-fetched; hits={resume_hits:?} all={:?}",
            reqs.iter().map(|r| r.range.clone()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn conn_limit_change_resplits_running_task_on_resume() {
    let total = 8 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let expect = pattern_sha256(total);
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        // 故意放慢：必须保证"暂停时还没下完"，否则续跑直接完成就看不到切分。
        ranged_mem(&server_body, req, true).slow(4 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env_conns("resplit_run", Some(2));
    let id = env
        .manager
        .add(&server.url("/r.bin"), None, Some("r.bin"), None, 0)
        .unwrap();
    let db_path = env.dir.join("db.sqlite");

    // 2 段且已有进度（下载仍在跑）
    assert!(
        until(Duration::from_secs(30), || {
            let conn = open_db(&db_path).unwrap();
            model::list_segments(&conn, id as i64)
                .map(|s| s.len() == 2 && s.iter().any(|x| x.done_bytes > 0))
                .unwrap_or(false)
        }),
        "need 2 running segments with progress: {:?}",
        env.manager.status(id)
    );
    let before = {
        let conn = open_db(&db_path).unwrap();
        model::list_segments(&conn, id as i64)
            .unwrap()
            .into_iter()
            .map(|s| (s.pos_start, s.pos_end.unwrap(), s.done_bytes))
            .collect::<Vec<_>>()
    };
    assert_eq!(before.len(), 2);
    let done_before: i64 = before.iter().map(|(_, _, d)| *d).sum();
    assert!(
        done_before > 0 && (done_before as usize) < total / 2,
        "暂停时必须处在下载中段：{done_before}/{total}"
    );

    // 连接预算的唯一权威是「每服务器例外 > 全局闸门」，任务行里的派生值不参与：
    // 暂停 → 给这台主机加一条 4 的例外 → 续跑时在剩余区间中点再切分。
    env.manager.pause(id).unwrap();
    assert!(until(Duration::from_secs(15), || {
        env.manager.status(id).unwrap().unwrap().state == "paused"
    }));
    env.manager
        .settings_set("conn.global_conn_cap", "32")
        .unwrap();
    env.manager
        .host_conns_set("127.0.0.1", Some(4), None)
        .unwrap();
    env.manager.resume(id).unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            let conn = open_db(&db_path).unwrap();
            model::list_segments(&conn, id as i64)
                .map(|s| s.len() == 4)
                .unwrap_or(false)
        }),
        "续跑时必须切到 4 段: {:?}",
        env.manager.status(id)
    );

    let after = {
        let conn = open_db(&db_path).unwrap();
        model::list_segments(&conn, id as i64).unwrap()
    };
    assert_eq!(after.len(), 4, "segment count must follow the task's conns");
    for (i, s) in after.iter().enumerate() {
        assert_eq!(s.idx, i as i32, "renumbered by byte order");
    }
    for w in after.windows(2) {
        assert_eq!(w[1].pos_start, w[0].pos_end.unwrap() + 1, "no gap");
    }
    assert_eq!(after[0].pos_start, 0);
    assert_eq!(after.last().unwrap().pos_end.unwrap() as usize, total - 1);
    assert!(
        after.iter().map(|s| s.done_bytes).sum::<i64>() >= done_before,
        "downloaded bytes must not regress"
    );
    // 每段一分为二：前半段保留已完成字节，新段的下载从切点（已完成字节之后）开始
    for (start, end, done) in &before {
        let inside: Vec<_> = after
            .iter()
            .filter(|s| s.pos_start >= *start && s.pos_end.unwrap() <= *end)
            .collect();
        assert_eq!(inside.len(), 2, "each original segment is split in two");
        assert_eq!(inside[0].pos_start, *start);
        assert_eq!(inside[1].pos_end.unwrap(), *end);
        assert_eq!(inside[1].pos_start, inside[0].pos_end.unwrap() + 1);
        assert!(
            inside[0].done_bytes >= *done,
            "first half keeps its part file: {inside:?}"
        );
        assert!(
            inside[1].pos_start > *start + *done,
            "new connection starts at the cut: {inside:?}"
        );
    }
    // 切分发生在续跑后的 worker 里、段线程启动之前；从外部只能验证最终字节与事件。
    assert!(
        until(Duration::from_secs(90), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "resplit task must finish: {:?}",
        env.manager.status(id)
    );
    let task = env.manager.status(id).unwrap().unwrap();
    let data = std::fs::read(&task.save_path).unwrap();
    assert_eq!(data.len(), total);
    assert_eq!(
        sha256_reader(std::io::Cursor::new(&data)).unwrap(),
        expect,
        "bytes must merge in order after the split"
    );
    assert_eq!(data, pattern(total));
    assert!(leftover_parts(&env.dir, id as i64).is_empty());
    let kinds = event_kinds(&db_path, id as i64);
    assert_eq!(
        kinds.iter().filter(|k| *k == "resegmented").count(),
        1,
        "expected one resegmented event, got {kinds:?}"
    );
}

#[test]
fn cancel_multi_leaves_zero_part_files() {
    let total = 2 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true).slow(8 * 1024, Duration::from_millis(15))
    }));
    let env = temp_env_conns("cancel_multi", Some(4));
    let id = env
        .manager
        .add(&server.url("/c.bin"), None, Some("c.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        leftover_parts(&env.dir, id as i64)
            .iter()
            .any(|p| std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false))
            || env
                .manager
                .status(id)
                .unwrap()
                .map(|t| t.done > 32 * 1024)
                .unwrap_or(false)
    }));
    env.manager.cancel(id).unwrap();
    assert!(until(Duration::from_secs(10), || env
        .manager
        .list()
        .unwrap()
        .is_empty()));
    assert!(leftover_parts(&env.dir, id as i64).is_empty());
    assert!(!env.dir.join("downloads/c.bin").exists());
    let aidm_root = env.dir.join("downloads/.aidm");
    assert!(
        !aidm_root.exists()
            || std::fs::read_dir(&aidm_root)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
        ".aidm should be empty after cancel"
    );
}

#[test]
fn etag_change_refuses_resume_and_restarts() {
    let total = 2 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let etag = Arc::new(Mutex::new("\"v1\"".to_string()));
    let server_body = body.clone();
    let etag2 = etag.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        let tag = etag2.lock().unwrap().clone();
        ranged_mem(&server_body, req, true)
            .header("ETag", &tag)
            .slow(16 * 1024, Duration::from_millis(8))
    }));
    let env = temp_env_conns("etag", Some(4));
    let id = env
        .manager
        .add(&server.url("/e.bin"), None, Some("e.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager
            .status(id)
            .unwrap()
            .map(|t| t.done > 64 * 1024)
            .unwrap_or(false)
    }));
    env.manager.pause(id).unwrap();
    assert!(until(Duration::from_secs(10), || {
        env.manager.status(id).unwrap().unwrap().state == "paused"
    }));
    let done_before = env.manager.status(id).unwrap().unwrap().done;
    *etag.lock().unwrap() = "\"v2\"".into();

    env.manager.resume(id).unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager.status(id).unwrap().unwrap().state == "error"
    }));
    let details = event_details(&env.dir.join("db.sqlite"), id as i64, "validator_changed");
    assert!(
        details.iter().any(|d| d.contains("action=remote_changed")),
        "expected validator_changed remote_changed, got {details:?}"
    );
    assert!(done_before > 0);
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.error_code.as_deref(), Some("remote_changed"));
    assert!(task.http_status.is_none());
    assert!(task.error.as_deref().unwrap_or("").contains("变化"));
}

#[test]
fn segment_retry_honors_retry_after() {
    let total = 512 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let real_fails = Arc::new(AtomicU64::new(0));
    let fails = real_fails.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if let Some(range) = req.headers.get("range") {
            if range != "bytes=0-0" && fails.fetch_add(1, Ordering::SeqCst) == 0 {
                return Resp::empty(503).header("Retry-After", "1");
            }
        }
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env_conns("retry", Some(2));
    let id = env
        .manager
        .add(&server.url("/r.bin"), None, Some("r.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "should finish after Retry-After: {:?}",
        env.manager.status(id)
    );
    let kinds = event_kinds(&env.dir.join("db.sqlite"), id as i64);
    assert!(
        kinds.contains(&"segment_retry".into()),
        "expected segment_retry event, got {kinds:?}"
    );
}

#[test]
fn crash_recovery_missing_part_and_unmerged() {
    let total = 1024 * 1024u64;
    let spans = aidm_core::segment::plan_segments(total, 4);
    assert!(spans.len() >= 2);
    let env = temp_env("crash_parts");
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(
            &conn,
            "http://127.0.0.1/x.bin",
            "x.bin",
            &save_dir.to_string_lossy(),
            0,
            4,
        )
        .unwrap();
        let paths: Vec<String> = spans
            .iter()
            .enumerate()
            .map(|(i, _)| {
                aidm_core::segment::part_path(&save_dir, id, i as i32)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        model::replace_segments(&conn, id, &spans, &paths).unwrap();
        model::set_meta(
            &conn,
            id,
            "http://127.0.0.1/x.bin",
            Some(total as i64),
            Some("\"e\""),
            None,
            "x.bin",
        )
        .unwrap();
        model::set_status(&conn, id, Status::Downloading, None).unwrap();
        std::fs::create_dir_all(aidm_core::segment::part_dir(&save_dir, id)).unwrap();
        for (i, span) in spans.iter().enumerate() {
            let p = aidm_core::segment::part_path(&save_dir, id, i as i32);
            let mut data = vec![0u8; span.len() as usize];
            for (j, b) in data.iter_mut().enumerate() {
                *b = ((span.start as usize + j) % 251) as u8;
            }
            std::fs::write(&p, &data).unwrap();
            model::set_segment_state(&conn, id, i as i32, span.len() as i64, "done").unwrap();
        }
        id
    };

    // 全 done + part 在、最终文件无 → verifying
    env.manager.recover_on_startup();
    {
        let conn = open_db(&db_path).unwrap();
        let row = model::get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.status, Status::Verifying);
    }

    // 毁掉第 1 段 part，再恢复 → 该段 pending
    let part1 = aidm_core::segment::part_path(&save_dir, id, 1);
    std::fs::remove_file(&part1).unwrap();
    {
        let conn = open_db(&db_path).unwrap();
        model::set_status(&conn, id, Status::Paused, None).unwrap();
    }
    env.manager.recover_on_startup();
    {
        let conn = open_db(&db_path).unwrap();
        let segs = model::list_segments(&conn, id).unwrap();
        let s1 = segs.iter().find(|s| s.idx == 1).unwrap();
        assert_eq!(s1.status, "pending");
        assert_eq!(s1.done_bytes, 0);
        assert!(segs.iter().any(|s| s.idx == 0 && s.is_done()));
        let row = model::get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.status, Status::Paused);
    }
}

#[test]
fn resume_verifying_merges_without_redownload() {
    let total = 1024 * 1024usize;
    let body = pattern(total);
    let expect = pattern_sha256(total);
    let env = temp_env("remerge");
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let spans = aidm_core::segment::plan_segments(total as u64, 4);
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(
            &conn,
            "http://127.0.0.1/m.bin",
            "m.bin",
            &save_dir.to_string_lossy(),
            0,
            4,
        )
        .unwrap();
        let paths: Vec<String> = spans
            .iter()
            .enumerate()
            .map(|(i, _)| {
                aidm_core::segment::part_path(&save_dir, id, i as i32)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        model::replace_segments(&conn, id, &spans, &paths).unwrap();
        model::set_meta(
            &conn,
            id,
            "http://127.0.0.1/m.bin",
            Some(total as i64),
            None,
            None,
            "m.bin",
        )
        .unwrap();
        std::fs::create_dir_all(aidm_core::segment::part_dir(&save_dir, id)).unwrap();
        for (i, span) in spans.iter().enumerate() {
            let p = aidm_core::segment::part_path(&save_dir, id, i as i32);
            std::fs::write(&p, &body[span.start as usize..=span.end as usize]).unwrap();
            model::set_segment_state(&conn, id, i as i32, span.len() as i64, "done").unwrap();
        }
        model::set_status(&conn, id, Status::Verifying, None).unwrap();
        id
    };
    env.manager.resume(id).unwrap();
    assert!(until(Duration::from_secs(15), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let task = env.manager.status(id).unwrap().unwrap();
    let got = aidm_core::hash::sha256_file(Path::new(&task.save_path)).unwrap();
    assert_eq!(got, expect);
    assert!(leftover_parts(&env.dir, id).is_empty());
}

/// 离线 1GB 验收（默认 ignore）。见 `AIDM/scripts/verify_1gb.sh`。
/// 设置 `AIDM_1GB=1` 后以 `cargo test -p aidm-engine --test integration one_gb -- --ignored --nocapture` 运行。
#[test]
#[ignore]
fn one_gb_sha256_offline() {
    if std::env::var("AIDM_1GB").ok().as_deref() != Some("1") {
        eprintln!("skip: set AIDM_1GB=1 to run the 1GiB offline check");
        return;
    }
    // 临时目录由 `tempfile::tempdir()` 提供：绝对路径 + Drop 自动清理。
    let _tmp = common::tempdir("1gb");
    let dir = _tmp.path().to_path_buf();
    let src = dir.join("src.bin");
    {
        let mut f = std::fs::File::create(&src).unwrap();
        let mut left = 1024u64 * 1024 * 1024;
        let chunk = vec![0x5Au8; 1024 * 1024];
        while left > 0 {
            let n = left.min(chunk.len() as u64) as usize;
            f.write_all(&chunk[..n]).unwrap();
            left -= n as u64;
        }
    }
    let expect = aidm_core::hash::sha256_file(&src).unwrap();
    let total = 1024u64 * 1024 * 1024;
    let src2 = src.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_file(&src2, total, req).header("ETag", "\"1gb\"")
    }));
    let env = temp_env_conns("one_gb", Some(8));
    let id = env
        .manager
        .add(&server.url("/src.bin"), None, Some("out.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(600), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "1GB download failed: {:?}",
        env.manager.status(id)
    );
    let task = env.manager.status(id).unwrap().unwrap();
    let got = aidm_core::hash::sha256_file(Path::new(&task.save_path)).unwrap();
    assert_eq!(got, expect, "1GB SHA256 mismatch");
    assert!(leftover_parts(&env.dir, id as i64).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- 设置 / 限速 / 删除 / 推送 ----------

#[test]
fn settings_validation_and_password_not_plaintext() {
    let env = temp_env("m3_settings");
    let map = env.manager.settings_get().unwrap();
    assert!(map.contains_key("speed.global_limit_kbps"));
    assert!(map.contains_key("proxy.mode"));
    assert_eq!(
        map.get("proxy.has_password"),
        Some(&serde_json::json!(false))
    );
    assert!(!map.contains_key("proxy.pass"));

    assert_eq!(
        env.manager
            .settings_set("speed.global_limit_kbps", "-10")
            .unwrap_err()
            .code,
        "speed_limit_invalid"
    );
    assert_eq!(
        env.manager
            .settings_get()
            .unwrap()
            .get("speed.global_limit_kbps")
            .and_then(|v| v.as_str()),
        Some("0")
    );
    assert_eq!(
        env.manager
            .settings_set("proxy.host", "http://nope")
            .unwrap_err()
            .code,
        "proxy_host_malformed"
    );
    assert_eq!(
        env.manager
            .settings_set("proxy.port", "70000")
            .unwrap_err()
            .code,
        "proxy_port_malformed"
    );
    assert_eq!(
        env.manager
            .settings_set("does.not.exist", "1")
            .unwrap_err()
            .code,
        "unknown_setting_key"
    );

    env.manager
        .settings_set("speed.global_limit_kbps", "256")
        .unwrap();
    assert_eq!(env.manager.limiter().limit_bps(), 256 * 1024);

    env.manager
        .settings_set("proxy.pass", "hunter2-secret")
        .unwrap();
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let raw = settings::get(&conn, "proxy.pass").unwrap().unwrap();
    assert!(!raw.contains("hunter2-secret"), "plaintext in db: {raw}");
    assert!(secret::is_protected(&raw));
    let map = env.manager.settings_get().unwrap();
    assert_eq!(
        map.get("proxy.has_password"),
        Some(&serde_json::json!(true))
    );
    assert!(!map.contains_key("proxy.pass"));
    let sys = env.manager.system_proxy_get();
    assert!(sys.is_null() || sys.get("host").is_some());
}

#[test]
fn global_limiter_rough_accuracy() {
    let total = 160 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, false)
    }));
    let env = temp_env("m3_limit");
    env.manager
        .settings_set("speed.global_limit_kbps", "40")
        .unwrap();
    let t0 = std::time::Instant::now();
    let id = env
        .manager
        .add(&server.url("/lim.bin"), None, Some("lim.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(20), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "limited download should finish: {:?}",
        env.manager.status(id)
    );
    let elapsed = t0.elapsed();
    // 160KiB / 40KiB/s ≈ 4s；探测 + 突发允许 1.5..=12s
    assert!(
        elapsed >= Duration::from_millis(1500) && elapsed <= Duration::from_secs(12),
        "limiter elapsed={elapsed:?}"
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(std::fs::read(&task.save_path).unwrap(), pattern(total));
}

#[test]
fn delete_with_and_without_files() {
    let body = Arc::new(pattern(64 * 1024));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |_req: &Req| Resp::ok(server_body.to_vec())));
    let env = temp_env("m3_delete");
    let id_keep = env
        .manager
        .add(&server.url("/keep.bin"), None, Some("keep.bin"), None, 0)
        .unwrap();
    let id_drop = env
        .manager
        .add(&server.url("/drop.bin"), None, Some("drop.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager
            .status(id_keep)
            .unwrap()
            .is_some_and(|t| t.state == "done")
            && env
                .manager
                .status(id_drop)
                .unwrap()
                .is_some_and(|t| t.state == "done")
    }));
    let keep_path = env.manager.status(id_keep).unwrap().unwrap().save_path;
    let drop_path = env.manager.status(id_drop).unwrap().unwrap().save_path;
    assert!(Path::new(&keep_path).exists());
    assert!(Path::new(&drop_path).exists());

    env.manager
        .delete(&[id_keep as u64, id_drop as u64], false)
        .unwrap();
    assert!(env.manager.list().unwrap().is_empty());
    assert!(
        Path::new(&keep_path).exists(),
        "delete_files=false keeps file"
    );
    assert!(Path::new(&drop_path).exists());
    assert!(leftover_parts(&env.dir, id_keep as i64).is_empty());
    assert!(leftover_parts(&env.dir, id_drop as i64).is_empty());

    let id_rm = env
        .manager
        .add(&server.url("/rm.bin"), None, Some("rm.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager.status(id_rm).unwrap().unwrap().state == "done"
    }));
    let rm_path = env.manager.status(id_rm).unwrap().unwrap().save_path;
    env.manager.delete(&[id_rm as u64], true).unwrap();
    assert!(
        !Path::new(&rm_path).exists(),
        "delete_files=true removes file"
    );
    assert!(env.manager.status(id_rm).unwrap().is_none());
}

#[test]
fn derived_referer_is_not_sent_for_same_origin_downloads() {
    let total = 64 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, false)
    }));
    let env = temp_env("referer_origin");
    let id = env
        .manager
        .add(&server.url("/a.bin"), None, Some("a.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(15), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "下载未完成：{:?}",
        env.manager.status(id)
    );
    let reqs = server.requests.lock().unwrap();
    assert!(
        reqs.iter().all(|r| r.referer.is_none()),
        "同源兜底 Referer 不应发送（会触发 CDN 防盗链）：{:?}",
        reqs.iter().map(|r| &r.referer).collect::<Vec<_>>()
    );
}

#[test]
fn resume_only_starts_the_requested_task() {
    let env = temp_env("resume_single");
    let dir = env.dir.to_string_lossy().into_owned();
    let (a, b) = {
        let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
        let a = model::insert_download(&conn, "https://example.invalid/a.bin", "a.bin", &dir, 0, 1)
            .unwrap();
        let b = model::insert_download(&conn, "https://example.invalid/b.bin", "b.bin", &dir, 0, 1)
            .unwrap();
        model::set_status(&conn, a, Status::Paused, None).unwrap();
        model::set_status(&conn, b, Status::Paused, None).unwrap();
        (a, b)
    };
    env.manager.resume(a).unwrap();
    assert_ne!(
        env.manager.status(a).unwrap().unwrap().state,
        "paused",
        "被点名的任务应离开 paused"
    );
    assert_eq!(
        env.manager.status(b).unwrap().unwrap().state,
        "paused",
        "手动开始一个任务不得恢复其他已暂停任务"
    );
    // 收尾：把刚启动的 worker 叫停，避免用例结束后仍在连 example.invalid。
    let _ = env.manager.pause(a);
}

#[test]
fn quota_stop_marks_queued_tasks_as_error() {
    let tmp = common::tempdir("quota-stop");
    let dir = tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    settings::set(&db, "sched.quota_enabled", "true").unwrap();
    settings::set(&db, "sched.quota_mb", "1").unwrap();
    settings::set(&db, "sched.quota_action", "stop").unwrap();
    let id = model::insert_download(
        &db,
        "https://example.invalid/a.bin",
        "a.bin",
        dir.to_str().unwrap(),
        0,
        1,
    )
    .unwrap();
    let part = dir.join("a.part");
    model::init_single_segment(&db, id, &part.to_string_lossy(), Some(4 * 1024 * 1024)).unwrap();
    // 第一拍先暂停，避免调度器真的去连 example.invalid；只建立配额基线。
    model::set_start_mode(&db, id, "queue").unwrap();
    model::set_status(&db, id, Status::Paused, None).unwrap();

    let db = Arc::new(Mutex::new(db));
    let manager = DownloadManager::new(db.clone(), dir.join("downloads"));
    manager.tick(); // 建立"本周期已用"基线（0 字节）
    {
        let conn = db.lock().unwrap();
        model::set_segment_state(&conn, id, 0, 2 * 1024 * 1024, "done").unwrap();
        // 回到 queued：配额闸门应把它直接改成 error/quota，而不是放它去下载。
        model::set_status(&conn, id, Status::Queued, None).unwrap();
    }
    manager.tick(); // 2 MiB > 1 MiB：按 stop 处理

    let conn = db.lock().unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.status, Status::Error);
    assert_eq!(
        row.error_code.as_deref(),
        Some(aidm_core::error::CODE_QUOTA_EXCEEDED)
    );
}

#[test]
fn quota_stop_turns_running_task_into_error() {
    let total = 4 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, false).slow(8 * 1024, Duration::from_millis(10))
    }));
    let env = temp_env("quota_stop_running");
    env.manager
        .settings_set("sched.quota_enabled", "true")
        .unwrap();
    env.manager.settings_set("sched.quota_mb", "1").unwrap();
    env.manager
        .settings_set("sched.quota_action", "stop")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/big.bin"), None, None, None, 0)
        .unwrap();
    // 本用例没有启动后台调度线程：手动按 100 ms 节拍跑配额闸门。
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut stopped = false;
    while std::time::Instant::now() < deadline {
        env.manager.tick();
        let st = env.manager.status(id).unwrap().unwrap();
        if st.state == "error" && st.error_code.as_deref() == Some("quota_exceeded") {
            stopped = true;
            break;
        }
        if st.state == "done" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        stopped,
        "运行中的任务应被配额停止为 error/quota：{:?}",
        env.manager.status(id)
    );
}

#[test]
fn quota_pause_resumes_task_after_limit_is_raised() {
    let total = 4 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, false).slow(8 * 1024, Duration::from_millis(10))
    }));
    let env = temp_env("quota_pause_resume");
    env.manager
        .settings_set("sched.quota_enabled", "true")
        .unwrap();
    env.manager.settings_set("sched.quota_mb", "1").unwrap();
    env.manager
        .settings_set("sched.quota_action", "pause")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/big.bin"), None, None, None, 0)
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut paused = false;
    while std::time::Instant::now() < deadline {
        env.manager.tick();
        let st = env.manager.status(id).unwrap().unwrap();
        if st.state == "paused" {
            paused = true;
            break;
        }
        if st.state == "done" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(paused, "配额用尽后应暂停：{:?}", env.manager.status(id));

    // 调大配额：下一拍应只恢复“因配额暂停”的任务。
    env.manager.settings_set("sched.quota_mb", "10").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut done = false;
    while std::time::Instant::now() < deadline {
        env.manager.tick();
        if env.manager.status(id).unwrap().unwrap().state == "done" {
            done = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        done,
        "配额调大后任务应自动恢复并完成：{:?}",
        env.manager.status(id)
    );
}

#[test]
fn ipc_settings_delete_and_events() {
    let total = 192 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, false).slow(8 * 1024, Duration::from_millis(80))
    }));
    let _tmp = common::tempdir("m3-ipc");
    let dir = _tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("downloads")).unwrap();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        dir.join("downloads"),
    ));
    let port = server::serve_ephemeral(manager.clone()).expect("listen");

    let bad = engine_roundtrip(
        port,
        &EngineRequest::SettingsSet {
            key: "speed.global_limit_kbps".into(),
            value: "-3".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(!bad.ok);
    assert_eq!(bad.error.as_deref(), Some("speed_limit_invalid"));

    let got = engine_roundtrip(port, &EngineRequest::SettingsGet, Duration::from_secs(15)).unwrap();
    assert!(got.ok);
    let settings = got.settings.expect("settings");
    assert_eq!(
        settings.get("proxy.has_password"),
        Some(&serde_json::json!(false))
    );
    assert!(!settings.contains_key("proxy.pass"));

    let proxy = engine_roundtrip(
        port,
        &EngineRequest::SystemProxyGet,
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(proxy.ok);
    // 只读接口的契约是"形状正确且永不写系统"：值本身取决于跑测试的机器
    // 有没有配系统代理，断言必须为 null 会让套件在装了代理的开发机上必挂。
    match proxy.system_proxy.as_ref() {
        Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(o)) => {
            assert!(o.get("host").and_then(|v| v.as_str()).is_some(), "缺 host");
            assert!(o.get("port").is_some(), "缺 port");
        }
        other => panic!("system_proxy 形状不对: {other:?}"),
    }

    let mut sub = engine_subscribe(port, Duration::from_secs(8)).unwrap();
    sub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let add = engine_roundtrip(
        port,
        &EngineRequest::Add {
            url: server.url("/e.bin"),
            dir: Some(dir.join("downloads").to_string_lossy().into_owned()),
            filename: Some("e.bin".into()),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            source: None,
            speed_limit_kbps: 0,
            start: None,
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(add.ok);
    let id = add.id.unwrap();

    let mut saw_stats = false;
    let mut saw_zero = false;
    let mut completed = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        match sub.read_event() {
            Ok(EngineEvent::Stats {
                total_speed,
                active_conns,
                speed_limit,
            }) => {
                if total_speed > 0 || active_conns > 0 || speed_limit > 0 {
                    saw_stats = true;
                } else {
                    saw_zero = true;
                }
            }
            Ok(EngineEvent::TaskCompleted {
                id: cid,
                file_path,
                dir: save_dir,
                ..
            }) => {
                completed = Some((cid, file_path, save_dir));
                if saw_stats && saw_zero {
                    break;
                }
            }
            Ok(EngineEvent::Heartbeat)
            | Ok(EngineEvent::Candidates { .. })
            | Ok(EngineEvent::Sched { .. })
            | Ok(EngineEvent::SettingsChanged { .. })
            | Ok(EngineEvent::AfterDone { .. })
            | Ok(EngineEvent::Quota { .. })
            | Ok(EngineEvent::Update { .. }) => {}
            Err(_) => break,
        }
        if completed.is_some() && saw_zero {
            break;
        }
    }
    let (cid, file_path, save_dir) = completed.expect("task_completed event");
    assert_eq!(cid, id);
    assert!(file_path.ends_with("e.bin"));
    assert_eq!(save_dir, dir.join("downloads").to_string_lossy());
    assert!(saw_stats, "expected non-zero stats while active");
    // 空闲全 0 可能稍晚于 completed；再读几秒
    if !saw_zero {
        let extra = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < extra {
            match sub.read_event() {
                Ok(EngineEvent::Stats {
                    total_speed: 0,
                    active_conns: 0,
                    speed_limit: 0,
                }) => {
                    saw_zero = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
    assert!(saw_zero, "expected final all-zero stats");

    let del = engine_roundtrip(
        port,
        &EngineRequest::Delete {
            ids: vec![id],
            delete_files: true,
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(del.ok);
    assert!(!Path::new(&file_path).exists());
}

#[test]
fn cookies_stay_in_memory_and_go_out_as_header() {
    let secret = "session=super-secret-cookie-value";
    let server = TestServer::new(Arc::new(|req: &Req| {
        let body = b"abc".to_vec();
        ranged_mem(&body, req, false)
    }));
    let env = temp_env("cookies_mem");
    let id = env
        .manager
        .add_spec(aidm_engine::manager::AddSpec {
            url: &server.url("/c.bin"),
            dir: None,
            filename: Some("c.bin"),
            referrer: Some("https://ref.example/"),
            cookies: Some(secret),
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("ext"),
            start: None,
        })
        .unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let recs = server.requests.lock().unwrap();
    assert!(
        recs.iter().any(|r| r.cookie.as_deref() == Some(secret)),
        "Cookie header must be sent: {recs:?}"
    );
    drop(recs);

    let view = env.manager.status(id).unwrap().unwrap();
    let view_json = serde_json::to_string(&view).unwrap();
    assert!(
        !view_json.contains(secret),
        "TaskView leaked cookies: {view_json}"
    );
    assert_eq!(view.source.as_deref(), Some("ext"));

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let dump: String = {
        let mut stmt = conn
            .prepare("SELECT url_orig, file_name, dir, source FROM downloads")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| {
                Ok(format!(
                    "{} {} {} {}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        rows.join("|")
    };
    assert!(!dump.contains(secret), "downloads leaked cookies: {dump}");
    let events: String = {
        let mut stmt = conn
            .prepare("SELECT kind, COALESCE(detail,'') FROM events")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| {
                Ok(format!(
                    "{}:{}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        rows.join("|")
    };
    assert!(!events.contains(secret), "events leaked cookies: {events}");
}

#[test]
fn offer_candidates_and_ui_not_running() {
    let env = temp_env("offer_ui");
    let none = env.manager.offer(
        "https://page.example/".into(),
        "Title".into(),
        vec![OfferItem {
            url: "https://cdn.example/a.bin".into(),
            kind: OfferKind::Link,
            filename: Some("a.bin".into()),
        }],
        false,
        Some("k=v".into()),
    );
    assert_eq!(none.unwrap_err(), "ui_not_running");

    let _rx = env.manager.events().subscribe();
    let (oid, truncated) = env
        .manager
        .offer(
            "https://page.example/".into(),
            "Title".into(),
            vec![OfferItem {
                url: "https://cdn.example/a.bin".into(),
                kind: OfferKind::Video,
                filename: Some("a.bin".into()),
            }],
            false,
            Some("k=v".into()),
        )
        .unwrap();
    assert!(!truncated);
    assert!(oid.starts_with("ofr_"));
    let ev = _rx.recv_timeout(Duration::from_secs(2)).unwrap();
    match ev {
        EngineEvent::Candidates {
            offer_id,
            page_url,
            items,
            truncated,
            ..
        } => {
            assert_eq!(offer_id, oid);
            assert_eq!(page_url, "https://page.example/");
            assert_eq!(items[0].kind, OfferKind::Video);
            assert!(truncated.is_none());
            let js = serde_json::to_string(&items).unwrap();
            assert!(!js.contains("k=v"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn add_expired_or_unknown_offer_id_returns_code_offer_expired() {
    let env = temp_env("offer_expired");
    let _rx = env.manager.events().subscribe();
    let (oid, _) = env
        .manager
        .offer(
            "https://page.example/".into(),
            "Title".into(),
            vec![OfferItem {
                url: "https://cdn.example/a.bin".into(),
                kind: OfferKind::Link,
                filename: Some("a.bin".into()),
            }],
            false,
            None,
        )
        .unwrap();
    env.manager.expire_offer(&oid);
    let err = env
        .manager
        .add_spec(aidm_engine::manager::AddSpec {
            url: "https://cdn.example/a.bin",
            dir: None,
            filename: None,
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: Some(&oid),
            speed_limit_kbps: 0,
            source: None,
            start: None,
        })
        .unwrap_err();
    assert_eq!(err, aidm_ipc::ERR_OFFER_EXPIRED);

    let unknown = env
        .manager
        .add_spec(aidm_engine::manager::AddSpec {
            url: "https://cdn.example/a.bin",
            dir: None,
            filename: None,
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: Some("ofr_never"),
            speed_limit_kbps: 0,
            source: None,
            start: None,
        })
        .unwrap_err();
    assert_eq!(unknown, "offer_expired");

    let _tmp = common::tempdir("offer-expired");
    let dir = _tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        dir.join("downloads"),
    ));
    let port = server::serve_ephemeral(manager).expect("listen");
    for offer_id in [oid.as_str(), "ofr_missing"] {
        let expired = engine_roundtrip(
            port,
            &EngineRequest::Add {
                url: "https://cdn.example/a.bin".into(),
                dir: None,
                filename: None,
                referrer: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
                alt_urls: None,
                offer_id: Some(offer_id.into()),
                source: None,
                speed_limit_kbps: 0,
                start: None,
            },
            Duration::from_secs(15),
        )
        .unwrap();
        assert!(!expired.ok);
        assert_eq!(expired.code.as_deref(), Some("offer_expired"));
        assert!(
            expired.error.is_none(),
            "offer_expired must use code, not error text: {:?}",
            expired.error
        );
        let raw = serde_json::to_value(&expired).unwrap();
        assert_eq!(raw["ok"], false);
        assert_eq!(raw["code"], "offer_expired");
        assert!(raw.get("error").is_none(), "{raw}");
    }
}

#[test]
fn add_ftp_is_supported_and_other_schemes_are_not() {
    // FTP 已由引擎实现（crates/aidm-engine/src/ftp.rs），新建应当成功
    let env = temp_env("ftp_add");
    let id = env
        .manager
        .add("ftp://files.example/a.bin", None, None, None, 0)
        .unwrap();
    assert!(id > 0);
    // 大小写不敏感
    let id2 = env
        .manager
        .add("FTP://files.example/b.bin", None, None, None, 0)
        .unwrap();
    assert!(id2 > id);
    let http_err = env
        .manager
        .add("file:///tmp/a.bin", None, None, None, 0)
        .unwrap_err();
    assert_eq!(http_err, "bad_url");
}

#[test]
fn host_status_and_offer_ipc() {
    let _tmp = common::tempdir("m4-ipc");
    let dir = _tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        dir.join("downloads"),
    ));
    let port = server::serve_ephemeral(manager).expect("listen");

    let st = engine_roundtrip(port, &EngineRequest::HostStatus, Duration::from_secs(15)).unwrap();
    assert!(st.ok);
    assert!(st.registered.is_some());

    let ftp = engine_roundtrip(
        port,
        &EngineRequest::Add {
            url: "ftp://files.example/a.bin".into(),
            dir: None,
            filename: None,
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            source: None,
            speed_limit_kbps: 0,
            start: None,
        },
        Duration::from_secs(15),
    )
    .unwrap();
    // FTP 已由引擎实现：经 IPC 新建应当成功并拿到任务 id
    assert!(ftp.ok, "FTP 应被接受: {ftp:?}");
    assert!(ftp.id.unwrap_or(0) > 0);

    let items = vec![OfferItem {
        url: "https://cdn.example/v.mp4".into(),
        kind: OfferKind::Audio,
        filename: None,
    }];
    let no_ui = engine_roundtrip(
        port,
        &EngineRequest::Offer {
            page_url: "https://p.example/".into(),
            title: "P".into(),
            items: items.clone(),
            truncated: false,
            cookies: Some("k=v".into()),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(!no_ui.ok);
    assert_eq!(no_ui.error.as_deref(), Some("ui_not_running"));

    let mut sub = engine_subscribe(port, Duration::from_secs(5)).unwrap();
    sub.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    std::thread::sleep(Duration::from_millis(80));
    let offered = engine_roundtrip(
        port,
        &EngineRequest::Offer {
            page_url: "https://p.example/".into(),
            title: "P".into(),
            items,
            truncated: false,
            cookies: Some("k=v".into()),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(offered.ok);
    let oid = offered.offer_id.expect("offer_id");
    let ev = sub.read_event().unwrap();
    match ev {
        EngineEvent::Candidates {
            offer_id,
            truncated,
            ..
        } => {
            assert_eq!(offer_id, oid);
            assert!(truncated.is_none());
        }
        EngineEvent::Heartbeat | EngineEvent::Sched { .. } => {
            let ev = sub.read_event().unwrap();
            match ev {
                EngineEvent::Candidates { offer_id, .. } => assert_eq!(offer_id, oid),
                EngineEvent::Heartbeat | EngineEvent::Sched { .. } => {
                    let ev = sub.read_event().unwrap();
                    match ev {
                        EngineEvent::Candidates { offer_id, .. } => assert_eq!(offer_id, oid),
                        other => panic!("{other:?}"),
                    }
                }
                other => panic!("{other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

// ---------- 调度 / 队列 ----------

fn wait_state(mgr: &DownloadManager, id: i64, want: &str, timeout: Duration) -> bool {
    until(timeout, || {
        mgr.status(id)
            .ok()
            .flatten()
            .map(|t| t.state == want)
            .unwrap_or(false)
    })
}

fn slow_handler(body: Vec<u8>) -> Handler {
    Arc::new(move |req: &Req| ranged_mem(&body, req, true).slow(1024, Duration::from_millis(200)))
}

fn hold_handler(body: Vec<u8>, hold: Arc<AtomicBool>) -> Handler {
    Arc::new(move |req: &Req| {
        while hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
        ranged_mem(&body, req, true)
    })
}

#[test]
fn all_tasks_start_without_task_concurrency_cap() {
    let body = pattern(64 * 1024);
    let hold = Arc::new(AtomicBool::new(true));
    struct Release(Arc<AtomicBool>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _release = Release(hold.clone());
    let server = TestServer::new(hold_handler(body.clone(), hold.clone()));
    let env = temp_env_conns("no_task_cap", Some(4));
    env.manager
        .host_conns_set("127.0.0.1", Some(2), None)
        .unwrap();
    env.manager
        .settings_set("conn.global_conn_cap", "32")
        .unwrap();

    let a = env
        .manager
        .add(&server.url("/a.bin"), None, Some("a.bin"), None, 0)
        .unwrap();
    let b = env
        .manager
        .add(&server.url("/b.bin"), None, Some("b.bin"), None, 0)
        .unwrap();
    let c = env
        .manager
        .add(&server.url("/c.bin"), None, Some("c.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(5), || {
            [a, b, c].iter().all(|id| {
                matches!(
                    env.manager.status(*id).unwrap().unwrap().state.as_str(),
                    "connecting" | "downloading"
                )
            })
        }),
        "不再限制任务数：三个任务应同时启动：{:?}",
        env.manager.list()
    );
}

#[test]
fn conn_budget_plans_that_many_segments() {
    let body = pattern(2 * 1024 * 1024);
    let server = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body, req, true)));
    let env = temp_env("pertask");
    env.manager
        .settings_set("conn.global_conn_cap", "2")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/p.bin"), None, Some("p.bin"), None, 0)
        .unwrap();
    assert!(wait_state(
        &env.manager,
        id,
        "done",
        Duration::from_secs(30)
    ));
    let view = env.manager.status(id).unwrap().unwrap();
    let segs = view.segments.expect("segments");
    assert_eq!(segs.len(), 2, "per-task conns=2 => 2 segments");
    assert_eq!(view.mode.as_deref(), Some("multi"));
}

#[test]
fn retry_backoff_then_error_and_retry_failed() {
    let server = TestServer::new(Arc::new(|_req: &Req| Resp::empty(503)));
    let env = temp_env("retry_net");
    env.manager.settings_set("conn.retry_max", "2").unwrap();
    // 退避故意放宽到 2 秒：本用例断言的是"首次失败后停在 queued 且带 retry_at"
    // 这个**转瞬即逝**的状态；100 ms 的窗口在并行满载下会被轮询漏掉，
    // 导致断言随机失败（与引擎行为无关，纯属测试自身时序敏感）。
    env.manager
        .settings_set("conn.retry_backoff_ms", "2000")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/fail.bin"), None, Some("fail.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(15), || {
            env.manager.tick();
            let t = env.manager.status(id).unwrap().unwrap();
            t.state == "queued" && t.retry_at.is_some()
        }),
        "first network fail stays queued with retry_at"
    );
    let first_at = env.manager.status(id).unwrap().unwrap().retry_at.unwrap();
    assert!(
        until(Duration::from_secs(20), || {
            env.manager.tick();
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "after retry_max must go error"
    );
    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(view.error_code.as_deref(), Some("http_5xx"));
    assert_eq!(view.http_status, Some(503));
    assert!(view.error.as_deref().unwrap_or("").contains("503"));
    assert!(first_at > 0);
    assert_eq!(env.manager.retry_failed().unwrap(), 1);
    assert_eq!(env.manager.retry_failed().unwrap(), 0);
    let st = env.manager.status(id).unwrap().unwrap().state;
    assert_ne!(st, "error", "requeued task must leave error, got {st}");
}

#[test]
fn cron_validate_next_start_and_queue_vs_now() {
    let body = pattern(32 * 1024);
    let server = TestServer::new(slow_handler(body));
    let env = temp_env("cron");
    env.manager
        .settings_set("sched.start_cron", "0 0 1 1 *")
        .unwrap();
    let queued = env
        .manager
        .add_spec(aidm_engine::manager::AddSpec {
            url: &server.url("/q.bin"),
            filename: Some("q.bin"),
            start: Some("queue"),
            ..Default::default()
        })
        .unwrap();
    let now = env
        .manager
        .add_spec(aidm_engine::manager::AddSpec {
            url: &server.url("/n.bin"),
            filename: Some("n.bin"),
            start: Some("now"),
            ..Default::default()
        })
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(env.manager.status(queued).unwrap().unwrap().state, "queued");
    let ns = env.manager.status(now).unwrap().unwrap().state;
    assert!(
        ns == "connecting" || ns == "downloading" || ns == "done",
        "start=now ignores cron, got {ns}"
    );

    let (next, queued, _active) = env.manager.sched_status();
    assert!(queued >= 1);
    assert!(next.is_some(), "cron set => next_start_at");

    let _tmp = common::tempdir("m5-ipc");
    let dir = _tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        dir.join("downloads"),
    ));
    manager
        .settings_set("sched.start_cron", "0 0 1 1 *")
        .unwrap();
    let port = server::serve_ephemeral(manager).expect("listen");
    let st = engine_roundtrip(port, &EngineRequest::SchedStatus, Duration::from_secs(15)).unwrap();
    assert!(st.ok);
    assert_ne!(st.next_start_at, Some(serde_json::Value::Null));
    assert!(st.next_start_at.is_some());

    let retry =
        engine_roundtrip(port, &EngineRequest::RetryFailed, Duration::from_secs(15)).unwrap();
    assert!(retry.ok);
    assert_eq!(retry.count, Some(0));

    let bad = engine_roundtrip(
        port,
        &EngineRequest::SettingsSet {
            key: "sched.start_cron".into(),
            value: "bad cron".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(!bad.ok);
    assert_eq!(bad.code.as_deref(), Some("invalid_cron"));
    assert_eq!(bad.key.as_deref(), Some("sched.start_cron"));

}

// ---------- 异常路径 ----------

#[test]
fn network_drop_after_retries_emits_network() {
    let body = pattern(256 * 1024);
    let server = TestServer::new(Arc::new(move |_req: &Req| {
        Resp::ok(body.clone())
            .header("ETag", "\"n1\"")
            .drop_after(8 * 1024)
    }));
    let env = temp_env("net_drop");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager
        .settings_set("conn.global_conn_cap", "1")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/drop.bin"), None, Some("drop.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(20), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "dropped connection must become error: {:?}",
        env.manager.status(id)
    );
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.error_code.as_deref(), Some("network"));
    assert!(t.http_status.is_none());
    assert!(t.error.as_deref().unwrap_or("").contains("网络"));
}

#[test]
fn simulated_disk_full_emits_disk_full() {
    let body = pattern(64 * 1024);
    let server = TestServer::new(Arc::new(move |_req: &Req| Resp::ok(body.clone())));
    let env = temp_env("disk_full");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::DiskFull);
    let id = env
        .manager
        .add(&server.url("/full.bin"), None, Some("full.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(15), || {
        env.manager.status(id).unwrap().unwrap().state == "error"
    }));
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.error_code.as_deref(), Some("disk_full"));
    assert!(t.error.as_deref().unwrap_or("").contains("磁盘"));
}

/// 故障注入矩阵（规格 §8）：解析阶段失败必须**不进网络退避**，且与"连不上"分开。
#[test]
fn simulated_dns_failure_lands_in_resolve_phase() {
    let body = pattern(64 * 1024);
    let server = TestServer::new(Arc::new(move |_req: &Req| Resp::ok(body.clone())));
    let env = temp_env("fault_dns");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::DnsFail);
    let id = env
        .manager
        .add(&server.url("/d.bin"), None, Some("d.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(15), || {
        env.manager.status(id).unwrap().unwrap().state == "error"
    }));
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(
        t.error_code.as_deref(),
        Some("blocked_by_hosts"),
        "解析失败要和网络抖动分开：{:?}",
        t.error
    );
    let kinds = event_kinds(&env.dir.join("db.sqlite"), id as i64);
    assert!(
        kinds.contains(&"error".to_string()),
        "失败必须留事件：{kinds:?}"
    );
    // 阶段可归因：诊断包/错误视图能直接回答"失败在哪个阶段"。
    let view =
        aidm_core::diag::error_view(&open_db(&env.dir.join("db.sqlite")).unwrap(), id as i64);
    assert_eq!(view["phase"].as_str(), Some("resolve"), "{view}");
}

/// 故障注入矩阵：**建连成功之后**断流 —— 这条链路要与"连不上"区分开。
#[test]
fn simulated_timeout_after_connect_emits_network() {
    let total = 256 * 1024usize;
    let body = Arc::new(pattern(total));
    let body2 = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&body2, req, true).slow(8 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("fault_timeout");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::Timeout);
    let id = env
        .manager
        .add(&server.url("/t.bin"), None, Some("t.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(25), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "读超时必须失败：{:?}",
        env.manager.status(id)
    );
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.error_code.as_deref(), Some("network"));
    // 阶段归因：失败文本带 `phase=transfer` 标记，因此同一个 `network` 码也能
    // 落到读循环，而不是笼统的 connect（规格 §5 边界 1 的修法）。
    let view =
        aidm_core::diag::error_view(&open_db(&env.dir.join("db.sqlite")).unwrap(), id as i64);
    assert_eq!(view["phase"].as_str(), Some("transfer"), "{view}");
}

/// 故障注入矩阵：传输中途 RST。
#[test]
fn simulated_disconnect_after_connect_emits_network() {
    let total = 256 * 1024usize;
    let body = Arc::new(pattern(total));
    let body2 = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&body2, req, true).slow(8 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("fault_disconnect");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::Disconnect);
    let id = env
        .manager
        .add(&server.url("/r.bin"), None, Some("r.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(25), || {
        env.manager.status(id).unwrap().unwrap().state == "error"
    }));
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.error_code.as_deref(), Some("network"));
    let view =
        aidm_core::diag::error_view(&open_db(&env.dir.join("db.sqlite")).unwrap(), id as i64);
    assert_eq!(view["phase"].as_str(), Some("transfer"), "{view}");
    assert_eq!(
        view["retryable"].as_bool(),
        Some(true),
        "网络类应可退避重试"
    );
}

/// 故障注入矩阵：写完之后篡改文件 —— 必须被 SHA-256 校验拦下（而不是"看起来成功"）。
#[test]
fn simulated_corruption_is_caught_by_sha256() {
    let total = 256 * 1024usize;
    let body = Arc::new(pattern(total));
    let body2 = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&body2, req, true).slow(8 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("fault_corrupt");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::Corrupt);
    let id = env
        .manager
        .add(&server.url("/c.bin"), None, Some("c.bin"), None, 0)
        .unwrap();
    // 期望哈希必须在 `verify_expected_sha256` 之前落库；慢速 body 保证有充裕窗口。
    {
        let expect = pattern_sha256(total);
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        model::set_sha256_expected(&conn, id as i64, Some(expect.as_str())).unwrap();
    }
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "被篡改的文件不得判成功：{:?}",
        env.manager.status(id)
    );
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.error_code.as_deref(), Some("sha256_mismatch"));
    // 损坏必须落到 verify 阶段，且**不该**被当成可重试的网络抖动。
    let view =
        aidm_core::diag::error_view(&open_db(&env.dir.join("db.sqlite")).unwrap(), id as i64);
    assert_eq!(view["phase"].as_str(), Some("verify"), "{view}");
    assert_eq!(view["retryable"].as_bool(), Some(false), "{view}");
}

#[test]
fn no_write_permission_emits_no_permission() {
    let body = pattern(32 * 1024);
    let server = TestServer::new(Arc::new(move |_req: &Req| Resp::ok(body.clone())));
    let env = temp_env("noperm");
    env.manager.settings_set("conn.retry_max", "0").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = env.dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let id = env
            .manager
            .add(
                &server.url("/p.bin"),
                Some(locked.to_str().unwrap()),
                Some("p.bin"),
                None,
                0,
            )
            .unwrap();
        assert!(until(Duration::from_secs(15), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }));
        let t = env.manager.status(id).unwrap().unwrap();
        assert_eq!(t.error_code.as_deref(), Some("no_permission"));
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
        return;
    }

    #[cfg(not(unix))]
    {
        env.manager.set_io_fault(IoFault::NoPermission);
        let id = env
            .manager
            .add(&server.url("/p.bin"), None, Some("p.bin"), None, 0)
            .unwrap();
        assert!(until(Duration::from_secs(15), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }));
        let t = env.manager.status(id).unwrap().unwrap();
        assert_eq!(t.error_code.as_deref(), Some("no_permission"));
    }
}

#[test]
fn remote_changed_mid_download() {
    let total = 512 * 1024usize;
    let body = Arc::new(pattern(total));
    let hits = Arc::new(AtomicU64::new(0));
    let hits2 = hits.clone();
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        let n = hits2.fetch_add(1, Ordering::SeqCst);
        let tag = if n < 2 { "\"v1\"" } else { "\"v2\"" };
        ranged_mem(&server_body, req, true)
            .header("ETag", tag)
            .slow(16 * 1024, Duration::from_millis(4))
    }));
    let env = temp_env_conns("remote_mid", Some(4));
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    let id = env
        .manager
        .add(&server.url("/chg.bin"), None, Some("chg.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(25), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "etag flip mid-download must fail: {:?}",
        env.manager.status(id)
    );
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.error_code.as_deref(), Some("remote_changed"));
}

#[test]
fn crash_restart_recovery_requeues_and_resumes() {
    let total = 128 * 1024usize;
    let body = pattern(total);
    let expect = pattern_sha256(total);
    let env = temp_env("crash_restart");
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(
            &conn,
            "http://127.0.0.1/later.bin",
            "later.bin",
            &save_dir.to_string_lossy(),
            0,
            1,
        )
        .unwrap();
        model::set_status(&conn, id, Status::Downloading, None).unwrap();
        model::init_single_segment(
            &conn,
            id,
            &save_dir.join("later.bin").to_string_lossy(),
            None,
        )
        .unwrap();
        id
    };
    env.manager.recover_on_startup();
    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(view.state, "queued");
    assert_eq!(view.error_code.as_deref(), Some("interrupted"));
    assert_ne!(view.state, "error");

    let server = TestServer::new(Arc::new(move |_req: &Req| Resp::ok(body.clone())));
    {
        let conn = open_db(&db_path).unwrap();
        conn.execute(
            "UPDATE downloads SET url_orig = ?2 WHERE id = ?1",
            rusqlite::params![id, server.url("/later.bin")],
        )
        .unwrap();
    }
    assert!(until(Duration::from_secs(20), || {
        env.manager.tick();
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(
        aidm_core::hash::sha256_file(Path::new(&task.save_path)).unwrap(),
        expect
    );
}

#[test]
fn old_task_json_without_error_code_still_decodes() {
    let raw = r#"{"id":1,"name":"a.bin","state":"error","done":0,"speed":0,"save_path":"/t","error":"http_404"}"#;
    let v: aidm_ipc::TaskView = serde_json::from_str(raw).unwrap();
    assert!(v.error_code.is_none());
    assert!(v.http_status.is_none());
    assert_eq!(v.error.as_deref(), Some("http_404"));
}

#[test]
fn restart_wipes_segments_and_requeues_same_id() {
    // 大文件 + 慢速，保证 restart 时任务仍在跑（cancel 检查点在读循环里）。
    let total = 8 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
            .header("ETag", "\"rst1\"")
            .header("Last-Modified", "Wed, 01 Jan 2020 00:00:00 GMT")
            .slow(4 * 1024, Duration::from_millis(40))
    }));
    let env = temp_env_conns("restart", Some(4));
    let id = env
        .manager
        .add(&server.url("/r.bin"), None, Some("r.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager
            .status(id)
            .unwrap()
            .and_then(|t| t.segments)
            .map(|s| s.len() >= 2 && s.iter().any(|seg| seg.done_bytes > 0))
            .unwrap_or(false)
    }));
    let before = env.manager.status(id).unwrap().unwrap();
    assert!(before.done > 0);
    assert!(
        !leftover_parts(&env.dir, id).is_empty(),
        "expected .aidm/{id}/ part files before restart"
    );
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        let row = model::get_download(&conn, id).unwrap().unwrap();
        assert!(row.etag.is_some(), "probe should have stored ETag");
        assert!(row.size_total.is_some());
    }

    // 暂停默认队列：restart 后任务保持 queued，便于断言分段/元数据被擦除。
    env.manager
        .queue_update(1, None, Some(false), None, None)
        .unwrap();
    env.manager.restart(id).unwrap();
    let after = env.manager.status(id).unwrap().unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.state, "queued");
    assert_eq!(after.done, 0);
    assert!(after.error.is_none());
    assert!(after.error_code.is_none());
    assert!(after.http_status.is_none());
    assert!(after.segments.is_none());
    assert!(leftover_parts(&env.dir, id).is_empty());

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert!(row.etag.is_none());
    assert!(row.last_modified.is_none());
    assert!(row.size_total.is_none());
    assert!(row.error_code.is_none());
    assert!(row.error_message.is_none());
    assert!(row.http_status.is_none());
    assert!(model::list_segments(&conn, id).unwrap().is_empty());
    let kinds = event_kinds(&env.dir.join("db.sqlite"), id);
    assert!(kinds.iter().any(|k| k == "restart"));
    assert_eq!(
        env.manager.restart(id + 99_999).unwrap_err(),
        "task_not_found"
    );
    let _port_tmp = common::tempdir("restart-ipc");
    let port_dir = _port_tmp.path().to_path_buf();
    let db = open_db(&port_dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        port_dir.join("downloads"),
    ));
    let port = server::serve_ephemeral(manager.clone()).expect("listen");
    let added = engine_roundtrip(
        port,
        &EngineRequest::Add {
            url: server.url("/r2.bin"),
            dir: None,
            filename: Some("r2.bin".into()),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            source: None,
            speed_limit_kbps: 0,
            start: Some("queue".into()),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    let rid = added.id.expect("id");
    let rst = engine_roundtrip(
        port,
        &EngineRequest::Restart { id: rid },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(rst.ok, "{rst:?}");
    let st = engine_roundtrip(
        port,
        &EngineRequest::Status { id: rid },
        Duration::from_secs(15),
    )
    .unwrap();
    assert_eq!(st.task.as_ref().map(|t| t.id), Some(rid));
}

#[test]
fn rename_while_downloading_and_queued_keeps_parts() {
    let total = 4 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
            .header("ETag", "\"rn1\"")
            .slow(4 * 1024, Duration::from_millis(40))
    }));
    let env = temp_env_conns("rename_dl", Some(4));

    let running = env
        .manager
        .add(&server.url("/r.bin"), None, Some("r.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(20), || {
            env.manager
                .status(running)
                .unwrap()
                .and_then(|t| t.segments)
                .map(|s| s.len() >= 2 && s.iter().any(|seg| seg.done_bytes > 0))
                .unwrap_or(false)
        }),
        "running task should have part progress"
    );
    let mut parts_before = leftover_parts(&env.dir, running);
    assert!(
        !parts_before.is_empty(),
        "expected .aidm/{}/ parts",
        running
    );
    parts_before.sort();

    let view = env.manager.rename(running, "renamed-running.bin").unwrap();
    assert_eq!(view.name, "renamed-running.bin");
    assert_eq!(
        Path::new(&view.save_path).file_name().unwrap(),
        std::ffi::OsStr::new("renamed-running.bin")
    );
    let mut parts_after = leftover_parts(&env.dir, running);
    parts_after.sort();
    assert_eq!(
        parts_after, parts_before,
        "rename must not move .aidm/<id>/ part files"
    );

    // 停用默认队列，后加的任务保持 queued，便于断言重命名行为。
    env.manager
        .queue_update(1, None, Some(false), None, None)
        .unwrap();
    let queued = env
        .manager
        .add(&server.url("/q.bin"), None, Some("q.bin"), None, 0)
        .unwrap();
    assert_eq!(env.manager.status(queued).unwrap().unwrap().state, "queued");
    assert!(leftover_parts(&env.dir, queued).is_empty());
    let qv = env.manager.rename(queued, "renamed-queued.bin").unwrap();
    assert_eq!(qv.name, "renamed-queued.bin");
    assert_eq!(qv.state, "queued");
    assert!(leftover_parts(&env.dir, queued).is_empty());
    assert_eq!(
        Path::new(&qv.save_path).file_name().unwrap(),
        std::ffi::OsStr::new("renamed-queued.bin")
    );

    assert!(
        until(Duration::from_secs(40), || {
            env.manager.status(running).unwrap().unwrap().state == "done"
        }),
        "renamed running task should finish under new name"
    );
    let done = env.manager.status(running).unwrap().unwrap();
    assert_eq!(done.name, "renamed-running.bin");
    assert!(Path::new(&done.save_path).is_file());
    assert_eq!(std::fs::read(&done.save_path).unwrap(), pattern(total));
    assert!(
        !env.dir.join("downloads").join("r.bin").exists(),
        "final file must use the renamed name"
    );
}

#[test]
fn rename_done_renames_disk_and_rejects_invalid() {
    let body = pattern(64 * 1024);
    let server = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body, req, false)));
    let env = temp_env("rename_done");
    let id = env
        .manager
        .add(&server.url("/a.bin"), None, Some("a.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let old = env.manager.status(id).unwrap().unwrap().save_path;
    assert!(Path::new(&old).is_file());

    let view = env.manager.rename(id, "b.bin").unwrap();
    assert_eq!(view.name, "b.bin");
    assert!(Path::new(&view.save_path).is_file());
    assert!(!Path::new(&old).exists());
    assert_eq!(std::fs::read(&view.save_path).unwrap(), pattern(64 * 1024));

    std::fs::write(env.dir.join("downloads").join("taken.bin"), b"x").unwrap();
    assert_eq!(
        env.manager.rename(id, "taken.bin").unwrap_err(),
        aidm_ipc::ERR_NAME_TAKEN
    );
    assert_eq!(
        env.manager.status(id).unwrap().unwrap().name,
        "b.bin",
        "name_taken must not change DB"
    );

    assert_eq!(
        env.manager.rename(id, "").unwrap_err(),
        aidm_ipc::ERR_INVALID_FILENAME
    );
    assert_eq!(
        env.manager.rename(id, "a/b.bin").unwrap_err(),
        aidm_ipc::ERR_INVALID_FILENAME
    );
    assert_eq!(
        env.manager.rename(id, "a\\b.bin").unwrap_err(),
        aidm_ipc::ERR_INVALID_FILENAME
    );
    assert_eq!(
        env.manager.rename(id, "foo..bar").unwrap_err(),
        aidm_ipc::ERR_INVALID_FILENAME
    );
    assert_eq!(
        env.manager
            .rename(id, &"n".repeat(aidm_ipc::LIMIT_FILENAME + 1))
            .unwrap_err(),
        aidm_ipc::ERR_INVALID_FILENAME
    );
    assert_eq!(
        env.manager.rename(id + 99_999, "x.bin").unwrap_err(),
        "task_not_found"
    );
}

#[test]
fn rename_ipc_roundtrip_and_codes() {
    let body = pattern(32 * 1024);
    let server = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body, req, false)));
    let _tmp = common::tempdir("rename-ipc");
    let dir = _tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("downloads")).unwrap();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(DownloadManager::new(
        Arc::new(Mutex::new(db)),
        dir.join("downloads"),
    ));
    let port = server::serve_ephemeral(manager.clone()).expect("listen");

    let added = engine_roundtrip(
        port,
        &EngineRequest::Add {
            url: server.url("/e.bin"),
            dir: Some(dir.join("downloads").to_string_lossy().into_owned()),
            filename: Some("e.bin".into()),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            source: None,
            speed_limit_kbps: 0,
            start: None,
        },
        Duration::from_secs(15),
    )
    .unwrap();
    let id = added.id.expect("id");
    assert!(until(Duration::from_secs(20), || {
        manager
            .status(id as i64)
            .unwrap()
            .map(|t| t.state == "done")
            .unwrap_or(false)
    }));

    let empty = engine_roundtrip(
        port,
        &EngineRequest::Rename {
            id,
            filename: "".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(!empty.ok);
    assert_eq!(empty.code.as_deref(), Some(aidm_ipc::ERR_INVALID_FILENAME));
    assert!(empty.error.is_none());

    let slash = engine_roundtrip(
        port,
        &EngineRequest::Rename {
            id,
            filename: "a/b.bin".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert_eq!(slash.code.as_deref(), Some(aidm_ipc::ERR_INVALID_FILENAME));

    std::fs::write(dir.join("downloads").join("taken.bin"), b"x").unwrap();
    let taken = engine_roundtrip(
        port,
        &EngineRequest::Rename {
            id,
            filename: "taken.bin".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(!taken.ok);
    assert_eq!(taken.code.as_deref(), Some(aidm_ipc::ERR_NAME_TAKEN));

    let missing = engine_roundtrip(
        port,
        &EngineRequest::Rename {
            id: id + 99_999,
            filename: "x.bin".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(!missing.ok);
    assert_eq!(missing.error.as_deref(), Some("task_not_found"));

    let ok = engine_roundtrip(
        port,
        &EngineRequest::Rename {
            id,
            filename: "final.bin".into(),
        },
        Duration::from_secs(15),
    )
    .unwrap();
    assert!(ok.ok, "{ok:?}");
    let task = ok.task.expect("task");
    assert_eq!(task.name, "final.bin");
    assert!(Path::new(&task.save_path).is_file());
    assert!(!dir.join("downloads").join("e.bin").exists());
    assert_eq!(std::fs::read(&task.save_path).unwrap(), pattern(32 * 1024));
}

// ---------- 设置模块（声明式 schema + 快照 + 热调） ----------

#[test]
fn settings_schema_is_the_single_source_of_truth() {
    let env = temp_env("schema");
    let schema = env.manager.settings_schema();
    let arr = schema.as_array().expect("schema 数组");
    assert!(arr.len() >= 50, "schema 项太少: {}", arr.len());
    let keys: Vec<&str> = arr
        .iter()
        .filter_map(|s| s.get("key").and_then(|k| k.as_str()))
        .collect();
    for expect in [
        "conn.global_conn_cap",
        "conn.speed_limit_default_kbps",
        "sched.window_enabled",
        "sched.quota_mb",
        "sched.after_done",
        "proxy.bypass_hosts",
        "browser.exclude_hosts",
        "browser.auto_catch_exts",
        "browser.hotkey_prevent",
        "paths.category_dirs",
        "ui.sound_complete",
        "ui.duplicate_action",
        "engine.fastdl",
        "verify.sha256_after",
        "net.recv_buf_kb",
    ] {
        assert!(keys.contains(&expect), "schema 缺 {expect}");
    }
    // 每项都要有类型/分组/生效方式，UI 才能通用渲染
    for s in arr {
        assert!(s.get("kind").is_some(), "缺 kind: {s}");
        assert!(s.get("section").is_some(), "缺 section: {s}");
        assert!(s.get("apply").is_some(), "缺 apply: {s}");
        assert!(s.get("label").is_some(), "缺 label: {s}");
    }
    // 每服务器覆盖标记只给允许的键
    let per_host: Vec<&str> = arr
        .iter()
        .filter(|s| s.get("scope").and_then(|v| v.as_str()) == Some("per_host"))
        .filter_map(|s| s.get("key").and_then(|k| k.as_str()))
        .collect();
    assert!(per_host.contains(&"conn.speed_limit_default_kbps"));
    // settings_get 必须覆盖 schema 的全部可写键
    let got = env.manager.settings_get().unwrap();
    for s in arr {
        let k = s.get("key").and_then(|v| v.as_str()).unwrap();
        if s.get("secret").and_then(|v| v.as_bool()) == Some(true) {
            assert!(!got.contains_key(k), "密值不得回传: {k}");
            continue;
        }
        assert!(got.contains_key(k), "settings_get 缺 {k}");
    }
    assert!(got.contains_key("settings.revision"));
    assert!(got.contains_key("app.version"));
}

#[test]
fn per_host_override_beats_global_and_applies_to_new_tasks() {
    let env = temp_env_conns("host_override", Some(4));
    let server = TestServer::new(Arc::new(|_r: &Req| Resp::ok(vec![])));
    let host = server.addr.ip().to_string();

    // 覆盖前：用全局值 4
    let before = env.manager.host_conns_list();
    assert_eq!(before.as_array().unwrap().len(), 0);

    let after = env.manager.host_conns_set(&host, Some(12), None).unwrap();
    assert_eq!(after.as_array().unwrap().len(), 1);
    assert_eq!(after[0]["max_conns"], 12);

    // 新建任务时按主机取值（每服务器例外语义）
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        let effective = aidm_core::hosts::effective_max_conns(&conn, &host, 4, 32);
        assert_eq!(effective, 12, "每服务器覆盖未生效");
    }

    // 列 / 删
    let hosts = env.manager.host_conns_list();
    assert_eq!(hosts.as_array().unwrap()[0]["host"], host);
    let removed = env.manager.host_conns_remove(&host).unwrap();
    assert!(removed.as_array().unwrap().is_empty());
    // 非法输入
    assert!(env
        .manager
        .host_conns_set("bad host", Some(4), None)
        .is_err());
    assert!(env
        .manager
        .host_conns_set("a.com", Some(2000), None)
        .is_err());
}

/// 启动可观测性：走 fastdl 的任务必须留下"第一个字节什么时候到"。
///
/// `start` 事件到真正有数据之间，数据库里原本是空白的 —— 用户报
/// "start 之后还有 10 秒极低速率"时，没有任何数据能说明那段时间花在哪，
/// 只能靠猜。这条用例把那段变成可观测的，同时钉住连接预热不破坏功能
/// （`warm_left` 可以是 0：worker 自己建也合法，预热只是帮忙）。
#[test]
fn fastdl_records_when_the_first_byte_arrives() {
    // 必须大于 fastdl 门槛（16 MiB）才会走可热调的内核
    let total = 20 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env_conns("first_byte", Some(4));
    let id = env
        .manager
        .add(&server.url("/fb.bin"), None, Some("fb.bin"), None, 0)
        .unwrap();
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(90)),
        "下载未完成: {:?}",
        env.manager.status(id)
    );
    let details = event_details(&env.dir.join("db.sqlite"), id, "first_byte");
    assert_eq!(details.len(), 1, "第一个字节只该记一次: {details:?}");
    assert!(details[0].starts_with("ms="), "要带上耗时: {details:?}");
    assert!(
        details[0].contains("warm_left="),
        "要带上预热连接余量: {details:?}"
    );
    let got = std::fs::read(env.dir.join("downloads").join("fb.bin")).unwrap();
    assert_eq!(got.len(), total, "预热的连接必须能正常下完");
    let reqs = server.requests.lock().unwrap();
    assert!(
        reqs.iter().all(|r| r.referer.is_none()),
        "fastdl 也不应发送同源兜底 Referer（会触发 CDN 防盗链）：{:?}",
        reqs.iter().map(|r| &r.referer).collect::<Vec<_>>()
    );
}

/// 段内换连接（R-DL-14 的连接级动作）：一条被限速的连接必须被**放弃**，
/// 它那一块的剩余区间交给一条新连接续下。
///
/// fastdl 里没有"来源"这个概念（对着一个 URL 开 N 条连接），所以单源场景下能做的
/// 正是这件事 —— 基准里那条退化曲线就是"某条连接慢、整块被它拖着"。判据与 worker
/// 段循环共用同一个内核（`aidm_core::pace`），参照物是**已完成部分平均速率 ÷ 3**
/// （见 `SLOW_REF_DIVISOR`：严格按"低于平均"会把接近一半的连接判慢，反而更糟）。
///
/// 两组对照：
/// 1. 第一条真正的块连接被限到 40 KiB/s、其余 3.2 MiB/s ⇒ 它必须被放弃（`code=slow_conn`），
///    且整份文件仍然逐字节正确（换的是连接，不是内容）；
/// 2. 所有连接一样快 ⇒ **一次都不许放弃**（别把正常的快慢差异当成"慢"）。
#[test]
fn a_slow_fastdl_connection_is_dropped_and_its_remainder_moves_to_a_new_one() {
    /// 跑一遍，返回（`segment_retry` 事件、文件内容、是否 done）。
    #[allow(clippy::type_complexity)]
    fn run(tag: &str, slow_first: bool) -> (Vec<(String, Option<String>)>, Vec<u8>, bool) {
        let total = 20 * 1024 * 1024usize; // > 16 MiB 才走 fastdl 内核
        let body = Arc::new(pattern(total));
        let b = body.clone();
        let server = TestServer::new(Arc::new(move |req: &Req| {
            let range = req.headers.get("range").cloned().unwrap_or_default();
            // 只把**从 0 开始的那一块**限到 40 KiB/s（`bytes=0-0` 是探测，不算）：
            // 于是"慢"恒等于块 0 的属主连接，与并发到达顺序无关。
            let slow_this = slow_first && range.starts_with("bytes=0-") && range != "bytes=0-0";
            if slow_this {
                // 极慢：4 KiB / 100 ms ≈ 40 KiB/s，一个 5 MiB 的块要两分钟
                return ranged_mem(&b, req, true).slow(4 * 1024, Duration::from_millis(100));
            }
            // 其余连接 3.2 MiB/s：整个任务因此会跨过 1 秒的判定窗口
            ranged_mem(&b, req, true).slow(64 * 1024, Duration::from_millis(20))
        }));
        let env = temp_env_conns(tag, Some(4));
        env.manager.settings_set("proxy.mode", "none").unwrap();
        env.manager
            .settings_set("alt.measure_window_s", "1")
            .unwrap();
        let db = env.dir.join("db.sqlite");
        let id = env
            .manager
            .add(&server.url("/slow.bin"), None, Some("slow.bin"), None, 0)
            .unwrap();
        let done = wait_state(&env.manager, id, "done", Duration::from_secs(120));
        let row = model::get_download(&open_db(&db).unwrap(), id)
            .unwrap()
            .unwrap();
        let file = env.dir.join("downloads").join(&row.file_name);
        let data = std::fs::read(&file).unwrap_or_default();
        (all_events(&db, id), data, done)
    }

    let total = 20 * 1024 * 1024usize;
    let expect = pattern_sha256(total);

    let (events, data, done) = run("slow_conn_drop", true);
    assert!(done, "放弃慢连接之后应当能下完；events={events:?}");
    assert_eq!(data.len(), total, "长度必须完整");
    assert_eq!(
        sha256_reader(std::io::Cursor::new(data)).unwrap(),
        expect,
        "换连接只换剩余部分从哪里续：内容必须逐字节一致",
    );
    assert!(
        events.iter().any(|(k, d)| k == "segment_retry"
            && d.as_deref().is_some_and(|v| v.contains("code=slow_conn"))),
        "被限速的连接必须被放弃并留痕: {events:?}"
    );

    let (events2, data2, done2) = run("slow_conn_keep", false);
    assert!(done2, "对照任务应当能下完");
    assert_eq!(data2.len(), total);
    assert!(
        !events2.iter().any(|(k, d)| k == "segment_retry"
            && d.as_deref().is_some_and(|v| v.contains("code=slow_conn"))),
        "没有慢连接时一次都不许放弃: {events2:?}"
    );
}

#[test]
fn sending_limit_change_hot_retunes_without_restart() {
    // 必须大于 fastdl 门槛（16 MiB）才会走可热调的内核
    let total = 20 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true).slow(32 * 1024, Duration::from_millis(4))
    }));
    let env = temp_env_conns("hot_retune", Some(4));
    let id = env
        .manager
        .add(&server.url("/h.bin"), None, Some("h.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(60), || {
            env.manager
                .status(id)
                .unwrap()
                .map(|t| t.done > 512 * 1024)
                .unwrap_or(false)
        }),
        "下载未起步"
    );
    let before = env.manager.status(id).unwrap().unwrap();
    assert_eq!(before.state, "downloading", "应在下载中");

    // 改连接上限：应热调，不该打回队列 / 暂停 / 丢进度
    env.manager
        .settings_set("conn.global_conn_cap", "16")
        .unwrap();
    let mid = env.manager.status(id).unwrap().unwrap();
    assert_eq!(mid.state, "downloading", "热调后必须仍在下载");
    assert!(
        mid.done >= before.done,
        "热调不该丢进度: before={} mid={}",
        before.done,
        mid.done
    );
    let kinds = event_kinds(&env.dir.join("db.sqlite"), id as i64);
    assert!(
        kinds.contains(&"retune".to_string()),
        "应记录 retune 事件: {kinds:?}"
    );
    assert!(
        !kinds.contains(&"resegmented".to_string()),
        "不该走重排分段路径: {kinds:?}"
    );

    assert!(until(Duration::from_secs(90), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.done, total as u64);
    assert_eq!(std::fs::read(&task.save_path).unwrap(), pattern(total));
}
#[test]
fn scheduler_window_blocks_dispatch_then_reopens() {
    let total = 512 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("window");

    // 窗口关闭：把允许时段设成"永远不覆盖当前分钟"的窄窗
    env.manager
        .settings_set("sched.window_enabled", "true")
        .unwrap();
    let (iso, minute) = aidm_core::cron::local_weekday_minute(aidm_core::model::now_secs());
    // 选一个不含当前分钟且长度 1 分钟的窗口
    let blocked = (minute + 2) % 1440;
    env.manager
        .settings_set(
            "sched.window_start",
            &format!("{:02}:{:02}", blocked / 60, blocked % 60),
        )
        .unwrap();
    env.manager
        .settings_set(
            "sched.window_end",
            &format!("{:02}:{:02}", blocked / 60, blocked % 60),
        )
        .unwrap();
    // 星期一定包含今天才可能"开着"；这里显式排除今天以外的都可能，所以直接断言窗口判定
    let snap = env.manager.settings_snapshot();
    let _ = iso;
    assert!(!env.manager.window_open(&snap), "当前分钟不在窗口内");

    let id = env
        .manager
        .add(&server.url("/w.bin"), None, Some("w.bin"), None, 0)
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    env.manager.tick();
    let t = env.manager.status(id).unwrap().unwrap();
    assert_eq!(t.state, "queued", "时段外不得派发");

    // 打开全天窗口 → 立刻可跑
    env.manager
        .settings_set("sched.window_start", "00:00")
        .unwrap();
    env.manager
        .settings_set("sched.window_end", "23:59")
        .unwrap();
    env.manager
        .settings_set("sched.window_days", "1,2,3,4,5,6,7")
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
}

#[test]
fn category_dir_and_duplicate_policy() {
    let total = 128 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("category");
    let cat = env.dir.join("iso-category");
    env.manager
        .settings_set(
            "paths.category_dirs",
            &format!(
                r#"{{"iso":"{}"}}"#,
                cat.to_string_lossy().replace('\\', "\\\\")
            ),
        )
        .unwrap();

    let id = env
        .manager
        .add(&server.url("/disc.iso"), None, Some("disc.iso"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(20), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let task = env.manager.status(id).unwrap().unwrap();
    assert!(
        task.save_path
            .starts_with(&cat.to_string_lossy().to_string()),
        "分类目录未生效: {}",
        task.save_path
    );

    // 重复链接：造一个未完成的同 URL 任务，再按策略拒绝/回报
    let queued = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/disc.iso"),
            dir: None,
            filename: Some("queued.iso"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: None,
            start: Some("queue"),
        })
        .unwrap();
    env.manager
        .settings_set("ui.duplicate_action", "skip")
        .unwrap();
    let e = env
        .manager
        .add(&server.url("/disc.iso"), None, Some("disc2.iso"), None, 0)
        .unwrap_err();
    assert!(e.starts_with("duplicate_skipped:"), "得到 {e}");
    env.manager
        .settings_set("ui.duplicate_action", "ask")
        .unwrap();
    let e = env
        .manager
        .add(&server.url("/disc.iso"), None, Some("disc3.iso"), None, 0)
        .unwrap_err();
    assert!(
        e.starts_with("duplicate_url:") && e.ends_with(&queued.to_string()),
        "得到 {e}"
    );
}

#[test]
fn settings_revision_and_changed_event() {
    let env = temp_env("revision");
    let before = env
        .manager
        .settings_get()
        .unwrap()
        .get("settings.revision")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    let sub = env.manager.events().subscribe();
    env.manager
        .settings_set("speed.global_limit_kbps", "512")
        .unwrap();
    let after = env
        .manager
        .settings_get()
        .unwrap()
        .get("settings.revision")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();
    assert_ne!(before, after, "写入后 revision 必须变化");
    let ev = sub.try_recv().expect("应收到 settings_changed");
    match ev {
        aidm_ipc::EngineEvent::SettingsChanged { key, revision } => {
            assert_eq!(key, "speed.global_limit_kbps");
            assert_eq!(revision.to_string(), after);
        }
        other => panic!("事件类型不对: {other:?}"),
    }
    // 未声明的键仍然被拒绝（不再有静默放行）
    let e = env.manager.settings_set("nope.key", "1").unwrap_err();
    assert_eq!(e.code, "unknown_setting_key");
}
// ---------- 设置项行为验证：配额 / 完成后动作 / 引擎侧排除表 ----------

/// 流量配额：到达上限要暂停任务并广播 `quota` 事件，且只触发一次。
#[test]
fn quota_limit_pauses_tasks_and_emits_once() {
    let total = 4 * 1024 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true).slow(64 * 1024, Duration::from_millis(6))
    }));
    let env = temp_env("quota");
    let sub = env.manager.events().subscribe();
    // 1 MB / 每小时：很快到达
    env.manager
        .settings_set("sched.quota_enabled", "true")
        .unwrap();
    env.manager.settings_set("sched.quota_mb", "1").unwrap();
    env.manager
        .settings_set("sched.quota_period", "hour")
        .unwrap();
    env.manager
        .settings_set("sched.quota_action", "pause")
        .unwrap();

    // 第一个任务跑完，配额统计随之建立基线
    let id = env
        .manager
        .add(&server.url("/q.bin"), None, Some("q.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(40), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    // 手动驱动调度：第二拍起开始累计增量（首拍只建立基线）
    let mut saw_quota = None;
    for _ in 0..40 {
        env.manager.tick();
        while let Ok(ev) = sub.try_recv() {
            if let aidm_ipc::EngineEvent::Quota {
                used_bytes,
                limit_bytes,
                period,
                action,
            } = ev
            {
                saw_quota = Some((used_bytes, limit_bytes, period, action));
            }
        }
        if saw_quota.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (used, limit, period, action) = saw_quota.expect("应广播 quota 事件");
    assert!(used >= 1024 * 1024, "已用字节应达到上限: {used}");
    assert_eq!(limit, 1024 * 1024);
    assert_eq!(period, "hour");
    assert_eq!(action, "pause");

    // 关键行为：配额用尽后，**新任务不得被派发**（留在队列里等下一个周期）
    let blocked = env
        .manager
        .add(&server.url("/q2.bin"), None, Some("q2.bin"), None, 0)
        .unwrap();
    for _ in 0..6 {
        env.manager.tick();
        std::thread::sleep(Duration::from_millis(30));
    }
    let st = env.manager.status(blocked).unwrap().unwrap();
    assert_eq!(st.state, "queued", "配额用尽后不应再派发: {}", st.state);
    assert_eq!(st.done, 0);
    // 再拍几拍不应重复广播
    let mut extra = 0;
    for _ in 0..5 {
        env.manager.tick();
        while let Ok(ev) = sub.try_recv() {
            if matches!(ev, aidm_ipc::EngineEvent::Quota { .. }) {
                extra += 1;
            }
        }
    }
    assert_eq!(extra, 0, "quota 事件不应重复广播");
}

/// 完成后动作：队列跑空后广播一次 `after_done`，并且只广播一次。
#[test]
fn after_done_fires_once_when_queue_drains() {
    let total = 64 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("after_done");
    let sub = env.manager.events().subscribe();
    env.manager
        .settings_set("sched.after_done", "exit")
        .unwrap();
    env.manager
        .settings_set("sched.after_done_force", "true")
        .unwrap();

    let id = env
        .manager
        .add(&server.url("/a.bin"), None, Some("a.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));

    let mut fired = Vec::new();
    for _ in 0..6 {
        env.manager.tick();
        while let Ok(ev) = sub.try_recv() {
            if let aidm_ipc::EngineEvent::AfterDone { action, force } = ev {
                fired.push((action, force));
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(fired.len(), 1, "after_done 只应广播一次: {fired:?}");
    assert_eq!(fired[0], ("exit".to_string(), true));

    // 没有任务时也不该再触发
    env.manager.tick();
    let mut again = 0;
    while let Ok(ev) = sub.try_recv() {
        if matches!(ev, aidm_ipc::EngineEvent::AfterDone { .. }) {
            again += 1;
        }
    }
    assert_eq!(again, 0);
}

/// 引擎侧强制排除表：扩展来源命中 `browser.exclude_hosts` 必须被拒。
#[test]
fn excluded_host_is_refused_for_extension_source() {
    let env = temp_env("exclude_host");
    let server = TestServer::new(Arc::new(|_r: &Req| Resp::ok(vec![])));
    let host = server.addr.ip().to_string();
    env.manager
        .settings_set("browser.exclude_hosts", &host)
        .unwrap();
    // 扩展来源 → 拒绝
    let e = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/x.bin"),
            dir: None,
            filename: Some("x.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("ext"),
            start: Some("queue"),
        })
        .unwrap_err();
    assert_eq!(e, "host_excluded");
    // 手工来源 → 不受排除表限制
    let ok = env.manager.add_spec(aidm_engine::AddSpec {
        url: &server.url("/x.bin"),
        dir: None,
        filename: Some("x2.bin"),
        referrer: None,
        cookies: None,
        user_agent: None,
        custom_headers: None,
        alt_urls: None,
        offer_id: None,
        speed_limit_kbps: 0,
        source: Some("manual"),
        start: Some("queue"),
    });
    assert!(ok.is_ok(), "手工添加不应被排除表拦住: {ok:?}");
}
/// 每任务自定义请求头：能真正发到服务器；非法头在新建时就被拒。
#[test]
fn custom_headers_reach_the_server_and_invalid_are_rejected() {
    let total = 32 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("custom_headers");

    // 1) 正常头：应原样出现在请求里
    let id = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/h.bin"),
            dir: None,
            filename: Some("h.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: Some("X-Api-Key: secret123\nSec-Fetch-Site: cross-site"),
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let reqs = server.requests.lock().unwrap();
    assert!(!reqs.is_empty());
    for r in reqs.iter() {
        assert_eq!(
            r.all_headers.get("x-api-key").map(String::as_str),
            Some("secret123"),
            "自定义头应被发出"
        );
        assert_eq!(
            r.all_headers.get("sec-fetch-site").map(String::as_str),
            Some("cross-site")
        );
    }
    drop(reqs);

    // 2) 试图覆盖受管头：新建即被拒（不会发出畸形请求）
    let err = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/bad.bin"),
            dir: None,
            filename: Some("bad.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: Some("Range: bytes=0-1"),
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap_err();
    assert!(err.starts_with("header_managed"), "实际错误: {err}");

    // 3) 控制字符（头注入）：同样被拒
    let err2 = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/bad2.bin"),
            dir: None,
            filename: Some("bad2.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: Some("X-A: 1\u{1}"),
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap_err();
    assert!(err2.starts_with("header_control_char"), "实际错误: {err2}");
}
/// 自定义请求头必须落库：引擎重启后（pending 已清空）再派发仍要带上它，
/// 否则防盗链站点会在恢复后立刻失败。
#[test]
fn custom_headers_survive_engine_restart() {
    let total = 64 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("ch_restart");
    let db_path = env.dir.join("db.sqlite");

    // 用 cron 把任务钉在队列里：cron 有值且不在触发点 → 不派发
    env.manager
        .settings_set("sched.start_cron", "0 3 * * *")
        .unwrap();
    let id = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/r.bin"),
            dir: None,
            filename: Some("r.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: Some("X-Api-Key: k1"),
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: Some("queue"),
        })
        .unwrap();
    env.manager.tick();
    assert_eq!(server.requests.lock().unwrap().len(), 0, "排队中不应发请求");
    {
        let conn = aidm_core::open_db(&db_path).unwrap();
        let row = model::get_download(&conn, id).unwrap().unwrap();
        assert_eq!(
            row.custom_headers.as_deref(),
            Some("X-Api-Key: k1"),
            "自定义头应已落库"
        );
    }

    // 模拟引擎重启：同一份库上新建管理器（pending 为空）
    let db2 = aidm_core::open_db(&db_path).unwrap();
    let manager2 = DownloadManager::new(Arc::new(Mutex::new(db2)), env.dir.join("downloads"));
    manager2.recover_on_startup();
    // 放行队列（关掉 cron），驱动调度
    manager2.settings_set("sched.start_cron", "").unwrap();
    assert!(until(Duration::from_secs(30), || {
        manager2.tick();
        manager2
            .status(id)
            .unwrap()
            .map(|t| t.state == "done")
            .unwrap_or(false)
    }));

    let reqs = server.requests.lock().unwrap();
    assert!(!reqs.is_empty(), "重启后应真正发起请求");
    assert!(
        reqs.iter()
            .all(|r| r.all_headers.get("x-api-key").map(String::as_str) == Some("k1")),
        "重启后（pending 已空）的请求仍应带自定义头；实际: {:?}",
        reqs.iter().map(|r| &r.all_headers).collect::<Vec<_>>()
    );
}
/// 站点凭据 + 401 自动重试：无凭据时失败，有凭据时带 Basic 重试一次并成功；
/// 凭据不得出现在事件表里。
#[test]
fn site_login_basic_auth_retries_once() {
    let total = 32 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let want = aidm_core::logins::basic_authorization("alice", "s3cret");
    let want_for_handler = want.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        let got = req.headers.get("authorization").cloned();
        if got.as_deref() == Some(want_for_handler.as_str()) {
            ranged_mem(&server_body, req, true)
        } else {
            Resp::empty(401).header("WWW-Authenticate", "Basic realm=\"aidm-test\"")
        }
    }));
    let env = temp_env("site_login");

    // 1) 没存凭据：应失败在 http_401
    let id1 = env
        .manager
        .add(&server.url("/a.bin"), None, Some("a.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        let st = env.manager.status(id1).unwrap().unwrap();
        st.state == "error"
    }));
    let st1 = env.manager.status(id1).unwrap().unwrap();
    assert_eq!(st1.error_code.as_deref(), Some("http_401"));

    // 2) 存了凭据：应自动重试一次并成功
    env.manager
        .site_logins_set("127.0.0.1", "alice", "s3cret")
        .unwrap();
    let id2 = env
        .manager
        .add(&server.url("/b.bin"), None, Some("b.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id2).unwrap().unwrap().state == "done"
        }),
        "带凭据后应下载成功：{:?}",
        env.manager.status(id2).unwrap()
    );

    // 3) 凭据不能泄漏进事件/属性
    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let mut stmt = conn
        .prepare("SELECT COALESCE(detail,'') FROM events")
        .unwrap();
    let details: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    for d in &details {
        assert!(!d.contains("s3cret"), "事件泄漏了密码: {d}");
        assert!(!d.contains(&want), "事件泄漏了 Authorization: {d}");
    }
}

/// 服务端校验 Digest 应答：独立用 MD5 重算，不调用被测模块。
fn digest_ok(auth: &str, path: &str, realm: &str, nonce: &str, user: &str, pass: &str) -> bool {
    let Some(rest) = auth.strip_prefix("Digest ") else {
        return false;
    };
    let params: HashMap<&str, &str> = rest
        .split(", ")
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k, v.trim_matches('"')))
        .collect();
    let p = |k: &str| params.get(k).copied().unwrap_or("");
    if p("username") != user || p("realm") != realm || p("nonce") != nonce || p("uri") != path {
        return false;
    }
    if p("qop") != "auth" || p("algorithm") != "MD5" || p("opaque") != "op4que" {
        return false;
    }
    let ha1 = format!("{:x}", md5::compute(format!("{user}:{realm}:{pass}")));
    let ha2 = format!("{:x}", md5::compute(format!("GET:{path}")));
    let want = format!(
        "{:x}",
        md5::compute(format!(
            "{ha1}:{nonce}:{}:{}:auth:{ha2}",
            p("nc"),
            p("cnonce")
        ))
    );
    p("response") == want
}

/// Digest 挑战：存了凭据后按 RFC 7616 应答（同时提供 Basic 时也必须选 Digest），
/// 分段请求全部通过校验；应答与口令不进事件表。
#[test]
fn site_login_digest_auth_retries_once() {
    let total = 64 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let seen_basic = Arc::new(AtomicBool::new(false));
    let seen_basic_srv = seen_basic.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        let got = req
            .headers
            .get("authorization")
            .cloned()
            .unwrap_or_default();
        if got.starts_with("Basic ") {
            seen_basic_srv.store(true, Ordering::SeqCst);
        }
        if digest_ok(&got, &req.path, "aidm-digest", "n0nce", "bob", "pa55") {
            ranged_mem(&server_body, req, true)
        } else {
            Resp::empty(401)
                .header(
                    "WWW-Authenticate",
                    "Digest realm=\"aidm-digest\", qop=\"auth,auth-int\", algorithm=MD5, nonce=\"n0nce\", opaque=\"op4que\"",
                )
                .header("WWW-Authenticate", "Basic realm=\"aidm-digest\"")
        }
    }));
    let env = temp_env("site_login_digest");
    env.manager
        .site_logins_set("127.0.0.1", "bob", "pa55")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/d.bin?k=1"), None, Some("d.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "Digest 凭据应下载成功：{:?}",
        env.manager.status(id).unwrap()
    );
    let st = env.manager.status(id).unwrap().unwrap();
    assert_eq!(std::fs::read(&st.save_path).unwrap(), *body);
    assert!(
        !seen_basic.load(Ordering::SeqCst),
        "提供 Digest 时不应发 Basic"
    );

    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let mut stmt = conn
        .prepare("SELECT kind, COALESCE(detail,'') FROM events")
        .unwrap();
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(rows
        .iter()
        .any(|(k, d)| k == "auth_challenge" && d == "scheme=digest"));
    for (_, d) in &rows {
        assert!(
            !d.contains("pa55") && !d.contains("response="),
            "事件泄漏了凭据: {d}"
        );
    }
}

/// 服务端只接受未知方案时，即使存了凭据也不发明文 Basic，停在 http_401。
#[test]
fn site_login_unsupported_challenge_never_sends_basic() {
    let seen_auth = Arc::new(AtomicBool::new(false));
    let seen = seen_auth.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.headers.contains_key("authorization") {
            seen.store(true, Ordering::SeqCst);
        }
        Resp::empty(401).header("WWW-Authenticate", "Negotiate")
    }));
    let env = temp_env("site_login_negotiate");
    env.manager
        .site_logins_set("127.0.0.1", "bob", "pa55")
        .unwrap();
    let id = env
        .manager
        .add(&server.url("/n.bin"), None, Some("n.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "error"
    }));
    let st = env.manager.status(id).unwrap().unwrap();
    assert_eq!(st.error_code.as_deref(), Some("http_401"));
    assert!(
        !seen_auth.load(Ordering::SeqCst),
        "不支持的挑战不应带任何凭据"
    );
}

/// 站点凭据列表不回传密码。
#[test]
fn site_logins_list_hides_password() {
    let env = temp_env("site_login_list");
    env.manager
        .site_logins_set("Example.com:443", "bob", "pw!")
        .unwrap();
    let list = env.manager.site_logins_list().unwrap();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["host"], "example.com");
    assert_eq!(arr[0]["username"], "bob");
    assert_eq!(arr[0]["has_password"], true);
    assert!(arr[0].get("password").is_none(), "列表不应含密码字段");
    // 删除
    assert!(env.manager.site_logins_remove("example.com").unwrap());
    assert!(env
        .manager
        .site_logins_list()
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
}

// 追加到 integration.rs 的 FTP 测试段。
// 最小 FTP 服务器：只为验证客户端行为（命令序列、REST 续传、SIZE 回退、登录）。

/// 最小 FTP 服务器。
struct FtpServer {
    addr: SocketAddr,
    commands: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FtpServer {
    fn start(body: Vec<u8>, opts: FtpOpts) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ftp");
        let addr = listener.local_addr().unwrap();
        let commands = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let body = Arc::new(body);
        let cmds = commands.clone();
        let st = stop.clone();
        let handle = std::thread::spawn(move || {
            listener.set_nonblocking(false).ok();
            for stream in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let body = body.clone();
                let cmds = cmds.clone();
                let opts = opts.clone();
                std::thread::spawn(move || serve_ftp_conn(stream, body, cmds, opts));
            }
        });
        FtpServer {
            addr,
            commands,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("ftp://127.0.0.1:{}{path}", self.addr.port())
    }

    fn saw_command(&self, prefix: &str) -> Option<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.starts_with(prefix))
            .cloned()
    }
}

impl Drop for FtpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[derive(Clone)]
struct FtpOpts {
    /// 支持 `SIZE`（不支持时用 RETR 回复兜底）
    size_supported: bool,
    /// 支持 `REST`（续传）
    rest_supported: bool,
    /// 要求的账号（None = 任意）
    require_login: Option<(String, String)>,
    /// 数据分片与延迟（给"下到一半暂停"留窗口）
    chunk: usize,
    chunk_delay: Duration,
}

impl Default for FtpOpts {
    fn default() -> Self {
        Self {
            size_supported: true,
            rest_supported: true,
            require_login: None,
            chunk: 64 * 1024,
            chunk_delay: Duration::ZERO,
        }
    }
}

fn ftp_reply(stream: &mut TcpStream, line: &str) {
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\r\n");
    let _ = stream.flush();
}

fn serve_ftp_conn(
    mut stream: TcpStream,
    body: Arc<Vec<u8>>,
    commands: Arc<Mutex<Vec<String>>>,
    opts: FtpOpts,
) {
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    ftp_reply(&mut stream, "220 aidm-test ftp ready");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut data_listener: Option<TcpListener> = None;
    let mut offset = 0usize;
    let mut authed = false;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }
        let cmd = line.trim_end_matches(['\r', '\n']).to_string();
        if cmd.is_empty() {
            continue;
        }
        commands.lock().unwrap().push(cmd.clone());
        let (verb, arg) = match cmd.split_once(' ') {
            Some((v, a)) => (v.to_ascii_uppercase(), a.to_string()),
            None => (cmd.to_ascii_uppercase(), String::new()),
        };
        match verb.as_str() {
            "USER" => {
                if let Some((u, _)) = &opts.require_login {
                    if &arg == u {
                        ftp_reply(&mut stream, "331 need password");
                    } else {
                        ftp_reply(&mut stream, "331 need password");
                    }
                } else {
                    ftp_reply(&mut stream, "331 need password");
                }
            }
            "PASS" => {
                let ok = match &opts.require_login {
                    Some((_, p)) => &arg == p,
                    None => true,
                };
                if ok {
                    authed = true;
                    ftp_reply(&mut stream, "230 logged in");
                } else {
                    ftp_reply(&mut stream, "530 login incorrect");
                }
            }
            "TYPE" => ftp_reply(&mut stream, "200 type set"),
            "CWD" => ftp_reply(&mut stream, "250 directory changed"),
            "MDTM" => ftp_reply(&mut stream, "213 20240102030405"),
            "SIZE" => {
                if opts.size_supported {
                    ftp_reply(&mut stream, &format!("213 {}", body.len()));
                } else {
                    ftp_reply(&mut stream, "502 SIZE not implemented");
                }
            }
            "REST" => {
                if opts.rest_supported {
                    offset = arg.trim().parse::<usize>().unwrap_or(0);
                    ftp_reply(&mut stream, &format!("350 restarting at {offset}"));
                } else {
                    offset = 0;
                    ftp_reply(&mut stream, "502 REST not implemented");
                }
            }
            "PASV" => {
                let l = TcpListener::bind("127.0.0.1:0").expect("bind data");
                let p = l.local_addr().unwrap().port();
                data_listener = Some(l);
                ftp_reply(
                    &mut stream,
                    &format!(
                        "227 Entering Passive Mode (127,0,0,1,{},{}).",
                        p / 256,
                        p % 256
                    ),
                );
            }
            "RETR" => {
                if !authed {
                    ftp_reply(&mut stream, "530 not logged in");
                    continue;
                }
                let Some(l) = data_listener.take() else {
                    ftp_reply(&mut stream, "425 use PASV first");
                    continue;
                };
                ftp_reply(
                    &mut stream,
                    &format!(
                        "150 Opening BINARY mode data connection for {} ({} bytes)",
                        arg,
                        body.len()
                    ),
                );
                match l.accept() {
                    Ok((mut data, _)) => {
                        let mut pos = offset.min(body.len());
                        while pos < body.len() {
                            let end = (pos + opts.chunk).min(body.len());
                            if data.write_all(&body[pos..end]).is_err() {
                                break;
                            }
                            pos = end;
                            if !opts.chunk_delay.is_zero() {
                                std::thread::sleep(opts.chunk_delay);
                            }
                        }
                        let _ = data.flush();
                        drop(data);
                        ftp_reply(&mut stream, "226 transfer complete");
                    }
                    Err(_) => ftp_reply(&mut stream, "425 cannot open data connection"),
                }
            }
            "ABOR" => ftp_reply(&mut stream, "226 abort ok"),
            "QUIT" => {
                ftp_reply(&mut stream, "221 bye");
                return;
            }
            _ => ftp_reply(&mut stream, "502 command not implemented"),
        }
    }
}

// FTP 端到端测试（追加到 integration.rs）。
// 依赖前面的 FtpServer / FtpOpts 定义。

/// FTP：完整下载（登录 → TYPE I → SIZE → PASV → RETR），并校验内容。
#[test]
fn ftp_download_completes_and_matches_content() {
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let expect = body.clone();
    let server = FtpServer::start(body, FtpOpts::default());
    let env = temp_env("ftp_basic");

    let id = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/pub/file.bin"),
            dir: None,
            filename: Some("file.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "FTP 任务应完成：{:?}",
        env.manager.status(id)
    );

    // 命令序列要符合 FTP 规则
    assert!(server.saw_command("USER ").is_some(), "应发 USER");
    assert!(server.saw_command("PASS ").is_some(), "应发 PASS");
    assert!(server.saw_command("TYPE I").is_some(), "应设为二进制模式");
    assert!(server.saw_command("SIZE ").is_some(), "应先取 SIZE");
    assert!(server.saw_command("PASV").is_some(), "应进被动模式");
    assert!(server.saw_command("RETR ").is_some(), "应发 RETR");

    // 内容逐字节一致
    let path = env.dir.join("downloads").join("file.bin");
    let got = std::fs::read(&path).expect("FTP 文件应存在");
    assert_eq!(got.len(), expect.len(), "长度应一致");
    assert_eq!(got, expect, "内容应逐字节一致");

    // 总长与 MDTM 应落库
    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.size_total, Some(expect.len() as i64));
    assert_eq!(row.last_modified.as_deref(), Some("20240102030405"));
}

/// FTP：SIZE 不支持时，从 RETR 的 150 回复里取总长。
#[test]
fn ftp_falls_back_to_retr_reply_for_size() {
    let body: Vec<u8> = (0..120_000u32).map(|i| (i % 97) as u8).collect();
    let expect = body.clone();
    let server = FtpServer::start(
        body,
        FtpOpts {
            size_supported: false,
            ..Default::default()
        },
    );
    let env = temp_env("ftp_size_fallback");
    let id = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/f.bin"),
            dir: None,
            filename: Some("f.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.size_total,
        Some(expect.len() as i64),
        "总长应来自 RETR 回复"
    );
    assert_eq!(
        std::fs::read(env.dir.join("downloads").join("f.bin")).unwrap(),
        expect
    );
}

/// FTP：URL 里没写账号时，用站点凭据登录；没凭据时以 ftp_login_530 失败。
#[test]
fn ftp_uses_site_credentials_for_login() {
    let body: Vec<u8> = (0..40_000u32).map(|i| (i % 13) as u8).collect();
    let server = FtpServer::start(
        body,
        FtpOpts {
            require_login: Some(("alice".into(), "s3cret".into())),
            ..Default::default()
        },
    );
    let env = temp_env("ftp_login");

    // 1) 没有凭据 → 匿名登录被拒
    let id1 = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/a.bin"),
            dir: None,
            filename: Some("a.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        let st = env.manager.status(id1).unwrap().unwrap();
        st.state == "error"
    }));
    let st1 = env.manager.status(id1).unwrap().unwrap();
    assert_eq!(
        st1.error_code.as_deref(),
        Some("ftp_login_530"),
        "实际任务视图: {st1:?}"
    );

    // 2) 存了凭据 → 自动使用
    env.manager
        .site_logins_set("127.0.0.1", "alice", "s3cret")
        .unwrap();
    let id2 = env
        .manager
        .add_spec(aidm_engine::AddSpec {
            url: &server.url("/b.bin"),
            dir: None,
            filename: Some("b.bin"),
            referrer: None,
            cookies: None,
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: Some("manual"),
            start: None,
        })
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id2).unwrap().unwrap().state == "done"
        }),
        "带站点凭据应登录成功：{:?}",
        env.manager.status(id2)
    );
    assert!(
        server
            .commands
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "USER alice"),
        "应以站点凭据里的用户名登录"
    );
}

/// FTP：已有部分文件时用 REST 续传，且内容仍然正确。
#[test]
fn ftp_resumes_with_rest() {
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 199) as u8).collect();
    let expect = body.clone();
    let server = FtpServer::start(body, FtpOpts::default());
    let env = temp_env("ftp_resume");
    let dir = env.dir.join("downloads");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("part.bin");
    // 预置前 100_000 字节（模拟上次下到一半）
    let head = 100_000usize;
    std::fs::write(&path, &expect[..head]).unwrap();

    // 建行 + 单段，让派发时判定为"续传"
    let id = {
        let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
        let id = model::insert_download(
            &conn,
            &server.url("/part.bin"),
            "part.bin",
            &dir.to_string_lossy(),
            expect.len() as i64,
            1,
        )
        .unwrap();
        model::set_status(&conn, id, Status::Queued, None).unwrap();
        model::init_single_segment(
            &conn,
            id,
            &path.to_string_lossy(),
            Some(expect.len() as i64 - 1),
        )
        .unwrap();
        id
    };
    assert!(until(Duration::from_secs(30), || {
        env.manager.tick();
        env.manager
            .status(id)
            .unwrap()
            .map(|t| t.state == "done")
            .unwrap_or(false)
    }));

    let rest = server.saw_command("REST ").expect("续传应发 REST");
    assert_eq!(rest, format!("REST {head}"), "应从已下载偏移续传");
    let got = std::fs::read(&path).unwrap();
    assert_eq!(got.len(), expect.len());
    assert_eq!(got, expect, "续传后内容应逐字节一致");
}

// ---------- 封装链接 ----------

/// 测试用 Base64 编码器（构造封装链接）。
fn b64(input: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.as_bytes().chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 专用链应被解码成真实地址并正常下载，事件里留痕。
#[test]
fn wrapped_delimited_link_is_decoded_and_downloaded() {
    let total = 48 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("wrapped_delimited");
    let real = server.url("/w.bin");
    let wrapped = format!("thunder://{}", b64(&format!("AA{real}ZZ")));

    let id = env
        .manager
        .add(&wrapped, None, Some("w.bin"), None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(30), || {
        env.manager.status(id).unwrap().unwrap().state == "done"
    }));
    let got = std::fs::read(env.dir.join("downloads").join("w.bin")).unwrap();
    assert_eq!(got.len(), total);
    assert_eq!(got, body.as_ref().clone());

    // 库里存的是解码后的真实地址，不是封装串
    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.url_orig, real);
    // 事件里应有解码留痕
    let details: Vec<String> = conn
        .prepare("SELECT COALESCE(detail,'') FROM events WHERE download_id = ?1")
        .unwrap()
        .query_map([id], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        details.iter().any(|d| d.contains("decoded_from=thunder")),
        "应记录解码来源: {details:?}"
    );
}

/// 专用链同样被用来包 eD2k 链接。解码必须发生在 eD2k 判定**之前**：
/// 在原始串上判断会让文件名为空、`ed2k_hash` 不落库，而 worker 是按**解码后**的
/// `url_orig` 分派 eD2k 的 —— 两边不一致等于同一个任务在管理侧与下载侧是两种协议
/// （`is_ed2k = row.ed2k_hash.is_some()` 也会因此为假）。
#[test]
fn wrapped_ed2k_link_keeps_its_filename_and_hash() {
    let hash = "0123456789abcdef0123456789abcdef";
    let ed2k = format!("ed2k://|file|wrapped.iso|1024|{hash}|/");
    let wrapped = format!("thunder://{}", b64(&format!("AA{ed2k}ZZ")));
    let env = temp_env("wrapped_ed2k");
    let id = env.manager.add(&wrapped, None, None, None, 0).unwrap();

    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.url_orig, ed2k, "库里要存解码后的链接");
    assert_eq!(
        row.file_name, "wrapped.iso",
        "文件名必须从解码后的 eD2k 链接提取"
    );
    assert_eq!(row.ed2k_hash.as_deref(), Some(hash), "ed2k_hash 必须落库");
    drop(conn);
    let _ = env.manager.cancel(id);
}

/// 裸地址封装与带标记封装同样应被接受并下载。
#[test]
fn wrapped_raw_and_tagged_links_download() {
    let total = 16 * 1024usize;
    let body = Arc::new(pattern(total));
    let server_body = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&server_body, req, true)
    }));
    let env = temp_env("wrapped_qqdl");
    let real = server.url("/q.bin");

    for (idx, wrapped) in [
        format!("qqdl://{}", b64(&real)),
        format!("flashget://{}", b64(&format!("[FLASHGET]{real}[FLASHGET]"))),
    ]
    .iter()
    .enumerate()
    {
        let name = format!("q{idx}.bin");
        let id = env
            .manager
            .add(wrapped, None, Some(&name), None, 0)
            .unwrap();
        assert!(
            until(Duration::from_secs(30), || {
                env.manager.status(id).unwrap().unwrap().state == "done"
            }),
            "封装链接应能下载: {wrapped}"
        );
        assert_eq!(
            std::fs::read(env.dir.join("downloads").join(&name))
                .unwrap()
                .len(),
            total
        );
    }
}

/// 网盘资源标识不是直链：明确拒绝并说明原因，而不是假装能下。
#[test]
fn fs2you_link_is_rejected_with_reason() {
    let env = temp_env("wrapped_fs2you");
    let link = format!("fs2you://{}", b64("fs2you://deadbeef|x.mkv|1024"));
    let err = env.manager.add(&link, None, None, None, 0).unwrap_err();
    assert!(
        err.starts_with("link_not_downloadable"),
        "应明确拒绝并给出原因: {err}"
    );
    assert!(err.contains("已停运"), "应说明服务已停运: {err}");
}

// ---------- eD2k（电驴）L2：链接接入 + 按哈希认文件 ----------

/// 构造一个 `ed2k://` 文件链接（哈希由本项目自己的 eD2k 实现算出）。
fn ed2k_link_for(name: &str, data: &[u8]) -> String {
    let mut h = aidm_core::ed2k::Ed2kHasher::new(aidm_core::ed2k::Flavor::Official);
    h.update(data);
    let d = h.finish();
    format!("ed2k://|file|{name}|{}|{}|/", data.len(), d.file_hex())
}

/// eD2k 链接应被接受，元信息（大小/哈希）落库，文件名取自链接。
#[test]
fn ed2k_link_is_accepted_and_metadata_is_stored() {
    let env = temp_env("ed2k_add");
    // 本用例不断言网络行为：清空服务器避免 worker 出公网
    env.manager.settings_set("ed2k.servers", "").unwrap();
    let data = pattern(5_000);
    let link = ed2k_link_for("movie.bin", &data);
    let id = env.manager.add(&link, None, None, None, 0).unwrap();

    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.file_name, "movie.bin", "文件名应取自链接");
    assert_eq!(row.size_total, Some(data.len() as i64), "大小应落库");
    assert!(row.ed2k_hash.is_some(), "eD2k 哈希应落库");
    assert_eq!(row.ed2k_hash.as_deref().unwrap().len(), 32);
    assert_eq!(row.aich_root, None);
    assert_eq!(row.url_orig, link, "库里的 URL 应保持原始链接");
}

/// 没有可用本地文件时应进入"等待源"，且**不算失败**（状态 queued + 说明性错误码）。
#[test]
fn ed2k_without_sources_waits_instead_of_failing() {
    let env = temp_env("ed2k_wait");
    // 无源+无服务器时的纯等待语义：清空服务器、关闭 Kad，避免 worker 出公网
    // （Kad 搜源预算 45 秒，会撑爆下面的 20 秒断言窗）。
    env.manager.settings_set("ed2k.servers", "").unwrap();
    env.manager
        .settings_set("ed2k.kad_enabled", "false")
        .unwrap();
    let data = pattern(4_096);
    let link = ed2k_link_for("nope.bin", &data);
    let id = env.manager.add(&link, None, None, None, 0).unwrap();

    assert!(
        until(Duration::from_secs(20), || {
            let st = env.manager.status(id).unwrap().unwrap();
            // 没有服务器/Kad 时仍可能通过公共索引拿到候选源：此时状态是
            // `ed2k_incomplete`（有源但本轮未完成），否则是 `ed2k_no_sources`。
            // 测试要守的是"等待而不是失败"，两种等待码都接受。
            let waiting = matches!(
                st.error_code.as_deref(),
                Some("ed2k_no_sources") | Some("ed2k_incomplete")
            );
            st.state == "queued" && waiting
        }),
        "应停在 queued + ed2k_no_sources/ed2k_incomplete：{:?}",
        env.manager.status(id)
    );
    let view = env.manager.status(id).unwrap().unwrap();
    assert_ne!(view.state, "error", "等待源不能被判成失败");
    assert!(view.retry_at.is_some(), "应排入重试");
    assert!(
        view.error.as_deref().unwrap_or("").contains("源"),
        "应说明在等源：{:?}",
        view.error
    );
}

/// 本地已有同名且哈希一致的文件 → 直接完成，不走网络。
#[test]
fn ed2k_existing_file_with_matching_hash_completes() {
    let env = temp_env("ed2k_have");
    let data = pattern(6_000);
    let link = ed2k_link_for("already.bin", &data);
    let dir = env.dir.join("downloads");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("already.bin"), &data).unwrap();

    let id = env.manager.add(&link, None, None, None, 0).unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "哈希一致应直接完成：{:?}",
        env.manager.status(id)
    );
    // 事件里应留痕"本地已有"
    let conn = aidm_core::open_db(&env.dir.join("db.sqlite")).unwrap();
    // 事件类型在 kind 列，detail 里是哈希与说明
    let events: Vec<(String, String)> = conn
        .prepare("SELECT kind, COALESCE(detail,'') FROM events WHERE download_id = ?1")
        .unwrap()
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        events.iter().any(|(k, _)| k == "ed2k_hash_ok"),
        "应记录 ed2k_hash_ok：{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|(k, d)| k == "ed2k_hash_ok" && d.contains("本地已有")),
        "应说明是本地已有：{events:?}"
    );
}

/// 本地同名文件哈希不符 → 明确报 `ed2k_hash_mismatch`（不静默覆盖用户文件）。
#[test]
fn ed2k_existing_file_with_wrong_hash_fails_clearly() {
    let env = temp_env("ed2k_mismatch");
    let data = pattern(6_000);
    let link = ed2k_link_for("bad.bin", &data);
    let dir = env.dir.join("downloads");
    std::fs::create_dir_all(&dir).unwrap();
    let mut tampered = data.clone();
    tampered[1234] ^= 0xff;
    std::fs::write(dir.join("bad.bin"), &tampered).unwrap();

    let id = env.manager.add(&link, None, None, None, 0).unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            let st = env.manager.status(id).unwrap().unwrap();
            st.state == "error"
        }),
        "哈希不符应失败：{:?}",
        env.manager.status(id)
    );
    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(view.error_code.as_deref(), Some("ed2k_hash_mismatch"));
    assert!(view.error.as_deref().unwrap_or("").contains("哈希"));
    // 用户文件不得被改动
    assert_eq!(std::fs::read(dir.join("bad.bin")).unwrap(), tampered);
}

// ---------- eD2k L4 主链：按 `ed2k_sources` 连对端下载 ----------

/// 最小 eMule 对端：只服务单分片文件（HELLO → 文件名 → 入队 → 分片收发）。
/// 多分片的 hashset/位图分支由 `peer_session` 自身逻辑覆盖，这里只验证主链接线
/// （链接自带源落库 → `ed2k_task` 逐个试源 → 逐片校验 → 完成）。
struct MockEd2kPeer {
    addr: SocketAddr,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockEd2kPeer {
    fn start(file_hash: [u8; 16], file_name: &str, data: Vec<u8>) -> Self {
        Self::start_with_xs_sources(file_hash, file_name, data, Vec::new())
    }

    /// `xs` 里的地址会在收到源交换请求（0xC5/0x83）时以 v1 应答给出。
    fn start_with_xs_sources(
        file_hash: [u8; 16],
        file_name: &str,
        data: Vec<u8>,
        xs: Vec<SocketAddr>,
    ) -> Self {
        use aidm_core::ed2k::peer::{ed2k, emule, HelloInfo, Packet, Protocol};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let name = file_name.to_string();
        let handle = std::thread::spawn(move || {
            let read_pkt = |s: &mut TcpStream| -> Option<Packet> {
                let mut h = [0u8; 6];
                s.read_exact(&mut h).ok()?;
                let proto = Protocol::from_byte(h[0])?;
                let (_proto, len, opcode) = Packet::header(&h).ok()?;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    s.read_exact(&mut payload).ok()?;
                }
                Some(Packet::new(proto, opcode, payload))
            };
            let send = |s: &mut TcpStream, proto: Protocol, op: u8, payload: Vec<u8>| {
                let _ = s.write_all(&Packet::new(proto, op, payload).encode());
                let _ = s.flush();
            };
            let hello_answer = || {
                HelloInfo {
                    user_hash: aidm_core::ed2k::peer::make_emule_hash([0x77; 16]),
                    client_id: 0x0100_0001,
                    tcp_port: 4662,
                    tags: vec![],
                    server_ip: 0,
                    server_port: 0,
                }
                .encode(true)
            };
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                loop {
                    let Some(p) = read_pkt(&mut s) else { break };
                    match (p.protocol, p.opcode) {
                        (Protocol::Edonkey, ed2k::HELLO) => {
                            send(&mut s, Protocol::Edonkey, ed2k::HELLOANSWER, hello_answer());
                        }
                        (Protocol::Edonkey, ed2k::REQUESTFILENAME) => {
                            let mut v = file_hash.to_vec();
                            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
                            v.extend_from_slice(name.as_bytes());
                            send(&mut s, Protocol::Edonkey, ed2k::REQFILENAMEANSWER, v);
                        }
                        (Protocol::Edonkey, ed2k::STARTUPLOADREQ) => {
                            send(&mut s, Protocol::Edonkey, ed2k::ACCEPTUPLOADREQ, vec![]);
                        }
                        (Protocol::Emule, emule::REQUESTSOURCES2) => {
                            // v1：Version+FileHash+Count，每源还必须带服务器 IP/端口。
                            let mut v = vec![1u8];
                            v.extend_from_slice(&file_hash);
                            v.extend_from_slice(&(xs.len() as u16).to_le_bytes());
                            for a in &xs {
                                match a.ip() {
                                    std::net::IpAddr::V4(ip) => v.extend_from_slice(&ip.octets()),
                                    _ => v.extend_from_slice(&[0, 0, 0, 0]),
                                }
                                v.extend_from_slice(&a.port().to_le_bytes());
                                v.extend_from_slice(&[0, 0, 0, 0]);
                                v.extend_from_slice(&0u16.to_le_bytes());
                            }
                            send(&mut s, Protocol::Emule, emule::ANSWERSOURCES2, v);
                        }
                        (Protocol::Edonkey, ed2k::REQUESTPARTS) => {
                            if p.payload.len() < 40 {
                                continue;
                            }
                            let u32at = |o: usize| {
                                u32::from_le_bytes(p.payload[o..o + 4].try_into().unwrap()) as u64
                            };
                            for i in 0..3 {
                                let start = u32at(16 + i * 4);
                                let end = u32at(28 + i * 4);
                                if end <= start {
                                    continue;
                                }
                                let (a, b) = (start as usize, end as usize);
                                if b > data.len() || a >= b {
                                    continue;
                                }
                                let mut v = file_hash.to_vec();
                                v.extend_from_slice(&(a as u32).to_le_bytes());
                                v.extend_from_slice(&(b as u32).to_le_bytes());
                                v.extend_from_slice(&data[a..b]);
                                send(&mut s, Protocol::Edonkey, ed2k::SENDINGPART, v);
                            }
                        }
                        (Protocol::Edonkey, ed2k::END_OF_DOWNLOAD) => break,
                        _ => {}
                    }
                }
            }
        });
        MockEd2kPeer {
            addr,
            handle: Some(handle),
        }
    }
}

/// 主链打通：链接自带源落库 → worker 逐个试源 → 单分片文件一次下完 → done。
#[test]
fn ed2k_task_downloads_from_link_source_peer() {
    let data = pattern(6_000);
    let mut hasher = aidm_core::ed2k::Ed2kHasher::new(aidm_core::ed2k::Flavor::Official);
    hasher.update(&data);
    let digest = hasher.finish();
    let peer = MockEd2kPeer::start(digest.file, "frompeer.bin", data.clone());
    let link = format!(
        "ed2k://|file|frompeer.bin|{}|{}|/|sources,127.0.0.1:{}|/",
        data.len(),
        digest.file_hex(),
        peer.addr.port()
    );

    let env = temp_env("ed2k_peer");
    let id = env.manager.add(&link, None, None, None, 0).unwrap();

    // 链接自带源必须在建任务时落库（主链的第一批候选）。
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        let srcs = model::list_ed2k_sources(&conn, id, 10).unwrap();
        assert_eq!(srcs.len(), 1, "链接自带源应落库：{srcs:?}");
        assert_eq!(srcs[0].host, "127.0.0.1");
        assert_eq!(srcs[0].port, peer.addr.port());
    }

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "应从对端下完：{:?}",
        env.manager.status(id)
    );
    let got = std::fs::read(env.dir.join("downloads").join("frompeer.bin")).unwrap();
    assert_eq!(got, data, "落盘内容应与对端数据一致");

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let events: Vec<(String, String)> = conn
        .prepare("SELECT kind, COALESCE(detail,'') FROM events WHERE download_id = ?1")
        .unwrap()
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        events.iter().any(|(k, _)| k == "ed2k_try_source"),
        "应记录试源：{events:?}"
    );
    assert!(
        events.iter().any(|(k, _)| k == "ed2k_peer_session_end"),
        "应记录对端成功：{events:?}"
    );
    let _ = peer.handle;
}

/// L3 查源接入主链：无链接源时，用 `ed2k.servers` 登录查源 → 源入库 → 主链下完。
#[test]
fn ed2k_task_queries_configured_servers_for_sources() {
    let data = pattern(6_000);
    let mut hasher = aidm_core::ed2k::Ed2kHasher::new(aidm_core::ed2k::Flavor::Official);
    hasher.update(&data);
    let digest = hasher.finish();
    // 对端先起：服务器查源会返回它的地址
    let peer = MockEd2kPeer::start(digest.file, "srvsrc.bin", data.clone());
    let server = MockEdonkeyServer::start(
        vec![(Ipv4Addr::new(127, 0, 0, 1), peer.addr.port())],
        0x0100_0001,
    );
    // 链接本身不带源，源只能来自服务器
    let link = ed2k_link_for("srvsrc.bin", &data);

    let env = temp_env("ed2k_srvsrc");
    env.manager
        .settings_set("ed2k.servers", &format!("127.0.0.1:{}", server.addr.port()))
        .unwrap();
    let id = env.manager.add(&link, None, None, None, 0).unwrap();

    assert!(
        until(Duration::from_secs(60), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "服务器查源后应下完：{:?}",
        env.manager.status(id)
    );
    let got = std::fs::read(env.dir.join("downloads").join("srvsrc.bin")).unwrap();
    assert_eq!(got, data, "落盘内容应与对端数据一致");

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let srcs = model::list_ed2k_sources(&conn, id, 10).unwrap();
    assert!(
        srcs.iter().any(|s| s.kind.as_deref() == Some("server")),
        "查到的源应以 kind=server 入库：{srcs:?}"
    );
    let events: Vec<(String, String)> = conn
        .prepare("SELECT kind, COALESCE(detail,'') FROM events WHERE download_id = ?1")
        .unwrap()
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    for want in ["ed2k_server_login", "ed2k_server_sources", "ed2k_peer_session_end"] {
        assert!(
            events.iter().any(|(k, _)| k == want),
            "应记录 {want}：{events:?}"
        );
    }
}

#[test]
fn ed2k_low_id_source_is_not_dialed_as_an_ip() {
    let server = MockEdonkeyServer::start(vec![(Ipv4Addr::new(25, 245, 0, 0), 4662)], 1);
    let env = temp_env("ed2k_low_id");
    env.manager
        .settings_set("ed2k.servers", &format!("127.0.0.1:{}", server.addr.port()))
        .unwrap();
    // 只验证服务器源过滤：关闭 Kad，避免其预算撑爆 15 秒断言窗
    env.manager
        .settings_set("ed2k.kad_enabled", "false")
        .unwrap();
    let id = env
        .manager
        .add(&ed2k_link_for("lowid.bin", &[1, 2, 3]), None, None, None, 0)
        .unwrap();
    assert!(until(Duration::from_secs(15), || {
        env.manager
            .status(id)
            .unwrap()
            .unwrap()
            .error_code
            .as_deref()
            == Some("ed2k_no_sources")
    }));
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    assert!(model::list_ed2k_sources(&conn, id, 10).unwrap().is_empty());
    let attempts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE download_id=?1 AND kind='ed2k_try_source'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 0);
    let detail: String = conn
        .query_row(
            "SELECT detail FROM events WHERE download_id=?1 AND kind='ed2k_server_sources'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(detail.contains("callback_required=1"));
}

/// 非法服务器清单进不了库（引擎解析前就被 schema 拦下）。
#[test]
fn ed2k_servers_setting_rejects_garbage() {
    let env = temp_env("ed2k_srvset");
    let err = env
        .manager
        .settings_set("ed2k.servers", "noport")
        .unwrap_err();
    assert_eq!(err.code, "ed2k_servers_invalid");
    env.manager
        .settings_set("ed2k.servers", "1.2.3.4:4662, 5.6.7.8:5000")
        .unwrap();
}

/// 源交换（XS）：只配置了 peer1，peer1 的 0x84 应答给出 peer2，
/// peer2 应以 kind='pex' 入库并参与下载。
#[test]
fn ed2k_task_uses_peer_exchange_sources() {
    let data = pattern(6_000);
    let mut hasher = aidm_core::ed2k::Ed2kHasher::new(aidm_core::ed2k::Flavor::Official);
    hasher.update(&data);
    let digest = hasher.finish();
    let peer2 = MockEd2kPeer::start(digest.file, "xs.bin", data.clone());
    let peer1 =
        MockEd2kPeer::start_with_xs_sources(digest.file, "xs.bin", data.clone(), vec![peer2.addr]);
    let link = format!(
        "ed2k://|file|xs.bin|{}|{}|/|sources,127.0.0.1:{}|/",
        data.len(),
        digest.file_hex(),
        peer1.addr.port()
    );

    let env = temp_env("ed2k_xs");
    // 只走对端通道：清空服务器，XS 是唯一的源放大器
    env.manager.settings_set("ed2k.servers", "").unwrap();
    let id = env.manager.add(&link, None, None, None, 0).unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "XS 扩源后应下完：{:?}",
        env.manager.status(id)
    );
    let got = std::fs::read(env.dir.join("downloads").join("xs.bin")).unwrap();
    assert_eq!(got, data, "落盘内容应与对端数据一致");

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let srcs = model::list_ed2k_sources(&conn, id, 10).unwrap();
    assert!(
        srcs.iter().any(|s| s.kind.as_deref() == Some("pex")
            && s.host == "127.0.0.1"
            && s.port == peer2.addr.port()),
        "XS 发现的源应以 kind=pex 入库：{srcs:?}"
    );
}

/// 服务器/节点链接不是下载任务 → 明确拒绝。
#[test]
fn ed2k_server_link_is_not_a_download_task() {
    let env = temp_env("ed2k_server");
    for link in [
        "ed2k://|server|207.44.222.51|4242|/",
        "ed2k://|nodeslist|http://x/nodes.dat|/",
    ] {
        let err = env.manager.add(link, None, None, None, 0).unwrap_err();
        assert_eq!(err, "ed2k_not_file_link", "应明确拒绝：{link}");
    }
    // 坏哈希也要拒绝
    let err = env
        .manager
        .add("ed2k://|file|a.bin|10|zzzz|/", None, None, None, 0)
        .unwrap_err();
    assert_eq!(err, "ed2k_bad_hash");
}

// ---------- L3：eDonkey 服务器协议（登录 → 查源） ----------

/// 最小 eDonkey 服务器：验证分帧、登录、查源，以及"不请自来的消息不能打乱同步"。
struct MockEdonkeyServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// 记录收到的 opcode 序列
    seen: Arc<Mutex<Vec<u8>>>,
}

impl MockEdonkeyServer {
    fn start(sources: Vec<(Ipv4Addr, u16)>, assigned_id: u32) -> Self {
        use aidm_core::ed2k::peer::{Packet, Protocol};
        use aidm_core::ed2k::server::{op, IdChange};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let st = stop.clone();
        let seen2 = seen.clone();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut s) = stream else { continue };
                let seen = seen2.clone();
                let sources = sources.clone();
                std::thread::spawn(move || {
                    let send = |s: &mut TcpStream, pkt: Packet| {
                        let _ = s.write_all(&pkt.encode());
                        let _ = s.flush();
                    };
                    // 服务器不请自来：先 MOTD，再一条**未知 opcode**（用来验证跳过能力）
                    let text = b"welcome AIDM";
                    let mut motd = (text.len() as u16).to_le_bytes().to_vec();
                    motd.extend_from_slice(text);
                    send(
                        &mut s,
                        Packet::new(Protocol::Edonkey, op::SERVERMESSAGE, motd),
                    );
                    send(
                        &mut s,
                        Packet::new(Protocol::Edonkey, 0x7E, vec![1, 2, 3, 4, 5]),
                    );

                    // 读一条完整报文
                    let read_pkt = |s: &mut TcpStream| -> Option<Packet> {
                        let mut h = [0u8; 6];
                        s.read_exact(&mut h).ok()?;
                        let (_proto, len, opcode) = Packet::header(&h).ok()?;
                        let mut payload = vec![0u8; len];
                        if len > 0 {
                            s.read_exact(&mut payload).ok()?;
                        }
                        Some(Packet::new(Protocol::Edonkey, opcode, payload))
                    };

                    // 登录
                    let Some(login) = read_pkt(&mut s) else {
                        return;
                    };
                    seen.lock().unwrap().push(login.opcode);
                    // 校验登录载荷：hash16 + id4 + port2 + tagcount4
                    assert!(login.payload.len() > 26);
                    assert_eq!(
                        aidm_core::ed2k::server::is_client_user_hash(
                            &login.payload[0..16].try_into().unwrap()
                        ),
                        true,
                        "登录哈希必须带客户端特征位"
                    );
                    // 回 IDCHANGE：HighID + flags + 保留 + 公网 IP + 混淆端口
                    let mut idc = assigned_id.to_le_bytes().to_vec();
                    idc.extend_from_slice(
                        &(aidm_core::ed2k::server::tcp_flags::LARGEFILES
                            | aidm_core::ed2k::server::tcp_flags::UNICODE)
                            .to_le_bytes(),
                    );
                    idc.extend_from_slice(&0u32.to_le_bytes());
                    idc.extend_from_slice(&[85, 17, 116, 222]);
                    idc.extend_from_slice(&6082u32.to_le_bytes());
                    assert!(IdChange::decode(&idc).is_ok());
                    send(&mut s, Packet::new(Protocol::Edonkey, op::IDCHANGE, idc));

                    // 查源
                    let Some(gs) = read_pkt(&mut s) else { return };
                    seen.lock().unwrap().push(gs.opcode);
                    assert_eq!(gs.opcode, op::GETSOURCES);
                    // 期间插一条不请自来的 SERVERSTATUS，验证客户端不会错位
                    let mut st_payload = 4242u32.to_le_bytes().to_vec();
                    st_payload.extend_from_slice(&777u32.to_le_bytes());
                    send(
                        &mut s,
                        Packet::new(Protocol::Edonkey, op::SERVERSTATUS, st_payload),
                    );
                    // FOUNDSOURCES：hash16 + count(1) + 交错条目
                    let mut fs = gs.payload[0..16].to_vec();
                    fs.push(sources.len() as u8);
                    for (ip, port) in &sources {
                        fs.extend_from_slice(&ip.octets());
                        fs.extend_from_slice(&port.to_le_bytes());
                    }
                    send(&mut s, Packet::new(Protocol::Edonkey, op::FOUNDSOURCES, fs));
                    std::thread::sleep(Duration::from_millis(300));
                });
            }
        });
        MockEdonkeyServer {
            addr,
            stop,
            handle: Some(handle),
            seen,
        }
    }
}

impl Drop for MockEdonkeyServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// 登录 → 拿到分配的 ID/flags/公网 IP/混淆端口，且 MOTD 与未知消息不打乱同步。
#[test]
fn ed2k_server_login_parses_idchange_and_skips_unknown() {
    use aidm_engine::ed2k::server_session::{ServerSession, ServerSessionCfg};

    let server = MockEdonkeyServer::start(vec![], 0x551174DE);
    let cfg = ServerSessionCfg {
        addr: server.addr,
        user_hash: aidm_core::ed2k::server::make_user_hash([0x33; 16]),
        listen_port: 0,
        nickname: "AIDM",
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
    };
    let mut sess = ServerSession::connect(&cfg).unwrap();
    let login = sess.login(&cfg).unwrap();

    assert_eq!(login.client_id, 0x551174DE, "点分序读出的 ID");
    assert!(!login.is_low_id(), "0x551174DE 是 HighID");
    assert_eq!(
        login.tcp_flags,
        Some(
            aidm_core::ed2k::server::tcp_flags::LARGEFILES
                | aidm_core::ed2k::server::tcp_flags::UNICODE
        )
    );
    assert_eq!(login.public_ip, Some(Ipv4Addr::new(85, 17, 116, 222)));
    assert_eq!(login.obfuscation_port, Some(6082));
    assert!(
        login.motd.iter().any(|m| m.contains("welcome AIDM")),
        "应收下 MOTD：{:?}",
        login.motd
    );
}

/// 查源：`0x42` 的 count 是 1 字节，条目 IP 按点分序、端口小端。
#[test]
fn ed2k_server_get_sources_parses_dotted_order_ips() {
    use aidm_engine::ed2k::server_session::{ServerSession, ServerSessionCfg};

    let want = vec![
        (Ipv4Addr::new(85, 17, 116, 222), 6082u16),
        (Ipv4Addr::new(186, 64, 120, 70), 4232u16),
        (Ipv4Addr::new(176, 123, 5, 89), 4725u16),
    ];
    let server = MockEdonkeyServer::start(want.clone(), 0x0A000001);
    let cfg = ServerSessionCfg {
        addr: server.addr,
        user_hash: aidm_core::ed2k::server::make_user_hash([0x44; 16]),
        listen_port: 0,
        nickname: "AIDM",
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(3),
    };
    let mut sess = ServerSession::connect(&cfg).unwrap();
    let _ = sess.login(&cfg).unwrap();

    let hash = [0xABu8; 16];
    let srcs = sess
        .get_sources(&hash, 1_000_000, Duration::from_secs(3))
        .unwrap();
    let got: Vec<(Ipv4Addr, u16)> = srcs.iter().map(|s| (s.ip, s.port)).collect();
    assert_eq!(got.len(), 3, "应拿到 3 个源：{got:?}");
    for w in &want {
        assert!(got.contains(w), "缺少源 {w:?}；实际 {got:?}");
    }
    // 顺序无关，但 IP 必须是点分序（反了会变成 222.116.17.85 之类）
    assert!(
        !got.iter().any(|(ip, _)| ip.octets() == [222, 116, 17, 85]),
        "IP 被反序读了"
    );

    // 服务器侧的 opcode 序列：登录 → 查源（未知消息不影响）
    let seen = server.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            aidm_core::ed2k::server::op::LOGINREQUEST,
            aidm_core::ed2k::server::op::GETSOURCES
        ]
    );
}

#[test]
fn ed2k_reported_iso_keeps_64_bit_size_and_safe_filename() {
    let env = temp_env("ed2k_reported_iso");
    env.manager.settings_set("ed2k.servers", "").unwrap();
    let link = "ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
    let id = env.manager.add(link, None, Some(""), None, 0).unwrap();
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.file_name,
        "cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso"
    );
    assert_eq!(row.size_total, Some(4_478_906_368));
    assert_eq!(
        row.ed2k_hash.as_deref(),
        Some("e7c526499308841a4a6d116c857db669")
    );
    drop(conn);
    let unsafe_link = link.replace(
        "cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso",
        "..%5C..%5Csafe.iso",
    );
    let second = env.manager.add(&unsafe_link, None, None, None, 0).unwrap();
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    assert_eq!(
        model::get_download(&conn, second)
            .unwrap()
            .unwrap()
            .file_name,
        "safe.iso"
    );
}

// ---------- 备用地址（镜像）----------

/// 真实镜像上的启动曲线：复现用户报告的场景（主源 302 到死主机 → 自动镜像接管 →
/// 64 连接并发），每秒采样 `done` 的**增量**。
///
/// **自己算增量，不读 `live.speed_bps`** —— 后者受 `SpeedWindow` 影响（分母是
/// "当前时刻减最老样本"且下限 200 ms，停顿后会把一次突发算成虚高，用户看到的
/// "150 Mb/s 超过 100 Mb/s 宽带"就是这么来的）。自己算增量才是真实吞吐。
///
/// 不会下完：跑满 `SECS` 秒就取消。会真实产生约 `SECS × 出口带宽` 的流量，
/// 并在临时目录留下部分文件（跑完自动清理由 `Env` 的目录承担）。
#[test]
#[ignore = "live: 需公网，且会真实下载数十秒"]
fn live_startup_curve_against_a_real_mirror() {
    // 时长可调：VDL 填充是"一次性、有限"的成本，要看清"填充结束后下载是否恢复"
    // 就得跑得比它久。`AIDM_LIVE_SECS=40` 即可。
    let secs: u64 = std::env::var("AIDM_LIVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let panics = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let panics = panics.clone();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            panics.lock().unwrap().push(info.to_string());
            prev(info);
        }));
    }
    let env = temp_env("live_curve");
    // 对照开关：`AIDM_LIVE_NO_PROXY=1` 时让这条任务直连。
    // 若那 10 秒停顿只在走代理时出现，瓶颈就在代理的并发转发而不是 AIDM。
    let no_proxy = std::env::var("AIDM_LIVE_NO_PROXY").is_ok();
    let conns = std::env::var("AIDM_LIVE_CONNS").ok();
    let no_hash = std::env::var("AIDM_LIVE_NO_HASH").is_ok();
    if no_proxy || conns.is_some() || no_hash {
        let db = open_db(&env.dir.join("db.sqlite")).unwrap();
        if no_proxy {
            settings::set(&db, "proxy.mode", "none").unwrap();
        }
        // 关掉并行 SHA-256：`hash_step` 是唯一"每 tick 都干重活"的地方（读文件 +
        // 哈希，且每次都先 `pool.drain()`）。若关掉后停顿消失，瓶颈就在它。
        if no_hash {
            settings::set(&db, "verify.sha256_after", "false").unwrap();
        }
        if let Some(n) = &conns {
            settings::set(&db, "conn.global_conn_cap", n).unwrap();
        }
        drop(db);
    }
    println!(
        "走代理 = {} | 并发上限 = {:?} | 并行哈希 = {}",
        !no_proxy, conns, !no_hash
    );
    // 默认那条 15 GiB 的 ISO（分段 7.5 GB）；用 `AIDM_LIVE_URL` 换成小文件，
    // 就能把"引擎 vs aidm-fetch"与"大文件/大分段"这两个差异分开
    // —— `aidm-fetch --conns 64` 下 69 MiB 的文件是 42.9 MiB/s、毫无停顿。
    let url = std::env::var("AIDM_LIVE_URL").unwrap_or_else(|_| {
        "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso"
            .to_string()
    });
    println!("目标 = {url}");
    let id = env
        .manager
        .add(&url, None, Some("alma.iso"), None, 0)
        .unwrap();

    // 分段观测：`persist` 每秒把每段的 `done_bytes`/`retries` 落库（PERSIST_INTERVAL=1000ms），
    // 所以这里每秒读一次就能区分「只有少数分段在收数据」与「所有分段都在收但很慢」——
    // 这两者的修法完全不同，而 `done` 的总量看不出区别。
    let db = env.dir.join("db.sqlite");
    let started = std::time::Instant::now();
    let mut prev = 0u64;
    println!(
        "{:>5}  {:>13}  {:>11}  {:>7}  {:>9}  {:>7}  {}",
        "t", "done MiB", "inst MiB/s", "segs", "有数据段", "重试段", "state"
    );
    for _ in 0..secs {
        std::thread::sleep(Duration::from_secs(1));
        let Some(t) = env.manager.status(id).unwrap() else {
            break;
        };
        let inst = t.done.saturating_sub(prev) as f64 / 1_048_576.0;
        prev = t.done;
        let (segs, moved, retried) = {
            let conn = open_db(&db).unwrap();
            let rows = model::list_segments(&conn, id).unwrap_or_default();
            (
                rows.len(),
                rows.iter().filter(|s| s.done_bytes > 0).count(),
                rows.iter().filter(|s| s.retries > 0).count(),
            )
        };
        println!(
            "{:>4}s  {:>13.1}  {:>11.1}  {:>7}  {:>9}  {:>7}  {}",
            started.elapsed().as_secs(),
            t.done as f64 / 1_048_576.0,
            inst,
            segs,
            moved,
            retried,
            t.state
        );
        if matches!(t.state.as_str(), "error" | "done") {
            println!("最终状态 = {t:?}");
            break;
        }
    }
    {
        // 探测阶段的真实耗时（AIDM 自己的，不是从 curl 反推的）：
        // `created → alt_* → range_probe → start` 的逐条相对秒。
        println!("---- 事件时间线（相对首个事件，秒）----");
        for (dt, kind, detail) in timeline(&db, id).into_iter().take(40) {
            let d = detail.unwrap_or_default();
            let d = d.chars().take(110).collect::<String>();
            println!("  +{dt:>3}s  {kind:<14} {d}");
        }
    }
    {
        let p = panics.lock().unwrap();
        println!("worker panic 共 {} 次", p.len());
        for s in p.iter().take(3) {
            println!("  PANIC: {}", s.lines().next().unwrap_or(""));
        }
    }
    // **必须在 cancel 之前读**：`events` 表对 `downloads` 是 `ON DELETE CASCADE`，
    // 取消/删除任务会把事件一起带走 —— cancel 之后再读就什么都看不到。
    println!("全部事件 kind = {:?}", event_kinds(&db, id));
    let retries = event_details(&db, id, "segment_retry");
    println!("segment_retry 共 {} 次，前 4 条：", retries.len());
    for d in retries.iter().take(4) {
        println!("    {d}");
    }
    for k in [
        "first_byte",
        "start",
        "alt_switch",
        "range_probe",
        "checksum",
        "write_stall",
        "conn_timing",
        "ramp_stall",
        "ramp_stop",
    ] {
        let d = event_details(&db, id, k);
        if !d.is_empty() {
            println!("  {k} = {d:?}");
        }
    }
    let _ = env.manager.cancel(id);
    for kind in [
        "alt_failed",
        "alt_rejected",
        "alt_switch",
        "range_probe",
        "checksum",
        "start",
        "first_byte",
        "write_stall",
        "ramp",
        "error",
    ] {
        let d = event_details(&db, id, kind);
        if !d.is_empty() {
            println!("{kind:<14} {d:?}");
        }
    }
}

/// 量"往**未标记稀疏**的预分配文件深处写"的代价 —— 这是 `set_len` 之外的另一半。
///
/// `set_len` 只改 EOF（实测 0.5 ms / 1 GiB），**VDL 仍停在 0**；而 NTFS 对未标记
/// 稀疏的文件，在**写入超出 VDL 的位置**时必须先把 VDL 零填充到那里。
///
/// 填充量**不是**各段起点之和：VDL 是**单调最高水位**，前一次填充已经把水位推上去，
/// 后面的段只需补差值。所以 15 GiB 分 N 段的总填充量 ≈ 文件大小 × (N−1)/N，与段数
/// 几乎无关（8 段 87.5%、64 段 98.4%）—— 指望"少分段"来省这笔钱是没有用的。
///
/// **这正是 `wpool::set_sparse` 要消除的东西**，对照见下一条
/// `probe_sparse_flag_removes_the_deep_write_cost`。
/// 会真实占用磁盘（写入会实体化前面的部分）。
#[test]
#[ignore = "会创建 15 GiB 级文件，需手动运行"]
fn probe_sparse_write_cost_at_deep_offsets() {
    use std::os::windows::fs::FileExt;
    // 默认落在**受控测试根**内（`%TEMP%\aidm-tests\aidm-probe`）而不是 `%TEMP%` 根：
    // 这些用例会写 15 GiB 级文件，落在 `%TEMP%` 根既没有 `aidm-` 前缀（清扫器不收，
    // 见 R-TEST-11），又是用户临时目录里最难发现的那种占用（R-TEST-08）。
    let dir = std::env::var("AIDM_PROBE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| common::root().join("aidm-probe"));
    std::fs::create_dir_all(&dir).unwrap();
    println!("目录 {}", dir.display());
    println!(
        "{:>12}  {:>12}  {:>14}",
        "写入偏移", "首次写耗时", "第二次同位置"
    );

    for off in [0u64, 256 << 20, 1 << 30, 4 << 30, 7575961600] {
        let path = dir.join(format!("aidm-sparse-{off}.bin"));
        let _ = std::fs::remove_file(&path);
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.set_len(15_151_923_200).unwrap(); // 只改 EOF，VDL 仍为 0

        // 首次写：落在 VDL 之外，NTFS 需要先把 VDL 填到这里
        let t0 = std::time::Instant::now();
        f.seek_write(&[0xABu8; 256 * 1024], off).unwrap();
        let first = t0.elapsed();

        // 第二次写同一位置：VDL 已经覆盖，不应再付填充代价
        let t1 = std::time::Instant::now();
        f.seek_write(&[0xCDu8; 256 * 1024], off).unwrap();
        let second = t1.elapsed();

        drop(f);
        let _ = std::fs::remove_file(&path);
        println!(
            "{:>10} MiB  {:>9.1} ms  {:>11.1} ms",
            off >> 20,
            first.as_secs_f64() * 1000.0,
            second.as_secs_f64() * 1000.0
        );
    }
}

/// 上一条的对照：**同一个文件标记稀疏之后**，深偏移首写不再付 VDL 填充代价。
///
/// 这是 `fastdl::wpool::create_preallocated` 改成"先 `FSCTL_SET_SPARSE`、再 `set_len`"
/// 的直接依据 —— 两条路径各测一遍，差值就是修复本身。本机 M.2 实测（256 KiB 定位写）：
///
/// | 写入偏移 | 手工 `set_len` | `create_preallocated` |
/// |---|---|---|
/// | 256 MiB | 147.6 ms | 0.2 ms |
/// | 1 GiB | 612.1 ms | 0.2 ms |
/// | 4 GiB | 1997.5 ms | 0.2 ms |
///
/// 后一列不随偏移增长，说明洞是文件系统层的虚拟零，不需要 VDL 先"坐实"。
/// 用 `AIDM_PROBE_DIR` 指定目录时应指向真实下载盘。
#[test]
#[ignore = "会创建 15 GiB 级文件，需手动运行"]
fn probe_sparse_flag_removes_the_deep_write_cost() {
    use std::os::windows::fs::FileExt;
    // 默认落在**受控测试根**内（`%TEMP%\aidm-tests\aidm-probe`）而不是 `%TEMP%` 根：
    // 这些用例会写 15 GiB 级文件，落在 `%TEMP%` 根既没有 `aidm-` 前缀（清扫器不收，
    // 见 R-TEST-11），又是用户临时目录里最难发现的那种占用（R-TEST-08）。
    let dir = std::env::var("AIDM_PROBE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| common::root().join("aidm-probe"));
    std::fs::create_dir_all(&dir).unwrap();
    let total = 15_151_923_200u64;
    println!("目录 {} | 目标长度 {total} B", dir.display());
    println!(
        "{:>12}  {:>16}  {:>22}",
        "写入偏移", "手工 set_len", "create_preallocated"
    );
    for off in [256u64 << 20, 1 << 30, 4 << 30] {
        let mut row = Vec::new();
        for via_create in [false, true] {
            let path = dir.join(format!("sparse-flag-{off}-{via_create}.bin"));
            let _ = std::fs::remove_file(&path);
            let f = if via_create {
                aidm_engine::fastdl::wpool::create_preallocated(&path, total).unwrap()
            } else {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open(&path)
                    .unwrap();
                f.set_len(total).unwrap();
                f
            };
            let t = std::time::Instant::now();
            f.seek_write(&[0xABu8; 256 * 1024], off).unwrap();
            row.push(t.elapsed().as_secs_f64() * 1000.0);
            drop(f);
            let _ = std::fs::remove_file(&path);
        }
        println!(
            "{:>10} MiB  {:>13.1} ms  {:>19.1} ms",
            off >> 20,
            row[0],
            row[1]
        );
    }
}

/// 量 `create_preallocated`（NTFS 的 `SetEndOfFile`）对 15 GiB 目标的真实耗时。
///
/// 起因：用户报告 15 GiB 的任务启动后有约 10 秒"极低速率"。fastdl 在下载**之前**
/// 会对整个文件做一次 `set_len(总长)`（`create_preallocated` 只在长度不符时触发，
/// 全新任务必然触发）。如果这一步不是纯元数据操作，那 10 秒就正好是它 ——
/// 这条用例不改任何产品行为，只把这一步变成可复现的数字。
///
/// 会真实占用最大 15 GiB 磁盘（每个尺寸测完立即删除）。用 `AIDM_PROBE_DIR`
/// 指定目录（默认系统临时目录）—— 想和下载盘对比时应指向同一块盘。
#[test]
#[ignore = "会分配 15 GiB 磁盘，需手动运行"]
fn probe_preallocation_cost_for_a_15gib_target() {
    // 默认落在**受控测试根**内（`%TEMP%\aidm-tests\aidm-probe`）而不是 `%TEMP%` 根：
    // 这些用例会写 15 GiB 级文件，落在 `%TEMP%` 根既没有 `aidm-` 前缀（清扫器不收，
    // 见 R-TEST-11），又是用户临时目录里最难发现的那种占用（R-TEST-08）。
    let dir = std::env::var("AIDM_PROBE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| common::root().join("aidm-probe"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("aidm-prealloc-probe.bin");
    println!("目录 {} | 该 ISO 长度 15,151,923,200 B", dir.display());
    println!("{:>10}  {:>12}", "size", "set_len");
    for size in [1u64 << 30, 4 << 30, 15_151_923_200] {
        let _ = std::fs::remove_file(&path);
        let t0 = std::time::Instant::now();
        let f = aidm_engine::fastdl::wpool::create_preallocated(&path, size).unwrap();
        let el = t0.elapsed();
        drop(f);
        println!(
            "{:>7} MiB  {:>9.1} ms",
            size >> 20,
            el.as_secs_f64() * 1000.0
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// 候选探测并行化：主源慢死时不该再串行等它超时。
///
/// 主源要 3 秒才失败、备用地址立即可用。串行遍历必须先等满那 3 秒才轮到备用地址；
/// 并行预探让备用地址在 `HEDGE_DELAY`(800 ms) 后就开始跑，于是总耗时由**最快的源**
/// 决定，而不是由最慢的那次失败决定。
#[test]
fn slow_primary_does_not_delay_the_faster_alternate() {
    let total = 32 * 1024usize;
    let body = Arc::new(pattern(total));
    // 主源：睡满 3 秒再回 502（模拟那台要 5.14 秒才失败的死主机）
    let slow = TestServer::new(Arc::new(|_: &Req| {
        std::thread::sleep(Duration::from_millis(3000));
        Resp::empty(502)
    }));
    // 备用地址：立即可用
    let fast_body = body.clone();
    let fast = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&fast_body, req, true)));

    let env = temp_env("hedge_parallel");
    let started = std::time::Instant::now();
    let id = add_with_alts(&env, &slow.url("/a.bin"), "h.bin", &fast.url("/a.bin"));
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "备用地址必须接管: {:?}",
        env.manager.status(id)
    );
    let elapsed = started.elapsed();
    let got = std::fs::read(env.dir.join("downloads").join("h.bin")).unwrap();
    assert_eq!(got, body.as_ref().clone());
    // 串行下界就是主源那 3 秒；并行后总耗时由备用地址决定
    assert!(
        elapsed < Duration::from_secs(2),
        "不该串行等主源超时（串行下界 3 秒）: {elapsed:?}"
    );
}

/// 带备用地址新建任务（`add` 便捷方法没有这个参数）。
fn add_with_alts(env: &Env, url: &str, name: &str, alts: &str) -> i64 {
    env.manager
        .add_spec(aidm_engine::AddSpec {
            user_agent: None,
            custom_headers: None,
            alt_urls: Some(alts),
            url,
            dir: None,
            filename: Some(name),
            referrer: None,
            cookies: None,
            offer_id: None,
            speed_limit_kbps: 0,
            source: None,
            start: None,
        })
        .unwrap()
}

#[test]
fn mirror_takes_over_when_primary_probe_fails() {
    let total = 2 * 1024 * 1024usize;
    let expect = pattern_sha256(total);
    // 主地址探测就 404（文件被删/地址过期），备用地址可续传。
    let primary = TestServer::new(Arc::new(|_: &Req| Resp::empty(404)));
    let mirror_body = Arc::new(pattern(total));
    let mirror = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&mirror_body, req, true).header("ETag", "\"m1\"")
    }));
    let env = temp_env_conns("alt_failover", Some(4));
    let id = add_with_alts(
        &env,
        &primary.url("/a.bin"),
        "alt.bin",
        &mirror.url("/a.bin"),
    );
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "备用地址应接管并下完: {:?}",
        env.manager.status(id)
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.done, total as u64);
    // IPC 视图把镜像清单与当前生效序号一起下发
    assert_eq!(
        task.alt_urls.as_deref(),
        Some(mirror.url("/a.bin").as_str())
    );
    assert_eq!(task.alt_cursor, Some(1));

    let db = env.dir.join("db.sqlite");
    let switches = event_details(&db, id, "alt_switch");
    assert!(
        switches.iter().any(|d| d.contains("from=0 to=1")),
        "切换必须留痕: {switches:?}"
    );
    // 主地址的失败也要留痕，否则"为什么换了镜像"无从复盘
    assert!(
        event_details(&db, id, "alt_failed")
            .iter()
            .any(|d| d.contains("err=http_404")),
        "主地址失败要留痕: {:?}",
        event_details(&db, id, "alt_failed")
    );

    let conn = open_db(&db).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.url_final.as_deref(),
        Some(mirror.url("/a.bin").as_str())
    );
    assert_eq!(row.alt_cursor, 1);
    drop(conn);
    let file = env.dir.join("downloads").join("alt.bin");
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
}

#[test]
fn mirror_with_mismatched_size_is_rejected() {
    // 换镜像只允许"同一份文件"：记录里已有 2 MiB，镜像却是 3 MiB 就必须拒绝，
    // 否则会把两个不同文件的字节拼进同一个目标文件。
    let recorded = 2 * 1024 * 1024i64;
    let primary = TestServer::new(Arc::new(|_: &Req| Resp::empty(404)));
    let mirror = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&pattern(3 * 1024 * 1024), req, true)
    }));
    let env = temp_env("alt_size");
    // 4xx 不是瞬态错误，但仍显式关掉重试让状态判定确定
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(
            &conn,
            &primary.url("/a.bin"),
            "s.bin",
            &save_dir.to_string_lossy(),
            0,
            2,
        )
        .unwrap();
        model::set_probe_meta(
            &conn,
            id,
            &primary.url("/a.bin"),
            Some(recorded),
            None,
            None,
        )
        .unwrap();
        model::set_alt_urls(&conn, id, Some(&mirror.url("/a.bin"))).unwrap();
        model::set_status(&conn, id, Status::Paused, None).unwrap();
        id
    };
    env.manager.resume(id).unwrap();
    assert!(
        until(Duration::from_secs(25), || {
            env.manager
                .status(id)
                .ok()
                .flatten()
                .map(|t| t.state == "error")
                .unwrap_or(false)
        }),
        "长度对不上的镜像不能被用: {:?}",
        env.manager.status(id)
    );
    let rejected = event_details(&db_path, id, "alt_rejected");
    assert!(
        rejected.iter().any(|d| d.contains("reason=size")),
        "拒绝原因要留痕: {rejected:?}"
    );
    assert!(event_details(&db_path, id, "alt_switch").is_empty());
    let conn = open_db(&db_path).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.alt_cursor, 0);
    // 报的是当前生效地址（用户填的主地址）的错，不是镜像的
    assert_eq!(
        row.url_final.as_deref(),
        Some(primary.url("/a.bin").as_str())
    );
}

// ---------- 文件缺失：「在磁盘上查找」与重新关联 ----------

#[test]
fn find_file_recovers_a_moved_file_and_relocate_repoints_the_task() {
    let total = 64 * 1024usize;
    let expect = pattern_sha256(total);
    let env = temp_env("relocate");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let db_path = env.dir.join("db.sqlite");
    // 一条"已完成"的任务：记录里的位置已经没有文件了（用户把它挪到了子目录）
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(
            &conn,
            "http://127.0.0.1/moved.bin",
            "moved.bin",
            &save_dir.to_string_lossy(),
            0,
            1,
        )
        .unwrap();
        model::set_probe_meta(
            &conn,
            id,
            "http://127.0.0.1/moved.bin",
            Some(total as i64),
            None,
            None,
        )
        .unwrap();
        model::init_single_segment(
            &conn,
            id,
            &save_dir.join("moved.bin").to_string_lossy(),
            Some(total as i64 - 1),
        )
        .unwrap();
        let _ = model::finalize_segments(&conn, id);
        model::set_status(&conn, id, Status::Done, None).unwrap();
        id
    };
    let moved = save_dir.join("archive").join("2026").join("moved.bin");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::write(&moved, pattern(total)).unwrap();
    // 同名不同长度：不能算命中，否则会拿别的文件冒充下载结果
    std::fs::write(save_dir.join("decoy.bin"), pattern(8)).unwrap();

    let report = env.manager.find_file(id).unwrap();
    assert_eq!(
        report.hits.len(),
        1,
        "只应命中同名同大小那一个: {:?}",
        report.hits
    );
    assert_eq!(report.hits[0].path, moved);
    assert!(!report.truncated);

    // 记录里的位置确实没有文件了
    assert!(!save_dir.join("moved.bin").exists());
    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(view.save_path, save_dir.join("moved.bin").to_string_lossy());

    // 重新关联：只改指向，不搬文件
    let task = env.manager.relocate(id, &moved.to_string_lossy()).unwrap();
    assert_eq!(task.save_path, moved.to_string_lossy());
    assert_eq!(task.state, "done");
    assert_eq!(task.done, total as u64, "进度要按整份文件收尾，而不是 0");
    assert!(moved.exists());
    let conn = open_db(&db_path).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.file_name, "moved.bin");
    assert_eq!(PathBuf::from(&row.dir), moved.parent().unwrap());
    assert_eq!(row.status, Status::Done);
    assert!(row.finished_at.is_some());
    drop(conn);
    assert!(event_kinds(&db_path, id).contains(&"relocated".to_string()));
    assert_eq!(
        sha256_reader(std::fs::File::open(&moved).unwrap()).unwrap(),
        expect
    );
}

#[test]
fn relocate_rejects_missing_and_mismatched_files() {
    let total = 4096usize;
    let env = temp_env("relocate_bad");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(
            &conn,
            "http://127.0.0.1/a.bin",
            "a.bin",
            &save_dir.to_string_lossy(),
            0,
            1,
        )
        .unwrap();
        model::set_probe_meta(
            &conn,
            id,
            "http://127.0.0.1/a.bin",
            Some(total as i64),
            None,
            None,
        )
        .unwrap();
        model::set_status(&conn, id, Status::Error, Some("http_404")).unwrap();
        id
    };
    assert_eq!(
        env.manager
            .relocate(id, &save_dir.join("nope.bin").to_string_lossy()),
        Err("file_missing".into())
    );
    let wrong = save_dir.join("wrong.bin");
    std::fs::write(&wrong, pattern(total + 1)).unwrap();
    assert_eq!(
        env.manager.relocate(id, &wrong.to_string_lossy()),
        Err("size_mismatch".into())
    );
    // 被拒绝时记录不能变：还是原来那条错误，路径也没被改
    let conn = open_db(&db_path).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.file_name, "a.bin");
    assert_eq!(row.status, Status::Error);
    assert_eq!(row.error_code.as_deref(), Some("http_404"));
    assert_eq!(row.finished_at, None);
    assert!(event_details(&db_path, id, "relocated").is_empty());
}

#[test]
fn url_extraction_strips_page_annotation_before_storing() {
    // 真实成因：从镜像站整行复制会带上页面注释
    // （`.../a.bin  ✅  (stable "latest" name)`）。整串当 URL 发出去必然 404；
    // 落库的必须是抽出来的纯地址，并在 created 事件里留痕。
    let server = TestServer::new(Arc::new(|_: &Req| Resp::empty(404)));
    let env = temp_env("url_extract");
    let clean = server.url("/a.bin");
    let pasted = format!("{clean}  \u{2705}  (stable \"latest\" name)");
    let id = add_with_alts(&env, &pasted, "a.bin", "");

    let db = env.dir.join("db.sqlite");
    let conn = open_db(&db).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.url_orig, clean, "落库的是抽出来的地址");
    drop(conn);
    assert!(
        event_details(&db, id, "created")
            .iter()
            .any(|d| d.contains("[trimmed_pasted_text]")),
        "抽取要留痕: {:?}",
        event_details(&db, id, "created")
    );
}

#[test]
fn scheme_fallback_takes_over_when_https_probe_fails() {
    // 实测成因：镜像的 https 证书链不可信（`SEC_E_UNTRUSTED_ROOT`）而 http 正常。
    // 这里用"纯 HTTP 测试服务器 + `https://` 主地址"复现同一形态：
    // https 一定失败，同一地址换 http 必须能接管并下完。
    let total = 512 * 1024usize;
    let expect = pattern_sha256(total);
    let body = Arc::new(pattern(total));
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path.starts_with("/a.bin") {
            ranged_mem(&body, req, true)
        } else {
            // 兄弟文件不存在：校验器路径不参与本用例
            Resp::empty(404)
        }
    }));
    let env = temp_env("scheme_fallback");
    let https_url = format!("https://{}{}", server.addr, "/a.bin");
    let id = add_with_alts(&env, &https_url, "sch.bin", "");

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "换协议后应能下完: {:?}",
        env.manager.status(id)
    );
    let task = env.manager.status(id).unwrap().unwrap();
    assert_eq!(task.done, total as u64);
    // 逻辑候选没变（仍是主地址那一槽），所以 cursor 不动，但切换必须留痕
    assert_eq!(task.alt_cursor.unwrap_or(0), 0);

    let db = env.dir.join("db.sqlite");
    let switches = event_details(&db, id, "alt_switch");
    assert!(
        switches.iter().any(|d| d.contains("via=scheme")),
        "换协议接管要留痕: {switches:?}"
    );
    let file = env.dir.join("downloads").join("sch.bin");
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
}

#[test]
fn ed2k_nodes_refresh_stores_and_takes_effect() {
    // 公共 nodes.dat 里的节点会过期，所以必须能刷新。这里用本地服务端喂一份**真实**
    // 抓取样本（6030 B / v2 / **177** 节点），并断言它真的接管了 bootstrap ——
    // 编译期内嵌样本是 183 节点，节点数足以区分两者。
    let doc = std::fs::read(ed2k_fixture("nodes-20261018.dat")).unwrap();
    let body = Arc::new(doc.clone());
    let srv = TestServer::new(Arc::new(move |_: &Req| Resp::ok(body.to_vec())));
    let env = temp_env("nodes_refresh");
    env.manager
        .settings_set("ed2k.nodes_dat_url", &srv.url("/nodes.dat"))
        .unwrap();

    assert_eq!(env.manager.ed2k_nodes_refresh().unwrap(), 177);

    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    assert_eq!(
        aidm_engine::ed2k::kad_bootstrap::bootstrap_nodes(&conn).len(),
        177,
        "刷新过的列表必须真的被 bootstrap 用上"
    );
}

#[test]
fn ed2k_nodes_refresh_rejects_garbage_and_keeps_the_cache() {
    let doc = std::fs::read(ed2k_fixture("nodes-20261018.dat")).unwrap();
    let mut bad = doc.clone();
    bad.truncate(bad.len() - 1); // 长度与计数不符
    let body = Arc::new(bad);
    let srv = TestServer::new(Arc::new(move |_: &Req| Resp::ok(body.to_vec())));
    let env = temp_env("nodes_refresh_bad");

    // 先放一份好的缓存
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        aidm_core::ed2k::kad::store::store(&conn, "http://good.test/nodes.dat", &doc, 1_000)
            .unwrap();
    }
    env.manager
        .settings_set("ed2k.nodes_dat_url", &srv.url("/nodes.dat"))
        .unwrap();
    let err = env.manager.ed2k_nodes_refresh().unwrap_err();
    assert!(err.starts_with("nodes_dat_invalid:"), "{err}");

    // 坏响应既不入库，也不能盖掉已有缓存
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let kept = aidm_core::ed2k::kad::store::load(&conn).unwrap().unwrap();
    assert_eq!(kept.source_url, "http://good.test/nodes.dat");
    assert_eq!(kept.node_count, 177);
}

#[test]
fn ed2k_servers_refresh_writes_back_the_setting() {
    // server.met 的刷新语义是**写回 ed2k.servers**（不是另建缓存表），
    // 所以这里断言的是设置项本身被更新，用户可以继续手工编辑。
    let doc = std::fs::read(ed2k_fixture("emule-security-server.met")).unwrap();
    let body = Arc::new(doc);
    let srv = TestServer::new(Arc::new(move |_: &Req| Resp::ok(body.to_vec())));
    let env = temp_env("servers_refresh");
    env.manager
        .settings_set("ed2k.server_list_url", &srv.url("/server.met"))
        .unwrap();

    // 夹具是采集的 emule-security 列表：14 台
    assert_eq!(env.manager.ed2k_servers_refresh().unwrap(), 14);

    let settings = env.manager.settings_get().unwrap();
    let text = settings
        .get("ed2k.servers")
        .and_then(|v| v.as_str())
        .expect("写回后该键必须是字符串");
    assert_eq!(text.split(',').count(), 14, "{text}");
    assert!(text.contains(':'), "{text}");
}

#[test]
fn failed_segment_switches_to_the_other_source() {
    // B 镜像每次只发 1 KiB 就断开：绑到它的分段必然失败，失败后该段应换到 A 续下。
    // 注意 B 的**探测**仍然是成功的（`Range: bytes=0-0` 只有 1 字节，断连阈值没到），
    // 所以它会正常进池 —— 这正是"能进池 ≠ 能供数"的现实情形。
    let total = 2 * 1024 * 1024usize;
    let expect = pattern_sha256(total);
    let body_a = Arc::new(pattern(total));
    let body_b = Arc::new(pattern(total));
    let a = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_a, req, true)));
    let b = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&body_b, req, true).drop_after(1024)
    }));
    let env = temp_env("multi_source_switch");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let primary = a.url("/ms.bin");
    let secondary = b.url("/ms.bin");
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id =
            model::insert_download(&conn, &primary, "ms.bin", &save_dir.to_string_lossy(), 0, 4)
                .unwrap();
        model::set_probe_meta(&conn, id, &primary, Some(total as i64), None, None).unwrap();
        model::set_alt_urls(&conn, id, Some(&secondary)).unwrap();
        model::set_sha256_expected(&conn, id, Some(&expect)).unwrap();
        model::set_status(&conn, id, Status::Paused, None).unwrap();
        id
    };
    env.manager.resume(id).unwrap();

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(60)),
        "换源后应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&db_path, id)
    );
    let switches = event_details(&db_path, id, "segment_src_switch");
    assert!(
        switches
            .iter()
            .any(|d| d.contains(&secondary) || d.contains("to=")),
        "失败分段必须换源并留痕: {switches:?}"
    );
    // 换源不能破坏内容：整文件哈希仍然要对得上
    let file = env.dir.join("downloads").join("ms.bin");
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
    let row = model::get_download(&open_db(&db_path).unwrap(), id)
        .unwrap()
        .unwrap();
    assert_eq!(row.error_code, None);
}

#[test]
fn metalink_supplies_both_the_hash_and_the_extra_mirror() {
    // 主镜像提供一个 `.metalink`：里面既有整文件 SHA-256，也列着另一个镜像。
    // 这条链一次性把"身份凭证"和"多源"都补上 —— 而且是上游自己给的，比静态表权威。
    let total = 2 * 1024 * 1024usize;
    let expect = pattern_sha256(total);
    let body_a = Arc::new(pattern(total));
    let body_b = Arc::new(pattern(total));
    let mirror_b = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_b, req, true)));
    let b_url = mirror_b.url("/ms.bin");
    let metalink_body = Arc::new(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <metalink version=\"3.0\" xmlns=\"http://www.metalinker.org/\">\n\
         \x20 <files>\n\
         \x20   <file name=\"ms.bin\">\n\
         \x20     <size>{total}</size>\n\
         \x20     <verification><hash type=\"sha-256\">{expect}</hash></verification>\n\
         \x20     <resources><url type=\"https\">{b_url}</url></resources>\n\
         \x20   </file>\n\
         \x20 </files>\n\
         </metalink>\n"
    ));
    let body_a_for_iso = body_a.clone();
    let server_a = TestServer::new(Arc::new(move |req: &Req| {
        if req.path.ends_with(".metalink") || req.path.ends_with(".meta4") {
            return Resp::ok(metalink_body.as_bytes().to_vec());
        }
        ranged_mem(&body_a_for_iso, req, true)
    }));

    let env = temp_env("metalink_source");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = add_with_alts(&env, &server_a.url("/ms.bin"), "ms.bin", "");

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "Metalink 供源后应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let db = env.dir.join("db.sqlite");
    // 哈希与镜像地址都来自那份 metalink
    let md = event_details(&db, id, "metalink");
    assert!(
        md.iter()
            .any(|d| d.contains(&expect) && d.contains("urls=1")),
        "metalink 事件要记下哈希与镜像数: {md:?}"
    );
    let conn = open_db(&db).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.sha256_expected.as_deref(), Some(expect.as_str()));
    assert_eq!(model::get_mirrors_urls(&conn, id), vec![b_url.clone()]);
    // 两个来源都要被用上
    let segs = model::list_segments(&conn, id).unwrap();
    let srcs: std::collections::HashSet<String> =
        segs.iter().filter_map(|s| s.src_url.clone()).collect();
    assert!(
        srcs.contains(&server_a.url("/ms.bin")) && srcs.contains(&b_url),
        "Metallink 列的镜像要进来源池: {srcs:?}"
    );
    drop(conn);
    assert!(
        !event_details(&db, id, "multi_source").is_empty(),
        "应当启用跨源聚合"
    );
    let file = env.dir.join("downloads").join("ms.bin");
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
}

#[test]
fn mirrorlist_supplies_the_extra_mirror_when_the_hash_came_from_checksum() {
    // 哈希来自同目录 CHECKSUM（不带镜像列表），镜像列表来自 `.mirrorlist`。
    // 这条覆盖"两个来源各补一半"的现实组合（TDF/KDE 就是这种）。
    let total = 2 * 1024 * 1024usize;
    let expect = pattern_sha256(total);
    let body_a = Arc::new(pattern(total));
    let body_b = Arc::new(pattern(total));
    let mirror_b = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_b, req, true)));
    let b_url = mirror_b.url("/ms.bin");
    let mirrorlist_html = Arc::new(format!(
        "<!DOCTYPE html><html><body><div id=\"mirrorbrain-details\">\n\
         <ul><li><a href=\"{b_url}\">{b_url}</a></li></ul>\n\
         </div></body></html>\n"
    ));
    let checksum_body = Arc::new(format!("SHA256 (ms.bin) = {expect}\n"));
    let body_a_for_iso = body_a.clone();
    let server_a = TestServer::new(Arc::new(move |req: &Req| {
        if req.path.ends_with(".mirrorlist") {
            return Resp::ok(mirrorlist_html.as_bytes().to_vec());
        }
        if req.path == "/CHECKSUM" {
            return Resp::ok(checksum_body.as_bytes().to_vec());
        }
        // metalink / meta4 / 其它兄弟文件都不存在
        if req.path.ends_with(".metalink")
            || req.path.ends_with(".meta4")
            || req.path.ends_with(".sha256")
        {
            return Resp::empty(404);
        }
        ranged_mem(&body_a_for_iso, req, true)
    }));

    let env = temp_env("mirrorlist_source");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = add_with_alts(&env, &server_a.url("/ms.bin"), "ms.bin", "");

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "mirrorlist 供源后应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let db = env.dir.join("db.sqlite");
    let events = all_events(&db, id);
    assert!(
        events
            .iter()
            .any(|(k, d)| k == "checksum" && d.as_deref().is_some_and(|v| v.contains(&expect))),
        "哈希应当来自 CHECKSUM: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|(k, d)| k == "mirrorlist" && d.as_deref() == Some("urls=1")),
        "mirrorlist 事件要记下条数: {events:?}"
    );
    let conn = open_db(&db).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.sha256_expected.as_deref(), Some(expect.as_str()));
    assert_eq!(model::get_mirrors_urls(&conn, id), vec![b_url.clone()]);
    let segs = model::list_segments(&conn, id).unwrap();
    let srcs: std::collections::HashSet<String> =
        segs.iter().filter_map(|s| s.src_url.clone()).collect();
    assert!(
        srcs.contains(&server_a.url("/ms.bin")) && srcs.contains(&b_url),
        "mirrorlist 列的镜像要进来源池: {srcs:?}"
    );
    drop(conn);
    let file = env.dir.join("downloads").join("ms.bin");
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
}

#[test]
fn html_error_page_is_rejected_and_the_next_mirror_is_used() {
    // 复现真实故障：部分镜像站对特定 UA 返回
    // 200 + text/html 的反爬提示页。原来探测只看状态码与 Content-Range，于是这个提示页
    // 被当合法候选 → 降级单线程 → 5 KB 的 HTML 被存成 .iso 并**判定完成**。
    // 现在的行为：判为 `html_not_file` → 该候选被拒 → 继续试下一个镜像。
    let total = 512 * 1024usize;
    let body = Arc::new(pattern(total));
    let bad = TestServer::new(Arc::new(|_: &Req| {
        Resp::ok(b"<html><body>captcha</body></html>".to_vec())
            .header("Content-Type", "text/html; charset=utf-8")
    }));
    let body_b = body.clone();
    let good = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_b, req, true)));

    let env = temp_env("html_error_page");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    // 主地址 = 错误页，备用地址 = 真文件
    let id = add_with_alts(&env, &bad.url("/ms.iso"), "ms.iso", &good.url("/ms.iso"));

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(30)),
        "错误页被拒后应当换到真文件: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let db = env.dir.join("db.sqlite");
    // 首次失败记在 `alt_failed`，同候选的派生尝试记在 `alt_rejected`，所以查全部事件
    let events = all_events(&db, id);
    assert!(
        events
            .iter()
            .any(|(k, d)| (k == "alt_failed" || k == "alt_rejected")
                && d.as_deref()
                    .is_some_and(|v| v.contains("idx=0") && v.contains("html_not_file"))),
        "错误页必须被明确拒绝（html_not_file）: {events:?}"
    );
    // 内容必须是真文件，而不是那 5 KB 的 HTML
    let file = env.dir.join("downloads").join("ms.iso");
    let got = std::fs::read(&file).unwrap();
    assert_eq!(got.len(), total, "不能把错误页当文件");
    assert_eq!(got, *body);
    let row = model::get_download(&open_db(&db).unwrap(), id)
        .unwrap()
        .unwrap();
    assert_eq!(row.error_code, None);
    assert_eq!(row.url_final.as_deref(), Some(good.url("/ms.iso").as_str()));
}

#[test]
fn a_real_html_download_is_not_treated_as_an_error_page() {
    // 反向对照：地址本身就以 .html 结尾时，text/html 是**正确**的内容，不该被拒。
    // 这条守的是"别把修复做成误伤"。
    let html = b"<!DOCTYPE html><html><body><h1>hello</h1></body></html>".to_vec();
    let payload = Arc::new(html.clone());
    let srv = TestServer::new(Arc::new(move |_: &Req| {
        Resp::ok(payload.as_ref().clone()).header("Content-Type", "text/html; charset=utf-8")
    }));
    let env = temp_env("real_html_page");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = add_with_alts(&env, &srv.url("/page.html"), "page.html", "");

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(30)),
        "真 HTML 应当照常下载: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let file = env.dir.join("downloads").join("page.html");
    assert_eq!(std::fs::read(&file).unwrap(), html);
}

/// 某任务的全部事件（kind, detail），按发生顺序。断言失败时带上它，省一轮复现。
fn all_events(db_path: &std::path::Path, id: i64) -> Vec<(String, Option<String>)> {
    let Ok(conn) = open_db(db_path) else {
        return Vec::new();
    };
    let Ok(mut stmt) =
        conn.prepare("SELECT kind, detail FROM events WHERE download_id = ?1 ORDER BY id")
    else {
        return Vec::new();
    };
    let rows = stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)));
    match rows {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

/// 引擎测试读 `aidm-core` 的公共源夹具（**真实抓取样本**，不造假数据）。
fn ed2k_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../aidm-core/tests/fixtures/ed2k")
        .join(name)
}

/// 跨源聚合下载的公共布置：两台本地"镜像"服务**同一份**内容。
///
/// 返回的 `TestServer` **必须由调用方持有到测试结束** —— 一旦被 drop 就停止监听，
/// 后续连接会被直接拒绝（本地 mock 用例最容易踩的一个坑）。
///
/// `with_hash` 决定是否预置上游整文件 SHA-256，那正是"允不允许跨源"的唯一门槛。
#[allow(clippy::type_complexity)]
fn two_mirrors(
    tag: &str,
    total: usize,
    with_hash: bool,
) -> (Env, TestServer, TestServer, i64, u64, String) {
    let expect = pattern_sha256(total);
    let body_a = Arc::new(pattern(total));
    let body_b = Arc::new(pattern(total));
    let a = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_a, req, true)));
    let b = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_b, req, true)));
    let env = temp_env(tag);
    // 本地 mock 服务绝不该走开发机的系统代理：默认 `follow-system` 会把
    // 127.0.0.1 也交给代理，代理对本地地址返回 502，测试就会以"网络失败"收场。
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let primary = a.url("/ms.bin");
    let secondary = b.url("/ms.bin");
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id =
            model::insert_download(&conn, &primary, "ms.bin", &save_dir.to_string_lossy(), 0, 4)
                .unwrap();
        // 预置探测结果：url_final = 主地址，长度已知（新任务的第一跳免检要靠它）
        model::set_probe_meta(&conn, id, &primary, Some(total as i64), None, None).unwrap();
        model::set_alt_urls(&conn, id, Some(&secondary)).unwrap();
        if with_hash {
            model::set_sha256_expected(&conn, id, Some(&expect)).unwrap();
        }
        model::set_status(&conn, id, Status::Paused, None).unwrap();
        id
    };
    env.manager.resume(id).unwrap();
    (env, a, b, id, total as u64, expect)
}

#[test]
fn segmented_download_splits_across_two_sources_when_a_hash_proves_identity() {
    // 有上游整文件哈希 → 允许跨源：各段轮流绑到不同来源，完成后仍用哈希校验。
    let (env, mirror_a, mirror_b, id, total, expect) =
        two_mirrors("multi_source", 3 * 1024 * 1024, true);
    let primary = mirror_a.url("/ms.bin");
    let secondary = mirror_b.url("/ms.bin");
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "跨源聚合应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let db = env.dir.join("db.sqlite");
    let conn = open_db(&db).unwrap();
    let segs = model::list_segments(&conn, id).unwrap();
    let srcs: std::collections::HashSet<String> =
        segs.iter().filter_map(|s| s.src_url.clone()).collect();
    assert!(
        srcs.contains(&primary) && srcs.contains(&secondary),
        "两个来源都要被用上: {srcs:?}"
    );
    assert!(
        segs.len() >= 2,
        "3 MiB / 256 KiB 下限应当切出多段: {}",
        segs.len()
    );
    drop(conn);

    let events = event_details(&db, id, "multi_source");
    assert!(
        events.iter().any(|d| d.contains("sources=2")),
        "启用跨源要留痕: {events:?}"
    );
    let switches = event_details(&db, id, "segment_src_switch");
    assert!(switches.is_empty(), "两个源都健康时不该换源: {switches:?}");

    // 内容必须与上游哈希一致（跨源拼接的正确性靠这一步兜住）
    let file = env.dir.join("downloads").join("ms.bin");
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
    let conn = open_db(&db).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.error_code, None);
    assert_eq!(row.size_total, Some(total as i64));
}

#[test]
fn segmented_download_stays_single_source_without_an_upstream_hash() {
    // 没有上游哈希 → **没有任何兜底证明各源内容一致**，必须保持单源。
    // 这条是"不许悄悄放宽正确性"的守门用例。
    let (env, _mirror_a, _mirror_b, id, _total, _expect) =
        two_mirrors("multi_source_no_hash", 2 * 1024 * 1024, false);
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(40)),
        "单源也要能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let db = env.dir.join("db.sqlite");
    let conn = open_db(&db).unwrap();
    let segs = model::list_segments(&conn, id).unwrap();
    assert!(
        segs.iter().all(|s| s.src_url.is_none()),
        "没有哈希时不许绑定来源: {:?}",
        segs.iter().map(|s| s.src_url.clone()).collect::<Vec<_>>()
    );
    drop(conn);
    assert!(
        event_details(&db, id, "multi_source").is_empty(),
        "没哈希就不该有跨源事件"
    );
    // 仍然应当下完（主地址可用，不需要备用地址）
    let row = model::get_download(&open_db(&db).unwrap(), id)
        .unwrap()
        .unwrap();
    assert_eq!(row.error_code, None);
}

/// 预置一个"两源同内容"任务并启动，返回任务 id。
///
/// 与 `two_mirrors` 同构，但允许两个来源**速度不同**、也允许自定义文件名 ——
/// 跨任务用例要跑两个任务，两轮共用的只有"来源集合"（这正是跨任务评分的前提）。
fn start_two_source_task(
    env: &Env,
    primary: &str,
    secondary: &str,
    name: &str,
    total: usize,
    expect: &str,
) -> i64 {
    let db_path = env.dir.join("db.sqlite");
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    let id = {
        let conn = open_db(&db_path).unwrap();
        let id = model::insert_download(&conn, primary, name, &save_dir.to_string_lossy(), 0, 4)
            .unwrap();
        model::set_probe_meta(&conn, id, primary, Some(total as i64), None, None).unwrap();
        model::set_alt_urls(&conn, id, Some(secondary)).unwrap();
        model::set_sha256_expected(&conn, id, Some(expect)).unwrap();
        model::set_status(&conn, id, Status::Paused, None).unwrap();
        id
    };
    env.manager.resume(id).unwrap();
    id
}

/// **跨任务降级 e2e**：前一个任务累积出的实测评分，必须改变**下一个任务**的取源顺序。
///
/// 布置：两台本地"镜像"服务同一份 1 MiB 内容，主地址是**慢源**（每 8 KiB 停 20 ms）、
/// 备用地址是**快源**。这样"实测顺序"与上游给的字面顺序**相反** —— 否则顺序本来就对，
/// 断言等于没测。
///
/// 两次任务：
/// 1. 两个源都还没有记录 ⇒ 顺序必须**保持原样**（"没数据"不许乱动，见 `order_by_score`）；
/// 2. 补齐到入榜门槛（各 20 条，模拟前序任务的累积；不必真跑 20 次）后 ⇒ 快源必须被提到
///    前面，并留下 `source_rank` 留痕。
#[test]
fn cross_task_scores_reorder_the_next_tasks_source_pool() {
    let total = 1024 * 1024usize;
    let expect = pattern_sha256(total);
    let body_slow = Arc::new(pattern(total));
    let body_fast = Arc::new(pattern(total));
    // 慢源：每 8 KiB 停 20 ms ≈ 400 KiB/s（"本地内存服务上的一条慢线路"）。
    let slow = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&body_slow, req, true).slow(8 * 1024, Duration::from_millis(20))
    }));
    let fast = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_fast, req, true)));
    let slow_url = slow.url("/ms.bin");
    let fast_url = fast.url("/ms.bin");

    let env = temp_env_conns("rank_cross_task", Some(4));
    // 本地 mock 服务绝不该走系统代理（同 `two_mirrors` 的理由）。
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let db = env.dir.join("db.sqlite");

    // ---- 任务 1：两个源都还没有记录 ----
    let first = start_two_source_task(&env, &slow_url, &fast_url, "ms.bin", total, &expect);
    assert!(
        wait_state(&env.manager, first, "done", Duration::from_secs(60)),
        "任务 1 应当能下完: {:?} events={:?}",
        env.manager.status(first),
        all_events(&db, first)
    );
    assert_eq!(
        start_sources(&db, first),
        2,
        "两源必须都进池，否则这个用例根本走不到排序那一步"
    );
    assert!(
        event_details(&db, first, "source_rank").is_empty(),
        "两个源都还没有记录时不许重排（没数据不等于不可用）: {:?}",
        event_details(&db, first, "source_rank")
    );

    // ---- 前序任务的累积：各喂到入榜门槛（20 条）----
    // 口径与 worker 段循环一致（真实字节/耗时；ttfb 只有这里给得出）。任务 1 那几条
    // 真实记录已经落在同一个桶里，这里补到门槛即可 —— 不必真跑 20 次下载。
    let record = aidm_engine::source_registry::record;
    let now = aidm_engine::source_registry::now_ms();
    for _ in 0..20 {
        record(&slow_url, 8 * 1024, 1000, 200, true, now);
        record(&fast_url, 4 * 1024 * 1024, 1000, 10, true, now);
    }

    // ---- 任务 2：同一个"来源集合"，换了任务 ----
    let second = start_two_source_task(&env, &slow_url, &fast_url, "ms.bin", total, &expect);
    assert!(
        wait_state(&env.manager, second, "done", Duration::from_secs(60)),
        "任务 2 应当能下完: {:?} events={:?}",
        env.manager.status(second),
        all_events(&db, second)
    );
    assert_eq!(start_sources(&db, second), 2, "任务 2 仍应是两源");
    let rank = event_details(&db, second, "source_rank");
    assert!(
        !rank.is_empty(),
        "任务 2 必须留下重排留痕: events={:?}",
        all_events(&db, second)
    );
    for detail in &rank {
        let after = detail
            .split_once("after=")
            .map(|(_, a)| a)
            .unwrap_or_else(|| panic!("source_rank 事件要带 after= 顺序：{detail}"));
        let fast_at = after
            .find(&fast_url)
            .unwrap_or_else(|| panic!("重排后的顺序里必须有快源：{after}"));
        let slow_at = after
            .find(&slow_url)
            .unwrap_or_else(|| panic!("重排后的顺序里必须有慢源（降级不是剔除）：{after}"));
        assert!(
            fast_at < slow_at,
            "上一轮实测更快的源必须排到前面：after={after}"
        );
    }

    // 重排只改顺序、不改内容：两个任务都必须逐字节正确。
    //
    // 落盘名不一定是插入时给的那个：探测之后引擎会用 URL / `Content-Disposition` 推导出的
    // 名字覆盖它（`worker.rs` 里 `unique_file_name` 那一跳），所以从库里读**实际**落盘名。
    for id in [first, second] {
        let name = model::get_download(&open_db(&db).unwrap(), id)
            .unwrap()
            .unwrap()
            .file_name;
        let file = env.dir.join("downloads").join(&name);
        assert_eq!(
            sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
            expect,
            "任务 {id}（{name}）的内容必须与上游哈希一致"
        );
    }
}

/// 段级「持续慢」换源（R-DL-14）：**慢段的速率持续超过判定窗口后，必须换到实测最快的来源**。
///
/// 布置：主地址 = 慢源（每 4 KiB 停 100 ms ≈ 40 KiB/s，一个 256 KiB 的段要 6.4 秒），
/// 备用地址 = 快源。段轮换后慢源一定会拿到段，`alt.measure_window_s = 1` 让判定窗口
/// 短到测试里跑得完。快源段会在窗口关闭前就下完，于是"已完成分段的平均速率"有了参照 ——
/// 这正是 R-DL-14 的口径（不是拿绝对速度比，而是和已完成段比）。
#[test]
fn slow_segment_switches_to_a_faster_source() {
    let total = 1024 * 1024usize;
    let expect = pattern_sha256(total);
    let body_a = Arc::new(pattern(total));
    let body_b = Arc::new(pattern(total));
    let fast = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_a, req, true)));
    let slow = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&body_b, req, true).slow(4 * 1024, Duration::from_millis(100))
    }));
    let fast_url = fast.url("/ms.bin");
    let slow_url = slow.url("/ms.bin");

    let env = temp_env_conns("slow_seg_switch", Some(4));
    env.manager.settings_set("proxy.mode", "none").unwrap();
    env.manager
        .settings_set("alt.measure_window_s", "1")
        .unwrap();
    let db = env.dir.join("db.sqlite");
    let id = start_two_source_task(&env, &slow_url, &fast_url, "ms.bin", total, &expect);

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(60)),
        "换源后应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&db, id)
    );

    let switches = event_details(&db, id, "segment_src_switch");
    assert!(
        !switches.is_empty(),
        "持续慢的段必须换源并留痕: events={:?}",
        all_events(&db, id)
    );
    assert!(
        switches
            .iter()
            .any(|d| d.contains("reason=slow_vs_done") || d.contains("reason=below_min_bps")),
        "R-DL-14 要求事件带 reason=：{switches:?}"
    );

    // 该段不混源：库里一行一段、一段只有一个 `src_url`；而且换过源的段最终必须绑在
    // **快源**上（换到"实测最快的来源"，不是随便换一个）。
    let conn = open_db(&db).unwrap();
    let segs = model::list_segments(&conn, id).unwrap();
    assert!(segs.len() >= 2, "应当切出多段: {}", segs.len());
    for s in &segs {
        let src = s.src_url.as_deref().unwrap_or("<none>");
        assert!(
            src == fast_url || src == slow_url,
            "段的来源只能是池里的某一个（不混源）: idx={} src={src}",
            s.idx
        );
    }
    for detail in &switches {
        let idx: i32 = detail
            .split_whitespace()
            .find_map(|t| t.strip_prefix("idx="))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("事件里要有 idx=：{detail}"));
        let seg = segs
            .iter()
            .find(|s| s.idx == idx)
            .unwrap_or_else(|| panic!("事件里的段必须在库里：{detail}"));
        assert_eq!(
            seg.src_url.as_deref(),
            Some(fast_url.as_str()),
            "判慢之后该段应当绑在快源上: {detail}"
        );
    }
    drop(conn);

    // 换源只改"剩余部分从哪里续"：整文件仍然必须逐字节正确。
    let row = model::get_download(&open_db(&db).unwrap(), id)
        .unwrap()
        .unwrap();
    let file = env.dir.join("downloads").join(&row.file_name);
    assert_eq!(
        sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
        expect
    );
    assert_eq!(row.error_code, None);
}

/// 对照实验：**窗口没走完、或压根没开窗口时，一次都不许换源**。
///
/// 两种情形各跑一遍同一个布置（主地址慢源，但只有 400 KiB/s，整个任务约 1.5 秒）：
///
/// 1. `alt.measure_window_s = 5`（规则里写的默认口径）—— 任务在窗口内就下完了；
/// 2. 不设该键（setting 的默认值是 `0` = **关闭**）—— 完全不观察。
///
/// 这条守的是"别把慢当成慢"：没到窗口就换源等于把 `measure_window_s` 当成摆设，
/// 而默认关闭时更不该有任何行为变化（既有任务的下载路径必须逐字节不变）。
#[test]
fn slow_segment_gate_stays_quiet_inside_the_window_and_when_disabled() {
    for (tag, window) in [("slow_gate_window", Some("5")), ("slow_gate_off", None)] {
        let total = 1024 * 1024usize;
        let expect = pattern_sha256(total);
        let body_a = Arc::new(pattern(total));
        let body_b = Arc::new(pattern(total));
        let fast = TestServer::new(Arc::new(move |req: &Req| ranged_mem(&body_a, req, true)));
        let slow = TestServer::new(Arc::new(move |req: &Req| {
            ranged_mem(&body_b, req, true).slow(8 * 1024, Duration::from_millis(20))
        }));

        let env = temp_env_conns(tag, Some(4));
        env.manager.settings_set("proxy.mode", "none").unwrap();
        if let Some(w) = window {
            env.manager.settings_set("alt.measure_window_s", w).unwrap();
        }
        let db = env.dir.join("db.sqlite");
        let id = start_two_source_task(
            &env,
            &slow.url("/ms.bin"),
            &fast.url("/ms.bin"),
            "ms.bin",
            total,
            &expect,
        );
        assert!(
            wait_state(&env.manager, id, "done", Duration::from_secs(60)),
            "{tag}: 应当能下完: {:?} events={:?}",
            env.manager.status(id),
            all_events(&db, id)
        );
        let switches = event_details(&db, id, "segment_src_switch");
        assert!(
            switches.is_empty(),
            "{tag}: 窗口没到（或已关闭）就不该换源: {switches:?} events={:?}",
            all_events(&db, id)
        );
        let row = model::get_download(&open_db(&db).unwrap(), id)
            .unwrap()
            .unwrap();
        let file = env.dir.join("downloads").join(&row.file_name);
        assert_eq!(
            sha256_reader(std::fs::File::open(&file).unwrap()).unwrap(),
            expect,
            "{tag}: 不换源也必须下对"
        );
    }
}

#[test]
#[ignore = "需要真实网络；手动运行以验证自动镜像（L3 静态表）真的能接管"]
fn auto_mirror_takeover_against_real_mirrors() {
    // 主地址指向一个必然连不上的主机，但**路径落在已知命名空间**里，
    // 于是 `aidm_core::mirrors` 会派生出真实镜像站上的同一路径，
    // 第一个可用的应当接管并把字节下回来。
    //
    // 选 CHECKSUM 是因为它只有 1–2 KB：验证的是"接管链路"，不是吞吐。
    let env = temp_env("auto_mirror_live");
    let primary = "https://127.0.0.1:9/almalinux/9/isos/x86_64/CHECKSUM";
    let id = add_with_alts(&env, primary, "CHECKSUM", "");

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(90)),
        "派生镜像应当接管: {:?}",
        env.manager.status(id)
    );
    let db = env.dir.join("db.sqlite");
    let switches = event_details(&db, id, "alt_switch");
    assert!(
        switches.iter().any(|d| d.contains("from=0 to=")),
        "接管必须留痕: {switches:?}"
    );
    // 主地址必然失败并留痕
    assert!(
        event_details(&db, id, "alt_failed")
            .iter()
            .any(|d| d.contains("idx=0")),
        "主地址失败要留痕"
    );
    let file = env.dir.join("downloads").join("CHECKSUM");
    let body = std::fs::read_to_string(&file).unwrap_or_default();
    assert!(
        body.contains("SHA256") || body.contains("BEGIN PGP"),
        "下回来的应当是真清单: {}",
        &body[..body.len().min(120)]
    );
}

#[test]
fn redirect_target_is_derived_and_tried_after_the_primary_fails() {
    // 主地址 302 到一个不可达主机：跟随必然失败，此时**跳转目标本身**也要作为
    // 派生候选被试着探测（`via=redirect`）。
    //
    // 边界：本用例只证明"派生与尝试确实发生"，**不**证明它能接管。要构造
    // "跳转目标不可用、但它的另一协议可用"需要可信 TLS 端点，本地测试服务器给不了。
    let server = TestServer::new(Arc::new(|_: &Req| {
        Resp::empty(302).header("Location", "http://127.0.0.1:9/never.bin")
    }));
    let env = temp_env("redirect_derive");
    // 连接被拒是瞬态错误，显式关掉重试让状态判定确定
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    let id = add_with_alts(&env, &server.url("/a.bin"), "r.bin", "");

    let db = env.dir.join("db.sqlite");
    assert!(
        until(Duration::from_secs(40), || {
            env.manager
                .status(id)
                .ok()
                .flatten()
                .map(|t| t.state == "error")
                .unwrap_or(false)
        }),
        "所有候选都不可用时必须失败: {:?}",
        env.manager.status(id)
    );

    // 逻辑候选本身按原有语义记 alt_failed
    assert!(
        !event_details(&db, id, "alt_failed").is_empty(),
        "主地址失败要留痕"
    );
    let rejected = event_details(&db, id, "alt_rejected");
    assert!(
        rejected.iter().any(|d| d.contains("via=redirect")),
        "302 跳转目标必须被派生并尝试: {rejected:?}"
    );
    // 跳转目标是明文 http，所以它的另一协议也应在序列里
    assert!(
        rejected.iter().any(|d| d.contains("via=redirect-scheme")),
        "跳转目标的另一协议也要试: {rejected:?}"
    );
    assert!(
        rejected.iter().any(|d| d.contains("via=scheme")),
        "主地址的另一协议也要试: {rejected:?}"
    );
}

#[test]
fn a_slow_dead_redirect_target_is_probed_once_and_then_fused() {
    // 本次调查的真实形状：`mirrors.aliyun.com` 302 到 `iso-osm.mirrors.aliyuncs.com`，
    // 而那台机器 http 与 https 各自耗满 5 秒才失败。若在同一台死机器上连试 4 跳
    // （跟随、跟随到的目标、目标的另一协议……），会白等 20 秒才轮到镜像 ——
    // 而旁边 6 个镜像都是 0 秒可用。
    //
    // 这里把"慢死"压缩成 2 秒（门槛 1.5 秒），断言那台机器只被碰一次。
    let dead = TestServer::new(Arc::new(|_: &Req| {
        std::thread::sleep(Duration::from_millis(2000));
        Resp::empty(502)
    }));
    let dead_addr = dead.addr;
    let primary = TestServer::new(Arc::new(move |_: &Req| {
        Resp::empty(302).header("Location", &format!("http://{dead_addr}/never.bin"))
    }));
    let env = temp_env("slow_dead_redirect");
    // 超时是瞬态错误，显式关掉重试让状态判定确定
    env.manager.settings_set("conn.retry_max", "0").unwrap();

    let started = std::time::Instant::now();
    let id = add_with_alts(&env, &primary.url("/a.bin"), "sd.bin", "");
    let db = env.dir.join("db.sqlite");
    assert!(
        until(Duration::from_secs(60), || {
            env.manager
                .status(id)
                .ok()
                .flatten()
                .map(|t| t.state == "error")
                .unwrap_or(false)
        }),
        "所有候选都不可用时必须失败: {:?}",
        env.manager.status(id)
    );
    let elapsed = started.elapsed();

    // 跟随式那一跳碰过它一次；之后 redirect / redirect-scheme 都必须被熔断跳过。
    assert_eq!(
        dead.requests.lock().unwrap().len(),
        1,
        "同一台慢死主机只该被探测一次"
    );
    let rejected = event_details(&db, id, "alt_rejected");
    assert!(
        rejected.iter().any(|d| d.contains("reason=dead_host")),
        "熔断必须留痕: {rejected:?}"
    );
    // 四次超时的老行为要 8 秒起步；熔断后只剩最初那一次
    assert!(
        elapsed < Duration::from_secs(5),
        "不该为同一台死机器反复等超时: {elapsed:?}"
    );
}

#[test]
fn checksum_mismatch_blocks_completion_with_its_own_code() {
    // 上游 CHECKSUM 声明了整文件哈希，下完的内容却对不上 → 不能算完成。
    // 这正是"换过镜像 / 走过明文 http"时最后一道内容防线。
    let total = 256 * 1024usize;
    let body = Arc::new(pattern(total));
    let body_for_checksum = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path.starts_with("/CHECKSUM") {
            // 长度声明正确（否则整份清单不会被采信），但哈希是错的
            let text = format!(
                "# a.bin: {total} bytes\nSHA256 (a.bin) = {}\n",
                "0".repeat(64)
            );
            return Resp::ok(text.into_bytes());
        }
        if req.path.starts_with("/a.bin") {
            return ranged_mem(&body_for_checksum, req, true);
        }
        Resp::empty(404)
    }));
    let env = temp_env("sha256_mismatch");
    let id = add_with_alts(&env, &server.url("/a.bin"), "a.bin", "");

    assert!(
        until(Duration::from_secs(40), || {
            env.manager
                .status(id)
                .ok()
                .flatten()
                .map(|t| t.state == "error")
                .unwrap_or(false)
        }),
        "哈希不符必须失败: {:?}",
        env.manager.status(id)
    );

    let db = env.dir.join("db.sqlite");
    let conn = open_db(&db).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.error_code.as_deref(), Some("sha256_mismatch"));
    assert_eq!(row.finished_at, None, "没通过校验就不该有完成时间");
    assert_eq!(
        row.sha256_expected.as_deref(),
        Some("0".repeat(64).as_str()),
        "采信的清单要落库"
    );
    drop(conn);
    // 上游哈希先被记录，随后在校验时被判不符
    assert!(!event_details(&db, id, "checksum").is_empty());
    assert!(!event_details(&db, id, "sha256_mismatch").is_empty());
    assert!(
        event_details(&db, id, "done").is_empty(),
        "不该出现完成事件: {:?}",
        event_details(&db, id, "done")
    );
}

/// 从 `start` 事件里取出 `sources=N`（跨源聚合的来源池长度）。
fn start_sources(db: &std::path::Path, id: i64) -> usize {
    let details = event_details(db, id, "start");
    let d = details.last().unwrap_or_else(|| {
        panic!(
            "没有 start 事件，无法判断来源池：{:?}",
            event_details(db, id, "range_probe")
        )
    });
    d.split_whitespace()
        .find_map(|tok| tok.strip_prefix("sources="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("start 事件里没有 sources=：{d}"))
}

/// `alt.probe_min_size_mb`：小文件跳过跨源聚合，**对照组证明它真的被跳过了**。
///
/// 判据是 `start` 事件里的 `sources=` —— 它正是 `source_pool` 的产出长度。
/// 两个源都提供同一份内容（长度一致、都支持 Range），所以"没聚合"只可能是被
/// 阈值拦下的，而不是"找不到第二个源"。
#[test]
fn probe_min_size_skips_cross_source_discovery_for_small_files() {
    /// 跑一次两源任务，返回 (start 里的 sources, 文件内容)。
    fn run(tag: &str, min_size_mb: Option<&str>) -> (usize, Vec<u8>) {
        // 1 MiB：**必须大于最小段长**（否则 `plan_segments` 只给 1 段、任务降级
        // 成 `mode=single`，`source_pool` 根本不会被调用），同时仍小于 fastdl 的
        // 16 MiB 门槛，从而走多段路径。
        let total = 1024 * 1024usize;
        let body = Arc::new(pattern(total));
        let expect = {
            let f = std::io::Cursor::new(body.as_ref().clone());
            sha256_reader(f).unwrap()
        };
        let mk = || {
            let b = body.clone();
            TestServer::new(Arc::new(move |req: &Req| {
                if req.path.starts_with("/ms.bin") {
                    return ranged_mem(&b, req, true);
                }
                Resp::empty(404)
            }))
        };
        let a = mk();
        let b = mk();

        let env = temp_env(tag);
        env.manager.settings_set("proxy.mode", "none").unwrap();
        if let Some(v) = min_size_mb {
            env.manager
                .settings_set("alt.probe_min_size_mb", v)
                .unwrap();
        }
        let db_path = env.dir.join("db.sqlite");
        let save_dir = env.dir.join("downloads");
        std::fs::create_dir_all(&save_dir).unwrap();
        let primary = a.url("/ms.bin");
        let secondary = b.url("/ms.bin");
        let id = {
            let conn = open_db(&db_path).unwrap();
            let id = model::insert_download(
                &conn,
                &primary,
                "ms.bin",
                &save_dir.to_string_lossy(),
                0,
                4,
            )
            .unwrap();
            model::set_probe_meta(&conn, id, &primary, Some(total as i64), None, None).unwrap();
            model::set_alt_urls(&conn, id, Some(&secondary)).unwrap();
            model::set_sha256_expected(&conn, id, Some(&expect)).unwrap();
            model::set_status(&conn, id, Status::Paused, None).unwrap();
            id
        };
        env.manager.resume(id).unwrap();
        assert!(
            wait_state(&env.manager, id, "done", Duration::from_secs(60)),
            "两源任务应当能下完: {:?} events={:?}",
            env.manager.status(id),
            all_events(&db_path, id)
        );
        let n = start_sources(&db_path, id);
        let data = std::fs::read(env.dir.join("downloads").join("ms.bin")).unwrap();
        assert_eq!(data.len(), total);
        (n, data)
    }

    let (with_discovery, d1) = run("probe_min_off", None);
    assert_eq!(
        with_discovery, 2,
        "默认（阈值为 0）应当把第二个源也聚合进来，否则这个对照实验不成立"
    );

    let (skipped, d2) = run("probe_min_on", Some("100"));
    assert_eq!(
        skipped, 0,
        "文件 1 MiB 远小于 100 MiB 阈值 ⇒ 应当跳过镜像发现。\
         `source_pool` 的契约是「返回空 = 保持单源」，所以 `sources=` 记的是 0"
    );
    // 跳过发现不能改变**内容**：两份必须逐字节相同。
    assert_eq!(d1, d2, "跳过镜像发现不该影响下下来的字节");
}

/// HLS：清单 → 分片顺序下载 → 合并成一个文件。
///
/// 最关键的一条是**拼接顺序** —— 分片各自独立，顺序错了拼出来的文件就是坏的，
/// 而"下完了"这个状态会照常出现。所以这里用可区分的分片内容，逐字节比对。
#[test]
fn hls_playlist_segments_are_downloaded_and_concatenated_in_order() {
    let segs: Vec<Vec<u8>> = vec![pattern(3000), pattern(5000), pattern(7000)];
    let expected: Vec<u8> = segs.iter().flatten().copied().collect();
    let segs_for_server = segs.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/index.m3u8" {
            // 相对地址 —— 顺带验证清单里的相对 URI 会按清单地址补全。
            let text = "#EXTM3U\n#EXT-X-VERSION:3\n\
                        #EXTINF:4.0,\nseg0.ts\n#EXTINF:4.0,\nseg1.ts\n\
                        #EXTINF:4.0,\nseg2.ts\n#EXT-X-ENDLIST\n";
            return Resp::ok(text.as_bytes().to_vec());
        }
        for (i, body) in segs_for_server.iter().enumerate() {
            if req.path == format!("/seg{i}.ts") {
                return Resp::ok(body.clone());
            }
        }
        Resp::empty(404)
    }));
    let env = temp_env("hls_manifest");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = env
        .manager
        .add(&server.url("/index.m3u8"), None, Some("movie.ts"), None, 0)
        .unwrap();

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(60)),
        "HLS 任务应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let got = std::fs::read(env.dir.join("downloads").join("movie.ts")).unwrap();
    assert_eq!(got, expected, "合并后的字节必须等于三个分片按清单顺序拼接");
    // 清单事件要留痕：否则排查时看不出这是清单型任务、有几片。
    let ev = event_details(&env.dir.join("db.sqlite"), id, "manifest");
    assert!(
        ev.iter()
            .any(|d| d.contains("kind=hls") && d.contains("items=3")),
        "应当记一条 kind=hls items=3 的事件: {ev:?}"
    );
    // 完成后侧车要清掉，否则下次续传会拿旧进度。
    assert!(
        !env.dir
            .join("downloads")
            .join(".aidm")
            .join(id.to_string())
            .join("manifest.json")
            .exists(),
        "完成后不该留下清单侧车"
    );
}

/// 清单**解析成功**但分片取不回来时，失败必须归因到 `transfer` 而不是 `resolve`。
///
/// 为什么单列一条：`resolve`（取清单、展开分片）与 `transfer`（取分片）在同一个函数里
/// 前后相邻，标记加错层是很容易发生又很难发现的事 —— 归因错了，诊断包里这一段耗时会
/// 记到错误的阶段上，而任务状态、错误码**看起来都正常**。所以只在"清单层失败"上做断言
/// 不足以证明分片层也标的对。
#[test]
fn manifest_segment_failure_is_attributed_to_transfer() {
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/index.m3u8" {
            // 清单本身完全正常，是分片 404。
            let text = "#EXTM3U\n#EXT-X-VERSION:3\n\
                        #EXTINF:4.0,\nseg0.ts\n#EXTINF:4.0,\nmissing.ts\n#EXT-X-ENDLIST\n";
            return Resp::ok(text.as_bytes().to_vec());
        }
        if req.path == "/seg0.ts" {
            return Resp::ok(pattern(1024));
        }
        Resp::empty(404)
    }));
    let env = temp_env("hls_seg_fail");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = env
        .manager
        .add(
            &server.url("/index.m3u8"),
            None,
            Some("partial.ts"),
            None,
            0,
        )
        .unwrap();

    assert!(
        wait_state(&env.manager, id, "error", Duration::from_secs(60)),
        "分片取不回来就该失败，不能出个半截文件报完成: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.error_code.as_deref(),
        Some("http_404"),
        "机器码要归一成 HTTP 状态族；**不得**把内嵌完整 URL 的原始错误串当机器码"
    );
    let phase: String = conn
        .query_row(
            "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='error' \
             ORDER BY id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    assert!(
        phase.contains("phase=transfer"),
        "分片取回失败必须归因到 transfer（归到 resolve 会把阶段耗时记错）: {phase}"
    );
    // "是哪一片、什么原因"只能从事件里看 —— 机器码已经不带地址了，所以这条事件
    // 不是"锦上添花"，而是失败现场的唯一落点。
    let detail = event_details(&env.dir.join("db.sqlite"), id, "manifest");
    assert!(
        detail.iter().any(|d| d.contains("segment_failed")),
        "应当记一条 segment_failed 事件: {detail:?}"
    );
    // 半截文件不能被当成成品：任务失败时不该留下最终文件。
    assert!(
        !env.dir.join("downloads").join("partial.ts").exists(),
        "失败的任务不该留下不完整的最终文件"
    );
}

/// 清单**写盘**失败必须归因到 `store`，且不该产出最终文件。
///
/// 与 HTTP 路径的 `simulated_disk_full_emits_disk_full` 并列：那条走分段写池，这条走
/// 清单路径自己的 `write_all_checked` —— 两条不同的落盘路径，阶段标记各写一处，
/// 只测其中一条不能说明另一条也对。
#[test]
fn manifest_write_failure_is_attributed_to_store() {
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/index.m3u8" {
            let text = "#EXTM3U\n#EXT-X-VERSION:3\n\
                        #EXTINF:4.0,\nseg0.ts\n#EXT-X-ENDLIST\n";
            return Resp::ok(text.as_bytes().to_vec());
        }
        Resp::ok(pattern(2048))
    }));
    let env = temp_env("manifest_store");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    // 不退避：这里要的是"一次写盘失败"的归因，不是退避行为。
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::DiskFull);
    let id = env
        .manager
        .add(
            &server.url("/index.m3u8"),
            None,
            Some("nospace.ts"),
            None,
            0,
        )
        .unwrap();

    assert!(
        wait_state(&env.manager, id, "error", Duration::from_secs(60)),
        "写盘失败就该失败: {:?}",
        env.manager.status(id)
    );
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.error_code.as_deref(),
        Some("disk_full"),
        "写盘失败要归一成既有的 disk_full（而不是一个只有清单路径认识的新码）"
    );
    let phase: String = conn
        .query_row(
            "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='error' \
             ORDER BY id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    assert!(
        phase.contains("phase=store"),
        "写盘失败必须归因到 store: {phase}"
    );
    assert!(
        !env.dir.join("downloads").join("nospace.ts").exists(),
        "写盘失败不该产出最终文件"
    );
}

/// 清单任务失败后重试必须**接着下**，而不是把已下好的分片再下一遍。
///
/// 为什么单列一条：分片写进 `<保存目录>/.aidm/<id>/` 下的**工作文件**，完成时才改名成
/// 最终文件；"下到第几片、写了多少字节"记在侧车里。只测成功路径证明不了这套记账是准的
/// —— 记账错了的表现是**内容错位**（新分片接在旧数据中间）、或者重复下载，而任务照样报
/// 完成。所以这里断言的是"seg0 只被取过一次"＋"最终字节恰好是两片按序拼接"。
#[test]
fn manifest_retry_resumes_from_the_work_file_instead_of_restarting() {
    let seg0 = pattern(3000);
    let seg1 = pattern(5000);
    let mut expected = seg0.clone();
    expected.extend_from_slice(&seg1);

    // 第一次取 seg1 时回 404（模拟分片临时不可用），之后放行。
    let seg1_hits = Arc::new(AtomicU64::new(0));
    let seg0_hits = Arc::new(AtomicU64::new(0));
    let (s1_hits, s0_hits) = (seg1_hits.clone(), seg0_hits.clone());
    let (s0, s1) = (seg0.clone(), seg1.clone());
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/index.m3u8" {
            let text = "#EXTM3U\n#EXT-X-VERSION:3\n\
                        #EXTINF:4.0,\nseg0.ts\n#EXTINF:4.0,\nseg1.ts\n#EXT-X-ENDLIST\n";
            return Resp::ok(text.as_bytes().to_vec());
        }
        if req.path == "/seg0.ts" {
            s0_hits.fetch_add(1, Ordering::SeqCst);
            return Resp::ok(s0.clone());
        }
        if req.path == "/seg1.ts" {
            if s1_hits.fetch_add(1, Ordering::SeqCst) == 0 {
                return Resp::empty(404);
            }
            return Resp::ok(s1.clone());
        }
        Resp::empty(404)
    }));

    let env = temp_env("hls_resume");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = env
        .manager
        .add(
            &server.url("/index.m3u8"),
            None,
            Some("resumed.ts"),
            None,
            0,
        )
        .unwrap();

    assert!(
        wait_state(&env.manager, id, "error", Duration::from_secs(60)),
        "第二片取不回来就该失败: {:?}",
        env.manager.status(id)
    );
    let final_path = env.dir.join("downloads").join("resumed.ts");
    assert!(
        !final_path.exists(),
        "失败时保存目录里不该出现与成品同名的半截文件"
    );
    // 已下好的那一片留在工作文件里（这就是"能续传"的证据）。
    let part = env
        .dir
        .join("downloads")
        .join(".aidm")
        .join(id.to_string())
        .join(".resumed.ts.manifest.part");
    assert!(part.exists(), "工作文件应当保留，供下次续传: {part:?}");
    assert_eq!(
        std::fs::metadata(&part).unwrap().len(),
        seg0.len() as u64,
        "工作文件此时应当恰好是第一片的字节数"
    );

    assert_eq!(
        env.manager.retry_failed().unwrap(),
        1,
        "应当有一个待重试任务"
    );
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(60)),
        "重试应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    assert_eq!(
        std::fs::read(&final_path).unwrap(),
        expected,
        "重试后的最终字节必须是两片按序拼接"
    );
    assert_eq!(
        seg0_hits.load(Ordering::SeqCst),
        1,
        "第一片已经在工作文件里了，重试**不该**再取一次（否则就不是续传）"
    );
    assert!(
        !part.exists(),
        "完成后工作文件应当被改名成最终文件，不留下副本"
    );
}

// ---------- zsync ----------

/// 测试侧**独立**实现的控制文件编码器。
///
/// 刻意不复用产品代码：只有编码器与解码器是两条独立实现时，"能读回自己写的东西"才
/// 构成证据（同一份代码自编自解只能证明它自洽）。格式规则与 `zsync-rs 0.2.1` 一致：
/// 块表每项 = `rsum_bytes` 字节弱校验和（大端，按长度截断）+ `checksum_bytes` 字节
/// MD4 前缀；尾块**补零到整块**再算。
fn zsync_control_file(
    target: &[u8],
    blocksize: usize,
    rsum_bytes: u8,
    checksum_bytes: u8,
    sha1_hex: Option<&str>,
    content_url: &str,
) -> Vec<u8> {
    let mut head = String::from("zsync: 0.6.2\n");
    head.push_str("Filename: target.bin\n");
    head.push_str(&format!("Blocksize: {blocksize}\n"));
    head.push_str(&format!("Length: {}\n", target.len()));
    head.push_str(&format!("Hash-Lengths: 1,{rsum_bytes},{checksum_bytes}\n"));
    head.push_str(&format!("URL: {content_url}\n"));
    if let Some(s) = sha1_hex {
        head.push_str(&format!("SHA-1: {s}\n"));
    }
    head.push('\n');
    let mut out = head.into_bytes();

    for chunk in target.chunks(blocksize) {
        let mut padded = chunk.to_vec();
        padded.resize(blocksize, 0);
        // rsync 滚动弱校验和
        let mut a: u16 = 0;
        let mut b: u16 = 0;
        for &byte in &padded {
            a = a.wrapping_add(u16::from(byte));
            b = b.wrapping_add(a);
        }
        match rsum_bytes {
            1 => out.push(b as u8),
            2 => out.extend_from_slice(&b.to_be_bytes()),
            3 => {
                out.push((a >> 8) as u8);
                out.extend_from_slice(&b.to_be_bytes());
            }
            _ => {
                out.extend_from_slice(&a.to_be_bytes());
                out.extend_from_slice(&b.to_be_bytes());
            }
        }
        // MD4 走 aidm-core 的公开实现（它已由 eD2k 那套公开向量钉住），只取前 N 字节
        let strong = aidm_core::ed2k::hash::md4(&padded);
        out.extend_from_slice(&strong[..checksum_bytes as usize]);
    }
    out
}

fn sha1_hex_of(data: &[u8]) -> String {
    use ring::digest;
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// zsync：只取**缺失块**，绝不整份重下，也不碰用户的旧文件。
///
/// 这条用例同时守四件事：
/// 1. 认得出 `.zsync` 并**不**把控制文件本身当下载目标；
/// 2. 种子（本地旧文件）里已有的块**不重新请求** —— 用服务端记下的 Range 头来判；
/// 3. 最终文件逐字节等于目标；
/// 4. 整文件 SHA-1 对得上（控制文件里声明了）。
#[test]
fn zsync_fetches_only_the_missing_blocks() {
    let bs = 64usize;
    let target: Vec<u8> = (0..640u32).map(|i| (i % 211) as u8).collect();
    // 种子：与目标只有第 3 块（192..256）不同 —— 其余 9 块应当一个都不请求。
    let mut seed = target.clone();
    for b in seed[3 * bs..4 * bs].iter_mut() {
        *b ^= 0xFF;
    }
    let ranges = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = ranges.clone();
    let t = target.clone();
    let sha1 = sha1_hex_of(&target);
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/target.bin.zsync" {
            // 绝对内容地址靠 `Host` 头拼（端口在 bind 之后才知道）；这样也顺带覆盖
            // "优先用控制文件里声明的 URL"这条分支。
            let host = req.headers.get("host").cloned().unwrap_or_default();
            let url = format!("http://{host}/target.bin");
            return Resp::ok(zsync_control_file(&t, bs, 4, 16, Some(&sha1), &url));
        }
        // 内容：必须支持按区间取，否则这条路径无从谈起。
        if req.path == "/target.bin" {
            let range = req.headers.get("range").cloned();
            seen.lock().unwrap().push(range.clone().unwrap_or_default());
            return ranged_mem(&Arc::new(t.clone()), req, true);
        }
        Resp::empty(404)
    }));

    let env = temp_env("zsync");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    // 本地旧文件先放在保存目录里当种子。
    let save_dir = env.dir.join("downloads");
    std::fs::create_dir_all(&save_dir).unwrap();
    std::fs::write(save_dir.join("target.bin"), &seed).unwrap();

    let id = env
        .manager
        .add(&server.url("/target.bin.zsync"), None, None, None, 0)
        .unwrap();
    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(60)),
        "zsync 任务应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );

    // 3. 最终文件逐字节等于目标
    assert_eq!(
        std::fs::read(save_dir.join("target.bin")).unwrap(),
        target,
        "补齐后的文件必须与目标逐字节相同"
    );
    // 2. 只请求了缺失的那一块
    let got = ranges.lock().unwrap().clone();
    assert!(
        !got.is_empty(),
        "至少要取一次缺块；实际一次都没请求说明整份都被当成已有"
    );
    for r in &got {
        assert!(
            r.starts_with("bytes=192-255"),
            "只应请求改过的那一块（192..256），实际请求了 {r}"
        );
    }
    assert!(
        got.len() <= 2,
        "同一个缺失区间不该被反复请求（允许多一次是因为探测），实际 {} 次: {got:?}",
        got.len()
    );
    // 任务名去掉了 `.zsync` 后缀（内容是 target.bin，不是控制文件）
    let t = env.manager.status(id).unwrap().unwrap();
    assert!(
        t.save_path.ends_with("target.bin"),
        "最终文件名应当是去掉 .zsync 的内容名: {}",
        t.save_path
    );
    // 4. 留痕：控制文件的解析结果要能解释"为什么只下了这么点"
    let ev = event_details(&env.dir.join("db.sqlite"), id, "zsync");
    assert!(
        ev.iter().any(|d| d.contains("missing_ranges=1")),
        "应当记一条 zsync 事件说明缺了 1 段: {ev:?}"
    );
}

/// zsync 的整文件 SHA-1 不符必须**失败**，并且**不产出最终文件**。
///
/// 这里刻意给一个错的 SHA-1：正的路径（给对的值）需要测试自己算 SHA-1，而错的这条
/// 已经能证明"比较确实执行了、且不符会被拦下"——这才是这条分支的意义。
#[test]
fn zsync_sha1_mismatch_fails_without_producing_a_file() {
    let bs = 64usize;
    let target: Vec<u8> = (0..256u32).map(|i| (i % 173) as u8).collect();
    let t = target.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/t.bin.zsync" {
            let host = req.headers.get("host").cloned().unwrap_or_default();
            let url = format!("http://{host}/t.bin");
            // 全 0 的 SHA-1：一定不符（真实内容的 SHA-1 不可能是全 0）。
            // 正的路径需要测试自己算 SHA-1，而"不符会被拦下"才是这条分支的意义所在。
            return Resp::ok(zsync_control_file(
                &t,
                bs,
                4,
                16,
                Some(&"0".repeat(40)),
                &url,
            ));
        }
        if req.path == "/t.bin" {
            return ranged_mem(&Arc::new(t.clone()), req, true);
        }
        Resp::empty(404)
    }));

    let env = temp_env("zsync_sha1");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    let id = env
        .manager
        .add(&server.url("/t.bin.zsync"), None, None, None, 0)
        .unwrap();
    assert!(
        wait_state(&env.manager, id, "error", Duration::from_secs(60)),
        "SHA-1 不符就该失败: {:?}",
        env.manager.status(id)
    );
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.error_code.as_deref(),
        Some("zsync_sha1_mismatch"),
        "要能与「内容不完整」区分开"
    );
    assert!(
        !env.dir.join("downloads").join("t.bin").exists(),
        "校验不过就不该产出最终文件"
    );
    let phase: String = conn
        .query_row(
            "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='error' \
             ORDER BY id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    assert!(
        phase.contains("phase=verify"),
        "整文件校验失败属于 verify 阶段: {phase}"
    );
}

/// DASH：MPD 的模板展开 → 初始化段 + 分片顺序下载 → 合并。
///
/// 与 HLS 那条并列，因为**两者是两条不同的解析器**：DASH 走 `SegmentTemplate`
/// 模板展开（`$Number%03d$`），HLS 走逐行分片列表。只测其中一个不能说明另一个也通。
///
/// 初始化段必须**排在最前** —— 顺序错了拼出来的 fMP4 无法解码，而任务会照常报"完成"。
#[test]
fn dash_manifest_expands_template_and_orders_init_first() {
    let init: Vec<u8> = vec![0x11; 128];
    let segs: Vec<Vec<u8>> = vec![pattern(2000), pattern(4000)];
    let mut expected = init.clone();
    for s in &segs {
        expected.extend_from_slice(s);
    }
    let (init_c, segs_c) = (init.clone(), segs.clone());
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/stream.mpd" {
            // 时长 8 秒、每片 4 秒 ⇒ 2 片；`%03d` 补零由模板展开负责。
            let mpd = "<MPD mediaPresentationDuration=\"PT8S\">\
                       <Period><AdaptationSet mimeType=\"video/mp4\">\
                       <SegmentTemplate initialization=\"init.mp4\" \
                       media=\"chunk-$Number%03d$.m4s\" startNumber=\"1\" \
                       duration=\"4\" timescale=\"1\"/>\
                       <Representation id=\"v0\" bandwidth=\"100\"/>\
                       </AdaptationSet></Period></MPD>";
            return Resp::ok(mpd.as_bytes().to_vec());
        }
        if req.path == "/init.mp4" {
            return Resp::ok(init_c.clone());
        }
        for (i, body) in segs_c.iter().enumerate() {
            // 注意连字符：模板是 `chunk-$Number%03d$.m4s`，`-` 是字面字符，
            // `%03d` 只作用于 `$Number$`，所以展开结果是 `chunk-001.m4s`。
            if req.path == format!("/chunk-{:03}.m4s", i + 1) {
                return Resp::ok(body.clone());
            }
        }
        Resp::empty(404)
    }));
    let env = temp_env("dash_manifest");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = env
        .manager
        .add(&server.url("/stream.mpd"), None, Some("movie.mp4"), None, 0)
        .unwrap();

    assert!(
        wait_state(&env.manager, id, "done", Duration::from_secs(60)),
        "DASH 任务应当能下完: {:?} events={:?}",
        env.manager.status(id),
        all_events(&env.dir.join("db.sqlite"), id)
    );
    let got = std::fs::read(env.dir.join("downloads").join("movie.mp4")).unwrap();
    assert_eq!(
        got, expected,
        "合并结果必须是 [初始化段] + [按序分片]；顺序错了 fMP4 无法解码，而任务仍会报完成"
    );
    let ev = event_details(&env.dir.join("db.sqlite"), id, "manifest");
    assert!(
        ev.iter()
            .any(|d| d.contains("kind=dash") && d.contains("items=3")),
        "应当记一条 kind=dash items=3 的事件（init + 2 片）: {ev:?}"
    );
}

/// DASH 的 `ContentProtection`（DRM）同样必须**明确失败**。
///
/// 与 HLS 的加密清单是同一类风险：照下会得到一个装满加密数据的"完成"文件。
#[test]
fn drm_dash_fails_instead_of_producing_garbage() {
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/drm.mpd" {
            let mpd = "<MPD><Period><AdaptationSet>\
                       <ContentProtection schemeIdUri=\"urn:mpeg:dash:mp4protection:2011\"/>\
                       <SegmentTemplate media=\"s$Number$.m4s\" duration=\"2\" timescale=\"1\"/>\
                       <Representation id=\"a\" bandwidth=\"1\"/>\
                       </AdaptationSet></Period></MPD>";
            return Resp::ok(mpd.as_bytes().to_vec());
        }
        Resp::empty(404)
    }));
    let env = temp_env("dash_drm");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = env
        .manager
        .add(&server.url("/drm.mpd"), None, Some("drm.mp4"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager
                .status(id)
                .ok()
                .flatten()
                .map(|t| t.state == "error")
                .unwrap_or(false)
        }),
        "DRM 清单应当失败: {:?}",
        env.manager.status(id)
    );
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(row.error_code.as_deref(), Some("dash_encrypted"));
    // 同 `encrypted_hls_...`：DASH 与 HLS 走同一条清单路径，阶段也必须是 resolve。
    let phase: String = conn
        .query_row(
            "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='error' \
             ORDER BY id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    assert!(
        phase.contains("phase=resolve"),
        "清单展开失败应当归因到 resolve：{phase}"
    );
}

/// HLS 加密清单必须**明确失败**，而不是下出一个装满密文的"完成"文件。
#[test]
fn encrypted_hls_fails_instead_of_producing_garbage() {
    let server = TestServer::new(Arc::new(move |req: &Req| {
        if req.path == "/enc.m3u8" {
            let text = "#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"k.bin\"\n\
                        #EXTINF:4.0,\nseg0.ts\n#EXT-X-ENDLIST\n";
            return Resp::ok(text.as_bytes().to_vec());
        }
        if req.path == "/seg0.ts" {
            return Resp::ok(vec![0xAB; 512]);
        }
        Resp::empty(404)
    }));
    let env = temp_env("hls_encrypted");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    let id = env
        .manager
        .add(&server.url("/enc.m3u8"), None, Some("enc.ts"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager
                .status(id)
                .ok()
                .flatten()
                .map(|t| t.state == "error")
                .unwrap_or(false)
        }),
        "加密清单应当失败: {:?}",
        env.manager.status(id)
    );
    let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
    let row = model::get_download(&conn, id).unwrap().unwrap();
    assert_eq!(
        row.error_code.as_deref(),
        Some("hls_encrypted"),
        "错误码要能告诉用户为什么下不了"
    );
    // 阶段归因：清单取回与展开属于 `resolve`。规格 R-OBS-01 禁止"失败但阶段未知"，
    // R-OBS-10 要求失败行带 `phase=<阶段>:` 且 `classify` 剥标记后**机器码不变**——
    // 上面那条断言与这条一起，正好把"标记被正确剥离、又真的起了归因作用"钉住。
    let phase: String = conn
        .query_row(
            "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='error' \
             ORDER BY id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    assert!(
        phase.contains("phase=resolve"),
        "清单展开失败应当归因到 resolve：{phase}"
    );
}

// ---------------------------------------------------------------- C2 写盘拦截

fn dir_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for e in rd.flatten() {
        let p = e.path();
        match e.metadata() {
            Ok(m) if m.is_dir() => total += dir_bytes(&p),
            Ok(m) => total += m.len(),
            Err(_) => {}
        }
    }
    total
}

/// 退出条件：**暂停返回后不得再写入一字节**。
///
/// 这测的是真实写盘入口（`try_segment_once` 里 `write_all_checked` 之前）的许可检查，
/// 不是“命令已入队”或“pause 标志已置位”。用慢速滴灌保证暂停时刻确实有写入在跑。
#[test]
fn pause_returns_only_after_writes_really_stop() {
    let server = TestServer::new(Arc::new(|_req: &Req| {
        Resp::ok(pattern(1024 * 1024)).slow(16 * 1024, Duration::from_millis(30))
    }));
    let env = temp_env("c2_pause_quiesce");
    let id = env
        .manager
        .add(&server.url("/a.bin"), None, Some("a.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(20), || {
            env.manager
                .status(id)
                .unwrap()
                .unwrap()
                .done
                > 0
        }),
        "应先有真实写入：{:?}",
        env.manager.status(id)
    );

    env.manager.pause(id).expect("pause");
    let gate = env.manager.write_gate(id).expect("gate");
    assert_eq!(
        gate.in_flight(),
        0,
        "暂停返回时不允许还有在途写入（静止确认没做完）"
    );
    assert_eq!(
        gate.active_leases(),
        0,
        "暂停后不得有未撤销的写入许可"
    );

    let parts = env.dir.join("downloads").join(".aidm").join(id.to_string());
    let at_pause = dir_bytes(&parts);
    std::thread::sleep(Duration::from_millis(700));
    let after = dir_bytes(&parts);
    assert_eq!(
        after, at_pause,
        "暂停返回后仍在写盘：{} → {} 字节",
        at_pause, after
    );
}

/// 退出条件：**旧回调（旧轮次/被撤销的许可）没有写权**。
///
/// 在真实任务上验证：拿到许可 → 撤销 → 同一份凭据再检查必须被拒。
/// 这保证“暂停/删除之后，之前拿到的凭据不能再写”。
#[test]
fn revoked_lease_cannot_write_on_a_live_task() {
    use aidm_core::download::control::WriteDecision;
    use aidm_core::download::model::{AssignmentId, SliceId, Span};

    let server = TestServer::new(Arc::new(|_req: &Req| {
        Resp::ok(pattern(256 * 1024)).slow(16 * 1024, Duration::from_millis(30))
    }));
    let env = temp_env("c2_revoked_lease");
    let id = env
        .manager
        .add(&server.url("/b.bin"), None, Some("b.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(20), || {
            env.manager
                .status(id)
                .unwrap()
                .unwrap()
                .done
                > 0
        }),
        "应先有真实写入"
    );

    let gate = env.manager.write_gate(id).expect("gate");
    let lease = gate.issue(
        AssignmentId::new("test-assignment"),
        SliceId::new("test-slice"),
        Span::known(0, 4096).expect("span"),
    );
    assert!(gate.check(&lease, 0, 1024).is_ok(), "新许可应放行");
    gate.revoke_all_quiescent(Duration::from_secs(2))
        .expect("quiesce");
    assert_eq!(
        gate.check(&lease, 0, 1024).unwrap_err(),
        WriteDecision::Revoked,
        "撤销后的旧凭据必须失去写权"
    );

    // 真实任务也停了：撤销等价于断写入。
    env.manager.pause(id).expect("pause");
}

/// 核心证据：**写盘检查本身能停住下载**。
///
/// 这个用例故意**不置 pause 标志**，只撤销写入许可：
/// - 若检查不在真实写盘路径上，文件会继续增长、`write_denied_count` 保持 0；
/// - 若检查生效，下一个数据块写入前就被拒，段线程按暂停退出。
///
/// 这正是“覆盖实际写盘入口，而不是只检查命令入队”的验收方式。
#[test]
fn revoking_write_lease_stops_download_without_the_pause_flag() {
    let server = TestServer::new(Arc::new(|_req: &Req| {
        Resp::ok(pattern(1024 * 1024)).slow(16 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("c2_lease_stop");
    let id = env
        .manager
        .add(&server.url("/lease.bin"), None, Some("lease.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入：{:?}",
        env.manager.status(id)
    );

    let gate = env.manager.write_gate(id).expect("gate");
    assert!(gate.active_leases() > 0, "运行中的任务必须有写入许可");
    gate.revoke_all_quiescent(Duration::from_secs(2))
        .expect("quiesce");

    // 直接看事件：`paused` + `reason=write_lease_revoked` 是写盘检查自己写下的，
    // 命令入队、pause 标志都不会产生它。
    let db_path = env.dir.join("db.sqlite");
    assert!(
        until(Duration::from_secs(10), || {
            let Ok(conn) = aidm_core::open_db(&db_path) else {
                return false;
            };
            conn.query_row(
                "SELECT count(*) FROM events
                 WHERE download_id = ?1 AND kind = 'paused'
                   AND detail LIKE '%write_lease_revoked%'",
                [id],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
        }),
        "许可撤销后必须由写盘检查留下 paused/write_lease_revoked 证据"
    );

    let parts = env.dir.join("downloads").join(".aidm").join(id.to_string());
    // P2-a-03：被拒路径必须**落状态**，不能只返回 `WorkerEnd::Paused`。
    // 主循环对 `Paused` 只写 tracing 不改库，漏掉落状态的任务会停在
    // Downloading，调度器反复拉起、反复被拒。
    assert!(
        until(Duration::from_secs(10), || {
            env.manager.status(id).unwrap().unwrap().state == "paused"
        }),
        "许可撤销后任务必须落到 paused：{:?}",
        env.manager.status(id)
    );
    let after_exit = dir_bytes(&parts);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        dir_bytes(&parts),
        after_exit,
        "许可撤销后不得再有写入"
    );
}

/// P1-01 的真实路径复验：**暂停返回之后**，同一任务再签发许可也拿不到写权。
///
/// 这条对应“段线程刚起来/单连接刚要开跑”读到的是暂停完成后的闸门：
/// 撤销已经宣布完成，迟到的 `issue` 必须当场作废，不能出现“暂停了还在下载”。
#[test]
fn after_pause_the_task_gate_refuses_new_leases() {
    use aidm_core::download::control::WriteDecision;
    use aidm_core::download::model::{AssignmentId, SliceId, Span};

    let server = TestServer::new(Arc::new(|_req: &Req| {
        Resp::ok(pattern(1024 * 1024)).slow(16 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("c2_late_issue");
    let id = env
        .manager
        .add(&server.url("/late.bin"), None, Some("late.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入"
    );

    env.manager.pause(id).expect("pause");

    let gate = env.manager.write_gate(id).expect("gate");
    let late = gate.issue(
        AssignmentId::new("late-arrival"),
        SliceId::new("late-arrival"),
        Span::known(0, 4096).expect("span"),
    );
    assert_eq!(
        gate.check(&late, 0, 1024).unwrap_err(),
        WriteDecision::Revoked,
        "暂停完成后签发的许可必须当场作废"
    );
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(
        env.manager.pause_stragglers(id),
        0,
        "正常暂停不应遗留未退出的写入"
    );
}

/// P1-02 回归：**未知长度**（chunked / 无 `Content-Length`）的下载不能被误判成暂停。
///
/// 许可区间若写成 `Span::known(0, total.unwrap_or(0).max(1))`，`None` 会变成
/// `Some([0,1))`：预检放行，第一块 64 KiB 写入就因 `OutOfRange` 被拒，
/// 于是任何一个 chunked 下载在 unified 路径下第一次写盘就"暂停"。
#[test]
fn unknown_length_download_is_not_mistaken_for_a_pause() {
    let server = TestServer::new(Arc::new(|_req: &Req| {
        Resp::chunked(pattern(256 * 1024))
    }));
    let env = temp_env("c2_unknown_len");
    let id = env
        .manager
        .add(&server.url("/chunked.bin"), None, Some("chunked.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "无 Content-Length 的下载必须正常完成：{:?}",
        env.manager.status(id)
    );

    let db_path = env.dir.join("db.sqlite");
    let conn = aidm_core::open_db(&db_path).expect("db");
    let denied: i64 = conn
        .query_row(
            "SELECT count(*) FROM events
             WHERE download_id = ?1 AND detail LIKE '%write_lease_revoked%'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(denied, 0, "未知长度不得触发写盘许可拒绝");
}

/// C3-a 退出条件：**legacy 算出的切片方案与 `download_slices` 表里的方案逐字节相同**。
///
/// 这条是「接管切片决策权」的前置证明：只有当两条来源能投影出同一串字节，
/// 后面把决策权从 worker 搬到协调器才谈得上“没改语义”。
/// 顺带钉死最容易错的差一：`plan_segments` 返回**闭区间**，表里存**左闭右开**。
#[test]
fn legacy_plan_and_download_slices_table_agree_byte_for_byte() {
    // 必须支持 Range，否则探测会判 no_range → 退化成单连接，测不到“切片方案”。
    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(2 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(10))
    }));
    let env = temp_env("c3a_plan");
    // 2 MiB / 256 KiB 上限 8 段；给 4 个连接预算，期望切成 4 段。
    env.manager
        .settings_set("conn.global_conn_cap", "4")
        .expect("set cap");
    let id = env
        .manager
        .add(&server.url("/plan.bin"), None, Some("plan.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入：{:?}",
        env.manager.status(id)
    );

    let total = 2u64 * 1024 * 1024;
    let view = env.manager.status(id).unwrap().unwrap();
    let segs = view.segments.expect("segments");
    let n = segs.len();
    assert!(n >= 2, "2 MiB 至少要切两段，实际 {n}");

    let db = aidm_core::open_db(&env.dir.join("db.sqlite")).expect("db");
    // 版本只有一个来源：`download_runtime.plan_revision`，表里的同名列是它的镜像。
    let runtime = aidm_core::download::store::load_runtime(&db, id)
        .expect("runtime")
        .expect("row");
    let last = runtime.plan_revision;
    let rows = aidm_core::download::store::load_plan(&db, id, last).expect("load plan");
    assert_eq!(
        rows.len(),
        n,
        "表里的切片数必须与执行段数一致（表 {last} 版）"
    );

    let got = aidm_core::download::plan::project_rows(
        &rows
            .iter()
            .map(|r| (r.span_start, r.span_end_exclusive))
            .collect::<Vec<_>>(),
    );
    // 段数确定后切分只依赖段数，所以用实际段数反推与用 desired 等价。
    let expect = aidm_core::download::plan::project_legacy(total, n as u32);
    assert_eq!(
        got, expect,
        "legacy 方案与 download_slices 必须逐字节相同\n表: {got}\n算: {expect}"
    );

    // 再和执行用的 segment 表对一次：三方一致才算真的没改语义。
    let expect_segments: Vec<(u64, Option<u64>)> = segs
        .iter()
        .map(|s| (s.pos_start as u64, s.pos_end.map(|e| e as u64 + 1)))
        .collect();
    assert_eq!(
        aidm_core::download::plan::project_rows(&expect_segments),
        expect,
        "执行段表也必须和方案一致"
    );

    // 镜像校验：表里的 `plan_revision` 必须等于 runtime 的（单一来源）。
    let mirrored: i64 = db
        .query_row(
            "SELECT max(plan_revision) FROM download_slices WHERE task_id = ?1",
            [id],
            |r| r.get(0),
        )
        .expect("max");
    assert_eq!(
        mirrored as u64, last,
        "download_slices.plan_revision 必须镜像 runtime，不得各自递增"
    );

    env.manager.pause(id).ok();
}

/// C3-a B 步：worker 必须**读表优先**——表里有当前版本且恰好覆盖全文件的方案，
/// 就按表执行，而不是重新 `plan_segments`。
///
/// 判据是「段数变了」：默认预算会切 4 段，预置方案是 2 段。
#[test]
fn worker_prefers_a_persisted_plan_over_recomputing() {
    use aidm_core::download::store;

    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(2 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(10))
    }));
    let env = temp_env("c3a_read_table");
    env.manager
        .settings_set("conn.global_conn_cap", "4")
        .expect("cap");
    let id = env
        .manager
        .add(&server.url("/rt.bin"), None, Some("rt.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入"
    );
    env.manager.pause(id).expect("pause");

    // 预置一个 2 段方案并推进版本。
    let db_path = env.dir.join("db.sqlite");
    {
        let mut db = aidm_core::open_db(&db_path).expect("db");
        store::ensure_runtime(&db, id).expect("runtime");
        let rev = store::bump_plan_revision(&mut db, id).expect("bump");
        let total = 2 * 1024 * 1024u64;
        let half = total / 2;
        let rows = vec![
            store::SliceRow {
                slice_id: format!("task-{id}-seg-0"),
                resource_id: format!("task-{id}"),
                span_start: 0,
                span_end_exclusive: Some(half),
                state: "pending".into(),
            },
            store::SliceRow {
                slice_id: format!("task-{id}-seg-1"),
                resource_id: format!("task-{id}"),
                span_start: half,
                span_end_exclusive: Some(total),
                state: "pending".into(),
            },
        ];
        assert!(store::save_plan(&mut db, id, 0, rev, &rows).expect("save plan"));
    }

    env.manager.restart(id).expect("restart");
    assert!(
        until(Duration::from_secs(30), || {
            let st = env.manager.status(id).unwrap().unwrap();
            st.segments.as_ref().map(|s| s.len()) == Some(2)
        }),
        "必须按表里的 2 段方案执行，而不是重算成 4 段：{:?}",
        env.manager
            .status(id)
            .unwrap()
            .unwrap()
            .segments
            .map(|s| s.len())
    );
    env.manager.cancel(id).ok();
}

/// 表里的方案**与文件大小不匹配**时必须回退重算，不能拿来就用。
///
/// 用错方案会把字节写到错误位置，所以宁可丢弃表、重新规划。
#[test]
fn worker_ignores_a_persisted_plan_that_does_not_cover_the_file() {
    use aidm_core::download::store;

    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(2 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(10))
    }));
    let env = temp_env("c3a_bad_table");
    env.manager
        .settings_set("conn.global_conn_cap", "4")
        .expect("cap");
    let id = env
        .manager
        .add(&server.url("/bad.bin"), None, Some("bad.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入"
    );
    env.manager.pause(id).expect("pause");

    // 只覆盖前 1000 字节：对 2 MiB 的文件来说是残缺方案。
    let db_path = env.dir.join("db.sqlite");
    {
        let mut db = aidm_core::open_db(&db_path).expect("db");
        store::ensure_runtime(&db, id).expect("runtime");
        let rev = store::bump_plan_revision(&mut db, id).expect("bump");
        let rows = vec![store::SliceRow {
            slice_id: format!("task-{id}-seg-0"),
            resource_id: format!("task-{id}"),
            span_start: 0,
            span_end_exclusive: Some(1000),
            state: "pending".into(),
        }];
        assert!(store::save_plan(&mut db, id, 0, rev, &rows).expect("save plan"));
    }

    env.manager.restart(id).expect("restart");
    assert!(
        until(Duration::from_secs(30), || {
            let st = env.manager.status(id).unwrap().unwrap();
            st.segments.as_ref().map(|s| s.len()) == Some(4)
        }),
        "残缺方案必须被丢弃并重算成 4 段：{:?}",
        env.manager
            .status(id)
            .unwrap()
            .unwrap()
            .segments
            .map(|s| s.len())
    );
    env.manager.cancel(id).ok();
}

/// 裁决 2：unified 模式下 worker **不许自算切片方案**。
///
/// 自算就是「unified 名义、legacy 决策」，正是文档 12.2 禁止的双归属。
/// 表里没有方案时只能停下并如实报 `plan_missing`。
#[test]
fn unified_mode_pauses_instead_of_planning_by_itself() {
    use aidm_core::download::control::ExecutionMode;
    use aidm_core::download::store;

    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(2 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(10))
    }));
    let env = temp_env("c3a_unified_no_plan");
    env.manager
        .settings_set("conn.global_conn_cap", "4")
        .expect("cap");
    let id = env
        .manager
        .add(&server.url("/u.bin"), None, Some("u.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入"
    );
    env.manager.pause(id).expect("pause");

    let db_path = env.dir.join("db.sqlite");
    {
        let db = aidm_core::open_db(&db_path).expect("db");
        // 清掉方案 + 切到 unified：这是「协调器还没写方案」的真实状态。
        db.execute("DELETE FROM download_slices WHERE task_id = ?1", [id])
            .unwrap();
        store::set_execution_mode(&db, id, ExecutionMode::Unified).expect("mode");
    }

    env.manager.restart(id).expect("restart");
    assert!(
        until(Duration::from_secs(20), || {
            let Ok(conn) = aidm_core::open_db(&db_path) else {
                return false;
            };
            conn.query_row(
                "SELECT count(*) FROM events
                 WHERE download_id = ?1 AND kind = 'paused'
                   AND detail LIKE '%plan_missing%'",
                [id],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false)
        }),
        "unified 模式缺方案必须暂停并报 plan_missing"
    );
    assert_eq!(
        env.manager.status(id).unwrap().unwrap().state,
        "paused",
        "必须落到 paused，而不是停在 downloading"
    );
    env.manager.cancel(id).ok();
}

/// C3-a 接 Coordinator：manager 的 tick 必须能为**空闲无进度**的任务产出方案并落表。
///
/// 用手工插入的任务行（不经 worker），这样测的是 `coordinator_tick` 本身，
/// 不会被 worker 的兜底写表掩盖。
#[test]
fn manager_tick_emits_a_plan_for_an_idle_task() {
    use aidm_core::download::plan;
    use aidm_core::download::store;

    let env = temp_env("c3a_tick_plan");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/idle.bin', 'idle.bin', ?1, 'queued', 0, 2097152)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        db.last_insert_rowid()
    };

    env.manager.tick();

    let db = aidm_core::open_db(&db_path).expect("db");
    let rt = store::load_runtime(&db, id)
        .expect("runtime")
        .expect("运行记录应由协调器建立");
    assert!(rt.plan_revision >= 1, "tick 必须推进方案版本");
    let rows = store::load_plan(&db, id, rt.plan_revision).expect("plan");
    assert!(!rows.is_empty(), "tick 必须把方案写进 download_slices");
    let got = plan::project_rows(
        &rows
            .iter()
            .map(|r| (r.span_start, r.span_end_exclusive))
            .collect::<Vec<_>>(),
    );
    // 与 legacy 规划器同一份方案：预算来自唯一的 task_conns_for。
    let conns = {
        let row = aidm_core::model::get_download(&db, id).unwrap().unwrap();
        aidm_core::model::task_conns_for(&db, &row)
    };
    assert_eq!(got, plan::project_legacy(2 * 1024 * 1024, conns));
}

/// 同一 tick 反复执行不得让方案版本无限增长（幂等）。
#[test]
fn repeated_ticks_do_not_bump_the_plan_revision() {
    use aidm_core::download::store;

    let env = temp_env("c3a_tick_idem");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/idem.bin', 'idem.bin', ?1, 'queued', 0, 2097152)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        db.last_insert_rowid()
    };
    // 用 `error` 而不是 `queued`：两者都算“空闲无进度”，但 `queued` 会被
    // 调度器立刻派发给 worker，第二次 tick 时状态已经不是空闲了。
    env.manager.tick();
    let first = {
        let db = aidm_core::open_db(&db_path).expect("db");
        store::load_runtime(&db, id).unwrap().unwrap().plan_revision
    };
    for _ in 0..3 {
        env.manager.tick();
    }
    let after = {
        let db = aidm_core::open_db(&db_path).expect("db");
        store::load_runtime(&db, id).unwrap().unwrap().plan_revision
    };
    assert_eq!(first, after, "方案没变，版本不得继续增长");
}

/// 验收 ②（端到端）：方案真的变了，必须能产生**新**命令并落表。
///
/// 清表让 `plan_ready` 回到 false，再改连接预算——如果 `command_id` 不带方案指纹，
/// `CommandLedger::accept` 会先按 by_id 命中上一条命令直接 `Merged`，新方案永远
/// 发不出去。这条用「段数从 4 变成 2」作为可观测证据。
#[test]
fn a_changed_budget_produces_a_new_plan() {
    use aidm_core::download::plan;
    use aidm_core::download::store;

    let env = temp_env("c3a_tick_replan");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/re.bin', 're.bin', ?1, 'error', 0, 2097152)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        db.last_insert_rowid()
    };
    env.manager.tick();
    let first = {
        let db = aidm_core::open_db(&db_path).expect("db");
        let rt = store::load_runtime(&db, id).unwrap().unwrap();
        let rows = store::load_plan(&db, id, rt.plan_revision).unwrap();
        (rt.plan_revision, rows.len())
    };
    assert!(first.1 >= 2, "首次方案应切成多段，实际 {}", first.1);

    // 清表 + 把任务连接预算降到 1：下次 tick 必须按新预算重建。
    {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute("DELETE FROM download_slices WHERE task_id = ?1", [id])
            .unwrap();
    }
    // 注意：连接预算来自 `conn.global_conn_cap` 与 `download_conn_caps`，
    // 不是 `downloads.max_conns`（那是历史字段，`task_conns_for` 不读它）。
    env.manager
        .settings_set("conn.global_conn_cap", "1")
        .expect("cap");
    env.manager.tick();

    let db = aidm_core::open_db(&db_path).expect("db");
    let rt = store::load_runtime(&db, id).unwrap().unwrap();
    assert!(
        rt.plan_revision > first.0,
        "方案变了必须推进版本：{} → {}",
        first.0,
        rt.plan_revision
    );
    let rows = store::load_plan(&db, id, rt.plan_revision).unwrap();
    assert_eq!(rows.len(), 1, "1 个连接预算应只切 1 段");
    let got = plan::project_rows(
        &rows
            .iter()
            .map(|r| (r.span_start, r.span_end_exclusive))
            .collect::<Vec<_>>(),
    );
    assert_eq!(got, plan::project_legacy(2 * 1024 * 1024, 1));
}

/// 观察期前置动作：量 `coordinator_tick` 在 200 个空闲任务上的单拍开销。
///
/// 判定阈值：> 20ms 先优化再观察（500ms 周期下 20ms = 4% 占用）；
/// > 50ms 会开始影响调度精度。这里的断言放宽到 100ms 以容忍 CI 抖动，
/// 实际值靠打印记录在文档里。
#[test]
fn coordinator_tick_scales_to_two_hundred_idle_tasks() {
    let env = temp_env("c3a_tick_scale");
    let db_path = env.dir.join("db.sqlite");
    {
        let db = aidm_core::open_db(&db_path).expect("db");
        let mut stmt = db
            .prepare(
                "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
                 VALUES(?1, ?2, ?3, 'error', 0, 2097152)",
            )
            .unwrap();
        for i in 0..200 {
            stmt.execute([
                format!("http://127.0.0.1:1/{i}.bin"),
                format!("{i}.bin"),
                env.dir.to_string_lossy().to_string(),
            ])
            .unwrap();
        }
    }

    // 预热两拍：
    // - 第 1 拍为 200 个任务各写一份方案（`PlanSlices`）；
    // - 第 2 拍才首现 `Wait` 命令（每条要落一次库）。
    // 采样取**稳态**（第 3 拍），否则测到的是首次写库的成本。
    env.manager.tick();
    env.manager.tick();
    let start = std::time::Instant::now();
    env.manager.tick();
    let elapsed = start.elapsed();
    eprintln!(
        "coordinator_tick / 200 idle tasks: {} ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed < Duration::from_millis(100),
        "单拍 {}ms 已明显影响 500ms 调度周期",
        elapsed.as_millis()
    );

    // 稳态再确认：方案不变就不该继续写表。
    let before = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.query_row("SELECT count(*) FROM download_slices", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_or(0)
    };
    env.manager.tick();
    let after = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.query_row("SELECT count(*) FROM download_slices", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_or(0)
    };
    assert_eq!(before, after, "稳态下 tick 不得继续追加切片");
}

/// C3-c：覆盖账本必须拿到**真实**落盘区间，且与 segments 汇总一致。
#[test]
fn coverage_ledger_is_filled_from_segments() {
    use aidm_core::download::store;

    let env = temp_env("c3c_coverage");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/cov.bin', 'cov.bin', ?1, 'error', 0, 2097152)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        let id = db.last_insert_rowid();
        // 两段各有进度：[0, 1000) 与 [1048576, 1049576)。
        db.execute(
            "INSERT INTO segments(download_id, idx, pos_start, pos_end, done_bytes, part_path, status)
             VALUES(?1, 0, 0, 1048575, 1000, '/tmp/p0', 'running'),
                    (?1, 1, 1048576, 2097151, 1000, '/tmp/p1', 'running')",
            [id],
        )
        .unwrap();
        id
    };

    env.manager.tick();

    let db = aidm_core::open_db(&db_path).expect("db");
    let spans = store::load_coverage(&db, id, 0, "stored").expect("coverage");
    assert_eq!(
        spans,
        vec![0u64..1000, 1048576u64..1049576],
        "覆盖必须精确反映 segments 的已完成区间"
    );
    let checkpoint: i64 = db
        .query_row(
            "SELECT checkpoint FROM download_coverage WHERE task_id = ?1 AND kind = 'stored'",
            [id],
            |r| r.get(0),
        )
        .expect("checkpoint");
    assert_eq!(checkpoint, 2000, "checkpoint 是已落盘总字节");
}

/// C3-c：跨重启的未完成命令必须被回放（`Executor::recover` 接上）。
///
/// 之前协调器每次新建 `Executor`、ledger 恒空，`download_commands` 里的
/// `pending` 命令再也不会执行——重启即丢命令。
#[test]
fn pending_commands_are_replayed_after_restart() {
    use aidm_core::download::store;

    let env = temp_env("c3c_recover");
    let db_path = env.dir.join("db.sqlite");
    let (id, total) = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/rec.bin', 'rec.bin', ?1, 'error', 0, 2097152)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        let id = db.last_insert_rowid();
        store::ensure_runtime(&db, id).expect("runtime");
        // 模拟「上次崩溃前已接纳但未执行」的 PlanSlices 命令。
        let plan: Vec<aidm_core::download::model::Span> =
            aidm_core::segment::plan_segments(2097152, 2)
                .into_iter()
                .map(|b| aidm_core::download::model::Span::known(b.start, b.end + 1).expect("span"))
                .collect();
        let command = aidm_core::download::model::Command {
            command_id: aidm_core::download::model::CommandId::new("cmd-recover-1"),
            decision_id: None,
            task_id: id,
            run_epoch: 0,
            target: "task".to_owned(),
            action: aidm_core::download::model::Action::PlanSlices,
            parameters: aidm_core::download::model::ActionParams {
                plan: Some(plan),
                ..Default::default()
            },
            idempotency_key: format!("recover:{id}"),
            state: aidm_core::download::model::CommandStatus::Pending,
            result_event_id: None,
            error: None,
        };
        store::save_command(&db, &command).expect("save pending command");
        (id, 2097152u64)
    };

    env.manager.tick();

    let db = aidm_core::open_db(&db_path).expect("db");
    let state: String = db
        .query_row(
            "SELECT state FROM download_commands WHERE command_id = 'cmd-recover-1'",
            [],
            |r| r.get(0),
        )
        .expect("command row");
    assert_eq!(state, "succeeded", "未完成命令必须被回放并写入回执");

    let rt = store::load_runtime(&db, id).expect("runtime").expect("row");
    let rows = store::load_plan(&db, id, rt.plan_revision).expect("plan");
    assert!(!rows.is_empty(), "回放必须真的把方案写进表");
    let projected = aidm_core::download::plan::project_rows(
        &rows
            .iter()
            .map(|r| (r.span_start, r.span_end_exclusive))
            .collect::<Vec<_>>(),
    );
    assert_eq!(projected, aidm_core::download::plan::project_legacy(total, 2));
}

/// C4：重试预算来自 `download_runtime`，耗尽时必须终止而不是无限重试。
#[test]
fn exhausted_retry_budget_terminates_from_the_tick_path() {
    use aidm_core::download::store;

    let env = temp_env("c4_budget");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total,
                                   error_code, http_status)
             VALUES('http://127.0.0.1:1/r.bin', 'r.bin', ?1, 'error', 0, 2097152,
                    'network', NULL)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        let id = db.last_insert_rowid();
        store::ensure_runtime(&db, id).expect("runtime");
        db.execute(
            "UPDATE download_runtime SET retry_budget = 0 WHERE task_id = ?1",
            [id],
        )
        .unwrap();
        id
    };

    env.manager.tick();

    let db = aidm_core::open_db(&db_path).expect("db");
    let kind: String = db
        .query_row(
            "SELECT action FROM download_commands
             WHERE task_id = ?1 ORDER BY created_at_ms DESC, command_id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .expect("command row");
    assert_eq!(kind, "finish", "预算耗尽必须产 Finish 而不是 Retry");
    // 终止原因在 `parameters` JSON 里（`detail_code`），不是独立列。
    let params: String = db
        .query_row(
            "SELECT parameters FROM download_commands
             WHERE task_id = ?1 ORDER BY created_at_ms DESC, command_id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .expect("parameters");
    assert!(
        params.contains("network"),
        "终止原因的 code 要留在参数里：{params}"
    );
}

/// C5：写盘失败（磁盘满）时，覆盖账本**不得**包含没有真正落盘的区间。
///
/// 这是「写盘与记账之间」的崩溃窗口：如果先记覆盖再写盘，磁盘满时账本会比
/// 实际文件"更完整"，之后 resume 会跳过根本没写的区段。
#[test]
fn disk_full_does_not_record_unwritten_coverage() {
    use aidm_core::download::store;

    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(1024 * 1024), req, true).slow(32 * 1024, Duration::from_millis(5))
    }));
    let env = temp_env("c5_disk_full");
    env.manager.set_io_fault(IoFault::DiskFull);
    let id = env
        .manager
        .add(&server.url("/df.bin"), None, Some("df.bin"), None, 0)
        .unwrap();

    assert!(
        until(Duration::from_secs(20), || {
            env.manager.write_gate(id).is_none()
                && matches!(
                    env.manager.status(id).unwrap().unwrap().state.as_str(),
                    "error" | "paused"
                )
        }) || until(Duration::from_secs(5), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "磁盘满必须让任务失败或停下：{:?}",
        env.manager.status(id)
    );

    let db_path = env.dir.join("db.sqlite");
    let db = aidm_core::open_db(&db_path).expect("db");
    let recorded: u64 = store::load_coverage(&db, id, 0, "stored")
        .map(|spans| spans.iter().map(|r| r.end - r.start).sum())
        .unwrap_or(0);
    let on_disk = {
        let dir = env.dir.join("downloads").join(".aidm").join(id.to_string());
        dir_bytes(&dir)
    };
    assert!(
        recorded <= on_disk,
        "账本记录的覆盖 {} 超过了实际落盘 {}——先记账后落盘会制造这个窗口",
        recorded,
        on_disk
    );
    env.manager.cancel(id).ok();
}

/// C5：`recover` 之后重复执行同一条命令不得产生第二次副作用。
#[test]
fn recovered_commands_do_not_double_apply() {
    use aidm_core::download::store;

    let env = temp_env("c5_recover_idem");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/i.bin', 'i.bin', ?1, 'error', 0, 2097152)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        let id = db.last_insert_rowid();
        store::ensure_runtime(&db, id).expect("runtime");
        let plan: Vec<aidm_core::download::model::Span> =
            aidm_core::segment::plan_segments(2097152, 2)
                .into_iter()
                .map(|b| aidm_core::download::model::Span::known(b.start, b.end + 1).expect("span"))
                .collect();
        store::save_command(
            &db,
            &aidm_core::download::model::Command {
                command_id: aidm_core::download::model::CommandId::new("cmd-idem"),
                decision_id: None,
                task_id: id,
                run_epoch: 0,
                target: "task".to_owned(),
                action: aidm_core::download::model::Action::PlanSlices,
                parameters: aidm_core::download::model::ActionParams {
                    plan: Some(plan),
                    ..Default::default()
                },
                idempotency_key: format!("idem:{id}"),
                state: aidm_core::download::model::CommandStatus::Pending,
                result_event_id: None,
                error: None,
            },
        )
        .expect("save");
        id
    };

    env.manager.tick();
    let after_first = {
        let db = aidm_core::open_db(&db_path).expect("db");
        store::load_runtime(&db, id).unwrap().unwrap().plan_revision
    };
    // 再跑三拍：已完成的命令不得再执行一次（否则版本会被反复推进）。
    for _ in 0..3 {
        env.manager.tick();
    }
    let after_more = {
        let db = aidm_core::open_db(&db_path).expect("db");
        store::load_runtime(&db, id).unwrap().unwrap().plan_revision
    };
    assert_eq!(
        after_first, after_more,
        "已完成的命令被重复执行了（版本 {} → {}）",
        after_first, after_more
    );
}

/// C6：受控启用的对照验收——**unified 模式下的落盘内容必须与 legacy 逐字节相同**。
///
/// unified 路径下 worker 不再自己算方案（缺方案即暂停），所以要先让协调器把方案
/// 落表，再切换归属。这条同时验证了「切换必须静止」之外的另一半：
/// 切换之后执行结果没有变。
#[test]
fn unified_mode_downloads_the_same_bytes_as_legacy() {
    use aidm_core::download::control::ExecutionMode;

    let body = pattern(512 * 1024);
    let served = body.clone();
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&served, req, true)
    }));

    // --- legacy 基线 ---
    let env_legacy = temp_env("c6_legacy");
    let id_legacy = env_legacy
        .manager
        .add(&server.url("/same.bin"), None, Some("same.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env_legacy.manager.status(id_legacy).unwrap().unwrap().state == "done"
        }),
        "legacy 基线应完成：{:?}",
        env_legacy.manager.status(id_legacy)
    );
    let legacy_bytes = std::fs::read(env_legacy.dir.join("downloads").join("same.bin"))
        .expect("legacy 输出");

    // --- unified ---
    let env = temp_env("c6_unified");
    let db_path = env.dir.join("db.sqlite");
    let total = body.len() as u64;
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES(?1, 'same.bin', ?2, 'error', 0, ?3)",
            rusqlite::params![
                server.url("/same.bin"),
                env.dir.join("downloads").to_string_lossy().to_string(),
                total as i64
            ],
        )
        .expect("insert");
        db.last_insert_rowid()
    };
    // 先让协调器落方案（此时仍归 legacy），再切归属。
    env.manager.tick();
    env.manager
        .set_execution_mode(id, ExecutionMode::Unified)
        .expect("switch to unified");
    assert_eq!(
        env.manager.execution_mode(id),
        Some(ExecutionMode::Unified),
        "归属必须真的落库"
    );

    env.manager.restart(id).expect("restart");
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "done"
        }),
        "unified 应完成：{:?}",
        env.manager.status(id)
    );
    let unified_bytes = std::fs::read(env.dir.join("downloads").join("same.bin"))
        .expect("unified 输出");
    assert_eq!(
        unified_bytes, legacy_bytes,
        "两种归属的落盘内容必须逐字节相同"
    );
}

/// C6：正在跑的任务**不许**切换归属——两条路径同时持有一个任务就是双归属。
#[test]
fn switching_execution_mode_is_refused_while_the_task_runs() {
    use aidm_core::download::control::ExecutionMode;

    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(4 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("c6_busy");
    let id = env
        .manager
        .add(&server.url("/busy.bin"), None, Some("busy.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(20), || {
            matches!(
                env.manager.status(id).unwrap().unwrap().state.as_str(),
                "connecting" | "downloading"
            )
        }),
        "任务应在跑"
    );
    assert_eq!(
        env.manager.set_execution_mode(id, ExecutionMode::Unified),
        Err("task_running".to_string()),
        "运行中的任务不得切换归属"
    );
    env.manager.cancel(id).ok();
}

/// C6：**没有方案时不许切 unified**——切过去也跑不起来，只是换个标签。
#[test]
fn switching_to_unified_requires_a_plan() {
    use aidm_core::download::control::ExecutionMode;

    let env = temp_env("c6_no_plan");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/np.bin', 'np.bin', ?1, 'error', 0, 1048576)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        db.last_insert_rowid()
    };
    // 尚未 tick：表里没有任何方案。
    assert_eq!(
        env.manager.set_execution_mode(id, ExecutionMode::Unified),
        Err("plan_missing".to_string()),
        "没有方案时切 unified 必须被拒"
    );
    assert_eq!(env.manager.execution_mode(id), Some(ExecutionMode::Legacy));

    // 让协调器落方案之后才能切。
    env.manager.tick();
    assert!(env
        .manager
        .set_execution_mode(id, ExecutionMode::Unified)
        .is_ok());
}

/// C6：回退——停稳之后可以从 unified 切回 legacy。
#[test]
fn execution_mode_can_be_rolled_back_when_idle() {
    use aidm_core::download::control::ExecutionMode;

    let env = temp_env("c6_rollback");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        // `error` 而非 `queued`：空闲但不会被调度派发，tick 才有机会产方案。
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('http://127.0.0.1:1/rb.bin', 'rb.bin', ?1, 'error', 0, 1048576)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        db.last_insert_rowid()
    };
    // 切 unified 有实质前置：表里必须已有覆盖全文件的方案。
    env.manager.tick();
    env.manager
        .set_execution_mode(id, ExecutionMode::Unified)
        .expect("to unified");
    env.manager
        .set_execution_mode(id, ExecutionMode::Legacy)
        .expect("回退必须允许（任务空闲）");
    assert_eq!(env.manager.execution_mode(id), Some(ExecutionMode::Legacy));

    // 回退是显式动作，必须留痕，否则事后查不出什么时候切的。
    let db = aidm_core::open_db(&db_path).expect("db");
    let n: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE download_id = ?1 AND kind = 'execution_mode'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 2, "两次切换都要落事件");
}

/// C5：**校验与提交之间**的窗口——校验失败绝不能把工作文件改名成成品。
///
/// 这是 C5 唯一真正难的那类窗口：写盘成功了、账本也记了，就差最后一步提交。
/// 如果先 rename 再校验，用户会拿到一个坏文件，而任务显示"完成"。
#[test]
fn corrupt_content_is_never_committed_as_the_final_file() {
    let total = 64 * 1024;
    let server = TestServer::new(Arc::new(move |req: &Req| {
        ranged_mem(&pattern(total), req, true).slow(8 * 1024, Duration::from_millis(5))
    }));
    let env = temp_env("c5_commit_window");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    env.manager.set_io_fault(IoFault::Corrupt);
    let id = env
        .manager
        .add(&server.url("/c.bin"), None, Some("c.bin"), None, 0)
        .unwrap();
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        model::set_sha256_expected(&conn, id, Some(&pattern_sha256(total))).unwrap();
    }

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "内容被篡改必须失败：{:?}",
        env.manager.status(id)
    );

    // R-DL-19：正式文件名下**不得**出现内容不符的文件。
    let final_path = env.dir.join("downloads").join("c.bin");
    assert!(
        !final_path.exists(),
        "校验失败绝不能留下正式名文件——用户会以为下载成功，resume 还会从它续传"
    );
    // 坏文件按约定隔离成 `.bad`：保留诊断，又不在正式名下伪装成功。
    let bad = env.dir.join("downloads").join("c.bin.bad");
    assert!(bad.exists(), "坏文件应被隔离成 <名称>.bad");

    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(
        view.error_code.as_deref(),
        Some("sha256_mismatch"),
        "失败原因必须可定位"
    );
    assert_ne!(view.state, "done", "校验失败绝不能判完成");
    let db = open_db(&env.dir.join("db.sqlite")).unwrap();
    let done_events: i64 = db
        .query_row(
            "SELECT count(*) FROM events WHERE download_id = ?1 AND kind = 'done'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(done_events, 0, "校验失败绝不能产生 done 事件");
    let fail_events: i64 = db
        .query_row(
            "SELECT count(*) FROM events
             WHERE download_id = ?1 AND kind = 'verify.file' AND detail LIKE 'outcome=fail%'",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fail_events, 1, "隔离动作必须留一条 verify.file/outcome=fail");
    env.manager.cancel(id).ok();
}

/// C5：**取消**窗口——取消后不得留下成品，也不得继续写盘。
///
/// 与已有的 `cancel_mid_download_stops_and_cleans` 互补：那条验证清理，
/// 这条验证"取消不会产生半成品成品文件"。
#[test]
fn cancel_never_leaves_a_final_file_behind() {
    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(4 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("c5_cancel_window");
    let id = env
        .manager
        .add(&server.url("/cc.bin"), None, Some("cc.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入"
    );
    env.manager.cancel(id).expect("cancel");
    assert!(
        until(Duration::from_secs(10), || {
            !env.dir.join("downloads").join("cc.bin").exists()
        }),
        "取消后不得留下成品文件"
    );
}

/// P2 回归：**resume 路径**的坏样本必须落在保存目录，不能藏进工作目录。
///
/// resume 时 `finish_single` 的入参是 `.aidm/<id>/0.part`；如果隔离文件跟着入参
/// 的父目录走，用户看不到它，`cancel` 或 `remove_part_dir` 一跑就没了——
/// 正好违背 R-DL-19「留样本给用户比对」的意图。
#[test]
fn resume_failure_quarantines_into_the_save_dir_not_the_work_dir() {
    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(2 * 1024 * 1024), req, true).slow(64 * 1024, Duration::from_millis(20))
    }));
    let env = temp_env("p2_resume_quarantine");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    let id = env
        .manager
        .add(&server.url("/rq.bin"), None, Some("rq.bin"), None, 0)
        .unwrap();
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().done > 0
        }),
        "应先有真实写入"
    );
    env.manager.pause(id).expect("pause");
    assert!(
        until(Duration::from_secs(10), || env
            .manager
            .status(id)
            .unwrap()
            .unwrap()
            .state
            == "paused"),
        "应停在 paused"
    );

    // 续传 + 注入损坏 + 上游哈希：让 resume 路径走一次失败。
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        model::set_sha256_expected(&conn, id, Some(&pattern_sha256(2 * 1024 * 1024)))
            .unwrap();
    }
    env.manager.set_io_fault(IoFault::Corrupt);
    env.manager.resume(id).expect("resume");
    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "续传后校验应失败：{:?}",
        env.manager.status(id)
    );

    let save_dir = env.dir.join("downloads");
    let bad_in_save = save_dir.join("rq.bin.bad");
    assert!(
        bad_in_save.exists(),
        "坏样本必须落在保存目录，用户才看得到：{}",
        bad_in_save.display()
    );
    let work_dir = save_dir.join(".aidm").join(id.to_string());
    if work_dir.exists() {
        let stray = std::fs::read_dir(&work_dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".bad"));
        assert!(!stray, "工作目录里不得出现 .bad —— 那里 cancel 一跑就没了");
    }
    env.manager.cancel(id).ok();
}

/// P2 回归：**ed2k 哈希失败**与 sha256 失败必须同处置（隔离坏样本）。
///
/// 两者都是「内容不符」。之前 ed2k 分支裸返回：不留样本、不清 part，
/// 而 eD2k 的原生分块校验失败是常态——接阶段 D 时会立刻放大这个问题。
#[test]
fn ed2k_hash_mismatch_quarantines_the_sample() {
    let server = TestServer::new(Arc::new(|req: &Req| {
        ranged_mem(&pattern(512 * 1024), req, true)
    }));
    let env = temp_env("p2_ed2k_quarantine");
    env.manager.settings_set("conn.retry_max", "0").unwrap();
    let id = env
        .manager
        .add(&server.url("/eq.bin"), None, Some("eq.bin"), None, 0)
        .unwrap();
    // 给一个必然不匹配的 ed2k 哈希：`verify_http_ed2k` 只在 url 不是 ed2k: 且
    // 有哈希时才生效，所以这里走的是 HTTP 下载 + eD2k 内容校验。
    {
        let conn = open_db(&env.dir.join("db.sqlite")).unwrap();
        conn.execute(
            "UPDATE downloads SET ed2k_hash = ?2 WHERE id = ?1",
            rusqlite::params![id, "00000000000000000000000000000000"],
        )
        .unwrap();
    }

    assert!(
        until(Duration::from_secs(30), || {
            env.manager.status(id).unwrap().unwrap().state == "error"
        }),
        "eD2k 哈希不符必须失败：{:?}",
        env.manager.status(id)
    );
    let view = env.manager.status(id).unwrap().unwrap();
    assert_eq!(
        view.error_code.as_deref(),
        Some("ed2k_hash_mismatch"),
        "失败原因必须可定位"
    );
    let bad = env.dir.join("downloads").join("eq.bin.bad");
    assert!(
        bad.exists(),
        "eD2k 哈希失败也必须隔离样本：{}",
        bad.display()
    );
    // 事件里的 `algo` 必须是 **ed2k**，不是 sha256：两者是完全不同的排查方向
    // （前者查分块与源，后者查镜像/传输）。硬编码 sha256 会让阶段 D 的排查瞎掉。
    let db = open_db(&env.dir.join("db.sqlite")).unwrap();
    let detail: String = db
        .query_row(
            "SELECT detail FROM events
             WHERE download_id = ?1 AND kind = 'verify.file' AND detail LIKE 'outcome=fail%'
             ORDER BY id DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .expect("verify.file/outcome=fail 事件");
    assert!(
        detail.contains("algo=ed2k"),
        "eD2k 失败事件的 algo 必须是 ed2k：{detail}"
    );
    assert!(
        !env.dir.join("downloads").join("eq.bin").exists(),
        "校验失败不得留下正式名文件"
    );
    env.manager.cancel(id).ok();
}

/// P1 反例：**eD2k 任务不得写覆盖账本**。
///
/// `segments.done_bytes` 在 eD2k 上是「跨 part 的累计接收量」，不是「段内已落盘
/// 前缀」。拿它拼区间会造出一条假的连续覆盖（实测一条 eD2k 任务写出
/// `0:921968640`，同期磁盘上的 part 只有 725 MB 且 `done/9728000` 不是整数）。
#[test]
fn ed2k_tasks_never_write_coverage_ledger() {
    use aidm_core::download::coverage::done_bytes_is_prefix;
    use aidm_core::download::store;

    // 判定函数本身
    assert!(!done_bytes_is_prefix("ed2k://|file|x|100|deadbeef|/"));
    assert!(!done_bytes_is_prefix("  ED2K://|file|x|100|deadbeef|/"));
    assert!(!done_bytes_is_prefix("magnet:?xt=urn:btih:deadbeef"));
    assert!(!done_bytes_is_prefix("https://example/a.torrent"));
    assert!(done_bytes_is_prefix("https://example/a.bin"));
    assert!(done_bytes_is_prefix("ftp://example/a.bin"));

    // 端到端：造一个「已下 40 MiB 的 eD2k 任务」，tick 之后覆盖表必须为空。
    let env = temp_env("p1_ed2k_coverage");
    let db_path = env.dir.join("db.sqlite");
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total)
             VALUES('ed2k://|file|fake.iso|3196803072|2d39c54a2e99bac308191c74a15b3237|/',
                    'fake.iso', ?1, 'error', 0, 3196803072)",
            [env.dir.to_string_lossy().to_string()],
        )
        .expect("insert");
        let id = db.last_insert_rowid();
        db.execute(
            "INSERT INTO segments(download_id, idx, pos_start, pos_end, done_bytes, part_path, status)
             VALUES(?1, 0, 0, 3196803071, 41943040, '/tmp/part0', 'running')",
            [id],
        )
        .unwrap();
        // 模拟历史伪造行：修复后启动清理应当把它删掉。
        db.execute(
            "INSERT INTO download_coverage(task_id, content_generation, kind, intervals, checkpoint)
             VALUES(?1, 0, 'stored', '0:41943040', 41943040)",
            [id],
        )
        .unwrap();
        id
    };

    // 重开库 = 触发清理（`purge_untrusted_coverage`）。
    let db = aidm_core::open_db(&db_path).expect("db");
    let after_open = store::load_coverage(&db, id, 0, "stored").expect("coverage");
    assert!(
        after_open.is_empty(),
        "库里已有的伪造覆盖必须被启动清理删掉：{after_open:?}"
    );
    drop(db);

    env.manager.tick();

    let db = aidm_core::open_db(&db_path).expect("db");
    let rows: i64 = db
        .query_row(
            "SELECT count(*) FROM download_coverage WHERE task_id = ?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "eD2k 任务不得写出任何覆盖行");
}

#[test]
fn paused_ed2k_task_still_projects_slices() {
    // 需求：暂停/未运行时详情不能让切片整段消失。
    // `groups` 由 total + budget 确定性推导，重启后同值，所以可以重建。
    let env = temp_env("ed2k_paused_slices");
    let db_path = env.dir.join("db.sqlite");
    let total: u64 = 25 * 1024 * 1024; // 25 MiB → 3 个原生 part
    let hash = "0123456789abcdef0123456789abcdef";
    let id = {
        let db = aidm_core::open_db(&db_path).expect("db");
        db.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, size_total, ed2k_hash)
             VALUES(?1, 'idle.bin', ?2, 'paused', 0, ?3, ?4)",
            rusqlite::params![
                format!("ed2k://|file|idle.bin|{total}|{hash}|/"),
                env.dir.to_string_lossy().to_string(),
                total as i64,
                hash
            ],
        )
        .expect("insert");
        db.last_insert_rowid()
    };

    let view = env.manager.status(id).expect("status").expect("task");
    let u = view.unified_download.expect("unified view");
    assert!(
        !u.slices.is_empty(),
        "暂停的 eD2k 任务也必须能投影切片条目，实际：{:?}",
        u.slices.len()
    );
    let stored: u64 = u
        .slices
        .iter()
        .map(|s| s.progress.stored_unique_bytes.parse::<u64>().unwrap_or(0))
        .sum();
    assert_eq!(stored, 0, "没有 part 事实时不得伪造覆盖");
}
