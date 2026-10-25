//! 集成测试共享夹具。
//!
//! 三条约束（07-testing.md R-TEST-03/08/09/12/13）：
//! - 临时目录根为 `%TEMP%\aidm-tests`，用后自动清理；
//! - 端口一律 `127.0.0.1:0` 由内核分配；
//! - 不 mock 传输层：MCP 用真实子进程 + 真实管道，引擎用真实 socket + 线程。
//!
//! 每个测试二进制各自编译一份本模块（R-TEST-03 的既定做法）。

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// 自动清理的临时目录（不引入 tempfile：v1 零新增依赖）。
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        // 纳秒时钟在 Windows 上粒度可能粗到同一瞬间取两次相同值，而测试是并行跑的；
        // 只用纳秒曾导致两个测试共用同一个数据目录、互相覆盖 engine.port。
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join("aidm-tests")
            .join(format!("aidm-{tag}-{}-{nanos}-{seq}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 给参数表补上 modern 必需的 `_meta`；已有 `_meta` 则保留额外的键。
pub fn modern_params(extra: Value) -> Value {
    let mut map = extra.as_object().cloned().unwrap_or_default();
    let meta = map
        .entry("_meta")
        .or_insert_with(|| json!({}));
    if let Some(meta) = meta.as_object_mut() {
        meta.insert(
            "io.modelcontextprotocol/protocolVersion".into(),
            json!("2026-07-28"),
        );
        meta.insert(
            "io.modelcontextprotocol/clientCapabilities".into(),
            json!({}),
        );
    }
    Value::Object(map)
}

/// 被拉起的 `aidm-mcp` 子进程：一行请求、一行响应。
pub struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
    log: Arc<Mutex<String>>,
    dir: TempDir,
}

impl Mcp {
    /// 拉起子进程。`LOCALAPPDATA` 指向临时目录，因此端口文件与引擎数据
    /// 都不会碰到真实的 `%LOCALAPPDATA%\AIDM`（R-TEST-10）。
    pub fn spawn(allow_write: bool) -> Self {
        let dir = TempDir::new(if allow_write { "mcp-rw" } else { "mcp-ro" });
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_aidm-mcp"));
        if allow_write {
            cmd.arg("--allow-write");
        }
        cmd.env("LOCALAPPDATA", dir.path())
            // 防止开发机上的环境变量把默认只读测试变成可写。
            .env_remove("AIDM_MCP_ALLOW_WRITE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("拉起 aidm-mcp 失败");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let log = Arc::new(Mutex::new(String::new()));
        let sink = log.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut buffer = sink.lock().unwrap();
                buffer.push_str(&line);
                buffer.push('\n');
            }
        });

        Self {
            child,
            stdin: Some(stdin),
            rx,
            log,
            dir,
        }
    }

    pub fn data_dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn port_path(&self) -> PathBuf {
        self.dir
            .path()
            .join(aidm_core::paths::APP_DIR_NAME)
            .join(aidm_ipc::PORT_FILE)
    }

    /// 写端口文件，让子进程"发现"假引擎。
    pub fn write_port(&self, port: u16) {
        let path = self.port_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, port.to_string()).unwrap();
    }

    pub fn remove_port(&self) {
        let _ = std::fs::remove_file(self.port_path());
    }

    pub fn send(&mut self, value: &Value) {
        let line = serde_json::to_string(value).unwrap();
        self.send_raw(&line);
    }

    /// 原样写一行（用于空行、坏 JSON 这类"不是合法请求"的输入）。
    pub fn send_raw(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin 已关闭");
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    pub fn recv(&mut self) -> Value {
        let line = self
            .rx
            .recv_timeout(Duration::from_secs(10))
            .expect("等 MCP 响应超时（子进程可能已崩溃）");
        serde_json::from_str(&line).expect("MCP 响应不是合法 JSON")
    }

    /// 带超时的"看有没有消息"；没有就返回 None（用于断言"不应收到通知"）。
    pub fn try_recv(&mut self, timeout: Duration) -> Option<Value> {
        match self.rx.recv_timeout(timeout) {
            Ok(line) => Some(serde_json::from_str(&line).expect("MCP 消息不是合法 JSON")),
            Err(_) => None,
        }
    }

    pub fn call(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        self.recv()
    }

    /// modern 请求（自动补 `_meta`）。
    pub fn call_modern(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.call(id, method, modern_params(params))
    }

    pub fn notify(&mut self, method: &str) {
        self.send(&json!({"jsonrpc": "2.0", "method": method}));
    }

    /// legacy 握手 + `initialized`。
    pub fn legacy_handshake(&mut self) {
        let response = self.call(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
        );
        assert!(response["result"].is_object(), "initialize 失败: {response}");
        self.notify("notifications/initialized");
    }

    pub fn stderr(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// 轮询等待 stderr 出现某段文本（审计是异步线程写的）。
    pub fn wait_stderr(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.stderr().contains(needle) {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        // 关闭 stdin 是 MCP stdio 的标准关闭信号。
        self.stdin.take();
        let _ = self.child.wait();
    }
}

/// 假引擎：每个连接读一行、按 responder 回一行（短连接，与真实引擎一致）。
pub struct Stub {
    pub port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

pub fn start_stub<F>(responder: F) -> Stub
where
    F: Fn(Value) -> Value + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定假引擎失败");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_in_thread = stop.clone();
    let responder = Arc::new(responder);

    let handle = thread::spawn(move || {
        while !stop_in_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let responder = responder.clone();
                    thread::spawn(move || serve_one(stream, responder));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    Stub {
        port,
        stop,
        handle: Some(handle),
    }
}

fn serve_one<F>(stream: TcpStream, responder: Arc<F>)
where
    F: Fn(Value) -> Value + Send + Sync + 'static,
{
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let request: Value = match serde_json::from_str(&line) {
        Ok(value) => value,
        Err(_) => return,
    };
    let response = responder(request);
    let mut out = stream;
    let _ = out.write_all(serde_json::to_string(&response).unwrap().as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// 一个永远成功的假引擎响应（`ok` + 指定字段）。
pub fn ok_response(extra: Value) -> Value {
    let mut map = extra.as_object().cloned().unwrap_or_default();
    map.insert("ok".into(), json!(true));
    map.insert("version".into(), json!("0.1.0"));
    Value::Object(map)
}
