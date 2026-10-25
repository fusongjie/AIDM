//! Protocol acceptance checks: downloaded bytes, inferred filenames and explicit limits.
//! Public HTTPS is opt-in (`--ignored`) so the ordinary suite stays reproducible offline.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aidm_core::{hash::sha256_reader, open_db, settings};
use aidm_engine::DownloadManager;

struct TestEnv {
    manager: DownloadManager,
    /// 持有 tempdir：Drop 时自动删除。
    _tmp: tempfile::TempDir,
}

impl TestEnv {
    fn new(_tag: &str) -> Self {
        let tmp = common::tempdir("protocol");
        let root = tmp.path().to_path_buf();
        let db = open_db(&root.join("db.sqlite")).unwrap();
        settings::ensure_defaults(&db).unwrap();
        let manager = DownloadManager::new(Arc::new(Mutex::new(db)), root.join("downloads"));
        Self { manager, _tmp: tmp }
    }

    fn wait_download(&self, id: i64, timeout: Duration) -> Vec<u8> {
        let started = Instant::now();
        loop {
            self.manager.tick();
            let state = self.manager.status(id).unwrap().unwrap();
            if state.state == "done" {
                return std::fs::read(&state.save_path).unwrap();
            }
            assert_ne!(state.state, "error", "download failed: {state:?}");
            assert!(started.elapsed() < timeout, "download timeout: {state:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

struct HttpFixture {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HttpFixture {
    fn start(body: Vec<u8>, chunked: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let body = Arc::new(body);
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                let bytes = body.clone();
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut first = String::new();
                    if reader.read_line(&mut first).unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    let out = reader.get_mut();
                    let framing = if chunked {
                        "Transfer-Encoding: chunked\r\n".to_string()
                    } else {
                        format!("Content-Length: {}\r\n", bytes.len())
                    };
                    if write!(out, "HTTP/1.1 200 OK\r\n{framing}Connection: close\r\n\r\n").is_err()
                    {
                        return;
                    }
                    if first.starts_with("HEAD ") {
                        return;
                    }
                    if chunked {
                        for part in bytes.chunks(997) {
                            if write!(out, "{:X}\r\n", part.len())
                                .and_then(|_| out.write_all(part))
                                .and_then(|_| out.write_all(b"\r\n"))
                                .is_err()
                            {
                                return;
                            }
                        }
                        let _ = out.write_all(b"0\r\n\r\n");
                    } else {
                        let _ = out.write_all(&bytes);
                    }
                });
            }
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, name: &str) -> String {
        format!("http://{}/{name}", self.addr)
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        let _ = self.thread.take().unwrap().join();
    }
}

fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for block in bytes.chunks(3) {
        let bits = ((block[0] as u32) << 16)
            | ((*block.get(1).unwrap_or(&0) as u32) << 8)
            | *block.get(2).unwrap_or(&0) as u32;
        encoded.push(TABLE[((bits >> 18) & 63) as usize] as char);
        encoded.push(TABLE[((bits >> 12) & 63) as usize] as char);
        encoded.push(if block.len() > 1 {
            TABLE[((bits >> 6) & 63) as usize] as char
        } else {
            '='
        });
        encoded.push(if block.len() > 2 {
            TABLE[(bits & 63) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

#[test]
fn http_chunked_without_length_matches_sha256() {
    let body: Vec<u8> = (0..131_071).map(|i| (i % 251) as u8).collect();
    let fixture = HttpFixture::start(body.clone(), true);
    let env = TestEnv::new("chunked");
    let id = env
        .manager
        .add(&fixture.url("chunked.bin"), None, None, None, 0)
        .unwrap();
    let got = env.wait_download(id, Duration::from_secs(15));
    assert_eq!(got, body);
    assert_eq!(
        sha256_reader(&got[..]).unwrap(),
        sha256_reader(&body[..]).unwrap()
    );
    assert_eq!(env.manager.status(id).unwrap().unwrap().name, "chunked.bin");
}

#[test]
fn wrapped_protocols_infer_filename_and_match_sha256() {
    let body: Vec<u8> = (0..65_537).map(|i| (i % 239) as u8).collect();
    let fixture = HttpFixture::start(body.clone(), false);
    let env = TestEnv::new("wrapped");
    for scheme in ["thunder", "thunders", "qqdl", "flashget"] {
        let filename = format!("{scheme}.bin");
        let real = fixture.url(&filename);
        let payload = match scheme {
            // 早期专用链与常规专用链的载荷格式相同
            "thunder" | "thunders" => format!("AA{real}ZZ"),
            "flashget" => format!("[FLASHGET]{real}[FLASHGET]"),
            _ => real,
        };
        let url = format!("{scheme}://{}", b64(payload.as_bytes()));
        let id = env.manager.add(&url, None, None, None, 0).unwrap();
        let got = env.wait_download(id, Duration::from_secs(15));
        assert_eq!(env.manager.status(id).unwrap().unwrap().name, filename);
        assert_eq!(got, body, "{scheme} downloaded different bytes");
        assert_eq!(
            sha256_reader(&got[..]).unwrap(),
            sha256_reader(&body[..]).unwrap()
        );
    }
}

#[test]
fn unimplemented_protocols_are_rejected_before_task_creation() {
    let env = TestEnv::new("unsupported");
    // `ftps://` 已实现（显式 FTPS，见 docs/ftps-explicit.md），因此不在这张表里。
    for url in [
        "tftp://127.0.0.1/file.bin",
        "sftp://127.0.0.1/file.bin",
        "scp://127.0.0.1/file.bin",
        "rtsp://127.0.0.1/file.bin",
        "mms://127.0.0.1/file.bin",
        "ipfs://example/file.bin",
        "smb://127.0.0.1/file.bin",
    ] {
        let err = env.manager.add(url, None, None, None, 0).unwrap_err();
        assert_eq!(err, "bad_url", "unexpected scheme acceptance for {url}");
    }
}

#[test]
#[ignore = "Requires public HTTPS access; run explicitly with --ignored --nocapture"]
fn public_https_download_matches_independent_http_client() {
    let url = std::env::var("AIDM_HTTPS_FIXTURE_URL")
        .unwrap_or_else(|_| "https://example.com/".to_string());
    assert!(url.starts_with("https://"));
    let response = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(15))
        .build()
        .get(&url)
        .set("Accept-Encoding", "identity")
        .call()
        .expect("independent HTTPS baseline");
    let mut expected = Vec::new();
    response
        .into_reader()
        .take(8 * 1024 * 1024)
        .read_to_end(&mut expected)
        .unwrap();
    assert!(!expected.is_empty());
    let env = TestEnv::new("https-live");
    let id = env
        .manager
        .add(&url, None, Some("https-fixture.bin"), None, 0)
        .unwrap();
    let got = env.wait_download(id, Duration::from_secs(45));
    assert_eq!(got, expected, "fixture changed or HTTPS body differs");
    println!(
        "HTTPS {} bytes={} sha256={}",
        url,
        got.len(),
        sha256_reader(&got[..]).unwrap()
    );
}

#[test]
#[ignore = "Requires public FTP (control and passive data ports); run explicitly with --ignored --nocapture"]
fn public_ftp_download_matches_https_mirror() {
    // Also exercises the mixed-case scheme through task creation and the FTP worker.
    let ftp_url = "FtP://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz";
    let target = aidm_engine::ftp::parse(ftp_url).unwrap();
    aidm_engine::ftp::probe(&target, Duration::from_secs(8))
        .expect("public FTP control/login/SIZE probe");
    let response = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(15))
        .build()
        .get("https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz")
        .set("Accept-Encoding", "identity")
        .call()
        .expect("independent HTTPS mirror baseline");
    let mut expected = Vec::new();
    response
        .into_reader()
        .take(8 * 1024 * 1024)
        .read_to_end(&mut expected)
        .unwrap();
    assert!(!expected.is_empty());
    let env = TestEnv::new("ftp-live");
    let id = env
        .manager
        .add(ftp_url, None, Some("hello-2.12.1.tar.gz"), None, 0)
        .unwrap();
    let got = env.wait_download(id, Duration::from_secs(45));
    assert_eq!(got, expected, "FTP bytes differ from the HTTPS mirror");
    println!(
        "FTP {} bytes={} sha256={}",
        ftp_url,
        got.len(),
        sha256_reader(&got[..]).unwrap()
    );
}
