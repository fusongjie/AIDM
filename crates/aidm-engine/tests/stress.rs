//! CPU / 内存 / 长跑稳定性压测（默认不进 CI）。
//!
//! ```text
//! cargo test -p aidm-engine --test stress -- --ignored --nocapture
//! # 或：AIDM_STRESS=1 cargo test -p aidm-engine --test stress stress_churn -- --ignored
//! ```
//!
//! 1GiB 离线验收仍走 `scripts/verify_1gb.sh`，**不要**接到 CI。

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aidm_core::db::open_db;
use aidm_core::settings;
use aidm_engine::DownloadManager;

fn tiny_server(body: &'static [u8]) -> (std::net::SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    std::thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        for stream in listener.incoming() {
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            match stream {
                Ok(mut s) => {
                    let _ = s.set_nonblocking(false);
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes());
                    let _ = s.write_all(body);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (addr, stop)
}

#[test]
#[ignore]
fn stress_churn_cpu_and_memory() {
    if std::env::var("AIDM_STRESS").ok().as_deref() == Some("0") {
        eprintln!("skip: AIDM_STRESS=0");
        return;
    }
    let (addr, stop) = tiny_server(&[0x5Au8; 32 * 1024]);
    let _tmp = common::tempdir("stress");
    let dir = _tmp.path().to_path_buf();
    let db = open_db(&dir.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    let manager = DownloadManager::new(
        std::sync::Arc::new(std::sync::Mutex::new(db)),
        dir.join("dl"),
    );
    manager.settings_set("conn.retry_max", "1").unwrap();

    let done = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let budget = Duration::from_secs(20);
    let mut ids = Vec::new();
    let mut seq = 0u64;
    while start.elapsed() < budget {
        manager.tick();
        if ids.len() < 6 {
            seq += 1;
            let url = format!("http://{addr}/s{seq}.bin");
            if let Ok(id) = manager.add(&url, None, Some(&format!("s{seq}.bin")), None, 0) {
                ids.push(id);
            }
        }
        ids.retain(|id| match manager.status(*id) {
            Ok(Some(t)) if t.state == "done" || t.state == "error" => {
                done.fetch_add(1, Ordering::Relaxed);
                false
            }
            _ => true,
        });
        std::thread::sleep(Duration::from_millis(20));
    }
    stop.store(true, Ordering::SeqCst);
    let finished = done.load(Ordering::Relaxed);
    assert!(
        finished >= 3,
        "stress churn should complete several tasks, got {finished}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
