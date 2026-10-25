//! 手动验收真实 eD2k 任务；保留 DB、源失败原因与部分文件，不污染用户任务。
//! AIDM_ED2K_LIVE_DIR 指定独立目录；AIDM_ED2K_LIVE_SECS 控制最长等待。
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
#[ignore = "需要公网 eD2k 源，可能产生 4.48GB 下载"]
fn reported_iso_real_download() {
    run_reported_iso(None);
}

#[test]
#[ignore = "需要公网 eD2k 源；验证新增实传字节后暂停，不代表整包校验"]
fn reported_iso_real_transfer_starts() {
    run_reported_iso(Some(256 * 1024));
}

fn run_reported_iso(minimum_transfer: Option<u64>) {
    let dir = std::env::var_os("AIDM_ED2K_LIVE_DIR")
        .map(std::path::PathBuf::from)
        .expect("请设置独立验收目录 AIDM_ED2K_LIVE_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("db.sqlite");
    let conn = aidm_core::open_db(&db_path).unwrap();
    aidm_core::settings::ensure_defaults(&conn).unwrap();
    let manager =
        aidm_engine::DownloadManager::new(Arc::new(Mutex::new(conn)), dir.join("downloads"));
    let received = Arc::new(AtomicU64::new(0));
    let previous = Arc::new(AtomicU64::new(u64::MAX));
    let (rx, prev) = (received.clone(), previous.clone());
    manager.set_progress_callback(Arc::new(move |p| {
        let old = prev.swap(p.done_bytes, Ordering::Relaxed);
        if old != u64::MAX {
            rx.fetch_add(p.done_bytes.saturating_sub(old), Ordering::Relaxed);
        }
    }));
    manager
        .settings_set("ui.duplicate_action", "resume")
        .unwrap();
    manager.recover_on_startup();
    let url = "ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
    let id = manager.add(url, None, None, None, 0).unwrap();
    let seconds = std::env::var("AIDM_ED2K_LIVE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);
    let start = Instant::now();
    let mut last = String::new();
    let completed;
    let mut transfer_started = false;
    loop {
        // 直接使用 manager 的验收程序没有 serve 的调度线程；恢复后的 queued
        // 任务仍需与生产引擎相同的 tick 才能派发。
        manager.tick();
        let task = manager.status(id).unwrap().unwrap();
        let state = format!(
            "state={} done={} total={:?} code={:?}",
            task.state, task.done, task.total, task.error_code
        );
        if state != last {
            println!("{}s {state}", start.elapsed().as_secs());
            last = state;
        }
        if task.state == "done" {
            completed = true;
            break;
        }
        if minimum_transfer.is_some_and(|min| received.load(Ordering::Relaxed) >= min) {
            transfer_started = true;
            let _ = manager.pause(id);
            completed = false;
            break;
        }
        if task.state == "error"
            || task.error_code.as_deref() == Some("ed2k_no_sources")
            || start.elapsed() >= Duration::from_secs(seconds)
        {
            let _ = manager.pause(id);
            completed = false;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let conn = aidm_core::open_db(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT kind, COALESCE(detail,'') FROM events WHERE download_id=?1 ORDER BY id")
        .unwrap();
    for row in stmt
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
    {
        println!("EVENT {:?}", row.unwrap());
    }
    println!("evidence_dir={}", dir.display());
    println!(
        "new_transfer_bytes={} full_completed={completed}",
        received.load(Ordering::Relaxed)
    );
    if minimum_transfer.is_some() {
        assert!(
            completed || transfer_started,
            "尚未观察到足够的新增网络实传字节"
        );
        return;
    }
    assert!(
        completed,
        "公网 ISO 尚未完整下载；见上述实际源连接/排队结果，不应把查源成功当成下载成功"
    );
    let final_path = dir.join("downloads/cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso");
    assert_eq!(std::fs::metadata(&final_path).unwrap().len(), 4_478_906_368);
    assert!(aidm_engine::ed2k::peer_session::verify_whole_file(
        &final_path,
        &aidm_core::ed2k::hash::parse_hex("E7C526499308841A4A6D116C857DB669").unwrap()
    )
    .unwrap());
}
