//! AIDM 引擎进程（分段下载 + 设置 / 限速 / 代理 / 回环 IPC 推送）。
//!
//! 目标形态（ADR 0001）：引擎进程独占全部网络 IO 与下载调度，托盘常驻。
//! 启动顺序：日志 → SQLite（§4 downloads/segments/events）→
//! 崩溃恢复（connecting/downloading → queued + interrupted；未合并 part → verifying）→ IPC 监听。

use std::sync::{Arc, Mutex};

use aidm_core::paths;
use aidm_core::settings as kv;

use aidm_engine::DownloadManager;

/// 默认保存目录：读 settings `paths.default_dir`（token 形式存储）并**展开**；
/// 读取失败回退 §9 默认值的展开结果。
fn default_download_dir(conn: &rusqlite::Connection) -> std::path::PathBuf {
    let setting = kv::get(conn, "paths.default_dir")
        .ok()
        .flatten()
        .unwrap_or_else(|| paths::DEFAULT_DIR_SETTING.to_string());
    let dir = paths::expand_user_path(&setting);
    log::info!(
        "default download dir: {} (setting {setting:?})",
        dir.display()
    );
    dir
}

/// `aidm-engine diag export --task <id> [--out <目录>]`
///
/// 一键导出诊断包（规格 §7）：一次性命令，不进引擎主循环，也不抢实例锁 ——
/// 引擎正在跑的时候同样能把某个任务的现场导出来。
fn diag_cli() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("diag") {
        return None;
    }
    aidm_core::obs::init("diag", "info");
    // `aidm-engine diag metrics`：全局指标快照（成功率/重试/分片/内存/磁盘）。
    if args.get(1).map(String::as_str) == Some("metrics") {
        let conn = match aidm_core::open_db(&aidm_core::db_path()) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("打开数据库失败：{e}");
                return Some(1);
            }
        };
        println!("{}", aidm_core::diag::global_metrics(&conn));
        return Some(0);
    }
    let mut task: Option<i64> = None;
    let mut out: Option<String> = None;
    let mut since: Option<i64> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "export" => {}
            "--task" => {
                task = args.get(i + 1).and_then(|v| v.parse().ok());
                i += 1;
            }
            "--out" => {
                out = args.get(i + 1).cloned();
                i += 1;
            }
            "--since" => {
                since = args
                    .get(i + 1)
                    .and_then(|v| aidm_core::diag::parse_since(v));
                if since.is_none() {
                    eprintln!("--since 需要形如 30s / 10m / 2h / 1d 的时长");
                    return Some(2);
                }
                i += 1;
            }
            other => {
                eprintln!("未知参数：{other}");
                return Some(2);
            }
        }
        i += 1;
    }
    let Some(task) = task else {
        eprintln!("用法：aidm-engine diag export --task <id> [--since <dur>] [--out <目录>]");
        return Some(2);
    };
    let conn = match aidm_core::open_db(&aidm_core::db_path()) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("打开数据库失败：{e}");
            return Some(1);
        }
    };
    let dir = out
        .map(std::path::PathBuf::from)
        .unwrap_or_else(aidm_core::diag::default_out_dir);
    let since_ts = since.map(|secs| aidm_core::model::now_secs().saturating_sub(secs));
    match aidm_core::diag::export_task_bundle_since(&conn, task, &dir, since_ts) {
        Ok(report) => {
            println!("{}", report.path.display());
            eprintln!(
                "诊断包：{} 字节，{} 个条目，二次脱敏命中 {} 处",
                report.bytes,
                report.entries.len(),
                report.redaction_findings
            );
            Some(0)
        }
        Err(e) => {
            eprintln!("导出失败：{e}");
            Some(1)
        }
    }
}

fn main() {
    if let Some(code) = diag_cli() {
        std::process::exit(code);
    }
    // 结构化日志底座：JSON 行 + 脱敏 + 限流 + 落盘（docs/download-observability.md §3）。
    aidm_core::obs::init("engine", "info");
    tracing::info!(
        event = "process.start",
        role = "engine",
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        epoch = aidm_core::obs::epoch(),
    );

    // Windows 上 TerminateProcess 后 LockFileEx 可能仍短暂占用；崩溃重启要重试。
    let _instance_lock = acquire_instance_lock();

    let path = paths::db_path();
    let conn = match aidm_core::open_db(&path) {
        Ok(conn) => {
            // 建立默认配置：写入缺失键；用户没改过的键跟随新默认值升级。
            // 这三个数字是排查"设置没生效"的第一手线索，所以打日志而不是静默。
            match kv::ensure_defaults(&conn) {
                Ok(r) => log::info!(
                    "settings ready: {} new, {} migrated to new defaults, {} unchanged",
                    r.created,
                    r.upgraded,
                    r.kept
                ),
                Err(e) => log::error!("seed default settings failed: {e}"),
            }
            log::info!("database ready at {}", path.display());
            conn
        }
        Err(e) => {
            log::error!("open database at {} failed: {e}", path.display());
            std::process::exit(1);
        }
    };

    // 在连接移交给 manager 之前读默认目录（展开 token，不用字面量）
    let default_dir = default_download_dir(&conn);
    let db = Arc::new(Mutex::new(conn));
    // eD2k 入站上传服务（L6）：默认关闭，开启后才绑定端口。
    // 身份与下载侧共用同一份持久化 UserHash（信用按它记账）。
    let _inbound = match db
        .lock()
        .map_err(|_| "db poisoned".to_string())
        .and_then(|conn| aidm_engine::ed2k::identity::load_or_create(&conn))
    {
        Ok(identity) => Some(aidm_engine::ed2k::inbound::Inbound::spawn(
            db.clone(),
            identity,
        )),
        Err(e) => {
            log::warn!("ed2k identity unavailable, inbound upload disabled: {e}");
            None
        }
    };
    let manager = Arc::new(DownloadManager::new(db, default_dir));
    if let Some(inbound) = _inbound {
        manager.attach_ed2k_inbound(inbound);
    }
    manager.recover_on_startup();

    // 公共源列表会随时间失效（节点下线、服务器更替）：启动时尽力刷一次 Kad 节点列表。
    // 过期才刷、失败只记日志、不阻塞启动（详见 manager::spawn_source_refresh_on_start）。
    manager.spawn_source_refresh_on_start();

    if let Err(e) = aidm_engine::server::serve(manager) {
        log::error!("engine ipc failed: {e}");
        std::process::exit(1);
    }

    // 常驻：下载调度与 IPC 由各线程驱动，主线程等待退出信号。
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn acquire_instance_lock() -> aidm_core::InstanceLock {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(2);
    loop {
        match aidm_core::try_acquire_instance_lock(&paths::app_data_dir()) {
            Ok(lock) => return lock,
            Err(e) => {
                if start.elapsed() >= timeout {
                    log::error!("engine instance lock failed: {e}");
                    std::process::exit(1);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}
