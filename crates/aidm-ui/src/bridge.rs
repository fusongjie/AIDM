//! UI -> 引擎桥接：回环 IPC 客户端 + 引擎进程守护 + `subscribe` 长连接。
//!
//! 边界（ADR 0001 / 红线）：UI 进程零 HTTP 网络 IO——本模块只与引擎进程
//! 在 127.0.0.1 上交换单行 JSON；全部 HTTP 由引擎执行。

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use aidm_ipc::{EngineEvent, EngineRequest, EngineResponse, PORT_FILE};
use tauri::{Emitter, Manager};

use crate::logic::{self, SUBSCRIBE_STALE_SECS};

// ---- 超时预算 --------------------------------------------------------------
//
// 原则：**启动路径快失败，正常请求不变短**。所有探测都自己限时——
// `aidm_ipc::engine_roundtrip` 内部的 `TcpStream::connect` 没有超时，而本机连一个
// 已关闭的回环端口实测要 ~2040ms（SYN 被丢弃，不是立即 RST）。启动路径
// 若探测 2 轮 = 2×2040ms + 150ms ≈ 4.39s，必须给每次探测单独限时。

/// 探测已知端口的超时（连接 + 写 Ping + 读回包的整体预算）。
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// 退出前探测引擎：只跑一次，宁可稍长也别漏（漏了引擎会变孤儿进程）。
const SHUTDOWN_PROBE: Duration = Duration::from_millis(400);
/// 实例锁被占（引擎活着但暂时不可达）时最多等这么久。
const LOCK_WAIT: Duration = Duration::from_millis(800);
/// 拉起引擎后等它可连接的上限。
const SPAWN_WAIT: Duration = Duration::from_secs(3);
/// 探测/等待的轮询步长：够细才不会有「固定多等 200ms」的启动延迟。
const POLL_STEP: Duration = Duration::from_millis(50);
/// 端口确认后的信任窗口：窗口内每个 IPC 请求直接复用端口，不再探测。
const PORT_TRUST_MS: u64 = 5_000;
/// 单飞等待上限：非领导者最多等这么久，超时就快速失败交给上层重试
/// （绝不把 UI 主线程按在一次慢探测上）。
const FOLLOWER_WAIT: Duration = Duration::from_millis(1_000);
/// 请求失败后的重试间隔（第二次重试会强制完整探测，见 `with_engine`）。
const RETRY_DELAY: Duration = Duration::from_millis(300);
/// 正常请求的读写超时。**不要**为启动优化调小它：大文件请求（重命名/校验/
/// 更新下载）需要这条长超时。
const REQ_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIBE_HANDSHAKE: Duration = Duration::from_secs(5);
/// 一次 `ensure_engine` 超过该耗时才写 info 日志：正常请求的毫秒级探测不刷日志。
const SLOW_LOG_MS: u128 = 100;

/// 最近一次确认可用的引擎端口（0 = 未知）。端口文件被外部删除时靠它恢复连接。
static LAST_PORT: AtomicU32 = AtomicU32::new(0);
/// 端口确认时刻（相对进程启动的毫秒数）；0 = 尚未确认过（不可信任）。
static LAST_OK_MS: AtomicU64 = AtomicU64::new(0);
/// 进程启动的单调时刻（信任窗口只认真实时长，不受系统时钟调整影响）。
static INSTANT_0: OnceLock<Instant> = OnceLock::new();

fn port_file() -> PathBuf {
    aidm_core::app_data_dir().join(PORT_FILE)
}

fn read_port() -> Option<u16> {
    std::fs::read_to_string(port_file())
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// 相对进程启动的毫秒数（单调，不受系统时钟调整影响）。
fn now_ms() -> u64 {
    INSTANT_0.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// 记下「这个端口刚刚确认可用」，同时开启信任窗口。
fn remember_port(port: u16) {
    LAST_PORT.store(u32::from(port), Ordering::Relaxed);
    // 至少存 1：0 表示「没确认过」，别让进程启动 1ms 内的确认被当成未确认。
    LAST_OK_MS.store(now_ms().max(1), Ordering::Relaxed);
}

/// 作废信任窗口（端口已失效）。保留 `LAST_PORT` 当候选：端口文件被删时还靠它找。
fn invalidate_port() {
    LAST_OK_MS.store(0, Ordering::Relaxed);
}

/// 信任窗口判断（纯函数，便于单测）：`stamp` 是该端口的确认时刻。
/// `stamp == 0` 表示从未确认过，永远不可信任。
fn within_trust(stamp: u64, now: u64, ttl_ms: u64) -> bool {
    stamp != 0 && now.saturating_sub(stamp) <= ttl_ms
}

/// 信任窗口内直接复用端口：引擎连上之后，每个 IPC 请求都不必再做一次探测。
fn trusted_port() -> Option<u16> {
    let stamp = LAST_OK_MS.load(Ordering::Relaxed);
    let port = last_port()?;
    within_trust(stamp, now_ms(), PORT_TRUST_MS).then_some(port)
}

fn last_port() -> Option<u16> {
    match LAST_PORT.load(Ordering::Relaxed) {
        0 => None,
        p => u16::try_from(p).ok(),
    }
}

/// 已知端口候选：端口文件优先，其次进程内记忆的端口。
fn port_candidates() -> Vec<u16> {
    let mut out = Vec::new();
    if let Some(p) = read_port() {
        out.push(p);
    }
    if let Some(p) = last_port() {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// 有界探活：连上端口 → 发 `Ping` → 收一行 `{ok:true}`。整段不超过 `timeout`。
///
/// 为什么不用 `aidm_ipc::engine_roundtrip`：它的 `TcpStream::connect` 没有超时，
/// 探测一个**已关闭**的回环端口要 ~2040ms。启动路径上每一毫秒都会被用户看到，
/// 所以这里用 `connect_timeout` 把「连接 + 写 + 读」压进同一个预算；协议不变
/// （同一个 `Ping` 请求、同一行 JSON 响应）。
fn probe(port: u16, timeout: Duration) -> bool {
    let started = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let remain = timeout.saturating_sub(started.elapsed());
    if remain.is_zero() {
        return false;
    }
    let _ = stream.set_read_timeout(Some(remain));
    let _ = stream.set_write_timeout(Some(remain));
    let Ok(mut line) = serde_json::to_string(&EngineRequest::Ping) else {
        return false;
    };
    line.push('\n');
    if stream.write_all(line.as_bytes()).is_err() {
        return false;
    }
    let mut buf = String::new();
    if BufReader::new(stream).read_line(&mut buf).is_err() {
        return false;
    }
    matches!(
        serde_json::from_str::<EngineResponse>(&buf),
        Ok(EngineResponse { ok: true, .. })
    )
}

/// 探测最早出现的可用引擎端口。
fn ping_any(candidates: &[u16], timeout: Duration) -> Option<u16> {
    candidates.iter().copied().find(|&p| probe(p, timeout))
}

/// 是否已有引擎实例在运行（`engine.lock` 被占用）。
/// 这里短暂获取再释放：能拿到锁说明原引擎已退出。
fn engine_running() -> bool {
    match aidm_core::try_acquire_instance_lock(&aidm_core::app_data_dir()) {
        Ok(lock) => {
            drop(lock);
            false
        }
        Err(_) => true,
    }
}

/// 引擎可执行文件（与 UI 同目录：target/debug 或安装目录）。
fn engine_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = if cfg!(windows) {
        "aidm-engine.exe"
    } else {
        "aidm-engine"
    };
    let path = dir.join(name);
    path.exists().then_some(path)
}

/// 单飞闸门状态：同一时刻只允许一个线程做「探测 / 拉起」。
struct EnsureGate {
    /// 是否有线程正在探测/拉起。
    busy: bool,
    /// 完成代际：完成一次探测 +1，等待者据此判断「有新结果了」。
    epoch: u64,
    /// 最近一次结果，供等待者直接复用（失败也复用，避免各自重探一遍）。
    last: Result<u16, String>,
}

static ENSURE_GATE: Mutex<EnsureGate> = Mutex::new(EnsureGate {
    busy: false,
    epoch: 0,
    last: Err(String::new()),
});
static ENSURE_DONE: Condvar = Condvar::new();

fn gate() -> MutexGuard<'static, EnsureGate> {
    // 闸门里不存任何不变量：中毒就取回内部数据继续用，绝不 panic。
    ENSURE_GATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// 进程内单飞：同一时刻只有一个线程执行 `probe_once`，其余线程等它的结果
/// 并**直接复用**（不再各自重复探测、也不会重复 spawn）。
///
/// 等待有上限（[`FOLLOWER_WAIT`]）：UI 主线程调用 `engine_request` 时不能
/// 被一次慢探测长时间按住；超时就返回 `engine_busy`，让上层按自己的节奏重试。
fn single_flight<F>(force: bool, probe_once: F) -> Result<u16, String>
where
    F: FnOnce() -> Result<u16, String>,
{
    if !force {
        if let Some(port) = trusted_port() {
            return Ok(port);
        }
    }

    let wait_until = Instant::now() + FOLLOWER_WAIT;
    let mut g = gate();
    // 1) 已经有人在探测：等它的结果（这就是单飞，不重复工作）。
    while g.busy {
        let now = Instant::now();
        if now >= wait_until {
            return Err("engine_busy".into());
        }
        let epoch = g.epoch;
        let (next, _) = ENSURE_DONE
            .wait_timeout(g, wait_until.saturating_duration_since(now))
            .unwrap_or_else(|e| e.into_inner());
        g = next;
        if g.epoch != epoch {
            return g.last.clone();
        }
    }
    if !force {
        // 等锁期间别人可能已经确认过端口（例如事件泵刚连上）。
        if let Some(port) = trusted_port() {
            return Ok(port);
        }
    }
    // 2) 没人在探测：本线程接手，做完把结果广播给等待者。
    g.busy = true;
    drop(g);
    let outcome = probe_once();
    let mut g = gate();
    g.busy = false;
    g.epoch = g.epoch.wrapping_add(1);
    g.last = outcome.clone();
    ENSURE_DONE.notify_all();
    drop(g);
    outcome
}

/// 轮询等引擎可连接：每 [`POLL_STEP`] 重新取一次端口候选（引擎先监听、后写
/// 端口文件，所以不能只取一次），直到 `deadline`。启动等待与实例锁等待共用。
fn wait_for_engine(deadline: Instant) -> Option<u16> {
    while Instant::now() < deadline {
        std::thread::sleep(POLL_STEP);
        if let Some(port) = ping_any(&port_candidates(), PROBE_TIMEOUT) {
            return Some(port);
        }
    }
    None
}

/// 探测/拉起（只在单飞领导者线程里执行）。
fn probe_or_spawn() -> Result<u16, String> {
    // 1) 已知端口（端口文件 / 进程内记忆）探测一次，整段有界。
    if let Some(port) = ping_any(&port_candidates(), PROBE_TIMEOUT) {
        log::debug!("engine reachable on {port}");
        return Ok(port);
    }

    // 2) 实例锁被占 = 已有引擎在跑：只等它（短暂），绝不另起进程
    //    （另起的进程会被单实例锁挡下退出，形成拉起风暴）。
    if engine_running() {
        return wait_for_engine(Instant::now() + LOCK_WAIT).ok_or_else(|| "engine_busy".into());
    }

    // 3) 没有引擎：拉起一个，最多等 SPAWN_WAIT。
    let exe = engine_exe().ok_or("engine_binary_not_found")?;
    log::info!("spawning engine: {}", exe.display());
    let mut cmd = std::process::Command::new(&exe);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // 安装版由界面拉起引擎：DETACHED_PROCESS 彻底不分配控制台
        // （连隐藏的 conhost 都不创建，比 CREATE_NO_WINDOW 更干净）。
        // 引擎本身保留 console 子系统，`aidm-engine diag` 直接运行时不受影响。
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn engine: {e}"))?;
    let started = Instant::now();
    match wait_for_engine(started + SPAWN_WAIT) {
        Some(port) => {
            log::info!(
                "engine ready on {port} ({}ms after spawn)",
                started.elapsed().as_millis()
            );
            Ok(port)
        }
        None => {
            log::warn!(
                "engine not ready {}ms after spawn",
                started.elapsed().as_millis()
            );
            Err("engine_not_ready".into())
        }
    }
}

/// 确保引擎可连接（单飞）：先复用信任窗口内的端口；否则由一个线程探测或拉起，
/// 其余线程复用它的结果。
///
/// 拉起前先判断是否已有实例在跑——已有实例时只等待恢复，绝不另起进程。
fn ensure_engine(force: bool) -> Result<u16, String> {
    let started = Instant::now();
    let outcome = single_flight(force, probe_or_spawn);
    let took = started.elapsed();
    match outcome {
        Ok(port) => {
            remember_port(port);
            if took.as_millis() >= SLOW_LOG_MS {
                log::info!(
                    "engine ready on {port} (ensure took {}ms)",
                    took.as_millis()
                );
            }
            Ok(port)
        }
        Err(e) => {
            if took.as_millis() >= SLOW_LOG_MS {
                log::warn!("engine ensure failed after {}ms: {e}", took.as_millis());
            }
            Err(e)
        }
    }
}

fn with_engine<F>(mut send_once: F) -> Result<EngineResponse, String>
where
    F: FnMut(u16) -> Result<EngineResponse, String>,
{
    let mut last_err = None;
    for attempt in 0..2 {
        // 首次走快路径（信任窗口内零探测）；这次失败后强制完整探测 + 重连，
        // 引擎重启换了端口也能自愈。绝不删除端口文件：那是引擎的地址。
        let port = ensure_engine(attempt > 0)?;
        match send_once(port) {
            Ok(resp) => {
                remember_port(port);
                return Ok(resp);
            }
            Err(e) => {
                // 这个端口已经不可用：作废信任窗口，下一轮必须重新探测。
                invalidate_port();
                last_err = Some(e);
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "engine_unreachable".into()))
}

/// 发送单个请求；连接失败时重试一次（可能引擎刚被拉起或端口刷新）。
pub fn send(req: EngineRequest) -> Result<EngineResponse, String> {
    with_engine(|port| aidm_ipc::engine_roundtrip(port, &req, REQ_TIMEOUT))
}

/// `subscribe` 长连接：45 秒无任何消息则断开并重连（心跳 15s）。
pub fn spawn_event_pump(app: tauri::AppHandle) {
    let _ = std::thread::Builder::new()
        .name("aidm-ui-subscribe".into())
        .spawn(move || loop {
            if let Err(e) = pump_once(&app) {
                log::warn!("subscribe ended ({e}); reconnect in 1s");
            }
            std::thread::sleep(Duration::from_secs(1));
        });
}

fn emit_engine_status(app: &tauri::AppHandle, online: bool) {
    let _ = app.emit("engine-status", serde_json::json!({ "online": online }));
}

fn pump_once(app: &tauri::AppHandle) -> Result<(), String> {
    let port = match ensure_engine(false) {
        Ok(p) => p,
        Err(e) => {
            emit_engine_status(app, false);
            return Err(e);
        }
    };
    let mut sub = match aidm_ipc::engine_subscribe(port, SUBSCRIBE_HANDSHAKE) {
        Ok(s) => s,
        Err(e) => {
            // 端口已经不通了：作废信任窗口，1 秒后的重连会做完整探测/重新拉起。
            invalidate_port();
            emit_engine_status(app, false);
            return Err(e);
        }
    };
    sub.set_read_timeout(Some(Duration::from_secs(SUBSCRIBE_STALE_SECS)))?;
    emit_engine_status(app, true);
    log::info!("subscribe connected (stale={SUBSCRIBE_STALE_SECS}s)");
    loop {
        match sub.read_event() {
            Ok(ev) => dispatch_event(app, &ev),
            Err(e) => {
                emit_engine_status(app, false);
                return Err(e);
            }
        }
    }
}

fn dispatch_event(app: &tauri::AppHandle, ev: &EngineEvent) {
    if matches!(ev, EngineEvent::Candidates { .. }) {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.show();
            let _ = win.unminimize();
            let _ = win.set_focus();
        }
    }
    let _ = app.emit("engine-event", ev);
    if let EngineEvent::Stats { total_speed, .. } = ev {
        if let Some(tray) = app.tray_by_id("aidm-tray") {
            let tip = logic::tray_tooltip(*total_speed);
            let _ = tray.set_tooltip(Some(tip.as_str()));
        }
    }
}

pub fn pause_all_active() {
    let Ok(resp) = send(EngineRequest::List) else {
        return;
    };
    let Some(tasks) = resp.tasks else {
        return;
    };
    for t in tasks {
        if matches!(
            t.state.as_str(),
            "connecting" | "downloading" | "verifying" | "queued"
        ) {
            let _ = send(EngineRequest::Pause { id: t.id });
        }
    }
}

/// 「开始全部」：恢复 paused / verifying 状态的任务（error 不在此项处理）。
pub fn resume_all_paused() {
    let Ok(resp) = send(EngineRequest::List) else {
        return;
    };
    let Some(tasks) = resp.tasks else {
        return;
    };
    for t in tasks {
        if is_resumable_state(&t.state) {
            let _ = send(EngineRequest::Resume { id: t.id });
        }
    }
}

/// 「开始全部」的状态过滤器：只恢复可恢复的暂停/校验中任务。
fn is_resumable_state(state: &str) -> bool {
    matches!(state, "paused" | "verifying")
}

/// 请求引擎进程正常退出（托盘「完全退出」）。失败忽略：UI 仍要退出。
///
/// 只对**已在运行**的引擎发退出：不走 `send`（它会 `ensure_engine` 拉起新进程，
/// 且请求超时 10s）。探测与发请求都用 [`SHUTDOWN_PROBE`] 短超时：引擎活着时
/// 一次回环往返就结束（毫秒级），引擎已退出时最多等一格预算，不在退出路径上卡几秒。
pub fn shutdown_engine() {
    let Some(port) = ping_any(&port_candidates(), SHUTDOWN_PROBE) else {
        return;
    };
    let _ = aidm_ipc::engine_roundtrip(port, &EngineRequest::Shutdown, SHUTDOWN_PROBE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Barrier};

    /// 下面几个用例都会动进程级静态量（端口信任窗口 / 单飞闸门），
    /// 必须串行，否则 `cargo test` 的并行线程会互相干扰。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn resume_all_only_targets_paused_and_verifying() {
        assert!(is_resumable_state("paused"));
        assert!(is_resumable_state("verifying"));
        for state in [
            "queued",
            "connecting",
            "downloading",
            "done",
            "error",
            "interrupted",
            "",
        ] {
            assert!(!is_resumable_state(state), "{state} must not be resumed");
        }
    }

    #[test]
    fn trusted_port_window_and_invalidation() {
        let _g = serial();
        invalidate_port();
        assert_eq!(trusted_port(), None, "没确认过就不能信任");

        remember_port(4567);
        assert_eq!(trusted_port(), Some(4567), "刚确认的端口在窗口内直接复用");

        // 请求失败后必须作废：否则会一直往死端口发请求。
        invalidate_port();
        assert_eq!(trusted_port(), None);
    }

    /// 信任窗口的边界：过期就必须重新探测（时间注入，不靠 sleep 5 秒）。
    #[test]
    fn trust_window_boundaries() {
        let ttl = PORT_TRUST_MS;
        assert!(!within_trust(0, 1_000, ttl), "从未确认过不可信任");
        assert!(within_trust(1_000, 1_000, ttl), "刚确认");
        assert!(within_trust(1_000, 1_000 + ttl, ttl), "正好到边界仍可信");
        assert!(!within_trust(1_000, 1_001 + ttl, ttl), "越过边界即过期");
    }

    /// 并发进 `ensure_engine` 只能有一个线程真正探测/拉起（这就是「不再重复
    /// spawning engine」的证据），其余线程复用同一结果。
    #[test]
    fn concurrent_callers_probe_once() {
        let _g = serial();
        invalidate_port();
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let calls = Arc::clone(&calls);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait(); // 8 个线程同时冲闸门
                single_flight(true, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(200));
                    Ok(4567u16)
                })
            }));
        }
        for h in handles {
            assert_eq!(h.join().expect("thread"), Ok(4567));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "并发调用只应探测一次");
    }

    /// 失败结果同样复用：不会因为探测失败就让每个调用者各自重探一遍。
    #[test]
    fn concurrent_callers_reuse_failure() {
        let _g = serial();
        invalidate_port();
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(6));
        let mut handles = Vec::new();
        for _ in 0..6 {
            let calls = Arc::clone(&calls);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                single_flight(true, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(200));
                    Err("engine_busy".to_string())
                })
            }));
        }
        for h in handles {
            assert_eq!(h.join().expect("thread"), Err("engine_busy".to_string()));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// 已关闭的端口：本机 `connect` 实测要 ~2 秒，`probe` 必须自己把它压进预算。
    #[test]
    fn probe_rejects_closed_port_within_timeout() {
        let port = {
            // 先绑一个再立刻放手：保证“刚才没人监听”且端口号确定。
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let started = Instant::now();
        assert!(!probe(port, PROBE_TIMEOUT), "没有引擎的端口必须探测失败");
        let took = started.elapsed();
        assert!(
            took < PROBE_TIMEOUT + Duration::from_millis(400),
            "probe 必须在预算内返回，实际 {took:?}"
        );
    }

    /// 能连上但一直不回包（引擎繁忙/卡死）：读超时同样必须在预算内生效。
    #[test]
    fn probe_rejects_silent_listener_within_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(2));
                drop(stream);
            }
        });
        let started = Instant::now();
        assert!(!probe(port, PROBE_TIMEOUT), "不回包的端口必须探测失败");
        let took = started.elapsed();
        assert!(
            took < PROBE_TIMEOUT + Duration::from_millis(400),
            "probe 必须在预算内返回，实际 {took:?}"
        );
    }

    /// 正常引擎（回一行 `{"ok":true}`）：probe 必须判定可用。
    #[test]
    fn probe_accepts_engine_ping_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let reply = format!(
            "{}\n",
            serde_json::to_string(&EngineResponse::ok()).expect("json")
        );
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = String::new();
                let Ok(reader) = stream.try_clone() else {
                    break;
                };
                let _ = BufReader::new(reader).read_line(&mut buf);
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        assert!(probe(port, PROBE_TIMEOUT), "健康引擎应探测成功");
    }
}
