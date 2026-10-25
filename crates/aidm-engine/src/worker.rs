//! 下载协调线程：Range 探测、单线程（单连接路径）或多连接分段、合并校验。

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aidm_core::error;
use aidm_core::filename::resolve_filename;
use aidm_core::hash::sha256_file;
use aidm_core::download::control::WriteGate;
use aidm_core::download::control::WriteLease;
use aidm_core::download::model::{AssignmentId, SliceId, Span};
use aidm_core::model::{self, DownloadRow, Status};
use aidm_core::sched;
use aidm_core::segment::{
    self, backoff_for_attempt, parse_retry_after, plan_segments, validators_changed,
    SEGMENT_RETRY_MAX,
};
use aidm_core::settings;
use aidm_core::speed::SpeedWindow;
use rusqlite::Connection;

use aidm_ipc::EngineEvent;

use crate::checksum;
use crate::fastdl;
use crate::http_util::{apply_common, header_owned, HttpRuntime};
use crate::limiter::TokenBucket;
use crate::manager::{EventHub, IoFault, LiveState, Progress, ProgressCallback, TaskHandle};
use crate::merge::{cleanup_task_files, merge_parts, remove_part_dir};
use crate::metalink_source;
use crate::mirrorlist_source;
use crate::probe;

mod ed2k_parallel;

pub enum WorkerEnd {
    Done,
    Paused,
    Cancelled,
    Failed(String),
}

const READ_BUF: usize = 64 * 1024;
const PERSIST_INTERVAL: Duration = Duration::from_millis(500);

/// 一次下载任务的运行上下文。`pub(crate)`：只在引擎进程内部被
/// `manager::spawn_worker` 组装、被 `fastdl` 读取；字段里含
/// `pub(crate)` 的 `TaskHandle`，所以结构体本身也不该是 `pub`。
pub(crate) struct Args {
    pub id: i64,
    pub db: Arc<Mutex<Connection>>,
    pub default_dir: PathBuf,
    pub live: Arc<LiveState>,
    pub cancel: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
    /// 配额“停止”：与 pause 同时置位，退出时写 error/quota 而不是 paused。
    pub stop: Arc<AtomicBool>,
    pub referer: Option<String>,
    pub cookies: Option<String>,
    /// 浏览器发起时透传的 UA
    pub browser_user_agent: Option<String>,
    /// 每任务自定义请求头（`Name: value` 逐行）
    pub custom_headers: Option<String>,
    pub filename: Option<String>,
    pub resume: bool,
    pub speed_window: Arc<SpeedWindow>,
    pub progress_cb: Option<ProgressCallback>,
    pub tasks: Arc<Mutex<HashMap<i64, TaskHandle>>>,
    pub limiter: Arc<TokenBucket>,
    pub http: Arc<HttpRuntime>,
    pub events: Arc<EventHub>,
    pub active_conns: Arc<AtomicU64>,
    pub io_fault: IoFault,
    /// 下载内核在此登记"热调"回调：改并发上限不再需要停任务重启。
    pub retune: Arc<crate::manager::RetuneCell>,
    /// BitTorrent 完成后继续做种的会话登记处（L6/BT）。
    pub bt_seeds: Arc<crate::bt::SeedRegistry>,
    /// BitTorrent 逐文件选择的共享状态（IPC 写、worker 应用、双方读文件表）。
    pub bt_selection: Arc<Mutex<crate::bt::BtSelection>>,
    /// 写入许可闸门。`Some` 时**所有真实写盘**必须先通过 `check`，
    /// 撤销后新写入一律被拒；`None` 表示不启用闸门（仅用于不涉及写盘的测试夹具）。
    pub gate: Option<Arc<WriteGate>>,
    /// 任务归属（文档 12.2：任何时刻只能由一种模式拥有）。
    ///
    /// 决定切片方案缺失时的行为：legacy 允许兜底自算并写表；unified **不许自算**，
    /// 否则就是「unified 名义、legacy 决策」的双归属。
    pub execution_mode: aidm_core::download::control::ExecutionMode,
}

struct Ctx<'a> {
    args: &'a Args,
    /// UA / Accept 系列 / Referer 兜底
    profile: aidm_core::http_profile::RequestProfile,
    /// 每任务自定义请求头（已解析校验；空表示没有）
    custom_headers: Vec<aidm_core::headers::HeaderLine>,
    cookies: Option<String>,
}

struct ConnGuard(Arc<AtomicU64>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn acquire_conn(c: &Arc<AtomicU64>) -> ConnGuard {
    c.fetch_add(1, Ordering::Relaxed);
    ConnGuard(c.clone())
}

/// 主源之外的候选晚多久开始探。
///
/// 给主源一个"先手"：它可用且正常时，这段时间足够它探完，于是镜像请求**根本不会发出去**
/// （见 `cancel`）。取 800 ms —— 高于实测的镜像往返（本地毫秒级、公网 0.2–1 s），
/// 又远低于那次 5.14 s 的失败等待。
const HEDGE_DELAY: Duration = Duration::from_millis(800);

/// 并行预探的命中。
struct HedgeHit {
    idx: usize,
    url: String,
    /// 这一跳是靠"不声明客户端身份"通的 —— 之后的下载必须沿用同一套头。
    omit_ua: bool,
    probed: probe::ProbeResult,
}

/// 并行预探的结果。
struct HedgeProbe {
    /// 第一个可用（且长度自洽）的候选；`None` = 所有第一跳都没成。
    hit: Option<HedgeHit>,
    /// 并行阶段已经探过并失败的第一跳：`idx` →（错误, 耗时）。
    /// 串行阶段直接复用，**不再重复发一次请求** —— 否则失败路径要付两倍时间。
    failed: std::collections::HashMap<usize, (String, Duration)>,
}

/// 并行预探各候选的**第一跳**，返回第一个可用的候选。
///
/// 起因是实测：`mirrors.aliyun.com` 主源要 **5.14 秒**才失败（302 到一台死主机），
/// 而旁边 6 个镜像都是 **0 秒可用** —— 用户看到的就是"点下任务后干等 5 秒才开始下载"。
/// 串行遍历时这段纯粹是等待，与"哪个源更好"无关。
///
/// ## 为什么用分离线程，而不是 `thread::scope`
///
/// scope 退出时会 join 全部线程，于是"主源 0.2 秒就成了、某个死镜像 5 秒才失败"
/// 依然要等满 5 秒 —— 那正是要消掉的等待。分离线程让调用方拿到第一个成功结果就往下走；
/// 落后者自己跑完把结果投进已关闭的 channel（`send` 失败即返回，不 panic）。
/// 每个探测都有 ureq 的超时上界，线程必然结束，不会泄漏。
///
/// ## 零浪费
///
/// 主源在 `HEDGE_DELAY` 内成功时，其余线程还在分片睡眠，会被 `cancel` 立即叫停，
/// **一个镜像请求都不会发出去**；主源失败时收集端置 `hurry`，其余线程立刻结束等待
/// 开始探测，不必再等满延迟。分片睡眠就是为了让这两个信号能在 100 ms 粒度上生效。
///
/// 失败**不在这里记事件**：串行阶段本来就负责留痕，这里只把结果交给它复用
/// （`failed`），事件顺序因此不因并行而改变。
fn probe_first_hops_parallel(
    args: &Args,
    ctx: &Ctx<'_>,
    cands: &[String],
    order: &[usize],
    start: usize,
    primary_count: usize,
    row_size: Option<i64>,
) -> HedgeProbe {
    type Sent = (
        usize,
        String,
        bool,
        Result<probe::ProbeResult, String>,
        Duration,
    );

    let mut failed: std::collections::HashMap<usize, (String, Duration)> =
        std::collections::HashMap::new();
    let (tx, rx) = std::sync::mpsc::channel::<Sent>();
    let cancel = Arc::new(AtomicBool::new(false));
    let hurry = Arc::new(AtomicBool::new(false));
    let total = order.len();

    for &idx in order {
        let url = cands[idx].clone();
        let http = args.http.clone();
        let conns = args.active_conns.clone();
        let base_profile = ctx.profile.clone();
        let headers = ctx.custom_headers.clone();
        let cookies = ctx.cookies.clone();
        let referer = args.referer.clone();
        let is_start = idx == start;
        let omit_first = idx >= primary_count;
        let tx = tx.clone();
        let cancel = cancel.clone();
        let hurry = hurry.clone();
        std::thread::spawn(move || {
            if !is_start {
                // 分片睡眠：两个信号都能在 HEDGE_DELAY/8 内被打断
                const SLICES: u32 = 8;
                for _ in 0..SLICES {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    if hurry.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(HEDGE_DELAY / SLICES);
                }
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
            }
            let agent = http.agent_for(&url);
            let mut omit = omit_first;
            let started = Instant::now();
            let run = |p: &aidm_core::http_profile::RequestProfile| {
                let _g = acquire_conn(&conns);
                probe::probe(
                    &agent,
                    &url,
                    p,
                    referer.as_deref(),
                    cookies.as_deref(),
                    &headers,
                )
            };
            let mut outcome = if omit {
                run(&base_profile.clone().without_browser_ua())
            } else {
                run(&base_profile)
            };
            // 匿名不通 → 退回带 UA 重试**同一跳**（与串行路径同语义，且不记事件）
            if outcome.is_err() && omit {
                omit = false;
                outcome = run(&base_profile);
            }
            let _ = tx.send((idx, url, omit, outcome, started.elapsed()));
        });
    }
    drop(tx);

    let mut hit = None;
    for _ in 0..total {
        let Ok((idx, url, omit_ua, outcome, took)) = rx.recv() else {
            break;
        };
        match outcome {
            Ok(p) => {
                // 长度自洽才采纳；`start` 那一槽是已落库长度的来源，免检
                // —— 与串行路径用的是同一个判定。
                if idx == start || aidm_core::alt::size_compatible(row_size, p.total) {
                    hit = Some(HedgeHit {
                        idx,
                        url,
                        omit_ua,
                        probed: p,
                    });
                    break;
                }
                // 长度不符：不采纳，也**不缓存** —— 串行阶段会用原有的 `reason=size`
                // 分支重新判定并留痕，这里的重复探测只发生在失配这种罕见情况。
                if idx == start {
                    hurry.store(true, Ordering::Relaxed);
                }
            }
            Err(e) => {
                if idx == start {
                    // 主源已经失败，其余候选没必要再等满延迟
                    hurry.store(true, Ordering::Relaxed);
                }
                failed.insert(idx, (e, took));
            }
        }
    }
    // 命中就立刻叫停还在等待的线程：主源快时镜像请求一个都不发
    cancel.store(true, Ordering::Relaxed);
    HedgeProbe { hit, failed }
}

struct RateLimit {
    bps: u64,
    window_start: Mutex<Instant>,
    used: Mutex<u64>,
}

impl RateLimit {
    fn new(kbps: i64) -> Arc<Self> {
        Arc::new(Self {
            bps: (kbps.max(0) as u64).saturating_mul(1024),
            window_start: Mutex::new(Instant::now()),
            used: Mutex::new(0),
        })
    }

    fn take(&self, n: u64) {
        if self.bps == 0 {
            return;
        }
        loop {
            let sleep_for = {
                let mut used = self.used.lock().unwrap();
                let mut start = self.window_start.lock().unwrap();
                if start.elapsed() >= Duration::from_secs(1) {
                    *start = Instant::now();
                    *used = 0;
                }
                if *used + n <= self.bps {
                    *used += n;
                    return;
                }
                Duration::from_secs(1).saturating_sub(start.elapsed())
            };
            std::thread::sleep(sleep_for.max(Duration::from_millis(5)));
        }
    }
}

/// 任务实际连接数：正常预算再叠一层「找源失败后的退避上限」。
/// 每任务期望连接数。实现已搬到 `aidm_core::model::task_conns_for`
/// （协调器影子也要用同一个解析器，否则两边会切出不同段数）。
fn task_conns_for(conn: &Connection, row: &DownloadRow) -> u32 {
    aidm_core::model::task_conns_for(conn, row)
}

/// 签名直链的限流/拒绝：只有数据请求返回 503/429 才进入“先找源、后减半”。
fn is_signed_rate_limit(code: &str) -> bool {
    matches!(error::classify(code).http_status, Some(429 | 503))
}

/// 下一档连接上限：8 → 4 → 2 → 1；到 1 后不再继续减。
fn next_conn_cap(base: u32, current: Option<u32>) -> u32 {
    match current {
        Some(c) => (c / 2).max(1),
        None => (base / 2).max(1),
    }
}

/// 所有现有候选都失败后，按判断器预算找一轮新源；成功则返回 `(url, probe, cursor)`。
///
/// 只做“救一次”：找到的第一个可用候选立即返回，并把地址追加进 `alt_urls`，
/// 让重启后的候选序列与 cursor 仍然一致。完整候选池落 `source_candidates`，
/// 供后续多源调度（P2）消费。
/// 找源只对公网 http(s) 有意义：本机/内网地址在 Wayback/archive.org 上不可能有捕获，
/// 而且集成测试大量使用 127.0.0.1 的死端口 —— 不挡会把测试变成外网搜索。
fn finder_eligible(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host == "localhost" || host == "0.0.0.0" || host == "::1" || host.ends_with(".local") {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified())
            }
            std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified()),
        };
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FindRuntime {
    enabled: bool,
    total_ms: i64,
    max_candidates: usize,
    negative_ttl_ms: i64,
    platform_qpm: u32,
    slow_window_s: i64,
    slow_min_mbps: u64,
}

/// 从设置表读出找源预算。抽成函数便于单测“设置确实被消费”，而不是只测默认值。
fn find_runtime_config(conn: &Connection) -> FindRuntime {
    let get = |k: &str| {
        settings::get(conn, k)
            .ok()
            .flatten()
            .or_else(|| settings::default_of(k).map(str::to_string))
            .unwrap_or_default()
    };
    let int = |k: &str, fallback: i64| get(k).trim().parse::<i64>().unwrap_or(fallback);
    let enabled = get("find.enabled").trim().eq_ignore_ascii_case("true");
    // 用户明确：找源 60 秒硬顶。设置上限也只有 60，双保险。
    let total_ms = int("find.max_elapsed_s", 60).clamp(0, 60) * 1000;
    let max_candidates = int("find.max_candidates", 12).clamp(1, 32) as usize;
    let negative_ttl_ms = int("find.negative_ttl_s", 600).clamp(60, 86_400) * 1000;
    let platform_qpm = int("find.platform_qpm", 6).clamp(1, 120) as u32;
    let slow_window_s = int("find.slow_window_s", 60).clamp(0, 600);
    let slow_min_mbps = int("find.slow_min_mbps", 50).clamp(0, 10_000) as u64;
    FindRuntime {
        enabled,
        total_ms,
        max_candidates,
        negative_ttl_ms,
        platform_qpm,
        slow_window_s,
        slow_min_mbps,
    }
}

/// 下载开始后慢速重触发找源：连续 `slow_window_s` 秒低于 `slow_min_kbps`
/// （默认 60 s / 50 MiB/s）就开一轮 finder；任务结束/暂停/取消即退出。
fn spawn_slow_finder(args: &Args, row: &DownloadRow, effective_orig: &str, stop: Arc<AtomicBool>) {
    let runtime = {
        let conn = args.db.lock().unwrap();
        find_runtime_config(&conn)
    };
    if !runtime.enabled
        || runtime.slow_window_s <= 0
        || runtime.slow_min_mbps == 0
        || !finder_eligible(effective_orig)
    {
        return;
    }
    let db = args.db.clone();
    let http = args.http.clone();
    let live = args.live.clone();
    let cancel = args.cancel.clone();
    let pause = args.pause.clone();
    let orig = effective_orig.to_string();
    let task =
        aidm_core::source::TaskProfile::from_row(row, aidm_core::source::TaskPolicy::default());
    std::thread::spawn(move || {
        let stop_fn = || {
            stop.load(Ordering::SeqCst)
                || cancel.load(Ordering::SeqCst)
                || pause.load(Ordering::SeqCst)
        };
        let finder = crate::source::Finder::new(
            vec![
                Box::new(crate::source::ArchiveOrgAdapter::new(http.clone())),
                Box::new(crate::source::WaybackAdapter::new(http.clone())),
                Box::new(crate::source::GitHubAdapter::new(http.clone())),
            ],
            crate::source::FinderConfig {
                negative_ttl_ms: runtime.negative_ttl_ms,
                quota_per_min: runtime.platform_qpm,
                ..Default::default()
            },
        );
        let query = aidm_core::source::SourceQuery {
            file_name: task.file_name.clone(),
            size: task.size,
            hashes: task.hashes.clone(),
            version: task.version.clone(),
            orig_url: Some(orig),
            source_hint: None,
        };
        let min_bps = runtime.slow_min_mbps.saturating_mul(1024 * 1024);
        let mut below = 0i64;
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if stop_fn() {
                break;
            }
            let speed = live.speed_bps.load(Ordering::Relaxed);
            if speed < min_bps {
                below = below.saturating_add(1);
            } else {
                below = 0;
            }
            if below < runtime.slow_window_s {
                continue;
            }
            below = 0;
            let now = crate::source_registry::now_ms();
            let out = finder.find_cancellable(
                &query,
                now,
                runtime.total_ms,
                runtime.max_candidates,
                &stop_fn,
            );
            if stop_fn() {
                break;
            }
            let conn = db.lock().unwrap();
            let stored = model::upsert_source_candidates(&conn, task.task_id, &out.candidates, now)
                .unwrap_or(0);
            model::log_event(
                &conn,
                task.task_id,
                "source_find",
                Some(&format!(
                    "reason=slow found={} stored={} errors={} dur={}s",
                    out.candidates.len(),
                    stored,
                    out.errors.len(),
                    runtime.slow_window_s
                )),
            );
        }
    });
}

struct SlowFindGuard(Arc<AtomicBool>);

impl Drop for SlowFindGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn set_found_candidate_state(
    ctx: &Ctx<'_>,
    row: &DownloadRow,
    url: &str,
    state: &str,
    reason: &str,
) {
    let conn = ctx.args.db.lock().unwrap();
    if let Ok(rows) = model::list_source_candidates(&conn, row.id, None) {
        if let Some(r) = rows.iter().find(|r| r.url == url) {
            let _ = model::set_source_candidate_state(&conn, r.id, state);
        }
    }
    model::log_event(
        &conn,
        row.id,
        "source_suspend",
        Some(&format!("state={state} reason={reason}")),
    );
}

fn find_and_probe_alternative(
    ctx: &Ctx<'_>,
    row: &DownloadRow,
    effective_orig: &str,
    now_ms: i64,
) -> Option<(String, probe::ProbeResult, usize)> {
    use aidm_core::source::{SourceQuery, TaskPolicy, TaskProfile};

    let runtime = {
        let conn = ctx.args.db.lock().unwrap();
        find_runtime_config(&conn)
    };
    let (enabled, total_ms, max_candidates, negative_ttl_ms, platform_qpm) = (
        runtime.enabled,
        runtime.total_ms,
        runtime.max_candidates,
        runtime.negative_ttl_ms,
        runtime.platform_qpm,
    );
    let stop = || ctx.args.cancel.load(Ordering::SeqCst) || ctx.args.pause.load(Ordering::SeqCst);
    if stop() {
        return None;
    }
    let profile = TaskProfile::from_row(row, TaskPolicy::default());
    let query = SourceQuery {
        file_name: profile.file_name.clone(),
        size: profile.size,
        hashes: profile.hashes.clone(),
        version: profile.version.clone(),
        orig_url: Some(effective_orig.to_string()),
        source_hint: None,
    };

    // 源与任务绑定：`source_candidates` 按 download_id 持久化，暂停/重启/重新下载
    // 都会先复用它，避免"任务没删、重下又找一遍"。
    let cached: Vec<aidm_core::source::CandidateSource> = {
        let conn = ctx.args.db.lock().unwrap();
        model::list_source_candidates(&conn, row.id, None)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.state == "candidate" || r.state == "admitted")
            .filter(|r| r.expires_at.is_none_or(|e| e > now_ms))
            .filter_map(|r| model::row_to_candidate(&r))
            .collect()
    };
    let mut candidates = if cached.is_empty() {
        // 只有真正要发起外部查询时才限制公网地址；任务绑定的缓存源不受此限。
        if !finder_eligible(effective_orig) {
            return None;
        }
        if !enabled {
            let conn = ctx.args.db.lock().unwrap();
            model::log_event(&conn, row.id, "source_find", Some("skip=Disabled"));
            return None;
        }
        let finder = crate::source::Finder::new(
            vec![
                Box::new(crate::source::ArchiveOrgAdapter::new(ctx.args.http.clone())),
                Box::new(crate::source::WaybackAdapter::new(ctx.args.http.clone())),
                Box::new(crate::source::GitHubAdapter::new(ctx.args.http.clone())),
            ],
            crate::source::FinderConfig {
                negative_ttl_ms,
                quota_per_min: platform_qpm,
                ..Default::default()
            },
        );
        let out = finder.find_cancellable(&query, now_ms, total_ms, max_candidates, &stop);
        if stop() {
            return None;
        }
        let spent = crate::source_registry::now_ms().saturating_sub(now_ms);
        {
            let conn = ctx.args.db.lock().unwrap();
            let _ = model::set_find_state(
                &conn,
                row.id,
                row.find_rounds + 1,
                row.find_spent_ms + spent,
                Some(now_ms),
            );
            let stored = model::upsert_source_candidates(&conn, row.id, &out.candidates, now_ms)
                .unwrap_or(0);
            model::log_event(
                &conn,
                row.id,
                "source_find",
                Some(&format!(
                    "found={} stored={} errors={} unsupported={} dur_ms={spent}",
                    out.candidates.len(),
                    stored,
                    out.errors.len(),
                    out.unsupported
                )),
            );
        }
        out.candidates
    } else {
        let conn = ctx.args.db.lock().unwrap();
        model::log_event(
            &conn,
            row.id,
            "source_find",
            Some(&format!("cached={}", cached.len())),
        );
        cached
    };

    // 评分排序：有真实传输记录的源优先；没分的保持 finder 原顺序。只排能直接下载的候选。
    if let Some(size) = row.size_total.filter(|v| *v > 0) {
        let urls: Vec<String> = candidates
            .iter()
            .filter(|c| c.kind.is_direct_file())
            .map(|c| c.url.clone())
            .collect();
        let ranked = crate::source_registry::order_by_score(&urls, size as u64);
        candidates.sort_by_key(|c| {
            ranked
                .iter()
                .position(|u| u == &c.url)
                .unwrap_or(usize::MAX)
        });
    }

    // 抽样多数派：只淘汰“明显不同”的候选，**不**把抽样一致升格为文件身份，
    // 因此不会授权跨源分段。最多抽前 3 个能直接下载的候选。
    if let Some(size) = row.size_total.filter(|v| *v > 0) {
        let mut sampled: Vec<(usize, aidm_core::source::SampleSet, u64, u64, u64)> = Vec::new();
        for (idx, cand) in candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.kind.is_direct_file())
            .take(3)
        {
            if stop() {
                return None;
            }
            if let Ok(f) = crate::source::fetch_samples(
                &ctx.args.http,
                &ctx.profile,
                &cand.url,
                size as u64,
                ctx.args.referer.as_deref(),
                ctx.cookies.as_deref(),
                &ctx.custom_headers,
            ) {
                sampled.push((idx, f.set, f.ttfb_ms, f.elapsed_ms, f.bytes));
            }
        }
        if sampled.len() >= 2 {
            let sets: Vec<_> = sampled.iter().map(|(_, s, _, _, _)| s.clone()).collect();
            if let Some(m) = aidm_core::source::majority(&sets) {
                let conn = ctx.args.db.lock().unwrap();
                for (idx, _, _, _, _) in &sampled {
                    let url = &candidates[*idx].url;
                    let score = crate::source_registry::score_of(url, size as u64).map(|s| s.total);
                    let _ = model::set_source_candidate_probe(&conn, row.id, url, now_ms, score);
                }
                let reject: Vec<usize> = m.reject.iter().map(|k| sampled[*k].0).collect();
                for idx in &reject {
                    if let Ok(rows) =
                        model::list_source_candidates(&conn, row.id, Some("candidate"))
                    {
                        if let Some(r) = rows.iter().find(|r| r.url == candidates[*idx].url) {
                            let _ = model::set_source_candidate_state(&conn, r.id, "rejected");
                        }
                    }
                }
                model::log_event(
                    &conn,
                    row.id,
                    "source_verify",
                    Some(&format!(
                        "samples={} kept={} rejected={} uncertain={} ttfb_ms={} elapsed_ms={} bytes={}",
                        sampled.len(),
                        m.keep.len(),
                        reject.len(),
                        m.uncertain,
                        sampled.iter().map(|(_, _, t, _, _)| *t).min().unwrap_or(0),
                        sampled.iter().map(|(_, _, _, e, _)| *e).sum::<u64>(),
                        sampled.iter().map(|(_, _, _, _, b)| *b).sum::<u64>()
                    )),
                );
                drop(conn);
                let mut i = 0usize;
                candidates.retain(|_| {
                    let keep = !reject.contains(&i);
                    i += 1;
                    keep
                });
            }
        }
    }

    // 多源消费（G11）：只把 L4 强摘要候选喂给现有跨源聚合，且摘要必须一致。
    // L1/L2/L3 暂不进池：`multi_source_allowed` 目前只认整文件 SHA-256。
    {
        use aidm_core::source::IdentityEvidence;
        let l4: Vec<(String, String)> = candidates
            .iter()
            .filter_map(|c| match &c.evidence {
                IdentityEvidence::StrongDigest(h) if c.kind.is_direct_file() => {
                    let hex = h.normalized_hex();
                    (!hex.is_empty()).then(|| (c.url.clone(), hex))
                }
                _ => None,
            })
            .collect();
        if !l4.is_empty() {
            let mut expected = row.sha256_expected.clone();
            if expected.is_none() {
                // 只有“所有 L4 候选同一摘要”才敢把它写成任务身份。
                let first = l4[0].1.clone();
                if l4.iter().all(|(_, h)| h.eq_ignore_ascii_case(&first)) {
                    let conn = ctx.args.db.lock().unwrap();
                    let _ = model::set_sha256_expected(&conn, row.id, Some(&first));
                    drop(conn);
                    expected = Some(first);
                }
            }
            if let Some(expected) = expected {
                let matching: Vec<String> = l4
                    .into_iter()
                    .filter(|(_, h)| h.eq_ignore_ascii_case(&expected))
                    .map(|(u, _)| u)
                    .collect();
                if !matching.is_empty() {
                    let conn = ctx.args.db.lock().unwrap();
                    let mut pool = model::get_mirrors_urls(&conn, row.id);
                    let mut added = 0usize;
                    for url in matching {
                        if pool.iter().any(|u| u == &url) {
                            continue;
                        }
                        // active 占一个名额。
                        if pool.len() + 1 >= aidm_core::segment::MAX_SOURCES {
                            break;
                        }
                        pool.push(url);
                        added += 1;
                    }
                    if added > 0 {
                        let _ = model::set_mirrors_urls(&conn, row.id, Some(&pool.join("\n")));
                        model::log_event(
                            &conn,
                            row.id,
                            "source_pool",
                            Some(&format!("added={added} total={}", pool.len())),
                        );
                        for r in model::list_source_candidates(&conn, row.id, Some("candidate"))
                            .unwrap_or_default()
                        {
                            if pool.iter().any(|u| u == &r.url) {
                                let _ = model::set_source_candidate_state(&conn, r.id, "admitted");
                            }
                        }
                    }
                }
            }
        }
    }

    for cand in candidates {
        if stop() {
            return None;
        }
        if !cand.kind.is_direct_file() {
            continue;
        }
        let url = cand.url.clone();
        let p = match probe::probe(
            &ctx.args.http.agent_for(&url),
            &url,
            &ctx.profile,
            ctx.args.referer.as_deref(),
            ctx.cookies.as_deref(),
            &ctx.custom_headers,
        ) {
            Ok(p) => p,
            Err(_) => {
                // 错误串可能带完整 URL，不写事件，只记分类。
                set_found_candidate_state(ctx, row, &url, "suspended", "probe_error");
                continue;
            }
        };
        if p.status == 401 || p.status == 403 {
            set_found_candidate_state(ctx, row, &url, "rejected", &format!("http_{}", p.status));
            continue;
        }
        if p.status == 404 || p.status == 410 {
            set_found_candidate_state(ctx, row, &url, "rejected", &format!("http_{}", p.status));
            continue;
        }
        if p.status != 200 && p.status != 206 {
            set_found_candidate_state(ctx, row, &url, "suspended", &format!("http_{}", p.status));
            continue;
        }
        if let (Some(recorded), Some(total)) = (row.size_total, p.total) {
            if recorded > 0 && recorded as u64 != total {
                set_found_candidate_state(ctx, row, &url, "suspended", "size_mismatch");
                continue;
            }
        }
        // 追加进 alt_urls：重启后 cursor 仍指向它；超过 ALT_MAX 时丢最旧的。
        let mut lines: Vec<&str> = row
            .alt_urls
            .as_deref()
            .unwrap_or("")
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect();
        lines.push(url.as_str());
        if lines.len() > aidm_core::alt::ALT_MAX {
            lines.drain(0..lines.len() - aidm_core::alt::ALT_MAX);
        }
        let alt = lines.join("\n");
        let list = aidm_core::alt::candidates(effective_orig, Some(&alt));
        let Some(cursor) = list.iter().position(|u| u == &url) else {
            continue;
        };
        {
            let conn = ctx.args.db.lock().unwrap();
            let _ = model::set_alt_urls(&conn, row.id, Some(&alt));
            let _ = model::set_alt_cursor(&conn, row.id, cursor as i64);
            if let Ok(rows) = model::list_source_candidates(&conn, row.id, Some("candidate")) {
                if let Some(r) = rows.iter().find(|r| r.url == url) {
                    let _ = model::set_source_candidate_state(&conn, r.id, "admitted");
                }
            }
        }
        return Some((url, p, cursor));
    }
    None
}

pub fn run(args: Args) {
    let started = Instant::now();
    // 任务上下文：此后本线程打的每条日志都带 `task` 字段（规格 §2 不变量 I1）。
    let _task = aidm_core::obs::enter_task("download", args.id);
    // `attempt` = 已用重试次数 + 1，跨进程重启仍稳定（进程内另有 `epoch` 区分运行时）。
    let attempt = {
        let conn = args.db.lock().unwrap();
        model::get_download(&conn, args.id)
            .ok()
            .flatten()
            .map(|r| r.retry_count + 1)
            .unwrap_or(1)
    };
    tracing::info!(
        event = "task.start",
        attempt,
        resume_expected = args.resume
    );
    let end = download_inner(&args);
    // 净下载耗时：worker 线程存在即代表任务在跑，所以这段时长天然排除了
    // 暂停 / 排队 / 退避（那些时刻根本没有本线程）。累加落库，重启后继续。
    let active_ms = started.elapsed().as_millis() as i64;
    args.tasks.lock().unwrap().remove(&args.id);
    let conn = args.db.lock().unwrap();
    let _ = model::add_active_ms(&conn, args.id, active_ms);
    match end {
        WorkerEnd::Done => {
            let done_row = model::get_download(&conn, args.id).ok().flatten();
            let bytes = model::sum_done_bytes(&conn, args.id).unwrap_or(0);
            let avg_speed_bps = if active_ms > 0 {
                bytes.saturating_mul(1000) / active_ms as u64
            } else {
                0
            };
            tracing::info!(
                event = "task.finish",
                outcome = "ok",
                dur_ms = active_ms,
                attempt,
                bytes,
                avg_speed_bps,
                retries = done_row.as_ref().map(|r| r.retry_count).unwrap_or(0),
                alt_used = done_row.as_ref().is_some_and(|r| r.alt_cursor > 0),
            );
            if let Some(row) = done_row {
                let file_path = Path::new(&row.dir)
                    .join(&row.file_name)
                    .to_string_lossy()
                    .into_owned();
                args.events.emit(EngineEvent::TaskCompleted {
                    id: args.id as u64,
                    file_path,
                    source: row.source,
                    dir: row.dir,
                });
            }
        }
        WorkerEnd::Paused => {
            if args.stop.load(Ordering::SeqCst) {
                // 配额“停止”：保留已下载的部分，但任务进入 error/quota，
                // 不再随下一个周期自动排队；用户手动继续时从 Error 恢复。
                let classified = error::classify(error::CODE_QUOTA_EXCEEDED);
                persist_classified(&conn, args.id, &classified);
                model::log_event(&conn, args.id, "quota", Some("action=stop state=error"));
                tracing::warn!(
                    event = "task.fail",
                    outcome = "fail",
                    phase = "task",
                    err_code = error::CODE_QUOTA_EXCEEDED,
                    reason = "quota_exceeded",
                    attempt,
                );
            } else {
                tracing::info!(
                    event = "task.pause",
                    outcome = "skip",
                    dur_ms = active_ms,
                    attempt
                )
            }
        }
        WorkerEnd::Cancelled => {
            tracing::info!(
                event = "task.cancel",
                outcome = "cancel",
                dur_ms = active_ms,
                attempt
            )
        }
        WorkerEnd::Failed(code) => {
            // 配额停止与真实失败同时发生时，以配额为准：否则用户看到的
            // 会是“网络错误”，而不是“流量用尽”。
            if args.stop.load(Ordering::SeqCst) {
                let classified = error::classify(error::CODE_QUOTA_EXCEEDED);
                persist_classified(&conn, args.id, &classified);
                model::log_event(&conn, args.id, "quota", Some("action=stop state=error"));
                tracing::warn!(
                    event = "task.fail",
                    outcome = "fail",
                    phase = "task",
                    err_code = error::CODE_QUOTA_EXCEEDED,
                    reason = "quota_exceeded",
                    attempt,
                );
                return;
            }
            // 普通网络失败再确认一次是否为"本机 hosts/DNS 屏蔽"（运行期间 hosts 被改的情况）。
            // 用实际生效的地址（`url_final`）判断：换过镜像后主地址已经不代表失败原因。
            let code = if error::classify(&code).code == error::CODE_NETWORK {
                model::get_download(&conn, args.id)
                    .ok()
                    .flatten()
                    .and_then(|r| {
                        error::blocked_host(r.url_final.as_deref().unwrap_or(r.url_orig.as_str()))
                    })
                    .map(|detail| {
                        tracing::warn!(
                            event = "net.resolve",
                            phase = "resolve",
                            outcome = "fail",
                            blocked_by_hosts = true,
                            detail = detail.as_str(),
                        );
                        error::CODE_BLOCKED_BY_HOSTS.to_string()
                    })
                    .unwrap_or(code)
            } else {
                code
            };
            let classified = error::classify(&code);
            // 类型化视图：给出准确阶段与原因链（规格 §5）。
            let typed = error::DownloadError::from_code(&code);
            // P2P 等待源：这不是失败。按源状态分级重排，且**不计入重试次数**，
            // 否则"网络里暂时没有源"会把任务最终判成失败。
            if matches!(
                classified.code.as_str(),
                error::CODE_ED2K_NO_SOURCES | error::CODE_ED2K_INCOMPLETE
            ) {
                let row = model::get_download(&conn, args.id).ok().flatten();
                let count = row.as_ref().map(|r| r.retry_count).unwrap_or(0);
                // `ed2k_wait_sources` 命中 archive.org 后已经把 url_orig 改成 HTTP；
                // 此时不要再等 30 秒，也不要保留"暂无可用源"的错误文案。
                let auto_http = row.as_ref().is_some_and(|r| {
                    r.ed2k_hash.is_some()
                        && !r
                            .url_orig
                            .trim_start()
                            .to_ascii_lowercase()
                            .starts_with("ed2k:")
                });
                let wait_ms = p2p_wait_ms(&classified.code, auto_http);
                let retry_at = model::now_ms() + wait_ms;
                let _ = model::set_retry_wait(&conn, args.id, count, retry_at);
                if !auto_http {
                    // 明确告诉用户"为什么还停着"，但不改变 queued 状态
                    let _ = model::set_error_fields(
                        &conn,
                        args.id,
                        Status::Queued,
                        Some(&classified.code),
                        Some(&classified.message),
                        None,
                    );
                }
                let reason = if auto_http {
                    "ed2k_auto_http"
                } else if classified.code == error::CODE_ED2K_NO_SOURCES {
                    "ed2k_no_sources"
                } else {
                    "ed2k_incomplete"
                };
                model::log_event(
                    &conn,
                    args.id,
                    "p2p_wait",
                    Some(&format!(
                        "retry_at={retry_at} code={} auto_http={auto_http}",
                        classified.code
                    )),
                );
                tracing::info!(
                    event = "task.requeue",
                    reason = reason,
                    wait_ms = wait_ms,
                    retry_at_ms = retry_at,
                );
                return;
            }
            if sched::is_network_error(&code) {
                let (retry_max, base) = settings::retry_limits(&conn);
                let count = model::get_download(&conn, args.id)
                    .ok()
                    .flatten()
                    .map(|r| r.retry_count)
                    .unwrap_or(0);
                if (count as u64) >= retry_max {
                    tracing::warn!(
                        event = "task.fail",
                        outcome = "fail",
                        phase = typed.phase().as_str(),
                        err_code = %typed.code(),
                        raw_error = code.as_str(),
                        err_chain = %typed.chain().join(" <- "),
                        retries_exhausted = true,
                        attempt,
                    );
                    persist_classified(&conn, args.id, &classified);
                    // 事件里保留阶段：`error_code` 列是归一化后的机器码（UI/退避依赖它），
                    // 阶段只在原始失败文本里，所以在这里显式落一条（规格 §5 边界 1）。
                    model::log_event(
                        &conn,
                        args.id,
                        "error",
                        Some(&format!(
                            "{} phase={}",
                            classified.code,
                            typed.phase().as_str()
                        )),
                    );
                } else {
                    let next = count + 1;
                    let delay = sched::retry_backoff_ms(base, next as u32);
                    let retry_at = model::now_ms() + delay as i64;
                    let _ = model::set_retry_wait(&conn, args.id, next, retry_at);
                    model::log_event(
                        &conn,
                        args.id,
                        "retry",
                        Some(&format!("count={next} retry_at={retry_at} code={code}")),
                    );
                    tracing::info!(
                        event = "retry.scheduled",
                        reason = code.as_str(),
                        attempt_next = next,
                        retry_max,
                        backoff_ms = delay,
                        retry_at_ms = retry_at,
                    );
                }
            } else {
                tracing::warn!(
                    event = "task.fail",
                    outcome = "fail",
                    phase = typed.phase().as_str(),
                    err_code = %typed.code(),
                    raw_error = code.as_str(),
                    err_chain = %typed.chain().join(" <- "),
                    attempt,
                );
                persist_classified(&conn, args.id, &classified);
                model::log_event(
                    &conn,
                    args.id,
                    "error",
                    Some(&format!(
                        "{} phase={}",
                        classified.code,
                        typed.phase().as_str()
                    )),
                );
            }
        }
    }
}

fn persist_classified(conn: &Connection, id: i64, classified: &error::ClassifiedError) {
    let _ = model::set_error_fields(
        conn,
        id,
        Status::Error,
        Some(&classified.code),
        Some(&classified.message),
        classified.http_status,
    );
}

fn fail_io(fault: IoFault, err: std::io::Error, op: &str) -> WorkerEnd {
    WorkerEnd::Failed(io_fail_string(fault, err, op))
}

pub(crate) fn io_fail_string(fault: IoFault, err: std::io::Error, op: &str) -> String {
    // 写盘阶段的失败必须能一眼定位：故障注入（DiskFull/NoPermission）与真实 io
    // 错误（ENOSPC / 拒绝访问）走的是同一出口，所以在这里统一留痕（规格 §3.2 store）。
    let code = match fault {
        IoFault::DiskFull => error::CODE_DISK_FULL.to_string(),
        IoFault::NoPermission => error::CODE_NO_PERMISSION.to_string(),
        // 非写盘类注入若走到 io 出口，按各自语义给码（矩阵见规格 §8）。
        IoFault::Timeout | IoFault::Disconnect | IoFault::SlowDrip => {
            error::CODE_NETWORK.to_string()
        }
        IoFault::Corrupt => error::CODE_SHA256_MISMATCH.to_string(),
        IoFault::DnsFail => error::CODE_BLOCKED_BY_HOSTS.to_string(),
        IoFault::None => {
            let c = error::classify_io(&err);
            if error::is_known_code(&c.code) {
                c.code
            } else {
                format!("{op}: {err}")
            }
        }
    };
    tracing::warn!(
        event = "store.write",
        phase = "store",
        outcome = "fail",
        op,
        err_code = code.as_str(),
        io_error = %err,
        injected = !matches!(fault, IoFault::None),
    );
    code
}

fn write_all_checked(file: &mut impl Write, buf: &[u8], fault: IoFault) -> Result<(), String> {
    match fault {
        IoFault::DiskFull => Err(error::CODE_DISK_FULL.into()),
        IoFault::NoPermission => Err(error::CODE_NO_PERMISSION.into()),
        // 其余注入不改写盘行为：Timeout/Disconnect/SlowDrip 作用在读循环，
        // Corrupt 作用在校验之前，DnsFail 作用在解析阶段。
        _ => file
            .write_all(buf)
            .map_err(|e| io_fail_string(IoFault::None, e, "write")),
    }
}

/// 读循环的故障注入（规格 §8）：`Some` 表示本次读取应按注入的故障失败。
///
/// 与"建连失败"刻意分开：这里失败时连接**已经建立**，事件序列上必然先有
/// `net.probe` / `transfer.start`，才能把"连得上但收不到数据"与"连不上"区分开。
fn injected_read_fault(fault: IoFault) -> Option<std::io::Error> {
    match fault {
        IoFault::Timeout => Some(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "injected read timeout",
        )),
        IoFault::Disconnect => Some(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "injected connection reset",
        )),
        _ => None,
    }
}

/// 故障注入：写完之后、**校验之前**篡改文件尾字节。
///
/// 刻意篡改真实文件而不是伪造错误码 —— 这样走的是完整的哈希校验链路，
/// 「埋点能否定位文件损坏」才被真正验证（规格 §8）。
fn inject_corruption(fault: IoFault, path: &Path) {
    use std::io::{Read, Seek, SeekFrom};
    if !matches!(fault, IoFault::Corrupt) {
        return;
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    else {
        return;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return;
    };
    if len == 0 {
        return;
    }
    let mut byte = [0u8; 1];
    if f.seek(SeekFrom::Start(len - 1)).is_err() || f.read_exact(&mut byte).is_err() {
        return;
    }
    byte[0] ^= 0xFF;
    if f.seek(SeekFrom::Start(len - 1)).is_ok() {
        let _ = f.write_all(&byte);
        let _ = f.flush();
    }
    tracing::warn!(
        event = "io.fault.injected",
        kind = "corrupt",
        bytes = len,
        msg = "已在写盘后篡改尾字节，校验应当失败",
    );
}

fn download_inner(args: &Args) -> WorkerEnd {
    // 故障注入（规格 §8）：解析阶段失败。按 `blocked_by_hosts` 语义 ——
    // 它**不进网络退避**，与"连不上"是两条不同的处置路径。
    if matches!(args.io_fault, IoFault::DnsFail) {
        tracing::warn!(
            event = "io.fault.injected",
            kind = "dns_fail",
            msg = "解析阶段注入故障",
        );
        return WorkerEnd::Failed(error::CODE_BLOCKED_BY_HOSTS.into());
    }
    let id = args.id;
    let (mut row, was_verifying) = {
        let conn = args.db.lock().unwrap();
        let row = match model::get_download(&conn, id) {
            Ok(Some(r)) => r,
            Ok(None) => return WorkerEnd::Cancelled,
            Err(e) => return WorkerEnd::Failed(format!("db: {e}")),
        };
        let was_verifying = row.status == Status::Verifying;
        let _ = model::set_status(&conn, id, Status::Connecting, None);
        // 上一轮 P2P 等待的 retry_at 到这一轮已经失效；清掉避免库里出现
        // "downloading + retry_at" 的矛盾状态（调度器/诊断都按它判断）。
        let _ = model::clear_retry_at(&conn, id);
        (row, was_verifying)
    };

    let dir = if row.dir.trim().is_empty() {
        args.default_dir.clone()
    } else {
        PathBuf::from(&row.dir)
    };

    // P2P 工作文件由协议哈希验证，任何恢复状态都不能绕到 HTTP 的无 MD4 合并路径。
    if aidm_core::ed2k::is_ed2k_link(&row.url_orig) {
        return ed2k_task(args, &row, &dir);
    }
    if aidm_ipc::is_bittorrent_url(&row.url_orig) {
        return crate::bt::download(args, &row, &dir);
    }

    // fastdl 任务有自己的侧车文件（`.aidm/<id>/fastdl.json`），
    // 它的进度与「part 文件」布局无关，所以非 fastdl 路径的合并/对账分支必须让路。
    let has_fastdl = fastdl::load_state(&dir, id).is_some();

    if was_verifying && !has_fastdl {
        return merge_finish(args, &row, &dir);
    }

    if args.resume && !has_fastdl {
        let segs = {
            let conn = args.db.lock().unwrap();
            model::list_segments(&conn, id).unwrap_or_default()
        };
        if !segs.is_empty()
            && segs.iter().all(|s| s.is_done())
            && model::is_multi_part_layout(&segs)
        {
            return merge_finish(args, &row, &dir);
        }
    }

    // FTP 走独立路径：控制连接 + 数据连接 + REST 续传，与 HTTP 的探测/分段无关
    if aidm_ipc::is_ftp_url(&row.url_orig) {
        return ftp_task(args, &row, &dir);
    }

    // PyPI 坐标（`pip:requests==2.31.0`）：文件地址要查一次接口才知道（路径含哈希
    // 目录）。**就地换成真实地址**，随后继续走下面的普通 HTTP 路径 —— 拿到直链之后
    // 它就是一次普通下载，不需要另起一条协议路径。
    if aidm_core::devtools::resolve_pip(&row.url_orig).is_ok() {
        match resolve_pypi_target(args, &row) {
            Ok((url, file_name)) => {
                {
                    let conn = args.db.lock().unwrap();
                    // 落 `url_final` 而不是改 `url_orig`：坐标是**稳定标识**
                    //（续传、能力查询、重新解析都靠它），真实地址是它的派生物。
                    let _ = model::set_probe_meta(&conn, id, &url, None, None, None);
                    model::log_event(
                        &conn,
                        id,
                        "pypi_resolved",
                        Some(&format!("file={file_name} url={url}")),
                    );
                }
                // 用户没指定文件名时，用 PyPI 给的那个（含 wheel 的平台标签，
                // 比从 URL 尾巴猜准）。
                if row.file_name.trim().is_empty() {
                    row.file_name = file_name;
                }
                row.url_final = Some(url);
            }
            // 机器码原样报出去（`pypi_version_not_found` 与 `pypi_lookup` 的处置方式
            // 完全不同，必须能区分），阶段标记统一在外面加一次。
            Err(code) => return fail(aidm_core::error::Phase::Resolve, code),
        }
    }

    // 清单型媒体（HLS / MPEG-DASH）：分片是各自独立的资源，没有跨分片的 Range 语义，
    // 所以不能交给下面的分段内核。必须在 HTTP 路径**之前**拦下 —— 它们本身也是
    // http(s) URL，走到下面只会被当成"一个普通文件"去下，结果拿到一份 m3u8 文本。
    if let Some(kind) = manifest_kind(&row.url_orig) {
        return manifest_task(args, &row, &dir, kind);
    }

    // zsync（`.zsync`）：控制文件描述的是**另一个文件**，只取缺失块。
    // 同样必须在 HTTP 路径之前拦下 —— 否则会把那份控制文件本身当成"要下的东西"
    // 下下来（几百 KB 到几十 MB 的二进制块表），用户拿到的东西完全不是他要的。
    if zsync_suffix_len(url_without_query(&row.url_orig)).is_some() {
        return zsync_task(args, &row, &dir);
    }

    // 请求头：设置里的 UA/Accept 系列 + 浏览器透传的 UA + Referer 兜底
    let profile = {
        let conn = args.db.lock().unwrap();
        aidm_core::http_profile::RequestProfile::from_conn(&conn)
            .with_browser_user_agent(args.browser_user_agent.as_deref())
    };
    // 自定义头在 add 时已校验；这里再解析一次拿结构化结果（失败即视为无，不影响任务）
    let custom_headers = args
        .custom_headers
        .as_deref()
        .map(aidm_core::headers::parse_custom_headers)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut ctx = Ctx {
        args,
        profile,
        custom_headers,
        cookies: args.cookies.clone(),
    };

    // —— 候选地址（主地址 + 备用镜像）——
    //
    // 顺序：从落库的 `alt_cursor` 开始绕一圈。换镜像**必须**仍是同一份文件，
    // 所以只在"已落库大小 == 探测大小"时才接管；否则跳过该候选并留痕，
    // 绝不把两个不同文件的字节拼进同一个目标文件。规则集中在 `aidm_core::alt`。
    let auto_mirrors = {
        let conn = args.db.lock().unwrap();
        settings::get(&conn, "alt.auto_mirrors")
            .ok()
            .flatten()
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    };
    // 「生效的原始地址」。
    //
    // 用户给的地址可能是**坐标**（`pip:name==ver`）或**私有 scheme**（`s3://bucket/key`），
    // 它们不是 URL —— 直接拿去构造候选、算 host，会得到 `EmptyHost` 这种看起来莫名其妙的
    // 连接错误（实测：PyPI 任务正是这样反复 `alt_failed: connect: Bad URL: EmptyHost`）。
    // 这两类在更早的分支里已经把真实地址算好放进 `url_final` 了。
    //
    // **只在这两种情况下回退到 `url_final`**：普通 http(s)/ftp 任务保持原样，
    // 候选列表仍按用户填的原地址构造 —— 拿"上次 302 之后的地址"去派生镜像，会
    // 派生出一批错的候选。这条判断把零回归放在便利之前。
    let url_orig_is_url = {
        let u = row.url_orig.trim().to_ascii_lowercase();
        u.starts_with("http://")
            || u.starts_with("https://")
            || u.starts_with("ftp://")
            || u.starts_with("ftps://")
    };
    let mut effective_orig = if url_orig_is_url {
        row.url_orig.clone()
    } else {
        row.url_final
            .clone()
            .unwrap_or_else(|| row.url_orig.clone())
    };
    // 腾讯 QQ 等站点的下载直链必须先用官网签名接口换一次签名 URL，直连原地址必 403。
    // 这里**尽力而为**：解析失败（站点不需要签名、接口超时、返回体不认识）就沿用原地址，
    // 老路径的行为一字不改 —— 签名整体不可用时，所有既有任务仍按原逻辑走。
    if let Some(resolved) = crate::url_resolve::resolve(&args.http, &effective_orig) {
        log::info!(
            "task {id}: 预解析签名地址 via={} url={}",
            resolved.via,
            aidm_core::redact::redact_url(&resolved.url)
        );
        // 复用既有 `url_final` 语义（"派生出的真实地址"），不新增 DB 字段：
        // 探测成功后 `set_probe_meta` 还会用 `probed.final_url` 覆盖它，
        // 所以这里留下的只是一份更接近真实的中间态，不会改变落库契约。
        row.url_final = Some(resolved.url.clone());
        effective_orig = resolved.url;
    }
    let cands = aidm_core::alt::candidates_with_mirrors(
        &effective_orig,
        row.alt_urls.as_deref(),
        auto_mirrors,
    );
    // 每个候选都过一次解析链（只有命中站点的候选才会真正发签名请求）。
    //
    // 只解析主地址是不够的：用户填的备用地址可能也是同一站点的直链（例如另一个
    // QQ 版本/分片），主地址 403 后轮换到备用地址时，未签名的备用地址同样 403，
    // 等于把备用源白放着。这里对全部候选统一预处理；非命中站点 `resolve` 是纯
    // 本地匹配，不发请求，不会增加普通任务的流量。
    let cands: Vec<String> = cands
        .into_iter()
        .map(|c| {
            crate::url_resolve::resolve(&args.http, &c)
                .map(|r| r.url)
                .unwrap_or(c)
        })
        .collect();
    // 候选序列 = [主地址 + 用户填的备用地址] ++ [自动派生的镜像]。
    // 前一段是"用户给的地址"，保持默认请求头；
    // 只有后一段（AIDM 自己猜出来的镜像）才走"不发 UA"那条路。
    let primary_count = aidm_core::alt::candidates(&effective_orig, row.alt_urls.as_deref())
        .len()
        .min(cands.len());
    let start = (row.alt_cursor.max(0) as usize) % cands.len().max(1);
    let mut active_url = effective_orig.clone();
    let mut active_cursor = start;
    let mut first_error: Option<String> = None;
    let mut probed: Option<probe::ProbeResult> = None;
    // 生效地址是否来自「派生候选」（同一槽内的另一协议 / 302 跳转目标）。
    let mut derived_via: Option<&'static str> = None;

    let order = aidm_core::alt::try_order(cands.len(), start);
    // 阶段 1：并行预探各候选的第一跳（见 `probe_first_hops_parallel`）。
    // 命中就直接采用；没命中则把失败结果留给下面的串行阶段复用，不重复发请求。
    let mut hedge = probe_first_hops_parallel(
        &args,
        &ctx,
        &cands,
        &order,
        start,
        primary_count,
        row.size_total,
    );
    if let Some(hit) = hedge.hit.take() {
        // 并行阶段探过并失败的候选要补记留痕：串行的语义是"每失败一个留一条"，
        // 而并行阶段刻意不碰 DB（避免多线程抢锁、也保证事件顺序确定），
        // 于是"命中后直接返回"会让这些失败凭空消失 ——
        // `mirror_takes_over_when_primary_probe_fails` 与
        // `html_error_page_is_rejected_and_the_next_mirror_is_used` 两条验收用例
        // 正是断言主地址的失败必须留痕。
        //
        // 按候选下标排序后补记，事件顺序与串行遍历一致。
        let mut fails: Vec<(usize, String)> = hedge
            .failed
            .iter()
            .map(|(k, (e, _))| (*k, e.clone()))
            .collect();
        fails.sort_by_key(|(k, _)| *k);
        for (idx, err) in fails {
            // 与串行路径同一套命名：当前生效槽记 `alt_failed`，其余候选记 `alt_rejected`
            let kind = if idx == start {
                "alt_failed"
            } else {
                "alt_rejected"
            };
            let conn = args.db.lock().unwrap();
            model::log_event(&conn, id, kind, Some(&format!("idx={idx} err={err}")));
        }
        active_url = hit.url;
        active_cursor = hit.idx;
        if hit.omit_ua {
            // 这一跳是靠"不声明客户端身份"通的 —— 之后的下载必须沿用同一套头
            ctx.profile = ctx.profile.clone().without_browser_ua();
        }
        probed = Some(hit.probed);
    }

    // 阶段 2：串行（含槽内派生：另一协议 / 302 目标）。并行已命中时不探任何候选。
    'cand: for idx in order {
        if probed.is_some() {
            break 'cand;
        }
        let cand = cands[idx].clone();
        // 本机 hosts / DNS 屏蔽不是网络抖动，重试无意义：
        // 当前生效地址被屏蔽时保持原有失败语义；备用地址被屏蔽则跳过它。
        if let Some(detail) = error::blocked_host(&cand) {
            if idx == start {
                let conn = args.db.lock().unwrap();
                model::log_event(&conn, id, "blocked_by_hosts", Some(&detail));
                drop(conn);
                return WorkerEnd::Failed(error::CODE_BLOCKED_BY_HOSTS.into());
            }
            let conn = args.db.lock().unwrap();
            model::log_event(
                &conn,
                id,
                "alt_rejected",
                Some(&format!("idx={idx} reason=hosts {detail}")),
            );
            drop(conn);
            if first_error.is_none() {
                first_error = Some(error::CODE_BLOCKED_BY_HOSTS.into());
            }
            continue;
        }

        // 槽内尝试序列：逻辑候选本身 → 它的另一协议 → 302 跳转目标 → 跳转目标的另一协议。
        // 派生项**只在前面失败之后**才生成，所以成功路径的请求数一个都不多。
        // 值得试的两个实测成因：① `mirrors.aliyun.com` 把 ISO 302 到另一个主机，
        // 那个目标本身就是另一个候选；② 某镜像 https 证书链不可信而 http 正常
        // （`SEC_E_UNTRUSTED_ROOT`）——这不是网络抖动，只能靠换协议发现。
        let mut attempts: Vec<(String, &'static str)> = vec![(cand.clone(), "primary")];
        // 自动派生的镜像：先**不带 UA** 探一跳。实测依据见
        // `RequestProfile::no_browser_ua` —— 这类 WAF 只挑战"自称浏览器"的请求，
        // 带 UA 时 7 家里只有 4 家可用，不带 UA 时 7 家全通。
        let mut omit_ua = idx >= primary_count;
        // 403 自愈只允许对本候选触发一次：否则解析接口一旦返回"换汤不换药"的地址，
        // 失败 → 解析 → 再失败会把 `attempts` 撑成无限追加。第一跳之前它一直是 false。
        let mut sign_tried = false;
        let mut k = 0usize;
        let mut slot_error: Option<String> = None;
        // 本次寻源里已经「慢死」的主机（见 `alt::host_of` 为什么按主机而非地址归并）。
        // 实测 `mirrors.aliyun.com` 会把 ISO 302 到 `iso-osm.mirrors.aliyuncs.com`，
        // 而那台机器的 http 与 https 各自要耗满 5 秒才失败 —— 于是同一个死目标
        // 被连试 4 跳、白等 20 秒，旁边 6 个镜像却都是 0 秒可用。
        let mut dead_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
        // 「慢死」判定门槛。取 1.5 秒：远高于本机/内网的 connection refused（毫秒级，
        // 那种失败很便宜、多试几跳是既有语义），又低于实测镜像的 5 秒超时。
        const SLOW_FAIL: std::time::Duration = std::time::Duration::from_millis(1500);
        while k < attempts.len() {
            let (attempt_url, via) = attempts[k].clone();
            let is_first = k == 0;
            // 不为「本次寻源已经慢死的主机」再等一次超时。第一跳永远要试 ——
            // 它正是判定这台机器可用与否的依据。
            if !is_first {
                if let Some(h) = aidm_core::alt::host_of(&attempt_url) {
                    if dead_hosts.contains(&h) {
                        log::warn!("task {id}: 候选 {idx}（{via}）主机 {h} 本次寻源已慢死，跳过");
                        let conn = args.db.lock().unwrap();
                        model::log_event(
                            &conn,
                            id,
                            "alt_rejected",
                            Some(&format!("idx={idx} via={via} reason=dead_host {h}")),
                        );
                        drop(conn);
                        k += 1;
                        continue;
                    }
                }
            }
            // 代理决策留痕：排查"这条任务为什么直连 / 为什么走代理"时不用再猜
            if !ctx.args.http.proxy_applies(&attempt_url) {
                log::debug!("task {id}: 候选 {idx}（{via}）命中直连规则，不走代理");
            }
            let profile = if omit_ua {
                ctx.profile.clone().without_browser_ua()
            } else {
                ctx.profile.clone()
            };
            // 这次探测花了多久：熔断只认「慢死」，所以耗时是判据本身，
            // 不能靠错误字符串猜（`http_502` 背后可能是 0.2 秒也可能是 5 秒）。
            let (attempt, elapsed) = if is_first {
                match hedge.failed.remove(&idx) {
                    // 并行预探已经探过这一跳并失败：直接复用，不再发一次请求
                    Some((err, took)) => (Err(err), took),
                    None => {
                        let t = std::time::Instant::now();
                        let r = {
                            let _probe_conn = acquire_conn(&args.active_conns);
                            probe::probe(
                                &ctx.args.http.agent_for(&attempt_url),
                                &attempt_url,
                                &profile,
                                ctx.args.referer.as_deref(),
                                ctx.cookies.as_deref(),
                                &ctx.custom_headers,
                            )
                        };
                        (r, t.elapsed())
                    }
                }
            } else {
                let t = std::time::Instant::now();
                let r = {
                    let _probe_conn = acquire_conn(&args.active_conns);
                    probe::probe(
                        &ctx.args.http.agent_for(&attempt_url),
                        &attempt_url,
                        &profile,
                        ctx.args.referer.as_deref(),
                        ctx.cookies.as_deref(),
                        &ctx.custom_headers,
                    )
                };
                (r, t.elapsed())
            };
            match attempt {
                // 不带 UA 也不通 → 翻回带 UA 的正常路径，重试**同一跳**。
                // 不记失败事件：这只是一次策略回退，不是这个候选不可用。
                Err(_) if omit_ua => {
                    omit_ua = false;
                    continue;
                }
                Ok(p) => {
                    // 换候选、或换到派生地址，都必须与已落库大小一致——只有
                    // "当前生效槽的第一跳"可以免检：它就是已落库大小的来源。
                    if !(idx == start && is_first)
                        && !aidm_core::alt::size_compatible(row.size_total, p.total)
                    {
                        log::warn!(
                            "task {id}: 候选 {idx}（{via}）长度与已记录不符，跳过（stored={:?} probed={:?}）",
                            row.size_total,
                            p.total
                        );
                        let conn = args.db.lock().unwrap();
                        model::log_event(
                            &conn,
                            id,
                            "alt_rejected",
                            Some(&format!(
                                "idx={idx} via={via} reason=size stored={:?} probed={:?}",
                                row.size_total, p.total
                            )),
                        );
                        drop(conn);
                        k += 1;
                        continue;
                    }
                    active_url = attempt_url.clone();
                    active_cursor = idx;
                    if !is_first {
                        derived_via = Some(via);
                    }
                    // 这一跳是靠"不发 UA"才通的 —— 之后的下载必须沿用同一套头，
                    // 否则探测过了、真正下的时候又被同一个 WAF 拦掉。
                    if omit_ua {
                        ctx.profile = profile;
                    }
                    probed = Some(p);
                    break 'cand;
                }
                Err(e) => {
                    log::warn!("task {id}: 候选 {idx}（{via}）探测失败：{e}");
                    // 403 自愈的判定必须抢在 `e` 被移动进 `slot_error` 之前算出来；
                    // 只认第一跳：签名换来的地址再 403 就说明问题不在签名，不该再解析。
                    let heal_403 = is_first && !sign_tried && e.starts_with("http_403");
                    let conn = args.db.lock().unwrap();
                    // 逻辑候选本身沿用原有事件与格式；派生地址用 alt_rejected 区分，
                    // 并带 `via=` 说明它是怎么派生出来的。
                    let (kind, detail) = if is_first {
                        let kind = if idx == start {
                            "alt_failed"
                        } else {
                            "alt_rejected"
                        };
                        (kind, format!("idx={idx} err={e}"))
                    } else {
                        ("alt_rejected", format!("idx={idx} via={via} err={e}"))
                    };
                    model::log_event(&conn, id, kind, Some(&detail));
                    drop(conn);
                    if slot_error.is_none() {
                        slot_error = Some(e);
                    }
                    // 只有「慢死」才熔断：毫秒级的连接被拒很便宜，多试几跳是既有语义
                    // （`redirect_target_is_derived_and_tried_after_the_primary_fails`
                    // 钉住了它）；而耗满一次超时的主机，换个协议照样要耗满。
                    let slow = elapsed >= SLOW_FAIL;
                    if slow && !is_first {
                        // 派生尝试的 URL 本身就是它的落地地址。
                        if let Some(h) = aidm_core::alt::host_of(&attempt_url) {
                            dead_hosts.insert(h);
                        }
                    }
                    // 403 自愈（每个候选最多一次）：第一跳被签名校验拒绝时，重新换一次
                    // 官网签发的临时地址再试。放在协议/302 派生**之前** —— 签名只对原地址
                    // 有效，先花一次接口调用，比先试两跳注定也 403 的派生更省时间。
                    // 解析不到新地址就什么都不做：错误语义、候选顺序、事件全部保持原样。
                    if heal_403 {
                        sign_tried = true;
                        if let Some(resolved) =
                            crate::url_resolve::resolve(&ctx.args.http, &attempt_url)
                        {
                            if resolved.url != attempt_url {
                                log::info!(
                                    "task {id}: 候选 {idx} 403，换签名地址重试 via={} url={}",
                                    resolved.via,
                                    aidm_core::redact::redact_url(&resolved.url)
                                );
                                // 追加在当前跳之后，`k += 1` 正好落到它上面；
                                // `via="sign"` 会被既有的 `alt_switch` 留痕带出去。
                                attempts.push((resolved.url, "sign"));
                            }
                        }
                    }
                    // 第一跳失败后再派生：另一协议是零成本字符串改写；
                    // 302 目标要多发一次 `redirects(0)` 请求，失败路径才付这个成本。
                    if is_first {
                        let redirect = {
                            let _probe_conn = acquire_conn(&args.active_conns);
                            probe::redirect_target(
                                &ctx.args.http.agent_for_noredirect(&attempt_url),
                                &attempt_url,
                                &ctx.profile,
                                ctx.args.referer.as_deref(),
                                ctx.cookies.as_deref(),
                                &ctx.custom_headers,
                            )
                        };
                        // 跟随式探测在首跳的目标上失败了 ⇒ 那个目标刚被证明不可用：
                        // 跟随要是能成，这次探测就不会失败；即便它本身是活的，
                        // 它后面那一跳也是死的，跳过它同样无损。
                        // 这一次 `redirects(0)` 只花 0.17 秒，却省下后面每一跳的整次超时。
                        if slow {
                            if let Some(h) = redirect.as_deref().and_then(aidm_core::alt::host_of) {
                                dead_hosts.insert(h);
                            }
                        }
                        if let Some(swapped) = aidm_core::alt::scheme_swap(&attempt_url) {
                            // 换协议前先确认它不会又落到那台已经慢死的机器上。
                            // 死名单为空时（快速失败的常见情形）免掉这次请求。
                            let lands_on_dead = if dead_hosts.is_empty() {
                                false
                            } else {
                                let landed = {
                                    let _probe_conn = acquire_conn(&args.active_conns);
                                    probe::redirect_target(
                                        &ctx.args.http.agent_for_noredirect(&swapped),
                                        &swapped,
                                        &ctx.profile,
                                        ctx.args.referer.as_deref(),
                                        ctx.cookies.as_deref(),
                                        &ctx.custom_headers,
                                    )
                                };
                                landed
                                    .as_deref()
                                    .and_then(aidm_core::alt::host_of)
                                    .is_some_and(|h| dead_hosts.contains(&h))
                            };
                            if !lands_on_dead {
                                attempts.push((swapped, "scheme"));
                            } else {
                                log::warn!(
                                    "task {id}: 候选 {idx} 的另一协议仍会落到已慢死的主机，跳过"
                                );
                            }
                        }
                        if let Some(target) = redirect {
                            log::debug!(
                                "task {id}: 候选 {idx} 302 → {}",
                                aidm_core::redact::redact_url(&target)
                            );
                            if let Some(swapped) = aidm_core::alt::scheme_swap(&target) {
                                attempts.push((target, "redirect"));
                                attempts.push((swapped, "redirect-scheme"));
                            } else {
                                attempts.push((target, "redirect"));
                            }
                        }
                    }
                    k += 1;
                }
            }
        }
        if first_error.is_none() {
            first_error = slot_error;
        }
    }
    let mut probed = match probed {
        Some(p) => p,
        None => {
            // 所有现有候选都不可用：先按判断器预算找一轮新源；找到就接着下，
            // 找不到才报当前生效地址的错误（备用地址的失败已逐条留痕）。
            let now = crate::source_registry::now_ms();
            match find_and_probe_alternative(&ctx, &row, &effective_orig, now) {
                Some((url, p, cursor)) => {
                    // 换到新源后清掉旧的连接退避档位，按新源重新开始。
                    {
                        let conn = ctx.args.db.lock().unwrap();
                        let _ = model::clear_conn_cap(&conn, row.id);
                    }
                    active_url = url;
                    active_cursor = cursor;
                    p
                }
                None => {
                    if ctx.args.cancel.load(Ordering::SeqCst) {
                        return WorkerEnd::Cancelled;
                    }
                    if ctx.args.pause.load(Ordering::SeqCst) {
                        let conn = ctx.args.db.lock().unwrap();
                        let _ = model::set_status(&conn, row.id, Status::Paused, None);
                        model::log_event(&conn, row.id, "paused", Some("finder stopped"));
                        return WorkerEnd::Paused;
                    }
                    return WorkerEnd::Failed(
                        first_error.unwrap_or_else(|| "connect: no_candidate".into()),
                    );
                }
            }
        }
    };
    // 生效地址与落库的"当前生效候选"不同，或同槽内换到了派生地址（另一协议/302 目标），
    // 都要留痕：前者改 cursor，后者只记录来源。
    if active_cursor != start || derived_via.is_some() {
        let conn = args.db.lock().unwrap();
        model::log_event(
            &conn,
            id,
            "alt_switch",
            Some(&match derived_via {
                Some(via) => format!(
                    "from={start} to={active_cursor} via={via} total={:?}",
                    probed.total
                ),
                None => format!("from={start} to={active_cursor} total={:?}", probed.total),
            }),
        );
        let _ = model::set_alt_cursor(&conn, id, active_cursor as i64);
        drop(conn);
    }
    // 换过镜像（或换到派生地址）后，原地址的 ETag/Last-Modified 不再适用于新地址，
    // 校验器比对必须让路（同一地址上的内容被换掉才用它判定）；已下好的分段仍然保留。
    let switched = active_cursor != start || derived_via.is_some();
    // 阶段「解析地址」结果：status / range_ok / total 是后续所有决策（fastdl、
    // 断点续传、镜像切换）的输入，必须与任务一起留痕（规格 §3.2）。
    tracing::info!(
        event = "net.probe",
        phase = "resolve",
        outcome = "ok",
        status = probed.status,
        range_ok = probed.range_ok,
        size_known = probed.total.is_some(),
        total_bytes = probed.total.unwrap_or(0),
        alt_idx = active_cursor,
        switched,
    );

    // 401 挑战：这个站点若存了凭据，按挑战类型（Digest 优先、其次 Basic）带上去重试一次。
    // 只重试一次；凭据与应答绝不进日志/事件，事件里只记挑战类型。
    if probed.status == 401 && !ctx.has_authorization() {
        {
            let conn = args.db.lock().unwrap();
            let kind = auth_challenge_kind(&probed.www_authenticate);
            model::log_event(&conn, id, "auth_challenge", Some(kind));
            // 挑战到达与"是否带凭据重试"是两件事，分开记（规格 §3.3）。
            tracing::info!(
                event = "auth.challenge",
                phase = "auth",
                scheme = kind,
                status = probed.status,
            );
        }
        if let Some(auth) = credential_header(&ctx, &probed.final_url, &probed.www_authenticate) {
            let kind = auth_challenge_kind(&probed.www_authenticate);
            tracing::info!(
                event = "auth.result",
                phase = "auth",
                outcome = "ok",
                scheme = kind,
                retried = true,
                msg = "收到 401 挑战，带站点凭据重试一次",
            );
            ctx.custom_headers.push(auth);
            let _probe_conn = acquire_conn(&args.active_conns);
            match probe::probe(
                &ctx.args.http.agent_for(&active_url),
                &active_url,
                &ctx.profile,
                ctx.args.referer.as_deref(),
                ctx.cookies.as_deref(),
                &ctx.custom_headers,
            ) {
                Ok(p) => probed = p,
                Err(e) => return WorkerEnd::Failed(e),
            }
        }
    }

    // 挑战仍然没过去（没存凭据、凭据错误或挑战类型不支持）→ 按原来的失败语义结束
    if probed.status == 401 || probed.status == 407 {
        return WorkerEnd::Failed(format!("http_{}", probed.status));
    }

    {
        let conn = args.db.lock().unwrap();
        model::log_event(
            &conn,
            id,
            "range_probe",
            Some(&format!(
                "status={} total={:?} range_ok={}",
                probed.status, probed.total, probed.range_ok
            )),
        );
    }

    // —— 上游元数据：整文件 SHA-256（+ 可能的镜像列表）——
    //
    // 把「跨镜像同一性」从"长度相等"升级为"内容哈希相等"，并在下载完成后校验整包。
    // 取用顺序：**Metalink 优先**（同时给镜像地址与哈希），退回 CHECKSUM。
    // 只在**有理由在意**时才多花请求：换过镜像/派生地址（身份需要证明），
    // 或者生效地址是明文 http（传输不可信）。普通 https + 主地址不发这次请求。
    if row.sha256_expected.is_none()
        && (switched || active_url.starts_with("http://"))
        && probed.total.is_some()
    {
        let mut got_hash = false;
        let mut got_mirrors = false;
        let entry = {
            let _probe_conn = acquire_conn(&args.active_conns);
            metalink_source::fetch_linked(
                &ctx.args.http.agent_for(&active_url),
                &active_url,
                &row.file_name,
                &ctx.profile,
                ctx.args.referer.as_deref(),
                ctx.cookies.as_deref(),
                &ctx.custom_headers,
            )
        };
        match entry {
            // 长度对不上说明这份 Metalink 描述的不是这个文件，整份不采信
            Some(e) if e.size.is_some() && e.size != probed.total => {
                let conn = args.db.lock().unwrap();
                model::log_event(&conn, id, "metalink", Some("ignored=size_mismatch"));
                drop(conn);
            }
            Some(e) => {
                let conn = args.db.lock().unwrap();
                if let Some(h) = e.sha256.as_deref() {
                    let _ = model::set_sha256_expected(&conn, id, Some(h));
                    got_hash = true;
                }
                if !e.urls.is_empty() {
                    let _ = model::set_mirrors_urls(&conn, id, Some(&e.urls.join("\n")));
                    got_mirrors = true;
                }
                model::log_event(
                    &conn,
                    id,
                    "metalink",
                    Some(&format!(
                        "sha256={} urls={} pieces={}",
                        e.sha256.as_deref().unwrap_or("-"),
                        e.urls.len(),
                        e.piece_count
                    )),
                );
                drop(conn);
            }
            None => {}
        }
        // Metalink 已经给了哈希就不用再拉 CHECKSUM（省一次请求）
        if !got_hash {
            let found = {
                let _probe_conn = acquire_conn(&args.active_conns);
                checksum::fetch(
                    &ctx.args.http.agent_for(&active_url),
                    &active_url,
                    &row.file_name,
                    &ctx.profile,
                    ctx.args.referer.as_deref(),
                    ctx.cookies.as_deref(),
                    &ctx.custom_headers,
                )
            };
            match found {
                // 清单声明的长度与镜像报的长度不一致 → 这份清单描述的不是这个文件，不采信。
                Some(e) if e.size.is_some() && e.size != probed.total => {
                    log::warn!(
                        "task {id}: CHECKSUM 声明长度 {:?} 与镜像 {:?} 不符，忽略该哈希",
                        e.size,
                        probed.total
                    );
                    let conn = args.db.lock().unwrap();
                    model::log_event(&conn, id, "checksum", Some("ignored=size_mismatch"));
                    drop(conn);
                }
                Some(e) => {
                    log::info!("task {id}: 取得上游 SHA-256 {}", e.sha256);
                    let conn = args.db.lock().unwrap();
                    let _ = model::set_sha256_expected(&conn, id, Some(&e.sha256));
                    model::log_event(&conn, id, "checksum", Some(&format!("sha256={}", e.sha256)));
                    drop(conn);
                }
                None => {}
            }
        }
        // `.mirrorlist` 只给镜像、不给哈希，所以它是"已有哈希但不知道别的镜像"时的补位
        // （典型：哈希来自同目录 CHECKSUM）。整块只在新任务上跑一次（哈希落库后即跳过）。
        if !got_mirrors {
            let urls = {
                let _probe_conn = acquire_conn(&args.active_conns);
                mirrorlist_source::fetch_linked(
                    &ctx.args.http.agent_for(&active_url),
                    &active_url,
                    &row.file_name,
                    &ctx.profile,
                    ctx.args.referer.as_deref(),
                    ctx.cookies.as_deref(),
                    &ctx.custom_headers,
                )
            };
            if !urls.is_empty() {
                let conn = args.db.lock().unwrap();
                let _ = model::set_mirrors_urls(&conn, id, Some(&urls.join("\n")));
                model::log_event(
                    &conn,
                    id,
                    "mirrorlist",
                    Some(&format!("urls={}", urls.len())),
                );
                drop(conn);
            }
        }
    }

    let resume = args.resume;
    let size_changed = match (row.size_total, probed.total) {
        (Some(old), Some(new)) if old > 0 => old as u64 != new,
        _ => false,
    };
    if resume
        && !switched
        && (size_changed
            || validators_changed(
                row.etag.as_deref(),
                row.last_modified.as_deref(),
                probed.etag.as_deref(),
                probed.last_modified.as_deref(),
            ))
    {
        let detail = format!(
            "stored_etag={:?} new_etag={:?} stored_lm={:?} new_lm={:?} stored_size={:?} new_size={:?} action=remote_changed",
            row.etag, probed.etag, row.last_modified, probed.last_modified, row.size_total, probed.total
        );
        {
            let conn = args.db.lock().unwrap();
            model::log_event(&conn, id, "validator_changed", Some(&detail));
            let _ = model::clear_segments(&conn, id);
        }
        tracing::warn!(
            event = "resume.inspect",
            phase = "resume",
            outcome = "fail",
            err_code = error::CODE_REMOTE_CHANGED,
            size_changed,
            stored_bytes = row.size_total.unwrap_or(0),
            probed_bytes = probed.total.unwrap_or(0),
        );
        cleanup_task_files(&dir, &row.file_name, id, false);
        return WorkerEnd::Failed(error::CODE_REMOTE_CHANGED.into());
    }

    // 断点续传决策（正常路径）：`resume=false` 是全新下载，不是"续传失败"。
    tracing::info!(
        event = "resume.inspect",
        phase = "resume",
        outcome = if resume { "ok" } else { "skip" },
        resume,
        size_changed,
        stored_bytes = row.size_total.unwrap_or(0),
        probed_bytes = probed.total.unwrap_or(0),
    );

    let original_name = row.file_name.clone();
    let resolved = if resume {
        original_name.clone()
    } else {
        resolve_filename(
            args.filename.as_deref(),
            probed.content_disposition.as_deref(),
            &probed.final_url,
        )
    };

    let file_name = {
        let conn = args.db.lock().unwrap();
        let live_name = model::get_download(&conn, id)
            .ok()
            .flatten()
            .map(|r| r.file_name)
            .unwrap_or_else(|| original_name.clone());
        let file_name = if live_name != original_name {
            live_name
        } else if resume {
            resolved
        } else {
            // 自动重命名规则：磁盘上已有同名文件时不覆盖，改用「文件名 (n).ext」
            aidm_core::filename::unique_file_name(&dir, &resolved)
        };
        let _ = model::set_probe_meta(
            &conn,
            id,
            &probed.final_url,
            probed.total.map(|t| t as i64),
            probed.etag.as_deref(),
            probed.last_modified.as_deref(),
        );
        let _ = model::set_file_name_if(&conn, id, &file_name, &original_name);
        if let Ok(Some(updated)) = model::get_download(&conn, id) {
            row = updated;
        } else {
            row.file_name = file_name.clone();
            row.url_final = Some(probed.final_url.clone());
            row.size_total = probed.total.map(|t| t as i64);
        }
        row.file_name.clone()
    };

    args.live
        .total_bytes
        .store(probed.total.unwrap_or(0), Ordering::Relaxed);

    if let Err(e) = std::fs::create_dir_all(&dir) {
        return fail_io(args.io_fault, e, "mkdir");
    }

    // 下载期间慢速重触发：60 s 低于 50 MiB/s 就开新一轮找源。
    // 结果只落任务绑定的 source_candidates，不打断当前下载；任务结束/暂停/取消即停。
    let slow_stop = Arc::new(AtomicBool::new(false));
    spawn_slow_finder(args, &row, &effective_orig, slow_stop.clone());
    let _slow_guard = SlowFindGuard(slow_stop);

    // —— fastdl 快路径：Range 可用且总长已知时，走「预分配 + 定位直写 + 动态再分段」——
    //
    // 与分段 part 文件路径的差别：不再为每段建独立 part 文件、末尾也不再 merge，
    // 因此省掉整份文件的一遍全量读 + 一遍全量写；分段在下载过程中按
    // 「剩余最多的块砍一半」动态调整。
    if let Some(total) = probed.total.filter(|t| *t >= fastdl::MIN_TOTAL_FOR_FASTDL) {
        let use_fast = {
            let conn = args.db.lock().unwrap();
            fastdl::enabled(&conn)
        };
        if use_fast && probed.range_ok {
            tracing::info!(
                event = "transfer.start",
                phase = "transfer",
                mode = "fastdl",
                total_bytes = total,
            );
            // 来源打分**任务级**采数：fastdl 内部没有"单条连接收尾"这个点
            // （逐连接统计被聚合掉了，只有任务级 `finish_ok`），所以这里按**整个任务**
            // 记一次真实尝试 —— 粒度粗，但是真实数据，且是这条热路径唯一的采数口。
            // `ttfb` 传 0 = 没测到（fastdl 的 `first_byte` 事件不在这里回传），
            // 打分内核会把它排除在响应速度样本外。
            let url_for_score = row.url_final.as_deref().unwrap_or(row.url_orig.as_str());
            let mut fast_url = url_for_score.to_string();
            let mut fast_etag = probed.etag.clone().or_else(|| row.etag.clone());
            let mut fast_last_modified = probed
                .last_modified
                .clone()
                .or_else(|| row.last_modified.clone());
            let mut fast_resume = resume;
            let mut finder_tried = false;
            loop {
                let t_fastdl = std::time::Instant::now();
                let outcome = fastdl::run(fastdl::Job {
                    args,
                    row: &row,
                    dir: &dir,
                    file_name: &file_name,
                    url: &fast_url,
                    total,
                    etag: fast_etag.clone(),
                    last_modified: fast_last_modified.clone(),
                    resume: fast_resume,
                    // 把**探测实际生效的**那套头交给 fastdl：自动派生的镜像候选是在
                    // "不声明客户端身份"模式下才通的，fastdl 若自己重建档案就会带上 UA，
                    // 那 64 个连接会被同一个 WAF 挡成 302（实测故障）。
                    profile: ctx.profile.clone(),
                });
                // 失败的 `Failed(码)` 与成功都算一次尝试；暂停/取消是用户动作，不计入评分。
                let (ok, bytes) = match &outcome {
                    WorkerEnd::Done => (true, total),
                    WorkerEnd::Failed(_) => (false, 0),
                    _ => return outcome,
                };
                crate::source_registry::record(
                    &fast_url,
                    bytes,
                    t_fastdl.elapsed().as_millis() as u64,
                    0,
                    ok,
                    crate::source_registry::now_ms(),
                );

                let WorkerEnd::Failed(code) = outcome else {
                    return outcome;
                };
                if !is_signed_rate_limit(&code) {
                    return WorkerEnd::Failed(code);
                }

                // 先看当前是否已有退避档位。没有档位 = 本异常轮第一次失败：
                // 必须先找源；只有找源失败才写下一档，绝不一上来就降并发。
                let (base, current) = {
                    let conn = args.db.lock().unwrap();
                    let base = aidm_core::hosts::task_conns(&conn, &row.url_orig).max(1);
                    let current = model::get_conn_cap(&conn, id).ok().flatten();
                    (base, current)
                };
                if !finder_tried && current.is_none() {
                    finder_tried = true;
                    let now = crate::source_registry::now_ms();
                    if let Some((url, p, _cursor)) =
                        find_and_probe_alternative(&ctx, &row, &effective_orig, now)
                    {
                        // 只接受同大小、支持 Range、且确实换了一个地址的候选。
                        if p.range_ok && p.total == Some(total) && url != fast_url {
                            {
                                let conn = args.db.lock().unwrap();
                                let _ = model::clear_conn_cap(&conn, id);
                                model::log_event(
                                    &conn,
                                    id,
                                    "alt_switch",
                                    Some(&format!(
                                        "reason=signed_rate_limit from={} to={}",
                                        aidm_core::redact::redact_url(&fast_url),
                                        aidm_core::redact::redact_url(&url)
                                    )),
                                );
                            }
                            // 新地址的 ETag/分段布局不能复用旧侧车。
                            fastdl::discard_state(&dir, id);
                            fast_url = url;
                            fast_etag = p.etag.clone();
                            fast_last_modified = p.last_modified.clone();
                            fast_resume = false;
                            continue;
                        }
                    }
                }

                // 找源失败（或已经找过）：当前连接数减半，8 → 4 → 2 → 1。
                if args.cancel.load(Ordering::SeqCst) {
                    return WorkerEnd::Cancelled;
                }
                if args.pause.load(Ordering::SeqCst) {
                    return WorkerEnd::Paused;
                }
                let next = next_conn_cap(base, current.as_ref().map(|c| c.conn_cap));
                {
                    let conn = args.db.lock().unwrap();
                    let _ = model::set_conn_cap(&conn, id, next, true);
                    model::log_event(
                        &conn,
                        id,
                        "conn_backoff",
                        Some(&format!(
                            "reason=signed_rate_limit conns={next} base={base} finder_done=1"
                        )),
                    );
                }
                return WorkerEnd::Failed(code);
            }
        }
    }

    let mut existing = {
        let conn = args.db.lock().unwrap();
        model::list_segments(&conn, id).unwrap_or_default()
    };

    // 连接预算只有一个解析器：每服务器例外 > 全局闸门（`hosts::task_conns`）。
    let wanted = {
        let conn = args.db.lock().unwrap();
        task_conns_for(&conn, &row) as i64
    };
    let replan = resume
        && !existing.is_empty()
        && existing.iter().all(|s| s.done_bytes == 0)
        && existing.len() as i64 != wanted;
    if replan {
        let conn = args.db.lock().unwrap();
        let _ = model::clear_segments(&conn, id);
    }
    // 设置改动（或改设置时引擎没在跑）后重新核对分段数：不足则在剩余区间中点再切分
    //（§3.2「一分为二」）。前半段接着原来的 part 续下，新段从切点开始。
    if resume && !replan {
        let added = {
            let conn = args.db.lock().unwrap();
            model::resplit_task_segments(&conn, id, &dir, wanted).unwrap_or(0)
        };
        if added > 0 {
            let conn = args.db.lock().unwrap();
            model::log_event(
                &conn,
                id,
                "resegmented",
                Some(&format!("conns={} added={added}", existing.len() + added)),
            );
            drop(conn);
            existing = {
                let conn = args.db.lock().unwrap();
                model::list_segments(&conn, id).unwrap_or_default()
            };
        }
    }
    if resume && !replan && existing.len() >= 2 {
        return multi_download(&ctx, &row, &dir, &probed, false);
    }
    if resume && !replan && existing.len() == 1 {
        return single_download(&ctx, &row, &dir, &file_name, &probed, true);
    }

    // 连接预算只有一个解析器：每服务器例外 > 全局闸门（`hosts::task_conns`）。
    let desired = {
        let conn = args.db.lock().unwrap();
        task_conns_for(&conn, &row)
    };
    if probed.range_ok {
        if let Some(total) = probed.total {
            let spans = plan_segments(total, desired);
            if spans.len() >= 2 {
                return multi_download(&ctx, &row, &dir, &probed, true);
            }
            let conn = args.db.lock().unwrap();
            model::log_event(&conn, id, "degrade_single", Some("reason=min_segment"));
        } else {
            let conn = args.db.lock().unwrap();
            model::log_event(&conn, id, "degrade_single", Some("reason=unknown_size"));
        }
    } else {
        let conn = args.db.lock().unwrap();
        model::log_event(&conn, id, "degrade_single", Some("reason=no_range"));
    }
    single_download(&ctx, &row, &dir, &file_name, &probed, resume)
}

fn merge_finish(args: &Args, row: &DownloadRow, dir: &Path) -> WorkerEnd {
    if args.cancel.load(Ordering::SeqCst) {
        return WorkerEnd::Cancelled;
    }
    let segs = {
        let conn = args.db.lock().unwrap();
        let _ = model::set_status(&conn, args.id, Status::Verifying, None);
        model::log_event(
            &conn,
            args.id,
            "verifying",
            Some(&format!(
                "segments={}",
                model::list_segments(&conn, args.id)
                    .map(|s| s.len())
                    .unwrap_or(0)
            )),
        );
        match model::list_segments(&conn, args.id) {
            Ok(s) => s,
            Err(e) => return WorkerEnd::Failed(format!("db: {e}")),
        }
    };
    if segs.is_empty() {
        return WorkerEnd::Failed("no_segments_to_merge".into());
    }
    let file_name = target_file_name(args, &row.file_name);
    let final_path = dir.join(&file_name);
    // 合并到**暂存名**，校验通过后再提交到正式名（R-DL-19）。
    // 与 `finish_single` 同理：正式名下不得出现内容不符的文件。
    let staging = dir.join(format!(".{file_name}.staging"));
    let expected = row.size_total.map(|t| t.max(0) as u64);
    match merge_parts(&segs, &staging, expected) {
        Ok(out) => {
            // 故障注入：写完后篡改真实文件并**重算哈希** —— 否则比对的是合并时的
            // 内存哈希，根本看不出损坏（规格 §8）。
            let visible_hash = if matches!(args.io_fault, IoFault::Corrupt) {
                inject_corruption(args.io_fault, &staging);
                sha256_file(&staging)
                    .ok()
                    .unwrap_or_else(|| out.sha256.clone())
            } else {
                out.sha256.clone()
            };
            {
                let conn = args.db.lock().unwrap();
                model::log_event(&conn, args.id, "sha256", Some(&visible_hash));
            }
            tracing::info!(
                event = "verify.file",
                phase = "verify",
                outcome = "ok",
                algo = "sha256",
                mode = "merge",
                total_bytes = expected.unwrap_or(0),
            );
            // 上游声明了整文件哈希就必须对上——换过镜像 / 走过明文 http 的任务尤其重要。
            if let Some(err) = verify_expected_sha256(args, Some(&visible_hash)) {
                remove_part_dir(dir, args.id);
                quarantine_failed_file(args, &staging, row, "sha256");
                return WorkerEnd::Failed(err);
            }
            if let Some(end) = verify_http_ed2k(args, row, &staging) {
                // 与 sha256 失败同处置；暂停/取消不隔离（可续传）。
                if matches!(end, WorkerEnd::Failed(_)) {
                    remove_part_dir(dir, args.id);
                    quarantine_failed_file(args, &staging, row, "ed2k");
                }
                return end;
            }
            // 校验全部通过，此刻才把暂存文件提交到正式名。
            if let Err(e) = std::fs::rename(&staging, &final_path) {
                return WorkerEnd::Failed(format!("commit: {e}"));
            }
            // done 对外可见时，临时文件应已清理完毕。
            remove_part_dir(dir, args.id);
            let conn = args.db.lock().unwrap();
            let url = row.url_final.as_deref().unwrap_or(row.url_orig.as_str());
            let _ = model::mark_done(&conn, args.id, url);
            // 完成以合并结果为准：段行收尾成整段下满（进度必定 100%）
            let _ = model::finalize_segments(&conn, args.id);
            model::log_event(
                &conn,
                args.id,
                "done",
                Some(&format!("bytes={} sha256={}", out.bytes, out.sha256)),
            );
            drop(conn);
            args.live.done_bytes.store(out.bytes, Ordering::Relaxed);
            args.live.speed_bps.store(0, Ordering::Relaxed);
            WorkerEnd::Done
        }
        Err(e) => WorkerEnd::Failed(e),
    }
}

fn single_download(
    ctx: &Ctx<'_>,
    row: &DownloadRow,
    dir: &Path,
    file_name: &str,
    probed: &probe::ProbeResult,
    resume: bool,
) -> WorkerEnd {
    let args = ctx.args;
    let id = args.id;
    let save_path = if resume {
        let existing = {
            let conn = args.db.lock().unwrap();
            model::list_segments(&conn, id).unwrap_or_default()
        };
        existing
            .iter()
            .find(|s| s.idx == 0)
            .map(|s| PathBuf::from(&s.part_path))
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| dir.join(file_name))
    } else {
        dir.join(file_name)
    };
    let mut resume_offset = 0u64;
    if resume {
        if let Ok(meta) = std::fs::metadata(&save_path) {
            let len = meta.len();
            if let Some(total) = row.size_total.or(probed.total.map(|t| t as i64)) {
                if len > 0 && len < total.max(0) as u64 {
                    resume_offset = len;
                } else if len == total.max(0) as u64 && total > 0 {
                    return finish_single(args, row, &save_path, len);
                }
            } else if len > 0 {
                resume_offset = len;
            }
        }
    }

    let url = row.url_final.as_deref().unwrap_or(row.url_orig.as_str());
    let mut req = apply_common(
        ctx.args.http.agent_for(url).get(url),
        &ctx.profile,
        url,
        ctx.args.referer.as_deref(),
        ctx.cookies.as_deref(),
        &ctx.custom_headers,
    );
    if resume_offset > 0 {
        req = req.set("Range", &format!("bytes={resume_offset}-"));
    }
    let resp = match req.call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, _)) => return WorkerEnd::Failed(format!("http_{code}")),
        Err(e) => return WorkerEnd::Failed(format!("connect: {e}")),
    };
    let status_code = resp.status();
    let cl = header_owned(&resp, "content-length").and_then(|v| v.parse::<u64>().ok());
    let total = if status_code == 206 {
        header_owned(&resp, "content-range")
            .and_then(|v| v.rsplit('/').next()?.trim().parse::<u64>().ok())
            .or_else(|| cl.map(|l| resume_offset + l))
            .or(probed.total)
    } else if (200..300).contains(&status_code) {
        cl.or(probed.total)
    } else {
        return WorkerEnd::Failed(format!("http_{status_code}"));
    };
    let from_offset = if status_code == 206 { resume_offset } else { 0 };

    {
        let conn = args.db.lock().unwrap();
        let _ = model::set_probe_meta(
            &conn,
            id,
            resp.get_url(),
            total.map(|t| t as i64),
            header_owned(&resp, "etag")
                .as_deref()
                .or(probed.etag.as_deref()),
            header_owned(&resp, "last-modified")
                .as_deref()
                .or(probed.last_modified.as_deref()),
        );
        let pos_end = total.map(|t| t as i64 - 1);
        let _ = model::init_single_segment(&conn, id, &save_path.to_string_lossy(), pos_end);
        if from_offset == 0 {
            let _ = model::set_segment_progress(&conn, id, 0);
        } else {
            let _ = model::set_segment_progress(&conn, id, from_offset as i64);
        }
        model::log_event(
            &conn,
            id,
            "start",
            Some(&format!(
                "mode=single final={} size={total:?} mime={:?}",
                resp.get_url(),
                probed.content_type
            )),
        );
        let _ = model::set_status(&conn, id, Status::Downloading, None);
    }
    args.live
        .total_bytes
        .store(total.unwrap_or(0), Ordering::Relaxed);
    args.live.done_bytes.store(from_offset, Ordering::Relaxed);

    let mut file = if from_offset > 0 {
        match std::fs::OpenOptions::new().write(true).open(&save_path) {
            Ok(mut f) => {
                if let Err(e) = f.seek(SeekFrom::Start(from_offset)) {
                    return fail_io(args.io_fault, e, "seek");
                }
                f
            }
            Err(e) => return fail_io(args.io_fault, e, "open partial"),
        }
    } else {
        match std::fs::File::create(&save_path) {
            Ok(f) => f,
            Err(e) => return fail_io(args.io_fault, e, "create"),
        }
    };

    // 单连接路径也是真实写盘入口，必须持写入许可。
    // span 覆盖整个目标文件：单连接本来就顺序写到底，许可管的是“谁有权写”。
    //
    // 未知长度（chunked / 无 Content-Length）必须是**开区间**。
    // 写成 `total.unwrap_or(0).max(1)` 会得到 `Some([0,1))`：`unwrap_or_else` 那句
    // `Span::open(0)` 成死代码，第一块 64 KiB 写入就因越界被拒 → 任务被误判为暂停。
    let span = match total {
        Some(t) => Span::known(0, t.max(1)).unwrap_or_else(|| Span::open(0)),
        None => Span::open(0),
    };
    let lease = args.gate.as_ref().map(|gate| {
        let assignment = AssignmentId::new(format!("single:{id}"));
        gate.issue(
            assignment,
            SliceId::new(format!("single:{id}")),
            span,
        )
    });
    // 归属结束（任何返回路径）都要把许可摘掉，否则账本里会留下永不释放的分配。
    let _reaper = match (&args.gate, &lease) {
        (Some(gate), Some(lease)) => Some(gate.reaper(lease)),
        _ => None,
    };
    // P2-03：暂停可能发生在上层建连之后、走到这里之前。签发出来的许可若已作废，
    // 就直接按暂停收场，不要为一个注定被拒的写入再往下走（状态与其它 Paused 路径一致）。
    if let (Some(gate), Some(lease)) = (&args.gate, &lease) {
        let probe_end = from_offset.saturating_add(1);
        if !gate.accepts(lease, from_offset, probe_end) {
            persist_single(args, from_offset);
            pause_on_lease_revoked(args, "single_precheck");
            return WorkerEnd::Paused;
        }
    }

    let mut written = from_offset;
    let _http_conn = acquire_conn(&args.active_conns);
    let mut reader = resp.into_reader();
    let mut buf = vec![0u8; READ_BUF];
    let mut last_persist = Instant::now();
    let limit = RateLimit::new(row.speed_limit_kbps);

    loop {
        if args.cancel.load(Ordering::SeqCst) {
            return WorkerEnd::Cancelled;
        }
        if args.pause.load(Ordering::SeqCst) {
            if total.is_some_and(|t| written >= t) {
                break;
            }
            persist_single(args, written);
            let conn = args.db.lock().unwrap();
            let _ = model::set_status(&conn, id, Status::Paused, None);
            model::log_event(&conn, id, "paused", Some(&format!("done={written}")));
            return WorkerEnd::Paused;
        }
        let read_res = match injected_read_fault(args.io_fault) {
            Some(e) => Err(e),
            None => reader.read(&mut buf),
        };
        let n = match read_res {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                persist_single(args, written);
                // 阶段标记：`network` 码不区分建连失败与读中途断流（规格 §5 边界）。
                return WorkerEnd::Failed(format!("{}transfer: read: {e}", error::PHASE_PREFIX));
            }
        };
        // 唯一写盘检查点（单连接路径）。票据只覆盖这一块写。
        let _ticket = match (&args.gate, &lease) {
            (Some(gate), Some(lease)) => match gate.check(lease, written, written + n as u64) {
                Ok(t) => Some(t),

                Err(_decision) => {
                    args.live.last_write_denied.store(1, Ordering::Relaxed);
                    persist_single(args, written);
                    pause_on_lease_revoked(args, "single_write");
                    return WorkerEnd::Paused;
                }
            },
            _ => None,
        };
        if let Err(e) = write_all_checked(&mut file, &buf[..n], args.io_fault) {
            return WorkerEnd::Failed(e);
        }
        written += n as u64;
        args.speed_window.add(n as u64);
        emit_progress(args, written, total);
        if last_persist.elapsed() >= PERSIST_INTERVAL {
            persist_single(args, written);
            last_persist = Instant::now();
        }
        args.limiter.take(n as u64);
        limit.take(n as u64);
    }

    if let Some(total) = total {
        if written != total {
            persist_single(args, written);
            return WorkerEnd::Failed(error::CODE_REMOTE_CHANGED.into());
        }
    }
    persist_single(args, written);
    {
        let conn = args.db.lock().unwrap();
        let _ = model::set_segment_state(&conn, id, 0, written as i64, "done");
    }
    finish_single(args, row, &save_path, written)
}

fn target_file_name(args: &Args, fallback: &str) -> String {
    let conn = args.db.lock().unwrap();
    model::get_download(&conn, args.id)
        .ok()
        .flatten()
        .map(|r| r.file_name)
        .unwrap_or_else(|| fallback.to_string())
}

fn same_dir_entry(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

fn apply_target_name(args: &Args, working: &Path, fallback: &str) -> PathBuf {
    let name = target_file_name(args, fallback);
    let dest = working.with_file_name(&name);
    if dest != working && working.exists() {
        if dest.exists() && !same_dir_entry(working, &dest) {
            let _ = std::fs::remove_file(&dest);
        }
        if let Err(e) = std::fs::rename(working, &dest) {
            if std::fs::copy(working, &dest)
                .and_then(|_| std::fs::remove_file(working))
                .is_err()
            {
                log::warn!("apply target name {}: {e}", dest.display());
            }
        }
    }
    if dest.exists() {
        dest
    } else {
        working.to_path_buf()
    }
}

fn persist_single(args: &Args, written: u64) {
    let conn = args.db.lock().unwrap();
    let _ = model::set_segment_progress(&conn, args.id, written as i64);
}

/// 写盘许可被撤销时的统一收场：**落状态 + 落事件**。
///
/// 所有被拒路径都必须走这里。原因：`WorkerEnd::Paused` 的主循环分支
/// （`match end` 里的 `Paused =>`）只写 tracing、**不改库**——各路径自己
/// 忘了落状态，任务就会停在 `Downloading` 且没有事件，调度器于是反复拉起、
/// 反复被拒。四处（单连接预检 / 单连接写盘 / zsync / manifest）共用一个函数，
/// 也避免事件文案将来漂成四种写法。
///
/// 调用方仍负责自己的持久化（`persist_single` / `save_manifest_state`）：
/// 那两件事与“为什么停”无关，不该混进来。
fn pause_with_reason(args: &Args, detail: &str) {
    let conn = args.db.lock().unwrap();
    let _ = model::set_status(&conn, args.id, Status::Paused, None);
    model::log_event(&conn, args.id, "paused", Some(detail));
}

fn pause_on_lease_revoked(args: &Args, phase: &str) {
    pause_with_reason(args, &format!("reason=write_lease_revoked phase={phase}"));
}

/// 上游声明了整文件 SHA-256 时，完成前必须对上；不符返回错误串。
///
/// 取的是**当前库里**的值而不是任务开始时的快照——同一次运行里刚取到的
/// `CHECKSUM` 也要生效。本地哈希读不出来（`got` 为 `None`）时不算失败，
/// 保持"没有哈希可比"时的既有行为。
///
/// 注意：本函数自己加 `args.db` 锁，**不能**在持有该锁时调用。
fn verify_expected_sha256(args: &Args, got: Option<&str>) -> Option<String> {
    let expected = {
        let conn = args.db.lock().unwrap();
        model::get_download(&conn, args.id)
            .ok()
            .flatten()
            .and_then(|r| r.sha256_expected)
    }?;
    let got = got?;
    if got.eq_ignore_ascii_case(&expected) {
        return None;
    }
    let detail = format!("expected={expected} got={got}");
    {
        let conn = args.db.lock().unwrap();
        model::log_event(&conn, args.id, "sha256_mismatch", Some(&detail));
    }
    tracing::warn!(
        event = "verify.file",
        phase = "verify",
        outcome = "fail",
        algo = "sha256",
        expected = expected.as_str(),
        actual = got,
        err_code = error::CODE_SHA256_MISMATCH,
    );
    Some(format!("{}: {detail}", error::CODE_SHA256_MISMATCH))
}

/// 校验失败的文件隔离：改名成 `<正式名>.bad`。
///
/// 为什么不是直接删：用户可能需要它做比对；为什么不是留在正式名下：
/// 那会让"文件名存在"看起来像成功，而且 resume 会从这个坏文件继续写。
/// 记一条 `verify.file outcome=fail`，把隔离结果也写进去。
fn quarantine_failed_file(args: &Args, path: &Path, row: &DownloadRow, algo: &str) {
    let name = target_file_name(args, &row.file_name);
    // **必须落在保存目录**，不能用 `path.with_file_name(..)`：
    // resume 路径的 `path` 是 `.aidm/<id>/0.part`，那样隔离文件会藏进工作目录，
    // cancel 或 `remove_part_dir` 一跑就没了——正好违背“留样本给用户比对”的意图。
    //
    // 已知限制：同名 `.bad` 会被下一次失败覆盖（Windows 上 rename 是 replace 语义）。
    // 需要保留多次样本时再改成 `.bad.1/.bad.2`，现在只有单因诊断需求。
    let bad = std::path::Path::new(&row.dir).join(format!("{name}.bad"));
    let renamed = std::fs::rename(path, &bad).is_ok();
    let shown = if renamed { &bad } else { path };
    let conn = args.db.lock().unwrap();
    model::log_event(
        &conn,
        args.id,
        "verify.file",
        Some(&format!(
            "outcome=fail algo={algo} quarantined={renamed} path={}",
            aidm_core::redact::redact_url(&shown.display().to_string())
        )),
    );
}

fn finish_single(args: &Args, row: &DownloadRow, path: &Path, written: u64) -> WorkerEnd {
    // **先校验、后改名**（R-DL-19）。
    //
    // 反过来的顺序会在校验失败时留下一个正式文件名、内容错误的文件：
    // 用户看到 `file.bin` 会以为成功，点"继续"还会从这个坏文件续传，
    // 等于在错误的基础上继续写（静默数据损坏）。
    //
    // 故障注入必须在算哈希之前：篡改的是真实文件，随后走完整校验链路（规格 §8）。
    inject_corruption(args.io_fault, path);
    let hash = sha256_file(path).ok();
    // 上游声明了整文件哈希就必须对上，否则不算完成。
    if let Some(err) = verify_expected_sha256(args, hash.as_deref()) {
        quarantine_failed_file(args, path, row, "sha256");
        return WorkerEnd::Failed(err);
    }
    if let Some(end) = verify_http_ed2k(args, row, path) {
        // 两种校验都是「内容不符」，处置必须一致：隔离坏样本。
        // 但**暂停/取消不隔离**——文件本身没被判错，只是没算完，隔离会毁掉可续传的东西。
        if matches!(end, WorkerEnd::Failed(_)) {
            quarantine_failed_file(args, path, row, "ed2k");
        }
        return end;
    }
    // 校验通过，此刻才提交到正式文件名。
    // 返回值之后的代码只用 `hash`/`written`，不再用路径——所以这里不绑定。
    let _ = apply_target_name(args, path, &row.file_name);
    let url = row.url_final.as_deref().unwrap_or(row.url_orig.as_str());
    {
        let conn = args.db.lock().unwrap();
        if let Some(h) = hash.as_deref() {
            model::log_event(&conn, args.id, "sha256", Some(h));
            tracing::info!(
                event = "verify.file",
                phase = "verify",
                outcome = "ok",
                algo = "sha256",
                mode = "single",
                total_bytes = written,
            );
        }
        let _ = model::mark_done(&conn, args.id, url);
        // 完成以最终文件为准：段行收尾成整段下满（进度必定 100%）
        let _ = model::finalize_segments(&conn, args.id);
        model::log_event(
            &conn,
            args.id,
            "done",
            Some(&format!(
                "bytes={written} sha256={}",
                hash.as_deref().unwrap_or("-")
            )),
        );
    }
    args.live.done_bytes.store(written, Ordering::Relaxed);
    args.live.speed_bps.store(0, Ordering::Relaxed);
    WorkerEnd::Done
}

/// 整包 MD4（eD2k Official），**可见且可中断**：分块喂给 `Ed2kHasher`，
/// 每 ~250 ms 上报一次进度；`Ok(None)` 表示被暂停/取消打断（后续状态由调用方决定）。
///
/// 为什么不用 `aidm_core::ed2k::hash::hash_file`：它一口气读完整个文件，
/// 4 GB 级文件在调试构建下要两分钟，且没有任何进度点与中断点。
fn hash_file_visible(
    args: &Args,
    path: &Path,
    size: u64,
) -> std::io::Result<Option<aidm_core::ed2k::hash::Ed2kDigest>> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = aidm_core::ed2k::hash::Ed2kHasher::new(aidm_core::ed2k::Flavor::Official);
    // 4 MiB 缓冲：既不至于 syscall 过多，也不会让单次 update 太长而无法响应暂停。
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut done: u64 = 0;
    let mut last_report = Instant::now();
    loop {
        if args.cancel.load(Ordering::SeqCst) || args.pause.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        done += n as u64;
        if last_report.elapsed() >= Duration::from_millis(250) {
            emit_progress(args, done, Some(size));
            last_report = Instant::now();
        }
    }
    emit_progress(args, done, Some(size));
    Ok(Some(hasher.finish()))
}

/// HTTP 换源任务的完成验收：`ed2k_hash` 有值且任务已经不是 eD2k 链接时，
/// 按 eD2k 整包 MD4 再算一遍。eD2k 本地已有文件的路径已经在别处验过，
/// 这里用 `url_orig` 前缀跳过，避免 4GB 文件重复哈希。
fn verify_http_ed2k(args: &Args, row: &DownloadRow, path: &Path) -> Option<WorkerEnd> {
    let want = row.ed2k_hash.as_deref()?.trim();
    if want.is_empty()
        || row
            .url_orig
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("ed2k:")
    {
        return None;
    }
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    match hash_file_visible(args, path, size) {
        Ok(Some(done)) if done.file_hex().eq_ignore_ascii_case(want) => {
            let conn = args.db.lock().unwrap();
            model::log_event(
                &conn,
                args.id,
                "ed2k_hash_ok",
                Some(&format!("{} (http 换源)", want.to_ascii_lowercase())),
            );
            None
        }
        Ok(Some(done)) => {
            let got = done.file_hex();
            let conn = args.db.lock().unwrap();
            model::log_event(
                &conn,
                args.id,
                "ed2k_hash_mismatch",
                Some(&format!("want={} got={got}", want.to_ascii_lowercase())),
            );
            Some(WorkerEnd::Failed(
                aidm_core::error::CODE_ED2K_HASH_MISMATCH.into(),
            ))
        }
        Ok(None) => Some(if args.pause.load(Ordering::SeqCst) {
            WorkerEnd::Paused
        } else {
            WorkerEnd::Cancelled
        }),
        Err(e) => Some(WorkerEnd::Failed(format!("ed2k_hash_io: {e}"))),
    }
}

fn emit_progress(args: &Args, done: u64, total: Option<u64>) {
    args.live.done_bytes.store(done, Ordering::Relaxed);
    let sp = args.speed_window.bytes_per_sec();
    args.live.speed_bps.store(sp, Ordering::Relaxed);
    // 进度事件**节流**到 5 秒一条：这条路径每次读循环都会调用，逐次打日志会直接
    // 违反"正常路径不刷屏"（规格 §3.4）。用 CAS 保证并发分段下也只有一个线程发。
    const PROGRESS_LOG_MS: u64 = 5_000;
    let now = model::now_ms() as u64;
    let last = args.live.last_progress_log_ms.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= PROGRESS_LOG_MS
        && args
            .live
            .last_progress_log_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::debug!(
            event = "transfer.progress",
            phase = "transfer",
            done_bytes = done,
            total_bytes = total.unwrap_or(0),
            size_known = total.is_some(),
            speed_bps = sp,
        );
    }
    if let Some(cb) = &args.progress_cb {
        cb(Progress {
            id: args.id,
            done_bytes: done,
            total,
            speed_bps: sp,
        });
    }
}

/// 若这是 S3 任务，**现在**重新预签一次并返回新鲜地址；不是则返回 `None`。
///
/// 为什么每次下载都重签而不是复用落库那份：预签名带有效期（`s3.presign_ttl_s`），
/// 长任务续传、暂停后恢复、重试都会跨越它。重签是纯计算（HMAC，微秒级），
/// 比"落库一个过期时刻并保证它与 URL 同步"简单得多，也不可能不同步。
///
/// 判断依据是 `row.url_orig` —— S3 任务的 `url_orig` 保留 `s3://` 形态。
/// 其它协议的 `normalize` 直接回 `Ok(None)`，所以本函数对它们是零成本的空转。
fn refresh_s3_url(ctx: &Ctx<'_>, row: &DownloadRow) -> Option<String> {
    let (ak, sk, rg, ep, ttl) = {
        let conn = ctx.args.db.lock().unwrap();
        let g = |k: &str| settings::get(&conn, k).ok().flatten().unwrap_or_default();
        (
            g("s3.access_key"),
            g("s3.secret_key"),
            g("s3.region"),
            g("s3.endpoint"),
            g("s3.presign_ttl_s").trim().parse::<u64>().unwrap_or(3600),
        )
    };
    let cfg = crate::s3::S3Config {
        access_key: &ak,
        secret_key: &sk,
        region: &rg,
        endpoint: &ep,
        ttl_secs: ttl,
    };
    match crate::s3::normalize(&row.url_orig, &cfg) {
        Ok(Some(p)) => Some(p.url),
        // 不是 S3 任务，或凭据已失效：退回落库的地址，由后续探测如实报错 ——
        // 在这里 fail 掉会让"凭据被删"表现成"任务莫名其妙不动"。
        _ => None,
    }
}

/// 跨源聚合的来源池（含已生效地址）。返回空 = 保持单源。
///
/// 门槛见 [`aidm_core::segment::multi_source_allowed`]：**必须拿得到上游整文件哈希**
/// （换取"完成后能发现内容不一致"这一条兜底），且每个入池来源报出的总长度都与本任务
/// 一致。没哈希就没有任何兜底，此时宁可慢，也不能下出一个拼错的包。
///
/// 只在分段下载且已确认多源可用时调用，所以正常任务不会多花探测请求。
/// 探测结果 → 单源版本 token（与 `source::provider` 同口径）。
fn probe_version(p: &probe::ProbeResult) -> Option<String> {
    if let Some(etag) = p.etag.as_deref().filter(|v| !v.is_empty()) {
        return Some(format!("etag:{etag}"));
    }
    p.last_modified
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|lm| format!("lm:{lm}"))
}

fn source_pool(
    ctx: &Ctx<'_>,
    row: &DownloadRow,
    total: u64,
    active: &str,
    active_version: Option<&str>,
) -> (Vec<String>, HashMap<String, String>) {
    // 读**当前库里**的值，而不是任务开始时的快照：Metalink / CHECKSUM 可能刚在本轮
    // 把 `sha256_expected` 写进去（`row` 还是启动时那一份）。
    let (has_hash, recorded_size) = {
        let conn = ctx.args.db.lock().unwrap();
        match model::get_download(&conn, row.id) {
            Ok(Some(fresh)) => (fresh.sha256_expected.is_some(), fresh.size_total),
            _ => (row.sha256_expected.is_some(), row.size_total),
        }
    };
    if !has_hash {
        return (Vec::new(), HashMap::new());
    }
    // 智能加速的两个"值不值得"判据（都在这里读，避免多次加锁）。
    //
    // `measure_window_s` / `measure_min_bps` 这两个键**刻意不在这里用**：
    // 本函数在**下载开始之前**调用，此刻没有任何速度数据可依据。要让它们生效必须
    // 改变调用时机（边下边评估、再动态加源），那是 fastdl `Plan` 的动态加源改动，
    // 与这里的一次性静态发现不是同一件事。见 docs/protocol-capabilities.md。
    let (min_size_mb, max_sources) = {
        let conn = ctx.args.db.lock().unwrap();
        let g = |k: &str| settings::get(&conn, k).ok().flatten().unwrap_or_default();
        (
            g("alt.probe_min_size_mb")
                .trim()
                .parse::<u64>()
                .unwrap_or(0),
            g("alt.max_sources")
                .trim()
                .parse::<usize>()
                .unwrap_or(aidm_core::segment::MAX_SOURCES)
                .clamp(1, 16),
        )
    };
    // 小文件不值得为"多找几个源"发探测请求：每个候选一次 Range 探测，而小文件
    // 本身可能几秒就下完了。0 = 不启用（默认，保持既有行为）。
    if min_size_mb > 0 && total < min_size_mb.saturating_mul(1024 * 1024) {
        log::debug!(
            "task {}: {total} 字节小于 alt.probe_min_size_mb={min_size_mb} MiB，跳过镜像发现",
            row.id
        );
        return (Vec::new(), HashMap::new());
    }
    let auto_mirrors = {
        let conn = ctx.args.db.lock().unwrap();
        settings::get(&conn, "alt.auto_mirrors")
            .ok()
            .flatten()
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    };
    let cands = aidm_core::alt::candidates_with_mirrors(
        &row.url_orig,
        row.alt_urls.as_deref(),
        auto_mirrors,
    );
    let mut pool: Vec<String> = vec![active.to_string()];
    let mut versions: HashMap<String, String> = HashMap::new();
    if let Some(v) = active_version {
        versions.insert(active.to_string(), v.to_string());
    }
    // 上游 Metalink 发现的镜像**优先**：它们是上游自己列的，比静态表权威。
    // 它们不进候选序号（`alt_cursor` 承诺的是下标），只喂这个来源池。
    let discovered = {
        let conn = ctx.args.db.lock().unwrap();
        model::get_mirrors_urls(&conn, row.id)
    };
    let rest: Vec<String> = discovered
        .into_iter()
        .chain(cands.iter().cloned())
        .filter(|c| !aidm_core::alt::same_url(c, active))
        .collect();
    // 注意：这里的"候选不足"要看**合并之后**的列表 —— 主地址没有备用地址、
    // 也不在任何镜像命名空间里时，`cands` 只有一个，但 Metalink 可能给了一串镜像。
    if rest.is_empty() {
        return (Vec::new(), HashMap::new());
    }
    for cand in rest.iter() {
        if pool.len() >= max_sources {
            break;
        }
        let attempt = {
            let _probe_conn = acquire_conn(&ctx.args.active_conns);
            probe::probe(
                &ctx.args.http.agent_for(cand),
                cand,
                &ctx.profile,
                ctx.args.referer.as_deref(),
                ctx.cookies.as_deref(),
                &ctx.custom_headers,
            )
        };
        match attempt {
            // 长度必须与本次任务一致：不一致 = 不是同一份文件，不进池。
            // 段级版本也要对得上：同一地址换了内容就跳过，绝不把两个版本拼在一起。
            Ok(p) if p.total == Some(total) => {
                let version = probe_version(&p);
                let stored = {
                    let conn = ctx.args.db.lock().unwrap();
                    model::segment_src_version(&conn, row.id, cand).unwrap_or(None)
                };
                if let (Some(stored), Some(current)) = (stored.as_deref(), version.as_deref()) {
                    if stored != current {
                        let conn = ctx.args.db.lock().unwrap();
                        model::log_event(
                            &conn,
                            row.id,
                            "source_version_changed",
                            Some(&format!("stored={stored} current={current}")),
                        );
                        continue;
                    }
                }
                if let Some(v) = version {
                    versions.insert(cand.clone(), v);
                }
                pool.push(cand.clone());
            }
            Ok(p) => log::debug!(
                "task {}: 来源 {} 长度 {:?} 与 {:?} 不符，不参与跨源聚合",
                row.id,
                aidm_core::redact::redact_url(cand),
                p.total,
                total
            ),
            Err(e) => log::debug!("task {}: 来源探测失败（{e}），不参与跨源聚合", row.id),
        }
    }
    let sizes: Vec<Option<u64>> = pool.iter().map(|_| Some(total)).collect();
    if !aidm_core::segment::multi_source_allowed(true, recorded_size, &sizes) {
        return (Vec::new(), HashMap::new());
    }
    if pool.len() >= 2 {
        // 按**实测评分**重排：记录够 20 条且没被暂停的来源排前面，没数据的保持原有
        // 相对顺序排在后面（"没数据"不等于不可用，探测阶段还要能试到它）。
        // 这一步只改顺序、不改集合 —— 长度校验与跨源门槛都已经在上面判过了。
        let ordered = crate::source_registry::order_by_score(&pool, total);
        if ordered != pool {
            let conn = ctx.args.db.lock().unwrap();
            model::log_event(
                &conn,
                row.id,
                "source_rank",
                Some(&format!(
                    "before={:?} after={:?}",
                    pool.iter()
                        .map(|u| aidm_core::redact::redact_url(u))
                        .collect::<Vec<_>>(),
                    ordered
                        .iter()
                        .map(|u| aidm_core::redact::redact_url(u))
                        .collect::<Vec<_>>()
                )),
            );
            log::info!("task {}: 来源池按实测评分重排", row.id);
        }
        let conn = ctx.args.db.lock().unwrap();
        model::log_event(
            &conn,
            row.id,
            "multi_source",
            Some(&format!("sources={} total={total}", ordered.len())),
        );
        return (ordered, versions);
    }
    (pool, versions)
}

fn multi_download(
    ctx: &Ctx<'_>,
    row: &DownloadRow,
    dir: &Path,
    probed: &probe::ProbeResult,
    fresh: bool,
) -> WorkerEnd {
    let args = ctx.args;
    let id = args.id;
    let total = match probed
        .total
        .or_else(|| row.size_total.map(|t| t.max(0) as u64))
    {
        Some(t) if t > 0 => t,
        _ => return WorkerEnd::Failed("unknown_size".into()),
    };
    // 连接预算只有一个解析器：每服务器例外 > 全局闸门（`hosts::task_conns`）。
    let desired = {
        let conn = args.db.lock().unwrap();
        task_conns_for(&conn, row)
    };
    // 跨源聚合的来源池：空 = 单源（与从前完全一致）。
    //
    // S3 任务在这里**重签**：预签名地址带有效期，落库那份在长任务续传时可能已经
    // 失效。判断依据是 `url_orig`（它才是稳定标识，保留 `s3://` 形态），
    // 而不是去看 `url_final` —— 那样就得额外落库一个"过期时刻"并保证它同步。
    let active_url = match refresh_s3_url(ctx, row) {
        Some(fresh) => fresh,
        None => row
            .url_final
            .clone()
            .unwrap_or_else(|| row.url_orig.clone()),
    };
    let active_version = probe_version(probed);
    let (source_list, source_versions) =
        source_pool(ctx, row, total, &active_url, active_version.as_deref());
    let sources = Arc::new(source_list);
    let source_versions = Arc::new(source_versions);

    if fresh {
        // 读表优先：表里有**当前版本且恰好覆盖 [0,total)** 的方案就直接用。
        //
        // 为什么不是无条件信任表：表可能来自另一个 total（文件变了）、来自未知
        // 长度的开区间、或者被坏数据污染。用错方案会把字节写到错误位置，
        // 所以只要有一条不满足就回退重算——不修补、不猜测。
        let (persisted, had_rows) = {
            let conn = args.db.lock().unwrap();
            let rev = aidm_core::download::store::load_runtime(&conn, id)
                .ok()
                .flatten()
                .map(|r| r.plan_revision)
                .unwrap_or(0);
            let rows = aidm_core::download::store::load_plan(&conn, id, rev).unwrap_or_default();
            let had_rows = !rows.is_empty();
            let normalized: Vec<aidm_core::download::plan::NormalizedSpan> = rows
                .iter()
                .map(|r| (r.span_start, r.span_end_exclusive))
                .collect();
            // 段数上限：表里的方案可以由命令塞进来，不校验就是「一条命令
            // spawn 上千个线程」。
            let sane = normalized.len() <= aidm_core::download::plan::MAX_PLAN_SLICES
                && aidm_core::download::plan::covers_exactly(&normalized, total);
            if sane {
                (rows, had_rows)
            } else {
                (Vec::new(), had_rows)
            }
        };
        let spans: Vec<aidm_core::segment::ByteSpan> = if persisted.is_empty() {
            match args.execution_mode {
                aidm_core::download::control::ExecutionMode::Legacy => {
                    // legacy 允许兜底自算（并写表，见下面）。
                    plan_segments(total, desired)
                }
                aidm_core::download::control::ExecutionMode::Unified => {
                    // unified 下让 worker 自算就是「unified 名义、legacy 决策」，
                    // 正是文档 12.2 禁止的双归属。缺方案就停下并如实报原因。
                    let detail = if had_rows {
                        "reason=plan_invalid"
                    } else {
                        "reason=plan_missing"
                    };
                    pause_with_reason(args, detail);
                    return WorkerEnd::Paused;
                }
            }
        } else {
            // 表存的是左闭右开，`ByteSpan` 是闭区间：这里换算回来。
            persisted
                .iter()
                .map(|r| aidm_core::segment::ByteSpan {
                    start: r.span_start,
                    end: r.span_end_exclusive.unwrap_or(total).saturating_sub(1),
                })
                .collect()
        };
        let paths: Vec<String> = spans
            .iter()
            .enumerate()
            .map(|(i, _)| {
                segment::part_path(dir, id, i as i32)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        if let Err(e) = std::fs::create_dir_all(segment::part_dir(dir, id)) {
            return fail_io(args.io_fault, e, "mkdir parts");
        }
        let mut conn = args.db.lock().unwrap();
        if let Err(e) = model::replace_segments(&conn, id, &spans, &paths) {
            return WorkerEnd::Failed(format!("db: {e}"));
        }
        // C3-a 影子：把**同一份**方案写进 `download_slices`，供逐字节对照。
        //
        // 执行仍然用内存里的 `spans`，语义一行未改。之所以要有这一步：
        // 没有真实写入者，“表和 legacy 算的一样”就只能靠肉眼。
        // `plan_revision` 取递增版本——legacy 允许重规划，表必须反映当前方案。
        {
            use aidm_core::download::store as dstore;
            // 方案版本只有一个来源：`download_runtime.plan_revision`。
            // 表里的 `plan_revision` 是它的镜像，不再各自递增（两份计数迟早分叉）。
            let _ = dstore::ensure_runtime(&conn, id);
            let rt = dstore::load_runtime(&conn, id).ok().flatten();
            let generation = rt.as_ref().map(|r| r.content_generation).unwrap_or(0);
            let current = rt.as_ref().map(|r| r.plan_revision).unwrap_or(0);

            let rows: Vec<dstore::SliceRow> = spans
                .iter()
                .enumerate()
                .map(|(i, s)| dstore::SliceRow {
                    slice_id: format!("task-{id}-seg-{i}"),
                    resource_id: format!("task-{id}"),
                    span_start: s.start,
                    // `plan_segments` 返回**闭区间**，这里换算成左闭右开。
                    span_end_exclusive: Some(s.end.saturating_add(1)),
                    state: "pending".to_owned(),
                })
                .collect();

            // 只在**结构性变化**时递增版本（与 C1 的
            // `plan_revision_only_moves_on_structural_change` 一致）：
            // 方案没变还 bump，会让“版本”失去“方案变过”的含义。
            //
            // 读表命中时这里必然「相同」→ 不 bump、不重写，表与执行保持一致。
            let same = {
                let projected_new = aidm_core::download::plan::project_rows(
                    &rows
                        .iter()
                        .map(|r| (r.span_start, r.span_end_exclusive))
                        .collect::<Vec<_>>(),
                );
                let projected_old = aidm_core::download::plan::project_rows(
                    &dstore::load_plan(&conn, id, current)
                        .unwrap_or_default()
                        .iter()
                        .map(|r| (r.span_start, r.span_end_exclusive))
                        .collect::<Vec<_>>(),
                );
                projected_new == projected_old
            };
            if !same {
                if let Ok(rev) = dstore::bump_plan_revision(&mut conn, id) {
                    let _ = dstore::save_plan(&mut conn, id, generation, rev, &rows);
                }
            }
        }
        // 分段轮流绑来源。池为空时 `assign_sources` 返回全 `None`，
        // 等价于从前的"所有段打向同一个地址"。
        for (i, src) in aidm_core::segment::assign_sources(spans.len(), &sources)
            .iter()
            .enumerate()
        {
            let _ = model::set_segment_src(&conn, id, i as i32, src.as_deref());
            let version = src.as_deref().and_then(|u| source_versions.get(u)).cloned();
            let _ = model::set_segment_src_version(&conn, id, i as i32, version.as_deref());
        }
        model::log_event(
            &conn,
            id,
            "start",
            Some(&format!(
                "mode=multi conns={} final={} size={total} mime={:?} sources={}",
                spans.len(),
                probed.final_url,
                probed.content_type,
                sources.len()
            )),
        );
    } else if let Err(e) = std::fs::create_dir_all(segment::part_dir(dir, id)) {
        return fail_io(args.io_fault, e, "mkdir parts");
    }

    let segs = {
        let conn = args.db.lock().unwrap();
        let _ = model::set_status(&conn, id, Status::Downloading, None);
        match model::list_segments(&conn, id) {
            Ok(s) => s,
            Err(e) => return WorkerEnd::Failed(format!("db: {e}")),
        }
    };
    if segs.is_empty() {
        return WorkerEnd::Failed("no_segments".into());
    }

    // 方案漂移观测（只记录，不重建）。
    //
    // `segments` 是**执行事实**（带 done_bytes / part_path），`download_slices`
    // 只是计划。拿表去重建 segments 会把已完成字节清零，所以这里只留一条事件
    // 供诊断：出现它说明有人改了表却没改执行，接协调器之前必须解释清楚。
    {
        let conn = args.db.lock().unwrap();
        let rev = aidm_core::download::store::load_runtime(&conn, id)
            .ok()
            .flatten()
            .map(|r| r.plan_revision)
            .unwrap_or(0);
        let rows = aidm_core::download::store::load_plan(&conn, id, rev).unwrap_or_default();
        if !rows.is_empty() {
            let table_proj = aidm_core::download::plan::project_rows(
                &rows
                    .iter()
                    .map(|r| (r.span_start, r.span_end_exclusive))
                    .collect::<Vec<_>>(),
            );
            let seg_proj = aidm_core::download::plan::project_rows(
                &segs
                    .iter()
                    .map(|s| (s.pos_start as u64, s.pos_end.map(|e| e as u64 + 1)))
                    .collect::<Vec<_>>(),
            );
            if table_proj != seg_proj {
                model::log_event(
                    &conn,
                    id,
                    "plan_segments_drift",
                    Some(&format!("plan_revision={rev}")),
                );
            }
        }
    }

    let already: u64 = segs.iter().map(|s| s.done_bytes.max(0) as u64).sum();
    args.live.total_bytes.store(total, Ordering::Relaxed);
    args.live.done_bytes.store(already, Ordering::Relaxed);

    let fail = Arc::new(Mutex::new(None::<String>));
    let limit = RateLimit::new(row.speed_limit_kbps);
    // 段级「持续慢」的两个配置（R-DL-14）。两者默认都是 0 = 关闭，
    // 所以**默认行为与从前完全一致**，这两行读不到值时也不会改变任何事。
    let (measure_window_s, measure_min_bps) = {
        let conn = args.db.lock().unwrap();
        let g = |k: &str| settings::get(&conn, k).ok().flatten().unwrap_or_default();
        (
            g("alt.measure_window_s").trim().parse::<u64>().unwrap_or(0),
            g("alt.measure_min_bps").trim().parse::<u64>().unwrap_or(0),
        )
    };
    // "已完成分段的平均速率"由各段线程完成时自己往里累加。
    let done_pace = Arc::new(DonePace::default());
    let url = row
        .url_final
        .clone()
        .unwrap_or_else(|| row.url_orig.clone());

    let mut handles = Vec::new();
    for seg in segs {
        if seg.is_done() {
            continue;
        }
        // 段 = 分配单元：签一份覆盖 `pos_start..pos_end+1` 的许可。
        // 段线程退出后由 `revoke_write_lease` 撤销，暂停/删除时由闸门统一撤销。
        let lease = args.gate.as_ref().map(|gate| {
            let assignment = AssignmentId::new(format!("seg:{id}:{}", seg.idx));
            gate.issue(
                assignment,
                SliceId::new(format!("seg:{id}:{}", seg.idx)),
                Span::known(seg.pos_start as u64, seg.pos_end.unwrap_or(0) as u64 + 1)
                    .unwrap_or_else(|| Span::open(seg.pos_start as u64)),
            )
        });
        let handle = SegmentArgs {
            id,
            idx: seg.idx,
            gate: args.gate.clone(),
            lease,
            pos_start: seg.pos_start as u64,
            pos_end: seg.pos_end.unwrap_or(0) as u64,
            done_bytes: seg.done_bytes.max(0) as u64,
            part_path: PathBuf::from(&seg.part_path),
            // 该段绑定的来源；没绑过（老库 / 单源）就回落到任务级地址
            url: seg.src_url.clone().unwrap_or_else(|| url.clone()),
            sources: sources.clone(),
            source_versions: source_versions.clone(),
            src_version: seg.src_version.clone(),
            profile: ctx.profile.clone(),
            referer: ctx.args.referer.clone(),
            custom_headers: ctx.custom_headers.clone(),
            cookies: ctx.cookies.clone(),
            http: args.http.clone(),
            db: args.db.clone(),
            live: args.live.clone(),
            cancel: args.cancel.clone(),
            pause: args.pause.clone(),
            fail: fail.clone(),
            speed_window: args.speed_window.clone(),
            progress_cb: args.progress_cb.clone(),
            total,
            limit: limit.clone(),
            limiter: args.limiter.clone(),
            active_conns: args.active_conns.clone(),
            io_fault: args.io_fault,
            etag: row.etag.clone(),
            last_modified: row.last_modified.clone(),
            expected_total: total,
            measure_window_s,
            measure_min_bps,
            done_pace: done_pace.clone(),
        };
        match std::thread::Builder::new()
            .name(format!("aidm-seg-{id}-{}", seg.idx))
            .spawn(move || run_segment(handle))
        {
            Ok(h) => handles.push(h),
            Err(e) => return WorkerEnd::Failed(format!("spawn segment: {e}")),
        }
    }

    for h in handles {
        let _ = h.join();
    }

    if args.cancel.load(Ordering::SeqCst) {
        return WorkerEnd::Cancelled;
    }
    if let Some(e) = fail.lock().unwrap().clone() {
        return WorkerEnd::Failed(e);
    }
    let all_done = {
        let conn = args.db.lock().unwrap();
        model::all_segments_done(&conn, id).unwrap_or(false)
    };
    if args.pause.load(Ordering::SeqCst) && !all_done {
        let done = {
            let conn = args.db.lock().unwrap();
            model::sum_done_bytes(&conn, id).unwrap_or(0)
        };
        let conn = args.db.lock().unwrap();
        let _ = model::set_status(&conn, id, Status::Paused, None);
        model::log_event(&conn, id, "paused", Some(&format!("done={done}")));
        return WorkerEnd::Paused;
    }
    if !all_done {
        return WorkerEnd::Failed("segments_incomplete".into());
    }
    merge_finish(args, row, dir)
}

/// 任务级：**已完成分段**的累积字节与耗时。
///
/// 段级换源的参照物就是它 —— 规格 R-DL-14 的原话是「低于**已完成分段的平均速率**」。
/// 用累积比值而不是滑动窗口：它单调、不会被某一段的抖动带偏，也不需要额外的历史缓冲。
#[derive(Default)]
struct DonePace {
    bytes: AtomicU64,
    ms: AtomicU64,
}

impl DonePace {
    fn add(&self, bytes: u64, ms: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// 已完成段的平均速率（B/s）。**还没有段完成时回 `None` —— 不是 0**：
    /// 0 会让"低于平均"对每一个源都成立，等于一上来就乱换源。
    fn avg_bps(&self) -> Option<f64> {
        let ms = self.ms.load(Ordering::Relaxed);
        if ms == 0 {
            return None;
        }
        Some(self.bytes.load(Ordering::Relaxed) as f64 * 1000.0 / ms as f64)
    }
}

/// 一个分段最多按"慢"换几次源。
///
/// 规格（R-DL-14）说了什么时候**可以**换，没说可以换几次；没有上限时，两个都很慢的源
/// 会让这一段在两个地址之间来回弹，永远下不完。这里按"每段 3 次"封顶，
/// 用完之后该段就关掉观察、老老实实按当前来源下完 —— 慢，但会结束。
const SEGMENT_SLOW_SWITCH_MAX: u32 = 3;

/// 单源时（无可换之源）按"慢"重开连接的次数上限。语义与上一个常量相同：
/// 换一条新连接是有意义的（慢常常是这条连接的事），但同样必须有界。
const SEGMENT_SLOW_RECONNECT_MAX: u32 = 2;

struct SegmentArgs {
    id: i64,
    idx: i32,
    /// 写入许可闸门；与 `lease` 同时存在时才做写盘检查。
    gate: Option<Arc<WriteGate>>,
    /// 本段的写入许可。span 与 `pos_start..=pos_end` 一致。
    lease: Option<WriteLease>,
    pos_start: u64,
    pos_end: u64,
    done_bytes: u64,
    part_path: PathBuf,
    url: String,
    /// 本任务的来源池（跨源聚合）。长度 < 2 时 `url` 不会变，行为与单源一致。
    sources: Arc<Vec<String>>,
    /// 来源 → 版本 token（`etag:` / `lm:`），换源时同步更新。
    source_versions: Arc<HashMap<String, String>>,
    /// 本段绑定来源在分配时的版本 token；重启续传时用它恢复 etag/lm。
    src_version: Option<String>,
    /// 请求头配置（UA / Accept 系列 / Referer 兜底）
    profile: aidm_core::http_profile::RequestProfile,
    /// 显式 Referer（浏览器给的），优先于 profile 的站点根兜底
    referer: Option<String>,
    /// 每任务自定义请求头
    custom_headers: Vec<aidm_core::headers::HeaderLine>,
    cookies: Option<String>,
    http: Arc<HttpRuntime>,
    db: Arc<Mutex<Connection>>,
    live: Arc<LiveState>,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    fail: Arc<Mutex<Option<String>>>,
    speed_window: Arc<SpeedWindow>,
    progress_cb: Option<ProgressCallback>,
    total: u64,
    limit: Arc<RateLimit>,
    limiter: Arc<TokenBucket>,
    active_conns: Arc<AtomicU64>,
    io_fault: IoFault,
    etag: Option<String>,
    last_modified: Option<String>,
    expected_total: u64,
    /// 段级「持续慢」判定窗口（秒）。**0 = 关闭**（`alt.measure_window_s` 的默认值），
    /// 关闭时这一段走的代码路径与从前完全一致。
    measure_window_s: u64,
    /// 窗口内速率低于该值（字节/秒）即判慢（`alt.measure_min_bps`，0 = 不用这条判据）。
    measure_min_bps: u64,
    /// 任务级「已完成分段的平均速率」—— 段级换源的参照物（R-DL-14）。
    done_pace: Arc<DonePace>,
}

fn run_segment(mut args: SegmentArgs) {
    // 段线程退出（任何原因）时撤销本段许可，避免账本里堆积历史分配。
    let _reaper = match (&args.gate, &args.lease) {
        (Some(gate), Some(lease)) => Some(gate.reaper(lease)),
        _ => None,
    };
    // 段级版本优先后于任务级 etag/lm：跨源聚合时每一段绑的是不同地址，
    // 用任务级校验器比较会误判。重启续传也靠这里恢复。
    if let Some(version) = args.src_version.clone() {
        if let Some(v) = version.strip_prefix("etag:") {
            args.etag = Some(v.to_string());
        } else if let Some(v) = version.strip_prefix("lm:") {
            args.last_modified = Some(v.to_string());
        }
    }
    let mut done = args.done_bytes;
    let expected = args
        .pos_end
        .saturating_sub(args.pos_start)
        .saturating_add(1);
    if done >= expected {
        persist_seg(&args, expected, "done");
        return;
    }
    let mut attempt = 0u32;
    // 按"慢"（而不是按失败）换源/换连接的次数。两者都必须封顶，见上面两个常量。
    let mut slow_switches = 0u32;
    let mut slow_reconnects = 0u32;
    loop {
        if args.cancel.load(Ordering::SeqCst) {
            persist_seg(&args, done, "pending");
            return;
        }
        if args.pause.load(Ordering::SeqCst) {
            persist_seg(&args, done, "pending");
            return;
        }
        if args.fail.lock().unwrap().is_some() {
            persist_seg(&args, done, "pending");
            return;
        }
        // 计时并在**这一段的来源**上记一次尝试（来源打分的数据源）。
        //
        // 只有"下完"与"失败"记：暂停/取消是**用户**的动作，不是来源的问题，
        // 把它们记成失败会让用户每暂停一次就抹黑一次当前镜像。
        // 首字节耗时这里拿不到（传 0 = 没测到），打分内核会把它排除在响应速度样本外。
        let t_attempt = std::time::Instant::now();
        let done_before = done;
        let outcome = try_segment_once(&args, &mut done, expected);
        if let SegOnce::Done | SegOnce::Failed(..) = &outcome {
            crate::source_registry::record(
                &args.url,
                done.saturating_sub(done_before),
                t_attempt.elapsed().as_millis() as u64,
                0,
                matches!(outcome, SegOnce::Done),
                crate::source_registry::now_ms(),
            );
        }
        match outcome {
            SegOnce::Done => {
                // 这一段下完了：把字节/耗时计入"已完成分段"，给后面的慢判定当参照物。
                args.done_pace
                    .add(expected, t_attempt.elapsed().as_millis() as u64);
                persist_seg(&args, expected, "done");
                return;
            }
            SegOnce::Paused | SegOnce::Cancelled => {
                persist_seg(&args, done, "pending");
                return;
            }
            // **慢不是失败**：不计入 `attempt`（那会吃掉真实失败的重试预算），也不写给来源
            // 打分（"慢"已经通过速度分体现在评分里；在这里再记一次会让换源判定自我强化）。
            SegOnce::Slow(reason) => {
                persist_seg(&args, done, "pending");
                // 多源：换到池里**实测最快**的来源（R-DL-14 的口径，不是轮转到下一个）。
                if args.sources.len() > 1 && slow_switches < SEGMENT_SLOW_SWITCH_MAX {
                    if let Some(target) = fastest_source(&args) {
                        if target != args.url {
                            slow_switches += 1;
                            switch_segment_source(&mut args, target, reason, attempt);
                            continue;
                        }
                    }
                }
                if args.sources.len() < 2 && slow_reconnects < SEGMENT_SLOW_RECONNECT_MAX {
                    // 单源没有别的来源可换，但"换一条新连接"仍然可能有效 —— 慢的常常
                    // 就是这一条连接。**不退避**：目的就是尽快重连。
                    slow_reconnects += 1;
                    let conn = args.db.lock().unwrap();
                    model::log_event(
                        &conn,
                        args.id,
                        "segment_retry",
                        Some(&format!(
                            "idx={} attempt={attempt} code=slow reason={}",
                            args.idx,
                            reason.as_str()
                        )),
                    );
                    drop(conn);
                    continue;
                }
                // 换源与重连的额度都用完：关掉观察，按当前来源把这一段下完 ——
                // 慢，但一定会结束。这是防死循环的最后一道保险。
                args.measure_window_s = 0;
            }
            SegOnce::Failed(code, retry_after) => {
                classify_segment_source(&args, &code);
                if segment_fail_is_fatal(&code) {
                    persist_seg(&args, done, "error");
                    *args.fail.lock().unwrap() = Some(code);
                    return;
                }
                attempt += 1;
                // 有多个来源时换下一个：**同一段仍然只从一个源取**（不混源），
                // 换源只影响"这一段的剩余部分从哪里续"。
                // 换源后原地址的 ETag/Last-Modified 不再适用，必须让路。
                if args.sources.len() > 1 {
                    if let Some(next) =
                        aidm_core::segment::next_source(Some(&args.url), &args.sources)
                    {
                        if next != args.url {
                            let from = std::mem::replace(&mut args.url, next);
                            args.etag = None;
                            args.last_modified = None;
                            let conn = args.db.lock().unwrap();
                            let _ = model::set_segment_src(
                                &conn,
                                args.id,
                                args.idx,
                                Some(args.url.as_str()),
                            );
                            model::log_event(
                                &conn,
                                args.id,
                                "segment_src_switch",
                                Some(&format!(
                                    "idx={} attempt={attempt} from={} to={}",
                                    args.idx,
                                    aidm_core::redact::redact_url(&from),
                                    aidm_core::redact::redact_url(&args.url)
                                )),
                            );
                            tracing::info!(
                                event = "segment.src_switch",
                                phase = "transfer",
                                seg = args.idx,
                                attempt,
                                from = %aidm_core::redact::redact_url(&from),
                                to = %aidm_core::redact::redact_url(&args.url),
                            );
                            drop(conn);
                        }
                    }
                }
                {
                    let conn = args.db.lock().unwrap();
                    let _ =
                        model::set_segment_retries(&conn, args.id, args.idx, i64::from(attempt));
                    model::log_event(
                        &conn,
                        args.id,
                        "segment_retry",
                        Some(&format!(
                            "idx={} attempt={attempt} code={code} retry_after={retry_after:?}",
                            args.idx
                        )),
                    );
                }
                tracing::info!(
                    event = "retry.scheduled",
                    phase = "transfer",
                    seg = args.idx,
                    attempt_next = attempt,
                    reason = %code,
                    retry_after_ms = ?retry_after,
                );
                persist_seg(&args, done, "pending");
                if attempt > SEGMENT_RETRY_MAX {
                    *args.fail.lock().unwrap() = Some(format!("segment_{} {code}", args.idx));
                    return;
                }
                let wait = retry_after.unwrap_or_else(|| backoff_for_attempt(attempt));
                let deadline = Instant::now() + wait;
                while Instant::now() < deadline {
                    if args.cancel.load(Ordering::SeqCst) || args.pause.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

/// 池里「实测最快的来源」。
///
/// 先按来源评分排序取头名（`order_by_score` 就是"实测"那一套：24 小时窗口、Wilson 下界、
/// 速度/稳定/响应三项加权）；评分还没攒够（不足 20 条记录）时它保持原有顺序，
/// 那就**退回轮换下一个** —— 关键是必须换掉当前这个，否则等于没换。
///
/// 返回 `None` 只在连"下一个"都拿不到时发生（来源表为空）。
fn fastest_source(args: &SegmentArgs) -> Option<String> {
    let ordered = crate::source_registry::order_by_score(&args.sources, args.expected_total);
    if let Some(first) = ordered.first() {
        if first != &args.url {
            return Some(first.clone());
        }
    }
    aidm_core::segment::next_source(Some(&args.url), &args.sources)
}

/// 把一个分段换到新来源，并按 R-DL-13 / R-DL-14 留痕。
///
/// 三件事缺一不可：清掉旧地址的校验器（换了来源，`ETag`/`Last-Modified` 不再适用）、
/// 把新来源写进该段（同一段同一时刻只用一个来源，禁止段内混源）、
/// 记 `segment_src_switch idx=… from=… to=… reason=slow`。
/// 段级失败 → 候选状态分类。只归类“源的问题”，本机磁盘/权限错误不动候选。
fn classify_segment_source(args: &SegmentArgs, code: &str) {
    let cls = error::classify(code);
    let state = if matches!(
        cls.code.as_str(),
        error::CODE_HTTP_401 | error::CODE_HTTP_403 | error::CODE_HTTP_404 | "http_410"
    ) {
        "rejected"
    } else if matches!(
        cls.code.as_str(),
        error::CODE_NETWORK | error::CODE_HTTP_5XX | error::CODE_REMOTE_CHANGED
    ) {
        "suspended"
    } else {
        return;
    };
    let conn = args.db.lock().unwrap();
    if let Ok(rows) = model::list_source_candidates(&conn, args.id, None) {
        if let Some(r) = rows.iter().find(|r| r.url == args.url) {
            let _ = model::set_source_candidate_state(&conn, r.id, state);
        }
    }
    model::log_event(
        &conn,
        args.id,
        "source_suspend",
        Some(&format!(
            "seg={} state={state} reason={}",
            args.idx, cls.code
        )),
    );
}

fn switch_segment_source(
    args: &mut SegmentArgs,
    target: String,
    reason: aidm_core::pace::SlowReason,
    attempt: u32,
) {
    let from = std::mem::replace(&mut args.url, target);
    args.src_version = args.source_versions.get(&args.url).cloned();
    args.etag = args
        .src_version
        .as_deref()
        .and_then(|v| v.strip_prefix("etag:"))
        .map(str::to_string);
    args.last_modified = args
        .src_version
        .as_deref()
        .and_then(|v| v.strip_prefix("lm:"))
        .map(str::to_string);
    let conn = args.db.lock().unwrap();
    let _ = model::set_segment_src(&conn, args.id, args.idx, Some(args.url.as_str()));
    let _ = model::set_segment_src_version(&conn, args.id, args.idx, args.src_version.as_deref());
    model::log_event(
        &conn,
        args.id,
        "segment_src_switch",
        Some(&format!(
            "idx={} attempt={attempt} from={} to={} reason={}",
            args.idx,
            aidm_core::redact::redact_url(&from),
            aidm_core::redact::redact_url(&args.url),
            reason.as_str()
        )),
    );
    tracing::info!(
        event = "segment.src_switch",
        phase = "transfer",
        seg = args.idx,
        attempt,
        reason = reason.as_str(),
        from = %aidm_core::redact::redact_url(&from),
        to = %aidm_core::redact::redact_url(&args.url),
    );
}

fn persist_seg(args: &SegmentArgs, done: u64, status: &str) {
    let conn = args.db.lock().unwrap();
    let _ = model::set_segment_state(&conn, args.id, args.idx, done as i64, status);
}

fn segment_fail_is_fatal(code: &str) -> bool {
    let c = error::classify(code);
    match c.code.as_str() {
        error::CODE_REMOTE_CHANGED
        | error::CODE_DISK_FULL
        | error::CODE_NO_PERMISSION
        | error::CODE_HTTP_401
        | error::CODE_HTTP_403
        | error::CODE_HTTP_404 => true,
        error::CODE_HTTP_4XX => !matches!(c.http_status, Some(408 | 429)),
        _ => false,
    }
}

enum SegOnce {
    Done,
    Paused,
    Cancelled,
    /// 本次尝试被段级「持续慢」判定中止（`alt.measure_window_s` > 0 且窗口不达标）。
    ///
    /// 与 `Failed` 的区别是它**不是失败**：不消耗失败重试预算、不计入来源成功率。
    Slow(aidm_core::pace::SlowReason),
    Failed(String, Option<Duration>),
}

fn try_segment_once(args: &SegmentArgs, done: &mut u64, expected: u64) -> SegOnce {
    if *done >= expected {
        return SegOnce::Done;
    }
    // 段级「持续慢」观察窗：`alt.measure_window_s == 0`（默认）时是 `None` = 完全不观察，
    // 这一段的行为与从前逐字节一致。计时从**本次尝试开始**（含建连）算起：
    // "连上了却一个字节都收不到"同样是慢，而且是更该换源的那种慢。
    let t_try = Instant::now();
    let mut slow_gate = aidm_core::pace::SlowGate::new(args.measure_window_s, args.measure_min_bps);
    if let Some(parent) = args.part_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return SegOnce::Failed(io_fail_string(args.io_fault, e, "mkdir"), None);
        }
    }
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&args.part_path)
    {
        Ok(f) => f,
        Err(e) => return SegOnce::Failed(io_fail_string(args.io_fault, e, "open part"), None),
    };
    if let Ok(meta) = file.metadata() {
        let len = meta.len();
        if len != *done {
            *done = len.min(expected);
        }
    }
    if let Err(e) = file.seek(SeekFrom::Start(*done)) {
        return SegOnce::Failed(io_fail_string(args.io_fault, e, "seek"), None);
    }
    if let Err(e) = file.set_len(*done) {
        return SegOnce::Failed(io_fail_string(args.io_fault, e, "truncate"), None);
    }

    let req_start = args.pos_start + *done;
    let req_end = args.pos_end;
    {
        let conn = args.db.lock().unwrap();
        let _ = model::set_segment_state(&conn, args.id, args.idx, *done as i64, "running");
    }

    let req = apply_common(
        args.http.agent_for(&args.url).get(&args.url),
        &args.profile,
        &args.url,
        args.referer.as_deref(),
        args.cookies.as_deref(),
        &args.custom_headers,
    )
    .set("Range", &format!("bytes={req_start}-{req_end}"));
    let resp = match req.call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, resp)) if code == 429 || code == 503 => {
            let ra = header_owned(&resp, "retry-after");
            let wait = ra.as_deref().and_then(parse_retry_after);
            return SegOnce::Failed(format!("http_{code}"), wait);
        }
        Err(ureq::Error::Status(code, _)) => {
            return SegOnce::Failed(format!("http_{code}"), None);
        }
        Err(e) => return SegOnce::Failed(format!("connect: {e}"), None),
    };

    let status = resp.status();
    if status == 200 && req_start > 0 {
        return SegOnce::Failed("range_ignored".into(), None);
    }
    if status != 206 && status != 200 {
        return SegOnce::Failed(format!("http_{status}"), None);
    }
    let resp_etag = header_owned(&resp, "etag");
    let resp_lm = header_owned(&resp, "last-modified");
    if validators_changed(
        args.etag.as_deref(),
        args.last_modified.as_deref(),
        resp_etag.as_deref(),
        resp_lm.as_deref(),
    ) {
        return SegOnce::Failed(error::CODE_REMOTE_CHANGED.into(), None);
    }
    if let Some(cr) = header_owned(&resp, "content-range").as_deref() {
        if let Some(parsed) = segment::parse_content_range(cr) {
            if let Some(remote_total) = parsed.total {
                if remote_total != args.expected_total {
                    return SegOnce::Failed(error::CODE_REMOTE_CHANGED.into(), None);
                }
            }
        }
    }

    let _http_conn = acquire_conn(&args.active_conns);
    let mut reader = resp.into_reader();
    let mut buf = vec![0u8; READ_BUF];
    let mut last_persist = Instant::now();
    let remaining_total = expected.saturating_sub(*done);

    let mut got = 0u64;
    while got < remaining_total {
        if args.cancel.load(Ordering::SeqCst) {
            persist_seg(args, *done, "pending");
            return SegOnce::Cancelled;
        }
        if args.pause.load(Ordering::SeqCst) {
            persist_seg(args, *done, "pending");
            return SegOnce::Paused;
        }
        if args.fail.lock().unwrap().is_some() {
            persist_seg(args, *done, "pending");
            return SegOnce::Paused;
        }
        let want = ((remaining_total - got) as usize).min(buf.len());
        let read_res = match injected_read_fault(args.io_fault) {
            Some(e) => Err(e),
            None => reader.read(&mut buf[..want]),
        };
        let n = match read_res {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                persist_seg(args, *done, "pending");
                return SegOnce::Failed(
                    format!("{}transfer: read: {e}", error::PHASE_PREFIX),
                    None,
                );
            }
        };
        // 真实写盘前的许可检查——这是唯一的写盘拦截点。
        //
        // 票据只覆盖**这一次写**（一块屏缓冲），所以暂停的静止等待是毫秒级；
        // 反过来，若把票据挂在整次尝试上，撤销就必须等一个完整的网络往返。
        // 许可失效时按暂停处理：它不是失败，不能消耗失败重试预算。
        let _ticket = match (&args.gate, &args.lease) {
            (Some(gate), Some(lease)) => {
                let at = args.pos_start + *done;
                match gate.check(lease, at, at + n as u64) {
                    Ok(t) => Some(t),
                    Err(decision) => {
                        args.live
                            .last_write_denied
                            .store(1, Ordering::Relaxed);
                        let _ = decision;
                        persist_seg(args, *done, "pending");
                        return SegOnce::Paused;
                    }
                }
            }
            // 没有闸门（老夹具/不写盘路径）：直接写入，不做许可校验。
            _ => None,
        };
        if let Err(e) = write_all_checked(&mut file, &buf[..n], args.io_fault) {
            return SegOnce::Failed(e, None);
        }
        *done += n as u64;
        got += n as u64;
        args.speed_window.add(n as u64);
        args.live.done_bytes.fetch_add(n as u64, Ordering::Relaxed);
        let sp = args.speed_window.bytes_per_sec();
        args.live.speed_bps.store(sp, Ordering::Relaxed);
        if let Some(cb) = &args.progress_cb {
            cb(Progress {
                id: args.id,
                done_bytes: args.live.done_bytes.load(Ordering::Relaxed),
                total: Some(args.total),
                speed_bps: sp,
            });
        }
        if last_persist.elapsed() >= PERSIST_INTERVAL {
            persist_seg(args, *done, "running");
            last_persist = Instant::now();
        }
        args.limiter.take(n as u64);
        args.limit.take(n as u64);

        // R-DL-14：窗口内速率低于「已完成分段的平均速率」（或低于绝对下限）就该换源。
        // 判定本身只做算术（`aidm_core::pace`），这里只负责把"中止本次尝试"表达出来。
        if let Some(gate) = slow_gate.as_mut() {
            if let aidm_core::pace::Pace::Switch(reason) =
                gate.observe(t_try.elapsed(), got, args.done_pace.avg_bps())
            {
                persist_seg(args, *done, "pending");
                return SegOnce::Slow(reason);
            }
        }
    }

    if *done >= expected {
        SegOnce::Done
    } else {
        persist_seg(args, *done, "pending");
        SegOnce::Failed("short_body".into(), None)
    }
}

impl Ctx<'_> {
    /// 是否已经带了 `Authorization`（用户自定义头里也可能有）。
    fn has_authorization(&self) -> bool {
        self.custom_headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("authorization"))
    }
}

/// 按目标主机查站点凭据，并按 401 挑战生成 `Authorization`。
///
/// 有可用 Digest 挑战就用 Digest；只有服务端提供 Basic（或根本没给挑战头）时才发
/// Basic，避免把明文口令发给只接受其他方案的服务器。只返回头本身，不返回凭据内容。
fn credential_header(
    ctx: &Ctx<'_>,
    url: &str,
    challenges: &[String],
) -> Option<aidm_core::headers::HeaderLine> {
    use aidm_core::http_auth;
    let host = aidm_core::logins::normalize_host(&aidm_core::sched::url_host(url));
    let login = {
        let conn = ctx.args.db.lock().unwrap();
        aidm_core::logins::lookup(&conn, &host).ok().flatten()?
    };
    if login.password.is_empty() {
        return None;
    }
    let parsed = http_auth::parse_challenges(challenges);
    let value = if let Some(d) = http_auth::best_digest(&parsed) {
        // 分段请求复用同一个应答（nc 固定为 1）：多数服务器（如 Apache 默认
        // `AuthDigestNcCheck Off`）接受；严格校验 nonce-count 的服务器会在分段时再回 401。
        let u = url::Url::parse(url).ok()?;
        let target = match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        };
        http_auth::digest_authorization(
            d,
            &login.username,
            &login.password,
            "GET",
            &target,
            &http_auth::random_cnonce(),
            1,
        )?
    } else if parsed.is_empty() || http_auth::offers_basic(&parsed) {
        aidm_core::logins::basic_authorization(&login.username, &login.password)
    } else {
        return None;
    };
    Some(aidm_core::headers::HeaderLine {
        name: "Authorization".into(),
        value,
    })
}

fn auth_challenge_kind(challenges: &[String]) -> &'static str {
    use aidm_core::http_auth;
    let parsed = http_auth::parse_challenges(challenges);
    if http_auth::best_digest(&parsed).is_some() {
        "scheme=digest"
    } else if http_auth::offers_basic(&parsed) {
        "scheme=basic"
    } else if parsed.is_empty() {
        "scheme=none"
    } else {
        "scheme=unsupported"
    }
}

/// PyPI 元数据 JSON 的正文上限。一个包的 JSON 含每个文件的记录，通常几十 KB；
/// 设上限是为了防止对面回一个大文件时把任务卡在"读满再放弃"。
const PYPI_MAX_BODY: u64 = 1024 * 1024;

/// 把 `pip:name==ver` 解析成真实文件地址（查一次 PyPI 的 JSON 接口）。
///
/// **为什么必须联网**：PyPI 的下载路径含哈希目录（`packages/ab/cd/<hash>/…`），
/// 哈希是上传时算的，无法从包名与版本构造出来。这与 npm/cargo 有本质区别 ——
/// 那两个是纯字符串换算，所以它们在 `add_spec` 阶段就完成了。
///
/// **为什么放在执行期而不是建任务时**：建任务不该因为一次外部查询而变慢，
/// 也不该在 PyPI 抖动时失败；而且地址会随版本重新上传而变，缓存一份反而是负担。
fn resolve_pypi_target(args: &Args, row: &DownloadRow) -> Result<(String, String), String> {
    // 基地址可配：镜像（国内直连官方源很慢）与**可测试性**（让端到端测试能指向
    // 本地 stub，而不是只能联网跑）。
    let api_base = {
        let conn = args.db.lock().unwrap();
        settings::get(&conn, "devtools.pypi_api_base")
            .ok()
            .flatten()
            .unwrap_or_default()
    };
    let lookup = aidm_core::devtools::resolve_pip_with(&row.url_orig, &api_base)
        .map_err(|e| e.code().to_string())?;
    let profile = {
        let conn = args.db.lock().unwrap();
        aidm_core::http_profile::RequestProfile::from_conn(&conn)
            .with_browser_user_agent(args.browser_user_agent.as_deref())
    };
    let custom_headers = args
        .custom_headers
        .as_deref()
        .map(aidm_core::headers::parse_custom_headers)
        .transpose()
        .ok()
        .flatten()
        .unwrap_or_default();
    let call = crate::http_util::apply_common(
        args.http.agent_for(&lookup.api_url).get(&lookup.api_url),
        &profile,
        &lookup.api_url,
        args.referer.as_deref(),
        args.cookies.as_deref(),
        &custom_headers,
    )
    .call();
    // 404 是"这个版本不存在"，与"PyPI 出错"要分开 —— 前者用户改版本即可，
    // 后者重试才有意义。
    //
    // **必须在 `Err` 分支里分辨状态码**：ureq 把 >=400 一律作为
    // `Err(Error::Status(code, _))` 抛出，成功的 `Response` 只可能是 2xx/3xx。
    // 只看 `resp.status()` 的话，404 会先在 `.call()` 处变成一条笼统的
    // `pypi_lookup: …`，这个区分永远走不到（这个坑踩过一次）。
    let resp = match call {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => return Err("pypi_version_not_found".into()),
        Err(ureq::Error::Status(s, _)) => return Err(format!("pypi_status_{s}")),
        Err(e) => return Err(format!("pypi_lookup: {e}")),
    };
    let mut raw = Vec::new();
    resp.into_reader()
        .take(PYPI_MAX_BODY)
        .read_to_end(&mut raw)
        .map_err(|e| format!("pypi_read: {e}"))?;
    aidm_core::devtools::pick_pypi_file(&String::from_utf8_lossy(&raw))
        .ok_or_else(|| "pypi_no_files".to_string())
}

/// 清单型媒体：HLS（`.m3u8`）与 MPEG-DASH（`.mpd`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestKind {
    Hls,
    Dash,
}

impl ManifestKind {
    fn as_str(self) -> &'static str {
        match self {
            ManifestKind::Hls => "hls",
            ManifestKind::Dash => "dash",
        }
    }
}

/// 从地址判断是不是清单型媒体。
///
/// 只看路径后缀（忽略 query/fragment）。**不猜内容类型**：把一份普通文件当清单解析
/// 会得到"没有分片"的失败，而这里返回 `None` 时会走普通 HTTP 路径、反而能下下来。
fn manifest_kind(raw: &str) -> Option<ManifestKind> {
    let path = raw
        .split(['?', '#'])
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase();
    if path.ends_with(".m3u8") {
        Some(ManifestKind::Hls)
    } else if path.ends_with(".mpd") {
        Some(ManifestKind::Dash)
    } else {
        None
    }
}

/// 清单正文上限。真实清单是文本：HLS 每片一行、DASH 只描述模板，都远小于这个值。
/// 设上限是为了防止对面回一个大文件时把任务卡在"读满再放弃"。
const MANIFEST_MAX_BODY: u64 = 4 * 1024 * 1024;

/// 主清单最多再取几层。HLS 的主→媒体是正常的一层；再多就是在套娃，直接停。
const MANIFEST_MAX_HOPS: usize = 4;

/// 清单型媒体的侧车进度。
///
/// **为什么要它**：分片是一个个独立文件，续传的粒度只能是"第几个分片"。
/// 目标文件用追加写（不落地分片副本，省一份等量磁盘），所以"已写到哪"必须记下来。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ManifestState {
    kind: String,
    /// 清单地址。**换过清单就不能续**：分片列表可能完全不同。
    source: String,
    /// 下载项总数与已完成数。
    items: usize,
    done: usize,
    /// 已写入目标文件的字节数。
    bytes: u64,
}

fn manifest_state_path(dir: &Path, id: i64) -> std::path::PathBuf {
    dir.join(".aidm").join(id.to_string()).join("manifest.json")
}

/// 清单型任务的**工作文件**（不是最终文件）。
///
/// 为什么不能直接写最终名：清单分片是一个个独立资源，"下到一半"是常态（分片 404、
/// 取消、断网）。若直接写 `保存目录/<文件名>`，失败后用户会看到一个与成品同名同形的
/// 半截文件 —— 分不出它是不是下完了。这与引擎其余路径的约定也不一致（分段与工作文件
/// 一律在 `<保存目录>/.aidm/<任务id>/`，只有合并成功才产出最终文件，见
/// `docs/guides/08-build-artifacts.md` R-ART-12 与专项 PROJ-TPL-009）。
///
/// 前缀加点是为了让它在 `.aidm/<id>/` 里一眼看出是"临时工作文件"，不与 `manifest.json`
/// 侧车混在同一个命名空间。
fn manifest_part_path(dir: &Path, id: i64, file_name: &str) -> std::path::PathBuf {
    dir.join(".aidm")
        .join(id.to_string())
        .join(format!(".{file_name}.manifest.part"))
}

fn load_manifest_state(dir: &Path, id: i64) -> Option<ManifestState> {
    let raw = std::fs::read_to_string(manifest_state_path(dir, id)).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_manifest_state(dir: &Path, id: i64, st: &ManifestState) -> std::io::Result<()> {
    let path = manifest_state_path(dir, id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec(st).map_err(std::io::Error::other)?;
    // 先写临时文件再改名：中途断电不会留下半截 JSON 让续传读出垃圾。
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, &path)
}

/// 取一份文本资源（清单）。只接受 200；超过上限直接放弃而不是读满。
fn fetch_manifest_text(ctx: &Ctx<'_>, url: &str) -> Result<String, String> {
    let resp = crate::http_util::apply_common(
        ctx.args.http.agent_for(url).get(url),
        &ctx.profile,
        url,
        ctx.args.referer.as_deref(),
        ctx.cookies.as_deref(),
        &ctx.custom_headers,
    )
    .call()
    .map_err(|e| format!("manifest_fetch: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("manifest_status_{}", resp.status()));
    }
    if crate::http_util::header_owned(&resp, "content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > MANIFEST_MAX_BODY)
    {
        return Err("manifest_too_large".into());
    }
    let mut raw = Vec::new();
    resp.into_reader()
        .take(MANIFEST_MAX_BODY)
        .read_to_end(&mut raw)
        .map_err(|e| format!("manifest_read: {e}"))?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// 把一份清单解析成**有序下载项**。
///
/// HLS 的主清单会再往下取一层（选码率最高那个变体），最多 [`MANIFEST_MAX_HOPS`] 层。
/// 返回 `(下载项, 实际生效的清单地址)`。
fn manifest_items(
    ctx: &Ctx<'_>,
    kind: ManifestKind,
    start_url: &str,
) -> Result<(Vec<String>, String), String> {
    let mut url = start_url.to_string();
    for _ in 0..MANIFEST_MAX_HOPS {
        let text = fetch_manifest_text(ctx, &url)?;
        match kind {
            ManifestKind::Hls => {
                let p = aidm_core::hls::parse(&url, &text);
                if p.is_master() {
                    // 主清单本身不是媒体：挑码率最高的变体再取一层。
                    let v = p
                        .best_variant()
                        .ok_or_else(|| "hls_master_without_variant".to_string())?;
                    url = v.uri.clone();
                    continue;
                }
                if let Some(r) = p.reject_reason() {
                    return Err(r.to_string());
                }
                let items: Vec<String> = p.segments.iter().map(|s| s.uri.clone()).collect();
                return Ok((items, url));
            }
            ManifestKind::Dash => {
                let m = aidm_core::dash::parse(&url, &text)
                    .ok_or_else(|| "dash_parse_failed".to_string())?;
                if let Some(r) = m.reject_reason() {
                    return Err(r.to_string());
                }
                let rep = m
                    .best_representation()
                    .ok_or_else(|| "dash_no_representations".to_string())?;
                let items = rep.download_items(&url);
                if items.is_empty() {
                    return Err("dash_no_segments".into());
                }
                return Ok((items, url));
            }
        }
    }
    Err("hls_too_many_hops".into())
}

/// HLS / DASH 任务的执行路径。
///
/// 与 HTTP 路径的区别：**分片是各自独立的资源**，没有跨分片的 Range 语义，
/// 所以不能复用 fastdl 的分段内核。这里顺序取回并**追加写**进目标文件，
/// 进度按"第几片"记在侧车里，续传从下一片接着写。
///
/// 顺序而非并发：分片本身很小，而并发取回需要按序缓冲（否则拼出来的顺序是乱的），
/// 那块复杂度换不来多少收益；真正的带宽瓶颈在单片的服务端，不在并发度。
/// 带上阶段标记的失败（`phase=<阶段>: <原因>`）。
///
/// 为什么要有这个函数：规格 R-OBS-01/10 要求"产生失败的那一行"带阶段标记，而标记
/// **必须前置**（`error::strip_phase_marker` 只认开头的 `phase=`），`classify` 会先
/// 剥掉它再分类 —— 所以机器码与退避判定都不受影响。逐处手写字符串容易漏掉一个，
/// 漏掉就等于那个失败没有阶段归因。
fn fail(phase: aidm_core::error::Phase, reason: impl std::fmt::Display) -> WorkerEnd {
    WorkerEnd::Failed(format!("phase={}: {reason}", phase.as_str()))
}

/// 记一条**分片级**失败事件：地址先脱敏，原因也过一遍脱敏。
///
/// 存在的理由：分片失败时机器码只保留 HTTP 族（见调用点），"是哪一片、什么原因"
/// 就只剩这一个落点。不写这条，失败现场就只剩一个 `http_404`。
fn log_segment_failure(args: &Args, id: i64, seg_url: &str, reason: &str) {
    let conn = args.db.lock().unwrap();
    model::log_event(
        &conn,
        id,
        "manifest",
        Some(&format!(
            "segment_failed url={} reason={}",
            aidm_core::redact::redact_url(seg_url),
            aidm_core::redact::redact_text(reason)
        )),
    );
}

/// zsync 控制文件的体积上限。
///
/// 块表大小 ≈ 块数 × (rsum_bytes + checksum_bytes)：4 GiB 的文件在 2048 字节块下约
/// 200 万块、默认 20 字节/块 ≈ 40 MiB。所以给到 64 MiB。设上限不是为了省事，而是因为
/// 这份数据在**任何校验发生之前**就要进内存，且块数是由响应自己声称的。
const ZSYNC_MAX_CONTROL: u64 = 64 * 1024 * 1024;

/// 去掉 `?query` 与 `#fragment`（判断后缀与派生内容地址时只看路径）。
fn url_without_query(raw: &str) -> &str {
    raw.split(['?', '#']).next().unwrap_or(raw)
}

/// 名字以 `.zsync` 结尾时返回其**字节长度**（大小写不敏感）。
///
/// 返回长度而不是切片，是为了让调用方自己切原串：`to_ascii_lowercase()` 对非 ASCII
/// 可能改变字节长度，用它的长度去切原串会切坏。
fn zsync_suffix_len(name: &str) -> Option<usize> {
    const SUFFIX: &str = ".zsync";
    let lower = name.to_ascii_lowercase();
    lower.ends_with(SUFFIX).then(|| name.len() - SUFFIX.len())
}

/// 内容地址：优先用控制文件里声明的 `URL:`，没有就从 `.zsync` 地址去掉后缀推。
///
/// 只用 `http(s)` 的声明值：控制文件是外部输入，里面塞一个 `file:///` 或别的 scheme
/// 不该让我们去读本机文件。
fn zsync_content_url(control: &aidm_core::zsync::ZsyncControl, zsync_url: &str) -> Option<String> {
    if let Some(u) = control.urls.iter().find(|u| aidm_core::alt::is_http_url(u)) {
        return Some(u.clone());
    }
    let bare = url_without_query(zsync_url);
    let n = zsync_suffix_len(bare)?;
    Some(bare[..n].to_string())
}

/// 取回控制文件（二进制，带上限）。只接受 200。
fn fetch_zsync_control(ctx: &Ctx<'_>, url: &str) -> Result<Vec<u8>, String> {
    let resp = crate::http_util::apply_common(
        ctx.args.http.agent_for(url).get(url),
        &ctx.profile,
        url,
        ctx.args.referer.as_deref(),
        ctx.cookies.as_deref(),
        &ctx.custom_headers,
    )
    .call();
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(s, _)) => {
            return Err(aidm_core::error::http_code_for_status(s).to_string())
        }
        Err(e) => {
            // 与分片失败同样的理由：ureq 的 Display 内嵌完整 URL（含查询串），
            // 不能把它当机器码落库。细节交给事件。
            log::warn!("zsync 控制文件取回失败: {e}");
            return Err(aidm_core::error::CODE_NETWORK.to_string());
        }
    };
    if resp.status() != 200 {
        return Err(aidm_core::error::http_code_for_status(resp.status()).to_string());
    }
    if crate::http_util::header_owned(&resp, "content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > ZSYNC_MAX_CONTROL)
    {
        return Err("zsync_control_too_large".into());
    }
    let mut raw = Vec::new();
    if let Err(e) = resp
        .into_reader()
        .take(ZSYNC_MAX_CONTROL)
        .read_to_end(&mut raw)
    {
        // 机器码保持**裸码**：带详情的 `zsync_x: <err>` 会被 `classify` 整串当成机器码
        // （前缀族命中后就原样返回），落进 `error_code` 列。细节走进程日志。
        log::warn!("zsync 控制文件读取失败: {e}");
        return Err("zsync_fetch_read".into());
    }
    Ok(raw)
}

/// 整文件 SHA-1（十六进制小写）。用 `ring` —— 项目既有依赖，不另引 sha1 crate。
fn sha1_file(path: &Path) -> std::io::Result<String> {
    use ring::digest;
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(ctx
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// zsync 增量更新：控制文件 → 缺失块 → 只取缺失区间 → 整文件校验 → 改名成最终文件。
///
/// # 为什么先写工作文件而不是就地改种子
///
/// 种子里是**用户的最终文件**。就地打补丁的话，中途失败/断电就把用户的文件改成了一个
/// 半新半旧的混合物（而且没有任何标记能看出它坏了）。所以：种子只读，工作文件在
/// `<保存目录>/.aidm/<任务id>/` 下，全部块齐全且整文件校验通过才 `rename` 成最终文件
/// （与分段路径、清单路径同一约定，见专项 PROJ-TPL-009）。
///
/// 续传不需要侧车：工作文件本身就是进度，下一次进来重新按块比对即可算出还剩哪些区间。
fn zsync_task(args: &Args, row: &DownloadRow, dir: &Path) -> WorkerEnd {
    use aidm_core::error::Phase;

    let id = args.id;
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(Phase::Store, format!("mkdir: {e}"));
    }
    let ctx = Ctx {
        args,
        profile: {
            let conn = args.db.lock().unwrap();
            aidm_core::http_profile::RequestProfile::from_conn(&conn)
                .with_browser_user_agent(args.browser_user_agent.as_deref())
        },
        custom_headers: args
            .custom_headers
            .as_deref()
            .map(aidm_core::headers::parse_custom_headers)
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default(),
        cookies: args.cookies.clone(),
    };

    // ---- 1. 取回并解析控制文件（失败都在 resolve 阶段）----
    let raw = match fetch_zsync_control(&ctx, &row.url_orig) {
        Ok(v) => v,
        Err(code) => return fail(Phase::Resolve, code),
    };
    let control = match aidm_core::zsync::ZsyncControl::parse(raw.as_slice()) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("task {id}: zsync 控制文件不可用: {:?}", e);
            return fail(Phase::Resolve, e.code());
        }
    };
    let Some(content_url) = zsync_content_url(&control, &row.url_orig) else {
        return fail(Phase::Resolve, "zsync_no_content_url");
    };

    // ---- 2. 内容名：任务名去掉 `.zsync` ----
    // 只在名字**确实以 `.zsync` 结尾**时改写：用户显式 `rename` 过的名字不能被探测覆盖
    // （`set_probe_meta` 的注释里写着同一条约束）。
    let mut name = target_file_name(args, &row.file_name);
    if let Some(n) = zsync_suffix_len(&name) {
        let stripped = name[..n].to_string();
        if !stripped.is_empty() {
            {
                let conn = args.db.lock().unwrap();
                let _ = model::set_file_name(&conn, id, &stripped);
            }
            name = stripped;
        }
    }
    let save_path = dir.join(&name);
    let part_path = dir
        .join(".aidm")
        .join(id.to_string())
        .join(format!(".{name}.zsync.part"));
    if let Some(parent) = part_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return fail(Phase::Store, format!("mkdir: {e}"));
        }
    }

    // ---- 3. 工作文件：有种子就拷贝一份当底稿，否则建一个定长空文件 ----
    if !part_path.exists() {
        let seeded = save_path.exists();
        if seeded {
            if let Err(e) = std::fs::copy(&save_path, &part_path) {
                return fail(Phase::Store, format!("seed_copy: {e}"));
            }
        } else {
            match std::fs::File::create(&part_path) {
                Ok(f) => {
                    if let Err(e) = f.set_len(control.length) {
                        return fail(Phase::Store, format!("create: {e}"));
                    }
                }
                Err(e) => return fail(Phase::Store, format!("create: {e}")),
            }
        }
        log::info!("task {id}: zsync 工作文件已就绪（seeded={seeded}）");
    }
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&part_path)
    {
        Ok(f) => f,
        Err(e) => return fail(Phase::Store, format!("open: {e}")),
    };

    // ---- 4. 算出还缺哪些区间（进度就在工作文件里，不需要侧车）----
    let missing = match control.missing_ranges_reader(&file) {
        Ok(v) => v,
        Err(e) => return fail(Phase::Store, format!("scan: {e}")),
    };
    let missing_bytes: u64 = missing.iter().map(|r| r.end - r.start).sum();
    {
        let conn = args.db.lock().unwrap();
        model::log_event(
            &conn,
            id,
            "zsync",
            Some(&format!(
                "blocks={} blocksize={} length={} missing_ranges={} missing_bytes={} url={}",
                control.blocks.len(),
                control.blocksize,
                control.length,
                missing.len(),
                missing_bytes,
                aidm_core::redact::redact_url(&content_url)
            )),
        );
    }
    if missing.is_empty() {
        log::info!("task {id}: 本地内容已满足全部块，无需取回");
    }

    // zsync 的取回也是真实写盘入口，必须持写入许可。
    // 总长来自控制文件（`control.length`），区间覆盖整个工作文件。
    let zsync_span = Span::known(0, control.length.max(1))
        .unwrap_or_else(|| Span::open(0));
    let zsync_lease = args.gate.as_ref().map(|gate| {
        gate.issue(
            AssignmentId::new(format!("zsync:{id}")),
            SliceId::new(format!("zsync:{id}")),
            zsync_span,
        )
    });
    let _zsync_reaper = match (&args.gate, &zsync_lease) {
        (Some(gate), Some(lease)) => Some(gate.reaper(lease)),
        _ => None,
    };

    // ---- 5. 逐段取回（段间给取消/暂停留响应点）----
    for range in &missing {
        if args.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return WorkerEnd::Cancelled;
        }
        if args.pause.load(std::sync::atomic::Ordering::SeqCst) {
            return WorkerEnd::Paused;
        }
        let want = format!("bytes={}-{}", range.start, range.end - 1);
        let resp = crate::http_util::apply_common(
            ctx.args.http.agent_for(&content_url).get(&content_url),
            &ctx.profile,
            &content_url,
            ctx.args.referer.as_deref(),
            ctx.cookies.as_deref(),
            &ctx.custom_headers,
        )
        .set("Range", &want)
        .call();
        let resp = match resp {
            // 只有 206 才能确认服务器真的按区间给了字节。200 意味着它把**整份**内容
            // 发过来了：照单接收会让我们把第 0 段之后的偏移全写错，所以宁可明确失败。
            Ok(r) if r.status() == 206 => r,
            Ok(r) => {
                let code = aidm_core::error::http_code_for_status(r.status());
                log_segment_failure(args, id, &content_url, &format!("status={}", r.status()));
                return fail(Phase::Transfer, code);
            }
            Err(ureq::Error::Status(s, _)) => {
                log_segment_failure(args, id, &content_url, &format!("status={s}"));
                return fail(Phase::Transfer, aidm_core::error::http_code_for_status(s));
            }
            Err(e) => {
                log_segment_failure(args, id, &content_url, &e.to_string());
                return fail(Phase::Transfer, aidm_core::error::CODE_NETWORK);
            }
        };
        let mut reader = resp.into_reader();
        if let Err(e) = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(range.start)) {
            return fail(Phase::Store, format!("seek: {e}"));
        }
        let mut buf = vec![0u8; READ_BUF];
        let mut left = range.end - range.start;
        while left > 0 {
            let want_n = (left as usize).min(buf.len());
            match reader.read(&mut buf[..want_n]) {
                Ok(0) => {
                    // 服务器给到一半就断了：这一段的剩余部分没写全，任务失败。
                    return fail(Phase::Transfer, "zsync_short_range");
                }
                Ok(n) => {
                    // 写盘许可：票据只覆盖这一块。
                    let at = range.end - left;
                    match (&args.gate, &zsync_lease) {
                        (Some(gate), Some(lease)) => {
                            if gate.check(lease, at, at + n as u64).is_err() {
                                // zsync 的进度靠块校验和重扫恢复，不需要额外持久化；
                                // 但状态与事件必须落，否则任务会停在 Downloading。
                                pause_on_lease_revoked(args, "zsync");
                                return WorkerEnd::Paused;
                            }
                        }
                        _ => {}
                    }
                    if let Err(e) = write_all_checked(&mut file, &buf[..n], args.io_fault) {
                        return fail(Phase::Store, e);
                    }
                    left -= n as u64;
                }
                Err(e) => {
                    // 同上：机器码保持裸码，细节走进程日志。
                    log::warn!("task {id}: zsync 分片读取失败: {e}");
                    return fail(Phase::Transfer, "zsync_read");
                }
            }
        }
    }
    if let Err(e) = file.sync_all() {
        return fail(Phase::Store, format!("fsync: {e}"));
    }

    // ---- 6. 整文件校验 ----
    // 底线是"控制文件里的每一块都必须在本地对得上"：块校验和本身就是按块给的，
    // 全部对上是**内容健全**的直接证据（不强于块校验和的强度，这一点写在文档里）。
    let present = match control.present_blocks_reader(&file) {
        Ok(v) => v,
        Err(e) => return fail(Phase::Verify, format!("rescan: {e}")),
    };
    if present.len() != control.blocks.len() {
        log::warn!(
            "task {id}: zsync 结束后仍有 {}/{} 块对不上",
            control.blocks.len() - present.len(),
            control.blocks.len()
        );
        return fail(Phase::Verify, "zsync_incomplete");
    }
    // 上游声明了整文件 SHA-1 就更比一层（比块校验和强得多）。
    if let Some(want) = control.sha1.as_deref() {
        match sha1_file(&part_path) {
            Ok(got) if got.eq_ignore_ascii_case(want) => {}
            Ok(got) => {
                log::warn!("task {id}: zsync SHA-1 不符 expected={want} got={got}");
                return fail(Phase::Verify, "zsync_sha1_mismatch");
            }
            Err(e) => return fail(Phase::Verify, format!("sha1: {e}")),
        }
    }
    drop(file);

    // ---- 7. 改名成最终文件 ----
    if let Err(e) = std::fs::rename(&part_path, &save_path) {
        return fail(Phase::Store, format!("rename: {e}"));
    }
    finish_single(args, row, &save_path, control.length)
}

fn manifest_task(args: &Args, row: &DownloadRow, dir: &Path, kind: ManifestKind) -> WorkerEnd {
    let id = args.id;
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(aidm_core::error::Phase::Store, format!("mkdir: {e}"));
    }
    let file_name = target_file_name(args, &row.file_name);
    let save_path = dir.join(&file_name);
    // 先写工作文件，全部下完再改名成最终文件（见 `manifest_part_path`）。
    let part_path = manifest_part_path(dir, id, &file_name);
    // 工作文件在 `.aidm/<id>/` 下，这个目录原本是侧车落盘时才建的（`save_manifest_state`），
    // 而侧车是在**文件建好之后**才写 —— 不在这里先建，`create` 会以 "找不到指定的路径" 失败。
    if let Some(parent) = part_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return fail(aidm_core::error::Phase::Store, format!("mkdir: {e}"));
        }
    }
    // 与 HTTP 主路径用同一套请求头来源（设置里的 UA/Accept 系列 + 浏览器透传 UA）。
    let ctx = Ctx {
        args,
        profile: {
            let conn = args.db.lock().unwrap();
            aidm_core::http_profile::RequestProfile::from_conn(&conn)
                .with_browser_user_agent(args.browser_user_agent.as_deref())
        },
        custom_headers: args
            .custom_headers
            .as_deref()
            .map(aidm_core::headers::parse_custom_headers)
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default(),
        cookies: args.cookies.clone(),
    };

    let (items, effective_url) = match manifest_items(&ctx, kind, &row.url_orig) {
        Ok(v) => v,
        // 清单层面失败就把原因如实报出去（加密 / 主清单无变体 / 无分片…），
        // 这些都是**稳定的机器码**，用户能据此判断该怎么办。
        //
        // 阶段是 `resolve`：取清单、展开分片时还没开始传数据。**只在这一层加**——
        // 下面分片下载的失败属于 `transfer`，混在一起就是假的阶段归因。
        Err(code) => return fail(aidm_core::error::Phase::Resolve, code),
    };
    if items.is_empty() {
        return fail(aidm_core::error::Phase::Resolve, "manifest_no_segments");
    }

    // 续传：仅当侧车记的是**同一份清单**且项数一致时才接着写。
    let mut state = ManifestState {
        kind: kind.as_str().to_string(),
        source: effective_url.clone(),
        items: items.len(),
        done: 0,
        bytes: 0,
    };
    // 续传读写的都是**工作文件**（`part_path`），不是最终文件。
    //
    // **这里刻意不看 `args.resume`**：manager 的续传判据是"这个任务在 `downloads` 段表里
    // 有没有行"，而清单任务**从不建段行**（进度记在侧车里）—— 沿用那个判据会让清单续传
    // 永远不生效：每次重试都从头下，并把已经下好的字节直接截断重写（实测 seg0 被取了两次）。
    // 所以以**侧车是否存在且与当前清单自洽**为准；读不到或对不上就等价于从头开始（下面
    // 两个分支已经覆盖）。
    let mut file = if let Some(prev) = load_manifest_state(dir, id) {
        if prev.source == effective_url && prev.items == items.len() {
            match std::fs::OpenOptions::new().append(true).open(&part_path) {
                Ok(f) => {
                    let on_disk = f.metadata().map(|m| m.len()).unwrap_or(0);
                    // 磁盘长度与侧车不一致 ⇒ 侧车不可信（被外部改过/上次没落盘），
                    // 从头来。宁可重下，也不要拼出一个中间错位的文件。
                    if on_disk == prev.bytes {
                        state = prev;
                        f
                    } else {
                        log::warn!(
                            "task {id}: 侧车记 {} 字节但文件有 {on_disk} 字节，放弃续传",
                            prev.bytes
                        );
                        let _ = std::fs::remove_file(&part_path);
                        match std::fs::File::create(&part_path) {
                            Ok(f) => f,
                            Err(e) => {
                                return fail(aidm_core::error::Phase::Store, format!("create: {e}"))
                            }
                        }
                    }
                }
                Err(e) => return fail(aidm_core::error::Phase::Store, format!("open: {e}")),
            }
        } else {
            // 清单变了（换过源、或上游重新切片）：旧进度没有意义。
            let _ = std::fs::remove_file(&part_path);
            match std::fs::File::create(&part_path) {
                Ok(f) => f,
                Err(e) => return fail(aidm_core::error::Phase::Store, format!("create: {e}")),
            }
        }
    } else {
        match std::fs::File::create(&part_path) {
            Ok(f) => f,
            Err(e) => return fail(aidm_core::error::Phase::Store, format!("create: {e}")),
        }
    };

    {
        let conn = args.db.lock().unwrap();
        model::log_event(
            &conn,
            id,
            "manifest",
            Some(&format!(
                "kind={} items={} resume_from={} list={}",
                kind.as_str(),
                items.len(),
                state.done,
                aidm_core::redact::redact_url(&effective_url)
            )),
        );
    }

    // 清单分片的写盘同样要走许可。总长按分片累加、事先不可知，用开区间。
    let manifest_lease = args.gate.as_ref().map(|gate| {
        gate.issue(
            AssignmentId::new(format!("manifest:{id}")),
            SliceId::new(format!("manifest:{id}")),
            Span::open(0),
        )
    });
    let _manifest_reaper = match (&args.gate, &manifest_lease) {
        (Some(gate), Some(lease)) => Some(gate.reaper(lease)),
        _ => None,
    };

    let last_progress = std::cell::Cell::new(std::time::Instant::now());
    for (i, seg_url) in items.iter().enumerate() {
        if i < state.done {
            continue; // 已完成的分片：不重复取，但也不重复计数
        }
        // 每个分片之间给取消/暂停一个响应点：分片可能持续数秒，等到最后才看标志
        // 会让"取消"看起来没反应。
        if args.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return WorkerEnd::Cancelled;
        }
        if args.pause.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = save_manifest_state(dir, id, &state);
            return WorkerEnd::Paused;
        }

        let resp = match crate::http_util::apply_common(
            ctx.args.http.agent_for(seg_url).get(seg_url),
            &ctx.profile,
            seg_url,
            ctx.args.referer.as_deref(),
            ctx.cookies.as_deref(),
            &ctx.custom_headers,
        )
        .call()
        {
            Ok(r) if r.status() == 200 => r,
            // **机器码与详情分家**：机器码取标准 HTTP 族（`http_4xx`/`http_5xx`…），
            // 否则界面拿不到文案、退避也认不出。
            Ok(r) => {
                let code = aidm_core::error::http_code_for_status(r.status());
                log_segment_failure(args, id, seg_url, &format!("status={}", r.status()));
                return fail(aidm_core::error::Phase::Transfer, code);
            }
            // **绝不能把 ureq 的 Display 直接当机器码**：它内嵌完整 URL（含查询串）。
            // 真实清单的分片地址常带短时 token，落进 `downloads.error_code` 就是把凭据
            // 写进库里（专项 PROJ-TPL-011 禁记 URL 查询串/令牌）。所以只把**脱敏后**的
            // 地址与原因写事件，机器码用 HTTP 状态族；没有状态码（连接层失败）归 `network`。
            Err(ureq::Error::Status(s, _)) => {
                log_segment_failure(args, id, seg_url, &format!("status={s}"));
                return fail(
                    aidm_core::error::Phase::Transfer,
                    aidm_core::error::http_code_for_status(s),
                );
            }
            Err(e) => {
                log_segment_failure(args, id, seg_url, &e.to_string());
                return fail(
                    aidm_core::error::Phase::Transfer,
                    aidm_core::error::CODE_NETWORK,
                );
            }
        };
        let mut reader = resp.into_reader();
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let at = state.bytes;
                    match (&args.gate, &manifest_lease) {
                        (Some(gate), Some(lease)) => {
                            if gate.check(lease, at, at + n as u64).is_err() {
                                // 分片级续传状态要先存，否则已下完的分片会被重取。
                                let _ = save_manifest_state(dir, id, &state);
                                pause_on_lease_revoked(args, "manifest");
                                return WorkerEnd::Paused;
                            }
                        }
                        _ => {}
                    }
                    if let Err(e) = write_all_checked(&mut file, &buf[..n], args.io_fault) {
                        return fail(aidm_core::error::Phase::Store, e);
                    }
                    state.bytes += n as u64;
                }
                Err(e) => {
                    return fail(
                        aidm_core::error::Phase::Transfer,
                        format!("segment_read: {e}"),
                    )
                }
            }
        }
        state.done = i + 1;
        let _ = save_manifest_state(dir, id, &state);
        // 进度按分片数上报（总长事先不可知），节流到 PERSIST_INTERVAL。
        if last_progress.get().elapsed() >= PERSIST_INTERVAL {
            last_progress.set(std::time::Instant::now());
            if let Some(cb) = args.progress_cb.as_ref() {
                cb(Progress {
                    id,
                    done_bytes: state.bytes,
                    total: None,
                    speed_bps: 0,
                });
            }
        }
    }

    // 全部下完才把工作文件改名成最终文件：失败/取消时保存目录里**不会**出现一个与
    // 成品同名同形的半截文件（与引擎其余路径的约定一致）。
    drop(file);
    if let Err(e) = std::fs::rename(&part_path, &save_path) {
        return fail(aidm_core::error::Phase::Store, format!("rename: {e}"));
    }
    let _ = std::fs::remove_file(manifest_state_path(dir, id));
    finish_single(args, row, &save_path, state.bytes)
}

/// FTP 任务的执行路径。
///
/// 与 HTTP 路径的区别：没有 Range 分段，靠 `REST <offset>` 续传；总长优先取
/// `SIZE`，取不到时用 `RETR` 的 150 回复兜底。
fn ftp_task(args: &Args, row: &DownloadRow, dir: &Path) -> WorkerEnd {
    let id = args.id;
    let mut target = match crate::ftp::parse(&row.url_orig) {
        Ok(t) => t,
        Err(e) => return WorkerEnd::Failed(e),
    };
    // URL 里没写账号就用站点凭据（与 HTTP 的 401 重试共用同一份凭据库）
    if target.user == "anonymous" {
        let host = aidm_core::logins::normalize_host(&target.host);
        let found = {
            let conn = args.db.lock().unwrap();
            aidm_core::logins::lookup(&conn, &host).ok().flatten()
        };
        if let Some(l) = found.filter(|l| !l.username.is_empty()) {
            target.user = l.username;
            target.password = l.password;
        }
    }

    let (connect_s, idle_s) = {
        let conn = args.db.lock().unwrap();
        let c = aidm_core::settings::get(&conn, "conn.timeout_connect_s")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15)
            .clamp(5, 300);
        let i = aidm_core::settings::get(&conn, "conn.timeout_idle_s")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(30, 3600);
        (c, i)
    };
    let timeout = std::time::Duration::from_secs(idle_s.max(connect_s));

    // 探测（登录 / CWD / TYPE I / SIZE / MDTM）：失败即任务失败。
    // 这一段同时包含建连与登录，耗时记在 `auth.result`；FTP 的 USER/PASS 属于 auth 阶段。
    let probe_t = Instant::now();
    let probed = match crate::ftp::probe(&target, timeout) {
        Ok(p) => {
            tracing::info!(
                event = "auth.result",
                phase = "auth",
                proto = "ftp",
                outcome = "ok",
                host = target.host.as_str(),
                dur_ms = probe_t.elapsed().as_millis() as u64,
            );
            p
        }
        Err(e) => {
            tracing::warn!(
                event = "auth.result",
                phase = "auth",
                proto = "ftp",
                outcome = "fail",
                host = target.host.as_str(),
                dur_ms = probe_t.elapsed().as_millis() as u64,
                err = %e,
            );
            return WorkerEnd::Failed(e);
        }
    };

    // 保存目录可能与 HTTP 路径不同（FTP 分支在 HTTP 的建目录逻辑之前返回）
    if let Err(e) = std::fs::create_dir_all(dir) {
        return WorkerEnd::Failed(format!("mkdir: {e}"));
    }
    let file_name = target_file_name(args, &row.file_name);
    let save_path = dir.join(&file_name);
    let total = row
        .size_total
        .map(|v| v.max(0) as u64)
        .filter(|v| *v > 0)
        .or(probed.total);

    // 续传偏移：文件已有长度小于总长就从那里继续
    let mut offset = 0u64;
    if args.resume {
        if let Ok(meta) = std::fs::metadata(&save_path) {
            let len = meta.len();
            match total {
                Some(t) if len > 0 && len < t => offset = len,
                Some(t) if t > 0 && len == t => return finish_single(args, row, &save_path, len),
                None if len > 0 => offset = len,
                _ => {}
            }
        }
    }

    {
        let conn = args.db.lock().unwrap();
        let _ = model::set_probe_meta(
            &conn,
            id,
            &row.url_orig,
            total.map(|t| t as i64),
            None,
            probed.last_modified.as_deref(),
        );
        let pos_end = total.map(|t| t as i64 - 1);
        let _ = model::init_single_segment(&conn, id, &save_path.to_string_lossy(), pos_end);
        let _ = model::set_segment_progress(&conn, id, offset as i64);
        model::log_event(
            &conn,
            id,
            "start",
            Some(&format!(
                "mode=ftp host={} size={total:?} resume_from={offset} mdtm={:?}",
                target.host, probed.last_modified
            )),
        );
        tracing::info!(
            event = "transfer.start",
            phase = "transfer",
            proto = "ftp",
            host = target.host.as_str(),
            size_known = total.is_some(),
            total_bytes = total.unwrap_or(0),
            resume_from = offset,
        );
        let _ = model::set_status(&conn, id, Status::Downloading, None);
    }
    args.live
        .total_bytes
        .store(total.unwrap_or(0), Ordering::Relaxed);
    args.live.done_bytes.store(offset, Ordering::Relaxed);

    let mut last_persist = Instant::now();
    let limit = RateLimit::new(row.speed_limit_kbps);
    let mut stop_reason: Option<WorkerEnd> = None;
    let transfer_t = Instant::now();
    let mut first_byte = false;
    let outcome = crate::ftp::download(&target, &save_path, offset, total, |written| {
        if !first_byte && written > offset {
            first_byte = true;
            tracing::info!(
                event = "transfer.first_byte",
                phase = "transfer",
                proto = "ftp",
                dur_ms = transfer_t.elapsed().as_millis() as u64,
            );
        }
        if args.cancel.load(Ordering::SeqCst) {
            stop_reason = Some(WorkerEnd::Cancelled);
            return false;
        }
        if args.pause.load(Ordering::SeqCst) && total.is_none_or(|t| written < t) {
            stop_reason = Some(WorkerEnd::Paused);
            return false;
        }
        let delta = written.saturating_sub(args.live.done_bytes.load(Ordering::Relaxed));
        args.speed_window.add(delta);
        emit_progress(args, written, total);
        if last_persist.elapsed() >= PERSIST_INTERVAL {
            persist_single(args, written);
            last_persist = Instant::now();
        }
        args.limiter.take(delta);
        limit.take(delta);
        true
    });

    match outcome {
        Err(e) => {
            persist_single(args, args.live.done_bytes.load(Ordering::Relaxed));
            WorkerEnd::Failed(e)
        }
        Ok(out) => {
            persist_single(args, out.total_written);
            tracing::info!(
                event = "store.write",
                phase = "store",
                proto = "ftp",
                bytes = out.total_written,
                mode = "sequential",
                dur_ms = out.write_ms,
            );
            if out.stopped_early {
                let reason = stop_reason.take();
                if matches!(reason, Some(WorkerEnd::Paused)) {
                    let conn = args.db.lock().unwrap();
                    let _ = model::set_status(&conn, id, Status::Paused, None);
                    model::log_event(
                        &conn,
                        id,
                        "paused",
                        Some(&format!("done={}", out.total_written)),
                    );
                }
                return reason.unwrap_or(WorkerEnd::Paused);
            }
            {
                let conn = args.db.lock().unwrap();
                // 总长是 RETR 回复兜底拿到的：补写进库，续传与进度才有依据
                if row.size_total.unwrap_or(0) <= 0 {
                    if let Some(t) = out.total {
                        let _ = model::set_probe_meta(
                            &conn,
                            id,
                            &row.url_orig,
                            Some(t as i64),
                            None,
                            probed.last_modified.as_deref(),
                        );
                    }
                }
                let _ = model::set_segment_state(&conn, id, 0, out.total_written as i64, "done");
            }
            args.live
                .total_bytes
                .store(out.total.unwrap_or(out.total_written), Ordering::Relaxed);
            finish_single(args, row, &save_path, out.total_written)
        }
    }
}

/// eD2k 任务的执行路径。
///
/// 主链（L3/L4 已接进）：解析链接 → 本地已有同名文件按 eD2k 哈希判定
/// （一致即完成，不一致报 `ed2k_hash_mismatch`）→ 链接自带源落库 →
/// 缓存源立即连接；服务器与 Kad 并行增量查源；中央协调器将不同校验片
/// 分配给不同对端，同一源一条连接、每连接最多三个 180 KiB 请求块。
/// 经逐片/整文件校验后提交文件，详见 `worker/ed2k_parallel.rs`。
/// 全部源都失败或表空时如实进入"等待源"（Queued + `ed2k_no_sources`），
/// 由调度器稍后重试，而不是判成失败。
/// 5 秒 HTTP 竞速测速：8 条 Range 连接读数据并丢弃，只统计字节数。
///
/// 不落盘，所以“销毁慢速下载进程”时没有 HTTP 残留文件要清；eD2k 侧的
/// part 文件由切换路径统一删除。
fn race_http_bps(
    http: &Arc<HttpRuntime>,
    profile: &aidm_core::http_profile::RequestProfile,
    url: &str,
    total: u64,
    referer: Option<&str>,
    cookies: Option<&str>,
    headers: &[aidm_core::headers::HeaderLine],
    stop: &Arc<AtomicBool>,
    window: Duration,
) -> u64 {
    if total == 0 {
        return 0;
    }
    let deadline = Instant::now() + window;
    let counted = Arc::new(AtomicU64::new(0));
    let chunk = total.div_ceil(8).max(1);
    std::thread::scope(|scope| {
        for i in 0..8u64 {
            let start = i.saturating_mul(chunk);
            if start >= total {
                break;
            }
            let end = start.saturating_add(chunk).saturating_sub(1).min(total - 1);
            let counted = counted.clone();
            let stop = stop.clone();
            let agent = http.agent_for(url);
            scope.spawn(move || {
                let req = apply_common(agent.get(url), profile, url, referer, cookies, headers)
                    .set("Range", &format!("bytes={start}-{end}"))
                    .timeout(Duration::from_secs(6));
                let Ok(resp) = req.call() else {
                    return;
                };
                if resp.status() != 206 {
                    return;
                }
                let mut reader = resp.into_reader();
                let mut buf = [0u8; 64 * 1024];
                loop {
                    if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                        break;
                    }
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            counted.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    counted.load(Ordering::Relaxed)
}

fn ed2k_task(args: &Args, row: &DownloadRow, dir: &Path) -> WorkerEnd {
    let id = args.id;
    let user_hash = {
        let conn = args.db.lock().unwrap();
        match crate::ed2k::identity::load_or_create(&conn) {
            Ok(hash) => hash,
            Err(e) => return WorkerEnd::Failed(e),
        }
    };
    let link = match aidm_core::ed2k::parse_link(&row.url_orig) {
        Ok(aidm_core::ed2k::Link::File(f)) => f,
        Ok(_) => return WorkerEnd::Failed("ed2k_not_file_link".into()),
        Err(e) => return WorkerEnd::Failed(e.code().to_string()),
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        return WorkerEnd::Failed(format!("mkdir: {e}"));
    }
    let mut file_name = target_file_name(args, &row.file_name);
    // eD2k 的核心能力是**按内容认文件**：先看同目录下的同名同长文件能否被本链接认领。
    // 顺序很重要：必须在「同名文件自动改名」之前判定，否则预置的 `name.ext` 会先被改成
    // `name (1).ext`，哈希校验就永远看不到原文件（表现为明明有正确文件却又下一份）。
    let original_path = dir.join(&file_name);
    let local_candidate = if args.resume {
        false
    } else {
        std::fs::metadata(&original_path)
            .map(|m| link.size > 0 && m.len() == link.size)
            .unwrap_or(false)
    };
    // 只有本地没有可认领的同长文件时，才为避免覆盖而改名。
    if !args.resume && !local_candidate {
        let unique = aidm_core::filename::unique_file_name(dir, &file_name);
        if unique != file_name {
            {
                let conn = args.db.lock().unwrap();
                let _ = model::set_file_name(&conn, id, &unique);
                model::log_event(
                    &conn,
                    id,
                    "ed2k_target_renamed",
                    Some(&format!("{file_name} -> {unique}")),
                );
            }
            file_name = unique;
        }
    }
    let save_path = dir.join(&file_name);

    // 本地已有同名且同长文件：按 eD2k 哈希判定内容是否就是要的那一份。
    // 这正是 ed2k 链接的价值——按内容认文件，与文件名无关。
    //
    // **4 GB 级文件的整包 MD4 在调试构建下要两分钟**：这段时间必须让用户看见在做什么，
    // 并且可被暂停/取消打断。同步 `hash_file` 且不写任何事件、不改状态，
    // 界面会表现为"卡在 connecting、零事件、零字节"，看起来就是"连不上资源"。
    if let Ok(meta) = std::fs::metadata(&save_path) {
        if meta.len() == link.size && link.size > 0 {
            {
                let conn = args.db.lock().unwrap();
                model::log_event(
                    &conn,
                    id,
                    "ed2k_local_check",
                    Some(&format!("start size={}", link.size)),
                );
                tracing::info!(
                    event = "verify.file",
                    phase = "verify",
                    outcome = "pending",
                    proto = "ed2k",
                    algo = "md4",
                    total_bytes = link.size,
                    mode = "local_existing",
                );
                let _ = model::set_status(&conn, id, Status::Verifying, None);
            }
            args.live.total_bytes.store(link.size, Ordering::Relaxed);
            let started = Instant::now();
            let hashed = match hash_file_visible(args, &save_path, link.size) {
                Ok(Some(d)) => d,
                Ok(None) => {
                    let paused = args.pause.load(Ordering::SeqCst);
                    let conn = args.db.lock().unwrap();
                    let _ = model::set_status(
                        &conn,
                        id,
                        if paused {
                            Status::Paused
                        } else {
                            Status::Queued
                        },
                        None,
                    );
                    model::log_event(
                        &conn,
                        id,
                        "ed2k_local_check",
                        Some(if paused {
                            "interrupted=paused"
                        } else {
                            "interrupted=cancelled"
                        }),
                    );
                    return if paused {
                        WorkerEnd::Paused
                    } else {
                        WorkerEnd::Cancelled
                    };
                }
                Err(e) => return WorkerEnd::Failed(format!("ed2k_hash_io: {e}")),
            };
            let elapsed_ms = started.elapsed().as_millis();
            if hashed.file == link.hash {
                {
                    let conn = args.db.lock().unwrap();
                    model::log_event(
                        &conn,
                        id,
                        "ed2k_hash_ok",
                        Some(&format!(
                            "{} (本地已有, 整包校验 {elapsed_ms} ms)",
                            hashed.file_hex()
                        )),
                    );
                    tracing::info!(
                        event = "verify.file",
                        phase = "verify",
                        outcome = "ok",
                        proto = "ed2k",
                        algo = "md4",
                        total_bytes = link.size,
                        dur_ms = elapsed_ms as u64,
                        mode = "local_existing",
                    );
                }
                return finish_single(args, row, &save_path, link.size);
            }
            {
                let conn = args.db.lock().unwrap();
                model::log_event(
                    &conn,
                    id,
                    "ed2k_hash_mismatch",
                    Some(&format!(
                        "local={} want={} (整包校验 {elapsed_ms} ms)",
                        hashed.file_hex(),
                        link.hash_hex
                    )),
                );
                tracing::warn!(
                    event = "verify.file",
                    phase = "verify",
                    outcome = "fail",
                    proto = "ed2k",
                    algo = "md4",
                    err_code = error::CODE_ED2K_HASH_MISMATCH,
                    dur_ms = elapsed_ms as u64,
                    mode = "local_existing",
                );
            }
            return WorkerEnd::Failed(aidm_core::error::CODE_ED2K_HASH_MISMATCH.into());
        }
    }

    // 部分下载只放在任务私有目录；中断/换源后按分片哈希复用，
    // 不能把预分配的长度当作已下载，也不能让未完成文件占用最终文件名。
    let part_path = segment::part_path(dir, id, 0);
    if let Some(parent) = part_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return WorkerEnd::Failed(format!("mkdir: {e}"));
        }
    }
    {
        let conn = args.db.lock().unwrap();
        if model::list_segments(&conn, id)
            .unwrap_or_default()
            .is_empty()
            && link.size > 0
        {
            let spans = [segment::ByteSpan {
                start: 0,
                end: link.size - 1,
            }];
            let paths = [part_path.to_string_lossy().into_owned()];
            if let Err(e) = model::replace_segments(&conn, id, &spans, &paths) {
                return WorkerEnd::Failed(format!("ed2k_segments: {e}"));
            }
        }
    }

    // 链接自带源是第一批候选：建任务时已落库（`manager::add_spec`），这里再补一次
    // 是为了覆盖"老任务在补落库逻辑上线前建好"的情形；`add_ed2k_sources` 按
    // (任务,主机,端口) 去重，多调无害。
    if !link.sources.is_empty() {
        let conn = args.db.lock().unwrap();
        let _ = model::add_ed2k_sources(&conn, id, &link.sources, Some("link"));
        let _ = model::set_ed2k_meta(&conn, id, Some(&link.hash_hex), link.aich_root.as_deref());
    }

    // 并发竞速：archive.org HTTP 查询与 eD2k 服务器/Kad 查源同时开始。
    // 先到者胜：HTTP 先到且 eD2k 还没拿到任何源/字节时，停掉 eD2k 池并切 HTTP；
    // eD2k 先到则继续 eD2k，HTTP 结果只落候选库，供后续失败时直接复用。
    let switch_http = Arc::new(AtomicBool::new(false));
    let known = Arc::new(AtomicU64::new(0));
    let first_standard_source = Arc::new(AtomicBool::new(false));
    // 找源生命周期：pause / cancel（delete 会先 cancel）/ 任务完成 / 60s 硬顶。
    let find_stop = Arc::new(AtomicBool::new(false));
    let find_enabled = {
        let conn = args.db.lock().unwrap();
        settings::get(&conn, "find.enabled")
            .ok()
            .flatten()
            .or_else(|| settings::default_of("find.enabled").map(str::to_string))
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(true)
    };
    let (http_tx, http_rx) =
        std::sync::mpsc::channel::<Option<crate::archive_source::HttpSource>>();
    if find_enabled {
        let http = args.http.clone();
        let db = args.db.clone();
        // 重名任务会落成 `file (1).iso`；archive.org 上的文件仍是 eD2k 链接里的原名。
        let name = link.decoded_name();
        let size = (link.size >= 100 * 1024 * 1024).then_some(link.size);
        let find_stop_thread = find_stop.clone();
        let cancel = args.cancel.clone();
        let pause = args.pause.clone();
        std::thread::spawn(move || {
            if find_stop_thread.load(Ordering::SeqCst)
                || cancel.load(Ordering::SeqCst)
                || pause.load(Ordering::SeqCst)
            {
                return;
            }
            let started = Instant::now();
            let src = size.and_then(|s| {
                crate::archive_source::discover_checked_until(
                    &http,
                    &name,
                    Some(s),
                    Some(started + Duration::from_secs(60)),
                )
                .ok()
                .and_then(|v| v.into_iter().next())
            });
            // 请求本身有 6s/3s 超时；这里再兜 60s 硬顶 + 生命周期检查。
            if find_stop_thread.load(Ordering::SeqCst)
                || cancel.load(Ordering::SeqCst)
                || pause.load(Ordering::SeqCst)
                || started.elapsed() >= Duration::from_secs(60)
            {
                return;
            }
            if let Some(src) = &src {
                use aidm_core::source::{CandidateSource, IdentityEvidence, Platform, SourceKind};
                let evidence = match src.size {
                    Some(size) => IdentityEvidence::SizeOnly { size },
                    None => IdentityEvidence::Unverified,
                };
                let cand = CandidateSource {
                    url: src.url.clone(),
                    platform: Platform::ArchiveOrg,
                    kind: SourceKind::File,
                    size: src.size,
                    version: None,
                    container: None,
                    evidence,
                    auth_ref: None,
                    origin: Some(format!("archive_org:{}", src.label)),
                    expires_at: None,
                };
                let conn = db.lock().unwrap();
                let _ = model::upsert_source_candidates(
                    &conn,
                    id,
                    &[cand],
                    crate::source_registry::now_ms(),
                );
            }
            let _ = http_tx.send(src);
        });
    }
    let result = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            ed2k_parallel::download(
                args,
                row,
                &link,
                &part_path,
                user_hash,
                &switch_http,
                &known,
                &first_standard_source,
            )
        });
        // 优先原协议：HTTP 命中后给 eD2k 2 秒宽限。
        // 若这 2 秒内有“标准 eD2k 源”到达，就让 eD2k 继续；否则切 HTTP。
        // `known` 含私有池/排队对端，不能作为判断依据。
        // 双下载竞速：HTTP 候选到达后，eD2k 与 HTTP 各跑 5 秒，比较这 5 秒的
        // 实际字节数。慢的一方被销毁；HTTP 胜出则切 HTTP，eD2k 胜出则继续原协议。
        let mut race_started = false;
        let mut race_stop: Option<Arc<AtomicBool>> = None;
        loop {
            match http_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(src)) => {
                    if !race_started && args.live.done_bytes.load(Ordering::Relaxed) < link.size {
                        race_started = true;
                        let baseline = args.live.done_bytes.load(Ordering::Relaxed);
                        let http = args.http.clone();
                        let db = args.db.clone();
                        let live = args.live.clone();
                        let cancel = args.cancel.clone();
                        let pause = args.pause.clone();
                        let referer = args.referer.clone();
                        let cookies = args.cookies.clone();
                        let profile = {
                            let conn = args.db.lock().unwrap();
                            aidm_core::http_profile::RequestProfile::from_conn(&conn)
                        };
                        let headers = args
                            .custom_headers
                            .as_deref()
                            .map(aidm_core::headers::parse_custom_headers)
                            .transpose()
                            .ok()
                            .flatten()
                            .unwrap_or_default();
                        let stop = Arc::new(AtomicBool::new(false));
                        race_stop = Some(stop.clone());
                        let switch = switch_http.clone();
                        let total = link.size;
                        std::thread::spawn(move || {
                            let http_bytes = race_http_bps(
                                &http,
                                &profile,
                                &src.url,
                                total,
                                referer.as_deref(),
                                cookies.as_deref(),
                                &headers,
                                &stop,
                                Duration::from_secs(5),
                            );
                            if stop.load(Ordering::SeqCst)
                                || cancel.load(Ordering::SeqCst)
                                || pause.load(Ordering::SeqCst)
                                || live.done_bytes.load(Ordering::Relaxed) >= total
                            {
                                return;
                            }
                            let ed2k_bytes = live
                                .done_bytes
                                .load(Ordering::Relaxed)
                                .saturating_sub(baseline);
                            let conn = db.lock().unwrap();
                            let http_wins = http_bytes > ed2k_bytes;
                            model::log_event(
                                &conn,
                                id,
                                "source_race",
                                Some(&format!(
                                    "winner={} http_bytes={http_bytes} ed2k_bytes={ed2k_bytes} window_s=5",
                                    if http_wins { "http" } else { "ed2k" }
                                )),
                            );
                            if http_wins {
                                switch.store(true, Ordering::SeqCst);
                            } else if let Ok(rows) =
                                model::list_source_candidates(&conn, id, Some("candidate"))
                            {
                                if let Some(r) = rows.iter().find(|r| r.platform == "archive_org") {
                                    let _ =
                                        model::set_source_candidate_state(&conn, r.id, "suspended");
                                    model::log_event(
                                        &conn,
                                        id,
                                        "source_suspend",
                                        Some("state=suspended reason=race_lost"),
                                    );
                                }
                            }
                        });
                    }
                }
                Ok(None) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if handle.is_finished() {
                break;
            }
        }
        if let Some(stop) = race_stop {
            stop.store(true, Ordering::SeqCst);
        }
        handle
            .join()
            .unwrap_or_else(|_| WorkerEnd::Failed("ed2k_thread_panic".into()))
    });
    // 任务走到这里就代表完成/失败/暂停/取消，找源线程必须停止（in-flight 请求
    // 由它自己的 6s 超时收尾；返回后还会再检查一次 find_stop，不会写库）。
    find_stop.store(true, Ordering::SeqCst);
    if switch_http.load(Ordering::SeqCst) && try_auto_switch_http(args, id) {
        return WorkerEnd::Failed(aidm_core::error::CODE_ED2K_INCOMPLETE.into());
    }
    result
}

fn finish_ed2k(
    args: &Args,
    row: &DownloadRow,
    path: &Path,
    hash_hex: &str,
    written: u64,
) -> WorkerEnd {
    // 校验成功后才把任务私有 part 提交为最终文件；提交失败不能标记完成。
    let dest = Path::new(&row.dir).join(target_file_name(args, &row.file_name));
    if dest != path {
        if dest.exists() {
            return WorkerEnd::Failed("ed2k_target_exists".into());
        }
        if let Err(e) = std::fs::rename(path, &dest) {
            return WorkerEnd::Failed(format!("ed2k_commit: {e}"));
        }
    }
    let url = row.url_orig.as_str();
    remove_part_dir(Path::new(&row.dir), args.id);
    {
        let conn = args.db.lock().unwrap();
        model::log_event(&conn, args.id, "ed2k_hash_ok", Some(hash_hex));
        let _ = model::mark_done(&conn, args.id, url);
        let _ = model::finalize_segments(&conn, args.id);
        model::log_event(
            &conn,
            args.id,
            "done",
            Some(&format!("bytes={written} ed2k={hash_hex}")),
        );
    }
    args.live.done_bytes.store(written, Ordering::Relaxed);
    args.live.speed_bps.store(0, Ordering::Relaxed);
    WorkerEnd::Done
}

/// 无可用源时的统一出口：记事件 + 置 Queued + 返回说明性错误码（不算失败）。
/// eD2k 停滞时自动尝试 HTTP 源（当前：archive.org）。
///
/// 每个任务每 10 分钟最多查一次，避免 30 秒一轮地打 archive.org；命中后清空
/// eD2k 工作文件、把主地址改成 HTTP 并保留 `ed2k_hash` 供完成验收。网络失败/
/// 无同名文件返回 false，原 eD2k 等待逻辑不变。
fn ed2k_original_name(row: &DownloadRow) -> String {
    aidm_core::ed2k::parse_link(&row.url_orig)
        .ok()
        .and_then(|link| match link {
            aidm_core::ed2k::Link::File(f) => Some(f.decoded_name()),
            _ => None,
        })
        .unwrap_or_else(|| row.file_name.clone())
}

fn try_auto_switch_http(args: &Args, id: i64) -> bool {
    static TRIED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<i64, Instant>>> =
        std::sync::OnceLock::new();
    {
        let mut tried = TRIED
            .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
            .lock()
            .unwrap();
        if let Some(at) = tried.get(&id) {
            if at.elapsed() < Duration::from_secs(600) {
                return false;
            }
        }
        tried.insert(id, Instant::now());
    }
    let row = {
        let conn = args.db.lock().unwrap();
        model::get_download(&conn, id).ok().flatten()
    };
    let Some(row) = row else {
        return false;
    };
    {
        let conn = args.db.lock().unwrap();
        let enabled = settings::get(&conn, "find.enabled")
            .ok()
            .flatten()
            .or_else(|| settings::default_of("find.enabled").map(str::to_string))
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        if !enabled {
            return false;
        }
    }
    if !row
        .url_orig
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("ed2k:")
    {
        return false;
    }
    let size = row.size_total.map(|v| v.max(0) as u64).filter(|v| *v > 0);
    let lookup_name = ed2k_original_name(&row);
    // 竞速线程可能已经把 archive.org 命中写进 source_candidates；优先复用，
    // 避免同一次任务重复打 archive.org。没有再同步查一次（兼容老任务）。
    let cached = {
        let conn = args.db.lock().unwrap();
        model::list_source_candidates(&conn, id, Some("candidate"))
            .unwrap_or_default()
            .into_iter()
            .find(|r| r.platform == "archive_org")
            .and_then(|r| model::row_to_candidate(&r))
    };
    let (url, src_size, label, provider) = match cached {
        Some(c) => (
            c.url,
            c.size,
            c.origin.unwrap_or_else(|| "archive_org".into()),
            "archive_org".to_string(),
        ),
        None => {
            let Some(src) = crate::archive_source::discover_checked_until(
                &args.http,
                &lookup_name,
                size,
                Some(Instant::now() + Duration::from_secs(60)),
            )
            .ok()
            .and_then(|v| v.into_iter().next()) else {
                return false;
            };
            (src.url, src.size, src.label, src.provider.to_string())
        }
    };
    // 到这里 eD2k 线程已经结束（`ed2k_wait_sources` 只在 download 返回后调用），
    // 可以安全删除它的工作文件；随后 HTTP 从头下载，完成时再按 eD2k 哈希验收。
    crate::merge::remove_part_dir(Path::new(&row.dir), id);
    {
        let conn = args.db.lock().unwrap();
        let Ok(n) = model::reset_for_restart(&conn, id) else {
            return false;
        };
        if n == 0 {
            return false;
        }
        if model::set_url_orig(&conn, id, &url).is_err() {
            return false;
        }
        let _ = model::set_alt_urls(&conn, id, None);
        model::log_event(
            &conn,
            id,
            "ed2k_auto_http",
            Some(&format!(
                "{} {}",
                label,
                aidm_core::redact::redact_url(&url)
            )),
        );
    }
    tracing::info!(
        event = "ed2k_auto_http",
        source = provider.as_str(),
        size = src_size.unwrap_or(0),
        url = aidm_core::redact::redact_url(&url).as_ref(),
    );
    true
}

/// P2P 等待源的重排间隔。
///
/// - 自动切 HTTP 后 1 秒内重跑，尽快验证新地址；
/// - 有候选源但本轮没连上/没凑满分片（`ed2k_incomplete`）时 5 秒后重试，
///   私有 SN/NAT 握手常有一次失败、下一轮成功的情况，30 秒会明显拖慢首连；
/// - 真正零候选源（`ed2k_no_sources`）才按 30 秒低频探测。
fn p2p_wait_ms(code: &str, auto_http: bool) -> i64 {
    if auto_http {
        1000
    } else if code == aidm_core::error::CODE_ED2K_INCOMPLETE {
        5 * 1000
    } else {
        30 * 1000
    }
}

fn ed2k_wait_sources(
    args: &Args,
    id: i64,
    hash_hex: &str,
    size: u64,
    source_count: usize,
) -> WorkerEnd {
    if args.cancel.load(Ordering::SeqCst) {
        return WorkerEnd::Cancelled;
    }
    if args.pause.load(Ordering::SeqCst) {
        let conn = args.db.lock().unwrap();
        let _ = model::set_status(&conn, id, Status::Paused, None);
        return WorkerEnd::Paused;
    }
    // 小文件（测试/普通 ed2k）不走自动 archive.org 查询：既没有镜像价值，
    // 也会让"无源等待"多出十几秒网络时间。
    let switched = size >= 100 * 1024 * 1024 && try_auto_switch_http(args, id);
    let code = if switched {
        aidm_core::error::CODE_ED2K_INCOMPLETE
    } else if source_count == 0 {
        aidm_core::error::CODE_ED2K_NO_SOURCES
    } else {
        // 有候选源但本轮没凑满分片：不能报"没有源"，否则用户/诊断会误判。
        aidm_core::error::CODE_ED2K_INCOMPLETE
    };
    let conn = args.db.lock().unwrap();
    model::log_event(
        &conn,
        id,
        "ed2k_wait_sources",
        Some(&format!(
            "hash={hash_hex} size={size} 候选源={source_count} code={code} auto_http={switched}"
        )),
    );
    let _ = model::set_status(&conn, id, Status::Queued, None);
    WorkerEnd::Failed(code.into())
}

#[cfg(test)]
mod finder_policy_tests {
    use super::{
        finder_eligible, is_signed_rate_limit, next_conn_cap, p2p_wait_ms, task_conns_for,
    };

    #[test]
    fn p2p_wait_is_short_for_incomplete_sources_and_long_for_no_sources() {
        assert_eq!(
            p2p_wait_ms(aidm_core::error::CODE_ED2K_INCOMPLETE, false),
            5_000
        );
        assert_eq!(
            p2p_wait_ms(aidm_core::error::CODE_ED2K_NO_SOURCES, false),
            30_000
        );
        assert_eq!(
            p2p_wait_ms(aidm_core::error::CODE_ED2K_INCOMPLETE, true),
            1_000
        );
    }

    #[test]
    fn task_conns_apply_backoff_cap() {
        let conn = aidm_core::db::open_db(std::path::Path::new(":memory:")).unwrap();
        aidm_core::settings::ensure_defaults(&conn).unwrap();
        let id = aidm_core::model::insert_download(
            &conn,
            "https://example.com/a.bin",
            "a.bin",
            "/tmp",
            0,
            8,
        )
        .unwrap();
        let row = aidm_core::model::get_download(&conn, id).unwrap().unwrap();
        let base = aidm_core::hosts::task_conns(&conn, &row.url_orig);
        assert!(base >= 1);
        aidm_core::model::set_conn_cap(&conn, id, 4, true).unwrap();
        assert_eq!(task_conns_for(&conn, &row), base.min(4));
        aidm_core::model::set_conn_cap(&conn, id, 1, true).unwrap();
        assert_eq!(task_conns_for(&conn, &row), 1);
    }

    #[test]
    fn signed_rate_limit_halves_to_one() {
        assert_eq!(next_conn_cap(8, None), 4);
        assert_eq!(next_conn_cap(8, Some(4)), 2);
        assert_eq!(next_conn_cap(8, Some(2)), 1);
        assert_eq!(next_conn_cap(8, Some(1)), 1);
        assert_eq!(next_conn_cap(1, None), 1);
        assert!(is_signed_rate_limit("http_503"));
        assert!(is_signed_rate_limit("http_429"));
        assert!(!is_signed_rate_limit("http_404"));
        assert!(!is_signed_rate_limit("connect: timeout"));
    }

    #[test]
    fn find_settings_drive_budget_and_switch() {
        let conn = aidm_core::db::open_db(std::path::Path::new(":memory:")).unwrap();
        let rt = super::find_runtime_config(&conn);
        assert!(rt.enabled);
        assert_eq!(rt.total_ms, 60_000);
        assert_eq!(rt.max_candidates, 12);
        assert_eq!(rt.negative_ttl_ms, 600_000);
        assert_eq!(rt.platform_qpm, 6);
        assert_eq!(rt.slow_window_s, 60);
        assert_eq!(rt.slow_min_mbps, 50);

        aidm_core::settings::set(&conn, "find.enabled", "false").unwrap();
        aidm_core::settings::set(&conn, "find.max_elapsed_s", "5").unwrap();
        aidm_core::settings::set(&conn, "find.max_candidates", "2").unwrap();
        aidm_core::settings::set(&conn, "find.negative_ttl_s", "60").unwrap();
        aidm_core::settings::set(&conn, "find.platform_qpm", "1").unwrap();
        let rt = super::find_runtime_config(&conn);
        assert!(!rt.enabled);
        assert_eq!(rt.total_ms, 5_000);
        assert_eq!(rt.max_candidates, 2);
        assert_eq!(rt.negative_ttl_ms, 60_000);
        assert_eq!(rt.platform_qpm, 1);
    }

    #[test]
    fn only_public_http_is_eligible() {
        assert!(!finder_eligible("http://127.0.0.1/x"));
        assert!(!finder_eligible("http://localhost/x"));
        assert!(!finder_eligible("http://192.168.1.10/x"));
        assert!(!finder_eligible("http://10.0.0.1/x"));
        assert!(!finder_eligible("http://172.20.1.1/x"));
        assert!(!finder_eligible("http://[::1]/x"));
        assert!(!finder_eligible("ftp://example.com/x"));
        assert!(!finder_eligible("not a url"));
        assert!(finder_eligible("https://example.com/x"));
        assert!(finder_eligible("http://[2001:db8::1]/x"));
    }
}
