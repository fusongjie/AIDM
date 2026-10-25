//! `aidm-fetch`：fastdl 内核的独立基准程序。
//!
//! 用于单地址、单进程的吞吐基准：
//!
//! ```text
//! aidm-fetch --url <URL> --out D:\dl --conns 32 --init 8
//! ```

use std::path::PathBuf;
use std::time::Duration;

use aidm_engine::fastdl::{fetch_standalone, Standalone};

struct Opts {
    url: String,
    out: PathBuf,
    name: Option<String>,
    conns: usize,
    init: usize,
    buf_kb: usize,
    rcvbuf_kb: usize,
    proxy: Option<String>,
    no_proxy: bool,
    /// `--ua <字符串>`：覆盖 User-Agent（默认与引擎一致）
    user_agent: Option<String>,
    sha256: bool,
    json: bool,
    label: String,
    /// 切块源的判定窗口（秒）。默认 5 = 全自动；0 = 关闭。
    window_s: u64,
    /// 窗口内低于该值（B/s）即判慢；0 = 不用绝对判据。
    min_bps: u64,
}

fn usage() -> ! {
    eprintln!(
        "用法: aidm-fetch --url <URL> --out <DIR> [--name <FILE>] [--conns N] [--init N]\n\
         \x20              [--buf-kb N] [--proxy <URL>|--no-proxy] [--no-sha256] [--json] [--label S]"
    );
    std::process::exit(2);
}

fn parse_args() -> Opts {
    let mut a = std::env::args().skip(1);
    let mut o = Opts {
        url: String::new(),
        out: PathBuf::from("."),
        name: None,
        conns: 32,
        init: 8,
        buf_kb: 256,
        rcvbuf_kb: 0,
        proxy: None,
        no_proxy: false,
        user_agent: None,
        sha256: true,
        json: false,
        label: "aidm".into(),
        window_s: 5,
        min_bps: 0,
    };
    while let Some(k) = a.next() {
        let mut val = || a.next().unwrap_or_default();
        match k.as_str() {
            "--url" => o.url = val(),
            "--out" => o.out = PathBuf::from(val()),
            "--name" => o.name = Some(val()),
            "--conns" => o.conns = val().parse().unwrap_or(32),
            "--init" => o.init = val().parse().unwrap_or(8),
            "--buf-kb" => o.buf_kb = val().parse().unwrap_or(256),
            "--rcvbuf-kb" => o.rcvbuf_kb = val().parse().unwrap_or(0),
            "--proxy" => o.proxy = Some(val()),
            "--no-proxy" => o.no_proxy = true,
            "--ua" => o.user_agent = Some(val()),
            "--no-sha256" => o.sha256 = false,
            "--json" => o.json = true,
            "--label" => o.label = val(),
            "--window-s" => o.window_s = val().parse().unwrap_or(5),
            "--min-bps" => o.min_bps = val().parse().unwrap_or(0),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("未知参数: {other}");
                usage();
            }
        }
    }
    if o.url.is_empty() {
        usage();
    }
    o
}

/// 未显式指定代理时读系统代理。
fn system_proxy() -> Option<String> {
    aidm_core::proxy::read_system_proxy().map(|p| format!("http://{}:{}", p.host, p.port))
}

fn main() {
    aidm_core::obs::init("aidm-fetch", "warn");
    let o = parse_args();
    let name = o.name.clone().unwrap_or_else(|| {
        o.url
            .rsplit('/')
            .find(|s| !s.is_empty() && !s.contains('?'))
            .unwrap_or("download.bin")
            .to_string()
    });
    let proxy = if o.no_proxy {
        None
    } else {
        o.proxy.clone().or_else(system_proxy)
    };
    let spec = Standalone {
        url: o.url.clone(),
        dir: o.out.clone(),
        file_name: name.clone(),
        max_conns: o.conns,
        // `--init 0`（默认）= 与引擎一致：起步受 `INIT_CONNS_CAP` 限制，其余交给 ramp。
        // 显式给 `--init N` 时仍按用户说的来（诊断工具需要能强制放满来复现问题）。
        init_conns: if o.init == 0 {
            o.conns.min(aidm_engine::fastdl::INIT_CONNS_CAP)
        } else {
            o.init
        },
        chunk_buf: o.buf_kb * 1024,
        recv_buf: o.rcvbuf_kb * 1024,
        proxy: proxy.clone(),
        verify_sha256: o.sha256,
        // 与引擎一致的默认请求头（UA / Accept 系列 / Referer 兜底）
        profile: match o.user_agent.clone() {
            Some(ua) if !ua.trim().is_empty() => aidm_core::http_profile::RequestProfile {
                user_agent: ua,
                ..Default::default()
            },
            _ => aidm_core::http_profile::RequestProfile::default(),
        },
        connect_timeout: Duration::from_secs(15),
        read_timeout: Duration::from_secs(60),
        measure_window_s: o.window_s,
        measure_min_bps: o.min_bps,
    };
    if let Err(e) = std::fs::create_dir_all(&o.out) {
        eprintln!("mkdir {}: {e}", o.out.display());
        std::process::exit(1);
    }
    match fetch_standalone(spec) {
        Ok(r) => {
            // 来源打分**任务级采数**（基准路径）。
            //
            // 引擎路径的采数挂在 `worker` 调 `fastdl::run` 的地方，而本程序直接走
            // `fetch_standalone`、不经过 worker，所以必须在这里单独记一次，否则
            // "用基准对比镜像"这件事永远进不了记分板。粒度同样是任务级（一次运行 = 一次尝试），
            // 因为 fastdl 内部没有逐连接收尾点。
            // `ttfb` 传 0 = 没测到：`StandaloneResult` 不回传首字节时刻（trace 的 0.5 s 采样
            // 太粗，拿它当首字节会把响应速度分算歪）。
            aidm_engine::source_registry::record(
                &o.url,
                r.bytes,
                (r.secs * 1000.0) as u64,
                0,
                true,
                aidm_engine::source_registry::now_ms(),
            );
            if o.json {
                println!("{}", serde_json::to_string(&r).unwrap_or_default());
                return;
            }
            println!(
                "[{}] {} bytes in {:.3}s = {:.1} MiB/s | chunks={} splits={} http_requests={} proxy={:?}",
                o.label,
                r.bytes,
                r.secs,
                r.mb_per_s,
                r.chunks,
                r.splits,
                r.http_requests,
                proxy
            );
            if let Some(h) = &r.sha256 {
                println!("sha256 = {h}");
            }
            // 每 0.5 s 打一格瞬时速度，便于观察爬坡与限速
            let mut idx = 0usize;
            let mut next = 0.0f64;
            let mut prev = (0.0f64, 0u64);
            for (t, b) in &r.trace {
                if *t >= next {
                    let inst =
                        (b.saturating_sub(prev.1)) as f64 / 1_048_576.0 / (t - prev.0).max(0.05);
                    println!(
                        "  t={t:6.2}s  cum={:>8.1} MiB  inst={inst:>6.1} MiB/s",
                        *b as f64 / 1_048_576.0
                    );
                    prev = (*t, *b);
                    next = *t + 0.5;
                }
                idx += 1;
            }
            let _ = idx;
        }
        Err(e) => {
            // 失败也算一次尝试（分母要含失败，这正是"保守成功率"的意义）。
            aidm_engine::source_registry::record(
                &o.url,
                0,
                0,
                0,
                false,
                aidm_engine::source_registry::now_ms(),
            );
            eprintln!("[{}] FAILED: {e}", o.label);
            std::process::exit(1);
        }
    }
}
