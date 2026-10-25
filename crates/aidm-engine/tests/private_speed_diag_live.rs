//! Explicit live speed diagnostics for the original ISO's private channel.
//!
//! `cargo test --release -p aidm-engine --test private_speed_diag_live -- --ignored --nocapture`
//! Environment: AIDM_DIAG_SECS (default 60), AIDM_DIAG_CONNS (default 32),
//! AIDM_DIAG_LABEL (file name prefix). The partial ISO is deleted afterwards;
//! only the JSON report stays under `AIDM/target-check/speed-diag/`.
use aidm_core::ed2k::peer::PARTSIZE;
use aidm_engine::ed2k::{
    multi_source::{MultiSourceCfg, PoolProgress, TransferHooks},
    private_index,
    private_pool::{self, PoolDiag},
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const URI: &str = "ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";

struct Hooks {
    active: AtomicUsize,
    bytes: AtomicU64,
}
impl TransferHooks for Hooks {
    fn try_acquire_connection(&self) -> bool {
        self.active.fetch_add(1, Ordering::SeqCst);
        true
    }
    fn release_connection(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
    fn received(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }
}

#[cfg(windows)]
fn process_cpu() -> Duration {
    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(
            process: isize,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let (mut c, mut e, mut k, mut u) = Default::default();
    // SAFETY: valid out-pointers to stack values; pseudo-handle needs no close.
    let ok = unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
    if ok == 0 {
        return Duration::ZERO;
    }
    let ticks = |t: &FileTime| (u64::from(t.high) << 32) | u64::from(t.low);
    Duration::from_nanos((ticks(&k) + ticks(&u)) * 100)
}
#[cfg(not(windows))]
fn process_cpu() -> Duration {
    Duration::ZERO
}

fn ms(d: Option<Duration>) -> Value {
    d.map_or(Value::Null, |d| {
        json!((d.as_secs_f64() * 1e4).round() / 10.0)
    })
}
fn mbps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        (bytes as f64 / 1e6 / secs * 100.0).round() / 100.0
    }
}

#[test]
#[ignore = "explicit public network speed diagnostics; writes target-check/speed-diag JSON"]
fn private_channel_speed_diagnostics() {
    let secs: u64 = std::env::var("AIDM_DIAG_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let conns: usize = std::env::var("AIDM_DIAG_CONNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    let label = std::env::var("AIDM_DIAG_LABEL").unwrap_or_else(|_| "aidm".into());
    let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link(URI).unwrap() else {
        panic!("file link")
    };
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target-check/speed-diag");
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let work = root.join(format!("{label}-{stamp}.work"));
    fs::create_dir_all(&work).unwrap();
    let target = work.join("original.iso");
    // A fresh per-run identity: no reuse of another client's or run's PeerID.
    let mut seed = [0_u8; 16];
    seed.copy_from_slice(
        &ring::digest::digest(&ring::digest::SHA256, &stamp.to_le_bytes()).as_ref()[..16],
    );
    let identity = private_index::peer_id(&seed);

    let started = Instant::now();
    let cpu_start = process_cpu();
    let meta = private_index::query(&link, URI, &identity)
        .unwrap()
        .unwrap();
    let metadata_ms = started.elapsed().as_millis();
    let hooks = Hooks {
        active: AtomicUsize::new(0),
        bytes: AtomicU64::new(0),
    };
    let deadline = Duration::from_secs(secs);
    let stop = || started.elapsed() >= deadline;
    let events = |_| {};
    let cfg = MultiSourceCfg {
        user_hash: seed,
        file_hash: link.hash,
        file_size: link.size,
        target: &target,
        max_connections: conns,
        connect_timeout: Duration::from_secs(3),
        read_timeout: Duration::from_secs(8),
        discovery_timeout: Duration::from_secs(5),
        stop: &stop,
        hooks: &hooks,
        on_event: &events,
        xs_sources: None,
        feed_done: None,
        aich_root: None,
        part_filter: None,
        expansion: None,
        on_ownership: None,
        claim_base: 1,
        claim_reserve: 4096,
        claim_refill: None,
    };
    let mut directory_ms = None;
    let mut directory_peers = 0;
    let mut first_file_ms = None;
    let mut samples: Vec<Value> = Vec::new();
    let mut retired: Vec<Value> = Vec::new();
    let mut prev_bytes = 0_u64;
    let mut prev_udp = (0_u64, 0_u64);
    let mut prev_idle = Duration::ZERO;
    let mut prev_cpu = cpu_start;
    let mut prev_at = Instant::now();
    let mut prev_peer: HashMap<u16, (u64, u64, u64, u64)> = HashMap::new();
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
    let mut observer = |d: &PoolDiag| {
        let now = Instant::now();
        let dt = now.duration_since(prev_at).as_secs_f64().max(1e-3);
        prev_at = now;
        let bytes = hooks.bytes.load(Ordering::Relaxed);
        if bytes > 0 {
            first_file_ms.get_or_insert(started.elapsed().as_millis());
        }
        let cpu = process_cpu();
        let cpu_core_pct = (cpu - prev_cpu).as_secs_f64() / dt * 100.0;
        prev_cpu = cpu;
        let idle = d.idle_wait - prev_idle;
        prev_idle = d.idle_wait;
        let peers: Vec<Value> = d
            .peers
            .iter()
            .map(|p| {
                let s = p.stats;
                let (b, dup, ooo, rs) = prev_peer
                    .insert(
                        p.port,
                        (p.file_bytes, s.duplicate_packets, s.out_of_order_packets, s.resends),
                    )
                    .unwrap_or_default();
                let rate = (p.file_bytes - b) as f64 / dt;
                json!({
                    "port": p.port, "addr": p.addr.to_string(),
                    "rate_mbps": mbps(p.file_bytes - b, dt),
                    "file_bytes": p.file_bytes,
                    "part": p.part, "part_covered": p.part_covered,
                    "ready": p.ready, "queued": p.queued, "age_s": p.age.as_secs(),
                    "rtt_min_ms": ms(s.rtt_min), "rtt_last_ms": ms(s.rtt_last),
                    "request_latency_ms": ms(s.request_latency),
                    "dup_pkts": s.duplicate_packets - dup, "ooo_pkts": s.out_of_order_packets - ooo,
                    "our_resends": s.resends - rs,
                    "remote_window": s.remote_window, "reassembly_peak": s.reassembly_peak,
                    "flow_drops_total": s.flow_drops,
                    "data_pkts_total": s.data_packets,
                    "avg_payload": s.payload_bytes.checked_div(s.data_packets).unwrap_or(0),
                    // rate × RTT / advertised window: near 1 means the receive window caps this stream.
                    "window_util": s.rtt_min.map(|r| ((rate * r.as_secs_f64() / f64::from(s.advertised_window)) * 100.0).round() / 100.0),
                    "window_util_loaded": s.rtt_last.map(|r| ((rate * r.as_secs_f64() / f64::from(s.advertised_window)) * 100.0).round() / 100.0),
                })
            })
            .collect();
        for p in &d.retired {
            prev_peer.remove(&p.port);
            retired.push(json!({
                "t_s": d.elapsed.as_secs(), "addr": p.addr.to_string(), "file_bytes": p.file_bytes,
                "age_s": p.age.as_secs(), "reason": p.retired, "ready": p.ready,
                "rtt_min_ms": ms(p.stats.rtt_min), "dup_total": p.stats.duplicate_packets,
            }));
        }
        let transferring = d.peers.iter().filter(|p| p.part_covered > 0).count();
        samples.push(json!({
            "t_ms": started.elapsed().as_millis(),
            "speed_mbps": mbps(bytes - prev_bytes, dt),
            "file_bytes_total": bytes,
            "verified_parts": d.verified_parts,
            "verified_bytes": d.verified_parts as u64 * PARTSIZE,
            "active_sessions": d.peers.len(),
            "transferring": transferring,
            "queued": d.peers.iter().filter(|p| p.queued).count(),
            "udp_pps": ((d.udp_packets - prev_udp.0) as f64 / dt).round(),
            "udp_mbps": mbps(d.udp_bytes - prev_udp.1, dt),
            "loop_busy_pct": ((1.0 - idle.as_secs_f64() / dt).clamp(0.0, 1.0) * 1000.0).round() / 10.0,
            "cpu_core_pct": (cpu_core_pct * 10.0).round() / 10.0,
            "cpu_total_pct": (cpu_core_pct / cores * 10.0).round() / 10.0,
            "undecodable": d.undecodable, "unrouted": d.unrouted,
            "connections_opened": d.connections_opened,
            "connector": {
                "candidates": d.connector.candidates, "with_sn": d.connector.with_super_nodes,
                "online": d.connector.online, "offline": d.connector.offline,
                "connecting": d.connector.connecting, "connected_now": d.connector.connected_now,
                "registered": d.connector.registered, "discovery_finished": d.connector.discovery_finished,
            },
            "peers": peers,
        }));
        prev_bytes = bytes;
        prev_udp = (d.udp_packets, d.udp_bytes);
    };
    let total = meta.part_hashes.len();
    let out = private_pool::download_first_parts_diag(
        &cfg,
        &link,
        URI,
        &meta,
        &identity,
        total,
        |n| {
            directory_ms.get_or_insert(started.elapsed().as_millis());
            directory_peers = n;
        },
        |_: PoolProgress| {},
        &mut observer,
    );
    let elapsed = started.elapsed().as_secs_f64();
    let cpu_total = (process_cpu() - cpu_start).as_secs_f64();
    let bytes = hooks.bytes.load(Ordering::Relaxed);
    let speeds: Vec<f64> = samples
        .iter()
        .filter_map(|s| s["speed_mbps"].as_f64())
        .collect();
    let transferring: Vec<f64> = samples
        .iter()
        .filter_map(|s| s["transferring"].as_f64())
        .collect();
    let first_s = first_file_ms.unwrap_or(0) as f64 / 1000.0;
    let (verified, written, stopped, error) = match &out {
        Ok(o) => (o.verified_parts, o.written, o.stopped, None),
        Err(e) => (0, 0, false, Some(e.clone())),
    };
    let summary = json!({
        "label": label, "uri_size": link.size, "duration_s": secs, "max_connections": conns,
        "metadata_ms": metadata_ms, "directory_ms": directory_ms, "directory_peers": directory_peers,
        "first_file_ms": first_file_ms,
        "file_bytes": bytes,
        "avg_mbps_wall": mbps(bytes, elapsed),
        "avg_mbps_after_first_byte": mbps(bytes, elapsed - first_s),
        "peak_1s_mbps": speeds.iter().cloned().fold(0.0, f64::max),
        "verified_parts": verified, "verified_bytes": verified as u64 * PARTSIZE,
        "verified_mbps_wall": mbps(verified as u64 * PARTSIZE, elapsed),
        "covered_bytes_at_end": written, "stopped": stopped, "error": error,
        "max_transferring": transferring.iter().cloned().fold(0.0, f64::max),
        "avg_transferring": if transferring.is_empty() { 0.0 } else { transferring.iter().sum::<f64>() / transferring.len() as f64 },
        "cpu_core_pct_avg": (cpu_total / elapsed * 1000.0).round() / 10.0,
        "retired_count": retired.len(),
        "channels": { "private_p2p_bytes": bytes, "standard_ed2k_bytes": 0, "http_bytes": 0 },
    });
    let report = json!({ "summary": summary, "samples": samples, "retired": retired });
    let path = root.join(format!("{label}-{stamp}.json"));
    fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    let _ = fs::remove_dir_all(&work);
    println!("speed_diag {} report={}", summary, path.display());
    assert!(out.is_ok(), "{:?}", out.err());
}
