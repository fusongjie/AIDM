//! Explicit original-ISO private multi-source throughput and piece verification.
use aidm_core::ed2k::{hash, peer::PARTSIZE};
use aidm_engine::ed2k::{
    multi_source::{MultiSourceCfg, TransferHooks},
    private_index, private_pool,
};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
struct Hooks {
    active: AtomicUsize,
    peak: AtomicUsize,
    bytes: AtomicU64,
}
impl TransferHooks for Hooks {
    fn try_acquire_connection(&self) -> bool {
        let n = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        true
    }
    fn release_connection(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
    fn received(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::SeqCst);
    }
}
#[test]
#[ignore = "explicit public multi-source transfer; 16 pieces or AIDM_PRIVATE_FULL_ISO=1 for whole ISO"]
fn sixteen_distinct_pieces_use_shared_private_connections_and_match_the_original_hashset() {
    let full = std::env::var_os("AIDM_PRIVATE_FULL_ISO").is_some();
    let uri="ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
    let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link(uri).unwrap() else {
        panic!("file")
    };
    let identity = private_index::peer_id(&[0x56; 16]);
    let started = Instant::now();
    let meta = private_index::query(&link, uri, &identity)
        .unwrap()
        .unwrap();
    let dir = std::env::current_dir()
        .unwrap()
        .join("target-check")
        .join(format!("private-pool-live-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let target = dir.join(if full { "original.iso" } else { "prefix.part" });
    let hooks = Hooks {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        bytes: AtomicU64::new(0),
    };
    let stop = || started.elapsed() > Duration::from_secs(if full { 600 } else { 45 });
    let events = |_| {};
    let cfg = MultiSourceCfg {
        user_hash: [0x56; 16],
        file_hash: link.hash,
        file_size: link.size,
        target: &target,
        max_connections: 32,
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
    let (mut first, mut last_log, mut peak_transferring) = (None, Instant::now(), 0);
    let mut update = |p: aidm_engine::ed2k::multi_source::PoolProgress| {
        if p.done > 0 {
            first.get_or_insert(started.elapsed().as_millis());
        }
        peak_transferring = peak_transferring.max(p.transferring_peers);
        if last_log.elapsed() > Duration::from_secs(1) {
            println!("private_pool_progress ms={} bytes={} verified={} active={} transferring={} verifying={}", started.elapsed().as_millis(), p.done, p.verified_parts, p.active_peers, p.transferring_peers, p.verifying);
            last_log = Instant::now();
        }
    };
    let out = if full {
        private_pool::download(
            &cfg,
            &link,
            uri,
            &meta,
            &identity,
            |n| println!("private_directory_sources={n}"),
            &mut update,
        )
    } else {
        private_pool::download_first_parts(
            &cfg,
            &link,
            uri,
            &meta,
            &identity,
            16,
            |n| println!("private_directory_sources={n}"),
            &mut update,
        )
    }
    .unwrap();
    assert!(!out.stopped);
    let goal = if full { meta.part_hashes.len() } else { 16 };
    assert_eq!(out.verified_parts, goal);
    assert_eq!(out.written, if full { link.size } else { 16 * PARTSIZE });
    assert!(peak_transferring >= 2);
    assert!(hooks.peak.load(Ordering::SeqCst) <= 32);
    assert_eq!(hooks.active.load(Ordering::SeqCst), 0);
    let mut file = File::open(&target).unwrap();
    let mut piece = vec![0; PARTSIZE as usize];
    for i in 0..goal {
        file.seek(SeekFrom::Start(i as u64 * PARTSIZE)).unwrap();
        let len = (link.size - i as u64 * PARTSIZE).min(PARTSIZE) as usize;
        file.read_exact(&mut piece[..len]).unwrap();
        assert_eq!(hash::md4(&piece[..len]), meta.part_hashes[i]);
    }
    if full {
        let digest = hash::hash_file(hash::Flavor::Official, &target).unwrap();
        assert_eq!(digest.file, link.hash);
        println!("independent_whole_file_ed2k={}", digest.file_hex());
    }
    println!("independent_rust_private_pool first_file_ms={} finished_ms={} file_bytes={} verified_distinct_pieces={} peak_transferring={} task_cap=32 peak_permits={} network_bytes={} artifact={}",first.unwrap(),started.elapsed().as_millis(),out.written,goal,peak_transferring,hooks.peak.load(Ordering::SeqCst),hooks.bytes.load(Ordering::SeqCst),target.display());
}
