//! TCP peer acceptance tests: the mock enforces eMule wire limits and serves real
//! content/hashsets, rather than bypassing the download state machine.
mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aidm_core::ed2k::peer::{
    ed2k, emule, AichRequest, FileStatus, HelloInfo, MiscOptions1, Packet, PartRange, Protocol,
    RequestParts, SendingPart, TagValue, EMBLOCKSIZE, PARTSIZE,
};
use aidm_core::ed2k::{
    hash::{hash_reader, Ed2kDigest},
    Flavor,
};
use aidm_engine::ed2k::{download_from_peer, PeerDownload, PeerSessionCfg};

struct Target {
    path: PathBuf,
    /// 持有 tempdir：Drop 时自动删除整个目录。
    _tmp: tempfile::TempDir,
}
impl Target {
    fn new() -> Self {
        let tmp = common::tempdir("ed2k-peer");
        let path = tmp.path().join("download.bin");
        Self { path, _tmp: tmp }
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
    }
}

#[derive(Clone, Copy, Default)]
struct Mode {
    reorder_and_duplicate: bool,
    corrupt_first_block: bool,
    stop_after_one_block: bool,
    queue_delay_ms: u64,
    transfer_pause_ms: u64,
    /// 是否声明并应答 AICH：true 时 HELLOANSWER 带 aich_version=1，且 OP_AICHREQUEST
    /// 用真实内容生成恢复数据；false 时回 16 字节 Failed（测"退回整片重下"）。
    answer_aich: bool,
}

fn recv(stream: &mut TcpStream) -> Option<Packet> {
    let mut header = [0; 6];
    stream.read_exact(&mut header).ok()?;
    let (protocol, len, opcode) = Packet::header(&header).unwrap();
    let mut body = vec![0; len];
    stream.read_exact(&mut body).unwrap();
    Some(Packet::new(protocol, opcode, body))
}

fn send(stream: &mut TcpStream, protocol: Protocol, opcode: u8, body: Vec<u8>) {
    stream
        .write_all(&Packet::new(protocol, opcode, body).encode())
        .unwrap();
}

fn content(size: usize) -> Arc<Vec<u8>> {
    Arc::new(
        (0..size)
            .map(|i| ((i * 37 + i / 251 + 17) % 256) as u8)
            .collect(),
    )
}

fn digest(data: &[u8]) -> Ed2kDigest {
    hash_reader(Flavor::Official, data).unwrap()
}

fn peer(data: Arc<Vec<u8>>, mode: Mode) -> (SocketAddr, JoinHandle<Vec<PartRange>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let d = digest(&data);
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut requested = Vec::new();
        let mut corrupted = false;
        let mut transfer_paused = false;
        let mut sent_payload = false;
        while let Some(p) = recv(&mut stream) {
            match (p.protocol, p.opcode) {
                (Protocol::Edonkey, ed2k::HELLO) => {
                    let hello = HelloInfo::decode(ed2k::HELLO, &p.payload).unwrap();
                    let caps =
                        MiscOptions1::from_u32(hello.tag(0xFA).unwrap().as_u64().unwrap() as u32);
                    assert_eq!(
                        caps.data_compression, 0,
                        "mock sends uncompressed data only when negotiated"
                    );
                    assert_eq!(caps.ext_requests, 0);
                    let mut answer = hello.encode(true);
                    if mode.answer_aich {
                        // 声明 aich_version=1：客户端据此才会发 OP_AICHREQUEST。
                        let mut reply = HelloInfo::decode(ed2k::HELLOANSWER, &answer).unwrap();
                        for tag in reply.tags.iter_mut() {
                            if tag.name_id() == Some(0xFA) {
                                let patched = MiscOptions1 {
                                    aich_version: 1,
                                    ..caps
                                };
                                tag.value = TagValue::Uint(patched.to_u32() as u64);
                            }
                        }
                        answer = reply.encode(true);
                    }
                    send(&mut stream, Protocol::Edonkey, ed2k::HELLOANSWER, answer);
                }
                (Protocol::Edonkey, ed2k::REQUESTFILENAME) => {
                    assert_eq!(p.payload, d.file, "no extension fields were negotiated");
                    let name = b"peer-download.bin";
                    let mut body = d.file.to_vec();
                    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
                    body.extend_from_slice(name);
                    send(
                        &mut stream,
                        Protocol::Edonkey,
                        ed2k::REQFILENAMEANSWER,
                        body,
                    );
                }
                (Protocol::Edonkey, ed2k::HASHSETREQUEST) => {
                    let mut body = d.file.to_vec();
                    body.extend_from_slice(&(d.parts.len() as u16).to_le_bytes());
                    for hash in &d.parts {
                        body.extend_from_slice(hash);
                    }
                    send(&mut stream, Protocol::Edonkey, ed2k::HASHSETANSWER, body);
                }
                (Protocol::Edonkey, ed2k::SETREQFILEID) => send(
                    &mut stream,
                    Protocol::Edonkey,
                    ed2k::FILESTATUS,
                    FileStatus::complete(d.file, data.len() as u64).encode(),
                ),
                (Protocol::Edonkey, ed2k::STARTUPLOADREQ) => {
                    if mode.queue_delay_ms > 0 {
                        send(
                            &mut stream,
                            Protocol::Edonkey,
                            ed2k::QUEUERANK,
                            1u32.to_le_bytes().to_vec(),
                        );
                        thread::sleep(Duration::from_millis(mode.queue_delay_ms));
                    }
                    send(
                        &mut stream,
                        Protocol::Edonkey,
                        ed2k::ACCEPTUPLOADREQ,
                        vec![],
                    );
                }
                (Protocol::Edonkey, ed2k::REQUESTPARTS)
                | (Protocol::Emule, emule::REQUESTPARTS_I64) => {
                    let mut request = RequestParts::decode(p.opcode, &p.payload).unwrap();
                    assert_eq!(request.file_hash, d.file);
                    assert!(request.ranges.len() <= 3);
                    for r in &request.ranges {
                        assert!(
                            r.len() <= EMBLOCKSIZE,
                            "eMule rejects oversized requested blocks"
                        );
                        assert!(r.end <= data.len() as u64);
                        assert_eq!(r.start / PARTSIZE, (r.end - 1) / PARTSIZE);
                    }
                    requested.extend(request.ranges.clone());
                    if mode.reorder_and_duplicate || mode.stop_after_one_block {
                        request.ranges.reverse();
                    }
                    for r in request.ranges {
                        if sent_payload && !transfer_paused && mode.transfer_pause_ms > 0 {
                            transfer_paused = true;
                            thread::sleep(Duration::from_millis(mode.transfer_pause_ms));
                        }
                        let mut chunks: Vec<PartRange> = if mode.reorder_and_duplicate {
                            (r.start..r.end)
                                .step_by(10240)
                                .map(|start| PartRange {
                                    start,
                                    end: (start + 10240).min(r.end),
                                })
                                .collect()
                        } else {
                            vec![r.clone()]
                        };
                        if mode.reorder_and_duplicate {
                            chunks.reverse();
                        }
                        for chunk in chunks {
                            let mut bytes = data[chunk.start as usize..chunk.end as usize].to_vec();
                            if mode.corrupt_first_block && !corrupted && chunk.start == 0 {
                                bytes[0] ^= 0xFF;
                                corrupted = true;
                            }
                            let sp = SendingPart {
                                file_hash: d.file,
                                start: chunk.start,
                                end: chunk.end,
                                data: bytes,
                            };
                            let (op, body) = sp.encode();
                            send(&mut stream, Protocol::Edonkey, op, body.clone());
                            sent_payload = true;
                            if mode.reorder_and_duplicate {
                                send(&mut stream, Protocol::Edonkey, op, body);
                            }
                        }
                        if mode.stop_after_one_block {
                            break;
                        }
                    }
                }
                (Protocol::Emule, emule::AICHREQUEST) => {
                    let request = AichRequest::decode(&p.payload).unwrap();
                    assert_eq!(request.file_hash, d.file);
                    if !mode.answer_aich {
                        // 定长 16 字节 = "我没有/根不匹配"：客户端必须退回整片重下。
                        send(
                            &mut stream,
                            Protocol::Emule,
                            emule::AICHANSWER,
                            d.file.to_vec(),
                        );
                        continue;
                    }
                    let part_start = u64::from(request.part) * PARTSIZE;
                    let part_size = (data.len() as u64).saturating_sub(part_start).min(PARTSIZE);
                    // 恢复数据用**真实内容**生成：客户端据此定位自己被污染的块。
                    let tree = aidm_core::ed2k::aich::Tree::from_data(&data);
                    let entries = tree
                        .create_recovery(part_start, part_size, data.len() as u64 > u32::MAX as u64)
                        .unwrap();
                    let mut body = request.encode();
                    body.extend_from_slice(&aidm_core::ed2k::aich::encode_recovery(&entries));
                    send(&mut stream, Protocol::Emule, emule::AICHANSWER, body);
                }
                (Protocol::Edonkey, ed2k::END_OF_DOWNLOAD) => break,
                (Protocol::Emule, emule::REQUESTSOURCES2) => {
                    // 源交换请求合法但本用例无新增源：回空应答，保持严格 mock。
                    let mut v = vec![1u8];
                    v.extend_from_slice(&d.file);
                    v.extend_from_slice(&0u16.to_le_bytes());
                    send(&mut stream, Protocol::Emule, emule::ANSWERSOURCES2, v);
                }
                _ => panic!(
                    "unexpected protocol/opcode {:?}/0x{:02X}",
                    p.protocol, p.opcode
                ),
            }
        }
        requested
    });
    (addr, handle)
}

fn download(addr: SocketAddr, data: &[u8], target: &Target) -> (PeerDownload, Vec<u64>) {
    let mut progress = Vec::new();
    let result = download_from_peer(
        &PeerSessionCfg {
            addr,
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: digest(data).file,
            file_size: data.len() as u64,
            target: &target.path,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            stop: &|| false,
            aich_root: None,
        },
        |n| progress.push(n),
    )
    .unwrap();
    (result, progress)
}

#[test]
fn downloads_large_file_with_split_out_of_order_and_duplicate_blocks() {
    let data = content((EMBLOCKSIZE * 4 + 12345) as usize);
    let target = Target::new();
    let (addr, server) = peer(
        data.clone(),
        Mode {
            reorder_and_duplicate: true,
            ..Mode::default()
        },
    );
    let (result, progress) = download(addr, &data, &target);
    let requests = server.join().unwrap();
    assert_eq!(std::fs::read(&target.path).unwrap(), *data);
    assert!(result.is_complete());
    assert_eq!(result.written, data.len() as u64);
    assert_eq!(
        requests.iter().map(PartRange::len).sum::<u64>(),
        data.len() as u64
    );
    assert!(progress.windows(2).all(|w| w[1] >= w[0]));
    assert!(progress.iter().all(|n| *n <= data.len() as u64));
    assert_eq!(progress[1], 10240, "high offsets must not inflate progress");
}

#[test]
fn both_download_paths_keep_a_useful_peer_across_multiple_idle_read_timeouts() {
    use aidm_engine::ed2k::multi_source::{download_from_sources, MultiSourceCfg, TransferHooks};
    struct Hooks;
    impl TransferHooks for Hooks {
        fn try_acquire_connection(&self) -> bool {
            true
        }
        fn release_connection(&self) {}
        fn received(&self, _: u64) {}
    }
    let data = content((EMBLOCKSIZE * 4 + 12345) as usize);
    for multi_source in [false, true] {
        let target = Target::new();
        let (addr, server) = peer(
            data.clone(),
            Mode {
                transfer_pause_ms: 350,
                ..Default::default()
            },
        );
        let cfg = PeerSessionCfg {
            addr,
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: digest(&data).file,
            file_size: data.len() as u64,
            target: &target.path,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_millis(80),
            stop: &|| false,
            aich_root: None,
        };
        if multi_source {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(addr).unwrap();
            drop(tx);
            let out = download_from_sources(
                &MultiSourceCfg {
                    user_hash: cfg.user_hash,
                    file_hash: cfg.file_hash,
                    file_size: cfg.file_size,
                    target: cfg.target,
                    max_connections: 1,
                    connect_timeout: cfg.connect_timeout,
                    read_timeout: cfg.read_timeout,
                    discovery_timeout: Duration::from_secs(2),
                    stop: &|| false,
                    aich_root: None,
                    hooks: &Hooks,
                    on_event: &|_| {},
                    xs_sources: None,
                    feed_done: None,
                    part_filter: None,
                    expansion: None,
                    on_ownership: None,
                    claim_base: 1,
                    claim_reserve: 4096,
                    claim_refill: None,
                },
                rx,
                |_| {},
            )
            .unwrap();
            assert!(out.is_complete());
        } else {
            assert!(download_from_peer(&cfg, |_| {}).unwrap().is_complete());
        }
        let requests = server.join().unwrap();
        assert_eq!(std::fs::read(&target.path).unwrap(), *data);
        assert_eq!(
            requests.iter().map(PartRange::len).sum::<u64>(),
            data.len() as u64,
            "idle waits must not discard and request already received blocks again"
        );
    }
}

#[test]
fn verifies_multi_part_hashset_and_redownloads_corrupt_part() {
    let data = content((PARTSIZE + 65537) as usize);
    let target = Target::new();
    let (addr, server) = peer(
        data.clone(),
        Mode {
            corrupt_first_block: true,
            ..Mode::default()
        },
    );
    let (result, _) = download(addr, &data, &target);
    let requests = server.join().unwrap();
    assert_eq!(std::fs::read(&target.path).unwrap(), *data);
    assert!(result.has_hashset && result.is_complete());
    assert_eq!(result.parts_done, 2);
    assert_eq!(result.corrupt_parts, 1);
    assert_eq!(requests.iter().filter(|r| r.start == 0).count(), 2);
}

#[test]
fn resume_verifies_existing_parts_instead_of_trusting_length_or_sparse_holes() {
    let data = content((PARTSIZE + 65537) as usize);
    for variant in ["sparse", "wrong-file", "valid-prefix"] {
        let target = Target::new();
        let mut existing = std::fs::File::create(&target.path).unwrap();
        if variant == "valid-prefix" {
            existing.write_all(&data[..PARTSIZE as usize]).unwrap();
        } else {
            existing.set_len(data.len() as u64 + 17).unwrap();
            if variant == "wrong-file" {
                existing.write_all(&vec![0xF1; PARTSIZE as usize]).unwrap();
            }
            existing.seek(SeekFrom::Start(PARTSIZE)).unwrap();
            existing.write_all(&data[PARTSIZE as usize..]).unwrap();
        }
        drop(existing);
        let (addr, server) = peer(data.clone(), Mode::default());
        let (result, progress) = download(addr, &data, &target);
        let requests = server.join().unwrap();
        assert_eq!(std::fs::read(&target.path).unwrap(), *data, "{variant}");
        assert!(result.is_complete(), "{variant}");
        if variant == "valid-prefix" {
            assert!(requests.iter().all(|r| r.start >= PARTSIZE));
            assert_eq!(progress[0], PARTSIZE);
        } else {
            assert!(
                requests.iter().any(|r| r.start == 0),
                "must fill unverified holes: {variant}"
            );
            assert_eq!(
                progress[0], 65537,
                "only the validated tail can be resumed: {variant}"
            );
        }
    }
}

#[test]
fn stopped_sparse_transfer_reports_received_bytes_instead_of_highest_offset() {
    let data = content((EMBLOCKSIZE * 4) as usize);
    let target = Target::new();
    let (addr, server) = peer(
        data.clone(),
        Mode {
            stop_after_one_block: true,
            ..Mode::default()
        },
    );
    let stop = AtomicBool::new(false);
    let result = download_from_peer(
        &PeerSessionCfg {
            addr,
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: digest(&data).file,
            file_size: data.len() as u64,
            target: &target.path,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            stop: &|| stop.load(Ordering::Relaxed),
            aich_root: None,
        },
        |n| {
            if n > 0 {
                stop.store(true, Ordering::Relaxed);
            }
        },
    )
    .unwrap();
    server.join().unwrap();
    assert!(result.stopped && !result.is_complete());
    assert_eq!(result.written, EMBLOCKSIZE);
    assert_eq!(result.parts_done, 0);
    assert_eq!(
        std::fs::metadata(&target.path).unwrap().len(),
        EMBLOCKSIZE * 3
    );
}

#[test]
fn queued_peer_can_accept_after_multiple_idle_read_timeouts() {
    let data = content(8193);
    let target = Target::new();
    let (addr, server) = peer(
        data.clone(),
        Mode {
            queue_delay_ms: 550,
            ..Mode::default()
        },
    );
    let result = download_from_peer(
        &PeerSessionCfg {
            addr,
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: digest(&data).file,
            file_size: data.len() as u64,
            target: &target.path,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_millis(100),
            stop: &|| false,
            aich_root: None,
        },
        |_| {},
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(result.queue_rank, Some(1));
    assert!(result.is_complete());
    assert_eq!(std::fs::read(&target.path).unwrap(), *data);
}

#[test]
fn queued_wire_preserves_eof_and_partial_frame_errors() {
    for header in [vec![], vec![Protocol::Edonkey as u8, 1]] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&header).unwrap();
        });
        let mut connection = aidm_engine::ed2k::wire::Conn::connect(
            addr,
            Duration::from_secs(2),
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(
            connection.recv_idle().is_err(),
            "closed/partial frames must not be treated as idle"
        );
        server.join().unwrap();
    }
}

#[test]
fn wire_rejects_truncated_header_instead_of_clean_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&[Protocol::Edonkey as u8, 1]).unwrap();
    });
    let mut connection = aidm_engine::ed2k::wire::Conn::connect(
        addr,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(
        connection.recv_opt().unwrap_err(),
        "ed2k_read_header: truncated eof"
    );
    server.join().unwrap();
}

// ---------- AICH 块级重下 ----------

/// 带可信 AICH 根跑一次单源下载。
fn download_with_aich(
    addr: SocketAddr,
    data: &[u8],
    target: &Target,
    aich_root: [u8; 20],
) -> Result<(PeerDownload, Vec<u64>), String> {
    let mut progress = Vec::new();
    let result = download_from_peer(
        &PeerSessionCfg {
            addr,
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: digest(data).file,
            file_size: data.len() as u64,
            target: &target.path,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            stop: &|| false,
            aich_root: Some(aich_root),
        },
        |n| progress.push(n),
    )?;
    Ok((result, progress))
}

/// 多分片文件：只有分片 MD4 才会发现"块被污染"，因此 AICH 用例必须是多分片。
fn aich_fixture() -> (Vec<u8>, [u8; 20]) {
    let data = content((PARTSIZE + EMBLOCKSIZE * 6) as usize);
    let root = aidm_core::ed2k::aich::Tree::from_data(&data)
        .hash()
        .unwrap();
    ((*data).clone(), root)
}

/// 分片 MD4 失败时，AICH 应把重下范围精确到**损坏的 180 KiB 块**，而不是整个分片。
#[test]
fn aich_recovery_redownloads_only_the_corrupt_block() {
    let (data, root) = aich_fixture();
    let target = Target::new();
    let (addr, server) = peer(
        Arc::new(data.clone()),
        Mode {
            corrupt_first_block: true,
            answer_aich: true,
            ..Mode::default()
        },
    );
    let (result, _progress) = download_with_aich(addr, &data, &target, root).unwrap();
    let requests = server.join().unwrap();

    assert!(result.is_complete());
    assert_eq!(std::fs::read(&target.path).unwrap(), data);
    assert_eq!(result.aich_recovered_blocks, 1, "应当正好定位到 1 个损坏块");
    // 整份文件下完一次 + 坏块重下一次；恢复期间被丢掉的在途请求（至多 2 块）会一起补下。
    let full = PARTSIZE + EMBLOCKSIZE * 6;
    let total = requests.iter().map(PartRange::len).sum::<u64>();
    assert!(total > full, "坏块必须被重下");
    assert!(
        total <= full + EMBLOCKSIZE * 3,
        "只该重下坏块（外加丢掉的在途块），实际 {total}"
    );
    assert!(
        total < full + PARTSIZE,
        "绝不能退化成整片重下（整片 = {PARTSIZE} 字节）"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.start == 0 && r.end == EMBLOCKSIZE)
            .count(),
        2,
        "第 0 块应先发一次（被污染）再由 AICH 精确重下一次"
    );
}

/// 对端不应答 AICH（16 字节 Failed）时必须退回整片重下，且如实报告没用到块级恢复。
#[test]
fn aich_unavailable_falls_back_to_whole_part() {
    let (data, root) = aich_fixture();
    let target = Target::new();
    let (addr, server) = peer(
        Arc::new(data.clone()),
        Mode {
            corrupt_first_block: true,
            answer_aich: false,
            ..Mode::default()
        },
    );
    let (result, _progress) = download_with_aich(addr, &data, &target, root).unwrap();
    let requests = server.join().unwrap();

    assert!(result.is_complete());
    assert_eq!(std::fs::read(&target.path).unwrap(), data);
    assert_eq!(result.aich_recovered_blocks, 0);
    // 整片（PARTSIZE）重下一次：首次全文件 + 重下 part0
    assert_eq!(
        requests.iter().map(PartRange::len).sum::<u64>(),
        2 * PARTSIZE + EMBLOCKSIZE * 6
    );
}
