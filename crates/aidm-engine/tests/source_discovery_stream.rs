#[path = "../src/ed2k/kad_session.rs"]
#[allow(dead_code)]
mod kad_session;
#[path = "../src/ed2k/source_discovery.rs"]
#[allow(dead_code)]
mod source_discovery;

use aidm_core::ed2k::{
    peer::Packet,
    server::{self, op},
};
use source_discovery::{DiscoveryEvent, SourceDiscoveryCfg, SourceKind};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

fn read_packet(stream: &mut TcpStream) -> Packet {
    let mut header = [0; 6];
    stream.read_exact(&mut header).unwrap();
    let (protocol, len, opcode) = Packet::header(&header).unwrap();
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).unwrap();
    Packet::new(protocol, opcode, payload)
}

fn frame(opcode: u8, payload: Vec<u8>) -> Vec<u8> {
    server::packet(opcode, payload).encode()
}

fn sources(hash: [u8; 16], entries: &[([u8; 4], u16)]) -> Vec<u8> {
    let mut payload = hash.to_vec();
    payload.push(entries.len() as u8);
    for (ip, port) in entries {
        payload.extend_from_slice(ip);
        payload.extend_from_slice(&port.to_le_bytes());
    }
    frame(op::FOUNDSOURCES, payload)
}

fn cfg(hash: [u8; 16]) -> SourceDiscoveryCfg {
    SourceDiscoveryCfg {
        file_hash: hash,
        file_size: 4_478_906_368,
        user_hash: server::make_user_hash([1; 16]),
        total_budget: Duration::from_secs(2),
        server_budget: Duration::from_millis(800),
        per_server_budget: Duration::from_millis(800),
        ..SourceDiscoveryCfg::default()
    }
}

#[test]
fn fast_server_streams_sources_while_other_server_has_only_half_a_header_and_cancel_joins() {
    let slow = TcpListener::bind("127.0.0.1:0").unwrap();
    slow.set_nonblocking(true).unwrap();
    let fast = TcpListener::bind("127.0.0.1:0").unwrap();
    let slow_addr = slow.local_addr().unwrap();
    let fast_addr = fast.local_addr().unwrap();
    let server_done = Arc::new(AtomicBool::new(false));
    let stop_slow = server_done.clone();
    let slow_thread = std::thread::spawn(move || {
        let mut connection = None;
        while !stop_slow.load(Ordering::Acquire) {
            if connection.is_none() {
                if let Ok((mut stream, _)) = slow.accept() {
                    let _ = stream.write_all(&[0xe3, 5]); // permanently incomplete frame.
                    connection = Some(stream);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let hash = [8; 16];
    let stop_fast = server_done.clone();
    let fast_thread = std::thread::spawn(move || {
        let (mut stream, _) = fast.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let login = read_packet(&mut stream);
        assert_eq!(login.opcode, op::LOGINREQUEST);
        stream
            .write_all(&frame(op::IDCHANGE, 0x0100_0001u32.to_le_bytes().to_vec()))
            .unwrap();
        let query = read_packet(&mut stream);
        assert_eq!(query.opcode, op::GETSOURCES);
        assert_eq!(
            query.payload.len(),
            28,
            "large file queries retain their 64-bit size"
        );
        stream
            .write_all(&sources(hash, &[([8, 9, 10, 11], 4662)]))
            .unwrap();
        while !stop_fast.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut config = cfg(hash);
    config.servers = vec![slow_addr, fast_addr];
    config.server_parallelism = 2;
    let started = Instant::now();
    let handle = source_discovery::start(config, || false);
    match handle
        .events
        .recv_timeout(Duration::from_millis(600))
        .unwrap()
    {
        DiscoveryEvent::Source { addr, kind, .. } => {
            assert_eq!(addr.to_string(), "8.9.10.11:4662");
            assert_eq!(kind, SourceKind::Server(fast_addr));
            assert!(started.elapsed() < Duration::from_millis(600));
        }
        other => panic!("source should precede all finished events: {other:?}"),
    }
    let cancelled = Instant::now();
    let summary = handle.join().unwrap();
    assert!(summary.cancelled);
    assert_eq!(summary.unique_sources, 1);
    assert!(cancelled.elapsed() < Duration::from_millis(200));
    server_done.store(true, Ordering::Release);
    slow_thread.join().unwrap();
    fast_thread.join().unwrap();
}

#[test]
fn fragmented_login_and_multiple_batches_are_dispatched_and_deduplicated_incrementally() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = [9; 16];
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        read_packet(&mut stream);
        let response = frame(op::IDCHANGE, 0x0100_0001u32.to_le_bytes().to_vec());
        stream.write_all(&response[..3]).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        stream.write_all(&response[3..]).unwrap();
        read_packet(&mut stream);
        stream
            .write_all(&sources(hash, &[([8, 9, 10, 11], 4662)]))
            .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        stream
            .write_all(&sources(
                hash,
                &[
                    ([8, 9, 10, 11], 4662),
                    ([12, 13, 14, 15], 4663),
                    ([44, 0, 0, 0], 4664),
                ],
            ))
            .unwrap();
        std::thread::sleep(Duration::from_millis(350));
    });
    let mut config = cfg(hash);
    config.servers = vec![addr];
    let handle = source_discovery::start(config, || false);
    let mut seen = Vec::new();
    let mut server_result = None;
    loop {
        match handle.events.recv_timeout(Duration::from_secs(1)).unwrap() {
            DiscoveryEvent::Source { addr, .. } => {
                seen.push(addr);
                assert!(!handle.is_finished());
            }
            DiscoveryEvent::ServerFinished { result, .. } => server_result = Some(result.unwrap()),
            DiscoveryEvent::Finished(summary) => {
                assert_eq!(summary.unique_sources, 2);
                assert_eq!(summary.server_sources, 2);
                assert_eq!(summary.kad_sources, 0);
                assert_eq!(summary.server_errors, 0);
                break;
            }
            DiscoveryEvent::KadFinished { .. } => {
                panic!("empty Kad seeds must disable UDP entirely")
            }
        }
    }
    handle.join().unwrap();
    server.join().unwrap();
    assert_eq!(seen.len(), 2);
    let result = server_result.unwrap();
    assert_eq!(result.source_batches, 2);
    assert_eq!(result.low_id_sources, 1);
    assert_eq!(result.usable_sources, 3); // aggregate dedup belongs to the sink.
    assert!(!result.cancelled);
}

#[test]
fn dropping_consumer_or_external_stop_joins_incomplete_discovery_without_network() {
    let handle = source_discovery::start(SourceDiscoveryCfg::default(), || true);
    let started = Instant::now();
    drop(handle);
    assert!(started.elapsed() < Duration::from_millis(200));
    let mut handle = source_discovery::start(SourceDiscoveryCfg::default(), || false);
    let (_, replacement) = std::sync::mpsc::channel();
    drop(std::mem::replace(&mut handle.events, replacement));
    drop(handle); // a disconnected receiver cannot block any event send or join.
}

#[test]
fn kad_source_is_dispatched_while_server_login_is_still_silent() {
    use aidm_core::ed2k::kad::{KadId, KadNode};
    use std::net::{Ipv4Addr, UdpSocket};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_nonblocking(true).unwrap();
    let server_addr = listener.local_addr().unwrap();
    let hash = [7; 16];
    let mut id = hash;
    id[0] ^= 1;
    let seed = KadNode {
        id: KadId(id),
        ip: Ipv4Addr::LOCALHOST,
        udp_port: udp.local_addr().unwrap().port(),
        tcp_port: 4662,
        version: 9,
        udp_key: None,
        key_ip: None,
        verified: false,
    };
    let finished = Arc::new(AtomicBool::new(false));
    let tcp_stop = finished.clone();
    let tcp = std::thread::spawn(move || {
        let mut connection = None;
        while !tcp_stop.load(Ordering::Acquire) {
            if connection.is_none() {
                if let Ok((stream, _)) = listener.accept() {
                    connection = Some(stream);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let udp_stop = finished.clone();
    let kad = std::thread::spawn(move || {
        let mut buf = [0; 1024];
        while !udp_stop.load(Ordering::Acquire) {
            if let Ok((_, client)) = udp.recv_from(&mut buf) {
                let mut packet = vec![0xe4];
                match buf[1] {
                    0x01 => {
                        packet.push(0x09);
                        packet.extend_from_slice(&id);
                        packet.extend_from_slice(&4662u16.to_le_bytes());
                        packet.push(9);
                        packet.extend_from_slice(&0u16.to_le_bytes());
                    }
                    0x34 => {
                        packet.push(0x3b);
                        packet.extend_from_slice(&id);
                        packet.extend_from_slice(&hash);
                        packet.extend_from_slice(&1u16.to_le_bytes());
                        packet.extend_from_slice(&[2; 16]);
                        packet.push(3);
                        for (name, value) in [(0xffu8, 4u32), (0xfe, 0x0809_0a0b), (0xfd, 4662)] {
                            packet.extend_from_slice(&[3, 1, 0, name]);
                            packet.extend_from_slice(&value.to_le_bytes());
                        }
                    }
                    0x21 => continue,
                    _ => unreachable!(),
                }
                udp.send_to(&packet, client).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let mut config = cfg(hash);
    config.servers = vec![server_addr];
    config.kad_seeds = vec![seed];
    config.kad_cfg.allow_private_addresses = true;
    config.kad_cfg.bootstrap_requests = 1;
    config.kad_cfg.request_timeout = Duration::from_millis(600);
    let started = Instant::now();
    let handle = source_discovery::start(config, || false);
    match handle
        .events
        .recv_timeout(Duration::from_millis(500))
        .unwrap()
    {
        DiscoveryEvent::Source {
            kind,
            addr,
            user_hash,
        } => {
            assert_eq!(kind, SourceKind::Kad);
            assert_eq!(addr.to_string(), "8.9.10.11:4662");
            assert_eq!(user_hash, Some([2; 16]));
            assert!(started.elapsed() < Duration::from_millis(500));
        }
        other => panic!("Kad source was held behind the silent server: {other:?}"),
    }
    let summary = handle.join().unwrap();
    assert_eq!(summary.kad_sources, 1);
    finished.store(true, Ordering::Release);
    tcp.join().unwrap();
    kad.join().unwrap();
}
