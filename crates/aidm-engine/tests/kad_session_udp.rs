//! Real UDP socket tests: wire compatibility, iterative discovery, packed
//! source results, endpoint/target matching, cancellation, and hard budgets.

#[path = "../src/ed2k/kad_session.rs"]
mod kad_session;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use aidm_core::ed2k::kad::{KadId, KadNode};
use flate2::{write::ZlibEncoder, Compression};
use kad_session::{lookup_sources_with_config, KadLookupCfg};

fn node(socket: &UdpSocket, id: [u8; 16]) -> KadNode {
    KadNode {
        id: KadId(id),
        ip: Ipv4Addr::LOCALHOST,
        udp_port: socket.local_addr().unwrap().port(),
        tcp_port: 4662,
        version: 9,
        udp_key: None,
        key_ip: None,
        verified: false,
    }
}

fn wire_hash(mut hash: [u8; 16]) -> [u8; 16] {
    for word in hash.chunks_exact_mut(4) {
        word.reverse();
    }
    hash
}

fn config() -> KadLookupCfg {
    KadLookupCfg {
        timeout: Duration::from_secs(2),
        request_timeout: Duration::from_millis(80),
        bootstrap_requests: 1,
        lookup_requests: 8,
        source_requests: 8,
        allow_private_addresses: true,
        ..KadLookupCfg::default()
    }
}

fn record(out: &mut Vec<u8>, node: &KadNode) {
    out.extend_from_slice(&node.id.0);
    out.extend_from_slice(&u32::from(node.ip).to_le_bytes());
    out.extend_from_slice(&node.udp_port.to_le_bytes());
    out.extend_from_slice(&node.tcp_port.to_le_bytes());
    out.push(node.version);
}

fn int_tag(out: &mut Vec<u8>, name: u8, value: u32) {
    out.extend_from_slice(&[0x03, 1, 0, name]);
    out.extend_from_slice(&value.to_le_bytes());
}

fn result_entry(out: &mut Vec<u8>, source_type: u32, crypto: u32, port: u32) {
    // Source answerID is CUInt128(user hash); convert it back before returning.
    out.extend_from_slice(&wire_hash([
        0x15, 2, 3, 4, 5, 0x0e, 7, 8, 9, 10, 11, 12, 13, 14, 0x6f, 16,
    ]));
    out.push(6);
    int_tag(out, 0xff, source_type);
    int_tag(out, 0xfe, u32::from(Ipv4Addr::new(8, 9, 10, 11)));
    int_tag(out, 0xfd, port);
    int_tag(out, 0xfc, 4672);
    int_tag(out, 0xf3, crypto);
    // Unknown but well-formed string tags must be skipped by type and length.
    out.extend_from_slice(&[2, 1, 0, 1, 4, 0, b't', b'e', b's', b't']);
}

#[test]
fn discovers_via_bootstrap_walks_closer_and_decodes_packed_high_id_sources() {
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let closer = UdpSocket::bind("127.0.0.1:0").unwrap();
    first.set_nonblocking(true).unwrap();
    closer.set_nonblocking(true).unwrap();
    let hash = [
        0xe7, 0xc5, 0x26, 0x49, 0x93, 0x08, 0x84, 0x1a, 0x4a, 0x6d, 0x11, 0x6c, 0x85, 0x7d, 0xb6,
        0x69,
    ];
    let target = wire_hash(hash);
    assert_eq!(&target[..4], &[0x49, 0x26, 0xc5, 0xe7]);
    let first_node = node(&first, [0xdd; 16]);
    let mut closer_id = target;
    closer_id[0] ^= 1;
    let closer_node = node(&closer, closer_id);
    let seed = node(&first, [0xcc; 16]); // bootstrap must refresh this stale ID.
    let done = Arc::new(AtomicBool::new(false));
    let stop_server = done.clone();
    let server = std::thread::spawn(move || {
        let mut buffer = [0; 2048];
        let mut seen_lookup = 0;
        let mut seen_source = 0;
        while !stop_server.load(Ordering::Relaxed) {
            for (socket, me) in [(&first, &first_node), (&closer, &closer_node)] {
                let Ok((len, client)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                assert_eq!(buffer[0], 0xe4);
                let mut packet = Vec::new();
                match buffer[1] {
                    0x01 => {
                        assert_eq!(len, 2, "bootstrap request has an empty body");
                        packet.extend_from_slice(&[0xe4, 0x09]);
                        packet.extend_from_slice(&me.id.0);
                        packet.extend_from_slice(&4662u16.to_le_bytes());
                        packet.push(9);
                        packet.extend_from_slice(&1u16.to_le_bytes());
                        record(&mut packet, &closer_node);
                    }
                    0x21 => {
                        assert_eq!(len, 35);
                        assert_eq!(buffer[2], 0x0b);
                        assert_eq!(&buffer[3..19], &target);
                        assert_eq!(
                            &buffer[19..35],
                            &me.id.0,
                            "receiver ID must be current remote ID"
                        );
                        seen_lookup += 1;
                        packet.extend_from_slice(&[0xe4, 0x29]);
                        packet.extend_from_slice(&target);
                        packet.push(0); // u8 count, not u16.
                    }
                    0x34 => {
                        assert_eq!(len, 28);
                        assert_eq!(&buffer[2..18], &target);
                        assert_eq!(&buffer[18..20], &[0, 0]);
                        assert_eq!(
                            u64::from_le_bytes(buffer[20..28].try_into().unwrap()),
                            4_478_906_368
                        );
                        seen_source += 1;
                        let mut body = Vec::new();
                        body.extend_from_slice(&me.id.0);
                        body.extend_from_slice(&target);
                        body.extend_from_slice(&4u16.to_le_bytes());
                        result_entry(&mut body, 4, 1, 4662);
                        result_entry(&mut body, 4, 1, 4662); // duplicate is returned only once.
                        result_entry(&mut body, 6, 0, 4663); // needs UDP callback.
                        result_entry(&mut body, 4, 4, 4664); // requires obfuscation.
                                                             // A valid-looking answer from an unrequested UDP port
                                                             // must not add its otherwise connectable source.
                        let mut spoof_body = Vec::new();
                        spoof_body.extend_from_slice(&me.id.0);
                        spoof_body.extend_from_slice(&target);
                        spoof_body.extend_from_slice(&1u16.to_le_bytes());
                        result_entry(&mut spoof_body, 4, 0, 5555);
                        let mut spoof = vec![0xe4, 0x3b];
                        spoof.extend_from_slice(&spoof_body);
                        let unrelated = UdpSocket::bind("127.0.0.1:0").unwrap();
                        unrelated.send_to(&spoof, client).unwrap();
                        let mut wrong_target = vec![0xe4, 0x3b];
                        wrong_target.extend_from_slice(&body);
                        wrong_target[18] ^= 1;
                        socket.send_to(&wrong_target, client).unwrap();
                        let mut bomb = ZlibEncoder::new(Vec::new(), Compression::default());
                        bomb.write_all(&vec![0; 70_000]).unwrap();
                        let mut bomb_packet = vec![0xe5, 0x3b];
                        bomb_packet.extend_from_slice(&bomb.finish().unwrap());
                        socket.send_to(&bomb_packet, client).unwrap();
                        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                        encoder.write_all(&body).unwrap();
                        packet.extend_from_slice(&[0xe5, 0x3b]);
                        packet.extend_from_slice(&encoder.finish().unwrap());
                    }
                    other => panic!("unexpected outbound opcode {other:02x}"),
                }
                socket.send_to(&packet, client).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        (seen_lookup, seen_source)
    });
    let result =
        lookup_sources_with_config(&hash, 4_478_906_368, &[seed], &config(), || false).unwrap();
    done.store(true, Ordering::Relaxed);
    let (seen_lookup, seen_source) = server.join().unwrap();
    assert_eq!((seen_lookup, seen_source), (2, 2));
    assert_eq!(result.bootstrap_replies, 1);
    assert_eq!(result.lookup_replies, 2);
    assert_eq!(result.source_replies, 2);
    assert_eq!(result.sources.len(), 1);
    assert_eq!(result.sources[0].ip, Ipv4Addr::new(8, 9, 10, 11));
    assert_eq!(result.sources[0].port, 4662);
    assert_eq!(result.sources[0].user_hash[0], 0x15);
    assert_eq!(result.skipped_callback_sources, 2);
    assert_eq!(result.skipped_crypto_sources, 2);
    assert!(
        result.malformed_packets >= 2,
        "wrong-target replies must not be accepted"
    );
    assert!(!result.cancelled);
}

#[test]
fn cancellation_is_observed_before_socket_creation_and_during_receive_wait() {
    assert!(kad_session::lookup_sources(&[1; 16], 3, &[], || false)
        .unwrap()
        .sources
        .is_empty());
    let mut cfg = config();
    cfg.bind_addr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 1234);
    let result = lookup_sources_with_config(&[1; 16], 3, &[], &cfg, || true).unwrap();
    assert!(result.cancelled);
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let seed = node(&silent, [1; 16]);
    let started = Instant::now();
    let result = lookup_sources_with_config(&[2; 16], 3, &[seed], &config(), || {
        started.elapsed() > Duration::from_millis(30)
    })
    .unwrap();
    assert!(result.cancelled);
    assert!(started.elapsed() < Duration::from_millis(300));
}

#[test]
fn silent_nodes_respect_packet_budget_and_deadline() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let seed = node(&silent, [1; 16]);
    let mut cfg = config();
    cfg.timeout = Duration::from_millis(120);
    cfg.bootstrap_requests = 0;
    cfg.lookup_requests = 1;
    cfg.source_requests = 0;
    let result = lookup_sources_with_config(&[2; 16], 3, &[seed], &cfg, || false).unwrap();
    assert_eq!(result.lookup_sent, 1);
    assert_eq!(result.bootstrap_sent + result.source_sent, 0);
    assert!(result.elapsed < Duration::from_millis(400));
    assert!(result.sources.is_empty());
}

#[test]
fn streaming_delivers_source_before_silent_node_lookup_finishes() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let hash = [7; 16];
    let target = wire_hash(hash);
    let mut id = target;
    id[0] ^= 1;
    let seed = node(&socket, id);
    let responder = seed.clone();
    let received = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let server_stop = done.clone();
    let server = std::thread::spawn(move || {
        let mut buf = [0; 1024];
        while !server_stop.load(Ordering::Acquire) {
            if let Ok((_, client)) = socket.recv_from(&mut buf) {
                let mut packet = vec![0xe4];
                match buf[1] {
                    0x01 => {
                        packet.push(0x09);
                        packet.extend_from_slice(&responder.id.0);
                        packet.extend_from_slice(&4662u16.to_le_bytes());
                        packet.push(9);
                        packet.extend_from_slice(&0u16.to_le_bytes());
                    }
                    0x34 => {
                        packet.push(0x3b);
                        packet.extend_from_slice(&responder.id.0);
                        packet.extend_from_slice(&target);
                        packet.extend_from_slice(&1u16.to_le_bytes());
                        result_entry(&mut packet, 4, 0, 4662);
                    }
                    0x21 => continue, // a slow node walk must not hold back this source.
                    _ => unreachable!(),
                }
                socket.send_to(&packet, client).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let mut cfg = config();
    cfg.request_timeout = Duration::from_millis(400);
    let started = Instant::now();
    let result = kad_session::lookup_sources_streaming(
        &hash,
        3,
        &[seed],
        &cfg,
        || received.load(Ordering::Acquire),
        |_| {
            received.store(true, Ordering::Release);
        },
    )
    .unwrap();
    done.store(true, Ordering::Release);
    server.join().unwrap();
    assert!(received.load(Ordering::Acquire));
    assert!(result.cancelled);
    assert_eq!(result.lookup_replies, 0);
    assert_eq!(result.sources.len(), 1);
    assert!(started.elapsed() < Duration::from_millis(300));
}

/// Opt in explicitly: downloads no file data, queries only the user's public
/// file hash through public Kad nodes and prints aggregate discovery counts.
#[test]
#[ignore = "public UDP network probe; cargo test -p aidm-engine --test kad_session_udp public_iso_kad_probe -- --ignored --nocapture"]
fn public_iso_kad_probe() {
    let hash = [
        0xe7, 0xc5, 0x26, 0x49, 0x93, 0x08, 0x84, 0x1a, 0x4a, 0x6d, 0x11, 0x6c, 0x85, 0x7d, 0xb6,
        0x69,
    ];
    let nodes = kad_session::default_bootstrap_nodes().unwrap();
    let started = Instant::now();
    let mut first_source = None;
    let result = kad_session::lookup_sources_streaming(
        &hash,
        4_478_906_368,
        &nodes,
        &KadLookupCfg::default(),
        || false,
        |_| {
            first_source.get_or_insert_with(|| started.elapsed());
        },
    )
    .unwrap();
    println!("bootstrap={}/{}, lookup={}/{}, source={}/{}, peers={}, malformed={}, unsupported={}, first_source_ms={:?}, elapsed_ms={}",
        result.bootstrap_replies, result.bootstrap_sent, result.lookup_replies, result.lookup_sent,
        result.source_replies, result.source_sent, result.sources.len(), result.malformed_packets,
        result.unsupported_packets, first_source.map(|time| time.as_millis()), result.elapsed.as_millis());
    assert!(
        result.bootstrap_replies + result.lookup_replies > 0,
        "public UDP Kad reachability was not verified"
    );
}
