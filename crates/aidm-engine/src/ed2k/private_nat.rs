//! 独立的可靠 UDP 封装和 SN 目录查询。SN 是穿透协调节点，并非文件数据源。
//! 线路按协议语义实现，并与独立实网应答交叉校验。
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};

const MAX_DATAGRAM: usize = 65_507;
const MAX_SN_PEERS: usize = 1024;
const HOSTS: [&str; 3] = [
    "hub5pn.sandai.net",
    "g1.hub5pn.sandai.net",
    "g2.hub5pn.sandai.net",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub protocol: u32,
    pub command: u8,
    pub algorithm: u8,
    pub wrapper_length: usize,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnPeer {
    pub peer_id: [u8; 16],
    pub endpoint: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnResponse {
    pub status: u8,
    pub super_nodes: Vec<SnPeer>,
    pub queried_peer_id: [u8; 16],
    /// 旧 SDK 按两个 LE32 消费的 IPv4 尾部，尚不赋予未经证明的语义。
    pub unknown_ipv4_words: Option<[u32; 2]>,
    /// 当前服务显式附加 count=0/1 及对应个数的 LE32；不静默丢弃尾部。
    pub observed_extension_words: Option<Vec<u32>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub directory_endpoint: SocketAddr,
    pub response: SnResponse,
}

/// 实际 PingSN/ICallSomeOne 输入；fresh 状态的零值仅表示尚无外部端口历史。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatState {
    pub nat_type: u32,
    pub latest_external_port: u16,
    pub time_elapsed: u32,
    pub delta_port: u32,
    pub udt_version: u16,
    pub local_udp_port: u16,
    pub mhxy_version: u8,
    pub local_tcp_port: u16,
    pub internal_ip: Ipv4Addr,
    pub upnp_ip: Ipv4Addr,
    pub upnp_port: u16,
    pub peer_status_flags: u16,
}

impl NatState {
    pub fn initial(local_udp_port: u16, local_tcp_port: u16, internal_ip: Ipv4Addr) -> Self {
        Self {
            nat_type: 0,
            latest_external_port: 0,
            time_elapsed: 0,
            delta_port: 0,
            udt_version: 1,
            local_udp_port,
            mhxy_version: 3,
            local_tcp_port,
            internal_ip,
            upnp_ip: Ipv4Addr::UNSPECIFIED,
            upnp_port: 0,
            peer_status_flags: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingSnResponse {
    pub sn_peer_id: [u8; 16],
    pub external_ip: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallResponse {
    pub sn_peer_id: [u8; 16],
    pub remote_peer_id: [u8; 16],
    pub online: u8,
    pub remote_endpoint: SocketAddr,
    pub local_virtual_port: u16,
    pub remote_nat_type: Option<u32>,
    pub latest_remote_port: Option<u16>,
    pub guessed_remote_port: Option<u16>,
    pub remote_udt_version: Option<u16>,
    pub mhxy_version: Option<u8>,
    /// 2026 服务在已定位旧 SDK 格式后附加的零 word，显式消费并保留。
    pub observed_trailing_word: Option<u32>,
}

fn header_ok(h: &[u8]) -> bool {
    let n = h.len();
    (9..=12).contains(&n)
        && n == usize::from(h[4] & 3) + 9
        && h[n - 2] == h[n - 3].wrapping_mul(13) ^ (n as u8).wrapping_mul(7)
        && h[n - 1] == h[n - 2].wrapping_mul(13) ^ (n as u8 + 1).wrapping_mul(7)
}

fn transform(data: &mut [u8], header: &[u8], algorithm: u8, decrypt: bool) {
    let mut key = header.to_vec();
    let mut i = 0;
    for byte in data {
        let j = (i + 1) % key.len();
        key[i] ^= key[j].wrapping_add(0x5b);
        *byte = match algorithm {
            1 => *byte ^ key[i],
            2 if decrypt => byte.wrapping_sub(key[i]),
            2 => byte.wrapping_add(key[i]),
            3 => key[i].wrapping_sub(*byte),
            _ => unreachable!("validated wrapper algorithm"),
        };
        i = j;
    }
}

pub fn decode_datagram(data: &[u8]) -> Result<Packet, String> {
    if !(5..=MAX_DATAGRAM).contains(&data.len()) {
        return Err("private_nat_datagram_size".into());
    }
    let algorithm = (u32::from_le_bytes(data[..4].try_into().unwrap()) >> 29) as u8;
    let (mut plain, wrapper_length) = match algorithm {
        0 => (data.to_vec(), 0),
        1..=3 => {
            let n = usize::from(data[4] & 3) + 9;
            if n + 5 > data.len() || !header_ok(&data[..n]) {
                return Err("private_nat_wrapper_header".into());
            }
            (data[n..].to_vec(), n)
        }
        _ => return Err("private_nat_wrapper_algorithm".into()),
    };
    if algorithm != 0 {
        transform(&mut plain, &data[..wrapper_length], algorithm, true);
    }
    Ok(Packet {
        protocol: u32::from_le_bytes(plain[..4].try_into().unwrap()),
        command: plain[4],
        algorithm,
        wrapper_length,
        body: plain[5..].to_vec(),
    })
}

fn encode_with_header(
    protocol: u32,
    command: u8,
    body: &[u8],
    algorithm: u8,
    header: &[u8],
) -> Result<Vec<u8>, String> {
    if protocol >= 1 << 29 || body.len() + 5 + header.len() > MAX_DATAGRAM {
        return Err("private_nat_packet_size".into());
    }
    if algorithm > 3
        || (algorithm == 0 && !header.is_empty())
        || (algorithm != 0
            && (!header_ok(header)
                || u32::from_le_bytes(header[..4].try_into().unwrap()) >> 29
                    != u32::from(algorithm)))
    {
        return Err("private_nat_wrapper_header".into());
    }
    let mut data = Vec::with_capacity(5 + body.len());
    data.extend_from_slice(&protocol.to_le_bytes());
    data.push(command);
    data.extend_from_slice(body);
    if algorithm == 0 {
        return Ok(data);
    }
    transform(&mut data, header, algorithm, false);
    let mut out = header.to_vec();
    out.extend(data);
    Ok(out)
}

pub fn encode_datagram(
    protocol: u32,
    command: u8,
    body: &[u8],
    algorithm: u8,
) -> Result<Vec<u8>, String> {
    let mut h = [0_u8; 12];
    let n = if algorithm == 0 {
        0
    } else {
        if !(1..=3).contains(&algorithm) {
            return Err("private_nat_wrapper_algorithm".into());
        }
        SystemRandom::new()
            .fill(&mut h)
            .map_err(|_| "private_nat_random")?;
        let word = u32::from_le_bytes(h[..4].try_into().unwrap()) & 0x1fff_ffff
            | u32::from(algorithm) << 29;
        h[..4].copy_from_slice(&word.to_le_bytes());
        let n = usize::from(h[4] & 3) + 9;
        h[n - 2] = h[n - 3].wrapping_mul(13) ^ (n as u8).wrapping_mul(7);
        h[n - 1] = h[n - 2].wrapping_mul(13) ^ (n as u8 + 1).wrapping_mul(7);
        n
    };
    encode_with_header(protocol, command, body, algorithm, &h[..n])
}

fn push_peer_id(out: &mut Vec<u8>, peer_id: &[u8; 16]) {
    out.extend_from_slice(&16_u32.to_le_bytes());
    out.extend_from_slice(peer_id);
}

pub fn build_get_peer_sn_request(
    peer_id: &[u8; 16],
    ipv6: bool,
    algorithm: u8,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::with_capacity(20);
    push_peer_id(&mut body, peer_id);
    encode_datagram(
        if ipv6 { 0x46 } else { 0x43 },
        if ipv6 { 0x1a } else { 0 },
        &body,
        algorithm,
    )
}

pub fn build_ping_sn_request(
    identity: &[u8; 16],
    state: &NatState,
    algorithm: u8,
) -> Result<Vec<u8>, String> {
    if state.local_udp_port == 0 {
        return Err("private_nat_ping_port".into());
    }
    let mut body = Vec::with_capacity(53);
    push_peer_id(&mut body, identity);
    body.extend_from_slice(&state.nat_type.to_le_bytes());
    body.extend_from_slice(&state.latest_external_port.to_le_bytes());
    body.extend_from_slice(&state.time_elapsed.to_le_bytes());
    body.extend_from_slice(&state.delta_port.to_le_bytes());
    body.extend_from_slice(&state.udt_version.to_le_bytes());
    body.extend_from_slice(&state.local_udp_port.to_le_bytes());
    body.push(state.mhxy_version);
    body.extend_from_slice(&state.local_tcp_port.to_le_bytes());
    body.extend_from_slice(&state.internal_ip.octets());
    body.extend_from_slice(&state.upnp_ip.octets());
    body.extend_from_slice(&state.upnp_port.to_le_bytes());
    body.extend_from_slice(&state.peer_status_flags.to_le_bytes());
    encode_datagram(0x42, 2, &body, algorithm)
}

/// SNInfo 是目标 SN 的身份及地址，来自目标资源的 GetPeerSN 应答。
pub fn build_icall_request(
    identity: &[u8; 16],
    remote_peer_id: &[u8; 16],
    local_virtual_port: u16,
    state: &NatState,
    sn: &SnPeer,
    algorithm: u8,
) -> Result<Vec<u8>, String> {
    let IpAddr::V4(sn_ip) = sn.endpoint.ip() else {
        return Err("private_nat_icall_ipv6_not_implemented".into());
    };
    if local_virtual_port == 0 || state.local_udp_port == 0 || sn.endpoint.port() == 0 {
        return Err("private_nat_icall_port".into());
    }
    let mut body = Vec::new();
    push_peer_id(&mut body, identity);
    push_peer_id(&mut body, remote_peer_id);
    body.extend_from_slice(&local_virtual_port.to_le_bytes());
    body.extend_from_slice(&state.nat_type.to_le_bytes());
    body.extend_from_slice(&state.latest_external_port.to_le_bytes());
    body.extend_from_slice(&state.time_elapsed.to_le_bytes());
    body.extend_from_slice(&state.delta_port.to_le_bytes());
    body.extend_from_slice(&state.udt_version.to_le_bytes());
    body.extend_from_slice(&state.local_udp_port.to_le_bytes());
    body.push(state.mhxy_version);
    push_peer_id(&mut body, &sn.peer_id);
    body.extend_from_slice(&sn_ip.octets());
    body.extend_from_slice(&sn.endpoint.port().to_le_bytes());
    encode_datagram(0x3e, 3, &body, algorithm)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.0.len() {
            return Err("private_nat_truncated".into());
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn peer_id(&mut self) -> Result<[u8; 16], String> {
        if self.u32()? != 16 {
            return Err("private_nat_peer_id_size".into());
        }
        Ok(self.take(16)?.try_into().unwrap())
    }
}

pub fn parse_ping_sn_response(packet: &Packet) -> Result<PingSnResponse, String> {
    if (packet.protocol, packet.command) != (0x42, 0xfd) {
        return Err("private_nat_ping_response_command".into());
    }
    let mut r = Reader(&packet.body);
    let sn_peer_id = r.peer_id()?;
    let external_ip = Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap());
    if !r.0.is_empty() {
        return Err("private_nat_ping_trailing_bytes".into());
    }
    Ok(PingSnResponse {
        sn_peer_id,
        external_ip,
    })
}

pub fn parse_icall_response(
    packet: &Packet,
    expected_peer_id: &[u8; 16],
    expected_virtual_port: u16,
) -> Result<CallResponse, String> {
    if (packet.protocol, packet.command) != (0x3e, 0xfc) {
        return Err("private_nat_icall_response_command".into());
    }
    let mut r = Reader(&packet.body);
    let sn_peer_id = r.peer_id()?;
    let remote_peer_id = r.peer_id()?;
    let online = r.u8()?;
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap());
    let port = r.u16()?;
    let local_virtual_port = r.u16()?;
    if remote_peer_id != *expected_peer_id || local_virtual_port != expected_virtual_port {
        return Err("private_nat_icall_response_mismatch".into());
    }
    if online != 0 && (port == 0 || ip.is_unspecified() || ip.is_multicast()) {
        return Err("private_nat_icall_response_endpoint".into());
    }
    let (
        remote_nat_type,
        latest_remote_port,
        guessed_remote_port,
        remote_udt_version,
        mhxy_version,
    ) = if online != 0 {
        (
            Some(r.u32()?),
            Some(r.u16()?),
            Some(r.u16()?),
            Some(r.u16()?),
            Some(r.u8()?),
        )
    } else {
        (None, None, None, None, None)
    };
    let observed_trailing_word = if r.0.len() == 4 {
        let word = r.u32()?;
        if word != 0 {
            return Err("private_nat_icall_unknown_extension".into());
        }
        Some(word)
    } else {
        None
    };
    if !r.0.is_empty() {
        return Err("private_nat_icall_trailing_bytes".into());
    }
    Ok(CallResponse {
        sn_peer_id,
        remote_peer_id,
        online,
        remote_endpoint: SocketAddr::new(IpAddr::V4(ip), port),
        local_virtual_port,
        remote_nat_type,
        latest_remote_port,
        guessed_remote_port,
        remote_udt_version,
        mhxy_version,
        observed_trailing_word,
    })
}

pub fn parse_get_peer_sn_response(
    packet: &Packet,
    expected_peer_id: &[u8; 16],
) -> Result<SnResponse, String> {
    let ipv6 = packet.command == 0x1b;
    if !((packet.protocol == 0x43 && packet.command == 0xff)
        || (ipv6 && [0x43, 0x46].contains(&packet.protocol)))
    {
        return Err("private_nat_sn_response_command".into());
    }
    let mut r = Reader(&packet.body);
    let status = r.u8()?;
    let count = r.u32()? as usize;
    let entry_minimum = if ipv6 { 38 } else { 26 };
    if count > MAX_SN_PEERS || count.saturating_mul(entry_minimum) > r.0.len() {
        return Err("private_nat_sn_count".into());
    }
    let mut super_nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let peer_id = r.peer_id()?;
        let ip = if ipv6 {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap()))
        } else {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap()))
        };
        let port = r.u16()?;
        if port == 0 || ip.is_unspecified() || ip.is_multicast() {
            return Err("private_nat_sn_endpoint".into());
        }
        super_nodes.push(SnPeer {
            peer_id,
            endpoint: SocketAddr::new(ip, port),
        });
    }
    let queried_peer_id = r.peer_id()?;
    if queried_peer_id != *expected_peer_id {
        return Err("private_nat_sn_peer_mismatch".into());
    }
    let mut observed_extension_words = None;
    let unknown_ipv4_words = if ipv6 {
        None
    } else {
        let base = [r.u32()?, r.u32()?];
        if !r.0.is_empty() {
            let count = r.u32()? as usize;
            if count > 1 || r.0.len() != count * 4 {
                return Err("private_nat_sn_unknown_extension".into());
            }
            let mut words = Vec::with_capacity(count);
            for _ in 0..count {
                words.push(r.u32()?);
            }
            observed_extension_words = Some(words);
        }
        Some(base)
    };
    if !r.0.is_empty() {
        return Err("private_nat_sn_trailing_bytes".into());
    }
    Ok(SnResponse {
        status,
        super_nodes,
        queried_peer_id,
        unknown_ipv4_words,
        observed_extension_words,
    })
}

/// 同一 UDP socket 对最多三个目标和三个原生目录 endpoint 查址，响应到达即回调。
/// DNS 结果通过 channel 传回；超时/取消不 join 可能仍处于系统解析中的线程。
/// 返回值是合法应答数，不能作为文件 peer 连接或下载成功数。
pub fn query_super_nodes<F>(
    peer_ids: &[[u8; 16]],
    timeout: Duration,
    cancelled: &AtomicBool,
    mut on_response: F,
) -> Result<usize, String>
where
    F: FnMut(Lookup),
{
    let mut peers = Vec::new();
    for peer in peer_ids {
        if !peers.contains(peer) {
            peers.push(*peer);
            if peers.len() == 3 {
                break;
            }
        }
    }
    if peers.is_empty() || cancelled.load(Ordering::Relaxed) {
        return Ok(0);
    }
    let deadline = Instant::now() + timeout.min(Duration::from_secs(5));
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("aidm-sn-dns".into())
        .spawn(move || {
            for host in HOSTS {
                if let Ok(addrs) = (host, 8000).to_socket_addrs() {
                    if let Some(addr) = addrs.into_iter().find(SocketAddr::is_ipv4) {
                        if tx.send(addr).is_err() {
                            return;
                        }
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
    let mut endpoints = HashSet::new();
    let mut seen = HashSet::new();
    let mut count = 0;
    let mut buf = [0_u8; MAX_DATAGRAM];
    while Instant::now() < deadline && !cancelled.load(Ordering::Relaxed) {
        while let Ok(addr) = rx.try_recv() {
            if endpoints.len() < 3 && endpoints.insert(addr) {
                for peer in &peers {
                    let request = build_get_peer_sn_request(peer, false, 3)?;
                    // 单个目录不可达不抛弃其他目录已发出的请求。
                    let _ = socket.send_to(&request, addr);
                }
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(30))))
            .map_err(|e| e.to_string())?;
        match socket.recv_from(&mut buf) {
            Ok((n, source)) if endpoints.contains(&source) => {
                let Ok(packet) = decode_datagram(&buf[..n]) else {
                    continue;
                };
                for peer in &peers {
                    let Ok(response) = parse_get_peer_sn_response(&packet, peer) else {
                        continue;
                    };
                    if seen.insert((source, *peer)) {
                        count += 1;
                        on_response(Lookup {
                            directory_endpoint: source,
                            response,
                        });
                    }
                    break;
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    // 来自本实现独立 UDP 查询的真实响应，不含任何外部客户端身份或账号。
    const RESPONSE: &str = "43000000ff01010000001000000035323442343135334138463030303030b7e830a3401f1000000041303843464443463739463654324955000103000400000001000000204e0752";
    const PEER: &[u8; 16] = b"A08CFDCF79F6T2IU";

    #[test]
    fn real_independent_sn_response_and_exact_extension() {
        let packet = decode_datagram(&hex(RESPONSE)).unwrap();
        let response = parse_get_peer_sn_response(&packet, PEER).unwrap();
        assert_eq!(response.status, 1);
        assert_eq!(response.super_nodes.len(), 1);
        assert_eq!(response.super_nodes[0].peer_id, *b"524B4153A8F00000");
        assert_eq!(
            response.super_nodes[0].endpoint.to_string(),
            "183.232.48.163:8000"
        );
        assert_eq!(response.unknown_ipv4_words, Some([0x30100, 4]));
        assert_eq!(response.observed_extension_words, Some(vec![0x52074e20]));
        assert!(parse_get_peer_sn_response(&packet, b"0123456789ABCDEF").is_err());
    }

    #[test]
    fn malformed_captured_response_is_rejected() {
        let packet = decode_datagram(&hex(RESPONSE)).unwrap();
        for n in 0..packet.body.len() {
            let mut cut = packet.clone();
            cut.body.truncate(n);
            // 8 字节尾部也是独立、已证明的合法版本。
            if n == packet.body.len() - 8 {
                assert!(parse_get_peer_sn_response(&cut, PEER).is_ok());
            } else {
                assert!(
                    parse_get_peer_sn_response(&cut, PEER).is_err(),
                    "offset {n}"
                );
            }
        }
        let mut extra = packet.clone();
        extra.body.push(0);
        assert!(parse_get_peer_sn_response(&extra, PEER).is_err());
        let mut count = packet.clone();
        count.body[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_get_peer_sn_response(&count, PEER).is_err());
    }

    #[test]
    fn real_algorithm_three_request_vector() {
        let data = hex("cb0d0f7c7ce79e39a36067d8ab3e0e0ac75d1e1ca9f01045e747ac9a381a415fa49d");
        let packet = decode_datagram(&data).unwrap();
        assert_eq!(
            (packet.protocol, packet.command, packet.algorithm),
            (67, 0, 3)
        );
        assert_eq!(packet.wrapper_length, 9);
        assert_eq!(&packet.body[..4], &16_u32.to_le_bytes());
        assert_eq!(packet.body.len(), 20);
        assert_eq!(
            encode_with_header(67, 0, &packet.body, 3, &data[..9]).unwrap(),
            data
        );
        let mut corrupt = data.clone();
        corrupt[8] ^= 1;
        assert!(decode_datagram(&corrupt).is_err());
    }

    #[test]
    fn request_algorithms_roundtrip_and_early_cancel() {
        for algorithm in 0..=3 {
            let packet =
                decode_datagram(&build_get_peer_sn_request(PEER, false, algorithm).unwrap())
                    .unwrap();
            assert_eq!((packet.protocol, packet.command), (67, 0));
            assert_eq!(&packet.body[4..], PEER);
        }
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            query_super_nodes(&[*PEER], Duration::from_secs(3), &cancelled, |_| panic!(
                "cancelled"
            ))
            .unwrap(),
            0
        );
    }

    #[test]
    fn real_registration_and_icall_responses() {
        let ping = decode_datagram(&hex(
            "42000000fd1000000030303136334530304535463730303030df5d077f",
        ))
        .unwrap();
        let registered = parse_ping_sn_response(&ping).unwrap();
        assert_eq!(registered.sn_peer_id, *b"00163E00E5F70000");
        assert_eq!(registered.external_ip.octets(), [223, 93, 7, 127]);
        let packet = decode_datagram(&hex("3e000000fc100000003532344234313533413846303030303010000000413038434644434637394636543249550178e54e0d8f240140000103003930000001002900000000")).unwrap();
        let called = parse_icall_response(&packet, PEER, 0x4001).unwrap();
        assert_eq!(called.online, 1);
        assert_eq!(called.sn_peer_id, *b"524B4153A8F00000");
        assert_eq!(called.remote_endpoint.to_string(), "120.229.78.13:9359");
        assert_eq!(called.remote_nat_type, Some(0x30100));
        assert_eq!(called.remote_udt_version, Some(1));
        assert_eq!(called.mhxy_version, Some(41));
        assert_eq!(called.observed_trailing_word, Some(0));
        assert!(parse_icall_response(&packet, PEER, 0x4002).is_err());
        let mut extra = packet.clone();
        extra.body.push(0);
        assert!(parse_icall_response(&extra, PEER, 0x4001).is_err());
        for n in 0..packet.body.len() {
            let mut cut = packet.clone();
            cut.body.truncate(n);
            if n == packet.body.len() - 4 {
                assert!(parse_icall_response(&cut, PEER, 0x4001).is_ok());
            } else {
                assert!(
                    parse_icall_response(&cut, PEER, 0x4001).is_err(),
                    "offset {n}"
                );
            }
        }
    }

    #[test]
    fn registration_and_icall_request_layouts() {
        let state = NatState::initial(49_152, 0, Ipv4Addr::new(192, 0, 2, 10));
        let ping = decode_datagram(&build_ping_sn_request(PEER, &state, 3).unwrap()).unwrap();
        assert_eq!((ping.protocol, ping.command, ping.body.len()), (66, 2, 53));
        assert_eq!(&ping.body[20..24], &0_u32.to_le_bytes());
        assert_eq!(&ping.body[34..36], &1_u16.to_le_bytes());
        assert_eq!(&ping.body[36..38], &49_152_u16.to_le_bytes());
        let sn = SnPeer {
            peer_id: *b"524B4153A8F00000",
            endpoint: "183.232.48.163:8000".parse().unwrap(),
        };
        let call = decode_datagram(
            &build_icall_request(PEER, b"0123456789ABCDEF", 0x4001, &state, &sn, 3).unwrap(),
        )
        .unwrap();
        assert_eq!((call.protocol, call.command, call.body.len()), (62, 3, 87));
        assert_eq!(&call.body[40..42], &0x4001_u16.to_le_bytes());
        assert_eq!(&call.body[65..81], &sn.peer_id);
        assert_eq!(&call.body[81..85], &[183, 232, 48, 163]);
        assert_eq!(&call.body[85..], &8000_u16.to_le_bytes());
    }

    #[test]
    #[ignore = "explicit native directory interoperability check; requires a fresh QueryPeer ID"]
    fn live_native_directory_lookup() {
        let value = std::env::var("AIDM_REA_TEST_PEER_ID")
            .expect("set AIDM_REA_TEST_PEER_ID to one fresh 16-byte ASCII resource peer ID");
        let peer: [u8; 16] = value.as_bytes().try_into().expect("16-byte peer ID");
        let cancelled = AtomicBool::new(false);
        let start = Instant::now();
        let mut first_ms = None;
        let mut super_nodes = 0;
        let count = query_super_nodes(&[peer], Duration::from_secs(3), &cancelled, |result| {
            first_ms.get_or_insert(start.elapsed().as_millis());
            super_nodes += result.response.super_nodes.len();
        })
        .unwrap();
        println!("valid_responses={count} super_nodes={super_nodes} first_ms={first_ms:?}");
        assert!(
            count > 0,
            "no valid native SN directory response within the bounded window"
        );
    }
}
