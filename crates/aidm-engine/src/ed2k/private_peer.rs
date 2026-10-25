//! Independently encoded QueryPeer source directory. These records describe the
//! private protocol: InternalIP is not an eD2k public endpoint. Transport must
//! resolve PeerID through SN/Broker before treating a record as usable.
use super::private_index::Metadata;
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use aidm_core::ed2k::FileLink;
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

const MAX_PACKET: usize = 1024 * 1024;
const MAX_PEERS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerResource {
    pub peer_id: [u8; 16],
    pub internal_ip: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub capability: u64,
    pub hub_type: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Directory {
    pub peers: Vec<PeerResource>,
    pub query_interval: u32,
    pub total_peers: u32,
    pub delta_peers: i32,
    /// Raw server values; this client has no verified error-code enum.
    pub hub_errors: Vec<(u32, i32)>,
}

/// 调用方提供自己观测到的网络状态。未知 NAT 类型为 0，
/// 不得用外部客户端的实测值替代。
#[derive(Clone, Debug)]
pub struct NetworkInfo {
    pub internal_ip: Ipv4Addr,
    pub nat_type: u32,
    pub upnp_ip: Ipv4Addr,
    pub upnp_port: u16,
    pub address_is_translated_or_unknown: bool,
}

fn varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn number(out: &mut Vec<u8>, tag: u32, n: u64) {
    varint(out, (tag as u64) << 3);
    varint(out, n);
}
fn bytes(out: &mut Vec<u8>, tag: u32, s: &[u8]) {
    varint(out, (tag as u64) << 3 | 2);
    varint(out, s.len() as u64);
    out.extend_from_slice(s);
}

fn request(
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
    network: &NetworkInfo,
) -> Result<Vec<u8>, String> {
    if uri.len() > 64 * 1024 || link.size == 0 {
        return Err("private_directory_request_size".into());
    }
    let mut client = Vec::new();
    number(&mut client, 1, 134217728);
    for (n, value) in [
        (2, b"2.86.100.10".as_slice()),
        (3, b"pc.thunderX"),
        (4, b""),
        (5, identity),
    ] {
        bytes(&mut client, n, value);
    }
    let mut file = Vec::new();
    bytes(&mut file, 1, &meta.gcid);
    number(&mut file, 2, link.size);
    bytes(&mut file, 3, &meta.cid);
    bytes(&mut file, 5, uri.as_bytes());
    number(&mut file, 6, 1);
    let mut user = Vec::new();
    bytes(&mut user, 1, b"");
    bytes(&mut user, 2, b"");
    let mut net = Vec::new();
    bytes(&mut net, 1, &network.internal_ip.octets());
    number(&mut net, 2, network.nat_type.into());
    bytes(&mut net, 3, &network.upnp_ip.octets());
    number(&mut net, 4, network.upnp_port.into());
    let mut trace = Vec::new();
    bytes(&mut trace, 1, b"");
    let mut body = Vec::new();
    for (tag, data) in [(1, client), (2, file), (3, user), (4, net), (5, trace)] {
        bytes(&mut body, tag, &data);
    }
    number(
        &mut body,
        10,
        0xb06a | u64::from(network.address_is_translated_or_unknown),
    );
    number(&mut body, 11, 0x6d);
    bytes(&mut body, 12, b"");
    number(&mut body, 13, 0);
    let pad = 16 - body.len() % 16;
    body.resize(body.len() + pad, pad as u8);
    let key = md5::compute([2_u32.to_le_bytes(), 1_u32.to_le_bytes()].concat());
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    for b in body.chunks_exact_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(b));
    }
    let mut out = Vec::new();
    for n in [2_u32, 0, 1, 1, body.len() as u32] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&body);
    Ok(out)
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Number(u64),
    Bytes(&'a [u8]),
    Other,
}
struct Proto<'a> {
    data: &'a [u8],
    fields: usize,
}
impl<'a> Proto<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, fields: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.data.len() {
            return Err("private_directory_truncated".into());
        }
        let (value, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(value)
    }
    fn varint(&mut self) -> Result<u64, String> {
        let mut n = 0_u64;
        for i in 0..10 {
            let b = self.take(1)?[0];
            if i == 9 && b > 1 {
                break;
            }
            n |= (b as u64 & 127) << (7 * i);
            if b < 128 {
                return Ok(n);
            }
        }
        Err("private_directory_varint".into())
    }
    fn next(&mut self) -> Result<Option<(u32, Value<'a>)>, String> {
        if self.data.is_empty() {
            return Ok(None);
        }
        self.fields += 1;
        if self.fields > 16384 {
            return Err("private_directory_field_limit".into());
        }
        let key = self.varint()?;
        if key >> 3 == 0 || key >> 3 > 0x1fffffff {
            return Err("private_directory_tag".into());
        }
        let value = match key & 7 {
            0 => Value::Number(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Other
            }
            2 => {
                let n = usize::try_from(self.varint()?).map_err(|_| "private_directory_length")?;
                Value::Bytes(self.take(n)?)
            }
            5 => {
                self.take(4)?;
                Value::Other
            }
            _ => return Err("private_directory_wire_type".into()),
        };
        Ok(Some(((key >> 3) as u32, value)))
    }
}
fn scalar(value: Value<'_>) -> Result<u64, String> {
    if let Value::Number(v) = value {
        Ok(v)
    } else {
        Err("private_directory_number".into())
    }
}
fn blob(value: Value<'_>) -> Result<&[u8], String> {
    if let Value::Bytes(v) = value {
        Ok(v)
    } else {
        Err("private_directory_bytes".into())
    }
}
fn uint(value: Value<'_>) -> Result<u32, String> {
    u32::try_from(scalar(value)?).map_err(|_| "private_directory_integer".into())
}

fn parse_peer(data: &[u8]) -> Result<PeerResource, String> {
    let mut p = Proto::new(data);
    let mut id = None;
    let mut ip = None;
    let (mut tcp, mut udp, mut capability, mut hub_type) = (0, 0, 0, 0);
    let mut seen = 0_u32;
    while let Some((tag, value)) = p.next()? {
        if [1, 2, 3, 4, 5, 8].contains(&tag) {
            let bit = 1 << tag;
            if seen & bit != 0 {
                return Err("private_directory_duplicate_peer_field".into());
            }
            seen |= bit;
        }
        match tag {
            1 => {
                id = Some(
                    blob(value)?
                        .try_into()
                        .map_err(|_| "private_directory_peer_id")?,
                )
            }
            2 => {
                let b = blob(value)?;
                ip = Some(match b.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b).unwrap())),
                    16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap())),
                    _ => return Err("private_directory_ip".into()),
                });
            }
            3 => tcp = u16::try_from(scalar(value)?).map_err(|_| "private_directory_port")?,
            4 => udp = u16::try_from(scalar(value)?).map_err(|_| "private_directory_port")?,
            5 => capability = scalar(value)?,
            8 => hub_type = uint(value)?,
            _ => {}
        }
    }
    Ok(PeerResource {
        peer_id: id.ok_or("private_directory_peer_id_missing")?,
        internal_ip: ip.ok_or("private_directory_ip_missing")?,
        tcp_port: tcp,
        udp_port: udp,
        capability,
        hub_type,
    })
}

pub fn parse_response(packet: &[u8]) -> Result<Directory, String> {
    if packet.len() < 36 || packet.len() > MAX_PACKET || (packet.len() - 20) % 16 != 0 {
        return Err("private_directory_packet_size".into());
    }
    let h: Vec<u32> = packet[..20]
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    if h[0] != 2 || h[1] != 0 || h[2] != 1 || h[3] != 2 || h[4] as usize != packet.len() - 20 {
        return Err("private_directory_header".into());
    }
    let key = md5::compute([h[2].to_le_bytes(), h[0].to_le_bytes()].concat());
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    let mut plain = packet[20..].to_vec();
    for b in plain.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(b));
    }
    let pad = *plain.last().unwrap() as usize;
    if !(1..=16).contains(&pad)
        || !plain[plain.len() - pad..]
            .iter()
            .all(|&b| b as usize == pad)
    {
        return Err("private_directory_padding".into());
    }
    plain.truncate(plain.len() - pad);
    let mut out = Directory::default();
    let mut p = Proto::new(&plain);
    let mut seen = 0_u64;
    while let Some((tag, value)) = p.next()? {
        if [1, 2, 3, 4, 20, 21, 22, 23, 24].contains(&tag) {
            let bit = 1 << tag;
            if seen & bit != 0 {
                return Err("private_directory_duplicate_field".into());
            }
            seen |= bit;
        }
        match tag {
            1 => {
                if scalar(value)? != 0 {
                    return Err("private_directory_server_result".into());
                }
            }
            2 => out.query_interval = uint(value)?,
            3 => out.total_peers = uint(value)?,
            4 => out.delta_peers = scalar(value)? as i32,
            11 => {
                if out.peers.len() >= MAX_PEERS {
                    return Err("private_directory_peer_limit".into());
                }
                out.peers.push(parse_peer(blob(value)?)?);
            }
            20..=24 => out.hub_errors.push((tag, scalar(value)? as i32)),
            _ => {} // New server fields are length-checked, never interpreted as addresses.
        }
    }
    Ok(out)
}

/// One bounded anonymous directory request. Failure has no effect on the
/// standard eD2k download; source records are not transferred to its TCP pool.
pub fn query(
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
    network: &NetworkInfo,
) -> Result<Directory, String> {
    let body = request(link, uri, meta, identity, network)?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout_read(Duration::from_secs(3))
        .timeout_write(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let response = agent
        .post("http://pr.hub.sandai.net/querypeer")
        .set("Content-Type", "application/octet-stream")
        .set("Connection", "Close")
        .send_bytes(&body)
        .map_err(|_| "private_directory_http")?;
    let mut data = Vec::new();
    response
        .into_reader()
        .take((MAX_PACKET + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| "private_directory_read")?;
    parse_response(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    const RESPONSE: &[u8] = include_bytes!("../../tests/fixtures/private-query-peer-20261014.bin");
    #[test]
    fn independent_server_response_preserves_private_peers_and_signed_delta() {
        let d = parse_response(RESPONSE).unwrap();
        assert!(!d.peers.is_empty());
        assert!(d
            .peers
            .iter()
            .all(|p| p.internal_ip.is_ipv4() && p.tcp_port > 0));
        assert!(d
            .peers
            .iter()
            .any(|p| matches!(p.internal_ip, IpAddr::V4(a) if a.is_private())));
        assert!(d.hub_errors.iter().any(|&(tag, _)| tag == 22));
        assert!(d.delta_peers < 0);
    }
    #[test]
    fn malformed_network_frames_do_not_produce_usable_peers() {
        for n in 0..RESPONSE.len() {
            assert!(
                parse_response(&RESPONSE[..n]).is_err(),
                "accepted truncation {n}"
            );
        }
        let mut b = RESPONSE.to_vec();
        b[8] = 2;
        assert!(parse_response(&b).is_err());
        let mut b = RESPONSE.to_vec();
        b[16] ^= 16;
        assert!(parse_response(&b).is_err());
        let mut b = RESPONSE.to_vec();
        *b.last_mut().unwrap() ^= 1;
        assert!(parse_response(&b).is_err());
        let mut p = Proto::new(&[0x80; 11]);
        assert!(p.next().is_err());
    }
    #[test]
    fn request_matches_independent_python_protocol_vector() {
        let uri = "ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
        let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link(uri).unwrap() else {
            panic!("file")
        };
        let m = super::super::private_index::parse_response(
            include_bytes!("../../tests/fixtures/private-emule-info-20261014.bin"),
            &link,
        )
        .unwrap()
        .unwrap();
        let h = ring::digest::digest(
            &ring::digest::SHA256,
            // 身份探针字符串；改动它需要同步更新协议向量 fixture。
            b"AIDM protocol interoperability probe",
        );
        let hex: String = h.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        let mut identity = [0; 16];
        identity[..14].copy_from_slice(&hex.as_bytes()[..14]);
        identity[14..].copy_from_slice(b"NM");
        let net = NetworkInfo {
            internal_ip: Ipv4Addr::UNSPECIFIED,
            nat_type: 0,
            upnp_ip: Ipv4Addr::UNSPECIFIED,
            upnp_port: 0,
            address_is_translated_or_unknown: true,
        };
        assert_eq!(
            request(&link, uri, &m, &identity, &net).unwrap(),
            include_bytes!("../../tests/fixtures/private-query-peer-request-20261014.bin")
        );
    }
}
