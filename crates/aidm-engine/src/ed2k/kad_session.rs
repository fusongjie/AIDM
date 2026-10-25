//! Bounded, download-only Kad2 source discovery. No routing service, publishing,
//! firewall callback, or obfuscation capability is advertised.
//!
//! eMule evidence and the deliberately limited scope are recorded in
//! `docs/emule-kad-protocol-spec.md §10`. In particular CUInt128 wire bytes are four
//! little-endian u32 words; a displayed eD2k hash must be reversed per word.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use aidm_core::ed2k::kad::{parse_nodes_dat, KadId, KadNode, MIN_ACCEPTED_VERSION};
use flate2::read::ZlibDecoder;

const KAD: u8 = 0xe4;
const KAD_PACKED: u8 = 0xe5;
const BOOTSTRAP_REQ: u8 = 0x01;
const BOOTSTRAP_RES: u8 = 0x09;
const FIND_REQ: u8 = 0x21;
const FIND_RES: u8 = 0x29;
const SEARCH_SOURCE_REQ: u8 = 0x34;
const SEARCH_RES: u8 = 0x3b;
const MAX_UNPACKED: usize = 65_536;

#[derive(Debug, Clone)]
pub struct KadLookupCfg {
    pub bind_addr: SocketAddrV4,
    pub timeout: Duration,
    pub request_timeout: Duration,
    pub bootstrap_requests: usize,
    pub lookup_requests: usize,
    pub source_requests: usize,
    pub parallelism: usize,
    pub max_nodes: usize,
    pub max_sources: usize,
    /// For explicit local mock networks only; normal download discovery rejects
    /// private, loopback, multicast, unspecified and documentation addresses.
    pub allow_private_addresses: bool,
}

impl Default for KadLookupCfg {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            timeout: Duration::from_secs(45),
            request_timeout: Duration::from_millis(1500),
            bootstrap_requests: 12,
            lookup_requests: 64,
            source_requests: 20,
            parallelism: 3,
            max_nodes: 1024,
            max_sources: 300,
            allow_private_addresses: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadSource {
    pub ip: Ipv4Addr,
    pub port: u16,
    /// The source's eD2k user hash, converted from CUInt128 wire words.
    pub user_hash: [u8; 16],
    pub udp_port: u16,
    pub source_type: u8,
    pub crypt_options: u8,
}

#[derive(Debug, Clone, Default)]
pub struct KadLookupResult {
    pub sources: Vec<KadSource>,
    pub bootstrap_sent: usize,
    pub bootstrap_replies: usize,
    pub lookup_sent: usize,
    pub lookup_replies: usize,
    pub source_sent: usize,
    pub source_replies: usize,
    pub malformed_packets: usize,
    pub unsupported_packets: usize,
    pub skipped_callback_sources: usize,
    pub skipped_crypto_sources: usize,
    pub cancelled: bool,
    pub elapsed: Duration,
}

/// Public nodes.dat fixture retained from the protocol investigation. Its UDP
/// keys belong to the publisher's public IP and are intentionally never reused.
///
/// 这是**编译期内嵌的兜底样本**（采集自公开节点列表）：节点会过期，正常路径应当用
/// [`super::kad_bootstrap::bootstrap_nodes`] 取刷新过的那份（见 `kad_bootstrap` 模块）。
pub fn default_bootstrap_nodes() -> Result<Vec<KadNode>, String> {
    parse_nodes_dat(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../aidm-core/tests/fixtures/ed2k/nodes.dat"
    )))
    .map_err(|e| format!("{}: {}", e.code(), e.message()))
}

pub fn lookup_sources(
    file_hash: &[u8; 16],
    file_size: u64,
    seeds: &[KadNode],
    should_stop: impl Fn() -> bool,
) -> Result<KadLookupResult, String> {
    lookup_sources_with_config(
        file_hash,
        file_size,
        seeds,
        &KadLookupCfg::default(),
        should_stop,
    )
}

pub fn lookup_sources_with_config(
    file_hash: &[u8; 16],
    file_size: u64,
    seeds: &[KadNode],
    cfg: &KadLookupCfg,
    should_stop: impl Fn() -> bool,
) -> Result<KadLookupResult, String> {
    lookup_sources_streaming(file_hash, file_size, seeds, cfg, should_stop, |_| {})
}

/// Notify a caller immediately for every new usable source. The callback runs
/// on this lookup's thread; keep it nonblocking (an mpsc send is appropriate).
/// Iterative node discovery continues after the callback returns.
pub fn lookup_sources_streaming(
    file_hash: &[u8; 16],
    file_size: u64,
    seeds: &[KadNode],
    cfg: &KadLookupCfg,
    should_stop: impl Fn() -> bool,
    mut on_source: impl FnMut(&KadSource),
) -> Result<KadLookupResult, String> {
    let started = Instant::now();
    let mut result = KadLookupResult::default();
    if should_stop() {
        result.cancelled = true;
        return Ok(result);
    }
    if seeds.is_empty() {
        result.elapsed = started.elapsed();
        return Ok(result);
    }
    // Clamp caller-supplied values as well as providing bounded defaults.
    let timeout = cfg.timeout.min(Duration::from_secs(60));
    let deadline = started + timeout;
    // Leave one third of the total budget for the actual source requests.
    let lookup_deadline = started + timeout.mul_f64(2.0 / 3.0);
    let request_timeout = cfg
        .request_timeout
        .clamp(Duration::from_millis(20), Duration::from_secs(5));
    let alpha = cfg.parallelism.clamp(1, 8);
    let max_nodes = cfg.max_nodes.clamp(1, 2048);
    let max_sources = cfg.max_sources.clamp(1, 300);
    let socket = UdpSocket::bind(cfg.bind_addr).map_err(|e| format!("kad_udp_bind: {e}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("kad_udp_nonblocking: {e}"))?;
    let target = swap_words(*file_hash);
    let mut nodes = HashMap::<SocketAddrV4, KadNode>::new();
    let mut responsive = HashSet::<SocketAddrV4>::new();
    for node in seeds {
        add_node(
            &mut nodes,
            node.clone(),
            max_nodes,
            cfg.allow_private_addresses,
        );
    }
    if nodes.is_empty() || timeout.is_zero() {
        result.elapsed = started.elapsed();
        return Ok(result);
    }

    // Bootstrap only a small subset. The seed already contains IDs, so lookup
    // can still proceed when bootstrap is filtered or these entries are stale.
    let mut bootstrap_pending = HashSet::new();
    for addr in sorted_nodes(&nodes, &target)
        .into_iter()
        .take(cfg.bootstrap_requests.min(24))
    {
        send(&socket, addr, BOOTSTRAP_REQ, &[])?;
        bootstrap_pending.insert(addr);
        result.bootstrap_sent += 1;
    }
    let bootstrap_deadline = deadline.min(Instant::now() + request_timeout);
    while !bootstrap_pending.is_empty() && Instant::now() < bootstrap_deadline {
        if should_stop() {
            result.cancelled = true;
            break;
        }
        if let Some((addr, opcode, payload)) = receive(&socket, &mut result)? {
            if opcode == BOOTSTRAP_RES && bootstrap_pending.contains(&addr) {
                match decode_bootstrap(addr, &payload) {
                    Ok(contacts) => {
                        bootstrap_pending.remove(&addr);
                        responsive.insert(addr);
                        result.bootstrap_replies += 1;
                        for node in contacts {
                            add_node(&mut nodes, node, max_nodes, cfg.allow_private_addresses);
                        }
                    }
                    Err(()) => result.malformed_packets += 1,
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // Iteratively walk toward the file ID. Last 16 request bytes are the
    // receiver's current ID, not our own ID (eMule checks this before replying).
    let mut asked = HashSet::new();
    let mut pending = HashMap::<SocketAddrV4, Instant>::new();
    let mut source_pending = HashMap::<SocketAddrV4, Instant>::new();
    let mut source_asked = HashSet::<SocketAddrV4>::new();
    // Reserve half of the source budget for the final closest set. Early
    // requests can start as soon as any verified responder enters eMule's
    // SEARCHTOLERANCE range; no need to finish all node lookups first.
    let early_source_limit = cfg.source_requests.min(20).div_ceil(2);
    let max_lookup = cfg.lookup_requests.min(96);
    while !result.cancelled && Instant::now() < lookup_deadline {
        if should_stop() {
            result.cancelled = true;
            break;
        }
        pending.retain(|_, sent| sent.elapsed() < request_timeout);
        source_pending.retain(|_, sent| sent.elapsed() < request_timeout);
        for addr in sorted_nodes(&nodes, &target) {
            if source_pending.len() >= alpha || result.source_sent >= early_source_limit {
                break;
            }
            if !responsive.contains(&addr)
                || source_asked.contains(&addr)
                || u32::from_be_bytes(distance(&target, &nodes[&addr])[..4].try_into().unwrap())
                    > 16_777_216
            {
                continue;
            }
            send_source_request(&socket, addr, &target, file_size)?;
            source_asked.insert(addr);
            source_pending.insert(addr, Instant::now());
            result.source_sent += 1;
        }
        let sorted = sorted_nodes(&nodes, &target);
        // All ten closest candidates have been tried and no response is in
        // flight: no further branch improved the nearest set.
        if pending.is_empty()
            && !asked.is_empty()
            && sorted.iter().take(10).all(|a| asked.contains(a))
        {
            break;
        }
        for addr in sorted {
            if pending.len() >= alpha || result.lookup_sent >= max_lookup {
                break;
            }
            if !asked.insert(addr) {
                continue;
            }
            let mut payload = Vec::with_capacity(33);
            payload.push(0x0b); // FIND_NODE; asks for eleven close contacts.
            payload.extend_from_slice(&target);
            payload.extend_from_slice(&nodes[&addr].id.0);
            send(&socket, addr, FIND_REQ, &payload)?;
            pending.insert(addr, Instant::now());
            result.lookup_sent += 1;
        }
        if pending.is_empty() {
            break;
        }
        if let Some((addr, opcode, payload)) = receive(&socket, &mut result)? {
            if opcode == SEARCH_RES && source_pending.contains_key(&addr) {
                accept_sources(
                    &target,
                    &payload,
                    cfg.allow_private_addresses,
                    max_sources,
                    &mut result,
                    &mut on_source,
                );
                continue;
            }
            if opcode == FIND_RES && pending.contains_key(&addr) {
                match decode_find(&target, &payload) {
                    Ok(contacts) => {
                        pending.remove(&addr);
                        responsive.insert(addr);
                        result.lookup_replies += 1;
                        for node in contacts {
                            add_node(&mut nodes, node, max_nodes, cfg.allow_private_addresses);
                        }
                    }
                    Err(()) => result.malformed_packets += 1,
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // Query only nodes that actually replied to our socket, closest first.
    // A search may span several result datagrams, so keep its transaction open
    // until its timeout instead of closing after the first result packet.
    let source_nodes: Vec<_> = sorted_nodes(&nodes, &target)
        .into_iter()
        .filter(|a| responsive.contains(a) && !source_asked.contains(a))
        .take(
            cfg.source_requests
                .min(20)
                .saturating_sub(result.source_sent),
        )
        .collect();
    let mut source_iter = source_nodes.into_iter();
    pending = source_pending;
    while !result.cancelled && Instant::now() < deadline && result.sources.len() < max_sources {
        if should_stop() {
            result.cancelled = true;
            break;
        }
        pending.retain(|_, sent| sent.elapsed() < request_timeout);
        while pending.len() < alpha {
            let Some(addr) = source_iter.next() else {
                break;
            };
            send_source_request(&socket, addr, &target, file_size)?;
            pending.insert(addr, Instant::now());
            result.source_sent += 1;
        }
        if pending.is_empty() {
            break;
        }
        if let Some((addr, opcode, payload)) = receive(&socket, &mut result)? {
            if opcode == SEARCH_RES && pending.contains_key(&addr) {
                accept_sources(
                    &target,
                    &payload,
                    cfg.allow_private_addresses,
                    max_sources,
                    &mut result,
                    &mut on_source,
                );
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    result.elapsed = started.elapsed();
    Ok(result)
}

fn send_source_request(
    socket: &UdpSocket,
    addr: SocketAddrV4,
    target: &[u8; 16],
    file_size: u64,
) -> Result<(), String> {
    let mut payload = Vec::with_capacity(26);
    payload.extend_from_slice(target);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&file_size.to_le_bytes());
    send(socket, addr, SEARCH_SOURCE_REQ, &payload)
}

fn accept_sources(
    target: &[u8; 16],
    payload: &[u8],
    allow_private: bool,
    max_sources: usize,
    result: &mut KadLookupResult,
    on_source: &mut impl FnMut(&KadSource),
) {
    match decode_sources(target, payload, allow_private) {
        Ok(decoded) => {
            result.source_replies += 1;
            result.skipped_callback_sources += decoded.callback;
            result.skipped_crypto_sources += decoded.crypto;
            for source in decoded.sources {
                if result.sources.len() >= max_sources {
                    break;
                }
                if !result
                    .sources
                    .iter()
                    .any(|s| s.ip == source.ip && s.port == source.port)
                {
                    on_source(&source);
                    result.sources.push(source);
                }
            }
        }
        Err(()) => result.malformed_packets += 1,
    }
}

fn swap_words(mut value: [u8; 16]) -> [u8; 16] {
    for word in value.chunks_exact_mut(4) {
        word.reverse();
    }
    value
}

fn distance(target: &[u8; 16], node: &KadNode) -> [u8; 16] {
    let mut value = [0; 16];
    for i in 0..16 {
        value[i] = target[i] ^ node.id.0[i];
    }
    swap_words(value)
}

fn sorted_nodes(nodes: &HashMap<SocketAddrV4, KadNode>, target: &[u8; 16]) -> Vec<SocketAddrV4> {
    let mut out: Vec<_> = nodes.keys().copied().collect();
    out.sort_by_key(|a| (distance(target, &nodes[a]), *a));
    out
}

fn allowed_ip(ip: Ipv4Addr, allow_private: bool) -> bool {
    if ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
    {
        return false;
    }
    allow_private
        || !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_documentation())
}

fn add_node(
    nodes: &mut HashMap<SocketAddrV4, KadNode>,
    node: KadNode,
    max: usize,
    allow_private: bool,
) {
    if node.version < MIN_ACCEPTED_VERSION
        || node.id.is_zero()
        || node.udp_port == 0
        || !allowed_ip(node.ip, allow_private)
    {
        return;
    }
    let addr = SocketAddrV4::new(node.ip, node.udp_port);
    if nodes.len() < max || nodes.contains_key(&addr) {
        nodes.insert(addr, node);
    }
}

fn send(socket: &UdpSocket, addr: SocketAddrV4, opcode: u8, payload: &[u8]) -> Result<(), String> {
    let mut packet = Vec::with_capacity(payload.len() + 2);
    packet.extend_from_slice(&[KAD, opcode]);
    packet.extend_from_slice(payload);
    socket
        .send_to(&packet, addr)
        .map(|_| ())
        .map_err(|e| format!("kad_udp_send: {e}"))
}

fn receive(
    socket: &UdpSocket,
    result: &mut KadLookupResult,
) -> Result<Option<(SocketAddrV4, u8, Vec<u8>)>, String> {
    let mut buffer = [0; MAX_UNPACKED];
    match socket.recv_from(&mut buffer) {
        Ok((n, SocketAddr::V4(addr))) => {
            if n < 2 {
                result.malformed_packets += 1;
                return Ok(None);
            }
            let payload = match buffer[0] {
                KAD => buffer[2..n].to_vec(),
                KAD_PACKED => {
                    let mut decoder =
                        ZlibDecoder::new(&buffer[2..n]).take((MAX_UNPACKED + 1) as u64);
                    let mut decoded = Vec::new();
                    if decoder.read_to_end(&mut decoded).is_err() || decoded.len() > MAX_UNPACKED {
                        result.malformed_packets += 1;
                        return Ok(None);
                    }
                    decoded
                }
                _ => {
                    result.unsupported_packets += 1;
                    return Ok(None);
                }
            };
            Ok(Some((addr, buffer[1], payload)))
        }
        Ok(_) => Ok(None),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::ConnectionReset =>
        {
            Ok(None)
        }
        Err(e) => Err(format!("kad_udp_receive: {e}")),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        let end = self.pos.checked_add(n).ok_or(())?;
        let out = self.bytes.get(self.pos..end).ok_or(())?;
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ()> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| ())?,
        ))
    }
    fn u32(&mut self) -> Result<u32, ()> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| ())?,
        ))
    }
    fn u64(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| ())?,
        ))
    }
    fn id(&mut self) -> Result<KadId, ()> {
        Ok(KadId(self.take(16)?.try_into().map_err(|_| ())?))
    }
    fn done(&self) -> Result<(), ()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn contact(reader: &mut Reader<'_>) -> Result<KadNode, ()> {
    Ok(KadNode {
        id: reader.id()?,
        ip: Ipv4Addr::from(reader.u32()?),
        udp_port: reader.u16()?,
        tcp_port: reader.u16()?,
        version: reader.u8()?,
        udp_key: None,
        key_ip: None,
        verified: false,
    })
}

fn decode_bootstrap(addr: SocketAddrV4, payload: &[u8]) -> Result<Vec<KadNode>, ()> {
    let mut reader = Reader::new(payload);
    let responder = KadNode {
        id: reader.id()?,
        ip: *addr.ip(),
        udp_port: addr.port(),
        tcp_port: reader.u16()?,
        version: reader.u8()?,
        udp_key: None,
        key_ip: None,
        verified: false,
    };
    let count = reader.u16()? as usize;
    if count > 32 {
        return Err(());
    }
    let mut nodes = vec![responder];
    for _ in 0..count {
        nodes.push(contact(&mut reader)?);
    }
    reader.done()?;
    Ok(nodes)
}

fn decode_find(target: &[u8; 16], payload: &[u8]) -> Result<Vec<KadNode>, ()> {
    let mut reader = Reader::new(payload);
    if &reader.id()?.0 != target {
        return Err(());
    }
    let count = reader.u8()? as usize;
    if count > 32 {
        return Err(());
    }
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        nodes.push(contact(&mut reader)?);
    }
    reader.done()?;
    Ok(nodes)
}

#[derive(Default)]
struct DecodedSources {
    sources: Vec<KadSource>,
    callback: usize,
    crypto: usize,
}

fn tag(reader: &mut Reader<'_>) -> Result<(Option<u8>, Option<u64>), ()> {
    let kind = reader.u8()?;
    let name_len = reader.u16()? as usize;
    let name = reader.take(name_len)?;
    let code = if name.len() == 1 { Some(name[0]) } else { None };
    let value = match kind {
        0x01 => {
            reader.take(16)?;
            None
        }
        0x02 => {
            let len = reader.u16()? as usize;
            reader.take(len)?;
            None
        }
        0x03 => Some(reader.u32()? as u64),
        0x04 => {
            reader.take(4)?;
            None
        }
        0x05 => Some(reader.u8()? as u64),
        0x06 => {
            let bits = reader.u16()? as usize;
            reader.take(bits.div_ceil(8))?;
            None
        }
        0x07 => {
            let len = reader.u32()? as usize;
            reader.take(len)?;
            None
        }
        0x08 => Some(reader.u16()? as u64),
        0x09 => Some(reader.u8()? as u64),
        0x0a => {
            let len = reader.u8()? as usize;
            reader.take(len)?;
            None
        }
        0x0b => Some(reader.u64()?),
        0x11..=0x26 => {
            reader.take((kind - 0x10) as usize)?;
            None
        }
        _ => return Err(()),
    };
    Ok((code, value))
}

fn decode_sources(
    target: &[u8; 16],
    payload: &[u8],
    allow_private: bool,
) -> Result<DecodedSources, ()> {
    let mut reader = Reader::new(payload);
    reader.id()?; // responder ID; source endpoint is checked against pending requests.
    if &reader.id()?.0 != target {
        return Err(());
    }
    let count = reader.u16()?;
    if count > 300 {
        return Err(());
    }
    let mut decoded = DecodedSources::default();
    for _ in 0..count {
        let user_hash = swap_words(reader.id()?.0);
        let tags = reader.u8()?;
        let mut ip = 0;
        let mut port = 0;
        let mut udp = 0;
        let mut source_type = 0;
        let mut crypt_options = 0;
        for _ in 0..tags {
            let (code, value) = tag(&mut reader)?;
            if let Some(value) = value {
                match code {
                    Some(0xfe) if value <= u32::MAX as u64 => ip = value as u32,
                    Some(0xfd) if value <= u16::MAX as u64 => port = value as u16,
                    Some(0xfc) if value <= u16::MAX as u64 => udp = value as u16,
                    Some(0xff) if value <= u8::MAX as u64 => source_type = value as u8,
                    Some(0xf3) if value <= u8::MAX as u64 => crypt_options = value as u8,
                    _ => {}
                }
            }
        }
        if matches!(source_type, 3 | 5 | 6) {
            decoded.callback += 1;
            continue;
        }
        if !matches!(source_type, 1 | 4) {
            continue;
        }
        if crypt_options & 4 != 0 {
            decoded.crypto += 1;
            continue;
        }
        let ip = Ipv4Addr::from(ip);
        if port == 0 || !allowed_ip(ip, allow_private) {
            continue;
        }
        decoded.sources.push(KadSource {
            ip,
            port,
            user_hash,
            udp_port: udp,
            source_type,
            crypt_options,
        });
    }
    reader.done()?;
    Ok(decoded)
}
