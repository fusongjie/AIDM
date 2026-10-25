//! Own-identity SN registration -> resource lookup -> ICall -> SYN -> basic ACK.
//! The returned socket is the one used for every stage, preserving its NAT mapping.
//! This establishes a transport only; file-channel negotiation is still required.
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};

use super::private_nat::{
    build_get_peer_sn_request, build_icall_request, build_ping_sn_request, decode_datagram,
    encode_datagram, parse_get_peer_sn_response, parse_icall_response, parse_ping_sn_response,
    NatState, Packet, SnPeer,
};
use super::private_peer::PeerResource;
use super::private_transport::{peer_id_hash, Data, Syn};

const MAX_DATAGRAM: usize = 65_507;
const WINDOW: u32 = 0x50000;
const RETRY: Duration = Duration::from_millis(500);
const MAX_ATTEMPTS: u8 = 3;
const MAX_DIRECTORY_TARGETS: usize = 64;
const MAX_DIRECTORY_ENDPOINTS: usize = 12;
const MAX_CONNECTIONS: usize = 32;
const HOSTS: [&str; 3] = [
    "hub5pn.sandai.net",
    "g1.hub5pn.sandai.net",
    "g2.hub5pn.sandai.net",
];

#[derive(Debug)]
pub struct Connection {
    pub socket: UdpSocket,
    pub remote_endpoint: SocketAddr,
    pub remote_peer_id: [u8; 16],
    pub identity: [u8; 16],
    /// Logical ports, not the physical UDP endpoints.
    pub source_port: u16,
    pub target_port: u16,
    pub send_next: u32,
    pub receive_next: u32,
    pub window: u32,
    pub external_ip: Option<Ipv4Addr>,
    /// Any stream data arriving with the handshake confirmation is retained.
    /// The consumer must apply reliable-stream/channel processing before using it.
    pub pending: Vec<Data>,
}

#[derive(Default)]
struct Retry {
    attempts: u8,
    last: Option<Instant>,
}
impl Retry {
    fn due(&self) -> bool {
        self.attempts < MAX_ATTEMPTS && self.last.is_none_or(|at| at.elapsed() >= RETRY)
    }
    fn mark(&mut self) {
        self.attempts += 1;
        self.last = Some(Instant::now());
    }
    fn exhausted(&self) -> bool {
        self.attempts >= MAX_ATTEMPTS && self.last.is_some_and(|at| at.elapsed() >= RETRY)
    }
}

struct Candidate {
    resource: PeerResource,
    nodes: Vec<SnPeer>,
    directory_marker: Option<u32>,
    active: bool,
    finished: bool,
    call: Retry,
    offline: bool,
    endpoints: Vec<SocketAddr>,
    source_port: u16,
    target_port: u16,
    initial_sequence: u32,
    remote_initial: Option<u32>,
    syn: Retry,
    basic_ack: Retry,
}

fn candidates(identity: &[u8; 16], targets: &[PeerResource]) -> Result<Vec<Candidate>, String> {
    let mut random = [0_u8; 4];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "private_connection_random")?;
    let base_port = 0x4000 | (u16::from_le_bytes(random[..2].try_into().unwrap()) & 0x3fff);
    let base_sequence = u16::from_le_bytes(random[2..].try_into().unwrap());
    let mut out: Vec<Candidate> = Vec::new();
    for resource in targets {
        if resource.peer_id == *identity
            || out.iter().any(|c| c.resource.peer_id == resource.peer_id)
        {
            continue;
        }
        let n = out.len() as u16;
        out.push(Candidate {
            resource: resource.clone(),
            nodes: Vec::new(),
            directory_marker: None,
            active: false,
            finished: false,
            call: Retry::default(),
            offline: false,
            endpoints: Vec::new(),
            source_port: base_port.wrapping_add(n),
            target_port: 0,
            initial_sequence: u32::from(base_sequence.wrapping_sub(n.wrapping_mul(0x600))),
            remote_initial: None,
            syn: Retry::default(),
            basic_ack: Retry::default(),
        });
        if out.len() == MAX_DIRECTORY_TARGETS {
            break;
        }
    }
    Ok(out)
}

fn activate(candidates: &mut [Candidate], limit: usize) {
    let mut active = candidates
        .iter()
        .filter(|c| c.active && !c.finished)
        .count();
    while active < limit {
        let next = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.active && !c.finished && !c.nodes.is_empty())
            // This raw value is the class observed in the successful public
            // handshake, not a claim that all other NAT classes are supported.
            .min_by_key(|(_, c)| usize::from(c.directory_marker != Some(196_864)))
            .map(|(n, _)| n);
        let Some(n) = next else { break };
        candidates[n].active = true;
        active += 1;
    }
}

fn send_punch(socket: &UdpSocket, identity: &[u8; 16], c: &Candidate) -> Result<(), String> {
    let mut body = 16_u32.to_le_bytes().to_vec();
    body.extend_from_slice(identity);
    body.extend_from_slice(&c.source_port.to_le_bytes());
    body.extend_from_slice(&c.target_port.to_le_bytes());
    let wire = encode_datagram(59, 5, &body, 3)?;
    for endpoint in &c.endpoints {
        let _ = socket.send_to(&wire, endpoint);
    }
    Ok(())
}

fn local_ipv4_for(endpoint: SocketAddr) -> Ipv4Addr {
    // UDP connect chooses the local route without transmitting a datagram.
    let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0));
    if let Ok(route) = route {
        if route.connect(endpoint).is_ok() {
            if let Ok(SocketAddr::V4(addr)) = route.local_addr() {
                return *addr.ip();
            }
        }
    }
    Ipv4Addr::UNSPECIFIED
}

fn send_syn(socket: &UdpSocket, identity: &[u8; 16], c: &mut Candidate) -> Result<(), String> {
    if c.syn.attempts >= MAX_ATTEMPTS || c.remote_initial.is_some() {
        return Ok(());
    }
    let frame = Syn {
        flags: 0,
        source_port: c.source_port,
        target_port: c.target_port,
        peer_hash: peer_id_hash(identity),
        sequence: c.initial_sequence,
        ack: 0,
        window: WINDOW,
        udt_version: 0,
    };
    let wire = encode_datagram(59, 6, &frame.encode(), 3)?;
    c.syn.mark();
    for endpoint in &c.endpoints {
        let _ = socket.send_to(&wire, endpoint);
    }
    Ok(())
}

fn send_basic_ack(
    socket: &UdpSocket,
    identity: &[u8; 16],
    c: &mut Candidate,
) -> Result<(), String> {
    let Some(remote_initial) = c.remote_initial else {
        return Ok(());
    };
    if c.basic_ack.attempts >= MAX_ATTEMPTS {
        return Ok(());
    }
    let frame = Data {
        source_port: c.source_port,
        target_port: c.target_port,
        peer_hash: peer_id_hash(identity),
        sequence: c.initial_sequence.wrapping_add(1),
        ack: remote_initial.wrapping_add(1),
        window: WINDOW,
        packet_sequence: None,
        timing: None,
        payload: Vec::new(),
    };
    let wire = encode_datagram(59, 9, &frame.encode(59)?, 3)?;
    c.basic_ack.mark();
    // The successful SYN endpoint is placed first; the reply confirms this path.
    let _ = socket.send_to(&wire, c.endpoints[0]);
    Ok(())
}

fn punch(packet: &Packet, expected: &[u8; 16], own_port: u16) -> Option<u16> {
    if (packet.protocol, packet.command) != (59, 5)
        || packet.body.len() != 24
        || packet.body[..4] != 16_u32.to_le_bytes()
        || packet.body[4..20] != *expected
        || packet.body[22..24] != own_port.to_le_bytes()
    {
        return None;
    }
    Some(u16::from_le_bytes(packet.body[20..22].try_into().unwrap()))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorStats {
    pub candidates: usize,
    pub with_super_nodes: usize,
    pub online: usize,
    pub offline: usize,
    pub connecting: usize,
    pub connected_now: usize,
    pub registered: bool,
    pub discovery_finished: bool,
}

/// A single registered physical UDP endpoint with independent virtual connections.
/// The caller exclusively owns recv_from and routes decoded packets to on_packet.
/// Handles returned for sessions are clones for sending; they must not receive.
pub struct Connector {
    identity: [u8; 16],
    socket: UdpSocket,
    candidates: Vec<Candidate>,
    state: NatState,
    directories: Receiver<SocketAddr>,
    directory_endpoints: HashSet<SocketAddr>,
    registration: Retry,
    registered: bool,
    external_ip: Option<Ipv4Addr>,
    deadline: Instant,
    /// Ignore the discovery deadline; finish only when every candidate is spent.
    streaming: bool,
    max_connections: usize,
    connected: HashSet<u16>,
}

impl Connector {
    /// Begin at most 64 candidate lookups with 1..=32 global connection slots.
    /// DNS and connection attempts are bounded to ten seconds; an established
    /// session remains usable after that connection-discovery deadline.
    pub fn begin(
        identity: &[u8; 16],
        targets: &[PeerResource],
        max_connections: usize,
        timeout: Duration,
    ) -> Result<Self, String> {
        if timeout.is_zero() || targets.is_empty() || max_connections == 0 {
            return Err("private_connection_no_targets_or_time_or_slots".into());
        }
        let deadline = Instant::now() + timeout.min(Duration::from_secs(10));
        let (tx, rx) = mpsc::channel();
        let connector = Self::resolved(identity, targets, max_connections, deadline, rx)?;
        std::thread::Builder::new()
            .name("aidm-private-dns".into())
            .spawn(move || {
                // 同一 SN 域名通常解析出多个运营商/地域入口。只取第一个时，
                // 一旦该入口不可达，整轮私有发现会在连接窗口内空转；这里把
                // 所有不同的 IPv4 入口都交给 Connector，由它在注册阶段并行探测。
                let mut seen = HashSet::new();
                for host in HOSTS {
                    if let Ok(addresses) = (host, 8000).to_socket_addrs() {
                        for endpoint in addresses.filter(SocketAddr::is_ipv4) {
                            if !seen.insert(endpoint) {
                                continue;
                            }
                            if seen.len() > MAX_DIRECTORY_ENDPOINTS {
                                return;
                            }
                            if tx.send(endpoint).is_err() {
                                return;
                            }
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(connector)
    }

    fn resolved(
        identity: &[u8; 16],
        targets: &[PeerResource],
        max_connections: usize,
        deadline: Instant,
        directories: Receiver<SocketAddr>,
    ) -> Result<Self, String> {
        if max_connections == 0 {
            return Err("private_connection_no_slots".into());
        }
        let candidates = candidates(identity, targets)?;
        if candidates.is_empty() {
            return Err("private_connection_no_targets".into());
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
        let local_port = socket.local_addr().map_err(|e| e.to_string())?.port();
        Ok(Self {
            identity: *identity,
            socket,
            candidates,
            state: NatState::initial(local_port, 0, Ipv4Addr::UNSPECIFIED),
            directories,
            directory_endpoints: HashSet::new(),
            registration: Retry::default(),
            registered: false,
            external_ip: None,
            deadline,
            streaming: false,
            max_connections: max_connections.min(MAX_CONNECTIONS),
            connected: HashSet::new(),
        })
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn stats(&self) -> ConnectorStats {
        ConnectorStats {
            candidates: self.candidates.len(),
            with_super_nodes: self
                .candidates
                .iter()
                .filter(|c| !c.nodes.is_empty())
                .count(),
            online: self
                .candidates
                .iter()
                .filter(|c| !c.endpoints.is_empty())
                .count(),
            offline: self.candidates.iter().filter(|c| c.offline).count(),
            connecting: self
                .candidates
                .iter()
                .filter(|c| c.active && !c.finished)
                .count(),
            connected_now: self.connected.len(),
            registered: self.registered,
            discovery_finished: self.is_finished(),
        }
    }

    /// True when no more connection discoveries can be produced. Existing
    /// returned connections are independent of this discovery lifetime.
    pub fn is_finished(&self) -> bool {
        if Instant::now() < self.deadline {
            return self.candidates.iter().all(|c| c.finished);
        }
        if !(self.streaming && self.registered) {
            return true;
        }
        // Lookups are not retried, so a candidate without super nodes after
        // the deadline can never be activated.
        !self
            .candidates
            .iter()
            .any(|c| !c.finished && !c.nodes.is_empty())
    }

    /// Keep replacing released slots from untried candidates for the owner's
    /// whole lifetime instead of only during the initial discovery window.
    /// Requires registration within the deadline; each candidate keeps its
    /// own bounded retries, so this still terminates.
    pub fn stream_until_exhausted(&mut self) {
        self.streaming = true;
    }

    /// Return a live-session slot after its owner has discarded the session.
    /// Its peer is not retried; the next unused candidate may fill the slot.
    pub fn release_connection(&mut self, source_port: u16) {
        self.connected.remove(&source_port);
    }

    /// Drive sends, DNS results, bounded retries and candidate replacement.
    /// This method never reads UDP, sleeps, or waits for the whole pool.
    pub fn tick(&mut self, cancelled: &AtomicBool) -> Result<Vec<Connection>, String> {
        if cancelled.load(Ordering::Relaxed) {
            return Err("private_connection_cancelled".into());
        }
        if self.is_finished() {
            return Ok(Vec::new());
        }
        while let Ok(endpoint) = self.directories.try_recv() {
            if !endpoint.is_ipv4()
                || self.directory_endpoints.len() >= MAX_DIRECTORY_ENDPOINTS
                || !self.directory_endpoints.insert(endpoint)
            {
                continue;
            }
            if self.state.internal_ip.is_unspecified() {
                self.state.internal_ip = local_ipv4_for(endpoint);
            }
            for c in &self.candidates {
                let request = build_get_peer_sn_request(&c.resource.peer_id, false, 3)?;
                let _ = self.socket.send_to(&request, endpoint);
            }
        }
        if !self.registered && !self.directory_endpoints.is_empty() && self.registration.due() {
            let request = build_ping_sn_request(&self.identity, &self.state, 3)?;
            self.registration.mark();
            for endpoint in &self.directory_endpoints {
                let _ = self.socket.send_to(&request, endpoint);
            }
        }
        for c in &mut self.candidates {
            if c.active
                && (c.offline
                    || if c.remote_initial.is_some() {
                        c.basic_ack.exhausted()
                    } else if !c.endpoints.is_empty() {
                        c.syn.exhausted()
                    } else {
                        c.call.exhausted()
                    })
            {
                c.active = false;
                c.finished = true;
            }
        }
        if self.registered {
            let available = self.max_connections.saturating_sub(self.connected.len());
            activate(&mut self.candidates, available);
        }
        for c in &mut self.candidates {
            if !c.active || c.finished {
                continue;
            }
            if self.registered
                && !c.nodes.is_empty()
                && !c.offline
                && c.endpoints.is_empty()
                && c.call.due()
            {
                let node = &c.nodes[usize::from(c.call.attempts) % c.nodes.len()];
                let request = build_icall_request(
                    &self.identity,
                    &c.resource.peer_id,
                    c.source_port,
                    &self.state,
                    node,
                    3,
                )?;
                c.call.mark();
                let _ = self.socket.send_to(&request, node.endpoint);
            }
            if !c.endpoints.is_empty() && c.remote_initial.is_none() && c.syn.due() {
                send_syn(&self.socket, &self.identity, c)?;
            }
            if c.remote_initial.is_some() && c.basic_ack.due() {
                send_basic_ack(&self.socket, &self.identity, c)?;
            }
        }
        Ok(Vec::new())
    }

    /// Feed exactly one decoded datagram from the external single receive owner.
    /// The first confirmed ACK returns a connection immediately. Later stream
    /// packets for that virtual port belong exclusively to the session owner.
    pub fn on_packet(
        &mut self,
        source: SocketAddr,
        packet: &Packet,
    ) -> Result<Option<Connection>, String> {
        if self.is_finished() {
            return Ok(None);
        }
        if self.directory_endpoints.contains(&source) {
            if let Ok(response) = parse_ping_sn_response(packet) {
                self.registered = true;
                self.external_ip = Some(response.external_ip);
                return Ok(None);
            }
            for c in &mut self.candidates {
                if let Ok(response) = parse_get_peer_sn_response(packet, &c.resource.peer_id) {
                    c.directory_marker = response.unknown_ipv4_words.map(|w| w[0]);
                    for node in response.super_nodes {
                        if node.endpoint.is_ipv4() && c.nodes.len() < 3 && !c.nodes.contains(&node)
                        {
                            c.nodes.push(node);
                        }
                    }
                    return Ok(None);
                }
            }
        }
        for c in &mut self.candidates {
            if !c.active || c.finished {
                continue;
            }
            if c.nodes.iter().any(|node| node.endpoint == source) {
                if let Ok(response) =
                    parse_icall_response(packet, &c.resource.peer_id, c.source_port)
                {
                    if !c
                        .nodes
                        .iter()
                        .any(|node| node.peer_id == response.sn_peer_id)
                    {
                        continue;
                    }
                    if response.online == 0 {
                        c.offline = true;
                    } else if c.endpoints.is_empty() {
                        c.endpoints.push(response.remote_endpoint);
                        for port in [response.latest_remote_port, response.guessed_remote_port]
                            .into_iter()
                            .flatten()
                        {
                            let endpoint = SocketAddr::new(response.remote_endpoint.ip(), port);
                            if port != 0
                                && c.endpoints.len() < 3
                                && !c.endpoints.contains(&endpoint)
                            {
                                c.endpoints.push(endpoint);
                            }
                        }
                        send_punch(&self.socket, &self.identity, c)?;
                        send_syn(&self.socket, &self.identity, c)?;
                    }
                    return Ok(None);
                }
            }
            if c.call.attempts > 0 || !c.endpoints.is_empty() {
                if let Some(port) = punch(packet, &c.resource.peer_id, c.source_port) {
                    if c.remote_initial.is_none() {
                        c.target_port = port;
                        c.endpoints.retain(|endpoint| *endpoint != source);
                        c.endpoints.insert(0, source);
                        c.endpoints.truncate(3);
                        send_syn(&self.socket, &self.identity, c)?;
                    }
                    return Ok(None);
                }
            }
            if !c.endpoints.contains(&source) {
                continue;
            }
            if let Ok(syn) = Syn::parse(packet) {
                if syn.flags == 1
                    && syn.peer_hash == peer_id_hash(&c.resource.peer_id)
                    && syn.target_port == c.source_port
                    && syn.ack == c.initial_sequence.wrapping_add(1)
                    && c.remote_initial.is_none_or(|seq| seq == syn.sequence)
                {
                    c.remote_initial = Some(syn.sequence);
                    c.target_port = syn.source_port;
                    c.endpoints.retain(|endpoint| *endpoint != source);
                    c.endpoints.insert(0, source);
                    send_basic_ack(&self.socket, &self.identity, c)?;
                    return Ok(None);
                }
                continue;
            }
            if let (Some(remote_initial), Ok(data)) = (c.remote_initial, Data::parse(packet)) {
                if c.basic_ack.attempts > 0
                    && data.peer_hash == peer_id_hash(&c.resource.peer_id)
                    && data.source_port == c.target_port
                    && data.target_port == c.source_port
                    && data.sequence == remote_initial.wrapping_add(1)
                    && data.ack == c.initial_sequence.wrapping_add(1)
                {
                    let socket = self.socket.try_clone().map_err(|e| e.to_string())?;
                    let pending = if data.payload.is_empty() {
                        Vec::new()
                    } else {
                        vec![data]
                    };
                    c.active = false;
                    c.finished = true;
                    self.connected.insert(c.source_port);
                    return Ok(Some(Connection {
                        socket,
                        remote_endpoint: source,
                        remote_peer_id: c.resource.peer_id,
                        identity: self.identity,
                        source_port: c.source_port,
                        target_port: c.target_port,
                        send_next: c.initial_sequence.wrapping_add(1),
                        receive_next: remote_initial.wrapping_add(1),
                        window: WINDOW,
                        external_ip: self.external_ip,
                        pending,
                    }));
                }
            }
        }
        Ok(None)
    }

    fn timeout_error(&self) -> String {
        format!(
            "private_connection_timeout targets={} online={} connected={}",
            self.candidates.len(),
            self.candidates
                .iter()
                .filter(|c| !c.endpoints.is_empty())
                .count(),
            self.connected.len(),
        )
    }
}

/// Compatibility entry point for one connection. Only this driver reads UDP;
/// pool callers must use Connector and their own single receive dispatcher.
pub fn connect(
    identity: &[u8; 16],
    targets: &[PeerResource],
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Connection, String> {
    if cancelled.load(Ordering::Relaxed) {
        return Err("private_connection_cancelled".into());
    }
    let connector = Connector::begin(identity, targets, 3, timeout)?;
    drive_one(connector, cancelled)
}

#[cfg(test)]
fn connect_resolved(
    identity: &[u8; 16],
    targets: &[PeerResource],
    deadline: Instant,
    cancelled: &AtomicBool,
    directories: Receiver<SocketAddr>,
) -> Result<Connection, String> {
    drive_one(
        Connector::resolved(identity, targets, 3, deadline, directories)?,
        cancelled,
    )
}

fn drive_one(mut connector: Connector, cancelled: &AtomicBool) -> Result<Connection, String> {
    let mut buffer = [0_u8; MAX_DATAGRAM];
    while !connector.is_finished() {
        if let Some(connection) = connector.tick(cancelled)?.into_iter().next() {
            return Ok(connection);
        }
        let remaining = connector.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        connector
            .socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(30))))
            .map_err(|e| e.to_string())?;
        let (n, source) = match connector.socket.recv_from(&mut buffer) {
            Ok(value) => value,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => return Err(e.to_string()),
        };
        let Ok(packet) = decode_datagram(&buffer[..n]) else {
            continue;
        };
        if let Some(connection) = connector.on_packet(source, &packet)? {
            return Ok(connection);
        }
    }
    Err(connector.timeout_error())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    const OWN: &[u8; 16] = b"0123456789ABCDNM";
    const REMOTE: &[u8; 16] = b"0123456789ABCDDU";
    const SN: &[u8; 16] = b"524B4153A8F00000";

    /// Explicit opt-in: the fixture must be a fresh QueryPeer response. This
    /// identity belongs to this probe only and must not be shared with downloads.
    #[test]
    #[ignore = "explicit live SN/peer network probe"]
    fn live_fresh_directory_connection() {
        let path = std::env::var("AIDM_REA_QUERY_PEER_FIXTURE").unwrap();
        let bytes = std::fs::read(path).unwrap();
        let directory = super::super::private_peer::parse_response(&bytes).unwrap();
        let identity = super::super::private_index::peer_id(&[0x72; 16]);
        let start = Instant::now();
        let connection = connect(
            &identity,
            &directory.peers,
            Duration::from_secs(5),
            &AtomicBool::new(false),
        )
        .unwrap();
        println!(
            "live_connection elapsed_ms={} remote={} remote_peer_id={} src_vport={} dst_vport={} send_next={} receive_next={} local_udp_port={}",
            start.elapsed().as_millis(),
            connection.remote_endpoint,
            String::from_utf8_lossy(&connection.remote_peer_id),
            connection.source_port,
            connection.target_port,
            connection.send_next,
            connection.receive_next,
            connection.socket.local_addr().unwrap().port(),
        );
    }

    #[test]
    #[ignore = "explicit live shared-socket two-peer network probe"]
    fn live_shared_socket_two_peers() {
        let path = std::env::var("AIDM_REA_QUERY_PEER_FIXTURE").unwrap();
        let bytes = std::fs::read(path).unwrap();
        let directory = super::super::private_peer::parse_response(&bytes).unwrap();
        let identity = super::super::private_index::peer_id(&[0x73; 16]);
        let mut connector =
            Connector::begin(&identity, &directory.peers, 2, Duration::from_secs(5)).unwrap();
        let local = connector.socket().local_addr().unwrap();
        connector
            .socket()
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let start = Instant::now();
        let stopped = AtomicBool::new(false);
        let mut connections = Vec::new();
        let mut buffer = [0_u8; MAX_DATAGRAM];
        while connections.len() < 2 && !connector.is_finished() {
            assert!(connector.tick(&stopped).unwrap().is_empty());
            let (n, source) = match connector.socket().recv_from(&mut buffer) {
                Ok(value) => value,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(e) => panic!("{e}"),
            };
            let Ok(packet) = decode_datagram(&buffer[..n]) else {
                continue;
            };
            if let Some(connection) = connector.on_packet(source, &packet).unwrap() {
                assert_eq!(connection.socket.local_addr().unwrap(), local);
                println!("live_pool elapsed_ms={} remote={} remote_peer_id={} src_vport={} dst_vport={} send_next={} receive_next={} local_udp_port={}",
                    start.elapsed().as_millis(), connection.remote_endpoint,
                    String::from_utf8_lossy(&connection.remote_peer_id), connection.source_port,
                    connection.target_port, connection.send_next, connection.receive_next, local.port());
                connections.push(connection);
            }
        }
        assert_eq!(connections.len(), 2, "{}", connector.timeout_error());
        assert_ne!(connections[0].remote_peer_id, connections[1].remote_peer_id);
        assert_ne!(connections[0].source_port, connections[1].source_port);
        assert_eq!(connector.connected.len(), 2);
    }

    fn resource() -> PeerResource {
        PeerResource {
            peer_id: *REMOTE,
            internal_ip: "192.0.2.10".parse().unwrap(),
            tcp_port: 54321,
            udp_port: 12345,
            capability: 0,
            hub_type: 1,
        }
    }
    fn lp(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    fn transmit(socket: &UdpSocket, to: SocketAddr, protocol: u32, command: u8, body: &[u8]) {
        socket
            .send_to(&encode_datagram(protocol, command, body, 3).unwrap(), to)
            .unwrap();
    }

    #[test]
    fn same_socket_registration_icall_syn_and_bidirectional_ack() {
        let directory = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dir_addr = directory.local_addr().unwrap();
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let hint = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let hint_addr = hint.local_addr().unwrap();
        directory
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        hint.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let dir_thread = thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            let mut source = None;
            loop {
                let (n, from) = directory.recv_from(&mut buf).unwrap();
                if let Some(expected) = source {
                    assert_eq!(from, expected);
                }
                source = Some(from);
                let p = decode_datagram(&buf[..n]).unwrap();
                match (p.protocol, p.command) {
                    (66, 2) => {
                        let mut body = Vec::new();
                        lp(&mut body, SN);
                        body.extend([127, 0, 0, 1]);
                        transmit(&directory, from, 66, 253, &body);
                    }
                    (67, 0) => {
                        assert_eq!(&p.body[4..], REMOTE);
                        let mut body = vec![1];
                        body.extend(1_u32.to_le_bytes());
                        lp(&mut body, SN);
                        body.extend([127, 0, 0, 1]);
                        body.extend(dir_addr.port().to_le_bytes());
                        lp(&mut body, REMOTE);
                        body.extend([0_u8; 12]);
                        transmit(&directory, from, 67, 255, &body);
                    }
                    (62, 3) => {
                        let vport = u16::from_le_bytes(p.body[40..42].try_into().unwrap());
                        let mut body = Vec::new();
                        lp(&mut body, SN);
                        lp(&mut body, REMOTE);
                        body.push(1);
                        body.extend([127, 0, 0, 1]);
                        body.extend(hint_addr.port().to_le_bytes());
                        body.extend(vport.to_le_bytes());
                        body.extend(0_u32.to_le_bytes());
                        body.extend(0_u16.to_le_bytes());
                        body.extend(0_u16.to_le_bytes());
                        body.extend(1_u16.to_le_bytes());
                        body.push(3);
                        body.extend(0_u32.to_le_bytes());
                        transmit(&directory, from, 62, 252, &body);
                        return from;
                    }
                    _ => panic!("unexpected directory packet"),
                }
            }
        });
        let peer_thread = thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            let (n, from) = hint.recv_from(&mut buf).unwrap();
            let first = decode_datagram(&buf[..n]).unwrap();
            assert_eq!((first.protocol, first.command), (59, 5));
            let own_port = u16::from_le_bytes(first.body[20..22].try_into().unwrap());
            let mut mapped_punch = Vec::new();
            lp(&mut mapped_punch, REMOTE);
            mapped_punch.extend(0_u16.to_le_bytes());
            mapped_punch.extend(own_port.to_le_bytes());
            // The real peer appears on a different physical port than ICall's
            // hint. Its full identity and our virtual port authorize migration.
            transmit(&peer, from, 59, 5, &mapped_punch);
            let (n, from) = peer.recv_from(&mut buf).unwrap();
            let p = decode_datagram(&buf[..n]).unwrap();
            let syn = Syn::parse(&p).unwrap();
            assert_eq!(syn.flags, 0);
            assert_eq!(syn.target_port, 0);
            assert_eq!(syn.peer_hash, peer_id_hash(OWN));
            let answer = Syn {
                flags: 1,
                source_port: 0,
                target_port: syn.source_port,
                peer_hash: peer_id_hash(REMOTE),
                sequence: 49152,
                ack: syn.sequence.wrapping_add(1),
                window: WINDOW,
                udt_version: 0,
            };
            // A forged identity must not advance the handshake.
            let mut wrong = answer.clone();
            wrong.peer_hash ^= 1;
            transmit(&peer, from, 59, 6, &wrong.encode());
            transmit(&peer, from, 59, 6, &answer.encode());
            let (n, again) = peer.recv_from(&mut buf).unwrap();
            assert_eq!(again, from);
            let ack = Data::parse(&decode_datagram(&buf[..n]).unwrap()).unwrap();
            assert_eq!(ack.sequence, syn.sequence.wrapping_add(1));
            assert_eq!(ack.ack, 49153);
            assert!(ack.payload.is_empty());
            assert!(ack.packet_sequence.is_none());
            let reply = Data {
                source_port: 0,
                target_port: syn.source_port,
                peer_hash: peer_id_hash(REMOTE),
                sequence: 49153,
                ack: ack.sequence,
                window: WINDOW,
                packet_sequence: None,
                timing: None,
                payload: Vec::new(),
            };
            transmit(&peer, from, 59, 9, &reply.encode(59).unwrap());
            from
        });
        let (tx, rx) = mpsc::channel();
        tx.send(dir_addr).unwrap();
        drop(tx);
        let cancelled = AtomicBool::new(false);
        let connection = connect_resolved(
            OWN,
            &[resource()],
            Instant::now() + Duration::from_secs(2),
            &cancelled,
            rx,
        )
        .unwrap();
        assert_eq!(connection.remote_endpoint, peer_addr);
        assert_eq!(connection.remote_peer_id, *REMOTE);
        assert_eq!(connection.receive_next, 49153);
        assert_eq!(connection.target_port, 0);
        assert!(connection.pending.is_empty());
        let from_dir = dir_thread.join().unwrap();
        let from_peer = peer_thread.join().unwrap();
        assert_eq!(from_dir, from_peer);
        assert_eq!(
            connection.socket.local_addr().unwrap().port(),
            from_dir.port()
        );
    }

    #[test]
    fn cancellation_and_source_bound() {
        let stopped = AtomicBool::new(true);
        assert!(
            connect(OWN, &[resource()], Duration::from_secs(5), &stopped)
                .unwrap_err()
                .contains("cancelled")
        );
        let mut resources = Vec::new();
        for n in 0..8 {
            let mut item = resource();
            item.peer_id[0] = b'A' + n;
            resources.push(item);
        }
        assert_eq!(candidates(OWN, &resources).unwrap().len(), 8);
        let mut large = Vec::new();
        for n in 0..96 {
            let mut item = resource();
            item.peer_id[0] = b'A' + n;
            large.push(item);
        }
        assert_eq!(candidates(OWN, &large).unwrap().len(), 64);
        let mut bounded = candidates(OWN, &resources).unwrap();
        for c in &mut bounded {
            c.nodes.push(SnPeer {
                peer_id: *SN,
                endpoint: "127.0.0.1:8000".parse().unwrap(),
            });
        }
        activate(&mut bounded, 3);
        assert_eq!(bounded.iter().filter(|c| c.active).count(), 3);
        bounded[0].active = false;
        bounded[0].finished = true;
        activate(&mut bounded, 3);
        assert_eq!(bounded.iter().filter(|c| c.active).count(), 3);
        assert_eq!(candidates(OWN, &[resource(), resource()]).unwrap().len(), 1);
    }

    #[test]
    fn streaming_pool_isolates_virtual_ports_and_replaces_released_slots() {
        let directory = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dir_addr = directory.local_addr().unwrap();
        // All mock identities share an endpoint to exercise virtual-port routing.
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let mut targets = Vec::new();
        for n in 0..3 {
            let mut item = resource();
            item.peer_id[0] = b'A' + n;
            targets.push(item);
        }
        let (tx, rx) = mpsc::channel();
        tx.send(dir_addr).unwrap();
        let mut connector = Connector::resolved(
            OWN,
            &targets,
            2,
            Instant::now() + Duration::from_secs(2),
            rx,
        )
        .unwrap();
        let stopped = AtomicBool::new(false);
        connector.tick(&stopped).unwrap();
        let mut registered = Vec::new();
        lp(&mut registered, SN);
        registered.extend([127, 0, 0, 1]);
        let packet = |protocol, command, body: &[u8]| {
            decode_datagram(&encode_datagram(protocol, command, body, 0).unwrap()).unwrap()
        };
        connector
            .on_packet(dir_addr, &packet(66, 253, &registered))
            .unwrap();
        for target in &targets {
            let mut body = vec![1];
            body.extend(1_u32.to_le_bytes());
            lp(&mut body, SN);
            body.extend([127, 0, 0, 1]);
            body.extend(dir_addr.port().to_le_bytes());
            lp(&mut body, &target.peer_id);
            body.extend([0_u8; 12]);
            connector
                .on_packet(dir_addr, &packet(67, 255, &body))
                .unwrap();
        }
        connector.tick(&stopped).unwrap();
        assert_eq!(connector.candidates.iter().filter(|c| c.active).count(), 2);
        let mut connected = Vec::new();
        // Finish the second candidate first; the first candidate shares its
        // endpoint and must not consume a SYN for another local virtual port.
        for n in [1, 0] {
            let c = &connector.candidates[n];
            let (id, port, initial) = (c.resource.peer_id, c.source_port, c.initial_sequence);
            let mut body = Vec::new();
            lp(&mut body, SN);
            lp(&mut body, &id);
            body.push(1);
            body.extend([127, 0, 0, 1]);
            body.extend(peer_addr.port().to_le_bytes());
            body.extend(port.to_le_bytes());
            body.extend([0_u8; 15]);
            connector
                .on_packet(dir_addr, &packet(62, 252, &body))
                .unwrap();
            let syn = Syn {
                flags: 1,
                source_port: 0,
                target_port: port,
                peer_hash: peer_id_hash(&id),
                sequence: 49152 + n as u32,
                ack: initial.wrapping_add(1),
                window: WINDOW,
                udt_version: 0,
            };
            assert!(connector
                .on_packet(peer_addr, &packet(59, 6, &syn.encode()))
                .unwrap()
                .is_none());
            let data = Data {
                source_port: 0,
                target_port: port,
                peer_hash: peer_id_hash(&id),
                sequence: syn.sequence + 1,
                ack: initial.wrapping_add(1),
                window: WINDOW,
                packet_sequence: Some(0),
                timing: None,
                payload: vec![n as u8; 4],
            };
            let frame = packet(59, 18, &data.encode(59).unwrap());
            let connection = connector.on_packet(peer_addr, &frame).unwrap().unwrap();
            assert_eq!(connection.pending[0].payload, vec![n as u8; 4]);
            assert_eq!(connection.receive_next, syn.sequence + 1);
            assert_eq!(
                connection.socket.local_addr().unwrap(),
                connector.socket.local_addr().unwrap()
            );
            // This port now belongs to the caller's Session, not Connector.
            assert!(connector.on_packet(peer_addr, &frame).unwrap().is_none());
            connected.push(connection);
            connector.tick(&stopped).unwrap();
            assert!(!connector.candidates[2].active);
        }
        assert_ne!(connected[0].source_port, connected[1].source_port);
        assert_eq!(connector.registration.attempts, 1);
        connector.release_connection(connected[0].source_port);
        connector.tick(&stopped).unwrap();
        assert!(connector.candidates[2].active);
        assert_eq!(connector.connected.len(), 1);
        assert_eq!(connector.registration.attempts, 1);
        connector.deadline = Instant::now();
        assert!(connector.tick(&stopped).unwrap().is_empty());
        assert!(connector.is_finished());
        assert_eq!(
            connected[1].socket.local_addr().unwrap(),
            connector.socket.local_addr().unwrap()
        );

        // A long-lived owner keeps filling slots after the discovery deadline
        // and still terminates once every reachable candidate is spent.
        connector.stream_until_exhausted();
        assert!(!connector.is_finished());
        let calls = connector.candidates[2].call.attempts;
        connector.candidates[2].call.last = None;
        connector.tick(&stopped).unwrap();
        assert_eq!(connector.candidates[2].call.attempts, calls + 1);
        connector.candidates[2].finished = true;
        assert!(connector.is_finished());
    }

    #[test]
    fn streaming_never_outlives_a_failed_registration() {
        let (_tx, rx) = mpsc::channel();
        let mut connector = Connector::resolved(OWN, &[resource()], 2, Instant::now(), rx).unwrap();
        connector.stream_until_exhausted();
        assert!(connector.is_finished());
    }
}
