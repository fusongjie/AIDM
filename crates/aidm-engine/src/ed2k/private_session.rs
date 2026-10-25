//! Reliable private-channel session. One UDP receive owner may feed many
//! sessions; a session never consumes another virtual connection's datagrams.
use super::{
    private_channel::{self, Decoder, Frame},
    private_connection::Connection,
    private_index::Metadata,
    private_nat::{self, Packet},
    private_transport::{peer_id_hash, Data, Syn},
};
use aidm_core::ed2k::FileLink;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const WINDOW: usize = 0x50000;
// ACK 超时不能按"本机回环"调：公网 P2P 的 RTT 抖动远大于 300ms。
// 300ms×5 次（1.5s）会把只是慢一点的源判死；500ms×10 次（5s）才接近
// 一个可用的公网等待窗口。
const RETRY: Duration = Duration::from_millis(500);
const MAX_ATTEMPTS: u8 = 10;
const MAX_RANGE: u64 = 9_728_000;
/// 单帧 payload 上限（MTU 预算），与协议窗口无关。
const MAX_FRAME: usize = 1400;
/// 未 ACK 帧的内存保护上限（不是协议窗口；正常窗口约 234 帧）。
const MAX_UNACKED_FRAMES: usize = 1024;

/// 发送窗口是否已满：**按 payload 字节**算，不是按帧数。
///
/// 协议声明的 `WINDOW` 是 327,680 B；按 64 帧（约 89KB）算会提前判满，
/// 窗口满还会直接判会话失败。这里抽成纯函数，便于单测钉住边界。
fn window_full(inflight: usize, frame_len: usize) -> bool {
    inflight.saturating_add(frame_len) > WINDOW
}

struct Sent {
    end: u32,
    wire: Vec<u8>,
    /// 该帧的协议 payload 字节数（窗口按 payload 计，不是 UDP 线长）。
    len: usize,
    first: Instant,
    last: Instant,
    attempts: u8,
}

/// Per-stream transfer counters for diagnostics; they never affect protocol state.
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionStats {
    pub data_packets: u64,
    pub payload_bytes: u64,
    pub duplicate_packets: u64,
    pub out_of_order_packets: u64,
    pub acks_sent: u64,
    pub resends: u64,
    pub remote_window: u32,
    pub advertised_window: u32,
    pub reassembly_peak: usize,
    pub flow_drops: u64,
    pub rtt_min: Option<Duration>,
    pub rtt_last: Option<Duration>,
    pub request_latency: Option<Duration>,
    pub requests: u64,
}

#[derive(Default)]
struct Reassembly {
    pending: HashMap<u32, Vec<u8>>,
    bytes: usize,
    /// Segments refused for flow control; they are neither stored nor acknowledged.
    dropped: u64,
}
impl Reassembly {
    fn push(
        &mut self,
        next: &mut u32,
        mut sequence: u32,
        mut data: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let distance = sequence.wrapping_sub(*next) as i32;
        if distance < 0 {
            let skip = next.wrapping_sub(sequence) as usize;
            if skip >= data.len() {
                return Ok(Vec::new());
            }
            data = &data[skip..];
            sequence = *next;
        }
        // Peers overshoot the advertised window; refusing the segment keeps
        // memory bounded and lets the sender retransmit, unlike a reset.
        if sequence.wrapping_sub(*next) as usize > WINDOW || data.len() > WINDOW {
            self.dropped += 1;
            return Ok(Vec::new());
        }
        if let Some(old) = self.pending.get(&sequence) {
            if old != data {
                return Err("private_stream_conflicting_retransmit".into());
            }
        } else {
            if self.bytes + data.len() > WINDOW * 2 || self.pending.len() >= 1024 {
                self.dropped += 1;
                return Ok(Vec::new());
            }
            self.bytes += data.len();
            self.pending.insert(sequence, data.to_vec());
        }
        let mut out = Vec::new();
        while let Some(data) = self.pending.remove(next) {
            self.bytes -= data.len();
            *next = next.wrapping_add(data.len() as u32);
            out.push(data);
        }
        Ok(out)
    }
}

pub struct Session {
    pub connection: Connection,
    decoder: Decoder,
    reassembly: Reassembly,
    sent: Vec<Sent>,
    handshake_ok: bool,
    unchoked: bool,
    pub last_file_data: Instant,
    pub stats: SessionStats,
    requested_at: Option<Instant>,
}

impl Drop for Session {
    fn drop(&mut self) {
        // 可靠 UDP 的 Close 帧 (1002fe80 -> 10030a00) 在释放前发 Reset7
        // a connected stream. Only this virtual connection is reset; other
        // sessions retain the shared UDP socket and its SN registration.
        let c = &self.connection;
        let mut body = Vec::with_capacity(8);
        body.extend_from_slice(&c.source_port.to_le_bytes());
        body.extend_from_slice(&c.target_port.to_le_bytes());
        body.extend_from_slice(&peer_id_hash(&c.identity).to_le_bytes());
        if let Ok(wire) = private_nat::encode_datagram(59, 7, &body, 3) {
            let _ = c.socket.send_to(&wire, c.remote_endpoint);
        }
    }
}

fn at_or_after(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) as i32 >= 0
}

impl Session {
    pub fn new(connection: Connection, link: &FileLink, meta: &Metadata) -> Result<Self, String> {
        let _ = socket2::SockRef::from(&connection.socket).set_recv_buffer_size(4 * 1024 * 1024);
        let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok();
        let local_ip = route
            .and_then(|s| {
                s.connect(connection.remote_endpoint).ok()?;
                match s.local_addr().ok()? {
                    SocketAddr::V4(a) => Some(*a.ip()),
                    _ => None,
                }
            })
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut random = [0; 4];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "private_channel_random")?;
        let frame = private_channel::handshake(
            link,
            meta,
            &connection.identity,
            local_ip,
            u32::from_le_bytes(random) | 0x80000000,
        )?;
        let mut out = Self {
            connection,
            decoder: Decoder::new(),
            reassembly: Reassembly::default(),
            sent: Vec::new(),
            handshake_ok: false,
            unchoked: false,
            last_file_data: Instant::now(),
            stats: SessionStats {
                advertised_window: WINDOW as u32,
                ..Default::default()
            },
            requested_at: None,
        };
        out.send_frame(&frame)?;
        Ok(out)
    }

    pub fn is_ready(&self) -> bool {
        self.handshake_ok && self.unchoked
    }
    pub fn is_queued(&self) -> bool {
        self.handshake_ok && !self.unchoked
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        // 窗口按**字节**算，而不是 64 个帧：协议在 Data.window 里声明 WINDOW=0x50000，
        // 按 64 帧（约 89KB）算会在 5MB/2MB 处把还能正常工作的 peer 丢掉。
        // 这里按 payload 字节限流；窗口满返回**可重试**标记，调用方等 ACK 后再继续。
        let inflight: usize = self.sent.iter().map(|s| s.len).sum();
        if window_full(inflight, frame.len()) {
            return Err("private_channel_window_full".into());
        }
        // 内存保护上限（不是协议窗口）：异常对端完全不 ACK 时，tick 的超时/重试会兜底。
        if self.sent.len() >= MAX_UNACKED_FRAMES || frame.len() > MAX_FRAME {
            return Err("private_channel_send_limit".into());
        }
        let c = &self.connection;
        let data = Data {
            source_port: c.source_port,
            target_port: c.target_port,
            peer_hash: peer_id_hash(&c.identity),
            sequence: c.send_next,
            ack: c.receive_next,
            window: WINDOW as u32,
            packet_sequence: None,
            timing: None,
            payload: frame.to_vec(),
        };
        let wire = private_nat::encode_datagram(59, 9, &data.encode(59)?, 3)?;
        c.socket
            .send_to(&wire, c.remote_endpoint)
            .map_err(|_| "private_channel_send")?;
        self.connection.send_next = self.connection.send_next.wrapping_add(frame.len() as u32);
        let now = Instant::now();
        self.sent.push(Sent {
            end: self.connection.send_next,
            wire,
            len: frame.len(),
            first: now,
            last: now,
            attempts: 1,
        });
        Ok(())
    }

    fn ack(&mut self) -> Result<(), String> {
        self.stats.acks_sent += 1;
        let c = &self.connection;
        let data = Data {
            source_port: c.source_port,
            target_port: c.target_port,
            peer_hash: peer_id_hash(&c.identity),
            sequence: c.send_next,
            ack: c.receive_next,
            window: WINDOW as u32,
            packet_sequence: None,
            timing: None,
            payload: Vec::new(),
        };
        let wire = private_nat::encode_datagram(59, 9, &data.encode(59)?, 3)?;
        c.socket
            .send_to(&wire, c.remote_endpoint)
            .map_err(|_| "private_channel_ack")?;
        Ok(())
    }

    /// Called by the single shared-socket receive loop after demultiplexing.
    pub fn on_packet(&mut self, from: SocketAddr, packet: &Packet) -> Result<Vec<Frame>, String> {
        let c = &self.connection;
        if from != c.remote_endpoint {
            return Ok(Vec::new());
        }
        if packet.protocol == 59 && packet.command == 6 {
            let syn = Syn::parse(packet)?;
            if syn.flags == 1
                && syn.target_port == c.source_port
                && syn.source_port == c.target_port
                && syn.peer_hash == peer_id_hash(&c.remote_peer_id)
            {
                self.ack()?;
            }
            return Ok(Vec::new());
        }
        if ![9, 18].contains(&packet.command) {
            return Ok(Vec::new());
        }
        let data = Data::parse(packet)?;
        self.ingest(data)
    }

    fn ingest(&mut self, data: Data) -> Result<Vec<Frame>, String> {
        let c = &self.connection;
        if data.source_port != c.target_port
            || data.target_port != c.source_port
            || data.peer_hash != peer_id_hash(&c.remote_peer_id)
        {
            return Ok(Vec::new());
        }
        // An out-of-window ACK cannot release retransmit state.
        if !at_or_after(data.ack, c.send_next.wrapping_add(1)) {
            let stats = &mut self.stats;
            self.sent.retain(|s| {
                let acked = at_or_after(data.ack, s.end);
                // Karn: only never-retransmitted segments yield RTT samples.
                if acked && s.attempts == 1 {
                    let rtt = s.first.elapsed();
                    stats.rtt_last = Some(rtt);
                    stats.rtt_min = Some(stats.rtt_min.map_or(rtt, |m| m.min(rtt)));
                }
                !acked
            });
        }
        self.stats.remote_window = data.window;
        if data.payload.is_empty() {
            return Ok(Vec::new());
        }
        self.stats.data_packets += 1;
        self.stats.payload_bytes += data.payload.len() as u64;
        let ahead = data.sequence.wrapping_sub(self.connection.receive_next) as i32;
        if ahead < 0 || self.reassembly.pending.contains_key(&data.sequence) {
            self.stats.duplicate_packets += 1;
        } else if ahead > 0 {
            self.stats.out_of_order_packets += 1;
        }
        let pieces = self.reassembly.push(
            &mut self.connection.receive_next,
            data.sequence,
            &data.payload,
        )?;
        self.stats.reassembly_peak = self.stats.reassembly_peak.max(self.reassembly.bytes);
        self.stats.flow_drops = self.reassembly.dropped;
        self.ack()?;
        let mut frames = Vec::new();
        for piece in pieces {
            frames.extend(self.decoder.push(&piece)?);
        }
        for frame in &frames {
            match frame.command {
                101 => {
                    // Observed successful handshake: Result + lp(remote PeerID).
                    if frame.body.len() < 21
                        || frame.body[0] != 0
                        || frame.body[1..5] != 16_u32.to_le_bytes()
                        || frame.body[5..21] != self.connection.remote_peer_id
                    {
                        return Err("private_file_handshake_rejected".into());
                    }
                    self.handshake_ok = true;
                }
                113 => self.unchoked = false,
                114 => self.unchoked = true,
                107 => {
                    self.last_file_data = Instant::now();
                    if let Some(at) = self.requested_at.take() {
                        self.stats.request_latency = Some(at.elapsed());
                    }
                }
                115 => return Err("private_file_peer_finished".into()),
                _ => {}
            }
        }
        Ok(frames)
    }

    pub fn take_pending(&mut self) -> Result<Vec<Frame>, String> {
        let pending = std::mem::take(&mut self.connection.pending);
        let mut frames = Vec::new();
        for data in pending {
            frames.extend(self.ingest(data)?);
        }
        Ok(frames)
    }

    pub fn tick(&mut self, cancelled: &AtomicBool) -> Result<(), String> {
        if cancelled.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        for item in &mut self.sent {
            if item.last.elapsed() >= RETRY {
                if item.attempts >= MAX_ATTEMPTS {
                    return Err("private_channel_send_timeout".into());
                }
                self.connection
                    .socket
                    .send_to(&item.wire, self.connection.remote_endpoint)
                    .map_err(|_| "private_channel_resend")?;
                item.attempts += 1;
                item.last = Instant::now();
                self.stats.resends += 1;
            }
        }
        Ok(())
    }

    pub fn request_range(&mut self, position: u64, length: u64) -> Result<(), String> {
        if !self.is_ready() {
            return Err("private_file_not_unchoked".into());
        }
        if length == 0 || length > MAX_RANGE {
            return Err("private_file_range_limit".into());
        }
        self.send_frame(&private_channel::request(position, length, 65536)?)?;
        self.requested_at = Some(Instant::now());
        self.stats.requests += 1;
        Ok(())
    }
}

/// Single-connection validation entry point. Production multi-source scheduling
/// feeds Session::on_packet from one receive owner, sharing the same SN mapping.
pub fn download_range<F>(
    mut session: Session,
    position: u64,
    length: u64,
    timeout: Duration,
    cancelled: &AtomicBool,
    mut on_data: F,
) -> Result<Vec<u8>, String>
where
    F: FnMut(u64, &[u8]) -> Result<(), String>,
{
    if length == 0 || length > MAX_RANGE || position.checked_add(length).is_none() {
        return Err("private_file_range_limit".into());
    }
    let deadline = Instant::now() + timeout.min(Duration::from_secs(120));
    let mut output = RangeOutput::new(position, length as usize);
    let mut requested = false;
    let mut buffer = [0; 65507];
    let mut frames = session.take_pending()?;
    session
        .connection
        .socket
        .set_read_timeout(Some(Duration::from_millis(30)))
        .map_err(|_| "private_channel_timeout_option")?;
    while Instant::now() < deadline {
        session.tick(cancelled)?;
        if session.is_ready() && !requested {
            session.request_range(position, length)?;
            requested = true;
        }
        for frame in frames.drain(..) {
            if frame.command == 107 {
                let response = private_channel::parse_response(&frame)?;
                output.insert(response.position, &response.data, &mut on_data)?;
                if output.covered == length as usize {
                    return Ok(output.data);
                }
            }
        }
        match session.connection.socket.recv_from(&mut buffer) {
            Ok((n, from)) => {
                if let Ok(packet) = private_nat::decode_datagram(&buffer[..n]) {
                    frames = session.on_packet(from, &packet)?;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err("private_channel_receive".into()),
        }
    }
    Err("private_file_range_timeout".into())
}

pub(crate) struct RangeOutput {
    position: u64,
    pub data: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    pub covered: usize,
}
impl RangeOutput {
    pub fn new(position: u64, length: usize) -> Self {
        Self {
            position,
            data: vec![0; length],
            ranges: Vec::new(),
            covered: 0,
        }
    }
    pub fn insert<F>(&mut self, position: u64, data: &[u8], on_data: &mut F) -> Result<(), String>
    where
        F: FnMut(u64, &[u8]) -> Result<(), String>,
    {
        let start = position
            .checked_sub(self.position)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or("private_file_position")?;
        let end = start.checked_add(data.len()).ok_or("private_file_length")?;
        if data.is_empty() || end > self.data.len() {
            return Err("private_file_outside_requested_range".into());
        }
        let mut cursor = start;
        for &(a, b) in &self.ranges {
            let left = a.max(start);
            let right = b.min(end);
            if left < right && self.data[left..right] != data[left - start..right - start] {
                return Err("private_file_conflicting_data".into());
            }
            if a > cursor {
                let stop = a.min(end);
                if cursor < stop {
                    self.data[cursor..stop].copy_from_slice(&data[cursor - start..stop - start]);
                    on_data(
                        self.position + cursor as u64,
                        &data[cursor - start..stop - start],
                    )?;
                    self.covered += stop - cursor;
                }
            }
            cursor = cursor.max(b);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            self.data[cursor..end].copy_from_slice(&data[cursor - start..]);
            on_data(self.position + cursor as u64, &data[cursor - start..])?;
            self.covered += end - cursor;
        }
        self.ranges.push((start, end));
        self.ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (a, b) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if a <= last.1 {
                    last.1 = last.1.max(b);
                    continue;
                }
            }
            merged.push((a, b));
        }
        self.ranges = merged;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_is_counted_in_bytes_not_64_frames() {
        // 64 帧（约 89,600 B）必须仍在协议窗口内，不能提前判满。
        assert!(
            !window_full(64 * MAX_FRAME, MAX_FRAME),
            "64 帧不应触发窗口满（窗口按 WINDOW 字节算）"
        );
        assert!(!window_full(0, MAX_FRAME));
        assert!(
            window_full(WINDOW - MAX_FRAME + 1, MAX_FRAME),
            "超过 WINDOW 字节必须判满"
        );
        assert!(MAX_FRAME * 64 < WINDOW, "64 帧上限应明显小于协议窗口");
    }

    #[test]
    fn reliable_stream_reorders_deduplicates_and_wraps() {
        let mut r = Reassembly::default();
        let mut next = u32::MAX - 2;
        assert!(r.push(&mut next, 1, b"def").unwrap().is_empty());
        assert_eq!(
            r.push(&mut next, u32::MAX - 2, b"abcd").unwrap(),
            vec![b"abcd".to_vec(), b"def".to_vec()]
        );
        assert_eq!(next, 4);
        assert!(r.push(&mut next, u32::MAX - 2, b"abcd").unwrap().is_empty());
        let outside = next.wrapping_add(WINDOW as u32 + 1);
        assert!(r.push(&mut next, outside, b"x").unwrap().is_empty());
        assert_eq!((r.dropped, r.bytes, next), (1, 0, 4));
        assert!(r.push(&mut next, 4, b"gh").unwrap() == vec![b"gh".to_vec()]);
    }

    #[test]
    fn reassembly_buffer_limit_refuses_segments_without_failing_the_stream() {
        let mut r = Reassembly::default();
        let mut next = 0;
        for n in 0..1024_u32 {
            assert!(r.push(&mut next, 10 + n * 2, b"a").unwrap().is_empty());
        }
        assert!(r.push(&mut next, 5000, b"b").unwrap().is_empty());
        assert_eq!((r.dropped, r.pending.len()), (1, 1024));
        assert!(
            r.push(&mut next, 10, b"x").is_err(),
            "conflicting data still fails closed"
        );
    }
    #[test]
    fn file_coverage_counts_only_new_bytes_and_rejects_conflicts() {
        let mut r = RangeOutput::new(100, 8);
        let mut count = 0;
        let mut on_data = |_, b: &[u8]| {
            count += b.len();
            Ok(())
        };
        r.insert(104, b"efgh", &mut on_data).unwrap();
        r.insert(102, b"cdef", &mut on_data).unwrap();
        r.insert(100, b"abcd", &mut on_data).unwrap();
        r.insert(100, b"abcdefgh", &mut on_data).unwrap();
        assert_eq!(r.covered, 8);
        assert_eq!(r.data, b"abcdefgh");
        assert_eq!(count, 8);
        assert!(r.insert(103, b"XX", &mut |_, _| Ok(())).is_err());
        assert!(r.insert(99, b"a", &mut |_, _| Ok(())).is_err());
    }
}
