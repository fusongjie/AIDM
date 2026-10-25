//! Independent file-channel codec for the observed native protocol 72.
//!
//! File data starts at response-body byte 13. The 25 bytes of transfer counters
//! follow the data; moving them before the data silently corrupts every block.
//! This module encodes the normal header only. Unverified obfuscated headers
//! fail closed rather than being guessed or treated as file content.
use std::net::Ipv4Addr;

use aidm_core::ed2k::FileLink;

use super::private_index::Metadata;

pub const PROTOCOL: u32 = 72;
pub const MAX_DATA_LENGTH: usize = 1024 * 1024;
const RESPONSE_OVERHEAD: usize = 38;
const HEADER_LENGTH: usize = 9;
const MAX_BODY_LENGTH: usize = MAX_DATA_LENGTH + RESPONSE_OVERHEAD;
const MAX_PUSH_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAMES_PER_PUSH: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub protocol: u32,
    pub command: u8,
    pub body: Vec<u8>,
}

/// Reassembles file frames from a reliable byte stream, independently of its
/// UDP packet boundaries. Memory and per-call output counts are bounded.
#[derive(Debug)]
pub struct Decoder {
    pending: Vec<u8>,
    frame_length: Option<usize>,
    failed: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            pending: Vec::with_capacity(HEADER_LENGTH),
            frame_length: None,
            failed: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, String> {
        if self.failed {
            return Err("ed2k_channel_decoder_failed".into());
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.pending.clear();
            self.frame_length = None;
        }
        result
    }

    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<Vec<Frame>, String> {
        if bytes.len() > MAX_PUSH_BYTES {
            return Err("ed2k_channel_batch_too_large".into());
        }
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let target = self.frame_length.unwrap_or(HEADER_LENGTH);
            let take = (target - self.pending.len()).min(bytes.len());
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];

            if self.pending.len() >= 4
                && u32::from_le_bytes(self.pending[..4].try_into().unwrap()) != PROTOCOL
            {
                return Err("ed2k_channel_unsupported_header".into());
            }
            if self.pending.len() < HEADER_LENGTH {
                continue;
            }
            if self.frame_length.is_none() {
                let length = u32::from_le_bytes(self.pending[4..8].try_into().unwrap()) as usize;
                // The length includes the command byte, but excludes both u32s.
                if length == 0 || length > MAX_BODY_LENGTH + 1 {
                    return Err("ed2k_channel_frame_length".into());
                }
                let total = length + 8;
                self.frame_length = Some(total);
                self.pending.reserve_exact(total - self.pending.len());
            }
            if self.pending.len() == self.frame_length.unwrap() {
                if frames.len() == MAX_FRAMES_PER_PUSH {
                    return Err("ed2k_channel_too_many_frames".into());
                }
                frames.push(Frame {
                    protocol: PROTOCOL,
                    command: self.pending[8],
                    body: self.pending[HEADER_LENGTH..].to_vec(),
                });
                self.pending = Vec::with_capacity(HEADER_LENGTH);
                self.frame_length = None;
            }
        }
        Ok(frames)
    }

    /// Call when the reliable stream ends. A partial frame is not a clean EOF.
    pub fn finish(&self) -> Result<(), String> {
        if self.failed {
            Err("ed2k_channel_decoder_failed".into())
        } else if !self.pending.is_empty() {
            Err("ed2k_channel_truncated".into())
        } else {
            Ok(())
        }
    }
}

fn frame(command: u8, body: Vec<u8>) -> Result<Vec<u8>, String> {
    if body.len() > MAX_BODY_LENGTH {
        return Err("ed2k_channel_frame_length".into());
    }
    let mut out = Vec::with_capacity(body.len() + HEADER_LENGTH);
    out.extend_from_slice(&PROTOCOL.to_le_bytes());
    out.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    out.push(command);
    out.extend_from_slice(&body);
    Ok(out)
}

fn lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn u32_field(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u64_field(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Encodes native command 100 with the independently verified minimal options.
/// The caller supplies AIDM's own stable identity and a per-connection ID.
pub fn handshake(
    link: &FileLink,
    meta: &Metadata,
    identity: &[u8; 16],
    local_ip: Ipv4Addr,
    connection_id: u32,
) -> Result<Vec<u8>, String> {
    if link.size == 0 || meta.gcid == [0; 20] {
        return Err("ed2k_channel_file_identity".into());
    }
    let mut body = Vec::with_capacity(208);
    u32_field(&mut body, connection_id);
    body.push(1); // ByWhat: file identity is GCID.
    lp(&mut body, &meta.gcid);
    u64_field(&mut body, link.size);
    body.push(1); // FileStatus, as observed in the successful minimal handshake.
    lp(&mut body, identity);
    lp(&mut body, local_ip.to_string().as_bytes());

    // Remaining native optional fields retain their observed zero/empty defaults.
    u32_field(&mut body, 0);
    u32_field(&mut body, 0);
    u64_field(&mut body, 0);
    u64_field(&mut body, 0);
    body.push(0);
    for _ in 0..6 {
        u32_field(&mut body, 0);
    }
    body.push(0);
    lp(&mut body, b"");
    u32_field(&mut body, 0);
    u32_field(&mut body, 0);
    u64_field(&mut body, 0);
    lp(&mut body, b"");
    u64_field(&mut body, 0);
    u32_field(&mut body, 0);
    u32_field(&mut body, 0);
    lp(&mut body, b"");
    u64_field(&mut body, 0);
    u32_field(&mut body, 0);
    body.push(0);
    u64_field(&mut body, 0);
    body.push(0);
    lp(&mut body, b"");
    lp(&mut body, b"");
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.push(0);
    frame(100, body)
}

/// Encodes native command 106. A request can span several bounded response
/// packets; `max_packet` limits each packet's file payload, not the whole range.
pub fn request(position: u64, length: u64, max_packet: u32) -> Result<Vec<u8>, String> {
    if length == 0 || position.checked_add(length).is_none() {
        return Err("ed2k_channel_request_range".into());
    }
    if max_packet == 0 || max_packet as usize > MAX_DATA_LENGTH {
        return Err("ed2k_channel_request_packet_size".into());
    }
    let mut body = Vec::with_capacity(47);
    body.push(1); // ByWhat
    u64_field(&mut body, position);
    u64_field(&mut body, length);
    u32_field(&mut body, max_packet);
    body.push(0); // Priority
    u32_field(&mut body, 0); // UploadSpeed
    u32_field(&mut body, 0); // UnchokeNum
    u32_field(&mut body, 1); // PipeNum
    u32_field(&mut body, 1); // TaskNum
    u32_field(&mut body, 0); // LocalRequested
    u32_field(&mut body, 0); // RemoteRequested
    body.push(0); // FileRatio
    frame(106, body)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub result: u8,
    pub position: u64,
    pub data: Vec<u8>,
    pub upload_speed: u32,
    pub unchoke_num: u32,
    pub pipe_num: u32,
    pub task_num: u32,
    pub local_requested: u32,
    pub remote_requested: u32,
    pub file_ratio: u8,
}

/// Parses a successful command 107. Error results never become writable data.
pub fn parse_response(frame: &Frame) -> Result<Response, String> {
    if frame.protocol != PROTOCOL || frame.command != 107 {
        return Err("ed2k_channel_response_command".into());
    }
    let body = &frame.body;
    let result = *body.first().ok_or("ed2k_channel_response_truncated")?;
    if result != 0 {
        return Err(format!("ed2k_channel_remote_result:{result}"));
    }
    if body.len() < RESPONSE_OVERHEAD || body.len() > MAX_BODY_LENGTH {
        return Err("ed2k_channel_response_length".into());
    }
    let position = u64::from_le_bytes(body[1..9].try_into().unwrap());
    let length = u32::from_le_bytes(body[9..13].try_into().unwrap()) as usize;
    if length > MAX_DATA_LENGTH || body.len() != length + RESPONSE_OVERHEAD {
        return Err("ed2k_channel_response_length".into());
    }
    if position.checked_add(length as u64).is_none() {
        return Err("ed2k_channel_response_range".into());
    }
    let data_end = 13 + length;
    let tail = &body[data_end..];
    let counter = |offset| u32::from_le_bytes(tail[offset..offset + 4].try_into().unwrap());
    Ok(Response {
        result,
        position,
        data: body[13..data_end].to_vec(),
        upload_speed: counter(0),
        unchoke_num: counter(4),
        pipe_num: counter(8),
        task_num: counter(12),
        local_requested: counter(16),
        remote_requested: counter(20),
        file_ratio: tail[24],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::ed2k::{parse_link, Link};

    const LIVE: &[u8] = include_bytes!("fixtures/private_channel_107_iso_64k.bin");
    const HANDSHAKE: &[u8] = include_bytes!("fixtures/private_channel_100_synthetic.bin");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn live_frame() -> Frame {
        Decoder::new().push(LIVE).unwrap().remove(0)
    }

    fn file() -> (FileLink, Metadata) {
        let Link::File(link) = parse_link("ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/").unwrap() else {
            panic!("file fixture");
        };
        let bytes = |s: &str| -> [u8; 20] {
            std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        };
        let meta = Metadata {
            cid: bytes("967af63b1f363d038d476986b595ca410ede42dd"),
            gcid: bytes("49c167d23ee04adee731ee857ab17ed619d49d05"),
            part_hashes: Vec::new(),
            block_size: 2097152,
            gcid_level: 81,
        };
        (link, meta)
    }

    #[test]
    fn actual_107_keeps_payload_before_tail_and_matches_independent_http_hash() {
        assert_eq!(
            hex(ring::digest::digest(&ring::digest::SHA256, LIVE).as_ref()),
            "24ca5a202eb673a9ec66a8d265121533cd724ba4e0253c0bfe9b9aa0934cdfa4"
        );
        let response = parse_response(&live_frame()).unwrap();
        assert_eq!(
            (response.result, response.position, response.data.len()),
            (0, 0, 65536)
        );
        assert_eq!(
            hex(ring::digest::digest(&ring::digest::SHA256, &response.data).as_ref()),
            "ace8a9fd072227270e07430ff7f8ebb666f46d930ed2c434dc5335972c9f4983"
        );
        assert_eq!(&response.data[0x8001..0x8006], b"CD001");
        assert_eq!(response.upload_speed, 0);
        assert_eq!(response.unchoke_num, 0);
        assert_eq!(response.pipe_num, 0);
        assert_eq!(response.task_num, 1);
        assert_eq!(response.local_requested, 0);
        assert_eq!(response.remote_requested, 65536);
        assert_eq!(response.file_ratio, 0);
    }

    #[test]
    fn stream_accepts_fragmented_headers_payload_and_coalesced_frames() {
        for chunk_size in [1, 2, 3, 7, 8, 9, 10, 13, 1460, 65536] {
            let mut decoder = Decoder::new();
            let mut frames = Vec::new();
            for chunk in LIVE.chunks(chunk_size) {
                frames.extend(decoder.push(chunk).unwrap());
            }
            assert_eq!(frames, vec![live_frame()]);
            decoder.finish().unwrap();
        }
        let mut decoder = Decoder::new();
        let mut twice = LIVE.to_vec();
        twice.extend_from_slice(LIVE);
        assert_eq!(
            decoder.push(&twice).unwrap(),
            vec![live_frame(), live_frame()]
        );
        decoder.finish().unwrap();
    }

    #[test]
    fn partial_stream_is_only_an_error_at_eof() {
        for cut in [1, 3, 4, 7, 8, 9, 22, LIVE.len() - 1] {
            let mut decoder = Decoder::new();
            assert!(decoder.push(&LIVE[..cut]).unwrap().is_empty());
            assert_eq!(decoder.finish().unwrap_err(), "ed2k_channel_truncated");
            assert_eq!(decoder.push(&LIVE[cut..]).unwrap(), vec![live_frame()]);
            decoder.finish().unwrap();
        }
        Decoder::new().finish().unwrap();
    }

    #[test]
    fn malformed_headers_and_batch_attacks_fail_before_body_allocation() {
        for length in [0_u32, MAX_BODY_LENGTH as u32 + 2, u32::MAX] {
            let mut decoder = Decoder::new();
            let mut header = PROTOCOL.to_le_bytes().to_vec();
            header.extend_from_slice(&length.to_le_bytes());
            header.push(107);
            assert_eq!(
                decoder.push(&header).unwrap_err(),
                "ed2k_channel_frame_length"
            );
            assert!(decoder.pending.is_empty());
            assert!(decoder.push(LIVE).is_err());
        }
        for protocol in [0_u32, 71, 73, 0x80000048, u32::MAX] {
            assert_eq!(
                Decoder::new().push(&protocol.to_le_bytes()).unwrap_err(),
                "ed2k_channel_unsupported_header"
            );
        }
        assert_eq!(
            Decoder::new()
                .push(&vec![0; MAX_PUSH_BYTES + 1])
                .unwrap_err(),
            "ed2k_channel_batch_too_large"
        );
        let empty = frame(114, Vec::new()).unwrap();
        assert_eq!(
            Decoder::new()
                .push(&empty.repeat(MAX_FRAMES_PER_PUSH + 1))
                .unwrap_err(),
            "ed2k_channel_too_many_frames"
        );
    }

    #[test]
    fn response_rejects_bad_lengths_commands_error_results_and_position_wrap() {
        let good = live_frame();
        for cut in [0, 1, 12, 13, 37, good.body.len() - 1] {
            let mut bad = good.clone();
            bad.body.truncate(cut);
            assert!(parse_response(&bad).is_err());
        }
        let mut bad = good.clone();
        bad.body.push(0);
        assert!(parse_response(&bad).is_err());
        for length in [65535_u32, 65537, u32::MAX] {
            let mut bad = good.clone();
            bad.body[9..13].copy_from_slice(&length.to_le_bytes());
            assert!(parse_response(&bad).is_err());
        }
        let mut bad = good.clone();
        bad.body[0] = 7;
        assert_eq!(
            parse_response(&bad).unwrap_err(),
            "ed2k_channel_remote_result:7"
        );
        bad.body.truncate(1);
        assert_eq!(
            parse_response(&bad).unwrap_err(),
            "ed2k_channel_remote_result:7"
        );
        let mut bad = good.clone();
        bad.body[1..9].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            parse_response(&bad).unwrap_err(),
            "ed2k_channel_response_range"
        );
        let mut bad = good.clone();
        bad.command = 106;
        assert!(parse_response(&bad).is_err());
        bad.command = 107;
        bad.protocol = 71;
        assert!(parse_response(&bad).is_err());
    }

    #[test]
    fn handshake_matches_independent_native_layout_with_synthetic_identity() {
        let (link, meta) = file();
        let wire = handshake(
            &link,
            &meta,
            b"00112233445566NM",
            Ipv4Addr::new(192, 168, 100, 1),
            0x80000001,
        )
        .unwrap();
        assert_eq!(wire, HANDSHAKE);
        assert_eq!(wire.len() - HEADER_LENGTH, 202);
        let short = handshake(&link, &meta, b"00112233445566NM", Ipv4Addr::LOCALHOST, 2).unwrap();
        assert_eq!(short.len() + 4, wire.len());
        assert_eq!(&short[9..13], &2_u32.to_le_bytes());
        let mut bad = meta.clone();
        bad.gcid.fill(0);
        assert!(handshake(&link, &bad, &[1; 16], Ipv4Addr::LOCALHOST, 1).is_err());
    }

    #[test]
    fn request_encodes_exact_47_byte_native_body_and_checks_boundaries() {
        let wire = request(0, 65536, 65536).unwrap();
        assert_eq!(&wire[..9], &[72, 0, 0, 0, 48, 0, 0, 0, 106]);
        let body = &wire[9..];
        assert_eq!(body.len(), 47);
        assert_eq!(body[0], 1);
        assert_eq!(&body[9..17], &65536_u64.to_le_bytes());
        assert_eq!(&body[17..21], &65536_u32.to_le_bytes());
        assert_eq!(&body[30..38], &[1, 0, 0, 0, 1, 0, 0, 0]);
        assert!(request(u64::MAX, 1, 65536).is_err());
        assert!(request(0, 0, 65536).is_err());
        assert!(request(0, 1, 0).is_err());
        assert!(request(0, 1, MAX_DATA_LENGTH as u32 + 1).is_err());
        assert!(request(u64::MAX - 1, 1, MAX_DATA_LENGTH as u32).is_ok());
    }
}
