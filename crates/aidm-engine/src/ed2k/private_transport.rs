//! 可靠 UDP 帧的线格式，并用采集到的样本交叉校验。
//! This module does not claim a completed session, congestion control or file IO.
use super::private_nat::Packet;

const MAX_BODY: usize = 65_502;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Syn {
    pub flags: u32,
    pub source_port: u16,
    pub target_port: u16,
    pub peer_hash: u32,
    pub sequence: u32,
    pub ack: u32,
    pub window: u32,
    pub udt_version: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    pub source_port: u16,
    pub target_port: u16,
    pub peer_hash: u32,
    pub sequence: u32,
    pub ack: u32,
    pub window: u32,
    pub packet_sequence: Option<u32>,
    pub timing: Option<(u32, u32)>,
    /// Reliable-stream bytes. Channel framing is still required before these
    /// can be interpreted as ISO bytes or counted as verified download progress.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvancedAck {
    pub source_port: u16,
    pub target_port: u16,
    pub peer_hash: u32,
    pub window: u32,
    pub sequence: u32,
    pub ack: u32,
    pub acked_sequence: u32,
    pub bitmap_base: u32,
    pub bitmap_bits: u32,
    pub bitmap: Vec<u8>,
}

/// ELF/PJW hash used by the observed x86 artifact, at most 16 signed chars.
pub fn peer_id_hash(identity: &[u8; 16]) -> u32 {
    let mut h = 0_u32;
    for &b in identity {
        if b == 0 {
            break;
        }
        h = h.wrapping_mul(16).wrapping_add(i32::from(b as i8) as u32);
        let high = h & 0xf0000000;
        if high != 0 {
            h ^= high >> 24;
        }
        h &= !high;
    }
    h
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.0.len() {
            return Err("private_transport_truncated".into());
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn finish(self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("private_transport_trailing".into())
        }
    }
}
fn u16s(out: &mut Vec<u8>, values: &[u16]) {
    for n in values {
        out.extend_from_slice(&n.to_le_bytes());
    }
}
fn u32s(out: &mut Vec<u8>, values: &[u32]) {
    for n in values {
        out.extend_from_slice(&n.to_le_bytes());
    }
}

impl Syn {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(26);
        u32s(&mut out, &[self.flags]);
        u16s(&mut out, &[self.source_port, self.target_port]);
        u32s(
            &mut out,
            &[self.peer_hash, self.sequence, self.ack, self.window],
        );
        u16s(&mut out, &[self.udt_version]);
        out
    }
    pub fn parse(packet: &Packet) -> Result<Self, String> {
        if packet.protocol != 59 || packet.command != 6 {
            return Err("private_transport_syn_command".into());
        }
        let mut r = Reader(&packet.body);
        let out = Self {
            flags: r.u32()?,
            source_port: r.u16()?,
            target_port: r.u16()?,
            peer_hash: r.u32()?,
            sequence: r.u32()?,
            ack: r.u32()?,
            window: r.u32()?,
            udt_version: r.u16()?,
        };
        r.finish()?;
        Ok(out)
    }
}

impl Data {
    pub fn encode(&self, protocol: u32) -> Result<Vec<u8>, String> {
        if ![59, 60].contains(&protocol)
            || self.timing.is_some() != (protocol > 59 && self.packet_sequence.is_some())
        {
            return Err("private_transport_data_version".into());
        }
        let header = if self.timing.is_some() {
            36
        } else if self.packet_sequence.is_some() {
            28
        } else {
            24
        };
        if self.payload.len() > MAX_BODY - header {
            return Err("private_transport_data_size".into());
        }
        let mut out = Vec::with_capacity(header + self.payload.len());
        u16s(&mut out, &[self.source_port, self.target_port]);
        u32s(
            &mut out,
            &[
                self.peer_hash,
                self.sequence,
                self.ack,
                self.window,
                self.payload.len() as u32,
            ],
        );
        if let Some(sequence) = self.packet_sequence {
            u32s(&mut out, &[sequence]);
        }
        if let Some((time, reply)) = self.timing {
            u32s(&mut out, &[time, reply]);
        }
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
    pub fn parse(packet: &Packet) -> Result<Self, String> {
        if ![59, 60].contains(&packet.protocol)
            || ![9, 18].contains(&packet.command)
            || packet.body.len() > MAX_BODY
        {
            return Err("private_transport_data_command".into());
        }
        let mut r = Reader(&packet.body);
        let (source_port, target_port, peer_hash, sequence, ack, window) =
            (r.u16()?, r.u16()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let n = r.u32()? as usize;
        let packet_sequence = if packet.command == 18 {
            Some(r.u32()?)
        } else {
            None
        };
        let timing = if packet.protocol > 59 && packet_sequence.is_some() {
            Some((r.u32()?, r.u32()?))
        } else {
            None
        };
        let payload = r.take(n)?.to_vec();
        r.finish()?;
        Ok(Self {
            source_port,
            target_port,
            peer_hash,
            sequence,
            ack,
            window,
            packet_sequence,
            timing,
            payload,
        })
    }
}

impl AdvancedAck {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let n = (u64::from(self.bitmap_bits) + 7) / 8;
        if n != self.bitmap.len() as u64 || n > (MAX_BODY - 32) as u64 {
            return Err("private_transport_bitmap_size".into());
        }
        let mut out = Vec::with_capacity(32 + self.bitmap.len());
        u16s(&mut out, &[self.source_port, self.target_port]);
        u32s(
            &mut out,
            &[
                self.peer_hash,
                self.window,
                self.sequence,
                self.ack,
                self.acked_sequence,
                self.bitmap_base,
                self.bitmap_bits,
            ],
        );
        out.extend_from_slice(&self.bitmap);
        Ok(out)
    }
    pub fn parse(packet: &Packet) -> Result<Self, String> {
        // Protocol 60 also has version-dependent timing fields; not inferred.
        if packet.protocol != 59 || packet.command != 17 || packet.body.len() > MAX_BODY {
            return Err("private_transport_ack_command".into());
        }
        let mut r = Reader(&packet.body);
        let (
            source_port,
            target_port,
            peer_hash,
            window,
            sequence,
            ack,
            acked_sequence,
            bitmap_base,
            bitmap_bits,
        ) = (
            r.u16()?,
            r.u16()?,
            r.u32()?,
            r.u32()?,
            r.u32()?,
            r.u32()?,
            r.u32()?,
            r.u32()?,
            r.u32()?,
        );
        let n = (u64::from(bitmap_bits) + 7) / 8;
        if n > (MAX_BODY - 32) as u64 {
            return Err("private_transport_bitmap_size".into());
        }
        let bitmap = r.take(n as usize)?.to_vec();
        r.finish()?;
        Ok(Self {
            source_port,
            target_port,
            peer_hash,
            window,
            sequence,
            ack,
            acked_sequence,
            bitmap_base,
            bitmap_bits,
            bitmap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(v: &serde_json::Value) -> Packet {
        let s = v["body_hex"].as_str().unwrap();
        Packet {
            protocol: v["protocol"].as_u64().unwrap() as u32,
            command: v["command"].as_u64().unwrap() as u8,
            algorithm: 0,
            wrapper_length: 0,
            body: s
                .as_bytes()
                .chunks_exact(2)
                .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
                .collect(),
        }
    }
    fn vectors() -> serde_json::Value {
        serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/private-transport-native-vectors-20261014.json"
        ))
        .unwrap()
    }
    #[test]
    fn native_serializers_match_independent_rust_frames() {
        let v = vectors();
        for x in v["vectors"].as_array().unwrap() {
            let p = packet(x);
            match p.command {
                6 => {
                    let s = Syn::parse(&p).unwrap();
                    assert_eq!(s.flags, 0);
                    assert_eq!(s.encode(), p.body);
                    assert_eq!(s.peer_hash, peer_id_hash(b"0123456789ABCDNM"));
                }
                17 => {
                    let a = AdvancedAck::parse(&p).unwrap();
                    assert_eq!(a.bitmap_bits, 9);
                    assert_eq!(a.bitmap, [0x85, 1]);
                    assert_eq!(a.encode().unwrap(), p.body);
                }
                9 | 18 => {
                    let d = Data::parse(&p).unwrap();
                    assert_eq!(
                        d.payload,
                        if p.command == 9 {
                            b"".as_slice()
                        } else {
                            // fixture 为合成向量；payload 标示串必须与向量一致。
                            b"AIDM differential data".as_slice()
                        }
                    );
                    assert_eq!(d.sequence, 0xfffffff0);
                    assert_eq!(d.encode(p.protocol).unwrap(), p.body);
                }
                _ => panic!("native vector"),
            }
        }
        assert_eq!(
            peer_id_hash(b"0123456789ABCDNM"),
            v["peer_hash"]["value"].as_u64().unwrap() as u32
        );
    }
    #[test]
    fn all_native_frame_truncations_and_bad_payload_lengths_fail() {
        let v = vectors();
        for x in v["vectors"].as_array().unwrap() {
            let p = packet(x);
            let valid = |p: &Packet| match p.command {
                6 => Syn::parse(p).is_ok(),
                17 => AdvancedAck::parse(p).is_ok(),
                9 | 18 => Data::parse(p).is_ok(),
                _ => false,
            };
            for n in 0..p.body.len() {
                let mut c = p.clone();
                c.body.truncate(n);
                assert!(!valid(&c), "cmd {} length {n}", p.command);
            }
            let mut c = p.clone();
            c.body.push(0);
            assert!(!valid(&c));
            if [9, 18].contains(&p.command) {
                let mut c = p.clone();
                c.body[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
                assert!(!valid(&c));
            }
        }
    }
}
