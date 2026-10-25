//! 独立实现的原生 SHub 67 / 5001 文件信息查询。
//! 只接受能重新计算为原 ed2k MD4 的 hashset，不把索引记录当成可用传输源。
//! 线路证据与尚缺的私有传输见 docs/private-protocol-alignment.md。
use std::io::Read;
use std::time::Duration;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aidm_core::ed2k::{hash, peer::part_count, FileLink};

const HOST: &str = "hub5emu.v6.shub.sandai.net";
const MAX_PACKET: usize = 4 * 1024 * 1024;

/// 服务返回了记录，但记录不能证明属于请求文件时，按完整性拒绝而不是普通网络失败处理。
pub fn is_integrity_rejection(code: &str) -> bool {
    matches!(
        code,
        "ed2k_index_hashset_count"
            | "ed2k_index_hashset_mismatch"
            | "ed2k_index_cid_length"
            | "ed2k_index_gcid_length"
            | "ed2k_index_trailing_data"
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub part_hashes: Vec<[u8; 16]>,
    /// 两个 20-byte 字段已按线路实际输入核实为 CID/GCID。
    /// 文件完整性仍仅由原链接的 MD4 和 hashset 校验保证。
    pub cid: [u8; 20],
    pub gcid: [u8; 20],
    pub block_size: u32,
    pub gcid_level: u32,
}

/// 按配置身份稳定派生自己的索引 PeerID，不使用外部客户端的身份或账号字段。
pub fn peer_id(user_hash: &[u8; 16]) -> [u8; 16] {
    let mut seed = b"AIDM index identity\0".to_vec();
    seed.extend_from_slice(user_hash);
    let digest = ring::digest::digest(&ring::digest::SHA256, &seed);
    let mut out = [0; 16];
    for (i, byte) in digest.as_ref()[..7].iter().enumerate() {
        out[i * 2] = b"0123456789ABCDEF"[(byte >> 4) as usize];
        out[i * 2 + 1] = b"0123456789ABCDEF"[(byte & 15) as usize];
    }
    out[14..].copy_from_slice(b"NM");
    out
}

fn lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn request(link: &FileLink, uri: &str, identity: &[u8; 16]) -> Result<Vec<u8>, String> {
    if uri.len() > 64 * 1024 || part_count(link.size) > 65535 {
        return Err("ed2k_index_request_too_large".into());
    }
    let mut p = Vec::new();
    for n in [67_u32, 1, 0, 2754522] {
        p.extend_from_slice(&n.to_le_bytes());
    }
    p.extend_from_slice(&0_u16.to_le_bytes());
    p.extend_from_slice(&55_u32.to_le_bytes());
    lp(&mut p, b"2.86.100.10");
    p.extend_from_slice(&134217728_u32.to_le_bytes());
    lp(&mut p, b"pc.thunderX");
    lp(&mut p, b"");
    lp(&mut p, b"pcdownloadsdk");
    p.extend_from_slice(&5001_u16.to_le_bytes());
    lp(&mut p, identity);
    lp(&mut p, &link.hash);
    p.extend_from_slice(&link.size.to_le_bytes());
    p.extend_from_slice(&0_u32.to_le_bytes());
    lp(&mut p, b"");
    p.extend_from_slice(&0_u32.to_le_bytes());
    lp(&mut p, uri.as_bytes());
    lp(&mut p, b"");
    lp(&mut p, b"");
    seal(&p)
}

fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
    if plain.len() < 12 || plain.len() > MAX_PACKET - 16 {
        return Err("ed2k_index_packet_size".into());
    }
    let mut out = plain.to_vec();
    let pad = 16 - (out.len() - 12) % 16;
    out.resize(out.len() + pad, pad as u8);
    let key = md5::compute(&out[..8]);
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    for block in out[12..].chunks_exact_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    let len = (out.len() - 12) as u32;
    out[8..12].copy_from_slice(&len.to_le_bytes());
    Ok(out)
}

fn open(packet: &[u8]) -> Result<Vec<u8>, String> {
    if packet.len() < 28 || packet.len() > MAX_PACKET || (packet.len() - 12) % 16 != 0 {
        return Err("ed2k_index_packet_size".into());
    }
    if u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize != packet.len() - 12 {
        return Err("ed2k_index_packet_length".into());
    }
    let mut plain = packet.to_vec();
    let key = md5::compute(&packet[..8]);
    let cipher = Aes128::new(GenericArray::from_slice(&key.0));
    for block in plain[12..].chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    let pad = *plain.last().unwrap() as usize;
    if !(1..=16).contains(&pad)
        || !plain[plain.len() - pad..]
            .iter()
            .all(|&b| b as usize == pad)
    {
        return Err("ed2k_index_padding".into());
    }
    plain.truncate(plain.len() - pad);
    Ok(plain)
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        if len > self.0.len() {
            return Err("ed2k_index_truncated".into());
        }
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

pub fn parse_response(packet: &[u8], link: &FileLink) -> Result<Option<Metadata>, String> {
    let plain = open(packet)?;
    let mut c = Cursor(&plain);
    if c.u32()? != 67 || c.u32()? != 1 {
        return Err("ed2k_index_response_header".into());
    }
    c.take(14)?; // length, SDK version, flags, extension flags
    c.field()?;
    c.u32()?;
    for _ in 0..3 {
        c.field()?;
    }
    if c.take(2)? != 5002_u16.to_le_bytes() {
        return Err("ed2k_index_response_command".into());
    }
    if c.take(1)? != [1] {
        return Ok(None);
    }
    if c.u32()? != 1 {
        return Ok(None);
    }
    c.field()?; // auxiliary 20-byte identity, not used as a transfer address
    let parts = c.field()?;
    let count = part_count(link.size);
    if count == 0 || count > 65535 || parts.len() != count * 16 {
        return Err("ed2k_index_hashset_count".into());
    }
    let file_hash: [u8; 16] = if count == 1 {
        parts.try_into().unwrap()
    } else {
        hash::md4(parts)
    };
    if file_hash != link.hash {
        return Err("ed2k_index_hashset_mismatch".into());
    }
    let cid = c.field()?.try_into().map_err(|_| "ed2k_index_cid_length")?;
    let gcid = c
        .field()?
        .try_into()
        .map_err(|_| "ed2k_index_gcid_length")?;
    let block_size = c.u32()?;
    let gcid_level = c.u32()?;
    for _ in 0..3 {
        c.u32()?;
    }
    c.field()?;
    if !c.0.is_empty() {
        return Err("ed2k_index_trailing_data".into());
    }
    Ok(Some(Metadata {
        part_hashes: parts
            .chunks_exact(16)
            .map(|v| v.try_into().unwrap())
            .collect(),
        cid,
        gcid,
        block_size,
        gcid_level,
    }))
}

pub fn query(link: &FileLink, uri: &str, identity: &[u8; 16]) -> Result<Option<Metadata>, String> {
    let body = request(link, uri, identity)?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout_read(Duration::from_secs(3))
        .timeout_write(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let response = agent
        .post(&format!("http://{HOST}/"))
        .set("Host", &format!("{HOST}:80"))
        .set("Content-Type", "application/octet-stream")
        .set("Connection", "Close")
        .send_bytes(&body)
        .map_err(|_| "ed2k_index_http")?;
    let mut data = Vec::new();
    response
        .into_reader()
        .take((MAX_PACKET + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| "ed2k_index_read")?;
    parse_response(&data, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn iso() -> FileLink {
        let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link("ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/").unwrap() else { panic!("file link") };
        link
    }
    #[test]
    fn independent_native_response_has_matching_461_piece_hashset() {
        let packet = include_bytes!("../../tests/fixtures/private-emule-info-20261014.bin");
        let m = parse_response(packet, &iso()).unwrap().unwrap();
        assert_eq!(m.part_hashes.len(), 461);
        assert_eq!(m.block_size, 2_097_152);
        assert_eq!(m.gcid_level, 81);
        let mut wrong = iso();
        wrong.hash[0] ^= 1;
        assert_eq!(
            parse_response(packet, &wrong).unwrap_err(),
            "ed2k_index_hashset_mismatch"
        );
        assert!(is_integrity_rejection("ed2k_index_hashset_mismatch"));
        assert!(!is_integrity_rejection("ed2k_index_http"));
        assert!(parse_response(&packet[..packet.len() - 1], &iso()).is_err());
    }
    #[test]
    fn independent_python_codec_request_vector() {
        let identity = *b"879E94D4B23C7ANM";
        let uri="ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
        let req = request(&iso(), uri, &identity).unwrap();
        let expected =
            include_bytes!("../../tests/fixtures/private-emule-query-python-20261014.bin");
        assert_eq!(req.as_slice(), expected);
    }
}
