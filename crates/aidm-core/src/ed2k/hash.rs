//! eD2k（电驴）文件哈希：MD4 分片哈希树。
//!
//! 算法语义以 eMule `CKnownFile::CreateFromFile` 的公开描述为准
//! （见 <https://en.wikipedia.org/wiki/Ed2k_URI_scheme#eD2k_hash_algorithm>）：

//! - 文件按 **9500 KiB（9,728,000 字节）** 分片，最后一片是余数；
//! - 每个分片算一次 MD4；
//! - **文件大于一个分片**时，eD2k 哈希 = MD4(各分片 MD4 依次拼接)；
//! - **只有一个分片**（含空文件）时，eD2k 哈希就是该分片的 MD4。
//!
//! 历史歧义：文件大小恰好是分片整数倍时，旧工具会**追加一个空分片的 MD4**，
//! 现在已废弃。本模块两种口径都实现并显式命名：
//!
//! | 口径 | 含义 |
//! |---|---|
//! | [`Flavor::Official`] | 当前标准（无额外空分片）——与 eMule 现行实现、`ed2k` crate 的 `Ed2kBlue` 一致 |
//! | [`Flavor::Legacy`] | 旧工具口径（整倍数时追加空串 MD4）——用于校验老文件哈希 |
//!
//! MD4 在本项目里**只用于 eD2k 协议兼容与完整性校验**，不作为任何安全用途。

use std::io::Read;
use std::path::Path;

use md4::{Digest, Md4};

/// eD2k 分片大小：9500 KiB。
pub const PART_SIZE: u64 = 9_728_000;
/// MD4 输出长度。
pub const HASH_LEN: usize = 16;
/// 一个 MD4 哈希。
pub type Md4Hash = [u8; HASH_LEN];

/// 哈希口径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// 当前标准口径（等价于 `ed2k` crate 的 `Ed2kBlue`）。
    Official,
    /// 旧工具口径（等价于 `Ed2kRed`）：大小恰为分片整数倍时追加空串 MD4。
    Legacy,
}

/// 一次哈希的完整结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kDigest {
    /// 每个分片的 MD4（末片为余数）。
    pub parts: Vec<Md4Hash>,
    /// 文件级 eD2k 哈希。
    pub file: Md4Hash,
    /// 参与哈希的总字节数。
    pub size: u64,
    /// 使用的口径。
    pub flavor: Flavor,
}

impl Ed2kDigest {
    /// 文件哈希的小写十六进制形式（`ed2k://` 链接里就是它）。
    pub fn file_hex(&self) -> String {
        hex(&self.file)
    }
}

/// 流式 eD2k 哈希器。
#[derive(Debug, Clone)]
pub struct Ed2kHasher {
    flavor: Flavor,
    cur: Md4,
    cur_len: usize,
    parts: Vec<Md4Hash>,
    size: u64,
}

impl Ed2kHasher {
    pub fn new(flavor: Flavor) -> Self {
        Self {
            flavor,
            cur: Md4::new(),
            cur_len: 0,
            parts: Vec::new(),
            size: 0,
        }
    }

    /// 喂入数据（可多次调用）。
    pub fn update(&mut self, mut data: &[u8]) {
        self.size += data.len() as u64;
        while !data.is_empty() {
            let free = PART_SIZE as usize - self.cur_len;
            let n = free.min(data.len());
            self.cur.update(&data[..n]);
            self.cur_len += n;
            data = &data[n..];
            if self.cur_len as u64 == PART_SIZE {
                let h: Md4Hash = self.cur.finalize_reset().into();
                self.parts.push(h);
                self.cur_len = 0;
            }
        }
    }

    /// 收尾并给出结果。
    pub fn finish(mut self) -> Ed2kDigest {
        let has_remainder = self.cur_len > 0;
        // 还没有任何完整分片：把当前（可能为空）缓冲当唯一分片 —— 即 MD4(全部数据)。
        // 空文件因此得到 MD4("") = 31d6cfe0…
        if self.parts.is_empty() {
            let file: Md4Hash = self.cur.finalize_reset().into();
            return Ed2kDigest {
                parts: vec![file],
                file,
                size: self.size,
                flavor: self.flavor,
            };
        }

        let mut parts = std::mem::take(&mut self.parts);
        if has_remainder {
            let last: Md4Hash = self.cur.finalize_reset().into();
            parts.push(last);
            let file = hash_concat(&parts);
            return Ed2kDigest {
                parts,
                file,
                size: self.size,
                flavor: self.flavor,
            };
        }

        // 到这里说明总长是分片整数倍，且已有 >= 1 个完整分片
        let file = match self.flavor {
            Flavor::Official => {
                if parts.len() == 1 {
                    // 恰好一个分片：标准口径直接取该分片哈希（等价于 MD4(文件)），
                    // 而不是再套一层 MD4 —— 这是与 Legacy 的关键差异。
                    parts[0]
                } else {
                    hash_concat(&parts)
                }
            }
            Flavor::Legacy => {
                // 旧口径：追加空串的 MD4 后再拼接
                let empty: Md4Hash = Md4::new().finalize().into();
                parts.push(empty);
                hash_concat(&parts)
            }
        };
        Ed2kDigest {
            parts,
            file,
            size: self.size,
            flavor: self.flavor,
        }
    }
}

/// 把分片哈希依次拼接后再 MD4。
fn hash_concat(parts: &[Md4Hash]) -> Md4Hash {
    let mut h = Md4::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// 对整个读取器做 eD2k 哈希。缓冲区 1 MiB：分片是 9.5 MiB，
/// 这样既不会一次吃下整片，也不会碎读。
pub fn hash_reader(flavor: Flavor, mut r: impl Read) -> std::io::Result<Ed2kDigest> {
    let mut hasher = Ed2kHasher::new(flavor);
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish())
}

/// 对文件做 eD2k 哈希。
pub fn hash_file(flavor: Flavor, path: &Path) -> std::io::Result<Ed2kDigest> {
    let f = std::fs::File::open(path)?;
    hash_reader(flavor, std::io::BufReader::new(f))
}

/// 裸 MD4（不经过分片树）。用于 eD2k 的分片哈希集校验。
pub fn md4(data: &[u8]) -> Md4Hash {
    Md4::digest(data).into()
}

/// 第 `idx` 片的字节长度（最后一片是余数）。
pub fn part_len(file_size: u64, idx: usize) -> u64 {
    let start = idx as u64 * PART_SIZE;
    file_size.saturating_sub(start).min(PART_SIZE)
}

/// 校验一个分片内容（用于下载后逐片验证）。
pub fn verify_part(expected: &Md4Hash, data: &[u8]) -> bool {
    let got: Md4Hash = Md4::digest(data).into();
    &got == expected
}

/// 校验整份数据是否匹配期望的文件哈希。
pub fn verify_file(flavor: Flavor, expected: &Md4Hash, data: &[u8]) -> bool {
    let mut h = Ed2kHasher::new(flavor);
    h.update(data);
    &h.finish().file == expected
}

/// 哈希 → 小写十六进制。
pub fn hex(h: &Md4Hash) -> String {
    let mut s = String::with_capacity(HASH_LEN * 2);
    for b in h {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 十六进制 → 哈希（大小写不敏感，必须 32 位）。
pub fn parse_hex(s: &str) -> Option<Md4Hash> {
    let t = s.trim();
    if t.len() != HASH_LEN * 2 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    for i in 0..HASH_LEN {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_bytes(flavor: Flavor, data: &[u8]) -> String {
        let mut h = Ed2kHasher::new(flavor);
        h.update(data);
        h.finish().file_hex()
    }

    /// 公开测试向量（与 `ed2k` crate 的 Blue/Red 用例一致）。
    /// 这些向量覆盖了"整分片 / 多分片 / 余数分片"三种边界。
    #[test]
    fn published_vectors_official_and_legacy() {
        let cases: Vec<(Vec<u8>, &str, &str)> = vec![
            (
                vec![0; 0],
                "31d6cfe0d16ae931b73c59d7e0c089c0",
                "31d6cfe0d16ae931b73c59d7e0c089c0",
            ),
            (
                vec![0; 412],
                "a89605d61bb80c73ead447285c05f588",
                "a89605d61bb80c73ead447285c05f588",
            ),
            (
                vec![0x55; 412],
                "41dfbddfe5a4b05236a0d932dd445a74",
                "41dfbddfe5a4b05236a0d932dd445a74",
            ),
            (
                vec![0; 9_728_000],
                "d7def262a127cd79096a108e7a9fc138",
                "fc21d9af828f92a8df64beac3357425d",
            ),
            (
                vec![0x55; 9_728_000],
                "4127a47867b6110f0f86f2d9845fb374",
                "49e80f377b7e4e706dbd3ecc89f39306",
            ),
            (
                vec![0; 9_728_412],
                "9828f449478a35b909e86ba9bdbce24b",
                "9828f449478a35b909e86ba9bdbce24b",
            ),
            (
                vec![0x55; 9_728_412],
                "ac4fd3e805f05d29e3e119f0f3e61bf0",
                "ac4fd3e805f05d29e3e119f0f3e61bf0",
            ),
            (
                vec![0; 19_456_000],
                "194ee9e4fa79b2ee9f8829284c466051",
                "114b21c63a74b6ca922291a11177dd5c",
            ),
            (
                vec![0x55; 19_456_000],
                "322b445351fab0a78970a6a083693b5a",
                "54fc1e8d35b382c0aa7e73e54297c582",
            ),
            (
                vec![0; 19_456_412],
                "38ce731644eed021ba5c14c980fd6a32",
                "38ce731644eed021ba5c14c980fd6a32",
            ),
            (
                vec![0x55; 19_456_412],
                "0171e3f247bdd948d299a5178d9295e7",
                "0171e3f247bdd948d299a5178d9295e7",
            ),
        ];
        for (data, official, legacy) in cases {
            let len = data.len();
            assert_eq!(
                hash_bytes(Flavor::Official, &data),
                official,
                "Official 口径不符，长度 {len}"
            );
            assert_eq!(
                hash_bytes(Flavor::Legacy, &data),
                legacy,
                "Legacy 口径不符，长度 {len}"
            );
        }
    }

    /// 与独立实现（`ed2k` crate）逐尺寸交叉验证，避免自证自洽。
    /// 尺寸特意包含分片边界 ±1，以及分片整数倍。
    #[test]
    fn cross_check_against_independent_implementation() {
        use ed2k::digest::Digest;
        let sizes: Vec<usize> = vec![
            0,
            1,
            411,
            412,
            413,
            1024 * 1024,
            (PART_SIZE - 1) as usize,
            PART_SIZE as usize,
            (PART_SIZE + 1) as usize,
            (PART_SIZE + 412) as usize,
            (2 * PART_SIZE) as usize,
            (2 * PART_SIZE + 412) as usize,
            (3 * PART_SIZE) as usize,
        ];
        for size in sizes {
            // 确定性伪随机内容（避免每次分配大块零）
            let data: Vec<u8> = (0..size).map(|i| ((i * 31 + 7) % 251) as u8).collect();
            let ours_official = hash_bytes(Flavor::Official, &data);
            let theirs_blue = format!("{:x}", ed2k::Ed2kBlue::digest(&data));
            assert_eq!(ours_official, theirs_blue, "Blue 不一致，长度 {size}");

            let ours_legacy = hash_bytes(Flavor::Legacy, &data);
            let theirs_red = format!("{:x}", ed2k::Ed2kRed::digest(&data));
            assert_eq!(ours_legacy, theirs_red, "Red 不一致，长度 {size}");
        }
    }

    /// 分片列表与文件哈希自洽：文件哈希必须等于对分片列表再哈希。
    #[test]
    fn parts_are_consistent_with_file_hash() {
        let data: Vec<u8> = (0..(2 * PART_SIZE + 1234))
            .map(|i| (i % 256) as u8)
            .collect();
        let mut h = Ed2kHasher::new(Flavor::Official);
        h.update(&data);
        let d = h.finish();
        assert_eq!(d.parts.len(), 3, "应切成 3 片");
        assert_eq!(d.parts[0].len(), HASH_LEN);
        assert_eq!(d.size, data.len() as u64);
        // 末片是余数
        assert_eq!(
            d.parts[2],
            Md4::digest(&data[2 * PART_SIZE as usize..]).as_slice()
        );
        assert_eq!(d.file, hash_concat(&d.parts));
        assert_eq!(d.file_hex().len(), 32);
    }

    /// 流式喂入与一次性喂入结果一致（含跨片边界的碎片化喂入）。
    #[test]
    fn streaming_matches_single_shot() {
        let data: Vec<u8> = (0..(PART_SIZE + 5000)).map(|i| (i % 253) as u8).collect();
        let one_shot = hash_bytes(Flavor::Official, &data);
        for chunk in [1usize, 7, 1024, 999_983] {
            let mut h = Ed2kHasher::new(Flavor::Official);
            for piece in data.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(h.finish().file_hex(), one_shot, "分块 {chunk} 时结果不一致");
        }
    }

    #[test]
    fn hex_roundtrip_and_part_verify() {
        let h: Md4Hash = Md4::digest(b"abc").into();
        let s = hex(&h);
        assert_eq!(s, "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(parse_hex(&s.to_uppercase()).unwrap(), h);
        assert!(parse_hex("abc").is_none());
        assert!(parse_hex("zz48017aaf21d8525fc10ae87aa6729d").is_none());

        assert!(verify_part(&h, b"abc"));
        assert!(!verify_part(&h, b"abd"));
        assert!(verify_file(Flavor::Official, &h, b"abc"));
    }
}
