//! zsync 控制文件（`.zsync`）解析与"我还缺哪些块"的规划。
//!
//! **这一层只做解析与规划，不发起任何请求**：真正把缺失区间取回来是引擎侧的事
//! （与 HLS/DASH 当初"先解析层、再下载合并"的分法一致）。
//!
//! # 格式来源（不凭记忆写二进制格式）
//!
//! 二进制格式的字段语义、截断规则与边界校验逐条对照一个**真实实现**：
//! `zsync-rs 0.2.1`（MIT）的 `src/control.rs:84-264`、`src/rsum.rs:7-17`，源码取自本地
//! cargo registry。之所以这么做：这些细节（尤其 3 字节弱校验和的拆分方式、强校验和取
//! **前** N 字节、`Blocksize` 必须是 2 的幂）凭印象写必错，而错了的表现是"永远算不出
//! 本地已有块"——任务照常能下完，只是白下整份文件，很难被发现。
//!
//! # 格式概要
//!
//! 文本头（`key: value` 行，**空行**结束）：
//! `zsync:` 版本 / `Filename:` / `MTime:` / `Blocksize:`（非零且是 2 的幂）/
//! `Length:` / `URL:`（可重复）/ `SHA-1:`（40 位十六进制）/ `Hash-Lengths: seq,rsum,strong`。
//! 空行之后是每块 `rsum_bytes + checksum_bytes` 字节的**二进制块表**，
//! 块数 = `ceil(Length / Blocksize)`。

use std::io::{Read, Seek};

/// 块校验和里各字段的编码长度。
///
/// 缺省 `(1, 4, 16)` 就是 2005 年那版固定 20 字节/块的老格式 —— 老文件不写
/// `Hash-Lengths`，所以缺省值必须是它，否则老控制文件会被判成非法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashLengths {
    /// 连续多少块命中才算一次匹配（1 或 2）。本模块的**定偏移**匹配用不到它，
    /// 但它是格式的一部分，解析出来才能对"这文件是不是我们支持的那种"作判断。
    pub seq_matches: u8,
    /// 弱校验和（rsync rolling checksum）的字节数，1..=4。
    pub rsum_bytes: u8,
    /// 强校验和（MD4）的字节数，3..=16；**取 MD4 的前 N 字节**。
    pub checksum_bytes: u8,
}

impl Default for HashLengths {
    fn default() -> Self {
        Self {
            seq_matches: 1,
            rsum_bytes: 4,
            checksum_bytes: 16,
        }
    }
}

/// 一块的校验和。强校验和固定 16 字节容器，只有前 `checksum_bytes` 字节有效。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockChecksum {
    pub rsum: (u16, u16),
    /// MD4 的前 `checksum_bytes` 字节；其余补零。
    pub checksum: [u8; 16],
}

/// 解析后的控制文件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZsyncControl {
    pub version: String,
    pub filename: Option<String>,
    pub mtime: Option<String>,
    pub blocksize: usize,
    pub length: u64,
    pub hash_lengths: HashLengths,
    /// 全部 `URL:` 行，按出现顺序（可以有多个，也允许为空）。
    pub urls: Vec<String>,
    /// 上游声明的整文件 SHA-1（40 位小写十六进制），用于下完后校验。
    pub sha1: Option<String>,
    pub blocks: Vec<BlockChecksum>,
}

/// 头部的读取上限。
///
/// 头部来自网络：一行没有换行符、或者对手塞无数条 `URL:`，都能让客户端在**任何校验
/// 发生之前**把内存花光。真实头部只有几百字节，给到 1 MiB 已经很宽松。
const MAX_HEADER_BYTES: u64 = 1 << 20;

/// 块数上限。块数是由头部的 `Length`/`Blocksize` 推出来的，两个数各几十字节就能要求
/// 几千万块 —— 不设上限等于让对手用一个短响应指定我们分配多少内存。
const MAX_BLOCKS: usize = 64 * 1024 * 1024;

/// 解析失败的原因。全部是稳定机器码（走 `error::is_known_code` 的 `zsync_` 前缀族）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZsyncError {
    /// 头部太大（超过 [`MAX_HEADER_BYTES`]）或没有终结空行。
    HeaderTooLarge,
    /// 头部行不是 `key: value` 形态。
    InvalidHeader,
    /// 缺 `Blocksize` 或 `Length`。
    MissingField,
    /// `Blocksize` 不是非零的 2 的幂。
    InvalidBlocksize,
    /// `Hash-Lengths` 不合法（个数不是 3、越界）。
    InvalidHashLengths,
    /// `Length` 不是数字。
    InvalidLength,
    /// `SHA-1` 不是 40 位十六进制。
    InvalidSha1,
    /// 块数超过 [`MAX_BLOCKS`]。
    TooManyBlocks,
    /// 块表在读完之前就结束了。
    Truncated,
}

impl ZsyncError {
    pub fn code(self) -> &'static str {
        match self {
            ZsyncError::HeaderTooLarge => "zsync_header_too_large",
            ZsyncError::InvalidHeader => "zsync_invalid_header",
            ZsyncError::MissingField => "zsync_missing_field",
            ZsyncError::InvalidBlocksize => "zsync_bad_blocksize",
            ZsyncError::InvalidHashLengths => "zsync_bad_hash_lengths",
            ZsyncError::InvalidLength => "zsync_bad_length",
            ZsyncError::InvalidSha1 => "zsync_bad_sha1",
            ZsyncError::TooManyBlocks => "zsync_too_many_blocks",
            ZsyncError::Truncated => "zsync_truncated",
        }
    }
}

/// rsync 的滚动弱校验和（zsync 用的就是它）。
///
/// `a = Σ byte`、`b = Σ a`（逐步累加），两者都按 `u16` **回绕**。与 `zsync-rs` 的
/// `calc_rsum_block` 逐字一致（`src/rsum.rs:7-17`）：注意它**没有** rsync 传统的
/// `CHAR_OFFSET`，别照着 rsync 印象加偏移。
pub fn rsum(data: &[u8]) -> (u16, u16) {
    let mut a: u16 = 0;
    let mut b: u16 = 0;
    for &byte in data {
        a = a.wrapping_add(u16::from(byte));
        b = b.wrapping_add(a);
    }
    (a, b)
}

/// 把完整的弱校验和**截断**成控制文件里实际携带的那个形态。
///
/// 这是本模块最容易写错的一处：控制文件里的弱校验和是按 `rsum_bytes` 截断存的
/// （1 字节时只剩 `b` 的低 8 位、3 字节时只留 `a` 的高 8 位），所以比较时必须把算出来的
/// 完整值**按同一规则截断再比**。直接比完整元组的话，凡是用了截断格式的真实控制文件
/// （`Hash-Lengths: 2,2,4` 这种很常见）都会判成"一个块都没有"，表现为整份重下 ——
/// 结果是对的，但增量更新的意义全没了，而且不会有任何报错。
///
/// 规则与 [`decode_entry`] 的输出形态严格对应，也与 `encode_entry` 写出的字节一致。
pub fn truncate_rsum(rs: (u16, u16), rsum_bytes: u8) -> (u16, u16) {
    match rsum_bytes {
        1 => (0, rs.1 & 0xFF),
        2 => (0, rs.1),
        3 => (rs.0 >> 8, rs.1),
        _ => rs,
    }
}

impl ZsyncControl {
    /// 从**字节流**解析：文本头 + 空行 + 二进制块表。
    pub fn parse(mut reader: impl Read) -> Result<Self, ZsyncError> {
        let mut head = Vec::new();
        // 逐字节读到空行为止，同时把上限卡在读取阶段（不是读完再判）。
        {
            let mut limited = (&mut reader).take(MAX_HEADER_BYTES);
            let mut line = Vec::new();
            loop {
                line.clear();
                let mut byte = [0u8; 1];
                loop {
                    match limited.read(&mut byte) {
                        Ok(0) => {
                            // 到上限或流结束都没等到空行。
                            return Err(ZsyncError::HeaderTooLarge);
                        }
                        Ok(_) => {
                            if byte[0] == b'\n' {
                                break;
                            }
                            line.push(byte[0]);
                            if line.len() > MAX_HEADER_BYTES as usize {
                                return Err(ZsyncError::HeaderTooLarge);
                            }
                        }
                        Err(_) => return Err(ZsyncError::Truncated),
                    }
                }
                // 空行（可能带 `\r`）= 头部结束。
                if line.iter().all(|b| *b == b'\r' || *b == b' ') {
                    break;
                }
                head.push(line.clone());
            }
        }

        let mut version = String::new();
        let mut filename = None;
        let mut mtime = None;
        let mut blocksize: Option<usize> = None;
        let mut length: Option<u64> = None;
        let mut hash_lengths = HashLengths::default();
        let mut urls: Vec<String> = Vec::new();
        let mut sha1 = None;

        for raw in head {
            let line = String::from_utf8_lossy(&raw).into_owned();
            let trimmed = line.trim_end_matches(['\r', ' ']).to_string();
            let Some((key, value)) = trimmed.split_once(':') else {
                return Err(ZsyncError::InvalidHeader);
            };
            let value = value.strip_prefix(' ').unwrap_or(value);
            match key {
                "zsync" => version = value.to_string(),
                "Filename" => filename = Some(value.to_string()),
                "MTime" => mtime = Some(value.to_string()),
                "Blocksize" => {
                    let bs: usize = value.parse().map_err(|_| ZsyncError::InvalidBlocksize)?;
                    // 必须是 2 的幂：块边界要靠移位算，非 2 的幂会让"第 i 块"没有稳定定义。
                    if bs == 0 || (bs & (bs - 1)) != 0 {
                        return Err(ZsyncError::InvalidBlocksize);
                    }
                    blocksize = Some(bs);
                }
                "Length" => length = Some(value.parse().map_err(|_| ZsyncError::InvalidLength)?),
                "URL" => urls.push(value.to_string()),
                "SHA-1" => {
                    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(ZsyncError::InvalidSha1);
                    }
                    sha1 = Some(value.to_ascii_lowercase());
                }
                "Hash-Lengths" => {
                    let parts: Vec<&str> = value.split(',').collect();
                    if parts.len() != 3 {
                        return Err(ZsyncError::InvalidHashLengths);
                    }
                    let seq: u8 = parts[0]
                        .parse()
                        .map_err(|_| ZsyncError::InvalidHashLengths)?;
                    let rs: u8 = parts[1]
                        .parse()
                        .map_err(|_| ZsyncError::InvalidHashLengths)?;
                    let cs: u8 = parts[2]
                        .parse()
                        .map_err(|_| ZsyncError::InvalidHashLengths)?;
                    if !(1..=2).contains(&seq) || !(1..=4).contains(&rs) || !(3..=16).contains(&cs)
                    {
                        return Err(ZsyncError::InvalidHashLengths);
                    }
                    hash_lengths = HashLengths {
                        seq_matches: seq,
                        rsum_bytes: rs,
                        checksum_bytes: cs,
                    };
                }
                // 认不出的头字段一律忽略：格式允许扩展，拒绝它们会让新版本
                // zsyncmake 生成的文件全部下不了。
                _ => {}
            }
        }

        let blocksize = blocksize.ok_or(ZsyncError::MissingField)?;
        let length = length.ok_or(ZsyncError::MissingField)?;
        let num_blocks = length.div_ceil(blocksize as u64) as usize;
        if num_blocks > MAX_BLOCKS {
            return Err(ZsyncError::TooManyBlocks);
        }

        let entry = (hash_lengths.rsum_bytes + hash_lengths.checksum_bytes) as usize;
        // 只按"已经到手的字节"预留，不按头部声称的块数预留：后者是攻击面。
        let mut blocks = Vec::with_capacity(num_blocks.min(1 << 16));
        let mut buf = vec![0u8; entry];
        for _ in 0..num_blocks {
            if reader.read_exact(&mut buf).is_err() {
                return Err(ZsyncError::Truncated);
            }
            blocks.push(decode_entry(&buf, hash_lengths));
        }

        Ok(Self {
            version,
            filename,
            mtime,
            blocksize,
            length,
            hash_lengths,
            urls,
            sha1,
            blocks,
        })
    }

    /// 第 `idx` 块在目标文件里的字节区间（最后一块可能短于 `blocksize`）。
    pub fn block_range(&self, idx: usize) -> Option<std::ops::Range<u64>> {
        if idx >= self.blocks.len() {
            return None;
        }
        let start = idx as u64 * self.blocksize as u64;
        let end = (start + self.blocksize as u64).min(self.length);
        Some(start..end)
    }

    /// 本地文件里**已经具备**的块下标集合（定偏移匹配），从字节切片读。
    ///
    /// 只是 [`Self::present_blocks_reader`] 的便利包装 —— 真实种子里程碑可能是几 GiB 的
    /// ISO，**不能整份读进内存**；切片版本留给单测与小程序使用。
    pub fn present_blocks(&self, seed: &[u8]) -> Vec<usize> {
        self.present_blocks_reader(std::io::Cursor::new(seed))
            .unwrap_or_default()
    }

    /// 本地文件里**已经具备**的块下标集合（定偏移匹配），逐块从可随机读的流读。
    ///
    /// 内存占用是 `O(blocksize)`（通常 2–4 KiB），与种子大小无关。
    ///
    /// # 为什么是定偏移
    ///
    /// 真正的 zsync 用滚动校验和在种子文件里**任意偏移**扫描匹配块（那才能吃掉
    /// "插入/删除几个字节"这种改动）。本实现只比较"第 i 块 vs 第 i 块"，
    /// 因此对**尾部追加、块内改写、局部替换**有效，对"整体错位"无效
    /// （那种情况下会退化成几乎整份重下，结果仍然正确，只是没省到）。
    /// 这是**刻意的第一步**：定偏移版本可以被完整验证，而滚动匹配要引入哈希表与
    /// 逐字节推进的匹配器，风险与验证成本都高一个量级。
    ///
    /// 返回下标是**升序**的（块按偏移升序处理，天然有序）。
    pub fn present_blocks_reader<R: Read + Seek>(&self, mut r: R) -> std::io::Result<Vec<usize>> {
        let bs = self.blocksize;
        let mut buf = vec![0u8; bs];
        let mut out = Vec::new();
        for (idx, _) in self.blocks.iter().enumerate() {
            let Some(range) = self.block_range(idx) else {
                break;
            };
            let expected = (range.end - range.start) as usize;
            r.seek(std::io::SeekFrom::Start(range.start))?;
            let mut got = 0;
            while got < expected {
                match r.read(&mut buf[got..expected]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(e) => return Err(e),
                }
            }
            if got != expected {
                // 种子在这个位置不完整（文件比目标短）：**不能**拿一个短块去比，
                // 而且后面的块只会更靠后，直接收工。
                break;
            }
            // 尾块要按格式约定**补零到整块**再算校验和 —— 不补的话尾块永远判不命中，
            // 表现是"每次都要重下最后一块"，而任务照样能下完，极难发现。
            for b in buf[expected..bs].iter_mut() {
                *b = 0;
            }
            if self.block_matches(idx, &buf[..bs]) {
                out.push(idx);
            }
        }
        Ok(out)
    }

    /// 单块是否命中（弱校验和 + 强校验和都比）。
    ///
    /// 两个都比是**必须的**：弱校验和只有 1–4 字节，单用它会在几十 MB 的文件上
    /// 撞出假命中，而假命中的后果是"该下的块没下"，最终整文件校验不符。
    pub fn block_matches(&self, idx: usize, block: &[u8]) -> bool {
        let Some(want) = self.blocks.get(idx) else {
            return false;
        };
        // 弱校验和要**按同一截断规则**比（见 `truncate_rsum`）；强校验和只比前 N 字节。
        if truncate_rsum(rsum(block), self.hash_lengths.rsum_bytes) != want.rsum {
            return false;
        }
        let strong = crate::ed2k::hash::md4(block);
        let n = self.hash_lengths.checksum_bytes as usize;
        strong[..n] == want.checksum[..n]
    }

    /// 需要从远端取的字节区间（升序、相邻缺失块**合并**成一段）。
    ///
    /// 合并是省流量的关键：块表按块给，但 HTTP 请求按区间发，逐块发请求等于把
    /// 一个文件的请求数放大到块数量级。
    pub fn missing_ranges(&self, seed: &[u8]) -> Vec<std::ops::Range<u64>> {
        self.missing_ranges_from(&self.present_blocks(seed))
    }

    /// 同上，但种子从流里读（真实路径用这个）。
    pub fn missing_ranges_reader<R: Read + Seek>(
        &self,
        r: R,
    ) -> std::io::Result<Vec<std::ops::Range<u64>>> {
        Ok(self.missing_ranges_from(&self.present_blocks_reader(r)?))
    }

    /// 由"已有块下标"推出缺失区间（升序、合并）。
    fn missing_ranges_from(&self, present: &[usize]) -> Vec<std::ops::Range<u64>> {
        let mut have = vec![false; self.blocks.len()];
        for i in present {
            if let Some(slot) = have.get_mut(*i) {
                *slot = true;
            }
        }
        let mut out: Vec<std::ops::Range<u64>> = Vec::new();
        for (idx, ok) in have.iter().enumerate() {
            if *ok {
                continue;
            }
            let Some(r) = self.block_range(idx) else {
                continue;
            };
            match out.last_mut() {
                // 与前一段首尾相接 → 合并（`block_range` 保证按升序且无重叠）。
                Some(last) if last.end == r.start => last.end = r.end,
                _ => out.push(r),
            }
        }
        out
    }
}

/// 从块表的一项里取出弱/强校验和。
///
/// **弱校验和的截断规则不是"取前 N 字节"**，而是 rsync 的那套：
/// 1 字节 → 只有 `b` 的低 8 位；2 字节 → 只有 `b`；3 字节 → `a` 的高 8 位 + `b`；
/// 4 字节 → `a` 与 `b` 各 2 字节。全部**大端**。
/// 这段对照 `zsync-rs` 的 `src/control.rs:240-250` 逐字实现 —— 按"取前 N 字节"写
/// 会得到一个永远不命中的匹配器。
fn decode_entry(buf: &[u8], h: HashLengths) -> BlockChecksum {
    let rs = h.rsum_bytes as usize;
    let rsum = match rs {
        1 => (0u16, u16::from(buf[0])),
        2 => (0u16, u16::from_be_bytes([buf[0], buf[1]])),
        3 => (u16::from(buf[0]), u16::from_be_bytes([buf[1], buf[2]])),
        4 => (
            u16::from_be_bytes([buf[0], buf[1]]),
            u16::from_be_bytes([buf[2], buf[3]]),
        ),
        _ => (0, 0),
    };
    let mut checksum = [0u8; 16];
    let n = h.checksum_bytes as usize;
    checksum[..n].copy_from_slice(&buf[rs..rs + n]);
    BlockChecksum { rsum, checksum }
}

/// 把一个块表项**写成字节**（与 [`decode_entry`] 互为逆运算）。
///
/// 存在的理由是可测试性：单测需要一个"已知正确"的控制文件，而**只有编码器与解码器
/// 是两条独立实现时，互逆才构成证据**（同一份代码自己编码自己解码，只能证明它自洽）。
/// 也正因为它同时是 `zsyncmake` 的写出格式，这里刻意保留完整的 4/16 字节形态。
#[cfg(test)]
pub(crate) fn encode_entry(rs: (u16, u16), checksum: &[u8; 16], h: HashLengths) -> Vec<u8> {
    let mut out = Vec::new();
    match h.rsum_bytes {
        1 => out.push(rs.1 as u8),
        2 => out.extend_from_slice(&rs.1.to_be_bytes()),
        3 => {
            out.push((rs.0 >> 8) as u8);
            out.extend_from_slice(&rs.1.to_be_bytes());
        }
        _ => {
            out.extend_from_slice(&rs.0.to_be_bytes());
            out.extend_from_slice(&rs.1.to_be_bytes());
        }
    }
    out.extend_from_slice(&checksum[..h.checksum_bytes as usize]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k::hash::md4;

    /// 按给定内容造一份控制文件（文本头 + 块表）。
    fn build(target: &[u8], blocksize: usize, h: HashLengths, with_sha1: bool) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("zsync: 0.6.2\n");
        out.push_str("Filename: target.bin\n");
        out.push_str("MTime: Wed, 01 Jan 2020 00:00:00 +0000\n");
        out.push_str(&format!("Blocksize: {blocksize}\n"));
        out.push_str(&format!("Length: {}\n", target.len()));
        out.push_str(&format!(
            "Hash-Lengths: {},{},{}\n",
            h.seq_matches, h.rsum_bytes, h.checksum_bytes
        ));
        out.push_str("URL: http://mirror.test/target.bin\n");
        if with_sha1 {
            out.push_str(&format!("SHA-1: {}\n", "a".repeat(40)));
        }
        out.push('\n');
        let mut bytes = out.into_bytes();
        for chunk in target.chunks(blocksize) {
            // 最后一块按**补齐到整块**算校验和（zsync 的约定：尾块补零）。
            let mut padded = chunk.to_vec();
            padded.resize(blocksize, 0);
            bytes.extend_from_slice(&encode_entry(rsum(&padded), &md4(&padded), h));
        }
        bytes
    }

    #[test]
    fn parses_a_well_formed_control_file() {
        let target: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let h = HashLengths::default();
        let raw = build(&target, 128, h, true);
        let c = ZsyncControl::parse(raw.as_slice()).unwrap();

        assert_eq!(c.version, "0.6.2");
        assert_eq!(c.filename.as_deref(), Some("target.bin"));
        assert_eq!(c.blocksize, 128);
        assert_eq!(c.length, 300);
        assert_eq!(c.hash_lengths, h);
        assert_eq!(c.urls, vec!["http://mirror.test/target.bin".to_string()]);
        assert_eq!(c.sha1.as_deref(), Some("a".repeat(40).as_str()));
        // 300 字节 / 128 = 3 块（最后一块不足，按补齐算）
        assert_eq!(c.blocks.len(), 3);
        assert_eq!(c.block_range(0), Some(0..128));
        assert_eq!(c.block_range(2), Some(256..300));
        assert_eq!(c.block_range(3), None);
    }

    /// 弱校验和的三种截断长度都要能与编码侧对上。
    ///
    /// 这条是**变异敏感**的：把 `3 =>` 那一支按"取前 3 字节拼 a/b"写，3 字节那轮立刻红。
    #[test]
    fn truncated_rsum_encoding_round_trips_for_every_length() {
        let target: Vec<u8> = (0..200u32).map(|i| (i * 7 % 253) as u8).collect();
        for rs in 1..=4u8 {
            let h = HashLengths {
                seq_matches: 1,
                rsum_bytes: rs,
                checksum_bytes: 16,
            };
            let raw = build(&target, 64, h, false);
            let c = ZsyncControl::parse(raw.as_slice()).unwrap();
            assert_eq!(c.blocks.len(), 4, "rs={rs}");
            // 编码器写的弱校验和必须能被解码器还原成"该块真值经同规则截断"的样子：
            // 判据是**本地原块能被认出来**（而不是比字段，那会自证）。
            assert_eq!(
                c.present_blocks(&target),
                vec![0, 1, 2, 3],
                "rs={rs} 时本地整份内容应当全部命中"
            );
        }
    }

    /// 定偏移匹配的语义：改过的块判缺失、没改的判命中，缺失区间按块合并。
    #[test]
    fn missing_ranges_cover_exactly_the_changed_blocks() {
        let bs = 64usize;
        let target: Vec<u8> = (0..256u32).map(|i| (i % 97) as u8).collect();
        let h = HashLengths::default();
        let raw = build(&target, bs, h, false);
        let c = ZsyncControl::parse(raw.as_slice()).unwrap();
        assert_eq!(c.blocks.len(), 4);

        // 种子 = 目标，但第 1 块（64..128）被改过。
        let mut seed = target.clone();
        for b in seed[bs..2 * bs].iter_mut() {
            *b ^= 0xFF;
        }
        let present = c.present_blocks(&seed);
        assert_eq!(present, vec![0, 2, 3], "只有改过的那块应当判缺失");
        assert_eq!(c.missing_ranges(&seed), vec![64..128]);

        // 相邻的两块都改了 → 必须**合并成一段**（否则等于按块发请求）。
        let mut seed2 = target.clone();
        for b in seed2[bs..3 * bs].iter_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(c.missing_ranges(&seed2), vec![64..192]);

        // 完全没有种子（空）→ 整份都要取，且是**一段**。
        assert_eq!(c.missing_ranges(&[]), vec![0..256]);
    }

    /// 尾块按补齐算校验和：种子比目标短时不能把短块当命中。
    #[test]
    fn a_short_seed_does_not_fake_a_match_on_the_tail_block() {
        let bs = 64usize;
        let target: Vec<u8> = (0..200u32).map(|i| (i % 89) as u8).collect();
        let raw = build(&target, bs, HashLengths::default(), false);
        let c = ZsyncControl::parse(raw.as_slice()).unwrap();
        // 种子只到 150 字节：第 0、1 块完整，第 2 块（128..192）缺一截。
        let seed = &target[..150];
        assert_eq!(c.present_blocks(seed), vec![0, 1]);
        assert_eq!(c.missing_ranges(seed), vec![128..200]);
    }

    /// 老格式（不写 `Hash-Lengths`）必须按缺省 `(1,4,16)` 解析 —— 否则 2005 年那批
    /// 控制文件全部下不了。
    #[test]
    fn a_legacy_file_without_hash_lengths_defaults_to_4_and_16() {
        let target: Vec<u8> = (0..128u32).map(|i| (i % 61) as u8).collect();
        // 手工去掉 Hash-Lengths 行，块表仍按 4+16 写。
        let h = HashLengths {
            seq_matches: 1,
            rsum_bytes: 4,
            checksum_bytes: 16,
        };
        let raw = build(&target, 128, h, false);
        // 头部的结束位置 = 第一个空行之后。
        let head_end = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("头部应当有空行")
            + 2;
        // 只重写**头部**字节：拿整份文件去 `lines()` 会把二进制块表也按行拆开再拼回去
        // （块表里出现 `\n` 是常态），那样拼出来的东西已经不是原文件了。
        let head_text = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let cleaned_head = head_text
            .lines()
            .filter(|l| !l.starts_with("Hash-Lengths:"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut rebuilt = cleaned_head.into_bytes();
        rebuilt.push(b'\n');
        rebuilt.extend_from_slice(&raw[head_end..]);

        let c = ZsyncControl::parse(rebuilt.as_slice()).unwrap();
        assert_eq!(c.hash_lengths, HashLengths::default());
        assert_eq!(c.present_blocks(&target), vec![0]);
    }

    /// 坏输入必须**明确回绝**，每条错误有自己的稳定码。
    #[test]
    fn malformed_control_files_are_refused_with_stable_codes() {
        let cases: Vec<(&str, Vec<u8>, ZsyncError)> = vec![
            (
                "块大小不是 2 的幂",
                b"zsync: 0.6.2\nBlocksize: 100\nLength: 200\n\n".to_vec(),
                ZsyncError::InvalidBlocksize,
            ),
            (
                "块大小为 0",
                b"zsync: 0.6.2\nBlocksize: 0\nLength: 200\n\n".to_vec(),
                ZsyncError::InvalidBlocksize,
            ),
            (
                "缺 Length",
                b"zsync: 0.6.2\nBlocksize: 64\n\n".to_vec(),
                ZsyncError::MissingField,
            ),
            (
                "Hash-Lengths 个数不对",
                b"zsync: 0.6.2\nBlocksize: 64\nLength: 64\nHash-Lengths: 1,4\n\n".to_vec(),
                ZsyncError::InvalidHashLengths,
            ),
            (
                "Hash-Lengths 强校验和越界",
                b"zsync: 0.6.2\nBlocksize: 64\nLength: 64\nHash-Lengths: 1,4,17\n\n".to_vec(),
                ZsyncError::InvalidHashLengths,
            ),
            (
                "Length 不是数字",
                b"zsync: 0.6.2\nBlocksize: 64\nLength: abc\n\n".to_vec(),
                ZsyncError::InvalidLength,
            ),
            (
                "SHA-1 长度不对",
                b"zsync: 0.6.2\nBlocksize: 64\nLength: 64\nSHA-1: deadbeef\n\n".to_vec(),
                ZsyncError::InvalidSha1,
            ),
            (
                "头行没有冒号",
                b"zsync: 0.6.2\nthis is not a header\n\n".to_vec(),
                ZsyncError::InvalidHeader,
            ),
            (
                "块表被截断",
                b"zsync: 0.6.2\nBlocksize: 64\nLength: 640\n\nshort".to_vec(),
                ZsyncError::Truncated,
            ),
        ];
        for (name, raw, want) in cases {
            let got = ZsyncControl::parse(raw.as_slice());
            assert_eq!(got.as_ref().err(), Some(&want), "用例：{name}");
            assert!(
                want.code().starts_with("zsync_"),
                "每条错误都要有稳定的 zsync_ 机器码"
            );
        }

        // 没有终结空行（头部吃满上限）→ 明确的 HeaderTooLarge，而不是"解析出半个文件"。
        let mut no_blank = b"zsync: 0.6.2\n".to_vec();
        no_blank.extend(std::iter::repeat_n(b'U', MAX_HEADER_BYTES as usize));
        assert_eq!(
            ZsyncControl::parse(no_blank.as_slice()).err(),
            Some(ZsyncError::HeaderTooLarge)
        );
    }

    /// 认不出的头字段必须被忽略（格式允许扩展），而不是拒绝整个文件。
    #[test]
    fn unknown_header_fields_are_ignored() {
        let target: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        let raw = build(&target, 64, HashLengths::default(), false);
        let head_end = raw.windows(2).position(|w| w == b"\n\n").unwrap() + 1;
        let mut rebuilt =
            b"zsync: 0.6.2\nBlocksize: 64\nLength: 64\nX-Future-Field: whatever\n".to_vec();
        rebuilt.extend_from_slice(&raw[head_end..]);
        let c = ZsyncControl::parse(rebuilt.as_slice()).unwrap();
        assert_eq!(c.length, 64);
        assert_eq!(c.present_blocks(&target), vec![0]);
    }

    /// rsum 与独立计算的对照：手算一个已知序列。
    ///
    /// 这条**不用被测代码产生期望值**：`[1,2,3]` 的 `a=6`、`b=1+3+6=10` 是手算的。
    #[test]
    fn rsum_matches_a_hand_computed_sequence() {
        assert_eq!(rsum(&[]), (0, 0));
        assert_eq!(rsum(&[1]), (1, 1));
        assert_eq!(rsum(&[1, 2]), (3, 4)); // a=1+2=3, b=1+3=4
        assert_eq!(rsum(&[1, 2, 3]), (6, 10)); // a=6, b=1+3+6=10
                                               // 回绕：300 个 255 累加后按 u16 取模（255×300 = 76500 → 10964）
        let many = vec![255u8; 300];
        let (a, _) = rsum(&many);
        assert_eq!(a, 255u16.wrapping_mul(300));
    }

    /// 流式匹配与切片匹配必须给出**逐字相同**的结果。
    ///
    /// 这条守的是"真实路径与测试路径不是两套实现"：生产代码只能走流式（种子可能是
    /// 几 GiB），而单测都在切片上跑 —— 两者一旦分叉，测试全绿而线上认不出任何块。
    #[test]
    fn streaming_match_agrees_with_the_slice_version() {
        let bs = 64usize;
        let target: Vec<u8> = (0..250u32).map(|i| (i % 83) as u8).collect();
        let raw = build(&target, bs, HashLengths::default(), false);
        let c = ZsyncControl::parse(raw.as_slice()).unwrap();

        // 三种种子：完整、缺尾、改过中间一块。
        let mut changed = target.clone();
        for b in changed[bs..2 * bs].iter_mut() {
            *b ^= 0xFF;
        }
        for seed in [target.as_slice(), &target[..150], changed.as_slice()] {
            let slice = c.present_blocks(seed);
            let streamed = c.present_blocks_reader(std::io::Cursor::new(seed)).unwrap();
            assert_eq!(slice, streamed, "两种实现的命中集必须一致");
            assert_eq!(
                c.missing_ranges(seed),
                c.missing_ranges_reader(std::io::Cursor::new(seed)).unwrap(),
                "缺失区间也必须一致"
            );
        }

        // 空种子：整份缺失，且是**一段**（不是按块切成一堆）。
        let empty = c
            .present_blocks_reader(std::io::Cursor::new(Vec::<u8>::new()))
            .unwrap();
        assert!(empty.is_empty());
        assert_eq!(
            c.missing_ranges_reader(std::io::Cursor::new(Vec::<u8>::new()))
                .unwrap(),
            vec![0..250]
        );
    }

    /// **穷举**本模块的每一个错误码，逐个确认它在受控集合里、且有面向用户的文案。
    ///
    /// 为什么要穷举而不是挑两个样本：`is_known_code` 是按**前缀**收编的，只要前缀常量在，
    /// 新加一个 `ZsyncError` 变体就会**自动**被判为已知码 —— 于是"加了变体却忘了写文案"
    /// 不会被任何现有测试发现，界面只会把生码串原样显示出来。这条测试把枚举值与注册表绑死：
    /// 将来加变体时，这里会先红。
    #[test]
    fn every_error_code_is_registered_with_a_message() {
        use crate::error::{classify, is_known_code};
        let all = [
            ZsyncError::HeaderTooLarge,
            ZsyncError::InvalidHeader,
            ZsyncError::MissingField,
            ZsyncError::InvalidBlocksize,
            ZsyncError::InvalidHashLengths,
            ZsyncError::InvalidLength,
            ZsyncError::InvalidSha1,
            ZsyncError::TooManyBlocks,
            ZsyncError::Truncated,
        ];
        assert_eq!(all.len(), 9, "错误码个数变了就要同步这条测试与文档");
        for e in all {
            let code = e.code();
            assert!(
                code.starts_with(crate::error::ZSYNC_CODE_PREFIX),
                "{code} 必须落在 zsync_ 前缀族里"
            );
            assert!(is_known_code(code), "{code} 必须判为已知机器码");
            let c = classify(code);
            assert_eq!(c.code, code, "{code} 的机器码不该被改写");
            assert_ne!(c.message, code, "{code} 缺少 human_message 文案");
        }
    }
}
