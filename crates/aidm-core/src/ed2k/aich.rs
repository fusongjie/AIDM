//! AICH（Advanced Intelligent Corruption Handling）SHA-1 哈希树。
//!
//! 两份能力：
//! 1. **建树/校验**：按 eMule 的规则（`SHAHashSet.cpp:120-149`）把文件切成 180 KiB 叶块，
//!    分片（9,728,000 字节）为给定层级；父哈希 = `SHA1(left || right)`；奇数分裂时多数
//!    元素进入**与父节点同侧**的子树（`SHAHashSet.h:25-28`）。
//! 2. **块级恢复**（`OP_AICHREQUEST`/`OP_AICHANSWER`）：按 16/32 位哈希标识符把对端给的
//!    兄弟哈希与叶哈希插回树，用可信根验证整棵树，从而只重下**损坏的 180 KiB 块**，
//!    而不是整个 9,728,000 字节分片。
//!
//! 标识符语义（`SHAHashSet.h:46-62` 原文示例）：从根到节点的路径，最高置位 bit 是起点
//! （首节点恒视为左枝），其后每个 bit：1 = 走左枝，0 = 走右枝。根 = `0x0001`，
//! 左子 = `0x0003`，左子的右子 = `0x0006`。
//!
//! **安全边界**：AICH 只用来**定位**损坏块，最终接受与否仍由分片 MD4 决定
//! （`peer_session` 的验收闸门不变）。因此对端给出的 AICH 数据即便撒谎，也只能让我们
//! 白下几块或退回整片重下，不可能让坏数据被接受。

use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};

use super::peer::{EMBLOCKSIZE, PARTSIZE};

pub type AichHash = [u8; 20];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AichTree {
    pub root: AichHash,
    /// 按文件偏移递增排列的 180 KiB（尾块可更短）叶哈希。
    pub blocks: Vec<AichHash>,
}

fn sha1(data: &[u8]) -> AichHash {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .try_into()
        .unwrap()
}

fn tree_hash(data: &[u8], base_size: usize, is_left: bool) -> AichHash {
    if data.len() <= base_size {
        return sha1(data);
    }
    let blocks = data.len().div_ceil(base_size);
    let left_blocks = if is_left {
        (blocks + 1) / 2
    } else {
        blocks / 2
    };
    let left_len = left_blocks * base_size;
    let (left, right) = data.split_at(left_len);
    let left_base = if left.len() <= PARTSIZE as usize {
        EMBLOCKSIZE as usize
    } else {
        PARTSIZE as usize
    };
    let right_base = if right.len() <= PARTSIZE as usize {
        EMBLOCKSIZE as usize
    } else {
        PARTSIZE as usize
    };
    let left_hash = tree_hash(left, left_base, true);
    let right_hash = tree_hash(right, right_base, false);
    let mut pair = [0u8; 40];
    pair[..20].copy_from_slice(&left_hash);
    pair[20..].copy_from_slice(&right_hash);
    sha1(&pair)
}

/// 叶哈希清单：**块边界在分片边界处重置**。
///
/// `PARTSIZE / EMBLOCKSIZE = 52.78…`，所以每个分片是「52 整块 + 一个 143,360 字节的尾块」。
/// 跨分片按 180 KiB 齐步走会得到树里根本不存在的"块"，因此这里逐分片切。
pub fn leaf_blocks(data: &[u8]) -> Vec<AichHash> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let part_len = (PARTSIZE as usize).min(data.len() - offset);
        let part = &data[offset..offset + part_len];
        out.extend(part.chunks(EMBLOCKSIZE as usize).map(sha1));
        offset += part_len;
    }
    out
}

pub fn build(data: &[u8]) -> AichTree {
    let base = if data.len() <= PARTSIZE as usize {
        EMBLOCKSIZE as usize
    } else {
        PARTSIZE as usize
    };
    AichTree {
        root: tree_hash(data, base, true),
        blocks: leaf_blocks(data),
    }
}

/// 用可信叶哈希定位损坏块。
///
/// `data` 必须是**一个分片**的字节（或整份文件不超过一个分片时的全部字节）：
/// 块边界在分片边界重置，跨分片传入会得到错误的下标。数量不符直接拒绝，不能猜尾块边界。
pub fn corrupt_blocks(data: &[u8], trusted: &[AichHash]) -> Result<Vec<usize>, &'static str> {
    let expected = data.len().div_ceil(EMBLOCKSIZE as usize);
    if trusted.len() != expected {
        return Err("aich_block_count");
    }
    Ok(data
        .chunks(EMBLOCKSIZE as usize)
        .zip(trusted)
        .enumerate()
        .filter_map(|(index, (block, expected))| (sha1(block) != *expected).then_some(index))
        .collect())
}

pub fn decode_base32(value: &str) -> Option<AichHash> {
    if value.len() != 32 || !value.is_ascii() {
        return None;
    }
    let mut out = [0u8; 20];
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let mut offset = 0usize;
    for byte in value.bytes() {
        let upper = byte.to_ascii_uppercase();
        let digit = match upper {
            b'A'..=b'Z' => upper - b'A',
            b'2'..=b'7' => upper - b'2' + 26,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[offset] = (accumulator >> bits) as u8;
            offset += 1;
            accumulator &= (1u32 << bits).saturating_sub(1);
        }
    }
    (offset == 20 && bits == 0).then_some(out)
}

// ---------- 恢复树 ----------

/// 32 位标识符上限：eMule 拒绝 `> 0x400000`（`SHAHashSet.cpp:720`）。
pub const WIDE_IDENTIFIER_MAX: u32 = 0x40_0000;
/// 根标识符：永远不允许被对端覆盖（`SHAHashSet.cpp:699/719`）。
pub const ROOT_IDENTIFIER: u32 = 1;

/// `OP_AICHANSWER` 里的一条哈希：标识符 + 宽度 + 20 字节 SHA-1。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryHash {
    pub identifier: u32,
    /// true = 32 位标识符（大文件），false = 16 位。
    pub wide: bool,
    pub hash: AichHash,
}

/// 可增量填充的 AICH 树。节点按需展开（`FindHash` 建骨架）。
#[derive(Debug, Clone)]
pub struct Tree {
    data_size: u64,
    is_left: bool,
    base: u64,
    hash: Option<AichHash>,
    left: Option<Box<Tree>>,
    right: Option<Box<Tree>>,
}

impl Tree {
    /// 按 eMule 的 BaseSize 规则建节点：数据量 ≤ 分片大小 → 叶层是 180 KiB，否则是分片。
    pub fn new(data_size: u64, is_left: bool) -> Self {
        Self {
            data_size,
            is_left,
            base: if data_size <= PARTSIZE {
                EMBLOCKSIZE
            } else {
                PARTSIZE
            },
            hash: None,
            left: None,
            right: None,
        }
    }

    /// 用真实数据建满树（叶 = 180 KiB SHA-1）。
    pub fn from_data(data: &[u8]) -> Self {
        let mut tree = Tree::new(data.len() as u64, true);
        tree.fill(data, 0);
        tree
    }

    fn fill(&mut self, data: &[u8], offset: usize) {
        if self.data_size <= self.base {
            self.hash = Some(sha1(data));
            return;
        }
        let (nleft, _) = self.split_sizes().expect("split");
        let mut left = Tree::new(nleft, true);
        let mut right = Tree::new(self.data_size - nleft, false);
        let (l, r) = data.split_at(nleft as usize);
        left.fill(l, offset);
        right.fill(r, offset + nleft as usize);
        let mut pair = [0u8; 40];
        pair[..20].copy_from_slice(left.hash.as_ref().expect("left hash"));
        pair[20..].copy_from_slice(right.hash.as_ref().expect("right hash"));
        self.hash = Some(sha1(&pair));
        self.left = Some(Box::new(left));
        self.right = Some(Box::new(right));
    }

    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    pub fn base_size(&self) -> u64 {
        self.base
    }

    pub fn hash(&self) -> Option<AichHash> {
        self.hash
    }

    /// 装入可信的根哈希（链接里的 `h=` 或对端 FileIdentifier 给的 AICH 根）。
    pub fn set_master(&mut self, root: AichHash) {
        self.hash = Some(root);
    }

    /// 当前节点可分的左右子数据量；已是叶层返回 None。
    fn split_sizes(&self) -> Option<(u64, u64)> {
        if self.data_size <= self.base {
            return None;
        }
        let blocks = self.data_size.div_ceil(self.base);
        // 奇数分裂时多数元素进入与父节点同侧的子树；首节点恒视为左枝。
        let left_blocks = if self.is_left {
            blocks.div_ceil(2)
        } else {
            blocks / 2
        };
        let nleft = (left_blocks * self.base).min(self.data_size);
        Some((nleft, self.data_size - nleft))
    }

    fn left_mut(&mut self) -> &mut Tree {
        let (nleft, _) = self.split_sizes().expect("left of a splittable node");
        self.left
            .get_or_insert_with(|| Box::new(Tree::new(nleft, true)))
    }

    fn right_mut(&mut self) -> &mut Tree {
        let (nleft, _) = self.split_sizes().expect("right of a splittable node");
        let nright = self.data_size - nleft;
        self.right
            .get_or_insert_with(|| Box::new(Tree::new(nright, false)))
    }

    /// 展开骨架并返回该节点（`FindHash`）。
    fn node_at_mut(&mut self, start: u64, size: u64) -> Option<&mut Tree> {
        let mut node = &mut *self;
        let mut start = start;
        loop {
            if start.checked_add(size)? > node.data_size || size > node.data_size {
                return None;
            }
            if start == 0 && size == node.data_size {
                return Some(node);
            }
            let (nleft, nright) = node.split_sizes()?;
            if start < nleft {
                if start + size > nleft {
                    return None;
                }
                node = node.left_mut();
            } else {
                start -= nleft;
                if start + size > nright {
                    return None;
                }
                node = node.right_mut();
            }
        }
    }

    /// 展开骨架并返回该节点的层级（根 = 1，与 `FindHash` 的 `nLevel` 一致）。
    pub fn level_of(&mut self, start: u64, size: u64) -> Option<u8> {
        let mut node = &mut *self;
        let mut start = start;
        let mut level = 1u8;
        loop {
            if start.checked_add(size)? > node.data_size || size > node.data_size {
                return None;
            }
            if start == 0 && size == node.data_size {
                return Some(level);
            }
            let (nleft, nright) = node.split_sizes()?;
            if start < nleft {
                if start + size > nleft {
                    return None;
                }
                node = node.left_mut();
            } else {
                start -= nleft;
                if start + size > nright {
                    return None;
                }
                node = node.right_mut();
            }
            level = level.checked_add(1)?;
            if level > 22 {
                return None;
            }
        }
    }

    /// 直接设置某分片节点的哈希（`OP_HASHSETANSWER2` 的分片哈希集路径）。
    pub fn set_part_hash(&mut self, part_start: u64, part_size: u64, hash: AichHash) -> bool {
        match self.node_at_mut(part_start, part_size) {
            Some(node) => {
                node.hash = Some(hash);
                true
            }
            None => false,
        }
    }

    /// 按标识符把一个哈希插进树（`SetHash`，`SHAHashSet.cpp:461-516`）。
    ///
    /// `wide` 只用来记录线格式宽度：路径语义与宽度无关（最高置位 bit 是起点）。
    pub fn insert_hash(&mut self, identifier: u32, wide: bool, hash: AichHash) -> bool {
        let _ = wide;
        if identifier == 0 || identifier == ROOT_IDENTIFIER {
            // 根不允许被对端覆盖（否则"验证"就变成自我确认）。
            return false;
        }
        if wide && identifier > WIDE_IDENTIFIER_MAX {
            return false;
        }
        let mut level = 31 - identifier.leading_zeros();
        let mut ident = identifier << (31 - level);
        let mut node = &mut *self;
        while level > 0 {
            let Some((_nleft, _nright)) = node.split_sizes() else {
                return false;
            };
            ident <<= 1;
            level -= 1;
            node = if ident & 0x8000_0000 != 0 {
                node.left_mut()
            } else {
                node.right_mut()
            };
        }
        node.hash = Some(hash);
        true
    }

    /// 用已有子哈希补齐父哈希（`ReCalculateHash`）。`dont_replace` 时保留已有值。
    fn recalc(&mut self, dont_replace: bool) -> bool {
        match (self.left.as_mut(), self.right.as_mut()) {
            (Some(left), Some(right)) => {
                if !left.recalc(dont_replace) || !right.recalc(dont_replace) {
                    return false;
                }
                if dont_replace && self.hash.is_some() {
                    return true;
                }
                match (left.hash, right.hash) {
                    (Some(l), Some(r)) => {
                        let mut pair = [0u8; 40];
                        pair[..20].copy_from_slice(&l);
                        pair[20..].copy_from_slice(&r);
                        self.hash = Some(sha1(&pair));
                        true
                    }
                    _ => self.hash.is_some(),
                }
            }
            (None, None) => true,
            // 半边子树在 eMule 里是不变量被破坏（ASSERT）。
            _ => false,
        }
    }

    /// 校验整棵树：每个父哈希必须等于 `SHA1(left || right)`（`VerifyHashTree`）。
    pub fn verify(&mut self) -> bool {
        if self.hash.is_none() {
            return false;
        }
        if let Some(left) = self.left.as_mut() {
            if left.hash.is_none() {
                left.recalc(true);
            }
        }
        if let Some(right) = self.right.as_mut() {
            if right.hash.is_none() {
                right.recalc(true);
            }
        }
        let left_valid = self.left.as_ref().is_some_and(|n| n.hash.is_some());
        let right_valid = self.right.as_ref().is_some_and(|n| n.hash.is_some());
        if left_valid != right_valid {
            // 单侧可验证的树不完整。
            return false;
        }
        if left_valid && right_valid {
            let (l, r) = (
                self.left.as_ref().unwrap().hash.unwrap(),
                self.right.as_ref().unwrap().hash.unwrap(),
            );
            let mut pair = [0u8; 40];
            pair[..20].copy_from_slice(&l);
            pair[20..].copy_from_slice(&r);
            if Some(sha1(&pair)) != self.hash {
                return false;
            }
            return self.left.as_mut().unwrap().verify() && self.right.as_mut().unwrap().verify();
        }
        true
    }

    fn find_existing(&self, start: u64, size: u64) -> Option<&Tree> {
        if start.checked_add(size)? > self.data_size || size > self.data_size {
            return None;
        }
        if start == 0 && size == self.data_size {
            return self.hash.map(|_| self);
        }
        let (nleft, nright) = self.split_sizes()?;
        if start < nleft {
            if start + size > nleft {
                return None;
            }
            self.left.as_deref()?.find_existing(start, size)
        } else {
            let start = start - nleft;
            if start + size > nright {
                return None;
            }
            self.right.as_deref()?.find_existing(start, size)
        }
    }

    /// 某分片里每个 180 KiB 块的叶哈希（全部必须已在树里）。
    pub fn block_hashes(&self, part_start: u64, part_size: u64) -> Option<Vec<AichHash>> {
        let mut out = Vec::new();
        let mut pos = 0u64;
        while pos < part_size {
            let size = EMBLOCKSIZE.min(part_size - pos);
            let node = self.find_existing(part_start + pos, size)?;
            out.push(node.hash?);
            pos += size;
        }
        (!out.is_empty()).then_some(out)
    }

    /// 分片节点自身的哈希（`GetPartHashs` 逐个分片取一次）。
    pub fn part_hash(&self, part_start: u64, part_size: u64) -> Option<AichHash> {
        self.find_existing(part_start, part_size)?.hash
    }

    /// 全部分片哈希（`GetPartHashs`）；单分片文件没有分片哈希（返回空表）。
    pub fn part_hashes(&self, file_size: u64) -> Vec<AichHash> {
        if file_size <= PARTSIZE {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut start = 0u64;
        while start < file_size {
            let size = PARTSIZE.min(file_size - start);
            match self.part_hash(start, size) {
                Some(h) => out.push(h),
                None => return Vec::new(),
            }
            start += size;
        }
        out
    }

    /// 分片哈希是否已齐。
    ///
    /// **必须与 [`Tree::verify`] 一起用**：eMule 的 `VerifyHashTree` 对"两侧都没有哈希"
    /// 的节点按"这条枝到此为止"处理并返回成功（`SHAHashSet.cpp:289-309`），
    /// 完整性是调用方另外检查的（`ReadRecoveryData` 逐块 `FindExistingHash`，
    /// `VerifyAICHHashSet` 则检查分片哈希个数）。
    pub fn part_hashes_complete(&self, file_size: u64) -> bool {
        if file_size <= PARTSIZE {
            return true;
        }
        let mut start = 0u64;
        while start < file_size {
            let size = PARTSIZE.min(file_size - start);
            if self.part_hash(start, size).is_none() {
                return false;
            }
            start += size;
        }
        true
    }

    /// 生成某分片的恢复数据（`CreatePartRecoveryData`，`SHAHashSet.cpp:335-398`）。
    ///
    /// 顺序：自根向下每一层的**兄弟**哈希，然后是该分片自左到右的全部叶哈希。
    /// 条数必须等于 `(分片层级 - 1) + ceil(分片大小 / 180 KiB)`。
    pub fn create_recovery(
        &self,
        part_start: u64,
        part_size: u64,
        wide: bool,
    ) -> Option<Vec<RecoveryHash>> {
        if self.hash.is_none() {
            return None;
        }
        let level = {
            let mut probe = self.clone();
            probe.level_of(part_start, part_size)?
        };
        let blocks = part_size.div_ceil(EMBLOCKSIZE);
        let expected = usize::from(level - 1) + blocks as usize;
        let mut out = Vec::with_capacity(expected);
        self.write_recovery(part_start, part_size, 0, wide, &mut out)?;
        (out.len() == expected).then_some(out)
    }

    fn write_recovery(
        &self,
        start: u64,
        size: u64,
        ident: u32,
        wide: bool,
        out: &mut Vec<RecoveryHash>,
    ) -> Option<()> {
        if start == 0 && size == self.data_size {
            return self.write_lowest_level(ident, wide, out);
        }
        let (nleft, nright) = self.split_sizes()?;
        let ident = (ident << 1) | u32::from(self.is_left);
        if start < nleft {
            if start + size > nleft {
                return None;
            }
            let right = self.right.as_deref()?;
            let hash = right.hash?;
            out.push(RecoveryHash {
                identifier: (ident << 1) | u32::from(right.is_left),
                wide,
                hash,
            });
            self.left
                .as_deref()?
                .write_recovery(start, size, ident, wide, out)
        } else {
            let start = start - nleft;
            if start + size > nright {
                return None;
            }
            let left = self.left.as_deref()?;
            let hash = left.hash?;
            out.push(RecoveryHash {
                identifier: (ident << 1) | u32::from(left.is_left),
                wide,
                hash,
            });
            self.right
                .as_deref()?
                .write_recovery(start, size, ident, wide, out)
        }
    }

    fn write_lowest_level(
        &self,
        ident: u32,
        wide: bool,
        out: &mut Vec<RecoveryHash>,
    ) -> Option<()> {
        let ident = (ident << 1) | u32::from(self.is_left);
        match (self.left.as_deref(), self.right.as_deref()) {
            (None, None) => {
                if self.data_size > self.base {
                    return None;
                }
                out.push(RecoveryHash {
                    identifier: ident,
                    wide,
                    hash: self.hash?,
                });
                Some(())
            }
            (Some(left), Some(right)) => {
                left.write_lowest_level(ident, wide, out)?;
                right.write_lowest_level(ident, wide, out)
            }
            _ => None,
        }
    }
}

/// `OP_AICHANSWER` 恢复数据载荷：`count1(u16) + [id16+hash]×count1 + count2(u16) + [id32+hash]×count2`（`SHAHashSet.cpp:674-679`）。
pub fn encode_recovery(hashes: &[RecoveryHash]) -> Vec<u8> {
    let wide = hashes.first().is_some_and(|h| h.wide);
    let mut out = Vec::with_capacity(4 + hashes.len() * 24);
    if wide {
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
    } else {
        out.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
    }
    for h in hashes {
        if wide {
            out.extend_from_slice(&h.identifier.to_le_bytes());
        } else {
            out.extend_from_slice(&(h.identifier as u16).to_le_bytes());
        }
        out.extend_from_slice(&h.hash);
    }
    if !wide {
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    out
}

/// 把对端给的哈希插进树。任何非法标识符/重复插入都 fail-closed。
pub fn insert_recovery(tree: &mut Tree, hashes: &[RecoveryHash]) -> Result<(), &'static str> {
    if hashes.is_empty() {
        return Err("aich_no_hashes");
    }
    for h in hashes {
        if h.identifier == ROOT_IDENTIFIER {
            return Err("aich_root_overwrite");
        }
        if h.wide && h.identifier > WIDE_IDENTIFIER_MAX {
            return Err("aich_identifier_range");
        }
        if !tree.insert_hash(h.identifier, h.wide, h.hash) {
            return Err("aich_bad_identifier");
        }
    }
    Ok(())
}

/// 解析 `OP_AICHANSWER` 的恢复数据（只认 `count1`/`count2` 两种宽度）。
pub fn decode_recovery(payload: &[u8]) -> Result<Vec<RecoveryHash>, &'static str> {
    let mut reader = Slice::new(payload);
    let count1 = reader.u16().ok_or("aich_truncated")? as usize;
    let mut out = Vec::new();
    for _ in 0..count1 {
        let identifier = reader.u16().ok_or("aich_truncated")? as u32;
        let hash = reader.hash().ok_or("aich_truncated")?;
        out.push(RecoveryHash {
            identifier,
            wide: false,
            hash,
        });
    }
    let count2 = reader.u16().ok_or("aich_truncated")? as usize;
    for _ in 0..count2 {
        let identifier = reader.u32().ok_or("aich_truncated")?;
        let hash = reader.hash().ok_or("aich_truncated")?;
        out.push(RecoveryHash {
            identifier,
            wide: true,
            hash,
        });
    }
    // 尾随数据一律拒绝：恢复数据是定长的，多出来的字节说明对端在试探解析边界。
    if reader.remaining() != 0 {
        return Err("aich_trailing");
    }
    Ok(out)
}

/// 用恢复数据 + 可信根定位某分片的损坏块。
///
/// 返回该分片每个 180 KiB 块的**可信叶哈希**；调用方再拿它与本地数据比对
/// （[`corrupt_blocks`]）。树不自洽、根不匹配、块不齐一律报错，绝不猜。
pub fn recover_part_blocks(
    file_size: u64,
    part_start: u64,
    part_size: u64,
    master: AichHash,
    hashes: &[RecoveryHash],
) -> Result<Vec<AichHash>, &'static str> {
    if part_start
        .checked_add(part_size)
        .is_none_or(|end| end > file_size)
    {
        return Err("aich_part_range");
    }
    let mut tree = Tree::new(file_size, true);
    tree.set_master(master);
    insert_recovery(&mut tree, hashes)?;
    if !tree.verify() {
        return Err("aich_verify_failed");
    }
    tree.block_hashes(part_start, part_size)
        .ok_or("aich_incomplete_part")
}

struct Slice<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Slice<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.o)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let out = &self.b[self.o..self.o + n];
        self.o += n;
        Some(out)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn hash(&mut self) -> Option<AichHash> {
        self.take(20)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_block_matches_published_sha1() {
        let tree = build(b"abc");
        assert_eq!(tree.root, hex20("a9993e364706816aba3e25717850c26c9cd0d89d"));
        assert_eq!(tree.blocks, vec![tree.root]);
    }

    #[test]
    fn detects_only_the_corrupted_block() {
        let data = vec![0x55; EMBLOCKSIZE as usize * 2 + 17];
        let tree = build(&data);
        let mut damaged = data.clone();
        damaged[EMBLOCKSIZE as usize + 9] ^= 1;
        assert_eq!(corrupt_blocks(&damaged, &tree.blocks).unwrap(), vec![1]);
        assert_eq!(
            corrupt_blocks(&data, &tree.blocks).unwrap(),
            Vec::<usize>::new()
        );
        assert_eq!(
            corrupt_blocks(&data, &tree.blocks[..2]),
            Err("aich_block_count")
        );
    }

    #[test]
    fn base32_is_exact_and_fail_closed() {
        let decoded = decode_base32("H52BRVWPBBTAED5NXQDH2RJDDAKRUWST").unwrap();
        assert_eq!(decoded.len(), 20);
        assert!(decode_base32("H52BRVWPBBTAED5NXQDH2RJDDAKRUWS").is_none());
        assert!(decode_base32("H52BRVWPBBTAED5NXQDH2RJDDAKRUWS0").is_none());
    }

    fn hex20(value: &str) -> AichHash {
        let mut out = [0; 20];
        for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    // ---------- 恢复树 ----------

    /// 增量树必须与已被独立向量验证过的扁平实现给出同一个根。
    #[test]
    fn tree_root_matches_the_verified_flat_builder() {
        for len in [
            1usize,
            100,
            EMBLOCKSIZE as usize,
            EMBLOCKSIZE as usize + 1,
            3 * EMBLOCKSIZE as usize + 7,
            PARTSIZE as usize,
            PARTSIZE as usize + 1,
            PARTSIZE as usize + 5 * EMBLOCKSIZE as usize + 13,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let flat = build(&data);
            let mut tree = Tree::from_data(&data);
            assert_eq!(tree.hash(), Some(flat.root), "len={len}");
            assert_eq!(flat.blocks, leaf_blocks(&data), "len={len}");
            // 叶哈希按分片取：跨分片要逐分片比对（块边界在分片处重置）
            let mut at = 0usize;
            let mut start = 0u64;
            while start < len as u64 {
                let part_size = (PARTSIZE).min(len as u64 - start);
                let count = part_size.div_ceil(EMBLOCKSIZE) as usize;
                assert_eq!(
                    tree.block_hashes(start, part_size).unwrap(),
                    flat.blocks[at..at + count],
                    "len={len} part_start={start}"
                );
                at += count;
                start += part_size;
            }
            // verify 与"分片哈希是否齐"是两件事：完整树两者都成立
            assert!(tree.verify(), "len={len}");
            assert!(tree.part_hashes_complete(len as u64), "len={len}");
        }
    }

    /// eMule `SHAHashSet.h:46-62` 的标识符示例：根 0x0001、左子 0x0003、左子的右子 0x0006。
    /// 3 个分片的文件正好让 part0/part1/part2 落在 0x0007 / 0x0006 / 0x0002。
    #[test]
    fn identifier_paths_follow_the_emule_example() {
        let file_size = 3 * PARTSIZE;
        // 3 块 → 左 2 块（奇数时多数进与父同侧）→ 左 1 右 1；右侧 1 块。
        assert_eq!(Tree::new(file_size, true).level_of(0, PARTSIZE), Some(3));
        assert_eq!(
            Tree::new(file_size, true).level_of(PARTSIZE, PARTSIZE),
            Some(3)
        );
        assert_eq!(
            Tree::new(file_size, true).level_of(2 * PARTSIZE, PARTSIZE),
            Some(2)
        );

        let data = vec![7u8; file_size as usize];
        let full = Tree::from_data(&data);
        let master = full.hash().unwrap();
        let part_hash = |index: u64| full.part_hash(index * PARTSIZE, PARTSIZE).unwrap();

        let mut tree = Tree::new(file_size, true);
        tree.set_master(master);
        assert!(tree.insert_hash(0x0007, false, part_hash(0)));
        assert!(tree.insert_hash(0x0006, false, part_hash(1)));
        assert!(tree.insert_hash(0x0002, false, part_hash(2)));
        assert!(tree.verify(), "按 0x0007/0x0006/0x0002 插入必须能验证到根");
        assert_eq!(tree.part_hash(0, PARTSIZE), Some(part_hash(0)));
        assert_eq!(tree.part_hash(PARTSIZE, PARTSIZE), Some(part_hash(1)));
        assert_eq!(tree.part_hash(2 * PARTSIZE, PARTSIZE), Some(part_hash(2)));

        // 把 part1 的哈希插到 part0 的位置（0x0007）→ 根对不上，必须拒绝
        let mut swapped = Tree::new(file_size, true);
        swapped.set_master(master);
        assert!(swapped.insert_hash(0x0007, false, part_hash(1)));
        assert!(swapped.insert_hash(0x0006, false, part_hash(0)));
        assert!(swapped.insert_hash(0x0002, false, part_hash(2)));
        assert!(!swapped.verify());

        // 根标识符永远不允许被覆盖
        assert!(!tree.insert_hash(ROOT_IDENTIFIER, false, [1; 20]));
        assert!(!tree.insert_hash(0, false, [1; 20]));
        // 叶层节点无法再分：单块文件的根就是叶，任何下降路径都必须失败
        assert!(!Tree::new(1000, true).insert_hash(0x0003, false, [1; 20]));
        assert!(!Tree::new(1000, true).insert_hash(0x0002, false, [1; 20]));
    }

    /// 分片哈希集（`OP_HASHSETANSWER2` 里那一段）装进树后必须能验证到根。
    #[test]
    fn part_hashset_verifies_against_the_master_root() {
        let file_size = 2 * PARTSIZE + 5 * EMBLOCKSIZE;
        let data: Vec<u8> = (0..file_size as usize).map(|i| (i % 241) as u8).collect();
        let full = Tree::from_data(&data);
        let part_hashes = full.part_hashes(file_size);
        assert_eq!(part_hashes.len(), 3, "3 个分片各一个哈希");

        let mut tree = Tree::new(file_size, true);
        tree.set_master(full.hash().unwrap());
        for (index, hash) in part_hashes.iter().enumerate() {
            let start = index as u64 * PARTSIZE;
            let size = PARTSIZE.min(file_size - start);
            assert!(tree.set_part_hash(start, size, *hash));
        }
        assert!(tree.verify(), "分片哈希集必须能验证到根");
        assert!(tree.part_hashes_complete(file_size));
        // 换掉一个分片哈希 → 根不匹配，必须拒绝
        let mut bad = tree.clone();
        assert!(bad.set_part_hash(0, PARTSIZE, [0xAB; 20]));
        assert!(!bad.verify());
        // 少一个分片：`verify` 按 eMule 语义会把"两侧都没有哈希"的枝当作到此为止
        //（所以它仍可能返回成功），完整性必须另外用 `part_hashes_complete` 判定。
        let mut hole = Tree::new(file_size, true);
        hole.set_master(full.hash().unwrap());
        assert!(hole.set_part_hash(0, PARTSIZE, part_hashes[0]));
        assert!(!hole.part_hashes_complete(file_size));
        assert!(hole.part_hash(0, PARTSIZE).is_some());
        assert!(hole.part_hash(PARTSIZE, PARTSIZE).is_none());
    }

    /// 单分片文件没有分片哈希（`GetTheoreticalAICHPartHashCount` 返回 0）。
    #[test]
    fn single_part_file_has_no_part_hashes() {
        let data = vec![3u8; 4 * EMBLOCKSIZE as usize];
        let tree = Tree::from_data(&data);
        assert!(tree.part_hashes(data.len() as u64).is_empty());
    }

    #[test]
    fn recovery_roundtrip_locates_only_the_corrupt_block() {
        let file_size = 5 * EMBLOCKSIZE + 1000;
        let data: Vec<u8> = (0..file_size as usize).map(|i| (i % 233) as u8).collect();
        let tree = Tree::from_data(&data);
        let master = tree.hash().unwrap();

        for wide in [false, true] {
            let entries = tree.create_recovery(0, file_size, wide).unwrap();
            // 单分片：没有兄弟哈希，条数 = 块数
            assert_eq!(entries.len(), 6);
            let payload = encode_recovery(&entries);
            let decoded = decode_recovery(&payload).unwrap();
            assert_eq!(decoded.len(), entries.len());
            let blocks = recover_part_blocks(file_size, 0, file_size, master, &decoded).unwrap();
            assert_eq!(blocks.len(), 6);

            // 只弄坏第 3 块：必须只报第 3 块
            let mut damaged = data.clone();
            damaged[3 * EMBLOCKSIZE as usize + 9] ^= 0xFF;
            assert_eq!(
                corrupt_blocks(&damaged[..file_size as usize], &blocks).unwrap(),
                vec![3]
            );
            assert!(corrupt_blocks(&data, &blocks).unwrap().is_empty());
        }
    }

    #[test]
    fn recovery_roundtrip_for_a_multi_part_file() {
        let part0 = PARTSIZE;
        let part1 = 5 * EMBLOCKSIZE;
        let file_size = part0 + part1;
        let data: Vec<u8> = (0..file_size as usize).map(|i| (i % 229) as u8).collect();
        let tree = Tree::from_data(&data);
        let master = tree.hash().unwrap();

        // 第二个分片在树里的层级是 2 → 条数 = 1 个兄弟 + 5 个块
        let entries = tree.create_recovery(part0, part1, false).unwrap();
        assert_eq!(entries.len(), 6);
        let payload = encode_recovery(&entries);
        let decoded = decode_recovery(&payload).unwrap();
        assert_eq!(decoded.len(), 6);
        // 兄弟哈希的标识符必须是 part1 在根下的**左**兄弟 → 根(0x0001) 走左枝 = 0x0003
        assert_eq!(decoded[0].identifier, 0x0003);

        let blocks = recover_part_blocks(file_size, part0, part1, master, &decoded).unwrap();
        assert_eq!(blocks.len(), 5);
        let local = &data[part0 as usize..];
        let mut damaged = local.to_vec();
        damaged[4 * EMBLOCKSIZE as usize + 1] ^= 1;
        assert_eq!(corrupt_blocks(&damaged, &blocks).unwrap(), vec![4]);
        assert!(corrupt_blocks(local, &blocks).unwrap().is_empty());

        // 缺一块（只发 6 条里的 5 条）→ 该分片两侧不齐，验证阶段就被拒
        let short = &decoded[..decoded.len() - 1];
        assert_eq!(
            recover_part_blocks(file_size, part0, part1, master, short),
            Err("aich_verify_failed")
        );
        // 根不对 → 验证失败
        assert_eq!(
            recover_part_blocks(file_size, part0, part1, [0; 20], &decoded),
            Err("aich_verify_failed")
        );
        // 篡改一个兄弟哈希 → 验证失败
        let mut tampered = decoded.clone();
        tampered[0].hash[0] ^= 1;
        assert_eq!(
            recover_part_blocks(file_size, part0, part1, master, &tampered),
            Err("aich_verify_failed")
        );
        // 32 位标识符超界 → fail-closed
        let mut out_of_range = decoded.clone();
        out_of_range.push(RecoveryHash {
            identifier: WIDE_IDENTIFIER_MAX + 1,
            wide: true,
            hash: [0; 20],
        });
        assert_eq!(
            recover_part_blocks(file_size, part0, part1, master, &out_of_range),
            Err("aich_identifier_range")
        );
    }

    #[test]
    fn recovery_payload_is_length_strict() {
        let entries = vec![RecoveryHash {
            identifier: 0x0003,
            wide: false,
            hash: [1; 20],
        }];
        let payload = encode_recovery(&entries);
        assert_eq!(payload.len(), 2 + 2 + 20 + 2);
        assert_eq!(decode_recovery(&payload).unwrap(), entries);
        // 尾随字节
        let mut extra = payload.clone();
        extra.push(0);
        assert_eq!(decode_recovery(&extra), Err("aich_trailing"));
        // 截断
        assert_eq!(
            decode_recovery(&payload[..payload.len() - 1]),
            Err("aich_truncated")
        );
        assert_eq!(decode_recovery(&[]), Err("aich_truncated"));
        // 声明条数而不给数据
        assert_eq!(decode_recovery(&[2, 0, 0, 0]), Err("aich_truncated"));
        // 空表也拒绝（对端"成功"但没给任何哈希）
        assert_eq!(
            insert_recovery(&mut Tree::new(100, true), &[]),
            Err("aich_no_hashes")
        );
    }

    /// 布局与 eMule 的写入顺序一致：16 位在前、32 位在后，另一边写 0。
    #[test]
    fn encoded_recovery_layout_matches_emule() {
        let narrow = vec![
            RecoveryHash {
                identifier: 0x0003,
                wide: false,
                hash: [2; 20],
            },
            RecoveryHash {
                identifier: 0x0002,
                wide: false,
                hash: [3; 20],
            },
        ];
        let bytes = encode_recovery(&narrow);
        assert_eq!(&bytes[..2], &2u16.to_le_bytes(), "count1");
        assert_eq!(&bytes[2..4], &0x0003u16.to_le_bytes());
        assert_eq!(&bytes[bytes.len() - 2..], &0u16.to_le_bytes(), "count2=0");

        let wide = vec![RecoveryHash {
            identifier: 0x0000_0007,
            wide: true,
            hash: [4; 20],
        }];
        let bytes = encode_recovery(&wide);
        assert_eq!(&bytes[..2], &0u16.to_le_bytes(), "count1=0");
        assert_eq!(&bytes[2..4], &1u16.to_le_bytes(), "count2=1");
        assert_eq!(&bytes[4..8], &7u32.to_le_bytes());
        assert_eq!(decode_recovery(&bytes).unwrap(), wide);
    }
}
