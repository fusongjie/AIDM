//! 同文件抽样验证（`docs/source-discovery.md` §4.7 的 S1 阶段）。
//!
//! # 抽样只能排除，不能证明
//!
//! 3 段 × 64 KiB 的指纹只回答"这两个候选**明显不同**"；它**不是**文件身份，
//! 因此：
//!
//! - 抽样一致 **不会**把 `L1` 升格成 `L3/L4`；
//! - 抽样不一致的候选可以被淘汰；
//! - 只有一个候选时，抽样没有比较对象，结论只能是"未知"。
//!
//! 指纹计算把 `(offset, len, bytes)` 一起喂进 SHA-256，避免"两段错位但拼接后
//! 恰好相同"这种歧义。

/// 每段抽样字节数。
pub const SAMPLE_BYTES: u64 = 64 * 1024;

/// 小于等于该大小的文件直接整文件比较（3 段抽样已覆盖全文件）。
pub const SMALL_FILE_BYTES: u64 = 3 * SAMPLE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleRange {
    pub offset: u64,
    pub len: u64,
}

/// 抽样计划：小文件整文件；大文件取头、中、尾各 64 KiB。
///
/// `size == 0` 返回空（空文件没有可抽样的字节；是否同一份由长度与其它证据决定）。
pub fn sample_ranges(size: u64) -> Vec<SampleRange> {
    if size == 0 {
        return Vec::new();
    }
    if size <= SMALL_FILE_BYTES {
        return vec![SampleRange {
            offset: 0,
            len: size,
        }];
    }
    let head = SampleRange {
        offset: 0,
        len: SAMPLE_BYTES,
    };
    let middle = SampleRange {
        offset: (size - SAMPLE_BYTES) / 2,
        len: SAMPLE_BYTES,
    };
    let tail = SampleRange {
        offset: size - SAMPLE_BYTES,
        len: SAMPLE_BYTES,
    };
    vec![head, middle, tail]
}

/// 一组抽样结果的指纹。`ranges` 与 `samples` 必须一一对应且长度相等。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleSet {
    pub size: u64,
    pub ranges: Vec<SampleRange>,
    /// 小写 hex；对 `(offset_le, len_le, bytes)` 拼接后取 SHA-256。
    pub digest: String,
}

/// 计算指纹；长度对不上返回 `None`（不猜、不补零）。
pub fn fingerprint(size: u64, ranges: &[SampleRange], samples: &[Vec<u8>]) -> Option<SampleSet> {
    if ranges.len() != samples.len() {
        return None;
    }
    let mut buf =
        Vec::with_capacity(samples.iter().map(|s| s.len()).sum::<usize>() + ranges.len() * 16);
    for (range, bytes) in ranges.iter().zip(samples) {
        if bytes.len() as u64 != range.len {
            return None;
        }
        buf.extend_from_slice(&range.offset.to_le_bytes());
        buf.extend_from_slice(&range.len.to_le_bytes());
        buf.extend_from_slice(bytes);
    }
    Some(SampleSet {
        size,
        ranges: ranges.to_vec(),
        digest: crate::hash::sha256_hex(&buf),
    })
}

/// 多数派结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Majority {
    /// 与最大指纹组一致的候选下标（保持原顺序）。
    pub keep: Vec<usize>,
    /// 与最大指纹组不一致的候选下标。
    pub reject: Vec<usize>,
    /// 最大组不唯一（例如 1 对 1）时为 true：此时只保留第一个，但不声称"已验证"。
    pub uncertain: bool,
}

/// 按指纹取多数派。返回 `None` 表示没有可比较的输入。
///
/// - 1 个样本：`keep=[0], reject=[], uncertain=true`（没有比较对象）；
/// - 2 个相同：`keep=[0,1], uncertain=false`；
/// - 2 个不同：`keep=[0], reject=[1], uncertain=true`（并列时保留先出现的）；
/// - 3 个中 2 个相同：保留那 2 个，淘汰另 1 个。
pub fn majority(sets: &[SampleSet]) -> Option<Majority> {
    if sets.is_empty() {
        return None;
    }
    // 按首次出现顺序统计指纹组，避免 HashMap 迭代顺序引入不确定性。
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        match groups.iter_mut().find(|(digest, _)| *digest == set.digest) {
            Some((_, idx)) => idx.push(i),
            None => groups.push((set.digest.clone(), vec![i])),
        }
    }
    let max = groups.iter().map(|(_, idx)| idx.len()).max().unwrap_or(0);
    let largest: Vec<&(String, Vec<usize>)> =
        groups.iter().filter(|(_, idx)| idx.len() == max).collect();
    let uncertain = largest.len() > 1;
    let keep = largest
        .first()
        .map(|(_, idx)| idx.clone())
        .unwrap_or_default();
    let reject = (0..sets.len()).filter(|i| !keep.contains(i)).collect();
    Some(Majority {
        keep,
        reject,
        uncertain: uncertain || sets.len() == 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_file_is_one_full_range() {
        assert!(sample_ranges(0).is_empty());
        assert_eq!(
            sample_ranges(100),
            vec![SampleRange {
                offset: 0,
                len: 100
            }]
        );
        assert_eq!(
            sample_ranges(SMALL_FILE_BYTES),
            vec![SampleRange {
                offset: 0,
                len: SMALL_FILE_BYTES
            }]
        );
    }

    #[test]
    fn large_file_takes_head_middle_tail_without_overlap() {
        let size = 10 * 1024 * 1024;
        let r = sample_ranges(size);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].offset, 0);
        assert_eq!(r[2].offset + r[2].len, size);
        assert!(r[1].offset >= r[0].offset + r[0].len);
        assert!(r[2].offset >= r[1].offset + r[1].len);
        assert!(r.iter().all(|x| x.len == SAMPLE_BYTES));
    }

    #[test]
    fn fingerprint_is_deterministic_and_binds_offsets() {
        let ranges = sample_ranges(1_000_000);
        let samples: Vec<Vec<u8>> = ranges.iter().map(|r| vec![7u8; r.len as usize]).collect();
        let a = fingerprint(1_000_000, &ranges, &samples).unwrap();
        let b = fingerprint(1_000_000, &ranges, &samples).unwrap();
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.ranges, ranges);

        // 同样的字节放到另一个 offset，指纹必须不同。
        let moved = vec![
            SampleRange {
                offset: 1,
                len: SAMPLE_BYTES,
            },
            ranges[1],
            ranges[2],
        ];
        let c = fingerprint(1_000_000, &moved, &samples).unwrap();
        assert_ne!(a.digest, c.digest);
    }

    #[test]
    fn fingerprint_rejects_length_mismatch() {
        let ranges = sample_ranges(200_000);
        let bad = vec![vec![0u8; 10]; ranges.len()];
        assert!(fingerprint(200_000, &ranges, &bad).is_none());
        assert!(fingerprint(200_000, &ranges, &[]).is_none());
    }

    #[test]
    fn majority_keeps_matching_group_and_rejects_outlier() {
        let ranges = sample_ranges(1_000_000);
        let a = fingerprint(1_000_000, &ranges, &vec![vec![1; 65536]; 3]).unwrap();
        let b = a.clone();
        let c = fingerprint(1_000_000, &ranges, &vec![vec![2; 65536]; 3]).unwrap();
        let m = majority(&[a, b, c]).unwrap();
        assert_eq!(m.keep, vec![0, 1]);
        assert_eq!(m.reject, vec![2]);
        assert!(!m.uncertain);
    }

    #[test]
    fn majority_tie_is_uncertain_and_keeps_first() {
        let ranges = sample_ranges(1_000_000);
        let a = fingerprint(1_000_000, &ranges, &vec![vec![1; 65536]; 3]).unwrap();
        let b = fingerprint(1_000_000, &ranges, &vec![vec![2; 65536]; 3]).unwrap();
        let m = majority(&[a, b]).unwrap();
        assert_eq!(m.keep, vec![0]);
        assert_eq!(m.reject, vec![1]);
        assert!(m.uncertain);
    }

    #[test]
    fn majority_single_is_uncertain() {
        let ranges = sample_ranges(100);
        let a = fingerprint(100, &ranges, &[vec![0; 100]]).unwrap();
        let m = majority(&[a]).unwrap();
        assert_eq!(m.keep, vec![0]);
        assert!(m.reject.is_empty());
        assert!(m.uncertain);
    }

    #[test]
    fn majority_empty_is_none() {
        assert!(majority(&[]).is_none());
    }
}
