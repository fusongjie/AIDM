//! BitTorrent 逐文件选择：索引集合的解析/编码与校验（纯函数，便于单测）。
//!
//! 存储形态是 `downloads.bt_files` 里的**逗号分隔索引**（升序、去重）：
//! `""` 或 `NULL` = 全选（默认），`"0,2,5"` = 只下第 0/2/5 个文件。
//!
//! 为什么不用 JSON：这是给用户看也能手改的一行短文本，逗号分隔更直白；
//! 越界/重复/非数字一律在解析阶段被过滤掉（fail-closed 到"忽略该条"，
//! 而不是让整个任务因为一个坏字符失败）。

/// 索引上限：单种子文件数远小于这个数，用它挡住畸形输入带来的巨量内存。
pub const MAX_FILES: usize = 100_000;
/// 存储文本长度上限（`MAX_FILES` 个 6 位索引 + 逗号）。
pub const MAX_TEXT: usize = 800_000;

/// 解析逗号分隔索引：忽略空项、非数字、越界与重复，结果升序。
pub fn parse(raw: &str) -> Vec<usize> {
    if raw.len() > MAX_TEXT {
        return Vec::new();
    }
    let mut out: Vec<usize> = raw
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|i| *i < MAX_FILES)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// 编码成存储文本（升序去重）；空集合编码为 `""`（= 全选）。
pub fn encode(indices: &[usize]) -> String {
    let mut sorted: Vec<usize> = indices.iter().copied().filter(|i| *i < MAX_FILES).collect();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// 把用户给的选择按"该种子实际有几个文件"收敛：
/// 全部越界 → 视为全选（不能让用户"选中 0 个文件"导致任务永远不开始）。
pub fn resolve(selection: &[usize], file_count: usize) -> Vec<usize> {
    let mut out: Vec<usize> = selection
        .iter()
        .copied()
        .filter(|i| *i < file_count)
        .collect();
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        (0..file_count).collect()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_lenient_but_bounded() {
        assert_eq!(parse(""), Vec::<usize>::new());
        assert_eq!(parse("2,0,2"), vec![0, 2]);
        assert_eq!(parse(" 1 , x ,3, 999999999999999999999"), vec![1, 3]);
        assert_eq!(parse("0,-1,1"), vec![0, 1], "负号解析失败被忽略");
        assert_eq!(parse("100001"), Vec::<usize>::new(), "超过 MAX_FILES 忽略");
        assert_eq!(
            parse(&"1,".repeat(MAX_TEXT / 2 + 10)),
            Vec::<usize>::new(),
            "超长文本整体拒绝"
        );
    }

    #[test]
    fn encode_roundtrips_and_is_canonical() {
        assert_eq!(encode(&[3, 1, 3, 0]), "0,1,3");
        assert_eq!(encode(&[]), "");
        assert_eq!(parse(&encode(&[5, 2])), vec![2, 5]);
    }

    #[test]
    fn resolve_drops_out_of_range_and_never_yields_empty() {
        assert_eq!(resolve(&[0, 2, 9], 3), vec![0, 2]);
        assert_eq!(resolve(&[9], 3), vec![0, 1, 2], "全越界 = 全选");
        assert_eq!(resolve(&[], 2), vec![0, 1]);
        assert_eq!(resolve(&[1, 1], 2), vec![1]);
        assert_eq!(resolve(&[], 0), Vec::<usize>::new(), "零文件种子保持空");
    }
}
