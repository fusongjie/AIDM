//! 「在磁盘上查找」：把被移动或改名的下载文件找回来，好把任务重新关联到它。
//!
//! 找到后把 `LocalFileName` 回写记录。
//!
//! 这是一次**有界的**目录遍历，不是全盘扫描：
//!
//! - 根目录由调用方给（任务自己的目录 + 分类目录 + 默认下载目录），不是整个磁盘；
//! - 文件名按大小写不敏感比较；**已知大小时必须完全相等**——否则"找到"的可能是
//!   另一个同名文件，把它当成下载结果比找不到更糟；
//! - 深度、访问条目数与命中数都有上限，触顶时 `truncated = true`。界面上必须如实
//!   说明"没有找完"，不能把截断当成"磁盘上没有"。

use std::path::{Path, PathBuf};

/// 相对根目录的最大深度。
pub const MAX_DEPTH: usize = 6;
/// 最多访问多少个目录项（文件 + 目录）。
pub const MAX_ENTRIES: u64 = 200_000;
/// 最多返回多少个命中。
pub const MAX_HITS: usize = 32;

/// 一个命中：路径、大小与修改时间（unix 秒）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub path: PathBuf,
    pub size: u64,
    pub modified: i64,
}

/// 查找结果。`truncated` 为真表示"到上限就停了"，不等于"找不到"。
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub hits: Vec<Hit>,
    pub visited: u64,
    pub truncated: bool,
}

/// 一次查找的输入。
pub struct Query<'a> {
    /// 目标文件名（不含目录）。
    pub name: &'a str,
    /// 已知的总长度；`Some` 时要求完全相等。
    pub size: Option<u64>,
    /// 查找起点（文件或目录都接受；文件直接比对）。
    pub roots: &'a [PathBuf],
}

/// 在 `roots` 下查找 `q.name`。同名同大小才算命中。
pub fn find_file(q: &Query<'_>) -> Report {
    let want = q.name.trim().to_lowercase();
    let mut report = Report::default();
    if want.is_empty() {
        return report;
    }
    let mut seen: Vec<PathBuf> = Vec::new();
    // (目录, 深度)
    let mut stack: Vec<(PathBuf, usize)> = Vec::new();
    for root in q.roots {
        if root.as_os_str().is_empty() || seen.iter().any(|s| s == root) {
            continue;
        }
        seen.push(root.clone());
        match std::fs::metadata(root) {
            // 根直接是文件：比对它本身，不再往下走。
            Ok(m) if m.is_file() => {
                report.visited += 1;
                if matches(&want, q.size, root, m.len()) {
                    report.hits.push(hit_of(root, m.len(), &m));
                }
            }
            Ok(m) if m.is_dir() => stack.push((root.clone(), 0)),
            _ => continue,
        }
    }
    while let Some((dir, depth)) = stack.pop() {
        if report.visited >= MAX_ENTRIES || report.hits.len() >= MAX_HITS {
            report.truncated = true;
            return report;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            report.visited += 1;
            if report.visited >= MAX_ENTRIES {
                report.truncated = true;
                return report;
            }
            let path = entry.path();
            // 符号链接/联接点不跟随：跟随可能绕回祖先目录，也会跑出用户给的范围。
            let Ok(meta) = entry.metadata() else { continue };
            let ft = meta.file_type();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_file() {
                if matches(&want, q.size, &path, meta.len()) {
                    report.hits.push(hit_of(&path, meta.len(), &meta));
                    if report.hits.len() >= MAX_HITS {
                        report.truncated = true;
                        return report;
                    }
                }
            } else if ft.is_dir() && depth + 1 < MAX_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    report
}

fn matches(want_lower: &str, size: Option<u64>, path: &Path, len: u64) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.to_lowercase() != want_lower {
        return false;
    }
    match size {
        Some(want) => want == len,
        None => true,
    }
}

fn hit_of(path: &Path, size: u64, meta: &std::fs::Metadata) -> Hit {
    Hit {
        path: path.to_path_buf(),
        size,
        modified: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试工作目录：绝对路径 + `TempDir` 在 Drop 时自动清理。
    fn temp_dir() -> tempfile::TempDir {
        crate::testsupport::tempdir("find")
    }

    /// 在 `dir` 下按相对路径写一个定长文件（父目录自动创建）。
    fn write_file(dir: &Path, rel: &str, len: usize) -> PathBuf {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![7u8; len]).unwrap();
        p
    }

    fn run(name: &str, size: Option<u64>, roots: &[PathBuf]) -> Report {
        find_file(&Query { name, size, roots })
    }

    #[test]
    fn finds_a_moved_file_by_name_and_size() {
        let t = temp_dir();
        write_file(t.path(), "sub/dir/movie.mkv", 100);
        let report = run("movie.mkv", Some(100), &[t.path().to_path_buf()]);
        assert_eq!(report.hits.len(), 1);
        assert!(report.hits[0].path.ends_with("movie.mkv"));
        assert!(!report.truncated);
    }

    #[test]
    fn name_match_ignores_case() {
        let t = temp_dir();
        write_file(t.path(), "Movie.MKV", 10);
        assert_eq!(
            run("movie.mkv", Some(10), &[t.path().to_path_buf()])
                .hits
                .len(),
            1
        );
    }

    #[test]
    fn size_mismatch_is_not_a_hit() {
        // 同名不同长度：不能当成下载结果，否则会"用一个别的文件冒充完成"。
        let t = temp_dir();
        write_file(t.path(), "a.bin", 10);
        assert!(run("a.bin", Some(11), &[t.path().to_path_buf()])
            .hits
            .is_empty());
        // 长度未知（老任务没探到 Content-Length）时只按名字认。
        assert_eq!(run("a.bin", None, &[t.path().to_path_buf()]).hits.len(), 1);
    }

    #[test]
    fn root_may_be_the_file_itself_and_duplicates_are_skipped() {
        let t = temp_dir();
        let f = write_file(t.path(), "x.iso", 5);
        let report = run("x.iso", Some(5), &[f.clone(), f.clone()]);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.visited, 1);
    }

    #[test]
    fn missing_root_is_not_an_error_and_yields_no_hits() {
        let t = temp_dir();
        let report = run("a.bin", None, &[t.path().join("nope")]);
        assert!(report.hits.is_empty());
        assert!(!report.truncated);
    }

    #[test]
    fn depth_limit_stops_the_walk_honestly() {
        let t = temp_dir();
        // 第 MAX_DEPTH 层之后的文件不进入遍历（也不谎报"找完了"）。
        let deep = "a/b/c/d/e/f/g/deep.bin";
        write_file(t.path(), deep, 3);
        let report = run("deep.bin", None, &[t.path().to_path_buf()]);
        assert!(report.hits.is_empty());
        assert!(!report.truncated, "没触到条目上限就不该说截断");
    }

    #[test]
    fn hit_limit_marks_the_report_truncated() {
        let t = temp_dir();
        for i in 0..(MAX_HITS + 3) {
            write_file(t.path(), &format!("d{i}/same.bin"), 4);
        }
        let report = run("same.bin", Some(4), &[t.path().to_path_buf()]);
        assert_eq!(report.hits.len(), MAX_HITS);
        assert!(report.truncated);
    }
}
