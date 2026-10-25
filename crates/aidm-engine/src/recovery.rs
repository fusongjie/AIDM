//! §4 崩溃恢复：以 segments 表 + 磁盘 part 为准回写进度。
//!
//! - 缺失 / 损坏的 part → 该段 pending 重下
//! - 未完成 part：`done_bytes` 与文件实际长度对齐
//! - 全部段 done 且 part 未合并 → 调用方把任务置为 verifying

use std::path::Path;

use aidm_core::model::{self, DownloadRow, SegmentRow};
use rusqlite::Connection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverOutcome {
    /// 没有可恢复的分段
    None,
    /// 仍有未完成段（保持 paused）
    Pending,
    /// 全部分段完成且 part 仍在、最终文件未就绪 → 应进入 verifying
    ReadyToMerge,
}

/// 按磁盘实际情况回写一段。返回该段是否已完成。
pub fn reconcile_segment(conn: &Connection, seg: &SegmentRow) -> rusqlite::Result<bool> {
    let path = Path::new(&seg.part_path);
    let expected = seg.expected_len();
    let meta = std::fs::metadata(path);
    match meta {
        Ok(meta) => {
            let len = meta.len();
            if let Some(exp) = expected {
                if seg.is_done() {
                    if len == exp {
                        return Ok(true);
                    }
                    // 损坏：长度对不上
                    let _ = std::fs::remove_file(path);
                    model::set_segment_state(conn, seg.download_id, seg.idx, 0, "pending")?;
                    return Ok(false);
                }
                if len > exp {
                    let _ = std::fs::remove_file(path);
                    model::set_segment_state(conn, seg.download_id, seg.idx, 0, "pending")?;
                    return Ok(false);
                }
                model::set_segment_state(conn, seg.download_id, seg.idx, len as i64, "pending")?;
                Ok(false)
            } else {
                // 未知总长：以文件长度为准
                model::set_segment_state(conn, seg.download_id, seg.idx, len as i64, "pending")?;
                Ok(false)
            }
        }
        Err(_) => {
            model::set_segment_state(conn, seg.download_id, seg.idx, 0, "pending")?;
            Ok(false)
        }
    }
}

pub fn recover_download(conn: &Connection, row: &DownloadRow) -> rusqlite::Result<RecoverOutcome> {
    // eD2k 多源定位写共享工作文件，文件尾可能先写到，长度不表示覆盖范围。
    // 保留上次落库快照，下次会话按哈希重新验证完整片；不能走 HTTP 合并路径。
    //
    // 注意：eD2k 自动切 HTTP 后 `ed2k_hash` 仍保留用于完成校验，但实际 URL
    // 已经是 HTTP，必须让下面的 fastdl 侧车分支先恢复进度；否则按 eD2k 的
    // `part_path` 规则会把所有分段 done_bytes 清零。
    if aidm_core::ed2k::is_ed2k_link(&row.url_orig) {
        let segs = model::list_segments(conn, row.id)?;
        if segs.is_empty() {
            return Ok(RecoverOutcome::None);
        }
        for seg in &segs {
            if !Path::new(&seg.part_path).is_file() {
                model::set_segment_state(conn, row.id, seg.idx, 0, "pending")?;
            }
        }
        return Ok(RecoverOutcome::Pending);
    }
    // fastdl 任务用 `<save_dir>/.aidm/<id>/fastdl.json` 记录进度，磁盘上没有
    // 「每段一个 part 文件」这回事。用侧车文件回填 segments 表后直接按「未完成」
    // 处理，绝不能按 part 文件长度再对账一次（那只会把进度清零）。
    if crate::fastdl::restore_from_sidecar(conn, Path::new(&row.dir), row.id) {
        return Ok(RecoverOutcome::Pending);
    }
    let segs = model::list_segments(conn, row.id)?;
    if segs.is_empty() {
        return Ok(RecoverOutcome::None);
    }
    let mut all_done = true;
    for seg in &segs {
        if !reconcile_segment(conn, seg)? {
            all_done = false;
        }
    }
    if !all_done {
        return Ok(RecoverOutcome::Pending);
    }
    let multi_parts = segs.len() >= 2
        || segs
            .iter()
            .any(|s| s.part_path.contains("/.aidm/") || s.part_path.contains("\\.aidm\\"));
    if !multi_parts {
        return Ok(RecoverOutcome::Pending);
    }
    let parts_exist = segs.iter().all(|s| Path::new(&s.part_path).is_file());
    if !parts_exist {
        return Ok(RecoverOutcome::Pending);
    }
    let final_path = Path::new(&row.dir).join(&row.file_name);
    let final_ok = match (row.size_total, std::fs::metadata(&final_path)) {
        (Some(total), Ok(meta)) => meta.len() == total.max(0) as u64,
        _ => final_path.is_file(),
    };
    if final_ok {
        Ok(RecoverOutcome::Pending)
    } else {
        Ok(RecoverOutcome::ReadyToMerge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed2k_sparse_file_length_never_becomes_download_progress_or_http_merge() {
        // 临时目录由 `tempfile::tempdir()` 提供：绝对路径 + Drop 自动清理。
        let _tmp = crate::testsupport::tempdir("ed2k-recovery");
        let dir = _tmp.path().to_path_buf();
        let conn = aidm_core::open_db(&dir.join("db.sqlite")).unwrap();
        let id = model::insert_download(
            &conn,
            "ed2k://|file|a.bin|8192|00000000000000000000000000000000|/",
            "a.bin",
            &dir.to_string_lossy(),
            0,
            4,
        )
        .unwrap();
        model::set_ed2k_meta(&conn, id, Some("00000000000000000000000000000000"), None).unwrap();
        let part = dir.join("part0");
        std::fs::File::create(&part).unwrap().set_len(8192).unwrap();
        model::replace_segments(
            &conn,
            id,
            &[aidm_core::segment::ByteSpan {
                start: 0,
                end: 8191,
            }],
            &[part.to_string_lossy().into_owned()],
        )
        .unwrap();
        model::set_segment_progress(&conn, id, 123).unwrap();
        let row = model::get_download(&conn, id).unwrap().unwrap();
        assert_eq!(
            recover_download(&conn, &row).unwrap(),
            RecoverOutcome::Pending
        );
        assert_eq!(model::sum_done_bytes(&conn, id).unwrap(), 123);
        std::fs::remove_file(&part).unwrap();
        recover_download(&conn, &row).unwrap();
        assert_eq!(model::sum_done_bytes(&conn, id).unwrap(), 0);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
