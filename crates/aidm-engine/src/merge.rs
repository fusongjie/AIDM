//! 分段流式合并 + Content-Length / SHA256 校验（§3.2 / §4）。

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aidm_core::model::SegmentRow;
use ring::digest::{Context, SHA256};

pub struct MergeOutcome {
    pub bytes: u64,
    pub sha256: String,
}

/// 按 idx 顺序把 part 流式复制到最终路径，同时计算 SHA256。
pub fn merge_parts(
    segments: &[SegmentRow],
    final_path: &Path,
    expected: Option<u64>,
) -> Result<MergeOutcome, String> {
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    let tmp = tmp_path(final_path);
    let mut out = File::create(&tmp).map_err(|e| format!("create merge tmp: {e}"))?;
    let mut hasher = Context::new(&SHA256);
    let mut written = 0u64;

    for seg in segments {
        let mut part =
            File::open(&seg.part_path).map_err(|e| format!("open part idx={}: {e}", seg.idx))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = part.read(&mut buf).map_err(|e| format!("read part: {e}"))?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])
                .map_err(|e| format!("write merge: {e}"))?;
            hasher.update(&buf[..n]);
            written += n as u64;
        }
    }
    out.flush().map_err(|e| format!("flush merge: {e}"))?;
    drop(out);

    if let Some(exp) = expected {
        if written != exp {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("size_mismatch {written}/{exp}"));
        }
    }

    let sha256 = hex_lower(hasher.finish().as_ref());
    if let Err(e) = std::fs::rename(&tmp, final_path) {
        std::fs::copy(&tmp, final_path).map_err(|e2| format!("rename merge: {e}; copy: {e2}"))?;
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(MergeOutcome {
        bytes: written,
        sha256,
    })
}

fn tmp_path(final_path: &Path) -> PathBuf {
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(".aidm.merge");
    final_path.with_file_name(name)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 删除 `<save_dir>/.aidm/<task_id>/`（成功合并或取消时调用）。
pub fn remove_part_dir(save_dir: &Path, task_id: i64) {
    let dir = aidm_core::segment::part_dir(save_dir, task_id);
    if dir.exists() {
        // Windows 上文件句柄释放有延迟，remove_dir_all 可能短暂失败；
        // 早先直接 let _ = 会静默留下 part 垃圾（实测并行满载时集成用例会因此抖动）。
        // 这里退避重试；仍失败则保留目录，等下次任务收尾再清（不阻塞完成）。
        for attempt in 0u32..6 {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => break,
                Err(_) if attempt < 5 => std::thread::sleep(std::time::Duration::from_millis(
                    20 * u64::from(attempt + 1),
                )),
                Err(_) => break,
            }
        }
    }
    let parent = save_dir.join(".aidm");
    if parent.is_dir() {
        if let Ok(mut rd) = std::fs::read_dir(&parent) {
            if rd.next().is_none() {
                let _ = std::fs::remove_dir(&parent);
            }
        }
    }
}

/// 取消/删除：去掉未完成最终文件与全部 part。
pub fn cleanup_task_files(save_dir: &Path, file_name: &str, task_id: i64, keep_final: bool) {
    if !keep_final {
        let _ = std::fs::remove_file(save_dir.join(file_name));
        let mut name = std::ffi::OsString::from(file_name);
        name.push(".aidm.merge");
        let _ = std::fs::remove_file(save_dir.join(name));
    }
    remove_part_dir(save_dir, task_id);
}
