//! 集成测试共用的临时目录工厂（与 `src/testsupport.rs` 同一契约）。
//!
//! 目录落在 `%TEMP%\aidm-tests\aidm-<tag>-XXXXXX`：可辨识、并行安全。建目录前顺手
//! 清理同根下 1 小时前的旧目录 —— Windows 上 worker 线程可能比用例活得久，
//! `TempDir::drop` 的一次删除会失败，这里保证 `%TEMP%` 不会无限堆积。
//!
//! 每个测试二进制各自编译一份，`Once` 的清扫因此每个进程只跑一次。

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};

static SWEEP: Once = Once::new();
static PROCESS_START: OnceLock<std::time::SystemTime> = OnceLock::new();

/// 测试根目录：`%TEMP%\aidm-tests`。
pub fn root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| std::env::temp_dir().join("aidm-tests"))
        .as_path()
}

/// 清理同根下 10 分钟前的旧测试目录（best effort）。
///
/// 为什么是这个阈值：`DownloadManager` 的 worker 线程活到进程退出，`TempDir::drop`
/// 的删除必然失败，残留只能等句柄释放后（进程退出）才删得掉 —— 所以由**后续**的测试
/// 运行来清。10 分钟既保证同轮并行的测试进程（启动差以秒计）绝不会被误删，又能在
/// 跨会话/CI 之间收敛。急着手动清：`Remove-Item $env:TEMP\aidm-tests -Recurse -Force`。
fn sweep_stale(root: &Path, start: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let is_ours = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("aidm-"));
        if !is_ours {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| start.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > 600);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// 建一个用例专属临时目录：`%TEMP%\aidm-tests\aidm-<tag>-XXXXXX`。
///
/// 返回的 [`tempfile::TempDir`] 必须由调用者持有到用例结束。
pub fn tempdir(tag: &str) -> tempfile::TempDir {
    let root = root();
    let _ = std::fs::create_dir_all(root);
    let start = *PROCESS_START.get_or_init(std::time::SystemTime::now);
    SWEEP.call_once(|| sweep_stale(root, start));
    tempfile::Builder::new()
        .prefix(&format!("aidm-{tag}-"))
        .tempdir_in(root)
        .expect("创建测试临时目录失败")
}
