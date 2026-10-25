//! 测试临时目录工厂（仅 `#[cfg(test)]`）。
//!
//! 目标：
//! 1. 所有测试目录都收在 `%TEMP%\aidm-tests\` 这一个受控根下，不再散落在 `%TEMP%` 根；
//! 2. 名字带 `aidm-<tag>-` 前缀 + 随机后缀：可辨识、并行安全、可收敛清理。
//!
//! Windows 上 `DownloadManager` 的 worker 线程可能比用例活得久，`TempDir::drop` 的
//! 一次删除会失败（句柄未释放）。所以每次建目录前顺手清理同根下 1 小时前的旧目录；
//! 清扫范围仅限 `aidm-tests` 根内的 `aidm-*`，不会误删别人的临时文件。
//!
//! 不用 `CARGO_TARGET_TMPDIR`：它只对集成测试/基准定义，lib 单测拿不到。

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
/// `tag` 用来从目录名看出是哪个用例/模块；返回的 [`tempfile::TempDir`] 必须由
/// 调用者持有到用例结束（Drop 时自动尝试删除）。
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
