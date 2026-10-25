//! 测试临时目录工厂（仅 `#[cfg(test)]`）。
//!
//! 与 `aidm-engine` 的同名模块保持同一契约：
//! 1. 所有测试目录都收在 `%TEMP%\aidm-tests\` 这一个受控根下；
//! 2. 名字带 `aidm-<tag>-` 前缀 + 随机后缀，可辨识、并行安全；
//! 3. 每次建目录前清理同根下 1 小时前的 `aidm-*` 旧目录（sqlite 句柄可能拖住 Drop）。
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
