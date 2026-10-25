//! 数据目录单实例文件锁：阻止两个引擎进程同时调度同一库。

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// 持有 `engine.lock` 的独占锁；drop 时释放。
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 在 `data_dir/engine.lock` 上尝试独占锁。已被占用则失败。
pub fn try_acquire(data_dir: &Path) -> Result<InstanceLock, String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("create data dir: {e}"))?;
    let path = data_dir.join("engine.lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| format!("open lock: {e}"))?;
    try_lock_exclusive(&file)?;
    Ok(InstanceLock { _file: file, path })
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err("engine_already_running".into())
    }
}

#[cfg(windows)]
fn try_lock_exclusive(file: &File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut ov = unsafe { std::mem::zeroed::<OVERLAPPED>() };
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut ov,
        )
    };
    if ok == 0 {
        Err("engine_already_running".into())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock_exclusive(_file: &File) -> Result<(), String> {
    Err("engine_lock_unsupported".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_fails_until_first_dropped() {
        // 临时目录由 `tempfile::tempdir()` 提供：绝对路径 + Drop 自动清理。
        let tmp = crate::testsupport::tempdir("lock");
        let dir = tmp.path().to_path_buf();
        let first = try_acquire(&dir).expect("first lock");
        assert_eq!(try_acquire(&dir).unwrap_err(), "engine_already_running");
        drop(first);
        let second = try_acquire(&dir).expect("lock after drop");
        drop(second);
    }
}
