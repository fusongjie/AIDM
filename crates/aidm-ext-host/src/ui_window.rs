//! 唤起桌面版 AIDM：主窗口在就置顶，没在运行就启动再置顶。
//!
//! 唯一入口是扩展的 `show_ui` 请求。启动的可执行文件固定在宿主所在目录，
//! 不接收扩展传来的路径或参数——这条链路不能变成任意程序启动器。
//!
//! Windows 的前台锁：宿主是后台进程，直接 `SetForegroundWindow` 可能被系统拒绝。
//! 这里先附加到当前前台线程，再把窗口抬到 topmost，最后撤销 topmost——既带到
//! 屏幕顶层，又不让它永久压住所有窗口。

use std::path::PathBuf;

/// 主窗口标题（`crates/aidm-ui/tauri.conf.json` 的 `app.windows[0].title`）。
/// 改标题必须同步这里，否则「找到窗口」会退化成「再启动一个实例」。
const MAIN_WINDOW_TITLE: &str = "AIDM 下载管理器";

/// 唤起主窗口。成功返回空，失败返回给扩展的错误码：
/// `ui_not_found` / `launch_failed` / `ui_timeout` / `unsupported`。
pub fn open_or_focus() -> Result<(), &'static str> {
    #[cfg(windows)]
    {
        windows_impl::open_or_focus()
    }
    #[cfg(not(windows))]
    {
        Err("unsupported")
    }
}

/// 可执行文件候选：安装版是 Tauri 生成的 `AIDM.exe`，源码构建是 `aidm-ui.exe`。
fn ui_exe_candidates() -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    let names: &[&str] = if cfg!(windows) {
        &["AIDM.exe", "aidm-ui.exe"]
    } else {
        &["aidm-ui"]
    };
    names
        .iter()
        .map(|name| dir.join(name))
        .filter(|path| path.is_file())
        .collect()
}

/// 映像名是否 AIDM 桌面 UI。用于「进程已在跑、窗口还没建好」时避免再启动一个。
fn is_ui_image(file_name: &str) -> bool {
    let name = file_name.to_ascii_lowercase();
    name == "aidm.exe" || name == "aidm-ui.exe" || name == "aidm-ui"
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        AttachThreadInput, GetCurrentProcessId, GetCurrentThreadId,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, FindWindowW, GetForegroundWindow, GetWindowThreadProcessId,
        SetForegroundWindow, SetWindowPos, ShowWindow, HWND_NOTOPMOST, HWND_TOPMOST, SWP_NOMOVE,
        SWP_NOSIZE, SWP_SHOWWINDOW, SW_RESTORE,
    };

    const POLL_STEP: Duration = Duration::from_millis(100);
    /// 启动/等待窗口的上限。首次启动要初始化 WebView2，留足时间但不无限等。
    const WAIT_WINDOW: Duration = Duration::from_secs(10);

    pub fn open_or_focus() -> Result<(), &'static str> {
        if let Some(hwnd) = find_main_window() {
            focus(hwnd);
            return Ok(());
        }
        // 进程在跑但窗口还没建好（刚启动/正在退出）：只等，不再起一个。
        if ui_process_running() {
            let hwnd = wait_for_window(Instant::now() + WAIT_WINDOW).ok_or("ui_timeout")?;
            focus(hwnd);
            return Ok(());
        }
        let exe = ui_exe_candidates()
            .into_iter()
            .next()
            .ok_or("ui_not_found")?;
        let mut cmd = std::process::Command::new(&exe);
        if let Some(dir) = exe.parent() {
            cmd.current_dir(dir);
        }
        cmd.spawn().map_err(|_| "launch_failed")?;
        let hwnd = wait_for_window(Instant::now() + WAIT_WINDOW).ok_or("ui_timeout")?;
        focus(hwnd);
        Ok(())
    }

    fn find_main_window() -> Option<HWND> {
        let title: Vec<u16> = MAIN_WINDOW_TITLE
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
        if hwnd.is_null() || !window_belongs_to_ui(hwnd) {
            None
        } else {
            Some(hwnd)
        }
    }

    /// 标题是常量，但仍核对窗口所属进程：别的程序也可能占用同名标题。
    fn window_belongs_to_ui(hwnd: HWND) -> bool {
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        pid != 0 && crate::parent::image_name_of(pid).is_some_and(|name| is_ui_image(&name))
    }

    fn wait_for_window(deadline: Instant) -> Option<HWND> {
        loop {
            if let Some(hwnd) = find_main_window() {
                return Some(hwnd);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(POLL_STEP);
        }
    }

    /// 是否有 AIDM UI 进程在运行（无论窗口是否已创建）。
    fn ui_process_running() -> bool {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap.is_null() || snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let me = unsafe { GetCurrentProcessId() };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        let mut found = false;
        let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
        while ok != 0 {
            if entry.th32ProcessID != me {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if is_ui_image(&name) {
                    found = true;
                    break;
                }
            }
            ok = unsafe { Process32NextW(snap, &mut entry) };
        }
        unsafe { CloseHandle(snap) };
        found
    }

    fn focus(hwnd: HWND) {
        unsafe {
            ShowWindow(hwnd, SW_RESTORE);
            let fg = GetForegroundWindow();
            let fg_thread = if fg.is_null() {
                0
            } else {
                GetWindowThreadProcessId(fg, std::ptr::null_mut())
            };
            let me = GetCurrentThreadId();
            // 附加到前台线程：解除「后台进程不许抢前台」的限制。
            let attached =
                fg_thread != 0 && fg_thread != me && AttachThreadInput(me, fg_thread, 1) != 0;
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
            );
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            // 撤销 topmost：窗口已在最前，不需要永久压住其它程序。
            SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            if attached {
                AttachThreadInput(me, fg_thread, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_images_are_recognized() {
        assert!(is_ui_image("AIDM.exe"));
        assert!(is_ui_image("aidm-ui.exe"));
        assert!(is_ui_image("AIDM-UI.EXE"));
        assert!(!is_ui_image("aidm-engine.exe"));
        assert!(!is_ui_image("aidm-ext-host.exe"));
        assert!(!is_ui_image("chrome.exe"));
    }

    #[test]
    fn window_title_matches_tauri_config() {
        // 标题漂移会让「置顶已有窗口」退化成「每次点击都尝试启动新实例」。
        assert_eq!(MAIN_WINDOW_TITLE, "AIDM 下载管理器");
    }
}
