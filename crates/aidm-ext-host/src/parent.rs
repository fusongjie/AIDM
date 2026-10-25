//! 父进程校验（开发文档 §6）。
//!
//! Windows：Toolhelp 快照取父 PID，再用 `QueryFullProcessImageName` 核对映像
//! 文件名是否为 `chrome.exe` / `msedge.exe`。
//!
//! 直接父进程**不一定**是浏览器：Chrome 在 Windows 上是否直接启动可执行宿主由
//! 策略 `NativeHostsExecutablesLaunchDirectly` 决定——停用该策略时固定经
//! `cmd.exe` 中转，未设置时由浏览器自行选择（Chrome 155 实测走 `cmd.exe`）。
//! 因此校验沿父链回溯，但只允许 `cmd.exe` 出现在中间：其它映像一律视为非浏览器。
//!
//! 本里程碑**不能**核实的内容见模块底部与 PR 说明。

/// 调试逃生：非浏览器父进程仍放行（仅开发；生产浏览器拉起时不要设）。
pub const SKIP_PARENT_ENV: &str = "AIDM_HOST_ALLOW_NON_BROWSER";

/// 父链上最多回溯的层数（宿主 → cmd.exe → 浏览器 = 2 层，留一层余量）。
const PARENT_CHAIN_DEPTH: usize = 3;

pub fn skip_parent_check() -> bool {
    matches!(
        std::env::var(SKIP_PARENT_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// 父链上是否出现 Chrome / Edge。非 Windows 返回 `None`（未实现，由调用方决定）。
pub fn parent_is_browser() -> Option<bool> {
    #[cfg(windows)]
    {
        Some(windows_parent_chain_has_browser())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

pub fn parent_allowed() -> bool {
    if skip_parent_check() {
        return true;
    }
    match parent_is_browser() {
        Some(ok) => ok,
        // 非 Windows：CI / 开发机不拦；生产目标是 Windows。
        None => true,
    }
}

/// 父进程链诊断：`(直接父 PID, 从直接父进程起的映像名链)`。
///
/// 只用于写诊断日志，**不参与判定**。之所以要整条链：真实浏览器拉起宿主时
/// 直接父进程可能是 `cmd.exe`，也可能已经退出——只记一层看不出发生过什么。
pub fn parent_diag() -> (Option<u32>, Vec<String>) {
    #[cfg(windows)]
    {
        let first = parent_pid();
        let mut chain = Vec::new();
        let mut cur = first;
        for _ in 0..PARENT_CHAIN_DEPTH {
            let Some(pid) = cur else { break };
            match image_name_of(pid) {
                Some(name) => chain.push(name),
                None => {
                    chain.push(format!("<pid {pid}: 已退出或无法读取>"));
                    break;
                }
            }
            cur = parent_pid_of(pid);
        }
        (first, chain)
    }
    #[cfg(not(windows))]
    {
        (None, Vec::new())
    }
}

#[cfg(windows)]
fn windows_parent_chain_has_browser() -> bool {
    let mut pid = match parent_pid() {
        Some(p) => p,
        None => return false,
    };
    for _ in 0..PARENT_CHAIN_DEPTH {
        let Some(name) = image_name_of(pid) else {
            return false;
        };
        if is_browser_image(&name) {
            return true;
        }
        // 链上出现非浏览器映像时，只有命令解释器可以继续向上追溯；
        // 别的进程都说明这次调用不是浏览器发起的。
        if !is_shell_image(&name) {
            return false;
        }
        let Some(next) = parent_pid_of(pid) else {
            return false;
        };
        pid = next;
    }
    false
}

pub fn is_browser_image(file_name: &str) -> bool {
    let n = file_name.to_ascii_lowercase();
    n == "chrome.exe" || n == "msedge.exe"
}

/// 允许出现在父链中间的中转进程。
///
/// 只认 Windows 命令解释器：Chrome 用它转发可执行宿主，这是浏览器自身的行为；
/// 恶意进程即使也经 `cmd.exe` 启动宿主，再往上一层仍是它自己，链上找不到浏览器
/// 映像，因此不会被放行。
pub fn is_shell_image(file_name: &str) -> bool {
    file_name.eq_ignore_ascii_case("cmd.exe")
}

/// 本进程的父 PID。
#[cfg(windows)]
fn parent_pid() -> Option<u32> {
    parent_pid_of(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() })
}

/// 任意 PID 的父 PID（Toolhelp 快照）。父进程已退出时仍返回那个已消失的 PID。
#[cfg(windows)]
fn parent_pid_of(pid: u32) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snap: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() || snap == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut parent = 0u32;
    let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
    while ok != 0 {
        if entry.th32ProcessID == pid {
            parent = entry.th32ParentProcessID;
            break;
        }
        ok = unsafe { Process32NextW(snap, &mut entry) };
    }
    unsafe { CloseHandle(snap) };
    if parent == 0 {
        None
    } else {
        Some(parent)
    }
}

/// 某个 PID 的映像文件名；进程已退出或打不开时返回 `None`。
#[cfg(windows)]
pub(crate) fn image_name_of(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, MAX_PATH};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut buf = [0u16; MAX_PATH as usize + 1];
    let mut len = buf.len() as u32;
    let qok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(handle) };
    if qok == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buf[..len as usize]);
    std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_image_names() {
        assert!(is_browser_image("chrome.exe"));
        assert!(is_browser_image("MSEdge.EXE"));
        assert!(!is_browser_image("aidm-ext-host.exe"));
        assert!(!is_browser_image("cmd.exe"));
        assert!(!is_browser_image("brave.exe"));
    }

    #[test]
    fn only_cmd_may_sit_in_the_middle_of_the_parent_chain() {
        // Chrome 经 cmd.exe 转发可执行宿主：这是唯一允许出现在链中间的映像。
        assert!(is_shell_image("cmd.exe"));
        assert!(is_shell_image("CMD.EXE"));
        assert!(!is_shell_image("powershell.exe"));
        assert!(!is_shell_image("explorer.exe"));
        assert!(!is_shell_image("aidm-ext-host.exe"));
        // 中转映像绝不能被当成浏览器，否则校验形同虚设。
        assert!(!is_browser_image("cmd.exe"));
    }
}
