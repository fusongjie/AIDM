//! 剪贴板链接嗅探。
//!
//! 三层策略在 `aidm_core::clipboard_policy`（识别 / 判定 / 提示），这里只负责平台侧：
//! 读剪贴板、在**独立线程**里查"是否已有同地址任务"、按决策结果通知界面。
//!
//! 平台侧用 `GetClipboardSequenceNumber` 轮询来发现文本变化（不挂剪贴板查看链），
//! 比链式回调更省事；判定规则统一在 core 模块（见 `aidm_core::clipboard_policy`），
//! 这里不重复一套协议头判断。

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Mutex,
};
use std::time::{Duration, Instant};

use aidm_core::clipboard_policy::{
    self as cp, ClipboardPolicy, Judgement, PromptDecider, PromptDecision,
};
use tauri::{Emitter, Manager};

/// 剪贴板监视总开关（`browser.monitor_clipboard`）。
static ENABLED: AtomicBool = AtomicBool::new(false);
/// 当前策略（扩展名表由设置注入；其余为 AIDM 默认值）。
static POLICY: Mutex<Option<ClipboardPolicy>> = Mutex::new(None);
/// 发给策略线程的消息通道（命令侧只做 send，不碰判定状态）。
static SENDER: Mutex<Option<mpsc::Sender<Msg>>> = Mutex::new(None);

const POLL_INTERVAL: Duration = Duration::from_millis(500);

enum Msg {
    /// 一次剪贴板变化里"够格进入提示决策"的候选。
    Candidates(Vec<Judgement>),
    /// 用户在候选框里放弃了这批地址 → 进入抑制窗口。
    Dismissed(Vec<String>),
}

fn current_policy() -> ClipboardPolicy {
    POLICY
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(ClipboardPolicy::default)
}

/// 由界面在读到 / 保存设置后调用：`browser.monitor_clipboard` 与 `browser.auto_catch_exts`。
#[tauri::command]
pub fn set_clipboard_watch(enabled: bool, exts: String) {
    {
        let mut guard = POLICY.lock().unwrap();
        let p = guard.get_or_insert_with(ClipboardPolicy::default);
        p.set_watched_exts(&exts);
    }
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// 界面的候选框被取消时调用：同一批地址在抑制窗口内不再弹提示。
#[tauri::command]
pub fn clipboard_dismissed(urls: Vec<String>) {
    if urls.is_empty() {
        return;
    }
    let guard = SENDER.lock().unwrap();
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(Msg::Dismissed(urls));
    }
}

/// 轮询剪贴板序号；启动时已在剪贴板里的内容、以及 AIDM 自己窗口在前台时的复制都不处理。
pub fn spawn_watcher(app: tauri::AppHandle) {
    let (tx, rx) = mpsc::channel::<Msg>();
    *SENDER.lock().unwrap() = Some(tx.clone());

    // 策略线程：查"已有任务"、做防抖/去重/抑制，最后才通知界面。
    // 与剪贴板监听解耦，所以引擎 IPC 再慢也不会卡住监听或 UI。
    let policy_app = app.clone();
    let _ = std::thread::Builder::new()
        .name("aidm-clipboard-policy".into())
        .spawn(move || {
            let mut decider = PromptDecider::new(current_policy());
            while let Ok(msg) = rx.recv() {
                match msg {
                    Msg::Dismissed(urls) => {
                        log::info!("clipboard dismissed by user: {} link(s)", urls.len());
                        decider.dismiss(&urls, Instant::now());
                    }
                    Msg::Candidates(judged) => {
                        // 设置可能刚被改过：每次都取一次最新扩展名表。
                        decider.policy_mut().watched_exts = current_policy().watched_exts;
                        // 不按“任务已存在”直接抑制：重复链接也要能再次提示，
                        // 用户确认后可创建一个重命名的新任务重新下载。
                        match decider.decide(judged, &[], Instant::now()) {
                            PromptDecision::Show { links, reason } => {
                                log::info!(
                                    "clipboard prompt: {} link(s), reason={reason}",
                                    links.len()
                                );
                                for l in &links {
                                    log::debug!("clipboard link {}", cp::redacted(l));
                                }
                                if let Some(w) = policy_app.get_webview_window("main") {
                                    let _ = w.show();
                                    let _ = w.unminimize();
                                    let _ = w.set_focus();
                                }
                                let _ = policy_app.emit("clipboard-links", links);
                            }
                            PromptDecision::Suppress { reason } => {
                                log::info!("clipboard ignored: reason={reason}");
                            }
                        }
                    }
                }
            }
        });

    let _ = std::thread::Builder::new()
        .name("aidm-clipboard".into())
        .spawn(move || {
            let mut seen = win::sequence();
            let mut pending_text: Option<String> = None;
            let mut last_text: Option<(String, Instant)> = None;
            loop {
                std::thread::sleep(POLL_INTERVAL);
                let now = win::sequence();
                if now != seen {
                    seen = now;
                    // 先保存变化：即使此刻 AIDM 在前台，等窗口失焦后仍能处理，
                    // 不会因为一次跳过就永久丢掉这次剪贴板刷新。
                    if ENABLED.load(Ordering::Relaxed) {
                        pending_text = win::read_text();
                    }
                }
                if !ENABLED.load(Ordering::Relaxed) || win::own_window_in_front() {
                    continue;
                }
                let Some(text) = pending_text.take() else {
                    continue;
                };
                // 有的程序一次复制会写两遍剪贴板；同一文本短时间内只处理一次。
                let policy = current_policy();
                if last_text
                    .as_ref()
                    .is_some_and(|(t, at)| *t == text && at.elapsed() < policy.same_text_cooldown)
                {
                    continue;
                }
                last_text = Some((text.clone(), Instant::now()));

                let judged: Vec<Judgement> = cp::extract(&text, &policy)
                    .iter()
                    .map(|c| cp::judge(c, &policy))
                    .collect();
                let promptable: Vec<Judgement> = judged
                    .into_iter()
                    .filter(|j| j.verdict.promptable())
                    .collect();
                if promptable.is_empty() {
                    continue;
                }
                for j in &promptable {
                    log::debug!(
                        "clipboard candidate {} verdict={:?} score={} reasons={:?}",
                        cp::redacted(&j.url),
                        j.verdict,
                        j.score,
                        j.reasons
                    );
                }
                if tx.send(Msg::Candidates(promptable)).is_err() {
                    break;
                }
            }
        });
}

/// 兼容包装：文本里值得提示的地址（界面单测与诊断用）。
pub fn sniff_links(text: &str, exts: &[String]) -> Vec<String> {
    let mut policy = ClipboardPolicy::default();
    policy.watched_exts = exts.to_vec();
    cp::extract(text, &policy)
        .iter()
        .map(|c| cp::judge(c, &policy))
        .filter(|j| j.verdict.promptable())
        .map(|j| j.url)
        .collect()
}

fn ext_list(raw: &str) -> Vec<String> {
    ClipboardPolicy::parse_exts(raw)
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    const CF_UNICODETEXT: u32 = 13;
    /// 超长文本不会是用户想下载的链接列表，也避免一次复制大文件内容时卡顿。
    const MAX_CHARS: usize = 64 * 1024;

    #[link(name = "user32")]
    extern "system" {
        fn GetClipboardSequenceNumber() -> u32;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn OpenClipboard(owner: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(format: u32) -> *mut c_void;
        fn GetForegroundWindow() -> *mut c_void;
        fn GetWindowThreadProcessId(hwnd: *mut c_void, pid: *mut u32) -> u32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalLock(mem: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(mem: *mut c_void) -> i32;
        fn GlobalSize(mem: *mut c_void) -> usize;
    }

    pub fn sequence() -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }

    pub fn own_window_in_front() -> bool {
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(GetForegroundWindow(), &mut pid) };
        pid == std::process::id()
    }

    pub fn read_text() -> Option<String> {
        unsafe {
            if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
                return None;
            }
            // 别的程序正占着剪贴板时稍后重试一次即可，读不到就放弃这次变化。
            let mut opened = false;
            for _ in 0..5 {
                if OpenClipboard(std::ptr::null_mut()) != 0 {
                    opened = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if !opened {
                return None;
            }
            let mut out = None;
            let handle = GetClipboardData(CF_UNICODETEXT);
            if !handle.is_null() {
                let ptr = GlobalLock(handle) as *const u16;
                if !ptr.is_null() {
                    let cap = (GlobalSize(handle) / 2).min(MAX_CHARS + 1);
                    let units = std::slice::from_raw_parts(ptr, cap);
                    let len = units.iter().position(|&u| u == 0).unwrap_or(cap);
                    if len <= MAX_CHARS {
                        out = Some(String::from_utf16_lossy(&units[..len]));
                    }
                    GlobalUnlock(handle);
                }
            }
            CloseClipboard();
            out
        }
    }
}

#[cfg(not(windows))]
mod win {
    pub fn sequence() -> u32 {
        0
    }
    pub fn own_window_in_front() -> bool {
        true
    }
    pub fn read_text() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exts() -> Vec<String> {
        ext_list("iso zip exe r0*")
    }

    #[test]
    fn single_ed2k_is_cut_at_its_terminator() {
        let text = "看这个 ed2k://|file|a.iso|4478906368|E7C526499308841A4A6D116C857DB669|/ 很快";
        assert_eq!(
            sniff_links(text, &exts()),
            ["ed2k://|file|a.iso|4478906368|E7C526499308841A4A6D116C857DB669|/"]
        );
    }

    #[test]
    fn magnet_keeps_trackers_and_drops_trailing_text() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        let text = format!("magnet:?xt=urn:btih:{hash}&tr=http://t.example/announce");
        assert_eq!(sniff_links(&text, &exts()), std::slice::from_ref(&text));
        let glued = format!("magnet:?xt=urn:btih:{hash}复制自网页");
        assert_eq!(
            sniff_links(&glued, &exts()),
            [format!("magnet:?xt=urn:btih:{hash}")]
        );
    }

    #[test]
    fn plain_links_need_a_watched_extension() {
        assert_eq!(
            sniff_links("https://cdn.example/a/b.iso?sig=1", &exts()),
            ["https://cdn.example/a/b.iso?sig=1"]
        );
        assert!(sniff_links("https://example.com/article.html", &exts()).is_empty());
        assert_eq!(sniff_links("http://x/p.r01", &exts()), ["http://x/p.r01"]);
        assert_eq!(
            sniff_links("http://x/seed.torrent", &exts()),
            ["http://x/seed.torrent"]
        );
        assert!(sniff_links("http://x/list(*).zip", &exts()).is_empty());
        assert!(sniff_links("没有链接的普通文字", &exts()).is_empty());
    }

    #[test]
    fn multiple_links_are_split_trimmed_and_deduplicated() {
        let text = "1. http://a.example/x.zip 下载\n2.https://b.example/y.exe,备用\nhttp://a.example/x.zip";
        assert_eq!(
            sniff_links(text, &exts()),
            ["http://a.example/x.zip", "https://b.example/y.exe"]
        );
    }

    #[test]
    fn delimited_links_are_judged_by_their_decoded_target() {
        let encode = |s: &str| {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in s.as_bytes().chunks(3) {
                let n = chunk
                    .iter()
                    .enumerate()
                    .fold(0u32, |a, (i, &v)| a | (u32::from(v) << (16 - 8 * i)));
                for i in 0..4 {
                    let c = if i <= chunk.len() {
                        T[((n >> (18 - 6 * i)) & 63) as usize]
                    } else {
                        b'='
                    };
                    out.push(c as char);
                }
            }
            out
        };
        let iso = format!("thunder://{}", encode("AAhttp://x/a.isoZZ"));
        assert_eq!(
            sniff_links(&format!("{iso}，复制"), &exts()),
            std::slice::from_ref(&iso)
        );
        let page = format!("thunder://{}", encode("AAhttp://x/a.htmlZZ"));
        assert!(sniff_links(&page, &exts()).is_empty());
    }

    #[test]
    fn non_ascii_text_around_links_is_handled_on_char_boundaries() {
        assert_eq!(
            sniff_links("链接：http://x/a.zip　提取", &exts()),
            ["http://x/a.zip"]
        );
    }

    // ---- 回归：之前"见协议头就提示"的误触发场景 ----

    #[test]
    fn protocol_header_alone_no_longer_prompts() {
        for text in [
            "https://example.com/",
            "https://example.com/article.html",
            "https://example.com/docs/index.php?page=2",
            "https://example.com/about",
        ] {
            assert!(sniff_links(text, &exts()).is_empty(), "不该提示: {text}");
        }
    }

    #[test]
    fn malformed_wrapped_links_do_not_prompt() {
        assert!(sniff_links("magnet:?xt=urn:btih:nothex", &exts()).is_empty());
        assert!(sniff_links("ed2k://|file|a.iso|", &exts()).is_empty());
        assert!(sniff_links("thunder://%%%not-base64%%%", &exts()).is_empty());
    }

    #[test]
    fn extensionless_download_entry_still_prompts() {
        assert_eq!(
            sniff_links("https://pan.example/download/9f8c1?token=abc", &exts()),
            ["https://pan.example/download/9f8c1?token=abc"]
        );
    }
}
