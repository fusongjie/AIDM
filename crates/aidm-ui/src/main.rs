// 安装版不显示控制台窗口；debug 构建保留，方便 cargo run 看日志。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! AIDM 桌面 UI（Tauri 2）：列表 / 设置 / 队列 / 定时；零 HTTP IO。
//!
//! 边界约束（ADR 0001）：UI 进程零 HTTP 网络 IO——本 crate 不做任何 HTTP 请求，
//! 仅通过回环 IPC 与引擎进程交换单行 JSON；下载业务全部由引擎负责。

mod autostart;
mod bridge;
mod clipboard;
// 界面逻辑跑在 `ui/*.js`；Rust 侧这几个模块是它的**规格镜像**，只被各自的单测
// 使用（`cargo test` 才编译），用来在没有 WebView 的环境里守住同一套规则。
// - `browser`（接管判定）、`polish`（列表虚拟化/列宽归一）在二进制里完全没有消费者，
//   直接按 `cfg(test)` 编译；
// - `logic` / `sched` / `error_display` / `task_display` 只被托盘提示等少数入口用到，
//   其余条目同样是"只给单测看"的规格，故在文件内以 `#![allow(dead_code)]` 标注原因。
#[cfg(test)]
mod browser;
mod error_display;
mod logic;
#[cfg(test)]
mod polish;
mod sched;
mod task_display;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use aidm_ipc::EngineRequest;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, RunEvent, WindowEvent,
};

/// 关闭窗口是「收进托盘」还是「退出程序」（`general.close_to_tray`）。
/// 默认 true：下载管理器关窗通常只想让它在后台继续跑。
static CLOSE_TO_TRAY: AtomicBool = AtomicBool::new(true);
/// 真退出标志：托盘「退出」与 `quit_app` 先置位，绕过关窗拦截。
static QUITTING: AtomicBool = AtomicBool::new(false);
/// 启动瞬间关窗时窗口还没注册进 Tauri 管理器，只能记下「等它可用再隐藏」。
static HIDE_WHEN_REGISTERED: AtomicBool = AtomicBool::new(false);

/// 主窗口关闭请求的统一处理：命中「收进托盘」就阻止关闭并隐藏，否则放行退出。
///
/// **为什么挂在应用级 `RunEvent::WindowEvent`，而不是只挂 `Builder::on_window_event`**：
/// Tauri 2 先把原生窗口创建出来（用户已经能看到），之后才把窗口事件监听器挂到运行时
/// 窗口上——`tauri-runtime-wry::on_close_requested` 只遍历「当时已注册」的监听器。
/// 启动瞬间（WebView 初始化完成前）收到的 WM_CLOSE 因此没人拦：wry 直接
/// `on_window_close` 销毁窗口，最后一个窗口没了，进程以退出码 0 结束；日志里连
/// `close requested` 都不会出现，用户看到的就是"点 X 程序直接退出"。
/// 应用级回调在 wry 判定是否销毁**之前**被调用，所以只有这里能兜住这个竞态。
fn intercept_close(app: &tauri::AppHandle, label: &str, api: &tauri::CloseRequestApi) {
    // 用户在设置里关掉了「关闭到托盘」，或正在真退出：不拦截，按系统默认关闭。
    if !CLOSE_TO_TRAY.load(Ordering::SeqCst) || QUITTING.load(Ordering::SeqCst) {
        return;
    }
    log::info!("close requested: label={label} -> hide to tray");
    api.prevent_close();
    hide_main(app, label);
}

/// 隐藏主窗口；窗口尚未注册（启动竞态）时交给 `MainEventsCleared` 补做。
fn hide_main(app: &tauri::AppHandle, label: &str) {
    match app.get_webview_window(label) {
        Some(win) => {
            HIDE_WHEN_REGISTERED.store(false, Ordering::SeqCst);
            if let Err(e) = win.hide() {
                log::warn!("hide window failed: {e}");
            }
        }
        None => HIDE_WHEN_REGISTERED.store(true, Ordering::SeqCst),
    }
}

/// 透传引擎请求（短连接）。请求/响应用 aidm-ipc 类型
///（含 `restart`、`rename`、`update_check` / `update_download_apply`、`EngineEvent::Update`）。
#[tauri::command]
fn engine_request(req: EngineRequest) -> Result<aidm_ipc::EngineResponse, String> {
    let resp = bridge::send(req.clone())?;
    if let EngineRequest::SettingsSet { key, .. } = &req {
        if !resp.ok {
            log::warn!(
                "settings_set failed key={key} error={}",
                resp.error.as_deref().unwrap_or("unknown")
            );
        }
    }
    Ok(resp)
}

#[tauri::command]
fn app_db_path() -> String {
    aidm_core::db_path().display().to_string()
}

#[tauri::command]
fn expand_user_path(path: String) -> String {
    aidm_core::paths::expand_user_path(&path)
        .to_string_lossy()
        .into_owned()
}

/// Tauri 侧本地目录选择（系统原生对话框；无网络）。
///
/// `initial` 是对话框打开时的起始目录（界面传"上次目录"或默认目录）。传空串、
/// 传一个已不存在的目录，都只是退回系统默认位置，不报错。
#[tauri::command]
fn pick_directory(initial: Option<String>) -> Option<String> {
    let mut dialog = rfd::FileDialog::new().set_title("选择保存目录");
    if let Some(dir) = initial.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        dialog = dialog.set_directory(dir);
    }
    dialog
        .pick_folder()
        .map(|p| p.to_string_lossy().into_owned())
}

/// 用本机关联程序打开文件。
///
/// **不再静默退化成"打开父目录"**：文件不在时返回 `file_missing`，界面据此给出
/// 「文件已被移动或删除」并让用户选「重新下载 / 打开所在目录 / 在磁盘上查找」
/// （见 `docs/file-missing-handling.md`）。打开目录有独立命令与独立菜单项。
#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err("file_missing".into());
    }
    open::that(&p).map_err(|e| e.to_string())
}

/// 用默认浏览器打开外部链接（项目仓库等）。
///
/// 与 [`open_path`] 分开：那个要求路径**存在**，而 URL 不是文件。只放行
/// http/https——其它 scheme 可能被系统关联到任意本地程序。
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    let u = url.trim();
    if !(u.starts_with("https://") || u.starts_with("http://")) {
        return Err("unsupported_url".into());
    }
    open::that(u).map_err(|e| e.to_string())
}

/// 打开扩展安装说明（本地 Markdown；不自动安装扩展）。
///
/// 安装版优先读 Tauri 资源目录：扩展由 `bundle.resources` 打包到
/// `<安装目录>/extension/`，`resource_dir()` 在 Windows 上就是 exe 所在目录。
/// 源码目录候选只用于开发机。
#[tauri::command]
fn open_extension_install_doc(app: tauri::AppHandle) -> Result<(), String> {
    let mut candidates = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        candidates.push(dir.join("extension/INSTALL.md"));
    }
    candidates.push(
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("extension/INSTALL.md")))
            .unwrap_or_default(),
    );
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../extension/INSTALL.md"));
    candidates.push(
        std::env::current_dir()
            .map(|d| d.join("extension/INSTALL.md"))
            .unwrap_or_default(),
    );
    for p in candidates {
        if p.as_os_str().is_empty() {
            continue;
        }
        if p.exists() {
            return open::that(&p).map_err(|e| e.to_string());
        }
    }
    Err("install_doc_not_found".into())
}

/// 打开安装包内置的**解压版扩展目录**，方便用户在 Chrome/Edge 里
/// 「加载已解压的扩展程序」时直接选择它。
#[tauri::command]
fn open_extension_dir(app: tauri::AppHandle) -> Result<(), String> {
    let mut candidates = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        candidates.push(dir.join("extension"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("extension"));
        }
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../extension"));
    for dir in candidates {
        if dir.join("manifest.json").is_file() {
            return open::that(&dir).map_err(|e| e.to_string());
        }
    }
    Err("extension_dir_not_found".into())
}

/// 打开目录；传入文件路径时打开父目录。
#[tauri::command]
fn open_directory(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    let dir: &Path = if p.is_dir() {
        &p
    } else {
        p.parent().unwrap_or(&p)
    };
    if !dir.as_os_str().is_empty() && dir.exists() {
        open::that(dir).map_err(|e| e.to_string())
    } else {
        Err("path_not_found".into())
    }
}

/// 批量检查本地路径是否存在（只读；列表「文件已被移动或删除」灰度提示用）。
///
/// 返回与 `paths` 等长、同序的布尔值：空串 / 纯空白 / 不存在都为 `false`。
/// 只做 `Path::exists()`（元数据查询），不打开文件、不读写内容、不访问网络。
fn paths_exist_impl(paths: &[String]) -> Vec<bool> {
    paths
        .iter()
        .map(|p| {
            let p = p.trim();
            !p.is_empty() && Path::new(p).exists()
        })
        .collect()
}

#[tauri::command]
fn paths_exist(paths: Vec<String>) -> Vec<bool> {
    paths_exist_impl(&paths)
}

/// 选择提示音文件（下载完成 / 失败时的自定义声音）。
#[tauri::command]
fn pick_audio_file() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("选择提示音")
        .add_filter("音频", &["wav", "mp3", "ogg", "m4a"])
        .pick_file()
        .map(|p| p.to_string_lossy().into_owned())
}

/// 退出界面进程（窗口与托盘都属于 UI 进程）。
///
/// `sched.after_done = exit` 走这里：队列跑完后由 UI 询问用户再退出。
/// 引擎是常驻进程，不随界面退出而停止——它本来就要在界面关闭时继续下载。
#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    QUITTING.store(true, Ordering::SeqCst);
    app.exit(0);
}

/// 开机自启：只写当前用户的 Run 键（`general.start_with_windows`）。
///
/// 返回注册表里的**实际**状态，而不是"调用成功"——界面据此显示是否真的生效。
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<bool, String> {
    autostart::set_enabled(enabled)?;
    Ok(autostart::is_enabled())
}

/// 托盘图标显隐（`general.tray_icon`）。
///
/// 托盘在启动时就建好，这里只切可见性：销毁再重建会把菜单状态和图标句柄一起
/// 丢掉，而显隐是 O(1)。
#[tauri::command]
fn apply_tray_icon(app: tauri::AppHandle, visible: bool) -> Result<bool, String> {
    let Some(tray) = app.tray_by_id("aidm-tray") else {
        return Err("tray_unavailable".into());
    };
    tray.set_visible(visible).map_err(|e| e.to_string())?;
    Ok(visible)
}

/// 关窗行为（general.close_to_tray）：true = 收进托盘继续后台运行，false = 退出。
///
/// 只存一个原子标志，不在关窗瞬间读数据库：CloseRequested 要走同步返回，
/// 磁盘 IO 会把关闭动作拖出可感知的延迟。
#[tauri::command]
fn apply_close_to_tray(enabled: bool) -> bool {
    CLOSE_TO_TRAY.store(enabled, Ordering::SeqCst);
    enabled
}

/// 下载完成通知（`ui.notify_on_complete`）。
///
/// 走 Rust 侧插件 API 而不是在 JS 里拼 `plugin:notification|notify`：参数结构由
/// 类型系统守着，插件升级时编译期就会报错，不会静默失效。
#[tauri::command]
fn notify_complete(app: tauri::AppHandle, title: String, body: String) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| e.to_string())
}

/// 内置提示音：代码合成的 WAV（44.1kHz / 16-bit / 单声道）。
/// 完成音上行（880 → 1318.5Hz），失败音下行（660 → 440Hz）。
fn builtin_chime_wav(error: bool) -> Vec<u8> {
    const RATE: u32 = 44_100;
    let notes: &[(f32, f32)] = if error {
        &[(660.0, 0.13), (440.0, 0.19)]
    } else {
        &[(880.0, 0.11), (1318.51, 0.17)]
    };
    let gap = 0.035f32;
    let mut samples: Vec<i16> = Vec::new();
    for (i, (freq, dur)) in notes.iter().enumerate() {
        let n = (dur * RATE as f32) as usize;
        for k in 0..n {
            let t = k as f32 / RATE as f32;
            // 10ms 淡入 + 40ms 淡出，避免爆音。
            let attack = (t / 0.01).min(1.0);
            let release = ((dur - t) / 0.04).clamp(0.0, 1.0);
            let env = attack * release;
            let s = (2.0 * std::f32::consts::PI * freq * t).sin() * env * 0.22;
            samples.push((s * i16::MAX as f32) as i16);
        }
        if i + 1 < notes.len() {
            samples.extend(std::iter::repeat(0i16).take((gap * RATE as f32) as usize));
        }
    }
    let data_len = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_len as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&RATE.to_le_bytes());
    out.extend_from_slice(&(RATE * 2).to_le_bytes()); // byte rate
    out.extend_from_slice(&2u16.to_le_bytes()); // block align
    out.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    for s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

#[cfg(windows)]
fn play_builtin_chime(error: bool) -> Result<(), String> {
    use std::sync::OnceLock;
    use windows_sys::Win32::Media::Audio::{PlaySoundW, SND_ASYNC, SND_MEMORY, SND_NODEFAULT};

    // SND_MEMORY | SND_ASYNC 要求内存在播放期间保持有效：放进 static。
    static COMPLETE: OnceLock<Vec<u8>> = OnceLock::new();
    static ERROR: OnceLock<Vec<u8>> = OnceLock::new();
    let wav = if error {
        ERROR.get_or_init(|| builtin_chime_wav(true))
    } else {
        COMPLETE.get_or_init(|| builtin_chime_wav(false))
    };
    let ok = unsafe {
        PlaySoundW(
            wav.as_ptr() as *const u16,
            std::ptr::null_mut(),
            SND_MEMORY | SND_ASYNC | SND_NODEFAULT,
        )
    };
    if ok == 0 {
        Err("play_sound_failed".into())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn play_builtin_chime(_error: bool) -> Result<(), String> {
    Err("unsupported".into())
}

/// 播放内置提示音：`kind = "error"` 为失败音，其余为完成音。
#[tauri::command]
fn play_builtin_sound(kind: String) -> Result<(), String> {
    play_builtin_chime(kind.eq_ignore_ascii_case("error"))
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    // 托盘菜单：显示主窗口 / 开始全部 / 暂停全部 / 完全退出
    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let start_all = MenuItem::with_id(app, "start_all", "开始全部", true, None::<&str>)?;
    let pause_all = MenuItem::with_id(app, "pause_all", "暂停全部", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "完全退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &start_all, &pause_all, &quit])?;

    let tray = TrayIconBuilder::with_id("aidm-tray")
        .icon(
            app.default_window_icon()
                .expect("default window icon embedded")
                .clone(),
        )
        .tooltip("AIDM")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| match event {
            // 左键单击直接恢复窗口。只有双击才恢复的托盘会被用户当成"点了没反应"，
            // 尤其关闭到托盘后，第一反应都是单击图标。
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => show_main(tray.app_handle()),
            TrayIconEvent::DoubleClick { .. } => show_main(tray.app_handle()),
            _ => {}
        })
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "start_all" => {
                bridge::resume_all_paused();
                let _ = app.emit("tray-action", "start_all");
            }
            "pause_all" => {
                bridge::pause_all_active();
                let _ = app.emit("tray-action", "pause_all");
            }
            "quit" => {
                QUITTING.store(true, Ordering::SeqCst);
                bridge::shutdown_engine();
                app.exit(0);
            }
            other => log::info!("tray action: {other}"),
        })
        .build(app)?;
    app.manage(tray);
    Ok(())
}

fn main() {
    aidm_core::obs::init("ui", "info");

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            engine_request,
            app_db_path,
            expand_user_path,
            pick_directory,
            pick_audio_file,
            quit_app,
            open_path,
            open_directory,
            open_url,
            paths_exist,
            open_extension_install_doc,
            open_extension_dir,
            clipboard::set_clipboard_watch,
            clipboard::clipboard_dismissed,
            set_autostart,
            apply_tray_icon,
            apply_close_to_tray,
            notify_complete,
            play_builtin_sound
        ])
        .setup(|app| {
            build_tray(app.handle())?;
            bridge::spawn_event_pump(app.handle().clone());
            clipboard::spawn_watcher(app.handle().clone());
            log::info!("AIDM UI v{} started", env!("CARGO_PKG_VERSION"));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("AIDM UI failed to start")
        .run(|app, event| match event {
            // 关窗统一在这里处理：无论是正常时机，还是窗口刚创建、监听器还没挂上的启动瞬间，
            // wry 的 `on_close_requested` 都会**先**调用应用级回调、再决定是否销毁窗口。
            RunEvent::WindowEvent {
                label,
                event: WindowEvent::CloseRequested { api, .. },
                ..
            } => intercept_close(app, &label, &api),
            // 启动竞态下窗口当时还没注册，等它一进管理器就补做隐藏。
            // 正常路径 `HIDE_WHEN_REGISTERED` 恒为 false，这里只是一次原子读。
            RunEvent::MainEventsCleared => {
                if HIDE_WHEN_REGISTERED.load(Ordering::SeqCst) {
                    if let Some(win) = app.get_webview_window("main") {
                        let _ = win.hide();
                        HIDE_WHEN_REGISTERED.store(false, Ordering::SeqCst);
                    }
                }
            }
            _ => {}
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn builtin_chime_is_wav() {
        let wav = super::builtin_chime_wav(false);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert!(wav.len() > 44);
        assert_eq!(u32::from_le_bytes(wav[24..28].try_into().unwrap()), 44_100);
        let err = super::builtin_chime_wav(true);
        assert_ne!(wav, err);
    }

    #[test]
    fn db_lives_in_app_data_dir() {
        let path = aidm_core::db_path();
        assert_eq!(path.file_name().unwrap(), std::ffi::OsStr::new("db.sqlite"));
        assert!(path.starts_with(aidm_core::app_data_dir()));
    }

    #[test]
    fn paths_exist_reports_present_missing_and_empty() {
        // 测试可执行文件必然存在；不触碰真实下载目录，也不创建任何文件。
        let existing = std::env::current_exe().expect("current_exe");
        let missing = std::env::temp_dir().join(format!(
            "aidm-definitely-missing-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(!missing.exists(), "fixture must not exist: {missing:?}");

        let paths = vec![
            existing.to_string_lossy().into_owned(),
            missing.to_string_lossy().into_owned(),
            String::new(),
            "   ".to_string(),
        ];
        assert_eq!(
            super::paths_exist_impl(&paths),
            vec![true, false, false, false]
        );
    }
}
