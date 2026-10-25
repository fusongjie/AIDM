; AIDM 安装/卸载钩子：结束占用安装目录的进程。
;
; 背景：aidm-ext-host.exe 由浏览器以 Native Messaging 方式拉起，主窗口关闭后
; 仍可能驻留。Tauri 默认只检测主程序 aidm-ui.exe，升级安装复制 sidecar 时会弹
; 「无法打开要写入的文件 ...\aidm-ext-host.exe」。这里在复制文件前主动结束，
; 避免用户手动去任务管理器杀进程。
;
; 只结束当前用户下的同名进程（安装模式 currentUser）；若插件失败，用
; taskkill 兜底（同用户进程无需提权）。aidm-* 是本产品专属映像名，不会误伤。

!macro AIDM_KillImage image
  nsis_tauri_utils::FindProcessCurrentUser "${image}"
  Pop $R0
  ${If} $R0 = 0
    DetailPrint "正在结束 ${image} ..."
    nsis_tauri_utils::KillProcessCurrentUser "${image}"
    Pop $R0
    ${If} $R0 != 0
    ${AndIf} $R0 != 2
      nsExec::ExecToLog 'taskkill /F /IM "${image}" /T'
      Pop $R0
    ${EndIf}
  ${EndIf}
!macroend

!macro AIDM_StopProcesses
  Push $R0

  ; 顺序：先后台宿主，再引擎，最后界面。
  !insertmacro AIDM_KillImage "aidm-ext-host.exe"
  !insertmacro AIDM_KillImage "aidm-engine.exe"
  !insertmacro AIDM_KillImage "aidm-ui.exe"

  ; 给 Windows 一点时间释放 exe 文件句柄：浏览器可能正在等 native host 退出，
  ; 句柄没释放时 NSIS 覆盖文件仍会失败。
  Sleep 1200

  Pop $R0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro AIDM_StopProcesses
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro AIDM_StopProcesses
!macroend
