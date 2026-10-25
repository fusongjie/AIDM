// 任务失败文案：只按 aidm-ipc TaskView.error_code 映射，永不匹配 error 文本。
// http_4xx/http_5xx 只读 TaskView.http_status（u16）。与 error_display.rs 对齐。
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AidmErrors = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  const T = function (key, vars) {
    const api = root && root.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  };
  const FAIL_GENERIC = T("下载失败");
  const FAIL_NETWORK = T("网络连接失败，请检查网络后重试");
  const FAIL_BLOCKED_BY_HOSTS = T("域名被本机 hosts/DNS 屏蔽（解析为 0.0.0.0），请检查 hosts 文件或改用代理");
  const FAIL_DISK_FULL = T("磁盘空间不足，请清理后重试");
  const FAIL_NO_PERMISSION = T("没有权限写入保存位置，请换一个文件夹");
  const FAIL_REMOTE_CHANGED = T("服务器上的文件已更新，需要重新下载");
  const EXT_AUTH_EXPIRED = T("登录信息已失效，请回到网页重新点下载");
  const FAIL_HTTP_401 = T("需要登录（401）");
  const FAIL_HTTP_403 = T("服务器拒绝访问（403）");
  const FAIL_HTTP_404 = T("文件不存在或链接已失效");
  const FAIL_UNSUPPORTED_SCHEME = T("暂不支持该类型的链接");
  // 上游 CHECKSUM 声明了整文件 SHA-256，但下完的内容对不上（换过镜像 / 走过明文 http）
  const FAIL_SHA256 = T("下载内容与上游声明的 SHA-256 不符，请更换下载源");
  // 配额选“停止”：任务保留进度，但不是网络失败，文案要给出下一步。
  const FAIL_QUOTA = T("已达到本周期流量配额，任务已停止；配额重置后可手动继续");
  const INTERRUPTED_TOOLTIP = T("程序意外退出，已自动重新排队");
  const ENGINE_OFFLINE_BANNER = T("无法连接下载引擎，正在重新连接…");
  const LIST_LOAD_FAIL = T("无法连接下载引擎，请确认 AIDM 正在运行后重试");
  const ADD_DOWNLOAD_FAIL = T("添加下载失败，请重试");
  const PROPS_LOAD_FAIL = T("无法获取任务信息，请稍后重试");
  const OP_FAIL = T("操作失败，请重试");
  const SETTINGS_LOAD_FAIL = T("无法读取设置，请重试");
  const OPEN_DIR_FAIL = T("无法打开目录");
  const OPEN_INSTALL_FAIL = T("无法打开安装说明");
  const COPY_ERROR_DETAIL = T("复制错误详情");
  const DISCARD_SETTINGS = T("放弃未保存的修改？");
  const ACTION_CHANGE_LOCATION = T("更改位置");
  const ACTION_REDOWNLOAD = T("重新下载");
  const URL_EMPTY = T("请输入下载链接");
  const URL_SCHEME = T("仅支持 http:// 或 https://");
  const HEARTBEAT_STALE_MS = 45000;
  const CTX_LOCAL_ACTIONS = ["copy", "open-dir", "props"];

  function normalizeCode(errorCode) {
    if (errorCode == null) return "";
    return String(errorCode).trim();
  }

  function normalizeHttpStatus(httpStatus) {
    const n = Number(httpStatus);
    if (!Number.isInteger(n) || n < 100 || n > 599) return null;
    return n;
  }

  function authSentence(code, source) {
    if (source === "ext") return EXT_AUTH_EXPIRED;
    return code === "http_401" ? FAIL_HTTP_401 : FAIL_HTTP_403;
  }

  function httpRangeSentence(kind, httpStatus) {
    const status = normalizeHttpStatus(httpStatus);
    // 3xx 很少见但**很有指向性**：下载中途收到跳转，通常是镜像的反爬/防直链挑战
    // （实测 mirrors.nju.edu.cn、mirrors.sjtug.sjtu.edu.cn 对"自称浏览器"的请求回 302）。
    // 这时"稍后重试"没用，换一个来源才有用，所以要单独给文案。
    if (kind === "http_3xx" && status != null) {
      return T("服务器要求跳转（") + status + T("），通常是镜像的反爬校验，请换一个来源或稍后重试");
    }
    if (kind === "http_3xx") return T("服务器要求跳转，通常是镜像的反爬校验，请换一个来源");
    if (kind === "http_5xx" && status != null) return T("服务器返回错误（") + status + T("），请稍后重试");
    if (kind === "http_4xx" && status != null) return T("服务器返回错误（") + status + "）";
    if (kind === "http_5xx") return T("服务器返回错误，请稍后重试");
    return T("服务器返回错误");
  }

  function describeTaskError(taskOrCode, source, error, httpStatus) {
    let code = "";
    let src = source;
    let rawError = error;
    let status = httpStatus;
    if (taskOrCode && typeof taskOrCode === "object") {
      code = normalizeCode(taskOrCode.error_code);
      src = src != null ? src : taskOrCode.source;
      rawError = rawError != null ? rawError : taskOrCode.error;
      if (status == null) status = taskOrCode.http_status;
    } else {
      code = normalizeCode(taskOrCode);
    }
    const raw = rawError == null || String(rawError).trim() === "" ? "" : String(rawError).trim();
    if (!code) {
      return {
        code: "",
        sentence: FAIL_GENERIC,
        raw,
        action: null,
        actionLabel: "",
        isFailure: true,
        isInterrupted: false,
      };
    }
    if (code === "interrupted") {
      return {
        code,
        sentence: T("排队中"),
        raw,
        action: null,
        actionLabel: "",
        isFailure: false,
        isInterrupted: true,
      };
    }
    if (code === "ed2k_no_sources") {
      return {
        code,
        sentence: T("等待可用下载源，将自动重试"),
        raw,
        action: null,
        actionLabel: "",
        isFailure: false,
        isInterrupted: false,
      };
    }
    let sentence = FAIL_GENERIC;
    let action = null;
    let actionLabel = "";
    if (code === "network") sentence = FAIL_NETWORK;
    else if (code === "blocked_by_hosts") sentence = FAIL_BLOCKED_BY_HOSTS;
    else if (code === "disk_full") sentence = FAIL_DISK_FULL;
    else if (code === "no_permission") {
      sentence = FAIL_NO_PERMISSION;
      action = "change_location";
      actionLabel = ACTION_CHANGE_LOCATION;
    } else if (code === "remote_changed") {
      sentence = FAIL_REMOTE_CHANGED;
      action = "redownload";
      actionLabel = ACTION_REDOWNLOAD;
    } else if (code === "http_401" || code === "http_403") sentence = authSentence(code, src);
    else if (code === "http_404") sentence = FAIL_HTTP_404;
    else if (code === "http_3xx") sentence = httpRangeSentence("http_3xx", status);
    else if (code === "http_4xx") sentence = httpRangeSentence("http_4xx", status);
    else if (code === "http_5xx") sentence = httpRangeSentence("http_5xx", status);
    else if (code === "unsupported_scheme") sentence = FAIL_UNSUPPORTED_SCHEME;
    else if (code === "ed2k_hash_mismatch") sentence = T("文件内容与电驴链接的哈希不一致，请更换下载源");
    else if (code === "sha256_mismatch") sentence = FAIL_SHA256;
    else if (code === "quota_exceeded") sentence = FAIL_QUOTA;
    return {
      code,
      sentence,
      raw,
      action,
      actionLabel,
      isFailure: true,
      isInterrupted: false,
    };
  }

  function taskFailReason(task) {
    return describeTaskError(task).sentence;
  }

  function isInterrupted(task) {
    return describeTaskError(task).isInterrupted;
  }

  function taskErrorCode(task) {
    return task ? normalizeCode(task.error_code) : "";
  }

  function emptyCategoryTitle(cat) {
    if (cat === "active") return T("暂无未完成的任务");
    if (cat === "done") return T("暂无已完成的任务");
    if (cat === "queue") return T("暂无队列中的任务");
    if (cat === "error") return T("暂无失败的任务");
    return T("暂无下载任务");
  }

  /// 空分类的说明行。以前只有「全部」有说明，其余分类的空状态只剩一行标题，
  /// 看起来像页面没加载出来。每个分类都给一句"为什么这里是空的"。
  function emptyCategoryHint(cat) {
    if (cat === "active") return T("正在下载或暂停的任务会出现在这里。");
    if (cat === "done") return T("已完成的任务会出现在这里。");
    if (cat === "queue") return T("排队中或等待重试的任务会出现在这里。");
    if (cat === "error") return T("失败的任务会出现在这里，可在右侧重试。");
    return T("点击「新建下载」开始，或从托盘菜单发起。");
  }

  function settingsPageForKey(key) {
    const k = String(key || "");
    if (k.indexOf("paths.") === 0) return "paths";
    if (k.indexOf("conn.") === 0) return "conn";
    // eD2k / 镜像开关全部渲染在「连接」页（Section::Connection），漏了会跳到「常规」页
    if (
      k.indexOf("ed2k.") === 0 ||
      k.indexOf("bt.") === 0 ||
      k.indexOf("alt.") === 0 ||
      k.indexOf("find.") === 0
    ) {
      return "conn";
    }
    if (k.indexOf("sched.") === 0) return "sched";
    if (k.indexOf("speed.") === 0) return "speed";
    if (k.indexOf("proxy.") === 0) return "proxy";
    if (k.indexOf("browser.") === 0) return "browser";
    if (k.indexOf("update.") === 0) return "update";
    // 引擎内部开关、UA、接收缓冲在"高级"页
    if (
      k.indexOf("engine.") === 0 ||
      k.indexOf("verify.") === 0 ||
      k.indexOf("net.") === 0 ||
      k.indexOf("settings.revision") === 0
    ) {
      return "adv";
    }
    // 重复链接策略跟队列行为放一起
    if (k === "ui.duplicate_action") return "sched";
    return "general";
  }

  function settingsSetUserError(key, respOrCode, min, max) {
    let c = "";
    let mn = min;
    let mx = max;
    if (respOrCode && typeof respOrCode === "object") {
      c = String(respOrCode.code || "").trim();
      if (mn == null) mn = respOrCode.min;
      if (mx == null) mx = respOrCode.max;
    } else {
      c = String(respOrCode || "").trim();
    }
    if (c === "invalid_cron") return T("定时格式不对，例如 0 2 * * *");
    if (c === "invalid_value" && mn != null && mx != null) {
      if (key === "conn.retry_backoff_ms") {
        return T("请输入 ") + (Number(mn) / 1000) + "–" + (Number(mx) / 1000) + T(" 秒");
      }
      return T("请输入 ") + mn + "–" + mx + T(" 之间的整数");
    }
    if (c === "clock_invalid") return T("时间格式应为 HH:MM");
    if (c === "weekdays_invalid") return T("星期请填 1–7，用逗号分隔");
    if (c === "hosts_invalid") return T("服务器名不合法（可用 *.example.com）");
    if (c === "exts_invalid") return T("扩展名不合法（字母数字，逗号或空格分隔）");
    if (c === "category_dirs_invalid") return T('分类目录要写成 {"iso":"D:\\\\iso"} 这样的 JSON');
    if (c === "sound_invalid") return T("提示音取值不合法");
    if (c === "duplicate_action_invalid") return T("重复链接策略取值不合法");
    if (c === "proxy_only_for_invalid") return T("代理适用范围取值不合法");
    if (c === "quota_period_invalid" || c === "quota_action_invalid") return T("配额设置取值不合法");
    if (c === "after_done_invalid") return T("完成后动作取值不合法");
    if (c === "host_invalid") return T("服务器名不合法（可用 *.example.com）");
    if (c === "max_conns_invalid") return T("连接数需在 1–32 之间");
    if (c === "setting_readonly") return T("该项只读，由引擎维护");
    return T("设置保存失败，请重试");
  }

  function fileNameFromPath(p) {
    const s = String(p || "").trim();
    if (!s) return "";
    const parts = s.split(/[/\\]/);
    return parts[parts.length - 1] || s;
  }

  // 对齐 aidm-ipc：`{ok:false, code:"offer_expired"}`；只读 `code`。
  function isOfferExpired(resp) {
    if (!resp || resp.ok !== false) return false;
    return String(resp.code || "").trim() === "offer_expired";
  }

  function candidateOkLabel(selectedCount, retryFailed) {
    const n = Number(selectedCount) || 0;
    if (retryFailed) return T("重试失败的 ") + n + T(" 项");
    return T("下载选中的 ") + n + T(" 项");
  }

  function uncheckSucceededCandidates(selected, succeeded) {
    const next = new Set(selected);
    for (const i of succeeded) next.delete(i);
    return next;
  }

  function isLocalCtxAction(action) {
    return CTX_LOCAL_ACTIONS.indexOf(action) !== -1;
  }

  return {
    FAIL_GENERIC,
    FAIL_NETWORK,
    FAIL_BLOCKED_BY_HOSTS,
    FAIL_DISK_FULL,
    FAIL_NO_PERMISSION,
    FAIL_REMOTE_CHANGED,
    EXT_AUTH_EXPIRED,
    FAIL_HTTP_401,
    FAIL_HTTP_403,
    FAIL_HTTP_404,
    FAIL_UNSUPPORTED_SCHEME,
    FAIL_SHA256,
    FAIL_QUOTA,
    INTERRUPTED_TOOLTIP,
    ENGINE_OFFLINE_BANNER,
    LIST_LOAD_FAIL,
    ADD_DOWNLOAD_FAIL,
    PROPS_LOAD_FAIL,
    OP_FAIL,
    SETTINGS_LOAD_FAIL,
    OPEN_DIR_FAIL,
    OPEN_INSTALL_FAIL,
    COPY_ERROR_DETAIL,
    DISCARD_SETTINGS,
    ACTION_CHANGE_LOCATION,
    ACTION_REDOWNLOAD,
    URL_EMPTY,
    URL_SCHEME,
    HEARTBEAT_STALE_MS,
    CTX_LOCAL_ACTIONS,
    normalizeCode,
    normalizeHttpStatus,
    describeTaskError,
    taskFailReason,
    isInterrupted,
    taskErrorCode,
    emptyCategoryTitle,
    emptyCategoryHint,
    settingsPageForKey,
    settingsSetUserError,
    fileNameFromPath,
    isOfferExpired,
    candidateOkLabel,
    uncheckSucceededCandidates,
    isLocalCtxAction,
  };
});
