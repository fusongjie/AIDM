// 设置 › 更新：文案 / 状态机 / 错误码。零网络 IO；引擎走 HTTP。
// 使用 aidm-ipc：EngineRequest::UpdateCheck / UpdateDownloadApply、EngineEvent::Update。
// phase 含 up_to_date；当前版本用 settings_get 只读 app.version。
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AidmUpdate = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  const T = function (key, vars) {
    const api = root && root.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  };
  const OP_CHECK = "update_check";
  const OP_APPLY = "update_download_apply";

  const CHANNEL_STABLE = "stable";
  const CHANNEL_BETA = "beta";
  const CHANNEL_LABEL = { stable: T("正式版"), beta: T("测试版") };
  const CHANNEL_HINT = T("测试版可能不稳定，仅建议尝鲜时使用");
  const AUTO_CHECK_LABEL = T("启动后自动检查更新");
  const AUTO_CHECK_HINT = T("每 1 小时检查一次");
  const CHECK_LABEL = T("检查更新");
  const CHECKING_LABEL = T("正在检查…");
  const APPLY_LABEL = T("立即更新");
  const APPLYING_LABEL = T("下载中…");
  const VERIFYING_LABEL = T("正在校验…");
  const INSTALLING_LABEL = T("正在安装…");
  const DONE_LABEL = T("更新完成");
  const IDLE_LABEL = T("已经是最新版");
  const RETRY_LABEL = T("重试");
  const UP_TO_DATE = T("已是最新版本");
  const VERIFYING = T("正在校验文件…");
  const APPLYING = T("正在安装，应用即将重启…");
  const DONE_RESTART = T("更新完成，正在重启…");
  const ERR_NETWORK = T("无法连接更新服务器，请检查网络后重试");
  const ERR_CHECK_FAILED = T("检查更新失败，请稍后重试");
  const ERR_CHECKSUM = T("更新文件校验失败，未安装任何改动");
  const ERR_SIGNATURE = T("更新签名无效，已拒绝安装");
  const ERR_UPDATE_FAILED = T("更新失败，请稍后重试");

  function firstNonEmpty() {
    for (let i = 0; i < arguments.length; i++) {
      const v = arguments[i];
      if (v == null) continue;
      const s = String(v).trim();
      if (s) return s;
    }
    return "";
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function sameYmd(a, b) {
    return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  }

  function parseTimestamp(raw) {
    if (raw == null || raw === "") return null;
    if (typeof raw === "number" && Number.isFinite(raw)) {
      return raw < 1e12 ? raw * 1000 : raw;
    }
    const s = String(raw).trim();
    if (!s) return null;
    if (/^\d+$/.test(s)) {
      const n = Number(s);
      if (!Number.isFinite(n)) return null;
      return n < 1e12 ? n * 1000 : n;
    }
    const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
    if (m) {
      const d = new Date(
        Number(m[1]),
        Number(m[2]) - 1,
        Number(m[3]),
        Number(m[4]),
        Number(m[5]),
        Number(m[6] || 0)
      );
      return Number.isNaN(d.getTime()) ? null : d.getTime();
    }
    const d = new Date(s);
    return Number.isNaN(d.getTime()) ? null : d.getTime();
  }

  function formatLastCheck(raw, nowMs) {
    const ms = parseTimestamp(raw);
    if (ms == null) return T("上次检查：—");
    const at = new Date(ms);
    const now = new Date(nowMs == null ? Date.now() : nowMs);
    if (Number.isNaN(at.getTime()) || Number.isNaN(now.getTime())) return T("上次检查：—");
    const hm = pad2(at.getHours()) + ":" + pad2(at.getMinutes());
    if (sameYmd(at, now)) return T("上次检查：今天 ") + hm;
    const yest = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    if (sameYmd(at, yest)) return T("上次检查：昨天 ") + hm;
    return (
      T("上次检查：") +
      at.getFullYear() +
      "-" +
      pad2(at.getMonth() + 1) +
      "-" +
      pad2(at.getDate()) +
      " " +
      hm
    );
  }

  function formatCurrentVersion(version) {
    const v = firstNonEmpty(version);
    return v ? T("当前版本 ") + v : "—";
  }

  function resolveAppVersion(event, settings, pingVersion) {
    if (settings && typeof settings === "object") {
      const fromSettings = firstNonEmpty(settings["app.version"]);
      if (fromSettings) return fromSettings;
    }
    if (event && typeof event === "object") {
      const fromEvent = firstNonEmpty(event.current_version);
      if (fromEvent) return fromEvent;
    }
    return firstNonEmpty(pingVersion);
  }

  function eventPercent(ev) {
    if (!ev || typeof ev !== "object") return null;
    if (ev.percent != null && Number.isFinite(Number(ev.percent))) {
      return Math.max(0, Math.min(100, Number(ev.percent)));
    }
    const done = Number(ev.bytes_done);
    const total = Number(ev.bytes_total);
    if (Number.isFinite(done) && Number.isFinite(total) && total > 0) {
      return Math.max(0, Math.min(100, (done / total) * 100));
    }
    return null;
  }

  function channelLabel(value) {
    return CHANNEL_LABEL[String(value || "").trim()] || "";
  }

  function normalizeChannel(value) {
    return String(value || "").trim() === CHANNEL_BETA ? CHANNEL_BETA : CHANNEL_STABLE;
  }

  function normalizeAutoCheck(value) {
    if (value == null || value === "") return true;
    return value === true || value === "true";
  }

  function describeUpdateError(code) {
    const c = String(code == null ? "" : code).trim();
    if (c === "network") return ERR_NETWORK;
    if (c === "check_failed") return ERR_CHECK_FAILED;
    if (c === "checksum_mismatch") return ERR_CHECKSUM;
    if (c === "signature_invalid") return ERR_SIGNATURE;
    if (c === "update_failed") return ERR_UPDATE_FAILED;
    return ERR_UPDATE_FAILED;
  }

  function emptyState() {
    return {
      phase: "idle",
      currentVersion: "",
      availableVersion: "",
      notes: "",
      percent: 0,
      code: "",
      message: "",
      lastCheckAt: "",
      userCheck: false,
      applyingDownload: false,
    };
  }

  function isDownloadPhase(phase) {
    return phase === "downloading" || phase === "verifying" || phase === "applying" || phase === "done";
  }

  function eventPhase(ev) {
    if (!ev || typeof ev !== "object") return "";
    return firstNonEmpty(ev.phase, ev.status);
  }

  function applyUpdateEvent(state, ev) {
    const prev = state && typeof state === "object" ? state : emptyState();
    const next = Object.assign(emptyState(), prev);
    const phase = eventPhase(ev);
    const current = ev && firstNonEmpty(ev.current_version);
    if (current) next.currentVersion = current;
    if (ev && ev.last_check_at != null && String(ev.last_check_at).trim()) {
      next.lastCheckAt = ev.last_check_at;
    }
    if (ev && ev.notes != null) next.notes = String(ev.notes);
    const pct = eventPercent(ev);
    if (pct != null) next.percent = pct;
    if (ev && ev.code != null) next.code = String(ev.code).trim();
    if (ev && (ev.error != null || ev.message != null)) {
      next.message = String(ev.error != null ? ev.error : ev.message);
    }
    if (ev && ev.version != null && phase === "available") {
      next.availableVersion = String(ev.version).trim();
    }

    if (phase === "checking") {
      if (prev.applyingDownload || isDownloadPhase(prev.phase)) {
        next.phase = prev.phase === "checking" || prev.phase === "idle" || prev.phase === "available"
          ? "downloading"
          : prev.phase;
        if (next.phase === "available") next.phase = "downloading";
      } else {
        next.phase = "checking";
      }
    } else if (phase === "available") {
      next.phase = "available";
      next.applyingDownload = false;
    } else if (phase === "up_to_date") {
      next.phase = "up_to_date";
      next.applyingDownload = false;
    } else if (phase === "downloading") {
      next.phase = "downloading";
    } else if (phase === "verifying") {
      next.phase = "verifying";
    } else if (phase === "applying") {
      next.phase = "applying";
    } else if (phase === "done") {
      next.phase = "done";
      next.applyingDownload = false;
    } else if (phase === "error") {
      const code = String((ev && ev.code) || "").trim();
      if (code === "network" || code === "check_failed") {
        // 检查请求失败按「无更新」处理：按钮保持灰色「已经是最新版」。
        next.phase = "up_to_date";
        next.code = "";
        next.message = "";
      } else {
        next.phase = "error";
      }
    }
    return next;
  }

  function applyCheckResponse(state, resp) {
    const prev = state && typeof state === "object" ? state : emptyState();
    const next = Object.assign(emptyState(), prev, { userCheck: true, phase: "checking" });
    if (resp && resp.ok) return next;
    // 检查请求失败（含引擎不可达）视为无更新，不把错误面板抛给用户。
    next.phase = "up_to_date";
    next.code = "";
    next.message = "";
    return next;
  }

  function beginDownload(state) {
    const prev = state && typeof state === "object" ? state : emptyState();
    return Object.assign(emptyState(), prev, {
      applyingDownload: true,
      phase: "downloading",
      percent: prev.phase === "downloading" ? prev.percent : 0,
      code: "",
      message: "",
    });
  }

  /// 更新页不再有「标签提醒」。
  ///
  /// 状态一律由**按钮文案**表达（可用更新时按钮自带版本号，校验/安装/完成也都有
  /// 对应按钮文字），这里刻意返回空串：同一件事在页面上说两遍就是重复提醒。
  /// 唯一例外是错误原因——按钮里说不出来，改由说明区（notes）显示。
  function statusTitle() {
    return "";
  }

  /// 状态区只在**按钮装不下信息**时显示：下载进度条、更新说明、错误原因。
  /// `up_to_date` / `verifying` / `applying` / `done` 这些阶段按钮已经说清楚了，
  /// 再留一块只有标题的状态区就是重复。
  function shouldShowStatus(state) {
    const s = state || emptyState();
    if (s.phase === "error") {
      const checkLike = s.code === "network" || s.code === "check_failed";
      if (checkLike && !s.userCheck && !s.applyingDownload) return false;
      return true;
    }
    if (s.phase === "downloading") return true;
    if (s.phase === "available") return !!String(s.notes || "").trim();
    return false;
  }

  function showUpdateDot(state) {
    const s = state || emptyState();
    return s.phase === "available";
  }

  /// 可用更新时按钮自带版本号，让"要更新到哪一版"只在这一处出现。
  function applyLabelForAvailable(s) {
    const v = firstNonEmpty(s.availableVersion);
    return v ? T("立即更新到 ") + v : APPLY_LABEL;
  }

  function updateStatusView(state) {
    const s = state || emptyState();
    const locked = s.phase === "applying" || s.phase === "done";
    const checking = s.phase === "checking" && !s.applyingDownload;
    const downloading = s.phase === "downloading";
    const notes =
      s.phase === "available"
        ? String(s.notes || "").trim()
        : s.phase === "error"
          ? describeUpdateError(s.code)
          : "";
    return {
      currentVersionText: formatCurrentVersion(s.currentVersion),
      lastCheckText: formatLastCheck(s.lastCheckAt),
      checkLabel: checking ? CHECKING_LABEL : CHECK_LABEL,
      checkDisabled: checking || downloading || locked || s.phase === "verifying" || !!s.applyingDownload,
      applyVisible: true,
      applyLabel:
        s.phase === "available"
          ? applyLabelForAvailable(s)
          : s.phase === "downloading"
            ? APPLYING_LABEL
            : s.phase === "verifying"
              ? VERIFYING_LABEL
              : s.phase === "applying"
                ? INSTALLING_LABEL
                : s.phase === "done"
                  ? DONE_LABEL
                  : s.phase === "checking"
                    ? CHECKING_LABEL
                    : IDLE_LABEL,
      applyDisabled: s.phase !== "available" || locked || !!s.applyingDownload,
      retryVisible: s.phase === "error" && s.code === "checksum_mismatch",
      retryLabel: RETRY_LABEL,
      progressVisible: downloading,
      progressPercent: Math.max(0, Math.min(100, Number(s.percent) || 0)),
      notes,
      notesVisible: !!notes,
      title: statusTitle(s),
      showStatus: shouldShowStatus(s),
      redDot: showUpdateDot(s),
      pageLocked: locked,
    };
  }

  return {
    OP_CHECK,
    OP_APPLY,
    CHANNEL_STABLE,
    CHANNEL_BETA,
    CHANNEL_LABEL,
    CHANNEL_HINT,
    AUTO_CHECK_LABEL,
    AUTO_CHECK_HINT,
    CHECK_LABEL,
    CHECKING_LABEL,
    APPLY_LABEL,
    APPLYING_LABEL,
    VERIFYING_LABEL,
    INSTALLING_LABEL,
    DONE_LABEL,
    IDLE_LABEL,
    RETRY_LABEL,
    UP_TO_DATE,
    VERIFYING,
    APPLYING,
    DONE_RESTART,
    ERR_NETWORK,
    ERR_CHECK_FAILED,
    ERR_CHECKSUM,
    ERR_SIGNATURE,
    ERR_UPDATE_FAILED,
    firstNonEmpty,
    parseTimestamp,
    formatLastCheck,
    formatCurrentVersion,
    resolveAppVersion,
    eventPercent,
    channelLabel,
    normalizeChannel,
    normalizeAutoCheck,
    describeUpdateError,
    emptyState,
    applyUpdateEvent,
    applyCheckResponse,
    beginDownload,
    statusTitle,
    shouldShowStatus,
    showUpdateDot,
    updateStatusView,
  };
});
