// AIDM MV3 扩展纯逻辑（无 chrome.* / 无网络）。
// service worker 用 importScripts；Node 单测用 CommonJS。
(function (root) {
  const HOST_NAME = "com.aidm.host";
  const DEFAULT_EXT_ID = "npapgdblbbcppnbmhgdnmdbggfdnpahg";
  const OFFER_ITEM_LIMIT = 500;
  const URL_MAX = 8 * 1024;
  const REFERRER_MAX = 8 * 1024;
  const COOKIES_MAX = 16 * 1024;
  const FILENAME_MAX = 255;

  const FALLBACK_CODES = [
    "unsupported_scheme",
    "not_allowed",
    "bad_url",
    "disabled",
    "engine_unreachable",
  ];

  const MSG = {
    ui_not_running: "请先打开 AIDM",
    disabled: "浏览器集成已在 AIDM 中关闭，已改用浏览器下载",
    offer_disabled: "浏览器集成已在 AIDM 中关闭",
    offer_fail: "无法交给 AIDM，请稍后重试",
    offer_expired: "候选已过期，请在页面上重新收集",
    fallback: "无法交给 AIDM，已改用浏览器下载",
    too_long: "链接过长，已改用浏览器下载",
    uncertain: "无法确认是否已交给 AIDM，请在 AIDM 列表中查看",
    status_disconnect: "未连接到 AIDM，请先打开 AIDM",
    status_engine_off: "AIDM 引擎未运行",
    ext_not_ready: "扩展未就绪，请重新打开此窗口",
    collect_exception: "收集链接失败，请刷新页面后重试",
    no_page_links: "当前页面没有可下载的链接",
    ui_unavailable: "无法启动 AIDM，请手动打开主程序",
  };

  function deriveFilename(explicit, url) {
    const name = String(explicit || "").trim();
    if (name) {
      const base = name.split(/[/\\]/).pop() || name;
      return clip(base, FILENAME_MAX);
    }
    const raw = String(url || "");
    const after = raw.includes("://") ? raw.split("://").slice(1).join("://") : raw;
    const slash = after.indexOf("/");
    if (slash < 0) return "download.bin";
    let path = after.slice(slash + 1).split(/[?#]/)[0].replace(/\/+$/, "");
    let last = path.split(/[/\\]/).pop() || "";
    try {
      last = decodeURIComponent(last);
    } catch {
      /* keep */
    }
    if (!last || last === "." || last === "..") return "download.bin";
    return clip(last, FILENAME_MAX);
  }

  function clip(s, max) {
    const chars = [...s];
    return chars.length <= max ? s : chars.slice(0, max).join("");
  }

  function addFieldTooLong(url, referrer, cookies, filename) {
    if (String(url || "").length > URL_MAX) return true;
    if (referrer && String(referrer).length > REFERRER_MAX) return true;
    if (cookies && String(cookies).length > COOKIES_MAX) return true;
    if (filename && [...String(filename)].length > FILENAME_MAX) return true;
    return false;
  }

  function truncateOfferItems(items) {
    const list = Array.isArray(items) ? items : [];
    if (list.length <= OFFER_ITEM_LIMIT) return { items: list.slice(), truncated: false };
    return { items: list.slice(0, OFFER_ITEM_LIMIT), truncated: true };
  }

  /**
   * 注入到页面的采集函数：必须自包含（scripting.executeScript 会序列化源码）。
   * 扫描 a[href]、video/audio 与 source。
   */
  function collectPageItems() {
    const items = [];
    const seen = new Set();
    function add(url, kind) {
      if (!url) return;
      const raw = String(url);
      if (
        raw.startsWith("javascript:") ||
        raw.startsWith("blob:") ||
        raw.startsWith("data:") ||
        raw.startsWith("mailto:")
      ) {
        return;
      }
      try {
        const abs = new URL(raw, document.baseURI).href;
        if (!/^https?:/i.test(abs)) return;
        const key = kind + "\0" + abs;
        if (seen.has(key)) return;
        seen.add(key);
        items.push({ url: abs, kind: kind });
      } catch {
        /* ignore */
      }
    }
    document.querySelectorAll("a[href]").forEach(function (a) {
      add(a.href, "link");
    });
    document.querySelectorAll("video[src], audio[src]").forEach(function (el) {
      add(el.currentSrc || el.src, el.tagName === "AUDIO" ? "audio" : "video");
    });
    document.querySelectorAll("video source[src], audio source[src]").forEach(function (el) {
      const media = el.closest("video, audio");
      add(el.src, media && media.tagName === "AUDIO" ? "audio" : "video");
    });
    const truncated = items.length > 500;
    return {
      items: items.slice(0, 500),
      truncated: truncated,
      page_url: location.href,
      title: document.title || "",
    };
  }

  /// 悬浮面板要列出的媒体：`<video>/<audio>/<source>` 的地址，外加扩展名命中
  /// 面板清单的链接。
  ///
  /// 与 `collectPageItems` 的区别在**过滤口径**：那边用 `browser.auto_catch_exts`
  /// （决定要不要拦这次下载），这边用 `browser.panel_exts`（决定要不要在页面上
  /// 冒泡提醒）。媒体元素一律收，链接必须命中清单。只保留 http(s)，按 URL 去重。
  function collectPanelItems(settings, doc) {
    const d = doc || document;
    const base = d.baseURI || (typeof location !== "undefined" ? location.href : "");
    const items = [];
    const seen = new Set();
    function add(url, kind) {
      const raw = String(url || "").trim();
      if (!raw || /^(javascript|blob|data|mailto):/i.test(raw)) return;
      let abs;
      try {
        abs = new URL(raw, base).href;
      } catch {
        return;
      }
      if (!/^https?:/i.test(abs) || seen.has(abs)) return;
      seen.add(abs);
      items.push({ url: abs, kind: kind });
    }
    d.querySelectorAll("video[src], audio[src]").forEach(function (el) {
      add(el.currentSrc || el.src, el.tagName === "AUDIO" ? "audio" : "video");
    });
    d.querySelectorAll("video source[src], audio source[src]").forEach(function (el) {
      const media = el.closest && el.closest("video, audio");
      add(el.src, media && media.tagName === "AUDIO" ? "audio" : "video");
    });
    d.querySelectorAll("a[href]").forEach(function (a) {
      if (extInList(settings.panelExts, extOfUrl(a.href))) add(a.href, "link");
    });
    return items;
  }

  /**
   * lastError + response → 分类。
   * disconnected / unknown = 可能已接受，禁止降级。
   * 仅 explicit 且码在 FALLBACK_CODES 时回落浏览器下载。
   */
  function classifyNativeResult(lastError, response) {
    if (lastError) return { type: "disconnected" };
    if (response == null || typeof response !== "object") return { type: "unknown" };
    if (response.ok === true) return { type: "accepted" };
    if (response.ok === false) {
      const code = response.code == null ? "" : String(response.code);
      return {
        type: "explicit",
        code: code || "error",
      };
    }
    return { type: "unknown" };
  }

  function shouldFallbackToBrowser(classified) {
    if (!classified || classified.type !== "explicit") return false;
    return FALLBACK_CODES.indexOf(classified.code) !== -1;
  }

  function userMessage(classified, kind) {
    const k = kind || "add";
    if (k === "status") return statusMessage(classified, true);
    if (k === "offer") return offerMessage(classified);
    if (!classified) return MSG.uncertain;
    if (classified.type === "accepted") return "";
    if (classified.type === "explicit") {
      if (classified.code === "ui_not_running") return MSG.ui_not_running;
      if (classified.code === "disabled") return MSG.disabled;
      if (classified.code === "too_long") return MSG.too_long;
      if (classified.code === "offer_expired") return MSG.offer_expired;
      if (FALLBACK_CODES.indexOf(classified.code) !== -1) return MSG.fallback;
      return MSG.uncertain;
    }
    return MSG.uncertain;
  }

  function offerMessage(classified) {
    if (!classified || classified.type === "accepted") return "";
    if (classified.type === "explicit") {
      if (classified.code === "ui_not_running") return MSG.ui_not_running;
      if (classified.code === "disabled") return MSG.offer_disabled;
      if (classified.code === "offer_expired") return MSG.offer_expired;
    }
    return MSG.offer_fail;
  }

  /// 「唤起主程序」失败的提示。
  ///
  /// 与 add 的失败提示分开：这里不涉及下载接管，也没有"改用浏览器下载"的退路，
  /// 只说明为什么没能打开 AIDM。
  const OPEN_UI_MESSAGES = {
    ui_not_found: "未找到 AIDM 主程序，请确认已安装",
    ui_timeout: "AIDM 正在启动，请稍候再点一次",
    launch_failed: "无法启动 AIDM，请手动打开主程序",
    unsupported: "当前系统不支持自动启动 AIDM，请手动打开主程序",
    not_allowed: "浏览器集成未授权：请在 AIDM 设置页注册扩展",
  };

  function openUiMessage(classified) {
    if (!classified) return MSG.ui_unavailable;
    if (classified.type === "accepted") return "";
    if (classified.type === "explicit") {
      return OPEN_UI_MESSAGES[classified.code] || MSG.ui_unavailable;
    }
    return MSG.ui_unavailable;
  }

  /// 悬浮提示的显隐决策（panel.js 与单测共用）。
  ///
  /// 这是「自动消隐丢失」回归的守卫：后台每秒推一次进度，若每次推送都重置淡出
  /// 计时器，提示就永远不会消失。规则：
  ///   - 已经淡出/隐藏后，下载中的进度更新一律丢弃（`ignore`），不复活提示；
  ///   - 结束态（done / took / gone）允许重新冒泡一次（`show-auto`）；
  ///   - 提示仍可见时只更新文字（`update`），不动计时器；
  ///   - 鼠标悬停（force）立即显示并钉住（`show-pinned`），不计时。
  function panelStatusAction({ wasHidden, pinned, state, force }) {
    if (force) return "show-pinned";
    if (wasHidden) {
      return state === "downloading" ? "ignore" : "show-auto";
    }
    return "update";
  }

  function statusMessage(classified, engineOnline) {
    if (!classified || classified.type === "disconnected" || classified.type === "unknown") {
      return MSG.status_disconnect;
    }
    if (classified.type === "explicit") {
      if (classified.code === "engine_unreachable") return MSG.status_engine_off;
      return MSG.status_disconnect;
    }
    if (!engineOnline) return MSG.status_engine_off;
    return "";
  }

  // ---- 设置驱动的接管判定（扩展名清单 / 排除服务器 /
  //      悬浮面板 / 跳过网页）。这些设置由引擎持有，扩展通过宿主的
  //      `settings` op 只读拿到一个白名单子集。 ----

  /// 默认接管扩展名，与引擎 `setting_spec` 的 `browser.auto_catch_exts` 默认值
  /// **逐项一致**（52 项；`r0*` / `r1*` 是通配）。写成同一串是为了让漂移能被肉眼
  /// 和单测同时发现——引擎侧才是权威，这里只是读不到设置时的兜底。
  const DEFAULT_CATCH_EXTS_CSV =
    "3gp 7z aac ace aif apk arj asf avi bin bz2 exe gz gzip img iso lzh m4a m4v mkv mov " +
    "mp3 mp4 mpa mpe mpeg mpg msi msu ogg ogv plj pps ppt qt r0* r1* ra rar rm rmvb sea " +
    "sit sitx tar tif tiff wav wma wmv z zip";

  /// 悬浮面板默认扩展名（27 项），同样与引擎默认值一致。
  const DEFAULT_PANEL_EXTS_CSV =
    "3gp aac asf avi dfxp f4v flv m4a m4v mkv mov mp3 mp4 mpeg mpg ogg ogv qt rm srt ts " +
    "ttml ttml2 wav webm wma wmv";

  const DEFAULT_CATCH_EXTS = DEFAULT_CATCH_EXTS_CSV.split(" ");
  const DEFAULT_PANEL_EXTS = DEFAULT_PANEL_EXTS_CSV.split(" ");

  function urlHost(url) {
    const raw = String(url || "").trim();
    if (!raw) return "";
    let rest = raw.includes("://") ? raw.split("://").slice(1).join("://") : raw;
    rest = rest.split("/")[0].split("?")[0].split("#")[0];
    if (rest.startsWith("[")) {
      const end = rest.indexOf("]");
      return (end > 0 ? rest.slice(1, end) : rest).toLowerCase();
    }
    return rest.split(":")[0].toLowerCase();
  }

  /// 主机是否命中排除表（精确或 `*.` 通配）。与引擎 `sched::host_matches` 同规则。
  function hostMatches(pattern, host) {
    const p = String(pattern || "").trim().toLowerCase();
    const h = String(host || "").trim().toLowerCase();
    if (!p || !h) return false;
    if (p.startsWith("*.")) {
      const suffix = p.slice(2);
      return h === suffix || h.endsWith("." + suffix);
    }
    return h === p;
  }

  function hostListOf(csv) {
    return String(csv == null ? "" : csv)
      .split(/[,，;；\s]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
  }

  function extListOf(raw) {
    const parts = String(raw == null ? "" : raw)
      .split(/[,，;；\s]+/)
      .map((s) => s.trim().replace(/^\./, "").toLowerCase())
      .filter(Boolean);
    return parts.length ? parts : null;
  }

  function extOfUrl(url) {
    const raw = String(url || "");
    const path = raw.split("#")[0].split("?")[0];
    const name = path.split("/").pop() || "";
    if (!name.includes(".")) return "";
    return name.split(".").pop().toLowerCase();
  }

  /// 归一化设置快照：缺失 / 非法值时回落到引擎默认值。
  ///
  /// 注意"缺失"和"显式留空"是两回事：用户把快捷键选成「未设置」时值是空串，
  /// 必须保留，只有读不到该键时才用默认的 Delete / Insert。
  function normalizeSettings(raw) {
    const s = raw && typeof raw === "object" ? raw : {};
    const catchExts = extListOf(s["browser.auto_catch_exts"]) || DEFAULT_CATCH_EXTS;
    const panelExts = extListOf(s["browser.panel_exts"]) || DEFAULT_PANEL_EXTS;
    const pick = (value, fallback) => (value == null ? fallback : String(value));
    return {
      enabled: s["browser.enabled"] !== "false",
      clickTakeover: s["browser.click_takeover"] !== "false",
      excludeHosts: hostListOf(s["browser.exclude_hosts"]),
      panelExcludeHosts: hostListOf(s["browser.panel_exclude_hosts"]),
      autoCatchExts: catchExts,
      panelExts,
      panelEnabled: s["browser.panel_enabled"] !== "false",
      skipHtml: s["browser.skip_html"] !== "false",
      monitorClipboard: s["browser.monitor_clipboard"] === "true",
      hotkeyPrevent: pick(s["browser.hotkey_prevent"], "del"),
      hotkeyForce: pick(s["browser.hotkey_force"], "ins"),
      duplicateAction: String(s["ui.duplicate_action"] || "allow"),
    };
  }

  /// 该主机是否完全不接管（命中去重后的排除服务器清单）。
  function hostExcluded(settings, url) {
    const host = urlHost(url);
    if (!host) return false;
    return settings.excludeHosts.some((p) => hostMatches(p, host));
  }

  /// 该主机是否不显示悬浮面板。
  function panelHostExcluded(settings, url) {
    const host = urlHost(url);
    if (!host) return false;
    return settings.panelExcludeHosts.some((p) => hostMatches(p, host));
  }

  /// 链接扩展名是否属于"该交给下载器"的类型。
  function isCatchableExt(settings, url) {
    return extInList(settings.autoCatchExts, extOfUrl(url));
  }

  /// `r0*` 这类尾部通配按前缀匹配，其余全等。
  function extInList(list, ext) {
    if (!ext) return false;
    return list.some((p) => (p.endsWith("*") ? ext.startsWith(p.slice(0, -1)) : p === ext));
  }

  function extOfName(name) {
    const base = String(name || "").split(/[/\\]/).pop() || "";
    const dot = base.lastIndexOf(".");
    return dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
  }

  /// 浏览器下载项（chrome.downloads.DownloadItem 的子集）是否转交 AIDM。
  /// 扩展名优先取浏览器已确定的文件名（含 Content-Disposition），取不到再看 URL。
  ///
  /// `force`（按住「强制接管」键）只越过**挑内容**的三道闸：排除表、网页本身、
  /// 扩展名清单。上面三道是"能不能接管"的前提——总开关、下载状态、防回环——
  /// 任何热键都不越过，否则强制键会把用户退回给浏览器的下载再抢回来，来回弹。
  function shouldTakeOverDownload(settings, item, selfExtensionId, force) {
    if (!settings.enabled || !settings.clickTakeover || !item) return false;
    if (item.state === "complete" || item.state === "interrupted") return false;
    // 自己退回给浏览器的下载不能再被接管，否则会来回弹。
    if (selfExtensionId && item.byExtensionId === selfExtensionId) return false;
    if (force) return true;
    const url = item.finalUrl || item.url;
    if (shouldSkipUrl(settings, url)) return false;
    if (settings.skipHtml && /^(text\/html|application\/xhtml\+xml)\b/i.test(String(item.mime || ""))) {
      return false;
    }
    return extInList(settings.autoCatchExts, extOfName(item.filename) || extOfUrl(url));
  }

  /// chrome.cookies.getAll 的结果 → Cookie 请求头。
  function cookieHeader(cookies) {
    const list = Array.isArray(cookies) ? cookies : [];
    return list
      .filter((c) => c && c.name)
      .map((c) => c.name + "=" + (c.value == null ? "" : c.value))
      .join("; ");
  }

  /// 网页本身是否应当被跳过（按扩展名判断）。
  function isHtmlLike(url) {
    const ext = extOfUrl(url);
    return ext === "html" || ext === "htm" || ext === "xhtml" || ext === "shtml";
  }

  function shouldSkipUrl(settings, url) {
    if (!url) return true;
    const scheme = String(url).toLowerCase();
    if (!scheme.startsWith("http://") && !scheme.startsWith("https://")) return true;
    if (hostExcluded(settings, url)) return true;
    if (settings.skipHtml && isHtmlLike(url)) return true;
    return false;
  }

  /// 候选列表过滤：排除表 / SkipHtml / 非接管扩展名一律剔除。
  function filterOfferItems(settings, items) {
    const list = Array.isArray(items) ? items : [];
    const kept = list.filter((it) => {
      const url = it && it.url;
      if (shouldSkipUrl(settings, url)) return false;
      return isCatchableExt(settings, url);
    });
    return { items: kept, dropped: list.length - kept.length };
  }

  /// 「不接管 / 强制接管」支持跟踪的键。
  ///
  /// content script（`lib/hotkey_state.js`）直接引用这个常量来决定跟踪哪些键，
  /// 两边因此不会漂移——它只跟踪这几个键的按下状态，别的输入一概不碰。
  const HOTKEY_KEYS = ["ctrl", "alt", "shift", "del", "ins"];

  /// 修饰键 / 单键组合是否命中"不接管 / 强制接管"规则。
  ///
  /// `mods` 形如 `{ctrl:true, alt:false, shift:false, del:false, ins:false}`；
  /// `del` / `ins` 表示点击时按住的正是 Delete / Insert 键——默认规则就是这两个，
  /// 用单键比用 Ctrl/Alt 更不容易和页面或浏览器自身快捷键打架。
  function hotkeyDecision(settings, mods) {
    const keys = HOTKEY_KEYS;
    const active = !mods ? [] : keys.filter((k) => !!mods[k]).sort();
    const norm = (raw) =>
      String(raw || "")
        .split("+")
        .map((s) => s.trim().toLowerCase())
        .filter((s) => keys.includes(s))
        .sort();
    const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
    const prevent = norm(settings.hotkeyPrevent);
    const force = norm(settings.hotkeyForce);
    if (force.length && same(active.slice().sort(), force)) return "force";
    if (prevent.length && same(active.slice().sort(), prevent)) return "prevent";
    return "default";
  }

  const api = {
    HOST_NAME,
    DEFAULT_EXT_ID,
    OFFER_ITEM_LIMIT,
    FALLBACK_CODES,
    MSG,
    deriveFilename,
    addFieldTooLong,
    truncateOfferItems,
    collectPageItems,
    collectPanelItems,
    classifyNativeResult,
    shouldFallbackToBrowser,
    userMessage,
    offerMessage,
    openUiMessage,
    panelStatusAction,
    statusMessage,
    // 设置驱动的接管判定
    DEFAULT_CATCH_EXTS,
    DEFAULT_PANEL_EXTS,
    urlHost,
    hostMatches,
    hostListOf,
    extListOf,
    extOfUrl,
    normalizeSettings,
    hostExcluded,
    panelHostExcluded,
    isCatchableExt,
    extInList,
    extOfName,
    shouldTakeOverDownload,
    cookieHeader,
    isHtmlLike,
    shouldSkipUrl,
    filterOfferItems,
    HOTKEY_KEYS,
    hotkeyDecision,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.aidmLogic = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
