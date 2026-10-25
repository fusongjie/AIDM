/* global aidmLogic */
importScripts("lib/logic.js");

const HOST = aidmLogic.HOST_NAME;

// ---- 设置（只读）----
//
// 引擎把设置解析成一份快照；宿主只放行"接管相关"的白名单键
// （永远不含代理密码、路径这类敏感项），这里再归一化成扩展内部的形状。
// 有 TTL 缓存：设置改动不会主动推给扩展，30 秒内复用即可。
const SETTINGS_TTL_MS = 30 * 1000;
let settingsCache = null;
let settingsAt = 0;

async function loadSettings(force) {
  const now = Date.now();
  if (!force && settingsCache && now - settingsAt < SETTINGS_TTL_MS) return settingsCache;
  const { classified, response } = await callHost({ v: 1, op: "settings" });
  if (classified.type === "accepted" && response && response.settings) {
    settingsCache = aidmLogic.normalizeSettings(response.settings);
    settingsAt = now;
  } else if (!settingsCache) {
    // 拿不到就用引擎默认值，绝不因为设置读不到而拒绝接管
    settingsCache = aidmLogic.normalizeSettings(null);
    settingsAt = now;
  }
  return settingsCache;
}

// ---- 「按住时不接管 / 按住时强制接管」----
//
// MV3 的 service worker 读不到键盘状态，右键菜单与下载事件本身也不带修饰键，
// 所以按键由常驻 content script（`lib/hotkey_state.js`）在页面里记录，这里按需去问。
// 查不到时一律当 `default`：读不到按键就保持原有接管行为，绝不因此改变结果。

async function hotkeyModsFor(tabId, source) {
  if (tabId == null || tabId < 0) return null;
  try {
    // 只问主 frame：`all_frames` 曾让 iframe 里的实例也来应答，而按键事件不会
    // 跨 frame——先应答的那个可能报"什么都没按"，把热键整个吞掉。
    // `source: "menu"` 要的是"右键菜单弹出那一刻"的快照，而不是此刻的实时状态。
    const res = await chrome.tabs.sendMessage(
      tabId,
      { type: "hotkey-state", source: source || "live" },
      { frameId: 0 }
    );
    return res && res.mods ? { mods: res.mods, from: res.from || "live" } : null;
  } catch {
    // 没有 content script（chrome:// 页、扩展页、未授权的 file://）或页面已关闭
    return null;
  }
}

/// 最近一次「带修饰键的点击」——由 content script 主动上报，**跨标签**。
///
/// 点击下载链接时 Chrome 常先开一个新标签再关掉它，`DownloadItem.tabId` 指向的
/// 正是那个短命标签：里面没有按键记录（点击发生在原页面），content script 也可能
/// 来不及注入。所以这条路径不能靠"回头问标签"，只能靠主动上报。
const GESTURE_TTL_MS = 5000;
let lastGesture = null;

/// 最近一次热键查询的原始结果。
///
/// popup 打开时读它，用来回答"到底是没拿到按键，还是拿到了但判定不对"——
/// 这两种情况的修法完全不同，而失败时对外表现一模一样（都静默当 default）。
let lastHotkeyProbe = null;

async function hotkeyDecisionFor(tabId, settings, source) {
  const probed = await hotkeyModsFor(tabId, source);
  const mods = probed ? probed.mods : null;
  const decision = mods ? aidmLogic.hotkeyDecision(settings, mods) : "default";
  lastHotkeyProbe = {
    at: Date.now(),
    tabId: tabId == null ? null : tabId,
    mods,
    from: probed ? probed.from : null,
    decision,
    prevent: settings.hotkeyPrevent,
    force: settings.hotkeyForce,
  };
  return decision;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "aidm-download",
    title: "用 AIDM 下载",
    contexts: ["link", "video", "audio"],
  });
});

function nativeSend(payload) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (lastError, response) => {
      if (settled) return;
      settled = true;
      resolve({ lastError: lastError || null, response });
    };
    try {
      chrome.runtime.sendNativeMessage(HOST, payload, (response) => {
        const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : null;
        finish(err, response);
      });
    } catch {
      finish("disconnected", undefined);
    }
  });
}

async function callHost(payload) {
  const { lastError, response } = await nativeSend(payload);
  const classified = aidmLogic.classifyNativeResult(lastError, response);
  return { classified, response };
}

function browserDownload(url, filename) {
  return new Promise((resolve) => {
    const opts = { url };
    if (filename) opts.filename = filename;
    try {
      chrome.downloads.download(opts, () => resolve());
    } catch {
      resolve();
    }
  });
}

function setBadge(text, color) {
  chrome.action.setBadgeText({ text: text || "" });
  if (color) chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setTitle({ title: text ? text : "AIDM" });
}

/// 给某个页面发一条消息。页面已关、或那个页面没挂面板时静默丢弃。
function notifyPage(tabId, msg) {
  if (tabId == null || tabId < 0) return;
  try {
    chrome.tabs.sendMessage(tabId, msg, { frameId: 0 }, () => {
      void chrome.runtime.lastError;
    });
  } catch {
    /* 同上 */
  }
}

// ---- 下载进度跟踪（网页里点出来的下载）----
//
// 为什么必须用长连接：卡片要每秒刷新进度，而 `sendNativeMessage` 每次都新起一个
// 宿主进程（7 MB 上下），一秒一个进程不可接受。`connectNative` 让宿主常驻；代价
// 是请求必须串行——宿主的响应不带请求 id，并发会错配。
let nativePort = null;
let pendingResolve = null;

function ensurePort() {
  if (nativePort) return nativePort;
  try {
    const port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener((resp) => {
      const done = pendingResolve;
      pendingResolve = null;
      if (done) done(resp);
    });
    port.onDisconnect.addListener(() => {
      nativePort = null;
      const done = pendingResolve;
      pendingResolve = null;
      if (done) done(null);
    });
    nativePort = port;
  } catch {
    nativePort = null;
  }
  return nativePort;
}

function portAsk(payload) {
  const port = ensurePort();
  if (!port) return Promise.resolve(null);
  return new Promise((resolve) => {
    pendingResolve = resolve;
    try {
      port.postMessage(payload);
    } catch {
      pendingResolve = null;
      resolve(null);
    }
  });
}

const PROGRESS_MS = 1000;
/// 一小时还没结束就放弃跟踪，避免用户忘了关页面时永久轮询。
const WATCH_MAX_MS = 60 * 60 * 1000;

let watched = null;
/// 最近一次推给页面的进度。悬浮 UI 悬停时用它立即回显，不必等后台再查一遍。
let lastProgress = null;

function elapsedSecs() {
  return watched ? Math.round((Date.now() - watched.startedAt) / 1000) : 0;
}

function stopWatch() {
  if (watched && watched.timer) clearInterval(watched.timer);
  watched = null;
}

function pushProgress(payload) {
  if (!watched) return;
  lastProgress = { ...payload, taskId: watched.id, at: Date.now() };
  notifyPage(watched.tabId, { type: "aidm-progress", elapsed: elapsedSecs(), ...payload });
}

async function tickWatch() {
  if (!watched) return;
  if (Date.now() - watched.startedAt > WATCH_MAX_MS) {
    stopWatch();
    return;
  }
  const resp = await portAsk({ v: 1, op: "list" });
  if (!watched) return;
  const task = ((resp && resp.tasks) || []).find((t) => t && Number(t.id) === watched.id);
  if (!task) {
    // 列表里已经没有了：任务被清掉，或引擎重启过。按结束收尾，不再空转。
    pushProgress({ state: "gone", name: watched.name });
    stopWatch();
    return;
  }
  const done = Number(task.done) || 0;
  const total = task.total == null ? null : Number(task.total);
  const finished =
    task.state === "done" ||
    task.state === "completed" ||
    (total != null && total > 0 && done >= total);
  pushProgress({
    state: finished ? "done" : "downloading",
    done,
    total,
    name: task.name || watched.name,
  });
  if (finished) stopWatch();
}

/// 开始跟踪一个刚被接管的网页下载：先给卡片一个初值，再每秒刷新。
function startWatch(tabId, id, name) {
  if (tabId == null || tabId < 0 || id == null) return;
  stopWatch();
  watched = { id: Number(id), tabId, name: name || "", startedAt: Date.now(), timer: 0 };
  pushProgress({ state: "downloading", done: 0, total: null, name: watched.name });
  watched.timer = setInterval(() => {
    tickWatch().catch(() => {});
  }, PROGRESS_MS);
  tickWatch().catch(() => {});
}

/// 告诉发起页面"这次下载交给 AIDM 了"。
///
/// 只有网页里点出来的下载走这里；剪贴板来源的没有页面可通知（也不该通知），
/// 由主程序出声 + 出卡片。
function notifyPageTookOver(tabId, filename) {
  notifyPage(tabId, { type: "aidm-took-over", filename: filename || "" });
}

async function addWithFallback({ url, referrer, filename, notifyTabId }) {
  if (aidmLogic.addFieldTooLong(url, referrer, null, filename)) {
    const classified = { type: "explicit", code: "too_long" };
    setBadge("!", "#d73a49");
    await browserDownload(url, filename);
    chrome.action.setTitle({ title: aidmLogic.userMessage(classified) || "AIDM" });
    return { classified, message: aidmLogic.userMessage(classified) };
  }
  const { classified, response } = await callHost({
    v: 1,
    op: "add",
    url,
    referrer: referrer || undefined,
    filename: filename || undefined,
    // 透传浏览器 UA：下载器用它发请求，服务器看到的就是同一个客户端
    user_agent: browserUserAgent(),
  });
  const message = aidmLogic.userMessage(classified);
  if (aidmLogic.shouldFallbackToBrowser(classified)) {
    setBadge("!", "#d73a49");
    await browserDownload(url, filename);
  } else if (classified.type === "accepted") {
    setBadge("", null);
    notifyPageTookOver(notifyTabId, filename);
    startWatch(notifyTabId, response && response.id, filename);
  } else if (message) {
    setBadge("!", "#d73a49");
  }
  chrome.action.setTitle({ title: message || "AIDM" });
  return { classified, message };
}

/// 浏览器自己的 UA。service worker 里 `navigator.userAgent` 是浏览器 UA；
/// 取不到时返回 undefined（宿主会回落到设置里的 UA）。
function browserUserAgent() {
  try {
    const ua = self.navigator && self.navigator.userAgent;
    return ua ? String(ua) : undefined;
  } catch (_) {
    return undefined;
  }
}chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "aidm-download") return;
  const url = info.linkUrl || info.srcUrl;
  if (!url) return;
  const settings = await loadSettings(false);
  const decision = await hotkeyDecisionFor(tab && tab.id, settings, "menu");
  const filename = aidmLogic.deriveFilename(null, url);
  // 按住「不接管」键：连右键菜单都不抢，直接交回浏览器。
  if (decision === "prevent") {
    setBadge("", null);
    chrome.action.setTitle({ title: "按住「不接管」键，已改用浏览器下载" });
    await browserDownload(url, filename);
    return;
  }
  // 排除表 / SkipHtml：交回浏览器，不打扰引擎；「强制接管」键越过这一层。
  if (decision !== "force" && aidmLogic.shouldSkipUrl(settings, url)) {
    setBadge("", null);
    chrome.action.setTitle({ title: "该地址在排除列表里，已改用浏览器下载" });
    await browserDownload(url, filename);
    return;
  }
  const referrer = tab && tab.url ? tab.url : undefined;
  await addWithFallback({ url, referrer, filename, notifyTabId: tab && tab.id });
});

async function cookiesFor(url) {
  try {
    return aidmLogic.cookieHeader(await chrome.cookies.getAll({ url })) || undefined;
  } catch {
    return undefined;
  }
}

/// 浏览器下载在「确定文件名」阶段挂起，先问 AIDM：
/// 只有明确 accepted 才取消并抹掉浏览器这条下载；其余任何结果都让浏览器照常下载，
/// 宿主没装、AIDM 没开时浏览器下载不受影响。
async function takeOverBrowserDownload(item) {
  const settings = await loadSettings(false);
  // 点击链接触发的下载：优先用 content script 主动上报的点击手势（跨标签，与那个
  // 短命标签无关）；没有手势时才退回问发起标签的实时状态。
  let decision = "default";
  // 提示要发回"发起点击的那个页面"，而不是 item.tabId——后者常常指向 Chrome 为
  // 这次下载临时开出来的短命标签。
  let notifyTabId = item.tabId == null ? null : item.tabId;
  if (lastGesture && Date.now() - lastGesture.at < GESTURE_TTL_MS) {
    const gesture = lastGesture;
    // 一次性消费：一次点击只该影响它自己引发的那次下载。留着不放，下一次无键
    // 点击就会继续沿用上一次的"按住"快照——表现为"松手后还是走浏览器下载"。
    lastGesture = null;
    if (gesture.tabId != null) notifyTabId = gesture.tabId;
    decision = aidmLogic.hotkeyDecision(settings, gesture.mods);
    lastHotkeyProbe = {
      at: Date.now(),
      tabId: item.tabId == null ? null : item.tabId,
      mods: gesture.mods,
      from: "gesture",
      decision,
      prevent: settings.hotkeyPrevent,
      force: settings.hotkeyForce,
    };
  } else {
    decision = await hotkeyDecisionFor(item.tabId, settings, "click");
  }
  // 按住「不接管」键：这条下载是浏览器自己发起的，直接放行。
  if (decision === "prevent") return false;
  if (!aidmLogic.shouldTakeOverDownload(settings, item, chrome.runtime.id, decision === "force")) {
    return false;
  }
  const url = item.finalUrl || item.url;
  const filename = aidmLogic.deriveFilename(item.filename, url);
  const referrer = item.referrer || undefined;
  const cookies = await cookiesFor(url);
  if (aidmLogic.addFieldTooLong(url, referrer, cookies, filename)) return false;
  const { classified, response } = await callHost({
    v: 1,
    op: "add",
    url,
    referrer,
    filename,
    cookies,
    user_agent: browserUserAgent(),
  });
  if (classified.type !== "accepted") {
    const message = aidmLogic.userMessage(classified);
    if (message) {
      setBadge("!", "#d73a49");
      chrome.action.setTitle({ title: message });
    }
    return false;
  }
  setBadge("", null);
  notifyPageTookOver(notifyTabId, filename);
  startWatch(notifyTabId, response && response.id, filename);
  try {
    await chrome.downloads.cancel(item.id);
    await chrome.downloads.erase({ id: item.id });
  } catch {
    // 已经结束的下载无法取消；放行，避免它卡在「确定文件名」阶段
    return false;
  }
  return true;
}

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  takeOverBrowserDownload(item)
    .then((taken) => {
      if (!taken) suggest();
    })
    .catch(() => suggest());
  return true;
});

// ---- 页面 API 下载（MAIN world hook）----
//
// 城通等站点先 XHR `POST /api/v2/download` 拿签名地址，再用 Blob 触发浏览器下载。
// `downloads.onDeterminingFilename` 只能看到 `blob:`，拿不到真实 URL；这里由
// 页面主世界 hook 直接读取 API 响应，把 downurl 交给 AIDM。
const PAGE_API_SEEN_MS = 30_000;
const PAGE_API_BLOB_MS = 15_000;
const pageApiSeen = new Map();
const pageApiRecent = new Map();

async function handlePageApiDownload(msg, sender) {
  const url = String((msg && msg.url) || "");
  if (!/^https?:\/\//i.test(url)) return { ok: false, code: "bad_url" };
  const settings = await loadSettings(false);
  if (!settings.enabled) return { ok: false, code: "disabled" };

  const now = Date.now();
  for (const [key, at] of pageApiSeen) {
    if (now - at > PAGE_API_SEEN_MS) pageApiSeen.delete(key);
  }
  if (pageApiSeen.has(url)) return { ok: true, duplicate: true };
  pageApiSeen.set(url, now);

  const tabId = sender && sender.tab ? sender.tab.id : null;
  const rawName = String((msg && msg.filename) || "");
  const filename = rawName ? aidmLogic.deriveFilename(rawName, url) : undefined;
  const referer =
    String((msg && msg.referer) || "").slice(0, 2048) ||
    (sender && sender.tab && sender.tab.url) ||
    undefined;
  const cookies = await cookiesFor(url);
  if (aidmLogic.addFieldTooLong(url, referer, cookies, filename)) {
    return { ok: false, code: "too_long" };
  }
  const { classified, response } = await callHost({
    v: 1,
    op: "add",
    url,
    referrer: referer,
    filename,
    cookies,
    user_agent: browserUserAgent(),
  });
  if (classified.type !== "accepted") {
    const message = aidmLogic.userMessage(classified);
    if (message) {
      setBadge("!", "#d73a49");
      chrome.action.setTitle({ title: message });
    }
    return { ok: false, code: classified.code || "host_rejected" };
  }
  setBadge("", null);
  if (tabId != null && tabId >= 0) {
    pageApiRecent.set(tabId, { at: Date.now(), filename: filename || "" });
    notifyPageTookOver(tabId, filename || "");
    startWatch(tabId, response && response.id, filename || "");
  }
  return { ok: true, id: response && response.id };
}

// 页面 API 已交给 AIDM 后，浏览器可能紧接着生成一个 blob: 下载；取消它，
// 避免同一文件被浏览器和 AIDM 各下一遍。只处理最近 15 秒内同一标签的 blob/data。
chrome.downloads.onCreated.addListener((item) => {
  if (!item || item.tabId == null || item.tabId < 0) return;
  const recent = pageApiRecent.get(item.tabId);
  if (!recent || Date.now() - recent.at > PAGE_API_BLOB_MS) return;
  const scheme = String(item.url || "").toLowerCase();
  if (!scheme.startsWith("blob:") && !scheme.startsWith("data:")) return;
  pageApiRecent.delete(item.tabId);
  try {
    chrome.downloads.cancel(item.id, () => {
      chrome.downloads.erase({ id: item.id }, () => {});
    });
  } catch {}
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;
  if (msg.type === "page-api-download") {
    handlePageApiDownload(msg, sender)
      .then(sendResponse)
      .catch(() => sendResponse({ ok: false, code: "host_error" }));
    return true;
  }
  if (msg.type === "status") {
    callHost({ v: 1, op: "status" }).then(({ classified, response }) => {
      const engineOnline = !!(response && response.engine_online);
      sendResponse({
        classified,
        message: aidmLogic.statusMessage(classified, engineOnline),
        engine_online: engineOnline,
        active: response && response.active != null ? response.active : 0,
        host_ok: classified.type === "accepted",
      });
    });
    return true;
  }
  if (msg.type === "offer") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || tab.id == null) {
          sendResponse({ message: "无法读取当前标签页" });
          return;
        }
        const injected = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: aidmLogic.collectPageItems,
        });
        const page = (injected && injected[0] && injected[0].result) || {
          items: [],
          truncated: false,
          page_url: tab.url || "",
          title: tab.title || "",
        };
        // 候选先按设置过滤（排除的服务器、网页本身、扩展名清单），
        // 引擎侧还会再拦一次（双保险，引擎才是权威）。
        const settings = await loadSettings(false);
        const filtered = aidmLogic.filterOfferItems(settings, page.items);
        const cut = aidmLogic.truncateOfferItems(filtered.items);
        if (cut.items.length === 0) {
          sendResponse({
            classified: { type: "accepted" },
            message:
              filtered.dropped > 0
                ? `已按设置过滤掉 ${filtered.dropped} 个链接`
                : aidmLogic.MSG.no_page_links,
            offer_id: null,
            count: 0,
            truncated: false,
          });
          return;
        }
        const { classified, response } = await callHost({
          v: 1,
          op: "offer",
          page_url: page.page_url,
          title: page.title,
          items: cut.items,
        });
        sendResponse({
          classified,
          message: aidmLogic.offerMessage(classified),
          offer_id: response && response.offer_id,
          count: cut.items.length,
          truncated: cut.truncated || !!page.truncated,
        });
      } catch {
        sendResponse({ message: aidmLogic.MSG.collect_exception });
      }
    })();
    return true;
  }
  if (msg.type === "hotkey-gesture") {
    // content script 主动上报的点击手势；不需要回执。
    // 记下来源 tab：下载可能发生在 Chrome 临时开出的短命标签里，而用户实际在看、
    // 也该收到提示的是发起这次点击的页面。
    lastGesture = {
      at: Date.now(),
      mods: msg.mods || null,
      tabId: sender && sender.tab ? sender.tab.id : null,
    };
    return;
  }
  if (msg.type === "hotkey-probe") {
    // 纯读内存，同步回；service worker 刚处理过右键，不会被回收。
    sendResponse({ probe: lastHotkeyProbe });
    return true;
  }
  if (msg.type === "panel-status") {
    // 悬浮 UI 悬停时问一次「当前下载任务」。`watched` 是被跟踪的网页下载；
    // 它为空时还要问一次引擎，否则 AIDM 里手动添加的任务会被误报成"无任务"。
    if (!watched) {
      callHost({ v: 1, op: "status" })
        .then(({ classified, response }) => {
          const online = classified.type === "accepted" && response && response.engine_online;
          const active =
            classified.type === "accepted" && response ? Number(response.active) || 0 : 0;
          if (!online) {
            sendResponse({ task: { state: "notice", text: "AIDM 引擎未运行" } });
          } else if (active > 0) {
            sendResponse({
              task: { state: "notice", text: "AIDM 正在下载 " + active + " 个任务" },
            });
          } else {
            sendResponse({ task: { state: "idle" } });
          }
        })
        .catch(() => sendResponse({ task: { state: "idle" } }));
      return true;
    }
    const fresh = lastProgress && lastProgress.taskId === watched.id ? lastProgress : null;
    sendResponse({
      task: {
        state: "downloading",
        name: (fresh && fresh.name) || watched.name || "下载",
        done: fresh && fresh.done != null ? fresh.done : 0,
        total: fresh ? fresh.total : null,
        elapsed: elapsedSecs(),
      },
    });
    return true;
  }
  if (msg.type === "open-aidm") {
    // 点击悬浮圆钮：由原生宿主找到 AIDM 主窗口并置顶；没在运行就启动它。
    callHost({ v: 1, op: "show_ui" })
      .then(({ classified }) => {
        sendResponse({
          ok: classified.type === "accepted",
          code: classified.code || null,
          message: aidmLogic.openUiMessage(classified),
        });
      })
      .catch(() => sendResponse({ ok: false, message: aidmLogic.MSG.uncertain }));
    return true;
  }
  if (msg.type === "panel-settings") {
    // 悬浮面板每次展开都会问一次。设置本身已有 30 秒 TTL 缓存，这里不再加一层。
    loadSettings(false)
      .then((s) => sendResponse({ settings: s }))
      .catch(() => sendResponse({ settings: null }));
    return true;
  }
  if (msg.type === "panel-add") {
    const url = String(msg.url || "");
    if (!url) {
      sendResponse({ ok: false, code: "bad_url" });
      return true;
    }
    // 走和右键菜单同一条路：引擎拒绝时按既有规则回落到浏览器下载。
    addWithFallback({
      url,
      referrer: msg.referrer || undefined,
      filename: msg.filename || undefined,
      notifyTabId: sender && sender.tab ? sender.tab.id : null,
    })
      .then(({ classified }) =>
        sendResponse({ ok: classified.type === "accepted", code: classified.code || null })
      )
      .catch(() => sendResponse({ ok: false, code: "error" }));
    return true;
  }
});
