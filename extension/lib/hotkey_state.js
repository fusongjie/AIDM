/* global aidmLogic */
// 常驻 content script：记住"这一刻按住了什么键"。
//
// 为什么必须放在页面里：MV3 的 service worker 读不到键盘状态，
// `chrome.contextMenus.onClicked` 的 info 与 downloads 的 item 也都不带修饰键。
// 本脚本只跟踪 `aidmLogic.HOTKEY_KEYS` 那几个键的按下/松开状态，
// 不读取、不记录、不外发任何其它输入；只有扩展自己发消息来问时才回答。
//
// 它运行在 content script 的隔离世界里，页面脚本既看不到 `aidmLogic`，
// 也看不到这里维护的状态。
(() => {
  const pressed = {};
  for (const k of aidmLogic.HOTKEY_KEYS) pressed[k] = false;

  function clear() {
    for (const k of aidmLogic.HOTKEY_KEYS) pressed[k] = false;
  }

  // `e.key` 的事件名 → 扩展内部短名。只列 HOTKEY_KEYS 里出现过的键。
  const KEY_NAMES = {
    Control: "ctrl",
    Alt: "alt",
    Shift: "shift",
    Delete: "del",
    Insert: "ins",
  };

  function sync(e, down) {
    // 修饰键以事件自带的状态位为准（规范要求 keyup 时它已更新），
    // 再用 `e.key` 兜一次：个别情况下事件只带 key 不带状态位。
    pressed.ctrl = !!e.ctrlKey;
    pressed.alt = !!e.altKey;
    pressed.shift = !!e.shiftKey;
    const named = KEY_NAMES[e.key];
    if (named && aidmLogic.HOTKEY_KEYS.indexOf(named) !== -1) pressed[named] = down;
  }

  window.addEventListener("keydown", (e) => sync(e, true), true);
  window.addEventListener("keyup", (e) => sync(e, false), true);
  // 失焦后收不到 keyup，必须清空，否则会一直"按住"。
  window.addEventListener("blur", clear, true);
  // 切走标签页时同理。
  document.addEventListener(
    "visibilitychange",
    () => {
      if (document.hidden) clear();
    },
    true
  );

  // 两类用户手势都必须在"发生的那一刻"快照按键，不能等真正要判定时再问实时状态：
  //
  //   menu  —— 右键菜单。在链接上按下右键时手还按着修饰键，但要真正点到菜单项
  //            就得松手去移动鼠标，等 `contextMenus.onClicked` 触发时键早松了。
  //   click —— 左键点击链接。浏览器要等响应头才知道文件名，
  //            `onDeterminingFilename` 可能几百毫秒后才触发，那时用户同样早松手。
  const GESTURE_MS = 5000;
  const snapshots = { menu: null, click: null };

  function takeSnapshot(kind) {
    const mods = {};
    for (const k of aidmLogic.HOTKEY_KEYS) mods[k] = pressed[k];
    snapshots[kind] = { at: Date.now(), mods };
  }

  window.addEventListener("contextmenu", () => takeSnapshot("menu"), true);
  window.addEventListener(
    "click",
    () => {
      takeSnapshot("click");
      reportGesture();
    },
    true
  );

  /// 把"这次点击时按着什么键"主动告诉 background。
  ///
  /// 为什么不能只靠"下载时回头问这个标签"：点下载链接时 Chrome 常常先开一个新标签
  /// 再把它关掉，`DownloadItem.tabId` 指向的正是那个短命标签——里面既没有按键记录
  /// （点击发生在原页面），content script 也可能来不及注入或已随标签消失。
  /// 主动上报与标签无关，因此不会漏。
  ///
  /// **松开也必须报**：只在"按着键"时上报的话，松手后的下一次点击不会更新状态，
  /// background 那边还留着上一次的按住快照，紧接着的下载仍会被判成"不接管"。
  /// 去重只按"状态没变且刚报过"来做，普通连点依旧零开销。
  let lastReportKey = null;
  let lastReportAt = 0;

  function reportGesture() {
    const mods = {};
    for (const k of aidmLogic.HOTKEY_KEYS) mods[k] = pressed[k];
    const key = aidmLogic.HOTKEY_KEYS.filter((k) => mods[k]).join("+");
    const now = Date.now();
    if (key === lastReportKey && now - lastReportAt < 1000) return;
    lastReportKey = key;
    lastReportAt = now;
    try {
      chrome.runtime.sendMessage({ type: "hotkey-gesture", mods });
    } catch {
      /* service worker 未就绪等：手势丢了就退回实时查询，不影响主流程 */
    }
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || msg.type !== "hotkey-state") return;
    const live = {};
    for (const k of aidmLogic.HOTKEY_KEYS) live[k] = pressed[k];
    // 只有 menu / click 这两种手势名会命中快照；其余（含 "live"）一律走实时状态。
    const snap = snapshots[msg.source];
    if (snap && Date.now() - snap.at < GESTURE_MS) {
      sendResponse({ mods: snap.mods, from: msg.source });
      return;
    }
    sendResponse({ mods: live, from: "live" });
  });
})();
