"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const logic = require("../lib/logic.js");

test("filename derivation", () => {
  assert.equal(logic.deriveFilename(null, "https://cdn.example/a/pkg-1.2.zip?x=1"), "pkg-1.2.zip");
  assert.equal(logic.deriveFilename("mine.bin", "https://cdn.example/other.zip"), "mine.bin");
  assert.equal(logic.deriveFilename(null, "https://cdn.example/%E4%B8%AD.bin"), "中.bin");
  assert.equal(logic.deriveFilename(null, "https://cdn.example/"), "download.bin");
  assert.equal(logic.deriveFilename("  ", "https://x/"), "download.bin");
  assert.equal([...logic.deriveFilename("a".repeat(300), "https://x/a")].length, 255);
});

test("collectPageItems is self-contained", () => {
  assert.equal(typeof logic.collectPageItems, "function");
  assert.equal(logic.collectPageItems.length, 0);
});

test("collectPanelItems keeps media and only panel-extension links", () => {
  const s = logic.normalizeSettings({ "browser.panel_exts": "mp4 mp3" });
  const fakeDoc = (nodes) => ({
    baseURI: "https://page.example/dir/",
    querySelectorAll: (sel) => nodes[sel] || [],
  });
  const nodes = {
    "video[src], audio[src]": [
      { src: "https://cdn.example/v.mp4", currentSrc: "", tagName: "VIDEO" },
      { src: "https://cdn.example/a.mp3", currentSrc: "", tagName: "AUDIO" },
      { src: "blob:https://x/1", currentSrc: "", tagName: "VIDEO" },
    ],
    "video source[src], audio source[src]": [],
    "a[href]": [
      { href: "https://cdn.example/file.mp4" },
      { href: "https://cdn.example/page.html" },
      { href: "https://cdn.example/v.mp4" },
    ],
  };
  const items = logic.collectPanelItems(s, fakeDoc(nodes));
  assert.deepEqual(
    items.map((i) => i.url),
    ["https://cdn.example/v.mp4", "https://cdn.example/a.mp3", "https://cdn.example/file.mp4"]
  );
  assert.equal(items[0].kind, "video");
  assert.equal(items[1].kind, "audio");
  assert.equal(items[2].kind, "link");
});

test("collectPanelItems resolves relative urls and drops non-http", () => {
  const s = logic.normalizeSettings({ "browser.panel_exts": "mp4" });
  const fakeDoc = (nodes) => ({
    baseURI: "https://page.example/dir/",
    querySelectorAll: (sel) => nodes[sel] || [],
  });
  const items = logic.collectPanelItems(
    s,
    fakeDoc({
      "video[src], audio[src]": [],
      "video source[src], audio source[src]": [],
      "a[href]": [{ href: "clip.mp4" }, { href: "mailto:a@b.c" }, { href: "data:video/mp4;base64,AA" }],
    })
  );
  assert.deepEqual(items.map((i) => i.url), ["https://page.example/dir/clip.mp4"]);
});

test("hotkey content script records pressed keys and answers queries", () => {
  const vm = require("node:vm");
  const fsx = require("node:fs");
  const px = require("node:path");
  const root = px.join(__dirname, "..");

  const winListeners = {};
  const msgListeners = [];
  const sandbox = { console, URL, setTimeout, clearTimeout, module: undefined };
  sandbox.globalThis = sandbox;
  const win = {
    addEventListener: (t, fn) => {
      (winListeners[t] = winListeners[t] || []).push(fn);
    },
  };
  win.top = win;
  win.self = win;
  sandbox.window = win;
  sandbox.document = {
    addEventListener: () => {},
    hidden: false,
    readyState: "complete",
    baseURI: "https://page.example/",
    querySelectorAll: () => [],
    getElementById: () => null,
    createElement: () => ({
      style: {},
      classList: { toggle() {}, add() {}, remove() {} },
      addEventListener() {},
      append() {},
      appendChild() {},
      setAttribute() {},
    }),
    body: { appendChild() {} },
    documentElement: { appendChild() {} },
  };
  const sent = [];
  sandbox.chrome = {
    runtime: {
      onMessage: { addListener: (fn) => msgListeners.push(fn) },
      sendMessage: (m, cb) => {
        sent.push(m);
        if (cb) cb(null);
      },
      lastError: null,
    },
  };

  const ctx = vm.createContext(sandbox);
  for (const f of ["lib/logic.js", "lib/hotkey_state.js"]) {
    vm.runInContext(fsx.readFileSync(px.join(root, f), "utf8"), ctx, { filename: f });
  }
  assert.ok(sandbox.aidmLogic, "logic.js 应在隔离世界里挂上 aidmLogic");
  assert.equal(msgListeners.length, 1, "应注册一个 onMessage 监听");

  const press = (type, ev) => (winListeners[type] || []).forEach((fn) => fn(ev));
  // content script 在 vm 的独立 realm 里建对象，原型与主 realm 不同，
  // deepStrictEqual 会因为原型不一致而失败——展开成主 realm 的普通对象再比。
  const askFrom = (source) => {
    let got = null;
    msgListeners[0]({ type: "hotkey-state", source }, {}, (r) => {
      got = r;
    });
    return got && got.mods ? { mods: { ...got.mods }, from: got.from } : null;
  };
  const ask = (source) => {
    const r = askFrom(source);
    return r ? r.mods : null;
  };
  const none = { ctrl: false, alt: false, shift: false, del: false, ins: false };

  assert.deepEqual(ask(), none, "初始应什么都没按");
  press("keydown", { key: "Delete", ctrlKey: false, altKey: false, shiftKey: false });
  assert.equal(ask().del, true, "按住 Delete 应被记录");
  press("keydown", { key: "Shift", ctrlKey: false, altKey: false, shiftKey: true });
  assert.deepEqual(ask(), { ctrl: false, alt: false, shift: true, del: true, ins: false });
  press("keyup", { key: "Delete", ctrlKey: false, altKey: false, shiftKey: true });
  assert.equal(ask().del, false, "松开 Delete 应清掉");
  (winListeners.blur || []).forEach((fn) => fn({}));
  assert.deepEqual(ask(), none, "失焦应清空，否则会一直「按住」");

  // 带修饰键的点击要主动上报（跨标签），普通点击一律不上报
  sent.length = 0;
  press("keydown", { key: "Control", ctrlKey: true, altKey: false, shiftKey: false });
  press("click", {});
  assert.equal(sent.length, 1, "按住键的点击应上报一次");
  assert.equal(sent[0].type, "hotkey-gesture");
  assert.equal(sent[0].mods.ctrl, true);
  press("keyup", { key: "Control", ctrlKey: false, altKey: false, shiftKey: false });
  sent.length = 0;
  press("click", {});
  assert.equal(sent.length, 1, "松开后的第一次点击必须上报，否则上一次的按住状态会赖着不走");
  assert.equal(sent[0].mods.ctrl, false);
  sent.length = 0;
  press("click", {});
  assert.equal(sent.length, 0, "状态没变且刚报过：连点不重复上报");

  // 点击快照：点击时按着 Ctrl，点完松开，点击路径仍应看到 Ctrl
  press("keydown", { key: "Control", ctrlKey: true, altKey: false, shiftKey: false });
  press("click", {});
  press("keyup", { key: "Control", ctrlKey: false, altKey: false, shiftKey: false });
  assert.equal(askFrom("click").mods.ctrl, true, "点击路径用点击那一刻的快照");
  assert.equal(askFrom("click").from, "click");
  assert.equal(ask().ctrl, false, "实时状态已经松开");

  // 右键菜单快照：菜单弹出时按着 Ctrl，点菜单项前松手，菜单路径仍应看到 Ctrl
  press("keydown", { key: "Control", ctrlKey: true, altKey: false, shiftKey: false });
  (winListeners.contextmenu || []).forEach((fn) => fn({}));
  press("keyup", { key: "Control", ctrlKey: false, altKey: false, shiftKey: false });
  assert.equal(askFrom("menu").mods.ctrl, true, "菜单路径用菜单弹出那一刻的快照");
  assert.equal(askFrom("menu").from, "menu");
  assert.equal(ask().ctrl, false, "实时状态仍是松开的");
});

test("hotkey decision flows from recorded keys to prevent/force", () => {
  // 端到端把两段拼起来：content script 记录的键 → hotkeyDecision 的判定。
  // 单独测任一段都发现不了"键名对不上"这类断链。
  const s = logic.normalizeSettings(null); // 默认 del=prevent, ins=force
  const modsOf = (ev) => ({ ctrl: !!ev.ctrlKey, alt: !!ev.altKey, shift: !!ev.shiftKey, del: ev.key === "Delete", ins: ev.key === "Insert" });
  assert.equal(logic.hotkeyDecision(s, modsOf({ key: "Delete" })), "prevent");
  assert.equal(logic.hotkeyDecision(s, modsOf({ key: "Insert" })), "force");
  assert.equal(logic.hotkeyDecision(s, modsOf({ key: "a" })), "default");
});

test("user-set prevent=ctrl with force cleared still prevents", () => {
  // 线上实际出现过的组合：把"不接管"改成 ctrl、"强制接管"留空（值是空串，
  // 不是缺失——`pick` 只在 null 时才回落默认值）。
  const s = logic.normalizeSettings({
    "browser.hotkey_prevent": "ctrl",
    "browser.hotkey_force": "",
  });
  assert.equal(s.hotkeyPrevent, "ctrl");
  assert.equal(s.hotkeyForce, "");
  assert.equal(logic.hotkeyDecision(s, { ctrl: true }), "prevent");
  assert.equal(logic.hotkeyDecision(s, { ctrl: false }), "default");
  // 空串不能变成"任意组合都算强制接管"
  assert.equal(logic.hotkeyDecision(s, { alt: true }), "default");
  assert.equal(logic.hotkeyDecision(s, {}), "default");
});

test("offer truncate at 500", () => {
  const items = Array.from({ length: 501 }, (_, i) => ({ url: "https://e/" + i, kind: "link" }));
  const cut = logic.truncateOfferItems(items);
  assert.equal(cut.items.length, 500);
  assert.equal(cut.truncated, true);
  const small = logic.truncateOfferItems(items.slice(0, 3));
  assert.equal(small.truncated, false);
});

test("fallback only on explicit allowlist codes", () => {
  assert.equal(logic.shouldFallbackToBrowser({ type: "accepted" }), false);
  assert.equal(logic.shouldFallbackToBrowser({ type: "unknown" }), false);
  assert.equal(logic.shouldFallbackToBrowser({ type: "disconnected" }), false);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "unsupported_scheme" }), true);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "engine_unreachable" }), true);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "not_allowed" }), true);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "bad_url" }), true);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "disabled" }), true);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "too_long" }), false);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "ui_not_running" }), false);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "offer_expired" }), false);
  assert.equal(logic.shouldFallbackToBrowser({ type: "explicit", code: "mystery" }), false);
});

test("classify native result", () => {
  assert.equal(logic.classifyNativeResult("Specified native messaging host not found.", undefined).type, "disconnected");
  assert.equal(logic.classifyNativeResult(null, { ok: true, id: 1 }).type, "accepted");
  assert.deepEqual(logic.classifyNativeResult(null, { ok: false, code: "disabled" }), {
    type: "explicit",
    code: "disabled",
  });
  assert.equal(logic.classifyNativeResult(null, undefined).type, "unknown");
  assert.equal(logic.classifyNativeResult(null, { hello: true }).type, "unknown");
});

test("user messages", () => {
  assert.equal(logic.userMessage({ type: "explicit", code: "ui_not_running" }), "请先打开 AIDM");
  assert.equal(
    logic.userMessage({ type: "explicit", code: "disabled" }),
    "浏览器集成已在 AIDM 中关闭，已改用浏览器下载"
  );
  assert.equal(logic.userMessage({ type: "explicit", code: "offer_expired" }), "候选已过期，请在页面上重新收集");
  assert.equal(logic.userMessage({ type: "explicit", code: "engine_unreachable" }), "无法交给 AIDM，已改用浏览器下载");
  assert.equal(logic.userMessage({ type: "explicit", code: "unsupported_scheme" }), "无法交给 AIDM，已改用浏览器下载");
  assert.equal(logic.userMessage({ type: "explicit", code: "too_long" }), "链接过长，已改用浏览器下载");
  assert.equal(logic.userMessage({ type: "disconnected" }), "无法确认是否已交给 AIDM，请在 AIDM 列表中查看");
  assert.equal(logic.userMessage({ type: "unknown" }), "无法确认是否已交给 AIDM，请在 AIDM 列表中查看");
  assert.equal(logic.userMessage(null), "无法确认是否已交给 AIDM，请在 AIDM 列表中查看");
  assert.equal(logic.userMessage({ type: "accepted" }), "");
});

test("open UI failure messages", () => {
  assert.equal(logic.openUiMessage({ type: "accepted" }), "");
  assert.match(logic.openUiMessage({ type: "explicit", code: "ui_not_found" }), /未找到/);
  assert.match(logic.openUiMessage({ type: "explicit", code: "launch_failed" }), /无法启动/);
  assert.match(logic.openUiMessage({ type: "explicit", code: "ui_timeout" }), /正在启动/);
  assert.match(logic.openUiMessage({ type: "explicit", code: "not_allowed" }), /未授权/);
  assert.match(logic.openUiMessage({ type: "disconnected" }), /手动打开/);
  assert.match(logic.openUiMessage(null), /手动打开/);
});

test("panel status never lets per-second progress resurrect a faded hint", () => {
  const base = { pinned: false, state: "downloading", force: false };
  // 可见时的进度更新只换文字，不重置计时器。
  assert.equal(logic.panelStatusAction({ ...base, wasHidden: false }), "update");
  // 已经淡出/隐藏后，下载中的进度推送不得把提示复活。
  assert.equal(logic.panelStatusAction({ ...base, wasHidden: true }), "ignore");
  // 结束态允许重新冒泡一次。
  assert.equal(
    logic.panelStatusAction({ ...base, wasHidden: true, state: "done" }),
    "show-auto"
  );
  // 悬停强制显示；即使提示已隐藏也立刻出现并钉住。
  assert.equal(
    logic.panelStatusAction({ ...base, wasHidden: true, force: true }),
    "show-pinned"
  );
  assert.equal(
    logic.panelStatusAction({ ...base, wasHidden: false, force: true }),
    "show-pinned"
  );
});

test("offer collect messages never say browser fallback", () => {
  assert.equal(logic.offerMessage({ type: "explicit", code: "disabled" }), "浏览器集成已在 AIDM 中关闭");
  assert.equal(logic.offerMessage({ type: "explicit", code: "engine_unreachable" }), "无法交给 AIDM，请稍后重试");
  assert.equal(logic.offerMessage({ type: "disconnected" }), "无法交给 AIDM，请稍后重试");
  assert.ok(!logic.offerMessage({ type: "explicit", code: "disabled" }).includes("已改用浏览器下载"));
  assert.ok(!logic.offerMessage({ type: "explicit", code: "unsupported_scheme" }).includes("已改用浏览器下载"));
});

test("status query messages", () => {
  assert.equal(logic.statusMessage({ type: "disconnected" }, false), "未连接到 AIDM，请先打开 AIDM");
  assert.equal(logic.statusMessage({ type: "unknown" }, false), "未连接到 AIDM，请先打开 AIDM");
  assert.equal(logic.statusMessage({ type: "accepted" }, false), "AIDM 引擎未运行");
  assert.equal(logic.statusMessage({ type: "accepted" }, true), "");
  assert.equal(
    logic.statusMessage({ type: "explicit", code: "engine_unreachable" }, false),
    "AIDM 引擎未运行"
  );
  assert.equal(logic.MSG.ext_not_ready, "扩展未就绪，请重新打开此窗口");
  assert.equal(logic.MSG.collect_exception, "收集链接失败，请刷新页面后重试");
  assert.equal(logic.MSG.no_page_links, "当前页面没有可下载的链接");
});

test("classify reads only code not error text", () => {
  assert.deepEqual(logic.classifyNativeResult(null, { ok: false, error: "disabled", code: "too_long" }), {
    type: "explicit",
    code: "too_long",
  });
  assert.deepEqual(logic.classifyNativeResult(null, { ok: false, error: "disabled" }), {
    type: "explicit",
    code: "error",
  });
});

test("add field limits", () => {
  assert.equal(logic.addFieldTooLong("https://x/a", null, null, "a.bin"), false);
  assert.equal(logic.addFieldTooLong("u".repeat(8 * 1024 + 1), null, null, null), true);
  assert.equal(logic.addFieldTooLong("https://x", "r".repeat(8 * 1024 + 1), null, null), true);
  assert.equal(logic.HOST_NAME, "com.aidm.host");
  assert.equal(logic.DEFAULT_EXT_ID.length, 32);
  assert.deepEqual(logic.FALLBACK_CODES, [
    "unsupported_scheme",
    "not_allowed",
    "bad_url",
    "disabled",
    "engine_unreachable",
  ]);
});

// ---- 设置驱动的接管判定 ----

test("urlHost / extOfUrl basics", () => {
  assert.equal(logic.urlHost("https://CDN.Example.com:8443/a/b.iso?x=1"), "cdn.example.com");
  assert.equal(logic.urlHost("http://[::1]:8080/f"), "::1");
  assert.equal(logic.urlHost(""), "");
  assert.equal(logic.extOfUrl("https://a.com/b/c.ISO?x=1#z"), "iso");
  assert.equal(logic.extOfUrl("https://a.com/noext"), "");
});

test("host exclusion mirrors the engine wildcard rules", () => {
  const s = logic.normalizeSettings({
    "browser.exclude_hosts": "example.com, *.internal.test",
  });
  assert.equal(logic.hostExcluded(s, "https://example.com/a.bin"), true);
  assert.equal(logic.hostExcluded(s, "https://a.internal.test/a.bin"), true);
  assert.equal(logic.hostExcluded(s, "https://internal.test/a.bin"), true);
  assert.equal(logic.hostExcluded(s, "https://notinternal.test/a.bin"), false);
  assert.equal(logic.hostExcluded(s, "https://example.com.evil.net/a.bin"), false);
  // 不是 *. 前缀时只匹配自己
  assert.equal(logic.hostMatches("a.com", "b.a.com"), false);
});

test("normalizeSettings falls back to engine defaults", () => {
  const empty = logic.normalizeSettings(null);
  // 兜底清单必须与引擎 setting_spec 的默认值逐项一致（52 / 27 项）
  assert.equal(empty.autoCatchExts.length, 52, "接管扩展名条数");
  assert.equal(empty.panelExts.length, 27, "面板扩展名条数");
  assert.ok(empty.autoCatchExts.includes("iso"));
  assert.ok(empty.autoCatchExts.includes("r0*"), "通配项要保留");
  assert.ok(empty.panelExts.includes("ttml2"));
  assert.ok(!empty.panelExts.includes("vtt"), "VTT 在默认配置里是关闭的");
  assert.equal(empty.skipHtml, true);
  assert.equal(empty.panelEnabled, true);
  assert.equal(empty.monitorClipboard, false);
  const custom = logic.normalizeSettings({
    "browser.auto_catch_exts": ".ISO, zip",
    "browser.skip_html": "false",
    "browser.panel_enabled": "false",
    "browser.monitor_clipboard": "true",
  });
  assert.deepEqual(custom.autoCatchExts, ["iso", "zip"]);
  assert.equal(custom.skipHtml, false);
  assert.equal(custom.panelEnabled, false);
  assert.equal(custom.monitorClipboard, true);
});

test("shouldSkipUrl honours exclude list and skip_html", () => {
  const s = logic.normalizeSettings({ "browser.exclude_hosts": "*.microsoft.com" });
  assert.equal(logic.shouldSkipUrl(s, "https://update.microsoft.com/x.exe"), true);
  assert.equal(logic.shouldSkipUrl(s, "https://example.com/page.html"), true); // skip_html 默认开
  assert.equal(logic.shouldSkipUrl(s, "https://example.com/a.iso"), false);
  assert.equal(logic.shouldSkipUrl(s, "ftp://example.com/a.iso"), true);
  assert.equal(logic.shouldSkipUrl(s, ""), true);
  const noHtml = logic.normalizeSettings({ "browser.skip_html": "false" });
  assert.equal(logic.shouldSkipUrl(noHtml, "https://example.com/page.html"), false);
});

test("filterOfferItems keeps only catchable extensions", () => {
  const s = logic.normalizeSettings({});
  const items = [
    { url: "https://a.com/x.iso" },
    { url: "https://a.com/page.html" },
    { url: "https://a.com/video.mp4" },
    { url: "https://blocked.test/y.iso" },
    { url: "https://a.com/noext" },
  ];
  const withBlock = logic.normalizeSettings({ "browser.exclude_hosts": "blocked.test" });
  const r = logic.filterOfferItems(withBlock, items);
  assert.deepEqual(
    r.items.map((i) => i.url),
    ["https://a.com/x.iso", "https://a.com/video.mp4"]
  );
  assert.equal(r.dropped, 3);
  // 自定义扩展名清单生效
  const onlyZip = logic.normalizeSettings({ "browser.auto_catch_exts": "zip" });
  assert.equal(logic.filterOfferItems(onlyZip, items).items.length, 0);
});

test("hotkeyDecision distinguishes prevent from force", () => {
  const s = logic.normalizeSettings({
    "browser.hotkey_prevent": "ctrl",
    "browser.hotkey_force": "alt+shift",
  });
  assert.equal(logic.hotkeyDecision(s, { ctrl: true }), "prevent");
  assert.equal(logic.hotkeyDecision(s, { alt: true, shift: true }), "force");
  assert.equal(logic.hotkeyDecision(s, { ctrl: true, alt: true, shift: true }), "default");
  assert.equal(logic.hotkeyDecision(s, {}), "default");
  assert.equal(logic.hotkeyDecision(logic.normalizeSettings({}), { ctrl: true }), "default");
});

test("default hotkeys are single keys (Delete prevents, Insert forces)", () => {
  const s = logic.normalizeSettings(null);
  assert.equal(s.hotkeyPrevent, "del");
  assert.equal(s.hotkeyForce, "ins");
  assert.equal(logic.hotkeyDecision(s, { del: true }), "prevent");
  assert.equal(logic.hotkeyDecision(s, { ins: true }), "force");
  assert.equal(logic.hotkeyDecision(s, { ctrl: true }), "default");
  assert.equal(logic.hotkeyDecision(s, { del: true, ins: true }), "default");
});

test("hotkey content script tracks exactly the keys logic knows about", () => {
  assert.deepEqual(logic.HOTKEY_KEYS, ["ctrl", "alt", "shift", "del", "ins"]);
  const src = fs.readFileSync(path.join(__dirname, "..", "lib", "hotkey_state.js"), "utf8");
  // 必须引用常量，而不是自己抄一份键名清单——否则两边会漂移。
  assert.match(src, /aidmLogic\.HOTKEY_KEYS/);
  // `e.key` → 短名 的映射不得引入 logic 不认识的键。
  const mapped = [...src.matchAll(/^\s+(\w+):\s*"(\w+)",$/gm)].map((m) => m[2]);
  assert.ok(mapped.length > 0, "hotkey_state.js 应有 e.key 映射表");
  for (const name of mapped) {
    assert.ok(logic.HOTKEY_KEYS.includes(name), `hotkey_state.js 映射了未知键 ${name}`);
  }
});

test("force only bypasses the content-selection gates", () => {
  const s = logic.normalizeSettings({
    "browser.enabled": "true",
    "browser.click_takeover": "true",
    "browser.exclude_hosts": "blocked.com",
    "browser.auto_catch_exts": "zip",
  });
  const item = (over) =>
    Object.assign(
      { state: "in_progress", url: "https://blocked.com/a.zip", filename: "a.zip", mime: "application/zip" },
      over
    );
  // 排除表命中：普通情况不接管，「强制接管」越过它
  assert.equal(logic.shouldTakeOverDownload(s, item({}), "self"), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({}), "self", true), true);
  // 不在接管扩展名清单里：普通情况不接管，「强制接管」越过它
  const plain = item({ url: "https://ok.com/a.bin", filename: "a.bin" });
  assert.equal(logic.shouldTakeOverDownload(s, plain, "self"), false);
  assert.equal(logic.shouldTakeOverDownload(s, plain, "self", true), true);
  // 总开关 / 下载状态 / 防回环：任何热键都不越过
  const off = logic.normalizeSettings({ "browser.enabled": "false" });
  assert.equal(logic.shouldTakeOverDownload(off, item({}), "self", true), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({ state: "complete" }), "self", true), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({ byExtensionId: "self" }), "self", true), false);
});
test("browser downloads are taken over only for catchable, non-excluded, non-self items", () => {
  const s = logic.normalizeSettings({ "browser.auto_catch_exts": "iso zip r0*" });
  const item = (over) => Object.assign({ url: "https://cdn.example/a.iso", state: "in_progress", filename: "" }, over);
  assert.equal(logic.shouldTakeOverDownload(s, item({}), "self"), true);
  assert.equal(logic.shouldTakeOverDownload(s, item({ url: "https://x/get?id=1", filename: "C:\\D\\pack.r01" }), "self"), true);
  assert.equal(logic.shouldTakeOverDownload(s, item({ url: "https://x/a.pdf" }), "self"), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({ byExtensionId: "self" }), "self"), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({ state: "complete" }), "self"), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({ url: "blob:https://x/1", filename: "a.iso" }), "self"), false);
  assert.equal(logic.shouldTakeOverDownload(s, item({ finalUrl: "https://x/a.zip", url: "https://x/r" }), "self"), true);
  assert.equal(logic.shouldTakeOverDownload(s, item({ mime: "text/html", filename: "a.iso" }), "self"), false);
  const off = logic.normalizeSettings({ "browser.click_takeover": "false" });
  assert.equal(logic.shouldTakeOverDownload(off, item({}), "self"), false);
  const disabled = logic.normalizeSettings({ "browser.enabled": "false" });
  assert.equal(logic.shouldTakeOverDownload(disabled, item({}), "self"), false);
  const excluded = logic.normalizeSettings({ "browser.exclude_hosts": "*.example" });
  assert.equal(logic.shouldTakeOverDownload(excluded, item({}), "self"), false);
});

test("wildcard extensions and cookie header", () => {
  assert.equal(logic.extInList(["r0*", "zip"], "r05"), true);
  assert.equal(logic.extInList(["r0*", "zip"], "rar"), false);
  assert.equal(logic.extInList(["zip"], ""), false);
  assert.equal(logic.cookieHeader([{ name: "a", value: "1" }, { name: "b", value: "" }, {}]), "a=1; b=");
  assert.equal(logic.cookieHeader(null), "");
});
