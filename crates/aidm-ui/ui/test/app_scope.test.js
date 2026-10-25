"use strict";
// 守护性测试：app.js 里位于 IIFE 顶层的函数，必须真的在 IIFE 顶层可见。
//
// 背景（真实故障）：块级 `function` 声明在非严格模式下有 Annex B 兼容语义
// （会在外层函数作用域建一个 var 绑定），但**块级 `async function` 声明没有**。
// 所以一旦某个 async 函数被无意关进块里（例如 `if (listen) { ... }` 少了一个
// 右花括号），块外调用它就会抛 `ReferenceError`，表现为按钮"点了没反应"。
//
// 这里用 vm 在无 DOM 环境里只跑到 IIFE 入口（函数声明已提升），检查名字是否可见。

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");

const UI_DIR = path.join(__dirname, "..");

/// IIFE 顶层必须有名字（顺序按 app.js 中出现位置）
const TOP_LEVEL_FUNCTIONS = [
  "collectSettingsForm",
  "fillSettingsForm",
  "applySettings",
  "maybePlayErrorSound",
  "updateQuotaBoxes",
  "updateWindowBoxes",
  "loadSettingsSchema",
  "addHostConn",
  "removeHostConn",
  "hostConnError",
];

function probeTopLevel(source, names) {
  const marker = "(function () {";
  assert.equal(
    source.includes(marker),
    true,
    "app.js 应仍以 (function () { 包裹；若换了写法，请同步更新本测试"
  );
  const probed = source.replace(
    marker,
    `${marker}
  window.__scopeProbe = {};
  for (const n of ${JSON.stringify(names)}) {
    try { window.__scopeProbe[n] = eval("typeof " + n); }
    catch (e) { window.__scopeProbe[n] = "throw:" + e.name; }
  }`
  );

  const sandbox = {
    console,
    setTimeout: () => 1,
    clearTimeout: () => {},
    setInterval: () => 1,
    clearInterval: () => {},
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.document = {
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
  };

  try {
    vm.runInNewContext(probed, sandbox, { filename: "app.js" });
  } catch {
    // 没有真实 DOM，IIFE 后面必然抛错；入口探针已经跑完了，忽略即可
  }
  return sandbox.__scopeProbe || {};
}

test("app.js: 这些函数必须在 IIFE 顶层可见（防止 async 函数被关进块里）", () => {
  const src = fs.readFileSync(path.join(UI_DIR, "app.js"), "utf8");
  const probe = probeTopLevel(src, TOP_LEVEL_FUNCTIONS);
  const hidden = TOP_LEVEL_FUNCTIONS.filter((n) => probe[n] !== "function");
  assert.deepEqual(
    hidden,
    [],
    "以下函数不在 IIFE 顶层（多半是被误关进了某个块，块外调用会 ReferenceError）：" +
      hidden.map((n) => `${n}=${probe[n]}`).join(", ")
  );
});

test("app.js: 设置对话框的「确定」入口与它依赖的 schema 取数器同层", () => {
  const src = fs.readFileSync(path.join(UI_DIR, "app.js"), "utf8");
  const probe = probeTopLevel(src, ["applySettings", "loadSettingsSchema"]);
  assert.equal(probe.applySettings, "function");
  assert.equal(
    probe.loadSettingsSchema,
    "function",
    "applySettings 里的 await loadSettingsSchema() 会抛 ReferenceError，确定按钮将无声失效"
  );
});

test("app.js: magnet 只放行带合法 BTIH 的链接", () => {
  const src = fs.readFileSync(path.join(UI_DIR, "app.js"), "utf8");
  const marker = "(function () {";
  const probed = src.replace(
    marker,
    `${marker}
  window.__magnetProbe = [
    validateDownloadUrl("magnet:?xt=urn:btih:0123456789012345678901234567890123456789"),
    validateDownloadUrl("magnet:?dn=no-hash")
  ];`
  );
  const sandbox = { console, setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {} };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.document = { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
  try {
    vm.runInNewContext(probed, sandbox, { filename: "app.js" });
  } catch {
    // 入口探针执行后，后续 DOM 初始化会在桩环境报错。
  }
  assert.equal(sandbox.__magnetProbe[0].ok, true);
  assert.equal(sandbox.__magnetProbe[0].bittorrent, true);
  assert.equal(sandbox.__magnetProbe[1].ok, false);
});
