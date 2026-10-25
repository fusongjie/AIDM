"use strict";

// 设置页接线校验：把"漏接线"从"用户发现界面是空的"变成"测试直接失败"。
//
// 背景：时段 / 配额 / 完成后动作 / 重复链接四组控件只加进 index.html、
// 没有补进 fillSettingsForm / collectSettingsForm 时，界面永远显示为空、值也存不回去。
// 这个测试机械地比对三份文件：
//   index.html（有哪些控件） ↔ app.js 的 fill（回填）与 collect（收集）
// 只有明确列在 ALLOWLIST 里、并且写明理由的控件才允许不接线。

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const UI_DIR = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(UI_DIR, "index.html"), "utf8");
const app = fs.readFileSync(path.join(UI_DIR, "app.js"), "utf8");

/// 设置对话框区域：`#set-mask` 的开标签之后，到下一个对话框之前。
function settingsDialogHtml() {
  const start = html.indexOf('id="set-mask"');
  assert.ok(start > 0, "index.html 里找不到 #set-mask");
  const openEnd = html.indexOf(">", start) + 1;
  const next = html.indexOf('class="dlg-mask', openEnd);
  return next > openEnd ? html.slice(openEnd, next) : html.slice(openEnd);
}

/// 对话框里所有"会存值的控件"的 id（排除按钮与纯展示元素）。
function controlIds() {
  const dialog = settingsDialogHtml();
  const ids = new Set();
  const tagRe = /<(input|select|textarea)\b[^>]*>/g;
  let m;
  while ((m = tagRe.exec(dialog)) !== null) {
    const tag = m[0];
    if (/type\s*=\s*"button"/i.test(tag)) continue;
    const idm = /id\s*=\s*"([^"]+)"/.exec(tag);
    if (!idm) continue;
    ids.add(idm[1]);
  }
  return ids;
}

/// 去掉注释后再比对：否则"某行被注释掉"仍然能匹配到 id 字符串，
/// 测试就变成空跑（这一点是实测出来的）。
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    // 只剥"前面是空白"的 //，避免误伤 https:// 这类字面量
    .replace(/(^|\s)\/\/[^\n]*/g, "$1");
}

function functionBody(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start > 0, `app.js 里找不到 ${name}`);
  // 取到下一个顶层函数/常量的缩进级别（两个空格）收尾为止
  const rest = app.slice(start);
  const end = rest.search(/\n  (?:async )?function |\n  \/\* ----/);
  return stripComments(end > 0 ? rest.slice(0, end) : rest);
}

/// 这些控件由别的路径处理，或本来就不需要接线（理由必须写清楚）。
const ALLOWLIST = new Map([
  ["set-meta-dir", "只读展示，保存时不提交（引擎自管元数据目录）"],
  ["set-proxy-pass", "密码单独走 passActionFromForm（清空/不改/新值三态）"],
  ["set-sched-on", "定时启动走 fillSchedForm / collectSchedCron（模式+时间合成 cron）"],
  ["set-sched-time", "同上，由定时模式控件驱动"],
  ["set-sched-cron", "同上，自定义模式下才提交"],
  ["ext-id-new", "输入框，由“添加”按钮消费后写入 browser.allowed_ext_ids"],
  ["host-conn-host", "输入框，由“添加”按钮消费后走 host_conns_set"],
  ["host-conn-max", "同上"],
  ["host-conn-limit", "同上"],
  ["site-login-host", "输入框，由“添加”按钮消费后走 site_logins_set"],
  ["site-login-user", "同上"],
  ["site-login-pass", "同上（只在写入时读取，列表永不回显密码）"],
]);

test("every settings control is wired into fill and collect", () => {
  const ids = controlIds();
  assert.ok(ids.size >= 40, `设置控件太少，解析可能出错：${ids.size}`);

  const fill = functionBody("fillSettingsForm");
  const collect = functionBody("collectSettingsForm");

  const missingFill = [];
  const missingCollect = [];
  for (const id of ids) {
    if (ALLOWLIST.has(id)) {
      // 允许例外，但必须真的在别处被引用，避免"假例外"
      assert.ok(
        app.includes(`"${id}"`),
        `${id} 被列入例外却完全没被引用（应改成正常接线或删掉控件）`
      );
      continue;
    }
    if (!fill.includes(`"${id}"`)) missingFill.push(id);
    if (!collect.includes(`"${id}"`)) missingCollect.push(id);
  }
  assert.deepEqual(missingFill, [], `这些控件没有回填默认值/当前值：${missingFill.join(", ")}`);
  assert.deepEqual(missingCollect, [], `这些控件没有收集进保存：${missingCollect.join(", ")}`);
});

test("every collected setting key is declared in the engine schema", () => {
  // 收集表里的键必须都是引擎声明过的键，否则保存时必然 unknown_setting_key。
  // 这里用 setting_spec.rs 作为事实源（UI 不该凭空造键）。
  const spec = fs.readFileSync(
    path.join(UI_DIR, "..", "..", "aidm-core", "src", "setting_spec.rs"),
    "utf8"
  );
  const collect = functionBody("collectSettingsForm");
  const keys = [...collect.matchAll(/"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"\s*:/g)].map(
    (m) => m[1]
  );
  assert.ok(keys.length >= 20, `解析到的键太少：${keys.length}`);
  const missing = keys.filter((k) => !spec.includes(`"${k}"`));
  assert.deepEqual(missing, [], `这些键在 setting_spec 里不存在：${missing.join(", ")}`);
});

test("every schema key with a default is exposed somewhere in the dialog", () => {
  // 反向检查：引擎声明了、但设置页里没有任何控件能改的键，要么补界面，
  // 要么明确列在这里说明"由别处处理/故意不给改"。
  const spec = fs.readFileSync(
    path.join(UI_DIR, "..", "..", "aidm-core", "src", "setting_spec.rs"),
    "utf8"
  );
  const NOT_IN_DIALOG = new Set([
    "paths.metadata_dir", // 只读展示
    "settings.revision", // 只读展示
    "update.last_check_at", // 只读展示
    "app.version", // 只读展示
    "proxy.has_password", // 只读展示
    "proxy.pass", // 单独走密码三态
    "sched.start_cron", // 由模式+时间合成
    "net.user_agent", // 高级页里有控件（下面按 id 判定，不是键名）
  ]);
  const dialog = settingsDialogHtml();
  const collect = functionBody("collectSettingsForm");
  const keys = [...collect.matchAll(/"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"\s*:/g)].map(
    (m) => m[1]
  );
  const specKeys = [...spec.matchAll(/^\s{4}"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)",$/gm)].map(
    (m) => m[1]
  );
  const missing = specKeys.filter(
    (k) => !keys.includes(k) && !NOT_IN_DIALOG.has(k) && !dialog.includes(`data-err="${k}"`)
  );
  // `data-err` 只出现在报错槽上，所以再用一条更直接的判据兜底：
  const reallyMissing = missing.filter((k) => !collect.includes(k));
  assert.deepEqual(
    reallyMissing,
    [],
    `这些键在设置页里没有任何入口：${reallyMissing.join(", ")}`
  );
});

test("fill reads each control's value from its own settings key", () => {
  // 光看 id 出现还不够：控件可能填的是别的键（复制粘贴最容易犯）。
  // 这里从 collect 反推 id→key，再要求 fill 里确实读取了同一个键。
  const collect = functionBody("collectSettingsForm");
  const pairs = [
    ...collect.matchAll(
      /"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"\s*:\s*document\.getElementById\("([^"]+)"\)/g
    ),
  ].map((m) => ({ key: m[1], id: m[2] }));
  assert.ok(pairs.length >= 30, `从 collect 反推到的控件太少：${pairs.length}`);

  const fill = functionBody("fillSettingsForm");
  const missing = [];
  for (const { key, id } of pairs) {
    // 布尔项写成 settingBool(s["key"])，数值项写成 settingStr(s["key"])，
    // 两种都要求出现 s["key"]（fill 里 settingsCache 的别名是 s）。
    if (!fill.includes(`s["${key}"]`)) missing.push(`${key}（控件 ${id}）`);
  }
  assert.deepEqual(missing, [], `fill 没有从这些键读值，界面会显示为空：${missing.join(", ")}`);
});

test("controls that imply a dependency toggle each other's availability", () => {
  // 启用了才让填：时段与配额的子项在未启用时应为 disabled（避免"填了不生效"）。
  const app2 = app;
  for (const [master, children] of [
    ["updateWindowBoxes", ["set-window-start", "set-window-end", "set-window-days"]],
    ["updateQuotaBoxes", ["set-quota-mb", "set-quota-period", "set-quota-action"]],
  ]) {
    const body = functionBody(master);
    for (const child of children) {
      assert.ok(
        body.includes(`"${child}"`),
        `${master} 应当控制 ${child} 的可用性（否则未启用时还能填，容易误解）`
      );
    }
  }
  // 两者的初值也要在 fill 之后同步一次
  assert.ok(app2.includes("updateWindowBoxes();"), "fillSettingsForm 应调用 updateWindowBoxes");
  assert.ok(app2.includes("updateQuotaBoxes();"), "fillSettingsForm 应调用 updateQuotaBoxes");
  // 勾选/取消时也必须立刻切换，而不是等下次打开设置才更新。
  for (const [master, fn] of [
    ["set-window-on", "updateWindowBoxes"],
    ["set-quota-on", "updateQuotaBoxes"],
  ]) {
    assert.ok(
      app2.includes(`getElementById("${master}").addEventListener("change", ${fn})`),
      `${master} 的 change 应绑定 ${fn}（否则开关后子项仍保持旧状态）`
    );
  }
});

test("连接/计划数值规则必须与引擎 setting_spec 的 Kind::Int 一致", () => {
  // 回归：FIELD_BOUNDS 曾把 conn.global_conn_cap 写成 [1,128]，而引擎默认 256、
  // 合法区间 1–1024。默认设置直接越界 → validateConnForm 失败 → applySettings
  // 在发第一个 settings_set 之前就 return，表现为“点确定完全没反应”。
  const spec = fs.readFileSync(
    path.join(UI_DIR, "..", "..", "aidm-core", "src", "setting_spec.rs"),
    "utf8"
  );

  const start = app.indexOf("const FIELD_BOUNDS = {");
  assert.ok(start > 0, "app.js 里找不到 FIELD_BOUNDS");
  const end = app.indexOf("};", start);
  assert.ok(end > start, "FIELD_BOUNDS 结构变了，请同步本测试");
  const bounds = {};
  for (const m of app.slice(start, end).matchAll(/"([^"]+)":\s*\[(\d+),\s*(\d+)\]/g)) {
    bounds[m[1]] = [Number(m[2]), Number(m[3])];
  }

  const keys = [
    "conn.global_conn_cap",
    "conn.retry_max",
  ];
  for (const key of keys) {
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(
      `"${escaped}",\\s*"[^"]*",\\s*Kind::Int \\{ min: (\\d+), max: (\\d+) \\}`
    );
    const m = re.exec(spec);
    assert.ok(m, `setting_spec.rs 里找不到 ${key} 的 Kind::Int 声明`);
    assert.deepEqual(
      bounds[key],
      [Number(m[1]), Number(m[2])],
      `${key} 的 UI 区间与引擎不一致（UI=${JSON.stringify(bounds[key])}，引擎=[${m[1]},${m[2]}]）`
    );
  }
  assert.deepEqual(bounds["conn.global_conn_cap"], [1, 1024]);

  // 控件上限与「键缺失时的兜底默认」也要和引擎一致（默认 256，不是 32）。
  assert.ok(
    /id="set-global-cap"[^>]*min="1"[^>]*max="1024"/.test(html),
    "set-global-cap 的 min/max 应为 1–1024"
  );
  assert.ok(
    app.includes(
      'document.getElementById("set-global-cap").value = settingStr(s["conn.global_conn_cap"]) || "256";'
    ),
    "set-global-cap 的兜底默认值应为引擎默认的 256"
  );

  // 校验失败要跳到第一条错误所在页，否则错误提示在别的页签里等于“点确定没反应”。
  const body = functionBody("validateConnForm");
  assert.ok(body.includes("firstErrKey"), "validateConnForm 应记录第一条错误键");
  assert.ok(
    body.includes("showSettingPage(") && body.includes("settingsPageForKey(firstErrKey)"),
    "validateConnForm 失败时应跳到首个错误所在的设置页"
  );
});
