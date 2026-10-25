"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const P = require("../lib/polish.js");

test("eD2k displays peer activity independently of its single working file", () => {
  const task = { mode: "ed2k", state: "downloading", segments: [{ status: "running" }], p2p: {
    phase: "downloading", known_sources: 7, active_peers: 3, transferring_peers: 2,
    queued_peers: 1, max_connections: 8, verified_parts: 4, total_parts: 20,
  } };
  assert.equal(P.connectionsText(task), "3 / 8");
  assert.deepEqual(P.p2pDetails(task), {
    phase: "正在接收文件", sources: "候选源 7 · 连接 3 / 8",
    transfers: "正在传输 2 · 对方排队 1", pieces: "已校验 4 / 20 个切片",
  });
  assert.equal(P.p2pDetails({ mode: "multi" }), null);
  assert.equal(P.connectionsText({ mode: "ed2k", segments: [{ status: "running" }] }), "—");
});

test("eD2k discovery and paused state do not claim verified pieces or live connections", () => {
  const detail = P.p2pDetails({ mode: "ed2k", state: "paused", p2p: {
    phase: "paused", known_sources: 5, max_connections: 4, total_parts: 461,
  } });
  assert.equal(detail.phase, "已暂停");
  assert.equal(detail.sources, "候选源 5 · 连接 0 / 4");
  assert.equal(detail.pieces, "切片共 461 个");
});

test("eD2k slice lanes split 454 parts across 8 connections", () => {
  const lanes = P.sliceLaneRanges(454, 8);
  assert.equal(lanes.length, 8);
  assert.equal(lanes.reduce((sum, lane) => sum + lane.count, 0), 454);
  assert.deepEqual(lanes.map((lane) => lane.count), [56, 57, 57, 57, 56, 57, 57, 57]);
  assert.equal(lanes[0].start, 0);
  assert.equal(lanes[7].end, 454);
  assert.deepEqual(P.sliceLaneRanges(3, 8).map((lane) => lane.count), [1, 1, 1]);
});

test("list protocol badge: source count + protocol", () => {
  assert.deepEqual(P.protocolHint({ p2p: { transferring_peers: 3 } }), {
    count: 3, label: "[eD2k]",
  });
  assert.deepEqual(P.protocolHint({ mode: "multi", segments: new Array(8) }), {
    count: 8, label: "[HTTP]",
  });
  assert.deepEqual(P.protocolHint({ mode: "single" }), {
    count: 1, label: "[HTTP]",
  });
  assert.equal(P.protocolHint({}), null);
});

test("eD2k local retry queue is distinct from a remote upload queue", () => {
  const retry = { mode: "ed2k", state: "queued", error_code: "ed2k_no_sources", p2p: {
    phase: "queued", known_sources: 8, active_peers: 0, queued_peers: 0, max_connections: 32,
  } };
  assert.equal(P.p2pDetails(retry).phase, "等待可用下载源");
  assert.equal(P.p2pDetails({ mode: "ed2k", state: "queued" }).phase, "等待可用下载源");
  retry.p2p.active_peers = 1;
  retry.p2p.queued_peers = 1;
  assert.equal(P.p2pDetails(retry).phase, "等待对方分配下载位置");
});

test("speed-limit button: 0 or unset is 不限速", () => {
  assert.equal(P.formatSpeedLimitButton(0), "不限速");
  assert.equal(P.formatSpeedLimitButton(null), "不限速");
  assert.equal(P.formatSpeedLimitButton(undefined), "不限速");
  assert.equal(P.formatSpeedLimitButton(""), "不限速");
  assert.equal(P.formatSpeedLimitButtonBps(0), "不限速");
});

test("speed-limit button: value uses 限速 N KB/s", () => {
  assert.equal(P.formatSpeedLimitButton(500), "限速 500 KB/s");
  assert.equal(P.formatSpeedLimitButton(1024), "限速 1 MB/s");
  assert.equal(P.formatSpeedLimitButtonBps(500 * 1024), "限速 500 KB/s");
});

test("header 完成时间 never follows task state", () => {
  assert.equal(P.FINISH_TIME_HEADER, "完成时间");
  assert.notEqual(P.FINISH_TIME_HEADER, "剩余时间");
});

test("新建下载：链接 → 文件名解析（与引擎 filename_from_url 同规则）", () => {
  assert.equal(P.filenameFromUrl("https://cdn.example/a/pkg-1.2.zip?x=1"), "pkg-1.2.zip");
  assert.equal(P.filenameFromUrl("https://cdn.example/a/pkg-1.2.zip#frag"), "pkg-1.2.zip");
  assert.equal(P.filenameFromUrl("https://cdn.example/%E4%B8%AD.bin"), "中.bin");
  assert.equal(P.filenameFromUrl("https://cdn.example/a/na%20me.tar.gz"), "na me.tar.gz");
  // 解析不出的情况返回空串（由调用方决定是否兜底）
  assert.equal(P.filenameFromUrl("https://cdn.example/"), "");
  assert.equal(P.filenameFromUrl("https://cdn.example"), "");
  assert.equal(P.filenameFromUrl(""), "");
  assert.equal(P.filenameFromUrl(null), "");
  assert.equal(P.filenameFromUrl("   "), "");
  assert.equal([...P.filenameFromUrl("https://x/" + "a".repeat(300))].length, 255);
  assert.equal(P.FILENAME_FALLBACK, "download.bin");
  // eD2k 文件链接：名即权威文件名（与引擎 decoded_name 同规则）
  assert.equal(
    P.filenameFromUrl("ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/"),
    "cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso"
  );
  assert.equal(
    P.filenameFromUrl("ed2k://|file|My%20File%20%E4%B8%AD.bin|100|965c013e991ee246d63d45ea71954c4d|/"),
    "My File 中.bin"
  );
  assert.equal(P.filenameFromUrl("ed2k://|server|207.44.222.51|4242|/"), "");
  assert.equal(P.filenameFromUrl("ed2k://|file|"), "");
  assert.equal(P.autoFilenameFor("", "", "ed2k://|file|a.bin|100|965c013e991ee246d63d45ea71954c4d|/"), "a.bin");
});

test("新建下载：自动填名的覆盖规则", () => {
  // 空输入框 → 解析并填入
  assert.equal(P.autoFilenameFor("", "", "https://x/a.zip"), "a.zip");
  // 现值等于上次自动填入值 → 跟随新链接
  assert.equal(P.autoFilenameFor("a.zip", "a.zip", "https://x/b.zip"), "b.zip");
  // 用户手动改过 → 不动（null）
  assert.equal(P.autoFilenameFor("mine.zip", "a.zip", "https://x/b.zip"), null);
  // 清空文件名 → 恢复自动解析
  assert.equal(P.autoFilenameFor("", "a.zip", "https://x/b.zip"), "b.zip");
  // 链接清空 → 文件名一起清空
  assert.equal(P.autoFilenameFor("a.zip", "a.zip", ""), "");
});

test("新建下载：自动回填的 URL 尾名不作为显式文件名提交", () => {
  // 微软 CDN：URL 尾段只是 GUID，真名在 Content-Disposition 里。
  const url =
    "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/" +
    "37817b38-0a56-4e32-84fd-7e1053b13317?P1=1";
  assert.equal(
    P.shouldSubmitFilename("37817b38-0a56-4e32-84fd-7e1053b13317", "37817b38-0a56-4e32-84fd-7e1053b13317", url),
    false
  );
  // 即便自动名状态丢失，只要等于当前 URL 尾名也不算显式。
  assert.equal(P.shouldSubmitFilename("37817b38-0a56-4e32-84fd-7e1053b13317", "", url), false);
  // 用户改名后 → 显式提交。
  assert.equal(
    P.shouldSubmitFilename("mine.msix", "37817b38-0a56-4e32-84fd-7e1053b13317", url),
    true
  );
  // 空值不提交。
  assert.equal(P.shouldSubmitFilename("", "", url), false);
  // 普通链接同样适用。
  assert.equal(P.shouldSubmitFilename("a.zip", "a.zip", "https://x/a.zip"), false);
});

test("新建下载：对话框把链接输入接到自动解析上", () => {
  const uiDir = path.join(__dirname, "..");
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");
  assert.equal(
    app.includes('document.getElementById("dlg-url").addEventListener("input", syncDialogFilename)'),
    true
  );
  assert.equal(app.includes("P.autoFilenameFor"), true);
  assert.equal(app.includes("P.shouldSubmitFilename"), true);
  assert.equal(app.includes("P.filenameFromUrl"), true);
  // 提交成功后重置，避免下一次打开沿用旧名字
  assert.equal(app.includes("resetDialogFilename()"), true);
});

test("完成时间 cell: remaining / duration / dash", () => {
  assert.equal(
    P.formatFinishCell({ state: "downloading", done: 0, total: 18000, speed: 100 }),
    "3 分钟"
  );
  assert.equal(
    P.formatFinishCell({ state: "downloading", done: 0, total: 12, speed: 1 }),
    "12 秒"
  );
  assert.equal(
    P.formatFinishCell({
      state: "done",
      created_at: 1_700_000_000,
      finished_at: 1_700_000_000 + 12 * 60 + 30,
    }),
    "00:12:30"
  );
  assert.equal(P.formatFinishCell({ state: "done" }), P.DASH);
  assert.equal(P.formatFinishCell({ state: "queued", total: 100, speed: 10, done: 0 }), P.DASH);
  assert.equal(P.formatFinishCell({ state: "paused", total: 100, speed: 10, done: 0 }), P.DASH);
  assert.equal(P.formatFinishCell({ state: "error", total: 100, speed: 10, done: 0 }), P.DASH);
});

test("完成时间 properties prefixes", () => {
  assert.equal(
    P.formatFinishProps({ state: "downloading", done: 0, total: 18000, speed: 100 }),
    "约 3 分钟"
  );
  assert.equal(
    P.formatFinishProps({ state: "done", duration_secs: 12 * 60 + 30 }),
    "用时 00:12:30"
  );
  assert.equal(P.formatFinishProps({ state: "queued" }), P.DASH);
});

test("用时 = 净下载耗时（active_ms），不含暂停时间", () => {
  // 墙钟跨度 1 小时（中间暂停了 50 分钟），真正在下载只有 10 分钟
  const task = {
    state: "done",
    created_at: 1_700_000_000,
    finished_at: 1_700_000_000 + 3600,
    active_ms: 10 * 60 * 1000,
  };
  assert.equal(P.formatFinishCell(task), "00:10:00");
  assert.equal(P.formatFinishProps(task), "用时 00:10:00");
});

test("extension-change detect ignores case and stem", () => {
  assert.equal(P.extensionChanged("a.ZIP", "b.zip"), false);
  assert.equal(P.extensionChanged("movie.mkv", "movie-final.mkv"), false);
  assert.equal(P.extensionChanged("a.zip", "a.txt"), true);
  assert.equal(P.extensionChanged("a.zip", "a"), true);
  assert.equal(P.extensionChanged("a", "a.zip"), true);
  assert.equal(P.fileExtension("dir/name.Tar.Gz"), "gz");
});

test("rename confirm logic", () => {
  assert.deepEqual(P.renameCommitDecision("file.zip", "file.zip"), {
    action: "noop",
    filename: "file.zip",
  });
  assert.deepEqual(P.renameCommitDecision("file.zip", "other.zip"), {
    action: "rename",
    filename: "other.zip",
  });
  assert.deepEqual(P.renameCommitDecision("file.ZIP", "file.zip"), {
    action: "rename",
    filename: "file.zip",
  });
  assert.deepEqual(P.renameCommitDecision("file.zip", "file.txt"), {
    action: "confirm",
    filename: "file.txt",
  });
  assert.deepEqual(P.renameCommitDecision("file.zip", "file"), {
    action: "confirm",
    filename: "file",
  });
});

test("empty name is not saved", () => {
  assert.deepEqual(P.renameCommitDecision("a.bin", ""), {
    action: "empty",
    error: P.RENAME_EMPTY,
    filename: "",
  });
  assert.deepEqual(P.renameCommitDecision("a.bin", "   "), {
    action: "empty",
    error: P.RENAME_EMPTY,
    filename: "",
  });
  assert.equal(P.RENAME_EMPTY, "文件名不能为空");
});

test("rename error codes match PR #17 contract", () => {
  assert.equal(P.renameErrorText("invalid_filename"), P.RENAME_INVALID);
  assert.equal(P.renameErrorText("name_taken"), P.RENAME_TAKEN);
  assert.equal(P.renameErrorText("task_not_found"), P.RENAME_MISSING);
  assert.equal(P.renameErrorText({ code: "invalid_filename" }), P.RENAME_INVALID);
  assert.equal(P.renameErrorText({ code: "name_taken" }), P.RENAME_TAKEN);
  assert.equal(P.renameErrorText({ error: "task_not_found" }), P.RENAME_MISSING);
  assert.equal(P.renameErrorText({ code: "task_not_found" }), P.RENAME_MISSING);
  assert.equal(P.renameErrorText({ ok: false, error: "rename: io" }), P.RENAME_FAIL);
  assert.equal(P.renameErrorText("busy"), P.RENAME_FAIL);
  assert.equal(P.renameErrorText(""), P.RENAME_FAIL);
  assert.equal(P.RENAME_MISSING, "任务不存在或已删除");
});

test("rename disabled offline or missing", () => {
  assert.equal(P.canRenameTask({ id: 1 }, false), true);
  assert.equal(P.canRenameTask({ id: 1 }, true), false);
  assert.equal(P.canRenameTask(null, false), false);
  assert.equal(P.RENAME_UNAVAILABLE, "当前无法重命名");
});

test("source / connections / middle truncate", () => {
  assert.equal(P.sourceFieldText("ext", "https://example.com/page", "https://cdn/a.iso"), "https://example.com/page");
  assert.equal(P.sourceFieldText("ext", "", "https://cdn/a.iso"), "https://cdn/a.iso");
  assert.equal(P.sourceFieldText("manual", "https://example.com/page", "https://cdn/a.iso"), "手动下载");
  assert.equal(P.sourceFieldText("other", "", ""), P.DASH);
  assert.equal(P.connectionsText({ mode: "single" }), "1");
  assert.equal(
    P.connectionsText({
      mode: "multi",
      segments: [
        { status: "running" },
        { status: "running" },
        { status: "running" },
        { status: "pending" },
        { status: "pending" },
        { status: "done" },
        { status: "done" },
        { status: "done" },
      ],
    }),
    "3 / 8"
  );
  assert.equal(P.truncateMiddle("https://example.com/very/long/file.bin", 18).includes("…"), true);
  assert.equal(P.truncateMiddle("", 18), P.DASH);
  assert.equal(P.replaceFilenameInPath("/tmp/old.bin", "new.txt"), "/tmp/new.txt");
  assert.equal(P.replaceFilenameInPath("C:\\dl\\old.bin", "new.txt"), "C:\\dl\\new.txt");
});

test("html/css contracts for 8 polish items", () => {
  const uiDir = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const css = fs.readFileSync(path.join(uiDir, "styles.css"), "utf8");
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");
  assert.equal(html.includes("剩余时间"), false);
  assert.equal(html.includes("完成时间"), true);
  assert.equal(html.includes(">不限速<"), false, "工具栏不再有独立的「不限速」按钮");
  assert.equal(html.includes('id="speed-limit" class="pill"'), false);
  assert.equal(html.includes('id="speed-limit"'), false, "限速入口只在设置与状态栏");
  assert.equal(html.includes("文件类型已改变"), true);
  assert.equal(html.includes("切片详情（0）"), true);
  assert.equal(html.includes('id="props-filename"'), true);
  assert.equal(css.includes(".list-scroll:focus"), false);
  assert.equal(css.includes(".list-scroll:focus-within"), false);
  assert.equal(css.includes("border-left: 3px solid var(--accent)"), true);
  assert.equal(css.includes("position: absolute"), true);
  assert.equal(css.includes("z-index: 5"), true);
  assert.equal(app.includes('op: "rename"'), true);
  assert.equal(app.includes("innerHTML"), false);
});

test("props panel: 标题行「创建时间+状态灯」与合并后的「下载」块", () => {
  const uiDir = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const css = fs.readFileSync(path.join(uiDir, "styles.css"), "utf8");
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");

  // 标题行：左「任务属性」，右侧「创建时间 + 状态」
  assert.equal(html.includes('<div class="props-head">'), true);
  assert.equal(html.includes('id="props-head-meta" class="props-head-meta hidden"'), true);
  assert.equal(html.includes('id="props-created" class="props-value props-head-created"'), true);
  assert.equal(html.includes('id="props-state-dot" class="props-state-dot"'), true);
  assert.equal(html.includes('id="props-state-text" class="props-value props-head-state"'), true);

  // 字段顺序：文件名 → 保存位置 → 下载链接 → 来源 → 下载 → …
  const order = ["filename", "save", "url", "source", "download"]
    .map((f) => html.indexOf('data-field="' + f + '"'));
  assert.equal(order.every((i) => i > 0), true);
  assert.deepEqual(order, order.slice().sort((a, b) => a - b));

  // 大小 / 进度 / 完成时间并入「下载」块，原独立占位取消
  assert.equal(html.includes('id="props-size"'), false);
  assert.equal(html.includes('id="props-speed"'), false);
  assert.equal(html.includes('id="props-status"'), false);
  assert.match(
    html,
    /data-i18n="props\.download"[^>]*>下载/,
    "「下载」标签应保留且已接入 i18n"
  );
  assert.equal(html.includes('id="props-progress-pct"'), true);
  const metaAt = html.indexOf('class="props-dl-meta"');
  assert.equal(metaAt > 0, true);
  assert.equal(html.indexOf('id="props-progress"') > metaAt, true);
  assert.equal(html.indexOf('id="props-finish"') > metaAt, true);
  assert.equal(html.indexOf('id="speed-chart"') > html.indexOf('class="props-dl-meta"'), true);

  // 排版：标题行右对齐；完成时间在进度值右侧右对齐；下载中为呼吸灯
  assert.equal(css.includes(".props-head-meta {"), true);
  assert.equal(css.includes(".props-state-dot.is-active { animation: props-breathe"), true);
  assert.equal(css.includes("@keyframes props-breathe"), true);
  assert.equal(css.includes(".props-dl-finish { flex: 0 0 auto; text-align: right;"), true);
  assert.equal(app.includes("function propsStateSignal"), true);
  assert.equal(app.includes('dot: "🔴"'), true);
  assert.equal(app.includes('dot: "🟠"'), true);
  assert.equal(app.includes('dot: "🟢"'), true);
  assert.equal(app.includes("renderPropsHeadMeta(task)"), true);
});

test("属性面板：去掉连接数、切片详情默认展开、曲线停下即定稿", () => {
  const uiDir = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");

  // 「连接数」这一行在属性面板里取消（设置页/状态栏里的连接数照旧）
  const panel = html.slice(html.indexOf('<aside id="task-props"'), html.indexOf("</aside>"));
  assert.equal(panel.includes("连接数"), false);
  assert.equal(panel.includes('id="props-conns"'), false);
  assert.equal(app.includes("props-conns"), false);
  assert.equal(app.includes("connectionsText"), false);

  // 切片详情默认展开
  assert.equal(html.includes('id="props-segments-box" class="props-seg-box" open'), true);

  // 曲线把任务状态显式接进来，并且只在「还在跑的阶段」实时跟进
  assert.equal(app.includes('const running = state === "connecting" || state === "downloading";'), true);
  assert.equal(app.includes("if (signature === chartSignature) return;"), true);
  assert.equal(app.includes("已完成（无下载阶段速度记录）"), true);
});

test("速度图表：去 X 轴刻度/背景条纹，横轴按采样首尾铺满 0..cssW", () => {
  const app = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  // 底部 X 轴刻度与背景横向条纹都不要再画。
  assert.equal(app.includes("chartAxisLabel"), false);
  assert.equal(app.includes("chartAxisStepSeconds"), false);
  assert.equal(app.includes("chartAxisTicks"), false);
  assert.equal(app.includes("SPEED_X_TICKS"), false);
  assert.equal(app.includes("for (let i = 1; i <= 3; i++)"), false);
  // 横向映射用序列首尾，始终占满画布左右；单点/两点也不例外。
  assert.equal(app.includes("const span = x1 - x0;"), true);
  assert.equal(app.includes("x: Math.max(0, Math.min(1, frac)) * cssW,"), true);
  assert.equal(app.includes("const axisMax = Math.max(1000, axisStep * 8000);"), false);
  // 采样不足的提示分支保留。
  assert.equal(app.includes("if (series.length < 2) {"), true);
  assert.equal(app.includes("等待速度采样…"), true);
  // 峰值 / 当前速度文字与顶部留白保留。
  assert.equal(app.includes('ctx.fillText(T("峰值 ") + fmtSpeed(peak), 4, 2);'), true);
  assert.equal(app.includes("const padTop = 13;"), true);
});

test("速度采样：小文件在轮询间隙完成也能产出至少 2 个点", () => {
  const running = P.speedSampleFromTask(
    [],
    { state: "downloading", speed: 1024, active_ms: 180, done: 180, total: 180 },
    1000
  );
  assert.ok(running.length >= 2, "下载中首次观测就应补出起点 + 当前点");
  assert.equal(running.every((p) => !p.est), true, "有实时 speed 的补点不是估算值");
  const done = P.speedSampleFromTask(
    running,
    { state: "done", speed: 0, active_ms: 220, done: 220, total: 220 },
    1600
  );
  assert.ok(done.length >= 2);
  assert.equal(done[done.length - 1].bps, 0);
  // 第一次 list 就已经完成（两次 600ms 轮询之间跑完）：按平均速度补两个点。
  const direct = P.speedSampleFromTask(
    [],
    { state: "done", speed: 0, active_ms: 400, done: 8192, total: 8192 },
    2000
  );
  assert.equal(direct.length, 2);
  assert.ok(direct[0].bps > 0, "平均速度要能画出可见高度");
  assert.equal(direct[direct.length - 1].bps, 0);
  assert.equal(direct.every((p) => p.est === true), true, "平均速度补点必须标记为估算值");
  // verifying 也是“下载已结束”的终态（flush / sha256 / 改名阶段），同样补点。
  const verifying = P.speedSampleFromTask(
    [],
    { state: "verifying", speed: 0, active_ms: 600, done: 4096, total: 4096 },
    2500
  );
  assert.equal(verifying.length, 2);
  assert.ok(verifying[0].bps > 0);
  assert.equal(verifying[verifying.length - 1].bps, 0);
  assert.equal(verifying.every((p) => p.est === true), true, "verifying 补点也必须是估算值");
  // 暂停 / 失败不是“下载结束”：首次观测没有历史时不能虚构走势。
  assert.deepEqual(
    P.speedSampleFromTask([], { state: "paused", speed: 0, active_ms: 500, done: 1000 }, 4000),
    []
  );
  assert.deepEqual(
    P.speedSampleFromTask([], { state: "error", speed: 0, active_ms: 500, done: 1000 }, 4000),
    []
  );
  // 没有净下载耗时/速度时保持为空，交给图表提示文案。
  assert.deepEqual(P.speedSampleFromTask([], { state: "done", speed: 0 }, 3000), []);
});

test("速度采样：普通多拍仍按 400ms 去重且横轴只增不减", () => {
  const a = P.speedSampleFromTask([], { state: "downloading", speed: 1000, active_ms: 600 }, 1000);
  assert.equal(a.length, 2);
  const b = P.speedSampleFromTask(a, { state: "downloading", speed: 1200, active_ms: 900 }, 1100);
  assert.equal(b.length, 2, "同一拍内的重复 list 只覆盖最后一次");
  assert.equal(b[1].bps, 1200);
  const c = P.speedSampleFromTask(b, { state: "downloading", speed: 1400, active_ms: 900 }, 1600);
  assert.equal(c.length, 3);
  assert.ok(c[2].x >= c[1].x, "横轴不能回退");
});

test("速度采样：离开下载阶段就地补 0 收尾且只补一次", () => {
  const a = P.speedSampleFromTask([], { state: "downloading", speed: 500, active_ms: 1000 }, 1000);
  const paused = P.speedSampleFromTask(a, { state: "paused", speed: 0, active_ms: 1200 }, 1600);
  assert.equal(paused[paused.length - 1].bps, 0);
  const again = P.speedSampleFromTask(paused, { state: "paused", speed: 0, active_ms: 1200 }, 2200);
  assert.equal(again.length, paused.length, "收尾 0 只补一次");
});

test("列表速率：峰值/平均值与四种取值分支", () => {
  // peak：多点取最大，忽略 0 / 负数 / NaN；空/非法序列返回 0。
  assert.equal(
    P.peakSpeedBps([{ bps: 10 }, { bps: 30 }, { bps: 0 }, { bps: -5 }, { bps: NaN }]),
    30
  );
  assert.equal(P.peakSpeedBps([]), 0);
  assert.equal(P.peakSpeedBps(null), 0);
  assert.equal(P.peakSpeedBps([{ bps: -5 }, { bps: 0 }, { bps: NaN }]), 0);

  // average：done*1000/active_ms；参数非法或非正返回 0。
  assert.equal(P.averageSpeedBps(1000, 2000), 500);
  assert.equal(P.averageSpeedBps(1000, 0), 0);
  assert.equal(P.averageSpeedBps(1000, null), 0);
  assert.equal(P.averageSpeedBps(0, 1000), 0);
  assert.equal(P.averageSpeedBps("bad", 1000), 0);

  // 四种 kind：downloading=live；done 有峰值=peak；done 无峰值=平均；其它=none。
  assert.deepEqual(P.listSpeedCell({ state: "downloading", speed: 1234 }, [{ bps: 9999 }]), {
    kind: "live",
    bps: 1234,
  });
  assert.deepEqual(
    P.listSpeedCell(
      { state: "done", done: 1000, active_ms: 2000 },
      [{ bps: 50 }, { bps: 900 }, { bps: 0 }]
    ),
    { kind: "peak", bps: 900 }
  );
  assert.deepEqual(
    P.listSpeedCell({ state: "done", done: 1000, active_ms: 2000 }, [{ bps: 0 }]),
    { kind: "average", bps: 500 }
  );
  // 估算点（est）不是真实峰值：只剩估算点时必须退回平均值，不能伪装成 peak。
  assert.deepEqual(
    P.listSpeedCell(
      { state: "done", done: 1000, active_ms: 2000 },
      [{ bps: 500, est: true }, { bps: 0, est: true }]
    ),
    { kind: "average", bps: 500 }
  );
  // 后续采样必须保留 est 标记，否则一轮 refresh 后估算点又会被当成真实峰值。
  const preserved = P.speedSampleFromTask(
    [{ x: 0, bps: 500, t: 1000, est: true }],
    { state: "done", done: 1000, active_ms: 2000 },
    1600
  );
  assert.equal(preserved[0].est, true, "复制历史时不能丢掉 est 标记");
  for (const state of ["queued", "connecting", "paused", "verifying", "error"]) {
    assert.deepEqual(
      P.listSpeedCell({ state, speed: 100, done: 1000, active_ms: 2000 }, [{ bps: 900 }]),
      { kind: "none", bps: 0 }
    );
  }
  assert.deepEqual(P.listSpeedCell({ state: "done", done: 0, active_ms: 0 }, []), {
    kind: "none",
    bps: 0,
  });
});

test("速度曲线跨重启保留；崩溃回退与手动重启任务都清空历史", () => {
  const app = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  assert.equal(app.includes('const SPEED_STORE_KEY = "aidm.speedHistory";'), true);
  assert.equal(app.includes("function loadSpeedHistory()"), true);
  assert.equal(app.includes("function saveSpeedHistory(force)"), true);
  assert.equal(app.includes("loadSpeedHistory();"), true);
  // 每次采样都会尝试落盘（5s 节流）；本轮曲线被清空时立即强制落盘
  assert.equal(app.includes("saveSpeedHistory(curveReset)"), true);
  assert.equal(app.includes('window.addEventListener("pagehide", () => saveSpeedHistory(true));'), true);
  assert.equal(app.includes("if (keep <= SPEED_STORE_MIN_POINTS) return;"), true);
  // 「新的一轮」= 崩溃回退（本轮耗时未入库）或手动重启任务（active_ms 归零）：
  // 清空该任务历史、把本轮起点重设为当前 active_ms（新曲线从 0 起），并立即落盘。
  assert.equal(app.includes("P.speedCurveRestarted &&"), true);
  assert.equal(app.includes("speedHistory.delete(t.id);"), true);
  assert.equal(
    app.includes("speedOrigin.set(t.id, Number.isFinite(rawMs) && rawMs >= 0 ? rawMs : 0);"),
    true
  );
  assert.equal(app.includes("arr = null;"), true);
  // 持久化带本轮起点（旧裸数组格式仍可读）
  assert.equal(app.includes("o: speedOrigin.get(id) || 0,"), true);
  // 暂时没有可存点时不抹掉磁盘历史
  assert.equal(app.includes("if (speedHistory.size === 0)"), true);
  assert.equal(app.includes("Math.max(speedSampleX(t, last, now), last ? last.x : 0)"), true);
});

test("速度曲线：崩溃回退与手动重启任务都判为新的一轮", () => {
  // 手动重启任务：active_ms 归零，而本轮已画到 180s
  assert.equal(P.speedCurveRestarted(0, 120000, 180000), true);
  // 崩溃回退：active_ms 退回上一轮结束时的 120s，本轮已画到 180s
  assert.equal(P.speedCurveRestarted(120000, 120000, 180000), true);
  // 正常重启 / 同一轮推进：active_ms 连续
  assert.equal(P.speedCurveRestarted(300000, 120000, 180000), false);
  assert.equal(P.speedCurveRestarted(301000, 120000, 180000), false);
  // 拿不到 active_ms 不做判断
  assert.equal(P.speedCurveRestarted(NaN, 0, 1000), false);
  assert.equal(P.speedCurveRestarted(null, 0, 1000), false);

  // 清空后新点从 0 起
  assert.equal(P.speedCurveX(120000, 120000), 0);
  assert.equal(P.speedCurveX(300000, 120000), 180000);
  assert.equal(P.speedCurveX(0, 0), 0);
  assert.equal(P.speedCurveX(null, 0), null);
});

test("曲线只在真正传字节的阶段实时跟进（verifying 立刻定稿）", () => {
  const app = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  assert.equal(
    app.includes('const running = state === "connecting" || state === "downloading";'),
    true
  );
  assert.equal(app.includes('state === "verifying") {'), false);
});

test("compressUrl keeps protocol + host head + tail, hides the middle", () => {
  const long =
    "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso";
  assert.equal(
    P.compressUrl(long, 72),
    "https://mirrors……x86_64/AlmaLinux-9-latest-x86_64-dvd.iso"
  );
});

test("compressUrl leaves short urls untouched", () => {
  assert.equal(P.compressUrl("https://a.com/x.zip", 72), "https://a.com/x.zip");
  assert.equal(P.compressUrl("", 72), "");
});

test("compressUrl keeps two different files distinguishable", () => {
  const base = "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/";
  const a = P.compressUrl(base + "AlmaLinux-9-latest-x86_64-dvd.iso", 72);
  const b = P.compressUrl(base + "AlmaLinux-10-latest-x86_64-dvd.iso", 72);
  assert.notEqual(a, b);
  assert.ok(a.endsWith("AlmaLinux-9-latest-x86_64-dvd.iso"), a);
  assert.ok(b.endsWith("AlmaLinux-10-latest-x86_64-dvd.iso"), b);
});

test("compressUrl falls back to keeping the file name when the tail alone is too long", () => {
  const long = "https://verylonghostname.example.com/a/b/" + "f".repeat(90) + ".iso";
  const out = P.compressUrl(long, 72);
  assert.ok([...out].length <= 72, out);
  assert.ok(out.endsWith(".iso"), out);
});

test("compressUrl handles text that is not a url", () => {
  const out = P.compressUrl("x".repeat(200), 40);
  assert.ok([...out].length <= 40, out);
});

test("设置页的表格不会被长内容撑破容器", () => {
  const cssText = fs.readFileSync(path.join(__dirname, "..", "styles.css"), "utf8");
  // `.set-page` / `.set-group` 都是 flex column 容器，而 flex 子项默认
  // `min-width: auto` —— 表格会被长主机名 / 扩展 ID 撑开、不肯收缩，整页横向
  // 溢出。这条规则是那次修复的核心，删掉就会复发。
  assert.equal(cssText.includes(".set-group .ext-table,"), true);
  assert.equal(cssText.includes("min-width: 0; max-width: 100%;"), true);
});

test("点遮罩关闭弹窗要求按下与松开都在遮罩上", () => {
  // 只看 click 的 target 会被"在弹窗内部按下、移到背景上松开"骗过去：
  // click 派发在两者的最近公共祖先上，于是 target 恰好是遮罩，
  // 填了一半的新建下载就被关掉、内容全丢。
  assert.equal(P.backdropClickCloses(true, true), true, "按下与松开都在遮罩上 → 关");
  assert.equal(P.backdropClickCloses(false, true), false, "内部按下 + 背景松开 → 不能关");
  assert.equal(P.backdropClickCloses(true, false), false, "背景按下 + 内部松开 → 不能关");
  assert.equal(P.backdropClickCloses(false, false), false, "都在内部 → 不能关");
  // 拿不准的输入一律不关（fail-closed：宁可让用户再点一次）
  assert.equal(P.backdropClickCloses(undefined, true), false);
  assert.equal(P.backdropClickCloses(true, undefined), false);
  assert.equal(P.backdropClickCloses(1, 1), false, "只认真正的 true");
});

test("六处弹窗遮罩都走统一的 armBackdropClose，不再留裸判定", () => {
  const appJs = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  // 六处：新建下载 / 删除确认 / 设置 / 缺失文件 / 重命名扩展名 / 候选源
  const wired = [
    "armBackdropClose(mask, closeDialog);",
    "armBackdropClose(delMask, closeDeleteDialog);",
    "armBackdropClose(setMask, requestCloseSettings);",
    "armBackdropClose(mask, closeMissingDialog);",
    'armBackdropClose(document.getElementById("rename-ext-mask"), cancelRenameExt);',
    'armBackdropClose(document.getElementById("cand-mask"), closeCandidateDialog);',
  ];
  for (const line of wired) {
    assert.equal(appJs.includes(line), true, `缺少这处接线: ${line}`);
  }
  // 回归护栏：这些错误写法必须彻底消失，否则"松手位置"又会决定弹窗生死
  for (const stale of [
    'if (e.target === mask) closeDialog();',
    'if (e.target === delMask) closeDeleteDialog();',
    'if (e.target === setMask) requestCloseSettings();',
    'e.target.id === "missing-mask"',
    'e.target.id === "rename-ext-mask"',
    'e.target.id === "cand-mask"',
  ]) {
    assert.equal(appJs.includes(stale), false, `旧判定又回来了: ${stale}`);
  }
});

test("missingFileIds: done + 非空 path + false 才命中，其余一律忽略", () => {
  const tasks = [
    { id: 1, state: "done", save_path: "C:\\a.bin" },
    { id: 2, state: "downloading", save_path: "C:\\b.bin" },
    { id: 3, state: "done", save_path: "   " },
    { id: 4, state: "done", save_path: "C:\\d.bin" },
    { id: 5, state: "done" },
  ];
  const hit = P.missingFileIds(tasks, [false, false, false, true, false]);
  assert.ok(hit instanceof Set);
  assert.deepEqual([...hit], [1]);
});

test("missingFileIds: 缺项 / 非布尔 false 不算不存在", () => {
  const tasks = [
    { id: 1, state: "done", save_path: "C:\\a.bin" },
    { id: 2, state: "done", save_path: "C:\\b.bin" },
  ];
  assert.deepEqual([...P.missingFileIds(tasks, [false])], [1]);
  assert.deepEqual([...P.missingFileIds(tasks, [undefined, false])], [2]);
  assert.deepEqual([...P.missingFileIds(tasks, [0, "false"])], [], "只认严格 false");
});

test("missingFileIds: 多任务按顺序返回全部命中的 id", () => {
  const tasks = [
    { id: 10, state: "done", save_path: "C:\\a" },
    { id: 20, state: "done", save_path: "C:\\b" },
    { id: 30, state: "paused", save_path: "C:\\c" },
    { id: 40, state: "done", save_path: "C:\\d" },
  ];
  assert.deepEqual([...P.missingFileIds(tasks, [false, true, false, false])], [10, 40]);
});

test("missingFileIds: 非数组输入安全返回空 Set", () => {
  for (const [tasks, flags] of [
    [null, [false]],
    [undefined, undefined],
    [{}, [false]],
    [[], null],
    ["x", [false]],
    [[{ id: 1, state: "done", save_path: "C:\\a" }], "false"],
  ]) {
    const out = P.missingFileIds(tasks, flags);
    assert.ok(out instanceof Set);
    assert.equal(out.size, 0);
  }
});
