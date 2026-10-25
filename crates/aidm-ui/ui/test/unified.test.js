"use strict";
// 统一切片视图的纯逻辑测试（UI 侧正确性约束）。
//
// 这里守的不是“渲染函数被调用过”，而是**看得见的事实**：
// - 范围是左闭右开，终点缺失时必须说“长度未知”而不是编一个；
// - 通路细线只用真实子区间，越界要裁、重叠要能被发现；
// - 总长未知时不能给出百分比。

const test = require("node:test");
const assert = require("node:assert/strict");
const U = require("../lib/unified.js");

test("rangeLen 用左闭右开，终点缺失返回 null", () => {
  assert.equal(U.rangeLen({ start: "0", end_exclusive: "100" }), 100);
  assert.equal(U.rangeLen({ start: "0", end_exclusive: null }), null);
  assert.equal(U.rangeLen({ start: "100", end_exclusive: "100" }), null);
  assert.equal(U.rangeLen({ start: "100", end_exclusive: "50" }), null);
  assert.equal(U.rangeLen(null), null);
});

test("大整数：相邻端点差 1 字节必须被识别为有长度", () => {
  // 用户反例：2^53 与 2^53+1 转 Number 后相等，按 Number 直接比较会误判为“长度未知”。
  const a = "9007199254740992";
  const b = "9007199254740993";
  assert.equal(U.rangeLenBig({ start: a, end_exclusive: b }), 1n, "精确差值必须是 1 字节");
  assert.equal(
    U.rangeLen({ start: a, end_exclusive: b }),
    1,
    "长度必须可判断，不能是 null"
  );
  assert.equal(
    U.rangeLenBig({ start: "0", end_exclusive: b }),
    9007199254740993n,
    "超出安全整数的总长必须精确"
  );
});

test("大整数：覆盖判断用 BigInt，不因舍入把不同端点当同一位置", () => {
  const c = U.coverage({
    range: { start: "9007199254740992", end_exclusive: "9007199254740993" },
    progress: { stored_unique_bytes: "1" },
  });
  assert.equal(c.requiredBig, 1n);
  assert.equal(c.percent, 100);
});

test("coverage: 有效覆盖 / 所需长度，未知总长时为 null", () => {
  const c = U.coverage({
    range: { start: "0", end_exclusive: "1000" },
    progress: { stored_unique_bytes: "250", verified_unique_bytes: "200" },
  });
  assert.equal(c.stored, 250);
  assert.equal(c.verified, 200);
  assert.equal(c.required, 1000);
  assert.equal(c.percent, 25);

  const unknown = U.coverage({
    range: { start: "0", end_exclusive: null },
    progress: { stored_unique_bytes: "10" },
  });
  assert.equal(unknown.required, null);
  assert.equal(unknown.percent, null, "总长未知不得画百分比");
});

test("coverage: 覆盖超出所需长度时封顶 100%", () => {
  const c = U.coverage({
    range: { start: "0", end_exclusive: "100" },
    progress: { stored_unique_bytes: "150" },
  });
  assert.equal(c.percent, 100);
});

test("laneGeometry: 子区间按切片范围换算成百分比", () => {
  const slice = { range: { start: "0", end_exclusive: "1000" } };
  const a = { range: { start: "250", end_exclusive: "500" } };
  const g = U.laneGeometry(slice, a);
  assert.equal(Math.round(g.left), 25);
  assert.equal(Math.round(g.width), 25);
});

test("laneGeometry: 非零起点切片按相对偏移定位", () => {
  const slice = { range: { start: "1000", end_exclusive: "2000" } };
  const a = { range: { start: "1500", end_exclusive: "2000" } };
  const g = U.laneGeometry(slice, a);
  assert.equal(Math.round(g.left), 50);
  assert.equal(Math.round(g.width), 50);
});

test("laneGeometry: 左侧越界按交集定位，不是按原始起点", () => {
  // 用户反例：切片 [100,200)、通路 [50,125) 应画 0%~25%，按原始起点换算会画成 75%。
  const slice = { range: { start: "100", end_exclusive: "200" } };
  const g = U.laneGeometry(slice, { range: { start: "50", end_exclusive: "125" } });
  assert.ok(g, "有交集就必须画");
  assert.equal(g.left, 0, "起点被裁到切片起点");
  assert.equal(g.width, 25, "只算交集那一段的宽度");
});

test("laneGeometry: 右侧越界按交集收窄", () => {
  const slice = { range: { start: "100", end_exclusive: "200" } };
  const g = U.laneGeometry(slice, { range: { start: "175", end_exclusive: "300" } });
  assert.ok(g);
  assert.equal(g.left, 75);
  assert.equal(g.width, 25);
});

test("laneGeometry: 完全在切片外的通路不画", () => {
  const slice = { range: { start: "100", end_exclusive: "200" } };
  assert.equal(
    U.laneGeometry(slice, { range: { start: "0", end_exclusive: "50" } }),
    null,
    "完全在左侧（按原始起点会画出来）"
  );
  assert.equal(
    U.laneGeometry(slice, { range: { start: "250", end_exclusive: "300" } }),
    null,
    "完全在右侧"
  );
  assert.equal(
    U.laneGeometry(slice, { range: { start: "200", end_exclusive: "300" } }),
    null,
    "只在终点相接不算交集"
  );
});

test("laneGeometry: 子区间完全在切片内时位置不变", () => {
  const slice = { range: { start: "1000", end_exclusive: "2000" } };
  const g = U.laneGeometry(slice, { range: { start: "1250", end_exclusive: "1500" } });
  assert.equal(g.left, 25);
  assert.equal(g.width, 25);
});

test("laneGeometry: 无法定位时返回 null（不画假线）", () => {
  const open = { range: { start: "0", end_exclusive: null } };
  assert.equal(
    U.laneGeometry(open, { range: { start: "0", end_exclusive: "10" } }),
    null
  );
  const slice = { range: { start: "0", end_exclusive: "100" } };
  assert.equal(
    U.laneGeometry(slice, { range: { start: "10", end_exclusive: "10" } }),
    null
  );
});

test("lanesDisjoint: 并行通路必须互不重叠", () => {
  const ok = {
    assignments: [
      { range: { start: "0", end_exclusive: "50" } },
      { range: { start: "50", end_exclusive: "100" } },
    ],
  };
  assert.equal(U.lanesDisjoint(ok), true);

  const overlap = {
    assignments: [
      { range: { start: "0", end_exclusive: "60" } },
      { range: { start: "50", end_exclusive: "100" } },
    ],
  };
  assert.equal(
    U.lanesDisjoint(overlap),
    false,
    "重叠会被误读成同一段被两条通路写"
  );

  assert.equal(U.lanesDisjoint({ assignments: [] }), true);
  assert.equal(U.lanesDisjoint(null), true);
});

test("rangeText: 未知长度明说不编造终点", () => {
  const fmt = (n) => String(n);
  assert.equal(U.rangeText({ start: "0", end_exclusive: "100" }, fmt), "0 – 100");
  assert.equal(
    U.rangeText({ start: "50", end_exclusive: null }, fmt),
    "50 起（长度未知）"
  );
});

test("文案映射对未知值回退到原值而不是空白", () => {
  assert.equal(U.sliceStateText("done"), "完成");
  assert.equal(U.assignStateText("transferring"), "传输中");
  assert.equal(U.activityText("verifying"), "校验");
  assert.equal(U.waitText("no_source"), "无可用源");
  assert.equal(U.sliceStateText("future_state"), "future_state");
});

test("shortId: 过长编号只显示前 8 位，空值给占位符", () => {
  assert.equal(U.shortId("task-1-part-0-c12"), "task-1-p");
  assert.equal(U.shortId(""), "—");
  assert.equal(U.shortId(null), "—");
});

// ---- app.js 接线（源码级） ----------------------------------------------
//
// 纯逻辑对了不代表 UI 真的用了它。这里断言 DOM 层的接线顺序与视觉语义：
// 统一视图必须先于旧路径判断，原生块直接画进进度条。

const fs = require("node:fs");
const path = require("node:path");
const APP = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");

test("app.js 优先使用统一视图，缺失才回退旧路径", () => {
  const atUnified = APP.indexOf("if (task.unified_download)");
  const atP2p = APP.indexOf("const p2p = P.p2pDetails");
  assert.ok(atUnified > 0, "缺少 task.unified_download 分支");
  assert.ok(
    atP2p > atUnified,
    "统一视图必须在旧 p2p / segments 路径之前判断，否则旧路径会抢先 return"
  );
  assert.match(APP, /renderUnifiedSlices\(/, "缺少统一视图渲染入口");
});

test("原生块按块等分进进度条，四态各有样式，不再用可展开旧结构", () => {
  assert.match(APP, /unified-lane/, "缺少通路细线（无原生块时仍要画）");
  assert.match(APP, /bar\.classList\.add\("native-bar"\)/, "原生块应画进主进度条");
  assert.match(APP, /native-cell st-/, "每块一格，class 由状态决定");
  // 四态必须都能映射：完成 / 下载中 / 未开始 / 失败。
  for (const s of ['return "done"', 'return "active"', 'return "failed"']) {
    assert.ok(APP.includes(s), "缺少原生块状态映射：" + s);
  }
  assert.ok(APP.includes('return "pending"'), "未知/未开始必须归为 pending（灰）");
  // 旧的可展开 details 结构必须移除，避免一套数据两种视觉。
  assert.doesNotMatch(APP, /className = "unified-native"/, "旧的可展开原生块结构应已移除");
});

test("总长未知时不画虚假百分比", () => {
  assert.match(APP, /cov\.percent != null/, "必须先判断 percent 是否存在");
  assert.match(APP, /classList\.add\("indeterminate"\)/, "未知长度应走不定长进度");
  assert.match(APP, /if \(!slices\.length\)/, "空切片要单独给提示，不能画空条");
});

test("index.html 加载了 unified 纯逻辑", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  const atLib = html.indexOf("lib/unified.js");
  const atApp = html.indexOf("app.js");
  assert.ok(atLib > 0, "index.html 必须加载 lib/unified.js");
  assert.ok(atLib < atApp, "纯逻辑必须在 app.js 之前加载");
});

// ---- 详情请求（行为测试） ------------------------------------------------
//
// 用户复核：前端只请求 `list`，属性面板也从列表取任务，而 `unified_download`
// 只在 `status` 详情里返回——新渲染分支正常情况永远不会进入。
// 下面直接验证“会请求详情”和“详情优先”的行为，不只看源码里有没有分支。

const APP_FOR_WIRING = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");

test("fetchTaskDetail 请求 status 并带回 unified_download", async () => {
  const calls = [];
  const send = async (req) => {
    calls.push(req);
    return {
      ok: true,
      task: {
        id: 7,
        state: "downloading",
        unified_download: { schema_version: 1, slices: [] },
      },
    };
  };
  const task = await U.fetchTaskDetail(send, 7);
  assert.deepEqual(calls, [{ op: "status", id: 7 }], "必须请求详情，而不是只读列表");
  assert.ok(task && task.unified_download, "详情必须带统一视图");
});

test("fetchTaskDetail 失败时返回 null（交给调用方回退列表）", async () => {
  assert.equal(await U.fetchTaskDetail(async () => ({ ok: false }), 1), null);
  assert.equal(await U.fetchTaskDetail(async () => ({ ok: true })), null);
  assert.equal(await U.fetchTaskDetail(null, 1), null);
  assert.equal(await U.fetchTaskDetail(async () => ({ ok: true, task: {} }), null), null);
});

test("pickRenderTask: 同一任务的详情优先，其他情况回退列表", () => {
  const listTask = { id: 7, unified_download: null };
  const detail = { id: 7, task: { id: 7, unified_download: { slices: [1] } } };
  assert.equal(U.pickRenderTask(listTask, detail).unified_download.slices.length, 1);

  // 详情属于别的任务：切换选中时会串台，必须丢弃。
  const other = { id: 8, task: { id: 8, unified_download: { slices: [1, 2] } } };
  assert.equal(U.pickRenderTask(listTask, other), listTask);

  assert.equal(U.pickRenderTask(listTask, null), listTask);
  assert.equal(U.pickRenderTask(null, detail), null);
});

test("app.js: 属性面板渲染前触发详情请求，并用详情作为渲染数据源", () => {
  const atEnsure = APP_FOR_WIRING.indexOf("ensurePropsDetail(listTask.id)");
  const atPick = APP_FOR_WIRING.indexOf("UN.pickRenderTask(listTask, propsDetail)");
  assert.ok(atEnsure > 0, "renderProps 必须触发详情请求（否则统一视图永远拿不到）");
  assert.ok(atPick > atEnsure, "必须先触发请求，再选渲染数据源");
});

// ---- 详情缓存乱序（用户复核：A→B→A 时版本 3 被版本 1 覆盖） -------------

const taskV = (id, rev, engine) => ({
  id,
  unified_download: {
    identity: {
      engine_instance_id: engine || "engine-1",
      state_revision: String(rev),
    },
    slices: [],
  },
});

test("acceptDetail: 旧代次一律丢弃", () => {
  assert.equal(U.acceptDetail(null, taskV(1, 1), 1, 2), false, "已被更新的请求取代");
  assert.equal(U.acceptDetail(null, taskV(1, 1), 2, 2), true, "最新代次可写");
  assert.equal(U.acceptDetail(null, null, 1, 1), false, "空详情不写");
});

test("acceptDetail: 同一引擎实例内版本回退必须拒绝", () => {
  assert.equal(U.acceptDetail(taskV(1, 10), taskV(1, 9), 1, 1), false);
  assert.equal(U.acceptDetail(taskV(1, 10), taskV(1, 10), 1, 1), true, "同版本可刷新");
  assert.equal(U.acceptDetail(taskV(1, 10), taskV(1, 11), 1, 1), true);
});

test("acceptDetail: 引擎实例变化时允许版本从头开始", () => {
  assert.equal(
    U.acceptDetail(taskV(1, 99, "e1"), taskV(1, 0, "e2"), 1, 1),
    true,
    "重启后 state_revision 归零，不能按版本回退拒绝"
  );
});

test("详情缓存：A→B→A 的乱序返回不会把版本写回旧值", async () => {
  // 模拟 app.js 的写法：请求代次递增，返回时用 acceptDetail 判断是否写入。
  let detail = null; // { id, task }
  let seq = 0;

  const request = (id) => {
    const my = ++seq;
    let resolveFn = null;
    const promise = new Promise((r) => {
      resolveFn = r;
    });
    return {
      promise,
      settle: async (task) => {
        resolveFn();
        await promise;
        const prevTask = detail && detail.id === id ? detail.task : null;
        if (U.acceptDetail(prevTask, task, my, seq)) detail = { id: id, task: task };
      },
    };
  };

  const revOf = () =>
    detail && detail.task.unified_download.identity.state_revision;

  // 选择 A（版本 1）
  await request(1).settle(taskV(1, 1));
  assert.equal(revOf(), "1");

  // A → B → A
  const forB = request(2);
  const forA2 = request(1);

  // 新请求先返回版本 3
  await forA2.settle(taskV(1, 3));
  assert.equal(revOf(), "3");

  // 旧请求（B）晚返回
  await forB.settle(taskV(2, 1));
  assert.equal(revOf(), "3", "旧代次不得覆盖 A 的新版本");

  // 同一任务的两个请求乱序：最新代次版本 5 先回，旧代次版本 2 后回
  const staleA = request(1);
  const newestA = request(1);
  await newestA.settle(taskV(1, 5));
  assert.equal(revOf(), "5");
  await staleA.settle(taskV(1, 2));
  assert.equal(revOf(), "5", "同任务旧代次也不能回退版本");
});

test("app.js: 退避按任务隔离，不是全局变量", () => {
  assert.match(
    APP_FOR_WIRING,
    /propsDetailRetryAt = new Map\(\)/,
    "退避必须按任务记录，全局值会让一个任务失败阻塞其他任务"
  );
  assert.match(APP_FOR_WIRING, /propsDetailSeq/, "必须有请求代次");
  assert.match(
    APP_FOR_WIRING,
    /UN\.acceptDetail\(prevTask, task, seq, propsDetailSeq\)/,
    "写入缓存前必须做代次与版本校验"
  );
});

test("下载日志只保留任务本身的事件，过滤影子埋点", () => {
  const raw = [
    { kind: "unified_state_changed", detail: "from=a to=a" },
    { kind: "start", detail: "mode=fastdl" },
    { kind: "unified_decision", detail: "action=wait" },
    { kind: "error", err_code: "http_403" },
    { kind: "unified_source_changed" },
    { kind: "done", detail: "bytes=1" },
  ];
  const got = U.filterDownloadLog(raw, 50);
  assert.deepEqual(
    got.map((e) => e.kind),
    ["start", "error", "done"],
    "影子事件不能占下载日志的位置"
  );
});

test("下载日志过滤后仍受条数上限约束，且不因影子事件密集而变空", () => {
  const raw = [];
  for (let i = 0; i < 120; i++) raw.push({ kind: i % 2 ? "unified_state_changed" : "transfer" });
  const got = U.filterDownloadLog(raw, 10);
  assert.equal(got.length, 10);
  assert.ok(got.every((e) => e.kind === "transfer"));
  assert.deepEqual(U.filterDownloadLog(null, 10), [], "空输入不能抛");
});
