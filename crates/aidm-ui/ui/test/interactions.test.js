"use strict";
// 交互回归：这些是 UI 上真实会丢用户输入、或重复建任务的地方。
//
// 无 DOM 环境无法直接驱动弹窗，所以这里钉住 app.js 的**接线写法**（项目既有做法见
// polish.test.js 对 armBackdropClose 的同类护栏）：判据取错来源、顺序写反都会复发。
// 行为层能纯函数化的部分在 lib/clipboard.js，由 clipboard.test.js 覆盖。

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const P = require("../lib/polish.js");

const APP = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");

function slice(startMarker, endMarker) {
  const from = APP.indexOf(startMarker);
  assert.ok(from >= 0, `app.js 找不到起点: ${startMarker}`);
  const to = APP.indexOf(endMarker, from);
  assert.ok(to > from, `app.js 找不到终点: ${endMarker}`);
  return APP.slice(from, to);
}

test("遮罩关闭的第二判据必须是 mouseup 的真实目标，不能用 click.target 冒充", () => {
  const body = slice("function armBackdropClose(mask, close) {", "function closeLayer(mask) {");
  assert.ok(body.includes('mask.addEventListener("mouseup"'), "缺少 mouseup 记录");
  assert.ok(body.includes("upOnMask = e.target === mask;"), "mouseup 未记录松开位置");
  assert.ok(body.includes("decide(downOnMask, upOnMask)"), "判据没有用真实的松开位置");
  assert.ok(
    !body.includes("decide(downOnMask, e.target === mask)"),
    "错误写法：click.target 在「背景按下、内部松开」时也是遮罩"
  );
});

test("openLayer 只在首次打开时记录焦点来源（重复打开不得覆盖）", () => {
  const body = slice("function openLayer(mask, firstEl) {", "function armBackdropClose");
  const pushAt = body.indexOf("layerStack.push(mask)");
  const focusAt = body.indexOf("lastFocus = document.activeElement");
  assert.ok(pushAt >= 0 && focusAt >= 0, "openLayer 结构变了，请同步本测试");
  assert.ok(body.includes("if (!layerStack.includes(mask))"), "缺少「是否首次打开」判断");
  assert.ok(focusAt < pushAt, "lastFocus 必须写在首次打开分支里");
});

test("候选框已打开时，新的剪贴板命中必须合并而不是重置", () => {
  const body = slice("async function openCandidateDialog(ev) {", "async function downloadSelectedCandidates");
  assert.ok(body.includes("mergeClipboardCandidates(items);"), "缺少合并分支");
  assert.ok(body.includes('classList.contains("hidden")'), "合并分支缺少「是否已打开」判断");
  const mergeAt = body.indexOf("mergeClipboardCandidates(items);");
  const resetAt = body.indexOf("cand = {");
  assert.ok(mergeAt >= 0 && resetAt > mergeAt, "合并必须发生在重置 cand 之前");
});

test("候选框首次打开不聚焦搜索框，焦点交给对话框容器", () => {
  const body = slice("async function openCandidateDialog(ev) {", "async function downloadSelectedCandidates");
  // 回归：剪贴板一命中就弹框，焦点落进搜索框后用户接下来的按键会被当成搜索。
  assert.ok(
    !body.includes(
      'openLayer(document.getElementById("cand-mask"), document.getElementById("cand-search"))'
    ),
    "搜索框又成了候选框的首次焦点"
  );
  assert.ok(
    body.includes(
      'openLayer(document.getElementById("cand-mask"), document.getElementById("cand-dialog"))'
    ),
    "首次焦点应交给 .cand-dialog 容器"
  );
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.ok(html.includes('id="cand-dialog"'), "候选对话框容器缺少 id");
  assert.ok(
    /id="cand-dialog"[^>]*tabindex="-1"/.test(html),
    '候选对话框容器需要 tabindex="-1" 才能承接焦点'
  );
});

test("顶部「重试全部失败」按钮及接线已移除，失败任务的重试入口仍在", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.equal(html.includes("btn-retry-all"), false);
  assert.equal(APP.includes("btn-retry-all"), false);
  assert.equal(APP.includes("retryAllFailed"), false);
  // 失败任务自己的入口（fail-bar / 右键 / 属性面板）保留。
  assert.ok(html.includes('data-fail="retry"'), "fail-bar 的「重试」入口不应被删");
  assert.equal(APP.includes('"retry_failed"'), false, "批量重试字面量应随按钮一起移除");
});

test("顶部失败条改为悬浮浮层，带关闭按钮且不遮挡属性面板", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "..", "styles.css"), "utf8");
  assert.match(
    html,
    /id="fail-bar-close"[^>]*aria-label="[^"]+"/,
    "关闭按钮缺少 id 或 aria-label"
  );
  assert.ok(
    html.indexOf('id="fail-bar-close"') > html.indexOf('data-fail="dir"'),
    "关闭按钮应位于操作按钮之后"
  );
  const rule = css.match(/\.fail-bar\s*\{([\s\S]*?)\}/);
  assert.ok(rule, ".fail-bar 规则不见了，请同步本测试");
  assert.ok(rule[1].includes("position: fixed"), "失败条必须是 fixed 悬浮层，不能占文档流");
  assert.ok(
    css.includes("body:has(#task-props:not(.hidden)) .fail-bar"),
    "属性面板展开时失败条需要让出右侧空间"
  );
});

test("关闭失败条后，本次运行内不再因选中失败任务而弹出", () => {
  assert.match(APP, /let failBarDismissed = false;/, "缺少模块级关闭标志");
  const body = slice("function updateFailBar() {", "// ---- 列表增量渲染");
  assert.match(
    body,
    /if \(failBarDismissed\) \{\s*bar\.classList\.add\("hidden"\);\s*return;/,
    "updateFailBar 必须先检查关闭标志并保持隐藏"
  );
  const at = APP.indexOf('document.getElementById("fail-bar-close").addEventListener');
  assert.ok(at >= 0, "关闭按钮没有接线");
  const end = APP.indexOf("});", at);
  assert.ok(end > at, "关闭按钮监听结构变了，请同步本测试");
  const handler = APP.slice(at, end);
  assert.ok(handler.includes("failBarDismissed = true;"), "点击关闭没有置位标志");
  assert.ok(handler.includes('classList.add("hidden")'), "点击关闭没有立即隐藏失败条");
});

test("「下载选中」有连点保护，且异常路径也复位", () => {
  const body = slice("async function downloadSelectedCandidates() {", "function renderUpdatePage()");
  assert.ok(body.includes("if (candBusy) return;"), "缺少入口保护：连点会重复建任务");
  assert.ok(body.includes("candBusy = true;"), "缺少置位");
  assert.ok(body.includes("candBusy = false;"), "缺少复位");
  assert.ok(body.includes("finally"), "异常路径也要复位，否则按钮永久失效");
});

test("弹窗打开时全局快捷键不作用到后台列表（模态）", () => {
  const from = APP.indexOf('if ((e.shiftKey && e.key === "F10") || e.key === "ContextMenu")');
  assert.ok(from > 0, "F10/ContextMenu 分支不见了？请同步本测试");
  // 同一处理器里，Escape 分支（Escape/F10 之前最近的一次 `if (e.key === \"Escape\")`）
  const escapeAt = APP.lastIndexOf('if (e.key === "Escape")', from);
  assert.ok(escapeAt > 0, "找不到 Escape 分支");
  const between = APP.slice(escapeAt, from);
  assert.ok(
    between.includes("if (topLayer()) return;"),
    "Escape 之后、F10 之前必须有「弹窗打开就提前返回」，否则 Delete/Ctrl+A/空格会删后台任务"
  );
});

test("属性面板：顶部按钮已移除，无任务自动收起，点面板外收起", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.ok(!html.includes('id="btn-props"'), "顶部「属性」按钮应已移除");
  assert.ok(!APP.includes('"btn-props"'), "app.js 不应再引用顶部「属性」按钮");
  const body = slice("function renderProps() {", "function renderListWindow()");
  assert.ok(
    body.includes("if (!task) {") && body.includes("showPropsPanel(false)"),
    "没有可显示的任务时属性面板应自动收起"
  );
  assert.ok(
    APP.includes('closest("#task-props, .data-row, #row-ctx-menu")'),
    "点「任务属性」面板外部应收起面板"
  );
  assert.ok(APP.includes("E.emptyCategoryHint"), "空分类说明不应退回空白");
});

test("属性面板只在「普通单击 + 单选」时打开，列表名称改为双击重命名", () => {
  const clickBody = slice("function onRowClick(e) {", "function onRowDblClick(e) {");
  assert.ok(
    clickBody.includes("plain && selectedIds.size === 1"),
    "多选/带修饰键时不应打开属性面板"
  );
  assert.ok(APP.includes('nameText.addEventListener("dblclick"'), "双击名称才应进入文件名编辑");
  // 取「单击名称」处理器本体，确认里面不再有 startRename（它应只在 dblclick 里）
  const clickHandler = APP.match(/nameText\.addEventListener\("click", \(e\) => \{([\s\S]*?)\}\);/);
  assert.ok(clickHandler, "名称为单击处理器的结构变了，请同步本测试");
  assert.ok(!clickHandler[1].includes("startRename"), "单击名称仍在触发重命名");
});

test("整行即项目：除勾选框/下拉/编辑框外，行内单击（含名称）都打开属性", () => {
  const clickBody = slice("function onRowClick(e) {", "function onRowDblClick(e) {");
  const guard = clickBody.match(/e\.target\.closest\("([^"]+)"\)/);
  assert.ok(guard, "行单击的排除列表结构变了，请同步本测试");
  assert.ok(!guard[1].includes("name-editable"), "名称区域仍被排除，单击名称打不开属性");
  for (const keep of ["rename-input", "rename-wrap", "row-pick", "select"]) {
    assert.ok(guard[1].includes(keep), `单击即交互的 ${keep} 不该触发行单击`);
  }
  // 名称单击只在框选模式下阻止冒泡；否则行处理器收不到，属性面板不会打开
  const clickHandler = APP.match(/nameText\.addEventListener\("click", \(e\) => \{([\s\S]*?)\}\);/);
  assert.ok(clickHandler, "名称单击处理器结构变了，请同步本测试");
  const marqueeAt = clickHandler[1].indexOf("marqueeMode");
  const stopAt = clickHandler[1].indexOf("stopPropagation");
  assert.ok(marqueeAt >= 0 && stopAt > marqueeAt, "名称单击应只在框选模式下阻止冒泡");
});

test("框选模式只能由左键拖拽进入，其它路径一律不开启", () => {
  // 框选模式误开启的实际场景：在列表按下左键后 Alt+Tab / 右键弹出浏览器菜单，
  // mouseup 丢在窗口外，残留的按下状态在之后一次 mousemove 里把列表切进框选。
  // 钉住四道门：开关守卫、按键位兜底、右键/失焦清理。
  assert.doesNotMatch(APP, /marqueeMode = true/, "不能直接赋值开启框选模式");
  assert.match(APP, /if \(on && !\(marqueeDrag && marqueeDrag\.active\)\) return;/, "setMarqueeMode(true) 必须有 active 拖动守卫");
  assert.match(APP, /if \(\(e\.buttons & 1\) === 0\) \{[\s\S]*?cancelMarqueeDrag\(\);/, "鼠标键已松开时必须取消残留拖动");
  assert.match(APP, /document\.addEventListener\("contextmenu", cancelMarqueeDrag, true\)/, "右键必须取消未完成拖动");
  assert.match(
    APP,
    /window\.addEventListener\("blur", \(\) => \{[\s\S]*?cancelMarqueeDrag\(\);[\s\S]*?if \(marqueeMode\) setMarqueeMode\(false\);/, 
    "失焦必须取消拖动并退出框选（从浏览器右键建任务回来不再停在框选态）"
  );
  assert.match(
    APP,
    /if \(!marqueeDrag\.active\) \{[\s\S]*?Date\.now\(\) - marqueeDrag\.at > 1000 \|\| !document\.hasFocus\(\)/,
    "陈旧候选与无焦点窗口不得进入框选"
  );
});

test("批量开始/暂停只处理引擎真正接受的状态，批量删除遵守确认设置", () => {
  // 引擎 resume 只接受 paused/error/verifying，pause 只作用于运行中的 worker；
  // 把 queued 当可操作会让「全部开始/暂停」逐条报错。
  assert.match(APP, /function canStartTask[\s\S]*?return t\.state === "paused" \|\| t\.state === "error";/);
  assert.match(APP, /function canPauseTask[\s\S]*?\["connecting", "downloading", "verifying"\]\.includes\(t\.state\)/);
  // 批量删除不能绕开「删除前确认」设置。
  assert.match(APP, /if \(settingBool\(settingsCache\["ui\.confirm_on_delete"\]\)\) \{\s*openDeleteDialog\(list\.map\(\(t\) => t\.id\), true\);/);
  assert.match(APP, /if \(bulk\) setMarqueeMode\(false\);/);
});

test("框选模式的「选择」表头与数据列对齐，普通模式仍 6 列", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "..", "styles.css"), "utf8");

  // 表头第一个单元格必须是框选模式专用的「选择」，且位于文件名（data-col=0）之前。
  // HTML 现在带 `data-i18n`，断言只看列标识与文本，不绑属性顺序。
  const pickAt = html.indexOf('data-col="pick"');
  assert.ok(pickAt >= 0, "表头缺少框选模式专用的「选择」列");
  assert.ok(pickAt < html.indexOf('data-col="0"'), "「选择」表头必须在文件名列之前");
  const pickTag = html.slice(html.lastIndexOf("<", pickAt), html.indexOf("</div>", pickAt));
  assert.ok(pickTag.includes("选择"), "选择列应有可读标题");
  // 列宽已改为固定（只随窗口等比缩放），表头不再有任何拖拽手柄。
  const headers = html.slice(html.indexOf('id="col-headers"'), html.indexOf('id="list-scroll"'));
  assert.ok(!headers.includes("col-resizer"), "表头不应再有拖拽手柄");

  // 普通模式 7 个原标题必须原样保留，避免新增列把标题挤掉。
  // 「保存位置」列已取消：列表不再重复展示每行的落盘路径（属性面板仍有）。
  const titles = ["文件名", "大小", "进度", "速率", "完成时间", "状态"];
  titles.forEach((title, i) => {
    const re = new RegExp('data-col="' + i + '"[^>]*>' + title);
    assert.ok(re.test(html), `缺少第 ${i} 列表头：${title}`);
  });

  // CSS 显隐：普通模式隐藏，框选模式显示；表头与数据行共用同一套 7 列网格。
  assert.match(css, /\.head-pick\s*\{\s*display:\s*none;\s*\}/);
  assert.match(css, /\.head-row\s+\.head-pick\s*\{\s*display:\s*none;\s*\}/);
  assert.match(
    css,
    /\.list\.marquee\s+\.head-pick\s*\{[^}]*display:\s*flex;[^}]*justify-content:\s*center;[^}]*padding:\s*0\s+2px;/
  );
  assert.match(
    css,
    /\.list\.marquee\s+\.list-row\s*\{[^}]*grid-template-columns:\s*30px\s+var\(--col-0\)/
  );

  // 表头只能在 CSS 层显隐，不能在渲染时动态插删节点（否则列宽/列头会各写一套）。
  assert.equal(APP.includes("head-pick"), false, "表头选择列应由 CSS 控制，不要动态插删 DOM");
});

test("列表速率列：表头改「速率」，行内按状态显示实时/峰值/平均/—", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");

  assert.match(html, /data-col="3"[^>]*>速率/, "列表表头应为「速率」");
  assert.equal(html.includes('data-col="3">速度'), false, "列表表头不应再是「速度」");

  // 行更新必须复用 speedHistory 的纯函数；显示层允许先套中位数平滑。
  assert.ok(
    APP.includes("P.listSpeedCell(speedTask"),
    "速率单元格应使用显示速率与曲线采样"
  );
  assert.ok(
    APP.includes("displayedSpeed(t)"),
    "下载/连接阶段应保留短暂无字节前的最近速率"
  );
  assert.ok(
    APP.includes('speedCell.kind === "none" ? "—" : fmtSpeed(speedCell.bps)'),
    "none 分支应显示 —，其余分支走 fmtSpeed"
  );
  assert.ok(APP.includes('"实时速率"'), "live 的 title 应为“实时速率”");
  assert.ok(APP.includes('T("最高速率 ") + fmtSpeed'), "peak 的 title 应带“最高速率”");
  assert.ok(APP.includes('"平均速率（无峰值采样）"'), "average 的 title 应区分平均值");
  assert.ok(APP.includes("cells.speed.title = speedTip"), "title 应写回单元格");
  // 估算标记必须随曲线持久化，否则重启后平均速度会被当成最高速率。
  assert.ok(
    APP.includes("p.est ? [p.x, p.bps, 1] : [p.x, p.bps]"),
    "估算标记应写入 localStorage"
  );
  assert.ok(APP.includes("if (p[2] === 1) point.est = true;"), "读回历史应恢复估算标记");
});

test("空白右键菜单新增「刷新列表」，刷新完成后重新检测缺失文件", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.match(
    html,
    /id="bulk-ctx-menu"[\s\S]*?data-bulk="refresh"[^>]*>刷新列表<\/button>/,
    "批量右键菜单缺少「刷新列表」项"
  );
  // 原有「全部开始 / 全部暂停 / 全部删除」必须原样保留，可用性判断只依赖勾选项。
  const syncBody = slice("function syncBulkMenu() {", "function openBulkMenu");
  for (const act of ["start", "pause", "delete"]) {
    assert.ok(syncBody.includes(`data-bulk="${act}"`), `批量菜单项 ${act} 不见了`);
  }
  // 点击「刷新列表」：先 refresh()，完成后才检测；不能反过来。
  const at = APP.indexOf('else if (act === "refresh")');
  assert.ok(at >= 0, "「刷新列表」点击分支没有接线");
  const branch = APP.slice(at, APP.indexOf("});", at) + 3);
  const refreshAt = branch.indexOf("refresh()");
  const checkAt = branch.indexOf("checkMissingFiles()");
  assert.ok(refreshAt >= 0, "刷新列表必须先调用 refresh()");
  assert.ok(checkAt > refreshAt, "文件检测必须在 refresh() 完成之后");
  assert.ok(branch.includes("finally"), "刷新失败也要触发检测（finally）");
});

test("缺失文件检测：整行灰度类 + 顶层规则，且不引用主题变量", () => {
  const css = fs.readFileSync(path.join(__dirname, "..", "styles.css"), "utf8");
  const rule = css.match(/\.list-row\.data-row\.file-missing\s*\{([\s\S]*?)\}/);
  assert.ok(rule, "styles.css 缺少 .list-row.data-row.file-missing 规则");
  assert.ok(rule[1].includes("filter: grayscale(1)"), "缺失文件必须整行去色");
  assert.ok(!rule[1].includes("var(--"), "灰度规则不能依赖主题变量，否则换肤会改变效果");
  assert.ok(rule[1].includes("opacity:"), "缺失行应同时弱化");

  assert.equal(typeof P.missingFileIds, "function", "polish.js 必须导出 missingFileIds");
  assert.ok(APP.includes("missingFiles.has(t.id)"), "行渲染没有读取 missingFiles");
});

test("缺失文件检测：首次载入 / 窗口聚焦 / 可见性 / 行同步的接线", () => {
  assert.ok(APP.includes('invoke("paths_exist"'), "缺少 paths_exist 调用");
  assert.ok(APP.includes("function checkMissingFiles()"), "缺少 checkMissingFiles");

  // 首次成功载入列表后触发一次（render() 之后），并用 missingCheckedOnce 防止
  // 600ms 轮询反复做文件 IO。
  const once = slice("async function refreshOnce() {", "/// 把 missingFiles 同步");
  assert.ok(once.includes("missingCheckedOnce"), "首次载入缺少一次性标志");
  const renderAt = once.lastIndexOf("render();");
  const checkAt = once.indexOf("void checkMissingFiles();");
  assert.ok(renderAt >= 0 && checkAt > renderAt, "首次检测应在 render() 之后触发");

  // 任务被删 / 不再是 done 时清掉 id，避免旧行永久灰着。
  assert.ok(once.includes("for (const id of [...missingFiles])"), "缺少 missingFiles 清理");

  // 行级同步：toggle 到 rowEls 的每个 el；创建新行时直接带上类。
  const syncBody = slice("function syncMissingRows() {", "/// 检测已完成任务的目标文件是否仍然存在");
  assert.ok(
    syncBody.includes('el.classList.toggle("file-missing", missingFiles.has(id))'),
    "syncMissingRows 必须按 id 切换 file-missing"
  );
  const buildBody = slice("function buildRowEl(t) {", "function updateRowEl(");
  assert.ok(buildBody.includes('row.classList.add("file-missing")'), "新建行时没有应用缺失样式");

  // 窗口聚焦：250ms 防抖；切回前台（visibilitychange → visible）同样触发。
  assert.ok(APP.includes('window.addEventListener("focus"'), "缺少窗口聚焦监听");
  const schedule = slice("function scheduleMissingCheck() {", 'window.addEventListener("focus"');
  assert.ok(schedule.includes("setTimeout"), "聚焦检测必须防抖");
  assert.ok(schedule.includes("250"), "防抖窗口应为 250ms");
  assert.ok(APP.includes('document.addEventListener("visibilitychange"'), "缺少前台切换监听");
  assert.ok(APP.includes('document.visibilityState === "visible"'), "visibilitychange 应只在可见时检测");
});
test("右键菜单的开始/暂停只作用于右键任务，不扩散到其他选中项", () => {
  const body = slice('ctxMenu.addEventListener("click"', 'async function switchEd2kToHttp');
  assert.ok(body.includes("startTasks([target])"), "右键开始应只作用于右键任务");
  assert.ok(body.includes("pauseTasks([target])"), "右键暂停应只作用于右键任务");
  assert.ok(!body.includes("startSelected()"), "右键开始不能退回批量 startSelected");
  assert.ok(!body.includes("pauseSelected()"), "右键暂停不能退回批量 pauseSelected");
  const onRow = slice("function onRowContext(e) {", "function syncContextMenu(taskArg) {");
  assert.ok(onRow.includes("ctxTaskId = id;"), "右键时必须记录被点的任务 id");
  assert.ok(APP.includes("let ctxTaskId = null;"), "缺少右键任务 id 的声明");
  // 签名带 `taskArg`：打开菜单时把刚点的那条任务直接传进来，避免"先按旧状态
  // 渲染、再被下一次同步修正"的跳变。终点用下一个函数，避免误截到函数体内的
  // 第一个 `document.querySelectorAll`。
  const sync = slice("function syncContextMenu(taskArg) {", "function showActionToast");
  assert.ok(
    sync.includes("tasks.find((t) => t.id === ctxTaskId)"),
    "右键菜单按钮的可用性也必须按右键任务判断"
  );
});

// ---- 选中/右键交互：四条硬约束 ----

/// 剥掉 `//` 行注释与普通块注释：断言只看真实代码，否则解释性注释里
/// 提到 `render()` / `selectOnly()` 会把「不该出现」的断言误判为失败。
function stripComments(js) {
  return js
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((line) => {
      const at = line.indexOf("//");
      return at < 0 ? line : line.slice(0, at);
    })
    .join("\n");
}

test("左键单击不整表重绘：走 syncSelectionDom 而不是 render()", () => {
  // render() 会重建窗口内所有行节点 + 重绘速度曲线 + 重刷工具栏，
  // 单击因此有「点了之后过一会儿才变色」的可感知延迟。右键一直走
  // syncSelectionDom，两者行为应该一致。
  const body = stripComments(slice("function onRowClick(e)", "function onRowDblClick(e)"));
  assert.ok(body.includes("syncSelectionDom()"), "单击后应同步选中样式");
  assert.ok(!/\brender\(\)/.test(body), "单击不应触发整表重绘");
});

test("右键删除：框选状态删勾选集合，非框选状态只删右键任务", () => {
  // 之前的接线是无条件 requestDelete([...selectedIds])：没选中时删不掉，右键 A 却删了
  // 选中的 B。正确语义按模式分流：框选=批量，非框选=只删右键那一条。
  const body = stripComments(slice('ctxMenu.addEventListener("click"', 'async function switchEd2kToHttp'));
  assert.ok(body.includes("if (marqueeMode) await requestDelete([...selectedIds])"), "框选状态应删除勾选集合");
  assert.ok(body.includes("else if (target) await requestDelete([target.id])"), "非框选状态应只删右键任务");
});

test("右键只弹菜单，不改选中集合", () => {
  const body = stripComments(slice("function onRowContext(e)", "function syncSelectionDom("));
  assert.ok(body.includes("ctxTaskId = id"), "右键要记住目标任务");
  assert.ok(!body.includes("selectOnly("), "右键不得切换选中");
  assert.ok(!body.includes("syncSelectionDom("), "右键不得重刷选中样式");
  // 菜单动作按 ctxTaskId 定位，因此「删除」的可用性不能再依赖 selectedIds。
  const sync = stripComments(slice("function syncContextMenu(", "function showActionToast("));
  assert.ok(!sync.includes("selectedIds.size"), "菜单可用性不应依赖选中集合");
});

test("列表区域兜底吃掉原生右键菜单", () => {
  const body = slice('document.getElementById("list-root")', "listScroll.addEventListener(\"mousedown\"");
  assert.ok(body.includes('addEventListener("contextmenu"'), "list-root 缺少 contextmenu 兜底");
  assert.ok(body.includes("preventDefault()"), "兜底必须阻止原生菜单");
  assert.ok(body.includes(".rename-input"), "重命名输入框应保留原生菜单");
});

test("右键菜单项常驻显示，条件不满足用禁用态表达", () => {
  // 以前是按状态隐藏（不显示不可用项），菜单项数会跳变，也看不出为什么点不了。
  const sync = stripComments(slice("function syncContextMenu(", "function showActionToast("));
  assert.ok(!/classList\.toggle\("hidden", !visible\)/.test(sync), "菜单项不应再按条件隐藏");
  assert.ok(sync.includes("btn.disabled = !enabled"), "条件不满足应为禁用态");
  assert.ok(/show\("open-file", isDone\)/.test(sync), "打开文件应以「已完成且有路径」为可点条件");
  assert.ok(/show\("http-source", !offline && isEd2k && !isDone\)/.test(sync), "HTTP 源应以 eD2k 且未完成为可点条件");
  // updateToolbar 曾把非本地动作无条件重置为 !offline，会把刚灰显的项又点亮。
  const bar = stripComments(slice("function updateToolbar() {", "function updateLimitPills() {"));
  assert.ok(!bar.includes('querySelectorAll(".ctx-item")'), "updateToolbar 不得再批量改写菜单项禁用态");
  assert.ok(bar.includes("syncContextMenu()"), "菜单开着时应由 syncContextMenu 刷新可用性");
});

test("右键菜单分隔线：分组存在，且空分组不留线", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  const menu = html.slice(html.indexOf('id="row-ctx-menu"'), html.indexOf("</nav>", html.indexOf('id="row-ctx-menu"')));
  const seps = (menu.match(/class="ctx-sep"/g) || []).length;
  assert.ok(seps >= 2, `右键菜单应有多条分组线，实际 ${seps}`);
  // 开始/暂停互斥隐藏时不留下悬空的顶部分隔线
  const js = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
  assert.ok(js.includes("function normalizeSeparators()"), "缺少分隔线归一化");
  assert.ok(js.includes("normalizeSeparators();"), "syncContextMenu 应调用归一化");
});
