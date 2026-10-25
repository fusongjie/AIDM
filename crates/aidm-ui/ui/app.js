// AIDM UI：列表 / 设置 / 队列 / 定时。仅回环 IPC（invoke），零 HTTP。
(function () {
  // 取词是纯查表，用函数声明（提升）以便在模块任何位置安全调用；
  // 语言包没加载时直接回退键名（即中文原文）。
  function T(key, vars) {
    const api = window.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  }
  const invoke = window.__TAURI__?.core?.invoke;
  const listen = window.__TAURI__?.event?.listen;
  // 设置表单的纯逻辑（校验/规范化）。与引擎的声明式设置表对齐，见
  // ui/lib/settings_form.js 与 ui/test/settings_form.test.js。
  const SF = window.AidmSettingsForm || {};
  // 统一切片视图的纯逻辑（范围换算、覆盖比例、子区间几何）；DOM 渲染在本文件。
  const UN = window.AidmUnified || {};

  // ---- 每服务器连接数例外 ----

  let hostConns = [];

  function normalizeDays(raw) {
    return SF.normalizeDays ? SF.normalizeDays(raw) : String(raw || "");
  }

  async function refreshHostConns() {
    const resp = await send({ op: "host_conns_list" });
    hostConns = Array.isArray(resp.hosts) ? resp.hosts : [];
    renderHostConnRows();
  }

  function renderHostConnRows() {
    const tbody = document.getElementById("host-conn-rows");
    if (!tbody) return;
    tbody.textContent = "";
    if (!hostConns.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "hint";
      td.textContent = T("没有例外，所有服务器使用全局连接数");
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const item of hostConns) {
      const tr = document.createElement("tr");
      const host = document.createElement("td");
      host.textContent = item.host;
      const conns = document.createElement("td");
      conns.textContent = item.max_conns == null ? "—" : String(item.max_conns);
      const limit = document.createElement("td");
      limit.textContent = item.speed_limit_kbps == null ? "—" : String(item.speed_limit_kbps);
      const act = document.createElement("td");
      const del = document.createElement("button");
      del.type = "button";
      del.className = "tool";
      del.textContent = T("删除");
      del.addEventListener("click", () => removeHostConn(item.host));
      act.appendChild(del);
      tr.append(host, conns, limit, act);
      tbody.appendChild(tr);
    }
  }

  const KIB = 1024;
  const ROW_H = 36;
  const OVERSCAN = 8;
  const COL_MIN = 60;
  // 列宽（基准宽，实际显示会乘以 colScale）。
  // 顺序与表头 `data-col` 一致：文件名 / 大小 / 进度 / 速率 / 完成时间 / 状态。
  //
  // **列宽不可拖拽调整**：这里的值是唯一来源，用户只能通过改变窗口尺寸
  // 让所有列按等比缩放（见 computeColumnScale）。所以不再有 localStorage
  // 存档，也不再需要"预设版本"来作废旧存档。
  const COL_DEFAULTS = [280, 70, 225, 85, 80, 60];

  const STATE_TEXT = {
    queued: T("排队中"),
    connecting: T("连接中"),
    downloading: T("下载中"),
    paused: T("已暂停"),
    verifying: T("校验中"),
    done: T("已完成"),
    error: T("失败"),
  };
  // 状态文案走语言包；缺失时回退内置中文，不让界面出现裸键名。
  function stateText(state) {
    const key = "state." + state;
    const tr = T(key);
    return tr && tr !== key ? tr : STATE_TEXT[state] || state || "—";
  }
  function sliceStateText(state) {
    const key = "slice.state." + state;
    const tr = T(key);
    return tr && tr !== key ? tr : UN.sliceStateText ? UN.sliceStateText(state) : state || "—";
  }
  function assignStateText(state) {
    const key = "assign.state." + state;
    const tr = T(key);
    return tr && tr !== key ? tr : UN.assignStateText ? UN.assignStateText(state) : state || "—";
  }
  function segStatusText(state) {
    const key = "seg.status." + state;
    const tr = T(key);
    return tr && tr !== key ? tr : SEG_STATUS_TEXT[state] || state || "—";
  }
  function kindLabelText(kind) {
    const key = "kind." + kind;
    const tr = T(key);
    return tr && tr !== key ? tr : KIND_LABEL[kind] || kind || "—";
  }
  function fieldRangeText(key) {
    const text = FIELD_RANGE[key];
    return text ? T(text) : "";
  }
  const SEG_STATUS_TEXT = {
    pending: T("等待"),
    running: T("下载中"),
    done: T("完成"),
    error: T("失败"),
  };
  const SETTINGS_SAVE_FAILED = T("设置保存失败，请重试");
  const CRON_INVALID = T("定时格式不对，例如 0 2 * * *");
  const FIELD_RANGE = {
    "conn.global_conn_cap": T("请输入 1–1024 之间的整数"),
    "conn.retry_max": T("请输入 0–20 之间的整数"),
    "conn.retry_backoff_ms": T("请输入 0.1–60 秒"),
  };
  const FIELD_BOUNDS = {
    "conn.global_conn_cap": [1, 1024],
    "conn.retry_max": [0, 20],
  };
  // 与引擎 `aidm_ipc::AIDM_EXT_ID` / `browser.allowed_ext_ids` 默认值相同。
  const ENGINE_DEFAULT_EXT_ID = "npapgdblbbcppnbmhgdnmdbggfdnpahg";
  const E = window.AidmErrors || {};
  const P = window.AidmPolish || {};
  const U = window.AidmUpdate || {};
  const CB = window.AidmClipboard || {};
  // 国际化：`I18n.t` 直达；语言包缺失时回退 en-US，再回退键名（便于发现漏译）。
  const I18n = window.AidmI18n || { t: (k) => k, init: () => "zh-CN", apply: () => {}, available: () => [], setLanguage: () => false, language: () => "zh-CN" };
  const EXT_AUTH_EXPIRED = E.EXT_AUTH_EXPIRED || T("登录信息已失效，请回到网页重新点下载");
  const FAIL_GENERIC = E.FAIL_GENERIC || T("下载失败");
  const OFFER_EXPIRED_TEXT = T("候选已过期，请在页面上重新收集");
  const HOST_STATUS_FAIL = T("无法检测浏览器连接状态，请重试");
  const LAST_EXT_CONFIRM = T("这是最后一个允许的扩展，确定删除？");
  const UNCERTAIN_TEXT = T("无法确认是否已交给 AIDM，请在 AIDM 列表中查看");
  const LIST_LOAD_FAIL = E.LIST_LOAD_FAIL || T("无法连接下载引擎，请确认 AIDM 正在运行后重试");
  const ADD_DOWNLOAD_FAIL = E.ADD_DOWNLOAD_FAIL || T("添加下载失败，请重试");
  const PROPS_LOAD_FAIL = E.PROPS_LOAD_FAIL || T("无法获取任务信息，请稍后重试");
  const OP_FAIL = E.OP_FAIL || T("操作失败，请重试");
  const SETTINGS_LOAD_FAIL = E.SETTINGS_LOAD_FAIL || T("无法读取设置，请重试");
  const OPEN_DIR_FAIL = E.OPEN_DIR_FAIL || T("无法打开目录");
  const OPEN_INSTALL_FAIL = E.OPEN_INSTALL_FAIL || T("无法打开安装说明");
  const COPY_ERROR_DETAIL = E.COPY_ERROR_DETAIL || T("复制错误详情");
  const DISCARD_SETTINGS = E.DISCARD_SETTINGS || T("放弃未保存的修改？");
  const ENGINE_OFFLINE_BANNER = E.ENGINE_OFFLINE_BANNER || T("无法连接下载引擎，正在重新连接…");
  const ENGINE_BRIDGE_MISSING_BANNER = T("当前为网页预览，无法执行真实下载；请打开 AIDM 桌面程序（aidm-ui.exe）");
  const INTERRUPTED_TOOLTIP = E.INTERRUPTED_TOOLTIP || T("程序意外退出，已自动重新排队");
  const HEARTBEAT_STALE_MS = E.HEARTBEAT_STALE_MS || 45000;
  // 传输级失败连续达到该次数才判定引擎离线，避免瞬时抖动误报横幅。
  const ENGINE_FAIL_STREAK_MAX = 3;
  let engineFailStreak = 0;
  const KIND_LABEL = { link: T("链接"), video: T("视频"), audio: T("音频") };

  let tasks = [];
  // 已完成任务里目标文件已不存在（后端 paths_exist 的检测结果）的 id。
  // 只用于整行灰度；检测失败或缺库时保持为空，不影响其它状态。
  let missingFiles = new Set();
  let missingCheckInFlight = null;
  let missingCheckedOnce = false;
  let selectedIds = new Set();
  let anchorId = null;
  let listError = null;
  let listLoading = true;
  let propsVisible = false;
  // 属性面板的详情缓存：列表只带摘要，统一视图（unified_download）在 `status` 详情里。
  // 缓存 2 秒，避免 600ms 刷新时反复请求；失败后 5 秒内不重试。
  let propsDetail = null; // { id, task }
  let propsDetailLoadingId = null;
  let propsDetailAt = 0;
  let propsDetailRetryAt = new Map(); // id -> ts（按任务隔离，全局会互相阻塞）
  let propsDetailSeq = 0; // 请求代次：乱序返回时只接受最新一次
  // 任务速度曲线：按 list 轮询节奏（约 600ms）记录「每个任务下载阶段」的速度，
  // 每个任务保留最近 SPEED_HISTORY_MAX 个点。
  //
  // 横轴不是墙钟，而是引擎给的**净下载耗时** `task.active_ms`（暂停 / 排队 / 退避
  // 都不前进）。暂停时曲线就地冻结、恢复后从原处接着长，中间不会留出暂停的空白。
  const SPEED_HISTORY_MAX = 3600;
  const speedHistory = new Map();
  // 任务当前下载模式（ed2k / multi / single）。模式变化 = 换了一轮下载，
  // 旧曲线必须丢弃，不能把慢协议的历史接在快协议前面。
  const speedMode = new Map();
  // 显示层平滑：最近 3 次采样的中位数，避免单个突发样本把列表/曲线拉出尖峰。
  // 只做视觉平滑，不改变引擎实际传输与统计数据。
  const speedDisplay = new Map();
  // 下载/连接阶段短暂无字节时保留最近一次非零速率，避免列表闪一下后立刻变成「—」。
  const speedHold = new Map();
  // 每个任务本轮速度曲线的起点（active_ms 绝对值）。崩溃回退 / 手动重启后重设，
  // 横轴 = active_ms - 起点，所以「清空后从 0 重新计时」。
  const speedOrigin = new Map();
  // 曲线持久化（bug3）：程序重启后图表不能丢，所以尾部采样点落 localStorage。
  // 只留窗口用得上的尾部（1200 点 ≈ 20 分钟净下载时间），配额不够时自动降级。
  const SPEED_STORE_KEY = "aidm.speedHistory";
  const SPEED_STORE_POINTS = 1200;
  const SPEED_STORE_MIN_POINTS = 150;
  const SPEED_STORE_INTERVAL_MS = 5000;
  let speedStoreSavedAt = 0;
  // 框选（多选）模式：拖框选择 + 每行左侧复选框 + 列表区右键批量菜单
  let marqueeMode = false;
  let marqueeDrag = null;
  // 拖拽结束后的一小段时间内忽略 click（用时间窗而非布尔标志：
  // 若浏览器因 DOM 重建没有派发 click，布尔标志会残留并吞掉下一次正常点击）
  const CLICK_AFTER_DRAG_MS = 250;
  let marqueeDragEndAt = 0;
  let rename = null;
  let renderPending = false;

  function isRenameInputFocused() {
    const el = document.activeElement;
    return !!(el && el.classList && el.classList.contains("rename-input"));
  }
  let pendingOptimistic = null;
  let settingsCache = {};
  let stats = { total_speed: 0, active_conns: 0, speed_limit: 0 };
  let hasStats = false;
  let colWidths = COL_DEFAULTS.slice();
  /** 列宽的等比缩放因子：可视宽 > 基准总宽时 >1，否则保持 1（基准宽 + 横向滚动）。 */
  let colScale = 1;
  let passCleared = false;
  let hasSavedPassword = false;
  let allowedExtIds = [];
  let schedSnap = { next_start_at: null, queued: 0, active: 0 };
  let schedKnown = false;
  let engineOffline = false;
  let lastEngineEventAt = Date.now();
  let settingsLoadFailed = false;
  let engineVersion = "";
  let updateState = U.emptyState();
  /// 已提示过的可用版本，避免引擎重复推送 available 时反复弹 toast。
  let lastUpdateNotice = "";
  let layerStack = [];
  let lastFocus = null;
  let cand = {
    fromClipboard: false,
    clipboardUrls: [],
    addedAny: false,
    offerId: null,
    pageUrl: "",
    title: "",
    items: [],
    truncated: false,
    selected: new Set(),
    kindFilter: "",
    query: "",
    expired: false,
    retryFailed: false,
  };
  /// 「下载选中」进行中标志：连点会把同一批链接重复建任务。
  let candBusy = false;

  function focusableIn(root) {
    return [...root.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])")]
      .filter((el) => !el.disabled && !el.classList.contains("hidden") && el.offsetParent !== null);
  }

  function openLayer(mask, firstEl) {
    if (!mask) return;
    // 弹框出现会改变鼠标焦点；列表里若残留一次未结束的 mousedown，
    // 之后移动鼠标会被误判成框选拖拽。打开任何模态层都先取消它。
    cancelMarqueeDrag();
    // 只有**首次**打开才记"关闭后把焦点还回哪里"。
    // 同一层被重复打开时（典型：候选框开着又收到一次剪贴板提示）若再覆盖，
    // 关闭后焦点会被还给这一层内部、现已隐藏的元素，等于焦点丢到 body 上。
    if (!layerStack.includes(mask)) {
      lastFocus = document.activeElement;
      layerStack.push(mask);
    }
    mask.classList.remove("hidden");
    const focus = firstEl || focusableIn(mask)[0];
    if (focus && focus.focus) focus.focus();
  }

  // 点遮罩关闭弹窗：必须**按下与松开都在遮罩上**才算（判据见 lib/polish.js 的注释）。
  //
  // 只看 `click` 的 `e.target` 是不够的：当 mousedown 与 mouseup 落在不同元素上时，
  // `click` 会派发到两者的**最近公共祖先** —— 于是"在遮罩空白处按下、拖进弹窗松手"
  // 的 click target 也是遮罩（弹窗是遮罩的子元素），单看 click 一样会误关。
  // 所以第二个参数必须取 **mouseup 的真实目标**，不能用 click 的 target 冒充。
  function armBackdropClose(mask, close) {
    if (!mask) return;
    let downOnMask = false;
    let upOnMask = false;
    mask.addEventListener("mousedown", (e) => {
      downOnMask = e.target === mask;
      upOnMask = false;
    });
    mask.addEventListener("mouseup", (e) => {
      upOnMask = e.target === mask;
    });
    mask.addEventListener("click", () => {
      const decide = P.backdropClickCloses || (() => false);
      const shouldClose = decide(downOnMask, upOnMask);
      downOnMask = false;
      upOnMask = false;
      if (shouldClose) close();
    });
  }

  function closeLayer(mask) {
    mask.classList.add("hidden");
    layerStack = layerStack.filter((m) => m !== mask);
    if (lastFocus && lastFocus.focus && document.body.contains(lastFocus)) {
      try { lastFocus.focus(); } catch { /* ignore */ }
    }
  }

  function topLayer() {
    return layerStack[layerStack.length - 1] || null;
  }

  function taskSegments(task) {
    return task.segments || [];
  }

  // eD2k：条数按连接上限，条内按 454 个 part 细分。
  // 这里只是视觉聚合；part 的真实状态仍来自引擎的 slices 数组。
  function renderP2pSliceLanes(container, p2p, states) {
    const lanes = Math.max(1, Math.min(Number(p2p.max_connections) || 1, states.length));
    const ranges = P.sliceLaneRanges
      ? P.sliceLaneRanges(states.length, lanes)
      : (() => {
          const out = [];
          for (let i = 0; i < lanes; i++) {
            const start = Math.floor((i * states.length) / lanes);
            const end = Math.floor(((i + 1) * states.length) / lanes);
            out.push({ start, end, count: end - start });
          }
          return out;
        })();
    const wrap = document.createElement("div");
    wrap.className = "p2p-slice-lanes";
    const stateText = { 0: T("等待"), 1: T("下载中"), 2: T("完成"), 3: T("校验中") };
    for (const r of ranges) {
      if (!r.count) continue;
      const row = document.createElement("div");
      row.className = "p2p-slice-lane";
      const head = document.createElement("div");
      head.className = "p2p-slice-head";
      const label = document.createElement("span");
      label.textContent = r.count === 1
        ? T("切片 {n}", { n: r.start + 1 })
        : T("切片 {a}–{b}", { a: r.start + 1, b: r.end });
      const stats = document.createElement("span");
      let done = 0;
      let active = 0;
      for (let i = r.start; i < r.end; i++) {
        if (states[i] === 2) done++;
        else if (states[i] === 1) active++;
      }
      stats.textContent = T("完成 {done}/{total}", { done: done, total: r.count }) + (active ? T(" · 活跃 {n}", { n: active }) : "");
      head.append(label, stats);
      row.appendChild(head);
      const bar = document.createElement("div");
      bar.className = "p2p-slice-bar";
      for (let i = r.start; i < r.end; i++) {
        const cell = document.createElement("span");
        const state = Number(states[i]) || 0;
        cell.className = "p2p-slice-cell s" + state;
        cell.title = T("切片 {n} · {state}", { n: i + 1, state: stateText[state] || T("等待") });
        bar.appendChild(cell);
      }
      row.appendChild(bar);
      wrap.appendChild(row);
    }
    container.appendChild(wrap);
  }

  // 单条通路子行：源、状态、子区间、速度、失败原因。
  function buildUnifiedAssignmentRow(a) {
    const row = document.createElement("div");
    row.className = "unified-assignment";

    const src = document.createElement("span");
    src.className = "ua-src";
    src.textContent = UN.shortId(a.source_id);
    src.title = a.source_id || "";

    const state = document.createElement("span");
    state.className = "ua-state";
    state.textContent = assignStateText(a.state);

    const range = document.createElement("span");
    range.className = "ua-range";
    range.textContent = UN.rangeText(a.range, fmtBytes);

    const speed = document.createElement("span");
    speed.className = "ua-speed";
    speed.textContent = fmtSpeed(UN.parseDec(a.transfer_rate_bps) || 0);

    row.append(src, state, range, speed);
    if (a.error) {
      const err = document.createElement("span");
      err.className = "ua-err";
      err.textContent = a.error.message || a.error.code || T("失败");
      row.appendChild(err);
    }
    return row;
  }

  // 原生块状态 → 视觉档位。未知一律按 pending（灰），不猜。
  function nativeCellState(b) {
    const s = String((b && b.state) || "");
    if (s === "done" || (b && b.verified === true)) return "done";
    if (s === "active" || s === "checking") return "active";
    if (s === "failed" || s === "error") return "failed";
    return "pending";
  }

  function nativeCellText(b) {
    const t = { done: T("已完成"), active: T("下载中"), pending: T("未开始"), failed: T("失败") };
    return t[nativeCellState(b)] || T("未知");
  }

  // 单个切片：有原生块时按块等分进度条（一格 = 一个原生块），
  // 否则回退到覆盖率填充 + 通路细线。
  function buildUnifiedSliceRow(slice, index) {
    const row = document.createElement("div");
    row.className = "unified-slice";

    const cov = UN.coverage(slice);
    const blocks = Array.isArray(slice.native_blocks) ? slice.native_blocks : [];
    const assignments = Array.isArray(slice.assignments) ? slice.assignments : [];

    // 标题：左「切片 N」，右百分比。范围由进度条表达，不再重复文字。
    const head = document.createElement("div");
    head.className = "seg-head";
    const idLine = document.createElement("span");
    idLine.textContent = T("切片 ") + (index + 1);
    const pctLabel = document.createElement("span");
    pctLabel.className = "seg-range slice-pct";
    pctLabel.textContent = cov.percent != null ? cov.percent.toFixed(1) + "%" : "—";
    head.append(idLine, pctLabel);
    row.appendChild(head);

    const bar = document.createElement("div");
    bar.className = "seg-bar unified-bar";
    if (blocks.length) {
      bar.classList.add("native-bar");
      for (const b of blocks) {
        const cell = document.createElement("span");
        cell.className = "native-cell st-" + nativeCellState(b);
        cell.title = "#" + b.native_index + " · " + nativeCellText(b);
        bar.appendChild(cell);
      }
    } else {
      const fill = document.createElement("span");
      fill.className = "seg-bar-fill";
      if (cov.percent != null) {
        fill.style.width = cov.percent.toFixed(2) + "%";
      } else {
        // 总长未知：不定长进度，不画虚假百分比。
        bar.classList.add("indeterminate");
        fill.classList.add("indeterminate");
      }
      if (slice.state === "done") fill.classList.add("done");
      if (slice.state === "error") fill.classList.add("err");
      bar.appendChild(fill);

      if (assignments.length) {
        const lanes = document.createElement("div");
        lanes.className = "unified-lanes";
        for (const a of assignments) {
          const geom = UN.laneGeometry(slice, a);
          if (!geom) continue;
          const lane = document.createElement("span");
          lane.className = "unified-lane st-" + (a.state || "pending");
          if (a.error) lane.classList.add("has-error");
          lane.style.left = geom.left.toFixed(2) + "%";
          lane.style.width = geom.width.toFixed(2) + "%";
          lane.title = [
            UN.shortId(a.source_id),
            assignStateText(a.state),
            a.connection_id ? T("连接 ") + UN.shortId(a.connection_id) : "",
          ]
            .filter(Boolean)
            .join(" · ");
          lanes.appendChild(lane);
        }
        if (lanes.childElementCount) bar.appendChild(lanes);
      }
    }
    row.appendChild(bar);

    // 脚注：状态 + 已下 / 总量。百分比已在标题，不再重复。
    const bottom = document.createElement("div");
    bottom.className = "seg-head";
    const state = document.createElement("span");
    state.className = "slice-state";
    state.textContent = sliceStateText(slice.state);
    const bytesLabel = document.createElement("span");
    bytesLabel.className = "seg-range slice-bytes";
    bytesLabel.textContent =
      fmtBytes(cov.stored) + (cov.required != null ? " / " + fmtBytes(cov.required) : "");
    bottom.append(state, bytesLabel);
    row.appendChild(bottom);

    if (assignments.length) {
      const list = document.createElement("div");
      list.className = "unified-assignments";
      for (const a of assignments) list.appendChild(buildUnifiedAssignmentRow(a));
      row.appendChild(list);
    }

    return row;
  }

  // 统一视图入口：有 `unified_download` 就完全用它（包括空切片），
  // 只有缺失时旧调用方才回退到 segments / p2p 渲染。
  //
  // 结构未变时走**增量更新**：500ms 刷新重建 DOM 会让呼吸动画每帧重置，
  // 看起来是“每半秒闪一下”。只有切片/通路数量变化才重建。
  function unifiedSignature(view) {
    const slices = Array.isArray(view && view.slices) ? view.slices : [];
    return (
      slices.length +
      "|" +
      slices
        .map(function (s) {
          const nb = Array.isArray(s.native_blocks) ? s.native_blocks.length : 0;
          const as = Array.isArray(s.assignments) ? s.assignments.length : 0;
          return nb + ":" + as;
        })
        .join(",")
    );
  }

  function updateUnifiedSliceRow(row, slice) {
    const cov = UN.coverage(slice);
    const pct = row.querySelector(".slice-pct");
    if (pct) pct.textContent = cov.percent != null ? cov.percent.toFixed(1) + "%" : "—";
    const st = row.querySelector(".slice-state");
    if (st) st.textContent = sliceStateText(slice.state);
    const by = row.querySelector(".slice-bytes");
    if (by) {
      by.textContent =
        fmtBytes(cov.stored) + (cov.required != null ? " / " + fmtBytes(cov.required) : "");
    }
    const blocks = Array.isArray(slice.native_blocks) ? slice.native_blocks : [];
    const cells = row.querySelectorAll(".native-cell");
    for (let i = 0; i < cells.length && i < blocks.length; i++) {
      const next = "native-cell st-" + nativeCellState(blocks[i]);
      if (cells[i].className !== next) cells[i].className = next;
      cells[i].title = "#" + blocks[i].native_index + " · " + nativeCellText(blocks[i]);
    }
    const fill = row.querySelector(".seg-bar-fill");
    if (fill) {
      if (cov.percent != null) fill.style.width = cov.percent.toFixed(2) + "%";
      fill.classList.toggle("done", slice.state === "done");
      fill.classList.toggle("err", slice.state === "error");
    }
  }

  function renderUnifiedSlices(container, view, title) {
    const slices = Array.isArray(view.slices) ? view.slices : [];
    const total = view.completeness ? Number(view.completeness.total_count) : NaN;
    if (title) {
      title.textContent = T("props.segments", {
        n: Number.isFinite(total) ? total : slices.length,
      });
    }

    // 结构没变：原地更新数值与颜色，保留正在播放的呼吸动画。
    const sig = unifiedSignature(view);
    if (container.dataset.sig === sig && container.querySelector(".unified-slice")) {
      const rows = container.querySelectorAll(".unified-slice");
      for (let i = 0; i < slices.length && i < rows.length; i++) {
        updateUnifiedSliceRow(rows[i], slices[i]);
      }
      return;
    }
    container.dataset.sig = sig;
    container.textContent = "";

    const activity = UN.activityText(view.activity);
    const wait = view.wait ? UN.waitText(view.wait.reason) : "";
    if (activity || wait) {
      const line = document.createElement("p");
      line.className = "props-hint";
      line.textContent = [activity, wait ? T("等待：") + wait : ""].filter(Boolean).join(" · ");
      container.appendChild(line);
    }

    if (!slices.length) {
      const p = document.createElement("p");
      p.className = "props-hint";
      p.textContent =
        view.status === "queued" || view.status === "connecting"
          ? T("切片尚未规划，请稍候…")
          : T("暂无切片数据");
      container.appendChild(p);
      return;
    }

    for (let i = 0; i < slices.length; i++) {
      container.appendChild(buildUnifiedSliceRow(slices[i], i));
    }

    if (view.completeness && view.completeness.complete === false) {
      const p = document.createElement("p");
      p.className = "props-hint";
      p.textContent =
        T("仅显示部分切片（共 ") +
        (Number.isFinite(total) ? total : slices.length) +
        T(" 个），其余可稍后刷新。");
      container.appendChild(p);
    }

    if (view.error) {
      const p = document.createElement("p");
      p.className = "props-hint";
      p.textContent = T("错误：") + (view.error.message || view.error.code || T("未知"));
      container.appendChild(p);
    }
  }

  function fmtBytes(n) {
    if (n == null) return T("未知");
    if (n < 1024) return n + " B";
    const units = ["KB", "MB", "GB", "TB"];
    let v = n;
    let i = -1;
    do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
    return v.toFixed(v >= 100 ? 0 : 1) + " " + units[i];
  }

  function fmtSpeed(bps) {
    return bps > 0 ? fmtBytes(bps) + "/s" : "—";
  }

  function formatLimitKbps(kbps) {
    kbps = Number(kbps) || 0;
    if (kbps === 0) return T("不限");
    if (kbps >= KIB) {
      const mb = kbps / KIB;
      if (mb % 1 === 0 || mb >= 100) return Math.round(mb) + " MB/s";
      return mb.toFixed(1) + " MB/s";
    }
    return kbps + " KB/s";
  }

  function formatLimitBps(bps) {
    return formatLimitKbps(Math.floor((Number(bps) || 0) / KIB));
  }

  function validateDownloadUrl(url) {
    const u = (url || "").trim();
    if (!u) return { ok: false, code: "empty", text: E.URL_EMPTY || T("请输入下载链接") };
    const lower = u.toLowerCase();
    let rest = "";
    if (lower.startsWith("magnet:?")) {
      const btih = u.match(/[?&]xt=urn:btih:([0-9a-fA-F]{40}|[A-Za-z2-7]{32})(?:&|$)/i);
      if (btih) return { ok: true, bittorrent: true };
      return { ok: false, code: "scheme", text: T("磁力链接缺少有效的 BTIH") };
    }
    // eD2k（电驴）文件链接：|file|名|字节|32位MD4哈希|…
    if (lower.startsWith("ed2k://")) {
      const t = u.split("|");
      const okShape =
        t.length >= 5 &&
        t[1].trim().toLowerCase() === "file" &&
        t[2].trim() !== "" &&
        /^\d+$/.test(t[3].trim()) &&
        /^[0-9a-fA-F]{32}$/.test(t[4].trim());
      if (okShape) return { ok: true, ed2k: true };
      return {
        ok: false,
        code: "scheme",
        text: T("eD2k 文件链接格式应为 ed2k://|file|文件名|字节数|32位哈希|/"),
      };
    }
    // 私有封装协议：多家客户端的私有格式。引擎会在新建时解码成真实地址，
    // 这里只做"看起来像不像"的放行，避免把用户挡在对话框外面。
    for (const scheme of ["thunder://", "thunders://", "qqdl://", "flashget://", "fs2you://"]) {
      if (lower.startsWith(scheme)) {
        const payload = u.slice(scheme.length).trim();
        if (payload.length < 8) {
          return { ok: false, code: "scheme", text: T("链接内容不完整") };
        }
        return { ok: true, wrapped: scheme.slice(0, -3) };
      }
    }
    if (lower.startsWith("https://")) rest = u.slice(8);
    else if (lower.startsWith("http://")) rest = u.slice(7);
    else if (lower.startsWith("ftp://") || lower.startsWith("ftps://")) rest = u.slice(u.indexOf("://") + 3);
    else return { ok: false, code: "scheme", text: T("仅支持 http:// / https:// / ftp:// / ftps:// / magnet: 或封装链接") };
    if (!rest || rest.startsWith("/") || rest.startsWith("?") || rest.startsWith("#")) {
      return { ok: false, code: "scheme", text: T("链接缺少主机名") };
    }
    return { ok: true };
  }

  function settingsDiff(original, edited, passAction) {
    const out = [];
    const keys = Object.keys(edited).sort();
    for (const key of keys) {
      if (key === "proxy.pass" || key === "proxy.has_password") continue;
      const nv = String(edited[key] ?? "").trim();
      const ov = String(original[key] ?? "").trim();
      if (nv !== ov) out.push({ key, value: nv });
    }
    if (passAction === "clear") out.push({ key: "proxy.pass", value: "" });
    else if (passAction && passAction !== "omit") out.push({ key: "proxy.pass", value: passAction });
    return out;
  }

  function settingBool(v) {
    return v === true || v === "true";
  }

  function settingStr(v) {
    if (v == null) return "";
    return String(v);
  }

  function settingsSetUserError(key, respOrCode, min, max) {
    if (E.settingsSetUserError) return E.settingsSetUserError(key, respOrCode, min, max);
    let c = "";
    let mn = min;
    let mx = max;
    if (respOrCode && typeof respOrCode === "object") {
      c = String(respOrCode.code || "").trim();
      if (mn == null) mn = respOrCode.min;
      if (mx == null) mx = respOrCode.max;
    } else {
      c = String(respOrCode || "").trim();
    }
    if (c === "invalid_cron") return CRON_INVALID;
    if (c === "invalid_value" && mn != null && mx != null) {
      if (key === "conn.retry_backoff_ms") {
        return T("请输入 {min}–{max} 秒", { min: Number(mn) / 1000, max: Number(mx) / 1000 });
      }
      return T("请输入 {min}–{max} 之间的整数", { min: mn, max: mx });
    }
    return SETTINGS_SAVE_FAILED;
  }

  function parseIntInRange(raw, min, max) {
    const t = String(raw ?? "").trim();
    if (!/^-?\d+$/.test(t)) return null;
    const n = Number(t);
    if (!Number.isInteger(n) || n < min || n > max) return null;
    return n;
  }

  function backoffMsFromSeconds(raw) {
    const t = String(raw ?? "").trim();
    const n = Number(t);
    if (!Number.isFinite(n) || n < 0.1 || n > 60) return null;
    return Math.round(n * 1000);
  }

  function secondsFromBackoffMs(ms) {
    const n = Number(String(ms ?? "1000").trim());
    if (!Number.isFinite(n) || n < 0) return "1";
    const secs = n / 1000;
    return String(secs);
  }

  function describeTaskError(task) {
    return E.describeTaskError ? E.describeTaskError(task) : { sentence: FAIL_GENERIC, raw: "", action: null, isFailure: true, isInterrupted: false };
  }

  function taskFailReason(task) {
    return describeTaskError(task).sentence;
  }

  function isInterrupted(task) {
    return !!(task && E.isInterrupted ? E.isInterrupted(task) : String(task.error_code || "").trim() === "interrupted");
  }

  function isFailedTask(task) {
    return !!(task && task.state === "error" && !isInterrupted(task));
  }

  function cronFieldOk(field, min, max) {
    if (!field) return false;
    return field.split(",").every((atom) => cronAtomOk(atom, min, max));
  }

  function cronAtomOk(atom, min, max) {
    const parts = atom.split("/");
    const range = parts[0];
    const step = parts.length > 1 ? Number(parts[1]) : null;
    if (parts.length > 2) return false;
    if (step != null && (!Number.isInteger(step) || step <= 0)) return false;
    if (range === "*") return true;
    if (range.includes("-")) {
      const [a, b] = range.split("-");
      const lo = Number(a);
      const hi = Number(b);
      return Number.isInteger(lo) && Number.isInteger(hi) && lo >= min && hi <= max && lo <= hi;
    }
    const n = Number(range);
    return Number.isInteger(n) && n >= min && n <= max;
  }

  function isValidCron5(expr) {
    const t = String(expr || "").trim();
    if (!t) return true;
    const parts = t.split(/\s+/);
    if (parts.length !== 5) return false;
    return cronFieldOk(parts[0], 0, 59)
      && cronFieldOk(parts[1], 0, 23)
      && cronFieldOk(parts[2], 1, 31)
      && cronFieldOk(parts[3], 1, 12)
      && cronFieldOk(parts[4], 0, 7);
  }

  function cronFieldMatches(field, value, min, max) {
    if (!cronFieldOk(field, min, max)) return false;
    return field.split(",").some((atom) => cronAtomMatches(atom, value, min, max));
  }

  function cronAtomMatches(atom, value, min, max) {
    const slash = atom.split("/");
    const range = slash[0];
    const step = slash.length > 1 ? Number(slash[1]) : 1;
    if (range === "*") return ((value - min) % step) === 0;
    if (range.includes("-")) {
      const [a, b] = range.split("-");
      const lo = Number(a);
      const hi = Number(b);
      return value >= lo && value <= hi && ((value - lo) % step) === 0;
    }
    const n = Number(range);
    if (slash.length > 1) return value >= n && value <= max && ((value - n) % step) === 0;
    return n === value;
  }

  function cronFromPreset(mode, hour, minute, custom) {
    if (mode === "off") return "";
    if (mode === "daily") return minute + " " + hour + " * * *";
    if (mode === "weekdays") return minute + " " + hour + " * * 1-5";
    return String(custom || "").trim();
  }

  function parseSchedMode(cron) {
    const t = String(cron || "").trim();
    if (!t) return { mode: "off", time: null };
    const parts = t.split(/\s+/);
    if (parts.length !== 5) return { mode: "custom", time: null };
    const minute = Number(parts[0]);
    const hour = Number(parts[1]);
    if (!Number.isInteger(minute) || !Number.isInteger(hour) || hour > 23 || minute > 59) {
      return { mode: "custom", time: null };
    }
    if (parts[2] === "*" && parts[3] === "*" && parts[4] === "*") {
      return { mode: "daily", time: [hour, minute] };
    }
    if (parts[2] === "*" && parts[3] === "*" && parts[4] === "1-5") {
      return { mode: "weekdays", time: [hour, minute] };
    }
    return { mode: "custom", time: null };
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function sameYmd(a, b) {
    return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  }

  function formatNextStart(atMs, nowMs) {
    if (atMs == null) return "";
    const at = new Date(Number(atMs));
    const now = new Date(nowMs == null ? Date.now() : nowMs);
    if (Number.isNaN(at.getTime())) return "";
    const hm = pad2(at.getHours()) + ":" + pad2(at.getMinutes());
    if (sameYmd(at, now)) return T("今天 {t}", { t: hm });
    const tom = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    if (sameYmd(at, tom)) return T("明天 {t}", { t: hm });
    if (at.getFullYear() !== now.getFullYear()) {
      return T("{y}年{mo}月{d}日 {t}", { y: at.getFullYear(), mo: at.getMonth() + 1, d: at.getDate(), t: hm });
    }
    return T("{mo}月{d}日 {t}", { mo: at.getMonth() + 1, d: at.getDate(), t: hm });
  }

  function nextCronMs(cron, nowMs) {
    const t = String(cron || "").trim();
    if (!t || !isValidCron5(t)) return null;
    const parts = t.split(/\s+/);
    const d = new Date(nowMs == null ? Date.now() : nowMs);
    d.setSeconds(0, 0);
    d.setMinutes(d.getMinutes() + 1);
    const limit = 366 * 24 * 60;
    for (let i = 0; i < limit; i++) {
      const dow = d.getDay();
      const okMin = cronFieldMatches(parts[0], d.getMinutes(), 0, 59);
      const okHour = cronFieldMatches(parts[1], d.getHours(), 0, 23);
      const okDay = cronFieldMatches(parts[2], d.getDate(), 1, 31);
      const okMon = cronFieldMatches(parts[3], d.getMonth() + 1, 1, 12);
      const okDow = cronFieldMatches(parts[4], dow, 0, 7) || (dow === 0 && cronFieldMatches(parts[4], 7, 0, 7));
      if (okMin && okHour && okDay && okMon && okDow) return d.getTime();
      d.setMinutes(d.getMinutes() + 1);
    }
    return null;
  }

  function formatRetryCountdown(remainMs) {
    if (remainMs <= 0) return T("即将重试");
    const sec = Math.ceil(remainMs / 1000);
    if (sec < 60) return T("{n} 秒后", { n: sec });
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    if (m < 60) return s === 0 ? T("{n} 分钟后", { n: m }) : T("{m} 分 {s} 秒后", { m: m, s: pad2(s) });
    const h = Math.floor(m / 60);
    return T("{h} 小时 {m} 分钟后", { h: h, m: m % 60 });
  }

  function formatQueueStatus(task, nowMs) {
    if (isInterrupted(task)) {
      if (task.retry_at) return T("等待重试 · ") + formatRetryCountdown(Number(task.retry_at) - nowMs);
      return T("排队中");
    }
    if (isFailedTask(task)) return taskFailReason(task);
    if (task.state !== "queued") return stateText(task.state);
    if (task.retry_at) {
      return T("等待重试 · ") + formatRetryCountdown(Number(task.retry_at) - nowMs);
    }
    return T("排队中");
  }

  function retryTooltip(task) {
    if (!task.retry_at || task.retries == null || Number(task.retries) === 0) return "";
    const max = Number(settingStr(settingsCache["conn.retry_max"])) || 5;
    return T("第 {n}/{max} 次重试", { n: task.retries, max: max });
  }

  function currentSchedCron() {
    return settingStr(settingsCache["sched.start_cron"]);
  }

  function resolvedNextStartAt() {
    if (schedKnown && schedSnap.next_start_at) return schedSnap.next_start_at;
    const cron = currentSchedCron();
    return nextCronMs(cron, Date.now());
  }

  function deriveFilename(explicit, url) {
    const name = (explicit || "").trim();
    if (name) {
      const base = name.split(/[/\\]/).pop() || name;
      return base.length > 255 ? [...base].slice(0, 255).join("") : base;
    }
    // URL 路径解析放在 lib/polish.js（可单测）；这里只负责兜底名，
    // 与引擎 resolve_filename 的「URL 路径 > download.bin」两档一致。
    const parsed = P.filenameFromUrl ? P.filenameFromUrl(url) : "";
    return parsed || (P.FILENAME_FALLBACK || "download.bin");
  }

  // ---- 新建下载：链接 → 文件名实时解析 ----
  // autoFilename 记录上次自动填入的值：用户在文件名框里手动改过之后，
  // 再改链接就不覆盖用户输入（清空文件名则恢复自动解析）。
  let autoFilename = "";

  function syncDialogFilename() {
    const urlEl = document.getElementById("dlg-url");
    const nameEl = document.getElementById("dlg-name");
    if (!urlEl || !nameEl) return;
    const next = P.autoFilenameFor
      ? P.autoFilenameFor(nameEl.value, autoFilename, urlEl.value)
      : null;
    if (next == null) return; // 用户手动改过，保持不动
    autoFilename = next;
    if (nameEl.value !== next) nameEl.value = next;
  }

  function resetDialogFilename() {
    autoFilename = "";
  }

  function truncateUrl(url, maxChars) {
    const s = String(url || "");
    if ([...s].length <= maxChars) return s;
    return [...s].slice(0, Math.max(0, maxChars - 1)).join("") + "…";
  }

  function parseExtIdList(raw) {
    const t = String(raw || "").trim();
    if (!t) return [ENGINE_DEFAULT_EXT_ID];
    try {
      const arr = JSON.parse(t);
      if (!Array.isArray(arr)) return [ENGINE_DEFAULT_EXT_ID];
      return arr.map((s) => String(s).trim()).filter(Boolean);
    } catch {
      return [ENGINE_DEFAULT_EXT_ID];
    }
  }

  function hostRegState(resp) {
    if (resp && resp.ok && resp.registered === true) return "registered";
    if (resp && resp.ok && resp.registered === false) return "unregistered";
    return "unavailable";
  }

  function isOfferExpired(resp) {
    if (E.isOfferExpired) return E.isOfferExpired(resp);
    return !!(resp && resp.ok === false && resp.code === "offer_expired");
  }

  function filterCandidateItems(items, kindFilter, query) {
    const q = (query || "").trim().toLowerCase();
    return items.filter((it) => {
      if (kindFilter && it.kind !== kindFilter) return false;
      if (!q) return true;
      return (it.filename || "").toLowerCase().includes(q) || (it.url || "").toLowerCase().includes(q);
    });
  }

  function sourceLabel(source) {
    return source === "ext" ? T("浏览器扩展") : T("手动添加");
  }

  function visibleRange(scrollTop, viewportH, total, rowH, overscan) {
    if (total === 0 || rowH === 0) return { start: 0, end: 0 };
    const first = Math.min(Math.max(total - 1, 0), Math.floor(scrollTop / rowH));
    const visible = Math.floor(viewportH / rowH) + 1;
    const start = Math.max(0, first - overscan);
    const end = Math.min(total, first + visible + overscan);
    return { start, end };
  }

  /** 窗口/容器宽度变化时重算列宽缩放：比基准宽就等比拉长铺满，比基准窄就保持基准宽，
      交给 `.list-scroll` 的横向滚动——不再隐藏任何列。 */
  function computeColumnScale() {
    const scroll = document.getElementById("list-scroll");
    if (!scroll) return 1;
    const avail = scroll.clientWidth;
    if (!avail || avail <= 0) return 1;
    const total = colWidths.reduce((sum, w) => sum + w, 0);
    if (!total) return 1;
    // 框选模式最左侧多出 30px 的复选框列，先从可用宽度里扣掉。
    const list = scroll.closest(".list");
    const pick = list && list.classList.contains("marquee") ? 30 : 0;
    // **不留余量**：让各列之和正好等于可视宽，最后一列的右边缘才能贴住
    // UI 右边（留 1px 会看到一条细缝）。下面的累计取整保证不会因为四舍五入
    // 反而多出 1px 触发横向滚动。
    return Math.max(1, (avail - pick) / total);
  }

  /// recomputeScale=false 用于拖拽：只改被拖的那一列，不让其它列跟着缩放。
  ///
  /// 同时把"所有列之和"写进 `--list-total-w`。表头与行都按这个宽度排布，
  /// 拖宽某列时总宽变大 → 出现横向滚动条；**其它列宽度一个都不动**，
  /// 也不会被裁掉（这正是"后方列被顶走"的根因：之前宽度锁死在容器宽）。
  function applyColumnWidths(recomputeScale) {
    if (recomputeScale) colScale = computeColumnScale();
    const root = document.documentElement;
    // **累计边界取整**，不是逐列 `round(w * scale)`。
    //
    // 逐列舍入每列都会引入 ±0.5px 误差，累起来让最后一列右边缘离 UI 右边
    // 差 1–2px（宽度越碎越明显）。改成先算累计右边界再求差，总和恒等于
    // `round(总基准宽 × scale)`，末列精确贴边。
    let acc = 0;
    let prev = 0;
    colWidths.forEach((w, i) => {
      acc += w;
      const edge = Math.round(acc * colScale);
      // `COL_MIN` 是地板：某一列基准很窄且 scale 很小时会被抬到最小宽，
      // 此时总和会略大于可视宽，交给横向滚动，不裁切。
      root.style.setProperty("--col-" + i, Math.max(COL_MIN, edge - prev) + "px");
      prev = edge;
    });
    const list = document.querySelector(".list");
    const pick = list && list.classList.contains("marquee") ? 30 : 0;
    const total = Math.round(colWidths.reduce((sum, w) => sum + w, 0) * colScale) + pick;
    root.style.setProperty("--list-total-w", total + "px");
  }

  function fmtEta(task) {
    return P.formatFinishCell ? P.formatFinishCell(task) : "—";
  }

  function isRenaming() {
    return !!(rename && rename.id != null);
  }

  function canRename(task) {
    return P.canRenameTask ? P.canRenameTask(task, engineOffline) : !!(task && !engineOffline);
  }

  function segmentPct(seg) {
    if (seg.pos_end == null) return null;
    const span = Math.max(1, seg.pos_end - seg.pos_start + 1);
    return Math.min(100, (seg.done_bytes / span) * 100);
  }

  function segmentIndeterminate(seg) {
    return seg.pos_end == null;
  }

  function fmtByteRange(seg) {
    if (segmentIndeterminate(seg)) return T("{size} – 未知", { size: fmtBytes(seg.pos_start) });
    return fmtBytes(seg.pos_start) + " – " + fmtBytes(seg.pos_end);
  }

  function activeConnectionCount(allTasks) {
    let count = 0;
    for (const t of allTasks) {
      if (t.p2p) { count += Number(t.p2p.active_peers) || 0; continue; }
      count += taskSegments(t).filter((s) => s.status === "running").length;
    }
    return count;
  }

  // 桥接层的可用性错误（非业务错误）
  function isTransportError(code) {
    return /^engine_(unreachable|not_ready|busy|port_missing)/.test(String(code || ""));
  }

  function noteEngineFailure() {
    engineFailStreak += 1;
    if (engineFailStreak >= ENGINE_FAIL_STREAK_MAX) setEngineOffline(true);
  }

  async function send(req) {
    if (!invoke) {
      noteEngineFailure();
      return { ok: false, error: "engine_unreachable" };
    }
    let resp;
    try {
      resp = await invoke("engine_request", { req });
    } catch (error) {
      // 不记录请求参数（可能含 Cookie），保留桥接原始错误供调试定位。
      console.error("AIDM engine_request failed", req.op, error);
      noteEngineFailure();
      return { ok: false, error: "engine_unreachable", detail: String(error) };
    }
    // 界面更新异常不能伪装为“引擎离线”。
    if (resp && resp.ok) {
      lastEngineEventAt = Date.now();
      engineFailStreak = 0;
      setEngineOffline(false);
    } else if (resp && isTransportError(resp.error)) {
      noteEngineFailure();
    }
    return resp;
  }

  function currentCategory() {
    return document.querySelector(".sidebar li.active")?.dataset.cat || "all";
  }

  function filteredTasks() {
    const cat = currentCategory();
    return tasks.filter((t) => {
      if (cat === "done") return t.state === "done";
      if (cat === "error") return isFailedTask(t);
      if (cat === "active") return t.state !== "done" && !isFailedTask(t);
      return true;
    });
  }

  function taskById(id) {
    return tasks.find((t) => t.id === id) || null;
  }

  function primarySelected() {
    if (anchorId != null) {
      const t = taskById(anchorId);
      if (t && selectedIds.has(anchorId)) return t;
    }
    const first = selectedIds.values().next();
    return first.done ? null : taskById(first.value);
  }

  function selectedList() {
    return tasks.filter((t) => selectedIds.has(t.id));
  }

  function setFieldError(id, text) {
    const el = document.getElementById(id);
    if (!el) return;
    if (text) {
      el.textContent = text;
      el.classList.remove("hidden");
    } else {
      el.textContent = "";
      el.classList.add("hidden");
    }
  }

  function canStartTask(t) {
    if (!t) return false;
    // `queued` 已在调度队列里，引擎的 resume 只接受 paused/error/verifying；
    // 对 queued 发 resume 会回 `resume_from_queued`，批量操作因此误报失败。
    return t.state === "paused" || t.state === "error";
  }

  function canPauseTask(t) {
    if (!t) return false;
    // 引擎 pause 只作用于正在跑的 worker；queued 返回 task_not_running。
    return ["connecting", "downloading", "verifying"].includes(t.state);
  }

  function setEngineOffline(off) {
    const next = !!off;
    if (engineOffline === next) {
      syncOfflineUi();
      return;
    }
    engineOffline = next;
    syncOfflineUi();
  }

  function syncOfflineUi() {
    const banner = document.getElementById("engine-offline-banner");
    if (banner) {
      banner.textContent = invoke ? ENGINE_OFFLINE_BANNER : ENGINE_BRIDGE_MISSING_BANNER;
      banner.classList.toggle("hidden", !engineOffline);
    }
    updateToolbar();
  }

  function updateToolbar() {
    const sel = selectedList();
    const n = sel.length;
    const off = engineOffline;
    document.getElementById("btn-new").disabled = off;
    document.getElementById("empty-new").disabled = off;
    document.getElementById("btn-start").disabled = off || !sel.some(canStartTask);
    document.getElementById("btn-pause").disabled = off || !sel.some(canPauseTask);
    document.getElementById("btn-delete").disabled = off || n === 0;
    // 右键菜单项的可用性只由 syncContextMenu 按「右键任务 + 当前条件」计算。
    // 这里只在菜单开着时刷新一次：以前无条件把非本地动作重置成 !offline，
    // 会把刚灰显的项又点亮（"先灰后亮"的跳变来源）。
    const menuEl = document.getElementById("row-ctx-menu");
    if (menuEl && !menuEl.classList.contains("hidden")) syncContextMenu();
  }

  function updateLimitPills() {
    const kbps = Number(settingStr(settingsCache["speed.global_limit_kbps"])) || 0;
    const fromStats = hasStats ? formatLimitBps(stats.speed_limit) : formatLimitKbps(kbps);
    document.getElementById("st-limit").textContent = T("限速状态：") + fromStats;
  }

  function updateStatusbar() {
    const active = tasks.filter((t) => ["connecting", "downloading"].includes(t.state));
    const speed = hasStats ? stats.total_speed : active.reduce((s, t) => s + (t.speed || 0), 0);
    const conns = hasStats ? stats.active_conns : activeConnectionCount(tasks);
    document.getElementById("st-speed").textContent = T("总速度：") + fmtBytes(speed) + "/s";
    document.getElementById("st-active").textContent = T("活跃任务数：") + active.length;
    document.getElementById("st-conns").textContent = T("连接数：") + conns;
    updateLimitPills();
    updateSchedChip();
  }

  function updateSchedChip() {
    const chip = document.getElementById("st-sched");
    const at = resolvedNextStartAt();
    if (!currentSchedCron() || !at) {
      chip.classList.add("hidden");
      return;
    }
    chip.classList.remove("hidden");
    chip.textContent = T("下次启动 ") + formatNextStart(at, Date.now());
  }

  function showPropsPanel(show) {
    propsVisible = show;
    document.getElementById("task-props").classList.toggle("hidden", !show);
    renderProps();
  }

  // 采样点的横坐标：引擎的净下载耗时（毫秒）。`active_ms` 缺失时退化为
  // 「只在下载阶段累加墙钟」，语义一致（暂停同样不前进）。
  function speedSampleX(t, last, now) {
    const raw = Number(t.active_ms);
    if (Number.isFinite(raw) && raw >= 0) return raw;
    const base = last ? last.x : 0;
    const running = t.state === "connecting" || t.state === "downloading";
    if (!last || !running) return base;
    return base + Math.min(5000, Math.max(0, now - last.t));
  }

  // 曲线持久化：读回上次退出前的采样点（`[x, bps]` 紧凑存储）。
  function loadSpeedHistory() {
    let raw = null;
    try {
      raw = JSON.parse(localStorage.getItem(SPEED_STORE_KEY) || "null");
    } catch {
      return; // 存坏了就当没有：曲线会重新长出来，不影响下载
    }
    if (!raw || typeof raw !== "object") return;
    for (const [key, entry] of Object.entries(raw)) {
      const id = Number(key);
      if (!Number.isFinite(id)) continue;
      // 新格式 { o: 本轮起点, p: [[x,bps],…] }；旧格式是裸数组（起点视为 0）。
      let pts = entry;
      let origin = 0;
      if (entry && !Array.isArray(entry) && Array.isArray(entry.p)) {
        origin = Math.max(0, Number(entry.o) || 0);
        pts = entry.p;
      }
      if (!Array.isArray(pts)) continue;
      const arr = [];
      for (const p of pts) {
        if (!Array.isArray(p) || p.length < 2) continue;
        const x = Number(p[0]);
        const bps = Number(p[1]);
        if (!Number.isFinite(x) || !Number.isFinite(bps)) continue;
        // t = 0：时间戳只用于同拍去重，重启后没有意义。
        // 第三个元素 = 估算标记（平均速度补点），列表据此不把平均值当峰值。
        const point = { x, bps, t: 0 };
        if (p[2] === 1) point.est = true;
        arr.push(point);
      }
      if (arr.length > 1) {
        speedHistory.set(id, arr);
        speedOrigin.set(id, origin);
      }
    }
  }

  // 落盘。默认按 5 秒节流（`force` 用于退出前）；配额不够就砍尾部点数重试。
  function saveSpeedHistory(force) {
    const now = Date.now();
    if (!force && now - speedStoreSavedAt < SPEED_STORE_INTERVAL_MS) return;
    speedStoreSavedAt = now;
    const ids = [...speedHistory.keys()].filter((id) => {
      const arr = speedHistory.get(id);
      return arr && arr.length > 1;
    });
    if (!ids.length) {
      // 只有任务全被删光才清存储；「暂时没有可存点」不能抹掉磁盘上的历史，
      // 否则一次误判就会让重启后的曲线永久消失。
      if (speedHistory.size === 0) {
        try { localStorage.removeItem(SPEED_STORE_KEY); } catch { /* ignore */ }
      }
      return;
    }
    for (let keep = SPEED_STORE_POINTS; ; keep = Math.floor(keep / 4)) {
      const out = {};
      for (const id of ids) {
        const arr = speedHistory.get(id);
        out[id] = {
          o: speedOrigin.get(id) || 0,
          p: arr.slice(-keep).map((p) => (p.est ? [p.x, p.bps, 1] : [p.x, p.bps])),
        };
      }
      try {
        localStorage.setItem(SPEED_STORE_KEY, JSON.stringify(out));
        return;
      } catch {
        if (keep <= SPEED_STORE_MIN_POINTS) return; // 配额真的不够：曲线仍在内存里
      }
    }
  }

  // 记录每个任务「下载阶段」的速度采样（由 refresh() 每次 list 后调用）。
  // 只有下载/连接阶段才增长；离开下载阶段时补一个 0 点收尾。
  function displayedSpeed(task) {
    const t = task || {};
    const raw = Math.max(0, Number(t.speed) || 0);
    const active = t.state === "downloading" || t.state === "connecting";
    if (active && raw > 0) {
      speedHold.set(t.id, { bps: raw, at: Date.now() });
      return raw;
    }
    if (active) {
      const held = speedHold.get(t.id);
      if (held && Date.now() - held.at < 5000) return held.bps;
    }
    speedHold.delete(t.id);
    return raw;
  }

  function smoothSpeed(id, bps, state) {
    const raw = Math.max(0, Number(bps) || 0);
    if (state && state !== "downloading") {
      speedDisplay.delete(id);
      return raw;
    }
    const arr = speedDisplay.get(id) || [];
    arr.push(raw);
    if (arr.length > 3) arr.shift();
    speedDisplay.set(id, arr);
    // 启动/轮询间隙的 0 不参与中位数，否则 [0,0,16MB] 会连续显示成 0。
    const positive = arr.filter((v) => v > 0);
    if (!positive.length) return 0;
    positive.sort((a, b) => a - b);
    return positive[Math.floor(positive.length / 2)];
  }

  function sampleTaskSpeeds(list) {
    const now = Date.now();
    const seen = new Set();
    let curveReset = false;
    for (const t of list || []) {
      if (!t || t.id == null) continue;
      seen.add(t.id);
      let arr = speedHistory.get(t.id);
      const rawMs = Number(t.active_ms);
      const mode = String(t.mode || "");
      const prevMode = speedMode.get(t.id);
      if (mode) speedMode.set(t.id, mode);
      if (
        arr && arr.length && mode && prevMode && mode !== prevMode
      ) {
        // eD2k 输给 HTTP（或反过来）：旧曲线直接作废，新协议从当前点重新画。
        speedHistory.delete(t.id);
        speedDisplay.delete(t.id);
        speedOrigin.set(t.id, Number.isFinite(rawMs) && rawMs >= 0 ? rawMs : 0);
        arr = null;
        curveReset = true;
      }
      // 崩溃回退（本轮耗时未入库）与手动「重新下载」（active_ms 归零）都是新的一轮：
      // 旧曲线作废、起点重设为当前 active_ms，并立即落盘，别让旧数据留在磁盘上。
      if (
        arr && arr.length &&
        P.speedCurveRestarted &&
        P.speedCurveRestarted(rawMs, speedOrigin.get(t.id) || 0, arr[arr.length - 1].x)
      ) {
        speedHistory.delete(t.id);
        speedDisplay.delete(t.id);
        speedOrigin.set(t.id, Number.isFinite(rawMs) && rawMs >= 0 ? rawMs : 0);
        arr = null;
        curveReset = true;
      }
      const relX = P.speedCurveX ? P.speedCurveX(rawMs, speedOrigin.get(t.id) || 0) : null;
      // 采样规则集中在 lib/polish.js（可单测）：下载中追加；从未采样过但已有
      // active_ms 的任务（小文件在两次轮询之间完成）补起点 / 平均速度点；离开
      // 下载阶段补 0 收尾。横轴仍用这里算好的「本轮相对 active_ms」。
      const last = arr && arr.length ? arr[arr.length - 1] : null;
      const x = relX != null
        ? Math.max(relX, last ? last.x : 0)
        : Math.max(speedSampleX(t, last, now), last ? last.x : 0);
      const next = P.speedSampleFromTask
        ? P.speedSampleFromTask(
          arr,
          { ...t, speed: smoothSpeed(t.id, t.speed, t.state) },
          now,
          x,
        )
        : null;
      if (next && next.length) {
        arr = next;
        speedHistory.set(t.id, arr);
        if (arr.length > SPEED_HISTORY_MAX) arr.splice(0, arr.length - SPEED_HISTORY_MAX);
      }
    }
    // 任务被删除后清掉其曲线。
    for (const id of [...speedHistory.keys()]) {
      if (!seen.has(id)) {
        speedHistory.delete(id);
        speedDisplay.delete(id);
        speedOrigin.delete(id);
      }
    }
    // 本轮有曲线被清空（回退/重启）时立刻落盘，避免旧数据在磁盘上残留。
    saveSpeedHistory(curveReset);
  }

  function hexToRgba(hex, alpha) {
    const m = /^#([0-9a-f]{6})$/i.exec(String(hex || "").trim());
    if (!m) return "rgba(36,89,245," + alpha + ")";
    const n = parseInt(m[1], 16);
    return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + alpha + ")";
  }

  // 速度波浪图：高 100px，宽度撑满属性面板内容区（左右各 14px 内边距）。
  //
  // 只在「还在跑的阶段」（connecting/downloading/verifying）实时跟进；任务一旦
  // 完成、暂停或失败，这里立即定稿并停止重绘——所以任务状态必须传进来，并且用
  // 采样签名挡住重复绘制，避免属性面板开着时空转。
  let chartSignature = "";
  function drawSpeedChart(task) {
    const canvas = document.getElementById("speed-chart");
    if (!canvas || !canvas.getContext) return;
    const state = String((task && task.state) || "");
    // 只有真正在传字节的阶段才实时跟进；verifying（下完了在 flush/sha256/改名）
    // 已经不再下载，曲线应当立刻定稿，否则会出现「100% 了图标还在走」。
    const running = state === "connecting" || state === "downloading";
    const series = (task && task.id != null && speedHistory.get(task.id)) || [];
    const head = series.length ? series[series.length - 1] : null;
    const cssW = Math.max(1, canvas.clientWidth || 260);
    const cssH = Math.max(1, canvas.clientHeight || 100);
    // 状态 / 采样 / 尺寸都没变就不重画：完成后画布立即静止，不再每 600ms 跑一遍
    const signature = [
      task && task.id,
      state,
      series.length,
      head ? head.x : 0,
      head ? head.bps : 0,
      cssW,
      cssH,
    ].join("|");
    if (signature === chartSignature) return;
    chartSignature = signature;

    const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1));
    const pxW = Math.round(cssW * dpr);
    const pxH = Math.round(cssH * dpr);
    if (canvas.width !== pxW) canvas.width = pxW;
    if (canvas.height !== pxH) canvas.height = pxH;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const style = getComputedStyle(document.documentElement);
    const accent = (style.getPropertyValue("--accent") || "#2459f5").trim() || "#2459f5";
    const dimColor = (style.getPropertyValue("--text-dim") || "#59657c").trim() || "#59657c";

    const padTop = 13;
    const padBottom = 6;
    const plotH = Math.max(1, cssH - padTop - padBottom);
    const baseline = padTop + plotH;
    const font = "10px Arial,'Helvetica Neue','Microsoft YaHei',sans-serif";

    // 只有「还在跑」的时候才认实时速度；停下之后曲线定稿，不再跟着 task.speed 动
    const live = series.length
      ? series[series.length - 1].bps
      : running ? Math.max(0, Number(task && task.speed) || 0) : 0;
    let peak = live;
    for (const s of series) if (s.bps > peak) peak = s.bps;
    const scale = Math.max(peak * 1.15, 1024); // 至少 1 KB/s，并留 15% 顶部余量

    ctx.font = font;
    ctx.textBaseline = "top";
    ctx.fillStyle = dimColor;
    ctx.fillText(T("峰值 ") + fmtSpeed(peak), 4, 2);
    // 右上角：跑着看实时速度，停下来就把状态钉在那里
    ctx.textAlign = "right";
    ctx.fillText(running ? fmtSpeed(live) : stateText(state), cssW - 4, 2);
    ctx.textAlign = "left";

    if (series.length < 2) {
      ctx.textBaseline = "bottom";
      ctx.fillText(
        running ? T("等待速度采样…") : state === "done" ? T("已完成（无下载阶段速度记录）") : T("暂无下载阶段速度记录"),
        4,
        cssH - 3
      );
      return;
    }

    // 横轴不再按刻度留空白：用采样序列的首尾把曲线线性铺满 0..cssW。
    // 无论下载 0.5 秒还是 5 分钟，曲线都从左边画到右边；首尾横轴重合
    //（同一拍内完成、两个点 x 相同）时退回按点序号等分，两点照样贴边。
    const x0 = Number(series[0].x) || 0;
    const x1 = Number(series[series.length - 1].x) || 0;
    const span = x1 - x0;
    const pts = [];
    for (let i = 0; i < series.length; i++) {
      const frac = span > 0
        ? (Number(series[i].x) - x0) / span
        : i / (series.length - 1);
      pts.push({
        x: Math.max(0, Math.min(1, frac)) * cssW,
        y: baseline - (Math.min(series[i].bps, scale) / scale) * plotH,
      });
    }

    const trace = () => {
      ctx.beginPath();
      ctx.moveTo(pts[0].x, pts[0].y);
      for (let i = 1; i < pts.length - 1; i++) {
        ctx.quadraticCurveTo(pts[i].x, pts[i].y, (pts[i].x + pts[i + 1].x) / 2, (pts[i].y + pts[i + 1].y) / 2);
      }
      ctx.lineTo(pts[pts.length - 1].x, pts[pts.length - 1].y);
    };

    // 线下渐变面积
    const grad = ctx.createLinearGradient(0, padTop, 0, baseline);
    grad.addColorStop(0, hexToRgba(accent, 0.28));
    grad.addColorStop(1, hexToRgba(accent, 0.02));
    trace();
    ctx.lineTo(pts[pts.length - 1].x, baseline);
    ctx.lineTo(pts[0].x, baseline);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // 波浪线
    trace();
    ctx.strokeStyle = accent;
    ctx.lineWidth = 1.8;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    // 末端圆点（停下后不再画「当前」标记）
    const lastPt = pts[pts.length - 1];
    if (running) {
      const dotX = Math.min(cssW - 3, Math.max(3, lastPt.x));
      ctx.beginPath();
      ctx.arc(dotX, lastPt.y, 2.4, 0, Math.PI * 2);
      ctx.fillStyle = accent;
      ctx.fill();
    }
  }

  // 属性面板标题行右侧的状态灯：完成🟢 / 暂停🟠 / 任务异常🔴 / 下载中🟢（呼吸灯）
  function propsStateSignal(task) {
    if (!task) return { dot: "⚪", cls: "is-idle" };
    if (isFailedTask(task)) return { dot: "🔴", cls: "is-error" };
    if (isInterrupted(task)) return { dot: "⚪", cls: "is-idle" };
    switch (String(task.state || "")) {
      case "done": return { dot: "🟢", cls: "is-done" };
      case "paused": return { dot: "🟠", cls: "is-paused" };
      case "downloading":
      case "connecting":
      case "verifying": return { dot: "🟢", cls: "is-active" };
      default: return { dot: "⚪", cls: "is-idle" };
    }
  }

  // 标题右侧：创建时间 + 状态灯 + 状态文字（沿用原 .props-value 的字体风格）
  function renderPropsHeadMeta(task) {
    const created = P.formatTimestamp
      ? P.formatTimestamp(task.created_at != null ? task.created_at : task.created_at_ms)
      : (P.DASH || "—");
    const createdEl = document.getElementById("props-created");
    if (createdEl) {
      createdEl.textContent = created;
      createdEl.title = T("创建时间 ") + created;
    }
    const signal = propsStateSignal(task);
    const dot = document.getElementById("props-state-dot");
    if (dot) {
      dot.textContent = signal.dot;
      dot.className = "props-state-dot " + signal.cls;
    }
    const stateText = formatQueueStatus(task, Date.now());
    setText("props-state-text", stateText);
    const stateEl = document.getElementById("props-state");
    if (stateEl) stateEl.title = stateText;
  }

  // 备用地址（镜像）：引擎只在配置了镜像时下发该字段，没有就整行隐藏。
  // `alt_cursor` 是候选序号（0 = 主地址，n = 第 n 条备用地址）。
  function renderPropsAlternates(task) {
    const box = document.getElementById("props-alt-urls");
    if (!box) return;
    const row = box.closest(".props-row");
    const alts = String(task.alt_urls || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    box.textContent = "";
    if (!alts.length) {
      if (row) row.classList.add("hidden");
      return;
    }
    if (row) row.classList.remove("hidden");
    const active = Number.isInteger(task.alt_cursor) ? task.alt_cursor : 0;
    const entries = [{ label: T("主地址"), url: task.url || "" }].concat(
      alts.map((url, i) => ({ label: T("备用 ") + (i + 1), url }))
    );
    entries.forEach((entry, i) => {
      const line = document.createElement("div");
      line.className = "props-alt-line" + (i === active ? " current" : "");
      const tag = document.createElement("span");
      tag.className = "props-alt-tag";
      tag.textContent = entry.label;
      const link = document.createElement("span");
      link.className = "props-alt-url";
      link.textContent = P.truncateMiddle ? P.truncateMiddle(entry.url, 40) : entry.url;
      link.title = entry.url;
      line.appendChild(tag);
      line.appendChild(link);
      if (i === active) {
        const now = document.createElement("span");
        now.className = "props-alt-active";
        now.textContent = T("使用中");
        line.appendChild(now);
      }
      box.appendChild(line);
    });
  }

  // ---- 重复任务检测 ----
  // 判重键：eD2k 用链接里的文件哈希（与文件名无关），magnet 用 BTIH，其它用归一化 URL。
  function duplicateKeyOf(url) {
    const raw = String(url || "").trim();
    if (!raw) return "";
    const ed2k = raw.match(/^ed2k:\/\/\|file\|[^|]*\|\d+\|([0-9A-Fa-f]{32})\|/i);
    if (ed2k) return "ed2k:" + ed2k[1].toUpperCase();
    const magnet = raw.match(/urn:btih:([0-9a-z]{32,40})/i);
    if (magnet) return "btih:" + magnet[1].toLowerCase();
    return "url:" + raw.replace(/#.*$/, "").toLowerCase();
  }

  function findDuplicateTask(url) {
    const key = duplicateKeyOf(url);
    if (!key) return null;
    const list = Array.isArray(tasks) ? tasks : [];
    for (const t of list) {
      if (t && duplicateKeyOf(t.url) === key) return t;
    }
    return null;
  }

  /// 应用内确认弹窗。返回 Promise<boolean>。
  ///
  /// 替代 `window.confirm`：WebView 里那是系统对话框，字体/间距/主题都不一致，
  /// 而且会阻塞渲染线程。这里复用 `.dlg-mask` + `.dialog`，与「新建下载」同款。
  ///
  /// Esc / 点遮罩 = 取消；焦点默认落在「取消」（危险操作不默认确认）。
  function confirmDialog(opts) {
    const mask = document.getElementById("confirm-mask");
    const title = document.getElementById("confirm-title");
    const body = document.getElementById("confirm-body");
    const detail = document.getElementById("confirm-detail");
    const okBtn = document.getElementById("confirm-ok");
    const cancelBtn = document.getElementById("confirm-cancel");
    if (!mask || !title || !body || !detail || !okBtn || !cancelBtn) {
      // 兜底：DOM 不全时退回原生，至少不静默吞掉确认。
      return Promise.resolve(window.confirm(opts.body || ""));
    }
    title.textContent = opts.title || T("确认");
    body.textContent = opts.body || "";
    if (Array.isArray(opts.detail) && opts.detail.length) {
      detail.textContent = "";
      for (const [k, v] of opts.detail) {
        const line = document.createElement("div");
        const key = document.createElement("b");
        key.textContent = k + "：";
        line.appendChild(key);
        line.appendChild(document.createTextNode(String(v)));
        detail.appendChild(line);
      }
      detail.classList.remove("hidden");
    } else {
      detail.classList.add("hidden");
    }
    okBtn.textContent = opts.okText || T("确定");
    cancelBtn.textContent = opts.cancelText || T("取消");

    return new Promise((resolve) => {
      let done = false;
      const finish = (v) => {
        if (done) return;
        done = true;
        mask.classList.add("hidden");
        okBtn.removeEventListener("click", onOk);
        cancelBtn.removeEventListener("click", onCancel);
        mask.removeEventListener("mousedown", onMask);
        document.removeEventListener("keydown", onKey, true);
        resolve(v);
      };
      const onOk = () => finish(true);
      const onCancel = () => finish(false);
      // 只有点在遮罩本体（不是对话框内部）才算取消。
      const onMask = (e) => { if (e.target === mask) finish(false); };
      const onKey = (e) => {
        if (e.key === "Escape") { e.preventDefault(); finish(false); }
        else if (e.key === "Enter" && document.activeElement === okBtn) { e.preventDefault(); finish(true); }
      };
      okBtn.addEventListener("click", onOk);
      cancelBtn.addEventListener("click", onCancel);
      mask.addEventListener("mousedown", onMask);
      document.addEventListener("keydown", onKey, true);
      mask.classList.remove("hidden");
      cancelBtn.focus();
    });
  }

  // 命中重复时问用户：「重新下载」= 仍新建一份；「取消」= 什么都不做。
  async function confirmDuplicateOrSkip(url) {
    const dup = findDuplicateTask(url);
    if (!dup) return true;
    const stateText = dup.state === "done" ? T("已完成") : dup.state === "error" ? T("失败") : T("已在列表中");
    return confirmDialog({
      title: T("已存在相同任务"),
      body: T("列表里已经有一个相同的下载。重新下载会新建一份任务，两份互不影响。"),
      detail: [
        [T("任务"), "#" + dup.id],
        [T("状态"), stateText],
        [T("文件"), dup.name || dup.file_name || "—"],
      ],
      okText: T("重新下载"),
      cancelText: T("取消"),
    });
  }

  // BitTorrent 逐文件选择：属性面板给出入口，弹窗里勾选要下载的文件。
  // 判定"是不是 BT 任务"看 URL（magnet 或 .torrent）——引擎的 `mode` 只区分 eD2k/切片，
  // 不区分 BT，所以这里按链接形态判断。
  function isBtTask(task) {
    const url = String(task.url || "");
    return /^magnet:/i.test(url) || /\.torrent(\?|$)/i.test(url);
  }

  async function renderPropsBtFiles(task) {
    const row = document.querySelector('.props-row[data-field="bt-files"]');
    const summary = document.getElementById("props-bt-files");
    const button = document.getElementById("props-bt-choose");
    if (!row || !summary || !button) return;
    if (!isBtTask(task)) {
      row.classList.add("hidden");
      return;
    }
    row.classList.remove("hidden");
    const resp = await send({ op: "bt_files", id: task.id }).catch(() => null);
    const files = (resp && resp.ok && Array.isArray(resp.bt_files)) ? resp.bt_files : [];
    if (!files.length) {
      summary.textContent = T("等待元数据…");
    } else {
      const selected = files.filter((f) => f.selected).length;
      summary.textContent = T("{n} / {total} 个文件", { n: selected, total: files.length });
    }
    button.onclick = () => openBtFilesDialog(task);
  }

  async function openBtFilesDialog(task) {
    const mask = document.getElementById("bt-files-mask");
    const list = document.getElementById("bt-files-list");
    const hint = document.getElementById("bt-files-hint");
    list.textContent = "";
    hint.textContent = T("只下载勾选的文件；改动对运行中的任务立即生效。");
    const resp = await send({ op: "bt_files", id: task.id }).catch(() => null);
    const files = (resp && resp.ok && Array.isArray(resp.bt_files)) ? resp.bt_files : [];
    if (!files.length) {
      hint.textContent = T("还没有拿到种子元数据（磁力链接需要先连上 peer）。拿到之后再打开这里。");
    }
    files.forEach((f) => {
      const label = document.createElement("label");
      label.className = "bt-file-row";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = !!f.selected;
      box.value = String(f.index);
      const name = document.createElement("span");
      name.className = "bt-file-name";
      name.textContent = f.name;
      name.title = f.name;
      const size = document.createElement("span");
      size.className = "bt-file-size";
      size.textContent = fmtBytes(f.len);
      label.appendChild(box);
      label.appendChild(name);
      label.appendChild(size);
      list.appendChild(label);
    });
    const boxes = () => Array.from(list.querySelectorAll('input[type="checkbox"]'));
    document.getElementById("bt-files-all").onclick = () =>
      boxes().forEach((b) => (b.checked = true));
    document.getElementById("bt-files-none").onclick = () =>
      boxes().forEach((b) => (b.checked = false));
    document.getElementById("bt-files-cancel").onclick = () => closeLayer(mask);
    document.getElementById("bt-files-save").onclick = async () => {
      const indices = boxes().filter((b) => b.checked).map((b) => Number(b.value));
      if (!indices.length) {
        hint.textContent = T("至少要勾一个文件（不勾等于全选，请用「全选」）。");
        return;
      }
      const save = await send({ op: "bt_set_files", id: task.id, indices });
      if (!save || !save.ok) {
        hint.textContent = T("保存失败：") + ((save && (save.code || save.error)) || T("未知错误"));
        return;
      }
      closeLayer(mask);
      void refreshList({ keepSelection: true });
    };
    openLayer(mask, document.getElementById("bt-files-all"));
  }

  // ---- 任务下载日志（属性面板） ----
  let propsEventsTaskId = null;
  let propsEventsLoading = false;
  let propsEventsAt = 0;
  let propsEventsCache = [];
  let propsEventsTotal = 0;
  let propsEventsFilter = "all";
  let propsEventsExhausted = false;
  let propsEventsRenderKey = "";
  const PROPS_EVENTS_PAGE = 50;

  function eventTime(ts) {
    const d = new Date(Number(ts) * 1000);
    return Number.isNaN(d.getTime()) ? "—" : d.toLocaleTimeString();
  }

  function eventLine(ev) {
    const bits = [ev.kind || "event"];
    if (ev.phase) bits.push("phase=" + ev.phase);
    if (ev.outcome) bits.push("outcome=" + ev.outcome);
    if (ev.err_code) bits.push("err=" + ev.err_code);
    if (ev.dur_ms != null) bits.push(ev.dur_ms + "ms");
    if (ev.proto) bits.push("proto=" + ev.proto);
    if (ev.seg != null) bits.push("seg=" + ev.seg);
    if (ev.detail) bits.push(ev.detail);
    return bits.join(" ");
  }

  // 筛选图标两态：灰=全部日志，红=只看异常。
  function syncEventsFilterUi() {
    const btn = document.getElementById("props-events-filter");
    if (!btn) return;
    btn.dataset.filter = propsEventsFilter;
    btn.title = T(
      propsEventsFilter === "error" ? "props.logFilterError" : "props.logFilterAll"
    );
  }

  // 只在条数/头部/总数变化时重建，500ms 刷新不能把滚动位置和 DOM 反复推倒重来。
  function renderEventsRows(list) {
    const key =
      propsEventsCache.length +
      "|" +
      (propsEventsCache.length ? propsEventsCache[0].seq : 0) +
      "|" +
      propsEventsTotal;
    if (key === propsEventsRenderKey) return;
    propsEventsRenderKey = key;
    const top = list.scrollTop;
    list.textContent = "";
    for (const ev of propsEventsCache) {
      const row = document.createElement("div");
      row.className = "props-events-row" + (ev.err_code ? " error" : "");
      const time = document.createElement("span");
      time.className = "props-events-time";
      time.textContent = eventTime(ev.ts);
      const text = document.createElement("span");
      text.className = "props-events-text";
      text.textContent = eventLine(ev);
      row.append(time, text);
      list.appendChild(row);
    }
    list.scrollTop = top;
  }

  // opts: `{ reset }` 换任务/切筛选/手刷；`{ more }` 滚到底加载下一页；
  // 缺省 = 自动刷新头部（只拉第一页，合并新事件）。
  async function loadPropsEvents(task, opts) {
    const o = opts || {};
    if (!task || propsEventsLoading) return;
    const switching = propsEventsTaskId !== task.id;
    const reset = !!o.reset || switching;
    if (o.more && (propsEventsExhausted || !propsEventsCache.length)) return;
    if (!reset && !o.more && Date.now() - propsEventsAt < 500) return;
    if (reset) {
      propsEventsTaskId = task.id;
      propsEventsCache = [];
      propsEventsTotal = 0;
      propsEventsExhausted = false;
      propsEventsRenderKey = "";
    }
    const offset = o.more ? propsEventsCache.length : 0;
    propsEventsLoading = true;
    const status = document.getElementById("props-events-status");
    if (status && reset) status.textContent = T("加载中…");
    const resp = await send({
      op: "task_events",
      id: task.id,
      limit: PROPS_EVENTS_PAGE,
      offset: offset,
      filter: propsEventsFilter,
    });
    propsEventsLoading = false;
    const current = primarySelected();
    if (!current || current.id !== task.id) return;
    if (!resp || !resp.ok) {
      if (status) {
        status.textContent =
          T("加载失败：") + ((resp && (resp.code || resp.error)) || T("未知错误"));
      }
      return;
    }
    const batch = Array.isArray(resp.task_events) ? resp.task_events : [];
    propsEventsAt = Date.now();
    propsEventsTotal =
      resp.task_events_total != null ? Number(resp.task_events_total) : batch.length;
    if (offset === 0) {
      const known = new Set(propsEventsCache.map((e) => e.seq));
      const overlap = batch.some((ev) => known.has(ev.seq));
      // 新页与已加载历史不重叠（中间可能有断档）时，用新页重置。
      propsEventsCache = overlap
        ? batch.filter((ev) => !known.has(ev.seq)).concat(propsEventsCache)
        : batch;
    } else {
      const known = new Set(propsEventsCache.map((e) => e.seq));
      for (const ev of batch) if (!known.has(ev.seq)) propsEventsCache.push(ev);
    }
    propsEventsExhausted =
      batch.length < PROPS_EVENTS_PAGE || propsEventsCache.length >= propsEventsTotal;
    const count = document.getElementById("props-events-count");
    const list = document.getElementById("props-events");
    if (count) count.textContent = String(propsEventsTotal);
    if (status) {
      status.textContent = propsEventsTotal
        ? ""
        : propsEventsFilter === "error"
          ? T("没有异常日志")
          : T("暂无下载日志");
    }
    if (list) {
      const boxEl = document.getElementById("props-events-box");
      // 收起时只更新计数，不重建不可见的列表。
      if (!boxEl || boxEl.open) renderEventsRows(list);
    }
  }

  // 面板一打开就拉一次：即使日志收起，标题里的总数也要准确。
  function renderPropsEvents(task) {
    if (!task) return;
    if (propsEventsTaskId !== task.id) void loadPropsEvents(task, { reset: true });
  }

  async function loadPropsDetail(id, seq) {
    const task = await UN.fetchTaskDetail(send, id);
    if (!task) return false;
    // 代次 + 版本双重校验：更早的请求晚返回、或同一引擎实例的更旧状态，都不能覆盖缓存。
    const prevTask =
      propsDetail && propsDetail.id === id ? propsDetail.task : null;
    if (!UN.acceptDetail(prevTask, task, seq, propsDetailSeq)) return false;
    propsDetail = { id: id, task: task };
    propsDetailAt = Date.now();
    // 成功后清掉该任务的退避记录，避免“一次失败永久变慢”。
    propsDetailRetryAt.delete(id);
    return true;
  }

  // 按需拉取详情（带 `unified_download`）。
  //
  // 节流：同一任务 2 秒内不重复请求；退避**按任务**记录（全局会互相阻塞）；
  // 每个请求带递增代次，乱序返回时由 `acceptDetail` 丢弃旧代次。
  function ensurePropsDetail(id, force) {
    if (id == null) return;
    const fresh =
      !force && propsDetail && propsDetail.id === id && Date.now() - propsDetailAt < 500;
    if (fresh) return;
    if (propsDetailLoadingId === id) return;
    if (Date.now() < (propsDetailRetryAt.get(id) || 0)) return;
    const seq = ++propsDetailSeq;
    propsDetailLoadingId = id;
    loadPropsDetail(id, seq)
      .then((ok) => {
        if (ok) {
          // 详情到手只更「进度 + 切片」：500ms 刷新下整面板重绘会把
          // 文件名/URL/事件一起重排，成本高且会打断呼吸动画。
          if (propsVisible) {
            const t = primarySelected();
            if (t) renderSlicesOnly(UN.pickRenderTask(t, propsDetail));
          }
        } else if (seq === propsDetailSeq) {
          // 只在仍是当前代次时记退避；已被新请求取代的失败不影响新任务。
          propsDetailRetryAt.set(id, Date.now() + 5000);
        }
      })
      .catch(() => {
        if (seq === propsDetailSeq) {
          propsDetailRetryAt.set(id, Date.now() + 5000);
        }
      })
      .finally(() => {
        if (propsDetailLoadingId === id) propsDetailLoadingId = null;
      });
  }

  // 只更新「进度数字 + 切片」：属性面板 500ms 刷新走这里，
  // 不碰文件名 / URL / 源 / 事件，避免整面板重排。
  function renderSlicesOnly(task) {
    if (!task) return;
    const title = document.getElementById("props-segments-title");
    const container = document.getElementById("props-segments");
    if (!title || !container) return;
    const segs = taskSegments(task);
    title.textContent = T("props.segments", { n: segs.length });
    if (task.unified_download) {
      renderUnifiedSlices(container, task.unified_download, title);
    }
    const pctText = task.pct != null ? task.pct.toFixed(1) + "%" : (P.DASH || "—");
    setText("props-progress-pct", pctText);
    setText("props-progress", fmtBytes(task.done) + " / " + fmtBytes(task.total));
    drawSpeedChart(task);
  }

  function renderProps() {
    if (!propsVisible) {
      propsEventsTaskId = null;
      return;
    }
    // 触发器已收敛为「单击单个任务 / 右键属性」：没有可显示的任务就自动收起，
    // 不再留一页只有「请选择一个任务」的空白（删除、清空选中、任务消失都会走到这里）。
    const listTask = primarySelected();
    if (!listTask) {
      showPropsPanel(false);
      return;
    }
    // 统一视图只在 `status` 详情里返回（列表只带摘要），所以打开面板时必须
    // 主动拉一次详情；否则新渲染分支永远不会进入。
    ensurePropsDetail(listTask.id);
    // 详情优先；未就绪时先用列表摘要渲染，拿到详情后会自动重渲染。
    const task = UN.pickRenderTask(listTask, propsDetail);
    const errEl = document.getElementById("props-error");
    const body = document.getElementById("props-body");
    const headMeta = document.getElementById("props-head-meta");
    errEl.classList.add("hidden");
    body.classList.add("hidden");
    if (headMeta) headMeta.classList.add("hidden");
    if (listError) {
      errEl.textContent = PROPS_LOAD_FAIL;
      errEl.classList.remove("hidden");
      return;
    }
    body.classList.remove("hidden");
    if (headMeta) headMeta.classList.remove("hidden");
    renderPropsEvents(task);
    fillPropsFilename(task);
    setText("props-save", task.save_path || (P.DASH || "—"));
    document.getElementById("props-save").title = task.save_path || "";
    const pctText = task.pct != null ? task.pct.toFixed(1) + "%" : (P.DASH || "—");
    // 大小 / 已下载 / 进度 / 完成时间合并进「下载」块（原独立占位已取消）
    setText("props-progress-pct", pctText);
    setText("props-progress", fmtBytes(task.done) + " / " + fmtBytes(task.total));
    drawSpeedChart(task);
    setText("props-finish", P.formatFinishProps ? P.formatFinishProps(task) : fmtEta(task));
    renderPropsHeadMeta(task);
    const url = task.url || "";
    const sourceText = P.sourceFieldText
      ? P.sourceFieldText(task.source, task.referrer || task.referer, url)
      : sourceLabel(task.source);
    setText("props-source", sourceText);
    const sourceEl = document.getElementById("props-source");
    if (sourceEl) sourceEl.title = sourceText;
    const urlEl = document.getElementById("props-url");
    urlEl.textContent = url ? (P.truncateMiddle ? P.truncateMiddle(url, 42) : url) : (P.DASH || "—");
    urlEl.title = url ? T("点击复制链接\n") + url : "";
    renderPropsAlternates(task);
    void renderPropsBtFiles(task);
    const completedAt = task.state === "done"
      ? (task.finished_at != null ? task.finished_at
        : task.finished_at_ms != null ? task.finished_at_ms
          : task.completed_at != null ? task.completed_at
            : task.completed_at_ms)
      : null;
    setText("props-completed", P.formatTimestamp ? P.formatTimestamp(completedAt) : (P.DASH || "—"));
    const failReason = document.getElementById("props-fail-reason");
    const failActs = document.getElementById("props-fail-actions");
    failActs.textContent = "";
    if (isFailedTask(task)) {
      const desc = describeTaskError(task);
      failReason.textContent = desc.sentence || (P.DASH || "—");
      if (desc.action === "change_location") {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "tool";
        b.dataset.fail = "change-dir";
        b.textContent = T("更改位置");
        failActs.appendChild(b);
      } else if (desc.action === "redownload") {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "tool";
        b.dataset.fail = "redownload";
        b.textContent = T("重新下载");
        failActs.appendChild(b);
      }
      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "tool";
      copyBtn.dataset.fail = "copy-error";
      copyBtn.textContent = COPY_ERROR_DETAIL;
      failActs.appendChild(copyBtn);
    } else {
      failReason.textContent = P.DASH || "—";
    }
    const failRow = failReason.closest(".props-row");
    if (failRow) failRow.classList.toggle("hidden", !isFailedTask(task));
    renderSlicesOnly(task);
    if (task.unified_download) return;
    const title = document.getElementById("props-segments-title");
    const container = document.getElementById("props-segments");
    // 旧切片视图的兜底数据源。真实引擎的 `list` 摘要不带 `unified_download`
    // （只在 `status` 详情里返回），所以这条分支会真实执行到；缺这行会抛
    // ReferenceError，异常穿出 showPropsPanel 打断 onRowClick 的选中同步。
    const segs = taskSegments(task);
    container.textContent = "";
    const p2p = P.p2pDetails ? P.p2pDetails(task) : null;
    if (p2p) {
      title.textContent = T("eD2k 多源下载 · 切片");
      for (const text of [p2p.phase, p2p.sources, p2p.transfers, p2p.pieces]) {
        const line = document.createElement("p");
        line.className = "props-hint";
        line.textContent = text;
        container.appendChild(line);
      }
      const states = task.p2p && Array.isArray(task.p2p.slices) ? task.p2p.slices : [];
      if (states.length) renderP2pSliceLanes(container, task.p2p, states);
      return;
    }
    if (segs.length === 0) {
      const p = document.createElement("p");
      p.className = "props-hint";
      p.textContent =
        task.state === "queued" || task.state === "connecting"
          ? T("切片尚未规划，请稍候…")
          : T("暂无切片数据");
      container.appendChild(p);
      return;
    }
    for (const seg of segs) {
      const row = document.createElement("div");
      row.className = "seg-row";
      const top = document.createElement("div");
      top.className = "seg-head";
      const idLine = document.createElement("span");
      idLine.textContent = T("切片 {n}", { n: seg.idx + 1 });
      const rangeLine = document.createElement("span");
      rangeLine.className = "seg-range";
      rangeLine.textContent = fmtByteRange(seg);
      top.append(idLine, rangeLine);
      row.appendChild(top);
      const bar = document.createElement("div");
      bar.className = "seg-bar";
      const fill = document.createElement("span");
      fill.className = "seg-bar-fill";
      if (seg.status === "done") fill.classList.add("done");
      if (seg.status === "error") fill.classList.add("err");
      const pct = segmentPct(seg);
      if (segmentIndeterminate(seg)) {
        bar.classList.add("indeterminate");
        fill.classList.add("indeterminate");
      } else if (pct != null) {
        fill.style.width = pct.toFixed(1) + "%";
      }
      bar.appendChild(fill);
      row.appendChild(bar);
      const bottom = document.createElement("div");
      bottom.className = "seg-head";
      const status = document.createElement("span");
      const retry = seg.retries != null && seg.retries > 0 ? T(" · 重试 {n}", { n: seg.retries }) : "";
      status.textContent = segStatusText(seg.status) + retry;
      const pctLabel = document.createElement("span");
      const sizeHint =
        seg.pos_end != null
          ? `${fmtBytes(seg.done_bytes)} / ${fmtBytes(seg.pos_end - seg.pos_start + 1)}`
          : fmtBytes(seg.done_bytes);
      pctLabel.textContent = (pct != null ? pct.toFixed(1) + "%" : "—") + " · " + sizeHint;
      bottom.append(status, pctLabel);
      row.appendChild(bottom);
      container.appendChild(row);
    }
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function fillPropsFilename(task) {
    // 标签带上任务编号（下载编号 = 任务的 id），便于和日志/事件里的 task id 对照。
    // 编号缺失时回落到纯「文件名」，不留空括号。
    const label = document.getElementById("props-filename-label");
    if (label) {
      label.textContent = task.id != null ? T("文件名(No:{id})", { id: task.id }) : T("文件名");
    }
    const host = document.getElementById("props-filename");
    host.textContent = "";
    if (isRenaming() && rename.id === task.id && rename.source === "props") {
      host.appendChild(buildRenameEditor());
      return;
    }
    const name = document.createElement("span");
    name.textContent = task.name || (P.DASH || "—");
    if (canRename(task)) {
      name.className = "name-editable";
      name.title = task.name || "";
      name.addEventListener("click", (e) => {
        e.stopPropagation();
        startRename(task, "props");
      });
    } else {
      name.className = "name-locked";
      name.title = P.RENAME_UNAVAILABLE || T("当前无法重命名");
    }
    host.appendChild(name);
  }

  function buildRenameEditor() {
    const wrap = document.createElement("div");
    wrap.className = "rename-wrap";
    const input = document.createElement("input");
    input.type = "text";
    input.className = "rename-input";
    input.spellcheck = false;
    input.value = rename.draft;
    input.addEventListener("click", (e) => {
      e.stopPropagation();
      rename.caret = [input.selectionStart, input.selectionEnd];
    });
    input.addEventListener("mousedown", (e) => e.stopPropagation());
    input.addEventListener("keyup", () => {
      rename.caret = [input.selectionStart, input.selectionEnd];
    });
    input.addEventListener("input", () => {
      rename.draft = input.value;
      rename.caret = [input.selectionStart, input.selectionEnd];
      if (rename.error && input.value.trim()) {
        rename.error = "";
        const err = wrap.querySelector(".rename-error");
        if (err) err.remove();
      }
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        e.stopPropagation();
        tryCommitRename();
      } else if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        cancelRename();
      }
    });
    input.addEventListener("blur", () => {
      if (!renderPending) return;
      renderPending = false;
      setTimeout(() => render(), 0);
    });
    wrap.appendChild(input);
    if (rename.error) {
      const err = document.createElement("div");
      err.className = "rename-error";
      err.textContent = rename.error;
      wrap.appendChild(err);
    }
    queueMicrotask(() => {
      if (!rename || !rename.needsFocus) return;
      if (!document.body.contains(input)) return;
      if (topLayer() && topLayer().id === "rename-ext-mask") return;
      rename.needsFocus = false;
      input.focus();
      if (rename.selectAll) {
        input.select();
        rename.selectAll = false;
      } else if (rename.caret) {
        try { input.setSelectionRange(rename.caret[0], rename.caret[1]); } catch { /* ignore */ }
      }
    });
    return wrap;
  }

  function startRename(task, source) {
    if (!canRename(task)) return;
    if (topLayer() && topLayer().id === "rename-ext-mask") return;
    if (isRenaming() && rename.id === task.id) return;
    rename = {
      id: task.id,
      original: task.name || "",
      draft: task.name || "",
      source,
      error: "",
      selectAll: true,
      needsFocus: true,
      snapshot: { name: task.name, save_path: task.save_path, state: task.state },
    };
    render(true);
  }

  function cancelRename() {
    if (!rename) return;
    const t = taskById(rename.id);
    if (t && rename.snapshot) {
      t.name = rename.snapshot.name;
      t.save_path = rename.snapshot.save_path;
    }
    rename = null;
    renderPending = false;
    render(true);
  }

  function closeRenameSilent() {
    rename = null;
  }

  async function tryCommitRename() {
    if (!rename) return;
    const task = taskById(rename.id);
    if (!task) {
      rename = null;
      renderPending = false;
      render(true);
      return;
    }
    const decision = P.renameCommitDecision
      ? P.renameCommitDecision(rename.original, rename.draft)
      : { action: String(rename.draft || "").trim() ? "rename" : "empty", filename: String(rename.draft || "").trim(), error: T("文件名不能为空") };
    if (decision.action === "empty") {
      rename.error = decision.error || (P.RENAME_EMPTY || T("文件名不能为空"));
      rename.selectAll = false;
      rename.needsFocus = true;
      render(true);
      return;
    }
    if (decision.action === "noop") {
      closeRenameSilent();
      render(true);
      return;
    }
    if (decision.action === "confirm") {
      openRenameExtDialog(rename.original, decision.filename);
      return;
    }
    await performRename(task, decision.filename);
  }

  function openRenameExtDialog(oldName, newName) {
    const mask = document.getElementById("rename-ext-mask");
    document.getElementById("rename-ext-old").textContent = T("原文件名：") + oldName;
    document.getElementById("rename-ext-new").textContent = T("新文件名：") + newName;
    openLayer(mask, document.getElementById("rename-ext-cancel"));
  }

  function closeRenameExtDialog() {
    const mask = document.getElementById("rename-ext-mask");
    closeLayer(mask);
  }

  async function confirmRenameExt() {
    if (!rename) {
      closeRenameExtDialog();
      return;
    }
    const task = taskById(rename.id);
    const filename = String(rename.draft || "").trim();
    closeRenameExtDialog();
    if (!task) {
      rename = null;
      renderPending = false;
      render(true);
      return;
    }
    await performRename(task, filename);
  }

  function cancelRenameExt() {
    closeRenameExtDialog();
    if (!rename) return;
    rename.draft = rename.original;
    rename.error = "";
    rename.selectAll = true;
    rename.needsFocus = true;
    render(true);
  }

  async function performRename(task, filename) {
    const beforeDone = task.state === "done";
    const keepState = task.state;
    if (!beforeDone) {
      task.name = filename;
      task.save_path = P.replaceFilenameInPath
        ? P.replaceFilenameInPath(task.save_path, filename)
        : task.save_path;
      pendingOptimistic = {
        id: task.id,
        name: filename,
        save_path: task.save_path,
        state: keepState,
      };
      render(true);
    }
    const resp = await send({ op: "rename", id: task.id, filename });
    pendingOptimistic = null;
    if (resp && resp.ok) {
      const live = taskById(task.id);
      if (live) {
        if (resp.task) {
          if (resp.task.name) live.name = resp.task.name;
          if (resp.task.save_path) live.save_path = resp.task.save_path;
        } else {
          live.name = filename;
          live.save_path = P.replaceFilenameInPath
            ? P.replaceFilenameInPath(live.save_path, filename)
            : live.save_path;
        }
        if (!beforeDone) live.state = keepState;
      }
      closeRenameSilent();
      renderPending = false;
      render(true);
      return;
    }
    const live = taskById(task.id);
    if (live && rename && rename.snapshot) {
      live.name = rename.snapshot.name;
      live.save_path = rename.snapshot.save_path;
    }
    if (rename) {
      rename.draft = filename;
      rename.error = P.renameErrorText
        ? P.renameErrorText(resp)
        : T("重命名失败，请重试");
      rename.selectAll = false;
      rename.needsFocus = true;
    }
    render(true);
  }

  // 顶部失败条关闭后本次运行内不再弹出（不持久化，重启应用自然恢复）。
  let failBarDismissed = false;

  function updateFailBar() {
    const bar = document.getElementById("fail-bar");
    if (failBarDismissed) {
      bar.classList.add("hidden");
      return;
    }
    const task = primarySelected();
    const retry = bar.querySelector('[data-fail="retry"]');
    const change = bar.querySelector('[data-fail="change-dir"]');
    const redo = bar.querySelector('[data-fail="redownload"]');
    if (task && isFailedTask(task)) {
      const desc = describeTaskError(task);
      document.getElementById("fail-reason").textContent = desc.sentence;
      retry.classList.toggle("hidden", desc.action === "redownload");
      change.classList.toggle("hidden", desc.action !== "change_location");
      redo.classList.toggle("hidden", desc.action !== "redownload");
      bar.classList.remove("hidden");
    } else {
      bar.classList.add("hidden");
    }
  }

  // ---- 列表增量渲染：每行 DOM 只创建一次，之后只更新变化的单元格 ----
  // 每次 render 都 replaceChildren 重建整表会造成选中态闪烁/滚动抖动，
  // 并与点击事件竞争（节点被销毁导致点击丢失）。
  const rowEls = new Map(); // task id -> { el, cells, nameSig, labelSig, stateSig, renameWrap }

  function setCellText(el, text) {
    if (el && el.textContent !== text) el.textContent = text;
  }

  function appendSourceIcon(host) {
    const ic = document.createElement("span");
    ic.className = "src-icon src-ext";
    ic.title = T("来源：浏览器扩展");
    ic.setAttribute("aria-label", T("浏览器扩展"));
    host.appendChild(ic);
  }

  function syncRenameError(wrap) {
    const text = (rename && rename.error) || "";
    let err = wrap.querySelector(".rename-error");
    if (text) {
      if (!err) {
        err = document.createElement("div");
        err.className = "rename-error";
        wrap.appendChild(err);
      }
      if (err.textContent !== text) err.textContent = text;
    } else if (err) {
      err.remove();
    }
  }

  function buildRowEl(t) {
    const row = document.createElement("div");
    row.className = "list-row data-row";
    if (missingFiles.has(t.id)) row.classList.add("file-missing");
    row.dataset.id = String(t.id);
    row.setAttribute("role", "row");
    const cells = { marquee: marqueeMode };

    if (marqueeMode) {
      const pickCell = document.createElement("div");
      pickCell.className = "cell pick-cell";
      const pick = document.createElement("input");
      pick.type = "checkbox";
      pick.className = "row-pick";
      pick.setAttribute("aria-label", T("选择 ") + (t.name || T("任务")));
      pickCell.appendChild(pick);
      row.appendChild(pickCell);
      cells.pick = pick;
    }

    cells.name = document.createElement("div");
    cells.name.className = "cell name-cell";
    cells.size = document.createElement("div");
    cells.size.className = "cell";

    cells.pctCell = document.createElement("div");
    cells.pctCell.className = "cell";
    cells.bar = document.createElement("div");
    cells.bar.className = "progress";
    cells.fill = document.createElement("div");
    cells.fill.className = "progress-fill";
    cells.bar.appendChild(cells.fill);
    cells.label = document.createElement("span");
    cells.label.className = "progress-label";
    cells.pctCell.append(cells.bar, cells.label);

    cells.speed = document.createElement("div");
    cells.speed.className = "cell";
    cells.eta = document.createElement("div");
    cells.eta.className = "cell";
    cells.state = document.createElement("div");
    cells.state.className = "cell";

    row.append(cells.name, cells.size, cells.pctCell, cells.speed, cells.eta, cells.state);
    return { el: row, cells, nameSig: null, labelSig: null, stateSig: null, renameWrap: null };
  }

  function updateRowEl(entry, t, index) {
    const { cells } = entry;
    const el = entry.el;
    el.dataset.index = String(index);
    el.classList.toggle("selected", selectedIds.has(t.id));
    el.classList.toggle("file-missing", missingFiles.has(t.id));
    if (cells.pick) cells.pick.checked = selectedIds.has(t.id);

    // 名称单元格（含重命名输入框）
    const renaming = isRenaming() && rename.id === t.id && rename.source === "list";
    if (renaming) {
      if (!entry.renameWrap || !cells.name.contains(entry.renameWrap)) {
        cells.name.textContent = "";
        if (t.source === "ext") appendSourceIcon(cells.name);
        entry.renameWrap = buildRenameEditor();
        cells.name.appendChild(entry.renameWrap);
      } else {
        // 已在编辑中：只原地刷新错误提示，绝不重建输入框（否则会丢焦点/光标）
        syncRenameError(entry.renameWrap);
      }
      entry.nameSig = "rename";
    } else {
      entry.renameWrap = null;
      const nameSig = [t.name || "", t.source === "ext" ? "ext" : "", canRename(t) ? "r" : "l"].join("\u0001");
      if (entry.nameSig !== nameSig) {
        entry.nameSig = nameSig;
        cells.name.textContent = "";
        if (t.source === "ext") appendSourceIcon(cells.name);
        const nameText = document.createElement("span");
        nameText.textContent = t.name;
        if (canRename(t)) {
          nameText.className = "name-editable";
          nameText.title = t.name;
          // 名称也是行的一部分：普通单击不拦截，冒泡给行处理器 → 选中并打开属性面板。
          // 框选模式下与行一致：只切换勾选（并阻止行处理器再切一次）；改名仍走双击。
          nameText.addEventListener("click", (e) => {
            if (marqueeMode) {
              e.stopPropagation();
              toggleRowSelection(t.id);
            }
          });
          nameText.addEventListener("dblclick", (e) => {
            e.stopPropagation();
            if (marqueeMode) return;
            startRename(t, "list");
          });
        } else {
          nameText.className = "name-locked";
          nameText.title = P.RENAME_UNAVAILABLE || T("当前无法重命名");
        }
        cells.name.appendChild(nameText);
      }
      if (cells.name.title !== (t.save_path || "")) cells.name.title = t.save_path || "";
    }

    setCellText(cells.size, fmtBytes(t.total));

    const pct = t.pct != null ? Math.min(100, t.pct) : t.state === "done" ? 100 : 0;
    const width = pct.toFixed(1) + "%";
    if (cells.fill.style.width !== width) cells.fill.style.width = width;
    const fillClass = "progress-fill" + (isFailedTask(t) ? " err" : "");
    if (cells.fill.className !== fillClass) cells.fill.className = fillClass;

    const labelText = t.pct != null ? pct.toFixed(1) + "%" : "—";
    const hint = P.protocolHint ? P.protocolHint(t) : null;
    const hintSig = hint ? hint.count + hint.label : "";
    const labelSig = labelText + "|" + hintSig;
    if (entry.labelSig !== labelSig) {
      entry.labelSig = labelSig;
      cells.label.textContent = labelText;
      if (hint) {
        const badge = document.createElement("span");
        badge.className = "seg-mode-hint proto-hint";
        const count = document.createElement("span");
        count.className = "conn-count";
        count.textContent = String(hint.count);
        const proto = document.createElement("span");
        proto.className = "conn-proto";
        proto.textContent = hint.label;
        badge.append(count, proto);
        cells.label.appendChild(badge);
      }
    }

    // 列表「速率」列：下载中显示实时值；已完成优先显示采样峰值，没有采样才
    // 退回「已下载字节 / 净下载耗时」的平均值；其它状态显示 —。
    const shownSpeed = displayedSpeed(t);
    const speedTask = t.state === "downloading" || t.state === "connecting"
      ? { ...t, speed: shownSpeed }
      : t;
    const speedCell = P.listSpeedCell
      ? P.listSpeedCell(speedTask, speedHistory.get(t.id) || [])
      : { kind: t.state === "downloading" ? "live" : "none", bps: shownSpeed };
    setCellText(cells.speed, speedCell.kind === "none" ? "—" : fmtSpeed(speedCell.bps));
    const speedTip =
      speedCell.kind === "live"
        ? T("实时速率")
        : speedCell.kind === "peak"
          ? T("最高速率 ") + fmtSpeed(speedCell.bps)
          : speedCell.kind === "average"
            ? T("平均速率（无峰值采样）")
            : "";
    if (cells.speed.title !== speedTip) cells.speed.title = speedTip;
    setCellText(cells.eta, fmtEta(t));

    // 状态单元格：文本 / 类名 / tooltip 都只在变化时写
    const stateText = formatQueueStatus(t, Date.now());
    const stateTip = isInterrupted(t)
      ? INTERRUPTED_TOOLTIP
      : isFailedTask(t)
        ? taskFailReason(t)
        : t.state === "queued"
          ? retryTooltip(t) || ""
          : "";
    let stateCls = "cell";
    if (isInterrupted(t)) stateCls += " st-queued";
    else if (isFailedTask(t)) stateCls += " st-err";
    else if (t.state === "queued") stateCls += " st-queued";
    if (t.state === "downloading") stateCls += " st-dl";
    if (t.state === "done") stateCls += " st-done";
    const stateSig = stateText + "\u0001" + stateCls + "\u0001" + stateTip;
    if (entry.stateSig !== stateSig) {
      entry.stateSig = stateSig;
      cells.state.textContent = stateText;
      if (cells.state.className !== stateCls) cells.state.className = stateCls;
      if (cells.state.title !== stateTip) cells.state.title = stateTip;
    }
  }

  function renderListWindow() {
    const scroll = document.getElementById("list-scroll");
    const spacer = document.getElementById("list-spacer");
    const windowEl = document.getElementById("list-window");
    const rows = filteredTasks();
    spacer.style.height = (rows.length * ROW_H) + "px";
    const range = visibleRange(scroll.scrollTop, scroll.clientHeight, rows.length, ROW_H, OVERSCAN);
    const start = range.start;
    const end = range.end;
    windowEl.style.top = (start * ROW_H) + "px";

    const keep = [];
    for (let i = start; i < end; i++) {
      const t = rows[i];
      let entry = rowEls.get(t.id);
      if (!entry || entry.cells.marquee !== marqueeMode) {
        entry = buildRowEl(t);
        rowEls.set(t.id, entry);
      }
      updateRowEl(entry, t, i);
      keep.push(entry.el);
    }

    // keyed 顺序复用：只移动/移除必要的节点，不重建整表
    let ref = windowEl.firstChild;
    for (const el of keep) {
      if (ref === el) {
        ref = el.nextSibling;
        continue;
      }
      windowEl.insertBefore(el, ref);
    }
    while (ref) {
      const next = ref.nextSibling;
      ref.remove();
      ref = next;
    }

    // 缓存清理：已删除/已不在当前筛选内的行
    if (rowEls.size > rows.length + 64) {
      const alive = new Set(rows.map((t) => t.id));
      for (const id of [...rowEls.keys()]) {
        if (!alive.has(id)) rowEls.delete(id);
      }
    }
  }

  function render(force) {
    const editingRename = !force && isRenaming() && isRenameInputFocused();
    if (editingRename) renderPending = true;
    const empty = document.getElementById("empty-state");
    const skel = document.getElementById("list-skeleton");
    const fail = document.getElementById("list-fail");
    const scroll = document.getElementById("list-scroll");
    const head = document.getElementById("list-head");

    if (listLoading && tasks.length === 0 && !listError) {
      skel.classList.remove("hidden");
      empty.classList.add("hidden");
      fail.classList.add("hidden");
      scroll.classList.add("hidden");
      head.classList.add("hidden");
    } else if (listError && tasks.length === 0) {
      skel.classList.add("hidden");
      empty.classList.add("hidden");
      fail.classList.remove("hidden");
      document.getElementById("list-fail-reason").textContent = LIST_LOAD_FAIL;
      scroll.classList.add("hidden");
      head.classList.add("hidden");
    } else if (filteredTasks().length === 0) {
      skel.classList.add("hidden");
      fail.classList.add("hidden");
      empty.classList.remove("hidden");
      const cat = currentCategory();
      document.getElementById("empty-title").textContent =
        (E.emptyCategoryTitle && E.emptyCategoryTitle(cat)) || T("暂无下载任务");
      document.getElementById("empty-hint").textContent =
        (E.emptyCategoryHint && E.emptyCategoryHint(cat)) ||
        (cat === "all" ? T("点击「新建下载」开始，或从托盘菜单发起。") : "");
      document.getElementById("empty-new").classList.toggle("hidden", cat !== "all");
      scroll.classList.add("hidden");
      head.classList.add("hidden");
    } else {
      skel.classList.add("hidden");
      empty.classList.add("hidden");
      fail.classList.add("hidden");
      scroll.classList.remove("hidden");
      head.classList.remove("hidden");
      if (editingRename) renderPending = true;
      else renderListWindow();
    }
    updateToolbar();
    updateStatusbar();
    updateFailBar();
    if (editingRename) renderPending = true;
    else renderProps();
  }

  // 列表刷新单飞：600ms 定时器、引擎事件回调、设置页关闭后都会调 refresh()。
  // 上一次请求没回来就不再叠加（复用同一个 promise），否则引擎慢/重启时会排队
  // 堆积请求，界面表现就是卡顿、点击没反应。loadSettings 之后的首刷走同一条路。
  let refreshInFlight = null;

  function refresh() {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = refreshOnce().finally(() => {
      refreshInFlight = null;
    });
    return refreshInFlight;
  }

  async function refreshOnce() {
    const resp = await send({ op: "list" });
    listLoading = false;
    let listed = false;
    if (resp.ok && resp.tasks) {
      listed = true;
      tasks = resp.tasks;
      maybePlayErrorSound(tasks);
      sampleTaskSpeeds(tasks); // 与属性面板是否打开无关，持续记录下载阶段
      listError = null;
      setEngineOffline(false);
      lastEngineEventAt = Date.now();
      if (pendingOptimistic) {
        const t = tasks.find((x) => x.id === pendingOptimistic.id);
        if (t) {
          t.name = pendingOptimistic.name;
          t.save_path = pendingOptimistic.save_path;
          t.state = pendingOptimistic.state;
        }
      }
      for (const id of [...selectedIds]) {
        if (!tasks.some((t) => t.id === id)) selectedIds.delete(id);
      }
      if (anchorId != null && !tasks.some((t) => t.id === anchorId)) anchorId = null;
      if (rename && !tasks.some((t) => t.id === rename.id)) {
        rename = null;
        renderPending = false;
      }
      // 任务被删除、或不再是「已完成且有保存路径」时，清掉它的灰度标记，
      // 否则重新下载 / 改名后旧行会一直灰着。
      const stillDone = new Set(
        tasks
          .filter((t) => t && t.state === "done" && String(t.save_path || "").trim())
          .map((t) => t.id)
      );
      for (const id of [...missingFiles]) {
        if (!stillDone.has(id)) missingFiles.delete(id);
      }
    } else if (!resp.ok) {
      listError = LIST_LOAD_FAIL;
    }
    render();
    // 列表首次成功载入时检测一次「已完成任务的文件是否还在」。之后只由窗口
    // 聚焦 / 右键「刷新列表」触发，避免每 600ms 轮询都做一次文件 IO。
    if (listed && !missingCheckedOnce) {
      missingCheckedOnce = true;
      void checkMissingFiles();
    }
  }

  /// 把 missingFiles 同步到当前已渲染的行（虚拟列表只改存在的 DOM）。
  function syncMissingRows() {
    for (const [id, entry] of rowEls) {
      const el = entry && entry.el;
      if (!el) continue;
      el.classList.toggle("file-missing", missingFiles.has(id));
    }
  }

  /// 检测已完成任务的目标文件是否仍然存在。
  ///
  /// 仅由「窗口重新聚焦 / 列表首次载入 / 右键刷新列表」触发：`paths_exist` 要访问
  /// 文件系统，不能跟着 600ms 轮询跑。invoke 不可用、没有 done 任务、已有请求在飞
  /// 时直接返回；命令失败只 warn，保持现状（不误标灰度、不弹错误）。
  async function checkMissingFiles() {
    if (!invoke) return;
    if (missingCheckInFlight) return;
    const done = tasks.filter(
      (t) => t && t.state === "done" && String(t.save_path || "").trim()
    );
    if (done.length === 0) return;
    const paths = done.map((t) => t.save_path);
    missingCheckInFlight = (async () => {
      try {
        const flags = await invoke("paths_exist", { paths });
        if (!Array.isArray(flags)) return;
        missingFiles = P.missingFileIds ? P.missingFileIds(done, flags) : new Set();
        if (!(missingFiles instanceof Set)) missingFiles = new Set();
        syncMissingRows();
      } catch (e) {
        // 检测失败保持现状：不误标灰度、不弹错误。
        console.warn("检测已完成任务的文件是否存在失败", e);
      } finally {
        missingCheckInFlight = null;
      }
    })();
    await missingCheckInFlight;
  }

  function selectOnly(id) {
    selectedIds = new Set(id == null ? [] : [id]);
    anchorId = id;
  }

  function selectRange(fromId, toId, rows) {
    const a = rows.findIndex((t) => t.id === fromId);
    const b = rows.findIndex((t) => t.id === toId);
    if (a < 0 || b < 0) {
      selectOnly(toId);
      return;
    }
    const lo = Math.min(a, b);
    const hi = Math.max(a, b);
    selectedIds = new Set();
    for (let i = lo; i <= hi; i++) selectedIds.add(rows[i].id);
  }

  /// 只更新某一行的选中样式与复选框，避免整表重绘。
  /// 整表重绘会替换 DOM 节点，与点击/原生复选框切换竞争，曾导致选框与状态偶尔不一致。
  function syncRowSelectionDom(id, on) {
    const row = document.querySelector('.data-row[data-id="' + id + '"]');
    if (!row) return;
    row.classList.toggle("selected", on);
    const pick = row.querySelector(".row-pick");
    if (pick) pick.checked = on;
  }

  /// 反转某行的勾选状态（框选模式下的点击/复选框共用）
  function toggleRowSelection(id) {
    if (id == null) return;
    const on = !selectedIds.has(id);
    if (on) selectedIds.add(id);
    else selectedIds.delete(id);
    anchorId = id;
    syncRowSelectionDom(id, on);
    updateToolbar();
  }

  /// 取消尚未完成的框选拖动（不退出已进入的框选模式）。
  /// 统一入口：窗口失焦、右键、鼠标键已松开（mouseup 丢在窗口外）都走这里，
  /// 避免残留的按下状态在之后一次 mousemove 里把列表误切到框选模式。
  function cancelMarqueeDrag() {
    if (!marqueeDrag) return;
    marqueeDrag = null;
    document.body.classList.remove("marquee-drag");
    const box = document.getElementById("marquee-box");
    if (box) box.classList.add("hidden");
  }

  function setMarqueeMode(on) {
    // 框选模式只能由真实拖拽（marqueeDrag.active）进入：
    // 右键菜单、任务刷新、扩展创建任务等任何其它路径都不得开启它。
    if (on && !(marqueeDrag && marqueeDrag.active)) return;
    if (marqueeMode === on) return;
    marqueeMode = on;
    const root = document.getElementById("list-root");
    if (root) root.classList.toggle("marquee", on);
    // 复选框列占了 30px，可用宽度变了，列宽要重算。
    applyColumnWidths(true);
    const box = document.getElementById("marquee-box");
    if (box && !on) box.classList.add("hidden");
    if (on && propsVisible) {
      // 进入框选模式时关闭「任务属性」面板
      showPropsPanel(false);
    }
    closeRowContextMenu();
    closeBulkMenu();
    render();
  }

  /// 拖动框覆盖到的行（按虚拟滚动的内容坐标换算，未渲染的行也能命中）
  function marqueeHitIds(y0, y1) {
    const scroll = document.getElementById("list-scroll");
    if (!scroll) return [];
    const rect = scroll.getBoundingClientRect();
    const rows = filteredTasks();
    const c0 = scroll.scrollTop + (Math.min(y0, y1) - rect.top);
    const c1 = scroll.scrollTop + (Math.max(y0, y1) - rect.top);
    const out = [];
    for (let i = 0; i < rows.length; i++) {
      const lo = i * ROW_H;
      if (lo + ROW_H > c0 && lo < c1) out.push(rows[i].id);
    }
    return out;
  }

  const bulkMenu = document.getElementById("bulk-ctx-menu");
  function closeBulkMenu() {
    if (bulkMenu) bulkMenu.classList.add("hidden");
  }
  /// 批量菜单项是否可用：只依据**勾选项**
  function syncBulkMenu() {
    if (!bulkMenu) return;
    const list = selectedList();
    const startBtn = bulkMenu.querySelector('[data-bulk="start"]');
    const pauseBtn = bulkMenu.querySelector('[data-bulk="pause"]');
    const delBtn = bulkMenu.querySelector('[data-bulk="delete"]');
    if (startBtn) startBtn.disabled = !list.some(canStartTask);
    if (pauseBtn) pauseBtn.disabled = !list.some(canPauseTask);
    if (delBtn) delBtn.disabled = list.length === 0;
  }

  function openBulkMenu(x, y) {
    if (!bulkMenu) return;
    syncBulkMenu();
    bulkMenu.classList.remove("hidden");
    const pad = 4;
    const rect = bulkMenu.getBoundingClientRect();
    bulkMenu.style.left = Math.min(x, window.innerWidth - rect.width - pad) + "px";
    bulkMenu.style.top = Math.min(y, window.innerHeight - rect.height - pad) + "px";
  }

  /// 批量开始：只对**已勾选**的任务下发 resume
  async function bulkStart() {
    if (engineOffline) return;
    const list = selectedList();
    if (list.length === 0) return;
    let failed = false;
    for (const t of list) {
      if (canStartTask(t)) {
        const resp = await send({ op: "resume", id: t.id });
        if (!resp || !resp.ok) failed = true;
      }
    }
    if (failed) showActionToast(OP_FAIL);
    refresh();
  }

  /// 批量暂停：只对**已勾选**的任务生效
  async function bulkPause() {
    if (engineOffline) return;
    const list = selectedList();
    if (list.length === 0) return;
    let failed = false;
    for (const t of list) {
      if (canPauseTask(t)) {
        const resp = await send({ op: "pause", id: t.id });
        if (!resp || !resp.ok) failed = true;
      }
    }
    if (failed) showActionToast(OP_FAIL);
    refresh();
  }

  /// 批量删除：遵守「删除前确认」设置；未确认时按默认语义——已完成只删条目
  /// （保留本地文件），未完成的连未下完的文件一起删。
  async function bulkDelete() {
    const list = selectedList();
    if (list.length === 0) return;
    await loadSettings(false);
    if (settingBool(settingsCache["ui.confirm_on_delete"])) {
      openDeleteDialog(list.map((t) => t.id), true);
      return;
    }
    const doneIds = list.filter((t) => t.state === "done").map((t) => t.id);
    const unfinishedIds = list.filter((t) => t.state !== "done").map((t) => t.id);
    if (doneIds.length) await doDelete(doneIds, false);
    if (unfinishedIds.length) await doDelete(unfinishedIds, true);
    setMarqueeMode(false);
  }

  function onRowClick(e) {
    if (Date.now() - marqueeDragEndAt < CLICK_AFTER_DRAG_MS) return;
    // 整行算一个项目：除了「单击本身就有交互」的控件（勾选框、重命名输入框、下拉选择），
    // 行内任何位置（含任务名称）的单击都按「单击任务」处理 → 选中并打开属性面板。
    if (e.target.closest(".rename-input, .rename-wrap, .row-pick, select")) return;
    const row = e.target.closest(".data-row");
    if (!row) return;
    const id = Number(row.dataset.id);
    if (marqueeMode) {
      // 框选模式：点击条目只反转勾选，不弹属性、不改多选区间
      toggleRowSelection(id);
      return;
    }
    const rows = filteredTasks();
    const plain = !e.shiftKey && !e.ctrlKey && !e.metaKey;
    if (e.shiftKey && anchorId != null) {
      selectRange(anchorId, id, rows);
    } else if (e.ctrlKey || e.metaKey) {
      if (selectedIds.has(id)) selectedIds.delete(id);
      else selectedIds.add(id);
      anchorId = id;
    } else {
      selectOnly(id);
    }
    // 只有「普通单击 + 恰好选中一条」才展开属性面板：
    // Shift 区间、Ctrl 多选、框选时右侧只显示其中一条，容易让人误以为操作对象就是它。
    if (plain && selectedIds.size === 1) showPropsPanel(true);
    else if (propsVisible) showPropsPanel(false);
    // **不整表重绘**：`render()` 会重建窗口内所有行节点、重绘速度曲线、重刷工具栏，
    // 单击因此有一段「点了之后过一会儿才变色」的可感知延迟。右键走的是
    // `syncSelectionDom()`，只切 class，所以不卡——两者应该一致。
    // 行内容没有变化（点击不改变过滤/排序），同步选中样式就够了。
    syncSelectionDom();
  }

  function onRowDblClick(e) {
    if (marqueeMode) return;
    if (e.target.closest(".rename-input, .rename-wrap, .name-editable, select")) return;
    const row = e.target.closest(".data-row");
    if (!row) return;
    const id = Number(row.dataset.id);
    if (!selectedIds.has(id)) selectOnly(id);
    render();
    // 已完成的任务双击直接打开文件
    const task = tasks.find((t) => t.id === id);
    if (task && task.state === "done") openTaskFile(task);
  }

  const ctxMenu = document.getElementById("row-ctx-menu");
  // 右键菜单是单任务上下文：开始/暂停只认这个 id，不扩散到 selectedIds。
  let ctxTaskId = null;
  function closeRowContextMenu() {
    ctxMenu.classList.add("hidden");
  }
  function openRowContextMenu(x, y, task) {
    // **先按任务状态把菜单摆好，再显示**。反过来的顺序会让人看到"灰着的按钮
    // 突然变亮"——菜单复用的是同一份 DOM，上一次的 disabled 会延续到这一次。
    syncContextMenu(task);
    ctxMenu.classList.remove("hidden");
    const pad = 4;
    const rect = ctxMenu.getBoundingClientRect();
    ctxMenu.style.left = Math.min(x, window.innerWidth - rect.width - pad) + "px";
    ctxMenu.style.top = Math.min(y, window.innerHeight - rect.height - pad) + "px";
  }

  function onRowContext(e) {
    const row = e.target.closest(".data-row");
    if (!row) return;
    if (marqueeMode) {
      // 框选模式下，右键出批量菜单（全部开始 / 全部暂停 / 全部删除）
      e.preventDefault();
      closeRowContextMenu();
      openBulkMenu(e.clientX, e.clientY);
      return;
    }
    e.preventDefault();
    const id = Number(row.dataset.id);
    ctxTaskId = id;
    // **右键只弹菜单，不改选中集合**。菜单里的每个动作都按 `ctxTaskId` 定位，
    // 不依赖 selectedIds（见 syncContextMenu 的 delete 判据）。之前的
    // `selectOnly(id)` 会把选中态和属性面板内容一起切走，看起来就像
    // 「右键把任务属性弹出来了」。
    const task = tasks.find((t) => t.id === id) || null;
    openRowContextMenu(e.clientX, e.clientY, task);
  }

  /// 只更新选中样式与复选框，不重建列表。
  function syncSelectionDom() {
    document.querySelectorAll(".data-row").forEach((row) => {
      const id = Number(row.dataset.id);
      const on = selectedIds.has(id);
      row.classList.toggle("selected", on);
      const pick = row.querySelector(".row-pick");
      if (pick) pick.checked = on;
    });
    updateToolbar();
  }

  /// 按**任务状态 + 端点条件**一次性摆好右键菜单。
  ///
  /// 设计原则：**菜单项常驻显示，条件不满足就灰显（disabled）**，而不是整项隐藏。
  /// - 开始/暂停：能否执行互斥，不能执行的那一项灰显；
  /// - 打开文件：已完成且有保存路径才可点；
  /// - 查找 HTTP 源：eD2k 且未完成才可点；
  /// - 复制链接 / 打开目录：本地动作，不依赖引擎在线。
  ///
  /// 常驻的好处：菜单项数与位置不随任务状态跳变，弹出即是最终形态，
  /// 而且用户能看出「现在为什么点不了」，而不是面对一个少了几项的菜单。
  function syncContextMenu(taskArg) {
    const task = taskArg !== undefined
      ? taskArg
      : tasks.find((t) => t.id === ctxTaskId) || primarySelected();
    const item = (action) => document.querySelectorAll("#row-ctx-menu [data-action='" + action + "']");
    // 全部常驻显示，只切可用性：条件不满足 → 灰显不可点。
    const show = (action, enabled) => {
      item(action).forEach((btn) => {
        btn.classList.remove("hidden");
        btn.disabled = !enabled;
      });
    };

    const offline = !!engineOffline;
    const canStart = !offline && !!task && canStartTask(task);
    const canPause = !offline && !!task && canPauseTask(task);
    const isDone = !!(task && task.state === "done" && task.save_path);
    const isEd2k = !!(task && /^ed2k:/i.test(task.url || ""));

    // 开始 / 暂停：状态互斥，当前不能执行的那一项灰显。
    show("start", canStart);
    show("pause", canPause);
    // 右键是单任务上下文：只要右键到了一条任务，「删除」就一定删得掉这一条。
    show("delete", !offline && !!task);
    show("props", !!task);
    // 复制链接 / 打开目录是本地动作（不经过引擎），离线也可用。
    show("copy", !!task);
    show("open-file", isDone);
    show("open-dir", !!task);
    show("http-source", !offline && isEd2k && !isDone);

    item("open-file").forEach((btn) => {
      btn.title = isDone ? T("用默认程序打开下载好的文件") : "";
    });
    item("http-source").forEach((btn) => {
      btn.title = isEd2k ? T("在 archive.org 查找同名文件，或手动输入 HTTP 镜像") : "";
    });
    normalizeSeparators();
  }

  /// 分隔线只在**两侧都有可见项**时显示。菜单项现在常驻显示，所以正常情况下
  /// 两条分隔线都会保留；这个函数只是兜底（例如未来某项又改成按条件隐藏）。
  function normalizeSeparators() {
    const menu = document.getElementById("row-ctx-menu");
    if (!menu) return;
    const kids = [...menu.children];
    const visible = (el) => !el.classList.contains("hidden");
    kids.forEach((el, i) => {
      if (!el.classList.contains("ctx-sep")) return;
      let prev = null;
      for (let j = i - 1; j >= 0; j--) if (visible(kids[j])) { prev = kids[j]; break; }
      let next = null;
      for (let j = i + 1; j < kids.length; j++) if (visible(kids[j])) { next = kids[j]; break; }
      // 相邻的还是分隔线（连续两条）也只留一条。
      const keep = !!prev && !!next
        && !prev.classList.contains("ctx-sep")
        && !next.classList.contains("ctx-sep");
      el.classList.toggle("hidden", !keep);
    });
  }

  function showActionToast(text) {
    const stack = document.getElementById("toast-stack");
    const toast = document.createElement("div");
    toast.className = "toast";
    const title = document.createElement("div");
    title.className = "toast-title";
    title.textContent = text;
    toast.appendChild(title);
    stack.appendChild(toast);
    setTimeout(() => toast.remove(), 6000);
  }

  async function refreshSchedStatus() {
    const resp = await send({ op: "sched_status" });
    if (resp && resp.ok) {
      schedKnown = true;
      schedSnap = {
        next_start_at: resp.next_start_at || null,
        queued: resp.queued || 0,
        active: resp.active || 0,
      };
    }
    updateSchedChip();
    updateNewDialogHint();
  }

  async function startTasks(list) {
    if (engineOffline) return;
    let failed = false;
    for (const t of list) {
      if (canStartTask(t)) {
        const resp = await send({ op: "resume", id: t.id });
        if (!resp || !resp.ok) failed = true;
      }
    }
    if (failed) showActionToast(OP_FAIL);
    refresh();
  }

  async function pauseTasks(list) {
    if (engineOffline) return;
    let failed = false;
    for (const t of list) {
      if (canPauseTask(t)) {
        const resp = await send({ op: "pause", id: t.id });
        if (!resp || !resp.ok) failed = true;
      }
    }
    if (failed) showActionToast(OP_FAIL);
    refresh();
  }

  async function startSelected() {
    await startTasks(selectedList());
  }

  async function pauseSelected() {
    await pauseTasks(selectedList());
  }

  function spaceToggle() {
    const list = selectedList();
    if (list.length === 0) return;
    const anyRun = list.some((t) => ["connecting", "downloading", "verifying"].includes(t.state));
    if (anyRun) pauseSelected();
    else startSelected();
  }

  async function copyText(text) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch { /* ignore */ }
      ta.remove();
    }
  }

  async function copyUrls(list) {
    const urls = list.map((t) => t.url).filter(Boolean);
    if (urls.length === 0) return;
    await copyText(urls.join("\n"));
  }

  // 打开任务文件：文件不在时不再是"静默打开父目录"，而是明确告知并给出三个动作
  //（§8；「在磁盘上查找」命中后把任务重新指向找到的文件）。
  const FILE_MISSING_TEXT = T("文件已被移动或删除");
  let missingTask = null;

  function closeMissingDialog() {
    missingTask = null;
    closeLayer(document.getElementById("missing-mask"));
  }

  function openMissingDialog(task) {
    missingTask = task;
    setText("missing-path", task.save_path || "");
    const hits = document.getElementById("missing-hits");
    hits.textContent = "";
    hits.classList.add("hidden");
    const find = document.getElementById("missing-find");
    find.disabled = !invoke || engineOffline;
    openLayer(document.getElementById("missing-mask"), document.getElementById("missing-cancel"));
  }

  async function openTaskFile(task) {
    if (!task || !task.save_path) return;
    if (!invoke) {
      showActionToast(OPEN_DIR_FAIL);
      return;
    }
    try {
      await invoke("open_path", { path: task.save_path });
    } catch (e) {
      const code = String(e && e.message ? e.message : e);
      if (code.includes("file_missing")) openMissingDialog(task);
      else showActionToast(OPEN_DIR_FAIL);
    }
  }

  // 命中列表：点一条就把任务重新指向它。长度对不上的命中引擎会拒绝（size_mismatch）。
  function renderFindHits(task, resp) {
    const box = document.getElementById("missing-hits");
    box.textContent = "";
    box.classList.remove("hidden");
    const hits = Array.isArray(resp.hits) ? resp.hits : [];
    if (!hits.length) {
      const p = document.createElement("p");
      p.className = "hint";
      p.textContent = resp.truncated
        ? T("没有找到（查找到上限就停了，可以打开所在目录手动确认）")
        : T("没有找到同名同大小的文件");
      box.appendChild(p);
      return;
    }
    const head = document.createElement("p");
    head.className = "hint";
    head.textContent = resp.truncated
      ? T("找到 {n} 个（还有更多未列完），点一个把任务重新指向它：", { n: hits.length })
      : T("找到 {n} 个，点一个把任务重新指向它：", { n: hits.length });
    box.appendChild(head);
    hits.forEach((hit) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "tool find-hit";
      btn.textContent = hit.path;
      btn.title = `${hit.path}（${fmtBytes(hit.size)}）`;
      btn.addEventListener("click", async () => {
        const resp2 = await send({ op: "relocate", id: task.id, path: hit.path });
        if (resp2 && resp2.ok) {
          closeMissingDialog();
          showActionToast(T("已重新指向找到的文件"));
          refresh();
        } else {
          const code = resp2 && (resp2.error || resp2.code);
          showActionToast(code === "size_mismatch" ? T("找到的文件长度不一致，未采用") : OP_FAIL);
        }
      });
      box.appendChild(btn);
    });
  }

  function wireMissingDialog() {
    const mask = document.getElementById("missing-mask");
    if (!mask) return;
    document.getElementById("missing-cancel").addEventListener("click", closeMissingDialog);
    armBackdropClose(mask, closeMissingDialog);
    document.getElementById("missing-dir").addEventListener("click", async () => {
      const task = missingTask;
      if (task) await openDirs([task]);
    });
    document.getElementById("missing-redownload").addEventListener("click", async () => {
      const task = missingTask;
      if (!task) return;
      const resp = await send({ op: "restart", id: task.id });
      if (!resp || !resp.ok) {
        showActionToast(OP_FAIL);
        return;
      }
      closeMissingDialog();
      refresh();
    });
    document.getElementById("missing-find").addEventListener("click", async () => {
      const task = missingTask;
      if (!task) return;
      const btn = document.getElementById("missing-find");
      btn.disabled = true;
      const resp = await send({ op: "find_file", id: task.id });
      btn.disabled = false;
      if (!resp || !resp.ok) {
        showActionToast(OP_FAIL);
        return;
      }
      renderFindHits(task, resp);
    });
  }

  async function openDirs(list) {
    if (!invoke) {
      showActionToast(OPEN_DIR_FAIL);
      return;
    }
    const seen = new Set();
    let failed = false;
    for (const t of list) {
      const p = t.save_path;
      if (!p || seen.has(p)) continue;
      seen.add(p);
      try { await invoke("open_directory", { path: p }); }
      catch { failed = true; }
    }
    if (failed) showActionToast(OPEN_DIR_FAIL);
  }

  async function doDelete(ids, deleteFiles) {
    if (ids.length === 0) return;
    const resp = await send({ op: "delete", ids, delete_files: !!deleteFiles });
    if (!resp.ok) {
      showActionToast(OP_FAIL);
      return;
    }
    ids.forEach((id) => selectedIds.delete(id));
    if (anchorId != null && ids.includes(anchorId)) anchorId = null;
    refresh();
  }

  const delMask = document.getElementById("del-mask");
  let pendingDeleteIds = [];
  let pendingDeleteBulk = false;

  function openDeleteDialog(ids, bulk = false) {
    pendingDeleteIds = ids;
    pendingDeleteBulk = !!bulk;
    document.getElementById("del-msg").textContent =
      ids.length === 1 ? T("确定删除选中的 1 个任务？") : T("确定删除选中的 {n} 个任务？", { n: ids.length });
    document.getElementById("del-files").checked = false;
    openLayer(delMask, document.getElementById("del-cancel"));
  }
  function closeDeleteDialog() {
    closeLayer(delMask);
    pendingDeleteIds = [];
  }

  async function requestDelete(ids) {
    if (!ids || ids.length === 0) return;
    await loadSettings(false);
    if (settingBool(settingsCache["ui.confirm_on_delete"])) {
      openDeleteDialog(ids);
    } else {
      await doDelete(ids, false);
    }
  }

  const mask = document.getElementById("dlg-mask");
  async function openDialog() {
    setFieldError("dlg-url-err", "");
    setFieldError("dlg-dir-err", "");
    setFieldError("dlg-name-err", "");
    setFieldError("dlg-custom-headers-err", "");
    openLayer(mask, document.getElementById("dlg-url"));
    syncDialogFilename();
    try {
      await loadSettings(false);
      const raw = preferredDirToken();
      if (raw && invoke && !document.getElementById("dlg-dir").value) {
        try {
          document.getElementById("dlg-dir").value = await invoke("expand_user_path", { path: raw });
        } catch { /* keep empty */ }
      }
      updateNewDialogHint();
    } catch { /* keep dialog open */ }
  }

  function updateNewDialogHint() {
    const hint = document.getElementById("dlg-queue-hint");
    const at = resolvedNextStartAt();
    if (currentSchedCron() && at) {
      hint.textContent = T("将于 {t} 开始", { t: formatNextStart(at, Date.now()) });
      hint.classList.remove("hidden");
    } else {
      hint.textContent = "";
      hint.classList.add("hidden");
    }
  }
  function closeDialog() {
    closeLayer(mask);
  }

  async function submitNew(startMode) {
    setFieldError("dlg-url-err", "");
    setFieldError("dlg-dir-err", "");
    setFieldError("dlg-name-err", "");
    setFieldError("dlg-custom-headers-err", "");
    const url = document.getElementById("dlg-url").value.trim();
    const v = validateDownloadUrl(url);
    if (!v.ok) {
      setFieldError("dlg-url-err", v.text);
      return;
    }
    const dir = document.getElementById("dlg-dir").value.trim();
    const filename = document.getElementById("dlg-name").value.trim();
    // 自动回填的 URL 尾名不算显式指定：留空交给引擎读 Content-Disposition。
    const submitFilename = P.shouldSubmitFilename
      ? P.shouldSubmitFilename(filename, autoFilename, url)
      : Boolean(filename);
    const referrer = document.getElementById("dlg-referer").value.trim();
    // 自定义请求头：本地先按引擎同一套规则校验，错误指到具体行
    const customHeaders = document.getElementById("dlg-custom-headers").value;
    setFieldError("dlg-custom-headers-err", "");
    const hv = SF.validateCustomHeaders
      ? SF.validateCustomHeaders(customHeaders)
      : { ok: true };
    if (!hv.ok) {
      setFieldError("dlg-custom-headers-err", hv.text);
      return;
    }
    // 备用地址（镜像）：同一套规则先在本地校验，错到具体条目
    const altUrls = document.getElementById("dlg-alt-urls").value;
    setFieldError("dlg-alt-urls-err", "");
    const av = SF.validateAltUrls ? SF.validateAltUrls(altUrls) : { ok: true };
    if (!av.ok) {
      setFieldError("dlg-alt-urls-err", av.text);
      return;
    }
    // 同一链接 / 同一文件已有任务时先问用户（避免无意义地重复建任务）。
    if (!(await confirmDuplicateOrSkip(url))) return;
    const resp = await send({
      op: "add",
      url,
      dir: dir || null,
      filename: submitFilename ? filename : null,
      referrer: referrer || null,
      custom_headers: customHeaders.trim() ? customHeaders : null,
      alt_urls: altUrls.trim() ? altUrls : null,
      source: "manual",
      speed_limit_kbps: 0,
      start: startMode === "queue" ? "queue" : "now",
    });
    if (resp.ok && resp.id != null) {
      closeDialog();
      document.getElementById("dlg-url").value = "";
      document.getElementById("dlg-name").value = "";
      document.getElementById("dlg-custom-headers").value = "";
      document.getElementById("dlg-alt-urls").value = "";
      resetDialogFilename();
      selectOnly(resp.id);
      showPropsPanel(true);
      refresh();
    } else {
      setFieldError("dlg-url-err", ADD_DOWNLOAD_FAIL);
    }
  }

  // ---- 「记住上次目录」（`paths.remember_last_dir`）----
  //
  // 上次目录存 localStorage：它是界面状态，不是下载业务数据，不值得为它单开
  // 一个设置键。开关关掉时一律回落到 `paths.default_dir`。
  const LAST_DIR_KEY = "aidm.lastDir";

  function readLastDir() {
    try {
      const v = localStorage.getItem(LAST_DIR_KEY);
      return v && v.trim() ? v : "";
    } catch {
      // 隐私模式 / 存储被禁用：当作没记住
      return "";
    }
  }

  function rememberDir(dir) {
    const t = String(dir || "").trim();
    if (!t) return;
    try { localStorage.setItem(LAST_DIR_KEY, t); } catch { /* 同上 */ }
  }

  /// 目录选择框 / 保存目录输入框的起始目录。
  ///
  /// 可能是 `%USERPROFILE%` 这类 token，也可能是上次选定的绝对路径——两种形式
  /// 都能直接交给 `expand_user_path`。
  function preferredDirToken() {
    const fallback = settingStr(settingsCache["paths.default_dir"]);
    if (!settingBool(settingsCache["paths.remember_last_dir"])) return fallback;
    return readLastDir() || fallback;
  }

  async function browseInto(inputId) {
    if (!invoke) return;
    const el = document.getElementById(inputId);
    const initial = (el && el.value.trim()) || preferredDirToken();
    try {
      const dir = await invoke("pick_directory", { initial: initial || null });
      if (dir) {
        el.value = dir;
        rememberDir(dir);
      }
    } catch { /* cancelled */ }
  }

  function showSettingPage(page) {
    document.querySelectorAll(".settings-nav li").forEach((li) => {
      const on = li.dataset.page === page;
      li.classList.toggle("active", on);
      li.setAttribute("aria-selected", on ? "true" : "false");
    });
    document.querySelectorAll(".set-page").forEach((sec) => {
      sec.classList.toggle("hidden", sec.dataset.page !== page);
    });
  }

  function clearSettingErrors() {
    document.querySelectorAll("[data-err]").forEach((el) => {
      el.textContent = "";
      el.classList.add("hidden");
    });
  }

  function showSettingError(key, text) {
    const el = document.querySelector(`[data-err="${key}"]`);
    if (!el) return;
    el.textContent = text;
    el.classList.remove("hidden");
  }

  function proxyModeValue() {
    return document.querySelector('input[name="proxy-mode"]:checked')?.value || "follow-system";
  }

  function updateProxyBoxes() {
    const mode = proxyModeValue();
    document.getElementById("proxy-system-box").classList.toggle("hidden", mode !== "follow-system");
    document.getElementById("proxy-manual-box").classList.toggle("hidden", mode !== "manual");
  }

  async function loadSettings(force) {
    if (!force && Object.keys(settingsCache).length) return settingsCache;
    const resp = await send({ op: "settings_get" });
    if (resp.ok && resp.settings) {
      settingsCache = resp.settings;
      settingsLoadFailed = false;
      syncClipboardWatch();
      syncAutostart();
      syncTrayIcon();
      syncCloseToTray();
    } else {
      settingsLoadFailed = true;
    }
    if (resp && resp.version) engineVersion = String(resp.version);
    updateLimitPills();
    return settingsCache;
  }

  function clipboardLinkName(url) {
    const decode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };
    const ed2k = /^ed2k:\/\/\|file\|([^|]+)\|/i.exec(url);
    if (ed2k) return decode(ed2k[1]);
    const dn = /^magnet:\?.*?[?&]?dn=([^&]+)/i.exec(url);
    if (dn) return decode(dn[1].replace(/\+/g, " "));
    if (/^(magnet:|thunders?:)/i.test(url)) return url.slice(0, 48);
    return "";
  }

  // 电驴上传服务状态（L6）：只在设置页打开时渲染，不参与主循环。
  async function refreshEd2kUploadStatus() {
    const el = document.getElementById("ed2k-upload-status");
    if (!el || !invoke) return;
    try {
      const resp = await send({ op: "ed2k_upload_status" });
      const up = resp && resp.ed2k_upload;
      if (!up) {
        el.textContent = T("上传服务未启动。");
        return;
      }
      const mb = (up.uploaded_bytes / (1024 * 1024)).toFixed(1);
      if (!up.enabled) {
        el.textContent = T("上传已关闭（共享 {n} 个已完成的电驴任务）。", { n: up.shared_files });
      } else if (up.listening_port) {
        el.textContent =
          T("监听端口 {port}｜上传槽 {slots}｜排队 {queued}", { port: up.listening_port, slots: up.active_sessions, queued: up.queued_sessions }) +
          T("｜共享 {n} 个文件｜本次已上传 {mb} MB", { n: up.shared_files, mb: mb });
      } else {
        el.textContent = T("上传已开启但未监听成功{err}。", { err: up.last_error ? " (" + up.last_error + ")" : "" });
      }
    } catch {
      el.textContent = "";
    }
  }

  // 刷新公共源列表（Kad 节点 / eD2k 服务器）。
  //
  // 引擎用的是**已保存**的来源地址，所以先把三个地址字段落库，避免
  // 「改了地址、点了更新、却还在刷旧地址」。服务器刷新会把结果写回
  // `ed2k.servers`，因此成功后要重读设置让「公共服务器」输入框跟上。
  async function refreshEd2kSource(op, kind) {
    const status = document.getElementById("ed2k-source-status");
    if (!status) return;
    status.textContent = T("正在刷新…");
    const urls = [
      ["ed2k.nodes_dat_url", document.getElementById("set-ed2k-nodes-url").value],
      ["ed2k.nodes_dat_max_age_days", document.getElementById("set-ed2k-nodes-age").value],
      ["ed2k.server_list_url", document.getElementById("set-ed2k-servers-url").value],
    ];
    for (const [key, value] of urls) {
      const resp = await send({ op: "settings_set", key, value });
      if (!resp.ok) {
        showSettingError(key, settingsSetUserError(key, resp));
        status.textContent = T("来源地址无效，未刷新");
        return;
      }
    }
    const resp = await send({ op });
    if (!resp.ok) {
      status.textContent = T("刷新失败：") + (resp.error || T("未知错误"));
      return;
    }
    if (kind === "nodes") {
      status.textContent = T("已更新 {n} 个 Kad 节点。", { n: resp.nodes });
      return;
    }
    status.textContent = T("已更新 {n} 台公共服务器（已写回「公共服务器」）。", { n: resp.servers });
    const s = await loadSettings(true);
    document.getElementById("set-ed2k-servers").value = settingStr(s["ed2k.servers"]);
  }

  function syncClipboardWatch() {
    if (!invoke) return;
    invoke("set_clipboard_watch", {
      enabled: settingBool(settingsCache["browser.monitor_clipboard"]),
      exts: settingStr(settingsCache["browser.auto_catch_exts"]),
    }).catch(() => {});
  }

  // 本次运行是否已强制同步过开机自启。第一次必定同步：程序被移动后注册表里
  // 记的旧路径会失配，`set_autostart` 会按当前 exe 重写（自愈）；之后只在
  // 设置值真的变了才动注册表。
  let autostartSynced = false;
  let lastAutostart = null;

  /// 开机自启：设置（引擎库）是权威，注册表跟随。
  function syncAutostart() {
    if (!invoke) return;
    const want = settingBool(settingsCache["general.start_with_windows"]);
    if (autostartSynced && want === lastAutostart) return;
    autostartSynced = true;
    lastAutostart = want;
    invoke("set_autostart", { enabled: want }).catch(() => {
      // 失败就撤掉记忆，下次 loadSettings 再试一次。
      autostartSynced = false;
    });
  }

  let lastTrayIcon = null;
  let lastCloseToTray = null;

  function syncCloseToTray() {
    if (!invoke) return;
    const raw = settingsCache["general.close_to_tray"];
  // 拿不到这个键（引擎侧版本较旧 / 尚未下发）时不要下发 false，
  // 否则会把 Rust 侧默认（收进托盘）静默关掉。
  if (raw === undefined || raw === null) return;
  const want = settingBool(raw);
    if (want === lastCloseToTray) return;
    lastCloseToTray = want;
    invoke("apply_close_to_tray", { enabled: want }).catch(() => {
      lastCloseToTray = null;
    });
  }

  /// 托盘图标显隐。托盘本身在启动时就建好，这里只切可见性。
  function syncTrayIcon() {
    if (!invoke) return;
    const want = settingBool(settingsCache["general.tray_icon"]);
    if (want === lastTrayIcon) return;
    lastTrayIcon = want;
    invoke("apply_tray_icon", { visible: want }).catch(() => {
      lastTrayIcon = null;
    });
  }

  function schedModeValue() {
    return document.querySelector('input[name="sched-mode"]:checked')?.value || "daily";
  }

  function parseTimeInput(raw) {
    const m = String(raw || "").trim().match(/^(\d{1,2}):(\d{2})$/);
    if (!m) return null;
    const hour = Number(m[1]);
    const minute = Number(m[2]);
    if (hour > 23 || minute > 59) return null;
    return [hour, minute];
  }

  function fillSchedForm(cron) {
    const parsed = parseSchedMode(cron);
    const on = parsed.mode !== "off";
    document.getElementById("set-sched-on").checked = on;
    const mode = on ? parsed.mode : "daily";
    const radio = document.querySelector(`input[name="sched-mode"][value="${mode}"]`);
    if (radio) radio.checked = true;
    if (parsed.time) {
      document.getElementById("set-sched-time").value = pad2(parsed.time[0]) + ":" + pad2(parsed.time[1]);
    } else if (!document.getElementById("set-sched-time").value) {
      document.getElementById("set-sched-time").value = "02:00";
    }
    document.getElementById("set-sched-cron").value = on && parsed.mode === "custom" ? cron : "";
    updateSchedFormUi();
  }

  function collectSchedCron() {
    if (!document.getElementById("set-sched-on").checked) return "";
    const mode = schedModeValue();
    if (mode === "custom") return document.getElementById("set-sched-cron").value.trim();
    const hm = parseTimeInput(document.getElementById("set-sched-time").value);
    if (!hm) return "";
    return cronFromPreset(mode, hm[0], hm[1], "");
  }

  function updateSchedFormUi() {
    const on = document.getElementById("set-sched-on").checked;
    const mode = schedModeValue();
    document.getElementById("sched-mode-box").classList.toggle("is-disabled", !on);
    document.querySelectorAll('input[name="sched-mode"]').forEach((r) => {
      r.disabled = !on;
    });
    document.getElementById("sched-time-wrap").classList.toggle("hidden", !on || mode === "custom");
    document.getElementById("sched-cron-wrap").classList.toggle("hidden", !on || mode !== "custom");
    const cron = collectSchedCron();
    const at = cron && isValidCron5(cron) ? nextCronMs(cron, Date.now()) : null;
    document.getElementById("sched-next").textContent =
      T("下次启动时间：") + (at ? formatNextStart(at, Date.now()) : "—");
  }

  function validateConnForm() {
    let ok = true;
    let firstErrKey = "";
    const fail = (key, text) => {
      if (!firstErrKey) firstErrKey = key;
      showSettingError(key, text);
      ok = false;
    };
    for (const [key, bounds] of Object.entries(FIELD_BOUNDS)) {
      const id = {
        "conn.global_conn_cap": "set-global-cap",
        "conn.retry_max": "set-retry-max",
      }[key];
      const raw = document.getElementById(id).value;
      if (parseIntInRange(raw, bounds[0], bounds[1]) == null) {
        fail(key, fieldRangeText(key));
      }
    }
    if (backoffMsFromSeconds(document.getElementById("set-retry-backoff").value) == null) {
      fail("conn.retry_backoff_ms", fieldRangeText("conn.retry_backoff_ms"));
    }
    if (document.getElementById("set-sched-on").checked) {
      const cron = collectSchedCron();
      if (!isValidCron5(cron) || !cron) {
        fail("sched.start_cron", CRON_INVALID);
      }
    }
    // 错误提示分散在「连接 / 计划」页。用户停在「常规」页时若不跳转，
    // 表现就是“点确定完全没反应”；把用户带到第一条错误所在的页。
    if (!ok) {
      showSettingPage((E.settingsPageForKey && E.settingsPageForKey(firstErrKey)) || "conn");
    }
    return ok;
  }

  async function fillSettingsForm() {
    await loadSettings(true);
    const s = settingsCache;
    document.getElementById("set-start-win").checked = settingBool(s["general.start_with_windows"]);
    document.getElementById("set-confirm-del").checked = settingBool(s["ui.confirm_on_delete"]);
    document.getElementById("set-notify").checked = settingBool(s["ui.notify_on_complete"]);
    document.getElementById("set-tray-icon").checked = settingBool(s["general.tray_icon"]);
    document.getElementById("set-close-to-tray").checked = settingBool(s["general.close_to_tray"]);
    const completeMode = settingStr(s["ui.sound_complete"]) || "beep";
    const completeFile = settingStr(s["ui.sound_file_complete"]);
    document.getElementById("set-sound-complete").value =
      completeMode === "file" && completeFile.trim() ? "file" : "beep";
    document.getElementById("set-sound-file-complete").value = completeFile;
    const errorMode = settingStr(s["ui.sound_error"]) || "beep";
    const errorFile = settingStr(s["ui.sound_file_error"]);
    document.getElementById("set-sound-error").value =
      errorMode === "file" && errorFile.trim() ? "file" : "beep";
    document.getElementById("set-sound-file-error").value = errorFile;
    renderSoundName("complete");
    renderSoundName("error");
    document.getElementById("set-remember-dir").checked = settingBool(s["paths.remember_last_dir"]);
    document.getElementById("set-category-dirs").value = settingStr(s["paths.category_dirs"]) || "{}";
    document.getElementById("set-default-task-limit").value =
      settingStr(s["conn.speed_limit_default_kbps"]) || "0";
    document.getElementById("set-proxy-only-for").value = settingStr(s["proxy.only_for"]) || "all";
    document.getElementById("set-proxy-bypass").value = settingStr(s["proxy.bypass_hosts"]);
    document.getElementById("set-browser-exclude").value = settingStr(s["browser.exclude_hosts"]);
    document.getElementById("set-browser-exts").value = settingStr(s["browser.auto_catch_exts"]);
    document.getElementById("set-browser-skip-html").checked = settingBool(s["browser.skip_html"]);
    document.getElementById("set-browser-clipboard").checked = settingBool(s["browser.monitor_clipboard"]);
    document.getElementById("set-browser-hotkey-prevent").value =
      settingStr(s["browser.hotkey_prevent"]) || "";
    document.getElementById("set-browser-hotkey-force").value =
      settingStr(s["browser.hotkey_force"]) || "";
    document.getElementById("set-panel-enabled").checked = settingBool(s["browser.panel_enabled"]);
    document.getElementById("set-panel-exts").value = settingStr(s["browser.panel_exts"]);
    document.getElementById("set-panel-exclude").value = settingStr(s["browser.panel_exclude_hosts"]);
    document.getElementById("set-fastdl").checked = settingBool(s["engine.fastdl"]);
    document.getElementById("set-verify-sha256").checked = settingBool(s["verify.sha256_after"]);
    document.getElementById("set-recv-buf").value = settingStr(s["net.recv_buf_kb"]) || "0";
    document.getElementById("set-user-agent").value = settingStr(s["net.user_agent"]);
    document.getElementById("set-accept-language").value =
      settingStr(s["net.accept_language"]) || "auto";
    document.getElementById("set-accept").value = settingStr(s["net.accept"]) || "*/*";
    document.getElementById("set-accept-charset").value =
      settingStr(s["net.accept_charset"]) || "*";
    document.getElementById("set-accept-encoding").value =
      settingStr(s["net.accept_encoding"]) || "identity";
    document.getElementById("set-referer-fallback").checked = settingBool(
      s["net.referer_fallback"] !== "false"
    );
    document.getElementById("set-revision").textContent =
      T("设置版本：") + (settingStr(s["settings.revision"]) || "—");
    // 时段 / 配额 / 完成后动作 / 重复链接。
    // 这几项以前只画了控件、没在这里回填，界面永远是空的——设置页里的每个
    // 控件都必须在 fill 与 collect 两侧都有接线，见 test/settings_wiring.test.js。
    document.getElementById("set-window-on").checked = settingBool(s["sched.window_enabled"]);
    document.getElementById("set-window-start").value =
      settingStr(s["sched.window_start"]) || "00:00";
    document.getElementById("set-window-end").value = settingStr(s["sched.window_end"]) || "23:59";
    document.getElementById("set-window-days").value = normalizeDays(s["sched.window_days"]);
    document.getElementById("set-quota-on").checked = settingBool(s["sched.quota_enabled"]);
    document.getElementById("set-quota-mb").value = settingStr(s["sched.quota_mb"]) || "200";
    document.getElementById("set-quota-period").value = settingStr(s["sched.quota_period"]) || "day";
    document.getElementById("set-quota-action").value =
      settingStr(s["sched.quota_action"]) || "pause";
    document.getElementById("set-after-done").value = settingStr(s["sched.after_done"]) || "none";
    document.getElementById("set-after-done-force").checked = settingBool(
      s["sched.after_done_force"]
    );
    document.getElementById("set-duplicate-action").value =
      settingStr(s["ui.duplicate_action"]) || "allow";
    updateWindowBoxes();
    updateQuotaBoxes();
    // 注意：这里**不要**再插入 await。
    // 之前 `await refreshHostConns()` 夹在填充中间，它一旦失败/抛错，后面
    // paths/连接/重试/超时/代理/浏览器/更新 的所有字段就全都不填了——用户看到的
    // 就是"设置里一片空白"。所有可选异步查询统一挪到函数末尾，且互不影响。
    document.getElementById("set-default-dir").value = settingStr(s["paths.default_dir"]);
    const metaRaw = settingStr(s["paths.metadata_dir"]);
    const metaEl = document.getElementById("set-meta-dir");
    metaEl.dataset.raw = metaRaw;
    metaEl.value = metaRaw;
    document.getElementById("set-global-cap").value = settingStr(s["conn.global_conn_cap"]) || "256";
    document.getElementById("set-timeout-connect").value = settingStr(s["conn.timeout_connect_s"]) || "15";
    document.getElementById("set-timeout-idle").value = settingStr(s["conn.timeout_idle_s"]) || "60";
    document.getElementById("set-retry-max").value = settingStr(s["conn.retry_max"]) || "5";
    document.getElementById("set-ed2k-kad").checked = settingBool(s["ed2k.kad_enabled"]);
    document.getElementById("set-ed2k-servers").value = settingStr(s["ed2k.servers"]);
    document.getElementById("set-ed2k-nodes-url").value = settingStr(s["ed2k.nodes_dat_url"]);
    document.getElementById("set-ed2k-nodes-age").value =
      settingStr(s["ed2k.nodes_dat_max_age_days"]) || "7";
    document.getElementById("set-ed2k-servers-url").value = settingStr(s["ed2k.server_list_url"]);
    document.getElementById("set-alt-auto-mirrors").checked = settingBool(s["alt.auto_mirrors"]);
    document.getElementById("set-find-enabled").checked = settingBool(s["find.enabled"]);
    document.getElementById("set-find-slow-mbps").value =
      settingStr(s["find.slow_min_mbps"]) || "50";
    document.getElementById("set-find-slow-window").value =
      settingStr(s["find.slow_window_s"]) || "60";
    document.getElementById("set-ed2k-upload-enabled").checked = settingBool(
      s["ed2k.upload_enabled"],
    );
    document.getElementById("set-ed2k-listen-port").value =
      settingStr(s["ed2k.listen_port"]) || "4662";
    document.getElementById("set-ed2k-upload-slots").value =
      settingStr(s["ed2k.upload_slots"]) || "3";
    document.getElementById("set-ed2k-upload-max-waiting").value =
      settingStr(s["ed2k.upload_max_waiting"]) || "50";
    document.getElementById("set-ed2k-upload-rate").value =
      settingStr(s["ed2k.upload_rate_kbps"]) || "0";
    void refreshEd2kUploadStatus();
    document.getElementById("set-bt-listen-port").value = settingStr(s["bt.listen_port"]) || "0";
    document.getElementById("set-bt-seed-minutes").value = settingStr(s["bt.seed_minutes"]) || "0";
    document.getElementById("set-bt-extra-trackers").value = settingStr(s["bt.extra_trackers"]);
    document.getElementById("set-retry-backoff").value = secondsFromBackoffMs(settingStr(s["conn.retry_backoff_ms"]) || "1000");
    fillSchedForm(settingStr(s["sched.start_cron"]));
    document.getElementById("set-speed-limit").value = settingStr(s["speed.global_limit_kbps"]) || "0";
    let mode = settingStr(s["proxy.mode"]) || "follow-system";
    if (mode === "system") mode = "follow-system";
    const radio = document.querySelector(`input[name="proxy-mode"][value="${mode}"]`);
    if (radio) radio.checked = true;
    document.getElementById("set-proxy-scheme").value = settingStr(s["proxy.scheme"]) || "http";
    document.getElementById("set-proxy-host").value = settingStr(s["proxy.host"]);
    document.getElementById("set-proxy-port").value = settingStr(s["proxy.port"]);
    document.getElementById("set-proxy-user").value = settingStr(s["proxy.user"]);
    document.getElementById("set-proxy-pass").value = "";
    hasSavedPassword = settingBool(s["proxy.has_password"]);
    passCleared = false;
    const pass = document.getElementById("set-proxy-pass");
    pass.placeholder = hasSavedPassword ? T("已保存（留空不修改）") : "";
    document.getElementById("set-clear-pass").classList.toggle("hidden", !hasSavedPassword);
    updateProxyBoxes();
    document.getElementById("set-browser-enabled").checked = settingBool(
      s["browser.enabled"] != null ? s["browser.enabled"] : s["browser.integration_enabled"]
    );
    document.getElementById("set-click-takeover").checked = settingBool(s["browser.click_takeover"]);
    allowedExtIds = parseExtIdList(settingStr(s["browser.allowed_ext_ids"]));
    renderExtIdRows();
    updateBrowserRestEnabled();
    document.getElementById("set-update-auto").checked = U.normalizeAutoCheck(s["update.auto_check"]);
    updateState.lastCheckAt = settingStr(s["update.last_check_at"]);
    const resolved = U.resolveAppVersion(null, s, engineVersion);
    if (resolved) updateState.currentVersion = resolved;
    renderUpdatePage();
    // ---- 到这里所有"值"都已填好。以下是可选补充信息，逐个独立、失败不影响上面 ----
    await fillOptionalSettingsInfo(metaRaw);
  }

  /// 可选补充：元数据目录展开、系统代理显示、浏览器组件状态、每服务器例外。
  ///
  /// 每一项各自 try/catch：任何一项失败都只影响它自己那块展示，
  /// 绝不会让已经填好的设置值消失（这正是之前"一片空白"的根因）。
  async function fillOptionalSettingsInfo(metaRaw) {
    const metaEl = document.getElementById("set-meta-dir");
    if (invoke && metaRaw) {
      try {
        metaEl.value = await invoke("expand_user_path", { path: metaRaw });
      } catch {
        metaEl.value = metaRaw;
      }
    }
    try {
      const sys = await send({ op: "system_proxy_get" });
      const box = document.getElementById("sys-proxy-display");
      const p = sys ? sys.system_proxy : null;
      box.textContent = p && p.host ? p.host + ":" + p.port : T("未检测到系统代理");
    } catch (e) {
      console.warn("system_proxy_get 失败：", e);
    }
    try {
      await refreshHostAndEngineStatus();
    } catch (e) {
      console.warn("浏览器组件状态读取失败：", e);
    }
    try {
      await refreshHostConns();
    } catch (e) {
      // 以前这里静默失败，界面看不出问题；现在留痕，便于定位
      console.warn("每服务器例外读取失败：", e);
    }
    try {
      await refreshSiteLogins();
    } catch (e) {
      console.warn("站点凭据读取失败：", e);
    }
  }

  function collectSettingsForm() {
    return {
      "general.start_with_windows": document.getElementById("set-start-win").checked ? "true" : "false",
      "ui.confirm_on_delete": document.getElementById("set-confirm-del").checked ? "true" : "false",
      "ui.notify_on_complete": document.getElementById("set-notify").checked ? "true" : "false",
      "general.tray_icon": document.getElementById("set-tray-icon").checked ? "true" : "false",
      "general.close_to_tray": document.getElementById("set-close-to-tray").checked ? "true" : "false",
      "ui.sound_complete":
        document.getElementById("set-sound-complete").value === "file" &&
        document.getElementById("set-sound-file-complete").value.trim()
          ? "file"
          : "beep",
      "ui.sound_file_complete":
        document.getElementById("set-sound-complete").value === "file"
          ? document.getElementById("set-sound-file-complete").value.trim()
          : "",
      "ui.sound_error":
        document.getElementById("set-sound-error").value === "file" &&
        document.getElementById("set-sound-file-error").value.trim()
          ? "file"
          : "beep",
      "ui.sound_file_error":
        document.getElementById("set-sound-error").value === "file"
          ? document.getElementById("set-sound-file-error").value.trim()
          : "",
      "paths.remember_last_dir": document.getElementById("set-remember-dir").checked ? "true" : "false",
      "paths.category_dirs": document.getElementById("set-category-dirs").value.trim() || "{}",
      "conn.speed_limit_default_kbps": document.getElementById("set-default-task-limit").value,
      "sched.window_enabled": document.getElementById("set-window-on").checked ? "true" : "false",
      "sched.window_start": document.getElementById("set-window-start").value || "00:00",
      "sched.window_end": document.getElementById("set-window-end").value || "23:59",
      "sched.window_days": normalizeDays(document.getElementById("set-window-days").value),
      "sched.quota_enabled": document.getElementById("set-quota-on").checked ? "true" : "false",
      "sched.quota_mb": document.getElementById("set-quota-mb").value || "200",
      "sched.quota_period": document.getElementById("set-quota-period").value,
      "sched.quota_action": document.getElementById("set-quota-action").value,
      "ui.duplicate_action": document.getElementById("set-duplicate-action").value,
      "proxy.only_for": document.getElementById("set-proxy-only-for").value,
      "proxy.bypass_hosts": document.getElementById("set-proxy-bypass").value,
      "browser.exclude_hosts": document.getElementById("set-browser-exclude").value,
      "browser.auto_catch_exts": document.getElementById("set-browser-exts").value,
      "browser.skip_html": document.getElementById("set-browser-skip-html").checked ? "true" : "false",
      "browser.monitor_clipboard": document.getElementById("set-browser-clipboard").checked ? "true" : "false",
      "browser.hotkey_prevent": document.getElementById("set-browser-hotkey-prevent").value,
      "browser.hotkey_force": document.getElementById("set-browser-hotkey-force").value,
      "browser.panel_enabled": document.getElementById("set-panel-enabled").checked ? "true" : "false",
      "browser.panel_exts": document.getElementById("set-panel-exts").value,
      "browser.panel_exclude_hosts": document.getElementById("set-panel-exclude").value,
      "engine.fastdl": document.getElementById("set-fastdl").checked ? "true" : "false",
      "verify.sha256_after": document.getElementById("set-verify-sha256").checked ? "true" : "false",
      "net.recv_buf_kb": document.getElementById("set-recv-buf").value || "0",
      "net.user_agent": document.getElementById("set-user-agent").value,
      "net.accept_language": document.getElementById("set-accept-language").value,
      "net.accept": document.getElementById("set-accept").value,
      "net.accept_charset": document.getElementById("set-accept-charset").value,
      "net.accept_encoding": document.getElementById("set-accept-encoding").value,
      "net.referer_fallback": document.getElementById("set-referer-fallback").checked
        ? "true"
        : "false",
      "paths.default_dir": document.getElementById("set-default-dir").value,
      "conn.global_conn_cap": document.getElementById("set-global-cap").value,
      "conn.timeout_connect_s": document.getElementById("set-timeout-connect").value,
      "conn.timeout_idle_s": document.getElementById("set-timeout-idle").value,
      "conn.retry_max": document.getElementById("set-retry-max").value,
      "ed2k.kad_enabled": document.getElementById("set-ed2k-kad").checked ? "true" : "false",
      "ed2k.servers": document.getElementById("set-ed2k-servers").value,
      "ed2k.nodes_dat_url": document.getElementById("set-ed2k-nodes-url").value,
      "ed2k.nodes_dat_max_age_days": document.getElementById("set-ed2k-nodes-age").value,
      "ed2k.server_list_url": document.getElementById("set-ed2k-servers-url").value,
      "alt.auto_mirrors": document.getElementById("set-alt-auto-mirrors").checked
        ? "true"
        : "false",
      "find.enabled": document.getElementById("set-find-enabled").checked ? "true" : "false",
      "find.slow_min_mbps": document.getElementById("set-find-slow-mbps").value,
      "find.slow_window_s": document.getElementById("set-find-slow-window").value,
      "ed2k.upload_enabled": document.getElementById("set-ed2k-upload-enabled").checked
        ? "true"
        : "false",
      "ed2k.listen_port": document.getElementById("set-ed2k-listen-port").value,
      "ed2k.upload_slots": document.getElementById("set-ed2k-upload-slots").value,
      "ed2k.upload_max_waiting": document.getElementById("set-ed2k-upload-max-waiting").value,
      "ed2k.upload_rate_kbps": document.getElementById("set-ed2k-upload-rate").value,
      "bt.listen_port": document.getElementById("set-bt-listen-port").value,
      "bt.seed_minutes": document.getElementById("set-bt-seed-minutes").value,
      "bt.extra_trackers": document.getElementById("set-bt-extra-trackers").value,
      "conn.retry_backoff_ms": String(backoffMsFromSeconds(document.getElementById("set-retry-backoff").value) ?? ""),
      "sched.start_cron": collectSchedCron(),
      "sched.after_done": document.getElementById("set-after-done").value,
      "sched.after_done_force": document.getElementById("set-after-done-force").checked
        ? "true"
        : "false",
      "speed.global_limit_kbps": document.getElementById("set-speed-limit").value,
      "proxy.mode": proxyModeValue(),
      "proxy.scheme": document.getElementById("set-proxy-scheme").value,
      "proxy.host": document.getElementById("set-proxy-host").value,
      "proxy.port": document.getElementById("set-proxy-port").value,
      "proxy.user": document.getElementById("set-proxy-user").value,
      "browser.enabled": document.getElementById("set-browser-enabled").checked ? "true" : "false",
      "browser.click_takeover": document.getElementById("set-click-takeover").checked ? "true" : "false",
      "browser.allowed_ext_ids": JSON.stringify(allowedExtIds),
      "update.channel": "stable",
      "update.auto_check": document.getElementById("set-update-auto").checked ? "true" : "false",
    };
  }

  function originalSettingsAsStrings() {
    const out = {};
    for (const [k, v] of Object.entries(settingsCache)) {
      if (k === "proxy.has_password") continue;
      if (typeof v === "boolean") out[k] = v ? "true" : "false";
      else out[k] = settingStr(v);
    }
    if (out["proxy.mode"] === "system") out["proxy.mode"] = "follow-system";
    delete out["app.version"];
    delete out["update.last_check_at"];
    delete out["update.manifest_base_url"];
    if (!out["update.channel"]) out["update.channel"] = "stable";
    if (out["update.auto_check"] == null || out["update.auto_check"] === "") {
      out["update.auto_check"] = "true";
    }
    return out;
  }

  function passActionFromForm() {
    if (passCleared) return "clear";
    const typed = document.getElementById("set-proxy-pass").value;
    if (typed.length > 0) return typed;
    return "omit";
  }

  const setMask = document.getElementById("set-mask");
  async function openSettings(page) {
    clearSettingErrors();
    const formErr = document.getElementById("set-form-error");
    formErr.textContent = "";
    formErr.classList.add("hidden");
    const okBtn = document.getElementById("set-ok");
    const wasOpen = !setMask.classList.contains("hidden");
    // 首次打开时给语言拍快照：取消/关闭要回到这里的值。
    if (!wasOpen) langPreviewBase = I18n.language();
    if (page) showSettingPage(page);
    openLayer(setMask, document.getElementById("set-start-win") || okBtn);
    try {
      await fillSettingsForm();
      okBtn.disabled = settingsLoadFailed;
      if (settingsLoadFailed) {
        formErr.textContent = SETTINGS_LOAD_FAIL;
        formErr.classList.remove("hidden");
      }
    } catch { /* keep settings open */ }
    // 每次新打开设置界面自动检查一次更新；已在设置里切换页面不重复请求。
    if (!wasOpen) void requestUpdateCheck();
  }
  function closeSettings() {
    // 取消/关闭时撤销语言预览（确定路径会先把快照清空）。
    if (langPreviewBase && I18n.language() !== langPreviewBase) {
      I18n.setLanguage(langPreviewBase);
    }
    langPreviewBase = null;
    closeLayer(setMask);
  }

  function settingsHasUnsavedChanges() {
    if (settingsLoadFailed || setMask.classList.contains("hidden")) return false;
    try {
      const edited = collectSettingsForm();
      const orig = originalSettingsAsStrings();
      return settingsDiff(orig, edited, passActionFromForm()).length > 0;
    } catch {
      return false;
    }
  }

  function requestCloseSettings() {
    if (settingsHasUnsavedChanges() && !window.confirm(DISCARD_SETTINGS)) return false;
    closeSettings();
    return true;
  }

  function updateBrowserRestEnabled() {
    const on = document.getElementById("set-browser-enabled").checked;
    document.getElementById("browser-rest").classList.toggle("is-disabled", !on);
  }

  function renderExtIdRows() {
    const tbody = document.getElementById("ext-id-rows");
    tbody.textContent = "";
    for (const id of allowedExtIds) {
      const tr = document.createElement("tr");
      const tdId = document.createElement("td");
      tdId.textContent = id;
      const tdBtn = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "tool";
      btn.textContent = T("删除");
      btn.dataset.extId = id;
      tdBtn.appendChild(btn);
      tr.append(tdId, tdBtn);
      tbody.appendChild(tr);
    }
  }

  function addExtId() {
    const input = document.getElementById("ext-id-new");
    const id = input.value.trim();
    if (!id) return;
    if (!allowedExtIds.includes(id)) allowedExtIds.push(id);
    input.value = "";
    renderExtIdRows();
  }

  function removeExtId(id) {
    if (allowedExtIds.length === 1 && allowedExtIds[0] === id) {
      if (!window.confirm(LAST_EXT_CONFIRM)) return;
    }
    allowedExtIds = allowedExtIds.filter((x) => x !== id);
    renderExtIdRows();
  }

  async function refreshHostAndEngineStatus() {
    const engineEl = document.getElementById("engine-online-label");
    const hostEl = document.getElementById("host-reg-label");
    const btn = document.getElementById("btn-host-register");
    const stub = document.getElementById("host-reg-stub");
    const ping = await send({ op: "ping" });
    engineEl.textContent = ping.ok ? T("在线") : T("离线");
    const host = await send({ op: "host_status" });
    const state = hostRegState(host);
    stub.classList.add("hidden");
    if (state === "registered") {
      hostEl.textContent = T("已注册");
      btn.classList.add("hidden");
    } else if (state === "unregistered") {
      hostEl.textContent = T("未注册");
      btn.classList.remove("hidden");
    } else {
      hostEl.textContent = T("未知");
      btn.classList.add("hidden");
      stub.textContent = HOST_STATUS_FAIL;
      stub.classList.remove("hidden");
    }
  }

  async function registerHost() {
    const resp = await send({ op: "host_register", register: true });
    const stub = document.getElementById("host-reg-stub");
    if (!resp.ok) {
      stub.textContent = HOST_STATUS_FAIL;
      stub.classList.remove("hidden");
    }
    await refreshHostAndEngineStatus();
  }

  function visibleCandidateIndexes() {
    const kind = cand.kindFilter || "";
    const q = cand.query || "";
    const out = [];
    cand.items.forEach((it, i) => {
      if (filterCandidateItems([it], kind, q).length) out.push(i);
    });
    return out;
  }

  /// 候选表格里链接列的显示宽度（字符数）。列宽固定，超过就压缩中间。
  const CAND_URL_CHARS = 72;

  /// 压缩显示（纯逻辑在 lib/polish.js，node:test 直接覆盖）。lib 缺载时退化成
  /// 简单的尾部截断，绝不因为拿不到库就渲染不出列表。
  function compressUrl(url, maxChars) {
    if (P.compressUrl) return P.compressUrl(url, maxChars);
    const s = String(url || "");
    return [...s].length <= maxChars ? s : [...s].slice(0, Math.max(0, maxChars - 1)).join("") + "…";
  }

  /// 链接的扩展名（小写、不含点）；取路径最后一段的 `.` 之后部分。
  function fileExtOfUrl(url) {
    try {
      const u = new URL(String(url || ""));
      const last = u.pathname.split("/").filter(Boolean).pop() || "";
      const dot = last.lastIndexOf(".");
      return dot > 0 ? last.slice(dot + 1).toLowerCase() : "";
    } catch {
      return "";
    }
  }

  function renderCandidates() {
    const list = document.getElementById("cand-list");
    list.textContent = "";
    const kind = cand.kindFilter || "";
    const q = cand.query || "";
    cand.items.forEach((it, i) => {
      if (!filterCandidateItems([it], kind, q).length) return;
      const tr = document.createElement("tr");
      tr.className = "cand-row";

      // 下载链接：超长时压缩中间（协议 + 主机首段 …… 末尾目录/文件名），
      // 完整地址留在 title 里，鼠标停一下就能看到。
      const urlCell = document.createElement("td");
      urlCell.className = "cand-url";
      urlCell.textContent = compressUrl(it.url, CAND_URL_CHARS);
      urlCell.title = it.url;

      // 文件格式：优先取链接扩展名；取不到时退回「链接 / 视频 / 音频」类型标签。
      const extCell = document.createElement("td");
      extCell.className = "cand-ext";
      const ext = fileExtOfUrl(it.url);
      extCell.textContent = ext || kindLabelText(it.kind);

      // 操作：勾选这一项。勾选事件由表格上的 change 监听统一处理。
      const opCell = document.createElement("td");
      opCell.className = "cand-op";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = cand.selected.has(i);
      cb.dataset.idx = String(i);
      cb.title = T("勾选后点右下角「下载选中」");
      opCell.appendChild(cb);

      tr.append(urlCell, extCell, opCell);
      list.appendChild(tr);
    });
    const n = cand.selected.size;
    const ok = document.getElementById("cand-ok");
    ok.textContent = (E.candidateOkLabel && E.candidateOkLabel(n, cand.retryFailed))
      || (cand.retryFailed ? T("重试失败的 {n} 项", { n: n }) : T("下载选中的 {n} 项", { n: n }));
    ok.disabled = n === 0;
    document.getElementById("cand-truncated").classList.toggle("hidden", !cand.truncated);
    document.getElementById("cand-expired").classList.toggle("hidden", !cand.expired);
    const empty = document.getElementById("cand-empty");
    const visible = visibleCandidateIndexes();
    if (cand.items.length === 0) {
      empty.textContent = T("页面上没有发现可下载的链接");
      empty.classList.remove("hidden");
    } else if (visible.length === 0) {
      empty.textContent = T("没有匹配的链接");
      empty.classList.remove("hidden");
    } else {
      empty.classList.add("hidden");
    }
  }

  /// 候选框已打开、又收到同来源的新命中：只追加新区，保留用户的搜索词/勾选/目录。
  function mergeClipboardCandidates(items) {
    const incoming = (Array.isArray(items) ? items : [])
      .filter((it) => it && typeof it.url === "string")
      .map((it) => ({ url: it.url.trim(), kind: it.kind || "link", filename: it.filename }));
    const fresh = (CB.newUrls || (() => []))(
      cand.items.map((it) => it.url),
      incoming.map((it) => it.url)
    );
    if (fresh.length === 0) return false;
    const byUrl = new Map(incoming.map((it) => [it.url, it]));
    const base = cand.items.length;
    fresh.forEach((url, k) => {
      const src = byUrl.get(url) || { url };
      cand.items.push({
        url,
        kind: src.kind || "link",
        filename: deriveFilename(src.filename, url),
      });
      cand.selected.add(base + k);
    });
    if (cand.fromClipboard) {
      // 关闭时上报的是"整框放弃"，所以抑制集合要跟着列表一起更新。
      cand.clipboardUrls = cand.items.map((it) => it.url);
      document.getElementById("cand-title").textContent =
        T("从剪贴板发现 {n} 个链接", { n: cand.items.length });
    }
    renderCandidates();
    showActionToast(T("新增 {n} 个链接", { n: fresh.length }));
    return true;
  }

  async function openCandidateDialog(ev) {
    const items = Array.isArray(ev.items) ? ev.items : [];
    const fromClipboard = ev.from === "clipboard";
    // 剪贴板可能在一轮里连续命中：候选框已经开着、来源也相同 → 合并新区，
    // 而不是把用户已输入的搜索词、勾选和保存目录整体清掉（一条新通知不该打断手工挑选）。
    const candMask = document.getElementById("cand-mask");
    if (candMask && !candMask.classList.contains("hidden") && fromClipboard && cand.fromClipboard) {
      mergeClipboardCandidates(items);
      return;
    }
    cand = {
      fromClipboard,
      // 剪贴板来源的这批地址：用户放弃时要上报抑制（取消后不再反复弹同一批）。
      clipboardUrls: fromClipboard ? items.map((it) => it.url) : [],
      addedAny: false,
      offerId: ev.offer_id || null,
      pageUrl: ev.page_url || "",
      title: ev.title || "",
      items: items.map((it) => ({
        url: it.url,
        kind: it.kind,
        filename: deriveFilename(it.filename, it.url),
      })),
      truncated: !!ev.truncated,
      selected: fromClipboard ? new Set(items.map((_, i) => i)) : new Set(),
      kindFilter: "",
      query: "",
      expired: false,
      retryFailed: false,
    };
    document.getElementById("cand-title").textContent = fromClipboard
      ? T("从剪贴板发现 {n} 个链接", { n: cand.items.length })
      : T("从 {src} 发现 {n} 个链接", { src: cand.title.trim() || T("未命名页面"), n: cand.items.length });
    document.getElementById("cand-page-url").textContent = cand.pageUrl;
    document.getElementById("cand-kind").value = "";
    document.getElementById("cand-search").value = "";
    await loadSettings(false);
    const raw = preferredDirToken();
    const dirEl = document.getElementById("cand-dir");
    if (raw && invoke) {
      try { dirEl.value = await invoke("expand_user_path", { path: raw }); }
      catch { dirEl.value = raw; }
    } else {
      dirEl.value = raw;
    }
    // 首次打开把焦点交给对话框容器本身，而不是搜索框：剪贴板一命中就弹框时，
    // 用户接下来的按键不应被当成「按文件名搜索」。容器带 tabindex="-1"，
    // Tab 仍从第一个可聚焦控件（搜索框）开始，关闭后焦点照旧归还。
    openLayer(document.getElementById("cand-mask"), document.getElementById("cand-dialog"));
    renderCandidates();
  }

  function closeCandidateDialog() {
    // 判定规则在 ui/lib/clipboard.js（可单测）：剪贴板来源、且这次没加过任务，才算「用户不要」。
    const pending = (CB.dismissUrls || (() => []))(cand);
    closeLayer(document.getElementById("cand-mask"));
    if (pending.length && invoke) {
      invoke("clipboard_dismissed", { urls: pending }).catch(() => {});
    }
  }

  async function downloadSelectedCandidates() {
    if (candBusy) return; // 上一批还没走完：连点会把同一批链接再建一遍任务
    const dir = document.getElementById("cand-dir").value.trim();
    const indexes = [...cand.selected].sort((a, b) => a - b);
    if (indexes.length === 0) return;
    candBusy = true;
    const okBtn = document.getElementById("cand-ok");
    if (okBtn) okBtn.disabled = true;
    try {
      let added = 0;
      let failed = 0;
      const succeeded = [];
      for (const i of indexes) {
        const it = cand.items[i];
        if (!it) continue;
        const resp = await send({
          op: "add",
          url: it.url,
          dir: dir || null,
          filename: cand.fromClipboard ? null : (it.filename || null),
          referrer: cand.pageUrl || null,
          offer_id: cand.offerId,
          source: cand.fromClipboard ? "manual" : "ext",
          speed_limit_kbps: 0,
        });
        if (isOfferExpired(resp)) {
          cand.expired = true;
          renderCandidates();
          return;
        }
        if (resp && resp.ok) {
          added += 1;
          cand.addedAny = true;
          succeeded.push(i);
        } else {
          failed += 1;
        }
      }
      if (added > 0 && failed === 0) {
        cand.retryFailed = false;
        closeCandidateDialog();
        // 剪贴板候选框关闭后不能把焦点/拖拽状态留给列表，否则会偶发进入框选模式。
        setMarqueeMode(false);
        refresh();
        return;
      }
      if (added > 0 && failed > 0) {
        cand.selected = E.uncheckSucceededCandidates
          ? E.uncheckSucceededCandidates(cand.selected, succeeded)
          : (() => {
            const next = new Set(cand.selected);
            for (const i of succeeded) next.delete(i);
            return next;
          })();
        cand.retryFailed = true;
        showActionToast(T("已添加 {ok} 项，{fail} 项添加失败", { ok: added, fail: failed }));
        refresh();
        renderCandidates();
        return;
      }
      showActionToast(T("添加失败，请重试"));
    } finally {
      candBusy = false;
      // 重算「下载选中的 N 项」与按钮可用性（各分支的 return 都会经过这里）。
      renderCandidates();
    }
  }

  function renderUpdatePage() {
    const view = U.updateStatusView(updateState);
    const page = document.getElementById("update-page");
    if (page) page.classList.toggle("is-locked", !!view.pageLocked);
    const verEl = document.getElementById("update-current-version");
    if (verEl) verEl.textContent = view.currentVersionText;
    const lastEl = document.getElementById("update-last-check");
    if (lastEl) lastEl.textContent = view.lastCheckText;
    const checkBtn = document.getElementById("btn-update-check");
    if (checkBtn) {
      checkBtn.textContent = view.checkLabel;
      checkBtn.disabled = !!view.checkDisabled || !!view.pageLocked;
    }
    const status = document.getElementById("update-status");
    if (status) status.classList.toggle("hidden", !view.showStatus);
    const title = document.getElementById("update-status-title");
    if (title) {
      // 状态标题已取消（避免与按钮文案重复提醒），空串时同步隐藏，不留空白行。
      title.textContent = view.title || "";
      title.classList.toggle("hidden", !view.title);
    }
    const notes = document.getElementById("update-status-notes");
    if (notes) {
      notes.textContent = view.notes || "";
      notes.classList.toggle("hidden", !view.notesVisible);
    }
    const wrap = document.getElementById("update-progress-wrap");
    if (wrap) wrap.classList.toggle("hidden", !view.progressVisible);
    const bar = document.getElementById("update-progress-bar");
    if (bar) bar.style.width = (view.progressPercent || 0) + "%";
    const applyBtn = document.getElementById("btn-update-apply");
    if (applyBtn) {
      applyBtn.textContent = view.applyLabel;
      applyBtn.disabled = !!view.applyDisabled || !!view.pageLocked;
      applyBtn.classList.toggle("hidden", !(view.applyVisible || view.progressVisible));
    }
    const retryBtn = document.getElementById("btn-update-retry");
    if (retryBtn) retryBtn.classList.toggle("hidden", !view.retryVisible);
    const dot = document.getElementById("update-nav-dot");
    if (dot) dot.classList.toggle("hidden", !view.redDot);
    document.querySelectorAll("#set-update-auto").forEach((el) => {
      el.disabled = !!view.pageLocked;
    });
  }

  function handleUpdateEvent(ev) {
    updateState = U.applyUpdateEvent(updateState, ev);
    const resolved = U.resolveAppVersion(ev, settingsCache, engineVersion);
    if (resolved) updateState.currentVersion = resolved;
    if (ev && ev.phase === "available" && ev.version) {
      const v = String(ev.version);
      if (v !== lastUpdateNotice) {
        lastUpdateNotice = v;
        showActionToast(T("发现新版本 ") + v + T("，可在设置中更新"));
      }
    }
    renderUpdatePage();
  }

  async function requestUpdateCheck() {
    updateState.userCheck = true;
    updateState = U.applyCheckResponse(updateState, { ok: true });
    renderUpdatePage();
    const resp = await send({ op: U.OP_CHECK });
    if (resp && resp.version) engineVersion = String(resp.version);
    if (!resp || !resp.ok) {
      updateState = U.applyCheckResponse(updateState, resp || { ok: false });
      renderUpdatePage();
      return;
    }
    await loadSettings(true);
    updateState.lastCheckAt = settingStr(settingsCache["update.last_check_at"]) || updateState.lastCheckAt;
    if (!updateState.lastCheckAt) updateState.lastCheckAt = String(Date.now());
    renderUpdatePage();
  }

  async function requestUpdateApply() {
    updateState = U.beginDownload(updateState);
    renderUpdatePage();
    const resp = await send({ op: U.OP_APPLY });
    if (!resp || !resp.ok) {
      updateState.phase = "error";
      updateState.code = String((resp && resp.code) || "");
      renderUpdatePage();
    }
  }

  async function applySettings() {
    clearSettingErrors();
    if (!validateConnForm()) return;
    const edited = collectSettingsForm();
    if (edited["conn.retry_backoff_ms"] === "") {
      showSettingError("conn.retry_backoff_ms", fieldRangeText("conn.retry_backoff_ms"));
      return;
    }
    // 先用引擎下发的设置声明表在本地拦一遍：范围/枚举/格式都来自同一份
    // schema，UI 不再维护第二套硬编码区间；引擎侧仍会再校验一次。
    const schema = await loadSettingsSchema();
    for (const [key, raw] of Object.entries(edited)) {
      if (key === "proxy.pass") continue;
      // lib 缺载时降级为"只靠引擎校验"，绝不因此拦住整次保存
      const code = SF.validateWithSchema ? SF.validateWithSchema(schema, key, raw) : null;
      if (code) {
        showSettingError(key, settingsSetUserError(key, code));
        showSettingPage((E.settingsPageForKey && E.settingsPageForKey(key)) || "general");
        return;
      }
      edited[key] = SF.canonicalize ? SF.canonicalize(key, raw) : raw;
    }
    const orig = originalSettingsAsStrings();
    const diffs = settingsDiff(orig, edited, passActionFromForm());
    let failed = false;
    let firstErrKey = "";
    for (const change of diffs) {
      const resp = await send({ op: "settings_set", key: change.key, value: change.value });
      if (!resp.ok) {
        failed = true;
        if (!firstErrKey) firstErrKey = change.key;
        const el = document.querySelector(`[data-err="${change.key}"]`);
        if (el) showSettingError(change.key, settingsSetUserError(change.key, resp));
      }
    }
    if (failed) {
      const formErr = document.getElementById("set-form-error");
      formErr.textContent = SETTINGS_SAVE_FAILED;
      formErr.classList.remove("hidden");
      if (firstErrKey) {
        const page = (E.settingsPageForKey && E.settingsPageForKey(firstErrKey)) || "general";
        showSettingPage(page);
      }
      return;
    }
    await loadSettings(true);
    // 开关/端口改完立刻反映到状态行（引擎每 2 秒重读设置，这里只是顺手刷新）。
    void refreshEd2kUploadStatus();
    // 语言预览在这一刻才转正；之前只影响界面，不写持久化。
    try {
      localStorage.setItem("aidm.lang", I18n.language());
    } catch (e) {
      /* 存储不可用只影响下次启动 */
    }
    langPreviewBase = null;
    closeSettings();
    updateLimitPills();
    refreshSchedStatus();
  }

  function isTypingTarget(el) {
    if (!el) return false;
    const tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  function moveSelection(delta, extend) {
    const rows = filteredTasks();
    if (rows.length === 0) return;
    let idx = rows.findIndex((t) => t.id === anchorId);
    if (idx < 0) idx = delta > 0 ? -1 : 0;
    const next = Math.max(0, Math.min(rows.length - 1, idx + delta));
    const id = rows[next].id;
    if (extend && anchorId != null) selectRange(anchorId, id, rows);
    else selectOnly(id);
    render();
    const scroll = document.getElementById("list-scroll");
    const top = next * ROW_H;
    if (top < scroll.scrollTop) scroll.scrollTop = top;
    else if (top + ROW_H > scroll.scrollTop + scroll.clientHeight) {
      scroll.scrollTop = top + ROW_H - scroll.clientHeight;
    }
  }

  // ---- wire ----
  applyColumnWidths(true);

  document.getElementById("btn-new").addEventListener("click", openDialog);
  document.getElementById("empty-new").addEventListener("click", openDialog);
  document.getElementById("dlg-cancel").addEventListener("click", closeDialog);
  document.getElementById("dlg-ok").addEventListener("click", () => submitNew("now"));
  document.getElementById("dlg-queue").addEventListener("click", () => submitNew("queue"));
  document.getElementById("dlg-browse").addEventListener("click", () => browseInto("dlg-dir"));
  armBackdropClose(mask, closeDialog);
  // 输入 / 粘贴链接后立刻解析文件名（input 同时覆盖键盘输入与粘贴）
  document.getElementById("dlg-url").addEventListener("input", syncDialogFilename);
  for (const id of ["dlg-url", "dlg-dir", "dlg-name", "dlg-referer"]) {
    document.getElementById(id).addEventListener("keydown", (e) => {
      if (e.key === "Enter") submitNew("now");
    });
  }

  document.getElementById("del-cancel").addEventListener("click", closeDeleteDialog);
  document.getElementById("del-ok").addEventListener("click", async () => {
    const ids = pendingDeleteIds.slice();
    const files = document.getElementById("del-files").checked;
    const bulk = pendingDeleteBulk;
    closeDeleteDialog();
    await doDelete(ids, files);
    // 批量删除完成后退出框选模式（单条删除保持当前模式）。
    if (bulk) setMarqueeMode(false);
  });
  armBackdropClose(delMask, closeDeleteDialog);

  document.getElementById("btn-settings").addEventListener("click", () => openSettings());
  document.getElementById("set-cancel").addEventListener("click", requestCloseSettings);
  document.getElementById("set-ok").addEventListener("click", applySettings);
  armBackdropClose(setMask, requestCloseSettings);
  document.querySelectorAll(".settings-nav li").forEach((li) => {
    li.addEventListener("click", () => {
      showSettingPage(li.dataset.page);
      if (li.dataset.page === "browser") refreshHostAndEngineStatus();
    });
  });
  document.querySelectorAll('input[name="proxy-mode"]').forEach((r) => {
    r.addEventListener("change", updateProxyBoxes);
  });
  document.getElementById("set-browse-dir").addEventListener("click", () => browseInto("set-default-dir"));
  document.getElementById("set-open-meta").addEventListener("click", async () => {
    if (!invoke) {
      showActionToast(OPEN_DIR_FAIL);
      return;
    }
    const el = document.getElementById("set-meta-dir");
    const raw = el.dataset.raw || el.value;
    if (!raw) return;
    try {
      const path = await invoke("expand_user_path", { path: raw });
      await invoke("open_directory", { path });
    } catch {
      showActionToast(OPEN_DIR_FAIL);
    }
  });
  document.getElementById("set-clear-pass").addEventListener("click", () => {
    passCleared = true;
    document.getElementById("set-proxy-pass").value = "";
    document.getElementById("set-proxy-pass").placeholder = T("将清除已保存的密码");
  });
  document.getElementById("set-window-on").addEventListener("change", updateWindowBoxes);
  document.getElementById("set-quota-on").addEventListener("change", updateQuotaBoxes);
  document.getElementById("set-browser-enabled").addEventListener("change", updateBrowserRestEnabled);
  document.getElementById("ext-id-add").addEventListener("click", addExtId);
  document.getElementById("ext-id-new").addEventListener("keydown", (e) => {
    if (e.key === "Enter") addExtId();
  });
  document.getElementById("ext-id-rows").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-ext-id]");
    if (btn) removeExtId(btn.getAttribute("data-ext-id"));
  });
  document.getElementById("btn-update-apply").addEventListener("click", () => {
    requestUpdateApply();
  });
  document.getElementById("btn-update-retry").addEventListener("click", () => {
    requestUpdateApply();
  });
  document.getElementById("btn-host-register").addEventListener("click", registerHost);
  document.getElementById("btn-ed2k-nodes-refresh").addEventListener("click", () => {
    void refreshEd2kSource("ed2k_nodes_refresh", "nodes");
  });
  document.getElementById("btn-ed2k-servers-refresh").addEventListener("click", () => {
    void refreshEd2kSource("ed2k_servers_refresh", "servers");
  });
  document.getElementById("btn-ext-help").addEventListener("click", async () => {
    if (!invoke) {
      showActionToast(OPEN_INSTALL_FAIL);
      return;
    }
    try { await invoke("open_extension_install_doc"); }
    catch { showActionToast(OPEN_INSTALL_FAIL); }
  });
  // 安装包内置的解压版扩展就在 <安装目录>/extension；直接打开它，
  // 用户在 Chrome/Edge「加载已解压的扩展程序」里选这个文件夹即可。
  document.getElementById("btn-ext-dir").addEventListener("click", async () => {
    if (!invoke) {
      showActionToast(OPEN_INSTALL_FAIL);
      return;
    }
    try { await invoke("open_extension_dir"); }
    catch { showActionToast(OPEN_INSTALL_FAIL); }
  });
  document.getElementById("cand-cancel").addEventListener("click", closeCandidateDialog);
  document.getElementById("cand-ok").addEventListener("click", downloadSelectedCandidates);
  document.getElementById("cand-browse").addEventListener("click", () => browseInto("cand-dir"));
  armBackdropClose(document.getElementById("cand-mask"), closeCandidateDialog);
  document.getElementById("cand-select-all").addEventListener("click", () => {
    for (const i of visibleCandidateIndexes()) cand.selected.add(i);
    renderCandidates();
  });
  document.getElementById("cand-invert").addEventListener("click", () => {
    for (const i of visibleCandidateIndexes()) {
      if (cand.selected.has(i)) cand.selected.delete(i);
      else cand.selected.add(i);
    }
    renderCandidates();
  });
  document.getElementById("cand-kind").addEventListener("change", () => {
    cand.kindFilter = document.getElementById("cand-kind").value;
    renderCandidates();
  });
  document.getElementById("cand-search").addEventListener("input", () => {
    cand.query = document.getElementById("cand-search").value;
    renderCandidates();
  });
  document.getElementById("cand-list").addEventListener("change", (e) => {
    const cb = e.target.closest("input[type=checkbox]");
    if (!cb) return;
    const i = Number(cb.dataset.idx);
    if (cb.checked) cand.selected.add(i);
    else cand.selected.delete(i);
    renderCandidates();
  });
  document.getElementById("cand-list").addEventListener("click", (e) => {
    // 表格行里没有 <label> 包着复选框，点行的任意位置都应该能勾选——把旧列表
    // 那种"点哪都切换"的手感补回来。点复选框本身时交给上面的 change。
    if (e.target.closest("input[type=checkbox]")) return;
    const tr = e.target.closest("tr.cand-row");
    if (!tr) return;
    const cb = tr.querySelector("input[type=checkbox]");
    if (!cb) return;
    cb.checked = !cb.checked;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
  });

  document.getElementById("st-sched").addEventListener("click", () => openSettings("sched"));
  document.getElementById("set-sched-on").addEventListener("change", updateSchedFormUi);
  document.querySelectorAll('input[name="sched-mode"]').forEach((r) => {
    r.addEventListener("change", updateSchedFormUi);
  });
  document.getElementById("set-sched-time").addEventListener("input", updateSchedFormUi);
  document.getElementById("set-sched-cron").addEventListener("input", updateSchedFormUi);
  document.getElementById("btn-start").addEventListener("click", startSelected);
  document.getElementById("btn-pause").addEventListener("click", pauseSelected);
  document.getElementById("btn-delete").addEventListener("click", () => requestDelete([...selectedIds]));

  document.getElementById("list-window").addEventListener("click", onRowClick);
  document.getElementById("list-window").addEventListener("dblclick", onRowDblClick);
  // 关于页的 GitHub 入口：走 Tauri 的 open_url（WebView 不保证处理 <a target=_blank>）。
  // 命令不可用（浏览器直开/无 Tauri）时退化成复制链接，至少不让点击石沉大海。
  document.getElementById("about-github")?.addEventListener("click", async () => {
    const btn = document.getElementById("about-github");
    const url = btn?.dataset.repo || "";
    if (!url) return;
    try {
      if (invoke) await invoke("open_url", { url });
      else window.open(url, "_blank", "noopener");
    } catch (e) {
      try {
        await navigator.clipboard.writeText(url);
        showActionToast(T("无法打开浏览器，已复制仓库地址"));
      } catch {
        showActionToast(T("无法打开浏览器"));
      }
    }
  });

  document.getElementById("list-window").addEventListener("contextmenu", onRowContext);

  // ---- 框选（多选）模式：拖框选择 + 复选框 + 批量右键菜单 ----
  const listScroll = document.getElementById("list-scroll");
  listScroll.addEventListener("contextmenu", (e) => {
    if (e.target.closest(".data-row")) return; // 行内右键交给 onRowContext
    // 空白处右键默认弹批量菜单。但**列表为空时不该有任何右键交互**：
    // 一个任务都没有，"全部开始/全部暂停/全部删除"全是空操作，弹出来只会让人困惑。
    e.preventDefault();
    closeRowContextMenu();
    const list = Array.isArray(tasks) ? tasks : [];
    if (list.length === 0) return;
    openBulkMenu(e.clientX, e.clientY);
  });
  // 列表区域（表头 / 空状态 / 行间空白）兜底吃掉原生右键菜单。
  //
  // 上面两个 handler 只覆盖了 `.data-row` 与 `.list-scroll` 内部：列表为空时
  // DOM 里根本没有 `.list-scroll`（它被 hidden），空状态提示在它外面，右键
  // 于是会穿透到 WebView 的原生菜单。这里按区域统一拦掉。
  // 重命名输入框例外——那里需要"复制 / 粘贴 / 全选"。
  document.getElementById("list-root").addEventListener("contextmenu", (e) => {
    if (e.target.closest(".rename-input")) return;
    e.preventDefault();
  });

  listScroll.addEventListener("mousedown", (e) => {
    if (e.button !== 0 || e.buttons !== 1) return;
    if (e.target.closest(".rename-input, .rename-wrap, button, a, select")) return;
    const row = e.target.closest(".data-row");
    // 记录按下的行：mouseup 时据此自行完成"点击反转"，
    // 不依赖 click —— 列表每 600ms 轮询重绘，click 的目标节点可能已失效（偶发失效的根因）。
    marqueeDrag = {
      sx: e.clientX,
      sy: e.clientY,
      at: Date.now(),
      rowId: row ? Number(row.dataset.id) : NaN,
      active: false,
      deselect: !!(e.altKey || e.ctrlKey || e.metaKey),
      base: new Set(selectedIds),
    };
  });
  // 复选框由脚本接管：阻止浏览器原生切换，避免与状态同步竞争
  listScroll.addEventListener("click", (e) => {
    const pick = e.target.closest(".row-pick");
    if (!pick) return;
    e.preventDefault(); // 始终阻止浏览器原生切换复选框
    if (Date.now() - marqueeDragEndAt < CLICK_AFTER_DRAG_MS) return; // mouseup 已处理
    const row = pick.closest(".data-row");
    const id = Number(row && row.dataset.id);
    if (Number.isFinite(id)) toggleRowSelection(id);
  });
  window.addEventListener("mousemove", (e) => {
    if (!marqueeDrag) return;
    // mouseup 可能丢在窗口外（Alt+Tab、浏览器右键菜单）：按键已经松开就取消，
    // 否则之后移回窗口会被当成框选拖拽，把列表误切到框选模式。
    if ((e.buttons & 1) === 0) {
      cancelMarqueeDrag();
      return;
    }
    // 候选只在左键按住后的短暂窗口内有效，并要求窗口仍有焦点：
    // 从 AIDM 切到浏览器再回来时，陈旧的按下状态不得把列表带进框选模式。
    if (!marqueeDrag.active) {
      if (Date.now() - marqueeDrag.at > 1000 || !document.hasFocus()) {
        cancelMarqueeDrag();
        return;
      }
    }
    if (topLayer()) {
      cancelMarqueeDrag();
      return;
    }
    if (!marqueeDrag.active) {
      // 位移阈值：小于 10px 视为点击（在 mouseup 里做勾选反转），
      // 超过才算真正的框选拖拽，避免手抖把点击误判成拖拽。
      if (Math.abs(e.clientX - marqueeDrag.sx) < 10 && Math.abs(e.clientY - marqueeDrag.sy) < 10) return;
      marqueeDrag.active = true;
      setMarqueeMode(true);
      document.body.classList.add("marquee-drag");
    }
    marqueeDrag.lx = e.clientX;
    marqueeDrag.ly = e.clientY;
    const box = document.getElementById("marquee-box");
    const rect = listScroll.getBoundingClientRect();
    if (box) {
      const x0 = Math.max(rect.left, Math.min(marqueeDrag.sx, e.clientX));
      const x1 = Math.min(rect.right, Math.max(marqueeDrag.sx, e.clientX));
      const y0 = Math.max(rect.top, Math.min(marqueeDrag.sy, e.clientY));
      const y1 = Math.min(rect.bottom, Math.max(marqueeDrag.sy, e.clientY));
      box.style.left = (x0 - rect.left) + "px";
      box.style.top = (y0 - rect.top) + "px";
      box.style.width = Math.max(0, x1 - x0) + "px";
      box.style.height = Math.max(0, y1 - y0) + "px";
      box.classList.remove("hidden");
    }
    // 默认把框内行设为选中；按住 Alt/Ctrl 时改为取消选中
    const next = new Set(marqueeDrag.base);
    const hit = marqueeHitIds(marqueeDrag.sy, e.clientY);
    for (const id of hit) {
      if (marqueeDrag.deselect) next.delete(id);
      else next.add(id);
    }
    let changed = next.size !== selectedIds.size;
    if (!changed) {
      for (const id of next) {
        if (!selectedIds.has(id)) {
          changed = true;
          break;
        }
      }
    }
    if (changed) {
      const prev = selectedIds;
      selectedIds = next;
      if (hit.length) anchorId = hit[hit.length - 1];
      // 原地同步差异：整表重绘会让选中态每帧重建，出现快速闪烁
      for (const id of prev) if (!next.has(id)) syncRowSelectionDom(id, false);
      for (const id of next) if (!prev.has(id)) syncRowSelectionDom(id, true);
      updateToolbar();
    }
  });
  window.addEventListener("mouseup", () => {
    if (!marqueeDrag) return;
    const drag = marqueeDrag;
    marqueeDrag = null;
    document.body.classList.remove("marquee-drag");
    const box = document.getElementById("marquee-box");
    if (box) box.classList.add("hidden");
    if (!drag.active) {
      // 纯点击（鼠标没有任何位移）：由 mouseup 直接翻转，不依赖 click 事件
      if (marqueeMode && Number.isFinite(drag.rowId)) {
        toggleRowSelection(drag.rowId);
        marqueeDragEndAt = Date.now(); // 吞掉随后可能派发的 click，避免二次反转
      }
      return;
    }
    // 真拖拽：保留拖动过程中已原地同步好的框选结果。
    // 这里不重算框内行数或回滚 base —— 用"覆盖行数"做启发式判断，
    // 重算结果偏小就会在松手瞬间把已有选中全部还原（表现为"松开就复位"）。
    updateToolbar();
    marqueeDragEndAt = Date.now(); // 忽略随之而来的 click，避免二次翻转
  });
  // 右键、窗口失焦、切到后台都取消未完成的拖动：框选只能由左键拖拽进入。
  document.addEventListener("contextmenu", cancelMarqueeDrag, true);
  window.addEventListener("blur", () => {
    cancelMarqueeDrag();
    // 切到浏览器（例如右键建任务）就退出框选：回来时不应还停在框选态。
    if (marqueeMode) setMarqueeMode(false);
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) return;
    cancelMarqueeDrag();
    if (marqueeMode) setMarqueeMode(false);
  });
  // 点击其它位置只收起批量菜单（退出框选模式改为点击列表空白区域）
  document.addEventListener("mousedown", (e) => {
    if (e.target.closest("#bulk-ctx-menu")) return;
    closeBulkMenu();
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    cancelMarqueeDrag();
    if (marqueeMode) setMarqueeMode(false);
  }, true);
  if (bulkMenu) {
    bulkMenu.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-bulk]");
      if (!btn) return;
      const act = btn.getAttribute("data-bulk");
      closeBulkMenu();
      if (act === "start") bulkStart();
      else if (act === "pause") bulkPause();
      // 与顶部删除按钮走同一条路径：同一个确认对话框、同一个批量 IPC、同一份提示。
      else if (act === "delete") requestDelete([...selectedIds]);
      else if (act === "refresh") {
        // 手动刷新列表后，按同一套规则重新检测已完成任务的文件是否还在。
        void Promise.resolve(refresh()).finally(() => {
          void checkMissingFiles();
        });
      }
    });
  }
  document.getElementById("list-scroll").addEventListener("click", (e) => {
    if (e.target.closest(".data-row, .rename-input, .rename-wrap")) return;
    if (Date.now() - marqueeDragEndAt < CLICK_AFTER_DRAG_MS) return;
    if (marqueeMode) {
      // 点击列表空白区域：退出框选模式，并清空勾选（不残留任何选中行）
      selectedIds = new Set();
      anchorId = null;
      setMarqueeMode(false);
      return;
    }
    if (isRenaming()) return;
    if (propsVisible) {
      showPropsPanel(false);
      render();
    }
  });
  document.getElementById("list-scroll").addEventListener("scroll", () => {
    if (tasks.length > 0) renderListWindow();
  });
  document.getElementById("props-save-row").addEventListener("click", async () => {
    const task = primarySelected();
    if (!task) return;
    // 已完成：点「保存位置」直接开文件（文件不在就走缺失处理）；其余状态开所在目录
    if (task.state === "done") await openTaskFile(task);
    else await openDirs([task]);
  });
  // 下载链接：点一下整行就复制，不再单独放按钮。
  document.getElementById("props-url").addEventListener("click", async (e) => {
    e.stopPropagation();
    const task = primarySelected();
    if (!task || !task.url) return;
    await copyText(task.url);
    toast(T("已复制下载链接"));
  });
  document.getElementById("props-events-refresh").addEventListener("click", (e) => {
    e.stopPropagation();
    const task = primarySelected();
    if (task) void loadPropsEvents(task, { reset: true });
  });
  // 删除该任务的全部下载日志（不可恢复，先确认）。
  document.getElementById("props-events-clear").addEventListener("click", async (e) => {
    e.stopPropagation();
    const task = primarySelected();
    if (!task) return;
    const status = document.getElementById("props-events-status");
    if (!window.confirm(T("删除「") + (task.name || T("该任务")) + T("」的全部下载日志？此操作不可恢复。"))) {
      return;
    }
    const resp = await send({ op: "task_events_clear", id: task.id });
    if (!resp || !resp.ok) {
      if (status) {
        status.textContent =
          T("删除失败：") + ((resp && (resp.code || resp.error)) || T("未知错误"));
      }
      return;
    }
    const n = resp.count != null ? Number(resp.count) : 0;
    propsEventsCache = [];
    propsEventsTotal = 0;
    propsEventsExhausted = true;
    propsEventsRenderKey = "";
    propsEventsAt = Date.now();
    const count = document.getElementById("props-events-count");
    const list = document.getElementById("props-events");
    if (count) count.textContent = "0";
    if (list) renderEventsRows(list);
    if (status) status.textContent = T("已删除 ") + n + T(" 条日志");
  });
  // 筛选：灰=全部日志，红=只看异常。
  document.getElementById("props-events-filter").addEventListener("click", (e) => {
    e.stopPropagation();
    const task = primarySelected();
    if (!task) return;
    propsEventsFilter = propsEventsFilter === "error" ? "all" : "error";
    syncEventsFilterUi();
    void loadPropsEvents(task, { reset: true });
  });
  // 滚到底自动加载下一页（每页 50，不设上限，直到取完）。
  document.getElementById("props-events").addEventListener("scroll", (e) => {
    const el = e.currentTarget;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 24) {
      const task = primarySelected();
      if (task) void loadPropsEvents(task, { more: true });
    }
  });
  syncEventsFilterUi();
  // 复制日志：把当前面板里的日志行拼成文本直接写剪贴板（不再打包 zip）。
  document.getElementById("props-events-copy").addEventListener("click", async (e) => {
    e.stopPropagation();
    const task = primarySelected();
    if (!task) return;
    const status = document.getElementById("props-events-status");
    await loadPropsEvents(task, { reset: true });
    const events = propsEventsCache.slice();
    if (!events.length) {
      if (status) status.textContent = T("暂无日志可复制");
      return;
    }
    const text = events
      .map((ev) => "[" + eventTime(ev.ts) + "] " + eventLine(ev))
      .join("\n");
    await copyText(text);
    if (status) status.textContent = T("已复制 ") + events.length + T(" 条日志");
  });
  document.getElementById("props-events-box").addEventListener("toggle", (e) => {
    const task = primarySelected();
    if (e.target.open && task) void loadPropsEvents(task, { reset: true });
  });
  document.getElementById("rename-ext-cancel").addEventListener("click", cancelRenameExt);
  document.getElementById("rename-ext-ok").addEventListener("click", confirmRenameExt);
  armBackdropClose(document.getElementById("rename-ext-mask"), cancelRenameExt);
  // 点击窗口内其它区域：自动取消文件名编辑（Enter 仍为提交，Esc 同为取消）
  document.addEventListener("mousedown", (e) => {
    if (!isRenaming()) return;
    if (e.target.closest(".rename-input, .rename-wrap, #rename-ext-mask, #rename-ext-cancel, #rename-ext-ok")) return;
    cancelRename();
  });
  // 点「任务属性」面板以外的区域就收起。行与右键菜单各自决定（行会按单选/多选重开或收起，
  // 菜单项「属性」要能打开），所以排除它们；用 capture 保证菜单项打开后不被随后的冒泡关掉。
  document.addEventListener("click", (e) => {
    if (!propsVisible) return;
    if (e.target.closest("#task-props, .data-row, #row-ctx-menu")) return;
    showPropsPanel(false);
  }, true);

  window.addEventListener("resize", () => {
    applyColumnWidths(true);
    if (tasks.length > 0) renderListWindow();
  });

  // 窗口重新获得焦点 / 从后台切回前台时，检查已完成任务的文件是否还在。
  // 250ms 防抖：focus 与 visibilitychange 连续到达时只查一次。
  let missingFocusTimer = null;
  function scheduleMissingCheck() {
    clearTimeout(missingFocusTimer);
    missingFocusTimer = setTimeout(() => {
      missingFocusTimer = null;
      void checkMissingFiles();
    }, 250);
  }
  window.addEventListener("focus", scheduleMissingCheck);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") scheduleMissingCheck();
  });

  ctxMenu.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.getAttribute("data-action");
    const target = tasks.find((t) => t.id === ctxTaskId) || primarySelected();
    closeRowContextMenu();
    if (action === "props") {
      if (target) selectOnly(target.id);
      showPropsPanel(true);
      render();
    } else if (action === "start") {
      if (target) await startTasks([target]);
    } else if (action === "pause") {
      if (target) await pauseTasks([target]);
    } else if (action === "delete") {
      // 框选状态：右键删的是整个勾选集合（批量菜单的「全部删除」也走这条语义）。
      // 非框选状态：右键是单任务上下文，只删右键点中的那一条，与当前选中集合无关。
      // 之前无条件用 `[...selectedIds]`，导致「没选中就删不掉」「右键 A 却删了选中的 B」。
      if (marqueeMode) await requestDelete([...selectedIds]);
      else if (target) await requestDelete([target.id]);
    } else if (action === "copy") await copyUrls(selectedList());
    else if (action === "open-file") await openTaskFile(target);
    else if (action === "open-dir") await openDirs(target ? [target] : []);
    else if (action === "http-source") await switchEd2kToHttp(target);
  });

  async function switchEd2kToHttp(task) {
    if (!task) return;
    let list = [];
    try {
      const resp = await send({ op: "ed2k_http_sources", id: task.id });
      if (resp && resp.ok && Array.isArray(resp.http_sources)) list = resp.http_sources;
    } catch {
      list = [];
    }
    const lines = list.map((c, i) => {
      const label = c.label || c.provider || "HTTP";
      const size = c.size ? " · " + fmtBytes(c.size) : "";
      return (i + 1) + ". " + label + size + "\n   " + c.url;
    }).join("\n");
    const hint = list.length
      ? T("找到 {n} 个 HTTP 候选：\n", { n: list.length }) + lines + "\n\n"
      : T("archive.org 没有找到同名同大小的候选。\n\n");
    const input = window.prompt(
      hint + T("输入 HTTP/HTTPS 地址（切换会清空当前 eD2K 进度，从 0 重新下载，完成后按 eD2k 哈希校验）："),
      list.length && list[0].url ? list[0].url : ""
    );
    if (!input || !input.trim()) return;
    if (!window.confirm(T("切换会清空当前 eD2K 进度并从 HTTP 源重新下载。确定继续？"))) return;
    const resp = await send({ op: "ed2k_switch_http", id: task.id, url: input.trim() });
    if (!resp || !resp.ok) showActionToast(OP_FAIL);
    refresh();
  }

  async function handleFailAction(a, task) {
    if (!task) return;
    if (a === "retry") {
      const resp = await send({ op: "resume", id: task.id });
      if (!resp || !resp.ok) showActionToast(OP_FAIL);
      refresh();
    } else if (a === "redownload") {
      const resp = await send({ op: "restart", id: task.id });
      if (!resp || !resp.ok) showActionToast(OP_FAIL);
      refresh();
    } else if (a === "change-dir") {
      if (!invoke) return;
      let dir = null;
      try { dir = await invoke("pick_directory", { initial: preferredDirToken() || null }); } catch { dir = null; }
      if (!dir) return;
      rememberDir(dir);
      const originalId = task.id;
      const resp = await send({
        op: "add",
        url: task.url,
        dir,
        filename: task.name || null,
        source: task.source || "manual",
        speed_limit_kbps: 0,
      });
      if (!resp || !resp.ok) {
        showActionToast(OP_FAIL);
        return;
      }
      const del = await send({ op: "delete", ids: [originalId], delete_files: false });
      if (!del || !del.ok) showActionToast(OP_FAIL);
      refresh();
    } else if (a === "copy") await copyUrls([task]);
    else if (a === "dir") await openDirs([task]);
    else if (a === "copy-error") await copyText(describeTaskError(task).raw);
  }

  document.getElementById("fail-bar-close").addEventListener("click", () => {
    failBarDismissed = true;
    document.getElementById("fail-bar").classList.add("hidden");
  });
  document.getElementById("fail-bar").addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-fail]");
    if (!btn) return;
    await handleFailAction(btn.getAttribute("data-fail"), primarySelected());
  });
  document.getElementById("props-fail-actions").addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-fail]");
    if (!btn) return;
    await handleFailAction(btn.getAttribute("data-fail"), primarySelected());
  });
  wireMissingDialog();

  document.getElementById("list-fail-retry").addEventListener("click", () => {
    listLoading = true;
    render();
    refresh();
  });

  document.addEventListener("click", (e) => {
    if (!ctxMenu.contains(e.target)) closeRowContextMenu();
  });
  window.addEventListener("blur", closeRowContextMenu);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && topLayer()) {
      const root = topLayer().querySelector(".dialog") || topLayer();
      const list = focusableIn(root);
      if (list.length && !root.contains(e.target)) {
        e.preventDefault();
        list[0].focus();
        return;
      }
      if (list.length) {
        const first = list[0];
        const last = list[list.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
      return;
    }
    if (e.key === "Escape") {
      if (ctxMenu && !ctxMenu.classList.contains("hidden")) {
        closeRowContextMenu();
        return;
      }
      const top = topLayer();
      if (top && top.id === "rename-ext-mask") {
        cancelRenameExt();
        return;
      }
      if (isRenaming()) {
        cancelRename();
        return;
      }
      if (top === setMask) {
        requestCloseSettings();
        return;
      }
      if (top === mask) {
        closeDialog();
        return;
      }
      if (top === delMask) {
        closeDeleteDialog();
        return;
      }
      if (top && top.id === "cand-mask") {
        closeCandidateDialog();
        return;
      }
      if (propsVisible) {
        showPropsPanel(false);
        render();
      }
      return;
    }
    // 有弹窗时，除 Esc/Tab 外的全局快捷键一律不响应：
    // 否则 Delete / Ctrl+A / 空格 会作用到背后的任务列表（模态形同虚设）。
    if (topLayer()) return;
    if ((e.shiftKey && e.key === "F10") || e.key === "ContextMenu") {
      if (isTypingTarget(e.target)) return;
      const task = primarySelected();
      if (!task) return;
      e.preventDefault();
      ctxTaskId = task.id;
      const row = document.querySelector(`.data-row[data-id="${task.id}"]`);
      const rect = row ? row.getBoundingClientRect() : { left: 80, bottom: 120 };
      openRowContextMenu(rect.left + 8, rect.bottom);
      return;
    }
    if (e.ctrlKey && (e.key === "n" || e.key === "N")) {
      e.preventDefault();
      if (engineOffline) return;
      openDialog();
      return;
    }
    if (isTypingTarget(e.target)) return;
    if (e.ctrlKey && (e.key === "a" || e.key === "A")) {
      e.preventDefault();
      selectedIds = new Set(filteredTasks().map((t) => t.id));
      render();
      return;
    }
    if (e.key === "Delete" || e.key === "Backspace") {
      if (engineOffline) return;
      if (selectedIds.size) {
        e.preventDefault();
        requestDelete([...selectedIds]);
      }
      return;
    }
    if (e.key === " " || e.code === "Space") {
      e.preventDefault();
      spaceToggle();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      moveSelection(1, e.shiftKey);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      moveSelection(-1, e.shiftKey);
    }
  });

  for (const li of document.querySelectorAll(".sidebar li")) {
    li.addEventListener("click", () => {
      document.querySelectorAll(".sidebar li").forEach((other) => {
        other.classList.remove("active");
        other.setAttribute("aria-selected", "false");
      });
      li.classList.add("active");
      li.setAttribute("aria-selected", "true");
      render();
    });
  }

  // 表头随横向滚动平移：两者宽度相同，靠 `scrollLeft` 对齐。
  {
    const scroll = document.getElementById("list-scroll");
    const head = document.getElementById("col-headers");
    if (scroll && head) {
      scroll.addEventListener("scroll", () => {
        head.style.transform = "translateX(" + -scroll.scrollLeft + "px)";
      }, { passive: true });
    }
  }

  if (listen) {
    listen("engine-status", (event) => {
      const p = event.payload || {};
      if (p.online) {
        setEngineOffline(false);
        lastEngineEventAt = Date.now();
      } else {
        // 推送通道重连不代表普通请求不可用；按真实请求结果决定离线。
        send({ op: "ping" }).catch((error) => console.error("AIDM engine status render failed", error));
      }
    });
    listen("engine-event", (event) => {
      const ev = event.payload;
      if (!ev || !ev.event) return;
      lastEngineEventAt = Date.now();
      if (engineOffline) setEngineOffline(false);
      if (ev.event === "stats") {
        hasStats = true;
        stats = {
          total_speed: ev.total_speed || 0,
          active_conns: ev.active_conns || 0,
          speed_limit: ev.speed_limit || 0,
        };
        updateStatusbar();
      } else if (ev.event === "task_completed") {
        playSoundFor("ui.sound_complete", "ui.sound_file_complete");
        notifyTaskCompleted(ev);
        refresh();
      } else if (ev.event === "settings_changed") {
        // 设置被（别的窗口 / 扩展 / 引擎自身）改动：丢掉本地缓存，
        // 下次读设置时重新拉。`revision` 让这步不需要轮询。
        settingsCache = {};
        loadSettings(true);
      } else if (ev.event === "after_done") {
        onAfterDone(ev);
      } else if (ev.event === "quota") {
        notifyQuota(ev);
      } else if (ev.event === "candidates") {
        openCandidateDialog(ev);
      } else if (ev.event === "sched") {
        schedKnown = true;
        schedSnap = {
          next_start_at: ev.next_start_at || null,
          queued: ev.queued || 0,
          active: ev.active || 0,
        };
        updateSchedChip();
        updateNewDialogHint();
      } else if (ev.event === "update") {
        handleUpdateEvent(ev);
      }
    });
  }

  // ---- 设置驱动的界面行为：提示音、队列完成后的动作、配额提示 ----

  // 下载失败没有独立事件，靠 list 轮询的差集发现新进入 error 的任务。
  let knownErrorIds = new Set();

  function maybePlayErrorSound(list) {
    const now = new Set();
    let fresh = false;
    for (const t of list) {
      if (t.state === "error") {
        now.add(t.id);
        if (!knownErrorIds.has(t.id)) fresh = true;
      }
    }
    knownErrorIds = now;
    if (fresh && !listLoading) playSoundFor("ui.sound_error", "ui.sound_file_error");
  }

  // 播放完成/失败提示音：none / beep（内置代码合成）/ file（自定义 wav）。
  function playSoundFor(modeKey, fileKey) {
    const mode = settingStr(settingsCache[modeKey]) || "none";
    if (mode === "none") return;
    const isError = modeKey === "ui.sound_error";
    try {
      if (mode === "file") {
        const path = settingStr(settingsCache[fileKey]);
        if (!path) return;
        const a = new Audio(pathToFileUrl(path));
        a.play().catch(() => beep(isError));
        return;
      }
      beep(isError);
    } catch (_) {
      beep(isError);
    }
  }

  // 内置提示音由 Rust 用代码合成 WAV 播放，不受 WebView 自动播放策略限制。
  function beep(isError) {
    if (invoke) {
      invoke("play_builtin_sound", { kind: isError ? "error" : "complete" }).catch(() =>
        webBeep(isError)
      );
      return;
    }
    webBeep(isError);
  }

  // 浏览器/命令不可用时的 Web Audio 回退：同样是代码合成，不依赖文件。
  function webBeep(isError) {
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      const ctx = new Ctx();
      const notes = isError ? [[660, 0], [440, 0.14]] : [[880, 0], [1318.5, 0.12]];
      const now = ctx.currentTime;
      for (const [freq, offset] of notes) {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "sine";
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.0001, now + offset);
        gain.gain.exponentialRampToValueAtTime(0.16, now + offset + 0.015);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + offset + 0.22);
        osc.connect(gain).connect(ctx.destination);
        osc.start(now + offset);
        osc.stop(now + offset + 0.24);
      }
      setTimeout(() => {
        try {
          ctx.close();
        } catch (_) {}
      }, 800);
    } catch (_) {}
  }

  function soundBasename(path) {
    return String(path || "").split(/[\\/]/).pop() || "";
  }

  function renderSoundName(kind) {
    const mode = document.getElementById(`set-sound-${kind}`).value;
    const file = document.getElementById(`set-sound-file-${kind}`).value.trim();
    const name = mode === "file" && file ? soundBasename(file) : T("内置提示音");
    const el = document.getElementById(`sound-${kind}-name`);
    if (el) {
      el.textContent = name;
      el.title = mode === "file" && file ? file : T("内置提示音");
    }
  }

  function previewSound(kind) {
    const mode = document.getElementById(`set-sound-${kind}`).value;
    const file = document.getElementById(`set-sound-file-${kind}`).value.trim();
    if (mode === "file" && file) {
      try {
        const a = new Audio(pathToFileUrl(file));
        a.play().catch(() => beep(kind === "error"));
        return;
      } catch (_) {
        /* fall through to built-in */
      }
    }
    beep(kind === "error");
  }

  function pathToFileUrl(p) {
    // 纯逻辑放在 lib/settings_form.js（node:test 直接覆盖）
    return SF.pathToFileUrl ? SF.pathToFileUrl(p) : String(p || "");
  }

  // 队列跑完后的动作。引擎只广播、不动电源（后台下载器不该持有
  // SeShutdownPrivilege）；这里只做安全的那部分：提示 + 可选退出应用。
  function onAfterDone(ev) {
    const action = (ev && ev.action) || "none";
    if (action === "none") return;
    if (action === "exit") {
      if (window.confirm(T("队列已完成，是否退出 AIDM？")) && invoke) {
        invoke("quit_app", {}).catch(() => {});
      }
      return;
    }
    toast(T("队列已完成。引擎请求「{action}」，该动作需要你确认后自行执行。", { action: action }));
  }

  /// 下载完成通知（`ui.notify_on_complete`）。
  ///
  /// **视觉提示按来源分流**；声音不在这里——它由 `ui.sound_complete` 独立控制，
  /// 对所有来源的下载都响（用户要的是"无论哪条通道，完成时都要有声"）。
  ///   - 网页里点出来的（`source === "ext"`）：由扩展在**那个网页里**提示，
  ///     主程序不再弹系统通知——用户人就在页面上，弹到系统反而多余。
  ///   - 剪贴板 / 手动等其余来源：用户多半在看别处，走**系统通知**。
  function notifyTaskCompleted(ev) {
    if (!invoke) return;
    if (!settingBool(settingsCache["ui.notify_on_complete"])) return;
    const source = String((ev && ev.source) || "");
    if (source === "ext") return; // 网页来源的视觉提示归扩展管
    const filePath = String((ev && ev.file_path) || "");
    const name = filePath.split(/[/\\]/).pop() || "";
    invoke("notify_complete", {
      title: T("AIDM 下载完成"),
      body: name || T("任务已完成"),
    }).catch(() => {});
  }

  function notifyQuota(ev) {
    const used = Number(ev.used_bytes || 0) / (1024 * 1024);
    const limit = Number(ev.limit_bytes || 0) / (1024 * 1024);
    const period = { hour: T("每小时"), day: T("每天"), week: T("每周") }[ev.period] || ev.period;
    const action = ev.action === "stop" ? T("停止") : T("暂停");
    toast(
      T("已达到流量配额 {used} / {limit} MB（{period}），已按「{action}」处理。", { used: used.toFixed(0), limit: limit.toFixed(0), period: period, action: action })
    );
    refresh();
  }

  function toast(msg) {
    try {
      if (typeof showToast === "function") {
        showToast(msg);
        return;
      }
    } catch (_) {}
    console.info("[aidm] " + msg);
  }

  // ---- 设置项的"开关式"可用性：没启用的功能不让人误填 ----

  function updateWindowBoxes() {
    const on = document.getElementById("set-window-on").checked;
    for (const id of ["set-window-start", "set-window-end", "set-window-days"]) {
      const el = document.getElementById(id);
      if (el) el.disabled = !on;
    }
  }

  function updateQuotaBoxes() {
    const on = document.getElementById("set-quota-on").checked;
    for (const id of ["set-quota-mb", "set-quota-period", "set-quota-action"]) {
      const el = document.getElementById(id);
      if (el) el.disabled = !on;
    }
  }

  // ---- 设置声明表（引擎是唯一事实源）----

  let settingsSchemaCache = null;

  async function loadSettingsSchema() {
    if (settingsSchemaCache) return settingsSchemaCache;
    const resp = await send({ op: "settings_schema" });
    settingsSchemaCache = Array.isArray(resp.schema) ? resp.schema : [];
    return settingsSchemaCache;
  }


  async function addHostConn() {
    const hostEl = document.getElementById("host-conn-host");
    const maxEl = document.getElementById("host-conn-max");
    const limEl = document.getElementById("host-conn-limit");
    const errEl = document.getElementById("host-conn-error");
    const host = hostEl.value.trim();
    errEl.classList.add("hidden");
    errEl.textContent = "";
    if (!host) {
      errEl.textContent = T("请输入服务器名");
      errEl.classList.remove("hidden");
      return;
    }
    const max = maxEl.value === "" ? null : Number(maxEl.value);
    const limit = limEl.value === "" ? null : Number(limEl.value);
    const resp = await send({
      op: "host_conns_set",
      host,
      max_conns: max,
      speed_limit_kbps: limit,
    });
    if (!resp.ok) {
      errEl.textContent = hostConnError(resp.code || resp.error);
      errEl.classList.remove("hidden");
      return;
    }
    hostConns = Array.isArray(resp.hosts) ? resp.hosts : [];
    renderHostConnRows();
    hostEl.value = "";
    maxEl.value = "";
    limEl.value = "";
  }

  async function removeHostConn(host) {
    const resp = await send({ op: "host_conns_remove", host });
    if (resp.ok) {
      hostConns = Array.isArray(resp.hosts) ? resp.hosts : [];
      renderHostConnRows();
    }
  }

  function hostConnError(code) {
    if (code === "host_invalid") return T("服务器名不合法（可用 *.example.com 通配）");
    if (code === "max_conns_invalid") return T("连接数需在 1–1024 之间");
    if (code === "speed_limit_invalid") return T("限速不能为负数");
    return T("保存失败，请重试");
  }

  // ---- 站点凭据（401 自动重试）----

  let siteLogins = [];

  async function refreshSiteLogins() {
    const resp = await send({ op: "site_logins_list" });
    siteLogins = Array.isArray(resp.logins) ? resp.logins : [];
    renderSiteLoginRows();
  }

  function renderSiteLoginRows() {
    const tbody = document.getElementById("site-login-rows");
    if (!tbody) return;
    tbody.textContent = "";
    if (!siteLogins.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "hint";
      td.textContent = T("没有站点凭据；需要登录的站点在这里加一条即可");
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const item of siteLogins) {
      const tr = document.createElement("tr");
      const host = document.createElement("td");
      host.textContent = item.host;
      const user = document.createElement("td");
      user.textContent = item.username || "—";
      const pass = document.createElement("td");
      pass.textContent = item.has_password ? T("已设置") : T("无");
      const act = document.createElement("td");
      const del = document.createElement("button");
      del.type = "button";
      del.className = "tool";
      del.textContent = T("删除");
      del.addEventListener("click", () => removeSiteLogin(item.host));
      act.appendChild(del);
      tr.append(host, user, pass, act);
      tbody.appendChild(tr);
    }
  }

  async function addSiteLogin() {
    const hostEl = document.getElementById("site-login-host");
    const userEl = document.getElementById("site-login-user");
    const passEl = document.getElementById("site-login-pass");
    const errEl = document.getElementById("site-login-error");
    errEl.classList.add("hidden");
    errEl.textContent = "";
    const host = hostEl.value.trim();
    if (!host) {
      errEl.textContent = T("请输入服务器名");
      errEl.classList.remove("hidden");
      return;
    }
    const resp = await send({
      op: "site_logins_set",
      host,
      username: userEl.value,
      password: passEl.value,
    });
    if (!resp.ok) {
      errEl.textContent = siteLoginError(resp.code || resp.error);
      errEl.classList.remove("hidden");
      return;
    }
    siteLogins = Array.isArray(resp.logins) ? resp.logins : [];
    renderSiteLoginRows();
    hostEl.value = "";
    userEl.value = "";
    passEl.value = "";
  }

  async function removeSiteLogin(host) {
    const resp = await send({ op: "site_logins_remove", host });
    if (resp.ok) {
      siteLogins = Array.isArray(resp.logins) ? resp.logins : [];
      renderSiteLoginRows();
    }
  }

  function siteLoginError(code) {
    if (code === "host_empty") return T("服务器名不能为空");
    if (code === "host_too_long") return T("服务器名过长");
    if (code === "credential_control_char") return T("用户名或密码含控制字符");
    if (code === "credential_too_long") return T("用户名或密码过长");
    return T("保存失败，请重试");
  }

  document.getElementById("site-login-add")?.addEventListener("click", addSiteLogin);

  document.getElementById("host-conn-add")?.addEventListener("click", addHostConn);
  document.getElementById("btn-play-sound-complete")?.addEventListener("click", () => previewSound("complete"));
  document.getElementById("btn-play-sound-error")?.addEventListener("click", () => previewSound("error"));
  for (const id of ["set-browse-sound-complete", "set-browse-sound-error"]) {
    document.getElementById(id)?.addEventListener("click", async () => {
      if (!invoke) return;
      const kind = id.endsWith("complete") ? "complete" : "error";
      try {
        const picked = await invoke("pick_audio_file", {});
        if (picked) {
          document.getElementById(`set-sound-file-${kind}`).value = picked;
          document.getElementById(`set-sound-${kind}`).value = "file";
          renderSoundName(kind);
          previewSound(kind);
        }
      } catch (_) {
        /* 平台不支持时忽略 */
      }
    });
  }

  if (listen) {
    listen("tray-action", (event) => {
      const a = event.payload;
      if (a === "start_all" || a === "pause_all") refresh();
    });
    listen("clipboard-links", (event) => {
      const links = Array.isArray(event.payload) ? event.payload : [];
      if (!links.length) return;
      openCandidateDialog({
        from: "clipboard",
        items: links.map((url) => ({ url, kind: "link", filename: clipboardLinkName(url) })),
      });
    });
  }

  // 曲线跨重启保留：先读回上次的采样点，退出前再强制落一次盘。
  loadSpeedHistory();
  window.addEventListener("pagehide", () => saveSpeedHistory(true));

  // 语言初始化：HTML 静态文案靠 `data-i18n` 一次替换；动态文案走 `T()`。
  // 首次启动跟随系统语言；用户手动切换后存 localStorage 优先。
  function detectSystemLang() {
    const raw =
      (navigator.languages && navigator.languages[0]) || navigator.language || "";
    return /^zh/i.test(String(raw)) ? "zh-CN" : "en-US";
  }

  function syncLangSwitch() {
    const cur = I18n.language();
    for (const btn of document.querySelectorAll(".lang-opt")) {
      const on = btn.dataset.lang === cur;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-pressed", on ? "true" : "false");
    }
  }

  // 设置面板里的语言切换：只预览，点「确定」才落盘；取消要回滚。
  let langPreviewBase = null;
  const savedLang =
    typeof localStorage !== "undefined" && localStorage.getItem
      ? localStorage.getItem("aidm.lang")
      : null;
  I18n.init({ lng: savedLang || detectSystemLang() });
  syncLangSwitch();
  // 窗口标题：HTML 的 <title> 只能改 document.title，Tauri 原生窗口标题需要显式 setTitle。
  function syncWindowTitle() {
    const text = T("app.title");
    try {
      document.title = text;
    } catch (e) {
      /* 预览环境无 document.title 也没关系 */
    }
    try {
      const win = window.__TAURI__ && window.__TAURI__.window && window.__TAURI__.window.getCurrentWindow
        ? window.__TAURI__.window.getCurrentWindow()
        : null;
      if (win && typeof win.setTitle === "function") void win.setTitle(text);
    } catch (e) {
      /* 没有 window 权限时忽略，标题退回 tauri.conf.json 的默认值 */
    }
  }
  syncWindowTitle();
  // 语言切换后，把所有「运行时生成」的区域重绘一遂。静态文本由 apply() 负责，
  // 但列表、属性、设置页动态表格、对话框都是 JS 写的，必须重新渲染。
  function relocalizeDynamicUi() {
    const safe = (fn) => {
      try {
        fn();
      } catch (e) {
        /* 单个区域失败不影响其它区域 */
      }
    };
    safe(syncWindowTitle);
    safe(updateToolbar);
    safe(updateStatusbar);
    safe(updateLimitPills);
    safe(updateSchedChip);
    safe(updateFailBar);
    safe(() => render(true));
    safe(renderProps);
    safe(syncBulkMenu);
    const candMask = document.getElementById("cand-mask");
    if (candMask && !candMask.classList.contains("hidden")) safe(renderCandidates);
    if (setMask && !setMask.classList.contains("hidden")) {
      safe(renderHostConnRows);
      safe(renderExtIdRows);
      safe(renderSiteLoginRows);
      safe(() => renderSoundName("complete"));
      safe(() => renderSoundName("error"));
      safe(renderUpdatePage);
      safe(updateSchedFormUi);
      safe(updateProxyBoxes);
      safe(updateBrowserRestEnabled);
    }
  }
  I18n.onLanguageChange(() => {
    try {
      syncLangSwitch();
      syncEventsFilterUi();
      relocalizeDynamicUi();
    } catch (e) {
      /* 语言切换失败不影响主流程 */
    }
  });
  for (const btn of document.querySelectorAll(".lang-opt")) {
    btn.addEventListener("click", () => {
      const code = btn.dataset.lang;
      if (!I18n.setLanguage(code)) return;
      // 只预览。是否持久化由设置对话框的「确定 / 取消」决定。
    });
  }

  loadSettings(true).then(() => {
    refresh();
    refreshSchedStatus();
  });
  // 列表 1s：只需要「有哪些任务、大概到哪」，不需要 500ms。
  setInterval(refresh, 1000);
  // 属性面板详情 500ms：只在「面板打开 + 当前任务运行中」拉**单个任务**。
  // 暂停 / 完成 / 失败后停止刷新，避免无意义 IO。
  setInterval(() => {
    if (!propsVisible) return;
    const t = primarySelected();
    if (!t) return;
    if (["connecting", "downloading", "verifying"].includes(t.state)) {
      ensurePropsDetail(t.id, true);
    }
    // 下载日志跟着同一拍走：面板展开才拉，暂停/完成后仍可看最后一屏。
    // 日志数也要跟着 500ms 走（标题里的总数不能靠手刷）。
    void loadPropsEvents(t, {});
  }, 500);
  setInterval(() => {
    if (Date.now() - lastEngineEventAt > HEARTBEAT_STALE_MS) setEngineOffline(true);
  }, 1000);

  for (const li of document.querySelectorAll(".sidebar li, .settings-nav li")) {
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        li.click();
      }
    });
  }

  // 暴露给单测/调试（不发起网络）
  window.__aidmLogic = {
    validateDownloadUrl,
    formatLimitKbps,
    formatLimitBps,
    settingsDiff,
    visibleRange,
    settingBool,
    SETTINGS_SAVE_FAILED,
    deriveFilename,
    syncDialogFilename,
    resetDialogFilename,
    truncateUrl,
    parseExtIdList,
    hostRegState,
    isOfferExpired,
    filterCandidateItems,
    sourceLabel,
    ENGINE_DEFAULT_EXT_ID,
    OFFER_EXPIRED_TEXT,
    HOST_STATUS_FAIL,
    UNCERTAIN_TEXT,
    settingsSetUserError,
    taskFailReason,
    describeTaskError,
    isInterrupted,
    isFailedTask,
    canStartTask,
    canPauseTask,
    setEngineOffline,
    EXT_AUTH_EXPIRED,
    cronFromPreset,
    parseSchedMode,
    isValidCron5,
    formatNextStart,
    formatRetryCountdown,
    formatQueueStatus,
    propsStateSignal,
    renderPropsHeadMeta,
    retryTooltip,
    backoffMsFromSeconds,
    secondsFromBackoffMs,
    CRON_INVALID,
    FIELD_RANGE,
    LIST_LOAD_FAIL,
    ADD_DOWNLOAD_FAIL,
    OP_FAIL,
    OPEN_DIR_FAIL,
    OPEN_INSTALL_FAIL,
    COPY_ERROR_DETAIL,
    DISCARD_SETTINGS,
    ENGINE_OFFLINE_BANNER,
    INTERRUPTED_TOOLTIP,
    handleFailAction,
    requestCloseSettings,
    settingsHasUnsavedChanges,
    fmtEta,
    formatFinishCell: (t) => P.formatFinishCell ? P.formatFinishCell(t) : "—",
    formatFinishProps: (t) => P.formatFinishProps ? P.formatFinishProps(t) : "—",
    formatSpeedLimitButton: (v) => P.formatSpeedLimitButton ? P.formatSpeedLimitButton(v) : T("不限速"),
    renameCommitDecision: (...a) => P.renameCommitDecision ? P.renameCommitDecision(...a) : null,
    extensionChanged: (...a) => P.extensionChanged ? P.extensionChanged(...a) : false,
    renameErrorText: (c) => P.renameErrorText ? P.renameErrorText(c) : T("重命名失败，请重试"),
    FINISH_TIME_HEADER: P.FINISH_TIME_HEADER || T("完成时间"),
    startRename,
    tryCommitRename,
    cancelRename,
    renderUpdatePage,
    handleUpdateEvent,
    requestUpdateCheck,
    requestUpdateApply,
    get updateState() { return updateState; },
    setUpdateState(next) { updateState = next; renderUpdatePage(); },
    get engineOffline() { return engineOffline; },
    setEngineOffline,
    get tasks() { return tasks; },
    setTasks(next) { tasks = next; },
    render,
    refresh,
    renderListWindow,
  };
  window.__aidmApp = window.__aidmLogic;
})();

