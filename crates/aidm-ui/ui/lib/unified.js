// 统一切片视图的纯逻辑：范围换算、覆盖比例、通路子区间几何、文案映射。
//
// 为什么单独放在 lib/ 里：`app.js` 是 IIFE + DOM，node:test 里没有 DOM，
// 只能对源码做断言。把可计算的规则抽出来（与 `polish.js` / `errors.js` 同一模式），
// 就能直接验证「同一 slice_id 的范围不变」「通路细线不重叠」「未知长度不画百分比」
// 这类**正确性**约束，而不是只验证“渲染函数被调用过”。
(function (root) {
  "use strict";
  const T = function (key, vars) {
    const api = root && root.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  };

  const SLICE_TEXT = {
    pending: T("等待分配"),
    active: T("下载中"),
    waiting: T("等待中"),
    verifying: T("校验中"),
    done: T("完成"),
    error: T("错误"),
  };
  const ASSIGN_TEXT = {
    pending: T("待开始"),
    connecting: T("连接中"),
    queued: T("排队"),
    transferring: T("传输中"),
    draining: T("收尾"),
    completed: T("完成"),
    failed: T("失败"),
    cancelled: T("已取消"),
  };
  const ACTIVITY_TEXT = {
    discovering: T("发现源"),
    probing: T("探测"),
    connecting: T("连接"),
    transferring: T("传输"),
    waiting: T("等待"),
    verifying: T("校验"),
    committing: T("提交"),
    idle: T("空闲"),
  };
  const WAIT_TEXT = {
    scheduler: T("调度"),
    budget: T("连接预算"),
    metadata: T("元数据"),
    no_source: T("无可用源"),
    peer_queue: T("对端排队"),
    rate_limit: T("限流"),
    retry: T("重试退避"),
    local_action: T("本地操作"),
  };

  // IPC 里的大整数是十进制字符串（超出 JS 安全整数也不丢精度）。
  // 展示层转 Number 足够；空值/NaN 一律当“未知”，绝不当 0。
  function parseDec(v) {
    if (v == null || v === "") return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  // 精确解析：范围判断必须用 BigInt。
  //
  // 为什么不能用 `Number()`：相邻的两个大整数（如 2^53 与 2^53+1）转 Number 后
  // 相等，`end > start` 就会误判成“长度未知”。用户复核用这个反例抓到了。
  function parseBig(v) {
    if (v == null || v === "") return null;
    const s = String(v).trim();
    if (!/^-?\d+$/.test(s)) return null;
    try {
      return BigInt(s);
    } catch (e) {
      return null;
    }
  }

  function shortId(id) {
    const s = String(id == null ? "" : id);
    if (!s) return "—";
    return s.length > 8 ? s.slice(0, 8) : s;
  }

  function defaultFmt(n) {
    if (n == null || !Number.isFinite(n)) return T("未知");
    if (n < 1024) return n + " B";
    const units = ["KB", "MB", "GB", "TB"];
    let v = n;
    let i = -1;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return (v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i];
  }

  // 左闭右开范围的**精确**长度；终点缺失或非法时返回 null。
  function rangeLenBig(range) {
    if (!range || range.end_exclusive == null) return null;
    const start = parseBig(range.start);
    const end = parseBig(range.end_exclusive);
    if (start == null || end == null || end <= start) return null;
    return end - start;
  }

  // 长度的数值形式（仅用于展示与百分比）。判断“是否未知”一律用 rangeLenBig。
  function rangeLen(range) {
    const d = rangeLenBig(range);
    return d == null ? null : Number(d);
  }

  function rangeText(range, fmt) {
    const f = typeof fmt === "function" ? fmt : defaultFmt;
    if (!range) return "—";
    const start = parseBig(range.start);
    const end = parseBig(range.end_exclusive);
    if (start == null || end == null || end <= start) {
      return (start == null ? T("未知") : f(Number(start))) + T(" 起（长度未知）");
    }
    // 终点直接用 BigInt 换算，避免大数相加后丢精度。
    return f(Number(start)) + " – " + f(Number(end));
  }

  // 切片的主进度：有效落盘覆盖 / 所需长度。
  //
  // `percent` 为 null 表示“总长未知”——调用方必须画不定长进度，
  // 不能拿 0 或 100 冒充。`*Big` 字段是精确值，供调用方做相等/差值判断；
  // 数值字段只用于展示（百分比本来就是近似）。
  function coverage(slice) {
    const lenBig = rangeLenBig(slice && slice.range);
    const p = (slice && slice.progress) || {};
    const requiredBig = lenBig != null ? lenBig : parseBig(p.required_bytes);
    const storedBig = parseBig(p.stored_unique_bytes) || 0n;
    const verifiedBig = parseBig(p.verified_unique_bytes) || 0n;
    const percent =
      requiredBig != null && requiredBig > 0n
        ? Math.min(100, (Number(storedBig) / Number(requiredBig)) * 100)
        : null;
    return {
      stored: Number(storedBig),
      verified: Number(verifiedBig),
      required: requiredBig == null ? null : Number(requiredBig),
      percent: percent,
      storedBig: storedBig,
      verifiedBig: verifiedBig,
      requiredBig: requiredBig,
    };
  }

  // 通路子区间在切片主条上的位置（百分比，左/宽）。
  //
  // 必须**先求交集**再算位置：
  // - 切片 [100,200)、通路 [50,125) 应画 0%~25%；按原始起点算会得到 75%。
  // - 完全在切片左侧/右侧的通路不相交，应返回 null（不画）。
  // 越界部分会被裁到交点内，避免 UI 出现伸出条外的线。
  function laneGeometry(slice, assignment) {
    const s0 = parseBig(slice && slice.range && slice.range.start);
    const s1 = parseBig(slice && slice.range && slice.range.end_exclusive);
    const a0 = parseBig(assignment && assignment.range && assignment.range.start);
    const a1 = parseBig(assignment && assignment.range && assignment.range.end_exclusive);
    if (s0 == null || s1 == null || a0 == null || a1 == null) return null;
    const span = s1 - s0;
    if (span <= 0n) return null;

    const start = s0 > a0 ? s0 : a0;
    const end = s1 < a1 ? s1 : a1;
    if (end <= start) return null;

    const left = (Number(start - s0) / Number(span)) * 100;
    const width = (Number(end - start) / Number(span)) * 100;
    if (!(width > 0)) return null;
    return { left: left, width: width };
  }

  // 切片内所有通路是否互不重叠。返回 false 时 UI 不能把它们画成并列细线
  // （那会让人以为同一段字节被两条通路同时写）。
  function lanesDisjoint(slice) {
    const list = (slice && Array.isArray(slice.assignments) ? slice.assignments : [])
      .map((a) => {
        const span = a && a.range;
        const start = parseBig(span && span.start);
        const end = parseBig(span && span.end_exclusive);
        if (start == null || end == null || end <= start) return null;
        return [start, end];
      })
      .filter(Boolean)
      .sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
    for (let i = 1; i < list.length; i++) {
      if (list[i][0] < list[i - 1][1]) return false;
    }
    return true;
  }

  function sliceStateText(state) {
    return SLICE_TEXT[state] || state || "—";
  }  function assignStateText(state) {
    return ASSIGN_TEXT[state] || state || "—";
  }
  function activityText(state) {
    return ACTIVITY_TEXT[state] || state || "";
  }
  function waitText(reason) {
    return WAIT_TEXT[reason] || reason || "";
  }

  // 属性面板必须**主动请求详情**。
  //
  // 背景（真实缺陷）：列表 `list` 只带摘要，`unified_download` 只在 `status`
  // 详情里返回。前端之前只请求 `list`、属性面板也从列表取任务，于是统一视图
  // 的渲染分支永远不会进入——代码写了但真实界面看不到。
  async function fetchTaskDetail(send, id) {
    if (typeof send !== "function" || id == null) return null;
    const resp = await send({ op: "status", id: id });
    if (!resp || !resp.ok || !resp.task) return null;
    return resp.task;
  }

  // 渲染时优先用详情（它带 `unified_download`），否则回退列表摘要。
  // 只接受**同一任务**的详情，避免切换选中时旧响应覆盖新面板。
  function pickRenderTask(listTask, detail) {
    if (!listTask) return null;
    if (detail && detail.id != null && detail.id === listTask.id && detail.task) {
      return detail.task;
    }
    return listTask;
  }

  // 一份详情的“身份”：引擎实例 + 状态版本。
  //
  // 两者必须一起比较：引擎重启后 `state_revision` 会从 0 重新开始，
  // 只看版本会把新引擎实例的数据误判为过期而拒绝。
  function detailIdentity(task) {
    const u = task && task.unified_download;
    const id = u && u.identity;
    return {
      engine: id && id.engine_instance_id ? String(id.engine_instance_id) : null,
      revision: id && id.state_revision != null ? Number(id.state_revision) : null,
    };
  }

  // 是否接受一份新详情写入缓存。
  //
  // 背景（真实缺陷）：A → B → A 时，新请求返回版本 3、旧请求随后返回版本 1，
  // 缓存会从 3 回退到 1。仅比较任务 ID 不够，必须同时看**请求代次**与
  // **同一引擎实例内的版本**。
  function acceptDetail(prevTask, nextTask, seq, latestSeq) {
    if (nextTask == null) return false;
    // 旧代次（已被更新的请求取代）一律丢弃。
    if (seq !== latestSeq) return false;
    if (prevTask == null) return true;
    const prev = detailIdentity(prevTask);
    const next = detailIdentity(nextTask);
    // 只有同一引擎实例内才比较版本；跨实例（重启）允许从头计数。
    if (
      prev.engine &&
      next.engine &&
      prev.engine === next.engine &&
      prev.revision != null &&
      next.revision != null &&
      next.revision < prev.revision
    ) {
      return false;
    }
    return true;
  }

  // 「下载日志」只留用户看得懂的事件：`unified_*` 是协调器影子埋点，
  // 列在同一个面板里会把真正的建链/换源/校验/失败原因冲掉。
  function filterDownloadLog(events, limit) {
    const cap = typeof limit === "number" && limit > 0 ? limit : 50;
    return (Array.isArray(events) ? events : [])
      .filter((ev) => !String((ev && ev.kind) || "").startsWith("unified_"))
      .slice(0, cap);
  }

  const api = {
    parseDec: parseDec,
    parseBig: parseBig,
    shortId: shortId,
    rangeLen: rangeLen,
    rangeLenBig: rangeLenBig,
    rangeText: rangeText,
    coverage: coverage,
    laneGeometry: laneGeometry,
    lanesDisjoint: lanesDisjoint,
    sliceStateText: sliceStateText,
    assignStateText: assignStateText,
    activityText: activityText,
    waitText: waitText,
    fetchTaskDetail: fetchTaskDetail,
    pickRenderTask: pickRenderTask,
    detailIdentity: detailIdentity,
    acceptDetail: acceptDetail,
    filterDownloadLog: filterDownloadLog,
  };

  root.AidmUnified = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
