// 列表 / 属性面板 polish 纯逻辑（与 src/polish.rs 对齐）。无 DOM / 无网络。
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AidmPolish = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  const T = function (key, vars) {
    const api = root && root.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  };
  const KIB = 1024;
  const FINISH_TIME_HEADER = T("完成时间");
  const RENAME_EMPTY = T("文件名不能为空");
  const RENAME_INVALID = T("文件名无效，请重新输入");
  const RENAME_TAKEN = T("已存在同名文件，请换一个名字");
  const RENAME_MISSING = T("任务不存在或已删除");
  const RENAME_FAIL = T("重命名失败，请重试");
  const RENAME_UNAVAILABLE = T("当前无法重命名");
  const DASH = "—";
  const UNKNOWN_SIZE = T("未知");

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

  function formatSpeedLimitButton(kbps) {
    if (kbps == null || kbps === "") return T("不限速");
    const n = Number(kbps);
    if (!Number.isFinite(n) || n <= 0) return T("不限速");
    return T("限速 ") + formatLimitKbps(n);
  }

  function formatSpeedLimitButtonBps(bps) {
    return formatSpeedLimitButton(Math.floor((Number(bps) || 0) / KIB));
  }

  function remainingSeconds(task) {
    if (!task || task.state !== "downloading") return null;
    const total = Number(task.total);
    const done = Number(task.done) || 0;
    const speed = Number(task.speed) || 0;
    if (!Number.isFinite(total) || total <= 0 || speed <= 0) return null;
    const remain = total - done;
    if (remain <= 0) return null;
    return Math.ceil(remain / speed);
  }

  function toEpochMs(v) {
    if (v == null || v === "") return null;
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) return null;
    return n > 1e12 ? n : n * 1000;
  }

  function durationSeconds(task) {
    if (!task) return null;
    // 「用时」= 净下载耗时：暂停 / 排队 / 退避都不算，与速度曲线横轴同一把尺子。
    if (task.active_ms != null && Number.isFinite(Number(task.active_ms))) {
      return Math.max(0, Math.round(Number(task.active_ms) / 1000));
    }
    if (task.duration_secs != null && Number.isFinite(Number(task.duration_secs))) {
      return Math.max(0, Math.round(Number(task.duration_secs)));
    }
    if (task.duration_ms != null && Number.isFinite(Number(task.duration_ms))) {
      return Math.max(0, Math.round(Number(task.duration_ms) / 1000));
    }
    const start = toEpochMs(task.created_at != null ? task.created_at : task.created_at_ms);
    const end = toEpochMs(
      task.finished_at != null ? task.finished_at
        : task.finished_at_ms != null ? task.finished_at_ms
          : task.completed_at != null ? task.completed_at
            : task.completed_at_ms
    );
    if (start == null || end == null || end < start) return null;
    return Math.round((end - start) / 1000);
  }

  function formatRemainingSeconds(secs) {
    const s = Math.max(0, Math.ceil(Number(secs) || 0));
    if (s < 60) return s + T(" 秒");
    if (s < 3600) return Math.ceil(s / 60) + T(" 分钟");
    return (s / 3600).toFixed(1) + T(" 小时");
  }

  // 时长格式：HH:MM:SS（小时不封顶，例如 26:05:03）。
  function formatDurationSeconds(secs) {
    const s = Math.max(0, Math.round(Number(secs) || 0));
    const pad = (n) => String(n).padStart(2, "0");
    return pad(Math.floor(s / 3600)) + ":" + pad(Math.floor((s % 3600) / 60)) + ":" + pad(s % 60);
  }

  function formatFinishCell(task) {
    if (!task) return DASH;
    if (task.state === "downloading") {
      const remain = remainingSeconds(task);
      return remain == null ? DASH : formatRemainingSeconds(remain);
    }
    if (task.state === "done") {
      const dur = durationSeconds(task);
      return dur == null ? DASH : formatDurationSeconds(dur);
    }
    return DASH;
  }

  function formatFinishProps(task) {
    if (!task) return DASH;
    if (task.state === "downloading") {
      const remain = remainingSeconds(task);
      return remain == null ? DASH : T("约 ") + formatRemainingSeconds(remain);
    }
    if (task.state === "done") {
      const dur = durationSeconds(task);
      return dur == null ? DASH : T("用时 ") + formatDurationSeconds(dur);
    }
    return DASH;
  }

  const FILENAME_FALLBACK = "download.bin";

  // 从 URL 解析文件名。
  // - `ed2k://|file|<名>|<字节>|<哈希>|…`：名即权威文件名（与引擎 `FileLink::decoded_name`
  //   同规则：`%XX` 最好努力解码，解不开保留原样）；非 file 类型没有文件名。
  // - 普通 URL：去掉 scheme/host/query/片段，再做百分号解码。
  // 解析不出返回空串，兜底交给调用方。
  // 与 aidm-core 的 `filename_from_url` / `decoded_name` 同一套规则，保证对话框预览和最终落盘名一致。
  function filenameFromUrl(url) {
    const raw = String(url == null ? "" : url);
    if (!raw.trim()) return "";
    if (raw.trim().toLowerCase().startsWith("ed2k://")) {
      const t = raw.split("|");
      if (t.length < 5 || t[1].trim().toLowerCase() !== "file") return "";
      let name = t[2] || "";
      name = name.trim();
      if (!name || name === "." || name === "..") return "";
      try { name = decodeURIComponent(name); } catch { /* 解码失败保留原样 */ }
      if (!name || name === "." || name === "..") return "";
      return name.length > 255 ? [...name].slice(0, 255).join("") : name;
    }
    const after = raw.includes("://") ? raw.split("://")[1] : raw;
    const slash = after.indexOf("/");
    if (slash < 0) return "";
    const path = after.slice(slash + 1).split(/[?#]/)[0].replace(/\/+$/, "");
    let last = path.split(/[/\\]/).pop() || "";
    try { last = decodeURIComponent(last); } catch { /* 解码失败保留原样 */ }
    if (!last || last === "." || last === "..") return "";
    return last.length > 255 ? [...last].slice(0, 255).join("") : last;
  }

  // 新建下载对话框：输入链接后自动填文件名。
  // current=输入框现值，lastAuto=上次自动填入的值；返回 null 表示「用户手动改过，不要覆盖」。
  function autoFilenameFor(current, lastAuto, url) {
    const cur = String(current == null ? "" : current);
    if (cur && cur !== String(lastAuto == null ? "" : lastAuto)) return null;
    return filenameFromUrl(url);
  }

  /**
   * 新建对话框提交时，文件名是否算「用户显式指定」。
   * 自动回填值（等于上次自动名或当前 URL 尾名）不算：交给引擎读
   * Content-Disposition 定名（微软 CDN 的 `.../files/<GUID>` 尾段只是 ID）。
   */
  function shouldSubmitFilename(filename, autoFilename, url) {
    const name = String(filename == null ? "" : filename).trim();
    if (!name) return false;
    if (name === String(autoFilename == null ? "" : autoFilename).trim()) return false;
    return name !== filenameFromUrl(url);
  }

  // 速度曲线采样（纯函数）：根据一次任务快照决定追加哪些点。
  // - connecting/downloading：按净下载耗时（或调用方算好的横轴 x）追加；
  //   同一拍（<400ms）只覆盖最后一次非零采样，避免重复 list 画出毛刺。
  // - 从未采样过但已有 active_ms：小文件可能在两次 600ms 轮询之间就跑完，
  //   这里补一个 0 起点 / 平均速度点，再按完成补 0，保证至少 2 个点、能画出曲线。
  // - 离开下载阶段：在最后一拍就地补 0 收尾，之后不再增长。
  // 返回新数组，不修改 prevSeries（采样历史由调用方持有）。
  function speedSampleFromTask(prevSeries, task, nowMs, x) {
    const t = task || {};
    const prev = Array.isArray(prevSeries) ? prevSeries : [];
    const now = Number.isFinite(Number(nowMs)) ? Number(nowMs) : Date.now();
    const state = String(t.state || "");
    const running = state === "connecting" || state === "downloading";
    const speed = Math.max(0, Number(t.speed) || 0);
    const last = prev.length ? prev[prev.length - 1] : null;
    const rawActive = Number(t.active_ms);
    const active = Number.isFinite(rawActive) && rawActive >= 0 ? rawActive : null;
    const explicit = Number(x);
    const hasExplicit = Number.isFinite(explicit) && explicit >= 0;
    // 没有采样到瞬时速度时（小文件第一次 list 就可能已经完成），用
    // 「已下载字节 / 净下载耗时」估一个平均速度，保证曲线有可见高度。
    const averageSpeed = () => {
      if (speed) return speed;
      const done = Number(t.done);
      if (active == null || active <= 0) return 0;
      if (!Number.isFinite(done) || done <= 0) return 0;
      return (done * 1000) / active;
    };
    const at = (l) => {
      const fallback = l
        ? l.x + Math.min(5000, Math.max(0, now - l.t))
        : active != null ? active : 0;
      const base = hasExplicit ? explicit : active != null ? active : fallback;
      return Math.max(base, l ? l.x : 0);
    };
    const out = prev.map((p) => {
      const point = { x: p.x, bps: p.bps, t: p.t };
      if (p.est) point.est = true;
      return point;
    });

    if (running) {
      const nx = at(last);
      if (!out.length) {
        // 下载中从没采过样：补 0 起点，单拍也能画出线段；x=0 时只留当前点。
        // 没有瞬时速度时 bps 来自平均值，标记 est，列表不能把它当真实峰值。
        const bps = averageSpeed();
        const est = bps > 0 && !speed;
        if (nx > 0) out.push({ x: 0, bps, t: now, est });
        out.push({ x: nx, bps, t: now, est });
        return out;
      }
      if (now - last.t < 400 && last.bps !== 0) {
        // 同一拍内的重复 list 只覆盖值，保留首拍时间戳（否则 400ms 窗口会被不断顺延）
        out[out.length - 1] = { x: nx, bps: speed, t: last.t };
      } else {
        out.push({ x: nx, bps: speed, t: now });
      }
      return out;
    }

    if (!out.length) {
      // 只有“下载已结束”的终态才用平均速度补曲线：轮询间隙内完成的小文件
      // 来不及采到 running 点。paused / error / queued 等首次观测若也补点，
      // 等于虚构从未发生的走势，保持为空交给图表显示「无下载阶段速度记录」。
      if (state !== "done" && state !== "verifying") return out;
      if (active == null || active <= 0) return out;
      const avg = averageSpeed();
      if (!avg) return out;
      const endX = Math.max(hasExplicit ? explicit : active, 1);
      out.push({ x: 0, bps: avg, t: now, est: true });
      out.push({ x: endX, bps: 0, t: now, est: true });
      return out;
    }
    if (out[out.length - 1].bps !== 0) {
      out.push({ x: at(out[out.length - 1]), bps: 0, t: now });
    }
    return out;
  }

  // 速度曲线：`active_ms` 是否已回退到「本轮起点 + 已画到的位置」之前。
  // 崩溃/重启后进行中任务会回退（本轮耗时没入库），手动「重新下载」会直接归零 ——
  // 两者都说明是新的一轮：调用方应清空历史曲线，并把起点重设为当前 active_ms。
  function speedCurveRestarted(activeMs, originMs, lastX) {
    if (activeMs == null || activeMs === "") return false;
    const raw = Number(activeMs);
    if (!Number.isFinite(raw) || raw < 0) return false;
    const last = Number(lastX);
    if (!Number.isFinite(last)) return false;
    const origin = Number(originMs);
    const base = Number.isFinite(origin) && origin >= 0 ? origin : 0;
    return raw + 2000 < base + last;
  }

  // 曲线横轴（相对本轮起点）；拿不到 active_ms 时返回 null，由调用方退回墙钟增量。
  function speedCurveX(activeMs, originMs) {
    if (activeMs == null || activeMs === "") return null;
    const raw = Number(activeMs);
    if (!Number.isFinite(raw) || raw < 0) return null;
    const origin = Number(originMs);
    const base = Number.isFinite(origin) && origin >= 0 ? origin : 0;
    return Math.max(0, raw - base);
  }

  // 列表「速率」列：从速度采样序列取最高速率（忽略 0 / 负数 / 非法点）。
  function peakSpeedBps(series) {
    if (!Array.isArray(series)) return 0;
    let peak = 0;
    for (const point of series) {
      const bps = Number(point && point.bps);
      if (Number.isFinite(bps) && bps > peak) peak = bps;
    }
    return peak;
  }

  // 无峰值采样时的兜底：已下载字节 / 净下载耗时。参数非法或非正返回 0。
  function averageSpeedBps(doneBytes, activeMs) {
    const done = Number(doneBytes);
    const active = Number(activeMs);
    if (!Number.isFinite(done) || done <= 0) return 0;
    if (!Number.isFinite(active) || active <= 0) return 0;
    return (done * 1000) / active;
  }

  // 列表「速率」单元格取值：
  // - downloading：实时速率；
  // - done：优先采样峰值，没有峰值采样才退回平均速率；
  // - 其它状态：none，显示 “—”，不把暂停/失败/排队误标成有速率。
  function listSpeedCell(task, series) {
    const t = task || {};
    if (t.state === "downloading") {
      return { kind: "live", bps: Math.max(0, Number(t.speed) || 0) };
    }
    if (t.state !== "done") return { kind: "none", bps: 0 };
    // 采样序列里可能混有「平均速度估算点」（est，见 speedSampleFromTask），
    // 不能把它们当真实峰值，否则 tooltip 会把平均值伪装成最高速率。
    const real = Array.isArray(series) ? series.filter((p) => !(p && p.est)) : [];
    const peak = peakSpeedBps(real);
    if (peak > 0) return { kind: "peak", bps: peak };
    const avg = averageSpeedBps(t.done, t.active_ms);
    return avg > 0 ? { kind: "average", bps: avg } : { kind: "none", bps: 0 };
  }

  function fileBasename(name) {
    const s = String(name || "");
    const parts = s.split(/[/\\]/);
    return parts[parts.length - 1] || s;
  }

  function fileExtension(name) {
    const base = fileBasename(name);
    const i = base.lastIndexOf(".");
    if (i <= 0 || i === base.length - 1) return "";
    return base.slice(i + 1).toLowerCase();
  }

  function extensionChanged(original, next) {
    return fileExtension(original) !== fileExtension(next);
  }

  function renameCommitDecision(original, typed) {
    const name = String(typed ?? "").trim();
    if (!name) return { action: "empty", error: RENAME_EMPTY, filename: "" };
    if (name === String(original || "")) return { action: "noop", filename: name };
    if (extensionChanged(original, name)) return { action: "confirm", filename: name };
    return { action: "rename", filename: name };
  }

  function renameErrorCode(respOrCode) {
    if (respOrCode && typeof respOrCode === "object") {
      const code = String(respOrCode.code || "").trim();
      if (code) return code;
      return String(respOrCode.error || "").trim();
    }
    return String(respOrCode || "").trim();
  }

  function renameErrorText(respOrCode) {
    const code = renameErrorCode(respOrCode);
    if (code === "invalid_filename") return RENAME_INVALID;
    if (code === "name_taken") return RENAME_TAKEN;
    if (code === "task_not_found") return RENAME_MISSING;
    return RENAME_FAIL;
  }

  function canRenameTask(task, engineOffline) {
    return !!(task && task.id != null && !engineOffline);
  }

  function sourceFieldText(source, referrer, url) {
    if (source === "manual") return T("手动下载");
    const link = String(referrer || url || "").trim();
    if (source === "ext") return link || T("浏览器扩展");
    return link || DASH;
  }

  function connectionsText(task) {
    if (!task) return DASH;
    if (task.p2p) return (Number(task.p2p.active_peers) || 0) + " / " + (Number(task.p2p.max_connections) || 1);
    if (task.mode === "ed2k") return DASH;
    const segs = Array.isArray(task.segments) ? task.segments : [];
    const mode = task.mode;
    if (mode === "single") return "1";
    if (mode === "multi" || segs.length >= 2) {
      const running = segs.filter((s) => s && s.status === "running").length;
      const max = task.max_conns != null && Number(task.max_conns) > 0
        ? Number(task.max_conns)
        : segs.length;
      if (!max) return DASH;
      return running + " / " + max;
    }
    if (mode === "single" || segs.length === 1) return "1";
    return DASH;
  }

  /// 列表中的「源数 + 协议」徽标。eD2k 用正在传输的 peer 数，
  /// HTTP 用切片/连接数；颜色由 UI 的 conn-count / conn-proto 类决定。
  function protocolHint(task) {
    if (!task) return null;
    if (task.p2p || task.mode === "ed2k") {
      return {
        count: Math.max(0, Number(task.p2p && task.p2p.transferring_peers) || 0),
        label: "[eD2k]",
      };
    }
    if (task.mode === "single") return { count: 1, label: "[HTTP]" };
    if (task.mode === "multi") {
      const segs = Array.isArray(task.segments) ? task.segments : [];
      return { count: segs.length, label: "[HTTP]" };
    }
    return null;
  }

  function p2pDetails(task) {
    if (!task || (!task.p2p && task.mode !== "ed2k")) return null;
    const p = task.p2p || {};
    const phases = {
      discovering: T("正在查找下载源"), connecting: T("正在连接下载源"), queued: T("等待对方分配下载位置"),
      downloading: T("正在接收文件"), verifying: T("正在校验文件"), paused: T("已暂停"), done: T("已完成"), waiting: T("等待可用下载源"),
    };
    const n = (key) => Math.max(0, Number(p[key]) || 0);
    const phase = p.phase === "queued" && n("queued_peers") === 0
      ? "waiting" : (p.phase || (task.state === "queued" ? "waiting" : task.state));
    return {
      phase: phases[phase] || T("等待连接"),
      sources: T("候选源 ") + n("known_sources") + T(" · 连接 ") + n("active_peers") + " / " + Math.max(1, n("max_connections")),
      transfers: T("正在传输 ") + n("transferring_peers") + T(" · 对方排队 ") + n("queued_peers")
        + (p.queue_rank == null ? "" : T(" · 最靠前源排位 ") + Math.max(0, Number(p.queue_rank) || 0)),
      pieces: p.verified_parts == null
        ? T("切片共 ") + n("total_parts") + T(" 个")
        : T("已校验 ") + n("verified_parts") + " / " + n("total_parts") + T(" 个切片"),
    };
  }

  function truncateMiddle(text, maxChars) {
    const s = String(text || "");
    if (!s) return DASH;
    const chars = [...s];
    if (chars.length <= maxChars) return s;
    if (maxChars <= 1) return "…";
    const keep = maxChars - 1;
    const head = Math.ceil(keep / 2);
    const tail = Math.max(0, keep - head);
    return chars.slice(0, head).join("") + "…" + (tail ? chars.slice(chars.length - tail).join("") : "");
  }

  /// 超长下载链接的压缩显示：`scheme://主机首段……末尾目录/文件名`。
  ///
  /// 只在超过 `maxChars` 时才动。尾部优先保住**文件名**，再往前带一级目录——
  /// 同一镜像站的不同文件因此仍能一眼区分（`.../x86_64/A-dvd.iso` 与
  /// `.../x86_64/B-dvd.iso` 不会压成同一个样子）。
  /// 把 N 个切片按连接泳道均分：454 个切片、8 条连接 → 每条约 56/57 片。
  /// 只做界面聚合，不改变底层 part 归属。
  function sliceLaneRanges(total, lanes) {
    const n = Math.max(0, Math.floor(Number(total) || 0));
    if (n === 0) return [];
    const count = Math.max(1, Math.min(Math.floor(Number(lanes) || 1), n));
    const out = [];
    for (let i = 0; i < count; i++) {
      const start = Math.floor((i * n) / count);
      const end = Math.floor(((i + 1) * n) / count);
      out.push({ start, end, count: end - start });
    }
    return out;
  }

  function compressUrl(url, maxChars) {
    const s = String(url == null ? "" : url);
    const limit = Math.max(12, Number(maxChars) || 72);
    if (!s) return s;
    if ([...s].length <= limit) return s;
    let u = null;
    try {
      u = new URL(s);
    } catch {
      // 不是合法 URL（少见，但候选列表里可能有奇怪串）：退回通用中间截断。
      return truncateMiddle(s, limit);
    }
    const head = u.protocol + "//" + (u.hostname.split(".")[0] || u.hostname);
    const segs = u.pathname.split("/").filter(Boolean);
    const last = segs.length ? segs[segs.length - 1] : "";
    const tail = segs.slice(-2).join("/");
    if (tail) {
      const withTail = head + "……" + tail;
      if ([...withTail].length <= limit) return withTail;
    }
    // 文件名本身就吃满额度：退到"只保文件名"，再不行才整体中间截断。
    const minimal = head + "……" + last;
    if ([...minimal].length <= limit) return minimal;
    return truncateMiddle(minimal, limit);
  }

  function replaceFilenameInPath(savePath, newName) {
    const name = String(newName || "");
    const path = String(savePath || "");
    if (!path) return name;
    const slash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
    if (slash < 0) return name;
    return path.slice(0, slash + 1) + name;
  }

  function formatTimestamp(v) {
    const ms = toEpochMs(v);
    if (ms == null) return DASH;
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return DASH;
    const pad = (n) => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate())
      + " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function dashOr(value) {
    if (value == null) return DASH;
    const s = String(value).trim();
    return s ? s : DASH;
  }

  /**
   * 已完成任务中「目标文件已不存在」的 id 集合。
   *
   * `doneTasks` 与后端 `paths_exist` 的 `existsFlags` 按下标一一对应：
   * 只有 `state === "done"`、`save_path` 非空、且对应 flag **严格为 false** 才命中。
   * 非数组、缺项、true、非 done、空 path 一律忽略（检测失败时保持现状，不误标灰度）。
   *
   * @param {Array} doneTasks 任务快照（通常先按 done + 有 save_path 过滤）
   * @param {boolean[]} existsFlags 与 doneTasks 等长的存在性标记
   * @returns {Set} 命中的任务 id
   */
  function missingFileIds(doneTasks, existsFlags) {
    const out = new Set();
    if (!Array.isArray(doneTasks) || !Array.isArray(existsFlags)) return out;
    for (let i = 0; i < doneTasks.length; i++) {
      const t = doneTasks[i];
      if (!t || t.state !== "done") continue;
      if (!String(t.save_path == null ? "" : t.save_path).trim()) continue;
      if (existsFlags[i] !== false) continue;
      if (t.id == null) continue;
      out.add(t.id);
    }
    return out;
  }

  /**
   * 弹窗"点遮罩关闭"的判定：**按下与松开都必须发生在遮罩上**。
   *
   * 为什么不能只看 `click` 的 target：当 mousedown 与 mouseup 落在不同元素上时，
   * `click` 会派发到两者的**最近公共祖先**。于是"在弹窗内部按下、移到背景上松开"时
   * `click.target` 恰好就是遮罩 —— 弹窗照样关，用户填到一半的内容一起丢。
   * 六处遮罩（新建下载 / 删除确认 / 设置 / 缺失文件 / 重命名扩展名 / 候选源）共用这一条判定。
   *
   * @param {boolean} downOnMask  mousedown 的目标是不是遮罩本身
   * @param {boolean} clickOnMask click 的目标是不是遮罩本身
   */
  function backdropClickCloses(downOnMask, clickOnMask) {
    return downOnMask === true && clickOnMask === true;
  }

  return {
    KIB,
    FINISH_TIME_HEADER,
    RENAME_EMPTY,
    RENAME_INVALID,
    RENAME_TAKEN,
    RENAME_MISSING,
    RENAME_FAIL,
    RENAME_UNAVAILABLE,
    DASH,
    UNKNOWN_SIZE,
    FILENAME_FALLBACK,
    filenameFromUrl,
    autoFilenameFor,
    shouldSubmitFilename,
    speedSampleFromTask,
    speedCurveRestarted,
    speedCurveX,
    peakSpeedBps,
    averageSpeedBps,
    listSpeedCell,
    formatLimitKbps,
    formatSpeedLimitButton,
    formatSpeedLimitButtonBps,
    remainingSeconds,
    durationSeconds,
    formatRemainingSeconds,
    formatDurationSeconds,
    formatFinishCell,
    formatFinishProps,
    fileBasename,
    fileExtension,
    extensionChanged,
    renameCommitDecision,
    renameErrorCode,
    renameErrorText,
    canRenameTask,
    sourceFieldText,
    connectionsText,
    protocolHint,
    p2pDetails,
    sliceLaneRanges,
    truncateMiddle,
    compressUrl,
    replaceFilenameInPath,
    formatTimestamp,
    missingFileIds,
    // 弹窗"点背景关闭"的判定（见函数注释：为什么不能只看 click 的 target）
    backdropClickCloses,
    dashOr,
  };
});
