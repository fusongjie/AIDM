/* global aidmLogic */
// 悬浮下载状态：页面右下角的 AIDM 圆钮。
//
// 交互契约：
//   - 鼠标移入圆钮/提示条：显示当前下载任务；没有任务时显示「当前无下载任务」。
//   - 鼠标移出：立即隐藏提示。
//   - 下载进度自动冒泡：开始/结束时出现一次，3 秒后渐隐、再过 2 秒完全隐藏。
//     下载期间每秒一次的进度推送**只更新文字**，不重置计时器——否则提示会永久
//     常驻在页面上（这正是「自动消隐丢失」的根因）。
//   - 点击圆钮：拉起桌面版 AIDM 主窗口并置于屏幕顶层（未运行则启动）。
//
// 只受两个设置影响：`browser.panel_enabled`（总开关）与
// `browser.panel_exclude_hosts`（这些服务器上完全不显示）。
//
// 悬浮 UI 挂在 Shadow DOM 里：页面样式影响不到它，它也影响不到页面。
// 只在顶层文档运行——iframe 里再挂一个只会互相打架。
(() => {
  if (window.top !== window.self) return;

  const HOST_ID = "aidm-panel-host";
  // 顶到 int32 上限附近：页面自己也有 fixed 元素，别被它们盖住。
  const Z_INDEX = 2147483000;
  // 自动提示的寿命：先保持 3 秒，再用 2 秒渐隐。
  const HOLD_MS = 3000;
  const FADE_MS = 2000;

  let settings = null;
  let shadow = null;
  let wrapEl = null;
  let statusEl = null;
  let statusTextEl = null;
  let statusTimer = 0;
  let statusHideTimer = 0;
  // 鼠标是否停在悬浮 UI 上：停住时提示不自动消失。
  let pinned = false;
  // 最近一次自动提示。悬停瞬间先回显它，避免等待后台回包时出现空档。
  let lastStatus = null;

  function ask(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (resp) => {
          // 读掉 lastError，否则扩展控制台会刷 "Unchecked runtime.lastError"
          void chrome.runtime.lastError;
          resolve(resp || null);
        });
      } catch {
        resolve(null);
      }
    });
  }

  function fmtMB(bytes) {
    return String(Math.round((Number(bytes) || 0) / (1024 * 1024)));
  }

  /// 提示条的文案。`state` 由后台或本地产生：
  /// idle（无任务）/ loading（查询中）/ notice（一次性提示）/ took / gone /
  /// downloading / done。
  function statusLine(p) {
    if (!p) return "";
    if (p.state === "idle") return "当前无下载任务";
    if (p.state === "loading") return "正在读取下载状态…";
    if (p.state === "notice") return String(p.text || "");
    const name = p.name || "下载";
    if (p.state === "took") return "已交给 AIDM：" + name;
    if (p.state === "gone") return "已结束：" + name;
    const size =
      p.total == null ? fmtMB(p.done) + "MB" : fmtMB(p.done) + "/" + fmtMB(p.total) + "MB";
    const secs = Number(p.elapsed) || 0;
    if (p.state === "done") {
      return "下载完成：" + size + " | " + name + "【用时 " + secs + "s】";
    }
    return "正在下载 " + size + " | " + name + " | 【" + secs + "s】";
  }

  function clearTimers() {
    window.clearTimeout(statusTimer);
    window.clearTimeout(statusHideTimer);
    statusTimer = 0;
    statusHideTimer = 0;
  }

  function fadeOut() {
    if (!statusEl || pinned) return;
    statusEl.classList.add("fading");
    window.clearTimeout(statusHideTimer);
    statusHideTimer = window.setTimeout(() => {
      if (statusEl && !pinned) statusEl.classList.add("hidden");
    }, FADE_MS);
  }

  function scheduleFade() {
    clearTimers();
    statusTimer = window.setTimeout(fadeOut, HOLD_MS);
  }

  function hideNow() {
    clearTimers();
    if (!statusEl) return;
    statusEl.classList.add("hidden");
    statusEl.classList.remove("fading");
  }

  function ensureStatus() {
    if (statusEl || !wrapEl) return;
    statusEl = document.createElement("div");
    statusEl.className = "status hidden";
    // 文本与圆点分开建：文件名是外部数据，走 textContent 才不会带进标记。
    statusTextEl = document.createElement("span");
    statusTextEl.className = "txt";
    const dot = document.createElement("span");
    dot.className = "dot";
    statusEl.append(statusTextEl, dot);
    wrapEl.appendChild(statusEl);
  }

  /// 显示/更新提示条。
  ///
  /// `force`：鼠标悬停触发（立即显示、不计时、不自动消失）。
  /// 非 force 的更新来自后台每秒一次的进度推送；是否复活/重置计时由
  /// `aidmLogic.panelStatusAction` 统一判定（单测守着「自动消隐」这条回归）。
  function showStatus(p, opts) {
    if (!wrapEl || !p) return;
    const force = !!(opts && opts.force);
    ensureStatus();
    const wasHidden =
      statusEl.classList.contains("hidden") || statusEl.classList.contains("fading");
    const action = aidmLogic.panelStatusAction({
      wasHidden,
      pinned,
      state: p.state,
      force,
    });
    if (action === "ignore") return;
    lastStatus = p;
    statusTextEl.textContent = statusLine(p);
    statusEl.classList.toggle("breathing", p.state === "downloading");
    statusEl.classList.remove("hidden");
    if (action === "show-pinned") {
      pinned = true;
      clearTimers();
      statusEl.classList.remove("fading");
      return;
    }
    if (action === "show-auto") {
      // 新冒泡（下载开始 / 完成 / 已接管）：重新给满 HOLD。
      statusEl.classList.remove("fading");
      if (!pinned) scheduleFade();
    }
    // `update`：只换文字，计时器保持原样，到期照常渐隐。
  }

  /// 鼠标进入：立即显示当前任务。先回显最近一次进度，再向后台要权威状态——
  /// 页面刷新后后台可能正在跟踪另一个标签页的任务，本地缓存不一定准。
  async function onPointerEnter() {
    pinned = true;
    clearTimers();
    const quick =
      lastStatus && lastStatus.state === "downloading" ? lastStatus : { state: "loading" };
    showStatus(quick, { force: true });
    const resp = await ask({ type: "panel-status" });
    if (!pinned) return;
    const task = resp && resp.task;
    showStatus(
      task || { state: "notice", text: "无法获取下载状态，请刷新页面后重试" },
      { force: true }
    );
  }

  /// 鼠标离开：按需求立即隐藏，不做淡出。
  function onPointerLeave() {
    pinned = false;
    hideNow();
  }

  async function onFabClick(fab) {
    if (fab.dataset.busy === "1") return;
    fab.dataset.busy = "1";
    const resp = await ask({ type: "open-aidm" });
    fab.dataset.busy = "";
    if (resp && resp.ok) return;
    // 失败原因直接显示在提示条里；鼠标还停在按钮上，因此会保持到移开。
    showStatus(
      { state: "notice", text: (resp && resp.message) || "无法启动 AIDM，请手动打开主程序" },
      { force: true }
    );
  }

  function styleText() {
    return `
      .wrap { display: flex; flex-direction: column-reverse; align-items: flex-end;
              gap: 10px; font: 13px/1.45 system-ui, "Segoe UI", "Microsoft YaHei", sans-serif;
              color: #1f2328; }
      .fab { width: 44px; height: 44px; border: 0; border-radius: 50%; cursor: pointer;
             background: #2459F5; color: #fff; font-size: 15px; font-weight: 700;
             display: flex; align-items: center; justify-content: center; padding: 0;
             overflow: hidden; box-shadow: 0 4px 14px rgba(0,0,0,.25); }
      .fab svg { width: 32px; height: 32px; display: block; pointer-events: none; }
      .fab:hover { background: #1d4ed8; }
      .status { width: 330px; padding: 8px 10px; border-radius: 8px; background: #fff;
                border: 1px solid #d0d7de; box-shadow: 0 6px 20px rgba(0,0,0,.18);
                font-size: 12px; line-height: 1.5; color: #1f2328;
                opacity: 1; transition: opacity 2s ease; word-break: break-all; }
      .status.fading { opacity: 0; }
      .status.hidden { display: none; }
      .status .dot { display: inline-block; width: 8px; height: 8px; margin-left: 6px;
                     border-radius: 50%; background: #1f883d; vertical-align: middle; }
      .status.breathing .dot { animation: aidm-breathe 1.6s ease-in-out infinite; }
      @keyframes aidm-breathe {
        0%, 100% { opacity: .3; transform: scale(.8); }
        50%      { opacity: 1;  transform: scale(1.2); }
      }
    `;
  }

  function mount() {
    if (document.getElementById(HOST_ID)) return;
    const host = document.createElement("div");
    host.id = HOST_ID;
    host.style.cssText =
      "position:fixed;right:16px;bottom:16px;z-index:" + Z_INDEX + ";";
    shadow = host.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = styleText();

    wrapEl = document.createElement("div");
    wrapEl.className = "wrap";

    const fab = document.createElement("button");
    fab.type = "button";
    fab.className = "fab";
    // 内联 SVG：不依赖 web_accessible_resources，页面里不会出现失败图片。
    // 路径取自 AIDM 最新应用图标（流速蓝：白色 A + 下载箭头）。
    fab.innerHTML =
      '<svg viewBox="0 0 100 100" aria-hidden="true" focusable="false">' +
      '<path fill="#fff" fill-rule="evenodd" d="M10 82 43 18H62L90 82H69L64 68H37L30 82ZM45 51H58L52 33Z"/>' +
      '<path fill="#fff" d="M39 76H61L50 90Z"/>' +
      "</svg>";
    fab.title = "AIDM：查看下载任务 / 打开主程序";
    fab.addEventListener("click", () => {
      onFabClick(fab).catch(() => {
        /* 悬浮 UI 是锦上添花，异常不影响页面 */
      });
    });
    wrapEl.appendChild(fab);

    wrapEl.addEventListener("mouseenter", () => {
      onPointerEnter().catch(() => {});
    });
    wrapEl.addEventListener("mouseleave", onPointerLeave);

    shadow.append(style, wrapEl);
    (document.body || document.documentElement).appendChild(host);
  }

  async function boot() {
    const resp = await ask({ type: "panel-settings" });
    if (!resp || !resp.settings) return;
    settings = resp.settings;
    if (!settings.panelEnabled) return;
    // 排除表命中：这个站上完全不冒泡（连按钮都不出现）。
    if (aidmLogic.panelHostExcluded(settings, location.href)) return;
    mount();
  }

  function whenDomReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
    } else {
      fn();
    }
  }

  // 进度与接管结果都由 background 推来：它才是能问到 AIDM 状态的一方。
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg) return;
    if (msg.type === "aidm-progress") {
      showStatus(msg);
    } else if (msg.type === "aidm-took-over") {
      // 拿不到任务 id 时（问不到进度）至少给个"已收到"的反馈。
      showStatus({ state: "took", name: msg.filename || "", elapsed: 0 });
    }
  });

  whenDomReady(() => {
    boot().catch(() => {
      /* 面板是锦上添花，任何异常都不该影响页面 */
    });
  });
})();
