const engineEl = document.getElementById("engine");
const activeEl = document.getElementById("active");
const msgEl = document.getElementById("msg");
const btn = document.getElementById("collect");

function showMsg(text) {
  if (!text) {
    msgEl.hidden = true;
    msgEl.textContent = "";
    return;
  }
  msgEl.hidden = false;
  msgEl.textContent = text;
}

function refreshStatus() {
  chrome.runtime.sendMessage({ type: "status" }, (resp) => {
    if (chrome.runtime.lastError) {
      engineEl.textContent = "未知";
      activeEl.textContent = "—";
      showMsg("扩展未就绪，请重新打开此窗口");
      return;
    }
    if (!resp) {
      engineEl.textContent = "未知";
      activeEl.textContent = "—";
      showMsg("未连接到 AIDM，请先打开 AIDM");
      return;
    }
    if (resp.classified && (resp.classified.type === "disconnected" || resp.classified.type === "unknown")) {
      engineEl.textContent = "离线";
      activeEl.textContent = String(resp.active ?? "—");
      showMsg("未连接到 AIDM，请先打开 AIDM");
      return;
    }
    const online = !!resp.engine_online;
    engineEl.textContent = online ? "在线" : "离线";
    activeEl.textContent = String(resp.active ?? "—");
    if (!online) showMsg("AIDM 引擎未运行");
    else showMsg("");
  });
}

btn.addEventListener("click", () => {
  btn.disabled = true;
  showMsg("");
  chrome.runtime.sendMessage({ type: "offer" }, (resp) => {
    btn.disabled = false;
    if (chrome.runtime.lastError) {
      showMsg("扩展未就绪，请重新打开此窗口");
      return;
    }
    if (!resp) {
      showMsg("无法交给 AIDM，请稍后重试");
      return;
    }
    if (resp.message) showMsg(resp.message);
    else if (resp.offer_id) showMsg("已交给 AIDM，请在主窗口勾选。");
    else showMsg("");
  });
});

/// 「按住时不接管 / 强制接管」能不能在这个页面生效，以及上一次点右键时扩展
/// 究竟看到了什么。
///
/// 这两个键靠常驻 content script 记录，而 content script 只在页面加载时注入。
/// 失败时对外表现完全一样（都静默当 default），所以这里把原始事实摊开：
/// 上次查询拿到的按键、判定结果、以及当前设定值。
function refreshHotkey() {
  const el = document.getElementById("hotkey");
  chrome.runtime.sendMessage({ type: "hotkey-probe" }, (probeResp) => {
    const probe = probeResp && probeResp.probe;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs && tabs[0];
      if (!tab || tab.id == null) {
        el.textContent = "不可用";
        el.title = "读不到当前标签页。";
        return;
      }
      chrome.tabs.sendMessage(tab.id, { type: "hotkey-state" }, { frameId: 0 }, (resp) => {
        const err = chrome.runtime.lastError ? chrome.runtime.lastError.message : null;
        if (err || !resp || !resp.mods) {
          el.textContent = "需要刷新页面";
          el.title =
            "这个页面里还没有 AIDM 的按键脚本。按 F5 刷新一次即可；" +
            "之后按住设定键点右键就能生效。" +
            (err ? "（" + err + "）" : "");
          return;
        }
        const heldNow = Object.keys(resp.mods).filter((k) => resp.mods[k]);
        if (!probe) {
          el.textContent = heldNow.length ? "已按住 " + heldNow.join("+") : "可用";
          el.title = "还没记录到带按键的操作。按住设定键点一次链接（或右键），再打开这里看判定结果。";
          return;
        }
        const heldThen = probe.mods ? Object.keys(probe.mods).filter((k) => probe.mods[k]) : [];
        const fromLabel =
          { gesture: "点击手势", menu: "右键菜单", click: "点击链接", live: "实时查询" }[probe.from] ||
          "未知来源";
        el.textContent =
          (heldNow.length ? "已按住 " + heldNow.join("+") : "可用") + " · 上次判定 " + probe.decision;
        el.title =
          "设定：不接管=" + (probe.prevent || "未设置") + "，强制接管=" + (probe.force || "未设置") + "\n" +
          "上次操作（" + fromLabel + "）时检测到：[" + (heldThen.join("+") || "无") + "] → 判定 " + probe.decision + "\n" +
          "现在检测到：[" + (heldNow.join("+") || "无") + "]";
      });
    });
  });
}

refreshStatus();
refreshHotkey();
