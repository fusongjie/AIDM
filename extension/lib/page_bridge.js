// 隔离世界桥：把 MAIN world 提取到的下载地址转给 service worker。
// 只接受同窗口的固定消息形状，避免页面脚本随意触发其它扩展消息。
(function () {
  if (window.__aidmPageBridge) return;
  window.__aidmPageBridge = true;

  window.addEventListener("message", function (event) {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "aidm-page-hook" || data.type !== "api-download") return;
    if (typeof data.url !== "string" || !/^https?:\/\//i.test(data.url)) return;
    try {
      chrome.runtime.sendMessage({
        type: "page-api-download",
        url: data.url,
        filename: typeof data.filename === "string" ? data.filename : "",
        size: Number(data.size) || 0,
        referer: typeof data.referer === "string" ? data.referer : location.href,
      });
    } catch {
      /* service worker 已重启/不可用：忽略，页面下载继续 */
    }
  });
})();
