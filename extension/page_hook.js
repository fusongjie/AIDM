// 运行在页面 MAIN world：监听站点自己的 API 响应，提取真实下载地址。
// 只通过 window.postMessage 交给隔离世界的 page_bridge.js，不直接访问扩展 API。
(function () {
  if (window.__aidmPageHook) return;
  window.__aidmPageHook = true;

  const seen = new Set();
  const API_RE = /\/api\/v2\/download(?:\?|$)/;

  function emit(sourceUrl, text) {
    try {
      const json = JSON.parse(text);
      const data = json && json.data;
      if (!data || !data.downurl) return;
      const url = String(data.downurl);
      if (!/^https?:\/\//i.test(url) || seen.has(url)) return;
      seen.add(url);
      window.postMessage(
        {
          source: "aidm-page-hook",
          type: "api-download",
          url,
          filename: data.file_name ? String(data.file_name) : "",
          size: Number(data.file_size) || 0,
          referer: sourceUrl || location.href,
        },
        "*"
      );
    } catch {
      /* 不是目标 JSON，忽略 */
    }
  }

  try {
    const origFetch = window.fetch;
    if (typeof origFetch === "function") {
      window.fetch = function (input, init) {
        const p = origFetch.apply(this, arguments);
        try {
          const url = typeof input === "string" ? input : (input && input.url) || "";
          if (API_RE.test(url)) {
            p.then((resp) => {
              resp
                .clone()
                .text()
                .then((text) => emit(url, text))
                .catch(() => {});
            }).catch(() => {});
          }
        } catch {
          /* 不干扰原请求 */
        }
        return p;
      };
    }
  } catch {}

  try {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__aidmUrl = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      const xhr = this;
      xhr.addEventListener("load", function () {
        try {
          const url = String(xhr.__aidmUrl || "");
          if (!API_RE.test(url)) return;
          const type = xhr.responseType;
          const text =
            type === "" || type === "text"
              ? xhr.responseText
              : type === "json"
                ? JSON.stringify(xhr.response)
                : null;
          if (text) emit(url, text);
        } catch {}
      });
      return origSend.apply(this, arguments);
    };
  } catch {}
})();
