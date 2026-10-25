// AIDM 国际化引擎（自研，零依赖）。
//
// 设计依据 `05_product_doc/AIDM_i18n_语言机制规格.md`：
// - 语言包以 `code` 注册，缺失键先回退 `fallback`，再原样返回键名（便于发现漏译）；
// - 热切换是「整表替换 + 广播」，不做逐键合并，避免半加载状态；
// - `apply()` 只替换元素的**文本节点**，保留 SVG 图标等子元素；
// - 占位符用具名大括号 `{name}`，禁止位置序号。
(function (root, factory) {
  const api = factory();
  root.AidmI18n = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  const packs = Object.create(null);
  let current = "zh-CN";
  let fallback = "en-US";
  const warned = new Set();
  const listeners = [];

  function register(code, pkg) {
    if (!code || !pkg || !pkg.strings) return false;
    packs[code] = pkg;
    if (pkg.meta && pkg.meta.fallback) fallback = pkg.meta.fallback;
    return true;
  }

  function lookup(code, key) {
    const p = packs[code];
    if (!p) return undefined;
    const v = p.strings[key];
    return typeof v === "string" ? v : undefined;
  }

  function interpolate(text, vars) {
    if (!vars) return text;
    return text.replace(/\{(\w+)\}/g, function (m, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : m;
    });
  }

  function warnOnce(key) {
    if (warned.has(key)) return;
    warned.add(key);
    if (typeof console !== "undefined" && console.warn) {
      console.warn("[i18n] missing key:", key);
    }
  }

  function t(key, vars) {
    if (!key) return "";
    const direct = lookup(current, key);
    if (direct != null) return interpolate(direct, vars);
    const fb = lookup(fallback, key);
    if (fb != null) {
      warnOnce(key);
      return interpolate(fb, vars);
    }
    warnOnce(key);
    return key;
  }

  // 只替换文本节点：`<button data-i18n><svg/>新建下载</button>` 不会丢掉图标。
  function setText(el, text) {
    let replaced = false;
    for (const node of Array.from(el.childNodes)) {
      if (node.nodeType === 3 && String(node.nodeValue).trim() !== "") {
        node.nodeValue = text;
        replaced = true;
      }
    }
    if (!replaced) el.appendChild((el.ownerDocument || document).createTextNode(text));
  }

  function apply(scopeEl) {
    const scope = scopeEl || (typeof document !== "undefined" ? document : null);
    if (!scope || !scope.querySelectorAll) return;
    for (const el of scope.querySelectorAll("[data-i18n]")) {
      setText(el, t(el.getAttribute("data-i18n")));
    }
    for (const el of scope.querySelectorAll("[data-i18n-title]")) {
      el.title = t(el.getAttribute("data-i18n-title"));
    }
    for (const el of scope.querySelectorAll("[data-i18n-placeholder]")) {
      el.placeholder = t(el.getAttribute("data-i18n-placeholder"));
    }
    for (const el of scope.querySelectorAll("[data-i18n-aria]")) {
      el.setAttribute("aria-label", t(el.getAttribute("data-i18n-aria")));
    }
    for (const el of scope.querySelectorAll("[data-i18n-placeholder]")) {
      el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
    }
  }

  function setLanguage(code) {
    if (!packs[code] || code === current) return false;
    current = code;
    apply();
    for (const fn of listeners) {
      try {
        fn(code);
      } catch (e) {
        if (typeof console !== "undefined") console.warn("[i18n] listener failed", e);
      }
    }
    return true;
  }

  function onLanguageChange(fn) {
    if (typeof fn === "function") listeners.push(fn);
  }

  function init(opts) {
    const o = opts || {};
    if (o.lng && packs[o.lng]) current = o.lng;
    else if (!packs[current]) {
      const first = Object.keys(packs)[0];
      if (first) current = first;
    }
    warned.clear();
    apply();
    return current;
  }

  function available() {
    return Object.keys(packs).map(function (code) {
      const meta = packs[code].meta || {};
      return { code: code, name: meta.name || code };
    });
  }

  function language() {
    return current;
  }

  return {
    register: register,
    init: init,
    t: t,
    apply: apply,
    setLanguage: setLanguage,
    onLanguageChange: onLanguageChange,
    available: available,
    language: language,
  };
});
