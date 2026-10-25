// 设置表单的纯逻辑：与 DOM 无关，便于 node:test 直接覆盖。
//
// 这里的每条规则都必须和引擎侧的声明式设置表（`aidm-core::setting_spec`）
// 对齐；`validateWithSchema` 更直接：把引擎通过 `settings_schema` 下发的
// 类型/区间/枚举拿来校验表单值，UI 不再硬编码范围（硬编码是双份事实源，
// 正是这次架构整理要消灭的东西）。
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AidmSettingsForm = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  const T = function (key, vars) {
    const api = root && root.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  };
  /// ISO 星期：1=周一 … 7=周日。空 / 非法 → 全周。
  function normalizeDays(raw) {
    const seen = new Set();
    for (const part of String(raw == null ? "" : raw).split(/[,，;；\s]+/)) {
      const n = Number(part);
      if (Number.isInteger(n) && n >= 1 && n <= 7) seen.add(n);
    }
    if (seen.size === 0) [1, 2, 3, 4, 5, 6, 7].forEach((n) => seen.add(n));
    return [...seen].sort((a, b) => a - b).join(",");
  }

  /// 主机/URL 模式清单 → 规范 CSV。与 `settings::parse_host_list` 同规则：
  /// 去掉协议头与路径、保留 `*.` 通配、小写、去重。
  function parseHostListInput(raw) {
    const out = [];
    for (const part of String(raw == null ? "" : raw).split(/[,，;；\s]+/)) {
      let h = part.trim().toLowerCase();
      if (!h) continue;
      h = h.replace(/^https?:\/\//, "");
      h = h.split("/")[0];
      h = h.split(":")[0];
      h = h.replace(/\.+$/, "");
      if (!h) continue;
      if (!/^(\*\.)?[a-z0-9._-]+$/.test(h)) return null;
      if (!out.includes(h)) out.push(h);
    }
    return out.join(",");
  }

  /// 扩展名清单 → 规范 CSV（小写、去点、去重）。
  function parseExtListInput(raw) {
    const out = [];
    for (const part of String(raw == null ? "" : raw).split(/[,，;；\s]+/)) {
      const e = part.trim().replace(/^\./, "").toLowerCase();
      if (!e) continue;
      if (!/^[a-z0-9*_-]{1,32}$/.test(e)) return null;
      if (!out.includes(e)) out.push(e);
    }
    return out.join(" ");
  }

  /// 分类目录 JSON：必须是「字符串 → 非空字符串」的对象。
  function normalizeCategoryDirs(raw) {
    const text = String(raw == null ? "" : raw).trim();
    if (!text) return "{}";
    let obj;
    try {
      obj = JSON.parse(text);
    } catch (_) {
      return null;
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      const key = String(k).trim().replace(/^\./, "").toLowerCase();
      const val = String(v == null ? "" : v).trim();
      if (!key || !val) return null;
      out[key] = val;
    }
    return JSON.stringify(out);
  }

  /// 本地路径 → file:// URL（提示音播放用）。
  ///
  /// 盘符里的冒号不能编码（否则 webview 不认 `C%3A`），空格必须编码。
  function pathToFileUrl(p) {
    const s = String(p == null ? "" : p).replace(/\\/g, "/");
    if (!s) return s;
    if (/^[a-zA-Z]:/.test(s)) {
      const drive = s[0].toUpperCase();
      const rest = s.slice(2).split("/").filter((x) => x !== "");
      return `file:///${drive}:/` + rest.map(encodeURIComponent).join("/");
    }
    if (s.startsWith("/")) {
      return "file://" + s.split("/").map(encodeURIComponent).join("/");
    }
    return encodeURI(s);
  }

  function settingKind(schema, key) {
    if (!Array.isArray(schema)) return null;
    const hit = schema.find((s) => s && s.key === key);
    return hit || null;
  }

  /// 用引擎下发的 schema 校验一个值。
  ///
  /// 返回 `null` 表示通过；否则返回错误码（与引擎 `SettingError.code` 同名），
  /// 这样 UI 文案表可以共用一套映射。
  function validateWithSchema(schema, key, value) {
    const spec = settingKind(schema, key);
    if (!spec) return null; // 没拿到 schema 就不拦（引擎仍会校验）
    const v = String(value == null ? "" : value);
    const trim = v.trim();
    switch (spec.kind) {
      case "bool":
        return trim === "true" || trim === "false" ? null : "bool_invalid";
      case "int":
      case "nonneg": {
        if (!/^\d+$/.test(trim)) {
          return spec.kind === "nonneg" ? "speed_limit_invalid" : "invalid_value";
        }
        const n = Number(trim);
        if (spec.kind === "nonneg") return n >= 0 ? null : "speed_limit_invalid";
        if (typeof spec.min === "number" && n < spec.min) return "invalid_value";
        if (typeof spec.max === "number" && n > spec.max) return "invalid_value";
        return null;
      }
      case "enum": {
        const values = Array.isArray(spec.values) ? spec.values : [];
        const ok = values.some((x) => String(x).toLowerCase() === trim.toLowerCase());
        return ok ? null : spec.key === "proxy.mode" ? "proxy_mode_invalid" : "invalid_value";
      }
      case "clock":
        return /^([01]?\d|2[0-3]):[0-5]\d$/.test(trim) ? null : "clock_invalid";
      case "weekdays":
        return normalizeDays(trim) ? null : "weekdays_invalid";
      case "host_list":
        return parseHostListInput(trim) === null ? "hosts_invalid" : null;
      case "ext_list":
        return parseExtListInput(trim) === null ? "exts_invalid" : null;
      case "json_map":
        return normalizeCategoryDirs(trim) === null ? "category_dirs_invalid" : null;
      default:
        return null;
    }
  }

  /// 把表单值整理成引擎期望的规范形式（校验通过后调用）。
  function canonicalize(key, value) {
    switch (key) {
      case "sched.window_days":
        return normalizeDays(value);
      case "proxy.bypass_hosts":
      case "browser.exclude_hosts":
      case "browser.panel_exclude_hosts": {
        const v = parseHostListInput(value);
        return v === null ? String(value) : v;
      }
      case "browser.auto_catch_exts":
      case "browser.panel_exts": {
        const v = parseExtListInput(value);
        return v === null ? String(value) : v;
      }
      case "paths.category_dirs": {
        const v = normalizeCategoryDirs(value);
        return v === null ? String(value) : v;
      }
      default:
        return value;
    }
  }

  // 自定义请求头校验：与引擎 aidm-core/src/headers.rs 同一套规则，
  // 这样界面能把错误指到具体行，而不是等引擎回一个笼统错误码。
  const MANAGED_HEADERS = new Set([
    "host", "range", "content-length", "transfer-encoding", "connection",
    "proxy-authorization", "proxy-connection", "te", "trailer", "upgrade",
    "cookie", "cookie2", "user-agent", "referer", "accept-encoding",
    "accept-charset", "accept-language", "accept",
  ]);
  const HEADER_LIMITS = { max: 32, name: 64, value: 2048 };
  const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

  function validateCustomHeaders(raw) {
    const text = String(raw == null ? "" : raw);
    const seen = new Set();
    let count = 0;
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      if (count >= HEADER_LIMITS.max) {
        return { ok: false, text: `最多 ${HEADER_LIMITS.max} 个请求头` };
      }
      const at = trimmed.indexOf(":");
      if (at < 0) {
        return { ok: false, text: `第 ${i + 1} 行缺少冒号（应为「名称: 值」）` };
      }
      const name = trimmed.slice(0, at).trim();
      const value = trimmed.slice(at + 1).trim();
      if (!name) return { ok: false, text: `第 ${i + 1} 行名称为空` };
      if (!TOKEN_RE.test(name)) {
        return { ok: false, text: `第 ${i + 1} 行名称含非法字符：${name}` };
      }
      if (/[\u0000-\u001f\u007f]/.test(name) || /[\u0000-\u001f\u007f]/.test(value)) {
        return { ok: false, text: `第 ${i + 1} 行含控制字符` };
      }
      if (name.length > HEADER_LIMITS.name || value.length > HEADER_LIMITS.value) {
        return { ok: false, text: `第 ${i + 1} 行过长` };
      }
      const lower = name.toLowerCase();
      if (MANAGED_HEADERS.has(lower)) {
        return { ok: false, text: `第 ${i + 1} 行「${name}」由程序管理，不能自定义` };
      }
      if (seen.has(lower)) continue;
      seen.add(lower);
      count++;
    }
    return { ok: true, count };
  }

  // 备用地址（镜像）校验：与引擎 aidm-ipc/src/validate.rs 的 validate_alt_urls 同一套规则，
  // 界面先把错指到具体条目，而不是等引擎回一个笼统错误码。
  // 只认 HTTP(S)：FTP 的备用地址要另一套登录/续传语义，eD2k/BT 走各自的源发现。
  const ALT_URLS_MAX = 8;
  const ALT_URL_MAX = 8 * 1024;

  function isHttpUrlForAlt(url) {
    for (const scheme of ["https://", "http://"]) {
      if (url.toLowerCase().startsWith(scheme)) {
        const rest = url.slice(scheme.length);
        return rest.length > 0 && !"/?#".includes(rest[0]);
      }
    }
    return false;
  }

  function validateAltUrls(raw) {
    const text = String(raw == null ? "" : raw);
    let count = 0;
    for (const rawLine of text.split(/\r?\n/)) {
      // 整行注释：`#` 后面可以跟空格与说明文字（按空白切分会把说明文字当成地址）。
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      for (const item of line.split(/\s+/)) {
        if (!item) continue;
        count++;
        if (count > ALT_URLS_MAX) {
          return { ok: false, text: `最多 ${ALT_URLS_MAX} 个备用地址` };
        }
        if (item.length > ALT_URL_MAX) return { ok: false, text: "备用地址过长" };
        if (/[\u0000-\u001f\u007f]/.test(item)) {
          return { ok: false, text: "备用地址含控制字符" };
        }
        if (!isHttpUrlForAlt(item)) {
          return { ok: false, text: `备用地址必须是完整的 http:// 或 https:// 地址：${item}` };
        }
      }
    }
    return { ok: true, count };
  }

  return {
    normalizeDays,
    validateCustomHeaders,
    validateAltUrls,
    parseHostListInput,
    parseExtListInput,
    normalizeCategoryDirs,
    pathToFileUrl,
    settingKind,
    validateWithSchema,
    canonicalize,
  };
});
