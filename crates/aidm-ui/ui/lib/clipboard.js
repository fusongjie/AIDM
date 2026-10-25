// 剪贴板候选框的纯逻辑：关闭窗口时要不要把"这批地址"上报为「用户不要」。
// 与 Rust 侧的 aidm_core::clipboard_policy::PromptDecider::dismiss 对齐（决定在那边生效，
// 这里只负责产出该上报的地址集合）。无 DOM / 无网络，可 node --test 直接跑。
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AidmClipboard = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  const T = function (key, vars) {
    const api = root && root.AidmI18n;
    return api && typeof api.t === "function" ? api.t(key, vars) : key;
  };
  /// 只保留非空字符串地址，并去重（同一地址重复出现只报一次）。
  function usableUrls(list) {
    if (!Array.isArray(list)) return [];
    const seen = new Set();
    const out = [];
    for (const u of list) {
      if (typeof u !== "string") continue;
      const trimmed = u.trim();
      if (!trimmed || seen.has(trimmed)) continue;
      seen.add(trimmed);
      out.push(trimmed);
    }
    return out;
  }

  /// 关闭候选框时应抑制的地址。
  ///
  /// 返回空数组 = 「这次不算取消」，三种情况：
  /// * 不是剪贴板来源（网页/扩展来的候选与剪贴板抑制无关）；
  /// * 这次已经往任务里加过（用户要了，不是"不要"）；
  /// * 没有可用地址。
  function dismissUrls(cand) {
    if (!cand || !cand.fromClipboard) return [];
    if (cand.addedAny) return [];
    return usableUrls(cand.clipboardUrls);
  }

  /// 在已有地址之外**真正新增**的地址（去重、去空、保序）。
  ///
  /// 用于"候选框已经打开时又收到同一来源的新命中"：只追加新区，
  /// 不清掉用户已经输入的搜索词、勾选和保存目录。
  function newUrls(existingUrls, incomingUrls) {
    const known = new Set(usableUrls(existingUrls));
    const out = [];
    for (const u of usableUrls(incomingUrls)) {
      if (known.has(u)) continue;
      known.add(u);
      out.push(u);
    }
    return out;
  }

  return { dismissUrls: dismissUrls, usableUrls: usableUrls, newUrls: newUrls };
});
