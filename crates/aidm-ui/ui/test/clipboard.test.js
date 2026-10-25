"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../lib/clipboard.js");

test("剪贴板候选被取消时上报这批地址（供 Rust 侧抑制窗口使用）", () => {
  const cand = {
    fromClipboard: true,
    addedAny: false,
    clipboardUrls: ["http://x/a.iso", "http://x/b.zip"],
  };
  assert.deepEqual(C.dismissUrls(cand), ["http://x/a.iso", "http://x/b.zip"]);
});

test("已加过任务或不是剪贴板来源时不算「用户不要」", () => {
  assert.deepEqual(
    C.dismissUrls({ fromClipboard: true, addedAny: true, clipboardUrls: ["http://x/a.iso"] }),
    []
  );
  assert.deepEqual(
    C.dismissUrls({ fromClipboard: false, addedAny: false, clipboardUrls: ["http://x/a.iso"] }),
    []
  );
  assert.deepEqual(C.dismissUrls(null), []);
  assert.deepEqual(C.dismissUrls(undefined), []);
  assert.deepEqual(C.dismissUrls({ fromClipboard: true, addedAny: false }), []);
});

test("地址去重、去空白，空项与非字符串被丢弃", () => {
  const cand = {
    fromClipboard: true,
    addedAny: false,
    clipboardUrls: [" http://x/a.iso ", "http://x/a.iso", "", "   ", 42, null, "http://x/b.zip"],
  };
  assert.deepEqual(C.dismissUrls(cand), ["http://x/a.iso", "http://x/b.zip"]);
});

test("合并新命中只返回真正新增的地址（保序、去重、去空）", () => {
  assert.deepEqual(
    C.newUrls(["http://x/a.iso"], ["http://x/a.iso", "http://x/b.zip", " http://x/b.zip ", ""]),
    ["http://x/b.zip"]
  );
  assert.deepEqual(C.newUrls([], ["http://x/a.iso"]), ["http://x/a.iso"]);
  assert.deepEqual(C.newUrls(["http://x/a.iso"], []), []);
  assert.deepEqual(C.newUrls(null, null), []);
  assert.deepEqual(C.newUrls(["http://x/a.iso"], ["http://x/a.iso"]), []);
});
