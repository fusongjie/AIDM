"use strict";
// i18n 引擎的纯逻辑测试：缺失键回退、占位符、热切换、DOM 替换保留子元素。

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadEngine() {
  const code = fs.readFileSync(path.join(__dirname, "..", "lib", "i18n.js"), "utf8");
  const sandbox = { console: { warn() {} } };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  return sandbox.AidmI18n;
}

function fakeEl(attrs, text) {
  const node = {
    attrs: Object.assign({}, attrs),
    title: "",
    placeholder: "",
    childNodes: [],
    ownerDocument: { createTextNode: (t) => ({ nodeType: 3, nodeValue: t }) },
    getAttribute(k) {
      return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null;
    },
    setAttribute(k, v) {
      this.attrs[k] = v;
    },
    appendChild(n) {
      this.childNodes.push(n);
    },
    text() {
      return this.childNodes
        .filter((n) => n.nodeType === 3)
        .map((n) => n.nodeValue)
        .join("");
    },
  };
  if (text != null) node.childNodes.push({ nodeType: 3, nodeValue: text });
  return node;
}

function scopeOf(map) {
  return {
    querySelectorAll(sel) {
      return map[sel] || [];
    },
  };
}

function setup() {
  const I18n = loadEngine();
  I18n.register("zh-CN", {
    meta: { code: "zh-CN", name: "简体中文", fallback: "en-US" },
    strings: { a: "甲", b: "乙 {n}", onlyZh: "仅中文" },
  });
  I18n.register("en-US", {
    meta: { code: "en-US", name: "English", fallback: "en-US" },
    strings: { a: "A", b: "B {n}" },
  });
  I18n.init({ lng: "zh-CN" });
  return I18n;
}

test("基础取词与占位符", () => {
  const I18n = setup();
  assert.equal(I18n.t("a"), "甲");
  assert.equal(I18n.t("b", { n: 3 }), "乙 3");
  assert.equal(I18n.t("b", { n: 0 }), "乙 0", "0 不能被当成空值");
});

test("缺失键先回退 fallback，再回退键名", () => {
  const I18n = setup();
  assert.equal(I18n.t("onlyZh"), "仅中文");
  I18n.setLanguage("en-US");
  // en-US 没有 onlyZh，回退到 meta.fallback（en-US 自己），最终返回键名。
  assert.equal(I18n.t("onlyZh"), "onlyZh");
  assert.equal(I18n.t("nope"), "nope");
});

test("热切换后同一键返回新语言", () => {
  const I18n = setup();
  assert.equal(I18n.t("a"), "甲");
  assert.equal(I18n.setLanguage("en-US"), true);
  assert.equal(I18n.t("a"), "A");
  assert.equal(I18n.setLanguage("zh-CN"), true);
  assert.equal(I18n.t("a"), "甲");
  assert.equal(I18n.setLanguage("zh-CN"), false, "同语言重复切换不广播");
});

test("apply 替换文本/标题/占位符/aria，并保留子元素", () => {
  const I18n = setup();
  const textEl = fakeEl({ "data-i18n": "a" });
  const btn = fakeEl({ "data-i18n": "a" });
  const svg = { nodeType: 1, tagName: "svg" };
  btn.childNodes.push(svg);
  const titleEl = fakeEl({ "data-i18n-title": "a" });
  const phEl = fakeEl({ "data-i18n-placeholder": "a" });
  const ariaEl = fakeEl({ "data-i18n-aria": "a" });
  const scope = scopeOf({
    "[data-i18n]": [textEl, btn],
    "[data-i18n-title]": [titleEl],
    "[data-i18n-placeholder]": [phEl],
    "[data-i18n-aria]": [ariaEl],
  });

  I18n.apply(scope);

  assert.equal(textEl.text(), "甲");
  assert.equal(titleEl.title, "甲");
  assert.equal(phEl.placeholder, "甲");
  assert.equal(ariaEl.attrs["aria-label"], "甲");
  assert.equal(btn.text(), "甲", "应只替换文本节点");
  assert.ok(
    btn.childNodes.includes(svg),
    "SVG 图标不能被 textContent 清掉"
  );
});

test("available 暴露已注册语言与本地化名称", () => {
  const I18n = setup();
  const list = I18n.available();
  assert.equal(
    list
      .map((x) => x.code)
      .sort()
      .join(","),
    "en-US,zh-CN"
  );
  assert.equal(list.find((x) => x.code === "zh-CN").name, "简体中文");
});
