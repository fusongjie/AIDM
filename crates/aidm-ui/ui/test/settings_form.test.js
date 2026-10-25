"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const S = require("../lib/settings_form.js");

test("normalizeDays canonicalises weekday lists", () => {
  assert.equal(S.normalizeDays("1,3,5"), "1,3,5");
  assert.equal(S.normalizeDays("5,3,1,1,3"), "1,3,5");
  assert.equal(S.normalizeDays("1，2 3"), "1,2,3");
  assert.equal(S.normalizeDays(""), "1,2,3,4,5,6,7");
  assert.equal(S.normalizeDays("0,9,x"), "1,2,3,4,5,6,7");
  assert.equal(S.normalizeDays("7"), "7");
});

test("host list parsing mirrors the engine rules", () => {
  assert.equal(S.parseHostListInput("Example.COM"), "example.com");
  assert.equal(
    S.parseHostListInput("https://cdn.example.com:8443/path, *.internal.test"),
    "cdn.example.com,*.internal.test"
  );
  assert.equal(S.parseHostListInput("a.com,a.com,b.com"), "a.com,b.com");
  assert.equal(S.parseHostListInput(""), "");
  // 通配必须保留，否则会退化成"只匹配根域"
  assert.equal(S.parseHostListInput("*.example.com"), "*.example.com");
  // 非法字符直接拒绝，交给引擎报错或 UI 提示
  assert.equal(S.parseHostListInput("bad host!"), null);
});

test("ext list parsing normalises case, dots and duplicates", () => {
  assert.equal(S.parseExtListInput(".MP4, mkv  AVI"), "mp4 mkv avi");
  assert.equal(S.parseExtListInput("mp4,mp4"), "mp4");
  assert.equal(S.parseExtListInput(""), "");
  assert.equal(S.parseExtListInput("ok, bad!", null), null);
});

test("category dirs must be a flat string map", () => {
  assert.equal(S.normalizeCategoryDirs(""), "{}");
  assert.equal(S.normalizeCategoryDirs('{"ISO":"D:\\\\iso"}'), '{"iso":"D:\\\\iso"}');
  assert.equal(S.normalizeCategoryDirs("[]"), null);
  assert.equal(S.normalizeCategoryDirs('{"a":""}'), null);
  assert.equal(S.normalizeCategoryDirs("not json"), null);
  assert.equal(S.normalizeCategoryDirs('{"*":"D:\\\\dl","iso":"D:\\\\iso"}'), '{"*":"D:\\\\dl","iso":"D:\\\\iso"}');
});

test("pathToFileUrl keeps unix paths and escapes spaces", () => {
  assert.equal(S.pathToFileUrl("C:\\sounds\\done.wav"), "file:///C:/sounds/done.wav");
  assert.equal(S.pathToFileUrl("d:\\a b\\c.wav"), "file:///D:/a%20b/c.wav");
  assert.equal(S.pathToFileUrl("/usr/share/a b.wav"), "file:///usr/share/a%20b.wav");
  assert.equal(S.pathToFileUrl(""), "");
});

test("schema-driven validation catches out-of-range and enum errors", () => {
  const schema = [
    { key: "conn.max_conns_per_task", kind: "int", min: 1, max: 32 },
    { key: "speed.global_limit_kbps", kind: "nonneg" },
    { key: "sched.after_done", kind: "enum", values: ["none", "exit", "shutdown"] },
    { key: "sched.window_start", kind: "clock" },
    { key: "proxy.bypass_hosts", kind: "host_list" },
    { key: "paths.category_dirs", kind: "json_map" },
  ];
  assert.equal(S.validateWithSchema(schema, "conn.max_conns_per_task", "32"), null);
  assert.equal(S.validateWithSchema(schema, "conn.max_conns_per_task", "33"), "invalid_value");
  assert.equal(S.validateWithSchema(schema, "conn.max_conns_per_task", "0"), "invalid_value");
  assert.equal(S.validateWithSchema(schema, "conn.max_conns_per_task", "abc"), "invalid_value");
  assert.equal(S.validateWithSchema(schema, "speed.global_limit_kbps", "0"), null);
  assert.equal(S.validateWithSchema(schema, "speed.global_limit_kbps", "-1"), "speed_limit_invalid");
  assert.equal(S.validateWithSchema(schema, "sched.after_done", "SHUTDOWN"), null);
  assert.equal(S.validateWithSchema(schema, "sched.after_done", "reboot"), "invalid_value");
  assert.equal(S.validateWithSchema(schema, "sched.window_start", "22:00"), null);
  assert.equal(S.validateWithSchema(schema, "sched.window_start", "25:00"), "clock_invalid");
  assert.equal(S.validateWithSchema(schema, "proxy.bypass_hosts", "*.a.com"), null);
  assert.equal(S.validateWithSchema(schema, "proxy.bypass_hosts", "!!"), "hosts_invalid");
  assert.equal(S.validateWithSchema(schema, "paths.category_dirs", '{"iso":"D:\\\\i"}'), null);
  assert.equal(S.validateWithSchema(schema, "paths.category_dirs", "x"), "category_dirs_invalid");
  // 没拿到 schema 时不拦（引擎仍会校验）
  assert.equal(S.validateWithSchema(null, "anything", "bad"), null);
});

test("canonicalize produces what the engine will accept", () => {
  assert.equal(S.canonicalize("sched.window_days", "3,1,1"), "1,3");
  assert.equal(S.canonicalize("proxy.bypass_hosts", "HTTPS://A.com/x, *.b.test"), "a.com,*.b.test");
  assert.equal(S.canonicalize("browser.panel_exts", ".MP4, mkv"), "mp4 mkv");
  assert.equal(S.canonicalize("paths.category_dirs", '{"ISO":"D:\\\\iso"}'), '{"iso":"D:\\\\iso"}');
  assert.equal(S.canonicalize("conn.max_conns_per_task", "16"), "16");
});

test("validateCustomHeaders：合法块通过并统计条数", () => {
  const r = S.validateCustomHeaders("# 注释\nX-Api-Key: k\n\nSec-Fetch-Site: cross-site\n");
  assert.equal(r.ok, true);
  assert.equal(r.count, 2);
  assert.equal(S.validateCustomHeaders("").ok, true);
});

test("validateCustomHeaders：拒绝受管头与非法行", () => {
  const managed = S.validateCustomHeaders("Range: bytes=0-1");
  assert.equal(managed.ok, false);
  assert.match(managed.text, /由程序管理/);
  assert.equal(S.validateCustomHeaders("Cookie: a=1").ok, false);
  assert.equal(S.validateCustomHeaders("Host: evil").ok, false);
  assert.equal(S.validateCustomHeaders("NoColon").ok, false);
  assert.equal(S.validateCustomHeaders("Bad Name: v").ok, false);
  assert.equal(S.validateCustomHeaders("X-A: 1\u0001").ok, false);
  assert.match(S.validateCustomHeaders("X-A: 1\u0001").text, /控制字符/);
});

test("validateCustomHeaders：超长与超量被拒", () => {
  const long = "X-Long: " + "a".repeat(2049);
  assert.equal(S.validateCustomHeaders(long).ok, false);
  const many = Array.from({ length: 33 }, (_, i) => `X-H${i}: v`).join("\n");
  assert.match(S.validateCustomHeaders(many).text, /最多 32 个请求头/);
});

test("validateAltUrls：中间件规则与引擎 validate_alt_urls 一致", () => {
  const r = S.validateAltUrls("# 镜像\nhttps://m1.test/a.iso\n\nhttp://m2.test/a.iso?x=1\n");
  assert.equal(r.ok, true);
  assert.equal(r.count, 2);
  assert.equal(S.validateAltUrls("").ok, true);
  assert.equal(S.validateAltUrls(null).ok, true);
});

test("validateAltUrls：只认 HTTP(S) 绝对地址", () => {
  assert.equal(S.validateAltUrls("ftp://m.test/a.iso").ok, false);
  assert.equal(S.validateAltUrls("ed2k://|file|a|1|b|/").ok, false);
  assert.equal(S.validateAltUrls("magnet:?xt=urn:btih:" + "a".repeat(40)).ok, false);
  assert.equal(S.validateAltUrls("m.test/a.iso").ok, false);
  // scheme 后面必须是主机：`https://` `https:///x` `https://?x` 都不算地址
  assert.equal(S.validateAltUrls("https://").ok, false);
  assert.equal(S.validateAltUrls("https:///x").ok, false);
  assert.equal(S.validateAltUrls("https://?x").ok, false);
  // 大写 scheme 放行（引擎同样大小写不敏感）
  assert.equal(S.validateAltUrls("HTTPS://m.test/a.iso").ok, true);
});

test("validateAltUrls：控制字符、超长与超量被拒", () => {
  assert.match(S.validateAltUrls("https://m.test/a\u0001").text, /控制字符/);
  assert.equal(S.validateAltUrls("https://m.test/" + "a".repeat(9000)).ok, false);
  const many = Array.from({ length: 9 }, (_, i) => `https://m${i}.test/a`).join("\n");
  assert.match(S.validateAltUrls(many).text, /最多 8 个备用地址/);
});