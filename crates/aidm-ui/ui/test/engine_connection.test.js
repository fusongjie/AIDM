"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8");
// 执行生产的请求函数，替换其 Tauri 和界面边界；不复制连接判断逻辑。
const requests = source.slice(source.indexOf("  function isTransportError("), source.indexOf("  function currentCategory("));

function client(invoke, render = () => {}) {
  const errors = [];
  const context = {
    invoke, Date, engineFailStreak: 0, lastEngineEventAt: 0,
    ENGINE_FAIL_STREAK_MAX: 3, setEngineOffline: render,
    console: { error: (...args) => errors.push(args) },
  };
  vm.createContext(context);
  vm.runInContext(requests, context);
  return { context, errors, send: context.send };
}

test("a successful engine reply survives UI render exceptions without becoming a transport failure", async () => {
  const c = client(async () => ({ ok: true }), () => { throw new Error("render fault"); });
  await assert.rejects(c.send({ op: "ping" }), /render fault/);
  assert.equal(c.context.engineFailStreak, 0);
  assert.equal(c.errors.length, 0);
});

test("Tauri errors retain the original reason but never log request secrets", async () => {
  const c = client(async () => { throw new Error("engine_binary_not_found"); });
  const result = await c.send({ op: "add", cookies: "private-cookie", url: "private-url" });
  assert.equal(result.ok, false);
  assert.match(result.detail, /engine_binary_not_found/);
  assert.equal(c.context.engineFailStreak, 1);
  assert.equal(c.errors[0][1], "add");
  assert.equal(JSON.stringify(c.errors).includes("private"), false);
});

test("three genuine invoke failures mark the engine offline and a success restores it", async () => {
  let fail = true;
  const states = [];
  const c = client(async () => {
    if (fail) throw new Error("connect engine: refused");
    return { ok: true };
  }, (offline) => states.push(offline));
  for (let i = 0; i < 3; i++) await c.send({ op: "list" });
  assert.deepEqual(states, [true]);
  fail = false;
  await c.send({ op: "list" });
  assert.deepEqual(states, [true, false]);
  assert.equal(c.context.engineFailStreak, 0);
});

test("subscription reconnect probes the engine instead of disabling downloads immediately", async () => {
  const start = source.indexOf('    listen("engine-status",');
  const end = source.indexOf('    listen("engine-event",', start);
  const states = [];
  const ops = [];
  let onStatus;
  const context = {
    Date, lastEngineEventAt: 0, console,
    listen: (_, callback) => { onStatus = callback; },
    setEngineOffline: (offline) => states.push(offline),
    send: async (req) => { ops.push(req.op); return { ok: true }; },
  };
  vm.runInNewContext(source.slice(start, end), context);
  onStatus({ payload: { online: false } });
  await Promise.resolve();
  assert.deepEqual(ops, ["ping"]);
  assert.deepEqual(states, []);
  onStatus({ payload: { online: true } });
  assert.deepEqual(states, [false]);
});
