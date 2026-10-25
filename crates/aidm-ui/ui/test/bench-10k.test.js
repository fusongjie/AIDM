"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const ROW_H = 36;
const OVERSCAN = 8;

function visibleRange(scrollTop, viewportH, total, rowH, overscan) {
  if (total === 0 || rowH === 0) return { start: 0, end: 0 };
  const first = Math.min(Math.max(total - 1, 0), Math.floor(scrollTop / rowH));
  const visible = Math.floor(viewportH / rowH) + 1;
  const start = Math.max(0, first - overscan);
  const end = Math.min(total, first + visible + overscan);
  return { start, end };
}

function makeTasks(n) {
  const out = new Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = {
      id: i + 1,
      name: "file-" + i + ".bin",
      state: i % 7 === 0 ? "error" : "done",
      done: 100,
      total: 100,
      speed: 0,
      pct: 100,
      save_path: "/tmp/file-" + i + ".bin",
      error_code: i % 7 === 0 ? "network" : undefined,
    };
  }
  return out;
}

function renderWindow(tasks, scrollTop, viewportH) {
  const { start, end } = visibleRange(scrollTop, viewportH, tasks.length, ROW_H, OVERSCAN);
  const nodes = [];
  for (let i = start; i < end; i++) {
    const t = tasks[i];
    nodes.push({ kind: "row", id: t.id });
    for (let c = 0; c < 8; c++) nodes.push({ kind: "cell", c });
    nodes.push({ kind: "bar" }, { kind: "fill" }, { kind: "label" });
  }
  return { start, end, nodes };
}

test("10k virtual list: window bound, render time, memory", () => {
  const before = process.memoryUsage().heapUsed;
  const t0 = Date.now();
  const tasks = makeTasks(10_000);
  const allocMs = Date.now() - t0;
  assert.ok(allocMs < 500, "allocate 10k rows too slow: " + allocMs + "ms");

  const r0 = Date.now();
  const top = renderWindow(tasks, 0, 360);
  const mid = renderWindow(tasks, 3600, 360);
  const end = renderWindow(tasks, 36 * 9990, 360);
  const renderMs = Date.now() - r0;
  assert.ok(renderMs < 100, "window render too slow: " + renderMs + "ms");

  const windowRows = top.end - top.start;
  assert.ok(windowRows <= 30, "window too large: " + windowRows);
  assert.ok(windowRows >= 10, "window too small: " + windowRows);
  assert.ok(top.nodes.length < 500, "DOM node count " + top.nodes.length);
  assert.ok(mid.nodes.length < 500);
  assert.ok(end.nodes.length < 500);
  assert.equal(top.start, 0);
  assert.ok(mid.start >= 100 - OVERSCAN);

  const after = process.memoryUsage().heapUsed;
  const grew = after - before;
  assert.ok(grew < 80 * 1024 * 1024, "memory grew " + grew);
});
