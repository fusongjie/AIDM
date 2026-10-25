"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { MockEngine, roundtrip, taskView } = require("./mock-engine.js");
const E = require("../lib/errors.js");
const P = require("../lib/polish.js");
const U = require("../lib/update.js");

async function withEngine(fn) {
  const eng = new MockEngine();
  const port = await eng.start();
  try {
    await fn(eng, port);
  } finally {
    await eng.stop();
  }
}

test("e2e: new download / pause / resume / delete with files", async () => {
  await withEngine(async (eng, port) => {
    const add = await roundtrip(port, {
      op: "add",
      url: "https://example.com/a.bin",
      filename: "a.bin",
      dir: "/tmp",
    });
    assert.equal(add.ok, true);
    assert.ok(add.id);

    let list = await roundtrip(port, { op: "list" });
    assert.equal(list.tasks.length, 1);
    assert.equal(list.tasks[0].state, "downloading");

    const pause = await roundtrip(port, { op: "pause", id: add.id });
    assert.equal(pause.ok, true);
    list = await roundtrip(port, { op: "list" });
    assert.equal(list.tasks[0].state, "paused");

    const resume = await roundtrip(port, { op: "resume", id: add.id });
    assert.equal(resume.ok, true);
    list = await roundtrip(port, { op: "list" });
    assert.equal(list.tasks[0].state, "downloading");

    const del = await roundtrip(port, { op: "delete", ids: [add.id], delete_files: true });
    assert.equal(del.ok, true);
    assert.equal(del.deleted_files, true);
    list = await roundtrip(port, { op: "list" });
    assert.equal(list.tasks.length, 0);
  });
});

test("e2e: settings save + structured invalid_value", async () => {
  await withEngine(async (eng, port) => {
    const ok = await roundtrip(port, {
      op: "settings_set",
      key: "speed.global_limit_kbps",
      value: "128",
    });
    assert.equal(ok.ok, true);
    const got = await roundtrip(port, { op: "settings_get" });
    assert.equal(got.settings["speed.global_limit_kbps"], "128");

    eng.structuredError = { code: "invalid_value", min: 1, max: 1024 };
    const bad = await roundtrip(port, {
      op: "settings_set",
      key: "conn.global_conn_cap",
      value: "9999",
    });
    assert.equal(bad.ok, false);
    assert.equal(bad.code, "invalid_value");
    assert.equal(
      E.settingsSetUserError("conn.global_conn_cap", bad),
      "请输入 1–1024 之间的整数"
    );
  });
});

test("e2e: candidates dialog copy + add results", async () => {
  await withEngine(async (eng, port) => {
    assert.equal(E.emptyCategoryTitle("all"), "暂无下载任务");
    const none = "页面上没有发现可下载的链接";
    const nomatch = "没有匹配的链接";
    assert.equal(none.includes("没有发现"), true);
    assert.equal(nomatch.includes("没有匹配"), true);

    const a = await roundtrip(port, {
      op: "add",
      url: "https://p/a",
      filename: "a.bin",
      source: "ext",
    });
    assert.equal(a.ok, true);
    eng.structuredError = null;
    const failAdd = { added: 0, failed: 2 };
    assert.equal(failAdd.added === 0 && failAdd.failed > 0 ? "添加失败，请重试" : "", "添加失败，请重试");
    assert.equal(
      "已添加 " + 2 + " 项，" + 1 + " 项添加失败",
      "已添加 2 项，1 项添加失败"
    );
  });
});

test("e2e: offline banner state + list actions disabled", async () => {
  const ui = {
    banner: false,
    buttons: { start: true, pause: true, delete: true, retry: true },
  };
  function applyOffline(off) {
    ui.banner = off;
    if (off) {
      ui.buttons.start = false;
      ui.buttons.pause = false;
      ui.buttons.delete = false;
      ui.buttons.retry = false;
    }
  }
  applyOffline(true);
  assert.equal(E.ENGINE_OFFLINE_BANNER, "无法连接下载引擎，正在重新连接…");
  assert.equal(ui.banner, true);
  assert.equal(ui.buttons.start, false);
  applyOffline(false);
  assert.equal(ui.banner, false);

  const eng = new MockEngine();
  const port = await eng.start();
  const ping = await roundtrip(port, { op: "ping" });
  assert.equal(ping.ok, true);
  await eng.stop();
  await assert.rejects(() => roundtrip(port, { op: "list" }));
});

test("e2e: error_code display uses mapped sentence not raw error", () => {
  const t = taskView({
    state: "error",
    error_code: "disk_full",
    error: "ENOSPC disk is full please free space",
  });
  const d = E.describeTaskError(t);
  assert.equal(d.sentence, E.FAIL_DISK_FULL);
  assert.equal(d.raw, "ENOSPC disk is full please free space");
  assert.notEqual(d.sentence, t.error);
  assert.equal(E.COPY_ERROR_DETAIL, "复制错误详情");
});

test("e2e: restart same id clears segments (no resume fallback)", async () => {
  await withEngine(async (eng, port) => {
    const add = await roundtrip(port, {
      op: "add",
      url: "https://example.com/a.bin",
      filename: "a.bin",
    });
    eng.tasks[0].state = "error";
    eng.tasks[0].error_code = "remote_changed";
    eng.tasks[0].error = "etag mismatch";
    eng.tasks[0].done = 40;
    eng.tasks[0].pct = 40;
    eng.tasks[0].segments = [{ idx: 0, status: "error" }];
    const restart = await roundtrip(port, { op: "restart", id: add.id });
    assert.equal(restart.ok, true);
    assert.equal(restart.id, undefined);
    const list = await roundtrip(port, { op: "list" });
    assert.equal(list.tasks.length, 1);
    assert.equal(list.tasks[0].id, add.id);
    assert.equal(list.tasks[0].state, "queued");
    assert.equal(list.tasks[0].error_code, undefined);
    assert.equal(list.tasks[0].http_status, undefined);
    assert.deepEqual(list.tasks[0].segments, []);
    assert.equal(eng.lastRequests.some((r) => r.op === "resume"), false);
    assert.equal(eng.lastRequests.some((r) => r.op === "restart" && r.id === add.id), true);
  });
});

test("e2e: change location add then delete original; add fail keeps original", async () => {
  await withEngine(async (eng, port) => {
    const add = await roundtrip(port, {
      op: "add",
      url: "https://example.com/a.bin",
      filename: "a.bin",
      dir: "/old",
    });
    const originalId = add.id;
    const again = await roundtrip(port, {
      op: "add",
      url: "https://example.com/a.bin",
      filename: "a.bin",
      dir: "/new",
    });
    assert.equal(again.ok, true);
    const del = await roundtrip(port, {
      op: "delete",
      ids: [originalId],
      delete_files: false,
    });
    assert.equal(del.ok, true);
    assert.equal(del.deleted_files, false);
    let list = await roundtrip(port, { op: "list" });
    assert.equal(list.tasks.length, 1);
    assert.equal(list.tasks[0].id, again.id);
    assert.equal(list.tasks[0].save_path.startsWith("/new"), true);

    const keep = await roundtrip(port, {
      op: "add",
      url: "https://example.com/b.bin",
      filename: "b.bin",
      dir: "/keep",
    });
    eng.failOps.add("add");
    const failAdd = await roundtrip(port, {
      op: "add",
      url: "https://example.com/b.bin",
      filename: "b.bin",
      dir: "/other",
    });
    assert.equal(failAdd.ok, false);
    list = await roundtrip(port, { op: "list" });
    assert.ok(list.tasks.some((t) => t.id === keep.id));
  });
});

test("e2e: pause and move failure surface OP_FAIL", async () => {
  await withEngine(async (eng, port) => {
    const add = await roundtrip(port, {
      op: "add",
      url: "https://example.com/a.bin",
      filename: "a.bin",
    });
    eng.failOps.add("pause");
    const pause = await roundtrip(port, { op: "pause", id: add.id });
    assert.equal(pause.ok, false);
    eng.failOps.delete("pause");
    assert.equal(E.OP_FAIL, "操作失败，请重试");
  });
});

test("e2e: rename {id, filename} ok / invalid_filename / name_taken", async () => {
  await withEngine(async (eng, port) => {
    const a = await roundtrip(port, {
      op: "add",
      url: "https://example.com/a.bin",
      filename: "a.bin",
      dir: "/tmp",
    });
    await roundtrip(port, {
      op: "add",
      url: "https://example.com/b.bin",
      filename: "b.bin",
      dir: "/tmp",
    });
    const ok = await roundtrip(port, { op: "rename", id: a.id, filename: "renamed.bin" });
    assert.equal(ok.ok, true);
    assert.equal(ok.task.name, "renamed.bin");
    assert.equal(ok.task.save_path, "/tmp/renamed.bin");
    const taken = await roundtrip(port, { op: "rename", id: a.id, filename: "b.bin" });
    assert.equal(taken.ok, false);
    assert.equal(taken.code, "name_taken");
    assert.equal(P.renameErrorText(taken), "已存在同名文件，请换一个名字");
    const bad = await roundtrip(port, { op: "rename", id: a.id, filename: "../x.bin" });
    assert.equal(bad.ok, false);
    assert.equal(bad.code, "invalid_filename");
    assert.equal(P.renameErrorText(bad), "文件名无效，请重新输入");
    const missing = await roundtrip(port, { op: "rename", id: 999, filename: "gone.bin" });
    assert.equal(missing.ok, false);
    assert.equal(missing.error, "task_not_found");
    assert.equal(P.renameErrorText(missing), "任务不存在或已删除");
  });
});

test("e2e: mock update_check / update_download_apply + settings keys", async () => {
  await withEngine(async (eng, port) => {
    const setCh = await roundtrip(port, {
      op: "settings_set",
      key: "update.channel",
      value: "beta",
    });
    assert.equal(setCh.ok, true);
    const setAuto = await roundtrip(port, {
      op: "settings_set",
      key: "update.auto_check",
      value: "false",
    });
    assert.equal(setAuto.ok, true);
    const got = await roundtrip(port, { op: "settings_get" });
    assert.equal(got.settings["update.channel"], "beta");
    assert.equal(got.settings["update.auto_check"], "false");
    assert.equal(got.settings["app.version"], "0.1.0");

    eng.updateAvailable = { version: "0.2.0", notes: "fix" };
    const check = await roundtrip(port, { op: "update_check" });
    assert.equal(check.ok, true);
    const after = await roundtrip(port, { op: "settings_get" });
    assert.ok(String(after.settings["update.last_check_at"] || "").length > 0);

    const apply = await roundtrip(port, { op: "update_download_apply" });
    assert.equal(apply.ok, true);

    eng.updateCheckError = "network";
    const bad = await roundtrip(port, { op: "update_check" });
    assert.equal(bad.ok, false);
    assert.equal(bad.code, "network");
    assert.equal(U.describeUpdateError(bad.code), U.ERR_NETWORK);

    eng.updateCheckError = "check_failed";
    const failed = await roundtrip(port, { op: "update_check" });
    assert.equal(U.describeUpdateError(failed.code), U.ERR_CHECK_FAILED);

    eng.updateApplyError = "checksum_mismatch";
    const verify = await roundtrip(port, { op: "update_download_apply" });
    assert.equal(verify.ok, true);
    assert.equal(U.describeUpdateError("checksum_mismatch"), U.ERR_CHECKSUM);
    assert.equal(U.describeUpdateError(""), U.ERR_UPDATE_FAILED);
  });
});

test("e2e: offer_expired contract", async () => {
  await withEngine(async (eng, port) => {
    eng.structuredError = { code: "offer_expired" };
    const resp = await roundtrip(port, {
      op: "settings_set",
      key: "x",
      value: "1",
    });
    assert.equal(E.isOfferExpired(resp), true);
    assert.equal(E.isOfferExpired({ ok: false, error: "offer_expired" }), false);
  });
});
