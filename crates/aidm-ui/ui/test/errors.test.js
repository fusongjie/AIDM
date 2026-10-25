"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const E = require("../lib/errors.js");

test("电驴等待源是可自动重试的等待状态", () => {
  const waiting = E.describeTaskError({ error_code: "ed2k_no_sources", error: "network" });
  assert.equal(waiting.sentence, "等待可用下载源，将自动重试");
  assert.equal(waiting.isFailure, false);
  assert.equal(waiting.isInterrupted, false);
});

test("every error_code maps and never uses error text", () => {
  assert.equal(E.taskFailReason({ error_code: "network", error: "http_401" }), E.FAIL_NETWORK);
  assert.equal(E.taskFailReason({ error_code: "blocked_by_hosts" }), E.FAIL_BLOCKED_BY_HOSTS);
  assert.equal(E.describeTaskError({ error_code: "blocked_by_hosts" }).action, null);
  assert.equal(E.taskFailReason({ error_code: "disk_full" }), E.FAIL_DISK_FULL);
  const perm = E.describeTaskError({ error_code: "no_permission" });
  assert.equal(perm.sentence, E.FAIL_NO_PERMISSION);
  assert.equal(perm.action, "change_location");
  const remote = E.describeTaskError({ error_code: "remote_changed" });
  assert.equal(remote.sentence, E.FAIL_REMOTE_CHANGED);
  assert.equal(remote.action, "redownload");
  assert.equal(
    E.taskFailReason({ error_code: "http_401", source: "ext", error: "401 Unauthorized" }),
    E.EXT_AUTH_EXPIRED
  );
  assert.equal(E.taskFailReason({ error_code: "http_403", source: "ext" }), E.EXT_AUTH_EXPIRED);
  assert.equal(E.taskFailReason({ error_code: "http_401", source: "manual" }), E.FAIL_HTTP_401);
  assert.equal(E.taskFailReason({ error_code: "http_403" }), E.FAIL_HTTP_403);
  assert.equal(E.taskFailReason({ error_code: "http_404" }), E.FAIL_HTTP_404);
  assert.equal(
    E.taskFailReason({ error_code: "http_4xx", http_status: 418, error: "ignore 503" }),
    "服务器返回错误（418）"
  );
  assert.equal(
    E.taskFailReason({ error_code: "http_5xx", http_status: 502, error: "418" }),
    "服务器返回错误（502），请稍后重试"
  );
  assert.equal(
    E.taskFailReason({ error_code: "http_4xx", error: "418 I'm a teapot" }),
    "服务器返回错误"
  );
  assert.equal(E.taskFailReason({ error_code: "unsupported_scheme" }), E.FAIL_UNSUPPORTED_SCHEME);
  // 302 是"服务器要求跳转"，不是 4xx：实测成因是镜像的反爬挑战，
  // 这时"稍后重试"没用，换来源才有用，所以文案必须与 4xx 区分开。
  assert.equal(
    E.taskFailReason({ error_code: "http_3xx", http_status: 302 }),
    "服务器要求跳转（302），通常是镜像的反爬校验，请换一个来源或稍后重试"
  );
  assert.equal(
    E.taskFailReason({ error_code: "http_3xx" }),
    "服务器要求跳转，通常是镜像的反爬校验，请换一个来源"
  );
  // 上游 CHECKSUM 声明了整文件哈希但内容对不上（换过镜像 / 走过明文 http）
  assert.equal(E.taskFailReason({ error_code: "sha256_mismatch" }), E.FAIL_SHA256);
  assert.equal(E.taskFailReason({ error_code: "quota_exceeded" }), E.FAIL_QUOTA);
  assert.equal(E.describeTaskError({ error_code: "quota_exceeded" }).action, null);
  assert.equal(
    E.taskFailReason({ error_code: "sha256_mismatch", error: "expected=aa got=bb" }),
    E.FAIL_SHA256
  );
  const interrupted = E.describeTaskError({ error_code: "interrupted", error: "crash" });
  assert.equal(interrupted.sentence, "排队中");
  assert.equal(interrupted.isFailure, false);
  assert.equal(interrupted.isInterrupted, true);
  assert.equal(E.INTERRUPTED_TOOLTIP, "程序意外退出，已自动重新排队");
  assert.equal(E.taskFailReason({ error: "http_401" }), E.FAIL_GENERIC);
  assert.equal(E.taskFailReason({ error: "401 Unauthorized", http_status: 401 }), E.FAIL_GENERIC);
  assert.equal(E.taskFailReason({}), E.FAIL_GENERIC);
  assert.equal(E.taskFailReason({ error_code: "mystery" }), E.FAIL_GENERIC);
});

test("settings_set only honors explicit codes", () => {
  assert.equal(E.settingsSetUserError("sched.start_cron", "invalid_cron"), "定时格式不对，例如 0 2 * * *");
  assert.equal(
    E.settingsSetUserError("conn.global_conn_cap", { code: "invalid_value", min: 1, max: 1024 }),
    "请输入 1–1024 之间的整数"
  );
  assert.equal(
    E.settingsSetUserError("conn.retry_backoff_ms", { code: "invalid_value", min: 100, max: 60000 }),
    "请输入 0.1–60 秒"
  );
  assert.equal(
    E.settingsSetUserError("sched.start_cron", "定时格式不对，例如 0 2 * * *"),
    "设置保存失败，请重试"
  );
  assert.equal(
    E.settingsSetUserError("conn.global_conn_cap", "conn_value_invalid"),
    "设置保存失败，请重试"
  );
  assert.equal(
    E.settingsSetUserError("x", { code: "unknown", error: "请输入 1–16 之间的整数" }),
    "设置保存失败，请重试"
  );
});

test("copy helpers", () => {
  assert.equal(E.emptyCategoryTitle("done"), "暂无已完成的任务");
  assert.equal(E.emptyCategoryTitle("error"), "暂无失败的任务");
  assert.equal(E.emptyCategoryTitle("all"), "暂无下载任务");
  for (const cat of ["all", "active", "done", "queue", "error"]) {
    assert.ok(E.emptyCategoryHint(cat).length > 0, `空分类 ${cat} 不能只有标题没有说明`);
  }
  assert.equal(E.emptyCategoryHint("all"), "点击「新建下载」开始，或从托盘菜单发起。");
  assert.equal(E.settingsPageForKey("proxy.host"), "proxy");
  assert.equal(E.settingsPageForKey("update.channel"), "update");
  assert.equal(E.fileNameFromPath("/tmp/dir/a.zip"), "a.zip");
  assert.equal(E.fileNameFromPath("C\\\\Downloads\\\\b.bin"), "b.bin");
  assert.equal(E.URL_EMPTY, "请输入下载链接");
  assert.equal(E.LIST_LOAD_FAIL, "无法连接下载引擎，请确认 AIDM 正在运行后重试");
  assert.equal(E.ADD_DOWNLOAD_FAIL, "添加下载失败，请重试");
  assert.equal(E.OPEN_DIR_FAIL, "无法打开目录");
  assert.equal(E.OPEN_INSTALL_FAIL, "无法打开安装说明");
  assert.equal(E.COPY_ERROR_DETAIL, "复制错误详情");
  assert.equal(E.DISCARD_SETTINGS, "放弃未保存的修改？");
  assert.equal(E.OP_FAIL, "操作失败，请重试");
});

test("isOfferExpired reads only ok=false + code", () => {
  assert.equal(E.isOfferExpired({ ok: false, code: "offer_expired" }), true);
  assert.equal(E.isOfferExpired({ ok: false, code: "offer_expired", error: "other" }), true);
  assert.equal(E.isOfferExpired({ ok: true, code: "offer_expired" }), false);
  assert.equal(E.isOfferExpired({ code: "offer_expired" }), false);
  assert.equal(E.isOfferExpired({ ok: false, error: "offer_expired" }), false);
  assert.equal(E.isOfferExpired({ ok: false, code: "disabled" }), false);
  assert.equal(E.isOfferExpired(null), false);
});

test("candidate retry label and uncheck succeeded", () => {
  assert.equal(E.candidateOkLabel(3, false), "下载选中的 3 项");
  assert.equal(E.candidateOkLabel(2, true), "重试失败的 2 项");
  const remain = E.uncheckSucceededCandidates(new Set([0, 1, 2]), [0, 2]);
  assert.deepEqual([...remain].sort(), [1]);
});

test("context local actions stay available offline", () => {
  assert.equal(E.isLocalCtxAction("copy"), true);
  assert.equal(E.isLocalCtxAction("open-dir"), true);
  assert.equal(E.isLocalCtxAction("props"), true);
  assert.equal(E.isLocalCtxAction("start"), false);
  assert.equal(E.isLocalCtxAction("delete"), false);
});

test("html/app contracts for review round 2", () => {
  const uiDir = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");
  assert.equal(html.includes("props-fail-raw"), false);
  assert.equal(html.includes("按文件名或链接搜索"), true);
  assert.equal(html.includes("按文件名或 URL 搜索"), false);
  assert.equal(html.includes('role="tab"'), true);
  assert.equal(html.includes('role="menuitem"'), true);
  assert.equal((html.match(/role="tablist"/g) || []).length, 2);
  assert.equal(app.includes("failRaw"), false);
  assert.equal(app.includes("pickedDirOverride"), false);
  assert.equal(app.includes("testPickDirectory"), false);
  assert.equal(app.includes("setTestPickDirectory"), false);
  assert.equal(app.includes('op: "restart"'), true);
  assert.equal(app.includes("delete_files: false"), true);
  assert.equal(app.includes("del-cancel"), true);
  assert.equal(app.includes("OPEN_INSTALL_FAIL"), true);
  assert.equal(app.includes("COPY_ERROR_DETAIL"), true);
  assert.match(app, /op:\s*"restart"[\s\S]*id:\s*task\.id/);
});

test("settings page routing covers the new key families", () => {
  assert.equal(E.settingsPageForKey("paths.category_dirs"), "paths");
  assert.equal(E.settingsPageForKey("conn.speed_limit_default_kbps"), "conn");
  assert.equal(E.settingsPageForKey("sched.window_start"), "sched");
  assert.equal(E.settingsPageForKey("sched.quota_mb"), "sched");
  assert.equal(E.settingsPageForKey("ui.duplicate_action"), "sched");
  assert.equal(E.settingsPageForKey("ui.sound_complete"), "general");
  assert.equal(E.settingsPageForKey("engine.fastdl"), "adv");
  assert.equal(E.settingsPageForKey("verify.sha256_after"), "adv");
  assert.equal(E.settingsPageForKey("net.recv_buf_kb"), "adv");
  assert.equal(E.settingsPageForKey("proxy.bypass_hosts"), "proxy");
  assert.equal(E.settingsPageForKey("browser.hotkey_prevent"), "browser");
});

test("settings errors map to actionable text, never a bare code", () => {
  assert.match(E.settingsSetUserError("sched.window_start", "clock_invalid"), /HH:MM/);
  assert.match(E.settingsSetUserError("sched.window_days", "weekdays_invalid"), /1–7/);
  assert.match(E.settingsSetUserError("proxy.bypass_hosts", "hosts_invalid"), /example\.com/);
  assert.match(E.settingsSetUserError("browser.auto_catch_exts", "exts_invalid"), /扩展名/);
  assert.match(
    E.settingsSetUserError("paths.category_dirs", "category_dirs_invalid"),
    /JSON/
  );
  assert.match(E.settingsSetUserError("sched.after_done", "after_done_invalid"), /取值/);
  assert.match(E.settingsSetUserError("settings.revision", "setting_readonly"), /只读/);
  assert.match(E.settingsSetUserError("host", "host_invalid"), /example\.com/);
  assert.match(E.settingsSetUserError("host", "max_conns_invalid"), /1–32/);
  // 结构化越界仍然带区间
  assert.match(
    E.settingsSetUserError("conn.max_conns_per_task", { code: "invalid_value", min: 1, max: 32 }),
    /1–32/
  );
  assert.equal(E.settingsSetUserError("conn.retry_max", "unknown_setting_key"), "设置保存失败，请重试");
});
