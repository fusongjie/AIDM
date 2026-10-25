"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const U = require("../lib/update.js");
const E = require("../lib/errors.js");

test("channel labels and defaults", () => {
  assert.equal(U.channelLabel("stable"), "正式版");
  assert.equal(U.channelLabel("beta"), "测试版");
  assert.equal(U.normalizeChannel("beta"), "beta");
  assert.equal(U.normalizeChannel(""), "stable");
  assert.equal(U.normalizeAutoCheck(undefined), true);
  assert.equal(U.normalizeAutoCheck(""), true);
  assert.equal(U.normalizeAutoCheck("false"), false);
  assert.equal(U.CHANNEL_HINT, "测试版可能不稳定，仅建议尝鲜时使用");
  assert.equal(U.AUTO_CHECK_LABEL, "启动后自动检查更新");
  assert.equal(U.AUTO_CHECK_HINT, "每 1 小时检查一次");
});

test("last-check formatting", () => {
  const now = new Date(2026, 9, 12, 10, 0, 0).getTime();
  assert.equal(U.formatLastCheck(null, now), "上次检查：—");
  assert.equal(U.formatLastCheck("", now), "上次检查：—");
  const today = new Date(2026, 9, 12, 9, 12, 0).getTime();
  assert.equal(U.formatLastCheck(today, now), "上次检查：今天 09:12");
  const yest = new Date(2026, 9, 11, 18, 30, 0).getTime();
  assert.equal(U.formatLastCheck(yest, now), "上次检查：昨天 18:30");
  const older = new Date(2026, 9, 10, 21, 0, 0).getTime();
  assert.equal(U.formatLastCheck(older, now), "上次检查：2026-10-10 21:00");
  assert.equal(U.formatLastCheck("2026-10-10 21:00", now), "上次检查：2026-10-10 21:00");
});

test("current version prefers readonly app.version, never hardcodes", () => {
  assert.equal(U.formatCurrentVersion(""), "—");
  assert.equal(U.formatCurrentVersion(null), "—");
  assert.equal(U.formatCurrentVersion("0.1.0"), "当前版本 0.1.0");
  assert.equal(
    U.resolveAppVersion({ current_version: "1.2.3", version: "9.9.9" }, { "app.version": "0.1.0" }, "ping"),
    "0.1.0"
  );
  assert.equal(U.resolveAppVersion({ current_version: "1.2.3" }, {}, "ping"), "1.2.3");
  assert.equal(U.resolveAppVersion(null, { "app.version": "0.4.0" }, "ping"), "0.4.0");
  assert.equal(U.resolveAppVersion(null, {}, "0.5.0"), "0.5.0");
  assert.equal(U.resolveAppVersion(null, {}, ""), "");
});

test("error-code mapping", () => {
  assert.equal(U.describeUpdateError("network"), U.ERR_NETWORK);
  assert.equal(U.describeUpdateError("check_failed"), U.ERR_CHECK_FAILED);
  assert.equal(U.describeUpdateError("checksum_mismatch"), U.ERR_CHECKSUM);
  assert.equal(U.describeUpdateError("update_failed"), U.ERR_UPDATE_FAILED);
  assert.equal(U.describeUpdateError(""), U.ERR_UPDATE_FAILED);
  assert.equal(U.describeUpdateError(null), U.ERR_UPDATE_FAILED);
  assert.equal(U.describeUpdateError("mystery"), U.ERR_UPDATE_FAILED);
  assert.equal(U.ERR_NETWORK, "无法连接更新服务器，请检查网络后重试");
  assert.equal(U.ERR_CHECK_FAILED, "检查更新失败，请稍后重试");
  assert.equal(U.ERR_CHECKSUM, "更新文件校验失败，未安装任何改动");
  assert.equal(U.ERR_UPDATE_FAILED, "更新失败，请稍后重试");
});

test("applyUpdateEvent handles up_to_date explicitly, not via done", () => {
  const idle = U.emptyState();
  const fromIdle = U.applyUpdateEvent(idle, { phase: "up_to_date", current_version: "0.1.0" });
  assert.equal(fromIdle.phase, "up_to_date");
  // 标签提醒已取消：状态只留在按钮文案里（up_to_date → 按钮「已经是最新版」）。
  assert.equal(U.statusTitle(fromIdle), "");
  assert.equal(U.updateStatusView(fromIdle).title, "");
  assert.equal(U.updateStatusView(fromIdle).showStatus, false);

  const checking = U.applyUpdateEvent(
    Object.assign(U.emptyState(), { phase: "checking", userCheck: true }),
    { phase: "up_to_date" }
  );
  assert.equal(checking.phase, "up_to_date");
  assert.equal(U.statusTitle(checking), "");
  assert.equal(U.shouldShowStatus(checking), false);

  const viaDone = U.applyUpdateEvent(
    Object.assign(U.emptyState(), { phase: "checking", userCheck: true }),
    { phase: "done" }
  );
  assert.equal(viaDone.phase, "done");
  assert.notEqual(U.statusTitle(viaDone), "已是最新版本");
  assert.equal(U.statusTitle(viaDone), "");
  assert.equal(U.shouldShowStatus(viaDone), false);
});

test("按钮状态：无更新时灰色「已经是最新版」，有更新时「立即更新」", () => {
  const idle = U.updateStatusView(U.emptyState());
  assert.equal(idle.applyVisible, true);
  assert.equal(idle.applyLabel, "已经是最新版");
  assert.equal(idle.applyDisabled, true);

  const available = U.updateStatusView({
    ...U.emptyState(),
    phase: "available",
    availableVersion: "0.2.0",
  });
  // 「要更新到哪一版」只出现在按钮里（页内标题已去掉，避免同一件事说两遍）。
  assert.equal(available.applyLabel, "立即更新到 0.2.0");
  assert.equal(available.applyDisabled, false);

  const checking = U.updateStatusView({ ...U.emptyState(), phase: "checking" });
  assert.equal(checking.applyLabel, "正在检查…");
  assert.equal(checking.applyDisabled, true);
});

test("检查请求失败视为无更新，下载失败仍保留错误", () => {
  assert.equal(
    U.applyUpdateEvent(U.emptyState(), { phase: "error", code: "network" }).phase,
    "up_to_date"
  );
  assert.equal(
    U.applyUpdateEvent(U.emptyState(), { phase: "error", code: "check_failed" }).phase,
    "up_to_date"
  );
  const respFail = U.applyCheckResponse(U.emptyState(), { ok: false, code: "network" });
  assert.equal(respFail.phase, "up_to_date");
  assert.equal(respFail.code, "");
  assert.equal(U.applyCheckResponse(U.emptyState(), null).phase, "up_to_date");
  assert.equal(
    U.applyUpdateEvent(U.emptyState(), { phase: "error", code: "checksum_mismatch" }).phase,
    "error"
  );
});

test("state machine copy", () => {
  let s = U.emptyState();
  s.userCheck = true;
  s = U.applyUpdateEvent(s, { phase: "checking", current_version: "0.1.0" });
  assert.equal(s.phase, "checking");
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.shouldShowStatus(s), false);
  assert.equal(U.updateStatusView(s).checkLabel, "正在检查…");
  assert.equal(U.updateStatusView(s).checkDisabled, true);

  s = U.applyUpdateEvent(s, { phase: "up_to_date", current_version: "0.1.0" });
  assert.equal(s.phase, "up_to_date");
  assert.equal(U.statusTitle(s), "");
  // 只保留按钮内提醒：不再留一块空的状态区。
  assert.equal(U.shouldShowStatus(s), false);

  s = U.applyUpdateEvent(s, { phase: "available", version: "0.2.0", notes: "changelog" });
  assert.equal(s.phase, "available");
  // 页内**不再**出现"发现新版本 x"标题：这条信息只留在按钮里。
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.updateStatusView(s).title, "");
  assert.equal(U.updateStatusView(s).notes, "changelog");
  assert.equal(U.updateStatusView(s).notesVisible, true);
  assert.equal(U.updateStatusView(s).applyVisible, true);
  assert.equal(U.updateStatusView(s).applyLabel, "立即更新到 0.2.0");
  // 有说明才显示状态区（它此时只剩"更新说明"）。
  assert.equal(U.shouldShowStatus(s), true);

  s = U.applyUpdateEvent(s, { phase: "available", version: "0.2.1", notes: "" });
  assert.equal(U.updateStatusView(s).notesVisible, false);
  // 没说明 + 不再有标题 → 整块收起，页内只剩按钮一处提醒。
  assert.equal(U.shouldShowStatus(s), false);

  s = U.beginDownload(s);
  assert.equal(s.phase, "downloading");
  // 下载进度由进度条表达，标题不再重复「下载中…」。
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.shouldShowStatus(s), true);
  s = U.applyUpdateEvent(s, { phase: "checking" });
  assert.equal(s.phase, "downloading");
  s = U.applyUpdateEvent(s, { phase: "downloading", bytes_done: 45, bytes_total: 100 });
  assert.equal(U.eventPercent({ bytes_done: 45, bytes_total: 100 }), 45);
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.updateStatusView(s).progressVisible, true);
  assert.equal(U.updateStatusView(s).applyLabel, "下载中…");
  assert.equal(U.updateStatusView(s).applyDisabled, true);

  s = U.applyUpdateEvent(s, { phase: "verifying" });
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.shouldShowStatus(s), false);

  s = U.applyUpdateEvent(s, { phase: "applying" });
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.shouldShowStatus(s), false);
  assert.equal(U.updateStatusView(s).pageLocked, true);

  s = U.applyUpdateEvent(s, { phase: "done" });
  assert.equal(U.statusTitle(s), "");
  assert.equal(U.shouldShowStatus(s), false);

  let err = U.emptyState();
  // 错误原因不再放在标题里，改由说明区显示（按钮里说不出来）。
  err = U.applyUpdateEvent(err, { phase: "error", code: "checksum_mismatch" });
  assert.equal(U.statusTitle(err), "");
  assert.equal(U.updateStatusView(err).notes, U.ERR_CHECKSUM);
  assert.equal(U.updateStatusView(err).retryVisible, true);
  err = U.applyUpdateEvent(err, { phase: "error", code: "update_failed" });
  assert.equal(U.updateStatusView(err).notes, U.ERR_UPDATE_FAILED);
  assert.equal(U.updateStatusView(err).retryVisible, false);
  err = U.applyUpdateEvent(err, { phase: "error" });
  assert.equal(U.updateStatusView(err).notes, U.ERR_UPDATE_FAILED);
});

test("red-dot only when update available", () => {
  assert.equal(U.showUpdateDot({ phase: "available" }), true);
  assert.equal(U.showUpdateDot({ phase: "idle" }), false);
  assert.equal(U.showUpdateDot({ phase: "up_to_date", userCheck: true }), false);
  assert.equal(U.showUpdateDot({ phase: "error", code: "network" }), false);
  assert.equal(U.showUpdateDot({ phase: "downloading" }), false);
  assert.equal(U.updateStatusView({ phase: "available" }).redDot, true);
});

test("auto-check fail/up-to-date does not surface without user click", () => {
  let s = U.emptyState();
  s = U.applyUpdateEvent(s, { phase: "up_to_date" });
  assert.equal(s.phase, "up_to_date");
  assert.equal(U.shouldShowStatus(s), false);
  s = U.applyUpdateEvent(s, { phase: "error", code: "network" });
  assert.equal(U.shouldShowStatus(s), false);
  s.userCheck = true;
  // network 失败按「无更新」处理，状态区同样不再出现（信息只在按钮里）。
  assert.equal(U.shouldShowStatus(s), false);
});

test("settings page + html contracts", () => {
  assert.equal(E.settingsPageForKey("update.channel"), "update");
  assert.equal(E.settingsPageForKey("update.auto_check"), "update");
  const uiDir = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(uiDir, "index.html"), "utf8");
  const app = fs.readFileSync(path.join(uiDir, "app.js"), "utf8");
  const updateJs = fs.readFileSync(path.join(uiDir, "lib/update.js"), "utf8");
  assert.equal(html.includes("更新通道与检查将在后续版本提供。"), false);
  assert.equal(html.includes("启动后自动检查更新"), true);
  assert.equal(html.includes('id="btn-update-check"'), false);
  assert.equal(html.includes('id="btn-update-apply"'), true);
  assert.equal(html.includes("每 1 小时自动检查一次"), true);
  assert.equal(html.includes("已经是最新版"), true);
  assert.equal(html.includes("关于"), true);
  assert.equal(html.includes("开发信息"), true);
  assert.equal(html.includes("小熊宋"), true);
  assert.equal(html.includes("Apache License 2.0"), true);
  assert.equal(html.includes("github.com/fusongjie/AIDM"), true);
  assert.equal(app.includes("void requestUpdateCheck()"), true);
  assert.equal(html.includes("update-nav-dot"), true);
  assert.equal(html.includes('op: "http'), false);
  assert.equal(app.includes("innerHTML"), false);
  assert.equal(updateJs.includes("innerHTML"), false);
  assert.equal(updateJs.includes("update_check"), true);
  assert.equal(updateJs.includes("update_download_apply"), true);
  assert.equal(app.includes("U.OP_CHECK"), true);
  assert.equal(app.includes("U.OP_APPLY"), true);
  assert.match(app, /ev\.event === "update"/);
  assert.match(updateJs, /phase === "up_to_date"/);
});
