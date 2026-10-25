"use strict";

const net = require("node:net");

function taskView(partial) {
  return Object.assign(
    {
      id: 1,
      name: "a.bin",
      state: "queued",
      done: 0,
      total: 100,
      speed: 0,
      pct: 0,
      save_path: "/tmp/a.bin",
      url: "https://example.com/a.bin",
      source: "manual",
      priority: 0,
    },
    partial
  );
}

class MockEngine {
  constructor() {
    this.tasks = [];
    this.settings = {
      "ui.confirm_on_delete": "true",
      "paths.default_dir": "/tmp",
      "speed.global_limit_kbps": "0",
      "conn.max_conns_per_task": "8",
      "conn.global_conn_cap": "32",
      "conn.retry_max": "5",
      "conn.retry_backoff_ms": "1000",
      "sched.start_cron": "",
      "browser.enabled": "true",
      "browser.allowed_ext_ids": "[]",
      "proxy.mode": "follow-system",
      "update.channel": "stable",
      "update.auto_check": "true",
      "update.last_check_at": "",
      "app.version": "0.1.0",
    };
    this.appVersion = "0.1.0";
    this.updateAvailable = null;
    this.updateCheckError = null;
    this.updateApplyError = null;
    this.nextId = 1;
    this.subscribers = [];
    this.structuredError = null;
    this.failOps = new Set();
    this.lastRequests = [];
    this.offline = false;
    this.server = null;
    this.port = 0;
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this.onConn(socket));
      this.server.listen(0, "127.0.0.1", () => {
        this.port = this.server.address().port;
        resolve(this.port);
      });
      this.server.on("error", reject);
    });
  }

  stop() {
    this.offline = true;
    for (const s of this.subscribers) {
      try { s.destroy(); } catch { /* ignore */ }
    }
    this.subscribers = [];
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
      this.server = null;
    });
  }

  push(event) {
    const line = JSON.stringify(event) + "\n";
    for (const s of this.subscribers) {
      try { s.write(line); } catch { /* ignore */ }
    }
  }

  handle(req) {
    const op = req && req.op;
    this.lastRequests.push(req);
    if (this.failOps.has(op)) return { ok: false, error: "busy" };
    if (op === "ping") return { ok: true, version: this.appVersion || "test" };
    if (op === "list") return { ok: true, tasks: this.tasks };
    if (op === "add") {
      const id = this.nextId++;
      const t = taskView({
        id,
        url: req.url,
        name: req.filename || "download.bin",
        save_path: (req.dir || "/tmp") + "/" + (req.filename || "download.bin"),
        state: req.start === "queue" ? "queued" : "downloading",
        source: req.source || "manual",
      });
      this.tasks.push(t);
      return { ok: true, id };
    }
    if (op === "pause") {
      const t = this.tasks.find((x) => x.id === req.id);
      if (!t) return { ok: false, error: "not_found" };
      t.state = "paused";
      return { ok: true };
    }
    if (op === "resume") {
      const t = this.tasks.find((x) => x.id === req.id);
      if (!t) return { ok: false, error: "not_found" };
      t.state = "downloading";
      t.error_code = undefined;
      return { ok: true };
    }
    if (op === "restart") {
      const t = this.tasks.find((x) => x.id === req.id);
      if (!t) return { ok: false, error: "task_not_found" };
      t.state = "queued";
      t.error_code = undefined;
      t.error = undefined;
      t.http_status = undefined;
      t.done = 0;
      t.pct = 0;
      t.segments = [];
      return { ok: true };
    }
    if (op === "delete") {
      const ids = new Set(req.ids || []);
      this.tasks = this.tasks.filter((t) => !ids.has(t.id));
      return { ok: true, deleted_files: !!req.delete_files };
    }
    if (op === "settings_get") return { ok: true, settings: this.settings, version: this.appVersion || "test" };
    if (op === "settings_set") {
      if (this.structuredError) {
        const err = this.structuredError;
        return { ok: false, code: err.code, key: req.key, min: err.min, max: err.max };
      }
      this.settings[req.key] = req.value;
      return { ok: true };
    }
    if (op === "system_proxy_get") return { ok: true, system_proxy: null };
    if (op === "host_status") return { ok: true, registered: true };
    if (op === "sched_status") return { ok: true, next_start_at: null, queued: 0, active: 0 };
    if (op === "retry_failed") return { ok: true, count: 0 };
    if (op === "subscribe") return { ok: true, subscribe: true };
    if (op === "rename") {
      const t = this.tasks.find((x) => x.id === req.id);
      if (!t) return { ok: false, error: "task_not_found" };
      const name = String(req.filename || "").trim();
      if (!name || name.includes("/") || name.includes("\\") || name.includes("..")) {
        return { ok: false, code: "invalid_filename" };
      }
      if (this.tasks.some((x) => x.id !== t.id && x.name === name)) {
        return { ok: false, code: "name_taken" };
      }
      t.name = name;
      const slash = Math.max(t.save_path.lastIndexOf("/"), t.save_path.lastIndexOf("\\"));
      t.save_path = slash >= 0 ? t.save_path.slice(0, slash + 1) + name : name;
      return { ok: true, task: { ...t } };
    }
    if (op === "update_check") {
      if (this.updateCheckError) {
        return { ok: false, code: this.updateCheckError };
      }
      this.settings["update.last_check_at"] = String(Date.now());
      const current = this.settings["app.version"] || this.appVersion || "";
      const available = this.updateAvailable;
      setTimeout(() => {
        this.push({ event: "update", phase: "checking", current_version: current });
        if (available) {
          this.push({
            event: "update",
            phase: "available",
            version: available.version,
            notes: available.notes || "",
            current_version: current,
          });
        } else {
          this.push({ event: "update", phase: "up_to_date", current_version: current });
        }
      }, 0);
      return { ok: true, version: current || "test" };
    }
    if (op === "update_download_apply") {
      if (this.updateApplyError) {
        const code = this.updateApplyError;
        setTimeout(() => {
          this.push({ event: "update", phase: "error", code });
        }, 0);
        return { ok: true };
      }
      const current = this.settings["app.version"] || this.appVersion || "";
      setTimeout(() => {
        this.push({ event: "update", phase: "checking", current_version: current });
        this.push({
          event: "update",
          phase: "downloading",
          bytes_done: 45,
          bytes_total: 100,
          current_version: current,
        });
        this.push({ event: "update", phase: "verifying", current_version: current });
        this.push({ event: "update", phase: "applying", current_version: current });
        this.push({ event: "update", phase: "done", current_version: current });
      }, 0);
      return { ok: true };
    }
    return { ok: false, error: "unknown_op" };
  }

  onConn(socket) {
    if (this.offline) {
      socket.destroy();
      return;
    }
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        let req;
        try { req = JSON.parse(line); } catch { req = {}; }
        const resp = this.handle(req);
        if (resp.subscribe) {
          socket.write(JSON.stringify({ ok: true }) + "\n");
          this.subscribers.push(socket);
          socket.write(JSON.stringify({ event: "heartbeat" }) + "\n");
          return;
        }
        socket.write(JSON.stringify(resp) + "\n");
        socket.end();
      }
    });
  }
}

function roundtrip(port, req) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: "127.0.0.1", port }, () => {
      sock.write(JSON.stringify(req) + "\n");
    });
    let data = "";
    sock.on("data", (c) => { data += c.toString("utf8"); });
    sock.on("end", () => {
      try { resolve(JSON.parse(data.trim().split("\n")[0])); }
      catch (e) { reject(e); }
    });
    sock.on("error", reject);
    sock.setTimeout(2000, () => {
      sock.destroy();
      reject(new Error("timeout"));
    });
  });
}

module.exports = { MockEngine, taskView, roundtrip };
