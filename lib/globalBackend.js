"use strict";

// Global-mode backend: UniFi OS's own (undocumented) Alarm Manager API, used
// when alarm hardware has put Alarm Manager into Global mode. Endpoints and
// session handling follow violuke/ha_unifi_protect_alarm_bridge (MIT).
//
// Requires a local-only Super Admin without two-factor authentication.

const zlib = require("zlib");
const { request, HttpError } = require("./http");
const ws = require("./ws");

const LOGIN_PATH = "/api/auth/login";
const NVR_PATH = "/proxy/protect/api/nvr";
const PROFILES_PATH = "/api/v2/alarms/profiles";
const UPDATES_WS_PATH = "/proxy/protect/ws/updates";
const PROFILE_MODEL_KEY = "externalArmProfile";

class AuthError extends Error {}

function toMs(v) {
  if (typeof v !== "string") return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

function parseProfile(p) {
  if (!p || typeof p !== "object" || typeof p.id !== "string" || typeof p.title !== "string" ||
      typeof p.state !== "string") {
    return null;
  }
  const delay = Number.isInteger(p.activation_delay) ? p.activation_delay : null;
  const setAt = toMs(p.state_set_at);
  let dueAt = toMs(p.state_promotion_due_at);
  // Websocket payloads omit the due time; derive it like the HA bridge does.
  if (dueAt === null && p.state === "arming" && setAt !== null && delay) dueAt = setAt + delay * 1000;
  return { id: p.id, title: p.title, state: p.state.toLowerCase(), dueAt };
}

// Protect update packets: one or more frames, each with an 8-byte header
// (type, payload format, deflated flag, reserved, payload size).
function decodePacket(buf) {
  const frames = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 8 > buf.length) throw new Error("truncated frame header");
    const format = buf[off + 1];
    const deflated = buf[off + 2];
    const size = buf.readUInt32BE(off + 4);
    off += 8;
    if (off + size > buf.length) throw new Error("truncated frame payload");
    let payload = buf.subarray(off, off + size);
    off += size;
    if (deflated) payload = zlib.inflateSync(payload);
    if (format === 1) frames.push(JSON.parse(payload.toString("utf8")));
    else if (format === 2) frames.push(payload.toString("utf8"));
    else frames.push(payload);
  }
  return frames;
}

function csrfFromJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return typeof claims.csrfToken === "string" ? claims.csrfToken : null;
  } catch {
    return null;
  }
}

class GlobalBackend {
  constructor({ host, port, agent, username, password }) {
    Object.assign(this, { host, port, agent, username, password });
    this.supportsPush = true;
    this.mode = "Global (local admin login)";
    this.cookies = new Map();
    this.csrf = null;
    this.generation = 0;
    this.loginPromise = null;
  }

  captureCookies(headers) {
    for (const c of [].concat(headers["set-cookie"] || [])) {
      const m = /^\s*([^=;\s]+)=([^;]*)/.exec(c);
      if (!m) continue;
      if (/;\s*max-age=0\b/i.test(c) || /;\s*expires=Thu, 01 Jan 1970/i.test(c)) this.cookies.delete(m[1]);
      else this.cookies.set(m[1], m[2]);
    }
    const updated = headers["x-updated-csrf-token"];
    if (typeof updated === "string" && updated) this.csrf = updated;
  }

  authHeaders() {
    const h = {};
    if (this.cookies.size) h.Cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (this.csrf) h["X-CSRF-Token"] = this.csrf;
    return h;
  }

  // Only one login at a time; callers that saw an older session generation
  // share the in-flight login instead of starting another (avoids lockouts).
  login(staleGeneration) {
    if (staleGeneration !== undefined && staleGeneration !== this.generation) return Promise.resolve();
    if (!this.loginPromise) {
      this.loginPromise = this.doLogin().finally(() => { this.loginPromise = null; });
    }
    return this.loginPromise;
  }

  async doLogin() {
    this.cookies.clear();
    this.csrf = null;
    const res = await request({
      host: this.host, port: this.port, agent: this.agent, method: "POST", path: LOGIN_PATH,
      json: { username: this.username, password: this.password, rememberMe: true },
    });
    const fail = (msg, extra = {}) => Object.assign(new AuthError(msg), extra);
    if (res.status === 499) throw fail("Login needs two-factor authentication. Use a local-only admin without MFA.", { fatalAuth: true });
    if (res.status === 429) throw fail("Console is rate-limiting logins; waiting before retrying.", { rateLimited: true });
    if ([400, 401, 403].includes(res.status)) throw fail(`Login rejected (HTTP ${res.status}). Check 'username' and 'password'.`, { fatalAuth: true });
    if (res.status !== 200) throw new HttpError("POST", LOGIN_PATH, res.status, res.data);
    this.captureCookies(res.headers);
    this.csrf = res.headers["x-updated-csrf-token"] || res.headers["x-csrf-token"] || csrfFromJwt(this.cookies.get("TOKEN"));
    if (!this.csrf) throw new Error("Login response had no CSRF token (UniFi OS API may have changed)");
    this.generation++;
  }

  async send(method, path) {
    const res = await request({ host: this.host, port: this.port, agent: this.agent, method, path, headers: this.authHeaders() });
    this.captureCookies(res.headers);
    return res;
  }

  async call(method, path) {
    const fresh = !this.csrf;
    if (fresh) await this.login(this.generation);
    const gen = this.generation;
    let res = await this.send(method, path);
    const notSuper = () => Object.assign(new AuthError(
      `${method} ${path} is forbidden for this account. Alarm Manager needs a Super Admin ` +
      "(Admin Privileges: Full)."), { fatalAuth: true });
    if (res.status === 403 && fresh) throw notSuper();
    if (res.status === 401 || res.status === 403) {
      await this.login(gen); // session expired or stale CSRF: one fresh login, then trust the answer
      res = await this.send(method, path);
      if (res.status === 403) throw notSuper();
    }
    if (res.status === 429) throw Object.assign(new AuthError("Console is rate-limiting requests."), { rateLimited: true });
    if (res.status < 200 || res.status >= 300) throw new HttpError(method, path, res.status, res.data);
    if (typeof res.data === "string") throw new Error(`${method} ${path} returned non-JSON (API may have changed)`);
    return res.data;
  }

  async consoleInfo() {
    const nvr = await this.call("GET", NVR_PATH);
    const flags = (nvr && nvr.featureFlags) || {};
    return {
      globalMode: typeof flags.useExternalAlarmManager === "boolean" ? flags.useExternalAlarmManager : null,
      protectVersion: nvr && nvr.version,
    };
  }

  async fetchProfiles() {
    const data = await this.call("GET", PROFILES_PATH);
    if (!Array.isArray(data)) throw new Error("Profiles response is not a list (UniFi OS API may have changed)");
    const profiles = data.map(parseProfile);
    if (profiles.some((p) => !p)) throw new Error("Unexpected arm profile format (UniFi OS API may have changed)");
    return { profiles, rawStatuses: profiles.map((p) => p.state) };
  }

  async action(profileId, action) {
    const p = parseProfile(await this.call("POST", `${PROFILES_PATH}/${encodeURIComponent(profileId)}/actions/${action}`));
    if (!p) throw new Error(`Unexpected ${action} response (UniFi OS API may have changed)`);
    return p;
  }

  arm(profileId) { return this.action(profileId, "arm"); }
  disarm(profileId) { return this.action(profileId, "disarm"); }

  // Opens Protect's update websocket. Resolves to a connection emitting
  // "profile" (parsed profile), "resync" and "close".
  async openUpdates() {
    if (!this.csrf) await this.login(this.generation);
    const gen = this.generation;
    const open = () => ws.connect({ host: this.host, port: this.port, agent: this.agent, path: UPDATES_WS_PATH, headers: this.authHeaders() });
    let conn;
    try {
      conn = await open();
    } catch (err) {
      if (err.status !== 401 && err.status !== 403) throw err;
      await this.login(gen);
      conn = await open();
    }
    conn.on("message", (msg, binary) => {
      if (!binary) return;
      let frames;
      try { frames = decodePacket(msg); } catch { return; }
      const [head, body] = frames;
      if (!head || typeof head !== "object" || head.modelKey !== PROFILE_MODEL_KEY || head.action !== "update") return;
      const p = parseProfile(body);
      if (p) conn.emit("profile", p);
      else conn.emit("resync");
    });
    return conn;
  }
}

module.exports = { GlobalBackend, decodePacket, parseProfile, csrfFromJwt };
