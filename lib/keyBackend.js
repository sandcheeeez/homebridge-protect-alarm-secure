"use strict";

// API-key backend: the official Protect integration API. Only works when
// Alarm Manager is NOT in Global mode. The integration API arms whichever
// profile is *selected* on the console, so arming selects first.

const { request, HttpError } = require("./http");

const PREFIX = "/proxy/protect/integration/v1";
const TRIGGERED = new Set(["triggered", "alarm", "alarming", "breached", "breach"]);
const UNKNOWN_ACTIVE = "__unknown_active_profile__";

class KeyBackend {
  constructor({ host, port, agent, apiKey }) {
    Object.assign(this, { host, port, agent, apiKey });
    this.supportsPush = false;
    this.mode = "API key";
  }

  async call(method, path, json) {
    const res = await request({
      host: this.host, port: this.port, agent: this.agent, method, path: PREFIX + path,
      headers: { "X-API-KEY": this.apiKey }, json,
    });
    if (res.status >= 200 && res.status < 300) return res.data;
    let hint;
    const msg = JSON.stringify(res.data || "");
    if (/global alarm manager/i.test(msg)) {
      hint = "Alarm Manager is in Global mode (alarm hub/sensors adopted), which the API key can't control. " +
        "Set 'username' and 'password' for a local Super Admin instead (see README)";
    } else if (res.status === 401 || res.status === 403) {
      hint = "Check the API key: it must be a local key created on this console, not a Site Manager key";
    } else if (res.status === 404) {
      hint = "Arm profiles aren't available through the integration API on this console";
    }
    const err = new HttpError(method, path, res.status, res.data, hint);
    if (hint && /Global mode/.test(hint)) err.fatalConfig = true;
    throw err;
  }

  async login() { /* API keys need no session */ }

  async fetchProfiles() {
    const list = await this.call("GET", "/arm-profiles");
    let nvr = await this.call("GET", "/nvrs");
    nvr = Array.isArray(nvr) ? nvr[0] : nvr;
    const armMode = (nvr && nvr.armMode) || {};
    const raw = String(armMode.status || "disarmed").toLowerCase();
    const status = TRIGGERED.has(raw) ? "breached" : raw;
    const active = status === "armed" || status === "arming" || status === "breached";
    const profiles = (Array.isArray(list) ? list : []).map((p) => ({
      id: String(p.id), title: String(p.name || p.id),
      state: active && p.id === armMode.armProfileId ? status : "disarmed",
    }));
    if (active && !profiles.some((p) => p.id === armMode.armProfileId)) {
      profiles.push({ id: armMode.armProfileId || UNKNOWN_ACTIVE, title: armMode.armProfileId || "(unknown)", state: status });
    }
    return { profiles, rawStatuses: [raw] };
  }

  async arm(profileId) {
    await this.call("PATCH", "/arm-profiles/settings", { armProfileId: profileId });
    await this.call("POST", "/arm-profiles/enable", {});
    return null; // caller verifies by polling
  }

  async disarmAll() {
    await this.call("POST", "/arm-profiles/disable", {});
    return [];
  }
}

module.exports = { KeyBackend, UNKNOWN_ACTIVE };
