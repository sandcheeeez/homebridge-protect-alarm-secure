"use strict";

// Hardened fork of homebridge-protect-alarm 1.0.0 (MIT, see LICENSE).
// Changes vs upstream are summarised in CHANGELOG.md.
//
// No third-party dependencies: only Node built-ins, so nothing can be pulled
// in by a dependency update.

const https = require("https");
const tls = require("tls");
const fs = require("fs");
const path = require("path");

const PLUGIN_NAME = "homebridge-protect-alarm-secure";
const PLATFORM_NAME = "ProtectAlarmSecure";

const API_PREFIX = "/proxy/protect/integration/v1";
const REQUEST_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const PROFILE_REFRESH_MS = 10 * 60 * 1000;
const MAX_BACKOFF_MS = 5 * 60 * 1000;
const FAULT_AFTER_FAILURES = 3;
const VERIFY_ATTEMPTS = 8;
const VERIFY_DELAY_MS = 1000;

// Protect status strings that mean "an alarm is going off". Not documented by
// Ubiquiti; unknown statuses are logged so this list can be corrected.
const TRIGGERED_STATUSES = new Set(["triggered", "alarm", "alarming", "breached", "breach"]);
const ARMED_STATUSES = new Set(["armed", "arming"]);

let hap;

module.exports = (homebridge) => {
  hap = homebridge.hap;
  homebridge.registerPlatform(PLUGIN_NAME, PLATFORM_NAME, ProtectAlarmPlatform);
};

// ---------------------------------------------------------------------------
// Config helpers

function parseController(raw) {
  let s = String(raw || "").trim();
  s = s.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  const m = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(s);
  if (!m) return null;
  const port = m[2] ? Number(m[2]) : 443;
  if (port < 1 || port > 65535) return null;
  const host = m[1].replace(/^\[|\]$/g, "");
  return { host, port, label: m[2] ? `${m[1]}:${port}` : m[1] };
}

function normFingerprint(fp) {
  if (!fp) return null;
  const hex = String(fp).replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  return hex.length === 64 ? hex : null;
}

function prettyFingerprint(hex) {
  return hex.match(/../g).join(":");
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// TLS: certificate pinning
//
// UniFi consoles use a self-signed certificate, so normal CA validation fails.
// Upstream simply disabled verification, which lets anyone on the LAN who can
// intercept traffic capture the API key. Here every connection must present a
// certificate whose SHA-256 fingerprint matches a pinned value (configured, or
// recorded the first time the plugin connects). The socket is only handed to
// the HTTP layer after the check passes, so the API key is never sent to an
// unverified peer.

function readPeerFingerprint(host, port) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({
      host, port,
      servername: net_isIP(host) ? undefined : host,
      rejectUnauthorized: false,
      timeout: REQUEST_TIMEOUT_MS,
    });
    sock.once("secureConnect", () => {
      const cert = sock.getPeerCertificate();
      sock.destroy();
      const fp = cert && normFingerprint(cert.fingerprint256);
      fp ? resolve(fp) : reject(new Error("Console presented no certificate"));
    });
    sock.once("timeout", () => sock.destroy(new Error("TLS connect timed out")));
    sock.once("error", reject);
  });
}

function net_isIP(host) {
  return require("net").isIP(host) !== 0;
}

class PinnedAgent extends https.Agent {
  constructor(host, port, fingerprint) {
    super({ keepAlive: true, maxSockets: 2, maxCachedSessions: 0 });
    this.pinHost = host;
    this.pinPort = port;
    this.fingerprint = fingerprint;
  }

  createConnection(_options, callback) {
    const sock = tls.connect({
      host: this.pinHost,
      port: this.pinPort,
      servername: net_isIP(this.pinHost) ? undefined : this.pinHost,
      rejectUnauthorized: false, // replaced by the fingerprint check below
    });
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      if (err) { sock.destroy(); callback(err); } else callback(null, sock);
    };
    sock.once("secureConnect", () => {
      const seen = normFingerprint((sock.getPeerCertificate() || {}).fingerprint256);
      if (seen && seen === this.fingerprint) return finish(null);
      const err = new Error(
        `TLS certificate mismatch: console presented ${seen ? prettyFingerprint(seen) : "no certificate"}, ` +
        `expected ${prettyFingerprint(this.fingerprint)}. Refusing to send the API key. If you replaced the ` +
        `console certificate on purpose, verify the new fingerprint and put it in 'certFingerprint' (see README).`);
      err.code = "CERT_PIN_MISMATCH";
      err.seenFingerprint = seen;
      finish(err);
    });
    sock.once("error", finish);
    return undefined; // asynchronous: socket delivered via callback
  }
}

// ---------------------------------------------------------------------------
// Minimal JSON-over-HTTPS client

class ProtectClient {
  constructor({ host, port, apiKey, agent }) {
    this.host = host;
    this.port = port;
    this.apiKey = apiKey;
    this.agent = agent;
  }

  request(method, apiPath, body) {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = https.request({
        host: this.host,
        port: this.port,
        method,
        path: API_PREFIX + apiPath,
        agent: this.agent,
        timeout: REQUEST_TIMEOUT_MS,
        headers: {
          "X-API-KEY": this.apiKey,
          "Accept": "application/json",
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (c) => {
          size += c.length;
          if (size > MAX_RESPONSE_BYTES) {
            req.destroy(new Error("Response too large"));
          } else chunks.push(c);
        });
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let data = null;
          if (text) { try { data = JSON.parse(text); } catch { data = text; } }
          if (res.statusCode >= 200 && res.statusCode < 300) return resolve(data);
          const snippet = (typeof data === "string" ? data : JSON.stringify(data) || "").slice(0, 300);
          const err = new Error(`HTTP ${res.statusCode} from ${method} ${apiPath}${snippet ? ": " + snippet : ""}`);
          err.status = res.statusCode;
          reject(err);
        });
        res.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error(`Timed out: ${method} ${apiPath}`)));
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async getNvr() {
    const data = await this.request("GET", "/nvrs");
    return Array.isArray(data) ? data[0] : data;
  }

  async getArmProfiles() {
    const data = await this.request("GET", "/arm-profiles");
    return Array.isArray(data) ? data : [];
  }

  selectProfile(id) { return this.request("PATCH", "/arm-profiles/settings", { armProfileId: id }); }
  arm() { return this.request("POST", "/arm-profiles/enable", {}); }
  disarm() { return this.request("POST", "/arm-profiles/disable", {}); }
}

// ---------------------------------------------------------------------------
// Platform

class ProtectAlarmPlatform {
  constructor(log, config, api) {
    this.log = log;
    this.config = config || {};
    this.api = api;
    this.cached = [];
    if (!api) return;

    const ctl = parseController(this.config.controller);
    if (!ctl || !this.config.apiKey) {
      this.log.error("Config needs 'controller' (IP or hostname, optionally :port) and 'apiKey'. Plugin disabled.");
      return;
    }
    this.ctl = ctl;

    api.on("didFinishLaunching", () => {
      const uuid = hap.uuid.generate(`${PLUGIN_NAME}-${ctl.label}`);
      const stale = this.cached.filter(a => a.UUID !== uuid);
      if (stale.length) api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, stale);
      let accessory = this.cached.find(a => a.UUID === uuid);
      if (!accessory) {
        accessory = new api.platformAccessory(this.config.name || "Security System", uuid);
        api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
      }
      this.alarm = new ProtectAlarm(log, this.config, api, accessory, ctl);
    });
  }

  configureAccessory(accessory) {
    this.cached.push(accessory);
  }
}

// ---------------------------------------------------------------------------
// Accessory

class ProtectAlarm {
  constructor(log, config, api, accessory, ctl) {
    this.log = log;
    this.config = config;
    this.api = api;
    this.ctl = ctl;
    this.name = config.name || "Security System";
    const C = hap.Characteristic;
    this.T = C.SecuritySystemTargetState;
    this.S = C.SecuritySystemCurrentState;

    this.profileNames = {
      [this.T.AWAY_ARM]: config.awayProfileName || "Away",
      [this.T.NIGHT_ARM]: config.nightProfileName || "Night",
      [this.T.STAY_ARM]: config.homeProfileName || "Home",
    };
    this.pinnedIds = {
      [this.T.AWAY_ARM]: config.awayArmProfileId || null,
      [this.T.NIGHT_ARM]: config.nightArmProfileId || null,
      [this.T.STAY_ARM]: config.homeArmProfileId || null,
    };
    this.profileIds = { ...this.pinnedIds };
    this.profilesFetchedAt = 0;

    const p = Number(config.pollInterval);
    this.pollMs = (Number.isFinite(p) && p >= 2 ? Math.min(p, 300) : 5) * 1000;

    // Live state from the console. `known` stays false until the first
    // successful read so HomeKit sees "No Response" rather than a guess.
    this.known = false;
    this.status = null;
    this.activeProfileId = null;
    this.lastTarget = null;
    this.failures = 0;
    this.seenStatuses = new Set();
    this.warnedUnknownProfile = null;
    this.stopped = false;
    this.timer = null;
    this.queue = Promise.resolve();
    this.busy = 0;

    accessory.getService(hap.Service.AccessoryInformation)
      .setCharacteristic(C.Manufacturer, "Ubiquiti")
      .setCharacteristic(C.Model, "UniFi Protect Alarm")
      .setCharacteristic(C.SerialNumber, ctl.label);

    this.service = accessory.getService(hap.Service.SecuritySystem)
      || accessory.addService(hap.Service.SecuritySystem, this.name);
    this.service.getCharacteristic(this.S).onGet(() => this.getCurrent());
    this.service.getCharacteristic(this.T)
      .onGet(() => this.getTarget())
      .onSet((v) => this.setTarget(v));
    this.service.getCharacteristic(C.StatusFault).onGet(() =>
      this.failures >= FAULT_AFTER_FAILURES ? C.StatusFault.GENERAL_FAULT : C.StatusFault.NO_FAULT);

    api.on("shutdown", () => {
      this.stopped = true;
      clearTimeout(this.timer);
      if (this.client && this.client.agent) this.client.agent.destroy();
    });

    this.run();
  }

  // ---- startup / polling --------------------------------------------------

  async run() {
    let backoff = this.pollMs;
    while (!this.stopped) {
      try {
        if (!this.client) await this.connect();
        if (Date.now() - this.profilesFetchedAt > PROFILE_REFRESH_MS) await this.discoverProfiles();
        if (!this.busy) await this.refresh();
        if (this.failures > 0) this.log.info(`[${this.name}] Connection to console restored.`);
        this.setFailures(0);
        backoff = this.pollMs;
      } catch (err) {
        this.setFailures(this.failures + 1);
        if (err.code === "CERT_PIN_MISMATCH") this.client = null; // re-check pin config on retry
        const level = this.failures === 1 || this.failures % 20 === 0 ? "error" : "debug";
        this.log[level](`[${this.name}] ${err.message} (retrying in ${Math.round(backoff / 1000)}s)`);
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
      }
      await new Promise(r => { this.timer = setTimeout(r, backoff); });
    }
  }

  setFailures(n) {
    const wasFault = this.failures >= FAULT_AFTER_FAILURES;
    this.failures = n;
    const isFault = n >= FAULT_AFTER_FAILURES;
    if (wasFault !== isFault) {
      const F = hap.Characteristic.StatusFault;
      this.service.updateCharacteristic(F, isFault ? F.GENERAL_FAULT : F.NO_FAULT);
      if (isFault) {
        this.known = false;
        this.log.error(`[${this.name}] Console unreachable; HomeKit will show No Response until it recovers.`);
      }
    }
  }

  async connect() {
    const { host, port, label } = this.ctl;
    const mode = this.config.tlsMode === "ca" ? "ca" : "pin";
    let agent;

    if (mode === "ca") {
      // Console has a certificate from a public/trusted CA matching its hostname.
      agent = new https.Agent({ keepAlive: true, maxSockets: 2, rejectUnauthorized: true });
    } else {
      const configured = this.config.certFingerprint ? normFingerprint(this.config.certFingerprint) : null;
      if (this.config.certFingerprint && !configured) {
        throw new Error("'certFingerprint' is not a valid SHA-256 fingerprint (64 hex characters).");
      }
      let fp = configured;
      if (!fp) {
        const store = this.pinStore();
        fp = store.get(label);
        if (!fp) {
          fp = await readPeerFingerprint(host, port);
          store.set(label, fp);
          this.log.warn(
            `[${this.name}] First connection: pinned console certificate SHA-256 ${prettyFingerprint(fp)}. ` +
            `Verify this matches your console (see README), then optionally copy it into 'certFingerprint'.`);
        }
      }
      agent = new PinnedAgent(host, port, fp);
    }
    this.client = new ProtectClient({ host, port, apiKey: this.config.apiKey, agent });
  }

  pinStore() {
    const file = path.join(this.api.user.storagePath(), `${PLUGIN_NAME}-pins.json`);
    const read = () => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return {}; } };
    return {
      get: (k) => normFingerprint(read()[k]),
      set: (k, v) => {
        const all = read();
        all[k] = prettyFingerprint(v);
        fs.writeFileSync(file, JSON.stringify(all, null, 2), { mode: 0o600 });
      },
    };
  }

  async discoverProfiles() {
    let profiles;
    try {
      profiles = await this.client.getArmProfiles();
    } catch (err) {
      if (err.status === 401 || err.status === 403) {
        throw new Error(`${err.message}. Check the API key and that its user has Protect access.`);
      }
      if (err.status === 404) {
        throw new Error(`${err.message}. Arm profiles aren't available through the integration API on this console ` +
          `(Protect too old, or Alarm Manager is in Global mode, which this API reportedly can't control).`);
      }
      throw err;
    }
    this.profilesFetchedAt = Date.now();

    const byName = (n) => (profiles.find(p => (p.name || "").trim().toLowerCase() === n.trim().toLowerCase()) || {}).id || null;
    const before = JSON.stringify(this.profileIds);
    for (const mode of [this.T.AWAY_ARM, this.T.NIGHT_ARM, this.T.STAY_ARM]) {
      this.profileIds[mode] = this.pinnedIds[mode] || byName(this.profileNames[mode]);
    }
    this.profileNamesById = Object.fromEntries(profiles.map(p => [p.id, p.name]));

    if (JSON.stringify(this.profileIds) !== before || !this.loggedProfiles) {
      this.loggedProfiles = true;
      const show = (m, label) => `${label} → ${this.profileIds[m] ? `"${this.profileNames[m]}"` : "not mapped"}`;
      this.log.info(`[${this.name}] Profiles: ${show(this.T.AWAY_ARM, "Away")}, ${show(this.T.NIGHT_ARM, "Night")}, ` +
        `${show(this.T.STAY_ARM, "Home")}. Available on console: ${profiles.map(p => `"${p.name}"`).join(", ") || "none"}`);
      if (!profiles.length) {
        this.log.warn(`[${this.name}] Console returned no arm profiles. If you use UniFi alarm sensors/hub/fobs, ` +
          `Alarm Manager may be in Global mode, which the integration API reportedly can't control.`);
      }
    }

    // Only offer modes in the Home app that actually map to a profile.
    const valid = [this.T.DISARM, ...[this.T.STAY_ARM, this.T.AWAY_ARM, this.T.NIGHT_ARM].filter(m => this.profileIds[m])];
    this.service.getCharacteristic(this.T).setProps({ validValues: valid.sort() });
  }

  async refresh() {
    const nvr = await this.client.getNvr();
    const armMode = (nvr && nvr.armMode) || {};
    const status = String(armMode.status || "unknown").toLowerCase();
    if (!this.seenStatuses.has(status)) {
      this.seenStatuses.add(status);
      this.log.info(`[${this.name}] Console alarm status "${status}"` +
        (ARMED_STATUSES.has(status) || TRIGGERED_STATUSES.has(status) || ["disarmed", "disabled", "unknown"].includes(status)
          ? "" : " (unrecognised; treated as disarmed — please report this value)"));
    }

    const prev = `${this.known}|${this.status}|${this.activeProfileId}`;
    this.status = status;
    this.activeProfileId = this.isArmed() ? (armMode.armProfileId || null) : null;
    this.known = true;

    if (this.activeProfileId && this.modeForProfile(this.activeProfileId) === null &&
        this.warnedUnknownProfile !== this.activeProfileId) {
      this.warnedUnknownProfile = this.activeProfileId;
      const n = (this.profileNamesById || {})[this.activeProfileId];
      this.log.warn(`[${this.name}] Armed with profile ${n ? `"${n}"` : this.activeProfileId}, which isn't mapped to a ` +
        `HomeKit mode; showing it as Away.`);
      this.profilesFetchedAt = 0; // profile may be new; rediscover next cycle
    }

    if (`${this.known}|${this.status}|${this.activeProfileId}` !== prev) {
      this.log.info(`[${this.name}] State: ${this.describeState()}`);
      this.pushState();
    }
    return { status: this.status, activeProfileId: this.activeProfileId };
  }

  // ---- state mapping ------------------------------------------------------

  isTriggered() { return TRIGGERED_STATUSES.has(this.status); }
  isArmed() { return ARMED_STATUSES.has(this.status) || this.isTriggered(); }

  modeForProfile(id) {
    for (const m of [this.T.AWAY_ARM, this.T.NIGHT_ARM, this.T.STAY_ARM]) {
      if (this.profileIds[m] && this.profileIds[m] === id) return m;
    }
    return null;
  }

  armedMode() {
    const m = this.activeProfileId ? this.modeForProfile(this.activeProfileId) : null;
    if (m !== null) return m;
    if (!this.activeProfileId && this.lastTarget !== null && this.lastTarget !== this.T.DISARM) return this.lastTarget;
    return this.T.AWAY_ARM;
  }

  currentValue() {
    if (this.isTriggered()) return this.S.ALARM_TRIGGERED;
    if (!this.isArmed()) return this.S.DISARMED;
    return this.armedMode(); // STAY/AWAY/NIGHT share numeric values across both characteristics
  }

  targetValue() {
    return this.isArmed() ? this.armedMode() : this.T.DISARM;
  }

  describeState() {
    if (this.isTriggered()) return "ALARM TRIGGERED";
    if (!this.isArmed()) return "Disarmed";
    const names = { [this.T.AWAY_ARM]: "Away", [this.T.NIGHT_ARM]: "Night", [this.T.STAY_ARM]: "Home" };
    return `Armed (${names[this.armedMode()]})${this.status === "arming" ? ", exit delay" : ""}`;
  }

  pushState() {
    if (!this.known) return;
    this.service.updateCharacteristic(this.T, this.targetValue());
    this.service.updateCharacteristic(this.S, this.currentValue());
  }

  noResponse() {
    return new hap.HapStatusError(hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
  }

  getCurrent() {
    if (!this.known) throw this.noResponse();
    return this.currentValue();
  }

  getTarget() {
    if (!this.known) throw this.noResponse();
    return this.targetValue();
  }

  // ---- commands -----------------------------------------------------------

  setTarget(value) {
    // Serialise commands so rapid taps can't interleave select/arm calls.
    const run = this.queue.then(() => this.applyTarget(value));
    this.queue = run.catch(() => {});
    return run;
  }

  async applyTarget(value) {
    const names = { [this.T.AWAY_ARM]: "Away", [this.T.NIGHT_ARM]: "Night", [this.T.STAY_ARM]: "Home", [this.T.DISARM]: "Disarm" };
    this.busy++;
    try {
      if (!this.client) throw new Error("not connected to console yet");

      if (value === this.T.DISARM) {
        this.log.info(`[${this.name}] HomeKit requested Disarm.`);
        await this.client.disarm();
        await this.verify(() => !this.isArmed(), "disarmed");
        this.lastTarget = this.T.DISARM;
      } else {
        const profileId = this.profileIds[value];
        if (!profileId) throw new Error(`no arm profile mapped to HomeKit "${names[value]}"`);
        this.log.info(`[${this.name}] HomeKit requested ${names[value]} (profile "${this.profileNames[value]}").`);
        // The integration API arms whichever profile is *selected* on the
        // console, so select it first, then arm.
        await this.client.selectProfile(profileId);
        await this.client.arm();
        this.lastTarget = value;
        await this.verify(() => this.isArmed() && (this.activeProfileId === profileId || !this.activeProfileId),
          `armed with "${this.profileNames[value]}"`);
      }
      this.log.info(`[${this.name}] Confirmed: ${this.describeState()}.`);
    } catch (err) {
      this.log.error(`[${this.name}] ${names[value] || value} failed: ${err.message}`);
      // Snap HomeKit back to the real state once the error has been returned.
      setTimeout(() => this.refresh().catch(() => {}).then(() => this.pushState()), 500);
      throw this.noResponse();
    } finally {
      this.busy--;
    }
  }

  async verify(ok, what) {
    for (let i = 0; i < VERIFY_ATTEMPTS; i++) {
      await this.refresh();
      if (ok()) return;
      await sleep(VERIFY_DELAY_MS);
    }
    throw new Error(`console accepted the command but did not report ${what} after ${VERIFY_ATTEMPTS}s ` +
      `(now: ${this.describeState()})`);
  }
}

module.exports._internal = { parseController, normFingerprint, PinnedAgent, ProtectClient, PLUGIN_NAME, PLATFORM_NAME };
