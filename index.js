"use strict";

// Hardened fork of homebridge-protect-alarm 1.0.0 (MIT, see LICENSE), with
// Global Alarm Manager support modelled on violuke/ha_unifi_protect_alarm_bridge
// (MIT). Changes are summarised in CHANGELOG.md.
//
// No third-party dependencies: only Node built-ins.

const fs = require("fs");
const path = require("path");
const { normFingerprint, prettyFingerprint, readPeerFingerprint, PinnedAgent } = require("./lib/tls");
const { KeyBackend, UNKNOWN_ACTIVE } = require("./lib/keyBackend");
const { GlobalBackend } = require("./lib/globalBackend");

const PLUGIN_NAME = "homebridge-protect-alarm-secure";
const PLATFORM_NAME = "ProtectAlarmSecure";

const MAX_BACKOFF_MS = 5 * 60 * 1000;
const FAULT_AFTER_FAILURES = 3;
const VERIFY_ATTEMPTS = 8;
const VERIFY_DELAY_MS = 1000;
// Global mode: live updates carry state; polling is the safety net.
const POLL_PUSH_HEALTHY_MS = 60 * 1000;
const POLL_PUSH_DOWN_MS = 10 * 1000;
const WS_PING_MS = 30 * 1000;
const WS_SILENCE_MS = 90 * 1000;
const WS_BACKOFF_MAX_MS = 5 * 60 * 1000;
const PROMOTION_GRACE_MS = 2000;
const PROMOTION_MIN_MS = 5000;

const ACTIVE = new Set(["arming", "armed", "breached"]);
const KNOWN_STATES = new Set(["disarmed", "arming", "armed", "breached"]);

let hap;

module.exports = (homebridge) => {
  hap = homebridge.hap;
  homebridge.registerPlatform(PLUGIN_NAME, PLATFORM_NAME, ProtectAlarmPlatform);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseController(raw) {
  let s = String(raw || "").trim();
  s = s.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  const m = /^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(s);
  if (!m) return null;
  const port = m[2] ? Number(m[2]) : 443;
  if (port < 1 || port > 65535) return null;
  return { host: m[1].replace(/^\[|\]$/g, ""), port, label: m[2] ? `${m[1]}:${port}` : m[1] };
}

// ---------------------------------------------------------------------------

class ProtectAlarmPlatform {
  constructor(log, config, api) {
    this.log = log;
    this.config = config || {};
    this.api = api;
    this.cached = [];
    if (!api) return;

    const ctl = parseController(this.config.controller);
    const hasLogin = Boolean(this.config.username && this.config.password);
    if (!ctl || (!hasLogin && !this.config.apiKey)) {
      this.log.error("Config needs 'controller' (the Protect console's IP) plus either 'username'/'password' " +
        "(Global mode) or 'apiKey'. Plugin disabled.");
      return;
    }

    api.on("didFinishLaunching", () => {
      const uuid = hap.uuid.generate(`${PLUGIN_NAME}-${ctl.label}`);
      const stale = this.cached.filter((a) => a.UUID !== uuid);
      if (stale.length) api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, stale);
      let accessory = this.cached.find((a) => a.UUID === uuid);
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

class ProtectAlarm {
  constructor(log, config, api, accessory, ctl) {
    this.log = log;
    this.config = config;
    this.api = api;
    this.ctl = ctl;
    this.name = config.name || "Security System";
    this.useLogin = Boolean(config.username && config.password);
    const C = hap.Characteristic;
    this.T = C.SecuritySystemTargetState;
    this.S = C.SecuritySystemCurrentState;
    this.MODES = [this.T.STAY_ARM, this.T.AWAY_ARM, this.T.NIGHT_ARM];
    this.MODE_NAMES = { [this.T.STAY_ARM]: "Home", [this.T.AWAY_ARM]: "Away", [this.T.NIGHT_ARM]: "Night", [this.T.DISARM]: "Off" };

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

    const p = Number(config.pollInterval);
    this.keyPollMs = (Number.isFinite(p) && p >= 2 ? Math.min(p, 300) : 5) * 1000;

    this.profiles = new Map(); // id -> { id, title, state, dueAt }
    this.known = false;
    this.failures = 0;
    this.lastTarget = null;
    this.loggedStates = new Set();
    this.warnedUnmapped = new Set();
    this.mappingLogged = null;
    this.stopped = false;
    this.timers = new Set();
    this.queue = Promise.resolve();
    this.busy = 0;
    this.pushConnected = false;
    this.wakePoll = null;

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

    api.on("shutdown", () => this.shutdown());
    this.pollLoop();
  }

  shutdown() {
    this.stopped = true;
    for (const t of this.timers) clearTimeout(t);
    if (this.wsConn) this.wsConn.close();
    if (this.agent) this.agent.destroy();
    if (this.wakePoll) this.wakePoll();
  }

  delay(ms) {
    return new Promise((resolve) => {
      const t = setTimeout(() => { this.timers.delete(t); resolve(); }, ms);
      this.timers.add(t);
    });
  }

  // ---- connection -----------------------------------------------------------

  async connect() {
    const { host, port, label } = this.ctl;
    if (this.agent) this.agent.destroy(); // from a previous failed attempt
    if (this.config.tlsMode === "ca") {
      this.agent = new (require("https").Agent)({ keepAlive: true, maxSockets: 4, rejectUnauthorized: true });
    } else {
      const configured = this.config.certFingerprint ? normFingerprint(this.config.certFingerprint) : null;
      if (this.config.certFingerprint && !configured) {
        throw Object.assign(new Error("'certFingerprint' is not a valid SHA-256 fingerprint (64 hex characters)."), { fatalConfig: true });
      }
      let fp = configured;
      if (!fp) {
        const store = this.pinStore();
        fp = store.get(label);
        if (!fp) {
          fp = await readPeerFingerprint(host, port);
          store.set(label, fp);
          this.log.warn(`First connection: pinned console certificate SHA-256 ${prettyFingerprint(fp)}. ` +
            "Verify it matches your console (see README), then optionally copy it into 'certFingerprint'.");
        }
      }
      this.agent = new PinnedAgent(host, port, fp);
    }

    let backend;
    if (this.useLogin) {
      if (this.config.apiKey) this.log.info(`Both a login and an API key are set; using the login (Global mode).`);
      backend = new GlobalBackend({ host, port, agent: this.agent, username: this.config.username, password: this.config.password });
      const info = await backend.consoleInfo();
      if (info.globalMode === false) {
        this.log.warn(`Alarm Manager is not in Global mode on this console. Global-mode login works ` +
          "only in Global mode; use an API key instead.");
      }
    } else {
      backend = new KeyBackend({ host, port, agent: this.agent, apiKey: this.config.apiKey });
    }
    this.backend = backend; // only once fully connected
    this.log.info(`Connected to ${label} (${backend.mode}).`);
    if (backend.supportsPush) this.pushLoop(backend);
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

  // ---- polling (always on; the safety net in Global mode) --------------------

  pollInterval() {
    if (!this.backend || !this.backend.supportsPush) return this.keyPollMs;
    return this.pushConnected ? POLL_PUSH_HEALTHY_MS : POLL_PUSH_DOWN_MS;
  }

  async pollLoop() {
    let backoff = 0;
    while (!this.stopped) {
      let wait;
      try {
        if (!this.backend) await this.connect();
        if (!this.busy) await this.refresh();
        if (this.failures > 0) this.log.info(`Connection to console restored.`);
        this.setFailures(0);
        backoff = 0;
        wait = this.pollInterval();
      } catch (err) {
        this.setFailures(this.failures + 1);
        if (err.code === "CERT_PIN_MISMATCH") {
          this.backend = null;
          if (this.wsConn) this.wsConn.close();
          if (this.agent) this.agent.destroy();
        }
        // Bad credentials/config won't fix themselves, and repeated logins can lock the account.
        backoff = err.fatalAuth || err.rateLimited || err.fatalConfig
          ? MAX_BACKOFF_MS
          : Math.min(Math.max(backoff * 2, this.pollInterval()), MAX_BACKOFF_MS);
        wait = backoff;
        const level = this.failures === 1 || this.failures % 20 === 0 || err.fatalAuth || err.fatalConfig ? "error" : "debug";
        this.log[level](`${err.message} (retrying in ${Math.round(wait / 1000)}s)`);
      }
      await new Promise((resolve) => {
        const t = setTimeout(() => { this.timers.delete(t); this.wakePoll = null; resolve(); }, wait);
        this.timers.add(t);
        this.wakePoll = () => { clearTimeout(t); this.timers.delete(t); this.wakePoll = null; resolve(); };
      });
    }
  }

  async refresh() {
    const { profiles, rawStatuses } = await this.backend.fetchProfiles();
    for (const s of rawStatuses) {
      if (!this.loggedStates.has(s)) {
        this.loggedStates.add(s);
        if (!KNOWN_STATES.has(s)) this.log.warn(`Unrecognised alarm state "${s}" (treated as disarmed). Please report it.`);
      }
    }
    if (!profiles.length) {
      this.log.warn(`Console returned no arm profiles. Create at least one in Protect's Alarm Manager.`);
    }
    this.applyProfiles(profiles, true);
  }

  // ---- live updates (Global mode) --------------------------------------------

  async pushLoop(backend) {
    let backoff = 1000;
    let warned = false;
    // Ends if the backend is replaced (e.g. after a certificate problem); the new one starts its own loop.
    while (!this.stopped && this.backend === backend) {
      let established = false;
      try {
        const conn = await backend.openUpdates();
        if (this.stopped || this.backend !== backend) { conn.close(); break; }
        this.wsConn = conn;
        established = true;
        this.setPushConnected(true);
        if (warned) this.log.info(`Live updates reconnected.`);
        warned = false;
        this.resyncSoon(); // catch anything missed while disconnected
        await new Promise((resolve) => {
          const ping = setInterval(() => {
            if (Date.now() - conn.lastActivity > WS_SILENCE_MS) conn.close(1000);
            else conn.ping();
          }, WS_PING_MS);
          conn.on("profile", (p) => this.applyProfiles([p], false));
          conn.on("resync", () => this.resyncSoon());
          conn.once("close", (reason) => { clearInterval(ping); resolve(reason); });
        }).then((reason) => {
          if (!this.stopped && !warned) {
            warned = true;
            this.log.warn(`Live updates disconnected (${reason}); polling every ${POLL_PUSH_DOWN_MS / 1000}s until they reconnect.`);
          }
        });
      } catch (err) {
        if (!warned && !this.stopped) {
          warned = true;
          this.log.warn(`Live updates unavailable (${err.message}); polling every ${POLL_PUSH_DOWN_MS / 1000}s.`);
        }
      }
      this.wsConn = null;
      this.setPushConnected(false);
      if (this.stopped) break;
      if (established) backoff = 1000;
      await this.delay(backoff);
      backoff = Math.min(backoff * 2, WS_BACKOFF_MAX_MS);
    }
  }

  setPushConnected(v) {
    if (this.pushConnected === v) return;
    this.pushConnected = v;
    if (!v && this.wakePoll) this.wakePoll(); // switch to fast polling now
  }

  resyncSoon() {
    if (this.wakePoll) this.wakePoll();
  }

  // ---- state ---------------------------------------------------------------------

  applyProfiles(list, full) {
    const before = this.snapshot();
    if (full) this.profiles = new Map();
    for (const p of list) this.profiles.set(p.id, p);
    this.known = true;
    this.updateMapping();
    this.schedulePromotion();

    const primary = this.primaryActive();
    if (primary && this.modeFor(primary.id) === null && !this.warnedUnmapped.has(primary.id)) {
      this.warnedUnmapped.add(primary.id);
      this.log.warn(`Arm profile "${primary.title}" is ${primary.state} but isn't mapped to a HomeKit ` +
        "mode, so HomeKit shows it as Away.");
    }
    if (!primary) this.warnedUnmapped.clear();

    if (this.snapshot() !== before) {
      this.log.info(`State: ${this.describe()}`);
      this.pushState();
    }
  }

  snapshot() {
    return `${this.known}|` + [...this.profiles.values()].map((p) => `${p.id}=${p.state}`).sort().join(",");
  }

  updateMapping() {
    const byName = (n) => {
      const hit = [...this.profiles.values()].find((p) => p.title.trim().toLowerCase() === n.trim().toLowerCase());
      return hit ? hit.id : null;
    };
    for (const m of this.MODES) this.profileIds[m] = this.pinnedIds[m] || byName(this.profileNames[m]);

    const key = JSON.stringify(this.profileIds) + [...this.profiles.values()].map((p) => p.title).join("|");
    if (key === this.mappingLogged) return;
    this.mappingLogged = key;
    const show = (m) => `${this.MODE_NAMES[m]} → ${this.profileIds[m] ? `"${this.titleOf(this.profileIds[m]) || this.profileNames[m]}"` : "not mapped"}`;
    const available = [...this.profiles.values()].filter((p) => p.id !== UNKNOWN_ACTIVE).map((p) => `"${p.title}"`);
    this.log.info(`Profiles: ${this.MODES.map(show).join(", ")}. On console: ${available.join(", ") || "none"}`);

    const valid = [...this.MODES.filter((m) => this.profileIds[m]), this.T.DISARM].sort();
    this.service.getCharacteristic(this.T).setProps({ validValues: valid });
  }

  titleOf(id) {
    const p = this.profiles.get(id);
    return p ? p.title : null;
  }

  modeFor(id) {
    for (const m of this.MODES) if (this.profileIds[m] && this.profileIds[m] === id) return m;
    return null;
  }

  active() {
    return [...this.profiles.values()].filter((p) => ACTIVE.has(p.state));
  }

  // breached > armed > arming
  primaryActive() {
    const rank = { breached: 3, armed: 2, arming: 1 };
    return this.active().sort((a, b) => rank[b.state] - rank[a.state])[0] || null;
  }

  modeOf(profile) {
    if (profile.id === UNKNOWN_ACTIVE && this.lastTarget !== null && this.lastTarget !== this.T.DISARM) return this.lastTarget;
    const m = this.modeFor(profile.id);
    return m === null ? this.T.AWAY_ARM : m;
  }

  currentValue() {
    const p = this.primaryActive();
    if (!p) return this.S.DISARMED;
    if (p.state === "breached") return this.S.ALARM_TRIGGERED;
    if (p.state === "arming") return this.S.DISARMED; // with an armed target, the Home app shows "Arming…"
    return this.modeOf(p); // STAY/AWAY/NIGHT share numeric values across both characteristics
  }

  targetValue() {
    const p = this.primaryActive();
    return p ? this.modeOf(p) : this.T.DISARM;
  }

  describe() {
    const p = this.primaryActive();
    if (!p) return "Disarmed";
    const label = `"${p.title}"${this.modeFor(p.id) === null ? " (unmapped, shown as Away)" : ""}`;
    if (p.state === "breached") return `ALARM TRIGGERED (${label})`;
    if (p.state === "arming") return `Arming ${label} (exit delay)`;
    return `Armed ${label}`;
  }

  pushState() {
    if (!this.known) return;
    this.service.updateCharacteristic(this.T, this.targetValue());
    this.service.updateCharacteristic(this.S, this.currentValue());
  }

  // One refresh shortly after the earliest exit delay should have ended, in
  // case the "armed" push is missed.
  schedulePromotion() {
    if (this.promotionTimer) { clearTimeout(this.promotionTimer); this.timers.delete(this.promotionTimer); this.promotionTimer = null; }
    const due = this.active().filter((p) => p.state === "arming" && p.dueAt).map((p) => p.dueAt);
    if (!due.length || this.stopped) return;
    const ms = Math.max(Math.max(Math.min(...due) - Date.now(), 0) + PROMOTION_GRACE_MS, PROMOTION_MIN_MS);
    this.promotionTimer = setTimeout(() => {
      this.timers.delete(this.promotionTimer);
      this.promotionTimer = null;
      if (this.backend && !this.busy) this.refresh().catch(() => {});
    }, ms);
    this.timers.add(this.promotionTimer);
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
        this.log.error(`Console unreachable; HomeKit will show No Response until it recovers.`);
      }
    }
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

  // ---- commands --------------------------------------------------------------

  setTarget(value) {
    // Serialise commands so rapid taps can't interleave.
    const run = this.queue.then(() => this.applyTarget(value));
    this.queue = run.catch(() => {});
    return run;
  }

  async applyTarget(value) {
    const label = this.MODE_NAMES[value] || String(value);
    this.busy++;
    try {
      if (!this.backend || !this.known) throw new Error("not connected to console yet");
      const global = this.backend instanceof GlobalBackend;

      if (value === this.T.DISARM) {
        this.log.info(`HomeKit requested Off.`);
        this.lastTarget = this.T.DISARM;
        if (global) {
          for (const p of this.active()) this.applyProfiles([await this.backend.disarm(p.id)], false);
        } else {
          await this.backend.disarmAll();
        }
        await this.verify(() => this.active().length === 0, "disarmed");
      } else {
        const id = this.profileIds[value];
        if (!id) throw new Error(`no arm profile mapped to HomeKit "${label}"`);
        const title = this.titleOf(id) || this.profileNames[value];
        this.log.info(`HomeKit requested ${label} (profile "${title}").`);
        this.lastTarget = value;
        if (global) {
          // Only one profile active at a time: disarm any other first.
          for (const p of this.active()) {
            if (p.id !== id) this.applyProfiles([await this.backend.disarm(p.id)], false);
          }
          const cur = this.profiles.get(id);
          if (!cur || !ACTIVE.has(cur.state)) this.applyProfiles([await this.backend.arm(id)], false);
        } else {
          await this.backend.arm(id);
        }
        await this.verify(() => {
          const others = this.active().filter((p) => p.id !== id && p.id !== UNKNOWN_ACTIVE);
          const target = this.profiles.get(id);
          const unknown = this.profiles.get(UNKNOWN_ACTIVE);
          return others.length === 0 && ((target && ACTIVE.has(target.state)) || (unknown && ACTIVE.has(unknown.state)));
        }, `arming "${title}"`);
      }
      this.log.info(`Confirmed: ${this.describe()}.`);
    } catch (err) {
      this.log.error(`${label} failed: ${err.message}`);
      // Snap HomeKit back to the real state once the error has been returned.
      const t = setTimeout(() => {
        this.timers.delete(t);
        const r = this.backend ? this.refresh().catch(() => {}) : Promise.resolve();
        r.then(() => this.pushState());
      }, 500);
      this.timers.add(t);
      throw this.noResponse();
    } finally {
      this.busy--;
    }
  }

  async verify(ok, what) {
    if (ok()) return;
    for (let i = 0; i < VERIFY_ATTEMPTS; i++) {
      await this.refresh();
      if (ok()) return;
      await sleep(VERIFY_DELAY_MS);
    }
    throw new Error(`console accepted the command but did not report ${what} after ${VERIFY_ATTEMPTS}s (now: ${this.describe()})`);
  }
}

module.exports._internal = { parseController, PLUGIN_NAME, PLATFORM_NAME };
