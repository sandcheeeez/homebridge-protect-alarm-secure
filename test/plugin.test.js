"use strict";
// Runs the plugin against a fake UniFi Protect console over real HTTPS.
// Usage: node --test test/
const test = require("node:test");
const assert = require("node:assert");
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { EventEmitter } = require("events");

const FIX = path.join(__dirname, "fixtures");
const cert = (n) => ({ key: fs.readFileSync(path.join(FIX, `${n}.key`)), cert: fs.readFileSync(path.join(FIX, `${n}.crt`)) });
const fingerprintOf = (n) => new crypto.X509Certificate(cert(n).cert).fingerprint256;
const API_KEY = "test-key-123";

// ---- fake HAP / Homebridge -------------------------------------------------

const T = { STAY_ARM: 0, AWAY_ARM: 1, NIGHT_ARM: 2, DISARM: 3 };
const S = { STAY_ARM: 0, AWAY_ARM: 1, NIGHT_ARM: 2, DISARMED: 3, ALARM_TRIGGERED: 4 };
class HapStatusError extends Error { constructor(s) { super(`HAP ${s}`); this.hapStatus = s; } }
const hap = {
  Characteristic: {
    SecuritySystemTargetState: { ...T, key: "Target" },
    SecuritySystemCurrentState: { ...S, key: "Current" },
    StatusFault: { NO_FAULT: 0, GENERAL_FAULT: 1, key: "Fault" },
    Manufacturer: { key: "Manufacturer" }, Model: { key: "Model" }, SerialNumber: { key: "Serial" },
  },
  Service: { AccessoryInformation: "info", SecuritySystem: "security" },
  HAPStatus: { SERVICE_COMMUNICATION_FAILURE: -70402 },
  HapStatusError,
  uuid: { generate: (s) => crypto.createHash("sha1").update(s).digest("hex") },
};

class FakeService {
  constructor() { this.chars = {}; }
  getCharacteristic(C) {
    if (!this.chars[C.key]) {
      const ch = { value: null, props: {}, pushes: [],
        onGet(f) { this.get = f; return this; }, onSet(f) { this.set = f; return this; },
        setProps(p) { Object.assign(this.props, p); return this; } };
      this.chars[C.key] = ch;
    }
    return this.chars[C.key];
  }
  setCharacteristic(C, v) { this.getCharacteristic(C).value = v; return this; }
  updateCharacteristic(C, v) { const c = this.getCharacteristic(C); c.value = v; c.pushes.push(v); return this; }
}
class FakeAccessory {
  constructor(name, UUID) { this.UUID = UUID; this.services = { info: new FakeService() }; }
  getService(k) { return this.services[k]; }
  addService(k) { return (this.services[k] = new FakeService()); }
}

function startPlugin(config, storage) {
  delete require.cache[require.resolve("..")];
  const plugin = require("..");
  let Platform;
  const logs = [];
  const mk = (lvl) => (...a) => logs.push(`${lvl}: ${a.join(" ")}`);
  const log = Object.assign(mk("info"), { info: mk("info"), warn: mk("warn"), error: mk("error"), debug: mk("debug") });
  const api = new EventEmitter();
  api.hap = hap;
  api.user = { storagePath: () => storage };
  api.platformAccessory = FakeAccessory;
  api.registerPlatformAccessories = () => {};
  api.unregisterPlatformAccessories = () => {};
  plugin({ hap, registerPlatform: (_n, _p, cls) => { Platform = cls; } });
  const platform = new Platform(log, config, api);
  api.emit("didFinishLaunching");
  const alarm = platform.alarm;
  const svc = alarm && alarm.service;
  return {
    alarm, logs, svc,
    target: () => svc.getCharacteristic(hap.Characteristic.SecuritySystemTargetState),
    current: () => svc.getCharacteristic(hap.Characteristic.SecuritySystemCurrentState),
    stop: () => api.emit("shutdown"),
  };
}

// ---- fake Protect console --------------------------------------------------

function startConsole(certName = "good", port = 0) {
  const state = {
    status: "disabled", selected: null, armProfileId: null,
    profiles: [{ id: "p-away", name: "Away" }, { id: "p-night", name: "Night" }],
    failEnable: false, ignoreEnable: false, requests: [], keysSeen: [],
  };
  const server = https.createServer(cert(certName), (req, res) => {
    let body = "";
    req.on("data", c => (body += c));
    req.on("end", () => {
      state.requests.push(`${req.method} ${req.url}`);
      state.keysSeen.push(req.headers["x-api-key"]);
      const send = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
      if (req.headers["x-api-key"] !== API_KEY) return send(401, { error: "unauthorized" });
      const p = req.url.replace("/proxy/protect/integration/v1", "");
      if (req.method === "GET" && p === "/nvrs") return send(200, [{ id: "nvr", armMode: { status: state.status, armProfileId: state.armProfileId } }]);
      if (req.method === "GET" && p === "/arm-profiles") return send(200, state.profiles);
      if (req.method === "PATCH" && p === "/arm-profiles/settings") { state.selected = JSON.parse(body).armProfileId; return send(200, {}); }
      if (req.method === "POST" && p === "/arm-profiles/enable") {
        if (state.failEnable) return send(500, { error: "boom" });
        if (!state.ignoreEnable) { state.status = "armed"; state.armProfileId = state.selected; }
        return send(200, {});
      }
      if (req.method === "POST" && p === "/arm-profiles/disable") { state.status = "disabled"; state.armProfileId = null; return send(200, {}); }
      send(404, { error: "not found" });
    });
  });
  return new Promise(r => server.listen(port, "127.0.0.1", () => r({ server, state, port: server.address().port })));
}

const until = async (cond, ms = 15000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await cond()) return; await new Promise(r => setTimeout(r, 100)); }
  throw new Error("timed out waiting for condition");
};
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "hb-pa-"));
const closeServer = (s) => new Promise(r => { s.closeAllConnections(); s.close(r); });

// ---- tests -----------------------------------------------------------------

test("pins cert on first use, arms Away/Night, disarms, hides unmapped Home", async () => {
  const c = await startConsole();
  const storage = tmp();
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: API_KEY, pollInterval: 2 }, storage);
  try {
    await until(() => h.alarm.known);
    const pins = JSON.parse(fs.readFileSync(path.join(storage, "homebridge-protect-alarm-secure-pins.json"), "utf8"));
    assert.strictEqual(pins[`127.0.0.1:${c.port}`], fingerprintOf("good"));
    assert.strictEqual((fs.statSync(path.join(storage, "homebridge-protect-alarm-secure-pins.json")).mode & 0o777), 0o600);
    assert.deepStrictEqual(h.target().props.validValues, [T.AWAY_ARM, T.NIGHT_ARM, T.DISARM], "Home hidden");
    assert.strictEqual(h.current().get(), S.DISARMED);

    await h.target().set(T.NIGHT_ARM);
    assert.strictEqual(c.state.armProfileId, "p-night");
    assert.strictEqual(h.current().get(), S.NIGHT_ARM);

    await h.target().set(T.AWAY_ARM);
    assert.strictEqual(c.state.armProfileId, "p-away");
    assert.strictEqual(h.current().get(), S.AWAY_ARM);

    await h.target().set(T.DISARM);
    assert.strictEqual(c.state.status, "disabled");
    assert.strictEqual(h.current().get(), S.DISARMED);
  } finally { h.stop(); await closeServer(c.server); }
});

test("Home maps to a Home profile when one exists", async () => {
  const c = await startConsole();
  c.state.profiles.push({ id: "p-home", name: "home" });
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: API_KEY, pollInterval: 2 }, tmp());
  try {
    await until(() => h.alarm.known);
    assert.deepStrictEqual(h.target().props.validValues, [T.STAY_ARM, T.AWAY_ARM, T.NIGHT_ARM, T.DISARM]);
    await h.target().set(T.STAY_ARM);
    assert.strictEqual(c.state.armProfileId, "p-home");
    assert.strictEqual(h.current().get(), S.STAY_ARM);
  } finally { h.stop(); await closeServer(c.server); }
});

test("certificate swap (MITM) is refused and the API key is never sent", async () => {
  const good = await startConsole("good");
  const storage = tmp();
  let h = startPlugin({ controller: `127.0.0.1:${good.port}`, apiKey: API_KEY, pollInterval: 2 }, storage);
  await until(() => h.alarm.known);
  h.stop();
  const port = good.port;
  await closeServer(good.server);

  const evil = await startConsole("evil", port);
  h = startPlugin({ controller: `127.0.0.1:${port}`, apiKey: API_KEY, pollInterval: 2 }, storage);
  try {
    await until(() => h.logs.some(l => l.includes("TLS certificate mismatch")));
    assert.strictEqual(evil.state.requests.length, 0, "no HTTP request reached the impostor");
    assert.ok(!evil.state.keysSeen.includes(API_KEY));
    assert.throws(() => h.current().get(), HapStatusError, "HomeKit shows No Response");
  } finally { h.stop(); await closeServer(evil.server); }
});

test("configured fingerprint that doesn't match is refused even on first use", async () => {
  const c = await startConsole("good");
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: API_KEY, pollInterval: 2,
    certFingerprint: fingerprintOf("evil") }, tmp());
  try {
    await until(() => h.logs.some(l => l.includes("TLS certificate mismatch")));
    assert.strictEqual(c.state.requests.length, 0);
  } finally { h.stop(); await closeServer(c.server); }
});

test("failed arm is reported to HomeKit as an error, not success", async () => {
  const c = await startConsole();
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: API_KEY, pollInterval: 2 }, tmp());
  try {
    await until(() => h.alarm.known);
    c.state.failEnable = true;
    await assert.rejects(h.target().set(T.AWAY_ARM), HapStatusError);
    await until(() => h.target().pushes.at(-1) === T.DISARM, 3000); // snapped back to real state
    assert.strictEqual(h.current().get(), S.DISARMED);
  } finally { h.stop(); await closeServer(c.server); }
});

test("console that accepts but doesn't arm is caught by verification", async () => {
  const c = await startConsole();
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: API_KEY, pollInterval: 2 }, tmp());
  try {
    await until(() => h.alarm.known);
    c.state.ignoreEnable = true;
    await assert.rejects(h.target().set(T.AWAY_ARM), HapStatusError);
    assert.ok(h.logs.some(l => l.includes("did not report armed")));
  } finally { h.stop(); await closeServer(c.server); }
});

test("console down at startup: keeps retrying and recovers", async () => {
  const probe = await startConsole();
  const port = probe.port;
  await closeServer(probe.server);
  const h = startPlugin({ controller: `127.0.0.1:${port}`, apiKey: API_KEY, pollInterval: 2 }, tmp());
  try {
    await until(() => h.alarm.failures >= 1);
    assert.throws(() => h.current().get(), HapStatusError);
    const c = await startConsole("good", port);
    await until(() => h.alarm.known, 20000);
    assert.strictEqual(h.current().get(), S.DISARMED);
    await closeServer(c.server);
  } finally { h.stop(); }
});

test("external arming (fob/app) and triggered alarm are reflected", async () => {
  const c = await startConsole();
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: API_KEY, pollInterval: 2 }, tmp());
  try {
    await until(() => h.alarm.known);
    Object.assign(c.state, { status: "armed", armProfileId: "p-night" });
    await until(() => h.current().value === S.NIGHT_ARM, 5000);
    Object.assign(c.state, { status: "triggered" });
    await until(() => h.current().value === S.ALARM_TRIGGERED, 5000);
  } finally { h.stop(); await closeServer(c.server); }
});

test("wrong API key gives a clear error", async () => {
  const c = await startConsole();
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: "wrong", pollInterval: 2 }, tmp());
  try {
    await until(() => h.logs.some(l => l.includes("HTTP 401") && l.includes("Check the API key")));
    assert.ok(!h.logs.some(l => l.includes("wrong")), "API key never logged");
  } finally { h.stop(); await closeServer(c.server); }
});

test("controller parsing rejects junk", () => {
  const { parseController } = require("..")._internal;
  assert.deepStrictEqual(parseController("https://192.168.1.1/"), { host: "192.168.1.1", port: 443, label: "192.168.1.1" });
  assert.strictEqual(parseController("192.168.1.1/proxy?x=1"), null);
  assert.strictEqual(parseController("evil.com@192.168.1.1"), null);
  assert.strictEqual(parseController(""), null);
});
