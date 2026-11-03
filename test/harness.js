"use strict";
// Shared fake HomeKit/Homebridge environment for the tests.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { EventEmitter } = require("events");

const FIX = path.join(__dirname, "fixtures");
const cert = (n) => ({ key: fs.readFileSync(path.join(FIX, `${n}.key`)), cert: fs.readFileSync(path.join(FIX, `${n}.crt`)) });
const fingerprintOf = (n) => new crypto.X509Certificate(cert(n).cert).fingerprint256;

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
      this.chars[C.key] = { value: null, props: {}, pushes: [],
        onGet(f) { this.get = f; return this; }, onSet(f) { this.set = f; return this; },
        setProps(p) { Object.assign(this.props, p); return this; } };
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

function startPlugin(config, storage = tmp()) {
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
    alarm, logs, svc, storage,
    target: () => svc.getCharacteristic(hap.Characteristic.SecuritySystemTargetState),
    current: () => svc.getCharacteristic(hap.Characteristic.SecuritySystemCurrentState),
    stop: () => api.emit("shutdown"),
  };
}

const until = async (cond, ms = 15000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await cond()) return; await new Promise((r) => setTimeout(r, 50)); }
  throw new Error("timed out waiting for condition");
};
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "hb-pa-")); }
const closeServer = (s) => new Promise((r) => { s.closeAllConnections(); s.close(r); });

module.exports = { hap, T, S, HapStatusError, cert, fingerprintOf, startPlugin, until, tmp, closeServer };
