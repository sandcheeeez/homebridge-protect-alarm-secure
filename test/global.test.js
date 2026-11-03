"use strict";
// Global mode: runs the plugin against a fake UniFi OS console implementing
// the Alarm Manager API (login/session/CSRF, profiles, actions) and Protect's
// binary update websocket, over real HTTPS with certificate pinning.
const test = require("node:test");
const assert = require("node:assert");
const https = require("https");
const crypto = require("crypto");
const zlib = require("zlib");
const { T, S, HapStatusError, cert, startPlugin, until, closeServer } = require("./harness");
const { decodePacket, csrfFromJwt } = require("../lib/globalBackend");

const USER = "hb-alarm";
const PASS = "correct horse battery staple";

function encodeFrame(obj, deflate) {
  let payload = Buffer.from(JSON.stringify(obj));
  if (deflate) payload = zlib.deflateSync(payload);
  const h = Buffer.alloc(8);
  h[0] = 1; h[1] = 1; h[2] = deflate ? 1 : 0; h[3] = 0;
  h.writeUInt32BE(payload.length, 4);
  return Buffer.concat([h, payload]);
}

function wsServerFrame(buf) {
  const len = buf.length;
  const h = len < 126 ? Buffer.from([0x82, len]) : Buffer.from([0x82, 126, len >> 8, len & 0xff]);
  return Buffer.concat([h, buf]);
}

function startGlobalConsole({ certName = "good", port = 0, profiles } = {}) {
  const st = {
    user: { username: USER, password: PASS, superAdmin: true, mfa: false },
    globalMode: true,
    wsEnabled: true,
    csrfInHeader: false, // exercise the JWT-cookie CSRF path by default
    sessions: new Map(), // token -> csrf
    profiles: profiles || [
      { id: "p-stay", title: "Arm Stay", state: "disarmed", activation_delay: 0, state_set_at: null },
      { id: "p-away", title: "Arm Away", state: "disarmed", activation_delay: 0, state_set_at: null },
    ],
    logins: 0, requests: [], bodiesSeen: [], sockets: new Set(), timers: [],
  };
  const pub = (p) => ({ ...p });
  st.push = (p) => {
    const pkt = Buffer.concat([
      encodeFrame({ action: "update", newUpdateId: crypto.randomUUID(), modelKey: "externalArmProfile", id: p.id }, false),
      encodeFrame(pub(p), true),
    ]);
    for (const s of st.sockets) s.write(wsServerFrame(pkt));
  };
  st.set = (id, state) => {
    const p = st.profiles.find((x) => x.id === id);
    p.state = state; p.state_set_at = new Date().toISOString();
    st.push(p);
  };
  st.expireSessions = () => st.sessions.clear();

  const authed = (req) => {
    const m = /(?:^|;\s*)TOKEN=([^;]+)/.exec(req.headers.cookie || "");
    return m && st.sessions.has(m[1]) && st.sessions.get(m[1]) === req.headers["x-csrf-token"];
  };

  const server = https.createServer(cert(certName), (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      st.requests.push(`${req.method} ${req.url}`);
      st.bodiesSeen.push(body);
      const send = (code, obj, headers = {}) => {
        res.writeHead(code, { "Content-Type": "application/json", ...headers });
        res.end(obj === undefined ? "" : JSON.stringify(obj));
      };
      const url = req.url;
      if (req.method === "POST" && url === "/api/auth/login") {
        st.logins++;
        const b = JSON.parse(body || "{}");
        if (b.username !== st.user.username || b.password !== st.user.password) return send(401, { error: "bad" });
        if (st.user.mfa) return send(499, { error: "mfa" });
        const csrf = crypto.randomBytes(8).toString("hex");
        const token = `h.${Buffer.from(JSON.stringify({ csrfToken: csrf })).toString("base64url")}.sig${st.logins}`;
        st.sessions.set(token, csrf);
        return send(200, { username: b.username }, {
          "Set-Cookie": `TOKEN=${token}; path=/; secure; httponly`,
          ...(st.csrfInHeader ? { "X-CSRF-Token": csrf } : {}),
        });
      }
      if (url.startsWith("/proxy/protect/integration/")) {
        return send(400, { error: "This operation is not available when global alarm manager is enabled", name: "BAD_REQUEST" });
      }
      if (!authed(req)) return send(401, { error: "unauthorized" });
      if (req.method === "GET" && url === "/proxy/protect/api/nvr") {
        return send(200, { mac: "AABBCC", name: "NVR", version: "7.2.105", featureFlags: { useExternalAlarmManager: st.globalMode } });
      }
      if (url.startsWith("/api/v2/alarms") && !st.user.superAdmin) return send(403, { error: "forbidden" });
      if (req.method === "GET" && url === "/api/v2/alarms/profiles") return send(200, st.profiles.map(pub));
      const m = /^\/api\/v2\/alarms\/profiles\/([^/]+)\/actions\/(arm|disarm)$/.exec(url);
      if (req.method === "POST" && m) {
        const p = st.profiles.find((x) => x.id === decodeURIComponent(m[1]));
        if (!p) return send(404, { error: "no profile" });
        const now = new Date();
        if (m[2] === "disarm") {
          p.state = "disarmed"; p.state_set_at = now.toISOString(); delete p.state_promotion_due_at;
        } else if (p.activation_delay > 0) {
          p.state = "arming"; p.state_set_at = now.toISOString();
          p.state_promotion_due_at = new Date(now.getTime() + p.activation_delay * 1000).toISOString();
          st.timers.push(setTimeout(() => {
            if (p.state === "arming") { p.state = "armed"; delete p.state_promotion_due_at; p.state_set_at = new Date().toISOString(); st.push(p); }
          }, p.activation_delay * 1000));
        } else {
          p.state = "armed"; p.state_set_at = now.toISOString();
        }
        send(200, pub(p));
        const pushed = { ...p }; delete pushed.state_promotion_due_at; // websocket payloads omit it
        setTimeout(() => st.push(pushed), 20);
        return;
      }
      send(404, { error: "not found" });
    });
  });

  server.on("upgrade", (req, socket) => {
    st.requests.push(`WS ${req.url}`);
    if (req.url !== "/proxy/protect/ws/updates" || !st.wsEnabled) {
      socket.end("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    if (!authed(req)) { socket.end("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"); return; }
    const accept = crypto.createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    st.sockets.add(socket);
    socket.on("close", () => st.sockets.delete(socket));
    socket.on("error", () => st.sockets.delete(socket));
    socket.on("data", () => {}); // ignore client pings
  });

  const close = async () => {
    st.timers.forEach(clearTimeout);
    for (const s of st.sockets) s.destroy();
    await closeServer(server);
  };
  return new Promise((r) => server.listen(port, "127.0.0.1", () => r({ server, st, port: server.address().port, close })));
}

const cfg = (port, extra = {}) => ({
  controller: `127.0.0.1:${port}`, username: USER, password: PASS,
  homeProfileName: "Arm Stay", awayProfileName: "Arm Away", ...extra,
});
const connected = (h) => until(() => h.alarm.known && h.alarm.pushConnected);

// ---- tests -------------------------------------------------------------------

test("unit: packet decoding and CSRF-from-JWT", () => {
  const pkt = Buffer.concat([encodeFrame({ a: 1 }, false), encodeFrame({ b: "x" }, true)]);
  assert.deepStrictEqual(decodePacket(pkt), [{ a: 1 }, { b: "x" }]);
  assert.throws(() => decodePacket(pkt.subarray(0, 10)));
  const jwt = `h.${Buffer.from(JSON.stringify({ csrfToken: "abc" })).toString("base64url")}.s`;
  assert.strictEqual(csrfFromJwt(jwt), "abc");
  assert.strictEqual(csrfFromJwt("garbage"), null);
});

test("maps Arm Stay/Arm Away, exit delay shows Arming, live update completes it", async () => {
  const c = await startGlobalConsole();
  c.st.profiles[0].activation_delay = 1;
  const h = startPlugin(cfg(c.port));
  try {
    await connected(h);
    assert.deepStrictEqual(h.target().props.validValues, [T.STAY_ARM, T.AWAY_ARM, T.DISARM], "Night hidden");
    assert.strictEqual(h.current().get(), S.DISARMED);

    await h.target().set(T.STAY_ARM);
    assert.strictEqual(c.st.profiles[0].state, "arming");
    assert.strictEqual(h.target().get(), T.STAY_ARM, "target Home");
    assert.strictEqual(h.current().get(), S.DISARMED, "still disarmed during exit delay → Home app shows Arming…");
    // Poll interval is 60s while live updates are up, so this can only come from the push.
    await until(() => h.current().value === S.STAY_ARM, 3000);
    assert.ok(!h.logs.some((l) => l.includes("Live updates unavailable")));
  } finally { h.stop(); await c.close(); }
});

test("arming Away while Home is armed disarms Home first; Off disarms everything", async () => {
  const c = await startGlobalConsole();
  const h = startPlugin(cfg(c.port));
  try {
    await connected(h);
    await h.target().set(T.STAY_ARM);
    await h.target().set(T.AWAY_ARM);
    assert.deepStrictEqual(c.st.profiles.map((p) => p.state), ["disarmed", "armed"]);
    const disarmIdx = c.st.requests.indexOf("POST /api/v2/alarms/profiles/p-stay/actions/disarm");
    const armIdx = c.st.requests.lastIndexOf("POST /api/v2/alarms/profiles/p-away/actions/arm");
    assert.ok(disarmIdx > -1 && disarmIdx < armIdx, "disarm before arm");
    assert.strictEqual(h.current().get(), S.AWAY_ARM);

    await new Promise((r) => setTimeout(r, 100)); // let the fake console's delayed pushes land
    c.st.set("p-stay", "armed"); // something else arms a second profile too
    await until(() => h.alarm.active().length === 2, 2000);
    await h.target().set(T.DISARM);
    assert.deepStrictEqual(c.st.profiles.map((p) => p.state), ["disarmed", "disarmed"]);
    assert.strictEqual(h.current().get(), S.DISARMED);
  } finally { h.stop(); await c.close(); }
});

test("changes from the Protect app / keypad arrive instantly; breach shows Alarm Triggered", async () => {
  const c = await startGlobalConsole();
  const h = startPlugin(cfg(c.port));
  try {
    await connected(h);
    const t0 = Date.now();
    c.st.set("p-away", "armed");
    await until(() => h.current().value === S.AWAY_ARM, 1500);
    assert.ok(Date.now() - t0 < 1500);
    c.st.set("p-away", "breached");
    await until(() => h.current().value === S.ALARM_TRIGGERED, 1500);
    assert.ok(h.logs.some((l) => l.includes("ALARM TRIGGERED")));
    c.st.set("p-away", "disarmed");
    await until(() => h.current().value === S.DISARMED, 1500);
  } finally { h.stop(); await c.close(); }
});

test("an unmapped profile shows as Away and the log names it", async () => {
  const c = await startGlobalConsole();
  c.st.profiles.push({ id: "p-vac", title: "Vacation", state: "disarmed", activation_delay: 0 });
  const h = startPlugin(cfg(c.port));
  try {
    await connected(h);
    c.st.set("p-vac", "armed");
    await until(() => h.current().value === S.AWAY_ARM, 1500);
    assert.ok(h.logs.some((l) => l.includes('"Vacation" is armed but isn\'t mapped') && l.includes("shows it as Away")));
    assert.ok(h.logs.some((l) => l.includes('Armed "Vacation" (unmapped, shown as Away)')));
  } finally { h.stop(); await c.close(); }
});

test("expired session: logs in again once and the command still works", async () => {
  const c = await startGlobalConsole();
  c.st.csrfInHeader = true; // exercise the header CSRF path too
  const h = startPlugin(cfg(c.port));
  try {
    await connected(h);
    assert.strictEqual(c.st.logins, 1);
    c.st.expireSessions();
    await h.target().set(T.AWAY_ARM);
    assert.strictEqual(c.st.profiles[1].state, "armed");
    assert.strictEqual(c.st.logins, 2);
  } finally { h.stop(); await c.close(); }
});

test("not a Super Admin: clear message, no repeated logins", async () => {
  const c = await startGlobalConsole();
  c.st.user.superAdmin = false;
  const h = startPlugin(cfg(c.port));
  try {
    await until(() => h.logs.some((l) => l.includes("needs a Super Admin")));
    await new Promise((r) => setTimeout(r, 2000));
    assert.ok(c.st.logins <= 2, `logins: ${c.st.logins}`);
    assert.throws(() => h.current().get(), HapStatusError);
  } finally { h.stop(); await c.close(); }
});

test("two-factor account and wrong password: clear message, one login attempt", async () => {
  for (const [setup, text] of [[(st) => { st.user.mfa = true; }, "two-factor"], [(st) => { st.user.password = "other"; }, "Login rejected"]]) {
    const c = await startGlobalConsole();
    setup(c.st);
    const h = startPlugin(cfg(c.port));
    try {
      await until(() => h.logs.some((l) => l.includes(text)));
      await new Promise((r) => setTimeout(r, 1500));
      assert.strictEqual(c.st.logins, 1);
      assert.ok(!h.logs.some((l) => l.includes(PASS)), "password never logged");
    } finally { h.stop(); await c.close(); }
  }
});

test("certificate swap: the password is never sent to an impostor", async () => {
  const good = await startGlobalConsole();
  let h = startPlugin(cfg(good.port));
  await connected(h);
  const storage = h.storage;
  h.stop();
  const port = good.port;
  await good.close();

  const evil = await startGlobalConsole({ certName: "evil", port });
  h = startPlugin(cfg(port), storage);
  try {
    await until(() => h.logs.some((l) => l.includes("TLS certificate mismatch")));
    assert.strictEqual(evil.st.requests.length, 0);
    assert.ok(!evil.st.bodiesSeen.some((b) => b.includes(PASS)));
  } finally { h.stop(); await evil.close(); }
});

test("live updates unavailable: falls back to polling every 10s", async () => {
  const c = await startGlobalConsole();
  c.st.wsEnabled = false;
  const h = startPlugin(cfg(c.port));
  try {
    await until(() => h.alarm.known);
    await until(() => h.logs.some((l) => l.includes("Live updates unavailable")));
    c.st.profiles[1].state = "armed"; // changed without a push
    await until(() => h.current().value === S.AWAY_ARM, 13000);
  } finally { h.stop(); await c.close(); }
});

test("API key on a Global-mode console explains what to do", async () => {
  const c = await startGlobalConsole();
  const h = startPlugin({ controller: `127.0.0.1:${c.port}`, apiKey: "k" });
  try {
    await until(() => h.logs.some((l) => l.includes("Global mode") && l.includes("'username' and 'password'")));
  } finally { h.stop(); await c.close(); }
});
