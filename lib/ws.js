"use strict";

// Minimal WebSocket client (RFC 6455) over the pinned HTTPS agent, so the
// live-update connection gets the same certificate check as every request.
// Supports what Protect's update socket needs: binary/text messages,
// fragmentation, ping/pong and close.

const crypto = require("crypto");
const https = require("https");
const { EventEmitter } = require("events");

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;
const HANDSHAKE_TIMEOUT_MS = 15000;

function connect({ host, port, agent, path, headers = {} }) {
  const key = crypto.randomBytes(16).toString("base64");
  const expected = crypto.createHash("sha1").update(key + GUID).digest("base64");
  return new Promise((resolve, reject) => {
    const req = https.request({
      host, port, agent, path, method: "GET",
      timeout: HANDSHAKE_TIMEOUT_MS,
      headers: {
        ...headers,
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
      },
    });
    req.on("upgrade", (res, socket, head) => {
      if (res.headers["sec-websocket-accept"] !== expected) {
        socket.destroy();
        return reject(new Error("WebSocket handshake failed: bad Sec-WebSocket-Accept"));
      }
      resolve(new WsConnection(socket, head));
    });
    req.on("response", (res) => {
      res.resume();
      const err = new Error(`WebSocket handshake failed with HTTP ${res.statusCode}`);
      err.status = res.statusCode;
      reject(err);
    });
    req.on("timeout", () => req.destroy(new Error("WebSocket handshake timed out")));
    req.on("error", reject);
    req.end();
  });
}

class WsConnection extends EventEmitter {
  constructor(socket, head) {
    super();
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.fragments = null;
    this.fragmentOp = 0;
    this.closed = false;
    this.lastActivity = Date.now();
    socket.setNoDelay(true);
    socket.on("data", (d) => this.onData(d));
    socket.on("close", () => this.finish("socket closed"));
    socket.on("error", (e) => this.finish(e.message));
    if (head && head.length) this.onData(head);
  }

  onData(chunk) {
    this.lastActivity = Date.now();
    this.buf = Buffer.concat([this.buf, chunk]);
    try {
      while (this.parseFrame()) { /* keep parsing */ }
    } catch (err) {
      this.close(1002);
      this.finish(`protocol error: ${err.message}`);
    }
  }

  parseFrame() {
    const b = this.buf;
    if (b.length < 2) return false;
    const fin = (b[0] & 0x80) !== 0;
    const op = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return false;
      len = b.readUInt16BE(2); off = 4;
    } else if (len === 127) {
      if (b.length < 10) return false;
      const big = b.readBigUInt64BE(2);
      if (big > BigInt(MAX_MESSAGE_BYTES)) throw new Error("frame too large");
      len = Number(big); off = 10;
    }
    if (len > MAX_MESSAGE_BYTES) throw new Error("frame too large");
    let mask = null;
    if (masked) {
      if (b.length < off + 4) return false;
      mask = b.subarray(off, off + 4); off += 4;
    }
    if (b.length < off + len) return false;
    let payload = Buffer.from(b.subarray(off, off + len));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    this.buf = b.subarray(off + len);

    if (op === 0x8) { // close
      this.close(1000);
      this.finish("closed by console");
      return false;
    }
    if (op === 0x9) { this.send(0xA, payload); return true; } // ping -> pong
    if (op === 0xA) return true; // pong
    if (op === 0x1 || op === 0x2) {
      if (fin) { this.emit("message", payload, op === 0x2); return true; }
      this.fragments = [payload]; this.fragmentOp = op;
      return true;
    }
    if (op === 0x0 && this.fragments) {
      this.fragments.push(payload);
      const total = this.fragments.reduce((n, p) => n + p.length, 0);
      if (total > MAX_MESSAGE_BYTES) throw new Error("message too large");
      if (fin) {
        const msg = Buffer.concat(this.fragments);
        const binary = this.fragmentOp === 0x2;
        this.fragments = null;
        this.emit("message", msg, binary);
      }
      return true;
    }
    throw new Error(`unexpected opcode ${op}`);
  }

  // Client-to-server frames must be masked.
  send(op, payload = Buffer.alloc(0)) {
    if (this.closed || this.socket.destroyed) return;
    const len = payload.length;
    const header = len < 126 ? Buffer.alloc(2) : len < 65536 ? Buffer.alloc(4) : Buffer.alloc(10);
    header[0] = 0x80 | op;
    if (len < 126) header[1] = 0x80 | len;
    else if (len < 65536) { header[1] = 0x80 | 126; header.writeUInt16BE(len, 2); }
    else { header[1] = 0x80 | 127; header.writeBigUInt64BE(BigInt(len), 2); }
    const mask = crypto.randomBytes(4);
    const body = Buffer.from(payload);
    for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
    this.socket.write(Buffer.concat([header, mask, body]));
  }

  ping() { this.send(0x9); }

  close(code = 1000) {
    if (this.closed) return;
    const p = Buffer.alloc(2);
    p.writeUInt16BE(code, 0);
    this.send(0x8, p);
    this.socket.end();
  }

  finish(reason) {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
    this.emit("close", reason);
  }
}

module.exports = { connect };
