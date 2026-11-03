"use strict";

// Minimal HTTPS JSON request helper. Resolves for every HTTP status; callers
// decide what an error is.

const https = require("https");

const REQUEST_TIMEOUT_MS = 15000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function request({ host, port, agent, method, path, headers = {}, json }) {
  const payload = json === undefined ? null : Buffer.from(JSON.stringify(json));
  return new Promise((resolve, reject) => {
    const req = https.request({
      host, port, agent, method, path,
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        Accept: "application/json",
        ...headers,
        ...(payload ? { "Content-Type": "application/json" } : {}),
        "Content-Length": payload ? payload.length : 0,
      },
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > MAX_RESPONSE_BYTES) req.destroy(new Error("Response too large"));
        else chunks.push(c);
      });
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let data = null;
        if (text) { try { data = JSON.parse(text); } catch { data = text; } }
        resolve({ status: res.statusCode, headers: res.headers, data });
      });
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error(`Timed out: ${method} ${path}`)));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function snippet(data) {
  const s = typeof data === "string" ? data : (data === null ? "" : JSON.stringify(data));
  return (s || "").slice(0, 300);
}

class HttpError extends Error {
  constructor(method, path, status, data, hint) {
    const body = snippet(data);
    super(`HTTP ${status} from ${method} ${path}${body ? ": " + body : ""}${hint ? ". " + hint : ""}`);
    this.status = status;
    this.data = data;
  }
}

module.exports = { request, HttpError };
