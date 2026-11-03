"use strict";

// Certificate pinning for UniFi consoles, which use self-signed certificates.
// Every connection must present a certificate whose SHA-256 fingerprint
// matches the pin. The socket is only handed to the HTTP layer after the
// check passes, so no request (API key, password, cookie) is ever written to
// an unverified peer.

const https = require("https");
const net = require("net");
const tls = require("tls");

const CONNECT_TIMEOUT_MS = 15000;

function normFingerprint(fp) {
  if (!fp) return null;
  const hex = String(fp).replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  return hex.length === 64 ? hex : null;
}

function prettyFingerprint(hex) {
  return hex.match(/../g).join(":");
}

function servername(host) {
  return net.isIP(host) ? undefined : host;
}

function readPeerFingerprint(host, port) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: servername(host), rejectUnauthorized: false });
    sock.setTimeout(CONNECT_TIMEOUT_MS, () => sock.destroy(new Error("TLS connect timed out")));
    sock.once("secureConnect", () => {
      const fp = normFingerprint((sock.getPeerCertificate() || {}).fingerprint256);
      sock.destroy();
      fp ? resolve(fp) : reject(new Error("Console presented no certificate"));
    });
    sock.once("error", reject);
  });
}

class PinnedAgent extends https.Agent {
  constructor(host, port, fingerprint) {
    super({ keepAlive: true, maxSockets: 4, maxCachedSessions: 0 });
    this.pinHost = host;
    this.pinPort = port;
    this.fingerprint = fingerprint;
  }

  createConnection(_options, callback) {
    const sock = tls.connect({
      host: this.pinHost,
      port: this.pinPort,
      servername: servername(this.pinHost),
      rejectUnauthorized: false, // replaced by the fingerprint check below
    });
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      sock.setTimeout(0);
      if (err) { sock.destroy(); callback(err); } else callback(null, sock);
    };
    sock.setTimeout(CONNECT_TIMEOUT_MS, () => finish(new Error("TLS connect timed out")));
    sock.once("secureConnect", () => {
      const seen = normFingerprint((sock.getPeerCertificate() || {}).fingerprint256);
      if (seen && seen === this.fingerprint) return finish(null);
      const err = new Error(
        `TLS certificate mismatch: console presented ${seen ? prettyFingerprint(seen) : "no certificate"}, ` +
        `expected ${prettyFingerprint(this.fingerprint)}. Refusing to send credentials. If you replaced the ` +
        "console certificate on purpose, verify the new fingerprint and put it in 'certFingerprint' (see README).");
      err.code = "CERT_PIN_MISMATCH";
      finish(err);
    });
    sock.once("error", finish);
    return undefined; // asynchronous: socket delivered via callback
  }
}

module.exports = { normFingerprint, prettyFingerprint, readPeerFingerprint, PinnedAgent };
