# Changelog

## 1.1.0 (fork), 2026-11-01

Forked from `homebridge-protect-alarm` 1.0.0 (npm sha1 a51b7a89). The upstream
code is preserved in the first git commit for diffing.

### Security
- **Certificate pinning** replaces disabled TLS verification. The console's
  SHA-256 certificate fingerprint is pinned (configured, or recorded on first
  connect, stored with mode 0600). A mismatched certificate is refused *before*
  any HTTP request, so the API key is never sent to an impostor.
- **Zero dependencies**: axios removed; uses Node's built-in `https`.
- Controller address is validated (host/IP + optional port only).
- Response size cap and request timeouts; API key is never logged.

### Reliability
- Failed or unconfirmed commands now return an error to HomeKit instead of
  silently "succeeding"; HomeKit is snapped back to the real state.
- Every arm/disarm is **verified** by reading the console state back.
- Startup no longer gives up: retries with backoff forever and recovers on its own.
- HomeKit shows **No Response** / a fault when the console is unreachable, rather
  than stale state.
- **Alarm triggered** state is reported (status strings are best-guess; unknown
  ones are logged).
- **Home** maps to a "Home" arm profile if one exists; otherwise it's hidden in
  the Home app instead of silently disarming. Same for Night/Away.
- Commands are serialised; profiles are re-discovered every 10 minutes and when
  an unknown profile is seen.
- Clear log hints for bad API keys and the Alarm Manager "Global mode" case.

### Breaking
- Plugin name `homebridge-protect-alarm-secure`, platform `ProtectAlarmSecure`.
