# Changelog

## 1.2.1, 2026-11-03

- Log lines no longer repeat the plugin name (Homebridge already adds it).
- The Name field now defaults to "Protect Alarm" and explains that it's the log prefix.

## 1.2.0, 2026-11-03

### Global Alarm Manager support
- New **Global mode** for consoles with an Alarm Hub / UniFi alarm sensors, where
  the official integration API refuses alarm requests. Logs in with a local-only
  Super Admin and uses UniFi OS's Alarm Manager API, following
  [violuke/ha_unifi_protect_alarm_bridge](https://github.com/violuke/ha_unifi_protect_alarm_bridge) (MIT).
- **Live updates** over Protect's update websocket (instant arm/disarm/breach),
  with polling as a safety net: every 60s while live updates work, every 10s
  while they don't.
- Arming one mode disarms any other active profile first; Off disarms every
  active profile. Each profile is armed by ID (no "selected profile" side effect).
- Exit delay shows as HomeKit's "Arming…"; breached shows Alarm Triggered.
- An armed profile that isn't mapped to a HomeKit mode shows as Away, and the
  log names the real profile.
- The login, session cookie and live-update connection all go through the same
  certificate pinning, so the password is never sent to an unverified console.
- One login at a time, re-login only when the session expires, and a 5-minute
  back-off on bad credentials, two-factor accounts or rate limiting, so the
  account isn't locked out.
- API-key mode now explains Global mode when the console rejects the key for it.

### Internal
- Split into `lib/` modules (TLS pinning, HTTP, WebSocket client, backends).
  Still no third-party dependencies.

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
