# homebridge-protect-alarm-secure

Hardened fork of [homebridge-protect-alarm](https://github.com/Mac2100/homebridge-protect-alarm)
(MIT). It shows your UniFi Protect arm profiles in HomeKit as a Security System,
including Protect's **Global Alarm Manager** (Alarm Hub and UniFi alarm sensors),
with live updates. Global-mode support follows
[ha_unifi_protect_alarm_bridge](https://github.com/violuke/ha_unifi_protect_alarm_bridge) (MIT).
See [CHANGELOG.md](CHANGELOG.md) for what changed and why.

| HomeKit | UniFi Protect |
|---|---|
| Away | arm profile named "Away" (configurable) |
| Night | arm profile named "Night" |
| Home | arm profile named "Home", hidden if none exists |
| Off | disarm every active profile |
| Arming… | profile is in its exit delay |
| Alarm Triggered | profile is breached |

Only one profile is active at a time: choosing a mode disarms any other active
profile first. In API key mode, arming *selects* the profile on the console and
then enables it, so the Protect app's plain "Arm" will next use that profile.

## 1. Pick a mode

**Global mode: you have an Alarm Hub or UniFi alarm sensors.** Adopting alarm
hardware switches Protect's Alarm Manager to Global mode, where the official
API can't arm or disarm. This plugin then logs in like the Protect web app does.

1. In UniFi OS → Admins & Users, add an admin that is **local access only**,
   with **no two-factor login**.
2. Set **Admin Privileges: Full** (Super Admin). Alarm Manager refuses custom
   roles, including Protect "Full".
3. Put its username and password in the plugin config.

This is an unofficial API, so a Protect update could change it. The plugin says
so clearly in the log if that happens. A Super Admin password lives in your
Homebridge config, so keep the Homebridge UI password-protected and don't use
this account for anything else.

**API key mode: no alarm hardware.** Create a local API key on the Protect
console (`https://<console-ip>/protect/integrations/`). Site Manager (cloud)
keys don't work.

## 2. Install

Uninstall the original `homebridge-protect-alarm` first if you have it.

Pin to an exact **commit** (a tag can be moved and a commit can't). The GitHub
tarball URL works without `git` in the container.

**Docker (`homebridge/homebridge` image)**: in the Homebridge UI, open the
terminal (⋮ menu → Terminal; enable it in UI settings if hidden) and run:

```sh
cd /homebridge
npm install --save https://github.com/sandcheeeez/homebridge-protect-alarm-secure/archive/<commit-sha>.tar.gz
```

Then restart Homebridge. `/homebridge` is the container's persistent volume, so
the plugin survives container updates.

**Other installs**: `npm install -g <same URL>`.

To update later, run the same command with the new commit SHA.

## 3. Configure

```json
{
  "platform": "ProtectAlarmSecure",
  "name": "Security System",
  "controller": "192.168.1.1",
  "username": "hb-alarm",
  "password": "…",
  "certFingerprint": "AB:CD:…",
  "homeProfileName": "Arm Stay",
  "awayProfileName": "Arm Away"
}
```

Use the IP of the console running **Protect** (your NVR, not your gateway).
For API key mode, use `"apiKey"` instead of `username`/`password`. Optional fields: `awayProfileName`,
`nightProfileName`, `homeProfileName`, `pollInterval` (API key mode, 2–300 s, default 5),
`tlsMode` (`pin` default, or `ca` if the console has a real certificate for its
hostname), and `*ArmProfileId` to pin exact profile IDs.

### Certificate fingerprint

If `certFingerprint` is empty, the plugin pins whatever certificate it sees on
first connection and logs the fingerprint. Check it once from a machine you
trust, on your home network:

```sh
openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

If it matches, paste it into `certFingerprint`. If the console certificate later
changes (a reset, or you install a new one), the plugin refuses to connect and
logs both fingerprints. Verify the new one and update the config. The automatic
pin lives in `<homebridge storage>/homebridge-protect-alarm-secure-pins.json`.

## Limitations

- Global mode uses undocumented UniFi OS APIs (see above).
- HomeKit can't show custom state names. An armed profile that isn't mapped to
  Home/Away/Night shows as Away, and the Homebridge log names it.
- Anyone in your Apple Home with control access can disarm.

## Tests

Tested on Node 24. `npm test` runs the plugin against fake consoles (API-key and
Global mode, including the live-update websocket) over real HTTPS, covering
pinning and MITM refusal, login/session handling, failure reporting,
verification, outage recovery and mode mapping.
