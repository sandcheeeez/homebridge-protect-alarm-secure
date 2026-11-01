# homebridge-protect-alarm-secure

Hardened fork of [homebridge-protect-alarm](https://github.com/Mac2100/homebridge-protect-alarm)
(MIT). It shows your UniFi Protect arm profiles in HomeKit as a Security System.
See [CHANGELOG.md](CHANGELOG.md) for what changed and why.

| HomeKit | UniFi Protect |
|---|---|
| Away | arm profile named "Away" (configurable) |
| Night | arm profile named "Night" |
| Home | arm profile named "Home", hidden if none exists |
| Off | disarm |
| Alarm Triggered | console reports an alarm going off |

Arming works by *selecting* the profile on the console and then enabling it,
because the Protect API arms whichever profile is selected. The console keeps
that selection, so a key fob or the Protect app will next arm the profile you
last used from HomeKit.

## 1. Create a limited UniFi user for the API key

A UniFi OS API key carries **all** the permissions of the user who creates it.
Don't create it from your owner account.

1. UniFi OS → Admins & Users → add a **local-only** admin, e.g. `homebridge`.
2. Give it **Protect** access only (enough to manage alarms) and **no**
   Network/other app access.
3. Log in as that user → Settings → Control Plane → Integrations → create API key.
4. Test that arming works. If it gets HTTP 401/403, raise its Protect role one step.

## 2. Install

On the Homebridge host, uninstall the original `homebridge-protect-alarm` first.

```sh
# from a git remote you control
npm install -g git+https://github.com/<you>/homebridge-protect-alarm-secure.git#v1.1.0
# or copy this folder over and:
npm install -g /path/to/homebridge-protect-alarm-secure
```

For the Docker / homebridge-config-ui image, run the command in the UI's terminal.
Pin to a tag or commit, not a branch.

## 3. Configure

```json
{
  "platform": "ProtectAlarmSecure",
  "name": "Security System",
  "controller": "192.168.1.1",
  "apiKey": "…",
  "certFingerprint": "AB:CD:…",
  "homeProfileName": "Arm Stay",
  "awayProfileName": "Arm Away"
}
```

Use the console's **IP address**. Optional fields: `awayProfileName`,
`nightProfileName`, `homeProfileName`, `pollInterval` (2–300 s, default 5),
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

- Uses the official Protect integration API. If you have UniFi alarm hardware
  (sensors, hub, fobs), Alarm Manager may run in "Global mode", which this API
  reportedly can't control. The log will say so if the console returns no
  profiles or a 404.
- The status strings that mean "alarm triggered" aren't documented. Unknown
  statuses are logged. Please note them.
- Anyone in your Apple Home with control access can disarm.

## Tests

Tested on Node 22 and 24. `npm test` runs the plugin against a fake console over real HTTPS, covering
pinning and MITM refusal, failure reporting, verification, outage recovery and
mode mapping.
