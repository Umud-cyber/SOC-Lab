# Lab TODO — evidence gaps to close

[Back to project](README.md)

These are values the current screenshots do **not** prove. Each item has the exact commands to run and
what to capture. Running them turns the honest "not shown / not yet proven" notes in the README into
verified results. Capture on the isolated lab network only, against your own VMs.

## 1. Windows process-event rule ID / level (DET-001, DET-002)
The `net.exe` events (E12, E13, E25) were captured with the Sysmon `eventdata` fields expanded, not
the `rule.*` fields. Re-open one in Discover and scroll the expanded document to the rule section.
- **Capture:** the expanded document showing `rule.id`, `rule.level`, `rule.description`, `rule.groups`.
- **Drop in:** `evidence/06-attack-mapping/`
- **Then:** fill the `Rule ID / level: not shown` lines in DET-001 and DET-002.

## 2. Failed Windows logon — Event 4625 (planned detection)
```powershell
# win-client, lab-only, against itself:
runas /user:win-client\baduser cmd       # enter a wrong password
```
- In Discover: `agent.name:"win-client" AND data.win.system.eventID:"4625"`.
- **Capture:** the 4625 alert with rule fields. **Drop in:** `evidence/06-attack-mapping/`.
- **Then:** add detection card DET-006 (T1110) and move it from "planned" to "observed" in `detections/README.md`.

## 3. New local user created — Linux (planned detection)
```bash
# ubuntu-web
sudo useradd soc-test-user
# find it, then clean up:
sudo userdel soc-test-user
```
- In Discover: `agent.name:"ubuntu-web" AND rule.groups:"adduser"` (or `account_changed`).
- **Capture:** the account-creation alert. **Drop in:** `evidence/06-attack-mapping/`.
- **Then:** add detection card DET-007 (T1136.001).

## 4. Failed SSH login (planned detection)
```bash
# from any lab host, against ubuntu-web, wrong password:
ssh baduser@192.168.38.20
```
- In Discover: `agent.name:"ubuntu-web" AND rule.groups:"authentication_failed" AND data.srcip:*`.
- **Capture:** the SSH auth-failure alert (rule 5710/5760 family). **Drop in:** `evidence/06-attack-mapping/`.
- **Then:** add detection card DET-008 (T1110 / T1021.004).

## 5. NAT-off isolation proof (hygiene requirement S2)
```bash
# ubuntu-web and win-client, with the NAT adapter disconnected:
ip route                 # Linux: no default/internet route, host-only only
ping -c2 8.8.8.8         # expected: 100% loss
curl -I https://example.com   # expected: failure
```
```powershell
# win-client:
route print
Test-NetConnection 8.8.8.8 -Port 443   # expected: False
```
- **Capture:** the above on both endpoints. **Drop in:** `evidence/07-hardening-proof/`.
- **Then:** change README "permanent isolation still requires evidence" → "verified: endpoints have no internet route".

## 6. Clock synchronisation (NTP)
```bash
timedatectl status                 # Linux (siem-host, ubuntu-web)
```
```powershell
w32tm /query /status               # win-client
```
- **Capture:** sync status on all three. **Drop in:** `evidence/07-hardening-proof/`.
- **Then:** replace the "not clock-sync proof" caveat with "clocks verified synchronised".

## 7. Historical retention (requirement W4, strengthened)
Note a known alert's `_id`, reboot `siem-host`, then retrieve the **same `_id`** afterwards.
- **Capture:** the same document before and after restart. **Drop in:** `evidence/07-hardening-proof/`.
- **Then:** change "retention not demonstrated" → "verified: alert survived restart".

## 8. Windows VM hardware allocation (deliverable #1)
Open VMware **VM settings for `win-client`** with the VM name visible, showing RAM / CPU / disk.
- **Capture:** the settings window. **Drop in:** `evidence/00-virtual-machines/`.
- **Then:** fill the empty Windows row in the README inventory and sizing tables.

---
After each capture, add it to `evidence/manifest.csv` with its SHA-256 and a caption, and update
`evidence/EVIDENCE_INDEX.md`.
