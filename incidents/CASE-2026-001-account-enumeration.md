# CASE-2026-001 — Local account & group enumeration on `win-client`

[Back to project](../README.md) · Related detections: [DET-001](../detections/DET-001-windows-local-account-discovery.md), [DET-002](../detections/DET-002-windows-local-group-discovery.md)

| | |
|---|---|
| **Case ID** | CASE-2026-001 |
| **Severity** | Low |
| **Status** | Closed — benign (lab-controlled validation) |
| **Analyst** | Umud Agayev |
| **Host** | `win-client` (DESKTOP-TRFU523), `192.168.38.30`, agent `004` |
| **Detected via** | Wazuh Discover, Sysmon Event ID 1 |
| **ATT&CK** | T1087.001, T1069.001 (Discovery) |

## 1. Summary
Two local discovery commands (`net user`, `net localgroup administrators`) executed on `win-client`
under the interactive user `CORP\prod1`, parent process `powershell.exe`. Both were generated as
controlled Week 1 validation tests. No follow-on lateral movement, credential access or persistence
was observed. Closed as benign.

## 2. Timeline (UTC source times)
| Time (approx.) | Event | Source |
|---|---|---|
| 14 Oct 2026 ~15:40 | `net user` — local account listing | E12 |
| 14 Oct 2026 ~15:51 | `net localgroup administrators` — admin group listing | E13 |
| 16 Oct 2026 (NAT-off test) | `net user` re-run; matching Wazuh event | E21 |
| 16 Oct 2026 (post-reboot) | `net user` re-run after recovery; fresh event | E25 |

*Dashboard display times run +4 h ahead of these source times (see [event flow](../architecture/event-flow.md)).*

## 3. Investigation
- **Process lineage:** `net.exe` child of `powershell.exe` (`…\WindowsPowerShell\v1.0\powershell.exe`), user `CORP\prod1`, integrity High (E12) / Medium (E21, E25).
- **Command intent:** `net user` and `net localgroup administrators` are read-only Discovery commands — they *list*, they do not *create* or *modify* accounts (no `/add`, no `/delete`).
- **Scope:** single host (`win-client`). No authentication failures, no new accounts, no privileged execution correlated in the same window.
- **Account context:** `net user` output lists expected local accounts (admin, Administrator, Guest, DefaultAccount, soc_rdp_lab, WDAGUtilityAccount) — consistent with a lab build, no unexpected account present.

## 4. Assessment
Benign, lab-controlled validation activity. The telemetry path (Sysmon → agent → manager → indexer →
Discover) worked end to end, which was the purpose of the test. No indicator of real compromise.

## 5. Recommended detection improvement
In production, raw `net.exe` discovery is noisy. Prioritise it only when context is suspicious:
- parent process is a service host (`w3wp.exe`, `services.exe`, `wmiprvse.exe`) rather than an interactive shell;
- the command runs outside business hours or shortly after a remote logon;
- it appears as part of a **burst** (`net user` → `net localgroup administrators` → `whoami` → `net group /domain`).

## 6. Evidence
- [E12 — net user](../evidence/04-detections/windows-net-user.png)
- [E13 — net localgroup administrators](../evidence/04-detections/windows-administrators-enumeration.png)
- [E21 — command + event side by side](../evidence/05-recovery/windows-nat-off-test.png)
- [E25 — fresh event after recovery](../evidence/05-recovery/windows-alert-after-reboot.png)
