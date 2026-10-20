# DET-002 — Windows local group discovery (`net localgroup administrators`)

[Back to detections](README.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

| Field | Value |
|---|---|
| ATT&CK | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) — Permission Groups Discovery: Local Groups |
| Tactic | Discovery |
| Platform | Windows 11 Pro (`win-client`) |
| Data source | Sysmon **Event ID 1** (Process Create) via Wazuh agent |
| Agent | `win-client`, ID `004`, `192.168.38.30` |
| Index | `wazuh-alerts-4.x-*` |
| Rule ID / level | **not shown** — expanded document (E13) shows `data.win.eventdata.*` only; see [LAB_TODO](../LAB_TODO.md) |

## Hypothesis
After listing accounts, an operator enumerates the **local Administrators group** to find which
accounts hold privilege — a natural follow-on to DET-001 and a precursor to privilege escalation or
lateral movement planning.

## Trigger / test action
```powershell
net localgroup administrators
```

## Detection logic (DQL)
```
agent.name:"win-client" AND data.win.system.eventID:"1" AND data.win.eventdata.commandLine:*localgroup*administrators*
```

## Observed alert fields (from evidence)
| Field | Observed value |
|---|---|
| `data.win.eventdata.commandLine` | `"C:\WINDOWS\system32\net.exe" localgroup administrators` |
| `data.win.eventdata.originalFileName` | `net.exe` |
| `data.win.eventdata.processId` | `4072` |
| `data.win.eventdata.processGuid` | `{56056de0-a43b-6acf-bf06-000000001600}` |
| `data.win.eventdata.integrityLevel` | `High` |
| `data.win.eventdata.description` | `Net Command` |

## Triage / investigation
1. Confirm the **argument** is `localgroup administrators` — group enumeration, distinct from account listing (DET-001) or group modification (`/add`).
2. Correlate with DET-001 on the same host and user: listing accounts then listing admins within seconds is a recognisable discovery sequence.
3. Establish whether the user was expected to be performing administrative review at that time.

## False-positive notes
Routine for administrators and onboarding scripts. Treat as signal only when the parent, user or
timing is unusual, or when it is part of a broader discovery burst.

## Evidence
- [E13 — net.exe localgroup administrators, expanded](../evidence/04-detections/windows-administrators-enumeration.png)
