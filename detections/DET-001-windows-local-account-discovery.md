# DET-001 — Windows local account discovery (`net user`)

[Back to detections](README.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

| Field | Value |
|---|---|
| ATT&CK | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) — Account Discovery: Local Account |
| Tactic | Discovery |
| Platform | Windows 11 Pro (`win-client`) |
| Data source | Sysmon **Event ID 1** (Process Create) via Wazuh agent |
| Agent | `win-client`, ID `004`, `192.168.38.30` |
| Index | `wazuh-alerts-4.x-*` |
| Rule ID / level | **not shown** — the expanded documents (E12, E25) display the Sysmon `data.win.eventdata.*` fields, not the `rule.*` fields; see [LAB_TODO](../LAB_TODO.md) |

## Hypothesis
A user — or a process running in a user's context — enumerates local accounts to understand who
exists on the host. This is a common early Discovery step after initial access.

## Trigger / test action
Run on `win-client` (lab-controlled):
```powershell
net user
```

## Detection logic (DQL)
```
agent.name:"win-client" AND data.win.system.eventID:"1" AND data.win.eventdata.originalFileName:"net.exe"
```

## Observed alert fields (from evidence)
| Field | Observed value |
|---|---|
| `data.win.eventdata.commandLine` | `"C:\WINDOWS\system32\net.exe" user` |
| `data.win.eventdata.originalFileName` | `net.exe` |
| `data.win.eventdata.image` | `C:\Windows\System32\net.exe` |
| `data.win.eventdata.description` | `Net Command` |
| `data.win.eventdata.integrityLevel` | `High` (E12) / `Medium` (E21, E25) |
| `data.win.eventdata.parentImage` | `…\WindowsPowerShell\v1.0\powershell.exe` |
| `data.win.eventdata.parentUser` | `CORP\prod1` |
| `agent.id` / `agent.ip` | `004` / `192.168.38.30` |

## Triage / investigation
1. Read the **command line** — `net user` with no argument is account *listing*, distinct from `net user <name> <password> /add` (account creation).
2. Check the **parent process** and **user**: an interactive `powershell.exe` under `CORP\prod1` during testing is expected; the same command spawned by a service host (`w3wp.exe`, `services.exe`) or after an unexpected remote logon is not.
3. Look at **surrounding events** — a single discovery command is low signal; `net user` → `net localgroup administrators` → `whoami` in sequence is a discovery pattern.

## False-positive notes
Administrators and automation legitimately run `net user`. The parent process, the user context and
the timing — not the command alone — decide whether it is benign.

## Evidence
- [E12 — net.exe user, expanded](../evidence/04-detections/windows-net-user.png)
- [E21 — command and event side by side (NAT-off test)](../evidence/05-recovery/windows-nat-off-test.png)
- [E25 — fresh event after Windows recovery](../evidence/05-recovery/windows-alert-after-reboot.png)
