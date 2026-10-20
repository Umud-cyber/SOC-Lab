# DET-004 — Linux failed `sudo` (PAM authentication failure)

[Back to detections](README.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

| Field | Value |
|---|---|
| ATT&CK | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| Tactic | Privilege Escalation |
| Platform | Ubuntu 24.04.5 LTS (`ubuntu-web`) |
| Data source | journald, decoded as `pam` |
| Agent | `ubuntu-web`, ID `002`, `192.168.38.20` |
| Index | `wazuh-alerts-4.x-2026.10.16` |
| Rule level | **5** (shown) · Rule ID: **not shown** |
| Rule description | `PAM: User login failed.` |

## Hypothesis
A user invokes `sudo` to run a command with elevated privilege and fails authentication. Failed
elevation attempts are a privilege-escalation indicator, especially when repeated or from an account
not expected to use `sudo`.

## Trigger / test action
```bash
sudo -k        # clear any cached sudo credential first
sudo -v        # then enter an incorrect password
```

## Detection logic (DQL)
```
agent.name:"ubuntu-web" AND predecoder.program_name:"sudo" AND rule.groups:"authentication_failed"
```

## Observed alert fields (from evidence)
| Field | Observed value |
|---|---|
| `full_log` | `Oct 16 12:32:20 ubuntu-web sudo[6865]: pam_unix(sudo:auth): authentication failure; logname=umud uid=1000 euid=0 tty=/dev/tty1 ruser=umud rhost= user=umud` |
| `decoder.name` | `pam` |
| `predecoder.program_name` | `sudo` |
| `rule.level` | `5` |
| `rule.description` | `PAM: User login failed.` |
| `data.uid` / `data.euid` | `1000` / `0` |
| `data.tty` | `/dev/tty1` |

## Triage / investigation
1. The description `PAM: User login failed.` is **generic** — many PAM consumers share it. Use `predecoder.program_name` (`sudo`) to distinguish a sudo failure from SSH, console login, or another PAM caller.
2. Read `logname`, `ruser`, `euid=0` — this is an attempt to reach root. Confirm the actor is expected to have sudo rights.
3. Check for a **successful** privileged command immediately after; a failure alone does not prove escalation occurred.

## False-positive notes
Mistyped sudo passwords are routine. This event proves a *failed* authentication, not a successful
privileged command. Escalate on repetition or on an unexpected `logname`.

## Evidence
- [E16 — sudo/PAM authentication failure (level 5)](../evidence/04-detections/linux-sudo-authentication-failure.png)
