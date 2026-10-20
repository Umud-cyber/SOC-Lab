# DET-003 — Linux failed `su` (UID-change password failure)

[Back to detections](README.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

| Field | Value |
|---|---|
| ATT&CK | [T1110](https://attack.mitre.org/techniques/T1110/) — Brute Force |
| Tactic | Credential Access |
| Platform | Ubuntu 24.04.5 LTS (`ubuntu-web`) |
| Data source | journald, decoded as `su` |
| Agent | `ubuntu-web`, ID `002`, `192.168.38.20` |
| Index | `wazuh-alerts-4.x-2026.10.14` |
| Rule level | **5** (shown) · Rule ID: **not shown** (numeric ID not in the captured field view) |
| Rule description | `User missed the password to change UID (user id).` |

## Hypothesis
A user attempts to switch to another account with `su` and supplies the wrong password. Repeated
failures of this kind are an indicator of password-guessing against a local account.

## Trigger / test action
```bash
su           # on ubuntu-web; enter an incorrect password
```

## Detection logic (DQL)
```
agent.name:"ubuntu-web" AND predecoder.program_name:"su" AND rule.level:5
```

## Observed alert fields (from evidence)
| Field | Observed value |
|---|---|
| `full_log` | `Oct 14 15:52:48 ubuntu-web su[3032]: FAILED SU (to umud) umud on tty1` |
| `decoder.name` / `decoder.parent` | `su` / `su` |
| `rule.level` | `5` |
| `rule.description` | `User missed the password to change UID (user id).` |
| `rule.groups` | `syslog, su` |
| `location` | `journald` |
| `id` | `1791993170.7380329` |

## Triage / investigation
1. Read **source and target user**, terminal and timestamp from `full_log` (`to umud … on tty1`).
2. Count failures in a short window — a single deliberate failure is a validation event; a burst is a brute-force signal.
3. Check whether a **successful** `su`/login followed from the same terminal.

## False-positive notes
One mistyped password is normal operator behaviour. Escalate on repetition, on an unexpected target
account, or when paired with other authentication failures (see DET-004).

## Evidence
- [E14 — failed su (level 5)](../evidence/04-detections/linux-failed-su.png)
