# Detection coverage

[Back to project](../README.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

This folder documents the detections that were **actually observed in this lab**, each mapped to the
relevant [MITRE ATT&CK](https://attack.mitre.org/) technique. Every card is sourced from the
[evidence index](../evidence/EVIDENCE_INDEX.md); no technique is claimed without a matching capture.

The lab's five controlled test events were generated deliberately against the student's own VMs on
the isolated lab network. A failed password, an account-listing command or an HTTP 404 is useful
detection telemetry without being evidence of a real intrusion — interpretation always depends on
the initiating user, command, source, timing and surrounding activity.

## ATT&CK matrix — observed detections

| ID | Detection | Platform | Data source | ATT&CK technique | Tactic | Evidence |
|----|-----------|----------|-------------|------------------|--------|----------|
| [DET-001](DET-001-windows-local-account-discovery.md) | `net user` account listing | Windows | Sysmon Event ID 1 | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) Account Discovery: Local Account | Discovery | E12, E21, E25 |
| [DET-002](DET-002-windows-local-group-discovery.md) | `net localgroup administrators` | Windows | Sysmon Event ID 1 | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) Permission Groups Discovery: Local Groups | Discovery | E13 |
| [DET-003](DET-003-linux-su-failure.md) | Failed `su` (UID-change password) | Linux | journald (`su`) | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Credential Access | E14 |
| [DET-004](DET-004-linux-sudo-failure.md) | Failed `sudo` (PAM auth failure) | Linux | journald (`pam`) | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Abuse Elevation Control: Sudo & Sudo Caching | Privilege Escalation | E16 |
| [DET-005](DET-005-nginx-web-recon.md) | Nginx 404 to crafted path | Web (Linux) | nginx access log | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Active Scanning: Wordlist Scanning | Reconnaissance | E15, E20, E23, E27 |

### Coverage view

```
Reconnaissance   Credential Access   Privilege Escalation   Discovery
──────────────   ─────────────────   ────────────────────   ─────────────────────
T1595.003 ✔      T1110 ✔             T1548.003 ✔            T1087.001 ✔
(DET-005)        (DET-003)           (DET-004)              T1069.001 ✔
                                                            (DET-001, DET-002)
```

## Planned detections — required but not yet captured

These three events are required by the Week 1 brief (V1) but are **not** in the current evidence set.
They are tracked, with exact capture steps, in [`../LAB_TODO.md`](../LAB_TODO.md). They are listed here
only as planned coverage — they are **not** claimed as detections.

| Planned | Platform | ATT&CK technique | Tactic |
|---------|----------|------------------|--------|
| Failed SSH login | Linux | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force (+ [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH) | Credential Access / Lateral Movement |
| New local user created | Linux | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account | Persistence |
| Failed Windows logon (Event 4625) | Windows | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Credential Access |

## Card format

Each card follows the same structure: metadata, hypothesis, trigger action, detection logic (DQL),
observed alert fields, triage workflow, false-positive notes, and evidence references.
