# Data flow — source to alert

[Back to architecture](README.md) · [Event flow narrative](event-flow.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

This document traces each telemetry source through decode, rule matching and indexing, using the
decoder and rule values actually observed in this lab.

## Pipeline

```
 Endpoint source  ─▶  Wazuh agent  ─▶  Manager (decoder ─▶ ruleset)  ─▶  Filebeat ─▶ Indexer  ─▶  Dashboard (Discover)
 (log / channel)      (collects         (extracts fields,                  (ships      (stores        (analyst query)
                       configured         assigns rule + level)             alert)      wazuh-alerts)
                       sources)
```

## Source → decoder → rule → index (observed)

| Source | Collected as | `decoder.name` | Observed rule | Level | Index | Detection |
|---|---|---|---|---|---|---|
| Sysmon Operational channel (Windows) | Windows Event Channel | `windows_eventchannel` family | **not shown** (Sysmon EID 1 process event) | — | `wazuh-alerts-4.x-*` | [DET-001](../detections/DET-001-windows-local-account-discovery.md), [DET-002](../detections/DET-002-windows-local-group-discovery.md) |
| `su` authentication (Linux) | journald | `su` | level 5, "User missed the password to change UID (user id)." | 5 | `…2026.10.14` | [DET-003](../detections/DET-003-linux-su-failure.md) |
| `sudo` / PAM (Linux) | journald | `pam` | level 5, "PAM: User login failed." | 5 | `…2026.10.16` | [DET-004](../detections/DET-004-linux-sudo-failure.md) |
| Nginx access log | `/var/log/nginx/access.log` | `web-accesslog` | **rule 31101**, "Web server 400 error code." | 5 | `…2026.10.16` | [DET-005](../detections/DET-005-nginx-web-recon.md) |

## Reading notes
- **Collection is configured, not automatic.** Windows Event Channels (incl. Sysmon) and Linux log
  sources must be declared for the agent to forward them; the agent does not ship every possible log.
- **A local event is not an alert.** An entry in the local Sysmon log (E10) only becomes an alert in
  `wazuh-alerts-*` after collection, decode, rule match, the alert-logging threshold (default level 3),
  indexing, and a matching time window.
- **Generic rule names need the data field.** Rule 31101 reads "Web server 400 error code" but the
  real status is in `data.id` (404 here). Read the data field, not just the rule name.
- **Time display.** Raw logs are UTC; Discover shows browser-local time (+4 h in this lab). Compare
  explicit event fields, not filenames, when reconciling.
