# DET-005 — Nginx 404 to a crafted path (web reconnaissance)

[Back to detections](README.md) · [Evidence index](../evidence/EVIDENCE_INDEX.md)

| Field | Value |
|---|---|
| ATT&CK | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) — Active Scanning: Wordlist Scanning |
| Tactic | Reconnaissance |
| Platform | Nginx 1.24.0 on Ubuntu (`ubuntu-web`) |
| Data source | `/var/log/nginx/access.log`, decoder `web-accesslog` |
| Agent | `ubuntu-web`, ID `002`, `192.168.38.20` |
| Index | `wazuh-alerts-4.x-2026.10.16` |
| Rule ID / level | **31101 / 5** (verified) |
| Rule description | `Web server 400 error code.` |

## Hypothesis
A client requests a resource that does not exist, producing an HTTP 404. Bursts of 404s to crafted
or wordlist-style paths indicate someone probing the web server for hidden content — early
reconnaissance against the web application.

## Trigger / test action
```bash
curl -i http://127.0.0.1/soc-test-missing-page
```

## Detection logic (DQL)
```
agent.name:"ubuntu-web" AND rule.id:"31101" AND data.url:"/soc-test-missing-page"
```

## Observed alert fields (from evidence)
| Field | Observed value |
|---|---|
| `full_log` | `127.0.0.1 - - [16/Oct/2026:12:28:58 +0000] "GET /soc-test-missing-page HTTP/1.1" 404 162 "-" "curl/8.5.0"` |
| `decoder.name` | `web-accesslog` |
| `data.protocol` / `data.id` | `GET` / `404` |
| `data.srcip` | `127.0.0.1` (request generated locally with curl) |
| `rule.id` / `rule.level` | `31101` / `5` |
| `rule.description` | `Web server 400 error code.` |
| `rule.groups` | `web, accesslog, attack` |

> **Reading the rule name correctly:** rule 31101 is the generic *"Web server 400 error code"* class.
> The specific status is in `data.id` — here **404**, not 400. Always read `data.id` for the real code.

## Triage / investigation
1. Read `data.url` and `data.id` to see **what** was requested and the result.
2. Check `data.srcip` — loopback here because curl ran locally; a remote source IP with many 404s to
   different paths is the reconnaissance pattern to watch for.
3. Count 404s per source over time; a single crafted 404 is a validation event, a burst is scanning.

## Resilience note
This detection is the repository's recovery marker: distinct crafted URLs confirm *fresh* ingestion
after reboots — `/soc-test-without-nat` (E20), `/soc-test-after-reboot` (E23), `/soc-test-siem-reboot`
(E27), each producing a new rule 31101 / level 5 alert.

## False-positive notes
Legitimate clients hit 404s (stale links, missing favicons). Signal comes from **volume, variety of
paths, and source** rather than any single 404.

## Evidence
- [E15 — initial /soc-test-missing-page 404](../evidence/04-detections/nginx-missing-page.png)
- [E20 — /soc-test-without-nat (NAT-off test)](../evidence/05-recovery/nginx-nat-off-test.png)
- [E23 — /soc-test-after-reboot, rule 31101 level 5](../evidence/05-recovery/nginx-alert-after-endpoint-reboot.png)
- [E27 — /soc-test-siem-reboot after SIEM restart](../evidence/05-recovery/nginx-alert-after-siem-reboot.png)
