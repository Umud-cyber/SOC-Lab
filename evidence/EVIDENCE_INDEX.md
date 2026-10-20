# Evidence index

[Back to project](../README.md)

This index is the single source of truth for the repository. Every screenshot in `evidence/` was
read field by field and the observed values transcribed below. Where a value is not visible in any
capture, it is marked **not shown** and is never inferred. Nothing here is guessed; where the
dashboard crops a document, only the fields actually on screen are recorded.

Timestamps follow each capture: raw logs are UTC (`+0000`); the Wazuh Dashboard column is the
browser-local display (four hours ahead of the source in this lab).

## 00 — Virtual machines

| E-ID | File | Observed values |
|---|---|---|
| E32 | `00-virtual-machines/siem-vm-settings.png` | VMware VM settings: Memory **16 GB**, Processors **4**, Hard Disk (SCSI) **250 GB**, Network Adapter **NAT**, Network Adapter 2 **Host-only** (Connected, Connect at power on), USB Controller present. Title bar reads only "Virtual Machine Settings"; assignment to `siem-host` is by size/context. |
| E33 | `00-virtual-machines/ubuntu-vm-settings.png` | VMware VM settings: Memory **2 GB (2048 MB)**, Processors **2**, Hard Disk (SCSI) **40 GB**, Network Adapter **NAT**, Network Adapter 2 **Host-only**. Assignment to `ubuntu-web` by size/context. |

> No Windows VM settings capture exists. `win-client` RAM/CPU/disk are **not shown** anywhere (see `../LAB_TODO.md`).

## 01 — Network

| E-ID | File | Observed values |
|---|---|---|
| E01 | `01-network/vmware-host-only-dhcp.png` | `siem-host`: `hostname` = siem-host; `ip -br addr` ens33 **192.168.121.151/24**, ens34 **192.168.38.130/24**; default route via 192.168.121.2 dev ens33. VMware Virtual Network Editor → vmnet1 Host-only, subnet **192.168.38.0/255.255.255.0**, DHCP range **.128–.254** (explains the initial .130). |
| E02 | `01-network/siem-initial-interfaces.png` | Same interfaces; `cat /etc/netplan/*.yaml` → version 2, ens33 `dhcp4: true`, ens34 `dhcp4: true` (both DHCP initially). |
| E06 | `01-network/windows-enrollment-port.png` | Windows `route print -4`: default 0.0.0.0 via **192.168.121.2** on iface 192.168.121.146 (NAT present during setup); 192.168.38.0/24 on-link 192.168.38.30. `Test-NetConnection 192.168.38.10 -Port 1515` → SourceAddress **192.168.38.30**, InterfaceAlias Ethernet0, **TcpTestSucceeded: True**. |

## 02 — Platform

| E-ID | File | Observed values |
|---|---|---|
| E03 | `02-platform/indexer-kernel-prerequisite.png` | `sysctl -p /etc/sysctl.d/99-wazuh.conf` → **vm.max_map_count = 262144** (persisted via sysctl.d → survives reboot). git already newest **2.43.0**. APT warning: "Ignoring file 'docker.sources' … invalid filename extension". |
| E04 | `02-platform/dashboard-connectivity-restored.png` | Wed **14 Oct 2026 09:13 UTC**. `docker compose up -d` → up 3/3 (indexer-1, dashboard-1, manager-1 Running). ens34 now **192.168.38.10**; docker bridge br-… **172.18.0.1/16**. `curl -k -I https://127.0.0.1:443` → **HTTP/1.1 302 Found**, location /app/login?, osd-name wazuh.dashboard. |
| E17 | `02-platform/ports-before-hardening.png` | `docker ps` (Up 46h) — **wildcard bindings**: dashboard `0.0.0.0:443->5601`, manager `0.0.0.0:1514-1515`, `0.0.0.0:514/udp`, `0.0.0.0:55000`, `1516/tcp`; indexer `0.0.0.0:9200`. Baseline `docker stats`: dashboard 265.8 MiB, manager 447.2 MiB, indexer 1.669 GiB (limit 15.57 GiB). |
| E18 | `02-platform/ports-after-hardening.png` | `docker compose config --quiet` + `up -d` (3/3 Started). `docker ps` → dashboard **192.168.38.10:443->5601**, manager **192.168.38.10:1514-1515, :514/udp, :55000**, `1516/tcp`; indexer **127.0.0.1:9200->9200** (loopback). |
| E29 | `02-platform/docker-versions-and-service.png` | **Docker 29.9.0** build f415da8; **Docker Compose v5.6.0**; `systemctl is-active docker` = active; `is-enabled docker` = enabled. |
| E30 | `02-platform/final-container-port-bindings.png` | `docker compose ps -a`: three **wazuh/*:4.14.8** containers Up 13 min — dashboard `192.168.38.10:443->5601`, indexer `127.0.0.1:9200->9200`, manager `192.168.38.10:1514-1515, :514/udp, :55000, 1516/tcp`. Services wazuh.dashboard / wazuh.indexer / wazuh.manager. |
| E31 | `02-platform/resources-and-restart-policy.png` | `docker stats --no-stream`: dashboard 0.12 % / **190.4 MiB**, indexer 2.02 % / **1.434 GiB**, manager 1.38 % / **332.2 MiB** (limit 15.57 GiB). `docker inspect … RestartPolicy` → **always** for manager, indexer, dashboard. |

## 03 — Agents

| E-ID | File | Observed values |
|---|---|---|
| E05 | `03-agents/ubuntu-agent-active.png` | Endpoints (status=active, 1): **002 ubuntu-web 192.168.38.20** default, Ubuntu 24.04.5 LTS, node01, **v4.14.8, active**. |
| E07 | `03-agents/windows-agent-service.png` | Install: `msiexec /i …wazuh-agent-4.14.8-1.msi /q WAZUH_MANAGER='192.168.38.10' WAZUH_AGENT_NAME='win-client'`. `Get-Service Wazuh` → **Running, WazuhSvc, Wazuh**. |
| E08 | `03-agents/windows-registration-pending.png` | Intermediate: **003 WIN11 192.168.38.30 pending** (Win 11 Pro 10.0.26200.9457, v4.14.8) alongside 002 ubuntu-web active. By-status: Active 1 / Pending 1. Not the final identity. |
| E09 | `03-agents/two-agents-active.png` | Final (2 agents): **002 ubuntu-web 192.168.38.20** Ubuntu 24.04.5 LTS active; **004 win-client 192.168.38.30** Microsoft Windows 11 Pro 10.0.26200.9457 active. Both v4.14.8, node01. API id 1513629884013. |
| E10 | `03-agents/sysmon-local-events.png` | Local `Get-WinEvent` Sysmon/Operational on win-client: **Event ID 1** Process Create whoami.exe, Parent powershell.exe (`"powershell.exe" -w hidden -c whoami`), User NT AUTHORITY\SYSTEM, IntegrityLevel System; **Event ID 11** File created. TimeCreated 10/14 19:15 local vs UtcTime 02:15 → offset visible (not clock-sync proof). |
| E19 | `03-agents/agents-after-port-hardening.png` | After port change, both Active: 002 ubuntu-web; 004 win-client Microsoft Windows 11 Pro **10.0.26200.9711**, v4.14.8. |

## 04 — Detections

| E-ID | File | Observed values |
|---|---|---|
| E11 | `04-detections/windows-events-ingested.png` | DQL `agent.id:"004"` → **504 hits** over 24 h (SCA checks, Service Control Manager eventID 7040, Windows Update events). Demonstrates centralized Windows ingestion. |
| E12 | `04-detections/windows-net-user.png` | Sysmon EID 1, index wazuh-alerts-4.x-2026.10.14, agent 004 win-client 192.168.38.30. commandLine `"C:\WINDOWS\system32\net.exe" user`; originalFileName **net.exe**; image C:\Windows\System32\net.exe; description Net Command; integrityLevel **High**; logonId 0x293671; parentProcessId 10880. Time 14 Oct 19:40:25. **rule.id / rule.level not shown** in this expanded view (eventdata section only). |
| E13 | `04-detections/windows-administrators-enumeration.png` | Sysmon EID 1, same agent. commandLine `"C:\WINDOWS\system32\net.exe" localgroup administrators`; processId 4072; processGuid {56056de0-a43b-6acf-…}; integrityLevel High. **rule.id / rule.level not shown.** |
| E14 | `04-detections/linux-failed-su.png` | index 2026.10.14, agent 002 ubuntu-web 192.168.38.20. decoder.name/parent **su**; full_log `Oct 14 15:52:48 ubuntu-web su[3032]: FAILED SU (to umud) umud on tty1`; **rule.level 5**; rule.description **"User missed the password to change UID (user id)."**; rule.groups syslog, su; location journald; id 1791993170.7380329. **rule.id not shown.** |
| E15 | `04-detections/nginx-missing-page.png` | index 2026.10.16, agent 002 ubuntu-web. decoder **web-accesslog**; data.protocol GET; data.srcip 127.0.0.1; data.id **404**; data.url **/soc-test-missing-page**; full_log `127.0.0.1 - - [16/Oct/2026:12:28:58 +0000] "GET /soc-test-missing-page HTTP/1.1" 404 162 "-" "curl/8.5.0"`; **rule.level 5**; rule.description **"Web server 400 error code."**; rule.groups web, accesslog, attack. **rule.id not shown here (confirmed 31101 in E20/E23/E27).** |
| E16 | `04-detections/linux-sudo-authentication-failure.png` | index 2026.10.16, agent 002 ubuntu-web. decoder **pam**; predecoder.program_name sudo; full_log `Oct 16 12:32:20 ubuntu-web sudo[6865]: pam_unix(sudo:auth): authentication failure; logname=umud uid=1000 euid=0 tty=/dev/tty1 ruser=umud rhost= user=umud`; **rule.level 5**; rule.description **"PAM: User login failed."**; rule.groups pam, …; data.euid 0, data.uid 1000, data.tty /dev/tty1. **rule.id not shown.** |

## 05 — Recovery / resilience

| E-ID | File | Observed values |
|---|---|---|
| E20 | `05-recovery/nginx-nat-off-test.png` | NAT-off test: data.url **/soc-test-without-nat**, **rule.id 31101**, rule.level 5, full_log `[16/Oct/2026:12:48:21 +0000] "GET /soc-test-without-nat HTTP/1.1" 404 162 "-" "curl/8.5.0"`; id 1792154901.1207967. |
| E21 | `05-recovery/windows-nat-off-test.png` | Split screen. PowerShell on win-client (`CORP\prod1`, computer **DESKTOP-TRFU523**): `net user` → admin, Administrator, DefaultAccount, Guest, **soc_rdp_lab**, WDAGUtilityAccount. Discover: net.exe user, agent 004, integrityLevel **Medium**, parentImage powershell.exe, parentUser CORP\prod1, processId 1800. VMware tabs: siem-host, ubuntu-web, Windows 11 mid, **kali_SG**. |
| E22 | `05-recovery/ubuntu-services-after-reboot.png` | After endpoint reboot: `systemctl is-active wazuh-agent nginx` → **active / active**; `curl -i http://127.0.0.1/soc-test-after-reboot` → **HTTP/1.1 404**, Server **nginx/1.24.0 (Ubuntu)**, Date Fri 16 Oct 2026 12:54:04 GMT. Login banner shows cached older network info. |
| E23 | `05-recovery/nginx-alert-after-endpoint-reboot.png` | Post-endpoint-reboot alert: data.url **/soc-test-after-reboot**, **rule.id 31101**, rule.level 5, rule.groups web/accesslog/attack, rule.nist_800_53 SA.11/SI.4, rule.firedtimes 2; full_log `[16/Oct/2026:12:54:04 +0000] … 404 …`. |
| E24 | `05-recovery/windows-services-after-reboot.png` | After Windows reboot: `Get-Service WazuhSvc, Sysmon64` → **both Running**; `net user` → DESKTOP-TRFU523 accounts list. |
| E25 | `05-recovery/windows-alert-after-reboot.png` | 4 hits; net.exe user, agent 004 win-client, integrityLevel Medium, parentUser CORP\prod1, processId 2920, logonId 0xa2ecb. Fresh process event after recovery. |
| E26 | `05-recovery/siem-containers-after-reboot.png` | After SIEM reboot (Fri 16 Oct 13:08 UTC): `systemctl is-active docker` = active; `docker ps` → all three Up 24 s with **restricted bindings** (192.168.38.10 + 127.0.0.1:9200). |
| E27 | `05-recovery/nginx-alert-after-siem-reboot.png` | Fresh post-SIEM-reboot alert: data.url **/soc-test-siem-reboot**, **rule.id 31101**, rule.level 5; full_log `[16/Oct/2026:13:10:02 +0000] … 404 …`; Dashboard display ≈17:10:03 (+4 h offset illustration). |

## Excluded

| Original | Reason |
|---|---|
| E28 (credential-maintenance capture) | Contains password-hash material; excluded from the public set in full (hygiene requirement **S1**). |

## Values promoted to "verified" in v2.0 (with source)

- Nginx web alert **rule.id 31101 / level 5** — E20, E23, E27 (expanded documents).
- SIEM/Ubuntu **VM sizing** 16 GB·4·250 GB and 2 GB·2·40 GB — E32, E33.
- Container **restart policy `always`** and idle memory sample — E31.
- **Docker 29.9.0 / Compose v5.6.0**, service active+enabled — E29.
- Port **hardening** wildcard → host-only + loopback — E17 → E18 → E30.

## Values that remain "not shown" (kept honest, see `../LAB_TODO.md`)

- Windows process-event **rule.id / rule.level** for `net.exe` (E12/E13 show eventdata only).
- Linux **rule.id** for the `su` and `sudo/PAM` failures (level 5 and descriptions are shown; numeric IDs are not).
- **Windows VM** hardware allocation (no identified capture).
- Isolation **route proof**, **clock sync**, and **historical retention** (addressed as gaps).
