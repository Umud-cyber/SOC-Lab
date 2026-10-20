# Executive summary — Mini SOC Lab (Week 1)

[Full technical README](README.md)

## What was built
A small, isolated Security Operations Center on a single laptop using VMware. One Ubuntu **SIEM host**
runs the Wazuh Manager, Indexer and Dashboard in Docker. Two monitored endpoints — an Ubuntu web
server and a Windows 11 workstation — send their security events to it. The result is a working
pipeline that takes an event on an endpoint and turns it into a searchable, investigable alert.

## What it detects
Five controlled test events were generated and found in the dashboard, each mapped to a recognised
attacker technique (MITRE ATT&CK):

| Activity | What it represents | Technique |
|---|---|---|
| Windows account & group listing | Attacker reconnaissance of who exists and who is admin | T1087.001, T1069.001 |
| Failed `su` / failed `sudo` on Linux | Password guessing and privilege-escalation attempts | T1110, T1548.003 |
| Repeated 404s to crafted web paths | Scanning a web server for hidden content | T1595.003 |

See the [detection coverage](detections/README.md) for the technique-by-technique breakdown.

## How trustworthy is the evidence
Every claim in this repository is backed by a screenshot, and each screenshot was read field by field
into the [evidence index](evidence/EVIDENCE_INDEX.md). Where the dashboard did not display a value
(for example, the numeric rule ID on some Windows events), it is marked *not shown* rather than
guessed. Credentials, hashes and keys are excluded from the repository.

## What is proven vs. still to prove
**Proven:** the stack runs and survives restarts; both endpoints enrol and stay active; the five
detections fire with their evidence; service ports were tightened from wildcard to lab-only + loopback;
container restart policy is `always`.

**Not yet proven (tracked in [LAB_TODO](LAB_TODO.md)):** permanent internet isolation of the endpoints
(route proof), clock synchronisation across all three VMs, and historical alert retention across a
defined interval. These are stated honestly as gaps, not glossed over.

## Why it matters
Week 1 is the foundation the remaining capstone weeks build on: a safe place to break things and a
system that records what the machines are saying. This repository is written so a stranger could
rebuild the lab and reproduce every result.
