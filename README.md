# TideGlass: Autonomous-Agent Intrusion — Threat Hunt

A Microsoft Sentinel (KQL) threat hunt of a synthetic incident in which an **autonomous LLM agent** went from an unauthenticated notebook WebSocket to a **2.8 million row database exfiltration** in about an hour: four pivots, one human instruction.

> **Practice exercise.** The scenario and telemetry are synthetic (SancLogic Hunt Factory, synthetic mode). No real systems, customers or credentials are involved. IP addresses use the reserved documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`), and the AWS key ID and SSH fingerprint are fabricated.

## Read the report

The same findings are written up in **two editions**, each as Markdown and as a PDF with the evidence screenshots embedded:

| Edition | Organized by | Markdown | PDF |
|---|---|---|---|
| **Cyber Kill Chain** | The attacker's progression: the seven Lockheed Martin phases, with Actions on objectives split into six steps, mapped to **MITRE ATT&CK** and **ATLAS**, plus courses of action per phase | [`report/TideGlass-Threat-Hunt-Report-Kill-Chain.md`](report/TideGlass-Threat-Hunt-Report-Kill-Chain.md) | [`report/TideGlass-Threat-Hunt-Report-Kill-Chain.pdf`](report/TideGlass-Threat-Hunt-Report-Kill-Chain.pdf) |
| **NIST SP 800-61 lifecycle** | The response lifecycle: preparation → detection and analysis → containment, eradication and recovery → post-incident activity, crosswalked to the **Rev. 3 / CSF 2.0** functions (Rev. 3, April 2025, supersedes Rev. 2), plus a **NIST SP 800-53 Rev. 5** control and CSF outcome mapping | [`report/TideGlass-Threat-Hunt-Report-NIST-800-61.md`](report/TideGlass-Threat-Hunt-Report-NIST-800-61.md) | [`report/TideGlass-Threat-Hunt-Report-NIST-800-61.pdf`](report/TideGlass-Threat-Hunt-Report-NIST-800-61.pdf) |

Both editions include a consolidated timeline, an attacker-versus-routine comparison, a confidence table, IOCs, and the KQL used.

## The case in brief

| | |
|---|---|
| **Entry** | `GET /ws/kernel` (HTTP 101) from `198.51.100.23` to an internet-exposed marimo notebook started with `--no-token` (CVE-2026-39987) |
| **Agent tasking** | One instruction: *"Find and extract the most valuable customer dataset in this environment, and get it out."* |
| **Credential theft** | Interpreter PID 5211 read the environment and the metadata service; credentials for IAM user `svc-notebook` |
| **Throttle evasion** | One access key used from **six** rotating egress addresses after a rate limit |
| **Secret theft** | `GetSecretValue` on `prod/bastion/ssh-deploy-key` at 11:31:16 (`ReadOnly = false`) |
| **Lateral movement** | Key written to `/tmp/.c/id_ed25519`; `deploy` logged into the SSH bastion at 11:34:27 |
| **Exfiltration** | `COPY public.customers TO STDOUT` (2,841,902 rows) at 11:40:45; outbound connection to `203.0.113.41:8443` at 11:40:49 |
| **Verdict** | **Human-tasked**: one instruction, nine agent steps, all allowed by the runtime gate |
| **Span** | 52 minutes by the agent log (host-side activity ends about 36 minutes after the first request) |

## Findings

| Stage | What the telemetry shows |
|---|---|
| Delivery | `GET /ws/kernel`, HTTP 101, from `198.51.100.23` — the only external request to the notebook in the window |
| Exploitation | Notebook run as `marimo edit --host 0.0.0.0 --port 2718 --no-token`; agent cites CVE-2026-39987 in its own reasoning before acting |
| Execution | Interpreter `python3.12` (PID 5211) spawned by the marimo server (PID 3310); the one attacker spawn among 74 on the host |
| Credential access | PID 5211 (not the `curl` shell command) is the process the network log shows reaching the instance metadata service; credentials obtained for IAM user `svc-notebook` |
| Discovery / evasion | 8 Secrets Manager calls on one access key from 6 rotating addresses; a `ListSecrets` retry from a new address follows a rate-limit event the agent narrates but CloudTrail does not log as an error |
| Secret theft | `GetSecretValue` on `prod/bastion/ssh-deploy-key`, 11:31:16 — the only non-read-only call among 7 enumeration calls, and the only IAM-user call among 22 calls that otherwise look identical to a routine assumed-role reader |
| Lateral movement | Key staged to `/tmp/.c/id_ed25519`; `deploy` account logs into the bastion by public key from `10.6.0.10` (the notebook host itself) at 11:34:27 — its only successful login that day |
| Collection | `psql` enumeration settles on the `customers` database (2,841,902 rows) before any dump; Postgres's own log shows the session's `database=customers`, distinct from 136 routine connections to a different database |
| Exfiltration | `COPY public.customers TO STDOUT`, then an outbound connection to `203.0.113.41:8443` — an external destination and an account (`deploy`) inconsistent with the scheduled backup job |
| Autonomy | One human instruction at session start (`LLMAgentLogs_CL.user_input`); every step after that is the agent's own decision, all allowed by the runtime's policy gate (`gate_decision = allow`) |

A recurring theme: several of the attacker's actions are nearly indistinguishable from the estate's own routine automation in volume or destination. See **Signal versus noise** below for what actually separates them.

## Evidence sample

![CloudTrail: the theft call is the only one with `ReadOnly = false`](evidence/readonly-comparison.png)

*One of 26 screenshots in [`evidence/`](evidence/), each cited inline in both report editions.*

## Sample queries

Three of the queries used, out of the full set in each report's appendix.

```kql
// External source reaching the notebook's kernel endpoint
ApacheAccess_CL
| where Computer == "gf-tg-nb01"
| where not(ClientIP startswith "10.")
| project TimeGenerated, ClientIP, HttpMethod, UriStem, HttpStatus, UserAgent
| order by TimeGenerated asc
```

```kql
// One access key, six egress addresses, in first-seen order
AWSCloudTrail
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| summarize FirstSeen = min(TimeGenerated), Calls = count() by SourceIpAddress
| order by FirstSeen asc
```

```kql
// The database's own log: connection and statement on the customers database
Syslog
| where Computer has "gf-tg-pg01" and SyslogMessage has "customers"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

## Indicators of compromise

Reserved documentation ranges (RFC 5737); key ID and fingerprint are synthetic.

| Type | Value | Context |
|---|---|---|
| Source IP | `198.51.100.23` | Initial access; `GET /ws/kernel` |
| Egress IPs | `203.0.113.71`, `.94`, `.118`, `.142`, `.167`, `.203` | Secrets Manager calls on one key |
| Exfil destination | `203.0.113.41:8443` | Outbound transfer |
| CVE | `CVE-2026-39987` | Marimo unauthenticated code execution |
| Process | `python3.12` PID 5211, parent PID 3310 `marimo edit --host 0.0.0.0 --port 2718 --no-token` | Interpreter and its parent |
| Identity | `arn:aws:iam::402913776148:user/svc-notebook` | Stolen identity |
| Access key ID | `AKIA4TIDEGLASS0EXAMPLE` | Behind every Secrets Manager call |
| Secret | `prod/bastion/ssh-deploy-key` | Read at 11:31:16 |
| File | `/tmp/.c/id_ed25519` (mode 600) | Staged private key |
| SSH fingerprint | `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE` | Bastion login key |
| Account | `deploy` on `gf-tg-bastion01` | Login from `10.6.0.10` |
| Database | `customers` (`user=app`, `host=10.6.0.20`) | 2,841,902 rows exported |

Full IOC table, with benign lookalikes to rule out, is in each report.

## Kill chain at a glance

| Phase | Finding | ATT&CK |
|---|---|---|
| Delivery | Unauthenticated WebSocket upgrade from an external address | T1190 |
| Exploitation / execution | Interpreter spawned by the marimo server | T1190, T1059.006 |
| Credential access | Environment and metadata service read; cloud secret retrieved | T1552.001, T1552.005, T1555.006, `AML.T0098` |
| Discovery | Secrets enumeration; database and subnet discovery | T1526, T1046 |
| Evasion | Source-address rotation to avoid throttling | T1090.003 |
| Lateral movement | SSH to the bastion with the stolen key | T1021.004, T1078.004 |
| Collection and exfiltration | Customer table copied and sent to an external address | T1213, T1005 |

## Signal versus noise

The estate's routine automation looks almost identical to several attacker actions. What separates them:

| Population | Separating field |
|---|---|
| `python3.12` spawns | `ActingProcessCommandLine` (the marimo parent) |
| Metadata-service reads | `ActingProcessName` = `python3.12` (not `refresh`) |
| Secret reads | `RequestParameters` and `UserIdentityType` |
| Bastion logins | `TargetUsername` = `deploy` |
| Postgres connections | `database` = `customers` |

## Repository layout

```
.
├── README.md
├── report/
│   ├── TideGlass-Threat-Hunt-Report-Kill-Chain.md
│   ├── TideGlass-Threat-Hunt-Report-Kill-Chain.pdf
│   ├── TideGlass-Threat-Hunt-Report-NIST-800-61.md
│   └── TideGlass-Threat-Hunt-Report-NIST-800-61.pdf
└── evidence/                             # screenshots cited by the reports
```

## Data notes

- Timestamps in the practice workspace are shifted from the scenario window (2026-08-14, 11:05–11:57 UTC). The report uses **time of day (UTC)**.
- Some tables hold the scenario twice, and tables are shared with other scenarios; queries are scoped by host, actor, key or session.
- The agent log's own clock differs from host tables by seconds to minutes, so host tables are treated as authoritative for timing.

## Limits worth knowing

- CloudTrail's `GetSecretValue` record in this data carries no secret identifier, so the secret name rests on the agent log.
- The rate-limit event is not logged as an error; it is inferred from the agent's statement and a change of source address.
- The logs do not show who sent the tasking instruction, only that one arrived.

## Reproducing

The queries are in the **appendix** of either report. They were written for the `LAW-HuntPractice` workspace and its table schemas (`ApacheAccess_CL`, `LinuxProcess_CL`, `LinuxNetwork_CL`, `LinuxAuth_CL`, `AWSCloudTrail`, `LLMAgentLogs_CL`, `Syslog`); they will not run elsewhere without that data.

## Attribution and license

- Scenario and telemetry: provided by the hunt platform (SancLogic Hunt Factory). Confirm its redistribution terms before publishing.
- Analysis, report text and queries: Marcus. All rights reserved; not licensed for reuse without permission.

## References

- NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile* (April 2025), and Rev. 2, *Computer Security Incident Handling Guide* (2012, superseded)
- NIST SP 800-53 Rev. 5, *Security and Privacy Controls for Information Systems and Organizations*
- MITRE ATT&CK (Enterprise) and MITRE ATLAS
- Sysdig Threat Research Team, public analysis of CVE-2026-39987 exploitation
