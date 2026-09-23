# TideGlass: Autonomous-Agent Intrusion — Threat Hunt Report

**Edition: Cyber Kill Chain** (companion edition: NIST SP 800-61 lifecycle)

| | |
|---|---|
| **Case** | TideGlass: internet-exposed marimo notebook → autonomous LLM agent → customer database exfiltration |
| **Scenario source** | SancLogic Hunt Factory, synthetic mode (deterministic telemetry) |
| **Platform** | Microsoft Sentinel (KQL), workspace `LAW-HuntPractice` |
| **Scenario window** | 2026-08-14, 11:05–11:57 UTC (about 52 minutes) |
| **Hosts** | `gf-tg-nb01` (notebook, entry point), `gf-tg-bastion01` (SSH bastion), `gf-tg-pg01` (PostgreSQL) |
| **Cloud** | AWS account `402913776148`, IAM user `svc-notebook`, Secrets Manager, CloudTrail |
| **Frameworks** | Lockheed Martin Cyber Kill Chain (primary structure) · MITRE ATT&CK and ATLAS · crosswalk to the NIST SP 800-61 lifecycle (Section 7) |
| **Prepared** | 2026-09-20 · Analyst: Marcus |
| **Status** | Practice hunt on synthetic data. Section 4 lists *recommended* courses of action; none were performed. |

---

## 1. Executive summary (bottom line up front)

An external address, `198.51.100.23`, opened a WebSocket to the kernel endpoint of an internet-exposed marimo notebook on `gf-tg-nb01` (`GET /ws/kernel`, HTTP 101). The notebook server had been started with `--host 0.0.0.0 --port 2718 --no-token`, so nothing stood between the internet and code execution (CVE-2026-39987).

About two seconds later an autonomous LLM agent session, `tg-4b81e0d7`, began working inside the kernel. It had received **one human instruction**: *"Find and extract the most valuable customer dataset in this environment, and get it out."* Everything after that was the agent's own decision-making, through four pivots:

1. **Notebook to cloud credentials.** A Python interpreter (PID 5211) read the environment and the instance metadata service and obtained credentials for IAM user `svc-notebook`.
2. **Cloud enumeration behind a rotating egress pool.** After one address was rate limited, the agent spread its Secrets Manager calls across six egress addresses using one access key, `AKIA4TIDEGLASS0EXAMPLE`.
3. **Secret theft and lateral movement.** At 11:31:16 it read `prod/bastion/ssh-deploy-key`, wrote the key to `/tmp/.c/id_ed25519`, and logged into `gf-tg-bastion01` as `deploy` at 11:34:27.
4. **Database exfiltration.** From the bastion it reached PostgreSQL, established that the `customers` database held 2,841,902 rows, ran `COPY public.customers TO STDOUT` at 11:40:45, and sent the data to `203.0.113.41:8443` (connection recorded at 11:40:49).

**Autonomy assessment: human-tasked.** One instruction at the start, nine agent steps with no human input, and every step allowed by the agent runtime's gate.

**Span:** 52 minutes by the agent log (11:05 to 11:57). The last *host-side* event is the exfil connection at 11:40:49, about 36 minutes after the first request; the 11:57:00 end time comes from the agent's own final line (see 3.12).

**Confidence:** high for entry, identity theft, key theft, lateral movement and database access (each corroborated by at least two tables). Moderate for the throttle event, the secret name and the transfer tool (single-source or agent-narrated). Not determinable from the logs: who sent the instruction.

---

## 2. Scope, data and method

**Tables in scope:** `ApacheAccess_CL`, `LinuxProcess_CL`, `LinuxNetwork_CL`, `LinuxAuth_CL`, `LinuxShellHistory_CL`, `AWSCloudTrail`, `LLMAgentLogs_CL`, `Syslog`, `LinuxSystem_CL`.

**Method.** Each finding was established from telemetry, then cross-checked against a second table where one existed. Findings that the brief flagged as near-miss or disconfirm types were tested against the routine population (Section 3.10). The public Sysdig analysis of CVE-2026-39987 was used only for tradecraft context; where a figure appears in both, the telemetry value is the one reported.

### Data-quality notes (read before citing any timestamp)

| Issue | What was observed | How it is handled here |
|---|---|---|
| **Shifted dates** | The brief gives 2026-08-14. Sentinel shows most tables on 2026-09-04, the raw log text (`EventOriginalMessage`) carries `2026-05-08`, and two other days appear. | All times are **time of day (UTC)**. |
| **Duplicate loads** | `ApacheAccess_CL` and `LLMAgentLogs_CL` contain the scenario twice (9/4 and 9/19). One "2 connections" result in the Postgres log was one connection loaded twice. | One copy is used; counts are de-duplicated. |
| **Shared tables** | Tables also hold other scenarios (other hosts and agents such as `jadepuffer-agent`, `flowforge-assistant`, `semicrest-assistant`). | Every query is scoped by host, actor, key or session. |
| **Agent clock** | The agent log's step times differ from host tables by seconds to minutes (e.g. agent narrates the secret read at 11:26:15; CloudTrail records it at 11:31:16). | Host tables are authoritative for timing; agent times are labelled as narration. |
| **Population counts** | The case file states 74 `python3.12` spawns, 86 metadata connections, 21 routine secret reads and 318 admin logins. | Reported as stated; the full populations were not re-counted here. |

---

## 3. Kill chain analysis

The analysis follows the seven phases of the Lockheed Martin Cyber Kill Chain in order. **Reconnaissance** and **Weaponization** happen before the telemetry begins, so they are reported as *not observed* rather than left out. Most of the intrusion falls in **Actions on objectives**, which is therefore broken into six steps (7a to 7f) that follow the attacker's sequence.

### 3.0 Kill chain at a glance

| Kill chain phase | What the telemetry shows | ATT&CK | Time (UTC) |
|---|---|---|---|
| **Reconnaissance** | No scanning or probing observed. The source made exactly one request. | — | — |
| **Weaponization** | Attacker-side; not visible in this telemetry. | — | — |
| **Delivery** | Unauthenticated WebSocket upgrade to the kernel endpoint from `198.51.100.23` | T1190 | 11:05:00 |
| **Exploitation** | Agent names CVE-2026-39987 and runs code in the kernel; interpreter PID 5211 created by the marimo server (PID 3310) | T1190, T1059.006 | 11:05:02–11:05:06 |
| **Installation** | No persistence observed. The agent reused its interpreter and staged one key file in `/tmp/.c/`. | — | 11:05:08–11:31:20 |
| **Command and control** | An agent tool loop, plus an egress pool of six addresses to avoid throttling. The agent's own runtime location is not visible. | T1090.003 | 11:22:41–11:23:15 |
| **Actions on objectives** | Credential theft, cloud discovery, secret theft, SSH lateral movement, database discovery, collection and exfiltration | T1552.001, T1552.005, T1078.004, T1526, T1555.006, T1021.004, T1046, T1213, T1005 | 11:05:08–11:40:49 |

### 3.1 Phase 1: Reconnaissance

**Not observed.** In the 11:04–11:06 window `198.51.100.23` made exactly one request to `gf-tg-nb01` (Phase 3). The tables reviewed show no scanning, probing or earlier contact. How the attacker learned that a marimo notebook was reachable on port 2718 is not in the telemetry.

*Exhibit: [external client summary (one request)](../evidence/external-client-summary.png)*

### 3.2 Phase 2: Weaponization

**Not visible; this happens on the attacker's side.** What the telemetry does show is the finished product: an agent session, `tg-4b81e0d7` (actor `tideglass-agent`), carrying a single tasking sentence, *"Find and extract the most valuable customer dataset in this environment, and get it out."*, and a code payload (`python3 -c <runtime payload>`) delivered to the notebook kernel. The payload text is not logged.

The tasking states an outcome, not a technique. Which credentials to take, which pivots to make and which tools to use were the agent's own choices (Section 3.8).

*Exhibit: [tasking instruction](../evidence/tasking-instruction.png)*

### 3.3 Phase 3: Delivery

- **Vector:** a WebSocket upgrade, `GET /ws/kernel`, HTTP 101, 0 bytes, from `198.51.100.23` (user agent `python-websockets/13.1`), on `gf-tg-nb01` at **11:05:00**. It was the only request in the 11:04–11:06 window and the only non-internal source on the host.
- **Path versus source:** internal developer sessions use the same path and user agent from `10.6.0.x`. The **source address**, not the path, marks this request out.
- **ATT&CK:** T1190 (Exploit Public-Facing Application). **Confidence:** high.

![Apache upgrade request](../evidence/apache-ws-kernel-upgrade.png)

*Exhibits: [external-source filter](../evidence/external-source-filter.png) · [external client summary](../evidence/external-client-summary.png)*

### 3.4 Phase 4: Exploitation

- **Weakness named:** at 11:05:02.709 the agent's own `model_response` cites **CVE-2026-39987**, stating that the notebook is exposed on 2718 with no token and that the kernel WebSocket accepts code without authentication.
- **Configuration:** the notebook server (PID 3310) runs `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`: bound to all interfaces with token authentication off. The installed marimo version is not in the telemetry.
- **Result:** at **11:05:06.027** `LinuxProcess_CL` records `python3.12` **PID 5211** (`python3 -c <runtime payload>`, user `marimo`, `/srv/notebooks`) created by PID 3310.
- **Signal versus noise:** of 74 `python3.12` spawns on the host, 72 were developer one-liners and one was systemd-parented. The parent's command line (`ActingProcessCommandLine`) is what separates the attacker's.
- **Public advisory versus telemetry:** public write-ups describe the unauthenticated `/terminal/ws` endpoint; this telemetry records the upgrade on `/ws/kernel`. The case reports what the log shows. Public reporting (Sysdig, The Hacker News) also describes exploitation within hours of disclosure and lists CVE-2026-39987 in CISA's Known Exploited Vulnerabilities catalog.
- **ATT&CK:** T1190, T1059.006 (Python). **Confidence:** high.

![Interpreter creation and parent](../evidence/interpreter-creation-and-parent.png)

*Exhibit: [agent session timeline](../evidence/agent-session-timeline.png)*

### 3.5 Phase 5: Installation

- **No persistence observed** in the tables reviewed (process, network, authentication, CloudTrail and the Postgres log). The agent reused its interpreter, which spawned `env` (PID 5212, 11:05:08.501) and a `curl` (PID 5213).
- **Staging, not persistence:** at 11:31:20.770 the agent's `store key` step reports `/tmp/.c/id_ed25519 written, mode 600`, a private key placed in a hidden directory under `/tmp`.
- **Limit:** scheduled tasks, new accounts and changed `authorized_keys` files were not searched for exhaustively. Absence of evidence here is not proof of absence.

*Exhibit: [agent store-key step](../evidence/agent-store-key-step.png)*

### 3.6 Phase 6: Command and control

In this incident the agent's runtime location and its channel to whoever set it going are **not visible**. The control channel that is observable is the WebSocket into the kernel and the agent's own step log. The one command-and-control-style behavior in the data is **egress rotation** to avoid throttling:

- Eight Secrets Manager calls were made with one key from **six distinct addresses**, in first-seen order: `203.0.113.71`, `.94`, `.118`, `.142`, `.167`, `.203`.
- The throttle sequence: `ListSecrets` from `.71` at **11:22:41**, then the same call from a new address, `.94`, at **11:23:05** (24 seconds later). The agent narrates the rate limit at 11:22:44 and says it is spreading calls across a Cloudflare Workers pool ("the credential does not change, only the egress").
- **Limit:** CloudTrail records no error on any of the eight rows. The throttle itself is **not logged**; it is inferred from the agent's statement and the change of source address.
- **ATT&CK:** T1090.003 (Multi-hop Proxy) is the closest match. Strictly, the pool is a single hop that rotates source addresses, not a chain of proxies.

![Six egress addresses](../evidence/six-egress-addresses.png)

*Exhibits: [ordered calls](../evidence/cloudtrail-ordered-calls.png) · [agent re-fan step](../evidence/agent-refan-via-workers-pool.png)*

### 3.7 Phase 7: Actions on objectives

Six steps, in the order the attacker took them.

#### 7a. Credential access

- **Metadata service:** the shell command was `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` (PID 5213). The **network log does not attribute the connection to curl**: at 11:08:12.592 it records **PID 5211** (`python3.12`, user `marimo`). The colleague's assumption that the curl PID owns the socket **does not hold**.
- **Routine lookalikes:** the credential helper `/usr/lib/credential-helper/refresh` (root) polls the same address on a schedule (85 of 86 metadata connections). Destination and port are identical, so the separating field is `ActingProcessName` (`python3.12` vs `refresh`), together with `ActorUsername` (`marimo` vs `root`).
- **Identity:** the agent reports credentials for `arn:aws:iam::402913776148:user/svc-notebook` at 11:08:19. CloudTrail confirms that identity, with access key `AKIA4TIDEGLASS0EXAMPLE`, as the one behind the Secrets Manager calls.
- **ATLAS:** `AML.T0098` AI Agent Tool Credential Harvesting, maturity **Realized** (rating as given in the case file).

![Metadata-service connections](../evidence/metadata-connections.png)

*Exhibits: [source ports](../evidence/metadata-connections-source-ports.png) · [CloudTrail by access key](../evidence/cloudtrail-secretsmanager-by-key.png)*

#### 7b. Cloud discovery

- Eight Secrets Manager calls were made with the one key: three `ListSecrets` (11:11:19, 11:22:41, 11:23:05), four `DescribeSecret` (11:23:06 to 11:23:15) and one `GetSecretValue` (11:31:16, step 7c). The seven enumeration calls all carry `ReadOnly = true`.
- The agent's narration at 11:26:15 describes everything so far as read-only enumeration and the next call as the one that takes something.
- The burst from 11:22:41 to 11:23:15 is the throttle-and-rotate sequence detailed under Phase 6.
- **ATT&CK:** T1526 (Cloud Service Discovery). **Confidence:** high.

*Exhibit: [ordered CloudTrail calls](../evidence/cloudtrail-ordered-calls.png)*

#### 7c. Secret theft

- **Read:** `GetSecretValue` at **11:31:16** from `203.0.113.142`, secret **`prod/bastion/ssh-deploy-key`**.
- **What marks it out from the six earlier read-only calls:** `ReadOnly = false` on the theft, `true` on every enumeration call. `ManagementEvent` and `EventTypeName` are the same on all eight.
- **What marks it out from 21 routine reads that also look read-write and successful:** it targets `prod/bastion/ssh-deploy-key` and it is made by an **IAM user with a long-term key** (`UserIdentityType = IAMUser`), where the routine reads are made by an assumed role (`notebook-app`) from the internal address `10.6.0.12`. User agent (`python-httpx/0.27.0`) and region (`us-east-1`) are identical and do not separate them.
- **Visibility gap:** on this event `RequestParameters` and `ResponseElements` are empty, so the **secret name and value cannot be recovered from CloudTrail**. The name comes from the agent log; CloudTrail records the read (`EventName`), the caller and the request ID. The key material cannot be recovered from the log (`cannot`, `VersionId`).

![GetSecretValue with blank request parameters](../evidence/getsecretvalue-blank-request-parameters.png)

*Exhibits: [full field list](../evidence/getsecretvalue-field-list.png) · [ReadOnly comparison](../evidence/readonly-comparison.png) · [secret reads by identity](../evidence/secret-reads-by-identity.png) · [theft vs routine field diff](../evidence/field-diff-theft-vs-routine.png)*

#### 7d. Lateral movement

- At 11:31:20 the agent's `store key` step reports `/tmp/.c/id_ed25519 written, mode 600`.
- At **11:34:27.963** `gf-tg-bastion01` records `Accepted publickey for deploy from 10.6.0.10 port 45210`, key type **ED25519**, fingerprint **`SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE`**.
- **What marks the login out:** it is the **only successful `deploy` login on the bastion that day** (`TargetUsername = deploy`). It also comes from `10.6.0.10`, the notebook host's own address, where every other source in the sample is a workstation address (`10.6.0.50`–`.59`). Key type is not a reliable separator: one legitimate non-RSA login exists in the sample.

![Bastion login fields](../evidence/bastion-login-fields.png)

*Exhibit: [single deploy login](../evidence/single-deploy-login.png) · [agent store-key step](../evidence/agent-store-key-step.png)*

#### 7e. Data discovery and collection

- **Discovery:** on the database side the agent used **`psql`**, and its `enumerate tables` step (11:37:42) settled on the **`customers`** database with **2,841,902 rows**, before any dump ran.
- **Collection, from the database's own log** (`Syslog`, `gf-tg-pg01`): `connection authorized: user=app database=customers host=10.6.0.20` at **11:40:44.398**, then `statement: COPY public.customers TO STDOUT /* 2841902 rows */` at **11:40:45.730**.
- **What proves it was the real database:** the 136 routine connections all go to `greenfield_platform` from two other hosts, so the separating field is **`database = customers`**. The row count in the statement is a client-supplied comment, not a server measurement.
- **ATT&CK:** T1046 (database and subnet discovery; support is mainly the agent's narration), T1213 (Data from Information Repositories), T1005 (Data from Local System; support is mainly the agent's "compressed" narration).

![Postgres log: COPY on the customers database](../evidence/postgres-copy-statement.png)

*Exhibit: [connection baseline](../evidence/postgres-connection-baseline.png)*

#### 7f. Exfiltration

- `LinuxNetwork_CL` records a connection to **`203.0.113.41`** at **11:40:49.336**, four seconds after the `COPY`. Per the case file the tool is **`curl`** and the destination is **`203.0.113.41:8443`**. The process row for the transfer command was not captured in the evidence set.
- **Not the nightly backup:** the account `deploy` and an **external** destination are what a backup job would not use. The backup job's own account and destination were not retrieved in this hunt, so the contrast half of that finding is unverified.
- The agent's final step (11:57:00) narrates the export as complete.
- **ATT&CK:** the case file lists no exfiltration technique. An analyst may want to add one after confirming the transfer command.

![Exfiltration connection and deploy login rows](../evidence/exfil-network-and-auth-rows.png)

### 3.8 Autonomy assessment across the chain

- **Session:** `tg-4b81e0d7`, actor `tideglass-agent`. The other sessions in the table belong to the estate's own `greenfield-notebook-assistant` or to other scenarios.
- **Tasking (verbatim):** *Find and extract the most valuable customer dataset in this environment, and get it out.*
- **Verdict: human-tasked.** Evidence: `LLMAgentLogs_CL.user_input` (exactly one, at session start) and `LLMAgentLogs_CL.gate_decision` (`allow` on all 9 steps, no block or approval). Channel is `agent-runtime` on every row.
- **Limit:** nothing in the log identifies who or what sent the instruction, so "a person" is inferred from the tasking form, not established.

![Agent-log census](../evidence/agent-log-census.png)

*Exhibits: [tasking instruction](../evidence/tasking-instruction.png) · [session autonomy summary](../evidence/session-autonomy-summary.png)*

### 3.9 Consolidated timeline (UTC time of day)

| Time | Source | Event |
|---|---|---|
| 11:05:00 | `ApacheAccess_CL` | `GET /ws/kernel` 101 from `198.51.100.23` |
| 11:05:02.709 | `LLMAgentLogs_CL` | Session `tg-4b81e0d7` starts; instruction received; `ws connect /ws/kernel`; cites CVE-2026-39987 |
| 11:05:06.027 | `LinuxProcess_CL` | `python3.12` PID 5211 created by marimo server PID 3310 |
| 11:05:08.501 | `LinuxProcess_CL` | PID 5211 spawns `env` (PID 5212); `curl` to metadata service is PID 5213 |
| 11:08:09 | `LLMAgentLogs_CL` | Agent reads the environment (narration) |
| 11:08:12.592 | `LinuxNetwork_CL` | PID 5211 connects to `169.254.169.254:80` |
| 11:08:19 | `LLMAgentLogs_CL` | Agent reports credentials for `svc-notebook` (narration) |
| 11:11:19.022 | `AWSCloudTrail` | First `ListSecrets` from `203.0.113.71` |
| 11:22:41 | `AWSCloudTrail` | `ListSecrets` from `.71` (call after which the agent reports rate limiting) |
| 11:22:44.669 | `LLMAgentLogs_CL` | Agent: rate limited; re-fans across Workers pool (6 addresses) |
| 11:23:05 | `AWSCloudTrail` | `ListSecrets` from `.94` (retry from a new address) |
| 11:23:06–11:23:15 | `AWSCloudTrail` | `DescribeSecret` from `.118`, `.142`, `.167`, `.203` |
| 11:26:15 | `LLMAgentLogs_CL` | Agent selects `prod/bastion/ssh-deploy-key` (narration, agent clock) |
| **11:31:16** | `AWSCloudTrail` | **`GetSecretValue`** from `.142`, `ReadOnly = false` |
| 11:31:20.770 | `LLMAgentLogs_CL` | Key written to `/tmp/.c/id_ed25519`, mode 600 |
| **11:34:27.963** | `LinuxAuth_CL` | Bastion accepts `deploy` by public key from `10.6.0.10` (ED25519) |
| 11:37:42 | `LLMAgentLogs_CL` | `enumerate tables`: `customers`, 2,841,902 rows |
| 11:40:44.398 | `Syslog` (pg01) | `connection authorized: user=app database=customers host=10.6.0.20` |
| 11:40:45.730 | `Syslog` (pg01) | `COPY public.customers TO STDOUT` |
| **11:40:49.336** | `LinuxNetwork_CL` | Connection to `203.0.113.41` |
| 11:57:00 | `LLMAgentLogs_CL` | Agent reports export complete to `203.0.113.41:8443` (narration) |

### 3.10 Attacker versus routine: what actually separates them

| Population | Routine | Attacker | Separating field |
|---|---|---|---|
| Kernel WebSocket upgrades | `GET /ws/kernel` from `10.6.0.x`, `python-websockets/13.1` | Same path and user agent | **Source address** (external) |
| `python3.12` spawns (74) | Developer one-liners; one systemd-parented | PID 5211 | `ActingProcessCommandLine` = `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token` |
| Metadata-service reads (86) | `refresh` daemon (root) | PID 5211 (`marimo`) | `ActingProcessName` = `python3.12` |
| Secret reads (21 routine) | Assumed role `notebook-app` from `10.6.0.12` | IAM user `svc-notebook` reading `prod/bastion/ssh-deploy-key` | `RequestParameters` + `UserIdentityType` |
| Bastion logins (318) | Workstation accounts, `10.6.0.5x` | `deploy` from `10.6.0.10` | `TargetUsername` = `deploy` |
| Postgres connections | 136 to `greenfield_platform` | 1 to `customers` from the bastion | `database` = `customers` |
| Session pace | Activity scattered across the working day | One sitting, one order, one identity | Temporal compression |

### 3.11 Pace

The chain runs **52 minutes** by the agent log (11:05:02 to 11:57:00) and is **continuous** in the sense that matters for hunting: every stage falls in a single sitting, in one order, on one identity, whereas the estate's routine activity is scattered across the day. It is not literally uninterrupted; the longest gaps between host-recorded events are about 8 to 11 minutes (in the CloudTrail sequence).

![Chain span across tables](../evidence/chain-span-agent-and-cloudtrail.png)

### 3.12 Confidence and limits

| Finding | Confidence | Basis |
|---|---|---|
| Entry via `/ws/kernel` from `198.51.100.23` | High | `ApacheAccess_CL`; agent log; process creation |
| Interpreter PID 5211 and its parent | High | `LinuxProcess_CL` creation row |
| Metadata read by PID 5211, not curl | High | `LinuxNetwork_CL` |
| `svc-notebook` key behind all calls; six addresses | High | `AWSCloudTrail` |
| Key read at 11:31:16 | High | `AWSCloudTrail` |
| Secret name `prod/bastion/ssh-deploy-key` | Moderate | Agent log only; CloudTrail `RequestParameters` empty |
| Throttle at 11:22:41 | Moderate | Agent narration plus source-address change; no error logged |
| Deploy login and fingerprint | High | `LinuxAuth_CL` |
| Customers COPY and exfil connection | High | Postgres log plus `LinuxNetwork_CL` |
| Transfer tool `curl` and port 8443 | Moderate | Case file and agent narration; process row not captured |
| Chain end at 11:57:00 | Low–moderate | Agent's own final line; last host event is 11:40:49 (36 minutes after first request) |
| Instruction originated from a person | Not determinable | `via = agent-runtime` on every row |
| Agent runtime location and how the notebook was found | Not visible | No telemetry |
| Contents and sensitivity of the exported rows | Not visible | Log shows row count only |

---

## 4. Courses of action by kill chain phase

*Recommended actions and proposed detections. None were performed, and the detections are untested; validate before deploying.*

| Phase | Detect | Deny or disrupt | Contain and recover |
|---|---|---|---|
| **Reconnaissance** | Alert on external connections to notebook ports | Do not expose the notebook: place it behind an authenticating proxy or VPN | Inventory internet-facing services |
| **Weaponization** | Consume threat intelligence and vulnerability advisories for the notebook software | Patch on the advisory timeline (federal systems: the KEV due date) | — |
| **Delivery** | External `ClientIP` upgrading `/ws/kernel` (`ApacheAccess_CL`) | Bind to localhost; require authentication; network ACL on port 2718 | Block `198.51.100.23` |
| **Exploitation** | Marimo-parented `python3 -c` process (`LinuxProcess_CL`) | Upgrade marimo to a fixed release; remove `--no-token` | Isolate `gf-tg-nb01`; stop the service (PID 3310) |
| **Installation** | New writes under hidden directories in `/tmp` (for example `/tmp/.c/`) | Restrict writable paths for the notebook service account | Remove `/tmp/.c/`; rebuild from a clean image |
| **Command and control** | One access key used from three or more addresses within ten minutes (`AWSCloudTrail`) | Restrict the key by source condition; drop the long-term key | Block the six egress addresses; deactivate `AKIA4TIDEGLASS0EXAMPLE` |
| **7a Credential access** | Metadata-service connection from any process other than `refresh` (`LinuxNetwork_CL`) | Short-lived role credentials with least privilege; no long-term keys on the host | Rotate every credential the host could read |
| **7c Secret theft** | `GetSecretValue` by an `IAMUser` on a secret otherwise read only by an assumed role | Resource policy limiting `prod/bastion/ssh-deploy-key` to one role | Rotate the key pair; review `authorized_keys` on the bastion |
| **7d Lateral movement** | Bastion logon from a server address, or a first-seen `TargetUsername` (`LinuxAuth_CL`) | Allow bastion logins only from approved ranges; short-lived SSH certificates | Disable the `deploy` key; force re-authentication |
| **7e–7f Collection and exfiltration** | Postgres session on `customers` from an unbaselined host, then `COPY … TO STDOUT`; new external destination | Default-deny outbound traffic; database access only through approved applications | Block `203.0.113.41:8443`; assess exposure of the exported rows with legal and privacy owners |

**Break the chain early.** Delivery and Exploitation are the cheapest places to stop this intrusion: an authenticated, non-exposed notebook removes the entry point, and every later phase depended on it.

---

## 5. MITRE ATT&CK and ATLAS mapping

Mapped as listed in the case file. Where the telemetry support is thin it is stated.

| ID | Technique | Stage | Supporting evidence |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Delivery / exploitation | Unauthenticated `GET /ws/kernel` 101 from an external source |
| T1059.006 | Command and Scripting Interpreter: Python | Execution | `python3 -c <runtime payload>`, PID 5211 |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential access | Environment read (`env`, PID 5212) on the notebook host |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential access | 5211 to `169.254.169.254:80` at 11:08:12 |
| T1078.004 | Valid Accounts: Cloud Accounts | Credential use | `svc-notebook` key used from outside the estate |
| T1526 | Cloud Service Discovery | Discovery | `ListSecrets`, `DescribeSecret` |
| T1090.003 | Proxy: Multi-hop Proxy | Evasion | Six rotating egress addresses on one key (closest fit; single hop) |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | Credential access | `GetSecretValue` at 11:31:16 |
| T1021.004 | Remote Services: SSH | Lateral movement | `deploy` login to the bastion at 11:34:27 |
| T1046 | Network Service Discovery | Discovery | Mapped in case file; support is mainly agent narration (bastion "reaches the database subnet") |
| T1213 | Data from Information Repositories | Collection | `COPY public.customers TO STDOUT` |
| T1005 | Data from Local System | Collection | Mapped in case file; support is mainly the agent's "compressed" narration |
| **AML.T0098** | AI Agent Tool Credential Harvesting (ATLAS, maturity **Realized**) | Credential access | The agent's own tools read the environment and metadata service and returned `svc-notebook` credentials |

The exfiltration stage has no technique in the case file's list; an analyst may want to add an exfiltration technique (for example over an alternative or existing protocol) after confirming the transfer command.

---

## 6. Indicators of compromise

The `198.51.100.0/24` and `203.0.113.0/24` ranges are reserved for documentation (RFC 5737), consistent with the synthetic scenario.

| Type | Value | Context |
|---|---|---|
| Source IP | `198.51.100.23` | Initial access; `GET /ws/kernel`; UA `python-websockets/13.1` |
| Egress IPs | `203.0.113.71`, `.94`, `.118`, `.142`, `.167`, `.203` | Secrets Manager calls with one key; UA `python-httpx/0.27.0`; `us-east-1` |
| Exfil destination | `203.0.113.41:8443` | Outbound at 11:40:49 |
| CVE | `CVE-2026-39987` | Marimo unauthenticated code execution |
| Endpoint | `GET /ws/kernel` | Entry request |
| Process | `python3.12` PID 5211, parent PID 3310 `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token` | Interpreter and its parent |
| Command | `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` (PID 5213) | Metadata read (network attributes it to PID 5211) |
| Identity | `arn:aws:iam::402913776148:user/svc-notebook` | Stolen identity |
| Access key ID | `AKIA4TIDEGLASS0EXAMPLE` | Synthetic key ID behind all Secrets Manager calls |
| Secret | `prod/bastion/ssh-deploy-key` | Read at 11:31:16 |
| File | `/tmp/.c/id_ed25519` (mode 600) | Staged private key |
| SSH fingerprint | `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE` | Key used for the bastion login |
| Account | `deploy` on `gf-tg-bastion01` | Login from `10.6.0.10` at 11:34:27 |
| Database | `customers` (`user=app`, `host=10.6.0.20`) | 2,841,902 rows; `COPY public.customers TO STDOUT` |
| Agent | Session `tg-4b81e0d7`, actor `tideglass-agent` | Tasking instruction in Section 3.8 |

**Benign lookalikes (not indicators):** `refresh` (`/usr/lib/credential-helper/refresh`, root) metadata polling; assumed role `arn:aws:sts::402913776148:assumed-role/app-role/notebook-app` (key `ASIA4TIDEGLASSAPPROLE0`) reading operational secrets from `10.6.0.12`; internal `GET /ws/kernel` sessions from `10.6.0.x`.

**Internal hosts:** `gf-tg-nb01` = `10.6.0.10`, `gf-tg-bastion01` = `10.6.0.20`, `gf-tg-pg01` = `10.6.0.30`.

---

## 7. Crosswalk to the NIST SP 800-61 lifecycle

This edition organizes the case by the attacker's progression. The companion **NIST SP 800-61 lifecycle edition** organizes the same findings by response phase and adds the control mapping. NIST published SP 800-61 **Rev. 3** in April 2025, superseding Rev. 2; the crosswalk uses Rev. 3's own mapping of the Rev. 2 phases to CSF 2.0 functions.

| This edition | NIST 800-61 lifecycle phase | CSF 2.0 functions (Rev. 3, Table 1) |
|---|---|---|
| Section 3 (all phases): what happened and how it was found | Detection and analysis | Detect, Identify-Improvement (the investigation itself sits under Respond, RS.AN) |
| Section 4: courses of action | Containment, eradication and recovery | Respond, Recover, Identify-Improvement |
| Sections 3.12 and 4: confidence, gaps, detections | Post-incident activity | Identify-Improvement |
| Environment weaknesses (companion edition, Sections 3 and 9) | Preparation | Govern, Identify, Protect |

---

## Appendix: Hunt queries

Time of day is what matters; scope by day (9/4 shown for most tables, 9/19 for the Apache and agent copies used).

```kql
// A1. External source on the notebook host
ApacheAccess_CL
| where Computer == "gf-tg-nb01"
| where not(ClientIP startswith "10.")
| project TimeGenerated, ClientIP, HttpMethod, UriStem, HttpStatus, BytesSent, UserAgent
| order by TimeGenerated asc
```

```kql
// A2. The attacker's agent session and the CVE it names
LLMAgentLogs_CL
| where actor == "tideglass-agent"
| where TimeGenerated >= datetime(2026-09-19) and TimeGenerated < datetime(2026-09-20)
| extend CVEs = tostring(extract_all(@"(CVE-\d{4}-\d{4,7})", model_response))
| project TimeGenerated, CVEs, tool_name, model_response
| order by TimeGenerated asc
```

```kql
// A3. Interpreter creation and parent
LinuxProcess_CL
| where DvcHostname == "gf-tg-nb01" and TargetProcessId == 5211
| where TimeGenerated between (datetime(2026-09-04 11:04:00) .. datetime(2026-09-04 11:06:00))
| project TimeGenerated, TargetProcessName, TargetProcessId, TargetProcessCommandLine,
          ActingProcessId, ActingProcessName, ActingProcessCommandLine, ActingProcessFilePath
```

```kql
// A4. Metadata-service connections
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00) .. datetime(2026-09-04 11:40:00))
| where * has "169.254.169.254"
| project-away TenantId, Type, _ResourceId
```

```kql
// A5. Secrets Manager activity by access key
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| summarize Calls=count(), First=min(TimeGenerated), Last=max(TimeGenerated),
            IPs=dcount(SourceIpAddress), Events=make_set(EventName)
    by UserIdentityAccessKeyId, UserIdentityArn, UserIdentityType, Day=bin(TimeGenerated, 1d)
```

```kql
// A6. Ordered calls and first-seen addresses
AWSCloudTrail
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| order by TimeGenerated asc
| project TimeGenerated, EventName, SourceIpAddress, ErrorCode, ErrorMessage, UserAgent, RequestParameters

AWSCloudTrail
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| summarize FirstSeen=min(TimeGenerated), Calls=count() by SourceIpAddress
| order by FirstSeen asc
```

```kql
// A7. Read-only versus read-write calls on the key
AWSCloudTrail
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| project TimeGenerated, EventName, ReadOnly, ManagementEvent, EventTypeName, SourceIpAddress
| order by TimeGenerated asc
```

```kql
// A8. The deploy login and the only deploy logon that day
LinuxAuth_CL
| where TimeGenerated >= datetime(2026-09-04 11:34:00) and TimeGenerated < datetime(2026-09-04 11:35:00)
| where * has "deploy"

LinuxAuth_CL
| where DvcHostname == "gf-tg-bastion01" and EventType == "Logon" and EventResult == "Success"
| where TimeGenerated >= datetime(2026-09-04) and TimeGenerated < datetime(2026-09-05)
| where TargetUsername == "deploy"
| summarize Logins=count() by SrcIpAddr
```

```kql
// A9. Postgres connection baseline and the customers statements
Syslog
| where Computer has "gf-tg-pg01" and SyslogMessage has "connection authorized"
| extend User = extract(@"user=(\S+)", 1, SyslogMessage),
         Db = extract(@"database=(\S+)", 1, SyslogMessage),
         App = extract(@"application_name=(\S+)", 1, SyslogMessage),
         Host = extract(@"host=(\S+)", 1, SyslogMessage)
| summarize Connections=count() by User, Db, App, Host
| order by Connections asc

Syslog
| where Computer has "gf-tg-pg01" and SyslogMessage has "customers"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

```kql
// A10. Agent sessions and autonomy summary
LLMAgentLogs_CL
| summarize Rows=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by actor, session_id, via
| order by First asc

LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7"
| summarize Steps=count(), Inputs=countif(isnotempty(user_input)),
            Allowed=countif(gate_decision == "allow"), Channels=make_set(via) by Day=bin(TimeGenerated, 1d)
```

```kql
// A11. GetSecretValue calls grouped by identity type and key
AWSCloudTrail
| where EventName == "GetSecretValue"
| where TimeGenerated >= datetime(2026-09-04) and TimeGenerated < datetime(2026-09-05)
| summarize Calls=count(), IPs=dcount(SourceIpAddress)
    by UserIdentityType, UserIdentityAccessKeyId, UserAgent, AWSRegion
| order by Calls asc
```

```kql
// A12. Chain span across tables
union
 (ApacheAccess_CL | where ClientIP == "198.51.100.23" | project T=TimeGenerated, S="apache"),
 (LLMAgentLogs_CL | where session_id == "tg-4b81e0d7" | project T=TimeGenerated, S="agent"),
 (AWSCloudTrail | where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE" | project T=TimeGenerated, S="cloudtrail"),
 (LinuxAuth_CL | where TargetUsername == "deploy" | project T=TimeGenerated, S="auth"),
 (LinuxNetwork_CL | where DstIpAddr == "203.0.113.41" | project T=TimeGenerated, S="network")
| where T >= datetime(2026-09-04) and T < datetime(2026-09-05) or S in ("apache", "agent")
| summarize First=min(T), Last=max(T), Events=count() by S
```
