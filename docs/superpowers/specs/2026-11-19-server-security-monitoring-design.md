# Server Security Monitoring — Design

**Date:** 2026-11-19
**Status:** Draft for approval
**Size:** Project (full design)

---

## 1. Intent and the why

We operate a fleet of Linux servers. Some run a single project, some run several.
Today nobody knows what is happening on them unless someone SSHes in and looks.

The immediate motivation is a concrete and recurring attack: automated bots find a
weak door (exposed Docker API, a database bound to `0.0.0.0`, password SSH, a leaked
deploy key), get in, create a new account with root-equivalent privileges to keep
their access, install a cryptocurrency miner, and use our hardware. This class of
compromise has hit servers like ours repeatedly in recent months. It is usually
discovered late — by a performance complaint or a hosting bill — not by us noticing.

We want a system that watches every server continuously, understands each server's
own normal behaviour, and tells an admin in plain language when something is wrong,
early enough to act.

The secondary motivation is everyday operations: one place to see what is running on
which server, how much memory and CPU each project is using, who is connecting in,
and what the logs say — without SSHing anywhere.

### What success looks like

- An admin opens one dashboard and can answer "is anything wrong anywhere?" in
  ten seconds.
- A brute-force attempt, a newly created privileged account, or a miner process is
  reported to us within minutes, with enough evidence that we know what to do.
- An admin can see per-project memory and CPU on a shared server without guessing
  which process belongs to which project.
- Six months in, the alerts are still being read, because they are rare and almost
  always real.

---

## 2. Goals

1. **Continuous, unattended collection** from every server in the fleet.
2. **Per-project visibility** on shared servers — memory, CPU, ports, logs — across
   heterogeneous process managers (systemd, Docker, pm2, supervisor, and bare
   processes).
3. **Intrusion detection** aimed squarely at the real attack chain: credential
   brute force → access → privilege persistence → miner installation.
4. **Posture visibility** — what is exposed to the internet and who can log in,
   because that is how the intruder gets in. Finding the open door is worth more
   than detecting the miner afterwards.
5. **Plain-language alerting** with evidence, routed to a channel admins actually
   read.
6. **Low footprint.** The agent must be invisible in production: target under 1% of
   one CPU core and under 50 MB RSS in steady state. An agent that slows a
   production box will be uninstalled, and then the system protects nothing.

## 3. Non-goals

- Not an antivirus or signature-scanning engine.
- Not a WAF or an inline traffic blocker.
- Not a long-term log archive. We keep what detection needs, not everything.
- Not application performance monitoring (no traces, no request-level profiling).
- Not a multi-tenant SaaS product. Internal use, our own fleet. (Noted as a future
  possibility, but no design concession is made for it now.)
- Not configuration management. It observes; it does not deploy.

## 4. Anti-goals — what would make this a failure even if it works

- **An alert stream nobody reads.** If it cries wolf, it has failed, even when every
  individual alert is technically correct. Noise is the main risk to this project.
- **The central app becoming the breach vector.** A system holding standing root
  access to every server is a worse problem than the one it solves.
- **A dashboard that cannot answer "is this normal?"** Raw graphs without a baseline
  are what we already have via SSH.
- **An agent the team wants gone** because it is heavy, crashes, or needs babysitting.

## 5. Constraints

- **Heterogeneous fleet.** Process managers vary per server and per project; so do
  distributions and kernel versions. Nothing may assume a single layout.
- **cgroup v1 and v2 both exist.** Older distributions (CentOS 7, Ubuntu 18.04) are
  on v1 with a different path layout and different file names. Both must work.
- **Mixed SSH authentication.** Some servers accept passwords; on others password
  login is disabled and only a public key works. Server onboarding must support both.
- **Agent needs privilege.** Reading `/var/log/auth.log`, enumerating all processes,
  and reading other users' `authorized_keys` requires root or specific capabilities.
  This is unavoidable and must be handled deliberately.
- **No paid third-party components.** Self-hosted only.
- **Production servers are live.** No collection method may risk stalling a server
  (no unbounded log reads, no blocking shell-outs without timeouts).

---

## 6. Approaches considered

### A — Assemble existing open-source tools, build only the dashboard

Install Wazuh (host intrusion detection) and Prometheus exporters or Netdata
(metrics) on each server, run their server-side components centrally, and write only
an aggregation backend plus our own frontend.

*Trade-off:* fastest route to trustworthy detection, with thousands of maintained
rules that track real attacker techniques. But it means operating four or five
server-side services, Wazuh's central stack is memory-hungry (it runs an
Elasticsearch-class indexer), and the data model is theirs — per-project grouping
across pm2/supervisor/Docker stays awkward because no collector was built for it.

### B — Build our own agent and our own central stack *(chosen)*

One agent we write, one backend, one database, one frontend. We collect cgroup
metrics, tail logs, watch accounts and persistence locations, inventory exposure, and
write the detection rules ourselves.

*Trade-off:* full control, one coherent data model, exactly the project-centric view
we want, a single small binary to install, and one system to operate. The cost is
that we are writing intrusion detection from zero — the rule set starts empty and
"what does an attack look like" is a body of knowledge we rebuild by hand. Detection
breadth will lag a mature tool for a long time, and the failure mode is silent: it
looks fine right up until it misses something.

### C — Our own agent for inventory and metrics, a proven agent for intrusion detection

Two agents per server: ours for discovery, cgroup metrics and project mapping;
Wazuh or Falco for brute force, account changes, file integrity and rootkit checks.
Our backend merges both streams.

*Trade-off:* we own the differentiated part and inherit maintained detection rules
for free, at the cost of two agents to install and keep updated and a second data
format to learn.

### Decision

**Approach B, chosen by the user.** C was recommended on the grounds that
hand-rolled detection rules are the risky part; the user chose B for full control and
a single stack. The main risk this accepts — narrower detection coverage than a
mature tool — is mitigated by two deliberate choices in this design:

1. Detection is written as **data-driven rules**, not hardcoded logic, so coverage can
   grow without touching the engine (§10).
2. Phase 2 prioritises the **specific, well-understood attack chain** we actually
   face over broad coverage. Ten rules that catch the real thing beat two hundred
   generic ones.

---

## 7. Architecture

Three components.

```
   ┌─────────────────────────────────────────────────────────────┐
   │ MONITORED SERVER (one per server in the fleet)              │
   │                                                             │
   │   agent (single static binary, root or capabilities)        │
   │     ├─ discovery   : what projects exist here               │
   │     ├─ metrics     : cgroup + host resource sampling        │
   │     ├─ network     : listening sockets, outbound conns      │
   │     ├─ accounts    : users, sudoers, SSH keys, sessions     │
   │     ├─ persistence : cron, systemd units, profiles, modules │
   │     ├─ files       : integrity hashes, suspicious paths     │
   │     ├─ logs        : auth log + web access log tailing      │
   │     └─ shipper     : batch, compress, retry, local buffer   │
   └───────────────────────────┬─────────────────────────────────┘
                               │  HTTPS, outbound only, mTLS
                               ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ CENTRAL APP (on its own hardened server)                    │
   │                                                             │
   │   ingest API ──► TimescaleDB (metrics, events, state)       │
   │                        │                                    │
   │   detection worker ◄───┘   rules + baselines → incidents    │
   │        │                                                    │
   │        ├─► notifier (Telegram / email / webhook)            │
   │        └─► query API ──► frontend dashboard (React)         │
   │   Redis: job queue, alert dedup, cooldowns, cache           │
   └─────────────────────────────────────────────────────────────┘
```

### Why this shape

**The agent connects outbound; the central app never connects in.** This is the most
important security property in the design. Monitored servers expose no new port, need
no inbound firewall rule, and hold no credential that reaches another server. If the
central app is compromised, the attacker gets our telemetry — not root on the fleet.
This directly answers the anti-goal in §4.

**The agent is a single static binary with no runtime dependency.** Production servers
must not be made to install a Python or Node runtime, and must not have their
existing dependencies disturbed.

**One database.** Metrics, events, inventory and incidents live in one PostgreSQL
instance with the TimescaleDB extension. Relational state and time-series in one place
means one backup, one connection pool, and joins between "this CPU spike" and "this
project on this server" come free. Splitting into Prometheus + Postgres + a log store
buys scale we do not need at our size and costs operational complexity we would feel
every day.

---

## 8. Technology choices

These are the author's calls, made because the user asked for a recommendation rather
than having existing preferences to follow. Each is reversible; the reasoning is given
so it can be overridden knowingly.

| Layer | Choice | Why |
|---|---|---|
| Agent | **Go** | Single static binary, cross-compiles, no runtime on the host, ~20 MB RSS, mature libraries for `/proc`, cgroups, file watching and (later) eBPF. Rust would also serve; Go is faster to write and easier to hire for. A Python or Node agent is rejected outright: it needs a runtime on every production server. |
| Backend | **Go** | Chosen by the user. One language across agent and backend, shared type definitions between them, one toolchain and one deployment story — which matters a great deal when one person is building all three components. The analysis work (baselines, scoring, correlation) is more verbose in Go than in Python but entirely tractable; `gonum` covers the statistics required. |
| Database | **PostgreSQL + TimescaleDB** | Hypertables for metrics, continuous aggregates for rollups, retention policies to drop raw data automatically, and ordinary SQL tables for everything else. One system. |
| Cache / queue | **Redis** | Detection job queue, alert deduplication and cooldown state, session cache. |
| Agent ↔ backend | **HTTPS + gzipped JSON, batched** | Debuggable with `curl`, trivial to version. gRPC/protobuf is a later optimisation if bandwidth becomes real. |
| Frontend | **React + TypeScript + Vite** | Conventional, well-staffed, good charting ecosystem. |
| UI kit | **Tailwind + shadcn/ui** | Dense data-heavy screens without building primitives. |
| Charts | **uPlot** for dense time series, **Recharts** for everything else | uPlot handles thousands of points without stalling the browser; Recharts is pleasanter for simple bars and donuts. |
| Live updates | **SSE** for incident push | One-directional, survives proxies better than WebSocket, far simpler. Charts poll. |
| Central deployment | **Docker Compose** behind Caddy (automatic TLS) | Small enough to not need Kubernetes. |

---

## 9. What the agent collects

This is the substance of the system. Each group lists what is read, at what cadence,
and what it is for. Collection cadence is per-group and configurable from the central
app, because on a 60-server fleet the cheap checks should be frequent and the
expensive ones should not.

### 9.1 Discovery — "what projects exist on this server?" (every 10 min)

The key insight that makes a heterogeneous fleet tractable: **we do not model process
managers, we model cgroups.** Every manager — systemd, Docker, pm2, supervisor —
places its processes in a cgroup. Resource accounting therefore comes from one
mechanism regardless of who started the process. The manager only matters for
*naming* the project.

Discovery enumerates, with a timeout on every external call:

- **systemd** — `systemctl list-units --type=service --all`, then each unit's
  `ControlGroup` property.
- **Docker** — the Docker socket API (`/containers/json`), giving container name,
  image, labels, ports, and cgroup path. Compose project labels give us the stack name.
- **pm2** — `pm2 jlist` executed as each user that has a pm2 daemon running.
- **supervisor** — `supervisorctl status`, or its XML-RPC interface where configured.
- **Fallback** — long-running processes claimed by none of the above, grouped by
  executable path and owning user.

The output is a **project map**:

```
project → { name, manager, cgroup paths, PIDs, listening ports,
            log file paths, working directory, owning user, image/version }
```

Two consequences worth stating. First, a new project appears in the dashboard on its
own, with no human step. Second — and this is a security feature, not a convenience —
**anything discovery cannot attribute to a known project is itself a signal.** An
unexplained long-running process consuming CPU is the exact shape of a miner.

Log file paths are resolved by inspecting each project's open file descriptors in
`/proc/<pid>/fd` and, for nginx and Apache, by parsing their configuration for
`access_log` directives. Where resolution fails, the project is flagged in the UI as
"logs not found" so an admin can map it by hand once.

### 9.2 Resource metrics (every 15 s)

- **Per project, from cgroups:** `memory.current`, `memory.peak`, `memory.swap.current`,
  `cpu.stat` (`usage_usec`, throttling), `io.stat`, `pids.current`. Under cgroup v1,
  the equivalent `memory.usage_in_bytes` / `cpuacct.usage` / `blkio` files.
- **Per process:** RSS, CPU time, thread count, open FD count, start time, full
  command line, executable path, working directory, owning UID.
- **Host:** load average, total/available memory, swap usage, disk usage and inode
  usage per mount, network bytes and packets per interface, open connection count,
  CPU temperature where exposed.

Raw samples are retained 14 days; one-minute and one-hour rollups are kept 13 months
via continuous aggregates. Exact retention is configurable.

### 9.3 Network and exposure (listening sockets every 60 s; connections every 30 s)

- **Listening sockets** — port, protocol, bind address, owning process and project.
  A bind to `0.0.0.0` or `::` is treated as internet-exposed and recorded in an
  **exposure inventory**: the single most useful screen for answering "how could they
  get in?"
- **Established outbound connections** — remote IP, port, owning process. Enriched
  centrally with ASN, country and threat-list reputation.
- **Inbound connection sources** — counts per source IP, from conntrack where
  available and from log analysis otherwise. This feeds the "which IPs are requesting"
  view.
- **Firewall state** — the active nftables/iptables/ufw rule set, hashed. Changes are
  reported; an attacker opening a port is a strong signal.

### 9.4 Authentication and accounts (log tailing continuous; file watch via inotify)

This group covers the brute-force and rogue-account scenarios named in §1 directly.

- **Auth log tailing** — `/var/log/auth.log`, `/var/log/secure`, or journald depending
  on distribution. Extracted: failed password attempts (source IP, username, time),
  invalid-user attempts, accepted logins (user, source IP, method — key or password),
  `sudo` invocations and failures, `su` usage.
- **Account file watching** — `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `/etc/sudoers`, `/etc/sudoers.d/*`, PAM configuration. Reported as a semantic diff,
  not a raw diff, so the event reads *"user `backup2` created with UID 0"* rather
  than a patch.
- **SSH key watching** — every user's `~/.ssh/authorized_keys`, plus
  `AuthorizedKeysFile` as configured. **A newly added public key is the single most
  common persistence mechanism** and must be reported immediately.
- **Sessions** — currently logged-in users (utmp), and recent login history.

### 9.5 Persistence mechanisms (every 5 min + inotify where possible)

Where an intruder makes sure their miner survives a reboot. Each location is hashed
and diffed:

- User crontabs, `/etc/crontab`, `/etc/cron.{d,daily,hourly,weekly,monthly}`, `at` jobs
- New or modified systemd unit files and timers, including **user-level units** in
  `~/.config/systemd/user` (frequently overlooked)
- `/etc/rc.local` and SysV init scripts
- Shell startup files — `~/.bashrc`, `~/.profile`, `/etc/profile.d/*`
- `/etc/ld.so.preload` and any `LD_PRELOAD` in service environments — a rootkit hallmark
- Loaded kernel modules

### 9.6 File integrity and suspicious files (full baseline nightly; inotify on hot paths)

- Hash and watch critical binaries and configuration: `/bin`, `/sbin`, `/usr/bin`,
  `/usr/sbin`, `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/fstab`.
- **Executables in world-writable directories** — `/tmp`, `/var/tmp`, `/dev/shm`,
  `/run`. This is the classic miner drop location and a high-signal check.
- New SUID/SGID binaries anywhere on disk.
- **Processes whose executable has been deleted** (`/proc/<pid>/exe` resolving to a
  deleted path). Legitimate software almost never does this; malware routinely does.
  One of the strongest single indicators available.
- Processes whose name mimics a kernel thread (e.g. `[kworker/0:1]`) but has a real
  executable, or whose `cmdline` and `exe` disagree.
- Sudden shrinkage or truncation of files in `/var/log` — log wiping.

### 9.7 Container-specific checks (every 5 min)

- **Docker API exposed on 2375/2376** — in practice the most common entry point for
  this entire class of attack. Treated as critical on sight.
- Containers running `--privileged`, with `--network=host`, or with
  `/var/run/docker.sock` bind-mounted (each permits host escape).
- Images pulled or containers started outside our deployment process.
- Containers running as root where the image declares a non-root user.

### 9.8 Exposed-service posture checks (hourly)

The "how did they get in" half of the product. Mostly cheap local probes.

- `sshd_config` effective settings — `PasswordAuthentication`, `PermitRootLogin`,
  `Port`, `AllowUsers`.
- Services bound to all interfaces that usually should not be: Redis (6379),
  PostgreSQL (5432), MySQL (3306), MongoDB (27017), Elasticsearch (9200),
  Memcached (11211), Docker (2375/2376), Kubelet (10250).
- Authentication actually enabled on those services, verified by a local probe —
  e.g. does Redis answer `PING` without `AUTH`.
- Count of pending security updates (`apt list --upgradable`, `dnf updateinfo`).
- Exposed `.git` directories or world-writable files inside detected web roots.

### 9.9 Application and web logs (continuous tail, aggregated locally)

For the "what kind of IPs are requesting" view. The agent aggregates locally and ships
summaries plus flagged lines — never the whole log stream, which would be the single
biggest source of bandwidth and storage cost.

- Per project per minute: request count, status-code distribution, byte volume,
  p95 latency where logged.
- Top source IPs, top paths, top user agents.
- Flagged patterns: many 404s from one source (scanning), probes for `/.env`,
  `/.git/config`, `/wp-admin`, `/phpmyadmin`, path traversal, SQL injection
  signatures, and unusual methods.
- Application log tailing for `ERROR`/`FATAL` rates per project, from paths found in
  discovery.

### 9.10 Agent self-integrity (continuous)

An attacker who finds the agent will try to kill it, so the agent's own health is
monitored as a security signal, not just an operational one.

- Heartbeat every 30 s. **The central app alerts on silence** — a server that stops
  reporting is treated as a potential compromise, at high severity, not as a glitch.
- The agent verifies its own binary and configuration hashes and reports mismatches.
- Local disk buffer so data survives network outages and is sent on reconnect.

---

## 10. Detection: turning collection into judgement

Two tiers, deliberately separated because they fail differently.

### Tier 1 — deterministic rules

Immediate, high-confidence, no learning period. These fire from the moment a server is
added. They are defined as data (YAML), evaluated by a generic engine, so new rules
need no code change. The starting set, aimed at the attack chain in §1:

| Rule | Severity |
|---|---|
| New account created with UID 0, or added to `sudo`/`wheel`/`admin` | Critical |
| New entry in any `authorized_keys` | Critical |
| `/etc/ld.so.preload` created or modified | Critical |
| Docker API listening on a non-loopback address | Critical |
| Running process whose executable has been deleted | Critical |
| Agent silent for more than 3 minutes | High |
| Executable file created or executed in `/tmp`, `/var/tmp`, `/dev/shm` | High |
| More than N failed SSH authentications from one IP within M minutes | High |
| Successful SSH login immediately following a burst of failures from the same IP | Critical |
| Outbound connection to a known mining-pool port or a flagged destination | High |
| New or modified cron entry, systemd unit, or shell profile | Medium |
| New SUID binary | High |
| `sshd_config` changed, or password login / root login newly enabled | High |
| Log files in `/var/log` truncated or shrinking | High |
| Listening port newly exposed to `0.0.0.0` | Medium |
| New kernel module loaded | Medium |
| Pending security updates above a threshold, or unauthenticated database exposed | Low |

### Tier 2 — baselines and anomaly detection

Needs a learning period (7 days by default; the UI shows a server as "learning" and
suppresses Tier 2 alerts until it completes). These answer "is this normal *for this
server*?", which is the question raw graphs cannot.

- Per-project CPU and memory normal band, by hour of week — so a nightly batch job is
  not flagged every night, and a daytime spike in a usually-idle project is.
- A listening port, outbound destination ASN or country never seen on this host before.
- A process executable never seen on this host before.
- A successful login from an IP, ASN or country never seen for that account.
- Request-rate and error-rate deviation per project.

### Correlation into incidents

Individual signals are not alerts. The detection worker groups related signals on the
same server within a time window into a single **incident** with a timeline. The
textbook compromise — *new user → new SSH key → new cron entry → CPU spike → outbound
to a pool* — becomes one critical incident telling a story, not five separate pages.
This is what makes the alert readable, and it is the direct answer to the "alert nobody
reads" anti-goal.

Each incident carries: a plain-language summary, severity, the evidence that produced
it, the affected server and project, a timeline, and a suggested next action.

### Noise control

Non-negotiable, because noise is the project's main failure mode:

- Deduplication and per-rule cooldowns in Redis.
- Per-server and per-rule suppression, with an expiry date so suppressions do not
  become permanent blind spots.
- Acknowledge / resolve workflow with the acting admin recorded.
- Learning mode on newly added servers.
- An explicit allowlist mechanism: an admin can mark an observed state as expected
  (e.g. "this port is meant to be open"), which converts a recurring alert into a
  recorded, reviewable decision.

---

## 11. Server onboarding and credential handling

Two supported paths. The first is the default because it involves no credential
handling at all.

**Path 1 — install token (recommended).** The admin adds a server in the UI and gets a
one-line command containing a short-lived enrollment token:

```
curl -sSL https://central.example/install.sh | sudo bash -s -- --token=<ONE_TIME_TOKEN>
```

The installer verifies the binary signature, installs the agent as a systemd unit,
enrols it, receives a per-host client certificate, and discards the token. The central
app never learns an SSH credential.

**Path 2 — assisted install over SSH.** For convenience and bulk onboarding, the admin
pastes IP plus either a password or a private key. The backend connects **once**,
runs the same installer, confirms enrolment, and **discards the credential without
persisting it**. Both authentication methods are supported, since some servers have
password login disabled entirely. Credentials exist only in memory for the duration of
that one operation.

**Standing credentials are never stored.** The §4 anti-goal rules this out: a database
of root credentials for the whole fleet would make the central app a more attractive
target than any server it protects. If a future requirement forces stored credentials,
it needs its own design review.

**Agent privilege.** The agent runs as root by default because auth logs, other users'
SSH keys and full process enumeration require it. Where the distribution supports it,
the installer instead grants a dedicated system user the narrower capabilities needed
(`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`) plus group membership for log reading. The
agent itself needs no outbound network privilege beyond a single TLS client connection.

**Transport security.** Mutual TLS with a per-host client certificate issued at
enrolment, rotated automatically. A host certificate authenticates exactly one server
and authorises submitting data for that server only — it grants no read access to
fleet data and no ability to impersonate another host.

---

## 12. Frontend

Screens, in the order an admin uses them.

1. **Fleet overview.** Every server as a card or row: health, open incidents by
   severity, CPU/memory/disk at a glance, agent last-seen. Sortable by worst-first.
   Answers "is anything wrong anywhere?" without scrolling.
2. **Server detail**, with tabs:
   - *Overview* — host resources over time, open incidents, recent changes.
   - *Projects* — every discovered project with its memory and CPU share, manager,
     ports, status. This is the per-project view on shared servers.
   - *Network and exposure* — listening ports with exposure flagged, current outbound
     connections, top inbound source IPs.
   - *Access and accounts* — users, who can log in and how, SSH keys, recent logins,
     failed-attempt sources, sudo activity.
   - *Logs* — tailed auth and application logs, filterable, with flagged lines marked.
   - *Changes* — a chronological audit of everything that changed on this host:
     accounts, cron, units, files, firewall, ports. Often the fastest way to understand
     an incident.
3. **Incidents** — fleet-wide list, then incident detail: plain-language summary,
   evidence, timeline, affected project, suggested action, acknowledge/resolve.
4. **Projects** — fleet-wide, for projects spanning several servers.
5. **Settings** — servers and enrolment, notification channels and routing, rule
   configuration and thresholds, suppressions, retention, admin accounts.

**Notifications.** A single Telegram group is the channel. The bot token lives in the
central app's `.env`; the target chat ID is entered in the UI. Alerts are routed by
severity, with quiet hours for anything below High; Critical goes out immediately
regardless. Generic webhook and email are kept as a later addition, not built in the
committed phases.

Because host-compromise detail will pass through a third-party service, alert messages
carry the server name, the project, the rule and the severity, but **not** log excerpts,
command lines or IP reputation detail. The message links to the incident in the
dashboard, where the evidence lives behind a login. This keeps the convenience of
Telegram without publishing our internals into a chat history.

**Acknowledgement is out-of-band, by design.** Alerts that ask the admin to confirm an
expected change (§10, §16.1) carry inline buttons in the Telegram message, and the same
action exists in the dashboard. **Confirmation is never possible on the monitored server
itself** — the agent has no command, no local file and no socket that marks a change as
expected. The reason is direct: an attacker who has already obtained root on a server
would otherwise answer "yes, that was me" to the alert announcing their own intrusion,
and the system would record their SSH key as legitimate. The confirmation must happen
somewhere the attacker does not control.

This places a requirement on the Telegram integration: the bot verifies the Telegram
user ID behind every button press against a list of IDs mapped to admin accounts, and
ignores presses from anyone else in the group. Without that check, group membership
alone would be enough to approve an intrusion. Every acknowledgement is written to the
audit log with the admin identity, the channel it came from and the timestamp.

---

## 13. Build order

Each phase is independently useful and ends with something running.

**Committed scope: Phases 0, 1 and 2.** All three components — agent, backend and
frontend — are being built by one person. Phases 0–2 deliver the entire reason for the
project: fleet visibility, per-project resource attribution, and detection of the
brute-force → rogue-account → miner chain, with alerts in Telegram. Phases 3–5 are
designed here so that nothing in the earlier phases blocks them, but they are explicitly
*later work* and should not be started until Phase 2 has run against the real fleet for
a few weeks. Planning the whole six phases as one effort would be dishonest about the
timeline.

**Phase 0 — plumbing.** Agent skeleton, enrolment, mTLS, heartbeat, ingest API,
database schema, fleet list showing servers online. No collection yet. This proves the
hardest and least visible part first; everything later is additive.

**Phase 1 — visibility.** Discovery across all four managers, cgroup metrics (v1 and
v2), host metrics, per-project view, server detail charts. The system becomes useful
for operations even with zero detection.

**Phase 2 — the actual security value.** Auth log tailing, account and SSH key
watching, persistence watching, suspicious-process and suspicious-file checks, the
Tier 1 rule engine, incidents, notifications. **This is the phase that addresses why
we are building this.** If the project stalled after Phase 2, it would already have
done its job.

**Phase 3 — posture and traffic.** Exposure inventory, service posture checks,
container checks, web log aggregation and the source-IP views.

**Phase 4 — judgement.** Baselines, Tier 2 anomaly detection, correlation into
incidents with timelines, noise controls.

**Phase 5 — operability.** Agent auto-update, admin roles, audit log of admin actions,
retention tuning, backup and restore.

---

## 14. Risks

| Risk | Mitigation |
|---|---|
| **Alert fatigue** — the likeliest cause of failure | Correlation into incidents, learning mode, cooldowns, expiring suppressions, severity routing. Tune aggressively in the first month. |
| **Detection gaps from hand-written rules** — the accepted cost of Approach B | Data-driven rules so coverage grows cheaply; Phase 2 targets the known attack chain first; periodically compare our rule set against Wazuh's public rules as a free checklist. |
| **Agent resource footprint** | Hard budget (§2), measured in CI; local aggregation instead of raw log shipping; configurable cadence per group. |
| **Agent breaks on an unusual distribution** | Every external call has a timeout and a fallback; a collector that fails degrades to reporting its own failure, never crashes the agent. Test matrix across the distributions we actually run. |
| **Central app compromise** | Outbound-only agents, no stored SSH credentials, per-host certificates scoped to submission only, central app on its own hardened host. |
| **Attacker disables the agent** | Agent silence is a high-severity alert, not an operational warning. |
| **Storage growth** | Aggregate on the agent, roll up and expire centrally via Timescale policies. |

---

## 15. Left to the builder

- Database schema details, table and index layout, and hypertable partitioning intervals.
- Exact API shapes, endpoint naming, and payload versioning scheme.
- Repository layout, module boundaries, and whether agent and backend share one repo.
- Testing strategy, including how distribution variety is covered in CI.
- Specific library choices within the chosen languages.
- Concrete default thresholds for every Tier 1 rule (N failures in M minutes, etc.);
  the design fixes the rules, not the numbers.
- Visual design, exact chart choices, and layout within the screens described in §12.
- Mining-pool and threat-intelligence data sources, and how they are refreshed.

---

## 16. Decisions and remaining questions

### Decided by the user

- **Backend language: Go.** One language across agent and backend. §8 updated.
- **Built by one person** — agent, backend and frontend. Committed scope is therefore
  Phases 0–2; see §13.
- **Fleet size and composition unknown.** No count of servers or projects, and no fixed
  list of distributions. Consequences, which are design constraints rather than
  guesses: every collector must support **both cgroup v1 and v2**, **both `auth.log`
  file tailing and journald**, and **iptables, nftables and ufw**, detected at runtime
  with a clean degradation path when a mechanism is absent. On the central side, build
  for a small fleet but choose nothing that blocks growth: TimescaleDB hypertables and
  batched ingest from the start, and a fleet overview that paginates and summarises
  rather than rendering one live card per server.
- **Authentication and users.** Username and password login. Anyone may register, but a
  new account is inactive and cannot sign in until the admin activates it; an attempt to
  sign in before activation is refused without revealing whether the account exists.
  Two roles: **admin** (manage servers, users, rules, suppressions, notification
  settings) and **user** (read-only access to all fleet analytics and incidents, and
  acknowledge incidents). Author's call, open to correction: activated users see the
  whole fleet rather than a subset, since per-server scoping adds UI and schema work
  with no current need — but the scopes remain in the schema from the first migration
  (§17.5) so it can be added later without rework.
- **Alerting: one Telegram group.** Bot token in the central app's `.env`, chat ID
  entered in the UI. §12 updated, including the deliberate decision to keep evidence out
  of the chat message and behind the dashboard login.
- **Report-only.** The system never kills a process, locks an account or blocks an IP.

- **Changes are made manually, and acknowledgement must be out-of-band.** There is no
  deployment pipeline to hook, so the four rules that ordinary work can trigger — a new
  `authorized_keys` entry, a new or modified systemd unit, a new cron entry, a modified
  `sshd_config` — ship at **High** with a confirmation flow: the alert asks whether the
  change was expected, and confirming it records the new state as expected so the same
  key or unit never alerts again.

  **The confirmation is only ever possible through the Telegram bot or the dashboard,
  never on the server.** This was the user's requirement and it is the correct one: an
  attacker holding root on a compromised server would otherwise confirm the alert
  announcing their own SSH key and have it recorded as legitimate. The agent therefore
  exposes no local mechanism — no CLI subcommand, no file, no socket — for marking a
  change as expected. Button presses in Telegram are authorised against a list of
  Telegram user IDs mapped to admin accounts, so group membership alone cannot approve
  an intrusion. See §12.

- **Network path confirmed.** Every server can make outbound HTTPS requests, and a
  public domain will be purchased for the central app. So: public DNS name, automatic
  TLS via Caddy, agents connecting outbound on 443 with mutual TLS, the one-line
  enrolment command, and the dashboard protected by login with an optional IP allowlist.
  No internal certificate authority and no VPN required. Phase 0 proceeds as written.

### Remaining questions

None. This design is complete pending approval.

## 17. Calls made during review

A reviewer read this document as the builder who would plan from it. These are points
it raised that did not need the user's judgement, settled here by the author. Each is
open to being overridden.

1. **Telemetry is redacted on the host, in Phase 1, not later.** Command lines,
   environment values and log lines are pattern-scrubbed before they leave the server:
   credentials in connection URLs, `--password=` style flags, bearer tokens, private
   keys, and web-log query strings. Service environment contents are never shipped at
   all — only variable names and a hash, which is enough to detect an injected
   `LD_PRELOAD` without exporting secrets. *Reason:* §7's central security argument —
   "if central is compromised, the attacker gets telemetry, not root" — collapses if the
   telemetry is a searchable corpus of production credentials. Assumes no external
   compliance regime applies to this data; if one does (customer PII in web logs, for
   instance), the §12 Logs tab becomes a permissioned feature.
2. **Active service probing is off by default and narrow when enabled.** §9.8 ships as
   configuration-file inspection only. The probes that verify authentication is really
   enabled (Redis `PING` without `AUTH`, and similar) are opt-in per server, run at most
   hourly, connect over loopback only, make exactly one attempt per service and never
   retry. *Reason:* repeated unauthenticated connections to a live service can trip
   fail2ban, consume connection slots, pollute application logs and set off existing
   alerting. That is a behaviour change on production, which §5 forbids by default.
3. **Docker socket read access is accepted as a known trade.** Read access to the socket
   is effectively root-equivalent. It is accepted because the agent already holds
   root-class privilege for auth logs and process enumeration, so refusing it would cost
   container names, images and port mappings while reducing blast radius hardly at all.
   Where the socket is unavailable, Docker discovery falls back to cgroup paths plus
   container label files, with reduced detail.
4. **Certificate and release lifecycle.** Host certificates live 90 days and rotate at
   60. An agent whose certificate expired while the server was offline re-enrols
   automatically using a long-lived enrolment secret written at install time to a
   root-only file, so a server returning from a long outage does not generate a
   self-inflicted Critical "agent silent" incident. Decommissioning a server in the UI
   revokes its certificate. Release binaries are signed by a key held only in the
   release pipeline, and the installer pins the corresponding public key.
5. **Phase 0 authentication.** Username and password as the user specified, with
   server-side sessions and argon2id hashing, two roles (admin, user), and
   admin activation required before a new account can sign in. Rate limiting on the
   login endpoint. **TOTP is deliberately deferred to Phase 5**, not dropped: it was in
   an earlier draft of this document as the author's call, and the user specified
   username and password, which takes precedence. The schema carries per-server and
   per-project scopes from the first migration, so finer roles can be introduced later
   without retrofitting authorization onto the query API. OIDC is also a Phase 5 option.
6. **Rules that routine operations can trigger ship softer until there is an expected
   state to compare against.** Until the question in §16.1 is answered, these four rules
   ship at **High** with a 7-day tuning window rather than Critical: new `authorized_keys`
   entry, new or modified systemd unit, new cron entry, `sshd_config` modified. They are
   promoted to Critical once the system can tell an expected change from an unexpected
   one. *Reason:* shipping them at Critical on day one, against a fleet where deploys
   legitimately do these things, produces exactly the wall of false alarms that §4
   names as a failure condition.
