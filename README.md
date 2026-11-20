# FleetGuard

Self-hosted security monitoring for a fleet of Linux servers. A small agent on
each server reports to a central app; the app shows which servers are up.

FleetGuard is **report-only**. Nothing in it acts on a monitored server, and the
agent has no subcommand, flag, file or socket that acknowledges or silences
anything: an attacker with root on a host must not be able to confirm the alert
announcing their own intrusion.

## Phase 0: what it does, and does not

Does:

- An admin signs in to the dashboard, adds a server and gets a one-line install
  command containing a single-use token (valid for one hour).
- The installer enrols the agent over mutual TLS against a CA the central app
  runs itself. The agent keeps a short-lived certificate and renews it.
- The agent sends a heartbeat every 30 seconds. The fleet list shows each server
  online (heartbeat within 180 s) or offline, with its agent version.
- Users register and wait for an admin to activate them.

Does not (Phases 1 and 2): collect anything from the host, detect anything,
raise or route alerts, or keep history beyond the last heartbeat. A server that
is "online" means only that its agent is alive.

## Run it

Needs Docker with the compose plugin, Go 1.26 (to build the agent downloads) and
Node (to build the dashboard). Two DNS names pointing at the host, one for the
dashboard and one for agents; **the only inbound port is 443**.

```sh
cp .env.example .env && chmod 600 .env     # then edit it; see the comments inside
make up                                    # builds web, agent downloads, images; starts the stack
```

Set `FG_BOOTSTRAP_USER` / `FG_BOOTSTRAP_PASSWORD` for the first start to create
the first administrator, then remove the password from `.env`.

Open the dashboard origin, sign in, **Add server**, and run the command it
prints as root on the new host:

```sh
curl -sSL https://fleet.example.com/install.sh | sudo bash -s -- --token=<token> --server-url=https://agents.example.com
```

The host appears in the fleet list as online within a minute. Running the
installer again on an enrolled host refreshes the binary, unit and `ca.crt` and
leaves the identity alone (the agent answers "already enrolled" and spends no
token). `make down` stops the stack; volumes persist.

## Environment

| Variable | If it is wrong |
|---|---|
| `FG_BASE_URL` | **Must exactly equal the browser's `Origin`**: scheme, host and any non-default port. Otherwise the backend's Origin check refuses every state-changing request (login included) with 403. Also the origin the install command is built from. |
| `FG_AGENT_URL` | Must be a different hostname from `FG_BASE_URL`. The server refuses to start if equal. Agents enrolled against the dashboard origin enrol fine and then fail every request. |
| `FG_PROXY_SECRET` | Shared by Caddy and the backend. Mismatch: every request is 401. Without it the backend would be open to any local process. |
| `FG_DB_PASSWORD` | Required, no default. Goes into a connection URL: letters and digits only. |
| `FG_BOOTSTRAP_USER`, `FG_BOOTSTRAP_PASSWORD` | Optional; both or neither. |

## How it is deployed

```
browser ──443──► Caddy  dashboard host: ACME certificate; serves web/dist, /install.sh, /ca.crt, /downloads/*;
                         proxies /api/*  ──► 127.0.0.1:8080  (the backend)
agent ───443──► Caddy  agent host: the fleet-CA certificate; proxies /v1/*  ──► 127.0.0.1:8080
```

- **Two hostnames, two issuers.** Certificate selection is per hostname. The
  dashboard needs a browser-trusted ACME certificate. The agent host presents the
  certificate the server binary issues from the fleet CA
  (`agent-server.crt`/`.key` in its state directory), because agents pin that CA
  and have no fallback to system roots.
- **`client_auth { mode verify_if_given }` on the agent host.** A first-time agent
  has no certificate, and one whose certificate expired while the host was off
  must re-enrol without one. A presented certificate is verified against the
  fleet CA; the backend then enforces per route (heartbeat needs a verified
  certificate; enrol and re-enrol are authenticated by token and enrolment secret).
- **Three headers on every proxied request**, `X-Agent-Cert` (the handshake
  certificate), `X-Proxy-Auth` (`FG_PROXY_SECRET`) and `X-Real-IP` (the login rate
  limiter's key; without it all browsers share one bucket). `header_up` replaces
  client-supplied values, which the end-to-end test proves.
- **Loopback backend.** Caddy owns the container network namespace and the server
  joins it, so the backend is on Caddy's `127.0.0.1` and unreachable from
  anywhere else. Caddy owns the namespace (not the server) so that restarting the
  server does not strand Caddy.
- **Caddy reads `agent-server.key`**, which the server writes mode 0600 in a 0700
  directory. Both images run as uid 10001 and share one state volume. The cost:
  Caddy can also read `ca.key` in that volume. Only `/ca.crt` is mapped to a
  file, but a Caddy compromise would expose the CA key. Splitting the CA key
  into a separate volume needs a server change and is future work.
- **The agent's root of trust is one fetch.** `install.sh` fetches `ca.crt` from
  the dashboard host over publicly trusted TLS into the state directory
  (root, 0600) before enrolling. The agent treats a missing `ca.crt` as a hard
  error. The token reaches the agent in its environment (`FG_ENROL_TOKEN`),
  never on its command line, and is not written to disk. (The pasted command
  itself carries it for the length of the install; it is single-use and expires
  in an hour.)

### Restart cadence: the agent certificate

The server issues the agent-host certificate **only at process start**: one year
validity, reissued at start when fewer than 60 days remain. Caddy loads it only
at (re)load. A server process left running past about ten months serves an
expired certificate and every agent is locked out. **Restart the server at least
every 6 months** (or monthly, to be safe) and, after any restart whose log says
"issued agent server certificate", reload Caddy:

```sh
docker compose --env-file .env -f deploy/docker-compose.yml restart server
docker compose --env-file .env -f deploy/docker-compose.yml exec caddy caddy reload --config /etc/caddy/Caddyfile
```

Do not `restart caddy`: the server shares its network namespace and must be
restarted with it. Also reload after changing `FG_AGENT_URL`.

### The agent service

`deploy/fleetguard-agent.service` uses `Restart=always`: the agent exits at once,
with no retry, on a transient local-state error (an EIO, a `/var/lib` not yet
mounted), and any weaker policy turns a mount race into a permanent blind spot.

## Toolchain

Go **1.26.0** is the floor (`go` directive in `go.mod`). `goose` and
`testcontainers-go` both require it, so a CI image pinned to `GOTOOLCHAIN=local`
with Go 1.25 will not build.

## Tests

```sh
go test ./...                     # unit and store tests (testcontainers; needs Docker)
(cd web && npm test)
go test ./test/e2e/ -v            # the whole stack, a real agent in a container; a few minutes
```

The end-to-end test builds the real compose file with Caddy's `local_certs` in
place of ACME, maps both hostnames to Caddy, runs the **real installer** in a
container, and checks: enrolment and a green fleet list, that a client cannot
forge `X-Agent-Cert`/`X-Proxy-Auth`, and that the agent is back online after a
backend restart.

## Agent footprint

Budget: under 1% of one CPU core and under 50 MB RSS.

Measured over 10 minutes with the agent running in the end-to-end container
(Debian bookworm, linux/arm64, Docker Desktop, default 30 s poll, enrolled and
heartbeating), sampled each minute with `docker stats --no-stream` and from
`/proc/<pid>/status` and `/proc/<pid>/stat` inside the container:

| | Measured | Budget |
|---|---|---|
| CPU | 0.013% of one core (8 ticks of CPU in 613 s) | < 1% |
| RSS | 12.6 MB (peak, `VmHWM`, 12.7 MB); `docker stats` 8.0-8.3 MiB | < 50 MB |

Phase 0 only sends heartbeats, so this is a floor: Phases 1 and 2 add collection
and must be re-measured against the same budget.

## Deliberate deviation from the design: installer integrity

The design requires the installer to verify a **signed release against a pinned
public key**. Phase 0 has no release pipeline to hold a signing key, so the
installer verifies a **SHA-256 checksum served over the same TLS connection**.
That catches a corrupted download but **not a compromised central host**: whoever
controls the central host controls both the binary and its checksum. The trust
anchor in this phase is the TLS connection, not a signature.

**Outstanding, required in Phase 5 (auto-update):** signed releases and
signature verification against a pinned key, in the installer and the updater.
This is not done.
