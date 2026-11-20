# FleetGuard Phase 0 — Enrolment and Fleet List: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An admin can add a server in the dashboard, run one command on that server, and see the server appear and stay green in a fleet list — over mutual TLS, with no SSH credential ever stored.

**Architecture:** One Go module with two binaries. The agent holds a client certificate issued by the central app's own certificate authority and makes only outbound HTTPS requests. Caddy is the single public listener: it terminates public TLS for both hostnames and forwards the client certificate DER to the backend, which binds loopback only and re-verifies the chain itself. The agent hostname uses `verify_if_given` rather than `require_and_verify`, because an agent enrolling for the first time has no certificate yet and an agent whose certificate expired while offline must be able to re-enrol without one; the backend therefore enforces per route — heartbeat demands a verified certificate, enrolment and re-enrolment are authenticated by a single-use token and the enrolment secret respectively. Postgres with TimescaleDB is the only datastore.

**Tech Stack:** Go 1.25 (agent + backend, `net/http` with `ServeMux` method patterns, `pgx/v5`, `goose` migrations, `testcontainers-go`), PostgreSQL + TimescaleDB, React 18 + TypeScript + Vite + TanStack Query + Tailwind, Caddy, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-19-server-security-monitoring-design.md`

**Phase scope:** This plan implements **Phase 0 only** (spec §13). Collection (§9), detection (§10) and Telegram alerting (§12) are Phases 1 and 2 and get their own plans. Phase 0 ends with plumbing proven end to end and nothing collected.

## Global Constraints

Every task's requirements implicitly include these. Values are copied from the spec.

- **Report-only.** No code path may kill a process, modify an account, or change a firewall rule on a monitored server.
- **The agent makes outbound connections only.** It never listens on a port, never accepts a connection.
- **The agent exposes no local acknowledgement mechanism** — no CLI subcommand, no file, no socket that marks anything as expected. (Spec §12, §16.)
- **No SSH credentials are persisted.** Phase 0 implements token enrolment only; the assisted-SSH install path (spec §11, Path 2) is not in this phase.
- **Agent resource budget: under 1% of one CPU core and under 50 MB RSS in steady state.**
- **Host certificates live 90 days and rotate at 60.** An agent whose certificate expired while offline re-enrols automatically using the enrolment secret and does not require admin action.
- **The backend binds `127.0.0.1` only.** Caddy is the only process with a public listener.
- **Both `/v1/*` and `/api/*` require the proxy secret**, and the proxy supplies the client address. The reverse proxy sets `X-Proxy-Auth: $FG_PROXY_SECRET` and `X-Real-IP` (from the connection's remote host, which a client cannot influence) on every proxied request; the backend requires the secret on both trees and takes the client address from that header, falling back to `RemoteAddr` only when no valid secret is present. Two reasons. First, without a trusted client address every browser behind the proxy shares one rate-limit bucket, so ten failed logins would lock out the whole dashboard — and trusting a client-supplied `X-Forwarded-For` instead would let an attacker rotate the header to escape the limit entirely. Second, the admin API is the dashboard's entire perimeter: requiring the secret there too means an SSRF in anything else running on the central host cannot reach it, which loopback binding alone does not prevent.
- **Password hashing is capacity-limited.** Each login verification costs 64 MiB of argon2 memory, so concurrent verifications are capped by a semaphore and requests beyond the cap are refused rather than queued without bound. Rate limits alone do not bound this: a distributed set of sources, each inside its own per-IP limit, could otherwise exhaust the central host's memory with unauthenticated requests.
- **Two hostnames are mandatory, not a deployment preference.** TLS certificate selection is per hostname, and the two halves of this system need certificates from different authorities: the dashboard must present a browser-trusted ACME certificate, while the agent endpoint must present one issued by the fleet CA, because the agent pins that CA and has no system-roots fallback. One hostname cannot do both. So `FG_BASE_URL` is the dashboard origin — the UI, `/api/*`, `/install.sh` and `/ca.crt` — and `FG_AGENT_URL` is the agent origin, serving `/v1/*`. The install command must pass `--server-url=$FG_AGENT_URL`; pointing an agent at the dashboard origin produces an agent that cannot verify the server and fails every request after enrolment. `FG_AGENT_URL` is **required** and the binary refuses to start without it: a default derived from the base URL would silently produce exactly that broken agent across a whole fleet.
- **`/v1/*` requires the proxy secret.** Proof that an agent holds its private key happens in Caddy's TLS handshake, not in the backend — the backend only sees certificate bytes in a header, which prove nothing on their own. So the backend requires a shared secret header, `X-Proxy-Auth: $FG_PROXY_SECRET`, on every `/v1/*` request, set by Caddy and known only to Caddy and the backend. Loopback binding alone is **not** sufficient: any other local process, or an SSRF in the dashboard, could otherwise post a borrowed certificate to `127.0.0.1:8080` and be authenticated as that agent.
- **Enrolment tokens are single-use with a 1-hour TTL.**
- **One Go module**, `github.com/makhammatovb/fleetguard`, with shared wire types in `pkg/api` used by both binaries.
- **Secrets at rest are hashed, never stored in plaintext:** enrolment tokens, enrolment secrets, session tokens, passwords.
- **Go toolchain floor is 1.26.0**, set in `go.mod`. This was 1.25.4 in the plan's first draft, which described the dev machine rather than a product requirement; two dependencies this plan mandates — `github.com/pressly/goose/v3` v3.30.1 and `github.com/testcontainers/testcontainers-go` v0.45.0 — both declare `go 1.26.0`, so 1.25.4 is only reachable by downgrading them. Contributors on 1.25.4 still build, because `GOTOOLCHAIN=auto` fetches the required toolchain; a CI image pinned to `GOTOOLCHAIN=local` with Go 1.25 will not, so Task 12's README must state the 1.26.0 floor and why.
- Other toolchain present on the dev machine: Node 26.4.0, Docker 29.1.3.

## Review Focus

Input classes the spec implies that no task's happy path exercises. Each line's test is assigned to the task that owns the code.

1. **An enrolment token replayed, or used after its TTL** — a second enrolment with the same token must be refused and audited, not silently issue a second certificate. (Task 5)
2. **A certificate that expired while the server was offline** — the agent must re-enrol itself using the enrolment secret and resume, rather than going permanently silent and needing a human. (Task 6)
3. **A cloned VM or restored snapshot presenting an already-active server identity** — a changed boot ID on an existing identity must be flagged and audited, never silently accepted as the same host. (Task 7)
4. **Login against a non-existent username, a wrong password, and a registered-but-not-activated account** — all three must be indistinguishable to the caller, and an unactivated account must never receive a session. (Task 9)
5. **An oversized or flooding heartbeat from a compromised agent** — the request body must be capped and the per-server rate limited, so one host cannot fill the database. (Task 7)

---

### Task 1: Repository skeleton and shared wire types

**Files:**
- Create: `go.mod`, `.gitignore`, `Makefile`, `.golangci.yml`
- Create: `pkg/api/api.go`
- Test: `pkg/api/api_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `api.EnrolRequest{Token, CSRPEM []byte, Hostname, AgentVersion string}`, `api.EnrolResponse{ServerID string, CertPEM, CAPEM []byte, EnrolKey string}`, `api.ReEnrolRequest{ServerID, EnrolKey string, CSRPEM []byte}`, `api.Heartbeat{ServerID, AgentVersion, BootID string, UptimeSec int64, SentAt time.Time}`, `api.HeartbeatResponse{ConfigVersion int, PollIntervalSec int}`, and `Validate() error` on each request type. Also `api.MaxBodyBytes = 64 * 1024` and `api.AgentCertHeader = "X-Agent-Cert"`.

- [ ] **Step 1: Initialise the repository**

```bash
git init -b main
go mod init github.com/makhammatovb/fleetguard
```

Write `.gitignore` (binaries, `web/node_modules`, `web/dist`, `.env`, `*.pem`, `*.key`), a `Makefile` with `test`, `lint`, `build-agent`, `build-server`, `up`, `down` targets, and a `.golangci.yml` enabling `errcheck`, `govet`, `staticcheck`, `revive`, `gosec`.

- [ ] **Step 2: Write the failing tests**

```go
func TestEnrolRequestValidate(t *testing.T)        // empty Token, empty CSRPEM, empty Hostname each return a non-nil error naming the field
func TestEnrolRequestRoundTrip(t *testing.T)       // json.Marshal then Unmarshal yields an equal struct, CSRPEM bytes intact
func TestHeartbeatValidate(t *testing.T)           // empty ServerID and a ServerID that is not a UUID both error; a valid UUID passes
func TestMaxBodyBytesIsSixtyFourKiB(t *testing.T)  // assert api.MaxBodyBytes == 65536
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/api/ -v`
Expected: FAIL — package does not compile, undefined types.

- [ ] **Step 4: Implement the types and `Validate` methods in `pkg/api/api.go`**

Byte slices marshal as base64 under `encoding/json` by default; keep them as `[]byte` and let that happen. Validate UUIDs with `github.com/google/uuid`.

- [ ] **Step 5: Run tests and lint**

Run: `go test ./pkg/api/ -v && make lint`
Expected: PASS, no lint findings.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(api): shared agent/server wire types with validation"
```

---

### Task 2: Database schema, migrations and test harness

**Files:**
- Create: `migrations/0001_init.sql`
- Create: `internal/server/store/store.go` (connection open/close only)
- Create: `internal/server/store/testdb.go`
- Create: `deploy/docker-compose.yml` (database service only; the rest is added in Task 12)
- Test: `internal/server/store/store_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `store.Open(ctx context.Context, dsn string) (*store.Store, error)`, `(*Store).Close()`, `(*Store).Migrate(ctx) error`, and for tests `store.NewTestDB(t *testing.T) *Store` which starts a container, migrates, and registers cleanup. The TimescaleDB image tag is defined **once** as `store.TimescaleImage` and `deploy/docker-compose.yml` must use that same tag.

**Schema** (migration `0001_init.sql`, goose format with an `-- +goose Down` section):

- `users(id uuid pk, username text unique not null, password_hash text not null, role text not null check (role in ('admin','user')), is_active boolean not null default false, created_at timestamptz not null, activated_at timestamptz, activated_by uuid references users(id))`
- `sessions(token_hash bytea primary key, user_id uuid not null references users(id) on delete cascade, created_at timestamptz not null, expires_at timestamptz not null)`
- `servers(id uuid pk, name text unique not null, note text not null default '', created_at timestamptz not null, decommissioned_at timestamptz)`
- `enrolment_tokens(token_hash bytea pk, server_id uuid not null references servers(id) on delete cascade, expires_at timestamptz not null, consumed_at timestamptz)`
- `agents(server_id uuid pk references servers(id) on delete cascade, hostname text not null, agent_version text not null, cert_fingerprint text not null, cert_not_after timestamptz not null, enrol_key_hash bytea not null, boot_id text not null default '', last_seen_at timestamptz, revoked_at timestamptz)`
- `audit_log(at timestamptz not null, actor text not null, action text not null, target text not null, detail jsonb not null default '{}')` — created as a TimescaleDB hypertable on `at`, which establishes the pattern Phase 1's metrics tables follow and proves the extension is present.
- Scope columns reserved per spec §17.5: `users.scope_all boolean not null default true` and a `user_server_scopes(user_id, server_id)` table, created now and unused in this phase, so authorization can be narrowed later without a migration against live data.

- [ ] **Step 1: Write the failing tests**

```go
func TestMigrateCreatesEveryTable(t *testing.T)   // after NewTestDB, query information_schema for each table name above
func TestAuditLogIsHypertable(t *testing.T)       // select from timescaledb_information.hypertables where hypertable_name='audit_log' returns one row
func TestRoleCheckRejectsUnknownRole(t *testing.T) // inserting role 'root' returns a constraint violation
func TestMigrateIsIdempotent(t *testing.T)        // calling Migrate twice succeeds
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/store/ -v`
Expected: FAIL — no migrations, tables absent.

- [ ] **Step 3: Write `migrations/0001_init.sql` and implement `Open`, `Close`, `Migrate`, `NewTestDB`**

Embed the migrations directory with `embed.FS` and run them through `pressly/goose/v3` so the binary needs no files beside it. `NewTestDB` uses `testcontainers-go` with `store.TimescaleImage`, one container per test package.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/store/ -v`
Expected: PASS (first run pulls the image).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(store): initial schema, goose migrations, container test harness"
```

---

### Task 3: Internal certificate authority

**Files:**
- Create: `internal/server/ca/ca.go`
- Test: `internal/server/ca/ca_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `ca.Generate() (certPEM, keyPEM []byte, err error)`, `ca.Load(certPEM, keyPEM []byte) (*CA, error)`, `ca.LoadOrCreate(dir string) (*CA, error)`, `(*CA).Sign(csrPEM []byte, serverID string, ttl time.Duration, now time.Time) (certPEM []byte, err error)`, `(*CA).Verify(certDER []byte, now time.Time) (serverID string, err error)`, `(*CA).CertPEM() []byte`, `(*CA).Fingerprint(certDER []byte) string`. Sentinel errors `ca.ErrExpired`, `ca.ErrUntrusted`, `ca.ErrBadSubject`.

Subject convention: the issued certificate's Common Name is exactly `fleetguard-agent:<serverID>`; `Verify` returns the server ID parsed back out of it and errors with `ErrBadSubject` on any other shape. Keys are ECDSA P-256. The CA certificate lives 10 years; `LoadOrCreate` writes `ca.crt` and `ca.key` into `dir` with mode `0600` and never overwrites existing files.

- [ ] **Step 1: Write the failing tests**

```go
func TestSignThenVerifyRoundTrip(t *testing.T)        // Sign for a known UUID, Verify returns that same UUID
func TestVerifyRejectsForeignCA(t *testing.T)         // a cert from a second CA returns ErrUntrusted
func TestVerifyRejectsExpiredCert(t *testing.T)       // Sign with ttl=1h, Verify at now+2h returns ErrExpired
func TestVerifyRejectsWrongCommonName(t *testing.T)   // a cert whose CN is "admin" returns ErrBadSubject
func TestSignHonoursNinetyDayTTL(t *testing.T)        // NotAfter minus NotBefore == 90*24h when ttl is 90 days
func TestLoadOrCreateDoesNotOverwrite(t *testing.T)   // second call returns a CA with an identical CertPEM, file mtime unchanged
func TestLoadOrCreateWritesKeyAs0600(t *testing.T)    // os.Stat(ca.key).Mode().Perm() == 0600
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ca/ -v`
Expected: FAIL — package undefined.

- [ ] **Step 3: Implement the CA in `internal/server/ca/ca.go`**

Use `crypto/x509` directly; no third-party PKI library. `Verify` builds an `x509.CertPool` from the CA certificate and calls `cert.Verify` with `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}` and the supplied `now` as `CurrentTime`, so expiry is testable without sleeping. Fingerprint is the hex SHA-256 of the DER.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ca/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ca): internal CA issuing and verifying agent client certificates"
```

---

### Task 4: Store queries for servers, tokens and agents

**Files:**
- Modify: `internal/server/store/store.go`
- Create: `internal/server/store/servers.go`, `internal/server/store/agents.go`, `internal/server/store/audit.go`
- Test: `internal/server/store/servers_test.go`, `internal/server/store/agents_test.go`

**Interfaces:**
- Consumes: `store.NewTestDB` (Task 2).
- Produces, all methods on `*store.Store` taking `ctx context.Context` first:
  - `CreateServer(ctx, name, note string) (Server, error)` — `ErrNameTaken` on conflict
  - `GetServer(ctx, id string) (Server, error)` — `ErrNotFound`
  - `ListServersWithStatus(ctx, now time.Time) ([]ServerStatus, error)` — `ServerStatus{Server, LastSeenAt *time.Time, AgentVersion string, Online bool, CertNotAfter *time.Time}`; `Online` is true when `LastSeenAt` is within 180 seconds of `now`
  - `CreateEnrolToken(ctx, serverID string, ttl time.Duration, now time.Time) (plaintext string, err error)` — 32 random bytes, base64url, stored as SHA-256
  - `ConsumeEnrolToken(ctx, plaintext string, now time.Time) (serverID string, err error)` — atomic single-use via `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now RETURNING server_id`; `ErrTokenInvalid` covers unknown, expired and already-consumed alike
  - `RecordEnrolment(ctx, e Enrolment) error` where `Enrolment{ServerID, Hostname, AgentVersion, CertFingerprint, EnrolKeyHash []byte, CertNotAfter time.Time}` — upsert on `server_id`
  - `VerifyEnrolKey(ctx, serverID, enrolKey string) error` — constant-time compare against the stored hash; `ErrEnrolKeyInvalid`
  - `TouchHeartbeat(ctx, serverID, agentVersion, bootID string, at time.Time) (bootChanged bool, err error)`
  - `AppendAudit(ctx, actor, action, target string, detail any) error`

- [ ] **Step 1: Write the failing tests**

```go
func TestCreateServerRejectsDuplicateName(t *testing.T)
func TestConsumeEnrolTokenSucceedsOnce(t *testing.T)        // first call returns the server ID, second returns ErrTokenInvalid
func TestConsumeEnrolTokenRejectsExpired(t *testing.T)      // ttl 1h, consumed at now+2h, ErrTokenInvalid
func TestConsumeEnrolTokenIsAtomicUnderConcurrency(t *testing.T) // 10 goroutines consume the same token; exactly one succeeds
func TestVerifyEnrolKeyRejectsWrongKey(t *testing.T)
func TestTouchHeartbeatReportsBootIDChange(t *testing.T)    // same boot ID -> false; different non-empty boot ID -> true
func TestListServersWithStatusComputesOnline(t *testing.T)  // last seen 60s ago -> Online true; 600s ago -> false; never -> false
func TestAppendAuditStoresDetailAsJSON(t *testing.T)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/store/ -run 'Server|Enrol|Heartbeat|Audit' -v`
Expected: FAIL — methods undefined.

- [ ] **Step 3: Implement the queries**

Hand-written SQL with `pgx/v5`; no ORM, no codegen. Token and enrolment-secret hashes are plain SHA-256 of the random bytes (they are high-entropy secrets, so a password KDF is unnecessary); compare with `crypto/subtle.ConstantTimeCompare`. The single-use guarantee must come from the `UPDATE ... WHERE consumed_at IS NULL` row lock, not from a read-then-write in Go.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/store/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(store): server, enrolment token, agent and audit queries"
```

---

### Task 5: Enrolment and re-enrolment endpoints

**Files:**
- Create: `internal/server/httpapi/agentapi.go`
- Create: `internal/server/httpapi/httpapi.go` (router construction, body limit, JSON helpers)
- Test: `internal/server/httpapi/agentapi_test.go`

**Interfaces:**
- Consumes: `api.*` (Task 1), `*store.Store` (Task 4), `*ca.CA` (Task 3).
- Produces: `httpapi.NewAgentRouter(st *store.Store, authority *ca.CA, proxySecret string, lg *slog.Logger) http.Handler` serving `POST /v1/enrol` and `POST /v1/re-enrol`, plus `httpapi.RequireProxySecret(secret string)` middleware wrapping **every** `/v1/*` route. Request bodies are read through `http.MaxBytesReader` with `api.MaxBodyBytes`.

**Neither of these two routes requires a client certificate**, and that is not an oversight: an agent enrolling for the first time has none, and an agent whose certificate expired while its server was switched off must be able to re-enrol without one. They are authenticated by the single-use token and by the enrolment secret. What guards them against a local process bypassing Caddy is `RequireProxySecret`, which is why it wraps the whole `/v1/*` tree and not just the heartbeat route — build it here, in the task that creates the router, rather than in Task 7.

Behaviour: `/v1/enrol` consumes the token, signs the CSR for the token's server ID with a 90-day TTL, generates a 32-byte enrolment secret, records the enrolment, audits `agent.enrolled`, and returns `api.EnrolResponse`. The stored hash is built with `store.HashHighEntropySecret`, so it matches what `VerifyEnrolKey` compares against. `/v1/re-enrol` verifies the enrolment secret for the claimed server ID, signs a fresh certificate, and audits `agent.reenrolled`; it requires no token and works whether or not the previous certificate has expired.

A decommissioned server is refused by the **store** (Ruling 9), which collapses it into `ErrTokenInvalid` for token consumption and `ErrEnrolKeyInvalid` for the secret. The handler therefore answers **401, not 403**: distinguishing the decommissioned case would tell a caller holding a token that it names a real server which merely got retired, which is exactly the fact the indistinguishable error exists to hide. The audit entry records the real reason; the response does not.

- [ ] **Step 1: Write the failing tests**

Review Focus item 1 is covered here.

```go
func TestEnrolIssuesCertificateForTokensServer(t *testing.T) // CN parses back to the server ID the token was created for
func TestEnrolRejectsReplayedToken(t *testing.T)             // second POST with the same token -> 401, and no second agents row
func TestEnrolReplayIsAudited(t *testing.T)                  // audit_log contains action 'agent.enrol_rejected'
func TestEnrolRejectsExpiredToken(t *testing.T)              // -> 401
func TestEnrolRejectsOversizedBody(t *testing.T)             // 1 MiB body -> 413
func TestEnrolRejectsDecommissionedServer(t *testing.T)      // -> 401, NOT 403 (see below)
func TestEnrolRejectsMissingProxySecret(t *testing.T)        // valid token, no X-Proxy-Auth -> 401
func TestReEnrolRejectsMissingProxySecret(t *testing.T)      // valid secret, no X-Proxy-Auth -> 401
func TestReEnrolWithValidSecretIssuesNewCert(t *testing.T)   // new fingerprint differs from the first
func TestReEnrolRejectsWrongSecret(t *testing.T)             // -> 401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/httpapi/ -v`
Expected: FAIL — `NewAgentRouter` undefined.

- [ ] **Step 3: Implement the router and both handlers**

`http.ServeMux` with method patterns (`"POST /v1/enrol"`). Every failure returns a bare status code and a generic JSON body — never the reason — so an attacker probing tokens learns nothing; the reason goes to `lg` and the audit log.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/httpapi/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): single-use token enrolment and secret-based re-enrolment"
```

---

### Task 6: Agent identity, configuration and mTLS transport

**Files:**
- Create: `internal/agent/config.go`, `internal/agent/identity.go`, `internal/agent/transport.go`
- Test: `internal/agent/identity_test.go`, `internal/agent/transport_test.go`

**Interfaces:**
- Consumes: `api.*` (Task 1); the enrolment endpoints (Task 5) are exercised through a test server built from `httpapi.NewAgentRouter`.
- Produces: `agent.Config{ServerURL, StateDir string, PollInterval time.Duration}` with `agent.LoadConfig(path string) (Config, error)`; `agent.Identity{ServerID string, Cert tls.Certificate, CAPool *x509.CertPool, NotAfter time.Time}`; `agent.Enrol(ctx, cfg Config, token, hostname, version string) (Identity, error)`; `agent.LoadIdentity(cfg Config) (Identity, error)` returning `agent.ErrNoIdentity` when absent; `agent.ReEnrol(ctx, cfg Config) (Identity, error)`; `(Identity).NeedsRotation(now time.Time) bool`; `agent.NewClient(id Identity, cfg Config) *agent.Client` and `(*Client).SendHeartbeat(ctx, hb api.Heartbeat) (api.HeartbeatResponse, error)`.

**Trust anchor: the agent pins the fleet CA and never uses system roots.** The agent
verifies the server with `ca.crt` alone, on every call including the very first enrolment.
This requires the **agent hostname's server certificate to be issued by the fleet CA**, not
by ACME — see Task 12. The dashboard hostname keeps a public ACME certificate, because
browsers need one; the agent does not. Pinning this way means no public certificate
authority is in the agent's trust path at all, so no mis-issued or compromised public CA
can intercept agent traffic, read a fleet's telemetry, or feed an agent forged responses.

The bootstrap is the install command: `install.sh` fetches `ca.crt` from the dashboard
hostname over publicly trusted TLS and writes it into the state directory *before* calling
`enrol`, so the agent has its pin from the first request. The root of trust is therefore the
same TLS connection that already delivers the installer and the one-time token — nothing
weaker is introduced. There must be **no system-roots fallback**: a config field that
silently falls back to system roots when `ca.crt` is missing would turn a missing-file bug
into an undetectable downgrade, so a missing or unparseable `ca.crt` is a hard error.

State directory layout, all files written `0600` and owned by root: `agent.crt`, `agent.key`, `ca.crt`, `enrol.key`, `server_id`. Config file `/etc/fleetguard/agent.yaml` holds only `server_url` and `poll_interval`. `NeedsRotation` is true when fewer than 30 days remain, giving the 90-day/60-day rule from the spec.

- [ ] **Step 1: Write the failing tests**

Review Focus item 2 is covered here.

```go
func TestEnrolPersistsIdentityWith0600(t *testing.T)      // all five files exist, each Mode().Perm() == 0600
func TestLoadIdentityAfterEnrolReturnsSameServerID(t *testing.T)
func TestLoadIdentityWithoutStateReturnsErrNoIdentity(t *testing.T)
func TestNeedsRotationAtSixtyDays(t *testing.T)           // 90-day cert: false at day 59, true at day 61
func TestReEnrolRecoversFromExpiredCertificate(t *testing.T) // enrol, overwrite agent.crt with an expired cert, ReEnrol succeeds and SendHeartbeat then returns 200
func TestClientRejectsServerWithUntrustedCA(t *testing.T)  // test server using a foreign CA -> error mentioning certificate
func TestClientSendsClientCertificate(t *testing.T)        // test server with ClientAuth RequireAnyClientCert receives a chain of length 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/ -v`
Expected: FAIL — package undefined.

- [ ] **Step 3: Implement config, identity and transport**

Generate the agent key and CSR with `crypto/x509.CreateCertificateRequest` (ECDSA P-256) in `Enrol`; the private key never leaves the host. `NewClient` builds an `http.Client` with a `tls.Config` carrying `Certificates: []tls.Certificate{id.Cert}` and `RootCAs: id.CAPool` — `InsecureSkipVerify` must never appear in this package, and the lint config should fail the build if it does.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/agent/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): enrolment, on-disk identity and mutual-TLS client"
```

---

### Task 7: Heartbeat endpoint with certificate authentication

**Files:**
- Modify: `internal/server/httpapi/agentapi.go`
- Create: `internal/server/httpapi/agentauth.go`, `internal/server/httpapi/ratelimit.go`
- Test: `internal/server/httpapi/heartbeat_test.go`, `internal/server/httpapi/agentauth_test.go`

**Interfaces:**
- Consumes: `*ca.CA` (Task 3), `(*Store).TouchHeartbeat` and `AppendAudit` (Task 4).
- Produces: `POST /v1/heartbeat` on the agent router; middleware `httpapi.AgentAuth(authority *ca.CA)` which reads the base64 DER from the `api.AgentCertHeader` header, verifies it against the CA, and puts the server ID in the request context, retrievable with `httpapi.ServerIDFrom(ctx) (string, bool)`; `httpapi.NewRateLimiter(perMinute int) *RateLimiter` keyed by server ID.

The certificate arrives in a header because Caddy terminates TLS (Task 12). The backend re-verifies the chain itself rather than trusting Caddy's verdict.

**What the header does and does not prove.** `ca.Verify` is a chain-and-subject check over bytes; it proves the certificate was issued by our CA, *not* that the caller holds the matching private key. Possession is proven only by the TLS handshake Caddy performs. Two things therefore bind, and the middleware is not correct without both:

1. The backend binds loopback only (Task 10 enforces this in code).
2. `AgentAuth` rejects any `/v1/*` request that does not carry `X-Proxy-Auth` equal to `FG_PROXY_SECRET`, compared with `crypto/subtle.ConstantTimeCompare`. Caddy sets that header; nothing else knows it. Without this, any local process could replay a certificate it obtained anywhere — a public one scraped from a handshake would do — and be authenticated as that agent.

**`AgentAuth` is the complete gate, and nothing partial carries that name.** It takes the authority, a fingerprint lookup (`func(ctx context.Context, serverID string) (string, error)`, satisfied by the store but not typed to it), the rate limiter and `now`, and internally performs, in this order: verify the certificate chain; rate-limit by the server ID the chain established; compare `ca.Fingerprint(certDER)` against the stored `agents.cert_fingerprint`, rejecting a mismatch with 403 plus an audit entry.

That order is load-bearing and the two reasons pull against each other, so it is fixed here. The pin check needs a database round trip and writes an audit row on rejection, so it must sit **behind** the limiter — otherwise anyone holding any CA-issued certificate that is no longer current, which is exactly the certificate this check exists to stop, can drive unbounded `audit_log` writes and one query each at full request rate. But the limiter keys on the server ID, which only the chain check establishes, so it must sit **in front of** the pin. Hence chain, then limit, then pin — one middleware owning all three rather than a chain-only `AgentAuth` with the pin bolted on outside it, because an exported middleware named for authentication that proves only issuance is a trap: the next route to reach for it gets a gate a superseded certificate walks through, and an unexported pin cannot be composed by any caller to close it. Chaining to the CA is not sufficient: `RecordCertRotation` overwrites the fingerprint on re-enrolment but there is no CRL, so without this check a superseded certificate keeps authenticating for the remainder of its own 90 days. Pinning the fingerprint is what turns rotation into real retirement and caps a stolen key's useful life at the 60-day rotation interval rather than 90 days from issue. Add a test: rotate a certificate via re-enrolment, then heartbeat with the previous one and expect 403.

`AgentAuth` must also reject a server whose `decommissioned_at` or `agents.revoked_at` is set, which is what makes decommissioning in the UI (Task 10) an actual revocation: there is no CRL, and an issued certificate stays cryptographically valid for its full 90 days, so the database is the only revocation checkpoint.

**The store enforces this, not the handler.** `TouchHeartbeat` returns `store.ErrServerInactive` when the server is decommissioned or the agent revoked; `ConsumeEnrolToken` returns `ErrTokenInvalid` for a decommissioned server's token; `VerifyEnrolKey` returns `ErrEnrolKeyInvalid` for a revoked agent. The handler's job is to map `ErrServerInactive` to 403 and audit it — it must not be the only thing standing between a revoked agent and a fresh certificate, because a handler that forgets the check fails open.

A heartbeat whose body `ServerID` differs from the certificate's server ID is rejected with 403 and audited.

- [ ] **Step 1: Write the failing tests**

Review Focus items 3 and 5 are covered here.

```go
func TestHeartbeatUpdatesLastSeen(t *testing.T)
func TestHeartbeatWithoutCertHeaderIsUnauthorised(t *testing.T)      // 401
func TestHeartbeatWithForeignCertIsUnauthorised(t *testing.T)         // cert from a second CA -> 401
func TestHeartbeatWithExpiredCertIsUnauthorised(t *testing.T)          // 401
func TestHeartbeatBodyServerIDMustMatchCertificate(t *testing.T)       // 403 and audit action 'agent.identity_mismatch'
func TestHeartbeatFlagsChangedBootID(t *testing.T)                     // second heartbeat with a new boot ID -> 200, audit action 'agent.boot_id_changed', last_seen still updated
func TestHeartbeatRejectsOversizedBody(t *testing.T)                   // 1 MiB -> 413
func TestHeartbeatRateLimitPerServer(t *testing.T)                     // 61st request within a minute -> 429; a second server is unaffected
func TestHeartbeatResponseCarriesPollInterval(t *testing.T)            // PollIntervalSec == 30
func TestAgentRouteRejectsMissingProxySecret(t *testing.T)             // valid cert header, no X-Proxy-Auth -> 401
func TestAgentRouteRejectsWrongProxySecret(t *testing.T)               // valid cert header, wrong secret -> 401
func TestHeartbeatRejectedForDecommissionedServer(t *testing.T)        // valid cert, decommissioned_at set -> 403, audited
func TestHeartbeatRejectedForRevokedAgent(t *testing.T)                // valid cert, agents.revoked_at set -> 403, audited
func TestHeartbeatRejectsSupersededCertificate(t *testing.T)           // re-enrol, then heartbeat with the previous cert -> 403, audited
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/httpapi/ -run Heartbeat -v`
Expected: FAIL — route not registered.

- [ ] **Step 3: Implement the middleware, limiter and handler**

The rate limiter is an in-memory token bucket per server ID with a mutex; a restart resetting it is acceptable at this scale. A changed boot ID is **audited and alerted later** (Phase 2 turns it into an incident) but must not break ingestion — a legitimately rebooted server also changes boot ID, so this is a signal, not a rejection.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/httpapi/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): heartbeat ingest with client-certificate auth and rate limiting"
```

---

### Task 8: Agent heartbeat loop and binary

**Files:**
- Create: `internal/agent/run.go`, `cmd/agent/main.go`
- Test: `internal/agent/run_test.go`

**Interfaces:**
- Consumes: everything from Task 6, plus `api.Heartbeat`.
- Produces: `agent.Run(ctx context.Context, cfg Config, now func() time.Time) error`; the binary `fleetguard-agent` with subcommands `enrol --token=<token>` and `run`.

Loop behaviour: load identity (exit with a clear message if absent and the subcommand is `run`); every `PollInterval` send a heartbeat; on transport error retry with exponential backoff starting at 5 s, capped at 5 minutes, with full jitter; on 401 attempt `ReEnrol` once before backing off; when `NeedsRotation` is true, call `ReEnrol` and continue with the new identity. Boot ID is read from `/proc/sys/kernel/random/boot_id`, falling back to an empty string on platforms without it so the loop remains testable on macOS.

- [ ] **Step 1: Write the failing tests**

```go
func TestRunSendsHeartbeatEveryInterval(t *testing.T)     // fake clock + test server: 3 heartbeats in 3 intervals
func TestRunBacksOffOnServerError(t *testing.T)            // server returns 500; retry gaps increase and never exceed 5 minutes
func TestRunReEnrolsOnUnauthorised(t *testing.T)           // server returns 401 once then 200; exactly one re-enrol request observed
func TestRunRotatesCertificateBeforeExpiry(t *testing.T)   // identity 29 days from expiry triggers one re-enrol on the first tick
func TestRunStopsOnContextCancel(t *testing.T)             // Run returns ctx.Err() within one interval
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/ -run Run -v`
Expected: FAIL — `Run` undefined.

- [ ] **Step 3: Implement `Run` and `cmd/agent/main.go`**

Inject time through the `now` parameter and a `time.Ticker` created from the config so tests do not sleep in real time. `main` parses the subcommand with the standard `flag` package; no CLI framework. Per the global constraints, `main` must expose no subcommand that acknowledges or approves anything.

- [ ] **Step 4: Run tests and build the binary**

Run: `go test ./internal/agent/ -v && go build -o /tmp/fleetguard-agent ./cmd/agent`
Expected: PASS and a built binary.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): heartbeat loop with backoff, rotation and re-enrolment"
```

---

### Task 9: Users, sessions and authentication endpoints

**Files:**
- Create: `internal/server/auth/auth.go`, `internal/server/httpapi/authapi.go`
- Test: `internal/server/auth/auth_test.go`, `internal/server/httpapi/authapi_test.go`

**Interfaces:**
- Consumes: `*store.Store` (Task 2 schema, Task 4 audit).
- Produces: `auth.New(st *store.Store) *auth.Service` with `Register(ctx, username, password string) error`, `Activate(ctx, adminID, userID, role string) error`, `Login(ctx, username, password string, now time.Time) (sessionToken string, err error)`, `Session(ctx, token string, now time.Time) (User, error)`, `Logout(ctx, token string) error`, `CountAdmins(ctx) (int, error)`, `Bootstrap(ctx, username, password string) error`. Sentinel `auth.ErrInvalidCredentials` is returned for every login failure. Router: `httpapi.NewAdminRouter(st, authSvc, baseURL string) http.Handler` serving `POST /api/register`, `POST /api/login`, `POST /api/logout`, `GET /api/me`, `GET /api/users`, `POST /api/users/{id}/activate`, plus middleware `RequireUser` and `RequireAdmin`.

Rules: passwords hashed with `argon2id` (`golang.org/x/crypto/argon2`, 64 MiB, 3 iterations, 4 lanes, 16-byte salt). Registration always returns 202 regardless of whether the username was taken, so the endpoint cannot be used to enumerate users. A session token is 32 random bytes, returned in an `HttpOnly; Secure; SameSite=Lax` cookie named `fg_session`, stored as SHA-256, 7-day expiry. Login is rate limited to 10 attempts per minute per username **and** per source IP. `Bootstrap` creates the first admin — already active — and is callable only when `CountAdmins` returns 0; the server runs it at startup from `FG_BOOTSTRAP_USER` / `FG_BOOTSTRAP_PASSWORD` if set.

- [ ] **Step 1: Write the failing tests**

Review Focus item 4 is covered here.

```go
func TestLoginFailuresAreIndistinguishable(t *testing.T)  // unknown user, wrong password, and inactive user all return auth.ErrInvalidCredentials and no session
func TestInactiveUserGetsNoSession(t *testing.T)           // register then Login -> error; sessions table empty
func TestActivatedUserCanLogin(t *testing.T)               // Activate then Login -> non-empty token; Session resolves to that user
func TestRegisterDoesNotRevealTakenUsername(t *testing.T)  // same username twice: both 202, one row
func TestActivateRequiresAdmin(t *testing.T)               // a 'user' role caller -> 403
func TestActivateIsAudited(t *testing.T)                   // audit action 'user.activated' with both ids
func TestSessionExpires(t *testing.T)                      // Session at now+8d -> error
func TestLogoutInvalidatesSession(t *testing.T)
func TestLoginRateLimited(t *testing.T)                    // 11th attempt in a minute -> 429
func TestBootstrapOnlyWhenNoAdminsExist(t *testing.T)      // second call returns an error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/auth/ ./internal/server/httpapi/ -run 'Login|Register|Activate|Session|Logout|Bootstrap' -v`
Expected: FAIL — package undefined.

- [ ] **Step 3: Implement the service and handlers**

`Login` must hash the supplied password even when the username is unknown, against a fixed dummy hash, so response timing does not disclose account existence.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(auth): username/password login with admin activation and sessions"
```

---

### Task 10: Server management endpoints and the server binary

**Files:**
- Create: `internal/server/httpapi/serversapi.go`, `cmd/server/main.go`
- Test: `internal/server/httpapi/serversapi_test.go`

**Interfaces:**
- Consumes: Tasks 3, 4, 9.
- Produces: on the admin router — `POST /api/servers` (admin; body `{name, note}`; returns `{server, install_command, token_expires_at}`), `GET /api/servers` (any user; the fleet list), `GET /api/servers/{id}`, `POST /api/servers/{id}/enrol-token` (admin; issues a fresh token for re-installing), `POST /api/servers/{id}/decommission` (admin; sets `decommissioned_at` and revokes the agent). Plus `cmd/server/main.go`, the `fleetguard-server` binary.

`install_command` is rendered from both origins and the one-time token as:
`curl -sSL <baseURL>/install.sh | sudo bash -s -- --token=<token> --server-url=<agentURL>`

The installer is fetched from the dashboard origin over publicly trusted TLS — that connection is the agent's root of trust, and it is also where `ca.crt` comes from — while `--server-url` is the **agent** origin, whose certificate the fleet CA issued and the agent pins. Mixing these up is the single easiest way to break every enrolment at once, which is why the binary requires both values explicitly.

The binary reads `FG_DSN`, `FG_LISTEN` (default `127.0.0.1:8080`), `FG_BASE_URL` (dashboard origin), `FG_AGENT_URL` (agent origin — required), `FG_STATE_DIR` (default `/var/lib/fleetguard`), `FG_PROXY_SECRET` (required — the binary refuses to start without it), runs migrations, calls `ca.LoadOrCreate(FG_STATE_DIR)`, optionally bootstraps the first admin, and serves the agent and admin routers on one listener with `/v1/` and `/api/` prefixes. It must refuse to start if `FG_LISTEN` resolves to a non-loopback address unless `FG_ALLOW_PUBLIC_LISTEN=1` is set, so the loopback constraint is enforced in code rather than in documentation.

- [ ] **Step 1: Write the failing tests**

```go
func TestCreateServerReturnsInstallCommandWithToken(t *testing.T) // command contains the base URL and a token that ConsumeEnrolToken accepts
func TestCreateServerRequiresAdmin(t *testing.T)                   // 'user' role -> 403
func TestListServersVisibleToPlainUser(t *testing.T)               // 200
func TestListServersRequiresSession(t *testing.T)                  // no cookie -> 401
func TestFleetListReportsOnlineFlag(t *testing.T)                  // after a heartbeat the server shows online true
func TestDecommissionBlocksFurtherHeartbeats(t *testing.T)         // heartbeat after decommission -> 403
func TestEnrolTokenCanBeReissued(t *testing.T)                     // second token works, first is still single-use
func TestRefusesNonLoopbackListenWithoutOverride(t *testing.T)     // constructing the server with FG_LISTEN=0.0.0.0:8080 errors
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/httpapi/ -run 'Server|Fleet|Decommission|Loopback' -v`
Expected: FAIL

- [ ] **Step 3: Implement the handlers and `cmd/server/main.go`**

- [ ] **Step 4: Run tests and build**

Run: `go test ./... -v && go build -o /tmp/fleetguard-server ./cmd/server`
Expected: PASS and a built binary.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(api): server management, fleet list and the server binary"
```

---

### Task 11: Dashboard — login, pending approval, fleet list

**Files:**
- Create: `web/package.json`, `web/vite.config.ts`, `web/tsconfig.json`, `web/tailwind.config.ts`, `web/index.html`
- Create: `web/src/main.tsx`, `web/src/api/client.ts`, `web/src/routes/Login.tsx`, `web/src/routes/Register.tsx`, `web/src/routes/Pending.tsx`, `web/src/routes/Fleet.tsx`, `web/src/routes/AddServer.tsx`, `web/src/routes/Users.tsx`, `web/src/components/ServerCard.tsx`
- Test: `web/src/api/client.test.ts`, `web/src/routes/Fleet.test.tsx`, `web/src/routes/Login.test.tsx`

**Interfaces:**
- Consumes: the `/api/...` endpoints from Tasks 9 and 10.
- Produces: a Vite build in `web/dist`, served by Caddy in Task 12.

Screens, matching spec §12 for this phase only: **Login** (username, password, link to register), **Register** (shows "your account must be activated by an administrator" on success), **Pending** (shown when `/api/me` reports an inactive account), **Fleet** (one card per server: name, online indicator, last-seen relative time, agent version, certificate expiry; sorted offline-first), **Add server** (admin; name and note, then the install command with a copy button and the token's expiry), **Users** (admin; pending registrations with an Activate button and a role selector).
Each server card also carries a **Decommission** action for admins, with a confirmation
step, since spec §17.4 makes decommissioning the act that revokes a certificate — an
endpoint with no way to reach it would leave that rule unenforceable in practice.

Testing: Vitest with React Testing Library and MSW for request mocking. No end-to-end browser test in this phase; Task 12's smoke test covers the real stack.

- [ ] **Step 1: Scaffold and write the failing tests**

```bash
cd web && npm create vite@latest . -- --template react-ts
```

```ts
test('fleet list shows a server as offline when last seen is stale')
test('fleet list sorts offline servers before online ones')
test('login submits credentials and redirects to /fleet on success')
test('login shows one generic message for any failure')      // never "no such user"
test('register success shows the activation-required notice')
test('add server screen displays the returned install command verbatim')
test('api client surfaces a 401 by redirecting to /login')
test('decommission action is hidden for a non-admin user')
test('decommission asks for confirmation before calling the endpoint')
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd web && npm test`
Expected: FAIL — components do not exist.

- [ ] **Step 3: Implement the client and the six screens**

`client.ts` wraps `fetch` with `credentials: 'include'`, JSON handling, and a single place that turns 401 into a redirect. Data fetching through TanStack Query; the fleet list polls every 15 s. Keep the generic login error text identical for every failure, mirroring the server's behaviour from Task 9.

- [ ] **Step 4: Run tests and build**

Run: `cd web && npm test && npm run build`
Expected: PASS and `web/dist` produced.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(web): login, registration, pending approval, fleet list and add-server"
```

---

### Task 12: Deployment, installer and end-to-end smoke test

**Files:**
- Create: `deploy/Caddyfile`, `deploy/install.sh`, `deploy/fleetguard-agent.service`, `deploy/Dockerfile.server`, `deploy/Dockerfile.agent-test`, `.env.example`
- Modify: `deploy/docker-compose.yml` (add server, caddy and web services to the database service from Task 2)
- Test: `test/e2e/enrol_test.go`
- Create: `README.md`

**Interfaces:**
- Consumes: both binaries and `web/dist`.
- Produces: `make up` brings the stack up; a documented install command enrols a real agent.

**Caddy configuration.** Two site blocks on 443, with **different certificate sources**, which is deliberate. The dashboard hostname serves `web/dist` and reverse-proxies `/api/*` to `127.0.0.1:8080` with a public ACME certificate, because browsers need one. The agent hostname serves a certificate **issued by the fleet CA** (`tls <cert> <key>`), because the agent pins that CA and must never fall back to system roots (Task 6). This needs one addition to the CA package: `(*CA).IssueServerCert(dnsName string, ttl time.Duration, now time.Time) (certPEM, keyPEM []byte, err error)`, setting `ExtKeyUsageServerAuth` and the DNS SAN — the existing `Sign` issues client certificates only. The server binary writes `agent-server.crt`/`.key` into the state directory at startup, reissuing when fewer than 60 days remain, with a 1-year TTL so Phase 0 needs no renewal daemon; Caddy loads them from there and picks up a reissue on restart. Record that restart requirement in the README. The agent hostname uses `client_auth { mode verify_if_given; trust_pool file /var/lib/fleetguard/ca.crt }` — **not** `require_and_verify`, because an agent enrolling for the first time has no certificate and an agent whose certificate expired while offline must re-enrol without one; `verify_if_given` verifies the chain when a certificate is presented and admits the request when none is, and the backend then enforces per route — reverse-proxies `/v1/*` to the same backend, and sets both `header_up X-Agent-Cert {http.request.tls.client.certificate_der_base64}` and `header_up X-Proxy-Auth {env.FG_PROXY_SECRET}`. Because `header_up` replaces rather than appends, a client that supplies its own `X-Agent-Cert` or `X-Proxy-Auth` cannot have it reach the backend — the e2e test must assert that, since the whole agent-authentication model rests on it. `/install.sh` **and `/ca.crt`** are served unauthenticated from the dashboard hostname by Caddy as static files — the backend mounts only `/v1/` and `/api/`, so if Caddy does not serve these two paths nothing else will, and every install command 404s. Neither contains a secret: the token travels in the admin's command line, and the CA certificate is public by design. Serving `ca.crt` over the dashboard's publicly trusted TLS is what bootstraps the agent's pin, so it must be the fleet CA's current certificate, read from the state directory rather than copied.

**Deviation from spec §17.4, stated deliberately.** The spec requires the installer to
verify a release signature against a pinned public key. Phase 0 has no release pipeline
to hold a signing key, so the installer verifies a SHA-256 checksum served over the same
TLS connection — which protects against a corrupted download but not against a
compromised central host. The trust anchor in this phase is therefore the TLS connection
to the central app, not a signature. Signature verification with a pinned key is a
**required** part of Phase 5's auto-update work and is recorded in the README as an
outstanding item, not as done.

`install.sh` must: refuse to run as non-root; **fetch `ca.crt` from the dashboard hostname over publicly trusted TLS and install it into the state directory before enrolling**, since that connection is the agent's entire root of trust; detect `uname -m` and map to the right binary; download the agent over HTTPS; verify its SHA-256 against a published checksum file; install to `/usr/local/bin/fleetguard-agent`; create `/etc/fleetguard/agent.yaml` and `/var/lib/fleetguard` with mode `0700`; run `fleetguard-agent enrol --token=...`; install and enable the systemd unit; print the result. It must be idempotent — a second run re-enrols rather than failing — and must leave no copy of the token on disk.

- [ ] **Step 1: Write the failing end-to-end test**

```go
func TestEnrolAndHeartbeatEndToEnd(t *testing.T)
// Brings up compose (testcontainers compose module), bootstraps an admin, logs in,
// POSTs /api/servers, runs the agent container with the returned install command,
// then polls GET /api/servers until the server reports online, with a 90s deadline.
func TestClientSuppliedCertHeaderIsStrippedByCaddy(t *testing.T)
// POST /v1/heartbeat through Caddy with a forged X-Agent-Cert for another server's ID
// and no client certificate: must not authenticate as that server.
func TestAgentSurvivesBackendRestart(t *testing.T)
// Restarts the server container; the agent reports online again within two poll intervals.
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./test/e2e/ -v`
Expected: FAIL — compose file incomplete.

- [ ] **Step 3: Write the compose file, Caddyfile, Dockerfiles, systemd unit and `install.sh`**

For the test, Caddy runs with `local_certs` and the agent container trusts its internal CA, so no public DNS or ACME is needed in CI. Document in the README that production uses a real domain and that the only inbound port is 443.

- [ ] **Step 4: Run the end-to-end test**

Run: `go test ./test/e2e/ -v`
Expected: PASS — a real agent enrols and appears online.

- [ ] **Step 5: Measure the agent against its budget**

Run the agent container for 10 minutes and record `docker stats`. Expected: under 1% CPU and under 50 MB RSS, per the global constraints. Record the measured figures in the README; if the budget is exceeded, that is a defect in this task, not a later concern.

- [ ] **Step 6: Write the README and commit**

README covers: what Phase 0 does and does not do, how to run the stack locally, how to add a server, the environment variables, and the measured agent footprint.

```bash
git add -A && git commit -m "feat(deploy): compose stack, Caddy mTLS, installer and end-to-end test"
```

---

## Phase 0 exit criteria

- `go test ./... && (cd web && npm test)` passes.
- `make up`, bootstrap an admin, add a server, run the install command on a real Linux host, and that host shows **online** in the fleet list and stays online across a backend restart.
- The agent's measured footprint is within budget and recorded.
- No SSH credential is stored anywhere; the only inbound port on the central host is 443; the agent binary has no subcommand that approves or acknowledges anything.
