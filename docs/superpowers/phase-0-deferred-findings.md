# Deferred Minor findings — FleetGuard Phase 0

Raised by task reviews, judged Minor, and triaged by the final whole-branch review,
which ruled that none of them blocks the merge. Three stale entries were removed after
that review found them already fixed later in the branch; they are listed at the end so
the pruning is visible rather than silent. Two further items the final review judged
worse than Minor in whole-system context were fixed in the final fix wave: AppendAudit's
uninjected clock, and writeAtomic's missing fsync.

- Task 3: minor (deferred): Sign with ttl <= 1 min yields an already-expired cert
- Task 3: minor (deferred): TestFingerprintIsHexSHA256 asserts only len == 64, so it would
- Task 3: minor (deferred): only ca.key's 0600 mode is asserted; ca.crt's is not, and the
- Task 3: minor (deferred): a failed ca.crt write leaves ca.key behind, so every later
- Task 3: minor (deferred): partial-state error renders "cert: <nil>" and uses %v not %w,
- Task 3: minor (deferred): Verify accepts any non-empty CN suffix as a server ID; UUID
- Task 3: minor (deferred): root pool rebuilt on every Verify call (per-heartbeat, fleet-wide).
- Task 3: minor (deferred): Fingerprint ignores its receiver; plan-mandated method form.
- Task 3: minor (deferred): test at ca_test.go:376 swallows a GenerateKey error.
- Task 3: minor (deferred): untested branches — empty serverID, key/cert mismatch, bad CSR
- Task 3: minor (deferred): caLifetime is 3650 days (~9.993 years), not exactly 10.
- Task 3: minor (deferred): an expired CA also maps to ErrExpired, so at year 10 agents
- Task 2: minor (deferred): Store.Pool() is exported on the production type and its comment
- Task 2: minor (deferred): TestMigrateCreatesEveryTable checks table existence only —
- Task 2: minor (deferred): a panic in m.Run or a killed process still leaves termination
- Task 2: minor (deferred): TestMigrateIsIdempotent passes trivially via goose version
- Task 4: minor (deferred): CreateEnrolToken is the only method with no ID validation; a
- Task 4: minor (deferred): CreateServer maps any 23505 to ErrNameTaken without checking
- Task 4: minor (deferred): shared sentinels live in servers.go, not the store.go the plan
- Task 4: minor (deferred): AppendAudit stamps at with time.Now() while every other
- Task 4: minor (deferred): ORDER BY s.name ships untested.
- Task 4: minor (deferred): four tests discard CreateServer's error, so a failure surfaces
- Task 4: minor (deferred): TestEnrolTokenIsStoredHashedOnly asserts only that the
- Task 4: minor (deferred): file-plan deviation — the brief said modify store.go; it is
- Task 4: minor (deferred): no test that a revoked agent re-enrolling a decommissioned
- Task 5: minor (deferred): post-CSR signing failures answer 400 and audit "csr rejected",
- Task 5: minor (deferred): RecordCertRotation's existence probe costs a round trip to
- Task 5: minor (deferred): the `now func() time.Time` seam in the handlers is never
- Task 5: minor (deferred): two tests bind serverID then discard it with `_ = serverID`.
- Task 5: minor (deferred): no httpapi coverage for re-enrol against a decommissioned or
- Task 5: minor (deferred): a malformed CSR now produces no audit row at all, so a flood of
- Task 5: minor (deferred): the CSR is still parsed and signature-verified twice per
- Task 5: minor (deferred): stale comment at agentapi.go:112 still says "(checkCSR passed)".
- Task 6: minor (deferred): non-200 responses discard the server's error payload, so an
- Task 6: minor (deferred): each bootstrapClient call allocates an http.Transport never
- Task 6: minor (deferred): writeAtomic does not fsync the temp file or directory, so a
- Task 6: minor (deferred): a crash between the enrol.key and agent.crt writes leaves a
- Task 6: minor (deferred): nits — double TrimSpace, unbounded poll_interval, two tests
- Task 6: minor (deferred): TestReEnrolRecoversFromExpiredCertificate depends on ca.Sign's
- Task 6: minor (deferred): ReEnrol skips the ca_pem comparison when the server omits it
- Task 7: minor (deferred): ConfigVersion: 1 is a bare literal where pollIntervalSec got a
- Task 7: minor (deferred): heartbeat_test.go builds and discards a whole env (CA in a temp
- Task 7: minor (deferred): RED was a build failure on new symbols, so no test was observed
- Task 7: minor (deferred): per-certificate buckets bound a server's chain-verified
- Task 8: minor (deferred): defer l.client.Close() binds the receiver at defer time, so it
- Task 8: minor (deferred): HasEnrolSecrets/ErrAlreadyEnrolled/EnrolOrResume are
- Task 8: minor (deferred): IdleConnTimeout is 1 minute while Ruling 17 made server-directed
- Task 8: minor (deferred): two listed tests passed during RED, so they did not drive the
- Task 8: minor (deferred): enrolCmd's success and already-enrolled messages still use
- Task 8: minor (deferred): the loop.reenrolled field comment is stale now that a 403 wait
- Task 9: minor (deferred): GetLoginRecord runs outside the hashing slot, so each refused
- Task 9: minor (deferred): username normalization lives in the auth layer, not the schema;
- Task 9: minor (deferred): the Origin check is an exact string match and admits requests
- Task 9: minor (deferred): auth.go mixes the service, the semaphore and the argon2/PHC
- Task 9: minor (deferred): sweep iterates the whole map under the lock, a once-a-minute
- Task 9: minor (deferred): one address rotating usernames still mints a per-username key per
- Task 9: minor (deferred): the timing test is wall-clock and could flake under heavy CI
- Task 9: minor (deferred): cosmetic missing blank line in auth_test.go; sweepNow has no
- Task 10: minor (deferred): CheckListenAddr is a TCP listen policy in an HTTP package with
- Task 10: minor (deferred): authAPI now carries the whole admin API under a login-shaped
- Task 10: minor (deferred): getServer fetches the entire fleet and scans it linearly per
- Task 10: minor (deferred): u.ForceQuery and an empty-but-present fragment are unchecked, so
- Task 10: minor (deferred): the port is validated as digits only, so :99999 passes.
- Task 11: minor (deferred): the 429/503 test is order-dependent, reusing the rendered form.
- Task 11: minor (deferred): FLEET_POLL_MS is exported but no test asserts the poll.
- Task 11: minor (deferred): logout duplicates main.tsx's clear-and-redirect logic.
- Task 11: minor (deferred): path ids are interpolated unencoded (server-generated, low risk).
- Task 11: minor (deferred): the token-expiry assertion /2026/ would pass for any 2026 year.
- Task 11: minor (deferred): jsdom prints a harmless "Not implemented: navigation" line in
- Task 11: minor (deferred): useLogout uses try/finally with no catch, so a failed logout
- Task 11: minor (deferred): a reissued command stays on screen until the card unmounts with

## Removed as stale (already fixed in the branch)

- Task 2: minor (deferred): nothing enforces that docker-compose's image tag equals
- Task 5: minor (deferred): Task 10 should validate FG_PROXY_SECRET at startup so an
- Task 7: minor (deferred): limiter buckets are never evicted, so the map accumulates an

## New in the final fix wave

- IPv6 /64 defeats the per-address enrolment cap (the login limiter shares this property); a /64 prefix mask would close it.
- syncDir errors after a successful rename would report enrolment failure although the identity is durable (unlikely on ext4/xfs).
- auditnames_test.go scans a fixed domain-prefix set, so a new domain would slip past silently.
- audit_log has no retention policy; heartbeat-path rows are bounded only by per-fingerprint buckets.
