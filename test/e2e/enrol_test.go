// Package e2e runs the whole FleetGuard stack, built from the real compose file,
// and enrols a real agent binary, in a container, through the real installer.
//
// It needs Docker with the compose plugin and takes a few minutes, so it is
// skipped under -short. It shells out to `docker compose` rather than using a
// compose library: the point is to exercise the same file an operator runs.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

const (
	dashHost  = "fleet.test"
	agentHost = "agents.fleet.test"
	adminUser = "admin"

	// pollInterval is what the server tells agents (httpapi.pollIntervalSec).
	pollInterval = 30 * time.Second
)

// harness is one running stack. It is built lazily, shared by the tests in this
// package, and torn down by TestMain.
type harness struct {
	project  string
	env      []string
	httpsAt  string // host:port the published 443 is reachable on
	adminPwd string

	dash    *http.Client // browser-like: dashboard origin, session cookie, Origin header
	fleetCA *x509.CertPool
	caddyCA *x509.CertPool

	agentOnce sync.Once
	agentErr  error
	agentName string // container name of the enrolled agent
	serverID  string
	token     string
}

var (
	stack     *harness
	stackOnce sync.Once
	stackErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if stack != nil {
		stack.teardown()
	}
	os.Exit(code)
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// getStack brings the stack up once. It fails the calling test rather than
// skipping when Docker is missing: a skipped end-to-end test is trusted as a
// passed one.
func getStack(t *testing.T) *harness {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test skipped under -short")
	}
	stackOnce.Do(func() { stack, stackErr = bringUp() })
	if stackErr != nil {
		stack.dumpLogs(t)
		t.Fatalf("bring up stack: %v", stackErr)
	}
	return stack
}

func bringUp() (*harness, error) {
	h := &harness{project: "fge2e" + randHex(3), adminPwd: randHex(12)}
	stack = h // so TestMain tears down even a partial bring-up
	h.env = append(os.Environ(),
		"FG_DB_PASSWORD="+randHex(16),
		"FG_PROXY_SECRET="+randHex(32),
		"FG_BASE_URL=https://"+dashHost,
		"FG_AGENT_URL=https://"+agentHost,
		"FG_BOOTSTRAP_USER="+adminUser,
		"FG_BOOTSTRAP_PASSWORD="+h.adminPwd,
		"FG_CADDY_GLOBAL=local_certs",
		"FG_HTTPS_PUBLISH=127.0.0.1::443",
	)
	if out, err := h.runCmd(exec.Command("make", "-C", repoRoot(), "dist")); err != nil { //nolint:gosec // test harness: docker and make with test-generated arguments
		return h, fmt.Errorf("make dist: %v\n%s", err, out)
	}
	if out, err := h.compose("up", "-d", "--build", "--wait"); err != nil {
		return h, fmt.Errorf("compose up: %v\n%s", err, out)
	}
	out, err := h.compose("port", "caddy", "443")
	if err != nil {
		return h, fmt.Errorf("compose port: %v\n%s", err, out)
	}
	h.httpsAt = strings.TrimSpace(string(out))
	if strings.HasPrefix(h.httpsAt, "0.0.0.0:") {
		h.httpsAt = "127.0.0.1:" + strings.TrimPrefix(h.httpsAt, "0.0.0.0:")
	}

	// Caddy's local CA stands in for ACME: the dashboard certificate and the
	// agent container's system store both trust it.
	var rootPEM []byte
	deadline := time.Now().Add(90 * time.Second)
	for {
		rootPEM, err = h.compose("exec", "-T", "caddy", "cat", "/caddy/data/caddy/pki/authorities/local/root.crt")
		if err == nil && bytes.Contains(rootPEM, []byte("BEGIN CERTIFICATE")) {
			break
		}
		if time.Now().After(deadline) {
			return h, fmt.Errorf("caddy local root never appeared: %v %s", err, rootPEM)
		}
		time.Sleep(2 * time.Second)
	}
	h.caddyCA = x509.NewCertPool()
	h.caddyCA.AppendCertsFromPEM(rootPEM)

	jar, _ := cookiejar.New(nil)
	h.dash = &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: h.transport(dashHost, h.caddyCA, nil)}

	// Wait for the whole chain: Caddy, TLS, proxy secret, backend, database.
	for {
		resp, err := h.dash.Get("https://" + dashHost + "/api/me")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				break // reached the backend, which wants a session
			}
		}
		if time.Now().After(deadline.Add(60 * time.Second)) {
			return h, fmt.Errorf("stack never answered /api/me: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	return h, nil
}

func (h *harness) runCmd(c *exec.Cmd) ([]byte, error) {
	c.Env = h.env
	return c.CombinedOutput()
}

func (h *harness) compose(args ...string) ([]byte, error) {
	root := repoRoot()
	full := append([]string{
		"compose", "-p", h.project,
		"-f", filepath.Join(root, "deploy", "docker-compose.yml"),
		"-f", filepath.Join(root, "deploy", "docker-compose.e2e.yml"),
	}, args...)
	c := exec.Command("docker", full...) //nolint:gosec // test harness: docker and make with test-generated arguments
	c.Dir = root
	return h.runCmd(c)
}

func (h *harness) teardown() {
	if h.agentName != "" {
		_ = exec.Command("docker", "rm", "-f", h.agentName).Run() //nolint:gosec // test harness: docker and make with test-generated arguments
	}
	_, _ = h.compose("--profile", "agent", "down", "-v", "--remove-orphans", "--rmi", "local")
}

func (h *harness) dumpLogs(t *testing.T) {
	if h == nil {
		return
	}
	out, _ := h.compose("--profile", "agent", "logs", "--no-color", "--tail=80")
	t.Logf("compose logs:\n%s", out)
}

// transport dials the published port whatever the URL host is, and verifies the
// certificate for serverName against roots, as a real client would.
func (h *harness) transport(serverName string, roots *x509.CertPool, clientCert func() (*tls.Certificate, error)) *http.Transport {
	cfg := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return clientCert() }
	}
	return &http.Transport{
		TLSClientConfig: cfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, h.httpsAt)
		},
		DisableKeepAlives: true,
	}
}

func (h *harness) dashDo(t *testing.T, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://"+dashHost+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	// A browser sends the dashboard origin on state-changing requests; the
	// backend refuses anything else, which is why FG_BASE_URL must match it.
	req.Header.Set("Origin", "https://"+dashHost)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.dash.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

type fleetRow struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Online     bool    `json:"online"`
	LastSeenAt *string `json:"last_seen_at"`
}

func (h *harness) fleet(t *testing.T) []fleetRow {
	t.Helper()
	resp, body := h.dashDo(t, http.MethodGet, "/api/servers", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/servers = %d %s", resp.StatusCode, body)
	}
	var rows []fleetRow
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("decode fleet: %v: %s", err, body)
	}
	return rows
}

func (h *harness) row(t *testing.T, id string) fleetRow {
	t.Helper()
	for _, r := range h.fleet(t) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("server %s missing from the fleet list", id)
	return fleetRow{}
}

func (h *harness) login(t *testing.T) {
	t.Helper()
	resp, body := h.dashDo(t, http.MethodPost, "/api/login", map[string]string{"username": adminUser, "password": h.adminPwd})
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("login = %d %s", resp.StatusCode, body)
	}
}

// addServer registers a server and returns its ID and install command.
func (h *harness) addServer(t *testing.T, name string) (id, installCmd string) {
	t.Helper()
	resp, body := h.dashDo(t, http.MethodPost, "/api/servers", map[string]string{"name": name})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/servers = %d %s", resp.StatusCode, body)
	}
	var out struct {
		Server         struct{ ID string } `json:"server"`
		InstallCommand string              `json:"install_command"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Server.ID == "" || out.InstallCommand == "" {
		t.Fatalf("decode create server: %v: %s", err, body)
	}
	return out.Server.ID, out.InstallCommand
}

func (h *harness) waitOnline(t *testing.T, id string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if r := h.row(t, id); r.Online {
			return
		}
		if time.Now().After(deadline) {
			h.dumpLogs(t)
			t.Fatalf("server %s did not report online within %s", id, within)
		}
		time.Sleep(2 * time.Second)
	}
}

// enrolledAgent starts the agent container with the install command the API
// returned and waits for it to be online. It happens once; later tests reuse it.
func (h *harness) enrolledAgent(t *testing.T) (serverID string) {
	t.Helper()
	h.agentOnce.Do(func() {
		h.login(t)
		id, cmd := h.addServer(t, "e2e-agent")
		h.serverID = id
		h.token = tokenOf(cmd)
		if h.token == "" {
			t.Fatalf("install command carries no --token: %q", cmd)
		}
		h.agentName = h.project + "-agent"
		out, err := h.compose("--profile", "agent", "run", "-d", "--no-deps", "--name", h.agentName,
			"-e", "FG_INSTALL_COMMAND="+cmd, "agent")
		if err != nil {
			h.agentErr = fmt.Errorf("start agent container: %v\n%s", err, out)
		}
	})
	if h.agentErr != nil {
		t.Fatal(h.agentErr)
	}
	h.waitOnline(t, h.serverID, 90*time.Second)
	return h.serverID
}

func TestEnrolAndHeartbeatEndToEnd(t *testing.T) {
	h := getStack(t)

	// The two static files the installer depends on are served by the dashboard
	// origin: ca.crt is the agent's whole root of trust, and install.sh must
	// have had the dashboard origin written into it.
	resp, body := h.dashDo(t, http.MethodGet, "/ca.crt", nil)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("GET /ca.crt = %d %q", resp.StatusCode, body)
	}
	h.fleetCA = x509.NewCertPool()
	if !h.fleetCA.AppendCertsFromPEM(body) {
		t.Fatal("/ca.crt is not a parseable certificate")
	}
	resp, body = h.dashDo(t, http.MethodGet, "/install.sh", nil)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("https://"+dashHost)) || bytes.Contains(body, []byte("{{")) {
		t.Fatalf("GET /install.sh = %d, base URL not rendered into it: %.300s", resp.StatusCode, body)
	}
	// (The dashboard falls back to index.html for unknown paths, so a 200 alone
	// proves nothing: look for key material.)
	for _, p := range []string{"/ca.key", "/agent-server.key", "/../ca.key"} {
		if _, body = h.dashDo(t, http.MethodGet, p, nil); bytes.Contains(body, []byte("PRIVATE KEY")) {
			t.Fatalf("GET %s on the dashboard origin served a private key", p)
		}
	}

	id := h.enrolledAgent(t)
	if r := h.row(t, id); !r.Online || r.LastSeenAt == nil {
		t.Fatalf("enrolled agent is not online in the fleet list: %+v", r)
	}

	// Once the install is done the token must be nowhere on the agent host's
	// disk: it was handed to the agent by environment, not written anywhere.
	if out := mustExec(t, h.agentName, "sh", "-c",
		"grep -rIl -F -e '"+h.token+"' /etc /var /usr /root /tmp /home /opt 2>/dev/null || true"); strings.TrimSpace(out) != "" {
		t.Errorf("the enrolment token was left on disk in: %s", out)
	}
}

func mustExec(t *testing.T, container string, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", container}, args...)...).CombinedOutput() //nolint:gosec // test harness: docker and make with test-generated arguments
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// agentCert returns the enrolled agent's own identity, read from its container.
func (h *harness) agentCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	certPEM := mustExec(t, h.agentName, "cat", "/var/lib/fleetguard/agent.crt")
	keyPEM := mustExec(t, h.agentName, "cat", "/var/lib/fleetguard/agent.key")
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	return pair, pair.Certificate[0]
}

func (h *harness) heartbeat(t *testing.T, serverID string, client *http.Client, hdr map[string]string) int {
	t.Helper()
	b, _ := json.Marshal(api.Heartbeat{ServerID: serverID, AgentVersion: "e2e", BootID: "e2e-boot", UptimeSec: 1, SentAt: time.Now().UTC()})
	req, err := http.NewRequest(http.MethodPost, "https://"+agentHost+"/v1/heartbeat", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestClientSuppliedCertHeaderIsStrippedByCaddy(t *testing.T) {
	h := getStack(t)
	serverID := h.enrolledAgent(t)
	pair, der := h.agentCert(t)
	fleetCA := h.fleetCAPool(t)

	noCert := &http.Client{Timeout: 20 * time.Second, Transport: h.transport(agentHost, fleetCA, nil)}
	withCert := &http.Client{Timeout: 20 * time.Second, Transport: h.transport(agentHost, fleetCA, func() (*tls.Certificate, error) { return &pair, nil })}
	valid := base64.StdEncoding.EncodeToString(der)

	// Control: the genuine agent, presenting its certificate in the handshake,
	// is accepted. Without this the rejections below prove nothing.
	if got := h.heartbeat(t, serverID, withCert, nil); got != http.StatusOK {
		t.Fatalf("control heartbeat with the real client certificate = %d, want 200", got)
	}

	// No client certificate, but a header carrying a certificate that would
	// authenticate if it reached the backend (here the agent's own public
	// certificate, the best forgery an outsider can make). It must not.
	for name, hdr := range map[string]map[string]string{
		"valid certificate in the header":                    {api.AgentCertHeader: valid},
		"valid certificate plus a guess at the proxy secret": {api.AgentCertHeader: valid, "X-Proxy-Auth": "guess"},
		"garbage in the header":                              {api.AgentCertHeader: "AAAA"},
	} {
		if got := h.heartbeat(t, serverID, noCert, hdr); got != http.StatusUnauthorized {
			t.Errorf("heartbeat with no client certificate and %s = %d, want 401", name, got)
		}
	}

	// A real handshake certificate with forged headers: Caddy must replace both
	// headers, so the request authenticates as the handshake says and the
	// bogus proxy secret never reaches the backend (which would answer 401).
	forged := map[string]string{api.AgentCertHeader: "AAAA", "X-Proxy-Auth": "bogus", "X-Real-IP": "203.0.113.9"}
	if got := h.heartbeat(t, serverID, withCert, forged); got != http.StatusOK {
		t.Errorf("heartbeat with a real certificate and forged headers = %d, want 200 (Caddy must overwrite them)", got)
	}

	// A certificate from another CA is refused in the handshake itself:
	// verify_if_given verifies whatever is presented.
	rogue := rogueCert(t)
	rogueClient := &http.Client{Timeout: 20 * time.Second, Transport: h.transport(agentHost, fleetCA, func() (*tls.Certificate, error) { return &rogue, nil })}
	b, _ := json.Marshal(api.Heartbeat{ServerID: serverID, AgentVersion: "e2e", BootID: "e2e-boot", SentAt: time.Now().UTC()})
	if resp, err := rogueClient.Post("https://"+agentHost+"/v1/heartbeat", "application/json", bytes.NewReader(b)); err == nil {
		_ = resp.Body.Close()
		t.Errorf("a client certificate from another CA was admitted: %d", resp.StatusCode)
	}

	// The agent origin presents the fleet-CA certificate, which is not a
	// browser-trusted one: system roots (here, Caddy's local CA) must not verify it.
	if _, err := (&http.Client{Timeout: 20 * time.Second, Transport: h.transport(agentHost, h.caddyCA, nil)}).Get("https://" + agentHost + "/v1/"); err == nil {
		t.Error("the agent origin's certificate verified against the dashboard's CA")
	}
}

func (h *harness) fleetCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	if h.fleetCA == nil {
		resp, body := h.dashDo(t, http.MethodGet, "/ca.crt", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /ca.crt = %d", resp.StatusCode)
		}
		h.fleetCA = x509.NewCertPool()
		h.fleetCA.AppendCertsFromPEM(body)
	}
	return h.fleetCA
}

func rogueCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rogue"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAgentSurvivesBackendRestart(t *testing.T) {
	h := getStack(t)
	id := h.enrolledAgent(t)
	before := h.row(t, id)

	if out, err := h.compose("restart", "server"); err != nil {
		t.Fatalf("restart server: %v\n%s", err, out)
	}
	// The session survives (it is in the database), but wait for the backend.
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := h.dash.Get("https://" + dashHost + "/api/me")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			h.dumpLogs(t)
			t.Fatalf("backend did not come back after restart: %v", err)
		}
		time.Sleep(time.Second)
	}

	// Back online means a heartbeat newer than the one seen before the restart,
	// within two poll intervals plus the agent's first retry backoff.
	limit := 2*pollInterval + 15*time.Second
	deadline = time.Now().Add(limit)
	for {
		r := h.row(t, id)
		if r.Online && r.LastSeenAt != nil && before.LastSeenAt != nil && *r.LastSeenAt > *before.LastSeenAt {
			return
		}
		if time.Now().After(deadline) {
			h.dumpLogs(t)
			t.Fatalf("agent did not heartbeat again within %s of the backend restart: before=%+v now=%+v", limit, before, r)
		}
		time.Sleep(2 * time.Second)
	}
}

// tokenOf extracts the --token= value from an install command.
func tokenOf(cmd string) string {
	for _, f := range strings.Fields(cmd) {
		if v, ok := strings.CutPrefix(f, "--token="); ok {
			return v
		}
	}
	return ""
}
