package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/pkg/api"
)

// fleetEnv is an admin router and an agent router over one database and CA.
type fleetEnv struct {
	*adminEnv
	agent *httptest.Server
	ca    *ca.CA
}

func newFleetEnv(t *testing.T) *fleetEnv {
	t.Helper()
	a := newAdminEnv(t)
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(httpapi.NewAgentRouter(a.st, authority, proxySecret, lg))
	t.Cleanup(srv.Close)
	return &fleetEnv{adminEnv: a, agent: srv, ca: authority}
}

func (e *fleetEnv) adminCookie(t *testing.T) string {
	t.Helper()
	name, _ := e.makeUser(t, "admin")
	return e.loginCookie(t, name)
}

func (e *fleetEnv) userCookie(t *testing.T) string {
	t.Helper()
	name, _ := e.makeUser(t, "user")
	return e.loginCookie(t, name)
}

type createdServer struct {
	Server struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Note string `json:"note"`
	} `json:"server"`
	InstallCommand string    `json:"install_command"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

func (e *fleetEnv) createServer(t *testing.T, cookie string) createdServer {
	t.Helper()
	name := "srv-" + uuid.NewString()
	w := e.do("POST", "/api/servers", fmt.Sprintf(`{"name":%q,"note":"rack 4"}`, name), cookie, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	var out createdServer
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func tokenFromCommand(t *testing.T, cmd string) string {
	t.Helper()
	_, rest, ok := strings.Cut(cmd, "--token=")
	if !ok {
		t.Fatalf("no --token= in %q", cmd)
	}
	tok, _, _ := strings.Cut(rest, " ")
	return tok
}

type fleetRow struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Online       bool       `json:"online"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	AgentVersion string     `json:"agent_version"`
}

func (e *fleetEnv) fleet(t *testing.T, cookie string) []fleetRow {
	t.Helper()
	w := e.do("GET", "/api/servers", "", cookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d %s", w.Code, w.Body)
	}
	var rows []fleetRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rows
}

func findRow(rows []fleetRow, id string) *fleetRow {
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}

// enrolOver redeems token against the agent router and returns the cert DER.
func (e *fleetEnv) enrolOver(t *testing.T, token string) []byte {
	t.Helper()
	body, _ := json.Marshal(api.EnrolRequest{Token: token, CSRPEM: newCSR(t), Hostname: "host-1", AgentVersion: "0.0.1"})
	req, _ := http.NewRequest(http.MethodPost, e.agent.URL+"/v1/enrol", strings.NewReader(string(body)))
	req.Header.Set("X-Proxy-Auth", proxySecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enrol = %d", resp.StatusCode)
	}
	var out api.EnrolResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return certDER(t, out.CertPEM)
}

func TestCreateServerReturnsInstallCommandWithToken(t *testing.T) {
	e := newFleetEnv(t)
	out := e.createServer(t, e.adminCookie(t))

	token := tokenFromCommand(t, out.InstallCommand)
	want := "curl -sSL " + baseURL + "/install.sh | sudo bash -s -- --token=" + token + " --server-url=" + baseURL
	if out.InstallCommand != want {
		t.Fatalf("install_command = %q\nwant %q", out.InstallCommand, want)
	}
	id, err := e.st.ConsumeEnrolToken(context.Background(), token, time.Now())
	if err != nil || id != out.Server.ID {
		t.Fatalf("ConsumeEnrolToken = %q, %v; want %q, nil", id, err, out.Server.ID)
	}
	if got := time.Until(out.TokenExpiresAt); got < 59*time.Minute || got > time.Hour+time.Minute {
		t.Fatalf("token_expires_at is %v away, want about 1h", got)
	}
}

func TestCreateServerAuditsWithoutTheToken(t *testing.T) {
	e := newFleetEnv(t)
	out := e.createServer(t, e.adminCookie(t))
	token := tokenFromCommand(t, out.InstallCommand)

	var n int
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'server.created' AND target = $1`, out.Server.ID).Scan(&n)
	if err != nil || n != 1 {
		t.Fatalf("audit rows = %d, %v; want 1", n, err)
	}
	err = e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE detail::text LIKE '%' || $1 || '%' OR target LIKE '%' || $1 || '%'`, token).Scan(&n)
	if err != nil || n != 0 {
		t.Fatalf("token appears in %d audit rows, %v; want 0", n, err)
	}
}

func TestCreateServerRequiresAdmin(t *testing.T) {
	e := newFleetEnv(t)
	w := e.do("POST", "/api/servers", `{"name":"x-`+uuid.NewString()+`"}`, e.userCookie(t), "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	w = e.do("POST", "/api/servers", `{"name":"x"}`, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie status = %d, want 401", w.Code)
	}
}

func TestCreateServerValidatesAndReportsDuplicates(t *testing.T) {
	e := newFleetEnv(t)
	cookie := e.adminCookie(t)
	for _, body := range []string{`{}`, `{"name":"   "}`, `{"name":"` + strings.Repeat("a", 129) + `"}`, `not json`} {
		if w := e.do("POST", "/api/servers", body, cookie, ""); w.Code != http.StatusBadRequest {
			t.Errorf("body %.20q: status = %d, want 400", body, w.Code)
		}
	}
	first := e.createServer(t, cookie)
	w := e.do("POST", "/api/servers", fmt.Sprintf(`{"name":%q}`, first.Server.Name), cookie, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409", w.Code)
	}
	if strings.Contains(w.Body.String(), first.Server.Name) {
		t.Fatalf("error body leaks detail: %s", w.Body)
	}
}

func TestListServersVisibleToPlainUser(t *testing.T) {
	e := newFleetEnv(t)
	created := e.createServer(t, e.adminCookie(t))
	rows := e.fleet(t, e.userCookie(t))
	row := findRow(rows, created.Server.ID)
	if row == nil || row.Name != created.Server.Name {
		t.Fatalf("created server missing from list: %+v", rows)
	}
	if row.Online {
		t.Fatal("never-seen server reported online")
	}
}

func TestListServersRequiresSession(t *testing.T) {
	e := newFleetEnv(t)
	if w := e.do("GET", "/api/servers", "", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestFleetListReportsOnlineFlag(t *testing.T) {
	e := newFleetEnv(t)
	cookie := e.adminCookie(t)
	created := e.createServer(t, cookie)
	der := e.enrolOver(t, tokenFromCommand(t, created.InstallCommand))
	if row := findRow(e.fleet(t, cookie), created.Server.ID); row == nil || row.Online {
		t.Fatalf("before heartbeat: %+v, want present and offline", row)
	}
	resp := heartbeat(t, e.agent.URL, hbBody(created.Server.ID, "boot-1"), der, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat = %d", resp.StatusCode)
	}
	row := findRow(e.fleet(t, cookie), created.Server.ID)
	if row == nil || !row.Online || row.LastSeenAt == nil || row.AgentVersion != "0.0.2" {
		t.Fatalf("after heartbeat: %+v, want online with last_seen_at and version", row)
	}
}

func TestGetServer(t *testing.T) {
	e := newFleetEnv(t)
	created := e.createServer(t, e.adminCookie(t))
	userCookie := e.userCookie(t)

	w := e.do("GET", "/api/servers/"+created.Server.ID, "", userCookie, "")
	var row fleetRow
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &row) != nil || row.ID != created.Server.ID {
		t.Fatalf("get = %d %s", w.Code, w.Body)
	}
	for _, id := range []string{uuid.NewString(), "not-a-uuid"} {
		if w := e.do("GET", "/api/servers/"+id, "", userCookie, ""); w.Code != http.StatusNotFound {
			t.Errorf("id %q: status = %d, want 404", id, w.Code)
		}
	}
	if w := e.do("GET", "/api/servers/"+created.Server.ID, "", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie status = %d, want 401", w.Code)
	}
}

func TestEnrolTokenCanBeReissued(t *testing.T) {
	e := newFleetEnv(t)
	cookie := e.adminCookie(t)
	created := e.createServer(t, cookie)
	first := tokenFromCommand(t, created.InstallCommand)

	w := e.do("POST", "/api/servers/"+created.Server.ID+"/enrol-token", "", cookie, "")
	if w.Code != http.StatusOK {
		t.Fatalf("reissue = %d %s", w.Code, w.Body)
	}
	var re struct {
		InstallCommand string    `json:"install_command"`
		TokenExpiresAt time.Time `json:"token_expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &re); err != nil {
		t.Fatal(err)
	}
	second := tokenFromCommand(t, re.InstallCommand)
	if second == first {
		t.Fatal("reissue returned the same token")
	}

	ctx := context.Background()
	for name, tok := range map[string]string{"second": second, "first": first} {
		id, err := e.st.ConsumeEnrolToken(ctx, tok, time.Now())
		if err != nil || id != created.Server.ID {
			t.Fatalf("%s token: %q, %v; want %q, nil", name, id, err, created.Server.ID)
		}
		if _, err := e.st.ConsumeEnrolToken(ctx, tok, time.Now()); err == nil {
			t.Fatalf("%s token consumed twice", name)
		}
	}
}

func TestEnrolTokenReissueRequiresAdminAndAKnownServer(t *testing.T) {
	e := newFleetEnv(t)
	admin := e.adminCookie(t)
	created := e.createServer(t, admin)
	if w := e.do("POST", "/api/servers/"+created.Server.ID+"/enrol-token", "", e.userCookie(t), ""); w.Code != http.StatusForbidden {
		t.Fatalf("user status = %d, want 403", w.Code)
	}
	if w := e.do("POST", "/api/servers/"+uuid.NewString()+"/enrol-token", "", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown server status = %d, want 404", w.Code)
	}
}

func TestDecommissionBlocksFurtherHeartbeats(t *testing.T) {
	e := newFleetEnv(t)
	cookie := e.adminCookie(t)
	created := e.createServer(t, cookie)
	der := e.enrolOver(t, tokenFromCommand(t, created.InstallCommand))
	if resp := heartbeat(t, e.agent.URL, hbBody(created.Server.ID, "boot-1"), der, true); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-decommission heartbeat = %d, want 200", resp.StatusCode)
	}
	// An unspent token for the same server must die with it.
	pending := tokenFromCommand(t, func() string {
		w := e.do("POST", "/api/servers/"+created.Server.ID+"/enrol-token", "", cookie, "")
		var re struct {
			InstallCommand string `json:"install_command"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &re)
		return re.InstallCommand
	}())

	if w := e.do("POST", "/api/servers/"+created.Server.ID+"/decommission", "", cookie, ""); w.Code != http.StatusNoContent {
		t.Fatalf("decommission = %d %s, want 204", w.Code, w.Body)
	}

	if resp := heartbeat(t, e.agent.URL, hbBody(created.Server.ID, "boot-1"), der, true); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post-decommission heartbeat = %d, want 403", resp.StatusCode)
	}
	if _, err := e.st.ConsumeEnrolToken(context.Background(), pending, time.Now()); err == nil {
		t.Fatal("enrolment token still redeemable after decommission")
	}
	if err := e.st.VerifyEnrolKey(context.Background(), created.Server.ID, "anything"); err == nil {
		t.Fatal("enrol key still verifies after decommission")
	}

	var decommissioned, revoked *time.Time
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT s.decommissioned_at, a.revoked_at FROM servers s JOIN agents a ON a.server_id = s.id WHERE s.id = $1`,
		created.Server.ID).Scan(&decommissioned, &revoked); err != nil {
		t.Fatal(err)
	}
	if decommissioned == nil || revoked == nil {
		t.Fatalf("decommissioned_at = %v, revoked_at = %v; want both set", decommissioned, revoked)
	}
	if findRow(e.fleet(t, cookie), created.Server.ID) != nil {
		t.Fatal("decommissioned server still in the fleet list")
	}
	if w := e.do("GET", "/api/servers/"+created.Server.ID, "", cookie, ""); w.Code != http.StatusNotFound {
		t.Fatalf("get after decommission = %d, want 404", w.Code)
	}
	if w := e.do("POST", "/api/servers/"+created.Server.ID+"/enrol-token", "", cookie, ""); w.Code != http.StatusNotFound {
		t.Fatalf("reissue after decommission = %d, want 404", w.Code)
	}
	if w := e.do("POST", "/api/servers/"+created.Server.ID+"/decommission", "", cookie, ""); w.Code != http.StatusNotFound {
		t.Fatalf("second decommission = %d, want 404", w.Code)
	}

	var n int
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'server.decommissioned' AND target = $1`, created.Server.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("decommission audit rows = %d, %v; want 1", n, err)
	}
}

func TestDecommissionRequiresAdmin(t *testing.T) {
	e := newFleetEnv(t)
	created := e.createServer(t, e.adminCookie(t))
	if w := e.do("POST", "/api/servers/"+created.Server.ID+"/decommission", "", e.userCookie(t), ""); w.Code != http.StatusForbidden {
		t.Fatalf("user status = %d, want 403", w.Code)
	}
	if findRow(e.fleet(t, e.userCookie(t)), created.Server.ID) == nil {
		t.Fatal("server vanished after a refused decommission")
	}
	if w := e.do("POST", "/api/servers/"+uuid.NewString()+"/decommission", "", e.adminCookie(t), ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown server status = %d, want 404", w.Code)
	}
}

func TestDecommissionBeforeEnrolmentStillRevokesTheToken(t *testing.T) {
	e := newFleetEnv(t)
	cookie := e.adminCookie(t)
	created := e.createServer(t, cookie)
	if w := e.do("POST", "/api/servers/"+created.Server.ID+"/decommission", "", cookie, ""); w.Code != http.StatusNoContent {
		t.Fatalf("decommission = %d, want 204", w.Code)
	}
	if _, err := e.st.ConsumeEnrolToken(context.Background(), tokenFromCommand(t, created.InstallCommand), time.Now()); err == nil {
		t.Fatal("token redeemable for a decommissioned server")
	}
}

func TestRefusesNonLoopbackListenWithoutOverride(t *testing.T) {
	refused := []string{"0.0.0.0:8080", ":8080", "[::]:8080", "192.0.2.1:8080", "nonsense", "127.0.0.1", ""}
	for _, addr := range refused {
		if err := httpapi.CheckListenAddr(addr, false); err == nil {
			t.Errorf("CheckListenAddr(%q, false) = nil, want an error", addr)
		}
	}
	allowed := []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "127.0.0.2:9000"}
	for _, addr := range allowed {
		if err := httpapi.CheckListenAddr(addr, false); err != nil {
			t.Errorf("CheckListenAddr(%q, false) = %v, want nil", addr, err)
		}
	}
	if err := httpapi.CheckListenAddr("0.0.0.0:8080", true); err != nil {
		t.Errorf("override: CheckListenAddr(0.0.0.0:8080, true) = %v, want nil", err)
	}
}
