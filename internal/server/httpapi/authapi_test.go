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
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/internal/server/auth"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/internal/server/store"
)

const (
	baseURL  = "https://fleet.example.test"
	agentURL = "https://agents.example.test"
	userPW   = "correct horse battery staple" //nolint:gosec // test fixture
)

type adminEnv struct {
	st  *store.Store
	svc *auth.Service
	h   http.Handler
	now time.Time
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	st := store.NewTestDB(t)
	svc := auth.New(st)
	e := &adminEnv{st: st, svc: svc, now: time.Now()}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	e.h = httpapi.NewAdminRouterAt(st, svc, httpapi.Origins{Dashboard: baseURL, Agent: agentURL}, proxySecret, lg, func() time.Time { return e.now })
	return e
}

func (e *adminEnv) do(method, path, body, cookie, remote string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = remote
	if remote == "" {
		r.RemoteAddr = "192.0.2.1:1234"
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "fg_session", Value: cookie}) //nolint:gosec // request cookie in a test client
	}
	r.Header.Set(httpapi.ProxyAuthHeader, proxySecret)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func creds(u, p string) string { return fmt.Sprintf(`{"username":%q,"password":%q}`, u, p) }

// makeUser registers a user and activates it with the given role, returning
// its name and ID.
func (e *adminEnv) makeUser(t *testing.T, role string) (name, id string) {
	t.Helper()
	ctx := context.Background()
	name = "u-" + uuid.NewString()
	if err := e.svc.Register(ctx, name, userPW); err != nil {
		t.Fatal(err)
	}
	u, _, err := e.st.GetLoginRecord(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	adm, err := e.st.CreateUser(ctx, "a-"+uuid.NewString(), "x", "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Activate(ctx, adm.ID, u.ID, role); err != nil {
		t.Fatal(err)
	}
	return name, u.ID
}

// loginCookie signs in over HTTP and returns the session cookie value.
func (e *adminEnv) loginCookie(t *testing.T, name string) string {
	t.Helper()
	w := e.do("POST", "/api/login", creds(name, userPW), "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "fg_session" {
			return c.Value
		}
	}
	t.Fatal("no fg_session cookie")
	return ""
}

func TestRegisterAlwaysAccepted(t *testing.T) {
	e := newAdminEnv(t)
	name := "u-" + uuid.NewString()
	first := e.do("POST", "/api/register", creds(name, userPW), "", "")
	second := e.do("POST", "/api/register", creds(name, "another long password"), "", "")
	if first.Code != 202 || second.Code != 202 {
		t.Fatalf("codes %d, %d; want 202, 202", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("bodies differ: %q vs %q", first.Body, second.Body)
	}
	var n int
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM users WHERE username = $1`, name).Scan(&n)
	if n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
}

func TestRegisterBadBody(t *testing.T) {
	e := newAdminEnv(t)
	if w := e.do("POST", "/api/register", `{nope`, "", ""); w.Code != 400 {
		t.Fatalf("malformed = %d", w.Code)
	}
	if w := e.do("POST", "/api/register", creds("x", "short"), "", ""); w.Code != 400 {
		t.Fatalf("invalid = %d", w.Code)
	}
}

func TestLoginSetsHardenedCookie(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	w := e.do("POST", "/api/login", creds(name, userPW), "", "")
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	var c *http.Cookie
	for _, x := range w.Result().Cookies() {
		if x.Name == "fg_session" {
			c = x
		}
	}
	if c == nil {
		t.Fatal("no cookie")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("cookie not hardened: %+v", c)
	}
	if c.MaxAge != 7*24*3600 {
		t.Fatalf("MaxAge = %d", c.MaxAge)
	}
	if strings.Contains(w.Body.String(), c.Value) {
		t.Fatal("session token leaked into the response body")
	}
}

func TestLoginFailureIsGeneric(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	unknown := e.do("POST", "/api/login", creds("u-"+uuid.NewString(), userPW), "", "")
	wrong := e.do("POST", "/api/login", creds(name, "wrong password!!"), "", "")
	for _, w := range []*httptest.ResponseRecorder{unknown, wrong} {
		if w.Code != 401 || w.Body.String() != `{"error":"Unauthorized"}`+"\n" {
			t.Fatalf("got %d %q", w.Code, w.Body)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("failed login set a cookie")
		}
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newAdminEnv(t)
	name := "u-" + uuid.NewString()
	for i := 1; i <= 10; i++ {
		// Rotate source addresses: the per-username limit must still bite.
		w := e.do("POST", "/api/login", creds(name, "wrong password!!"), "", fmt.Sprintf("198.51.100.%d:1", i))
		if w.Code != 401 {
			t.Fatalf("attempt %d = %d, want 401", i, w.Code)
		}
	}
	if w := e.do("POST", "/api/login", creds(name, "wrong password!!"), "", "198.51.100.99:1"); w.Code != 429 {
		t.Fatalf("11th attempt for one username = %d, want 429", w.Code)
	}
}

func TestLoginRateLimitedPerSourceIP(t *testing.T) {
	e := newAdminEnv(t)
	for i := 1; i <= 10; i++ {
		// Rotate usernames: the per-IP limit must still bite.
		w := e.do("POST", "/api/login", creds("u-"+uuid.NewString(), "wrong password!!"), "", "203.0.113.7:9")
		if w.Code != 401 {
			t.Fatalf("attempt %d = %d, want 401", i, w.Code)
		}
	}
	if w := e.do("POST", "/api/login", creds("u-"+uuid.NewString(), "wrong password!!"), "", "203.0.113.7:9"); w.Code != 429 {
		t.Fatalf("11th attempt from one IP = %d, want 429", w.Code)
	}
	if w := e.do("POST", "/api/login", creds("u-"+uuid.NewString(), "wrong password!!"), "", "203.0.113.8:9"); w.Code != 401 {
		t.Fatalf("another IP = %d, want 401", w.Code)
	}
}

func TestLoginRateLimitRecovers(t *testing.T) {
	e := newAdminEnv(t)
	name := "u-" + uuid.NewString()
	for range 11 {
		e.do("POST", "/api/login", creds(name, "wrong password!!"), "", "")
	}
	e.now = e.now.Add(2 * time.Minute)
	if w := e.do("POST", "/api/login", creds(name, "wrong password!!"), "", ""); w.Code != 401 {
		t.Fatalf("after a minute = %d, want 401", w.Code)
	}
}

func TestMeRequiresSession(t *testing.T) {
	e := newAdminEnv(t)
	if w := e.do("GET", "/api/me", "", "", ""); w.Code != 401 {
		t.Fatalf("no cookie = %d", w.Code)
	}
	if w := e.do("GET", "/api/me", "", "bogus", ""); w.Code != 401 {
		t.Fatalf("bogus cookie = %d", w.Code)
	}
	name, id := e.makeUser(t, "user")
	w := e.do("GET", "/api/me", "", e.loginCookie(t, name), "")
	if w.Code != 200 {
		t.Fatalf("me = %d", w.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["id"] != id || got["username"] != name || got["role"] != "user" {
		t.Fatalf("me = %v", got)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "hash") || strings.Contains(w.Body.String(), "argon2") {
		t.Fatalf("me leaks credentials: %s", w.Body)
	}
}

func TestLogoutEndsSession(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	ck := e.loginCookie(t, name)
	w := e.do("POST", "/api/logout", "", ck, "")
	if w.Code != 204 {
		t.Fatalf("logout = %d", w.Code)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "fg_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the cookie")
	}
	if w := e.do("GET", "/api/me", "", ck, ""); w.Code != 401 {
		t.Fatalf("me after logout = %d", w.Code)
	}
}

func TestSessionExpiresOverHTTP(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	ck := e.loginCookie(t, name)
	e.now = e.now.Add(8 * 24 * time.Hour)
	if w := e.do("GET", "/api/me", "", ck, ""); w.Code != 401 {
		t.Fatalf("expired session = %d", w.Code)
	}
}

func TestUsersListAndActivateRequireAdmin(t *testing.T) {
	e := newAdminEnv(t)
	userName, _ := e.makeUser(t, "user")
	adminName, _ := e.makeUser(t, "admin")
	pendingName := "u-" + uuid.NewString()
	e.do("POST", "/api/register", creds(pendingName, userPW), "", "")
	pending, _, _ := e.st.GetLoginRecord(context.Background(), pendingName)
	activate := "/api/users/" + pending.ID + "/activate"

	if w := e.do("GET", "/api/users", "", "", ""); w.Code != 401 {
		t.Fatalf("anonymous list = %d", w.Code)
	}
	if w := e.do("POST", activate, `{"role":"user"}`, "", ""); w.Code != 401 {
		t.Fatalf("anonymous activate = %d", w.Code)
	}
	userCk := e.loginCookie(t, userName)
	if w := e.do("GET", "/api/users", "", userCk, ""); w.Code != 403 {
		t.Fatalf("user list = %d, want 403", w.Code)
	}
	if w := e.do("POST", activate, `{"role":"user"}`, userCk, ""); w.Code != 403 {
		t.Fatalf("user activate = %d, want 403", w.Code)
	}
	if u, _ := e.st.GetUser(context.Background(), pending.ID); u.IsActive {
		t.Fatal("a user-role caller activated an account")
	}

	adminCk := e.loginCookie(t, adminName)
	w := e.do("GET", "/api/users", "", adminCk, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), pendingName) {
		t.Fatalf("admin list = %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "argon2") {
		t.Fatal("user list leaks password hashes")
	}
	if w := e.do("POST", activate, `{"role":"user"}`, adminCk, ""); w.Code != 204 {
		t.Fatalf("admin activate = %d", w.Code)
	}
	if w := e.do("POST", "/api/login", creds(pendingName, userPW), "", ""); w.Code != 200 {
		t.Fatalf("activated user login = %d", w.Code)
	}
}

func TestActivateEdgeCases(t *testing.T) {
	e := newAdminEnv(t)
	adminName, _ := e.makeUser(t, "admin")
	ck := e.loginCookie(t, adminName)
	if w := e.do("POST", "/api/users/"+uuid.NewString()+"/activate", `{"role":"user"}`, ck, ""); w.Code != 404 {
		t.Fatalf("unknown id = %d", w.Code)
	}
	if w := e.do("POST", "/api/users/not-a-uuid/activate", `{"role":"user"}`, ck, ""); w.Code != 404 {
		t.Fatalf("bad id = %d", w.Code)
	}
	name := "u-" + uuid.NewString()
	e.do("POST", "/api/register", creds(name, userPW), "", "")
	u, _, _ := e.st.GetLoginRecord(context.Background(), name)
	if w := e.do("POST", "/api/users/"+u.ID+"/activate", `{"role":"root"}`, ck, ""); w.Code != 400 {
		t.Fatalf("bad role = %d", w.Code)
	}
}

func TestStateChangingRequestsRejectForeignOrigin(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	ck := e.loginCookie(t, name)
	if w := e.do("POST", "/api/logout", "", ck, "", "Origin", "https://evil.example"); w.Code != 403 {
		t.Fatalf("foreign origin = %d, want 403", w.Code)
	}
	if w := e.do("GET", "/api/me", "", ck, ""); w.Code != 200 {
		t.Fatal("session was destroyed by a cross-origin request")
	}
	if w := e.do("POST", "/api/logout", "", ck, "", "Origin", baseURL); w.Code != 204 {
		t.Fatalf("same origin = %d, want 204", w.Code)
	}
}

func TestAdminAPIRequiresProxySecret(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	for _, secret := range []string{"", "wrong-secret"} {
		for _, rt := range [][2]string{
			{"POST", "/api/login"}, {"POST", "/api/register"}, {"GET", "/api/me"},
			{"GET", "/api/users"}, {"POST", "/api/logout"},
		} {
			w := e.do(rt[0], rt[1], creds(name, userPW), "", "", httpapi.ProxyAuthHeader, secret)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with secret %q = %d, want 401", rt[0], rt[1], secret, w.Code)
			}
		}
	}
}

func TestClientAddressComesFromXRealIP(t *testing.T) {
	e := newAdminEnv(t)
	attempt := func(realIP string) int {
		return e.do("POST", "/api/login", creds("u-"+uuid.NewString(), "wrong password!!"), "",
			"192.0.2.50:1", "X-Real-IP", realIP).Code
	}
	for i := 1; i <= 10; i++ {
		if c := attempt("198.51.100.1"); c != 401 {
			t.Fatalf("attempt %d = %d, want 401", i, c)
		}
	}
	if c := attempt("198.51.100.1"); c != 429 {
		t.Fatalf("11th attempt from one X-Real-IP = %d, want 429", c)
	}
	// Same proxy peer, different browser: a separate bucket.
	if c := attempt("198.51.100.2"); c != 401 {
		t.Fatalf("different X-Real-IP = %d, want 401 (browsers must not share a bucket)", c)
	}
}

func TestBusyHashingReturns503(t *testing.T) {
	st := store.NewTestDB(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	svc := auth.New(st, auth.WithMaxConcurrentHashes(1), auth.WithHashObserver(func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}))
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := httpapi.NewAdminRouterAt(st, svc, httpapi.Origins{Dashboard: baseURL, Agent: agentURL}, proxySecret, lg, time.Now)
	post := func(i int) int {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(creds("u-"+uuid.NewString(), "wrong password!!")))
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1", i)
		r.Header.Set(httpapi.ProxyAuthHeader, proxySecret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	first := make(chan int, 1)
	go func() { first <- post(1) }()
	select { // request 1 now holds the only slot, and stays there until released
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the first login never reached the hashing slot")
	}

	if c := post(2); c != http.StatusServiceUnavailable {
		t.Fatalf("login while the only hashing slot is busy = %d, want 503", c)
	}
	r := httptest.NewRequest("POST", "/api/register", strings.NewReader(creds("u-"+uuid.NewString(), userPW)))
	r.Header.Set(httpapi.ProxyAuthHeader, proxySecret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("register while busy = %d, want 503", w.Code)
	}
	close(release)
	if c := <-first; c != http.StatusUnauthorized {
		t.Fatalf("the held login finished with %d, want 401", c)
	}
	if c := post(3); c != http.StatusUnauthorized {
		t.Fatalf("login after release = %d, want 401", c)
	}
}

func TestLogoutClearsCookieEvenWhenSessionIsGone(t *testing.T) {
	e := newAdminEnv(t)
	name, _ := e.makeUser(t, "user")
	ck := e.loginCookie(t, name)
	e.now = e.now.Add(8 * 24 * time.Hour) // the session has expired
	for _, cookie := range []string{ck, "garbage", ""} {
		w := e.do("POST", "/api/logout", "", cookie, "")
		if w.Code != http.StatusNoContent {
			t.Fatalf("logout with cookie %q = %d, want 204", cookie, w.Code)
		}
		cleared := false
		for _, c := range w.Result().Cookies() {
			if c.Name == "fg_session" && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatalf("logout with cookie %q did not clear the cookie", cookie)
		}
	}
}
