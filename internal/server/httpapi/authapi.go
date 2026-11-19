package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/auth"
	"github.com/makhammatovb/fleetguard/internal/server/store"
)

const (
	// SessionCookie is the name of the session cookie.
	SessionCookie = "fg_session"

	// attemptsPerMinute limits login attempts per username and, separately,
	// per source IP: rotating usernames cannot dodge the IP limit and rotating
	// addresses cannot dodge the per-account limit. Registration shares the
	// per-IP figure.
	attemptsPerMinute = 10

	// maxLimiterKeyLen bounds the memory one attacker-chosen username can take.
	maxLimiterKeyLen = 128
)

type userCtxKey struct{}

// UserFromContext returns the user RequireUser authenticated for the request.
func UserFromContext(ctx context.Context) (auth.User, bool) {
	u, ok := ctx.Value(userCtxKey{}).(auth.User)
	return u, ok
}

type authAPI struct {
	st           *store.Store
	svc          *auth.Service
	lg           *slog.Logger
	now          func() time.Time
	origin       string
	loginByUser  *RateLimiter
	loginByIP    *RateLimiter
	registerByIP *RateLimiter
}

// NewAdminRouter serves the human-facing API: registration, sign-in and user
// administration. baseURL is the public origin of the dashboard; browsers
// sending a different Origin on a state-changing request are refused.
func NewAdminRouter(st *store.Store, svc *auth.Service, baseURL string) http.Handler {
	return NewAdminRouterAt(st, svc, baseURL, slog.Default(), time.Now)
}

// NewAdminRouterAt is NewAdminRouter with an injectable logger and clock.
func NewAdminRouterAt(st *store.Store, svc *auth.Service, baseURL string, lg *slog.Logger, now func() time.Time) http.Handler {
	a := &authAPI{
		st: st, svc: svc, lg: lg, now: now,
		origin:       strings.TrimRight(baseURL, "/"),
		loginByUser:  NewRateLimiter(attemptsPerMinute),
		loginByIP:    NewRateLimiter(attemptsPerMinute),
		registerByIP: NewRateLimiter(attemptsPerMinute),
	}
	requireUser := RequireUser(svc, lg, now)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", a.register)
	mux.HandleFunc("POST /api/login", a.login)
	mux.Handle("POST /api/logout", requireUser(http.HandlerFunc(a.logout)))
	mux.Handle("GET /api/me", requireUser(http.HandlerFunc(a.me)))
	mux.Handle("GET /api/users", requireUser(RequireAdmin(http.HandlerFunc(a.listUsers))))
	mux.Handle("POST /api/users/{id}/activate", requireUser(RequireAdmin(http.HandlerFunc(a.activate))))
	return a.sameOrigin(mux)
}

// sameOrigin refuses a state-changing request whose Origin header names another
// site. It backs up SameSite=Lax; requests with no Origin (non-browser clients)
// pass, since they carry no ambient cookie to abuse.
func (a *authAPI) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if o := r.Header.Get("Origin"); o != "" && o != a.origin {
				a.lg.Warn("httpapi: cross-origin request refused", "path", r.URL.Path, "origin", o)
				writeError(w, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUser authenticates the request from its session cookie and stores the
// user in the request context. It answers 401 otherwise.
func RequireUser(svc *auth.Service, lg *slog.Logger, now func() time.Time) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(SessionCookie)
			if err != nil {
				writeError(w, http.StatusUnauthorized)
				return
			}
			u, err := svc.Session(r.Context(), c.Value, now())
			if errors.Is(err, auth.ErrUnauthenticated) {
				writeError(w, http.StatusUnauthorized)
				return
			}
			if err != nil {
				lg.Error("httpapi: session lookup failed", "err", err)
				writeError(w, http.StatusInternalServerError)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userCtxKey{}, u)))
		})
	}
}

// RequireAdmin answers 403 unless the authenticated user is an administrator.
// It must be wrapped by RequireUser; with no user in the context it answers 401.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized)
			return
		}
		if u.Role != auth.RoleAdmin {
			writeError(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// sourceIP is the peer address. Behind a reverse proxy this is the proxy's
// address unless the deployment makes the proxy the only peer and rewrites it;
// it is deliberately not read from X-Forwarded-For, which a client can forge to
// sidestep the limit.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *authAPI) register(w http.ResponseWriter, r *http.Request) {
	if !a.registerByIP.Allow(sourceIP(r), a.now()) {
		writeError(w, http.StatusTooManyRequests)
		return
	}
	var c credentials
	if status := decodeBody(w, r, &c, a.lg); status != 0 {
		writeError(w, status)
		return
	}
	err := a.svc.Register(r.Context(), c.Username, c.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidInput):
		writeError(w, http.StatusBadRequest)
	case err != nil:
		a.lg.Error("httpapi: register failed", "err", err)
		writeError(w, http.StatusInternalServerError)
	default:
		// Identical whether the account was created or the name was taken.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending activation"})
	}
}

func (a *authAPI) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if status := decodeBody(w, r, &c, a.lg); status != 0 {
		writeError(w, status)
		return
	}
	now := a.now()
	key := strings.ToLower(strings.TrimSpace(c.Username))
	if len(key) > maxLimiterKeyLen {
		key = key[:maxLimiterKeyLen]
	}
	// Spend both buckets before deciding, so a denial on one does not let an
	// attacker probe the other for free.
	byUser := a.loginByUser.Allow(key, now)
	byIP := a.loginByIP.Allow(sourceIP(r), now)
	if !byUser || !byIP {
		a.lg.Warn("httpapi: login rate limited", "ip", sourceIP(r), "by_user", !byUser, "by_ip", !byIP)
		writeError(w, http.StatusTooManyRequests)
		return
	}
	token, err := a.svc.Login(r.Context(), c.Username, c.Password, now)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		a.lg.Info("httpapi: login failed", "ip", sourceIP(r))
		writeError(w, http.StatusUnauthorized)
		return
	}
	if err != nil {
		a.lg.Error("httpapi: login failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/",
		MaxAge:   int(auth.SessionTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *authAPI) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		if err := a.svc.Logout(r.Context(), c.Value); err != nil {
			a.lg.Error("httpapi: logout failed", "err", err)
			writeError(w, http.StatusInternalServerError)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

type userDTO struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ActivatedBy *string    `json:"activated_by,omitempty"`
}

func toDTO(u auth.User) userDTO {
	return userDTO{u.ID, u.Username, u.Role, u.IsActive, u.CreatedAt, u.ActivatedAt, u.ActivatedBy}
}

func (a *authAPI) me(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFromContext(r.Context())
	writeJSON(w, http.StatusOK, toDTO(u))
}

func (a *authAPI) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.st.ListUsers(r.Context())
	if err != nil {
		a.lg.Error("httpapi: list users failed", "err", err)
		writeError(w, http.StatusInternalServerError)
		return
	}
	out := make([]userDTO, 0, len(users))
	for _, u := range users {
		out = append(out, toDTO(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *authAPI) activate(w http.ResponseWriter, r *http.Request) {
	admin, _ := UserFromContext(r.Context())
	body := struct {
		Role string `json:"role"`
	}{Role: auth.RoleUser} // least privilege unless an admin says otherwise
	if r.ContentLength != 0 {
		if status := decodeBody(w, r, &body, a.lg); status != 0 {
			writeError(w, status)
			return
		}
	}
	err := a.svc.Activate(r.Context(), admin.ID, r.PathValue("id"), body.Role)
	switch {
	case errors.Is(err, auth.ErrInvalidInput):
		writeError(w, http.StatusBadRequest)
	case errors.Is(err, auth.ErrForbidden):
		writeError(w, http.StatusForbidden)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound)
	case err != nil:
		a.lg.Error("httpapi: activate failed", "err", err)
		writeError(w, http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
