// Command fleetguard-server is the FleetGuard backend. It serves the agent API
// (/v1/) and the admin API (/api/) on one loopback listener behind the reverse
// proxy, which is the only process with a public listener.
//
// Configuration comes from the environment:
//
//	FG_DSN                  Postgres connection string (required)
//	FG_BASE_URL             public https origin of the dashboard (required)
//	FG_PROXY_SECRET         shared secret the proxy adds to every request (required)
//	FG_LISTEN               listen address, default 127.0.0.1:8080; must be loopback
//	FG_ALLOW_PUBLIC_LISTEN  set to 1 to allow a non-loopback FG_LISTEN
//	FG_STATE_DIR            CA directory, default /var/lib/fleetguard; the certificate pair for the
//	                        proxy goes in its proxy/ subdirectory
//	FG_AGENT_URL            agent origin on a different host from FG_BASE_URL (required); its host
//	                        gets the fleet-CA server certificate
//	FG_BOOTSTRAP_USER, FG_BOOTSTRAP_PASSWORD
//	                        create the first administrator if none exists
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/makhammatovb/fleetguard/internal/server/auth"
	"github.com/makhammatovb/fleetguard/internal/server/ca"
	"github.com/makhammatovb/fleetguard/internal/server/httpapi"
	"github.com/makhammatovb/fleetguard/internal/server/store"
)

const (
	defaultListen   = "127.0.0.1:8080"
	defaultStateDir = "/var/lib/fleetguard"
	// proxyDirName is the subdirectory of the state directory the reverse proxy
	// may read: the agent certificate pair and a public copy of ca.crt. ca.key
	// stays in the state directory itself, readable by the server alone.
	proxyDirName = "proxy"
)

type config struct {
	DSN               string
	Listen            string
	BaseURL           string
	AgentURL          string
	StateDir          string
	ProxySecret       string
	AgentHostname     string // host of AgentURL; the agent server certificate is issued for it
	BootstrapUser     string
	BootstrapPassword string
}

// loadConfig reads and validates the environment. Every refusal names the
// variable at fault, so a misconfigured start explains itself instead of
// panicking later.
func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		DSN:               getenv("FG_DSN"),
		Listen:            getenv("FG_LISTEN"),
		BaseURL:           getenv("FG_BASE_URL"),
		AgentURL:          getenv("FG_AGENT_URL"),
		StateDir:          getenv("FG_STATE_DIR"),
		ProxySecret:       getenv("FG_PROXY_SECRET"),
		BootstrapUser:     getenv("FG_BOOTSTRAP_USER"),
		BootstrapPassword: getenv("FG_BOOTSTRAP_PASSWORD"),
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.StateDir == "" {
		cfg.StateDir = defaultStateDir
	}
	if cfg.DSN == "" {
		return config{}, errors.New("FG_DSN is required")
	}
	if cfg.ProxySecret == "" {
		return config{}, errors.New("FG_PROXY_SECRET is required: the reverse proxy and this server share it, and without it any local process could reach the API")
	}
	if cfg.BaseURL == "" {
		return config{}, errors.New("FG_BASE_URL is required")
	}
	if cfg.AgentURL == "" {
		return config{}, errors.New("FG_AGENT_URL is required: the agent origin, on a different host from FG_BASE_URL, e.g. https://agents.example.com")
	}
	base, err := originHost("FG_BASE_URL", cfg.BaseURL)
	if err != nil {
		return config{}, err
	}
	agent, err := originHost("FG_AGENT_URL", cfg.AgentURL)
	if err != nil {
		return config{}, err
	}
	// The dashboard presents a browser-trusted ACME certificate; the agent
	// origin must present one from the fleet CA, which agents pin with no
	// fallback. One host cannot present both, so a shared host would enrol
	// agents that then never connect.
	if strings.EqualFold(base, agent) {
		return config{}, fmt.Errorf("FG_AGENT_URL and FG_BASE_URL must have a different host (both are %q): the dashboard needs a browser-trusted certificate and the agent origin needs one issued by the fleet CA, which a single hostname cannot present", base)
	}
	cfg.AgentHostname = agent
	if (cfg.BootstrapUser == "") != (cfg.BootstrapPassword == "") {
		return config{}, errors.New("FG_BOOTSTRAP_USER and FG_BOOTSTRAP_PASSWORD must be set together")
	}
	if err := httpapi.CheckListenAddr(cfg.Listen, getenv("FG_ALLOW_PUBLIC_LISTEN") == "1"); err != nil {
		return config{}, fmt.Errorf("FG_LISTEN: %w", err)
	}
	return cfg, nil
}

// originHost returns the host of an https origin, or an error naming the
// variable. The value is interpolated into an install command an admin pastes
// into a root shell, and the install script is the agent's only root of trust,
// so anything but a bare https origin (optional port, optional trailing slash)
// is refused: no plaintext, path, userinfo, query, fragment or shell-significant
// characters.
func originHost(name, raw string) (string, error) {
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%s %q must be a bare https origin such as https://fleet.example.com (%s)", name, raw, why)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return bad("not a URL")
	case u.Scheme != "https":
		return bad("scheme must be https")
	case u.Hostname() == "":
		return bad("no host")
	case u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "", u.User != nil, u.Opaque != "":
		return bad("no path, userinfo, query or fragment allowed")
	case strings.Trim(u.Hostname(), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != "":
		return bad("host may contain only letters, digits, dots and hyphens")
	case strings.TrimRight(u.Port(), "0123456789") != "":
		return bad("invalid port")
	}
	return u.Hostname(), nil
}

func main() {
	lg := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(lg); err != nil {
		lg.Error("fleetguard-server: fatal", "err", err)
		os.Exit(1)
	}
}

func run(lg *slog.Logger) error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DSN)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	authority, err := ca.LoadOrCreate(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("certificate authority: %w", err)
	}
	// The agent pins this CA as its only trust root, so the proxy's certificate
	// for the agent hostname must come from it, not from ACME.
	proxyDir := filepath.Join(cfg.StateDir, proxyDirName)
	issued, err := authority.EnsureServerCert(proxyDir, cfg.AgentHostname, time.Now())
	if err != nil {
		return fmt.Errorf("agent server certificate: %w", err)
	}
	if issued {
		lg.Info("issued agent server certificate; restart the reverse proxy to load it", "hostname", cfg.AgentHostname, "dir", proxyDir)
	} else {
		lg.Info("agent server certificate is current", "hostname", cfg.AgentHostname)
	}

	svc := auth.New(st)
	if err := bootstrapAdmin(ctx, svc, cfg, lg); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", httpapi.NewAgentRouter(st, authority, cfg.ProxySecret, lg))
	mux.Handle("/api/", httpapi.NewAdminRouterAt(st, svc, httpapi.Origins{Dashboard: cfg.BaseURL, Agent: cfg.AgentURL}, cfg.ProxySecret, lg, time.Now))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	lg.Info("fleetguard-server listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	lg.Info("fleetguard-server stopped")
	return nil
}

// bootstrapAdmin creates the first administrator when the bootstrap variables
// are set. auth.Bootstrap refuses when an administrator already exists, which
// is logged as the normal case on every start after the first.
func bootstrapAdmin(ctx context.Context, svc *auth.Service, cfg config, lg *slog.Logger) error {
	if cfg.BootstrapUser == "" {
		return nil
	}
	err := svc.Bootstrap(ctx, cfg.BootstrapUser, cfg.BootstrapPassword)
	switch {
	case errors.Is(err, auth.ErrAdminsExist):
		lg.Info("bootstrap skipped: an administrator already exists")
	case err != nil:
		return fmt.Errorf("bootstrap administrator: %w", err)
	default:
		lg.Info("bootstrap created the first administrator", "username", cfg.BootstrapUser)
	}
	return nil
}
