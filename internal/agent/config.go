// Package agent implements the FleetGuard agent's identity, configuration and
// outbound mutual-TLS transport. The agent only ever makes outbound
// connections; nothing in this package listens or accepts.
package agent

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultStateDir holds the agent's identity files.
	DefaultStateDir = "/var/lib/fleetguard"
	// DefaultPollInterval is used when the config file omits poll_interval.
	DefaultPollInterval = 30 * time.Second
)

// Config is the agent's runtime configuration. Only ServerURL and
// PollInterval come from the config file.
type Config struct {
	ServerURL    string
	StateDir     string
	PollInterval time.Duration

	// RootCAs is the trust anchor for the server's TLS certificate when the
	// agent has no ca.crt yet, i.e. during Enrol. Nil means the system roots.
	// Once enrolled, the CA from ca.crt is trusted instead. It is never read
	// from the config file.
	RootCAs *x509.CertPool
}

// fileConfig is the on-disk format: exactly these two keys.
type fileConfig struct {
	ServerURL    string        `yaml:"server_url"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// LoadConfig reads and validates the YAML config file at path.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path) //nolint:gosec // path is the operator-supplied config location
	if err != nil {
		return Config{}, fmt.Errorf("agent: open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	var fc fileConfig
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return Config{}, fmt.Errorf("agent: parse config: %w", err)
	}
	if err := validateServerURL(fc.ServerURL); err != nil {
		return Config{}, err
	}
	if fc.PollInterval < 0 {
		return Config{}, errors.New("agent: poll_interval must not be negative")
	}
	if fc.PollInterval == 0 {
		fc.PollInterval = DefaultPollInterval
	}
	return Config{
		ServerURL:    strings.TrimRight(fc.ServerURL, "/"),
		StateDir:     DefaultStateDir,
		PollInterval: fc.PollInterval,
	}, nil
}

// validateServerURL requires an https URL with a host. The agent never talks
// to its server in the clear.
func validateServerURL(raw string) error {
	if raw == "" {
		return errors.New("agent: server_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("agent: server_url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("agent: server_url must be an https URL with a host")
	}
	return nil
}
