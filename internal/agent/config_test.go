package agent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/internal/agent"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig(t *testing.T) {
	cfg, err := agent.LoadConfig(writeConfig(t, "server_url: https://agents.example.com/\npoll_interval: 45s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL != "https://agents.example.com" || cfg.PollInterval != 45*time.Second || cfg.StateDir != agent.DefaultStateDir {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadConfigDefaultsPollInterval(t *testing.T) {
	cfg, err := agent.LoadConfig(writeConfig(t, "server_url: https://a.example.com\n"))
	if err != nil || cfg.PollInterval != agent.DefaultPollInterval {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestLoadConfigRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"missing url":   "poll_interval: 30s\n",
		"plain http":    "server_url: http://a.example.com\n",
		"unknown key":   "server_url: https://a.example.com\nstate_dir: /tmp\n",
		"negative poll": "server_url: https://a.example.com\npoll_interval: -1s\n",
		"bad yaml":      "server_url: [\n",
	} {
		if _, err := agent.LoadConfig(writeConfig(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := agent.LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}
