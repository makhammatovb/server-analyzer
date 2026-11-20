package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func config(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte("server_url: https://127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRealMainExitCodes(t *testing.T) {
	cfg := config(t)
	state := t.TempDir()
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, 2},
		{"unknown command", []string{"ack"}, 2},
		{"help", []string{"help"}, 0},
		{"run without an identity", []string{"run", "--config=" + cfg, "--state-dir=" + state}, 1},
		{"run with a missing config", []string{"run", "--config=" + filepath.Join(state, "none.yaml")}, 1},
		{"enrol without a token", []string{"enrol", "--config=" + cfg, "--state-dir=" + state}, 1},
		{"enrol without the pinned ca.crt", []string{"enrol", "--token=x", "--config=" + cfg, "--state-dir=" + state}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var errw bytes.Buffer
			if got := realMain(c.args, &errw); got != c.want {
				t.Errorf("realMain(%v) = %d, want %d", c.args, got, c.want)
			}
			if c.want != 0 && !strings.Contains(errw.String(), "fleetguard-agent") {
				t.Errorf("a failing exit wrote no explanation to the error writer: %q", errw.String())
			}
		})
	}
}

// The token must be passable without argv, which any local user can read in ps.
func TestEnrolTakesTheTokenFromTheEnvironment(t *testing.T) {
	cfg := config(t)
	state := t.TempDir() // no ca.crt: enrolment gets as far as the pin and stops
	args := []string{"enrol", "--config=" + cfg, "--state-dir=" + state}

	t.Setenv("FG_ENROL_TOKEN", "")
	var errw bytes.Buffer
	if got := realMain(args, &errw); got != 1 || !strings.Contains(errw.String(), "token is required") {
		t.Fatalf("no token anywhere: exit %d, %q", got, errw.String())
	}

	t.Setenv("FG_ENROL_TOKEN", "from-env")
	errw.Reset()
	if got := realMain(args, &errw); got != 1 || strings.Contains(errw.String(), "token is required") || !strings.Contains(errw.String(), "ca.crt") {
		t.Fatalf("token in the environment was not used: exit %d, %q", got, errw.String())
	}
}
