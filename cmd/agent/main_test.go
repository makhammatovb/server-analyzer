package main

import (
	"os"
	"path/filepath"
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
			if got := realMain(c.args); got != c.want {
				t.Errorf("realMain(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}
