package main

import (
	"strings"
	"testing"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func validEnv() map[string]string {
	return map[string]string{ //nolint:gosec // test fixture, not a credential
		"FG_DSN":          "postgres://u:p@127.0.0.1:5432/fleetguard",
		"FG_BASE_URL":     "https://fleet.example.test",
		"FG_PROXY_SECRET": "s3cret",
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(env(validEnv()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.StateDir != "/var/lib/fleetguard" {
		t.Fatalf("defaults = %q, %q", cfg.Listen, cfg.StateDir)
	}
	if cfg.AgentHostname != "fleet.example.test" {
		t.Fatalf("AgentHostname = %q, want the base URL host", cfg.AgentHostname)
	}
}

func TestLoadConfigRefusesMissingRequiredValues(t *testing.T) {
	for _, key := range []string{"FG_DSN", "FG_BASE_URL", "FG_PROXY_SECRET"} {
		e := validEnv()
		delete(e, key)
		_, err := loadConfig(env(e))
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("without %s: err = %v, want one naming it", key, err)
		}
	}
}

func TestLoadConfigRefusesNonLoopbackListen(t *testing.T) {
	e := validEnv()
	e["FG_LISTEN"] = "0.0.0.0:8080"
	if _, err := loadConfig(env(e)); err == nil {
		t.Fatal("0.0.0.0:8080 accepted without FG_ALLOW_PUBLIC_LISTEN")
	}
	e["FG_ALLOW_PUBLIC_LISTEN"] = "1"
	if _, err := loadConfig(env(e)); err != nil {
		t.Fatalf("with override: %v", err)
	}
	e["FG_ALLOW_PUBLIC_LISTEN"] = "true" // only the literal 1 counts
	if _, err := loadConfig(env(e)); err == nil {
		t.Fatal(`FG_ALLOW_PUBLIC_LISTEN="true" accepted; only "1" should be`)
	}
}

func TestLoadConfigRequiresBothBootstrapValuesOrNeither(t *testing.T) {
	e := validEnv()
	e["FG_BOOTSTRAP_USER"] = "root"
	if _, err := loadConfig(env(e)); err == nil {
		t.Fatal("bootstrap user without password accepted")
	}
	e["FG_BOOTSTRAP_PASSWORD"] = "correct horse battery staple"
	if _, err := loadConfig(env(e)); err != nil {
		t.Fatalf("both set: %v", err)
	}
}

func TestLoadConfigRejectsABaseURLWithoutAHost(t *testing.T) {
	e := validEnv()
	e["FG_BASE_URL"] = "fleet.example.test"
	if _, err := loadConfig(env(e)); err == nil {
		t.Fatal("scheme-less base URL accepted")
	}
}
