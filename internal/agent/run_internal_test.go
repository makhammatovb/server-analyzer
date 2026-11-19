package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

func TestReadBootIDTrimsAndIsValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(p, []byte("3f1c2a9e-1b2d-4c3e-8f40-0a1b2c3d4e5f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readBootID(p)
	if got != "3f1c2a9e-1b2d-4c3e-8f40-0a1b2c3d4e5f" {
		t.Errorf("readBootID = %q", got)
	}
	hb := api.Heartbeat{ServerID: "3f1c2a9e-1b2d-4c3e-8f40-0a1b2c3d4e5f", BootID: got}
	if err := hb.Validate(); err != nil {
		t.Errorf("a real boot id fails the server's validation: %v", err)
	}
}

func TestReadBootIDDropsValuesTheServerWouldReject(t *testing.T) {
	for name, content := range map[string]string{
		"space":    "abc def",
		"slash":    "abc/def",
		"too long": strings.Repeat("a", 65),
	} {
		p := filepath.Join(t.TempDir(), "boot_id")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readBootID(p); got != "" {
			t.Errorf("%s: readBootID = %q, want empty (valid) not a value that earns a 400", name, got)
		}
	}
}

func TestReadBootIDMissingFileIsEmpty(t *testing.T) {
	if got := readBootID(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("readBootID(missing) = %q, want empty", got)
	}
}

func TestBackoffCeilingDoublesAndCaps(t *testing.T) {
	want := []time.Duration{5, 10, 20, 40, 80, 160, 300, 300}
	for i, w := range want {
		if got := backoffCeiling(i + 1); got != w*time.Second {
			t.Errorf("backoffCeiling(%d) = %v, want %v", i+1, got, w*time.Second)
		}
	}
	if got := backoffCeiling(1 << 30); got != maxBackoff {
		t.Errorf("backoffCeiling(huge) = %v, want %v", got, maxBackoff)
	}
}

func TestStatusErrorCarriesCode(t *testing.T) {
	var err error = &StatusError{Code: 403}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 {
		t.Fatal("StatusError not recoverable with errors.As")
	}
}
