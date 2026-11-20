package httpapi_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Audit action names are what Phase 2's detection rules will query, so a
// spelling that drifts is a silent miss. One convention: <domain>.<event>,
// lower case, words joined by underscores (never hyphens), no further dots.
func TestAuditActionNamesFollowOneConvention(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	literal := regexp.MustCompile(`"((?:agent|server|user|admin|auth|session)\.[A-Za-z0-9_.-]+)"`)
	valid := regexp.MustCompile(`^[a-z]+\.[a-z]+(_[a-z]+)*$`)
	seen := 0
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path) //nolint:gosec // walking the repository's own sources
		if err != nil {
			return err
		}
		for _, m := range literal.FindAllStringSubmatch(string(b), -1) {
			seen++
			if !valid.MatchString(m[1]) && !strings.HasSuffix(m[1], ".crt") && !strings.HasSuffix(m[1], ".key") {
				t.Errorf("%s: audit action %q does not match <domain>.<event_with_underscores>", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 8 {
		t.Fatalf("found only %d action literals; the scan is not seeing the code", seen)
	}
}
