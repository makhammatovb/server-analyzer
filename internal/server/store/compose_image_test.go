package store

import (
	"os"
	"regexp"
	"testing"
)

// The unit tests and the deployed stack must run the same database. The compose
// file cannot import a Go constant, so this keeps the two from drifting apart.
func TestComposeDatabaseImageMatchesTimescaleImage(t *testing.T) {
	b, err := os.ReadFile("../../../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s+image:\s*(timescale/\S+)\s*$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no timescale image found in deploy/docker-compose.yml")
	}
	if got := string(m[1]); got != TimescaleImage {
		t.Fatalf("deploy/docker-compose.yml uses %q but store.TimescaleImage is %q", got, TimescaleImage)
	}
}
