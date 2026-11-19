package agent

import (
	"net/http"
	"testing"
)

// A zero Identity has a nil CAPool, which crypto/tls would treat as "use the
// system roots". NewClient must fail closed instead.
func TestNewClientZeroIdentityHasEmptyRootPool(t *testing.T) {
	c := NewClient(Identity{}, Config{ServerURL: "https://127.0.0.1:1"})
	tc := c.http.Transport.(*http.Transport).TLSClientConfig
	if tc.RootCAs == nil {
		t.Fatal("RootCAs is nil: the client would fall back to system roots")
	}
	if n := len(tc.RootCAs.Subjects()); n != 0 { //nolint:staticcheck // counting an empty pool is the point
		t.Fatalf("pool has %d certificates, want 0", n)
	}
}
