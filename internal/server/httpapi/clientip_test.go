package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPTrustsXRealIPOnlyWithValidSecret(t *testing.T) {
	const secret = "s3cret" //nolint:gosec // test fixture
	cases := []struct {
		name, proxyHdr, realIP, want string
	}{
		{"valid secret uses X-Real-IP", secret, "198.51.100.9", "198.51.100.9"},
		{"no secret falls back to RemoteAddr", "", "198.51.100.9", "192.0.2.1"},
		{"wrong secret falls back to RemoteAddr", "nope", "198.51.100.9", "192.0.2.1"},
		{"valid secret but empty X-Real-IP", secret, "", "192.0.2.1"},
		{"valid secret but unparseable X-Real-IP", secret, "not-an-ip", "192.0.2.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.RemoteAddr = "192.0.2.1:4444"
		r.Header.Set(ProxyAuthHeader, c.proxyHdr)
		r.Header.Set("X-Real-IP", c.realIP)
		if got := clientIP(r, secret); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}
}
