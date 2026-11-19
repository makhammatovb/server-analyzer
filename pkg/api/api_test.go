package api_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

func TestEnrolRequestValidate(t *testing.T) {
	valid := api.EnrolRequest{
		Token:        "tok",
		CSRPEM:       []byte("csr"),
		Hostname:     "host-1",
		AgentVersion: "0.1.0",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*api.EnrolRequest)
		field  string
	}{
		{"empty token", func(r *api.EnrolRequest) { r.Token = "" }, "Token"},
		{"empty csr", func(r *api.EnrolRequest) { r.CSRPEM = nil }, "CSRPEM"},
		{"empty hostname", func(r *api.EnrolRequest) { r.Hostname = "" }, "Hostname"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mutate(&r)
			err := r.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error %q does not name field %s", err, tc.field)
			}
		})
	}
}

func TestEnrolRequestRoundTrip(t *testing.T) {
	in := api.EnrolRequest{
		Token:        "tok",
		CSRPEM:       []byte("-----BEGIN CERTIFICATE REQUEST-----\n\x00\xff\n-----END CERTIFICATE REQUEST-----\n"),
		Hostname:     "host-1",
		AgentVersion: "0.1.0",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out api.EnrolRequest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in: %#v\nout: %#v", in, out)
	}
}

func TestReEnrolRequestValidate(t *testing.T) {
	valid := api.ReEnrolRequest{
		ServerID: "7b0c2f0e-6d1a-4c53-9a63-1f2f4a1f9a10",
		EnrolKey: "key",
		CSRPEM:   []byte("csr"),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*api.ReEnrolRequest)
		field  string
	}{
		{"empty server id", func(r *api.ReEnrolRequest) { r.ServerID = "" }, "ServerID"},
		{"bad server id", func(r *api.ReEnrolRequest) { r.ServerID = "nope" }, "ServerID"},
		{"empty key", func(r *api.ReEnrolRequest) { r.EnrolKey = "" }, "EnrolKey"},
		{"empty csr", func(r *api.ReEnrolRequest) { r.CSRPEM = nil }, "CSRPEM"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mutate(&r)
			err := r.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("want error naming %s, got %v", tc.field, err)
			}
		})
	}
}

func TestHeartbeatValidate(t *testing.T) {
	hb := api.Heartbeat{
		ServerID:     "7b0c2f0e-6d1a-4c53-9a63-1f2f4a1f9a10",
		AgentVersion: "0.1.0",
		BootID:       "boot",
		UptimeSec:    10,
		SentAt:       time.Now().UTC(),
	}
	if err := hb.Validate(); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}

	for name, id := range map[string]string{"empty": "", "not a uuid": "server-1"} {
		t.Run(name, func(t *testing.T) {
			h := hb
			h.ServerID = id
			err := h.Validate()
			if err == nil || !strings.Contains(err.Error(), "ServerID") {
				t.Fatalf("want error naming ServerID, got %v", err)
			}
		})
	}
}

func TestMaxBodyBytesIsSixtyFourKiB(t *testing.T) {
	if api.MaxBodyBytes != 65536 {
		t.Fatalf("MaxBodyBytes = %d, want 65536", api.MaxBodyBytes)
	}
}

func TestAgentCertHeader(t *testing.T) {
	if api.AgentCertHeader != "X-Agent-Cert" {
		t.Fatalf("AgentCertHeader = %q", api.AgentCertHeader)
	}
}
