package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testServerID = "7b0e3c4a-5f1d-4a6e-9c52-0d3f8a1b2c3d"

func newCA(t *testing.T) *CA {
	t.Helper()
	certPEM, keyPEM, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	c, err := Load(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func newCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored-by-ca"},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func certDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in certificate")
	}
	return block.Bytes
}

func TestSignThenVerifyRoundTrip(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	certPEM, err := c.Sign(newCSR(t), testServerID, 90*24*time.Hour, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := c.Verify(certDER(t, certPEM), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != testServerID {
		t.Fatalf("server ID = %q, want %q", got, testServerID)
	}
}

func TestVerifyRejectsForeignCA(t *testing.T) {
	ours, theirs := newCA(t), newCA(t)
	now := time.Now()
	certPEM, err := theirs.Sign(newCSR(t), testServerID, time.Hour, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = ours.Verify(certDER(t, certPEM), now)
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("err = %v, want ErrUntrusted", err)
	}
}

func TestVerifyRejectsExpiredCert(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	certPEM, err := c.Sign(newCSR(t), testServerID, time.Hour, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = c.Verify(certDER(t, certPEM), now.Add(2*time.Hour))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsWrongCommonName(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	for _, cn := range []string{"admin", "fleetguard-agent:", "fleetguard-agent"} {
		der, err := c.issue(newCSR(t), cn, time.Hour, now)
		if err != nil {
			t.Fatalf("issue %q: %v", cn, err)
		}
		if _, err := c.Verify(der, now); !errors.Is(err, ErrBadSubject) {
			t.Fatalf("CN %q: err = %v, want ErrBadSubject", cn, err)
		}
	}
}

func TestVerifyRejectsNonClientAuthCert(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, err := newSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subjectPrefix + testServerID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := c.Verify(der, now); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("err = %v, want ErrUntrusted", err)
	}
}

func TestSignHonoursNinetyDayTTL(t *testing.T) {
	c := newCA(t)
	certPEM, err := c.Sign(newCSR(t), testServerID, 90*24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER(t, certPEM))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 90*24*time.Hour {
		t.Fatalf("lifetime = %v, want 90 days", got)
	}
	if cert.Subject.CommonName != "fleetguard-agent:"+testServerID {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
}

func TestSignRejectsBadCSR(t *testing.T) {
	c := newCA(t)
	if _, err := c.Sign([]byte("not pem"), testServerID, time.Hour, time.Now()); err == nil {
		t.Fatal("expected error for non-PEM CSR")
	}
}

func TestLoadOrCreateDoesNotOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "ca")
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	before, err := os.Stat(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first.CertPEM()) != string(second.CertPEM()) {
		t.Fatal("CertPEM changed between calls")
	}
	after, err := os.Stat(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("ca.crt was rewritten")
	}
}

func TestLoadOrCreateWritesKeyAs0600(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestFingerprintIsHexSHA256(t *testing.T) {
	c := newCA(t)
	fp := c.Fingerprint(c.cert.Raw)
	if len(fp) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fp))
	}
}
