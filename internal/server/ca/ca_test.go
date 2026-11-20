package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestCheckCSR(t *testing.T) {
	good := newCSR(t)
	csr, err := CheckCSR(good)
	if err != nil || csr == nil || csr.PublicKey == nil {
		t.Fatalf("valid CSR: %v, %v", csr, err)
	}

	block, _ := pem.Decode(good)
	corrupt := *block
	corrupt.Bytes = append([]byte(nil), block.Bytes...)
	corrupt.Bytes[len(corrupt.Bytes)-1] ^= 0xff
	wrongType := *block
	wrongType.Type = "CERTIFICATE"

	tests := map[string][]byte{
		"not pem":           []byte("not pem"),
		"wrong block type":  pem.EncodeToMemory(&wrongType),
		"corrupt signature": pem.EncodeToMemory(&corrupt),
	}
	for name, in := range tests {
		if _, err := CheckCSR(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSignRejectsWrongPEMType(t *testing.T) {
	c := newCA(t)
	block, _ := pem.Decode(newCSR(t))
	block.Type = "CERTIFICATE"
	if _, err := c.Sign(pem.EncodeToMemory(block), testServerID, time.Hour, time.Now()); err == nil {
		t.Fatal("Sign accepted a PEM block that is not a CERTIFICATE REQUEST")
	}
}

func TestIssueServerCertIsServerAuthForTheNameAndChainsToCA(t *testing.T) {
	c := newCA(t)
	now := time.Now()
	certPEM, keyPEM, err := c.IssueServerCert("agents.example.test", ServerCertTTL, now)
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "agents.example.test", CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("server verification: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "other.example.test", CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("certificate verified for a name it was not issued for")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("key does not match certificate: %v", err)
	}
	// A server certificate must never authenticate an agent.
	if _, err := c.Verify(block.Bytes, now); err == nil {
		t.Fatal("server certificate accepted as a client certificate")
	}
}

func TestIssueServerCertUsesAFreshKeyEachTime(t *testing.T) {
	c := newCA(t)
	_, k1, err1 := c.IssueServerCert("a.example.test", time.Hour, time.Now())
	_, k2, err2 := c.IssueServerCert("a.example.test", time.Hour, time.Now())
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v, %v", err1, err2)
	}
	if len(k1) == 0 || string(k1) == string(k2) {
		t.Fatal("keys empty or reused")
	}
}

func TestEnsureServerCertWritesReusesAndRenews(t *testing.T) {
	c := newCA(t)
	dir := t.TempDir()
	now := time.Now()
	read := func() (string, string) {
		crt, err := os.ReadFile(filepath.Join(dir, "agent-server.crt")) //nolint:gosec // test path
		if err != nil {
			t.Fatalf("read crt: %v", err)
		}
		key, err := os.ReadFile(filepath.Join(dir, "agent-server.key")) //nolint:gosec // test path
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		return string(crt), string(key)
	}

	if reissued, err := c.EnsureServerCert(dir, "agents.example.test", now); err != nil || !reissued {
		t.Fatalf("first call = %v, %v; want true, nil", reissued, err)
	}
	for name, want := range map[string]os.FileMode{"agent-server.crt": 0o644, "agent-server.key": 0o640, "ca.crt": 0o644} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: %v, mode %v; want %o", name, err, fi, want)
		}
	}
	crt1, key1 := read()

	if reissued, err := c.EnsureServerCert(dir, "agents.example.test", now.Add(24*time.Hour)); err != nil || reissued {
		t.Fatalf("second call = %v, %v; want false, nil", reissued, err)
	}
	if crt, key := read(); crt != crt1 || key != key1 {
		t.Fatal("files changed although the certificate had plenty of life left")
	}

	// 61 days before expiry: still left alone. 59 days: renewed.
	expiry := now.Add(ServerCertTTL)
	if reissued, _ := c.EnsureServerCert(dir, "agents.example.test", expiry.Add(-61*24*time.Hour)); reissued {
		t.Fatal("reissued with 61 days remaining")
	}
	if reissued, err := c.EnsureServerCert(dir, "agents.example.test", expiry.Add(-59*24*time.Hour)); err != nil || !reissued {
		t.Fatalf("with 59 days remaining = %v, %v; want true, nil", reissued, err)
	}
	if crt, _ := read(); crt == crt1 {
		t.Fatal("certificate not replaced")
	}
}

func TestEnsureServerCertReissuesForANewHostname(t *testing.T) {
	c := newCA(t)
	dir := t.TempDir()
	now := time.Now()
	if _, err := c.EnsureServerCert(dir, "old.example.test", now); err != nil {
		t.Fatal(err)
	}
	if reissued, err := c.EnsureServerCert(dir, "new.example.test", now); err != nil || !reissued {
		t.Fatalf("hostname change = %v, %v; want true, nil", reissued, err)
	}
}

func TestEnsureServerCertReissuesWhenIssuedByAnotherCA(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if _, err := newCA(t).EnsureServerCert(dir, "agents.example.test", now); err != nil {
		t.Fatal(err)
	}
	if reissued, err := newCA(t).EnsureServerCert(dir, "agents.example.test", now); err != nil || !reissued {
		t.Fatalf("foreign CA = %v, %v; want true, nil", reissued, err)
	}
}

func TestEnsureServerCertReissuesWhenTheFilesAreDamaged(t *testing.T) {
	c := newCA(t)
	dir := t.TempDir()
	now := time.Now()
	if _, err := c.EnsureServerCert(dir, "agents.example.test", now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent-server.key"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reissued, err := c.EnsureServerCert(dir, "agents.example.test", now); err != nil || !reissued {
		t.Fatalf("damaged key = %v, %v; want true, nil", reissued, err)
	}
}

// The proxy is the process most exposed to the internet. It may read the
// certificate pair it serves, a public copy of ca.crt and nothing else; above
// all not ca.key, which signs every agent identity and has no revocation. The
// deployment gives the proxy's group read access to the proxy directory only,
// so these modes are the contract: the state directory and ca.key admit the
// owner alone, and the proxy directory holds no CA private key.
func TestProxyDirectoryExposesTheCertPairButNotTheCAKey(t *testing.T) {
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil { //nolint:gosec // a directory needs the x bit
		t.Fatal(err)
	}
	c, err := LoadOrCreate(state)
	if err != nil {
		t.Fatal(err)
	}
	proxy := filepath.Join(state, "proxy")
	if _, err := c.EnsureServerCert(proxy, "agents.example.test", time.Now()); err != nil {
		t.Fatal(err)
	}
	mode := func(path string) os.FileMode {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	if m := mode(state); m&0o077 != 0 {
		t.Errorf("state directory mode %o admits group or other", m)
	}
	if m := mode(filepath.Join(state, "ca.key")); m&0o077 != 0 {
		t.Errorf("ca.key mode %o admits group or other", m)
	}
	if m := mode(proxy); m != 0o750 {
		t.Errorf("proxy directory mode %o, want 750 (owner rwx, proxy group r-x, others none)", m)
	}
	if m := mode(filepath.Join(proxy, "agent-server.key")); m&0o040 == 0 || m&0o007 != 0 || m&0o020 != 0 {
		t.Errorf("agent-server.key mode %o: the proxy group must read it, nobody else may", m)
	}
	entries, err := os.ReadDir(proxy)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "ca.key" {
			t.Fatal("the CA private key is in the proxy directory")
		}
		b, _ := os.ReadFile(filepath.Join(proxy, e.Name())) //nolint:gosec // test path
		if e.Name() != "agent-server.key" && strings.Contains(string(b), "PRIVATE KEY") {
			t.Errorf("%s in the proxy directory holds a private key", e.Name())
		}
	}
}

// A key without its certificate is a half-written pair (the certificate write
// failed after the key was created). LoadOrCreate must still fail closed, and
// the error must name the remedy: the operator cannot otherwise tell why first
// boot is stuck.
func TestLoadOrCreateHalfWrittenPairNamesTheRemedy(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, keyFile)
	if err := os.WriteFile(keyPath, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreate(dir)
	if err == nil {
		t.Fatal("LoadOrCreate succeeded with only a key present")
	}
	for _, want := range []string{"half-written", "remove", keyPath} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "orphan" { //nolint:gosec // test path
		t.Fatal("the orphaned key was modified; failing closed must not touch it")
	}
}
