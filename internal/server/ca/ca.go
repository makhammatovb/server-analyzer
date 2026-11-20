// Package ca implements FleetGuard's internal certificate authority. The
// central app generates it on first boot, signs one client certificate per
// enrolled server, and verifies those certificates on every request.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	subjectPrefix = "fleetguard-agent:"
	caLifetime    = 10 * 365 * 24 * time.Hour
	certFile      = "ca.crt"
	keyFile       = "ca.key"
)

var (
	// ErrExpired means the certificate is outside its validity window.
	ErrExpired = errors.New("ca: certificate expired or not yet valid")
	// ErrUntrusted means the certificate does not chain to this CA for client auth.
	ErrUntrusted = errors.New("ca: certificate not trusted")
	// ErrBadSubject means the Common Name is not fleetguard-agent:<serverID>.
	ErrBadSubject = errors.New("ca: unexpected certificate subject")
)

// CA is a loaded certificate authority able to sign and verify agent certificates.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// Generate creates a new self-signed CA and returns its PEM-encoded
// certificate and private key.
func Generate() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("ca: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "FleetGuard Internal CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: self-sign: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// Load parses a PEM certificate and private key into a CA.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("ca: no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("ca: no PEM private key found")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse private key: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("ca: private key does not match certificate")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// LoadOrCreate loads the CA from dir, generating and persisting a new one if
// neither file exists. Existing files are never overwritten.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca: create dir: %w", err)
	}
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	certPEM, certErr := os.ReadFile(certPath) //nolint:gosec // path is operator-configured
	keyPEM, keyErr := os.ReadFile(keyPath)    //nolint:gosec // path is operator-configured
	switch {
	case certErr == nil && keyErr == nil:
		return Load(certPEM, keyPEM)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		// fall through to create
	default:
		return nil, fmt.Errorf("ca: read existing CA files: cert: %v, key: %v", certErr, keyErr)
	}
	certPEM, keyPEM, err := Generate()
	if err != nil {
		return nil, err
	}
	// Key first, exclusive create, so an existing file is never clobbered.
	if err := writeExclusive(keyPath, keyPEM); err != nil {
		return nil, err
	}
	if err := writeExclusive(certPath, certPEM); err != nil {
		return nil, err
	}
	return Load(certPEM, keyPEM)
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path is operator-configured
	if err != nil {
		return fmt.Errorf("ca: create %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("ca: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ca: close %s: %w", filepath.Base(path), err)
	}
	return nil
}

// CertPEM returns the PEM-encoded CA certificate.
func (c *CA) CertPEM() []byte { return c.certPEM }

// Fingerprint returns the hex SHA-256 of a DER certificate.
func (c *CA) Fingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// Sign issues a client certificate for serverID, using the public key from
// csrPEM. The CSR's own subject is ignored. Returns the PEM certificate.
func (c *CA) Sign(csrPEM []byte, serverID string, ttl time.Duration, now time.Time) ([]byte, error) {
	if serverID == "" {
		return nil, errors.New("ca: empty server ID")
	}
	der, err := c.issue(csrPEM, subjectPrefix+serverID, ttl, now)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CheckCSR parses a PEM certificate signing request and verifies its
// self-signature. issue runs exactly this check, and callers that must reject a
// bad CSR before spending anything (such as a single-use token) call it too, so
// the two can never disagree.
func CheckCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("ca: no PEM CERTIFICATE REQUEST found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature: %w", err)
	}
	return csr, nil
}

// issue signs a client certificate with the given Common Name and returns DER.
func (c *CA) issue(csrPEM []byte, commonName string, ttl time.Duration, now time.Time) ([]byte, error) {
	csr, err := CheckCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	notBefore := now.Add(-time.Minute) // tolerate small clock skew on the agent
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign: %w", err)
	}
	return der, nil
}

// Verify checks that certDER chains to this CA for client authentication at
// time now, and returns the server ID from its Common Name.
func (c *CA) Verify(certDER []byte, now time.Time) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
			return "", ErrExpired
		}
		return "", fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	id, ok := strings.CutPrefix(cert.Subject.CommonName, subjectPrefix)
	if !ok || id == "" {
		return "", ErrBadSubject
	}
	return id, nil
}

const (
	// ServerCertTTL is the lifetime of the agent hostname's server certificate.
	// A year means Phase 0 needs no renewal daemon; the binary reissues at start.
	ServerCertTTL = 365 * 24 * time.Hour
	// ServerCertRenewBefore is how close to expiry a certificate is replaced.
	ServerCertRenewBefore = 60 * 24 * time.Hour

	// proxyCAFile is the public copy of the CA certificate the proxy reads.
	proxyCAFile = "ca.crt"

	serverCertFile = "agent-server.crt"
	serverKeyFile  = "agent-server.key"
)

// IssueServerCert issues a TLS server certificate for dnsName with its own
// fresh key. The agent pins this CA as its only trust root, so the agent
// hostname must present a certificate from here rather than from ACME. The
// certificate carries ExtKeyUsageServerAuth only and therefore never passes
// Verify, which demands client authentication.
func (c *CA) IssueServerCert(dnsName string, ttl time.Duration, now time.Time) (certPEM, keyPEM []byte, err error) {
	if dnsName == "" {
		return nil, nil, errors.New("ca: empty DNS name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate server key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("ca: serial: %w", err)
	}
	notBefore := now.Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: sign server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal server key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// EnsureServerCert makes sure dir holds a usable agent-server.crt and
// agent-server.key for dnsName, plus a public copy of ca.crt, and reports whether
// it (re)issued the pair. Existing files are kept only if the pair loads, the
// certificate chains to this CA for server authentication, names dnsName, and
// has more than ServerCertRenewBefore left; anything else, including unreadable
// or damaged files, is replaced.
//
// dir is the proxy's directory, not the CA's: the reverse proxy is the process
// most exposed to the internet, so it must be able to read this pair and
// nothing else. Callers therefore pass a subdirectory distinct from the one
// holding ca.key. The directory is created 0750 and the key 0640, so a proxy
// sharing the directory's group can read it and no one else can; the
// certificate and the CA copy are public (0644).
func (c *CA) EnsureServerCert(dir, dnsName string, now time.Time) (bool, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("ca: create dir: %w", err)
	}
	if err := writeReplace(filepath.Join(dir, proxyCAFile), c.certPEM, 0o644); err != nil {
		return false, err
	}
	if c.serverCertUsable(dir, dnsName, now) {
		return false, nil
	}
	certPEM, keyPEM, err := c.IssueServerCert(dnsName, ServerCertTTL, now)
	if err != nil {
		return false, err
	}
	// Key first: a crash between the two writes leaves a mismatched pair, which
	// serverCertUsable rejects, so the next start repairs it.
	if err := writeReplace(filepath.Join(dir, serverKeyFile), keyPEM, 0o640); err != nil {
		return false, err
	}
	if err := writeReplace(filepath.Join(dir, serverCertFile), certPEM, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func (c *CA) serverCertUsable(dir, dnsName string, now time.Time) bool {
	certPEM, err := os.ReadFile(filepath.Join(dir, serverCertFile)) //nolint:gosec // path is operator-configured
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, serverKeyFile)) //nolint:gosec // path is operator-configured
	if err != nil {
		return false
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: dnsName, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return false
	}
	return cert.NotAfter.Sub(now) > ServerCertRenewBefore
}

// writeReplace writes data to path with the given mode via a temporary file and
// a rename, so a reader never sees a half-written file. The mode is applied
// explicitly: the file's group comes from the directory (setgid in the
// deployment), not from the process.
func writeReplace(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ca: clear %s: %w", filepath.Base(tmp), err)
	}
	if err := writeExclusive(tmp, data); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("ca: chmod %s: %w", filepath.Base(tmp), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("ca: replace %s: %w", filepath.Base(path), err)
	}
	return nil
}
