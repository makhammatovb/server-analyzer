// Package ca implements FleetGuard's internal certificate authority. The
// central app generates it on first boot, signs one client certificate per
// enrolled server, and verifies those certificates on every request.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

// issue signs a client certificate with the given Common Name and returns DER.
func (c *CA) issue(csrPEM []byte, commonName string, ttl time.Duration, now time.Time) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("ca: no PEM CSR found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature: %w", err)
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
