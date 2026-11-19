package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/makhammatovb/fleetguard/pkg/api"
)

// State directory file names.
const (
	fileCert     = "agent.crt"
	fileKey      = "agent.key"
	fileCA       = "ca.crt"
	fileEnrolKey = "enrol.key"
	fileServerID = "server_id"
)

// rotateWithin is how close to expiry a certificate must be before it is
// rotated: 30 days left on a 90-day certificate means rotate at day 60.
const rotateWithin = 30 * 24 * time.Hour

// ErrNoIdentity is returned when the state directory holds no enrolled
// identity.
var ErrNoIdentity = errors.New("agent: no identity")

// ErrNoCA is returned when ca.crt is missing or unusable. ca.crt is the
// agent's only trust anchor, placed by the installer before enrolment; there is
// deliberately no fallback to system roots, so a missing pin fails closed.
var ErrNoCA = errors.New("agent: ca.crt missing or unusable in state directory; the agent trusts only that CA")

var (
	// ErrCertNotPinned means the issued certificate does not chain to ca.crt.
	ErrCertNotPinned = errors.New("agent: issued certificate does not chain to the pinned CA")
	// ErrCAMismatch means the CA the server reported is not the pinned CA.
	ErrCAMismatch = errors.New("agent: server's CA differs from the pinned ca.crt")
)

// loadPinnedCA reads ca.crt and returns its PEM and pool.
func loadPinnedCA(dir string) ([]byte, *x509.CertPool, error) {
	caPEM, err := readState(dir, fileCA)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoCA, err)
	}
	pool, err := poolFromPEM(caPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoCA, err)
	}
	return caPEM, pool, nil
}

// Identity is the agent's enrolled credentials.
type Identity struct {
	ServerID string
	Cert     tls.Certificate
	CAPool   *x509.CertPool
	NotAfter time.Time
}

// NeedsRotation reports whether fewer than 30 days of validity remain at now.
func (i Identity) NeedsRotation(now time.Time) bool {
	return i.NotAfter.Sub(now) < rotateWithin
}

// Enrol generates a key and CSR on this host, redeems the one-time token and
// persists the issued identity. The private key is never transmitted. The
// server is verified against the pinned ca.crt, which must already be in the
// state directory; Enrol never overwrites it with anything the server sends.
func Enrol(ctx context.Context, cfg Config, token, hostname, version string) (Identity, error) {
	caPEM, pool, err := loadPinnedCA(cfg.StateDir)
	if err != nil {
		return Identity{}, err
	}
	keyPEM, csrPEM, err := newKeyAndCSR()
	if err != nil {
		return Identity{}, err
	}
	var resp api.EnrolResponse
	err = postJSON(ctx, bootstrapClient(pool), cfg.ServerURL+"/v1/enrol", api.EnrolRequest{
		Token: token, CSRPEM: csrPEM, Hostname: hostname, AgentVersion: version,
	}, &resp)
	if err != nil {
		return Identity{}, fmt.Errorf("agent: enrol: %w", err)
	}
	if resp.EnrolKey == "" {
		return Identity{}, errors.New("agent: enrol: server returned no enrolment secret")
	}
	if _, err := uuid.Parse(resp.ServerID); err != nil {
		return Identity{}, errors.New("agent: enrol: server returned an invalid server id")
	}
	if err := checkReportedCA(resp.CAPEM, caPEM); err != nil {
		return Identity{}, fmt.Errorf("agent: enrol: %w", err)
	}
	id, err := buildIdentity(resp.ServerID, resp.CertPEM, keyPEM, caPEM)
	if err != nil {
		return Identity{}, fmt.Errorf("agent: enrol: %w", err)
	}
	if err := ensureStateDir(cfg.StateDir); err != nil {
		return Identity{}, err
	}
	// The certificate is written last: LoadIdentity treats its absence as
	// "not enrolled", so a crash part way through leaves no half identity.
	files := []stateFile{
		{fileEnrolKey, []byte(resp.EnrolKey)},
		{fileServerID, []byte(resp.ServerID)},
		{fileKey, keyPEM},
		{fileCert, resp.CertPEM},
	}
	if err := writeState(cfg.StateDir, files); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// ReEnrol obtains a fresh certificate using the enrolment secret already on
// disk. It works with an expired certificate and presents none, so it needs no
// admin action. enrol.key is deliberately never rewritten: the server does not
// rotate it and returns none, and overwriting it would destroy the only
// credential able to recover from an expired certificate.
func ReEnrol(ctx context.Context, cfg Config) (Identity, error) {
	serverID, err := readState(cfg.StateDir, fileServerID)
	if err != nil {
		return Identity{}, err
	}
	enrolKey, err := readState(cfg.StateDir, fileEnrolKey)
	if err != nil {
		return Identity{}, err
	}
	caPEM, pool, err := loadPinnedCA(cfg.StateDir)
	if err != nil {
		return Identity{}, err
	}
	keyPEM, csrPEM, err := newKeyAndCSR()
	if err != nil {
		return Identity{}, err
	}
	var resp api.EnrolResponse
	err = postJSON(ctx, bootstrapClient(pool), cfg.ServerURL+"/v1/re-enrol", api.ReEnrolRequest{
		ServerID: string(serverID), EnrolKey: string(enrolKey), CSRPEM: csrPEM,
	}, &resp)
	if err != nil {
		return Identity{}, fmt.Errorf("agent: re-enrol: %w", err)
	}
	if resp.ServerID != "" && resp.ServerID != string(serverID) {
		return Identity{}, errors.New("agent: re-enrol: server returned a different server id")
	}
	if len(resp.CAPEM) > 0 {
		if err := checkReportedCA(resp.CAPEM, caPEM); err != nil {
			return Identity{}, fmt.Errorf("agent: re-enrol: %w", err)
		}
	}
	id, err := buildIdentity(string(serverID), resp.CertPEM, keyPEM, caPEM)
	if err != nil {
		return Identity{}, fmt.Errorf("agent: re-enrol: %w", err)
	}
	// Only the key and certificate change. A mismatched pair after a crash
	// between the two writes fails LoadIdentity, which leads back here.
	if err := writeState(cfg.StateDir, []stateFile{{fileKey, keyPEM}, {fileCert, resp.CertPEM}}); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// LoadIdentity recovers the identity persisted by Enrol or ReEnrol. It does
// not check expiry: an expired identity is still loaded so the caller can see
// NeedsRotation and re-enrol. It returns ErrNoIdentity when none is enrolled.
func LoadIdentity(cfg Config) (Identity, error) {
	certPEM, err := readState(cfg.StateDir, fileCert)
	if err != nil {
		return Identity{}, err
	}
	keyPEM, err := readState(cfg.StateDir, fileKey)
	if err != nil {
		return Identity{}, err
	}
	serverID, err := readState(cfg.StateDir, fileServerID)
	if err != nil {
		return Identity{}, err
	}
	caPEM, _, err := loadPinnedCA(cfg.StateDir)
	if err != nil {
		return Identity{}, err
	}
	return buildIdentity(strings.TrimSpace(string(serverID)), certPEM, keyPEM, caPEM)
}

func buildIdentity(serverID string, certPEM, keyPEM, caPEM []byte) (Identity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Identity{}, fmt.Errorf("certificate and key do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return Identity{}, fmt.Errorf("parse certificate: %w", err)
	}
	cert.Leaf = leaf
	pool, err := poolFromPEM(caPEM)
	if err != nil {
		return Identity{}, err
	}
	// Verify at the certificate's own NotBefore, not the wall clock: an
	// expired certificate must still load so ReEnrol can replace it.
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: leaf.NotBefore,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrCertNotPinned, err)
	}
	return Identity{ServerID: serverID, Cert: cert, CAPool: pool, NotAfter: leaf.NotAfter}, nil
}

func poolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no usable CA certificate")
	}
	return pool, nil
}

// checkReportedCA compares the CA the server reported with the pin by parsed
// certificate, since the PEM bytes differ in trailing whitespace.
func checkReportedCA(reportedPEM, pinnedPEM []byte) error {
	reported, err := firstCert(reportedPEM)
	if err != nil {
		return fmt.Errorf("%w: server's ca_pem: %v", ErrCAMismatch, err)
	}
	pinned, err := firstCert(pinnedPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoCA, err)
	}
	if !reported.Equal(pinned) {
		return ErrCAMismatch
	}
	return nil
}

func firstCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// newKeyAndCSR generates an ECDSA P-256 key on this host. The CSR carries only
// the public key; the server ignores any subject and sets its own.
func newKeyAndCSR() (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: generate key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: marshal key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

type stateFile struct {
	name string
	data []byte
}

func ensureStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("agent: create state dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a directory needs the search bit; 0700 is the tightest usable mode
		return fmt.Errorf("agent: secure state dir: %w", err)
	}
	return nil
}

// writeState writes each file 0600 via a temporary file and rename, so a
// reader never sees a partial file.
func writeState(dir string, files []stateFile) error {
	for _, f := range files {
		if err := writeAtomic(filepath.Join(dir, f.name), f.data); err != nil {
			return fmt.Errorf("agent: write %s: %w", f.name, err)
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*") // created 0600
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readState(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // fixed file names under the state dir
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read %s: %w", name, err)
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("agent: %s is empty", name)
	}
	return b, nil
}
