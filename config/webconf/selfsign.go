package webconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// selfSignedCN marks a certificate as one we generated, so a later startup can
// tell "the operator installed their own cert here" apart from "we made this".
const selfSignedCN = "arkgated configurator (self-signed)"

// webCertValidity is deliberately long. This cert is not publicly trusted and
// cannot be renewed by anything automatic - it is verified by an admin
// comparing a fingerprint once - so an appliance silently locking its own
// admin UI out after a year would be a worse failure than a long-lived key.
// Browsers cap validity at 398 days only for chains ending in a public root,
// which this is not.
const webCertValidity = 10 * 365 * 24 * time.Hour

// certInfo describes the key pair the configurator ended up serving, for
// startup logging and for the fingerprint shown on the page itself.
type certInfo struct {
	Generated   bool
	SelfSigned  bool
	Fingerprint string
	Subject     string
	NotAfter    time.Time
}

// Expiring reports whether this cert is close enough to expiry to complain
// about. Nothing rotates it automatically, so the only useful action is to
// tell the operator while there is still time.
func (ci certInfo) Expiring() bool {
	return !ci.NotAfter.IsZero() && time.Until(ci.NotAfter) < 30*24*time.Hour
}

// Summary is the one-line description shown in the configurator and logged at
// startup.
func (ci certInfo) Summary() string {
	kind := "installed certificate"
	if ci.SelfSigned {
		kind = "self-signed certificate"
	}
	if ci.Generated {
		kind = "newly generated self-signed certificate"
	}
	s := fmt.Sprintf("%s, SHA-256 %s", kind, ci.Fingerprint)
	if !ci.NotAfter.IsZero() {
		s += ", expires " + ci.NotAfter.Format("2006-01-02")
	}
	return s
}

// ensureWebCert makes sure certPath/keyPath hold a key pair the configurator
// can serve HTTPS with, generating a self-signed one if either file is
// missing. It never overwrites an existing pair: an operator who drops their
// own certificate in here keeps it, including after it expires (we warn rather
// than clobber - regenerating over a real cert to "fix" it would be worse than
// the outage it causes).
//
// webaddr is used only to work out which names and addresses to put in the
// SANs of a generated cert.
func ensureWebCert(certPath, keyPath, webaddr string) (certInfo, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	switch {
	case certErr == nil && keyErr == nil:
		return inspectCert(certPath)
	case certErr != nil && !os.IsNotExist(certErr):
		return certInfo{}, fmt.Errorf("checking %s: %w", certPath, certErr)
	case keyErr != nil && !os.IsNotExist(keyErr):
		return certInfo{}, fmt.Errorf("checking %s: %w", keyPath, keyErr)
	}

	if err := generateWebCert(certPath, keyPath, webaddr); err != nil {
		return certInfo{}, err
	}
	ci, err := inspectCert(certPath)
	if err != nil {
		return certInfo{}, err
	}
	ci.Generated = true
	return ci, nil
}

// inspectCert reads the leaf certificate at path for its fingerprint, subject
// and expiry.
func inspectCert(path string) (certInfo, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return certInfo{}, fmt.Errorf("reading %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return certInfo{}, fmt.Errorf("%s does not start with a PEM CERTIFICATE block", path)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certInfo{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	sum := sha256.Sum256(crt.Raw)
	return certInfo{
		SelfSigned:  crt.Subject.CommonName == selfSignedCN,
		Fingerprint: colonHex(sum[:]),
		Subject:     crt.Subject.CommonName,
		NotAfter:    crt.NotAfter,
	}, nil
}

func colonHex(b []byte) string {
	s := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i+2 <= len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":")
}

// generateWebCert writes a fresh self-signed P-256 key pair to certPath and
// keyPath. It is marked IsCA so an admin can import it as a trust anchor
// instead of clicking through a warning on every visit.
func generateWebCert(certPath, keyPath, webaddr string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating configurator key: %w", err)
	}

	// 128 bits of randomness, per RFC 5280's advice for serials that nothing
	// central is handing out.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating certificate serial: %w", err)
	}

	dnsNames, ips := certNames(webaddr)
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: selfSignedCN, Organization: []string{"arkgate"}},
		// Backdated an hour: an appliance that has not reached its NTP
		// server yet can easily believe it is slightly in the past, and a
		// not-yet-valid cert fails in a much more confusing way than an
		// untrusted one.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(webCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating configurator certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling configurator key: %w", err)
	}

	// Key first, and at 0600 before anything is in it: a window where the
	// private key exists world-readable is exactly the thing to avoid.
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0600); err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0644); err != nil {
		return err
	}
	return nil
}

// certNames works out what a generated cert should be valid for: loopback and
// "localhost" always (the configurator's default bind, reached over an ssh
// tunnel), the host's own name, whatever WebAddr names explicitly, and - when
// WebAddr is a wildcard bind - this host's actual unicast addresses, since
// that is what an admin will type.
func certNames(webaddr string) ([]string, []net.IP) {
	dns := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}

	if h, err := os.Hostname(); err == nil && h != "" && h != "localhost" {
		dns = append(dns, h)
	}

	host, _, err := net.SplitHostPort(webaddr)
	if err != nil {
		host = ""
	}
	switch ip := net.ParseIP(host); {
	case host == "":
		// Unparseable WebAddr - loopback plus hostname is the best guess.
	case ip == nil:
		dns = append(dns, host)
	case ip.IsUnspecified():
		// 0.0.0.0 / :: - the cert has to cover whatever address the admin
		// actually browses to, so enumerate them.
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				n, ok := a.(*net.IPNet)
				if ok && n.IP.IsGlobalUnicast() {
					ips = append(ips, n.IP)
				}
			}
		}
	default:
		ips = append(ips, ip)
	}

	return dedupeStrings(dns), dedupeIPs(ips)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dedupeIPs(in []net.IP) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	for _, ip := range in {
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

// writePEM writes one PEM block to path at mode perm, creating the parent
// directory. Like the settings file, it goes through a temp file and a rename
// so a half-written key can never be picked up as a real one.
func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if buf == nil {
		return fmt.Errorf("encoding %s for %s", blockType, path)
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, buf, perm); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming %s to %s: %w", tmp, path, err)
	}
	return nil
}
