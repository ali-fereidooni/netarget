package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

// Agents are reached by IP over the public internet with self-signed
// certificates, so the master trusts an agent by the SHA-256 of its leaf
// certificate (the value `openssl x509 -fingerprint -sha256` prints) rather
// than by a CA chain.

// Fingerprint returns the lowercase hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ParseFingerprint accepts a SHA-256 fingerprint as 64 hex digits, with or
// without the colons openssl prints, in either case.
func ParseFingerprint(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("cert_sha256 must be 64 hex digits (colons allowed)")
	}
	return b, nil
}

// ServerTLSConfig is the agent's listener config: TLS 1.2+ with the given cert.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
}

// clientTLSConfig pins the agent's leaf certificate when pin is set; chain,
// name and expiry checks are skipped because the pin is the trust anchor.
// VerifyConnection (unlike VerifyPeerCertificate) also runs on resumed
// sessions. Without a pin the system roots and normal verification apply.
func clientTLSConfig(pin []byte) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin == nil {
		return cfg
	}
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("agent presented no certificate")
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
			return errors.New("agent certificate does not match cert_sha256")
		}
		return nil
	}
	return cfg
}

// GenerateCert creates a self-signed ECDSA P-256 certificate for an agent and
// returns the PEM cert, the PEM (PKCS#8) key and the cert's fingerprint.
// hosts become SANs (IPs or DNS names); they are informational only, since
// pinned clients do not check names.
func GenerateCert(hosts []string, validity time.Duration) (certPEM, keyPEM []byte, fingerprint string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "netarget-agent"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	var c, k bytes.Buffer
	pem.Encode(&c, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&k, &pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	return c.Bytes(), k.Bytes(), Fingerprint(der), nil
}
