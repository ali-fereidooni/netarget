package probe

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"time"
)

var tlsVersions = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1", tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3",
}

// InspectTLS reports certificate details and performs verification itself,
// so an invalid certificate is described rather than just rejected.
func InspectTLS(cs tls.ConnectionState, host string, roots *x509.CertPool, now time.Time) *TLSInfo {
	info := &TLSInfo{Version: tlsVersions[cs.Version], Cipher: tls.CipherSuiteName(cs.CipherSuite), ChainLength: len(cs.PeerCertificates)}
	if len(cs.PeerCertificates) == 0 {
		info.ChainError = "server sent no certificate"
		return info
	}
	leaf := cs.PeerCertificates[0]
	info.Subject = leaf.Subject.CommonName
	info.Issuer = leaf.Issuer.CommonName
	if info.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		info.Issuer = leaf.Issuer.Organization[0]
	}
	info.NotBefore, info.NotAfter = leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	info.DaysLeft = int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24))
	info.SANs = append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}
	info.HostnameMatch = leaf.VerifyHostname(host) == nil
	info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String() && leaf.CheckSignatureFrom(leaf) == nil

	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now}
	if _, err := leaf.Verify(opts); err != nil {
		info.ChainError = chainErr(err)
		var ua x509.UnknownAuthorityError
		if errors.As(err, &ua) && !info.SelfSigned && len(cs.PeerCertificates) == 1 {
			info.IncompleteChain = true
		}
	} else {
		info.ChainValid = true
	}
	return info
}

func chainErr(err error) string {
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) {
		switch ci.Reason {
		case x509.Expired:
			return "certificate expired or not yet valid"
		}
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return "certificate signed by unknown authority"
	}
	return err.Error()
}
