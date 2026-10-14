package safenet

import (
	"context"
	"net"
	"net/http"
	"time"
)

// SafeDialContext resolves the host once through Resolve (rejecting blocked
// addresses) and dials only the pinned results. Suitable for clients whose
// destinations come from semi-trusted sources (RDAP bootstrap, WHOIS
// referrals) where per-connection pinning is enough.
func SafeDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := Resolve(ctx, nil, host)
		if err != nil {
			return nil, err
		}
		return PinnedDialContext(ips, timeout)(ctx, network, addr)
	}
}

// SafeHTTPClient returns an HTTP client whose every connection goes through
// SafeDialContext and which does not follow redirects to other hosts blindly:
// each redirect hop re-enters the dialer and is validated again.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           SafeDialContext(5 * time.Second),
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
}
