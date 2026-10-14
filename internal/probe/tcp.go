package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"domaindoctor/internal/safenet"
)

// TCPConnect tests one port: open (handshake ok), closed (RST), filtered (timeout/no answer).
func TCPConnect(ctx context.Context, ip netip.Addr, port int, timeout time.Duration, allowLoopback bool) TCPResult {
	res := TCPResult{Port: port}
	d := safenet.Dialer(timeout)
	if allowLoopback {
		d = &net.Dialer{Timeout: timeout}
	}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err == nil {
		res.Status, res.LatencyMS = "open", ms(time.Since(start))
		c.Close()
		return res
	}
	switch ErrorKind(err) {
	case "refused":
		res.Status, res.LatencyMS = "closed", ms(time.Since(start))
	case "blocked":
		res.Status, res.Error = "filtered", "blocked target"
	default:
		res.Status, res.Error = "filtered", ErrorKind(err)
	}
	return res
}

// ErrorKind classifies a network/HTTP error into a stable, non-leaky label.
func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, safenet.ErrBlocked) || errors.Is(err, safenet.ErrNoAddress) {
		if errors.Is(err, safenet.ErrNoAddress) {
			return "dns"
		}
		return "blocked"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "reset"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "eof"):
		return "reset"
	case strings.Contains(s, "tls:") || strings.Contains(s, "handshake") || strings.Contains(s, "first record does not look like a tls"):
		return "tls_handshake"
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out"):
		return "timeout"
	case strings.Contains(s, "unreachable") || strings.Contains(s, "no route"):
		return "unreachable"
	}
	return "other"
}
