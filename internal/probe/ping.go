package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var ErrNoPing = errors.New("ping binary not available on this node")

// pingArgs builds the argument slice. The target is always an IP literal
// produced by netip, so no user text reaches exec.
func pingArgs(goos string, ip netip.Addr, count int) []string {
	if goos == "windows" {
		args := []string{"-n", strconv.Itoa(count), "-w", "2000"}
		if ip.Is6() {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
		}
		return append(args, ip.String())
	}
	args := []string{"-n", "-c", strconv.Itoa(count), "-i", "0.5", "-W", "2"}
	if ip.Is6() {
		args = append(args, "-6")
	} else {
		args = append(args, "-4")
	}
	return append(args, ip.String())
}

// Ping runs the system ping and parses its summary.
func Ping(ctx context.Context, ip netip.Addr, count int) (*PingResult, error) {
	if count < 1 || count > 10 {
		count = 4
	}
	path, err := exec.LookPath("ping")
	if err != nil {
		return nil, ErrNoPing
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(count)*2*time.Second+5*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, path, pingArgs(runtime.GOOS, ip, count)...).CombinedOutput()
	res, perr := ParsePing(string(out))
	if perr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("ping failed: %s", firstLine(string(out)))
		}
		return nil, perr
	}
	// Non-zero exit with parsed output just means packet loss.
	return res, nil
}

var (
	reLinuxCount = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received`)
	reLinuxRTT   = regexp.MustCompile(`(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)`)
	reWinCount   = regexp.MustCompile(`Sent = (\d+), Received = (\d+)`)
	reWinRTT     = regexp.MustCompile(`Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms`)
)

// ParsePing parses Linux (iputils/busybox), BSD/macOS and Windows ping output.
func ParsePing(out string) (*PingResult, error) {
	r := &PingResult{}
	switch {
	case reLinuxCount.MatchString(out):
		m := reLinuxCount.FindStringSubmatch(out)
		r.Sent, _ = strconv.Atoi(m[1])
		r.Received, _ = strconv.Atoi(m[2])
		if m := reLinuxRTT.FindStringSubmatch(out); m != nil {
			r.RTTMin, _ = strconv.ParseFloat(m[1], 64)
			r.RTTAvg, _ = strconv.ParseFloat(m[2], 64)
			r.RTTMax, _ = strconv.ParseFloat(m[3], 64)
		}
	case reWinCount.MatchString(out):
		m := reWinCount.FindStringSubmatch(out)
		r.Sent, _ = strconv.Atoi(m[1])
		r.Received, _ = strconv.Atoi(m[2])
		// Windows counts "Destination host unreachable" replies as received.
		r.Received -= strings.Count(out, "unreachable")
		if r.Received < 0 {
			r.Received = 0
		}
		if m := reWinRTT.FindStringSubmatch(out); m != nil && r.Received > 0 {
			r.RTTMin, _ = strconv.ParseFloat(m[1], 64)
			r.RTTMax, _ = strconv.ParseFloat(m[2], 64)
			r.RTTAvg, _ = strconv.ParseFloat(m[3], 64)
		}
	default:
		return nil, errors.New("unrecognized ping output")
	}
	if r.Sent > 0 {
		r.Loss = float64(r.Sent-r.Received) * 100 / float64(r.Sent)
	}
	return r, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
