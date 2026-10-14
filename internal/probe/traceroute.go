package probe

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

var ErrNoTraceroute = errors.New("traceroute is not available on this node")

func tracerouteCmd(goos string, ip netip.Addr, maxHops int) (string, []string) {
	if goos == "windows" {
		args := []string{"-d", "-h", strconv.Itoa(maxHops), "-w", "2000"}
		if ip.Is6() {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
		}
		return "tracert", append(args, ip.String())
	}
	args := []string{"-n", "-q", "1", "-w", "2", "-m", strconv.Itoa(maxHops)}
	if ip.Is6() {
		args = append(args, "-6")
	} else {
		args = append(args, "-4")
	}
	return "traceroute", append(args, ip.String())
}

// Traceroute streams output lines to line. ip must already be validated.
func Traceroute(ctx context.Context, ip netip.Addr, maxHops int, line func(string)) error {
	if maxHops < 5 || maxHops > 64 {
		maxHops = 30
	}
	name, args := tracerouteCmd(runtime.GOOS, ip, maxHops)
	path, err := exec.LookPath(name)
	if err != nil {
		return ErrNoTraceroute
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(maxHops)*7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			line(t)
		}
	}
	return cmd.Wait()
}

var reHopIP = regexp.MustCompile(`^\s*(\d+)\s+.*?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)`)

// HopIP extracts the hop number and first IP from a traceroute/tracert line.
func HopIP(line string) (int, netip.Addr, bool) {
	m := reHopIP.FindStringSubmatch(line)
	if m == nil {
		return 0, netip.Addr{}, false
	}
	n, _ := strconv.Atoi(m[1])
	a, err := netip.ParseAddr(m[2])
	if err != nil {
		return 0, netip.Addr{}, false
	}
	return n, a, true
}
