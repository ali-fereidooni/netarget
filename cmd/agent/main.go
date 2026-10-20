// Command agent runs on a measurement node and executes ping, TCP, HTTP and
// traceroute probes for the master. It must only be reachable from the
// master (see INSTALL.md for ufw rules). With AGENT_TLS_CERT/AGENT_TLS_KEY it
// serves HTTPS so the secret and results are encrypted when master and agent
// talk over the public internet; `gen-cert` creates a self-signed cert and
// prints the fingerprint the master pins (cert_sha256 in nodes.json).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"domaindoctor/internal/agent"
	"domaindoctor/internal/config"
	"domaindoctor/internal/probe"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen-cert" {
		if err := genCert(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "gen-cert:", err)
			os.Exit(1)
		}
		return
	}
	lg := log.New(os.Stderr, "agent ", log.LstdFlags|log.LUTC)
	secret := os.Getenv("AGENT_SECRET")
	if f := os.Getenv("AGENT_SECRET_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			lg.Fatalf("AGENT_SECRET_FILE: %v", err)
		}
		secret = string(trimSpace(b))
	}
	if len(secret) < 32 {
		lg.Fatal("AGENT_SECRET (or AGENT_SECRET_FILE) must be set to a random secret of at least 32 characters (openssl rand -hex 32)")
	}
	addr := config.Env("AGENT_LISTEN", "127.0.0.1:9090")
	ports, portSet := config.ServerCheckPorts(lg)
	extra := config.ServerCheckCustomPort()
	lg.Printf("TCP port allow-list: %v, plus %d custom port per check (SERVER_CHECK_PORTS / SERVER_CHECK_CUSTOM_PORT; must match the master)", ports, extra)
	h := (&agent.Server{Secret: secret, P: &probe.Local{AllowPorts: portSet, ExtraPorts: extra}, Log: lg}).Handler()

	hs := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	certFile, keyFile := os.Getenv("AGENT_TLS_CERT"), os.Getenv("AGENT_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		lg.Fatal("AGENT_TLS_CERT and AGENT_TLS_KEY must be set together")
	}
	if certFile != "" {
		// Load up front so a bad file fails at start, and log the
		// fingerprint so operators can compare it with cert_sha256.
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			lg.Fatalf("AGENT_TLS_CERT/AGENT_TLS_KEY: %v", err)
		}
		hs.TLSConfig = agent.ServerTLSConfig(cert)
		lg.Printf("TLS enabled, cert_sha256 %s", agent.Fingerprint(cert.Certificate[0]))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	lg.Printf("listening on %s", addr)
	var err error
	if hs.TLSConfig != nil {
		err = hs.ListenAndServeTLS("", "") // cert already in TLSConfig
	} else {
		err = hs.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		lg.Fatal(err)
	}
}

// genCert writes agent.crt (0644) and agent.key (0600) into -dir, refusing to
// overwrite existing files, and prints the cert_sha256 value for nodes.json.
func genCert(args []string) error {
	fs := flag.NewFlagSet("gen-cert", flag.ContinueOnError)
	dir := fs.String("dir", ".", "output directory for agent.crt and agent.key")
	hosts := fs.String("hosts", "", "comma-separated IPs/DNS names for the SAN (informational; pinning ignores names)")
	days := fs.Int("days", 3650, "validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *days < 1 {
		return errors.New("-days must be at least 1")
	}
	certPEM, keyPEM, fp, err := agent.GenerateCert(strings.Split(*hosts, ","), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(*dir) // absolute, so the printed env lines can be pasted as-is
	if err != nil {
		return err
	}
	certPath, keyPath := filepath.Join(abs, "agent.crt"), filepath.Join(abs, "agent.key")
	if err := writeNew(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(certPath, certPEM, 0o644); err != nil {
		os.Remove(keyPath)
		return err
	}
	fmt.Printf("wrote %s and %s\n", certPath, keyPath)
	fmt.Printf("AGENT_TLS_CERT=%s\nAGENT_TLS_KEY=%s\n", certPath, keyPath)
	fmt.Printf("cert_sha256: %s\n", fp)
	return nil
}

func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
