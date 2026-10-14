// Command agent runs on a measurement node and executes ping, TCP, HTTP and
// traceroute probes for the master. It must only be reachable from the
// master over private networking (see INSTALL.md for ufw rules).
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"domaindoctor/internal/agent"
	"domaindoctor/internal/config"
	"domaindoctor/internal/probe"
)

func main() {
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
	h := (&agent.Server{Secret: secret, P: &probe.Local{}, Log: lg}).Handler()

	hs := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	lg.Printf("listening on %s", addr)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		lg.Fatal(err)
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
