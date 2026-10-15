// Command master serves the netarget web UI and API and orchestrates
// checks across measurement agents. Configuration is via environment
// variables; see INSTALL.md.
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

	"domaindoctor/internal/api"
	"domaindoctor/internal/clientip"
	"domaindoctor/internal/config"
	"domaindoctor/internal/report"
	"domaindoctor/web"
)

func main() {
	lg := log.New(os.Stderr, "master ", log.LstdFlags|log.LUTC)
	addr := config.Env("LISTEN_ADDR", "127.0.0.1:8082")

	reg, err := config.Registry(lg)
	if err != nil {
		lg.Fatalf("node registry: %v", err)
	}
	deps, asnDB := config.Deps(lg)

	hops := config.EnvInt("TRUSTED_PROXY_HOPS", 1)
	cidrs, err := clientip.ParseCIDRs(config.Env("TRUSTED_PROXY_CIDRS", "127.0.0.1,::1"))
	if err != nil {
		lg.Fatalf("TRUSTED_PROXY_CIDRS: %v", err)
	}
	if hops > 0 {
		// X-Forwarded-For is only honoured from these peers; anyone else is
		// rate-limited by their socket address.
		lg.Printf("trusting %d proxy hop(s) from %v", hops, cidrs)
	}
	var store *report.Store
	if dir := config.Env("REPORTS_DIR", "./data/reports"); dir != "-" {
		store, err = report.OpenStore(dir, config.EnvInt("REPORTS_CAP", 2000), 24*time.Hour)
		if err != nil {
			lg.Printf("permanent links disabled: %v", err)
			store = nil
		}
	}

	srv := api.New(api.Config{
		Deps:          deps,
		Registry:      reg,
		ClientIP:      clientip.Extractor{Hops: hops, TrustedCIDRs: cidrs},
		Store:         store,
		ASN:           asnDB,
		UI:            web.Static(),
		MaxConcurrent: config.EnvInt("MAX_CONCURRENT_CHECKS", 30),
		Log:           lg,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reg.StartHealthChecker(ctx, 12*time.Second, 3*time.Second)
	srv.StartBackground(ctx)

	hs := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: SSE streams are long-lived; handlers bound their own work.
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	lg.Printf("listening on %s with %d node(s)", addr, len(reg.All()))
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		lg.Fatal(err)
	}
}
