// Package config builds shared runtime dependencies from environment variables.
package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"domaindoctor/internal/asn"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/rdap"
	"domaindoctor/internal/whois"
)

// Env returns the value of key or def.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvInt returns an int env var or def.
func EnvInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

// DefaultServerCheckPorts is the small, provider-relevant TCP port set the
// Server Accessibility check uses when SERVER_CHECK_PORTS is not set.
const DefaultServerCheckPorts = "22,80,443,8443"

// ServerCheckPorts returns the configured TCP port allow-list for the
// Server Accessibility check (env SERVER_CHECK_PORTS, else the default). It
// must be set to the same value on the master and on every agent, because
// each agent enforces its own allow-list and rejects ports outside it. An
// invalid value falls back to the default and is logged.
func ServerCheckPorts(lg *log.Logger) (ordered []int, set map[int]bool) {
	raw := Env("SERVER_CHECK_PORTS", DefaultServerCheckPorts)
	set, err := probe.ParsePorts(raw)
	if err != nil || len(set) == 0 {
		if err != nil && lg != nil {
			lg.Printf("SERVER_CHECK_PORTS %q is invalid (%v); using %s", raw, err, DefaultServerCheckPorts)
		}
		set, _ = probe.ParsePorts(DefaultServerCheckPorts)
	}
	return probe.SortedPorts(set), set
}

// Deps builds orchestrator dependencies (DNS, RDAP, WHOIS, optional ASN).
func Deps(lg *log.Logger) (orchestrator.Deps, *asn.DB) {
	var db *asn.DB
	if p := os.Getenv("ASN_CSV_PATH"); p != "" {
		d, err := asn.LoadFile(p)
		if err != nil {
			lg.Printf("ASN dataset not loaded (%v); continuing without ASN enrichment", err)
		} else {
			lg.Printf("ASN dataset loaded: %d prefixes", d.Count)
			db = d
		}
	}
	dc := dnsx.New()
	switch mode := Env("DNS_TRANSPORT", "auto"); mode {
	case "doh":
		dc.DoH = true
	case "direct":
	default: // auto: fall back to DNS-over-HTTPS when port 53 is blocked
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		direct := dc.ProbeDirect(ctx)
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		if !direct {
			if dc.ProbeDoH(ctx) {
				dc.DoH = true
				lg.Printf("outbound DNS (port 53) is blocked; using DNS-over-HTTPS resolver mode (reduced name-server checks)")
			} else {
				lg.Printf("neither direct DNS nor DNS-over-HTTPS works from this host; DNS layers will fail")
			}
		}
		cancel()
	}
	deps := orchestrator.Deps{DNS: dc, RDAP: rdap.New(), WHOIS: whois.New(), Now: time.Now}
	if db != nil {
		deps.ASN = db
	}
	return deps, db
}

// Registry builds the node registry: NODES_FILE agents, plus an in-process
// local agent when LOCAL_AGENT=1 or when no NODES_FILE is configured.
func Registry(lg *log.Logger) (*nodes.Registry, error) {
	var ns []*nodes.Node
	if f := os.Getenv("NODES_FILE"); f != "" {
		reg, err := nodes.Load(f, os.Getenv)
		if err != nil {
			return nil, err
		}
		ns = append(ns, reg.All()...)
	}
	if os.Getenv("LOCAL_AGENT") == "1" || len(ns) == 0 {
		_, portSet := ServerCheckPorts(lg)
		local := &probe.Local{AllowPorts: portSet}
		ns = append([]*nodes.Node{nodes.LocalNode(Env("LOCAL_NODE_NAME", "Master node"), Env("LOCAL_NODE_LOCATION", "local"), local)}, ns...)
	}
	if len(ns) == 0 {
		return nil, fmt.Errorf("no measurement nodes configured")
	}
	reg := nodes.New(ns...)
	reg.Log = lg
	return reg, nil
}
