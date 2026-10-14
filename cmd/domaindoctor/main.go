// Command domaindoctor is the CLI: it runs a full check in-process using a
// local agent (or the agents in NODES_FILE) and prints a summary or JSON.
//
//	domaindoctor check example.com [--json] [--md] [--timeout 3m]
//
// Exit status: 0 no failures, 2 at least one layer FAILed, 1 usage/input error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"domaindoctor/internal/checks"
	"domaindoctor/internal/config"
	"domaindoctor/internal/input"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/report"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: domaindoctor check <domain> [--json] [--md] [--timeout 3m]")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "check" {
		usage()
	}
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	asMD := fs.Bool("md", false, "print the report as Markdown")
	timeout := fs.Duration("timeout", 3*time.Minute, "overall timeout")
	verbose := fs.Bool("v", false, "log progress to stderr")
	// Flags may come before or after the domain.
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() == 0 {
		usage()
	}
	domainArg := fs.Arg(0)
	_ = fs.Parse(fs.Args()[1:])
	if fs.NArg() > 0 {
		usage()
	}
	d, err := input.Normalize(domainArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	lg := log.New(io.Discard, "", 0)
	if *verbose {
		lg = log.New(os.Stderr, "", 0)
	}
	reg, err := config.Registry(lg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	deps, _ := config.Deps(lg)
	deps.Nodes = reg.Live
	if deps.DNS.DoH {
		fmt.Fprintln(os.Stderr, "note: port 53 is blocked here; using DNS-over-HTTPS resolver mode (name-server checks are reduced)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	quiet := *asJSON || *asMD
	rep := orchestrator.Run(ctx, deps, d, report.NewID(), func(e orchestrator.Event) {
		if quiet || e.Type != "layer_done" {
			return
		}
		r := e.Result
		fmt.Printf("%-8s %-20s %s\n", "["+string(r.Status)+"]", r.Title, r.Summary)
	})

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	case *asMD:
		fmt.Print(orchestrator.Markdown(rep))
	default:
		printSummary(rep)
	}
	for _, l := range rep.Layers {
		if l.Status == checks.FAIL {
			os.Exit(2)
		}
	}
}

func printSummary(rep *orchestrator.Report) {
	d := rep.Diagnosis
	fmt.Println()
	fmt.Println("Diagnosis:", d.Headline)
	if d.RootCause != nil {
		fmt.Printf("  Root cause [%s]: %s\n", d.RootCause.Layer, d.RootCause.Explanation)
		if d.RootCause.Evidence != "" {
			fmt.Printf("  Evidence: %s\n", d.RootCause.Evidence)
		}
	}
	for _, c := range d.Causes {
		fmt.Printf("  Also: [%s] %s\n", c.Layer, c.Explanation)
	}
	if len(d.Symptoms) > 0 {
		fmt.Println("  Symptoms of the cause above:")
		for _, s := range d.Symptoms {
			fmt.Printf("    - %s\n", s.Message)
		}
	}
	if len(d.Fixes) > 0 {
		fmt.Println("\nFixes (in priority order):")
		for i, f := range d.Fixes {
			fmt.Printf("  %d. [P%d] %s — %s\n", i+1, f.Priority, f.Title, f.Action)
		}
	}
}
