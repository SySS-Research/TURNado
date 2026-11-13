package main

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"turnado/internal/app"
)

func usage() {
	if runtime.GOOS == "windows" {
		fmt.Fprint(os.Stderr, "TURNado\n\n")
	} else {
		fmt.Fprint(os.Stderr, "🌪️ \033[1mTURNado\033[0m 🦈\n\n")
	}
	fmt.Fprintln(os.Stderr, "Tool suite for testing and (ab)using TURN servers")
	fmt.Fprint(os.Stderr, "by Moritz Abrell, SySS GmbH\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s <mode> [options]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Modes:")
	for _, m := range app.Modes() {
		fmt.Fprintf(os.Stderr, "  %-8s %s\n", m.Name, m.Summary)
	}
	fmt.Fprintln(os.Stderr, "  --version, -V  Print version")
	fmt.Fprintln(os.Stderr, "\nRFC 6062 required: scan, tcprelay, socks --direct, and the TCP probes in info.")
	fmt.Fprintln(os.Stderr, "Paired socks, tunnel, forward, and dos use TURN UDP allocations.")
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  turnado info -t turn.example.org:3478 -u user -p -")
	fmt.Fprintln(os.Stderr, "  turnado help tunnel")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	mode := os.Args[1]
	args := os.Args[2:]

	if mode == "help" || mode == "-h" || mode == "--help" {
		if len(args) > 0 {
			if m, ok := app.LookupMode(args[0]); ok {
				_ = m.Run([]string{"-h"})
				return
			}
		}
		usage()
		return
	}
	if mode == "--version" || mode == "-V" {
		fmt.Printf("TURNado v%s\n", app.Version)
		return
	}

	m, ok := app.LookupMode(mode)
	if !ok {
		usage()
		os.Exit(2)
	}
	if err := m.Run(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
