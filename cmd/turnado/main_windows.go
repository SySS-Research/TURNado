//go:build windows

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
		fmt.Fprintln(os.Stderr, "TURNado\n")
	} else {
		fmt.Fprintln(os.Stderr, "🌪️ \033[1mTURNado\033[0m 🦈\n")
	}
	fmt.Fprintln(os.Stderr, "Tool suite for testing and (ab)using TURN servers")
	fmt.Fprintln(os.Stderr, "by Moritz Abrell, SySS GmbH\n")
	fmt.Fprintf(os.Stderr, "Usage: %s <mode> [options]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Modes:")
	fmt.Fprintln(os.Stderr, "  info     Inspect TURN server capabilities")
	fmt.Fprintln(os.Stderr, "  socks    SOCKS5-over-TURN UDP tunnel")
	fmt.Fprintln(os.Stderr, "  forward  UDP forwarder over TURN")
	fmt.Fprintln(os.Stderr, "  dos      Mass allocation creation for load tests")
	fmt.Fprintln(os.Stderr, "  --version, -V  Print version")
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
		if len(args) == 0 {
			usage()
			return
		}
		switch args[0] {
		case "info":
			_ = app.RunInfo([]string{"-h"})
		case "socks":
			_ = app.RunSocks([]string{"-h"})
		case "forward":
			_ = app.RunForward([]string{"-h"})
		case "dos":
			_ = app.RunDOS([]string{"-h"})
		default:
			usage()
		}
		return
	}
	if mode == "--version" || mode == "-V" {
		fmt.Printf("TURNado v%s\n", app.Version)
		return
	}

	var err error
	switch mode {
	case "info":
		err = app.RunInfo(args)
	case "socks":
		err = app.RunSocks(args)
	case "forward":
		err = app.RunForward(args)
	case "dos":
		err = app.RunDOS(args)
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
