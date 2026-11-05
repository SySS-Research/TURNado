//go:build !windows

package app

import (
	"os"

	"golang.org/x/term"
)

// enableANSI reports whether f is a terminal that renders ANSI escape codes.
func enableANSI(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
