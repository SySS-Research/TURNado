//go:build windows

package app

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableANSI turns on virtual terminal processing for a Windows console so
// ANSI escape codes render instead of printing raw. It reports false for
// redirected output and for consoles without VT support.
func enableANSI(f *os.File) bool {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
