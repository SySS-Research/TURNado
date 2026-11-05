package app

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"
)

const (
	envUsername = "TURNADO_USERNAME"
	envPassword = "TURNADO_PASSWORD"
)

// promptSecret reads from the controlling terminal so stdin stays free for
// connection-string pairing. Tests replace it.
var promptSecret = func(prompt string) (string, error) {
	in := os.Stdin
	if runtime.GOOS != "windows" {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			defer tty.Close()
			in = tty
		}
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(b), nil
}

// resolveCredentials accepts an explicit password, a terminal prompt, or the environment.
func resolveCredentials(cfg *commonConfig) error {
	if err := promptCredentials(cfg); err != nil {
		return err
	}
	applyCredentialEnv(cfg)
	return nil
}

// promptCredentials replaces "-p -" with a password read from the terminal.
func promptCredentials(cfg *commonConfig) error {
	if cfg.Password != "-" {
		return nil
	}
	p, err := promptSecret("TURN password: ")
	if err != nil {
		return err
	}
	cfg.Password = p
	return nil
}

// applyCredentialEnv fills credentials that are still unset from the environment.
func applyCredentialEnv(cfg *commonConfig) {
	if cfg.Username == "" {
		cfg.Username = os.Getenv(envUsername)
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv(envPassword)
	}
}
