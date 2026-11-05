package app

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPairingInputEOFReportsCause(t *testing.T) {
	a, _ := testTransport(t, true)
	readPeerAnswer(context.Background(), strings.NewReader("\n"), nil, a, "", true, 0)
	if _, err := a.waitPeer(); err == nil || !strings.Contains(err.Error(), "pairing input closed") {
		t.Fatalf("waitPeer error = %v", err)
	}
}

func TestPairingFailureReportsCause(t *testing.T) {
	a, _ := testTransport(t, true)
	b, _ := testTransport(t, true)
	wrong := testIdentity(t).fingerprint
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = b.pair(ctx, a.LocalAddr().(*net.UDPAddr), a.identity.fingerprint, false) }()
	if err := a.pair(ctx, b.LocalAddr().(*net.UDPAddr), wrong, true); err == nil {
		t.Fatal("pairing with a wrong fingerprint succeeded")
	}
	_, err := a.waitPeer()
	if err == nil || !strings.Contains(err.Error(), "pairing failed") || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("waitPeer error = %v, want the pairing cause", err)
	}
}

func TestExitPrefersConnectionStringCredentialsOverEnvironment(t *testing.T) {
	t.Setenv(envUsername, "env-user")
	t.Setenv(envPassword, "env-pass")
	offer := connString{V: 1, Turn: "turn.example:3478", User: "offer-user", Pass: "offer-pass", Control: "udp", Relay: "192.0.2.1:5000"}
	s, err := encodeConnString(offer, "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg tunnelCfg
	ok, err := parsePairedMode("tunnel", []string{"-c", s, "--no-tunnel-encryption"}, &cfg, nil)
	if err != nil || !ok {
		t.Fatalf("parse: ok=%v err=%v", ok, err)
	}
	if err := applyConnStringDefaults(&cfg, offer); err != nil {
		t.Fatal(err)
	}
	if cfg.Common.Username != "offer-user" || cfg.Common.Password != "offer-pass" {
		t.Fatalf("exit credentials = %q/%q, want the offer's", cfg.Common.Username, cfg.Common.Password)
	}

	var explicit tunnelCfg
	if _, err := parsePairedMode("tunnel", []string{"-c", s, "--no-tunnel-encryption", "-u", "flag-user", "-p", "flag-pass"}, &explicit, nil); err != nil {
		t.Fatal(err)
	}
	if err := applyConnStringDefaults(&explicit, offer); err != nil {
		t.Fatal(err)
	}
	if explicit.Common.Username != "flag-user" || explicit.Common.Password != "flag-pass" {
		t.Fatalf("explicit flags overridden: %q/%q", explicit.Common.Username, explicit.Common.Password)
	}

	noCreds := offer
	noCreds.User, noCreds.Pass = "", ""
	var fallback tunnelCfg
	if err := applyConnStringDefaults(&fallback, noCreds); err != nil {
		t.Fatal(err)
	}
	if fallback.Common.Username != "env-user" || fallback.Common.Password != "env-pass" {
		t.Fatalf("environment fallback missing: %q/%q", fallback.Common.Username, fallback.Common.Password)
	}
}

func TestSocksForwardFlagsRemoved(t *testing.T) {
	for _, flag := range []string{"-L", "--local-forward", "-R", "--remote-forward"} {
		if err := RunSocks([]string{flag, "127.0.0.1:1=127.0.0.1:2", "--help"}); err == nil {
			t.Errorf("removed flag %s was accepted", flag)
		}
	}
	if _, ok := LookupMode("bench"); ok {
		t.Error("removed bench mode is still registered")
	}
}
