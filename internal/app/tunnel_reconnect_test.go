package app

import (
	"bytes"
	"testing"
	"time"
)

func TestPeerResumesOnExistingAllocationAfterTimeout(t *testing.T) {
	a, _ := testTransport(t, false)
	b, _ := testTransport(t, false)
	pairTransports(t, a, b)
	b.lastSeen.Store(time.Now().Add(-2 * peerTimeout).UnixNano())
	b.checkPeerTimeout(time.Now())
	if !b.stale.Load() {
		t.Fatal("peer was not marked inactive")
	}
	select {
	case <-b.closed:
		t.Fatal("allocation closed while waiting for peer")
	default:
	}
	want := buildPacket(msgTypeIP, 0, []byte("resumed without a new connection string"))
	sendPacket(t, a, b.LocalAddr(), want)
	if got := readPacket(t, b); !bytes.Equal(got, want) {
		t.Fatalf("resumed packet = %q", got)
	}
	if b.stale.Load() {
		t.Fatal("peer remained inactive after a valid packet")
	}
}

func TestConnectionFileFlagsRemoved(t *testing.T) {
	for _, flag := range []string{"--connect-file", "--answer-file", "--connection-file"} {
		if err := RunTunnel([]string{flag, "unused", "--help"}); err == nil {
			t.Errorf("removed flag %s was accepted", flag)
		}
	}
}

func TestTunnelDefaultsAndRemovedFlags(t *testing.T) {
	t.Setenv(envPassword, "test-password")
	for _, tc := range []struct {
		args           []string
		wantEncryption bool
	}{
		{[]string{"-t", "localhost:3478"}, true},
		{[]string{"-t", "localhost:3478", "--no-tunnel-encryption"}, false},
	} {
		var cfg tunnelCfg
		ok, err := parsePairedMode("tunnel", tc.args, &cfg, nil)
		if err != nil || !ok || cfg.Encrypt != tc.wantEncryption {
			t.Fatalf("args=%v encryption=%v err=%v", tc.args, cfg.Encrypt, err)
		}
	}
	for _, flag := range []string{"--password-file", "--socks-password-file", "--reconnect", "-E", "--encrypt", "--identity", "--nat-out", "--netmask", "--route", "--tun-name", "--allocations", "--reliable"} {
		var err error
		if flag == "--socks-password-file" || flag == "--reliable" {
			err = RunSocks([]string{flag, "unused", "--help"})
		} else {
			err = RunTunnel([]string{flag, "unused", "--help"})
		}
		if err == nil {
			t.Errorf("removed flag %s was accepted", flag)
		}
	}
}
