//go:build linux

package app

import (
	"os"
	"testing"
	"time"
)

func TestTunDeviceCloseUnblocksRead(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	tun := &tunDevice{file: r, name: "test"}
	done := make(chan error, 1)
	go func() { _, err := tun.Read(make([]byte, 1500)); done <- err }()
	// Ensure this exercises an already-blocked read, not a read after Close.
	select {
	case err := <-done:
		t.Fatalf("read returned before close: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read unexpectedly succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("closing TUN did not unblock its read")
	}
}
