//go:build windows

package app

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const tunSupported = true

type tunDevice struct {
	adapter         *wintun.Adapter
	session         wintun.Session
	name            string
	readMu, writeMu sync.Mutex
	closed          atomic.Bool
}

func openTun(name string) (*tunDevice, error) {
	if name == "" || name == "turn%d" {
		name = "TURNado"
	}
	name = strings.ReplaceAll(name, "%d", "0")
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		adapter, err = wintun.CreateAdapter(name, "Wintun", nil)
	}
	if err != nil {
		return nil, fmt.Errorf("open Wintun adapter (wintun.dll required): %w", err)
	}
	session, err := adapter.StartSession(0x400000)
	if err != nil {
		_ = adapter.Close()
		return nil, err
	}
	return &tunDevice{adapter: adapter, session: session, name: name}, nil
}

func (t *tunDevice) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for !t.closed.Load() {
		packet, err := t.session.ReceivePacket()
		if err == nil {
			n := copy(p, packet)
			t.session.ReleaseReceivePacket(packet)
			if n < len(packet) {
				return n, fmt.Errorf("TUN read buffer too small")
			}
			return n, nil
		}
		if err != windows.ERROR_NO_MORE_ITEMS {
			return 0, err
		}
		_, err = windows.WaitForSingleObject(t.session.ReadWaitEvent(), 100)
		if err != nil {
			return 0, err
		}
	}
	return 0, net.ErrClosed
}

func (t *tunDevice) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.closed.Load() {
		return 0, net.ErrClosed
	}
	packet, err := t.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(packet, p)
	t.session.SendPacket(packet)
	return len(p), nil
}

func (t *tunDevice) Close() error {
	if t == nil || !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.session.End()
	return t.adapter.Close()
}

func configureTun(name, ipStr, peerIP, maskStr string, mtu int) error {
	_ = peerIP
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("invalid TUN MTU %d", mtu)
	}
	if out, err := exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+name, "static", ipStr, maskStr).CombinedOutput(); err != nil {
		return fmt.Errorf("configure Wintun address: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", name, "mtu="+strconv.Itoa(mtu), "store=active").CombinedOutput(); err != nil {
		return fmt.Errorf("configure Wintun MTU: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
