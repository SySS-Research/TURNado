//go:build darwin

package app

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/songgao/water"
)

const tunSupported = true

type tunDevice struct {
	iface *water.Interface
	name  string
}

func openTun(name string) (*tunDevice, error) {
	if name != "" && name != "turn%d" {
		return nil, fmt.Errorf("macOS assigns utun names automatically")
	}
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, fmt.Errorf("open macOS utun: %w", err)
	}
	return &tunDevice{iface: iface, name: iface.Name()}, nil
}
func (t *tunDevice) Read(p []byte) (int, error)  { return t.iface.Read(p) }
func (t *tunDevice) Write(p []byte) (int, error) { return t.iface.Write(p) }
func (t *tunDevice) Close() error {
	if t == nil || t.iface == nil {
		return nil
	}
	return t.iface.Close()
}

func configureTun(name, ipStr, peerIP, maskStr string, mtu int) error {
	_ = maskStr // utun is a point-to-point interface.
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("invalid TUN MTU %d", mtu)
	}
	out, err := exec.Command("ifconfig", name, "inet", ipStr, peerIP, "mtu", strconv.Itoa(mtu), "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure utun: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
