//go:build !linux && !darwin && !windows

package app

import (
	"fmt"
	"os"
)

const tunSupported = false

type tunDevice struct {
	file *os.File
	name string
}

func openTun(name string) (*tunDevice, error) {
	return nil, fmt.Errorf("tun mode is not supported on this platform")
}

func configureTun(name, ipStr, peerIP, maskStr string, mtu int) error {
	return fmt.Errorf("tun mode is not supported on this platform")
}

func (t *tunDevice) Read(b []byte) (int, error) {
	return 0, fmt.Errorf("tun mode is not supported on this platform")
}

func (t *tunDevice) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("tun mode is not supported on this platform")
}

func (t *tunDevice) Close() error {
	return nil
}
