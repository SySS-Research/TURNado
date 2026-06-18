//go:build !linux

package app

import (
	"fmt"
	"os"
)

type tunDevice struct {
	file *os.File
	name string
}

func openTun(name string) (*tunDevice, error) {
	return nil, fmt.Errorf("tun mode is only supported on linux")
}

func configureTun(name, ipStr, maskStr string) error {
	return fmt.Errorf("tun mode is only supported on linux")
}

func (t *tunDevice) Read(b []byte) (int, error) {
	return 0, fmt.Errorf("tun mode is only supported on linux")
}

func (t *tunDevice) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("tun mode is only supported on linux")
}

func (t *tunDevice) Close() error {
	return nil
}
