//go:build linux

package app

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const tunSupported = true

type tunDevice struct {
	file *os.File
	name string
}

func (t *tunDevice) Read(b []byte) (int, error) {
	return t.file.Read(b)
}

func (t *tunDevice) Write(b []byte) (int, error) {
	return t.file.Write(b)
}

func (t *tunDevice) Close() error {
	if t == nil || t.file == nil {
		return nil
	}
	return t.file.Close()
}

func configureTun(name, ipStr, peerIP, maskStr string, mtu int) error {
	_ = peerIP
	if name == "" {
		return fmt.Errorf("missing tun name")
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid tun ip %q", ipStr)
	}
	mask := net.ParseIP(maskStr).To4()
	if mask == nil {
		return fmt.Errorf("invalid tun netmask %q", maskStr)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket failed: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	if err := ifr.SetInet4Addr(ip); err != nil {
		return fmt.Errorf("set tun ip failed: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifr); err != nil {
		return fmt.Errorf("SIOCSIFADDR failed: %w", err)
	}

	ifr, err = unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	if err := ifr.SetInet4Addr(mask); err != nil {
		return fmt.Errorf("set tun netmask failed: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, ifr); err != nil {
		return fmt.Errorf("SIOCSIFNETMASK failed: %w", err)
	}
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("invalid tun MTU %d", mtu)
	}
	ifr, err = unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	ifr.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("SIOCSIFMTU failed: %w", err)
	}

	ifr, err = unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS failed: %w", err)
	}
	flags := ifr.Uint16()
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS failed: %w", err)
	}

	return nil
}

func openTun(name string) (*tunDevice, error) {
	if name == "" {
		name = "turn%d"
	}
	// Keep the descriptor nonblocking so os.File uses the runtime poller.
	// Closing it then wakes both pumps when the TURN control connection fails.
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun failed: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF failed: %w", err)
	}

	return &tunDevice{
		file: os.NewFile(uintptr(fd), "/dev/net/tun"),
		name: ifr.Name(),
	}, nil
}
