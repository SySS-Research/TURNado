//go:build linux

package app

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

type tunDevice struct {
	file *os.File
	name string
}

func (t *tunDevice) Read(b []byte) (int, error) {
	for {
		n, err := unix.Read(int(t.file.Fd()), b)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

func (t *tunDevice) Write(b []byte) (int, error) {
	for {
		n, err := unix.Write(int(t.file.Fd()), b)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

func (t *tunDevice) Close() error {
	if t == nil || t.file == nil {
		return nil
	}
	return t.file.Close()
}

func configureTun(name, ipStr, maskStr string) error {
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
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun failed: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("invalid tun name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	if err := unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, ifr); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("TUNSETIFF failed: %w", err)
	}

	return &tunDevice{
		file: f,
		name: ifr.Name(),
	}, nil
}
