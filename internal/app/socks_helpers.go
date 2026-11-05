package app

import (
	"errors"
	"fmt"
	"io"
	"net"
)

func readSocks5Request(c io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[2] != 0 {
		return nil, fmt.Errorf("invalid SOCKS5 request header")
	}
	var addressLen int
	switch header[3] {
	case 1:
		addressLen = 4
	case 4:
		addressLen = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(c, length); err != nil {
			return nil, err
		}
		header = append(header, length[0])
		addressLen = int(length[0])
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 address type %d", header[3])
	}
	rest := make([]byte, addressLen+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		return nil, err
	}
	return append(header, rest...), nil
}

func socksDialError(err error) byte {
	var op *net.OpError
	if errors.As(err, &op) && op.Timeout() {
		return 0x06
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return 0x04
	}
	return 0x05
}
