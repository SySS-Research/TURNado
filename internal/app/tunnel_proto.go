package app

import (
	"encoding/binary"
	"fmt"
	"net"
)

type tunnelHeader struct {
	Version byte
	Type    byte
	ConnID  uint32
}

// Header: [ver:1][type:1][connID:4]
const (
	tunnelHeaderLen = 6
	maxPacketSize   = 1200
)

func buildPacket(msgType byte, connID uint32, payload []byte) []byte {
	buf := make([]byte, tunnelHeaderLen+len(payload))
	buf[0] = tunnelProtoVersion
	buf[1] = msgType
	binary.BigEndian.PutUint32(buf[2:tunnelHeaderLen], connID)
	copy(buf[tunnelHeaderLen:], payload)
	return buf
}

func parseHeader(pkt []byte) (tunnelHeader, []byte, error) {
	var h tunnelHeader
	if len(pkt) < tunnelHeaderLen {
		return h, nil, fmt.Errorf("packet too short for header")
	}
	h.Version = pkt[0]
	h.Type = pkt[1]
	h.ConnID = binary.BigEndian.Uint32(pkt[2:tunnelHeaderLen])
	if h.Version != tunnelProtoVersion {
		return h, nil, fmt.Errorf("unsupported version %d", h.Version)
	}
	return h, pkt[tunnelHeaderLen:], nil
}

func maxDataPayload(sec *secureSession) int {
	if sec != nil && sec.enabled {
		return maxPacketSize - (2 * tunnelHeaderLen) - aesIVLen
	}
	return maxPacketSize - tunnelHeaderLen
}

func encodeTargetAddr(host string, port int) ([]byte, error) {
	ip := net.ParseIP(host)
	var atyp byte
	var addrBytes []byte

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp = 0x01
			addrBytes = ip4
		} else {
			atyp = 0x04
			addrBytes = ip.To16()
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("hostname too long")
		}
		atyp = 0x03
		addrBytes = append([]byte{byte(len(host))}, []byte(host)...)
	}

	buf := make([]byte, 0, 1+len(addrBytes)+2)
	buf = append(buf, atyp)
	buf = append(buf, addrBytes...)
	buf = append(buf, byte(port>>8), byte(port&0xff))
	return buf, nil
}

func decodeTargetAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, fmt.Errorf("empty target payload")
	}
	atyp := b[0]
	off := 1
	var host string

	switch atyp {
	case 0x01:
		if len(b) < off+4+2 {
			return "", 0, fmt.Errorf("too short for IPv4")
		}
		ip := net.IPv4(b[off], b[off+1], b[off+2], b[off+3])
		host = ip.String()
		off += 4
	case 0x03:
		if len(b) < off+1 {
			return "", 0, fmt.Errorf("too short for domain length")
		}
		dlen := int(b[off])
		off++
		if len(b) < off+dlen+2 {
			return "", 0, fmt.Errorf("too short for domain")
		}
		host = string(b[off : off+dlen])
		off += dlen
	case 0x04:
		if len(b) < off+16+2 {
			return "", 0, fmt.Errorf("too short for IPv6")
		}
		ip := net.IP(b[off : off+16])
		host = ip.String()
		off += 16
	default:
		return "", 0, fmt.Errorf("unsupported ATYP %d", atyp)
	}

	if len(b) < off+2 {
		return "", 0, fmt.Errorf("too short for port")
	}
	port := int(b[off])<<8 | int(b[off+1])
	return host, port, nil
}

func parseSocks5RequestAddr(pkt []byte) (string, int, error) {
	if len(pkt) < 7 {
		return "", 0, fmt.Errorf("request too short")
	}
	if pkt[0] != 0x05 {
		return "", 0, fmt.Errorf("invalid VER %d", pkt[0])
	}
	atyp := pkt[3]
	off := 4

	var host string
	switch atyp {
	case 0x01:
		if len(pkt) < off+4+2 {
			return "", 0, fmt.Errorf("too short for IPv4")
		}
		ip := net.IPv4(pkt[off], pkt[off+1], pkt[off+2], pkt[off+3])
		host = ip.String()
		off += 4
	case 0x03:
		if len(pkt) < off+1 {
			return "", 0, fmt.Errorf("too short for domain length")
		}
		dlen := int(pkt[off])
		off++
		if len(pkt) < off+dlen+2 {
			return "", 0, fmt.Errorf("too short for domain")
		}
		host = string(pkt[off : off+dlen])
		off += dlen
	case 0x04:
		if len(pkt) < off+16+2 {
			return "", 0, fmt.Errorf("too short for IPv6")
		}
		ip := net.IP(pkt[off : off+16])
		host = ip.String()
		off += 16
	default:
		return "", 0, fmt.Errorf("unsupported ATYP %d", atyp)
	}

	if len(pkt) < off+2 {
		return "", 0, fmt.Errorf("too short for port")
	}
	port := int(pkt[off])<<8 | int(pkt[off+1])
	return host, port, nil
}
