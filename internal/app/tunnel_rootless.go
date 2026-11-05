package app

import (
	"encoding/binary"
	"net"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
)

type stackWriter struct {
	stack   *slirp.Stack
	gateway net.IP
	reply   func([]byte) error
}

func (w stackWriter) Write(p []byte) (int, error) {
	if response, ok := rootlessGatewayEchoReply(p, w.gateway); ok {
		if err := w.reply(response); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if err := w.stack.Send(pktkit.Packet(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func runTurnTunRootlessExit(transport *peerTransport, gateway string, verbose int) error {
	peer, err := transport.waitPeer()
	if err != nil {
		return err
	}
	stack := slirp.New()
	defer stack.Close()
	stack.SetHandler(func(packet pktkit.Packet) error {
		return sendTunPayload(transport, peer, packet)
	})
	writer := stackWriter{stack: stack, gateway: net.ParseIP(gateway).To4(), reply: func(packet []byte) error {
		return sendTunPayload(transport, peer, packet)
	}}
	return turnToTunLoop(transport, writer, newFragReassembler(), verbose)
}

func rootlessGatewayEchoReply(packet []byte, gateway net.IP) ([]byte, bool) {
	if len(packet) < 28 || packet[0]>>4 != 4 || gateway == nil {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 || packet[9] != 1 || !net.IP(packet[16:20]).Equal(gateway) {
		return nil, false
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl+8 || total > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil, false
	}
	if packet[ihl] != 8 || packet[ihl+1] != 0 {
		return nil, false
	}
	if ipv4Checksum(packet[:ihl]) != 0 || ipv4Checksum(packet[ihl:total]) != 0 {
		return nil, false
	}
	reply := append([]byte(nil), packet[:total]...)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	reply[ihl] = 0
	reply[ihl+2], reply[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], ipv4Checksum(reply[ihl:]))
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], ipv4Checksum(reply[:ihl]))
	return reply, true
}

func ipv4Checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
