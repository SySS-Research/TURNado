package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/vclient"
)

type packetWriterFunc func([]byte) (int, error)

func (f packetWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestRootlessTunExitTCPOverTURN(t *testing.T) {
	a, b := testTURNPair(t)
	remote, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	go func() {
		for {
			c, err := remote.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	go func() { _ = runTurnTunRootlessExit(b, "10.0.1.1", 0) }()
	vc := vclient.New()
	defer vc.Close()
	vc.SetIP(net.ParseIP("10.0.1.2"), net.CIDRMask(24, 32), net.ParseIP("10.0.1.1"))
	vc.SetHandler(func(p pktkit.Packet) error { return sendTunPayload(a, b.LocalAddr().(*net.UDPAddr), p) })
	go func() {
		_ = turnToTunLoop(a, packetWriterFunc(func(p []byte) (int, error) {
			if err := vc.Send(pktkit.Packet(p)); err != nil {
				return 0, err
			}
			return len(p), nil
		}), newFragReassembler(), 0)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := vc.DialContext(ctx, "tcp", remote.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	want := []byte("rootless TUN over TURN")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("echo=%q err=%v", got, err)
	}
}

func TestRootlessGatewayEchoOverTURN(t *testing.T) {
	a, b := testTURNPair(t)
	go func() { _ = runTurnTunRootlessExit(b, "10.0.1.1", 0) }()
	request := make([]byte, 28)
	request[0] = 0x45
	binary.BigEndian.PutUint16(request[2:4], uint16(len(request)))
	request[8], request[9] = 64, 1
	copy(request[12:16], net.IPv4(10, 0, 1, 2).To4())
	copy(request[16:20], net.IPv4(10, 0, 1, 1).To4())
	binary.BigEndian.PutUint16(request[10:12], ipv4Checksum(request[:20]))
	request[20] = 8
	binary.BigEndian.PutUint16(request[22:24], ipv4Checksum(request[20:]))
	if err := sendTunPayload(a, b.LocalAddr().(*net.UDPAddr), request); err != nil {
		t.Fatal(err)
	}
	h, reply, err := parseHeader(readPacket(t, a))
	if err != nil || h.Type != msgTypeIP || len(reply) != len(request) {
		t.Fatalf("echo response header: %+v len=%d err=%v", h, len(reply), err)
	}
	if reply[20] != 0 || !net.IP(reply[12:16]).Equal(net.IPv4(10, 0, 1, 1)) || !net.IP(reply[16:20]).Equal(net.IPv4(10, 0, 1, 2)) || ipv4Checksum(reply[:20]) != 0 || ipv4Checksum(reply[20:]) != 0 {
		t.Fatalf("invalid ICMP echo reply: %x", reply)
	}
}
