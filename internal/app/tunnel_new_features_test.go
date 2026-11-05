package app

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestReliableSOCKSAuthAndUDPAssociateOverTURN(t *testing.T) {
	a, b := testTURNPair(t)
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		var buf [2048]byte
		for {
			n, from, err := udpEcho.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(buf[:n], from)
		}
	}()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()
	go func() { _ = runReliableSocksExit(b, 0) }()
	go func() {
		_ = runReliableSocksClient(a, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), socksAuth{"alice", "secret"}, 0)
	}()
	var tcp net.Conn
	for i := 0; i < 50; i++ {
		tcp, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tcp.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var two [2]byte
	if _, err := io.ReadFull(tcp, two[:]); err != nil || two != [2]byte{5, 2} {
		t.Fatalf("method %v %v", two, err)
	}
	if _, err := tcp.Write(append([]byte{1, 5}, append([]byte("alice"), append([]byte{6}, []byte("secret")...)...)...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcp, two[:]); err != nil || two != [2]byte{1, 0} {
		t.Fatalf("auth %v %v", two, err)
	}
	if _, err := tcp.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(tcp, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("associate %v %v", reply, err)
	}
	bind := &net.UDPAddr{IP: net.IPv4(reply[4], reply[5], reply[6], reply[7]), Port: int(reply[8])<<8 | int(reply[9])}
	udpClient, err := net.DialUDP("udp", nil, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	_ = udpClient.SetDeadline(time.Now().Add(5 * time.Second))
	want := []byte("DNS-like UDP over reliable TURN")
	pkt, err := socksUDPDatagram("127.0.0.1", udpEcho.LocalAddr().(*net.UDPAddr).Port, want)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpClient.Write(pkt); err != nil {
		t.Fatal(err)
	}
	var buf [2048]byte
	n, err := udpClient.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	_, _, got, err := parseSocksUDPDatagram(buf[:n])
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("UDP response %q %v", got, err)
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener %s did not start", addr)
	return nil
}
