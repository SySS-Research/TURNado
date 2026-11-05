package app

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

func TestDTLSControlRoundTrip(t *testing.T) {
	id := testIdentity(t)
	listener, err := dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{
		Certificates: []tls.Certificate{id.certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err == nil {
			_, err = c.Write(buf[:n])
		}
		done <- err
	}()
	control, err := dialDTLSControl(commonConfig{Turn: listener.Addr().String(), Insecure: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	want := []byte("TURN message in a DTLS record")
	if _, err := control.WriteTo(want, nil); err != nil {
		t.Fatal(err)
	}
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _, err := control.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], want) {
		t.Fatalf("DTLS round trip: %q, %v", buf[:n], err)
	}
	if err := <-done; err != nil && err != io.EOF {
		t.Fatal(err)
	}
}
