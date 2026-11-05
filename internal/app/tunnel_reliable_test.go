package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type dropFirstPacketConn struct {
	net.PacketConn
	dropped atomic.Bool
}

func (c *dropFirstPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) >= 24 && p[4] == 81 && c.dropped.CompareAndSwap(false, true) {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestReliableStreamRecoversLostPacketOverTURN(t *testing.T) {
	a, b := testTURNPair(t)
	listener, err := kcp.ServeConn(nil, 0, 0, &kcpPacketConn{b})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		session, err := listener.AcceptKCP()
		if err != nil {
			serverDone <- err
			return
		}
		defer session.Close()
		if err := configureKCPSession(session); err != nil {
			serverDone <- err
			return
		}
		mux, err := smux.Server(session, reliableMuxConfig())
		if err != nil {
			serverDone <- err
			return
		}
		defer mux.Close()
		stream, err := mux.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		data, err := io.ReadAll(stream)
		if err == nil {
			_, err = stream.Write(data)
		}
		if err == nil {
			err = stream.CloseWrite()
		}
		serverDone <- err
	}()
	dropping := &dropFirstPacketConn{PacketConn: &kcpPacketConn{a}}
	session, err := kcp.NewConn2(b.LocalAddr(), nil, 0, 0, dropping)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := configureKCPSession(session); err != nil {
		t.Fatal(err)
	}
	mux, err := smux.Client(session, reliableMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	stream, err := mux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	want := bytes.Repeat([]byte("ordered bytes through a lossy TURN relay;"), 2000)
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("reliable stream: len=%d want=%d err=%v", len(got), len(want), err)
	}
	if !dropping.dropped.Load() {
		t.Fatal("test did not drop a KCP packet")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal(fmt.Errorf("server stream did not finish"))
	}
}

func TestReliableSOCKSConnectOverTURN(t *testing.T) {
	a, b := testTURNPair(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	exitDone := make(chan error, 1)
	go func() { exitDone <- runReliableSocksExit(b, 0) }()
	kcpSession, err := kcp.NewConn2(b.LocalAddr(), nil, 0, 0, &kcpPacketConn{a})
	if err != nil {
		t.Fatal(err)
	}
	defer kcpSession.Close()
	if err := configureKCPSession(kcpSession); err != nil {
		t.Fatal(err)
	}
	mux, err := smux.Client(kcpSession, reliableMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	user, server := net.Pipe()
	defer user.Close()
	_ = user.SetDeadline(time.Now().Add(5 * time.Second))
	clientDone := make(chan error, 1)
	go func() { clientDone <- handleReliableSocksClient(server, mux, socksAuth{}) }()
	if _, err := user.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(user, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("greeting=%v err=%v", greeting, err)
	}
	addr, err := encodeTargetAddr("127.0.0.1", target.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.Write(append([]byte{5, 1, 0}, addr...)); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err := io.ReadFull(user, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("response=%v err=%v", response, err)
	}
	want := []byte("reliable SOCKS echo")
	if _, err := user.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(user, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("echo=%q err=%v", got, err)
	}
	_ = user.Close()
	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client stream did not close")
	}
	_ = b.Close()
	select {
	case <-exitDone:
	case <-time.After(3 * time.Second):
		t.Fatal("reliable exit did not close")
	}
}

// reliableMuxPair connects a client and a server smux session over a paired
// TURN transport, like the SOCKS client and exit roles do.
func reliableMuxPair(t *testing.T, a, b *peerTransport) (client, server *smux.Session) {
	t.Helper()
	listener, err := kcp.ServeConn(nil, 0, 0, &kcpPacketConn{b})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	session, err := kcp.NewConn2(b.LocalAddr(), nil, 0, 0, &kcpPacketConn{a})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if err := configureKCPSession(session); err != nil {
		t.Fatal(err)
	}
	client, err = smux.Client(session, reliableMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// KCP creates the server session on the first packet from the client.
	opened := make(chan *smux.Stream, 1)
	go func() {
		s, err := client.OpenStream()
		if err == nil {
			opened <- s
		}
	}()
	accepted, err := listener.AcceptKCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	if err := configureKCPSession(accepted); err != nil {
		t.Fatal(err)
	}
	server, err = smux.Server(accepted, reliableMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	select {
	case s := <-opened:
		_ = s.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("first stream was not opened")
	}
	// Remove the bootstrap stream so tests only see their own streams.
	bootstrap, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = bootstrap.Close()
	return client, server
}

// socksConnect performs a SOCKS5 CONNECT and returns the reply code.
func socksConnect(t *testing.T, c net.Conn, host string, port int) byte {
	t.Helper()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("greeting=%v err=%v", greeting, err)
	}
	addr, err := encodeTargetAddr(host, port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(append([]byte{5, 1, 0}, addr...)); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("SOCKS reply: %v", err)
	}
	return reply[1]
}

func TestReliableSOCKSPropagatesHalfClose(t *testing.T) {
	a, b := testTURNPair(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Answer only after the client has finished sending, like a server
		// reading a request to EOF.
		request, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("response to "), request...))
	}()
	go func() { _ = runReliableSocksExit(b, 0) }()
	socksPort := reserveTCPPort(t)
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	go func() { _ = runReliableSocksClient(a, listen, socksAuth{}, 0) }()
	user := waitTCP(t, listen)
	defer user.Close()
	_ = user.SetDeadline(time.Now().Add(5 * time.Second))
	if code := socksConnect(t, user, "127.0.0.1", target.Addr().(*net.TCPAddr).Port); code != 0 {
		t.Fatalf("CONNECT reply %d", code)
	}
	if _, err := user.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := user.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(user)
	if err != nil || string(got) != "response to request" {
		t.Fatalf("response after half-close = %q, err=%v", got, err)
	}
}

func TestReliableHalfCloseStallIsBounded(t *testing.T) {
	t.Cleanup(halfCloseStall.set(300 * time.Millisecond))
	a, b := testTURNPair(t)
	client, server := reliableMuxPair(t, a, b)
	go func() {
		// The exit side drops the stream completely, so it never grants more
		// flow-control window for data still sent towards it.
		s, err := server.AcceptStream()
		if err == nil {
			_ = s.Close()
		}
	}()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	app, local := tcpPair(t)
	defer app.Close()
	go func() {
		chunk := bytes.Repeat([]byte("x"), 32*1024)
		for {
			if _, err := app.Write(chunk); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() { copyReliableStream(local, stream); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("copy stayed blocked on a stream the peer had closed")
	}
}

func TestReliableClientRejectsStreamsFromExit(t *testing.T) {
	a, b := testTURNPair(t)
	clientLocal, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLocal.Close()
	reached := make(chan struct{}, 1)
	go func() {
		if c, err := clientLocal.Accept(); err == nil {
			reached <- struct{}{}
			_ = c.Close()
		}
	}()
	client, server := reliableMuxPair(t, a, b)
	go rejectPeerStreams(client)
	stream, err := server.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := encodeTargetAddr("127.0.0.1", clientLocal.Addr().(*net.TCPAddr).Port)
	// Former reverse-forward request: command 2 followed by a client-side target.
	if _, err := stream.Write(append([]byte{0, 2}, addr...)); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	if data, err := io.ReadAll(stream); len(data) != 0 || err != nil {
		t.Fatalf("exit stream got data %q err=%v; want immediate close", data, err)
	}
	select {
	case <-reached:
		t.Fatal("exit reached a client-side service")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestReliableMuxHasNoKeepaliveTimeout(t *testing.T) {
	// The transport heartbeat handles liveness; smux's 30 s keepalive timeout
	// would end the SOCKS tunnel during a temporary outage.
	if !reliableMuxConfig().KeepAliveDisabled {
		t.Fatal("smux keepalive would close the session after an outage")
	}
}

type failingSendConn struct {
	net.PacketConn
	fail *atomic.Bool
}

func (c *failingSendConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.fail.Load() {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: errors.New("network is unreachable")}
	}
	return c.PacketConn.WriteTo(p, addr)
}

func TestReliableStreamSurvivesTransientSendErrors(t *testing.T) {
	fail := &atomic.Bool{}
	newTransport := func() *peerTransport {
		pc, err := testUDPNetwork.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		transport := newPeerTransport(&failingSendConn{pc, fail}, nil)
		t.Cleanup(func() { _ = transport.Close() })
		return transport
	}
	a, b := newTransport(), newTransport()
	pairTransports(t, a, b)
	client, server := reliableMuxPair(t, a, b)
	received := make(chan []byte, 1)
	go func() {
		s, err := server.AcceptStream()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(s)
		received <- data
	}()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	want := []byte("sent while the network was unreachable")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	fail.Store(false)
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, want) {
			t.Fatalf("got %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not recover after send errors")
	}
}

func TestReliableSOCKSClientReportsTransportFailure(t *testing.T) {
	a, _ := testTURNPair(t)
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(reserveTCPPort(t)))
	done := make(chan error, 1)
	go func() { done <- runReliableSocksClient(a, listen, socksAuth{}, 0) }()
	_ = waitTCP(t, listen).Close()
	cause := errors.New("TURN control connection lost: EOF")
	_ = a.closeWithError(cause)
	select {
	case err := <-done:
		if !errors.Is(err, cause) {
			t.Fatalf("client returned %v, want the transport failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client kept running after the transport closed")
	}
}

func TestReliableSOCKSClientEndsWithSession(t *testing.T) {
	a, b := testTURNPair(t)
	client, _ := reliableMuxPair(t, a, b)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- serveReliableSocks(ln, client, a, socksAuth{}, 0) }()
	_ = client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, errReliableSessionClosed) {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS listener kept running without a session")
	}
}

func TestReliableSOCKSConnectFailsWhenExitDoesNotAnswer(t *testing.T) {
	t.Cleanup(reliableOpenTimeout.set(300 * time.Millisecond))
	a, b := testTURNPair(t)
	client, server := reliableMuxPair(t, a, b)
	go func() {
		// An exit that accepts the stream but never answers.
		for {
			if _, err := server.AcceptStream(); err != nil {
				return
			}
		}
	}()
	user, local := tcpPair(t)
	defer user.Close()
	_ = user.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { _ = handleReliableSocksClient(local, client, socksAuth{}) }()
	if code := socksConnect(t, user, "192.0.2.1", 80); code != 1 {
		t.Fatalf("CONNECT reply %d, want general failure", code)
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialed.Close() })
	select {
	case c := <-accepted:
		t.Cleanup(func() { _ = c.Close() })
		return dialed, c
	case <-time.After(3 * time.Second):
		t.Fatal("loopback accept timed out")
		return nil, nil
	}
}
