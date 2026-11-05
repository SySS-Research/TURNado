package app

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v4"
)

// Exercise allocations, permissions, ChannelData, DTLS and SRTP through a real
// Pion TURN server. Only the underlying network runs in memory.
func testTURNPair(t *testing.T) (*peerTransport, *peerTransport) {
	return testTURNPairWithChannelBind(t, true)
}

// Dropping ChannelBind keeps the client in the SendIndication fallback used
// while a TURN server is slow to bind, or when binding fails altogether.
type noChannelBindConn struct{ net.PacketConn }

func (c *noChannelBindConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, from, err
		}
		msg := &stun.Message{Raw: p[:n]}
		if stun.IsMessage(p[:n]) && msg.Decode() == nil && msg.Type == stun.NewType(stun.MethodChannelBind, stun.ClassRequest) {
			continue
		}
		return n, from, nil
	}
}

func testTURNPairWithChannelBind(t *testing.T, allowChannelBind bool) (*peerTransport, *peerTransport) {
	t.Helper()
	listener, err := testUDPNetwork.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if !allowChannelBind {
		listener = &noChannelBindConn{PacketConn: listener}
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "turnado.test", LoggerFactory: leveledLoggerFactory{},
		AuthHandler: func(user, realm string, _ net.Addr) ([]byte, bool) {
			return turn.GenerateAuthKey("test", "turnado.test", "password"), user == "test" && realm == "turnado.test"
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: listener,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1", Net: testUDPNetwork,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	makeClient := func() (*turn.Client, *peerTransport) {
		control, err := testUDPNetwork.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = control.Close() })
		client, err := turn.NewClient(&turn.ClientConfig{
			TURNServerAddr: listener.LocalAddr().String(), Username: "test", Password: "password",
			Conn: control, Net: testUDPNetwork, LoggerFactory: leveledLoggerFactory{}, RTO: 20 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		if err = client.Listen(); err != nil {
			t.Fatal(err)
		}
		relay, err := client.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		transport := newPeerTransport(relay, testIdentity(t))
		t.Cleanup(func() { _ = transport.Close() })
		return client, transport
	}
	ca, a := makeClient()
	cb, b := makeClient()
	if err = ca.CreatePermission(b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err = cb.CreatePermission(a.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	pairTransports(t, a, b)
	return a, b
}

func TestTUNTrafficWhileTURNChannelBindPending(t *testing.T) {
	a, b := testTURNPairWithChannelBind(t, false)
	for _, direction := range [][2]*peerTransport{{a, b}, {b, a}} {
		payload := bytes.Repeat([]byte{0x45}, 100)
		if err := sendTunPayload(direction[0], direction[1].LocalAddr().(*net.UDPAddr), payload); err != nil {
			t.Fatalf("TUN send through TURN SendIndication: %v", err)
		}
		got := readPacket(t, direction[1])
		if !bytes.Equal(got, buildPacket(msgTypeIP, 0, payload)) {
			t.Fatal("TUN payload corrupted by SendIndication fallback")
		}
	}
}

func TestDTLSSRTPOverTURN(t *testing.T) {
	a, b := testTURNPair(t)
	for i := 0; i < 4; i++ {
		p := buildPacket(msgTypeIP, uint32(i), bytes.Repeat([]byte{byte(i + 1)}, maxDataPayload(a)))
		sendPacket(t, a, b.LocalAddr(), p)
		if !bytes.Equal(readPacket(t, b), p) {
			t.Fatal("TURN client -> exit mismatch")
		}
		sendPacket(t, b, a.LocalAddr(), p)
		if !bytes.Equal(readPacket(t, a), p) {
			t.Fatal("TURN exit -> client mismatch")
		}
	}
}

func TestHeartbeatPacketsStayOutOfApplicationStream(t *testing.T) {
	a, b := testTURNPair(t)
	sendPacket(t, a, b.LocalAddr(), buildPacket(msgTypePing, 0, nil))
	want := buildPacket(msgTypeIP, 0, []byte("payload"))
	sendPacket(t, a, b.LocalAddr(), want)
	if got := readPacket(t, b); !bytes.Equal(got, want) {
		t.Fatalf("application received %v instead of %v", got, want)
	}
}
