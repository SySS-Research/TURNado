package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/transport/v4/vnet"
)

func testIdentity(t *testing.T) *dtlsIdentity {
	t.Helper()
	id, err := newDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type recordedConn struct {
	net.PacketConn
	mu       sync.Mutex
	packets  [][]byte
	dropDTLS bool
}

func (c *recordedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.packets = append(c.packets, append([]byte(nil), p...))
	drop := c.dropDTLS && len(p) > 0 && p[0] >= 20 && p[0] <= 63
	if drop {
		c.dropDTLS = false
	}
	c.mu.Unlock()
	if drop {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}
func (c *recordedConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.packets...)
}

// A virtual UDP stack keeps real DTLS/SRTP tests independent of OS sockets.
var testUDPNetwork, testUDPNetworkErr = vnet.NewNet(&vnet.NetConfig{})

func testTransport(t *testing.T, encrypted bool) (*peerTransport, *recordedConn) {
	t.Helper()
	if testUDPNetworkErr != nil {
		t.Fatal(testUDPNetworkErr)
	}
	pc, err := testUDPNetwork.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	raw := &recordedConn{PacketConn: pc}
	var id *dtlsIdentity
	if encrypted {
		id = testIdentity(t)
	}
	transport := newPeerTransport(raw, id)
	t.Cleanup(func() { _ = transport.Close() })
	return transport, raw
}
func pairTransports(t *testing.T, a, b *peerTransport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	afp, bfp := "", ""
	if a.identity != nil {
		afp = a.identity.fingerprint
	}
	if b.identity != nil {
		bfp = b.identity.fingerprint
	}
	done := make(chan error, 1)
	go func() { done <- b.pair(ctx, a.LocalAddr().(*net.UDPAddr), afp, false) }()
	if err := a.pair(ctx, b.LocalAddr().(*net.UDPAddr), bfp, true); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func readPacket(t *testing.T, c net.PacketConn) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64*1024)
	n, _, err := c.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), b[:n]...)
}
func sendPacket(t *testing.T, a net.PacketConn, b net.Addr, p []byte) {
	t.Helper()
	n, err := a.WriteTo(p, b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(p) {
		t.Fatalf("write: %d != %d", n, len(p))
	}
}

func TestDTLSSRTPHandshakeAndPackets(t *testing.T) {
	a, rawA := testTransport(t, true)
	b, rawB := testTransport(t, true)
	if a.identity.fingerprint == b.identity.fingerprint {
		t.Fatal("identities reused")
	}
	pairTransports(t, a, b)
	// Both directions carry every tunnel control/data packet type, including
	// an MTU-sized payload, with authentication and independent session keys.
	for _, kind := range []byte{msgTypeIP, msgTypeFrag, msgTypeReliable} {
		pkt := buildPacket(kind, 123, bytes.Repeat([]byte{kind}, maxDataPayload(a)))
		sendPacket(t, a, b.LocalAddr(), pkt)
		if got := readPacket(t, b); !bytes.Equal(got, pkt) {
			t.Fatal("client -> exit mismatch")
		}
		sendPacket(t, b, a.LocalAddr(), pkt)
		if got := readPacket(t, a); !bytes.Equal(got, pkt) {
			t.Fatal("exit -> client mismatch")
		}
	}
	for _, raw := range []*recordedConn{rawA, rawB} {
		foundDTLS, foundSRTP := false, false
		for _, p := range raw.snapshot() {
			if len(p) > maxPacketSize {
				t.Fatalf("wire packet exceeds MTU: %d", len(p))
			}
			if p[0] >= 20 && p[0] <= 63 {
				foundDTLS = true
			}
			if p[0] == 0x80 {
				foundSRTP = true
				if len(p) != maxPacketSize {
					t.Fatalf("incorrect SRTP overhead: %d", len(p))
				}
				if bytes.Contains(p, bytes.Repeat([]byte{msgTypeIP}, 32)) {
					t.Fatal("plaintext on wire")
				}
			}
		}
		if !foundDTLS || !foundSRTP {
			t.Fatal("missing DTLS or SRTP wire traffic")
		}
	}
	if _, err := a.WriteTo(make([]byte, maxPacketSize), b.LocalAddr()); err == nil {
		t.Fatal("oversized packet accepted")
	}
}

func TestDTLSSRTPRejectsFingerprints(t *testing.T) {
	for _, badClient := range []bool{false, true} {
		name := "client_verifies_exit"
		if badClient {
			name = "exit_verifies_client"
		}
		t.Run(name, func(t *testing.T) {
			a, _ := testTransport(t, true)
			b, _ := testTransport(t, true)
			afp, bfp := a.identity.fingerprint, b.identity.fingerprint
			if badClient {
				afp = testIdentity(t).fingerprint
			} else {
				bfp = testIdentity(t).fingerprint
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- b.pair(ctx, a.LocalAddr().(*net.UDPAddr), afp, false) }()
			aerr := a.pair(ctx, b.LocalAddr().(*net.UDPAddr), bfp, true)
			berr := <-done
			if aerr == nil || berr == nil {
				t.Fatalf("bad fingerprint accepted: client=%v exit=%v", aerr, berr)
			}
			verifierErr := aerr
			if badClient {
				verifierErr = berr
			}
			if !strings.Contains(verifierErr.Error(), "fingerprint mismatch") {
				t.Fatalf("wrong failure: %v", verifierErr)
			}
			if _, err := a.WriteTo(buildPacket(msgTypeIP, 1, nil), b.LocalAddr()); err == nil {
				t.Fatal("write after failed handshake")
			}
			select {
			case <-a.ready:
				t.Fatal("client marked ready")
			default:
			}
			select {
			case <-b.ready:
				t.Fatal("exit marked ready")
			default:
			}
		})
	}
}

func TestDTLSSRTPRejectsPlaintextTamperingReplayAndForeignPeer(t *testing.T) {
	a, rawA := testTransport(t, true)
	b, _ := testTransport(t, true)
	foreign, _ := testTransport(t, false)
	pairTransports(t, a, b)
	first := buildPacket(msgTypeIP, 7, []byte("first authenticated packet"))
	sendPacket(t, a, b.LocalAddr(), first)
	if !bytes.Equal(readPacket(t, b), first) {
		t.Fatal("first packet mismatch")
	}
	var replay []byte
	for _, p := range rawA.snapshot() {
		if p[0] == 0x80 {
			replay = p
		}
	}
	if replay == nil {
		t.Fatal("missing SRTP packet")
	}
	sendPacket(t, rawA.PacketConn, b.LocalAddr(), replay)
	sendPacket(t, rawA.PacketConn, b.LocalAddr(), buildPacket(msgTypeIP, 7, []byte("plaintext")))
	sendPacket(t, rawA.PacketConn, b.LocalAddr(), buildPacket(5, 0, bytes.Repeat([]byte{0}, 40)))
	// Generate a valid new packet, then corrupt it before sending the valid copy.
	a.writeMu.Lock()
	next := buildPacket(msgTypeIP, 7, []byte("next authenticated packet"))
	valid, err := a.secure.encrypt(next)
	a.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), valid...)
	tampered[srtpHeaderLen] ^= 0x01
	sendPacket(t, rawA.PacketConn, b.LocalAddr(), tampered)
	sendPacket(t, foreign.relay, b.LocalAddr(), valid)
	// A rejected tampered/foreign packet must not consume the valid sequence.
	sendPacket(t, rawA.PacketConn, b.LocalAddr(), valid)
	if got := readPacket(t, b); !bytes.Equal(got, next) {
		t.Fatalf("rejected packet reached application: %x", got)
	}
	// Directional keys and expected SSRC also reject reflected packets.
	sendPacket(t, b.relay, a.LocalAddr(), valid)
	reply := buildPacket(msgTypeIP, 7, []byte("valid return path"))
	sendPacket(t, b, a.LocalAddr(), reply)
	if got := readPacket(t, a); !bytes.Equal(got, reply) {
		t.Fatal("reflected packet accepted")
	}
}

func TestDTLSHandshakeRetransmission(t *testing.T) {
	a, raw := testTransport(t, true)
	b, _ := testTransport(t, true)
	raw.dropDTLS = true
	pairTransports(t, a, b)
	pkt := buildPacket(msgTypeIP, 1, []byte("after dropped ClientHello"))
	sendPacket(t, a, b.LocalAddr(), pkt)
	if !bytes.Equal(readPacket(t, b), pkt) {
		t.Fatal("retransmission failed")
	}
}

func TestDTLSHandshakeTimeoutAndClose(t *testing.T) {
	for _, client := range []bool{true, false} {
		a, _ := testTransport(t, true)
		b, _ := testTransport(t, true)
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		err := a.pair(ctx, b.LocalAddr().(*net.UDPAddr), b.identity.fingerprint, client)
		cancel()
		if err == nil {
			t.Fatal("handshake unexpectedly succeeded")
		}
		// Readers are unblocked with the cause instead of a bare ErrClosed.
		if _, _, err := a.ReadFrom(make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "pairing failed") {
			t.Fatalf("read not unblocked with pairing cause: %v", err)
		}
	}
	a, _ := testTransport(t, true)
	done := make(chan error, 1)
	go func() { _, _, err := a.ReadFrom(make([]byte, 32)); done <- err }()
	_ = a.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-pair read leaked")
	}
}

func TestSRTPSequenceRolloverAndConcurrentWriters(t *testing.T) {
	a, _ := testTransport(t, true)
	b, _ := testTransport(t, true)
	pairTransports(t, a, b)
	a.secure.sequence = 65534
	for i := 0; i < 4; i++ {
		p := buildPacket(msgTypeIP, uint32(i), []byte("rollover"))
		sendPacket(t, a, b.LocalAddr(), p)
		if !bytes.Equal(readPacket(t, b), p) {
			t.Fatal("rollover corrupts packet")
		}
	}
	const count = 32
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := a.WriteTo(buildPacket(msgTypeIP, uint32(i), []byte("concurrent")), b.LocalAddr())
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint32]bool)
	for i := 0; i < count; i++ {
		h, _, err := parseHeader(readPacket(t, b))
		if err != nil {
			t.Fatal(err)
		}
		if seen[h.ConnID] {
			t.Fatal("duplicate delivered")
		}
		seen[h.ConnID] = true
	}
}

func TestPlaintextTransportAndEncryptionMismatch(t *testing.T) {
	a, _ := testTransport(t, false)
	b, _ := testTransport(t, false)
	pairTransports(t, a, b)
	pkt := buildPacket(msgTypeIP, 0, bytes.Repeat([]byte{42}, maxDataPayload(a)))
	sendPacket(t, a, b.LocalAddr(), pkt)
	if !bytes.Equal(readPacket(t, b), pkt) {
		t.Fatal("plaintext regression")
	}
	c, _ := testTransport(t, true)
	if err := c.pair(context.Background(), a.LocalAddr().(*net.UDPAddr), "", true); err == nil {
		t.Fatal("missing fingerprint accepted")
	}
	d, _ := testTransport(t, false)
	if err := d.pair(context.Background(), a.LocalAddr().(*net.UDPAddr), c.identity.fingerprint, true); err == nil {
		t.Fatal("mode mismatch accepted")
	}
}

func TestConnectionStrings(t *testing.T) {
	id := testIdentity(t)
	secure := connString{V: 2, Turn: "turn.example:3478", Relay: "127.0.0.1:1234", Control: "udp", Enc: true, Fingerprint: id.fingerprint}
	encoded, err := encodeConnString(secure, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeConnString(encoded, "")
	if err != nil || decoded.V != secure.V || decoded.Relay != secure.Relay || decoded.Fingerprint != secure.Fingerprint || decoded.Turn != secure.Turn || !decoded.Enc {
		t.Fatalf("round trip: %+v %v", decoded, err)
	}
	var cfg tunnelCfg
	if err := applyConnStringDefaults(&cfg, decoded); err != nil || !cfg.Encrypt {
		t.Fatalf("encryption not inherited: %v", err)
	}
	plain := secure
	plain.V, plain.Enc, plain.Fingerprint = 1, false, ""
	encoded, err = encodeConnString(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeConnString(encoded, ""); err != nil {
		t.Fatal(err)
	}
	if err := applyConnStringDefaults(&cfg, plain); err == nil {
		t.Fatal("explicit encryption downgraded")
	}
	if err := applyConnStringDefaults(&tunnelCfg{NoTunnelEncryption: true}, secure); err == nil {
		t.Fatal("explicitly disabled encryption was overridden")
	}
	for _, change := range []func(*connString){
		func(c *connString) { c.Fingerprint = "" },
		func(c *connString) { c.Fingerprint = "sha-1 AA:BB" },
		func(c *connString) { c.Fingerprint = "sha-256 " + strings.Repeat("ZZ:", 31) + "ZZ" },
		func(c *connString) { c.Enc = false },
		func(c *connString) { c.V = 1 },
		func(c *connString) { c.V = 3 },
	} {
		bad := secure
		change(&bad)
		b, _ := json.Marshal(bad)
		if _, err := decodeConnString(base64.RawURLEncoding.EncodeToString(b), ""); err == nil {
			t.Fatalf("invalid string accepted: %s", b)
		}
	}
}

func TestTUNFragmentationOverSRTP(t *testing.T) {
	a, raw := testTransport(t, true)
	b, _ := testTransport(t, true)
	pairTransports(t, a, b)
	payload := bytes.Repeat([]byte("tunnel-ip-payload"), 400)
	if err := sendTunPayload(a, b.LocalAddr().(*net.UDPAddr), payload); err != nil {
		t.Fatal(err)
	}
	reasm := newFragReassembler()
	var result []byte
	for i := 0; i < (len(payload)+maxDataPayload(a)-fragHeaderLen-1)/(maxDataPayload(a)-fragHeaderLen); i++ {
		h, p, err := parseHeader(readPacket(t, b))
		if err != nil {
			t.Fatal(err)
		}
		if h.Type != msgTypeFrag {
			t.Fatalf("wrong packet type %d", h.Type)
		}
		out, complete := reasm.add(binary.BigEndian.Uint32(p[:4]), int(binary.BigEndian.Uint16(p[4:6])), int(binary.BigEndian.Uint16(p[6:8])), p[8:])
		if complete {
			result = out
		}
	}
	if !bytes.Equal(result, payload) {
		t.Fatal("fragment reassembly differs")
	}
	for _, p := range raw.snapshot() {
		if len(p) > maxPacketSize {
			t.Fatalf("fragment exceeds MTU: %d", len(p))
		}
	}
}

func TestPeerTransportBlocksBeforeHandshake(t *testing.T) {
	a, raw := testTransport(t, true)
	b, _ := testTransport(t, true)
	if err := a.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteTo(buildPacket(msgTypeIP, 1, nil), b.LocalAddr()); err == nil {
		t.Fatal("write before pairing succeeded")
	}
	if _, _, err := a.ReadFrom(make([]byte, 32)); err == nil {
		t.Fatal("read before pairing succeeded")
	}
	if len(raw.snapshot()) != 0 {
		t.Fatal("application data sent before handshake")
	}
	if err := a.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	pairTransports(t, a, b)
	p := buildPacket(msgTypeIP, 1, []byte("after handshake"))
	sendPacket(t, a, b.LocalAddr(), p)
	if !bytes.Equal(readPacket(t, b), p) {
		t.Fatal("transport did not become ready")
	}
}

func TestDTLSRejectsOtherSRTPProfile(t *testing.T) {
	a, _ := testTransport(t, true)
	b, _ := testTransport(t, true)
	// A correctly fingerprinted DTLS peer offering another profile must still
	// fail; a valid certificate alone does not authorize an algorithm fallback.
	b.peer = a.LocalAddr().(*net.UDPAddr)
	go b.readLoop()
	config, err := b.identity.config(a.identity.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	config.SRTPProtectionProfiles = []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_128_GCM}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		dc, err := newDTLSConn(&dtlsEndpoint{transport: b}, b.peer, config, false)
		if err == nil {
			err = dc.HandshakeContext(ctx)
			_ = dc.Close()
		}
		done <- err
	}()
	if err := a.pair(ctx, b.LocalAddr().(*net.UDPAddr), b.identity.fingerprint, true); err == nil {
		t.Fatal("unexpected SRTP profile accepted")
	}
	if err := <-done; err == nil {
		t.Fatal("incompatible peer completed handshake")
	}
	select {
	case <-a.ready:
		t.Fatal("incompatible session released application data")
	default:
	}
}
