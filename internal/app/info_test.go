package app

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v4"
)

// stunResponder answers STUN Binding requests; with replyFrom set it answers
// from that socket, like a host replying from another local address.
func stunResponder(t *testing.T, replyFrom net.PacketConn) net.PacketConn {
	t.Helper()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if replyFrom == nil {
		replyFrom = server
	}
	go func() {
		buf := make([]byte, 256)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			request := stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if request.Decode() != nil {
				continue
			}
			response := stun.Message{Raw: make([]byte, 0, 64), Type: stun.NewType(stun.MethodBinding, stun.ClassSuccessResponse), TransactionID: request.TransactionID}
			response.Encode()
			_, _ = replyFrom.WriteTo(response.Raw, addr)
		}
	}()
	return server
}

func TestProbeRelayResponsesMatchesTransactions(t *testing.T) {
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	other, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	direct := stunResponder(t, nil)
	redirected := stunResponder(t, other)
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	targets := []*net.UDPAddr{
		direct.LocalAddr().(*net.UDPAddr),
		redirected.LocalAddr().(*net.UDPAddr),
		silent.LocalAddr().(*net.UDPAddr),
	}
	start := time.Now()
	responders, sendErrs := probeRelayResponses(client, targets, 500*time.Millisecond)
	for i, err := range sendErrs {
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	want := []string{direct.LocalAddr().String(), other.LocalAddr().String(), ""}
	for i := range want {
		if responders[i] != want[i] {
			t.Errorf("target %d responder = %q, want %q", i, responders[i], want[i])
		}
	}
	// All probes share one wait instead of waiting per target.
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("probes took %s", elapsed)
	}
}

func TestRelayFamilyMismatch(t *testing.T) {
	v4, v6 := net.ParseIP("141.95.57.24"), net.ParseIP("2001:db8::1")
	if relayFamilyMismatch(v4, 1) || relayFamilyMismatch(v6, 2) {
		t.Fatal("matching family reported as mismatch")
	}
	if !relayFamilyMismatch(v4, 2) || !relayFamilyMismatch(v6, 1) {
		t.Fatal("ignored REQUESTED-ADDRESS-FAMILY not detected")
	}
}

func TestRFC6062ProbeTransport(t *testing.T) {
	for in, want := range map[string]string{"udp": "tcp", "tcp": "tcp", "tls": "tls", "dtls": "tls"} {
		if got := rfc6062Transport(in); got != want {
			t.Errorf("rfc6062Transport(%q) = %q, want %q", in, got, want)
		}
	}
}

func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	defer func() { os.Stdout = orig }()
	run()
	_ = w.Close()
	return <-out
}

func TestInfoWithoutCredentialsShowsAnonymousAllocation(t *testing.T) {
	t.Setenv(envUsername, "")
	t.Setenv(envPassword, "")
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "turnado.test", LoggerFactory: leveledLoggerFactory{},
		AuthHandler: func(string, string, net.Addr) ([]byte, bool) { return nil, false },
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var runErr error
	out := captureStdout(t, func() { runErr = RunInfo([]string{"-t", pc.LocalAddr().String(), "-o", "2s"}) })
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(out, "[!] Anonymous relay   rejected (401 Unauthorized)") {
		t.Fatalf("anonymous allocation result missing:\n%s", out)
	}
}
