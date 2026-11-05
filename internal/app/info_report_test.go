package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func permissionDenied() error {
	return errors.New("CreatePermission error response (error 403: Forbidden)")
}

// Mirrors a TURN server that blocks internal peers and TCP relays.
func restrictedReport() infoReport {
	r := infoReport{
		Turn: "turn.example.org:443", Transport: "tls", Realm: "rtcmedia", Software: "relay 1.0",
		Probe: "203.0.113.10:443", TurnPort: 443, Status: "ok", AnonymousKnown: true,
		Anonymous: serverHello{Code: 401, Reason: "Unauthorized"},
		IPv4:      allocationProbe{Address: "203.0.113.20:53162", LifetimeSeconds: 120},
		IPv6:      allocationProbe{Address: "203.0.113.21:54043", LifetimeSeconds: 120, FamilyMismatch: true},
		Mapped:    "198.51.100.7:39254", Relay: "203.0.113.22:52415",
		External:     peerProbe{Address: "203.0.113.10:443", Tested: true},
		TCPTransport: "tls", TCPTarget: "203.0.113.10:443",
		TCP: tcpRelayProbe{AllocErr: errors.New("Allocate error response (error 442: Unsupported Transport Protocol)")},
	}
	for _, address := range append(append([]string{}, loopbackPeers...), internalPeers...) {
		r.Peers = append(r.Peers, peerProbe{Address: address, Permission: permissionDenied()})
	}
	r.Peers[5] = peerProbe{Address: "64:ff9b::7f00:1", Tested: true}
	return r
}

// Mirrors a permissive TURN server whose CONNECT probe times out.
func permissiveReport() infoReport {
	r := restrictedReport()
	r.Transport, r.TurnPort, r.Probe, r.TCPTarget, r.TCPTransport = "udp", 3478, "203.0.113.10:3478", "203.0.113.10:3478", "tcp"
	r.Peers = nil
	for i, address := range append(append([]string{}, loopbackPeers...), internalPeers...) {
		r.Peers = append(r.Peers, peerProbe{Address: address, Tested: i < len(loopbackPeers)})
	}
	r.Peers[3].ResponseFrom = "127.0.0.2:3478"
	r.Peers[2].ResponseFrom = "127.0.0.1:3478"
	r.External = peerProbe{Address: "203.0.113.10:3478", Tested: true, ResponseFrom: "203.0.113.10:3478"}
	r.TCP = tcpRelayProbe{ConnectErr: errors.New("all retransmissions failed for 17J9ecf2ihZAshxT")}
	return r
}

func renderInfo(r infoReport) string {
	var b bytes.Buffer
	writeInfoText(&b, r)
	return b.String()
}

func TestInfoTextRestrictedServer(t *testing.T) {
	out := renderInfo(restrictedReport())
	for _, want := range []string{
		"TURN server           turn.example.org:443 (tls)",
		"[!] IPv6 relay        not provided: requested IPv6, server returned 203.0.113.21:54043",
		"[+] IPv4 relay        203.0.113.20:53162 (lifetime 120 s)",
		"[!] Anonymous relay   rejected (401 Unauthorized)",
		"[!] 10.0.0.1          denied (403 Forbidden)  -",
		"[+] 64:ff9b::7f00:1   granted                 no response",
		"[*] STUN via relay    no response (inconclusive",
		"[!] Allocation        rejected (442 Unsupported Transport Protocol)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, contradiction := range []string{"allowed (error", "error code: 0", "error: )", "CONNECT"} {
		if strings.Contains(out, contradiction) {
			t.Errorf("output contains %q:\n%s", contradiction, out)
		}
	}
}

func TestInfoTextPermissiveServer(t *testing.T) {
	out := renderInfo(permissiveReport())
	for _, want := range []string{
		"[+] 127.0.0.2         granted                 received\n",
		"[+] 0.0.0.0           granted                 received from 127.0.0.1:3478\n",
		"[+] 10.0.0.1          granted                 not tested\n",
		"no response is inconclusive",
		"[+] STUN via relay    response received\n",
		"[+] Allocation        allowed\n",
		"[*] CONNECT           203.0.113.10:3478 no answer (timeout; inconclusive)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "17J9ecf2ihZAshxT") {
		t.Errorf("raw transaction ID leaked into output:\n%s", out)
	}
}

func TestInfoTextConnectResults(t *testing.T) {
	r := permissiveReport()
	r.TCP = tcpRelayProbe{ConnectErr: errors.New("Connect error response (error 447: Connection Timeout or Failure)")}
	if out := renderInfo(r); !strings.Contains(out, "[!] CONNECT           203.0.113.10:3478 unreachable (447 Connection Timeout or Failure); CONNECT itself is supported") {
		t.Errorf("447 not explained:\n%s", out)
	}
	r.TCP = tcpRelayProbe{Connected: true}
	if out := renderInfo(r); !strings.Contains(out, "[+] CONNECT           203.0.113.10:3478 connected") {
		t.Errorf("connect success missing:\n%s", out)
	}
}

func TestInfoJSONKeepsEstablishedKeys(t *testing.T) {
	fields := restrictedReport().jsonFields()
	for _, key := range []string{
		"turn_server", "realm", "software", "probe_address", "xor_mapped_address", "relay_address",
		"ipv4_relay", "ipv6_relay", "anonymous_allocate_error_code", "anonymous_allocation",
		"loopback_ipv4_permission", "loopback_ipv4_stun_response", "loopback_ipv6_permission", "loopback_ipv6_stun_response",
		"internal_probes", "udp_permission", "udp_send", "udp_stun_response",
		"tcp_allocation", "tcp_connect_bind_supported", "tcp_connect_bind_error", "tcp_send", "status",
	} {
		if _, ok := fields[key]; !ok {
			t.Errorf("JSON key %q missing", key)
		}
	}
	if fields["tcp_connect_bind_supported"] != false || fields["anonymous_allocation"] != false {
		t.Errorf("unexpected JSON values: %v", fields)
	}
	if !fields["ipv6_relay"].(allocationProbe).FamilyMismatch {
		t.Error("IPv6 family mismatch missing from JSON")
	}
}

func TestInfoPeerTableAlignsLongReasons(t *testing.T) {
	r := restrictedReport()
	r.Peers[1].Permission = errors.New("CreatePermission error response (error 443: Peer Address Family Mismatch)")
	out := renderInfo(r)
	lines := strings.Split(out, "\n")
	header := -1
	for i, line := range lines {
		if strings.Contains(line, "STUN via relay to port") {
			header = i
		}
	}
	if header < 0 {
		t.Fatalf("peer table header missing:\n%s", out)
	}
	column := strings.Index(lines[header], "STUN via relay")
	for _, row := range lines[header+1 : header+1+len(r.Peers)] {
		if len(row) <= column || row[column-1] != ' ' || row[column] == ' ' {
			t.Fatalf("STUN column misaligned at %q:\n%s", row, out)
		}
	}
	if !strings.Contains(out, "denied (443 Peer Address Family Mismatch)") {
		t.Fatalf("443 reason missing:\n%s", out)
	}
}
