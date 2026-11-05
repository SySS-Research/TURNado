package app

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun/v3"
	"github.com/spf13/pflag"
)

const (
	turnAllocateMethod stun.Method   = 0x003
	attrRequestedTrans stun.AttrType = 0x0019
	maxRelayProbeWait                = 2 * time.Second
)

var (
	// Addresses that can reach the TURN host itself. A STUN Binding response
	// from the TURN port proves that the relay forwarded traffic to it.
	loopbackPeers = []string{"127.0.0.1", "::1", "0.0.0.0", "127.0.0.2", "::", "64:ff9b::7f00:1"}
	// Internal ranges whose permission policy is surveyed without traffic.
	internalPeers = []string{"10.0.0.1", "172.16.0.1", "192.168.0.1", "100.64.0.1", "169.254.169.254"}
)

// serverHello is the answer to an unauthenticated Allocate. It reveals the
// realm and software, and whether allocations work without credentials.
type serverHello struct {
	Realm, Software string
	Code            int // 0 = success, -1 = error response without ERROR-CODE
	Reason          string
}

func probeServerInfo(cfg commonConfig, requestedProto byte) (serverHello, error) {
	var hello serverHello
	pc, closeFn, err := dialControlConn(cfg)
	if err != nil {
		return hello, err
	}
	defer func() { _ = closeFn() }()

	var txID [12]byte
	_, _ = rand.Read(txID[:])

	m := stun.Message{Raw: make([]byte, 0, 512)}
	m.Type = stun.NewType(turnAllocateMethod, stun.ClassRequest)
	m.TransactionID = txID

	val := make([]byte, 4)
	val[0] = requestedProto
	m.Add(attrRequestedTrans, val)
	m.Encode()

	_ = pc.SetDeadline(time.Now().Add(cfg.Timeout))
	if cfg.Transport == "udp" {
		ua, rerr := net.ResolveUDPAddr("udp", cfg.Turn)
		if rerr != nil {
			return hello, rerr
		}
		if _, err := pc.WriteTo(m.Raw, ua); err != nil {
			return hello, fmt.Errorf("write allocate probe failed: %w", err)
		}
	} else {
		if _, err := pc.WriteTo(m.Raw, nil); err != nil {
			if _, werr := pc.WriteTo(m.Raw, &net.UDPAddr{}); werr != nil {
				return hello, fmt.Errorf("write allocate probe failed: %w", err)
			}
		}
	}

	buf := make([]byte, 2048)
	var resp stun.Message
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return hello, fmt.Errorf("read allocate probe failed: %w", err)
		}
		resp = stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if resp.Decode() == nil && resp.TransactionID == txID {
			break
		}
	}

	var r stun.Realm
	var s stun.Software
	if r.GetFrom(&resp) == nil {
		hello.Realm = string(r)
	}
	if s.GetFrom(&resp) == nil {
		hello.Software = string(s)
	}
	if resp.Type.Class == stun.ClassErrorResponse {
		hello.Code = -1
		var attr stun.ErrorCodeAttribute
		if attr.GetFrom(&resp) == nil {
			hello.Code, hello.Reason = int(attr.Code), string(attr.Reason)
		}
	}
	return hello, nil
}

func pickIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return nil, fmt.Errorf("no IPs resolved for host %q", host)
}

func resolveProbeAddrs(turnAddr, probe string) (*net.UDPAddr, *net.TCPAddr, string, error) {
	probe = strings.TrimSpace(probe)
	if probe == "" {
		host, port, err := net.SplitHostPort(turnAddr)
		if err != nil {
			return nil, nil, "", fmt.Errorf("invalid --turn %q: %w", turnAddr, err)
		}
		ip, err := pickIP(host)
		if err != nil {
			return nil, nil, "", fmt.Errorf("resolve TURN host %q failed: %w", host, err)
		}
		probe = net.JoinHostPort(ip.String(), port)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", probe)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid probe address %q (udp): %w", probe, err)
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", probe)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid probe address %q (tcp): %w", probe, err)
	}
	return udpAddr, tcpAddr, probe, nil
}

func dialTurnDataConn(cfg commonConfig) (net.Conn, error) {
	if cfg.Transport == "tls" {
		return dialServerTLS(cfg)
	}
	return dialServerTCP(cfg)
}

// rfc6062Transport picks the control transport for RFC 6062 TCP allocations.
// They need a stream connection, so DTLS maps to TLS on the same port.
func rfc6062Transport(transport string) string {
	if transport == "tls" || transport == "dtls" {
		return "tls"
	}
	return "tcp"
}

// probeRelayResponses sends one STUN Binding request through the relay to
// each target and collects answers until all arrived or the wait expired. An
// answer proves that the relay delivered the request and carried the reply
// back; no answer is inconclusive because the target might not speak STUN.
// Answers are matched by transaction ID, so a reply from another address
// (e.g. 127.0.0.1 answering for 0.0.0.0) counts and is reported as such.
// It returns each target's responder ("" without answer) and send error.
func probeRelayResponses(relay net.PacketConn, targets []*net.UDPAddr, wait time.Duration) ([]string, []error) {
	responders := make([]string, len(targets))
	sendErrs := make([]error, len(targets))
	pending := make(map[[stun.TransactionIDSize]byte]int, len(targets))
	for i, target := range targets {
		var txID [stun.TransactionIDSize]byte
		if _, err := rand.Read(txID[:]); err != nil {
			sendErrs[i] = err
			continue
		}
		m := stun.Message{Raw: make([]byte, 0, 64), Type: stun.NewType(stun.MethodBinding, stun.ClassRequest), TransactionID: txID}
		m.Encode()
		if _, err := relay.WriteTo(m.Raw, target); err != nil {
			sendErrs[i] = err
			continue
		}
		pending[txID] = i
	}
	if wait <= 0 || wait > maxRelayProbeWait {
		wait = maxRelayProbeWait
	}
	if len(pending) == 0 || relay.SetReadDeadline(time.Now().Add(wait)) != nil {
		return responders, sendErrs
	}
	defer relay.SetReadDeadline(time.Time{})
	buf := make([]byte, 2048)
	for len(pending) > 0 {
		n, from, err := relay.ReadFrom(buf)
		if err != nil {
			break // Deadline reached or relay closed: the rest stays unanswered.
		}
		resp := stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if resp.Decode() != nil || resp.Type.Method != stun.MethodBinding || resp.Type.Class == stun.ClassRequest || resp.Type.Class == stun.ClassIndication {
			continue
		}
		if i, ok := pending[resp.TransactionID]; ok {
			responders[i] = from.String()
			delete(pending, resp.TransactionID)
		}
	}
	return responders, sendErrs
}

// probePeers surveys which peer permissions the server grants and, for the
// addresses of the TURN host itself, whether the relay actually reaches them.
func probePeers(client permissionClient, relay net.PacketConn, port int, external *net.UDPAddr, label string, wait time.Duration) ([]peerProbe, peerProbe) {
	var peers []peerProbe
	var targets []*net.UDPAddr
	var probed []*peerProbe
	addPeer := func(p *peerProbe, addr *net.UDPAddr, sendSTUN bool) {
		p.Permission = client.CreatePermission(addr)
		if p.Permission == nil && sendSTUN {
			p.Tested = true
			targets = append(targets, addr)
			probed = append(probed, p)
		}
	}
	all := append(append([]string{}, loopbackPeers...), internalPeers...)
	peers = make([]peerProbe, len(all))
	for i, address := range all {
		peers[i].Address = address
		addPeer(&peers[i], &net.UDPAddr{IP: net.ParseIP(address), Port: port}, i < len(loopbackPeers))
	}
	ext := peerProbe{Address: label}
	addPeer(&ext, external, true)
	responders, sendErrs := probeRelayResponses(relay, targets, wait)
	for i, p := range probed {
		p.ResponseFrom, p.SendErr = responders[i], sendErrs[i]
	}
	return peers, ext
}

func RunInfo(argv []string) error {
	fs := pflag.NewFlagSet("info", pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	var cfg commonConfig
	cfg.Software = "turnado/info"
	addCommonFlags(fs, &cfg)

	help := fs.BoolP("help", "h", false, "Show help message")
	probeAddr := fs.StringP("probe", "a", "", "External ip:port for the permission, relay and TCP CONNECT probes (default: TURN server:port)")
	jsonOutput := fs.Bool("json", false, "Print machine-readable results")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado info [options]")
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		printModeExamples(os.Stdout, "info")
		fs.SetOutput(origOut)
	}

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if err := resolveCommonFlags(fs, &cfg); err != nil {
		return err
	}
	if err := requireTurn(fs, cfg.Turn); err != nil {
		return err
	}
	if err := validateCommon(cfg); err != nil {
		return err
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	_, portStr, err := net.SplitHostPort(cfg.Turn)
	if err != nil {
		return fmt.Errorf("invalid TURN address: %w", err)
	}
	turnPort, err := strconv.Atoi(portStr)
	if err != nil || turnPort < 1 || turnPort > 65535 {
		return fmt.Errorf("invalid TURN port %q", portStr)
	}
	probeUDP, probeTCP, probeLabel, err := resolveProbeAddrs(cfg.Turn, *probeAddr)
	if err != nil {
		return err
	}
	report := infoReport{
		Turn: cfg.Turn, Transport: cfg.Transport, Probe: probeLabel, TurnPort: turnPort,
		TCPTransport: rfc6062Transport(cfg.Transport), TCPTarget: probeTCP.String(),
	}
	emit := func() error {
		if *jsonOutput {
			return emitInfoJSON(report.jsonFields())
		}
		writeInfoText(os.Stdout, report)
		return nil
	}

	udpHello, err := probeServerInfo(cfg, 17)
	report.AnonymousKnown, report.Anonymous = err == nil, udpHello
	if err != nil && cfg.Verbose > 0 {
		log.Printf("UDP realm probe failed: %v", err)
	}
	tcpHello, err := probeServerInfo(cfg, 6)
	if err != nil && cfg.Verbose > 0 {
		log.Printf("TCP realm probe failed: %v", err)
	}
	report.Realm, report.Software = udpHello.Realm, udpHello.Software
	if report.Realm == "" {
		report.Realm = tcpHello.Realm
	}
	if report.Software == "" {
		report.Software = tcpHello.Software
	}

	if cfg.Username == "" || cfg.Password == "" {
		report.Status = "missing_credentials"
		return emit()
	}
	report.IPv4 = probeAllocationFamily(cfg, 1)
	report.IPv6 = probeAllocationFamily(cfg, 2)

	client, _, cleanup, err := newTurnClient(cfg)
	if err != nil {
		report.Status, report.ClientErr = "auth_client_failed", err
		return emit()
	}
	defer cleanup()

	if mapped, err := client.SendBindingRequestTo(client.TURNServerAddr()); err != nil {
		report.MappedErr = err
	} else {
		report.Mapped = mapped.String()
	}

	relayConn, err := client.Allocate()
	if err != nil {
		report.Status, report.AllocErr = "allocation_failed", err
		return emit()
	}
	defer relayConn.Close()
	report.Relay = relayConn.LocalAddr().String()
	report.Peers, report.External = probePeers(client, relayConn, turnPort, probeUDP, probeLabel, cfg.Timeout)

	tcpCfg := cfg
	tcpCfg.Transport = report.TCPTransport
	report.TCP = probeTCPRelay(tcpCfg, probeTCP)
	report.Status = "ok"
	return emit()
}

// tcpRelayProbe records the RFC 6062 steps. Once a step fails, the later
// ones are skipped and stay nil.
type tcpRelayProbe struct {
	ClientErr, AllocErr, ConnectErr, SendErr error
	Connected                                bool
}

// probeTCPRelay checks RFC 6062 support: a TCP allocation, then CONNECT and
// ConnectionBind to the target and a short write on the data connection.
func probeTCPRelay(cfg commonConfig, target *net.TCPAddr) tcpRelayProbe {
	var p tcpRelayProbe
	client, _, cleanup, err := newTurnClient(cfg)
	if err != nil {
		p.ClientErr = err
		return p
	}
	defer cleanup()
	allocation, err := client.AllocateTCP()
	if err != nil {
		p.AllocErr = err
		return p
	}
	defer allocation.Close()
	dataConn, err := dialTurnDataConn(cfg)
	if err != nil {
		p.ConnectErr = fmt.Errorf("data connection: %w", err)
		return p
	}
	conn, err := allocation.DialTCPWithConn(asTURNTCPConn(dataConn), "tcp", target)
	if err != nil {
		_ = dataConn.Close()
		p.ConnectErr = err
		return p
	}
	p.Connected = true
	_ = conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
	_, p.SendErr = conn.Write([]byte("probe"))
	_ = conn.Close()
	return p
}
