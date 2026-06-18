package app

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/stun"
	"github.com/spf13/pflag"
)

const (
	turnAllocateMethod stun.Method   = 0x003
	attrRequestedTrans stun.AttrType = 0x0019
)

func probeServerInfo(turnAddr string, controlTransport string, insecure bool, timeout time.Duration, requestedProto byte) (string, string, error) {
	cfg := commonConfig{Turn: turnAddr, Transport: controlTransport, Insecure: insecure, Timeout: timeout}
	pc, closeFn, err := dialControlConn(cfg)
	if err != nil {
		return "", "", err
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

	_ = pc.SetDeadline(time.Now().Add(timeout))
	if controlTransport == "udp" {
		ua, rerr := net.ResolveUDPAddr("udp", turnAddr)
		if rerr != nil {
			return "", "", rerr
		}
		if _, err := pc.WriteTo(m.Raw, ua); err != nil {
			return "", "", fmt.Errorf("write allocate probe failed: %w", err)
		}
	} else {
		if _, err := pc.WriteTo(m.Raw, nil); err != nil {
			if _, werr := pc.WriteTo(m.Raw, &net.UDPAddr{}); werr != nil {
				return "", "", fmt.Errorf("write allocate probe failed: %w", err)
			}
		}
	}

	buf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		return "", "", fmt.Errorf("read allocate probe failed: %w", err)
	}

	var resp stun.Message
	resp.Raw = append([]byte(nil), buf[:n]...)
	if err := resp.Decode(); err != nil {
		return "", "", fmt.Errorf("decode allocate probe failed: %w", err)
	}

	var r stun.Realm
	var s stun.Software
	realm := ""
	software := ""
	if getErr := r.GetFrom(&resp); getErr == nil {
		realm = string(r)
	}
	if getErr := s.GetFrom(&resp); getErr == nil {
		software = string(s)
	}
	return realm, software, nil
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
	d := &net.Dialer{Timeout: cfg.Timeout}
	if cfg.Transport == "tls" {
		tc := &tls.Config{InsecureSkipVerify: cfg.Insecure}
		return tls.DialWithDialer(d, "tcp", cfg.Turn, tc)
	}

	return d.Dial("tcp", cfg.Turn)
}

func isConnectBindSupported(err error) bool {
	if err == nil {
		return true
	}
	return strings.Contains(err.Error(), "error 447")
}

func RunInfo(argv []string) error {
	fs := pflag.NewFlagSet("info", pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	var cfg commonConfig
	cfg.Software = "turnado/info"
	addCommonFlags(fs, &cfg)

	help := fs.BoolP("help", "h", false, "Show help message")
	probeAddr := fs.StringP("probe", "a", "", "External address for permission/data probe (ip:port) (default: TURN server:port)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: turnado info [options]")
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		fs.SetOutput(origOut)
	}

	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *help {
		fs.Usage()
		return nil
	}
	if err := requireTurn(fs, cfg.Turn); err != nil {
		return err
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	probeUDP, probeTCP, probeLabel, err := resolveProbeAddrs(cfg.Turn, *probeAddr)
	if err != nil {
		return err
	}

	realmUDP, softwareUDP, err := probeServerInfo(cfg.Turn, cfg.Transport, cfg.Insecure, cfg.Timeout, 17)
	if err != nil && cfg.Verbose > 0 {
		log.Printf("UDP realm probe failed: %v", err)
	}
	realmTCP, softwareTCP, err := probeServerInfo(cfg.Turn, cfg.Transport, cfg.Insecure, cfg.Timeout, 6)
	if err != nil && cfg.Verbose > 0 {
		log.Printf("TCP realm probe failed: %v", err)
	}

	realm := realmUDP
	if realm == "" {
		realm = realmTCP
	}
	if realm == "" {
		realm = "unknown"
	}
	software := softwareUDP
	if software == "" {
		software = softwareTCP
	}

	if cfg.Username == "" || cfg.Password == "" {
		fmt.Printf("TURN server: %s\n", cfg.Turn)
		fmt.Printf("Realm: %s\n", realm)
		if software != "" {
			fmt.Printf("Software: %s\n", software)
		}
		fmt.Printf("Probe address: %s\n", probeLabel)
		fmt.Printf("XOR-MAPPED-ADDRESS: unavailable (missing credentials)\n")
		fmt.Printf("External permission/data probe: skipped (missing credentials)\n")
		return nil
	}

	client, _, cleanup, err := newTurnClient(cfg)
	if err != nil {
		fmt.Printf("TURN server: %s\n", cfg.Turn)
		fmt.Printf("Realm: %s\n", realm)
		if software != "" {
			fmt.Printf("Software: %s\n", software)
		}
		fmt.Printf("Probe address: %s\n", probeLabel)
		fmt.Printf("XOR-MAPPED-ADDRESS: unavailable (auth client init failed: %v)\n", err)
		fmt.Printf("External permission/data probe: unavailable\n")
		return nil
	}
	defer cleanup()

	mapped, mapErr := client.SendBindingRequestTo(client.TURNServerAddr())
	xorMapped := "unknown"
	if mapErr == nil {
		xorMapped = mapped.String()
	}

	relayConn, allocErr := client.Allocate()
	if allocErr != nil {
		fmt.Printf("TURN server: %s\n", cfg.Turn)
		fmt.Printf("Realm: %s\n", realm)
		if software != "" {
			fmt.Printf("Software: %s\n", software)
		}
		fmt.Printf("Probe address: %s\n", probeLabel)
		fmt.Printf("XOR-MAPPED-ADDRESS: %s\n", xorMapped)
		fmt.Printf("External permission/data probe: allocation failed (%v)\n", allocErr)
		return nil
	}
	defer relayConn.Close()

	loopV4 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	loopV6 := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 50000}
	loopV4Err := client.CreatePermission(loopV4)
	loopV6Err := client.CreatePermission(loopV6)

	udpPermErr := client.CreatePermission(probeUDP)
	var udpSendErr error
	if udpPermErr == nil {
		payload := []byte("probe")
		_, udpSendErr = relayConn.WriteTo(payload, probeUDP)
	} else {
		udpSendErr = fmt.Errorf("skipped (permission failed)")
	}

	tcpProbeCfg := cfg
	if cfg.Transport == "tls" {
		tcpProbeCfg.Transport = "tls"
	} else {
		tcpProbeCfg.Transport = "tcp"
	}

	tcpAllocErr := error(nil)
	tcpConnectBindErr := error(nil)
	tcpSendErr := error(nil)
	clientTCP, _, cleanupTCP, err := newTurnClient(tcpProbeCfg)
	if err != nil {
		tcpAllocErr = err
		tcpConnectBindErr = fmt.Errorf("skipped (allocation failed)")
		tcpSendErr = fmt.Errorf("skipped (allocation failed)")
	} else {
		defer cleanupTCP()
		tcpAlloc, err := clientTCP.AllocateTCP()
		if err != nil {
			tcpAllocErr = err
			tcpConnectBindErr = fmt.Errorf("skipped (allocation failed)")
			tcpSendErr = fmt.Errorf("skipped (allocation failed)")
		} else {
			defer tcpAlloc.Close()
			dataConn, err := dialTurnDataConn(tcpProbeCfg)
			if err != nil {
				tcpConnectBindErr = err
				tcpSendErr = err
			} else {
				conn, err := tcpAlloc.DialTCPWithConn(dataConn, "tcp", probeTCP)
				if err != nil {
					_ = dataConn.Close()
					tcpConnectBindErr = err
					tcpSendErr = err
				} else {
					tcpConnectBindErr = nil
					_ = conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
					_, tcpSendErr = conn.Write([]byte("probe"))
					_ = conn.Close()
				}
			}
		}
	}

	if tcpAllocErr != nil {
		tcpConnectBindErr = fmt.Errorf("skipped (allocation failed)")
		if tcpSendErr == nil {
			tcpSendErr = fmt.Errorf("skipped (allocation failed)")
		}
	}

	fmt.Printf("TURN server: %s\n", cfg.Turn)
	fmt.Printf("Realm: %s\n", realm)
	if software != "" {
		fmt.Printf("Software: %s\n", software)
	}
	fmt.Printf("Probe address: %s\n", probeLabel)
	fmt.Printf("XOR-MAPPED-ADDRESS: %s\n", xorMapped)

	fmt.Printf("Permission to 127.0.0.1 allowed: %v", loopV4Err == nil)
	if loopV4Err != nil {
		fmt.Printf(" (error: %v)", loopV4Err)
	}
	fmt.Println()

	fmt.Printf("Permission to ::1 allowed: %v", loopV6Err == nil)
	if loopV6Err != nil {
		fmt.Printf(" (error: %v)", loopV6Err)
	}
	fmt.Println()

	fmt.Printf("UDP permission allowed: %v", udpPermErr == nil)
	if udpPermErr != nil {
		fmt.Printf(" (error: %v)", udpPermErr)
	}
	fmt.Println()

	fmt.Printf("UDP data send: %v", udpSendErr == nil)
	if udpSendErr != nil {
		fmt.Printf(" (error: %v)", udpSendErr)
	}
	fmt.Println()

	fmt.Printf("TCP allocation allowed: %v", tcpAllocErr == nil)
	if tcpAllocErr != nil {
		fmt.Printf(" (error: %v)", tcpAllocErr)
	}
	fmt.Println()

	if tcpAllocErr == nil || cfg.Verbose > 0 {
		fmt.Printf("TCP connect/bind supported: %v", isConnectBindSupported(tcpConnectBindErr))
		if tcpConnectBindErr != nil {
			fmt.Printf(" (error: %v)", tcpConnectBindErr)
		}
		fmt.Println()

		fmt.Printf("TCP data send: %v", tcpSendErr == nil)
		if tcpSendErr != nil {
			fmt.Printf(" (error: %v)", tcpSendErr)
		}
		fmt.Println()
	}

	return nil
}
