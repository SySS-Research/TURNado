package app

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/spf13/pflag"
)

const envPassphrase = "TURNADO_PASSPHRASE"

type tunnelCfg struct {
	Common             commonConfig
	SocksPort          int
	SocksListen        string
	SocksUser          string
	SocksPass          string
	RootlessExit       bool
	NoTunnelEncryption bool
	Connect            string
	ClientIP           string
	ExitIP             string
	Encrypt            bool
	Passphrase         string
}

// parsePairedMode handles the flags shared by socks and tunnel. It returns
// false without error when only help was requested.
func parsePairedMode(mode string, argv []string, cfg *tunnelCfg, extra func(*pflag.FlagSet)) (bool, error) {
	fs := pflag.NewFlagSet(mode, pflag.ContinueOnError)

	origOut := io.Discard
	fs.SetOutput(origOut)

	cfg.Common.Software = "turnado/" + mode
	addCommonFlags(fs, &cfg.Common)

	fs.StringVarP(&cfg.Connect, "connect", "c", "", "Connection string for pairing")
	fs.BoolVar(&cfg.NoTunnelEncryption, "no-tunnel-encryption", false, "Disable DTLS-SRTP encryption of peer traffic")
	fs.StringVar(&cfg.Passphrase, "passphrase", "", "Encrypt connection strings with a shared passphrase (\"-\" prompts; default $"+envPassphrase+")")
	if extra != nil {
		extra(fs)
	}

	help := fs.BoolP("help", "h", false, "Show help message")

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: turnado %s [options]\n", mode)
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
		printModeExamples(os.Stdout, mode)
		fs.SetOutput(origOut)
	}

	if err := fs.Parse(argv); err != nil {
		return false, err
	}
	if *help {
		fs.Usage()
		return false, nil
	}
	cfg.Encrypt = !cfg.NoTunnelEncryption
	cfg.Common.transportSet = fs.Changed("transport")
	if err := promptCredentials(&cfg.Common); err != nil {
		return false, err
	}
	if err := resolvePassphrase(cfg); err != nil {
		return false, err
	}
	// On the exit, the connection string's credentials take precedence over
	// environment defaults; they are applied after decoding it.
	if cfg.Connect == "" {
		applyCredentialEnv(&cfg.Common)
		if err := requireTurn(fs, cfg.Common.Turn); err != nil {
			return false, err
		}
		if err := validateCommon(cfg.Common); err != nil {
			return false, err
		}
	}
	return true, nil
}

func resolvePassphrase(cfg *tunnelCfg) error {
	switch cfg.Passphrase {
	case "-":
		p, err := promptSecret("Connection string passphrase: ")
		if err != nil {
			return err
		}
		cfg.Passphrase = p
	case "":
		cfg.Passphrase = os.Getenv(envPassphrase)
	}
	return nil
}

func RunSocks(argv []string) error {
	var cfg tunnelCfg
	var direct bool
	ok, err := parsePairedMode("socks", argv, &cfg, func(fs *pflag.FlagSet) {
		fs.IntVarP(&cfg.SocksPort, "socks-port", "s", 1080, "Local SOCKS5 TCP listen port")
		fs.StringVar(&cfg.SocksListen, "socks-listen", "127.0.0.1", "SOCKS5 listen IP address")
		fs.StringVar(&cfg.SocksUser, "socks-user", "", "Require SOCKS5 username/password authentication (password from $"+envSocksPassword+")")
		fs.BoolVar(&direct, "direct", false, "Use RFC 6062 TCP allocations per SOCKS connection, without an exit peer (CONNECT only)")
	})
	if !ok || err != nil {
		return err
	}
	if cfg.SocksPort < 0 || cfg.SocksPort > 65535 {
		return fmt.Errorf("invalid SOCKS port %d", cfg.SocksPort)
	}
	if net.ParseIP(cfg.SocksListen) == nil {
		return fmt.Errorf("--socks-listen requires an IP address")
	}
	if err := resolveSocksAuth(&cfg); err != nil {
		return err
	}
	if direct {
		if cfg.Connect != "" || cfg.NoTunnelEncryption {
			return fmt.Errorf("--direct cannot be combined with pairing or --no-tunnel-encryption")
		}
		return runDirectSocks(cfg.Common, net.JoinHostPort(cfg.SocksListen, fmt.Sprint(cfg.SocksPort)), socksAuth{cfg.SocksUser, cfg.SocksPass})
	}
	return runTunnelAutoSocks(cfg)
}

func validateTunAddresses(cfg tunnelCfg) error {
	client := net.ParseIP(cfg.ClientIP).To4()
	exit := net.ParseIP(cfg.ExitIP).To4()
	if client == nil || exit == nil {
		return fmt.Errorf("--client-ip and --exit-ip must be IPv4 addresses")
	}
	mask := net.CIDRMask(24, 32)
	if client.Equal(exit) || !client.Mask(mask).Equal(exit.Mask(mask)) {
		return fmt.Errorf("client and exit IPs must be different addresses in the same subnet")
	}
	return nil
}
