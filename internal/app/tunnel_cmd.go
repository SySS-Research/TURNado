package app

import "github.com/spf13/pflag"

func RunTunnel(argv []string) error {
	var cfg tunnelCfg
	ok, err := parsePairedMode("tunnel", argv, &cfg, func(fs *pflag.FlagSet) {
		fs.StringVar(&cfg.ClientIP, "client-ip", "10.0.1.2", "Client TUN IPv4 address")
		fs.StringVar(&cfg.ExitIP, "exit-ip", "10.0.1.1", "Exit TUN IPv4 address")
		fs.BoolVar(&cfg.RootlessExit, "rootless-exit", false, "On the exit, route TCP/UDP through a userspace NAT without TUN or root")
	})
	if !ok || err != nil {
		return err
	}
	if err := validateTunAddresses(cfg); err != nil {
		return err
	}
	return runTunnelAutoTun(cfg)
}
