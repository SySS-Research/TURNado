package app

// Mode is one CLI sub-command. Platform-specific modes are only listed where
// they can run, so help output and dispatch never disagree.
type Mode struct {
	Name    string
	Summary string
	Run     func([]string) error
}

func Modes() []Mode {
	modes := []Mode{
		{"info", "Inspect TURN server capabilities", RunInfo},
		{"scan", "Test TCP targets from the TURN server via RFC 6062", RunScan},
		{"socks", "SOCKS5-over-TURN UDP tunnel", RunSocks},
	}
	if tunSupported {
		modes = append(modes, Mode{"tunnel", "IP tunnel (TUN) over TURN UDP", RunTunnel})
	}
	return append(modes,
		Mode{"forward", "UDP forwarder over TURN", RunForward},
		Mode{"dos", "Mass allocation creation for load tests", RunDOS},
	)
}

func LookupMode(name string) (Mode, bool) {
	for _, m := range Modes() {
		if m.Name == name {
			return m, true
		}
	}
	return Mode{}, false
}
