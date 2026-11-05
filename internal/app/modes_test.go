package app

import "testing"

func TestModesRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Modes() {
		if m.Name == "" || m.Summary == "" || m.Run == nil {
			t.Fatalf("incomplete mode %+v", m)
		}
		if seen[m.Name] {
			t.Fatalf("duplicate mode %q", m.Name)
		}
		seen[m.Name] = true
		if got, ok := LookupMode(m.Name); !ok || got.Name != m.Name {
			t.Fatalf("lookup %q failed", m.Name)
		}
		if err := m.Run([]string{"-h"}); err != nil {
			t.Fatalf("%s -h: %v", m.Name, err)
		}
	}
	if _, ok := LookupMode("tunnel"); ok != tunSupported {
		t.Fatalf("tunnel listed=%v, supported=%v", ok, tunSupported)
	}
	if _, ok := LookupMode("nope"); ok {
		t.Fatal("unknown mode found")
	}
}

func TestTunAddressConfiguration(t *testing.T) {
	cfg := tunnelCfg{ClientIP: "10.8.0.2", ExitIP: "10.8.0.1"}
	if err := validateTunAddresses(cfg); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*tunnelCfg){
		func(c *tunnelCfg) { c.ExitIP = c.ClientIP },
		func(c *tunnelCfg) { c.ExitIP = "10.9.0.1" },
		func(c *tunnelCfg) { c.ClientIP = "invalid" },
	} {
		bad := cfg
		change(&bad)
		if err := validateTunAddresses(bad); err == nil {
			t.Fatalf("accepted invalid TUN config: %+v", bad)
		}
	}
}
