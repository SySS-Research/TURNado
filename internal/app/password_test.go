package app

import (
	"testing"
)

func TestResolveCredentials(t *testing.T) {
	t.Setenv(envUsername, "env-user")
	t.Setenv(envPassword, "env-pass")
	orig := promptSecret
	t.Cleanup(func() { promptSecret = orig })
	promptSecret = func(string) (string, error) { return "typed-pass", nil }

	for _, tc := range []struct {
		name     string
		cfg      commonConfig
		user, pw string
	}{
		{"environment", commonConfig{}, "env-user", "env-pass"},
		{"flag wins", commonConfig{Username: "u", Password: "flag"}, "u", "flag"},
		{"prompt", commonConfig{Password: "-"}, "env-user", "typed-pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if err := resolveCredentials(&cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Username != tc.user || cfg.Password != tc.pw {
				t.Fatalf("got %q/%q", cfg.Username, cfg.Password)
			}
		})
	}
}
