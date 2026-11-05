package app

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestReliableConnectionStringVersion(t *testing.T) {
	cs := connString{V: 3, Turn: "turn.example:3478", Relay: "192.0.2.1:5000", Reliable: true}
	encoded, err := encodeConnString(cs, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeConnString(encoded, "")
	if err != nil || !decoded.Reliable {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	cs.V = 2
	if _, err := encodeConnString(cs, ""); err == nil {
		t.Fatal("accepted reliable mode without version 3")
	}
}

func TestUnknownConnectionStringVersionIsRejected(t *testing.T) {
	cs := connString{V: 4, Turn: "turn.example:3478", Relay: "192.0.2.1:5000", Reliable: true}
	if _, err := encodeConnString(cs, ""); err == nil {
		t.Fatal("accepted unsupported connection string version")
	}
}

func TestTunnelOfferIsRejectedBySocks(t *testing.T) {
	offer := connString{V: 1, Turn: "turn.example:3478", Relay: "192.0.2.1:5000"}
	s, err := encodeConnString(offer, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := tunnelCfg{Connect: s, NoTunnelEncryption: true}
	if err := runTunnelAutoSocks(cfg); err == nil || !strings.Contains(err.Error(), "different tunnel mode") {
		t.Fatalf("IP tunnel offer was accepted by socks: %v", err)
	}
}

func TestConnStringDefaultsRespectExplicitTransport(t *testing.T) {
	cs := connString{V: 1, Turn: "turn.example:443", User: "u", Pass: "p", Control: "tls", Relay: "192.0.2.1:5000"}

	var implicit tunnelCfg
	implicit.Common.Transport = "udp"
	if err := applyConnStringDefaults(&implicit, cs); err != nil {
		t.Fatal(err)
	}
	if implicit.Common.Transport != "tls" || implicit.Common.Turn != cs.Turn || implicit.Common.Password != "p" {
		t.Fatalf("defaults not inherited: %+v", implicit.Common)
	}

	var explicit tunnelCfg
	explicit.Common.Transport, explicit.Common.transportSet = "udp", true
	if err := applyConnStringDefaults(&explicit, cs); err != nil {
		t.Fatal(err)
	}
	if explicit.Common.Transport != "udp" {
		t.Fatalf("explicit -T udp overridden by %q", explicit.Common.Transport)
	}
}

func TestPassphraseProtectedConnString(t *testing.T) {
	cs := connString{V: 1, Turn: "turn.example:443", User: "user", Pass: "secret-pass", Control: "tls", Relay: "192.0.2.1:5000"}
	sealed, err := encodeConnString(cs, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, sealedPrefix) {
		t.Fatalf("missing prefix: %s", sealed)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, sealedPrefix))
	if bytes.Contains(raw, []byte("secret-pass")) || bytes.Contains(raw, []byte("turn.example")) {
		t.Fatal("credentials visible in sealed connection string")
	}
	got, err := decodeConnString(sealed, "correct horse")
	if err != nil || !reflect.DeepEqual(got, cs) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := decodeConnString(sealed, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := decodeConnString(sealed, ""); err == nil || !strings.Contains(err.Error(), "--passphrase") {
		t.Fatalf("missing passphrase not reported: %v", err)
	}
	tampered := []byte(sealed)
	tampered[len(tampered)-3] ^= 0x01
	if _, err := decodeConnString(string(tampered), "correct horse"); err == nil {
		t.Fatal("tampered connection string accepted")
	}
	again, _ := encodeConnString(cs, "correct horse")
	if again == sealed {
		t.Fatal("salt/nonce reused")
	}
	plain, _ := encodeConnString(cs, "")
	if got, err := decodeConnString(plain, "correct horse"); err != nil || !reflect.DeepEqual(got, cs) {
		t.Fatalf("plain string rejected with passphrase set: %v", err)
	}
}
