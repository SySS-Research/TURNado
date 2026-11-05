package app

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestDirectSocksReportsAllocationSetupFailure(t *testing.T) {
	user, server := net.Pipe()
	defer user.Close()
	defer server.Close()
	_ = user.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() { done <- handleDirectSocksConn(server, commonConfig{Turn: "127.0.0.1:3478"}, socksAuth{}) }()
	if _, err := user.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(user, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("greeting=%v err=%v", greeting, err)
	}
	if _, err := user.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	var response [10]byte
	if _, err := io.ReadFull(user, response[:]); err != nil || response[1] != 1 {
		t.Fatalf("response=%v err=%v", response, err)
	}
	if err := <-done; err == nil {
		t.Fatal("expected allocation setup error")
	}
}
