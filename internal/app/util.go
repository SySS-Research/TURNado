package app

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func mustResolveUDP(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		log.Fatalf("ResolveUDPAddr(%q) failed: %v", addr, err)
	}
	return a
}

func waitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

