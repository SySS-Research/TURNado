package app

import (
	"log"
	"net"
	"time"
)

func primeChannel(relayConn net.PacketConn, peer *net.UDPAddr, verbose int) {
	if relayConn == nil || peer == nil {
		return
	}
	if verbose > 1 {
		log.Printf("Priming channel bind to %s", peer.String())
	}
	dummy := buildPacket(msgTypePing, 0, nil)
	for i := 0; i < 3; i++ {
		_, _ = relayConn.WriteTo(dummy, peer)
		time.Sleep(100 * time.Millisecond)
	}
}
