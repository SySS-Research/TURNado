package app

import (
	"log"
	"net"
	"time"
)

func primeChannel(relayConn net.PacketConn, peer *net.UDPAddr, sec *secureSession, verbose int) {
	if relayConn == nil || peer == nil {
		return
	}
	if verbose > 1 {
		log.Printf("Priming channel bind to %s", peer.String())
	}
	dummy := buildPacket(msgTypeData, 0, []byte{0})
	for i := 0; i < 3; i++ {
		pkt, err := wrapPacket(sec, dummy)
		if err == nil {
			_, _ = relayConn.WriteTo(pkt, peer)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
