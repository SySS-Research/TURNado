package app

import (
	"encoding/binary"
	"testing"
)

func checksum16(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestClampTCPMSSPreservesChecksum(t *testing.T) {
	packet := make([]byte, 44)
	packet[0], packet[9] = 0x45, 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:20], []byte{192, 0, 2, 1, 198, 51, 100, 2})
	tcp := packet[20:]
	tcp[12], tcp[13] = 0x60, 0x02
	tcp[20], tcp[21] = 2, 4
	binary.BigEndian.PutUint16(tcp[22:24], 1460)
	pseudo := append(append([]byte(nil), packet[12:20]...), 0, 6, 0, byte(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:18], checksum16(append(pseudo, tcp...)))
	if got := checksum16(append(append([]byte(nil), pseudo...), tcp...)); got != 0 {
		t.Fatalf("initial checksum invalid: %04x", got)
	}
	if !clampTCPMSS(packet, 1172) {
		t.Fatal("MSS was not clamped")
	}
	if got := binary.BigEndian.Uint16(tcp[22:24]); got != 1132 {
		t.Fatalf("MSS=%d, want 1132", got)
	}
	if got := checksum16(append(append([]byte(nil), pseudo...), tcp...)); got != 0 {
		t.Fatalf("updated checksum invalid: %04x", got)
	}
	if clampTCPMSS(packet, 1172) {
		t.Fatal("unchanged MSS was reported as clamped")
	}
}
