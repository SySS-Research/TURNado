package app

import "encoding/binary"

// clampTCPMSS lowers a TCP SYN's MSS to what fits in one tunnel datagram.
// It handles unfragmented IPv4 packets; the TUN interface currently uses IPv4.
func clampTCPMSS(packet []byte, mtu int) bool {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}
	ipHeader := int(packet[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ipHeader < 20 || total > len(packet) || total < ipHeader+20 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return false
	}
	tcp := packet[ipHeader:total]
	tcpHeader := int(tcp[12]>>4) * 4
	if tcpHeader < 20 || tcpHeader > len(tcp) || tcp[13]&0x02 == 0 {
		return false
	}
	maxMSS := mtu - 40
	if maxMSS <= 0 {
		return false
	}
	for i := 20; i < tcpHeader; {
		kind := tcp[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= tcpHeader || tcp[i+1] < 2 || i+int(tcp[i+1]) > tcpHeader {
			return false
		}
		if kind == 2 && tcp[i+1] == 4 {
			old := int(binary.BigEndian.Uint16(tcp[i+2 : i+4]))
			if old <= maxMSS {
				return false
			}
			binary.BigEndian.PutUint16(tcp[i+2:i+4], uint16(maxMSS))
			// RFC 1624 incremental checksum update for one changed 16-bit word.
			oldSum := uint32(^binary.BigEndian.Uint16(tcp[16:18])) + uint32(^uint16(old)) + uint32(uint16(maxMSS))
			oldSum = (oldSum & 0xffff) + (oldSum >> 16)
			oldSum = (oldSum & 0xffff) + (oldSum >> 16)
			binary.BigEndian.PutUint16(tcp[16:18], ^uint16(oldSum))
			return true
		}
		i += int(tcp[i+1])
	}
	return false
}
