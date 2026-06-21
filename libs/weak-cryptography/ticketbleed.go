package weakcryptography

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var ticketbleedFakeSID = []byte{0x00, 0x0B, 0xAD, 0xC0, 0xDE, 0x00}

// Ticketbleed runs the CVE-2016-9244 (Ticketbleed) check on F5 BIG-IP devices.
// Detection follows testssl.sh run_ticketbleed.
func Ticketbleed(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	fmt.Println("Ticketbleed (CVE-2016-9244), experimental")

	wireVersion := pickProbeTLSVersion(host, portForConn)
	if !serverHasExtension(host, portForConn, wireVersion, tlsExtSessionTicket) {
		fmt.Println("  OK - not vulnerable, no session ticket extension")
		return
	}

	ticket, err := fetchSessionTicket(host, portForConn, wireVersion)
	if err != nil || len(ticket) == 0 {
		fmt.Println("  OK - not vulnerable, no session tickets")
		return
	}

	memories := make([][]byte, 3)
	sidMatches := 0
	for i := 0; i < 3; i++ {
		sid, leak, ok, probeErr := ticketbleedProbe(host, portForConn, wireVersion, ticket)
		if probeErr != nil || !ok {
			fmt.Printf("  WARN - test failed (%v)\n", probeErr)
			return
		}
		if bytes.Contains(sid, ticketbleedFakeSID) {
			sidMatches++
		}
		memories[i] = append([]byte(nil), leak...)
	}

	if sidMatches == 3 && len(memories[0]) > 0 && len(memories[1]) > 0 && len(memories[2]) > 0 &&
		(!bytes.Equal(memories[0], memories[1]) || !bytes.Equal(memories[1], memories[2])) {
		fmt.Println("  VULNERABLE - Ticketbleed memory leak detected (NOT ok)")
		fmt.Println("  Server may leak session ticket memory (CVE-2016-9244, F5 BIG-IP).")
		return
	}
	if sidMatches == 3 {
		fmt.Println("  OK - not vulnerable (session IDs returned but memory fragments do not differ)")
		return
	}
	fmt.Printf("  WARN - test failed, non reproducible results (# of faked TLS SIDs detected: %d)\n", sidMatches)
}

func fetchSessionTicket(host, port string, wireVersion uint16) ([]byte, error) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	ticketExt := []byte{0x00, 0x23, 0x00, 0x00}
	ch, err := buildClientHelloWithExtensions(wireVersion, defaultProbeCiphers(), host, ticketExt)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(ch); err != nil {
		return nil, err
	}
	data, err := readFullConn(conn, 65536)
	if err != nil && len(data) == 0 {
		return nil, err
	}
	return parseNewSessionTicket(data), nil
}

func parseNewSessionTicket(data []byte) []byte {
	for off := 0; off+5 <= len(data); {
		if data[off] != 0x16 {
			off++
			continue
		}
		length := int(data[off+3])<<8 | int(data[off+4])
		if off+5+length > len(data) {
			break
		}
		payload := data[off+5 : off+5+length]
		pos := 0
		for pos+4 <= len(payload) {
			msgType := payload[pos]
			msgLen := int(payload[pos+1])<<16 | int(payload[pos+2])<<8 | int(payload[pos+3])
			if pos+4+msgLen > len(payload) {
				break
			}
			msg := payload[pos+4 : pos+4+msgLen]
			if msgType == 0x04 && len(msg) >= 6 {
				ticketLen := int(msg[4])<<8 | int(msg[5])
				if 6+ticketLen <= len(msg) {
					return append([]byte(nil), msg[6:6+ticketLen]...)
				}
			}
			pos += 4 + msgLen
		}
		off += 5 + length
	}
	return nil
}

func ticketbleedProbe(host, port string, wireVersion uint16, ticket []byte) (sessionID, leak []byte, ok bool, err error) {
	ch, err := buildTicketbleedClientHello(host, wireVersion, ticket)
	if err != nil {
		return nil, nil, false, err
	}
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return nil, nil, false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))
	if _, err := conn.Write(ch); err != nil {
		return nil, nil, false, err
	}
	data, err := readFullConn(conn, 32768)
	if err != nil && len(data) == 0 {
		return nil, nil, false, err
	}
	if len(data) >= 1 && data[0] == 0x15 {
		return nil, nil, false, nil
	}
	sid, leak, parsed := parseTicketbleedServerHello(data)
	return sid, leak, parsed, nil
}

func parseTicketbleedServerHello(data []byte) (sessionID, leak []byte, ok bool) {
	for off := 0; off+5 <= len(data); {
		if data[off] != 0x16 {
			off++
			continue
		}
		length := int(data[off+3])<<8 | int(data[off+4])
		if off+5+length > len(data) {
			break
		}
		payload := data[off+5 : off+5+length]
		pos := 0
		for pos+4 <= len(payload) {
			msgType := payload[pos]
			msgLen := int(payload[pos+1])<<16 | int(payload[pos+2])<<8 | int(payload[pos+3])
			if pos+4+msgLen > len(payload) {
				break
			}
			if msgType == 0x02 {
				msg := payload[pos+4 : pos+4+msgLen]
				if len(msg) < 34 {
					return nil, nil, false
				}
				sidLen := int(msg[34])
				if 35+sidLen > len(msg) {
					return nil, nil, false
				}
				sid := msg[35 : 35+sidLen]
				if sidLen > len(ticketbleedFakeSID) {
					leak = append([]byte(nil), sid[len(ticketbleedFakeSID):]...)
				}
				return sid, leak, true
			}
			pos += 4 + msgLen
		}
		off += 5 + length
	}
	return nil, nil, false
}

func buildTicketbleedClientHello(serverName string, wireVersion uint16, ticket []byte) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	verHi, verLo := byte(wireVersion>>8), byte(wireVersion&0xff)
	recVerHi, recVerLo := byte(0x03), byte(0x01)

	ciphers := parseTestSSLHexList("c0,14, c0,13, c0,0a, c0,21, 00,39, 00,38, 00,88, 00,87, c0,0f, c0,05, 00,35, 00,84, c0,12, c0,08, c0,1c, c0,1b, 00,16, 00,13, c0,0d, c0,03, 00,0a, c0,13, c0,09, c0,1f, c0,1e, 00,33, 00,32, 00,9a, 00,99, 00,45, 00,44, c0,0e, c0,04, 00,2f, 00,96, 00,41, c0,11, c0,07, c0,0c, c0,02, 00,05, 00,04, 00,15, 00,12, c0,30, c0,2f, 00,9d, 00,9c, 00,3d, 00,3c, 00,9f, 00,9e, 00,ff")

	body := make([]byte, 0, 512+len(ticket)+len(ciphers)*2)
	body = append(body, verHi, verLo)
	body = append(body, random...)
	body = append(body, byte(len(ticketbleedFakeSID)))
	body = append(body, ticketbleedFakeSID...)
	body = append(body, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00)

	var extensions []byte
	if serverName != "" {
		sniPayload := append([]byte{0x00}, appendLengthPrefixed([]byte(serverName))...)
		sniList := appendLengthPrefixed(sniPayload)
		extensions = append(extensions, 0x00, 0x00)
		extensions = append(extensions, appendLengthPrefixed(sniList)...)
	}
	padding := make([]byte, 56)
	extensions = append(extensions, 0x00, 0x15, 0x00, 0x38)
	extensions = append(extensions, padding...)
	extensions = append(extensions, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02)
	extensions = append(extensions, 0x00, 0x0a, 0x00, 0x34, 0x00, 0x32)
	extensions = append(extensions, parseTestSSLHexBytes("00,0e, 00,0d, 00,19, 00,0b, 00,0c, 00,18, 00,09, 00,0a, 00,16, 00,17, 00,08, 00,06, 00,07, 00,14, 00,15, 00,04, 00,05, 00,12, 00,13, 00,01, 00,02, 00,03, 00,0f, 00,10, 00,11")...)
	extensions = append(extensions, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02)
	extensions = append(extensions, 0x00, 0x23, byte(len(ticket)>>8), byte(len(ticket)))
	extensions = append(extensions, ticket...)
	extensions = append(extensions, 0x00, 0x0f, 0x00, 0x01, 0x01)

	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte((len(body)>>8)&0xff), byte(len(body)&0xff))
	handshake = append(handshake, body...)

	rec := make([]byte, 0, 5+len(handshake))
	rec = append(rec, 0x16, recVerHi, recVerLo)
	rec = append(rec, byte(len(handshake)>>8), byte(len(handshake)))
	rec = append(rec, handshake...)
	return rec, nil
}

func parseTestSSLHexBytes(hex string) []byte {
	hex = strings.ReplaceAll(hex, " ", "")
	parts := strings.Split(hex, ",")
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			continue
		}
		out = append(out, byte(v))
	}
	return out
}
