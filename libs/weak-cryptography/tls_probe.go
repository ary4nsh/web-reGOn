package weakcryptography

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	probeConnectTimeout  = 10 * time.Second
	probeReadTimeout     = 8 * time.Second
	tlsEmptyRenegSCSV    = 0x5600
)

// testssl.sh cipher lists (run_beast, run_lucky13, run_freak, run_rc4).
var (
	beastCBCHex     = "00,06, 00,07, 00,08, 00,09, 00,0A, 00,0B, 00,0C, 00,0D, 00,0E, 00,0F, 00,10, 00,11, 00,12, 00,13, 00,14, 00,15, 00,16, 00,19, 00,1A, 00,1B, 00,1E, 00,1F, 00,21, 00,22, 00,23, 00,25, 00,26, 00,27, 00,29, 00,2A, 00,2F, 00,30, 00,31, 00,32, 00,33, 00,34, 00,35, 00,36, 00,37, 00,38, 00,39, 00,3A, 00,41, 00,42, 00,43, 00,44, 00,45, 00,46, 00,61, 00,62, 00,63, 00,84, 00,85, 00,86, 00,87, 00,88, 00,89, 00,8B, 00,8C, 00,8D, 00,8F, 00,90, 00,91, 00,93, 00,94, 00,95, 00,96, 00,97, 00,98, 00,99, 00,9A, 00,9B, 00,AE, 00,AF, 00,B2, 00,B3, 00,B6, 00,B7, C0,03, C0,04, C0,05, C0,08, C0,09, C0,0A, C0,0D, C0,0E, C0,0F, C0,12, C0,13, C0,14, C0,17, C0,18, C0,19, C0,1B, C0,1C, C0,1E, C0,1F, C0,21, C0,22, C0,34, C0,35, C0,36, C0,37, C0,38, C0,64, C0,65, C0,66, C0,67, C0,68, C0,69, C0,70, C0,71, C0,94, C0,95, C0,96, C0,97, C0,98, C0,99, C0,9A, C0,9B, FE,FE, FE,FF, FF,E0, FF,E1, C0,1A, C0,1D, C0,20"
	lucky13CBCHex1  = "c0,28, c0,24, c0,14, c0,0a, c0,22, c0,21, c0,20, 00,b7, 00,b3, 00,91, c0,9b, c0,99, c0,97, 00,af, c0,95, 00,6b, 00,6a, 00,69, 00,68, 00,39, 00,38, 00,37, 00,36, c0,77, c0,73, 00,c4, 00,c3, 00,c2, 00,c1, 00,88, 00,87, 00,86, 00,85, c0,19, 00,6d, 00,3a, 00,c5, 00,89, c0,2a, c0,26, c0,0f, c0,05, c0,79, c0,75, 00,3d, 00,35, 00,c0, c0,38, c0,36, 00,84, 00,95, 00,8d, c0,3d, c0,3f, c0,41, c0,43, c0,45, c0,47, c0,49, c0,4b, c0,4d, c0,4f, c0,65, c0,67, c0,69, c0,71, c0,27, c0,23, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,67, 00,40, 00,3f, 00,3e, 00,33, 00,32, 00,31, 00,30, c0,76, c0,72, 00,be, 00,bd, 00,bc, 00,bb, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44, 00,43, 00,42, c0,18, 00,6c, 00,34, 00,bf, 00,9b, 00,46, c0,29, c0,25, c0,0e, c0,04, c0,78, c0,74, 00,3c, 00,2f, 00,ba"
	lucky13CBCHex2  = "c0,37, c0,35, 00,b6, 00,b2, 00,90, 00,96, 00,41, c0,9a, c0,98, c0,96, 00,ae, c0,94, 00,07, 00,94, 00,8c, 00,21, 00,25, c0,3c, c0,3e, c0,40, c0,42, c0,44, c0,46, c0,48, c0,4a, c0,4c, c0,4e, c0,64, c0,66, c0,68, c0,70, c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, fe,ff, ff,e0, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,1a, 00,62, 00,09, 00,61, 00,1e, 00,22, fe,fe, ff,e1, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e"
	freakExportHex       = "00,62, 00,61, 00,64, 00,60, 00,14, 00,0E, 00,08, 00,06, 00,03"
	freakSSL2Export      = [][3]byte{{0x04, 0x00, 0x80}, {0x02, 0x00, 0x80}, {0x00, 0x00, 0x00}}
	sweet32Hex           = "00,07, 00,21, 00,25, c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, fe,ff, ff,e0, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,1a, 00,62, 00,09, 00,61, 00,1e, 00,22, fe,fe, ff,e1, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e"
	sweet32SSL2Hex       = "03,00,80, 04,00,80, 05,00,80, 06,00,40, 06,01,40, 07,00,C0, 07,01,C0, FF,80,00"
	poodleSSL3CBCHex     = "c0,14, c0,0a, c0,22, c0,21, c0,20, 00,91, 00,39, 00,38, 00,37, 00,36, 00,88, 00,87, 00,86, 00,85, c0,19, 00,3a, 00,89, c0,0f, c0,05, 00,35, c0,36, 00,84, 00,95, 00,8d, c0,13, c0,09, c0,1f, c0,1e, c0,1d, 00,33, 00,32, 00,31, 00,30, 00,9a, 00,99, 00,98, 00,97, 00,45, 00,44, 00,43, 00,42, c0,18, 00,34, 00,9b, 00,46, c0,0e, c0,04, 00,2f, c0,35, 00,90, 00,96, 00,41, 00,07, 00,94, 00,8c, 00,21, 00,25, c0,12, c0,08, c0,1c, c0,1b, c0,1a, 00,16, 00,13, 00,10, 00,0d, c0,17, 00,1b, c0,0d, c0,03, 00,0a, 00,93, 00,8b, 00,1f, 00,23, c0,34, 00,8f, 00,63, 00,15, 00,12, 00,0f, 00,0c, 00,1a, 00,62, 00,09, 00,1e, 00,22, 00,14, 00,11, 00,19, 00,08, 00,06, 00,27, 00,26, 00,2a, 00,29, 00,0b, 00,0e"
	logjamExportDHHex    = "00,63, 00,65, 00,14, 00,11"
	winshockFixedHex     = "00,9F, 00,9D, 00,9E, 00,9C"
	winshockARIAChachaHex = "C0,3D,C0,3F,C0,41,C0,43,C0,45,C0,47,C0,49,C0,4B,C0,4D,C0,4F,C0,51,C0,53,C0,55,C0,57,C0,59,C0,5B,C0,5D,C0,5F,C0,61,C0,63,C0,65,C0,67,C0,69,C0,6B,C0,6D,C0,6F,C0,71,C0,3C,C0,3E,C0,40,C0,42,C0,44,C0,46,C0,48,C0,4A,C0,4C,C0,4E,C0,50,C0,52,C0,54,C0,56,C0,58,C0,5A,C0,5C,C0,5E,C0,60,C0,62,C0,64,C0,66,C0,68,C0,6A,C0,6C,C0,6E,C0,70,CC,14,CC,13,CC,15,CC,A9,CC,A8,CC,AA,C0,AF,C0,AD,C0,A3,C0,9F,CC,AE,CC,AD,CC,AC,C0,AB,C0,A7,C0,A1,C0,9D,CC,AB,C0,A9,C0,A5,16,B7,16,B8,13,04,13,05,C0,AE,C0,AC,C0,A2,C0,9E,C0,AA,C0,A6,C0,A0,C0,9C,C0,A8,C0,A4"
	winshockCamelliaHex  = "C0,9B,C0,99,C0,97,C0,95,C0,77,C0,73,00,C4,00,C3,00,C2,00,C1,00,88,00,87,00,86,00,85,00,C5,00,89,C0,79,C0,75,00,C0,00,84,C0,7B,C0,7D,C0,7F,C0,81,C0,83,C0,85,C0,87,C0,89,C0,8B,C0,8D,C0,8F,C0,91,C0,93,C0,76,C0,72,00,BE,00,BD,00,BC,00,BB,00,45,00,44,00,43,00,42,00,BF,00,46,C0,78,C0,74,00,BA,00,41,C0,9A,C0,98,C0,96,C0,94,C0,7A,C0,7C,C0,7E,C0,80,C0,82,C0,84,C0,86,C0,88,C0,8A,C0,8C,C0,8E,C0,90,C0,92,C0,2F,C0,30"
	tlsExtHeartbeat      uint16 = 0x000f
	tlsExtSessionTicket  uint16 = 0x0023
	tlsExtEncryptThenMAC uint16 = 0x0016
	tlsExtMaxFragment    uint16 = 0x0001
	tlsAlertInapFallback uint8  = 0x56
)

var cipherNames map[uint16]string

func init() {
	cipherNames = make(map[uint16]string)
	for _, cs := range tls.CipherSuites() {
		cipherNames[cs.ID] = cs.Name
	}
	for _, cs := range tls.InsecureCipherSuites() {
		cipherNames[cs.ID] = cs.Name
	}
	manual := map[uint16]string{
		0x0066: "SSL3_DHE-DSS-RC4-SHA",
		0x0065: "SSL3_EXP1024-DHE-DSS-RC4-SHA",
		0x0064: "SSL3_EXP1024-RC4-SHA",
		0x0060: "SSL3_EXP1024-RC4-MD5",
		0x0062: "EXP1024-DES-CBC-SHA",
		0x0061: "EXP1024-RC2-CBC-MD5",
	}
	for id, name := range manual {
		if _, ok := cipherNames[id]; !ok {
			cipherNames[id] = name
		}
	}
}

func parseTestSSLHexList(hex string) []uint16 {
	hex = strings.ReplaceAll(hex, " ", "")
	parts := strings.Split(hex, ",")
	out := make([]uint16, 0, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		hi, err1 := strconv.ParseUint(parts[i], 16, 8)
		lo, err2 := strconv.ParseUint(parts[i+1], 16, 8)
		if err1 != nil || err2 != nil {
			continue
		}
		id := uint16(hi)<<8 | uint16(lo)
		if id == 0x00ff || id == tlsEmptyRenegSCSV {
			continue
		}
		out = append(out, id)
	}
	return out
}

func cipherName(id uint16) string {
	if name, ok := cipherNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", id)
}

func cipherSet(list []uint16) map[uint16]bool {
	m := make(map[uint16]bool, len(list))
	for _, id := range list {
		m[id] = true
	}
	return m
}

func isTLS13OnlyServer(host, port string) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	ch, err := buildTLS13OnlyClientHello(host)
	if err != nil {
		return false
	}
	if _, err := conn.Write(ch); err != nil {
		return false
	}
	data, err := readTLSRecordBuffer(conn, 8192)
	if err != nil || !tls13HandshakeStarted(data) {
		return false
	}
	_, _, tls12OK := probeTLSBatchOpts(host, port, tlsVersion12, []uint16{0xC02F, 0xC030, 0x009C, 0x009D}, host, []uint8{0x00}, false)
	return !tls12OK
}

func buildTLS13OnlyClientHello(serverName string) ([]byte, error) {
	return buildBatchTLSClientHello(tlsVersion12, []uint16{0x1301, 0x1302, 0x1303}, serverName, []uint8{0x00}, true)
}

func buildBatchTLSClientHello(wireVersion uint16, cipherSuites []uint16, serverName string, compression []uint8, tls13Only bool) ([]byte, error) {
	return buildBatchTLSClientHelloOpts(wireVersion, cipherSuites, serverName, compression, tls13Only, true)
}

func buildBatchTLSClientHelloOpts(wireVersion uint16, cipherSuites []uint16, serverName string, compression []uint8, tls13Only, includeSCSV bool) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	verHi, verLo := byte(wireVersion>>8), byte(wireVersion&0xff)
	recVerHi, recVerLo := verHi, verLo
	if wireVersion >= tlsVersion10 {
		recVerHi, recVerLo = 0x03, 0x03
	}

	suites := append([]uint16(nil), cipherSuites...)
	if includeSCSV {
		suites = append(suites, tlsEmptyRenegSCSV)
	}

	body := make([]byte, 0, 512+len(suites)*2)
	body = append(body, verHi, verLo)
	body = append(body, random...)
	if tls13Only {
		sid := make([]byte, 32)
		if _, err := rand.Read(sid); err != nil {
			return nil, err
		}
		body = append(body, 32)
		body = append(body, sid...)
	} else {
		body = append(body, 0x00)
	}
	body = append(body, byte(len(suites)*2>>8), byte(len(suites)*2))
	for _, c := range suites {
		body = append(body, byte(c>>8), byte(c))
	}
	if len(compression) == 0 {
		compression = []uint8{0x00}
	}
	body = append(body, byte(len(compression)))
	body = append(body, compression...)

	var ext []byte
	if serverName != "" {
		sniPayload := append([]byte{0x00}, appendLengthPrefixed([]byte(serverName))...)
		sniList := appendLengthPrefixed(sniPayload)
		ext = append(ext, 0x00, 0x00)
		ext = append(ext, appendLengthPrefixed(sniList)...)
	}
	if tls13Only {
		ext = append(ext, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	}
	if len(ext) > 0 {
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	}

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

func buildBatchSSL3ClientHello(cipherSuites []uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	body := make([]byte, 0, 64+len(cipherSuites)*2)
	body = append(body, 0x01)
	bodyLen := 2 + 32 + 1 + 2 + len(cipherSuites)*2 + 1 + 1
	body = append(body, byte(bodyLen>>16), byte((bodyLen>>8)&0xff), byte(bodyLen&0xff))
	body = append(body, 0x03, 0x00)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, byte(len(cipherSuites)*2>>8), byte(len(cipherSuites)*2))
	for _, c := range cipherSuites {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00)

	rec := make([]byte, 0, 5+len(body))
	rec = append(rec, 0x16, 0x03, 0x00)
	rec = append(rec, byte(len(body)>>8), byte(len(body)))
	rec = append(rec, body...)
	return rec, nil
}

func appendLengthPrefixed(b []byte) []byte {
	out := make([]byte, 2+len(b))
	out[0] = byte(len(b) >> 8)
	out[1] = byte(len(b))
	copy(out[2:], b)
	return out
}

func tlsAlertRecord(data []byte) bool {
	for off := 0; off+5 <= len(data); {
		recType := data[off]
		length := int(data[off+3])<<8 | int(data[off+4])
		if off+5+length > len(data) {
			return false
		}
		if recType == 0x15 && length >= 2 {
			if data[off+5] == 2 {
				return true
			}
		}
		off += 5 + length
	}
	return false
}

func tls13HandshakeStarted(data []byte) bool {
	for i := 0; i+5 <= len(data); {
		recType := data[i]
		length := int(data[i+3])<<8 | int(data[i+4])
		if i+5+length > len(data) {
			return false
		}
		payload := data[i+5 : i+5+length]
		if recType == 0x16 && len(payload) >= 4 && payload[0] == 0x02 {
			return true
		}
		if recType == 0x15 {
			return false
		}
		i += 5 + length
	}
	return false
}

func readTLSRecordBuffer(conn net.Conn, limit int) ([]byte, error) {
	buf := make([]byte, 4096)
	var out []byte
	for len(out) < limit {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			if _, _, ok := parseFirstServerHello(out); ok {
				break
			}
			if tlsAlertRecord(out) {
				break
			}
		}
		if err != nil {
			if len(out) > 0 {
				break
			}
			return nil, err
		}
	}
	return out, nil
}

func probeTLSBatch(host, port string, wireVersion uint16, cipherSuites []uint16, serverName string, compression []uint8) (chosen uint16, compressionMethod uint8, ok bool) {
	return probeTLSBatchOpts(host, port, wireVersion, cipherSuites, serverName, compression, true)
}

func probeTLSBatchOpts(host, port string, wireVersion uint16, cipherSuites []uint16, serverName string, compression []uint8, includeSCSV bool) (chosen uint16, compressionMethod uint8, ok bool) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return 0, 0, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	ch, err := buildBatchTLSClientHelloOpts(wireVersion, cipherSuites, serverName, compression, false, includeSCSV)
	if err != nil {
		return 0, 0, false
	}
	if _, err := conn.Write(ch); err != nil {
		return 0, 0, false
	}
	data, err := readTLSRecordBuffer(conn, 65536)
	if err != nil || tlsAlertRecord(data) {
		return 0, 0, false
	}
	return parseFirstServerHello(data)
}

func probeSSL3Batch(host, port string, cipherSuites []uint16) (chosen uint16, ok bool) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	ch, err := buildBatchSSL3ClientHello(cipherSuites)
	if err != nil {
		return 0, false
	}
	if _, err := conn.Write(ch); err != nil {
		return 0, false
	}
	data, err := readTLSRecordBuffer(conn, 65536)
	if err != nil || tlsAlertRecord(data) {
		return 0, false
	}
	chosen, _, ok = parseFirstServerHello(data)
	return chosen, ok
}

func parseFirstServerHello(data []byte) (cipherSuite uint16, compression uint8, ok bool) {
	for off := 0; off+5 <= len(data); {
		recType := data[off]
		length := int(data[off+3])<<8 | int(data[off+4])
		if off+5+length > len(data) {
			return 0, 0, false
		}
		payload := data[off+5 : off+5+length]
		if recType == 0x16 {
			pos := 0
			for pos+4 <= len(payload) {
				msgType := payload[pos]
				msgLen := int(payload[pos+1])<<16 | int(payload[pos+2])<<8 | int(payload[pos+3])
				if pos+4+msgLen > len(payload) {
					break
				}
				msg := payload[pos+4 : pos+4+msgLen]
				if msgType == 0x02 {
					return parseServerHelloBody(msg)
				}
				pos += 4 + msgLen
			}
		}
		off += 5 + length
	}
	return 0, 0, false
}

func parseServerHelloBody(msg []byte) (cipherSuite uint16, compression uint8, ok bool) {
	if len(msg) < 2+32+1+2+1 {
		return 0, 0, false
	}
	pos := 34
	sidLen := int(msg[pos])
	pos += 1 + sidLen
	if pos+2+1 > len(msg) {
		return 0, 0, false
	}
	cipherSuite = binary.BigEndian.Uint16(msg[pos : pos+2])
	compression = msg[pos+2]
	return cipherSuite, compression, true
}

func probeSSL2Export(host, port string) (supported bool) {
	var challenge [16]byte
	_, _ = rand.Read(challenge[:])
	cipherBytes := make([]byte, 0, 9)
	for _, code := range freakSSL2Export {
		cipherBytes = append(cipherBytes, code[0], code[1], code[2])
	}
	payload := make([]byte, 0, 1+2+2+2+2+len(cipherBytes)+16)
	payload = append(payload, sslMsgClientHello, 0x00, 0x02)
	payload = append(payload, byte(len(cipherBytes)>>8), byte(len(cipherBytes)))
	payload = append(payload, 0, 0, 0, 16)
	payload = append(payload, cipherBytes...)
	payload = append(payload, challenge[:]...)
	hello := ssl2RecordWrite(payload, 0)

	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return false
	}
	msgType, body, _, ok := ssl2RecordRead(buf[:n], 0)
	if !ok || msgType != sslMsgServerHello {
		return false
	}
	ciphers, ok := parseServerHello(body)
	if !ok {
		return false
	}
	exportNames := map[string]bool{
		"SSL2_RC2_128_CBC_EXPORT40_WITH_MD5": true,
		"SSL2_RC4_128_EXPORT40_WITH_MD5":     true,
		"SSL2_NULL_WITH_MD5":                 true,
	}
	for _, name := range ciphers {
		if exportNames[name] || strings.Contains(name, "EXPORT") {
			return true
		}
	}
	return false
}

func probeAnyCipherFromList(host, port string, wireVersion uint16, list []uint16, serverName string) (uint16, bool) {
	set := cipherSet(list)
	chosen, _, ok := probeTLSBatch(host, port, wireVersion, list, serverName, []uint8{0x00})
	if !ok || !set[chosen] {
		return 0, false
	}
	return chosen, true
}

// trySSL3CipherSuite probes a single SSLv3 cipher (used by null-ciphers).
func trySSL3CipherSuite(host, port string, cipherID uint16) bool {
	chosen, ok := probeSSL3Batch(host, port, []uint16{cipherID})
	return ok && chosen == cipherID
}

func defaultProbeCiphers() []uint16 {
	return []uint16{0xC02F, 0xC030, 0x009C, 0x009D, 0x0035, 0x002F}
}

func probeProtocolSupported(host, port string, wireVersion uint16) bool {
	_, _, ok := probeTLSBatchOpts(host, port, wireVersion, defaultProbeCiphers(), host, []uint8{0x00}, false)
	return ok
}

func probeSSL3Supported(host, port string) bool {
	_, ok := probeSSL3Batch(host, port, defaultProbeCiphers())
	return ok
}

func probeTLS13Supported(host, port string) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))
	ch, err := buildTLS13OnlyClientHello(host)
	if err != nil {
		return false
	}
	if _, err := conn.Write(ch); err != nil {
		return false
	}
	data, err := readTLSRecordBuffer(conn, 8192)
	return err == nil && tls13HandshakeStarted(data)
}

func buildClientHelloWithExtensions(wireVersion uint16, cipherSuites []uint16, serverName string, extraExtensions []byte) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	verHi, verLo := byte(wireVersion>>8), byte(wireVersion&0xff)
	recVerHi, recVerLo := verHi, verLo
	if wireVersion >= tlsVersion10 {
		recVerHi, recVerLo = 0x03, 0x03
	}
	suites := append([]uint16{tlsEmptyRenegSCSV}, cipherSuites...)
	body := make([]byte, 0, 512+len(extraExtensions))
	body = append(body, verHi, verLo)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, byte(len(suites)*2>>8), byte(len(suites)*2))
	for _, c := range suites {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00)
	if serverName != "" {
		sniPayload := append([]byte{0x00}, appendLengthPrefixed([]byte(serverName))...)
		sniList := appendLengthPrefixed(sniPayload)
		ext := append([]byte{0x00, 0x00}, appendLengthPrefixed(sniList)...)
		ext = append(ext, extraExtensions...)
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	} else if len(extraExtensions) > 0 {
		body = append(body, byte(len(extraExtensions)>>8), byte(len(extraExtensions)))
		body = append(body, extraExtensions...)
	}
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

func parseServerHelloExtensions(msg []byte) map[uint16]bool {
	exts := make(map[uint16]bool)
	if len(msg) < 2+32+1 {
		return exts
	}
	pos := 34
	sidLen := int(msg[pos])
	pos += 1 + sidLen + 2 + 1
	if pos+2 > len(msg) {
		return exts
	}
	extLen := int(msg[pos])<<8 | int(msg[pos+1])
	pos += 2
	if extLen <= 0 || pos+extLen > len(msg) {
		return exts
	}
	end := pos + extLen
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(msg[pos : pos+2])
		extDataLen := int(msg[pos+2])<<8 | int(msg[pos+3])
		pos += 4
		if pos+extDataLen > end {
			break
		}
		exts[extType] = true
		pos += extDataLen
	}
	return exts
}

func probeServerExtensions(host, port string, wireVersion uint16) map[uint16]bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	heartbeatExt := []byte{0x00, 0x0f, 0x00, 0x01, 0x01}
	ticketExt := []byte{0x00, 0x23, 0x00, 0x00}
	extra := append(heartbeatExt, ticketExt...)

	ch, err := buildClientHelloWithExtensions(wireVersion, defaultProbeCiphers(), host, extra)
	if err != nil {
		return nil
	}
	if _, err := conn.Write(ch); err != nil {
		return nil
	}
	data, err := readTLSRecordBuffer(conn, 65536)
	if err != nil {
		return nil
	}
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
				return parseServerHelloExtensions(payload[pos+4 : pos+4+msgLen])
			}
			pos += 4 + msgLen
		}
		off += 5 + length
	}
	return nil
}

func serverHasExtension(host, port string, wireVersion, extID uint16) bool {
	exts := probeServerExtensions(host, port, wireVersion)
	return exts[extID]
}

func pickProbeTLSVersion(host, port string) uint16 {
	order := []uint16{tlsVersion12, tlsVersion11, tlsVersion10, 0x0300}
	for _, v := range order {
		if v == 0x0300 {
			if probeSSL3Supported(host, port) {
				return v
			}
			continue
		}
		if probeProtocolSupported(host, port, v) {
			return v
		}
	}
	return tlsVersion12
}

func buildFallbackSCSVClientHello(wireVersion uint16, serverName string) ([]byte, error) {
	ciphers := []uint16{tlsEmptyRenegSCSV}
	ciphers = append(ciphers, defaultProbeCiphers()...)
	return buildBatchTLSClientHelloOpts(wireVersion, ciphers, serverName, []uint8{0x00}, false, false)
}

func tlsAlertDescription(data []byte) (level, desc uint8, found bool) {
	for off := 0; off+7 <= len(data); {
		recType := data[off]
		length := int(data[off+3])<<8 | int(data[off+4])
		if off+5+length > len(data) {
			return 0, 0, false
		}
		if recType == 0x15 && length >= 2 {
			return data[off+5], data[off+6], true
		}
		off += 5 + length
	}
	return 0, 0, false
}

func tlsHandshakeHasCertificate(data []byte) bool {
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
			if msgType == 0x0b {
				return true
			}
			pos += 4 + msgLen
		}
		off += 5 + length
	}
	return false
}

func probeFallbackSCSV(host, port string, highProto, lowProto uint16) (status, detail string) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return "warn", "couldn't connect"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	ch, err := buildFallbackSCSVClientHello(lowProto, host)
	if err != nil {
		return "warn", "failed to build ClientHello"
	}
	if _, err := conn.Write(ch); err != nil {
		return "warn", "write failed"
	}
	data, err := readFullConn(conn, 65536)
	if err != nil && len(data) == 0 {
		return "warn", "couldn't connect"
	}
	if _, _, ok := parseFirstServerHello(data); ok && tlsHandshakeHasCertificate(data) {
		return "not_supported", "downgrade attack prevention NOT supported"
	}
	if level, desc, ok := tlsAlertDescription(data); ok {
		if level == 2 && desc == tlsAlertInapFallback {
			return "supported", "downgrade attack prevention supported"
		}
		if level == 2 && desc == 0x28 {
			return "probably_ok", "received handshake failure instead of inappropriate fallback"
		}
		return "medium", fmt.Sprintf("unexpected alert level=%d desc=%d", level, desc)
	}
	return "warn", "unexpected result"
}

func readFullConn(conn net.Conn, limit int) ([]byte, error) {
	buf := make([]byte, 4096)
	var out []byte
	for len(out) < limit {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
	}
	return out, nil
}

func heartbleedCheck(host, port string) (vulnerable bool, detail string) {
	wireVersion := pickProbeTLSVersion(host, port)
	if !serverHasExtension(host, port, wireVersion, tlsExtHeartbeat) {
		return false, "no heartbeat extension"
	}

	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	hbExt := []byte{0x00, 0x0f, 0x00, 0x01, 0x01}
	ch, err := buildClientHelloWithExtensions(wireVersion, defaultProbeCiphers(), host, hbExt)
	if err != nil {
		return false, "ClientHello build failed"
	}
	if _, err := conn.Write(ch); err != nil {
		return false, "write failed"
	}
	if _, err := readTLSRecordBuffer(conn, 65536); err != nil {
		return false, "handshake read failed"
	}

	verHi, verLo := byte(wireVersion>>8), byte(wireVersion&0xff)
	if wireVersion >= tlsVersion10 {
		verHi, verLo = 0x03, 0x03
	}
	hb := []byte{0x18, verHi, verLo, 0x00, 0x03, 0x01, 0x40, 0x00}
	if _, err := conn.Write(hb); err != nil {
		return false, "heartbeat send failed"
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	resp, err := readFullConn(conn, 16384)
	if err != nil && len(resp) == 0 {
		return false, "timed out"
	}
	if len(resp) >= 5 && resp[0] == 0x18 && resp[1] == verHi && resp[2] == verLo {
		payloadLen := int(resp[3])<<8 | int(resp[4])
		if payloadLen > 3 {
			return true, "heartbleed reply received"
		}
	}
	return false, "not vulnerable"
}

func probeSSL2CipherHexList(host, port string, hexList string) bool {
	codes := parseSSL2CipherHexList(hexList)
	if len(codes) == 0 {
		return false
	}
	var challenge [16]byte
	_, _ = rand.Read(challenge[:])
	cipherBytes := make([]byte, 0, len(codes)*3)
	for _, code := range codes {
		cipherBytes = append(cipherBytes, code[0], code[1], code[2])
	}
	payload := make([]byte, 0, 1+2+2+2+len(cipherBytes)+16)
	payload = append(payload, sslMsgClientHello, 0x00, 0x02)
	payload = append(payload, byte(len(cipherBytes)>>8), byte(len(cipherBytes)))
	payload = append(payload, 0, 0, 0, 16)
	payload = append(payload, cipherBytes...)
	payload = append(payload, challenge[:]...)
	hello := ssl2RecordWrite(payload, 0)

	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return false
	}
	msgType, body, _, ok := ssl2RecordRead(buf[:n], 0)
	if !ok || msgType != sslMsgServerHello {
		return false
	}
	ciphers, ok := parseServerHello(body)
	return ok && len(ciphers) > 0
}

func parseSSL2CipherHexList(hex string) [][3]byte {
	hex = strings.ReplaceAll(hex, " ", "")
	parts := strings.Split(hex, ",")
	var out [][3]byte
	for i := 0; i+2 < len(parts); i += 3 {
		var code [3]byte
		for j := 0; j < 3; j++ {
			v, err := strconv.ParseUint(parts[i+j], 16, 8)
			if err != nil {
				break
			}
			code[j] = byte(v)
		}
		out = append(out, code)
	}
	return out
}

func highestSupportedProtocol(host, port string) (name string, wireVersion uint16, ok bool) {
	type proto struct {
		name string
		ver  uint16
	}
	order := []proto{
		{"TLS 1.2", tlsVersion12},
		{"TLS 1.1", tlsVersion11},
		{"TLS 1.0", tlsVersion10},
		{"SSLv3", 0x0300},
	}
	for _, p := range order {
		supported := false
		if p.ver == 0x0300 {
			supported = probeSSL3Supported(host, port)
		} else {
			supported = probeProtocolSupported(host, port, p.ver)
		}
		if supported {
			return p.name, p.ver, true
		}
	}
	if probeTLS13Supported(host, port) {
		return "TLS 1.3", tlsVersion13, true
	}
	return "", 0, false
}

func lowerSupportedProtocol(host, port string, highVer uint16) (name string, wireVersion uint16, ok bool) {
	type proto struct {
		name string
		ver  uint16
	}
	var candidates []proto
	switch highVer {
	case tlsVersion12:
		candidates = []proto{{"TLS 1.1", tlsVersion11}, {"TLS 1.0", tlsVersion10}, {"SSLv3", 0x0300}}
	case tlsVersion11:
		candidates = []proto{{"TLS 1.0", tlsVersion10}, {"SSLv3", 0x0300}}
	case tlsVersion10:
		candidates = []proto{{"SSLv3", 0x0300}}
	default:
		return "", 0, false
	}
	for _, p := range candidates {
		supported := false
		if p.ver == 0x0300 {
			supported = probeSSL3Supported(host, port)
		} else {
			supported = probeProtocolSupported(host, port, p.ver)
		}
		if supported {
			return p.name, p.ver, true
		}
	}
	return "", 0, false
}
