package weakcryptography

import (
	"fmt"
	"net"
	"time"
)

const ccsInjectionReadTimeout = 5 * time.Second

// Fixed ClientHello random from testssl.sh run_ccs_injection.
var ccsInjectionRandom = []byte{
	0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
	0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
	0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0b, 0x85,
	0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
}

// Cipher list from testssl.sh run_ccs_injection (52 suites).
var ccsInjectionCiphers = []uint16{
	0xc013, 0xc012, 0xc011, 0xc010,
	0xc00f, 0xc00e, 0xc00d, 0xc00c,
	0xc00b, 0xc00a, 0xc009, 0xc008,
	0xc007, 0xc006, 0xc005, 0xc004,
	0xc003, 0xc002, 0xc001,
	0x0039, 0x0038, 0x0037, 0x0036, 0x0035, 0x0034,
	0x0033, 0x0032, 0x0031, 0x0030,
	0x002f, 0x0016, 0x0015, 0x0014,
	0x0013, 0x0012, 0x0011, 0x0010,
	0x000f, 0x000e, 0x000d, 0x000c,
	0x000b, 0x000a, 0x0009, 0x0008,
	0x0007, 0x0006, 0x0005, 0x0004,
	0x0003, 0x0002, 0x0001,
}

type ccsResult int

const (
	ccsOK ccsResult = iota
	ccsVulnerable
	ccsLikelyOK
	ccsFailed
)

// CCSInjection runs the CVE-2014-0224 (CCS injection) check and prints results.
// Detection follows testssl.sh run_ccs_injection: ClientHello, then two early ChangeCipherSpec records.
func CCSInjection(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	fmt.Println("CCS (CVE-2014-0224)")
	result, detail, timedOut := ccsInjectionCheck(host, portForConn)
	switch result {
	case ccsVulnerable:
		fmt.Println("  VULNERABLE - server accepted early ChangeCipherSpec (NOT ok)")
		fmt.Printf("  %s\n", detail)
		fmt.Println("  Server is vulnerable to CCS injection (CVE-2014-0224).")
	case ccsLikelyOK:
		fmt.Println("  OK - likely not vulnerable")
		if detail != "" {
			fmt.Printf("  %s\n", detail)
		}
	case ccsFailed:
		fmt.Println("  WARN - test failed")
		if detail != "" {
			fmt.Printf("  %s\n", detail)
		}
	default:
		if timedOut {
			fmt.Println("  OK - not vulnerable (timed out)")
		} else {
			fmt.Println("  OK - not vulnerable")
		}
	}
}

func pickCCSProbeVersion(host, port string) uint16 {
	order := []uint16{tlsVersion10, tlsVersion11, tlsVersion12, 0x0300}
	for _, ver := range order {
		if ver == 0x0300 {
			if probeSSL3Supported(host, port) {
				return ver
			}
			continue
		}
		if probeProtocolSupported(host, port, ver) {
			return ver
		}
	}
	return tlsVersion12
}

func buildCCSInjectionClientHello(wireVersion uint16) []byte {
	verHi, verLo := byte(wireVersion>>8), byte(wireVersion&0xff)
	recHi, recLo := byte(0x03), byte(0x01)
	if wireVersion == 0x0300 {
		recHi, recLo = 0x03, 0x00
	}

	body := make([]byte, 0, 143)
	body = append(body, verHi, verLo)
	body = append(body, ccsInjectionRandom...)
	body = append(body, 0x00) // empty session ID
	body = append(body, 0x00, 0x68)
	for _, c := range ccsInjectionCiphers {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00) // NULL compression

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, 0x00, 0x00, 0x8f)
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, recHi, recLo, 0x00, 0x93)
	record = append(record, handshake...)
	return record
}

func buildCCSMessage(wireVersion uint16) []byte {
	verHi, verLo := byte(wireVersion>>8), byte(wireVersion&0xff)
	return []byte{0x14, verHi, verLo, 0x00, 0x01, 0x01}
}

func ccsInjectionCheck(host, port string) (result ccsResult, detail string, timedOut bool) {
	wireVersion := pickCCSProbeVersion(host, port)
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return ccsFailed, "couldn't connect", false
	}
	defer conn.Close()

	ch := buildCCSInjectionClientHello(wireVersion)
	if _, err := conn.Write(ch); err != nil {
		return ccsFailed, "failed to send ClientHello", false
	}

	drainCCSServerFlight(conn)

	ccs := buildCCSMessage(wireVersion)
	if _, err := conn.Write(ccs); err != nil {
		return ccsOK, "", false
	}
	conn.SetReadDeadline(time.Now().Add(ccsInjectionReadTimeout))
	_, _ = readFullConn(conn, 4096)

	if _, err := conn.Write(ccs); err != nil {
		return ccsOK, "", false
	}

	conn.SetReadDeadline(time.Now().Add(ccsInjectionReadTimeout))
	resp, readErr := readFullConn(conn, 4096)
	if readErr != nil && len(resp) == 0 {
		return ccsOK, "", true
	}
	if len(resp) == 0 {
		return ccsOK, "", false
	}

	return analyzeCCSInjectionResponse(resp)
}

func drainCCSServerFlight(conn net.Conn) {
	deadline := time.Now().Add(3 * time.Second)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if n > 0 {
			deadline = time.Now().Add(500 * time.Millisecond)
			conn.SetReadDeadline(deadline)
			continue
		}
		if err != nil {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
}

func analyzeCCSInjectionResponse(resp []byte) (ccsResult, string, bool) {
	if len(resp) < 5 {
		return ccsOK, "", false
	}
	if resp[0] != 0x15 {
		return ccsFailed, fmt.Sprintf("unexpected TLS record type 0x%02x", resp[0]), false
	}
	if len(resp) < 2 || resp[1] != 0x03 {
		return ccsFailed, "no proper TLS alert reply", false
	}
	if len(resp) < 7 {
		return ccsFailed, "TLS alert reply too short", false
	}

	alertDesc := resp[6]
	switch alertDesc {
	case 0x15: // decryption_failed
		return ccsVulnerable, "Alert: decryption failed (0x15)", false
	case 0x14: // bad_record_mac
		return ccsVulnerable, "Suspicious alert: bad_record_mac (0x14)", false
	case 0x0a: // unexpected_message
		return ccsLikelyOK, "Alert description type: 0x0a (unexpected message)", false
	case 0x28: // handshake_failure
		return ccsLikelyOK, "Alert description type: 0x28 (handshake failure)", false
	default:
		return ccsVulnerable, fmt.Sprintf("Suspicious alert error code 0x%02x returned", alertDesc), false
	}
}
