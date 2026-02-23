package weakcryptography

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const beastConnectTimeout = 10 * time.Second
const beastHandshakeTimeout = 5 * time.Second

// SSLv3 version and message types (same as TLS for handshake)
const ssl3Version = 0x0300
const ssl3HandshakeTypeServerHello = 0x02

// ssl3BuildClientHello builds an SSLv3 Client Hello record offering a single cipher suite.
func ssl3BuildClientHello(cipherID uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	// Client Hello: type(1) + length(3) + version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) + cipher_suites(2) + compression_len(1) + compression(1)
	// Handshake length = 2+32+1+2+2+1+1 = 41
	body := make([]byte, 0, 41)
	body = append(body, 0x01) // Client Hello
	body = append(body, 0x00, 0x00, 41) // length 41
	body = append(body, 0x03, 0x00) // SSLv3
	body = append(body, random...)
	body = append(body, 0x00)   // session_id_length = 0
	body = append(body, 0x00, 2) // cipher_suites_length = 2
	body = append(body, byte(cipherID>>8), byte(cipherID))
	body = append(body, 0x01) // compression_methods_length = 1
	body = append(body, 0x00) // null compression

	// Record: type(1) version(2) length(2) payload
	rec := make([]byte, 0, 5+len(body))
	rec = append(rec, 0x16, 0x03, 0x00) // handshake, SSLv3
	rec = append(rec, byte(len(body)>>8), byte(len(body)))
	rec = append(rec, body...)
	return rec, nil
}

// ssl3ParseServerHello parses the first Server Hello from data (SSLv3 record).
// Returns chosen cipher suite ID and true if parsing succeeded.
func ssl3ParseServerHello(data []byte) (cipherSuite uint16, ok bool) {
	if len(data) < 5 {
		return 0, false
	}
	if data[0] != 0x16 || data[1] != 0x03 || data[2] != 0x00 {
		return 0, false
	}
	payloadLen := int(data[3])<<8 | int(data[4])
	payload := data[5:]
	if len(payload) < payloadLen || payloadLen < 38 {
		return 0, false
	}
	payload = payload[:payloadLen]
	if payload[0] != ssl3HandshakeTypeServerHello {
		return 0, false
	}
	// Server Hello: type(1) length(3) version(2) random(32) session_id_length(1) [session_id] cipher_suite(2) compression(1)
	sidLen := int(payload[38])
	if 39+sidLen+2+1 > len(payload) {
		return 0, false
	}
	cipherSuite = binary.BigEndian.Uint16(payload[39+sidLen:])
	return cipherSuite, true
}

// trySSL3CipherSuite sends an SSLv3 Client Hello with the given cipher and returns true if server responds with Server Hello choosing that cipher.
func trySSL3CipherSuite(host, port string, cipherID uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, beastConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(beastHandshakeTimeout))

	clientHello, err := ssl3BuildClientHello(cipherID)
	if err != nil {
		return false
	}
	if _, err := conn.Write(clientHello); err != nil {
		return false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false
	}
	chosen, ok := ssl3ParseServerHello(buf[:n])
	return ok && chosen == cipherID
}

// cbcCipherSuitesForBEAST returns CBC-mode cipher suites that support TLS 1.0 (and same IDs used for SSLv3).
// BEAST (CVE-2011-3389) affects SSLv3 and TLS 1.0 with CBC ciphers.
func cbcCipherSuitesForBEAST() []*tls.CipherSuite {
	var out []*tls.CipherSuite
	add := func(cs *tls.CipherSuite) {
		if cs == nil || !strings.Contains(strings.ToUpper(cs.Name), "CBC") {
			return
		}
		for _, v := range cs.SupportedVersions {
			if v == tls.VersionTLS10 {
				out = append(out, cs)
				return
			}
		}
	}
	for _, cs := range tls.CipherSuites() {
		add(cs)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		add(cs)
	}
	return out
}

// tryCipherSuiteBeast tries to complete a TLS handshake with the given version and single cipher suite.
func tryCipherSuiteBeast(host, port string, version uint16, cipherID uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, beastConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       []uint16{cipherID},
	}
	tlsConn := tls.Client(conn, config)
	tlsConn.SetDeadline(time.Now().Add(beastHandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	state := tlsConn.ConnectionState()
	return state.CipherSuite == cipherID
}

// BEAST runs the CVE-2011-3389 (BEAST) vulnerability check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port normalization is the same as DROWN: no port -> https/443; 80 -> http; other -> http://host:port.
// BEAST affects SSLv3 and TLS 1.0 with CBC ciphers. Both SSLv3 (wire-level) and TLS 1.0 are tested.
func BEAST(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	cbcSuites := cbcCipherSuitesForBEAST()
	if len(cbcSuites) == 0 {
		fmt.Println("Vulnerability CVE-2011-3389 (BEAST)")
		fmt.Println("  OK - Not vulnerable to BEAST attack (no CBC ciphers to test)")
		fmt.Println("  Support protocols: Both SSL 3.0 and TLS 1.0 are not supported")
		fmt.Println("  Vulnerable cipher(s):")
		fmt.Println("    No vulnerable ciphers are supported")
		return
	}

	var vulnerableCiphers []string
	var supportProtocols []string
	seen := make(map[string]bool)
	ssl3Supported := false
	tls1Supported := false

	for _, cs := range cbcSuites {
		if trySSL3CipherSuite(host, portForConn, cs.ID) {
			ssl3Supported = true
			if !seen[cs.Name] {
				seen[cs.Name] = true
				vulnerableCiphers = append(vulnerableCiphers, cs.Name)
			}
		}
		if tryCipherSuiteBeast(host, portForConn, tls.VersionTLS10, cs.ID) {
			tls1Supported = true
			if !seen[cs.Name] {
				seen[cs.Name] = true
				vulnerableCiphers = append(vulnerableCiphers, cs.Name)
			}
		}
	}

	if ssl3Supported {
		supportProtocols = append(supportProtocols, "SSLv3")
	}
	if tls1Supported {
		supportProtocols = append(supportProtocols, "TLSv1")
	}

	protocolLine := strings.Join(supportProtocols, ", ")
	if len(supportProtocols) == 0 {
		protocolLine = "Both SSL 3.0 and TLS 1.0 are not supported"
	}

	fmt.Println("Vulnerability CVE-2011-3389 (BEAST)")
	if len(vulnerableCiphers) > 0 {
		fmt.Println("  The server might be vulnerable vulnerable to BEAST attack, needs timing attack checks to confirm")
		fmt.Printf("  Support protocols: %s\n", protocolLine)
		fmt.Println("  Vulnerable cipher(s):")
		for _, name := range vulnerableCiphers {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - Not vulnerable to BEAST attack")
		fmt.Printf("  Support protocols: %s\n", protocolLine)
		fmt.Println("  Vulnerable cipher(s):")
		fmt.Println("    No vulnerable ciphers are supported")
	}
}
