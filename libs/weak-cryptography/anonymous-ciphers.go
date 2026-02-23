package weakcryptography

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const anonCipherConnectTimeout = 10 * time.Second
const anonCipherHandshakeTimeout = 5 * time.Second

// anonymousCipherSuite is a cipher suite whose authentication is anonymous (anon).
var anonymousCipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
	{0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},
	{0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"},
	{0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"},
	{0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"},
	{0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"},
	{0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"},
	{0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"},
	{0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"},
	{0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"},
	{0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"},
	{0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"},
	{0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"},
	{0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"},
	{0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"},
	{0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"},
	{0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"},
	{0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"},
	{0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA"},
	{0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
	{0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA"},
	{0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"},
	{0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},
	{0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
	{0xC015, "TLS_ECDH_anon_WITH_NULL_SHA"},
	{0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
}

// TLS version constants (wire format)
const (
	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)

// buildTLSClientHello builds a TLS Client Hello record for the given version (0x0301, 0x0302, 0x0303, 0x0304).
// Offers a single cipher suite. Includes SNI and, for TLS 1.3, supported_versions extension.
func buildTLSClientHello(cipherID uint16, serverName string, version uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	// TLS 1.3 uses legacy version 0x0303 in Client Hello and requires 32-byte session_id
	isTLS13 := (version == tlsVersion13)
	verHi, verLo := byte(version>>8), byte(version&0xff)
	if isTLS13 {
		verHi, verLo = 0x03, 0x03
	}

	body := make([]byte, 0, 128)
	body = append(body, verHi, verLo)
	body = append(body, random...)
	if isTLS13 {
		sessionID := make([]byte, 32)
		if _, err := rand.Read(sessionID); err != nil {
			return nil, err
		}
		body = append(body, 32)
		body = append(body, sessionID...)
	} else {
		body = append(body, 0x00)
	}
	body = append(body, 0x00, 2)
	body = append(body, byte(cipherID>>8), byte(cipherID))
	body = append(body, 0x01, 0x00)

	// Extensions
	var ext []byte
	if serverName != "" && len(serverName) < 256 {
		sniPayload := make([]byte, 0, 5+len(serverName))
		sniPayload = append(sniPayload, 0x00)
		sniPayload = append(sniPayload, byte(len(serverName)>>8), byte(len(serverName)))
		sniPayload = append(sniPayload, serverName...)
		sniListLen := 1 + 2 + len(serverName)
		extValLen := 2 + sniListLen
		ext = append(ext, 0x00, 0x00)
		ext = append(ext, byte(extValLen>>8), byte(extValLen))
		ext = append(ext, byte(sniListLen>>8), byte(sniListLen))
		ext = append(ext, sniPayload...)
	}
	if isTLS13 {
		// supported_versions (0x002b): opaque versions<2..254> = length(1) + 0x0304
		sv := []byte{0x02, 0x03, 0x04}
		ext = append(ext, 0x00, 0x2b)
		ext = append(ext, byte(len(sv)>>8), byte(len(sv)))
		ext = append(ext, sv...)
	}
	if len(ext) > 0 {
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	}

	handshake := make([]byte, 0, 5+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte((len(body)>>8)&0xff), byte(len(body)&0xff))
	handshake = append(handshake, body...)

	// Record: TLS 1.3 uses 0x0303 in record layer for handshake
	recVer := version
	if isTLS13 {
		recVer = 0x0303
	}
	rec := make([]byte, 0, 5+len(handshake))
	rec = append(rec, 0x16, byte(recVer>>8), byte(recVer&0xff))
	rec = append(rec, byte(len(handshake)>>8), byte(len(handshake)))
	rec = append(rec, handshake...)
	return rec, nil
}

// parseTLSServerHello parses the first Server Hello from TLS record(s) in data.
// Returns the chosen cipher suite ID and true if a Server Hello was found and parsed.
func parseTLSServerHello(data []byte) (chosenCipher uint16, ok bool) {
	// TLS record: type(1) version(2) length(2) payload
	if len(data) < 5 {
		return 0, false
	}
	if data[0] != 0x16 {
		return 0, false
	}
	payloadLen := int(data[3])<<8 | int(data[4])
	payload := data[5:]
	if len(payload) < payloadLen {
		return 0, false
	}
	payload = payload[:payloadLen]
	// Handshake: type(1) length(3) body
	if len(payload) < 4 {
		return 0, false
	}
	if payload[0] != 0x02 {
		return 0, false // not Server Hello
	}
	msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	msg := payload[4:]
	if len(msg) > msgLen {
		msg = msg[:msgLen]
	}
	// Server Hello: version(2) random(32) session_id_length(1) [session_id] cipher_suite(2) compression(1) [extensions]
	if len(msg) < 2+32+1+2+1 {
		return 0, false
	}
	sidLen := int(msg[34])
	pos := 35 + sidLen
	if pos+2+1 > len(msg) {
		return 0, false
	}
	chosenCipher = binary.BigEndian.Uint16(msg[pos:])
	return chosenCipher, true
}

// tryAnonymousCipherRaw sends a raw TLS Client Hello for the given version offering one cipher
// and returns true if the server selects it. version is 0x0301, 0x0302, 0x0303, or 0x0304.
func tryAnonymousCipherRaw(host, port string, cipherID uint16, version uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, anonCipherConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(anonCipherHandshakeTimeout))

	clientHello, err := buildTLSClientHello(cipherID, host, version)
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
	chosen, ok := parseTLSServerHello(buf[:n])
	return ok && chosen == cipherID
}

// AnonymousCiphers runs the anonymous/NULL cipher suite check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port normalization is the same as DROWN: no port -> https/443; 80 -> http; other -> http://host:port.
// Tests for cipher suites that contain "anon" or "NULL" in their name (from ssltlstest.go).
func AnonymousCiphers(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	tlsVersions := []uint16{tlsVersion10, tlsVersion11, tlsVersion12, tlsVersion13}
	var supportedCiphers []string
	for _, c := range anonymousCipherSuites {
		for _, ver := range tlsVersions {
			if tryAnonymousCipherRaw(host, portForConn, c.ID, ver) {
				supportedCiphers = append(supportedCiphers, c.Name)
				break
			}
		}
	}

	fmt.Println("Anonymous / NULL cipher suites")
	if len(supportedCiphers) > 0 {
		fmt.Println("  VULNERABLE - server supports anonymous or NULL cipher suites")
		fmt.Println("  Supported anonymous/NULL cipher(s):")
		for _, name := range supportedCiphers {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - No anonymous or NULL cipher suites supported")
		fmt.Println("  Supported anonymous/NULL cipher(s):")
		fmt.Println("    None")
	}
}
