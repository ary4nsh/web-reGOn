package weakcryptography

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"
)

const nomoreConnectTimeout = 10 * time.Second
const nomoreHandshakeTimeout = 5 * time.Second

// RC4 cipher suites (TLS)
var rc4TLSCipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
	{0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
	{0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA"},
	{0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
	{0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"},
	{0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
	{0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"},
	{0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
	{0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA"},
	{0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"},
	{0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"},
	{0x0024, "TLS_KRB5_WITH_RC4_128_MD5"},
	{0x0020, "TLS_KRB5_WITH_RC4_128_SHA"},
	{0x008A, "TLS_PSK_WITH_RC4_128_SHA"},
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
	{0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"},
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
}

// RC4 cipher suites (SSLv3)
var rc4SSLv3CipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0066, "DHE-DSS-RC4-SHA"},
	{0x0065, "EXP1024-DHE-DSS-RC4-SHA"},
	{0x0064, "EXP1024-RC4-SHA"},
	{0x0060, "EXP1024-RC4-MD5"},
}

// tryRC4Cipher sends a raw TLS Client Hello for the given version offering one cipher suite
// and returns true if the server selects it. Used to detect RC4 support over TLS.
func tryRC4Cipher(host, port string, cipherID uint16, version uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, nomoreConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(nomoreHandshakeTimeout))

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

// NoMore runs the RC4 cipher check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port: no port -> https/443; port 80 -> http; other port -> http://host:port.
// Tests SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3 for cipher suites containing RC4
func NoMore(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	var supportedRC4 []string

	// SSLv2: doSetup returns server-offered ciphers; check if any is RC4.
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		challenge = [16]byte{}
	}
	_, _, ssl2Ciphers, ssl2Ok := doSetup(host, portForConn, challenge)
	if ssl2Ok {
		for _, name := range ssl2Ciphers {
			if strings.Contains(name, "RC4") {
				supportedRC4 = append(supportedRC4, "[SSLv2] "+name)
				break
			}
		}
	}

	// SSLv3: probe each RC4 cipher.
	for _, c := range rc4SSLv3CipherSuites {
		if trySSL3CipherSuite(host, portForConn, c.ID) {
			supportedRC4 = append(supportedRC4, "[SSLv3] "+c.Name)
			break
		}
	}

	// TLS 1.0, 1.1, 1.2, 1.3: probe each RC4 cipher per version.
	tlsVersions := []uint16{tlsVersion10, tlsVersion11, tlsVersion12, tlsVersion13}
	for _, c := range rc4TLSCipherSuites {
		for _, ver := range tlsVersions {
			if tryRC4Cipher(host, portForConn, c.ID, ver) {
				supportedRC4 = append(supportedRC4, "[TLS] "+c.Name)
				break
			}
		}
	}

	fmt.Println("RC4 (No More) - Cipher suites containing RC4 encryption")
	if len(supportedRC4) > 0 {
		fmt.Println("  VULNERABLE - server supports RC4 cipher suites")
		fmt.Println("  Supported RC4 cipher(s):")
		for _, name := range supportedRC4 {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - No RC4 cipher suites supported")
		fmt.Println("  Supported RC4 cipher(s):")
		fmt.Println("    None")
	}
}
