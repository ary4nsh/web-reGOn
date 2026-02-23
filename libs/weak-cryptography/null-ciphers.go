package weakcryptography

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"
)

const nullCiphersConnectTimeout = 10 * time.Second
const nullCiphersHandshakeTimeout = 5 * time.Second

// NULL cipher suites (TLS)
var nullTLSCipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x002D, "TLS_DHE_PSK_WITH_NULL_SHA"},
	{0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256"},
	{0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384"},
	{0xC015, "TLS_ECDH_anon_WITH_NULL_SHA"},
	{0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"},
	{0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
	{0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA"},
	{0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256"},
	{0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384"},
	{0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"},
	{0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA"},
	{0x0000, "TLS_NULL_WITH_NULL_NULL"},
	{0x002C, "TLS_PSK_WITH_NULL_SHA"},
	{0x00B0, "TLS_PSK_WITH_NULL_SHA256"},
	{0x00B1, "TLS_PSK_WITH_NULL_SHA384"},
	{0x002E, "TLS_RSA_PSK_WITH_NULL_SHA"},
	{0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256"},
	{0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384"},
	{0x0001, "TLS_RSA_WITH_NULL_MD5"},
	{0x0002, "TLS_RSA_WITH_NULL_SHA"},
	{0x003B, "TLS_RSA_WITH_NULL_SHA256"},
}

// NULL cipher suites (SSLv3)
var nullSSLv3CipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0083, "GOST2001-NULL-GOST94"},
	{0xFF87, "GOST2012256-NULL-STREEBOG256"},
}

func tryNullCipher(host, port string, cipherID uint16, version uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, nullCiphersConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(nullCiphersHandshakeTimeout))

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

// NullCiphers runs the NULL cipher check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port: no port -> https/443; port 80 -> http; other port -> http://host:port.
// Tests SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3 for cipher suites containing NULL
func NullCiphers(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	var supportedNULL []string
	seen := make(map[string]bool)
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			supportedNULL = append(supportedNULL, s)
		}
	}

	// SSLv2: doSetup returns server-offered ciphers; collect those containing NULL.
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		challenge = [16]byte{}
	}
	_, _, ssl2Ciphers, ssl2Ok := doSetup(host, portForConn, challenge)
	if ssl2Ok {
		for _, name := range ssl2Ciphers {
			if strings.Contains(name, "NULL") {
				add("[SSLv2] " + name)
			}
		}
	}

	// SSLv3: probe each NULL cipher.
	for _, c := range nullSSLv3CipherSuites {
		if trySSL3CipherSuite(host, portForConn, c.ID) {
			add("[SSLv3] " + c.Name)
		}
	}

	// TLS 1.0, 1.1, 1.2, 1.3: probe each NULL cipher per version.
	tlsVersions := []uint16{tlsVersion10, tlsVersion11, tlsVersion12, tlsVersion13}
	for _, c := range nullTLSCipherSuites {
		for _, ver := range tlsVersions {
			if tryNullCipher(host, portForConn, c.ID, ver) {
				add("[TLS] " + c.Name)
				break
			}
		}
	}

	fmt.Println("NULL cipher suites - Ciphers containing NULL encryption")
	if len(supportedNULL) > 0 {
		fmt.Println("  VULNERABLE - server supports NULL cipher suites")
		fmt.Println("  Supported NULL cipher(s):")
		for _, name := range supportedNULL {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - No NULL cipher suites supported")
		fmt.Println("  Supported NULL cipher(s):")
		fmt.Println("    None")
	}
}

