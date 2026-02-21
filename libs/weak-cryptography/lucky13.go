package weakcryptography

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

const lucky13ConnectTimeout = 10 * time.Second
const lucky13HandshakeTimeout = 5 * time.Second

// cbcCipherSuitesForLucky13 returns CBC-mode cipher suites that support TLS 1.1 or 1.2
// (Lucky 13 / CVE-2013-0169 affects TLS 1.1 and 1.2 with CBC ciphers).
func cbcCipherSuitesForLucky13() []*tls.CipherSuite {
	var out []*tls.CipherSuite
	add := func(cs *tls.CipherSuite) {
		if cs == nil || !strings.Contains(strings.ToUpper(cs.Name), "CBC") {
			return
		}
		for _, v := range cs.SupportedVersions {
			if v == tls.VersionTLS11 || v == tls.VersionTLS12 {
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

// tryCipherSuite tries to complete a TLS handshake with the given version and single cipher suite.
func tryCipherSuite(host, port string, version uint16, cipherID uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, lucky13ConnectTimeout)
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
	tlsConn.SetDeadline(time.Now().Add(lucky13HandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	state := tlsConn.ConnectionState()
	return state.CipherSuite == cipherID
}

// Lucky13 runs the CVE-2013-0169 (Lucky 13) vulnerability check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port normalization is the same as DROWN: no port -> https/443; 80 -> http; other -> http://host:port.
// Output format matches drown.go: Target line, then vulnerability status and list of vulnerable CBC ciphers if any.
func Lucky13(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	cbcSuites := cbcCipherSuitesForLucky13()
	if len(cbcSuites) == 0 {
		fmt.Println("Vulnerability CVE-2013-0169 (Lucky 13)")
		fmt.Println("  OK - Not vulnerable to Lucky13 attack (no CBC ciphers to test)")
		return
	}

	var vulnerableCiphers []string
	seen := make(map[string]bool)

	for _, cs := range cbcSuites {
		// Test with TLS 1.1 and TLS 1.2
		for _, version := range []uint16{tls.VersionTLS11, tls.VersionTLS12} {
			if tryCipherSuite(host, portForConn, version, cs.ID) {
				if !seen[cs.Name] {
					seen[cs.Name] = true
					vulnerableCiphers = append(vulnerableCiphers, cs.Name)
				}
				break
			}
		}
	}

	fmt.Println("Vulnerability CVE-2013-0169 (Lucky 13)")
	if len(vulnerableCiphers) > 0 {
		fmt.Println("  The server might be vulnerable to Lucky13 attack, needs timing attack checks to confirm")
		fmt.Println("  Vulnerable cipher(s):")
		for _, name := range vulnerableCiphers {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - Not vulnerable to Lucky13 attack")
	}
}
