package weakcryptography

import (
	"fmt"
	"net"
	"time"
)

const freakConnectTimeout = 10 * time.Second
const freakHandshakeTimeout = 5 * time.Second

// RSA export cipher suites (FREAK - CVE-2015-0204). Names contain RSA_EXPORT.
// From ssltlstest.go.
var freakCipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
}

// tryFreakCipher sends a raw TLS Client Hello for the given version offering one cipher suite
// and returns true if the server selects it. Used to detect export RSA (FREAK) support.
func tryFreakCipher(host, port string, cipherID uint16, version uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, freakConnectTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(freakHandshakeTimeout))

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

// FREAK runs the FREAK (CVE-2015-0204) export RSA cipher check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port normalization is the same as DROWN: no port -> https/443; 80 -> http; other -> http://host:port.
// Tests for cipher suites containing RSA_EXPORT in their name (from ssltlstest.go).
// Probes TLS 1.0, 1.1, 1.2, and 1.3 using tryFreakCipher.
func FREAK(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	tlsVersions := []uint16{tlsVersion10, tlsVersion11, tlsVersion12, tlsVersion13}
	var supportedCiphers []string
	for _, c := range freakCipherSuites {
		for _, ver := range tlsVersions {
			if tryFreakCipher(host, portForConn, c.ID, ver) {
				supportedCiphers = append(supportedCiphers, c.Name)
				break
			}
		}
	}

	fmt.Println("FREAK (CVE-2015-0204) - Export RSA")
	if len(supportedCiphers) > 0 {
		fmt.Println("  VULNERABLE - server supports export RSA cipher suites")
		fmt.Println("  Supported RSA export cipher(s):")
		for _, name := range supportedCiphers {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - No export RSA cipher suites supported")
		fmt.Println("  Supported RSA export cipher(s):")
		fmt.Println("    None")
	}
}
