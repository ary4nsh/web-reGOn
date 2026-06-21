package weakcryptography

import (
	"fmt"
)

// SWEET32 runs the CVE-2016-2183 / CVE-2016-6329 (SWEET32) check and prints results.
// Detection follows testssl.sh run_sweet32: 64-bit block ciphers on SSLv2 and TLS.
func SWEET32(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("SWEET32 (CVE-2016-2183, CVE-2016-6329) - 64-bit block ciphers")
		fmt.Println("  OK - not vulnerable")
		fmt.Println("  TLS 1.3-only server does not offer 64-bit block ciphers.")
		return
	}

	sweetList := parseTestSSLHexList(sweet32Hex)
	tlsSweet := false
	for _, ver := range []uint16{tlsVersion12, tlsVersion11, tlsVersion10} {
		if _, ok := probeAnyCipherFromList(host, portForConn, ver, sweetList, host); ok {
			tlsSweet = true
			break
		}
	}
	ssl3Sweet := false
	if _, ok := probeSSL3Batch(host, portForConn, sweetList); ok {
		ssl3Sweet = true
	}
	ssl2Sweet := probeSSL2CipherHexList(host, portForConn, sweet32SSL2Hex)

	fmt.Println("SWEET32 (CVE-2016-2183, CVE-2016-6329) - 64-bit block ciphers")
	switch {
	case tlsSweet && ssl2Sweet:
		fmt.Println("  VULNERABLE - uses 64-bit block ciphers for SSLv2 and above")
	case tlsSweet || ssl3Sweet:
		fmt.Println("  VULNERABLE - uses 64-bit block ciphers")
	case ssl2Sweet:
		fmt.Println("  VULNERABLE - uses 64-bit block ciphers with SSLv2 only")
	default:
		fmt.Println("  OK - not vulnerable")
		fmt.Println("  No 64-bit block ciphers (3DES, DES, RC2, IDEA) detected.")
	}
}
