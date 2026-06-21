package weakcryptography

import (
	"fmt"
)

// POODLE runs POODLE SSL (CVE-2014-3566) and POODLE TLS (CVE-2014-8730) checks.
// SSL detection follows testssl.sh run_ssl_poodle; TLS POODLE is experimental in testssl.sh.
func POODLE(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	// POODLE SSL (CVE-2014-3566)
	fmt.Println("POODLE, SSL (CVE-2014-3566)")
	if isTLS13OnlyServer(host, portForConn) || !probeSSL3Supported(host, portForConn) {
		fmt.Println("  OK - not vulnerable, no SSLv3 support")
	} else {
		cbcList := parseTestSSLHexList(poodleSSL3CBCHex)
		if _, ok := probeSSL3Batch(host, portForConn, cbcList); ok {
			fmt.Println("  VULNERABLE - uses SSLv3+CBC (check TLS_FALLBACK_SCSV mitigation)")
			fmt.Println("  Server supports SSLv3 with CBC ciphers (CVE-2014-3566).")
		} else {
			fmt.Println("  OK - not vulnerable")
		}
	}

	// POODLE TLS (CVE-2014-8730) - testssl.sh marks this experimental / not fully implemented
	fmt.Println("POODLE, TLS (CVE-2014-8730), experimental")
	fmt.Println("  WARN - not fully implemented (experimental check)")
	fmt.Println("  TLS POODLE requires padding-oracle timing analysis; use testssl.sh for full coverage.")
}
