package weakcryptography

import (
	"fmt"
)

// LOGJAM runs the CVE-2015-4000 (LOGJAM) check and prints results.
// Detection follows testssl.sh run_logjam: batch probe for DH EXPORT ciphers on TLS 1.2.
func LOGJAM(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("LOGJAM (CVE-2015-4000) - DH EXPORT")
		fmt.Println("  OK - not vulnerable, no DH EXPORT ciphers")
		fmt.Println("  Server does not offer export DH cipher suites.")
		return
	}

	exportList := parseTestSSLHexList(logjamExportDHHex)
	vulnExport := false
	if _, ok := probeAnyCipherFromList(host, portForConn, tlsVersion12, exportList, host); ok {
		vulnExport = true
	}

	fmt.Println("LOGJAM (CVE-2015-4000) - DH EXPORT")
	if vulnExport {
		fmt.Println("  VULNERABLE - server supports DH EXPORT cipher suites")
		fmt.Println("  Server is vulnerable to LOGJAM (CVE-2015-4000).")
	} else {
		fmt.Println("  OK - not vulnerable, no DH EXPORT ciphers")
		fmt.Println("  Server does not offer export DH cipher suites.")
	}
}
