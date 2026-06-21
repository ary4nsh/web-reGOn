package weakcryptography

import (
	"fmt"
)

// FREAK runs the FREAK (CVE-2015-0204) export RSA cipher check and prints results.
// Detection follows testssl.sh run_freak: batch TLS 1.2 export-RSA probe, then SSLv2 export fallback.
func FREAK(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("FREAK (CVE-2015-0204) - Export RSA")
		fmt.Println("  OK - No export RSA cipher suites supported")
		fmt.Println("  Supported RSA export cipher(s):")
		fmt.Println("    None")
		return
	}

	exportList := parseTestSSLHexList(freakExportHex)
	var supportedCiphers []string

	if chosen, ok := probeAnyCipherFromList(host, portForConn, tlsVersion12, exportList, host); ok {
		supportedCiphers = append(supportedCiphers, cipherName(chosen))
	} else if probeSSL2Export(host, portForConn) {
		supportedCiphers = append(supportedCiphers, "SSL2 export RSA cipher")
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
