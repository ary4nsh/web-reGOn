package weakcryptography

import (
	"fmt"
	"strings"
)

// BEAST runs the CVE-2011-3389 (BEAST) vulnerability check and prints results.
// Detection follows testssl.sh run_beast: batch CBC cipher probes on SSLv3 and TLS 1.0.
func BEAST(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("Vulnerability CVE-2011-3389 (BEAST)")
		fmt.Println("  OK - Not vulnerable to BEAST attack")
		fmt.Println("  Support protocols: Both SSL 3.0 and TLS 1.0 are not supported")
		fmt.Println("  Vulnerable cipher(s):")
		fmt.Println("    No vulnerable ciphers are supported")
		return
	}

	cbcList := parseTestSSLHexList(beastCBCHex)
	cbcSet := cipherSet(cbcList)

	var vulnerableCiphers []string
	var supportProtocols []string
	seen := make(map[string]bool)

	if chosen, ok := probeSSL3Batch(host, portForConn, cbcList); ok && cbcSet[chosen] {
		supportProtocols = append(supportProtocols, "SSLv3")
		name := cipherName(chosen)
		if !seen[name] {
			seen[name] = true
			vulnerableCiphers = append(vulnerableCiphers, name)
		}
	}
	if chosen, ok := probeAnyCipherFromList(host, portForConn, tlsVersion10, cbcList, host); ok && cbcSet[chosen] {
		supportProtocols = append(supportProtocols, "TLSv1")
		name := cipherName(chosen)
		if !seen[name] {
			seen[name] = true
			vulnerableCiphers = append(vulnerableCiphers, name)
		}
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
