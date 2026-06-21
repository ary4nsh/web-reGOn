package weakcryptography

import (
	"fmt"
)

// Lucky13 runs the CVE-2013-0169 (Lucky 13) vulnerability check and prints results.
// Detection follows testssl.sh run_lucky13: batch CBC cipher probes on TLS 1.2 (two batches).
func Lucky13(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("Vulnerability CVE-2013-0169 (Lucky 13)")
		fmt.Println("  OK - Not vulnerable to Lucky13 attack")
		return
	}

	batch1 := parseTestSSLHexList(lucky13CBCHex1)
	batch2 := parseTestSSLHexList(lucky13CBCHex2)
	cbcSet := cipherSet(append(append([]uint16{}, batch1...), batch2...))

	var vulnerableCiphers []string
	seen := make(map[string]bool)

	tryBatch := func(list []uint16) {
		if chosen, ok := probeAnyCipherFromList(host, portForConn, tlsVersion12, list, host); ok && cbcSet[chosen] {
			name := cipherName(chosen)
			if !seen[name] {
				seen[name] = true
				vulnerableCiphers = append(vulnerableCiphers, name)
			}
		}
	}
	tryBatch(batch1)
	if len(vulnerableCiphers) == 0 {
		tryBatch(batch2)
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
