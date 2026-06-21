package weakcryptography

import (
	"fmt"
)

// Heartbleed runs the CVE-2014-0160 (Heartbleed) check and prints results.
// Detection follows testssl.sh run_heartbleed: heartbeat extension + oversized heartbeat request.
func Heartbleed(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	fmt.Println("Heartbleed (CVE-2014-0160)")
	vulnerable, detail := heartbleedCheck(host, portForConn)
	if detail == "no heartbeat extension" {
		fmt.Println("  OK - not vulnerable, no heartbeat extension")
		return
	}
	if vulnerable {
		fmt.Println("  VULNERABLE - server responded to malformed heartbeat (NOT ok)")
		fmt.Println("  Server is vulnerable to Heartbleed (CVE-2014-0160).")
		return
	}
	if detail == "timed out" {
		fmt.Println("  OK - not vulnerable (timed out)")
		return
	}
	fmt.Println("  OK - not vulnerable")
}
