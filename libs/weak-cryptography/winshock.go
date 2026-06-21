package weakcryptography

import (
	"fmt"
	"strings"
)

// Winshock runs the CVE-2014-6321 (Winshock / MS14-066) heuristic check.
// Detection follows testssl.sh run_winshock (cipher + banner heuristics).
func Winshock(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	fmt.Println("Winshock (CVE-2014-6321), experimental")

	if probeTLS13Supported(host, portForConn) {
		fmt.Println("  OK - not vulnerable (TLS 1.3 found)")
		return
	}

	ariaList := parseTestSSLHexList(winshockARIAChachaHex)
	if _, ok := probeAnyCipherFromList(host, portForConn, tlsVersion12, ariaList, host); ok {
		fmt.Println("  OK - not vulnerable (ARIA, CHACHA or CCM ciphers found)")
		return
	}

	camList := parseTestSSLHexList(winshockCamelliaHex)
	if _, ok := probeAnyCipherFromList(host, portForConn, tlsVersion12, camList, host); ok {
		fmt.Println("  OK - not vulnerable (CAMELLIA or ECDHE_RSA GCM ciphers found)")
		return
	}

	fixedList := parseTestSSLHexList(winshockFixedHex)
	if _, ok := probeAnyCipherFromList(host, portForConn, tlsVersion12, fixedList, host); ok {
		fmt.Println("  OK - not vulnerable (GCM rollup ciphers found)")
		return
	}

	exts := probeServerExtensions(host, portForConn, tlsVersion12)
	if exts[tlsExtEncryptThenMAC] {
		fmt.Println("  OK - not vulnerable (encrypt-then-mac extension detected)")
		return
	}
	if exts[tlsExtMaxFragment] {
		fmt.Println("  OK - not vulnerable (max fragment length extension detected)")
		return
	}

	if portForConn != "443" && portForConn != "3389" {
		fmt.Println("  OK - not vulnerable (no HTTP or RDP on standard port)")
		return
	}

	if portForConn == "3389" {
		fmt.Println("  PROBABLY VULNERABLE - RDP on port 3389 (check patches locally to confirm)")
		return
	}

	banner, err := fetchHTTPServerBanner(host, portForConn, "/")
	if err != nil || banner == "" {
		fmt.Println("  WARN - check failed (could not fetch HTTP Server banner)")
		return
	}
	bannerLower := strings.ToLower(banner)
	switch {
	case strings.Contains(bannerLower, "microsoft-iis/8.5"):
		fmt.Println("  PROBABLY VULNERABLE - Microsoft-IIS/8.5 (check patches locally to confirm)")
	case strings.Contains(bannerLower, "microsoft-iis/8.0"):
		fmt.Println("  LIKELY VULNERABLE - Microsoft-IIS/8.0 (check patches locally to confirm)")
	case strings.Contains(bannerLower, "microsoft-httpapi/2.0"):
		fmt.Println("  PROBABLY VULNERABLE - Microsoft-HTTPAPI/2.0 (check patches locally to confirm)")
	default:
		fmt.Println("  OK - not vulnerable (doesn't seem to be IIS 8.x)")
	}
}
