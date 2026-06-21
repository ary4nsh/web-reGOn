package weakcryptography

import (
	"fmt"
	"net/url"
	"strings"
)

// BREACH runs the CVE-2013-3587 (BREACH) check and prints results.
// Detection follows testssl.sh run_breach: HTTP Content-Encoding over TLS.
func BREACH(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	path := "/"
	if strings.Contains(urlStr, "://") {
		if u, parseErr := url.Parse(urlStr); parseErr == nil && u.Path != "" {
			path = u.Path
		}
	}
	disclaimer := fmt.Sprintf(" - only supplied %q tested", path)

	fmt.Println("BREACH (CVE-2013-3587)")
	if portForConn != "443" && !strings.HasPrefix(displayURL, "https://") {
		fmt.Println("  OK - not applicable (BREACH requires HTTPS)")
		fmt.Println("  Use an https:// URL or port 443.")
		return
	}

	compressions := []string{"gzip", "deflate", "compress", "br"}
	first, stalled := breachDetectCompression(host, portForConn, path, strings.Join(compressions, ", "), "")
	if stalled {
		fmt.Println("  WARN - first HTTP request failed (stalled or connection error)")
		return
	}
	if first == "no_compression" {
		fmt.Println("  OK - no gzip/deflate/compress/br HTTP compression")
		fmt.Println(disclaimer)
		return
	}

	supported := map[string]bool{first: true}
	for _, c := range compressions {
		if c == first {
			continue
		}
		enc, stall := breachDetectCompression(host, portForConn, path, c, "")
		if stall {
			continue
		}
		if enc != "no_compression" && enc != "" {
			supported[enc] = true
		}
	}

	var detected []string
	for enc := range supported {
		detected = append(detected, enc)
	}
	fmt.Printf("  POTENTIALLY VULNERABLE - %q HTTP compression detected\n", strings.Join(detected, " "))
	fmt.Println(disclaimer)
	fmt.Println("  Can be ignored for static pages or if no secrets in the page.")
}
