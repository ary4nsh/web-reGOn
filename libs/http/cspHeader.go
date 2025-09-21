package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ANSI colour helpers (Unix terminals)
const (
	red   = "\033[31m"
	reset = "\033[0m"
)

// insecureTokens are the exact CSP tokens we flag.
var insecureTokens = map[string]bool{
	"'unsafe-inline'": true,
	"*":               true,
	"allow-scripts":   true,
	"allow-forms":     true,
}

// CspHeader gets the CSP header from url, prints every directive and flags insecure tokens in red.
func CspHeader(url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[-] CSP check failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Drain body so connection can be re-used
	io.Copy(io.Discard, resp.Body)

	// Locate first CSP header (case-insensitive)
	var csp string
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Content-Security-Policy") ||
			strings.EqualFold(k, "Content-Security-Policy-Report-Only") {
			if len(vv) > 0 {
				csp = vv[0]
				break
			}
		}
	}

	if csp == "" {
		fmt.Println("No CSP header found.")
		return
	}

	// Parse & print
	for _, raw := range strings.Split(csp, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, " ", 2)
		dir := parts[0]

		var values []string
		if len(parts) == 2 {
			values = strings.Fields(parts[1])
		}

		// Directive line
		fmt.Printf("- %s", dir)
		if len(values) > 0 {
			fmt.Printf(" %s", strings.Join(values, " "))
		}
		fmt.Println()

		// Flag insecure tokens
		for _, v := range values {
			if insecureTokens[v] {
				fmt.Printf("%s[INSECURE]%s %s\n", red, reset, v)
			}
		}
	}
}
