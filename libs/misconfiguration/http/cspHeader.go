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
	"'unsafe-eval'": true,
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
	io.Copy(io.Discard, resp.Body) // keep connection alive

	// locate first CSP header (case-insensitive)
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

	// parse directives
	type dir struct {
		name   string
		values []string
	}
	var dirs []dir

	for _, raw := range strings.Split(csp, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, " ", 2)
		d := dir{name: parts[0]}
		if len(parts) == 2 {
			d.values = strings.Fields(parts[1])
		}
		dirs = append(dirs, d)
	}

	// print directives + flag insecure tokens
	for _, d := range dirs {
		fmt.Printf("- %s", d.name)
		if len(d.values) > 0 {
			fmt.Printf(" %s", strings.Join(d.values, " "))
		}
		fmt.Println()

		for _, v := range d.values {
			if insecureTokens[v] {
				fmt.Printf("%s[INSECURE]%s %s\n", red, reset, v)
			}
		}
	}

	// MISSING headers logic
	hasDefault := false
	hasObject  := false
	objectIsNone := false

	for _, d := range dirs {
		switch strings.ToLower(d.name) {
		case "default-src":
			hasDefault = true
		case "object-src":
			hasObject = true
			for _, v := range d.values {
				if v == "'none'" {
					objectIsNone = true
					break
				}
			}
		}
	}

	if !hasDefault {
		if !hasObject {
			fmt.Printf("%s[MISSING]%s default-src/object-src (vulnerable)\n", red, reset)
		} else if !objectIsNone {
			fmt.Printf("%s[MISSING]%s default-src (can lead to malicious object-src usage)\n", red, reset)
		}
	}
	
	// script-src 'self' + object-src 'none'
	scriptSelfOnly := false
	objectNone := false

	for _, d := range dirs {
		switch strings.ToLower(d.name) {
		case "script-src":
			// must be exactly one token: 'self'
			if len(d.values) == 1 && d.values[0] == "'self'" {
				scriptSelfOnly = true
			}
		case "object-src":
			if len(d.values) == 1 && d.values[0] == "'none'" {
				objectNone = true
			}
		}
	}
	if scriptSelfOnly && objectNone {
		fmt.Printf("%s[INSECURE]%s vulnerable to arbitrary file upload\n", red, reset)
	}
}
