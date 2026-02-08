package sessionmanagement

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

const (
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	reset  = "\033[0m"
)

// buildURL returns the final URL: no port → https; 80 → http; other → http://host:port.
func buildURL(raw, port string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := u.Host
	if host == "" && u.Path != "" {
		if idx := strings.Index(u.Path, "/"); idx != -1 {
			host = u.Path[:idx]
			u.Path = u.Path[idx:]
		} else {
			host = u.Path
			u.Path = ""
		}
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	if hostname == "" {
		return raw
	}
	var scheme, hostPort string
	switch port {
	case "443":
		scheme = "https"
		hostPort = hostname
	case "80":
		scheme = "http"
		hostPort = hostname
	case "":
		scheme = "https"
		hostPort = hostname
	default:
		scheme = "http"
		hostPort = hostname + ":" + port
	}
	u.Scheme = scheme
	u.Host = hostPort
	return u.String()
}

// SessionCookie fetches the URL (with optional port), prints status code and
// Set-Cookie headers with secure/expiry analysis and coloring.
func SessionCookie(urlStr, port string) {
	finalURL := buildURL(urlStr, port)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}
	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	// Random user agent
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching URL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("HTTP Status Code:", resp.StatusCode)

	// Print Cookie header if present (e.g. echoed in response)
	for _, v := range resp.Header.Values("Cookie") {
		fmt.Println("Cookie:", v)
		fmt.Println()
	}

	// Get all Set-Cookie headers
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) == 0 && len(resp.Header.Values("Cookie")) == 0 {
		fmt.Println("No Cookie or Set-Cookie headers in response.")
		return
	}

	for _, cookieStr := range setCookies {
		analyzeAndPrintCookie("Set-Cookie", cookieStr)
	}
}

func analyzeAndPrintCookie(headerName, cookieStr string) {
	fmt.Print(headerName, ": ")
	parts := strings.Split(cookieStr, ";")
	var hasSecure, hasHttpOnly, hasSameSite, hasExpires, hasMaxAge bool

	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pl := strings.ToLower(p)
		if pl == "secure" {
			hasSecure = true
			parts[i] = green + p + reset
		} else if pl == "httponly" {
			hasHttpOnly = true
			parts[i] = green + p + reset
		} else if strings.HasPrefix(pl, "samesite=") {
			hasSameSite = true
			parts[i] = green + p + reset
		} else if strings.HasPrefix(pl, "expires=") {
			hasExpires = true
			parts[i] = green + p + reset
		} else if strings.HasPrefix(pl, "max-age=") {
			hasMaxAge = true
			parts[i] = green + p + reset
		}
	}

	// Print cookie line with Secure/HttpOnly/Expires/Max-Age in green
	fmt.Println(strings.Join(parts, "; "))

	// If Expires or Max-Age not found, print yellow message
	if !hasExpires && !hasMaxAge {
		fmt.Println("- " + yellow + "The cookie might be saved in the browser cache (no Expires or Max-Age attribute is set)" + reset)
	}

	// Missing Secure flag
	if !hasSecure {
		fmt.Println("- " + red + "The cookie is not being sent in an encrypted channel (no Secure attribute is set)" + reset)
	}

	// Missing HttpOnly flag (use "code" not "codes"; JavaScript capitalized)
	if !hasHttpOnly {
		fmt.Println("- " + red + "The cookie is accessible via JavaScript code (no HttpOnly attribute is set)" + reset)
	}

	// Missing both HttpOnly and SameSite: XSS can steal the cookie
	if !hasHttpOnly && !hasSameSite {
		fmt.Println("- " + red + "The cookie can be stolen if the site has an XSS vulnerability (no HttpOnly and SameSite attribute is set)" + reset)
	}

	// Insecure: none of Secure, HttpOnly, Expires (we treat Max-Age as expiry)
	if !hasSecure && !hasHttpOnly && !hasExpires && !hasMaxAge {
		fmt.Println("- " + red + "The cookie is insecure (no Secure, HttpOnly, Expires, or Max-Age attribute is set)" + reset)
	}

	fmt.Println()
}
