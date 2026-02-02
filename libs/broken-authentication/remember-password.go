package brokenauthorization

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	greenSecure  = "\033[32mPassword Reset is secure\033[0m"
	redInsecure = "\033[31mPassword Reset is insecure\033[0m"
)

// buildURL returns the final URL using raw URL and port.
func buildURL(raw, port string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	// Parse so we have host and path; handle raw "example.com" or "example.com/path"
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	host := u.Host
	if host == "" && u.Path != "" {
		// No scheme: "example.com" or "example.com/path" — Path may be host or host+path
		if idx := strings.Index(u.Path, "/"); idx != -1 {
			host = u.Path[:idx]
			u.Path = u.Path[idx:]
		} else {
			host = u.Path
			u.Path = ""
		}
	}
	// Host might be "example.com:444"; we want hostname only for rebuilding
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
		// No port given: treat as 443, add https:// if not present
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

// ResetPassword fetches the page at url (using port to build final URL), finds
// password input tags, prints each tag and whether autocomplete=off or current-password (secure, green)
// or autocomplete=on (insecure, red).
func ResetPassword(url, port string) {
	finalURL := buildURL(url, port)

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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching URL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("HTTP %d for %s\n", resp.StatusCode, finalURL)
		return
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		return
	}
	html := buf.String()

	// Find <input ... > tags (allowing newlines and spaces)
	inputRe := regexp.MustCompile(`(?is)<input\s[^>]*>`)
	typePasswordRe := regexp.MustCompile(`(?i)\btype\s*=\s*["']?\s*password\s*["']?`)
	autocompleteRe := regexp.MustCompile(`(?i)\bautocomplete\s*=\s*["']([^"']*)["']|\bautocomplete\s*=\s*(\S+)`)

	matches := inputRe.FindAllString(html, -1)
	foundAny := false

	for _, tag := range matches {
		// Must contain type="password" (case insensitive)
		if !typePasswordRe.MatchString(tag) {
			continue
		}
		foundAny = true

		// Check autocomplete (case insensitive)
		autocompleteMatch := autocompleteRe.FindStringSubmatch(tag)

		fmt.Printf("Found input tag:\n %s\n", strings.TrimSpace(tag))
		var val string
		if len(autocompleteMatch) >= 2 {
			// Prefer quoted value (group 1), then unquoted (group 2)
			if autocompleteMatch[1] != "" {
				val = strings.ToLower(strings.TrimSpace(autocompleteMatch[1]))
			} else if len(autocompleteMatch) >= 3 && autocompleteMatch[2] != "" {
				val = strings.ToLower(strings.TrimSpace(autocompleteMatch[2]))
			}
		}
		if val != "" {
			if val == "off" || val == "current-password" {
				fmt.Println(greenSecure)
			} else {
				// on, new-password, or any other value → insecure
				fmt.Println(redInsecure)
			}
		}
	}
	if !foundAny {
		fmt.Println("No password reset input tag was found")
	}
}
