package sessionmanagement

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
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

	// Optional: decode a cookie value from user
	line, _ := readLineWithEditing("Enter cookie value to decode (or press Enter to skip): ")
	cookieValue := strings.TrimSpace(line)
	if cookieValue != "" {
		tryDecodeCookieValue(cookieValue)
	}
}

// tryDecodeCookieValue tries to decode the cookie value: base64 (size multiple of 4),
// MD5 (16 bytes raw or 32 hex chars), ASCII (only 0-9 and a-f, even size; hex-decode then interpret as ASCII).
func tryDecodeCookieValue(s string) {
	fmt.Println()

	// Base64: only when size is multiple of 4
	if len(s)%4 != 0 {
		fmt.Println("- Base64 decode: not available (size is not a multiple of 4)")
	} else {
		decodedBytes, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			fmt.Println("- Base64 decode: not available (invalid base64 data)")
		} else {
			fmt.Println("- Base64 decoded:", formatDecodedBytes(decodedBytes))
		}
	}

	// MD5 decode: only when string is 16 or 32 hex chars (0-9, a-f)
	if (len(s) != 16 && len(s) != 32) || !isHexString(s) {
		fmt.Println("- MD5 decode: not available (size is not 16 or 32 hex characters)")
	} else {
		hashBytes, err := hex.DecodeString(s)
		if err != nil {
			fmt.Println("- MD5 decode: not available (invalid hex data)")
		} else {
			// Only offer cracking for 32-char (16-byte) MD5 hashes
			if len(hashBytes) == 16 {
				tryCrackMD5WithWordlist(hashBytes)
			}
		}
	}

	// ASCII: only 0-9 and a-f (case insensitive), even size; hex-decode then must be printable text (UTF-8)
	if len(s)%2 != 0 || !isHexString(s) {
		fmt.Println("- ASCII decode: not available (the string is not ASCII encoded)")
	} else {
		decodedBytes, err := hex.DecodeString(s)
		if err != nil {
			fmt.Println("- ASCII decode: not available (the string is not ASCII encoded)")
		} else if !isPrintableUTF8(decodedBytes) {
			fmt.Println("- ASCII decode: not available (the string is not ASCII encoded)")
		} else {
			fmt.Println("- ASCII decoded:", string(decodedBytes))
		}
	}
}

// tryCrackMD5WithWordlist prompts for a wordlist path and tries to crack the given 16-byte MD5 hash.
func tryCrackMD5WithWordlist(hashBytes []byte) {
	pathLine, _ := readLineWithEditing("This hash is 16 bytes long, so it might be a MD5 hash. Enter wordlist path to crack MD5 (or press Enter to skip): ")
	path := strings.TrimSpace(pathLine)
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("- Could not open wordlist:", err)
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		sum := md5.Sum([]byte(line))
		if bytes.Equal(sum[:], hashBytes) {
			fmt.Println("- MD5 decode:", line)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("- Error reading wordlist:", err)
		return
	}
	fmt.Println("- MD5 not found in wordlist.")
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isPrintableASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// isPrintableUTF8 reports whether b is valid UTF-8 and all runes are printable (e.g. hex-decoded "Hello World!").
func isPrintableUTF8(b []byte) bool {
	s := string(b)
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func formatDecodedBytes(b []byte) string {
	if isPrintableASCII(string(b)) {
		return string(b)
	}
	return hex.EncodeToString(b)
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
