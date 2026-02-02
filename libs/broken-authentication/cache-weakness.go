package brokenauthorization

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	cacheSecure   = "\033[32m[secure]\033[0m"
	cacheInsecure = "\033[31m[insecure]\033[0m"
)

// CacheWeakness fetches the URL (using optional port for scheme/host), prints
// Cache-Control, Expires, and Pragma headers with secure/insecure labels, then
// scans the HTML for meta Cache-Control tags and labels them.
func CacheWeakness(url, port string) {
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

	// Check if Cache-Control contains no-store (affects Pragma label)
	cacheControlHasNoStore := false
	if v := getHeaderValue(resp, "Cache-Control"); v != "" {
		cacheControlHasNoStore = strings.Contains(strings.ToLower(v), "no-store")
	}

	// Print Cache-Control, Expires, Pragma (case-insensitive key lookup)
	printHeaderWithLabel(resp, "Cache-Control", false)
	printHeaderWithLabel(resp, "Expires", false)
	printHeaderWithLabel(resp, "Pragma", cacheControlHasNoStore)

	// Read HTML body
	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		return
	}
	html := buf.String()

	// Find <meta ...> tags with http-equiv="Cache-Control" and content="no-cache" or "no-store"
	metaRe := regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	metaMatches := metaRe.FindAllString(html, -1)

	httpEquivRe := regexp.MustCompile(`(?i)\bhttp-equiv\s*=\s*["']([^"']*)["']`)
	contentRe := regexp.MustCompile(`(?i)\bcontent\s*=\s*["']([^"']*)["']`)

	for _, tag := range metaMatches {
		equivMatch := httpEquivRe.FindStringSubmatch(tag)
		contentMatch := contentRe.FindStringSubmatch(tag)
		if len(equivMatch) < 2 || len(contentMatch) < 2 {
			continue
		}
		equiv := strings.ToLower(strings.TrimSpace(equivMatch[1]))
		content := strings.ToLower(strings.TrimSpace(contentMatch[1]))
		if equiv != "cache-control" {
			continue
		}
		if content == "no-cache" {
			fmt.Println(cacheInsecure, strings.TrimSpace(tag))
		} else if content == "no-store" {
			fmt.Println(cacheSecure, strings.TrimSpace(tag))
		}
	}
}

// getHeaderValue returns the first value for the given header (case-insensitive).
func getHeaderValue(resp *http.Response, name string) string {
	for k, v := range resp.Header {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// printHeaderWithLabel gets the first value for the given header (case-insensitive),
// prints the header and value, with [secure] or [insecure] in front when value matches rules.
// When printing Pragma: no-cache, [insecure] is only shown if cacheControlHasNoStore is false.
func printHeaderWithLabel(resp *http.Response, name string, cacheControlHasNoStore bool) {
	value := getHeaderValue(resp, name)
	if value == "" {
		return
	}
	var canonicalName string
	for k := range resp.Header {
		if strings.EqualFold(k, name) {
			canonicalName = k
			break
		}
	}
	valLower := strings.ToLower(strings.TrimSpace(value))

	var label string
	switch strings.ToLower(name) {
	case "cache-control":
		if strings.Contains(valLower, "no-store") || strings.Contains(valLower, "must-revalidate") {
			label = cacheSecure
		} else if strings.Contains(valLower, "no-cache") {
			label = cacheInsecure
		}
	case "expires":
		if valLower == "0" || valLower == "-1" {
			label = cacheSecure
		}
	case "pragma":
		if valLower == "no-cache" && !cacheControlHasNoStore {
			label = cacheInsecure
		}
	}
	if label != "" {
		fmt.Println(label, canonicalName+":", value)
	} else {
		fmt.Println(canonicalName+":", value)
	}
}
