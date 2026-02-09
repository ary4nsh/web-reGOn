package sessionmanagement

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// CacheControl fetches the URL (with optional port via buildURL), then prints
// Cache-Control and Expires headers and analyzes them for caching security.
func CacheControl(urlStr, port string) {
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
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching URL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Cache-Control
	for _, v := range resp.Header.Values("Cache-Control") {
		if v == "" {
			continue
		}
		fmt.Println("Cache-Control:", colorCacheControlValue(v))
		analyzeCacheControl(v)
	}
	if len(resp.Header.Values("Cache-Control")) == 0 {
		fmt.Println("Cache-Control header not present.")
	}

	// Expires (separate header; 0 or -1 are often used to discourage caching)
	expires := resp.Header.Get("Expires")
	if expires != "" {
		fmt.Println("Expires:", expires)
		expiresTrim := strings.TrimSpace(strings.ToLower(expires))
		if expiresTrim == "0" || expiresTrim == "-1" {
			fmt.Println("- " + green + "Expires: " + expires + " (discourages caching)" + reset)
		}
	}

	// Strict-Transport-Security (HSTS)
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		fmt.Println(green + "Strict-Transport-Security: " + hsts + reset)
	} else {
		fmt.Println(red + "Strict Transport Security not enforced" + reset)
	}

	fmt.Println()
}

// colorCacheControlValue returns the Cache-Control value with public/private in red only
// when the header has no other directives (e.g. only "public" or only "private");
// otherwise public/private are not colored. Secure directives are always in green.
func colorCacheControlValue(value string) string {
	parts := strings.Split(value, ",")
	var directives []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			directives = append(directives, strings.ToLower(p))
		}
	}
	onlyPublicOrPrivate := len(directives) == 1 && (directives[0] == "public" || directives[0] == "private")

	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pl := strings.ToLower(p)
		switch {
		case (pl == "public" || pl == "private") && onlyPublicOrPrivate:
			parts[i] = red + p + reset
		case pl == "no-cache" || pl == "no-store" || pl == "must-revalidate":
			parts[i] = green + p + reset
		case strings.HasPrefix(pl, "max-age=") && (pl == "max-age=0" || strings.TrimSpace(strings.TrimPrefix(pl, "max-age=")) == "0"):
			parts[i] = green + p + reset
		}
	}
	return strings.Join(parts, ", ")
}

// analyzeCacheControl prints red messages only when Cache-Control has a single directive
// that is "public" or "private" (e.g. not "private, s-maxage=0, max-age=0" or "public, max-age=0").
func analyzeCacheControl(value string) {
	parts := strings.Split(value, ",")
	var directives []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			directives = append(directives, strings.ToLower(p))
		}
	}
	// Only when there is exactly one directive and it is "public" or "private"
	if len(directives) != 1 {
		return
	}
	switch directives[0] {
	case "public":
		fmt.Println("- " + red + "Insecure (The web pages can be cached by any proxy between the client and the server)" + reset)
	case "private":
		fmt.Println("- " + red + "Insecure (The stored Session ID might be exposed in a compromised system's filesystem or on shared computers)" + reset)
	}
}
