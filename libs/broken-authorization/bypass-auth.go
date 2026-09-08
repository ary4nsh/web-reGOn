package brokenauthorization

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const probePath = "/__rewrite_probe_nonexistent"

var rewriteHeaders = []string{"X-Original-URL", "X-Rewrite-URL"}

var ipHeaders = []string{
	"X-Forwarded-For",
	"X-Forward-For",
	"X-Remote-IP",
	"X-Originating-IP",
	"X-Remote-Addr",
	"X-Client-IP",
	"X-Real-IP",
}

// BypassAuthOptions configures authorization schema / header bypass checks.
type BypassAuthOptions struct {
	Host    string
	Port    string
	DstPath string   // single or comma-separated paths, e.g. /admin or /admin,/secret
	Headers []string // optional "Name: value" overrides for tested headers
}

type authResult struct {
	code int
	body []byte
}

// BypassAuth tests rewrite-URL and client-IP header tricks against protected paths.
func BypassAuth(opts BypassAuthOptions) {
	if err := validateBypassAuthOptions(&opts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}

	if rewritten, ok := rewriteLocalTarget(opts.Host); ok {
		fmt.Printf("%s[!] WSL detected: rewriting target host %s → %s%s\n", colorYellow, opts.Host, rewritten, colorReset)
		opts.Host = rewritten
	}

	base, err := buildAuthBaseURL(opts.Host, opts.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}

	paths := ParseAuthPaths(opts.DstPath)
	overrides := parseHeaderOverrides(opts.Headers)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	home, err := authFetch(client, base, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching base URL: %v\n", err)
		return
	}
	fmt.Printf("GET %s -> %d (%d bytes)\n", base, home.code, len(home.body))

	rewriteSupported := false
	rewriteBypass := false
	ipBypass := false

	for _, path := range paths {
		targetURL := joinAuthPath(base, path)
		fmt.Printf("\n\n\n========== Testing path %s ==========\n", path)

		baseline, err := authFetch(client, targetURL, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error fetching %s: %v\n", targetURL, err)
			continue
		}
		fmt.Printf("GET %s -> %d (%d bytes)\n", targetURL, baseline.code, len(baseline.body))

		for _, h := range rewriteHeaders {
			fmt.Printf("\nTesting %s:\n", h)

			pathVal := headerValue(overrides, h, path)
			probeVal := headerValue(overrides, h, probePath)

			onHome, err := authFetch(client, base, map[string]string{h: pathVal})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				continue
			}
			fmt.Printf("- GET %s + %s: %s -> %d (%d bytes)\n",
				base, h, pathVal, onHome.code, len(onHome.body))

			onTarget, err := authFetch(client, targetURL, map[string]string{h: pathVal})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				continue
			}
			fmt.Printf("- GET %s + %s: %s -> %d (%d bytes)\n",
				targetURL, h, pathVal, onTarget.code, len(onTarget.body))

			onHomeOther, err := authFetch(client, base, map[string]string{h: probeVal})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				continue
			}
			fmt.Printf("- GET %s + %s: %s -> %d (%d bytes)\n",
				base, h, probeVal, onHomeOther.code, len(onHomeOther.body))

			matchesHome := sameAuth(home, onHome)
			matchesTarget := sameAuth(baseline, onHome)
			otherMatchesHome := sameAuth(home, onHomeOther)

			supported := matchesTarget || !matchesHome
			if matchesHome && otherMatchesHome {
				supported = false
			}

			fmt.Println()
			if supported {
				fmt.Printf("%sHeader %s is supported%s\n", colorRed, h, colorReset)
				rewriteSupported = true
			} else {
				fmt.Printf("Header %s is not supported\n", h)
			}

			if isClientError(baseline.code) && onTarget.code >= 200 && onTarget.code < 300 {
				fmt.Printf("%sAccess control bypass possible via %s on %s (%d -> %d)%s\n",
					colorRed, h, path, baseline.code, onTarget.code, colorReset)
				rewriteSupported = true
				rewriteBypass = true
			} else if supported && isClientError(baseline.code) && isClientError(onTarget.code) {
				fmt.Printf("Access control bypass not possible via %s on %s (still %d)\n", h, path, onTarget.code)
			}
		}

		fmt.Println()
		for _, h := range ipHeaders {
			fmt.Printf("\nTesting %s against %s:\n", h, path)
			ipVal := headerValue(overrides, h, "127.0.0.1")
			r, err := authFetch(client, targetURL, map[string]string{h: ipVal})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				continue
			}
			fmt.Printf("- GET %s + %s: %s -> %d (%d bytes)\n",
				targetURL, h, ipVal, r.code, len(r.body))

			if isClientError(baseline.code) && r.code >= 200 && r.code < 300 {
				fmt.Printf("%sHeader %s is supported (access control bypass on %s)%s\n",
					colorRed, h, path, colorReset)
				ipBypass = true
				continue
			}
			fmt.Printf("Header %s did not bypass %s\n", h, path)
		}
	}

	fmt.Println()
	if rewriteSupported {
		if rewriteBypass {
			fmt.Println("Result: rewrite headers supported AND access control bypass possible")
		} else {
			fmt.Println("Result: rewrite headers supported, but access control bypass not possible")
		}
	} else {
		fmt.Println("Result: rewrite headers not supported")
	}
	if ipBypass {
		fmt.Println("Result: server trusts client IP headers (auth bypass)")
	} else {
		fmt.Println("Result: IP spoof headers did not bypass protected paths")
	}
}

func validateBypassAuthOptions(opts *BypassAuthOptions) error {
	opts.Host = strings.TrimSpace(opts.Host)
	if opts.Host == "" {
		return fmt.Errorf("domain/host is required")
	}
	if strings.Contains(opts.Host, "://") {
		if u, err := url.Parse(opts.Host); err == nil && u.Hostname() != "" {
			opts.Host = u.Hostname()
			if u.Port() != "" && (opts.Port == "" || opts.Port == defaultDirTraversalPort) {
				opts.Port = u.Port()
			}
		}
	}
	if opts.Port == "" {
		opts.Port = defaultDirTraversalPort
	}
	if strings.TrimSpace(opts.DstPath) == "" {
		return fmt.Errorf("--dst-path is required (e.g. /admin or /admin,/secret)")
	}
	if len(ParseAuthPaths(opts.DstPath)) == 0 {
		return fmt.Errorf("no paths to test in --dst-path")
	}
	return nil
}

func buildAuthBaseURL(host, port string) (string, error) {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	scheme := "https"
	switch port {
	case "", "443":
		scheme = "https"
		port = "443"
	case "80":
		scheme = "http"
	default:
		scheme = "http"
	}

	var hostPort string
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		hostPort = host
	} else {
		hostPort = net.JoinHostPort(host, port)
	}
	return scheme + "://" + hostPort + "/", nil
}

// ParseAuthPaths splits a comma-separated destination path list.
func ParseAuthPaths(raw string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func joinAuthPath(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return strings.TrimSuffix(base, "/") + path
	}
	root := *u
	root.Path = path
	root.RawQuery = ""
	root.Fragment = ""
	return root.String()
}

func sameAuth(a, b authResult) bool {
	return a.code == b.code && bytes.Equal(a.body, b.body)
}

func isClientError(code int) bool {
	return code >= 400 && code < 500
}

func authFetch(c *http.Client, target string, hdr map[string]string) (authResult, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return authResult{}, err
	}
	req.Header.Set("User-Agent", "web-reGOn-bypass-auth")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return authResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseRead))
	if err != nil {
		return authResult{}, err
	}
	return authResult{code: resp.StatusCode, body: body}, nil
}

// parseHeaderOverrides parses repeatable --header "Name: value" into a
// case-insensitive map. Later entries win for the same name.
func parseHeaderOverrides(headers []string) map[string]string {
	out := make(map[string]string)
	for _, raw := range headers {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			fmt.Fprintf(os.Stderr, "warning: ignoring malformed --header %q (expected \"Name: value\")\n", raw)
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			continue
		}
		out[http.CanonicalHeaderKey(name)] = value
	}
	return out
}

// headerValue returns the user override for header name when present, otherwise def.
func headerValue(overrides map[string]string, name, def string) string {
	if overrides == nil {
		return def
	}
	if v, ok := overrides[http.CanonicalHeaderKey(name)]; ok {
		return v
	}
	return def
}
