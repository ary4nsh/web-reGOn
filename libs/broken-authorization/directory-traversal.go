package brokenauthorization

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDirTraversalPort    = "443"
	defaultDirTraversalDepth   = 1
	defaultDirTraversalTimeout = 500 // milliseconds between probes
	maxResponseRead            = 512 * 1024
	requestTimeout             = 15 * time.Second

	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[93m"
)

// Options configures a directory traversal scan.
type Options struct {
	Host        string
	Port        string
	DstPath     string
	Depth       int
	TimeoutMs   int
	URL         string // fuzz URL containing TRAVERSAL (mutually exclusive with PayloadFile)
	PayloadFile string // raw HTTP request template with TRAVERSAL
	Pattern     string // optional response match; auto-derived from DstPath when empty
}

// DirectoryTraversal fuzzes TRAVERSAL tokens in a URL or raw payload file.
func DirectoryTraversal(opts Options) {
	if err := validateOptions(&opts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}

	// On WSL, localhost/127.0.0.1 is the Linux VM — rewrite to the Windows host IP
	// so lab servers bound on Windows are reachable.
	if rewritten, ok := rewriteLocalTarget(opts.Host); ok {
		fmt.Printf("%s[!] WSL detected: rewriting target host %s → %s%s\n", colorYellow, opts.Host, rewritten, colorReset)
		opts.Host = rewritten
	}
	if opts.URL != "" {
		if rewrittenURL, ok := rewriteLocalURL(opts.URL); ok {
			fmt.Printf("%s[!] WSL detected: rewriting --url host → %s%s\n", colorYellow, rewrittenURL, colorReset)
			opts.URL = rewrittenURL
		}
	}

	traversals := GenerateTraversals(opts.DstPath, opts.Depth)
	pattern := opts.Pattern
	if pattern == "" {
		pattern = PatternForDestination(opts.DstPath)
	}

	fmt.Printf("Target     : %s:%s\n", opts.Host, opts.Port)
	fmt.Printf("Destination: %s\n", opts.DstPath)
	fmt.Printf("Depth      : %d\n", opts.Depth)
	fmt.Printf("Traversals : %d generated\n", len(traversals))
	if pattern != "" {
		fmt.Printf("Pattern    : %q\n", pattern)
	} else {
		fmt.Println("Pattern    : (none — status 200 with non-empty body treated as candidate)")
	}
	if opts.URL != "" {
		fmt.Printf("Mode       : URL (%s)\n\n", opts.URL)
	} else {
		fmt.Printf("Mode       : payload-file (%s)\n\n", opts.PayloadFile)
	}

	var payloadTemplate string
	if opts.PayloadFile != "" {
		data, err := os.ReadFile(opts.PayloadFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading payload file: %v\n", err)
			return
		}
		payloadTemplate = string(data)
		if !strings.Contains(payloadTemplate, "TRAVERSAL") {
			fmt.Fprintln(os.Stderr, "error: payload file must contain the TRAVERSAL marker")
			return
		}
		payloadTemplate = rewritePayloadHost(payloadTemplate, opts.Host, opts.Port)
	}

	useTLS := false
	if opts.URL != "" {
		useTLS = strings.HasPrefix(strings.ToLower(opts.URL), "https://")
	} else {
		useTLS = opts.Port == "443"
	}
	delay := time.Duration(opts.TimeoutMs) * time.Millisecond
	found := 0

	for i, trav := range traversals {
		var (
			vulnerable bool
			evidence   string
			label      string
			err        error
		)

		if opts.URL != "" {
			testURL := strings.ReplaceAll(opts.URL, "TRAVERSAL", trav)
			label = testURL
			// Raw TCP — avoids http.Client URL
			// normalization/escaping that can break ../ and ..\ patterns.
			vulnerable, evidence, err = probeRawURL(opts.Host, opts.Port, useTLS, testURL, pattern)
		} else {
			raw := strings.ReplaceAll(payloadTemplate, "TRAVERSAL", trav)
			label = trav
			vulnerable, evidence, err = probeRawPayload(opts.Host, opts.Port, useTLS, raw, pattern)
		}

		if err != nil {
			fmt.Printf("[*] [%d/%d] %s — error: %v\n", i+1, len(traversals), shortLabel(label), err)
		} else if vulnerable {
			found++
			fmt.Printf("%s[VULNERABLE]%s %s\n", colorRed, colorReset, label)
			if evidence != "" {
				fmt.Printf("    evidence : %s\n", evidence)
			}
		} else {
			fmt.Printf("%s[SAFE]%s       %s\n", colorGreen, colorReset, shortLabel(label))
		}

		if i < len(traversals)-1 && delay > 0 {
			time.Sleep(delay)
		}
	}

	fmt.Printf("\n[+] Finished. Vulnerable traversals: %d / %d\n", found, len(traversals))
	if found == 0 {
		fmt.Printf("%sNo directory traversal confirmed.%s\n", colorYellow, colorReset)
	}
}

func validateOptions(opts *Options) error {
	opts.Host = strings.TrimSpace(opts.Host)
	if opts.Host == "" {
		return fmt.Errorf("domain/host is required")
	}
	// Strip scheme if user passed a URL-looking host by mistake.
	if strings.Contains(opts.Host, "://") {
		if u, err := url.Parse(opts.Host); err == nil && u.Hostname() != "" {
			opts.Host = u.Hostname()
		}
	}
	if opts.Port == "" {
		opts.Port = defaultDirTraversalPort
	}
	if opts.DstPath == "" {
		return fmt.Errorf("--dst-path is required (e.g. /etc/passwd)")
	}
	if opts.Depth <= 0 {
		opts.Depth = defaultDirTraversalDepth
	}
	if opts.TimeoutMs <= 0 {
		opts.TimeoutMs = defaultDirTraversalTimeout
	}
	hasURL := strings.TrimSpace(opts.URL) != ""
	hasPayload := strings.TrimSpace(opts.PayloadFile) != ""
	if hasURL == hasPayload {
		return fmt.Errorf("use exactly one of --url or --payload-file")
	}
	if hasURL {
		opts.URL = strings.TrimSpace(opts.URL)
		if !strings.Contains(opts.URL, "TRAVERSAL") {
			return fmt.Errorf("--url must contain the TRAVERSAL marker")
		}
		opts.URL = normalizeFuzzURL(opts.URL, opts.Host, opts.Port)
		if u, err := url.Parse(opts.URL); err == nil {
			if p := u.Port(); p != "" {
				opts.Port = p
			} else if strings.EqualFold(u.Scheme, "http") && opts.Port == defaultDirTraversalPort {
				opts.Port = "80"
			}
		}
	}
	return nil
}

func normalizeFuzzURL(raw, host, port string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		return raw
	}
	scheme := "https"
	if port == "80" {
		scheme = "http"
	} else if port != "443" && port != "" {
		scheme = "http"
		return fmt.Sprintf("%s://%s:%s/%s", scheme, host, port, strings.TrimPrefix(raw, "/"))
	}
	if port == "443" || port == "80" || port == "" {
		return fmt.Sprintf("%s://%s/%s", scheme, host, strings.TrimPrefix(raw, "/"))
	}
	return fmt.Sprintf("%s://%s:%s/%s", scheme, host, port, strings.TrimPrefix(raw, "/"))
}

// probeRawURL builds and sends a raw HTTP/1.1 request for the fuzzed URL.
// Traversal characters are kept verbatim in the request-target.
func probeRawURL(host, port string, useTLS bool, fuzzURL, pattern string) (bool, string, error) {
	reqLine, hostHeader, err := rawRequestFromURL(fuzzURL, host, port)
	if err != nil {
		return false, "", err
	}
	payload := reqLine + "\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"User-Agent: web-reGOn-dir-traversal\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	return probeRawPayload(host, port, useTLS, payload, pattern)
}

// rawRequestFromURL returns "GET /path?query HTTP/1.1" and Host header value.
// Path/query are taken from the string after the authority so ../ is not cleaned.
func rawRequestFromURL(fuzzURL, fallbackHost, fallbackPort string) (reqLine, hostHeader string, err error) {
	u, err := url.Parse(fuzzURL)
	if err != nil {
		return "", "", err
	}
	hostHeader = u.Host
	if hostHeader == "" {
		hostHeader = net.JoinHostPort(fallbackHost, fallbackPort)
	}

	rest := fuzzURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i:]
	} else {
		rest = "/"
	}
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		rest = "/"
	}
	return "GET " + rest + " HTTP/1.1", hostHeader, nil
}

func probeRawPayload(host, port string, useTLS bool, rawPayload, pattern string) (bool, string, error) {
	payload := ensureHTTPRequestComplete(rawPayload)
	addr := net.JoinHostPort(host, port)

	dialer := net.Dialer{Timeout: requestTimeout}
	var (
		conn net.Conn
		err  error
	)
	if useTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	if _, err := io.WriteString(conn, payload); err != nil {
		return false, "", err
	}

	// matches the raw socket bytes (headers + body).
	rawResp, err := io.ReadAll(io.LimitReader(conn, maxResponseRead))
	if err != nil && len(rawResp) == 0 {
		return false, "", err
	}
	return evaluateRawResponse(rawResp, pattern)
}

func ensureHTTPRequestComplete(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	var b strings.Builder
	for i, line := range lines {
		b.WriteString(line)
		if i < len(lines)-1 {
			b.WriteString("\r\n")
		}
	}
	out := b.String()
	if !strings.HasSuffix(out, "\r\n\r\n") {
		if strings.HasSuffix(out, "\r\n") {
			out += "\r\n"
		} else {
			out += "\r\n\r\n"
		}
	}
	return out
}

func evaluateRawResponse(raw []byte, pattern string) (bool, string, error) {
	text := string(raw)
	status := peekStatus(text)

	if pattern != "" {
		if strings.Contains(text, pattern) {
			return true, fmt.Sprintf("status %d; matched pattern %q", status, pattern), nil
		}
		return false, "", nil
	}

	body := raw
	if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
		body = raw[idx+4:]
	} else if idx := strings.Index(text, "\n\n"); idx >= 0 {
		body = raw[idx+2:]
	}
	if status == 200 && len(strings.TrimSpace(string(body))) > 0 {
		return true, fmt.Sprintf("status %d; non-empty body (%d bytes)", status, len(body)), nil
	}
	return false, "", nil
}

func peekStatus(raw string) int {
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			return code
		}
	}
	return 0
}

func shortLabel(s string) string {
	const max = 120
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ParsePort returns port string or default.
func ParsePort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return defaultDirTraversalPort
	}
	if _, err := strconv.Atoi(port); err != nil {
		return defaultDirTraversalPort
	}
	return port
}

func rewritePayloadHost(payload, host, port string) string {
	want := "Host: " + net.JoinHostPort(host, port)
	lines := strings.Split(payload, "\n")
	for i, line := range lines {
		trim := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(trim)), "host:") {
			lines[i] = want
			return strings.Join(lines, "\n")
		}
	}
	return payload
}

func isLocalHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(data))
	return strings.Contains(s, "microsoft") || strings.Contains(s, "wsl")
}

func wslHostIP() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		fields := strings.Fields(string(out))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				return fields[i+1]
			}
		}
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	return ""
}

func rewriteLocalTarget(host string) (string, bool) {
	if !isWSL() || !isLocalHost(host) {
		return host, false
	}
	gw := wslHostIP()
	if gw == "" || gw == host {
		return host, false
	}
	return gw, true
}

func rewriteLocalURL(raw string) (string, bool) {
	if !isWSL() {
		return raw, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	host := u.Hostname()
	if !isLocalHost(host) {
		return raw, false
	}
	gw := wslHostIP()
	if gw == "" {
		return raw, false
	}
	port := u.Port()
	if port != "" {
		u.Host = net.JoinHostPort(gw, port)
	} else {
		u.Host = gw
	}
	out := u.String()
	return out, out != raw
}
