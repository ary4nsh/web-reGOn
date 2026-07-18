package clientside

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	maxBodyRead    = 5 * 1024 * 1024 // 5 MB

	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[93m"
)

// Result holds the detection outcome for one candidate URL.
type Result struct {
	URL       string
	Payload   string
	Reflected bool
	Injected  bool
	Evidence  string
}

func (r *Result) Print() {
	switch {
	case r.Injected:
		fmt.Printf("%s[VULNERABLE]%s %s\n", colorRed, colorReset, r.URL)
		if r.Evidence != "" {
			fmt.Printf("    evidence : %s\n", r.Evidence)
		}
	case r.Reflected:
		fmt.Printf("[REFLECTED]  %s\n", r.URL)
		fmt.Printf("    note     : payload reflected but NOT injected into DOM — verify manually\n")
	case r.Evidence != "":
		fmt.Printf("[UNCONFIRMED] %s\n", r.URL)
		fmt.Printf("    note     : %s\n", r.Evidence)
	default:
		fmt.Printf("%s[SAFE]%s       %s  (payload not injected into DOM)\n", colorGreen, colorReset, r.URL)
	}
}

// dangerousMetaHTTPEquivValues returns refresh and/or set-cookie when present as
// meta http-equiv values in the payload.
func dangerousMetaHTTPEquivValues(payload string) []string {
	lower := strings.ToLower(payload)
	if !strings.Contains(lower, "http-equiv") {
		return nil
	}
	var found []string
	seen := map[string]bool{}
	for _, val := range []string{"refresh", "set-cookie"} {
		if metaHTTPEquivHasValue(lower, val) {
			if !seen[val] {
				seen[val] = true
				found = append(found, val)
			}
		}
	}
	return found
}

func payloadHasDangerousMetaHTTPEquiv(payload string) bool {
	return len(dangerousMetaHTTPEquivValues(payload)) > 0
}

func metaHTTPEquivHasValue(lowerPayload, val string) bool {
	patterns := []string{
		`http-equiv="` + val + `"`,
		`http-equiv='` + val + `'`,
		`http-equiv=` + val,
		`http-equiv = "` + val + `"`,
		`http-equiv = '` + val + `'`,
		`http-equiv = ` + val,
	}
	for _, p := range patterns {
		if strings.Contains(lowerPayload, p) {
			return true
		}
	}
	idx := 0
	for {
		i := strings.Index(lowerPayload[idx:], "http-equiv")
		if i < 0 {
			return false
		}
		i += idx
		rest := lowerPayload[i+len("http-equiv"):]
		rest = strings.TrimLeft(rest, " \t\r\n")
		if !strings.HasPrefix(rest, "=") {
			idx = i + 1
			continue
		}
		rest = strings.TrimLeft(rest[1:], " \t\r\n\"'")
		if strings.HasPrefix(rest, val) {
			after := rest[len(val):]
			if after == "" || !isHTTPEquivIdentChar(after[0]) {
				return true
			}
		}
		idx = i + 1
	}
}

func isHTTPEquivIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func dangerousMetaHTTPEquivFromPayloads(payloads []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range payloads {
		check := line
		if _, value, ok := parseQueryPayload(line); ok {
			check = decodePayloadValue(value)
		} else {
			check = decodePayloadValue(line)
		}
		for _, val := range dangerousMetaHTTPEquivValues(check) {
			if !seen[val] {
				seen[val] = true
				out = append(out, val)
			}
		}
	}
	return out
}

func printDangerousHTTPEquivWarning(attrs []string) {
	if len(attrs) == 0 {
		return
	}
	parts := make([]string, 0, len(attrs))
	for _, a := range attrs {
		parts = append(parts, "http-equiv="+a)
	}
	fmt.Printf("%sDangerous http-equiv attribute found, the web page might be vulnerable to HTML Injection (detected: %s)%s\n\n",
		colorYellow, strings.Join(parts, ", "), colorReset)
}

// Scanner coordinates the HTTP pre-filter and headless confirmation steps.
type Scanner struct {
	client     *http.Client
	timeout    time.Duration
	verbose    bool
	reflective bool
}

func newScanner(timeout time.Duration, verbose, reflective bool) *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout:    timeout,
		verbose:    verbose,
		reflective: reflective,
	}
}

type injectTarget struct {
	URL     string
	Payload string // HTML value used for reflection / DOM checks
}

func injectTargets(rawURL, payloadLine string) ([]injectTarget, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if name, value, ok := parseQueryPayload(payloadLine); ok {
		value = decodePayloadValue(value)
		params := cloneValues(parsed.Query())
		params.Set(name, value)
		c := *parsed
		c.RawQuery = encodeQuery(params)
		return []injectTarget{{URL: c.String(), Payload: value}}, nil
	}

	params := parsed.Query()
	if len(params) == 0 {
		return nil, fmt.Errorf("URL has no query parameters and payload does not specify one (use ?param=value in the payload file, or add ?param=test to the URL)")
	}

	payloadLine = decodePayloadValue(payloadLine)
	out := make([]injectTarget, 0, len(params))
	for key := range params {
		mod := cloneValues(params)
		mod.Set(key, payloadLine)
		c := *parsed
		c.RawQuery = encodeQuery(mod)
		out = append(out, injectTarget{URL: c.String(), Payload: payloadLine})
	}
	return out, nil
}

// decodePayloadValue undoes one layer of percent-encoding when the payload file
// already contains encoded HTML (e.g. %3Ciframe%20... from a lab example link).
// encodeQuery will re-encode once when building the request URL.
func decodePayloadValue(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil || decoded == value {
		return value
	}
	// Prefer decoded form when it looks like HTML markup or a tag payload.
	if strings.ContainsAny(decoded, "<>") || strings.HasPrefix(strings.TrimSpace(decoded), "<") {
		return decoded
	}
	return value
}

// encodeQuery builds a query string using %20 for spaces (not +).
// Client-side sinks that use decodeURIComponent do not treat + as space.
func encodeQuery(params url.Values) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, queryEscape(k)+"="+queryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func queryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// metaRefreshDestination extracts the url= target from a meta-refresh HTML payload.
func metaRefreshDestination(payload string) string {
	lower := strings.ToLower(payload)
	if !strings.Contains(lower, "http-equiv") || !strings.Contains(lower, "refresh") {
		return ""
	}
	idx := strings.Index(lower, "url=")
	if idx < 0 {
		return ""
	}
	rest := payload[idx+4:]
	rest = strings.TrimLeft(rest, " \t\"'")
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '"', '\'', ' ', '\t', '>':
			end = i
			goto done
		}
	}
done:
	return strings.TrimSpace(rest[:end])
}

// urlIndicatesMetaRefresh reports whether the browser left requestedURL and landed on dest
// (or a host-rewritten equivalent), which indicates a successful meta-refresh injection.
func urlIndicatesMetaRefresh(requestedURL, currentURL, dest string) bool {
	if dest == "" || currentURL == "" {
		return false
	}
	reqPath := strings.TrimSuffix(pathOnly(requestedURL), "/")
	curPath := strings.TrimSuffix(pathOnly(currentURL), "/")
	destPath := strings.TrimSuffix(pathOnly(dest), "/")

	if destPath != "" && curPath != "" && curPath == destPath && curPath != reqPath {
		return true
	}
	// Basename match (e.g. /redirect-target.html) when hosts differ (WSL vs localhost).
	if destPath != "" && curPath != "" && curPath != reqPath {
		if base := pathBase(destPath); base != "" && pathBase(curPath) == base && base != pathBase(reqPath) {
			return true
		}
	}
	if strings.Contains(currentURL, dest) {
		return curPath != reqPath
	}
	if destPath != "" && strings.Contains(currentURL, destPath) && curPath != reqPath {
		return true
	}
	return false
}

func pathBase(p string) string {
	p = strings.TrimSuffix(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pathOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return ""
	}
	return u.Path
}

// parseQueryPayload accepts lines like "?user=<h1>x</h1>" or "user=<h1>x</h1>".
// Raw HTML payloads (starting with "<") are not treated as named query payloads.
func parseQueryPayload(line string) (name, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "<") {
		return "", "", false
	}
	if strings.HasPrefix(line, "?") {
		line = strings.TrimPrefix(line, "?")
	}
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:idx])
	value = line[idx+1:]
	if name == "" || strings.ContainsAny(name, "<>\"'&/?#") {
		return "", "", false
	}
	return name, value, true
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func (s *Scanner) isReflected(targetURL, payload string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return false, err
	}
	return strings.Contains(string(body), payload), nil
}

func wslHostIP() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		fields := strings.Fields(string(out))
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		}
	}
	return ""
}

func browserURLCandidates(rawURL string) []string {
	if runtime.GOOS != "linux" {
		return []string{rawURL}
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return []string{rawURL}
	}
	host := parsed.Hostname()
	if host != "localhost" && host != "127.0.0.1" {
		return []string{rawURL}
	}
	gw := wslHostIP()
	if gw == "" {
		return []string{rawURL}
	}
	rewritten := rewriteLocalhostHost(rawURL, gw)
	if rewritten == rawURL {
		return []string{rawURL}
	}
	// Prefer the original localhost URL first so meta-refresh destinations that
	// also point at localhost (common in labs) resolve on the same host.
	return []string{rawURL, rewritten}
}

func rewriteLocalhostHost(rawURL, newHost string) string {
	if newHost == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := parsed.Hostname()
	if host != "localhost" && host != "127.0.0.1" {
		return rawURL
	}
	port := parsed.Port()
	if port != "" {
		parsed.Host = net.JoinHostPort(newHost, port)
	} else if parsed.Scheme == "https" {
		parsed.Host = net.JoinHostPort(newHost, "443")
	} else {
		parsed.Host = net.JoinHostPort(newHost, "80")
	}
	return parsed.String()
}

func (s *Scanner) htmlInjected(chrome *chromeProcess, targetURL, payload string) (bool, error) {
	var lastErr error
	for _, candidate := range browserURLCandidates(targetURL) {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout+10*time.Second)
		injected, err := chrome.htmlInjected(ctx, candidate, payload)
		cancel()
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "[warn] headless: %v\n", err)
			continue
		}
		if injected {
			return true, nil
		}
	}
	return false, lastErr
}

func isExpectedNavError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "net::ERR") ||
		strings.Contains(msg, "ERR_ABORTED") ||
		strings.Contains(msg, "context deadline exceeded")
}

func (s *Scanner) Scan(rawURL, payloadLine string) ([]*Result, error) {
	targets, err := injectTargets(rawURL, payloadLine)
	if err != nil {
		return nil, err
	}

	results := make([]*Result, 0, len(targets))
	var needHeadless []*Result

	for _, t := range targets {
		r := &Result{URL: t.URL, Payload: t.Payload}

		if s.reflective {
			s.logf("reflective mode — skipping HTTP pre-filter for %s", t.URL)
			results = append(results, r)
			needHeadless = append(needHeadless, r)
			continue
		}

		s.logf("HTTP check: %s", t.URL)
		r.Reflected, err = s.isReflected(t.URL, t.Payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] HTTP error for %s: %v\n", t.URL, err)
		}
		results = append(results, r)
		if r.Reflected {
			needHeadless = append(needHeadless, r)
		}
	}

	if len(needHeadless) == 0 {
		return results, nil
	}

	chrome, err := launchChrome()
	if err != nil {
		return results, err
	}
	defer chrome.close()

	for _, r := range needHeadless {
		s.logf("baseline check: %s", rawURL)
		baseline, baseErr := s.htmlInjected(chrome, rawURL, r.Payload)
		if baseErr != nil {
			s.logf("baseline check error: %v", baseErr)
		}
		if baseline {
			s.logf("baseline already contains payload HTML — marking target as unconfirmed")
			r.Evidence = "page already contains payload HTML without injection; cannot confirm HTML injection"
			continue
		}

		s.logf("headless check: %s", r.URL)
		injected, injErr := s.htmlInjected(chrome, r.URL, r.Payload)
		if injErr != nil {
			fmt.Fprintf(os.Stderr, "[warn] headless error for %s: %v\n", r.URL, injErr)
			continue
		}
		r.Injected = injected
		if injected {
			r.Reflected = true
			r.Evidence = "payload HTML parsed into DOM after injection (unescaped markup rendered)"
		}
	}

	return results, nil
}

func (s *Scanner) logf(format string, args ...any) {
	if s.verbose {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", args...)
	}
}

func readPayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(
			strings.TrimPrefix(strings.TrimSpace(sc.Text()), "\xef\xbb\xbf"),
			"\r\n",
		)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// HTMLInjection injects each payload from payloadFile into every query parameter
// of rawURL and confirms HTML injection into the DOM via headless browser (native CDP).
func HTMLInjection(rawURL, payloadFile string) {
	payloads, err := readPayloads(payloadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading payload file: %v\n", err)
		return
	}
	if len(payloads) == 0 {
		fmt.Fprintln(os.Stderr, "error: payload file is empty")
		return
	}

	fmt.Printf("Target   : %s\n", rawURL)
	fmt.Printf("Payloads : %d loaded from %s\n\n", len(payloads), payloadFile)

	if attrs := dangerousMetaHTTPEquivFromPayloads(payloads); len(attrs) > 0 {
		printDangerousHTTPEquivWarning(attrs)
	}

	scanner := newScanner(defaultTimeout, false, true)

	var allResults []*Result
	for _, payload := range payloads {
		results, scanErr := scanner.Scan(rawURL, payload)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", scanErr)
			return
		}
		allResults = append(allResults, results...)
	}

	for _, r := range allResults {
		r.Print()
	}
}
