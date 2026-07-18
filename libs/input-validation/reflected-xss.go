package inputvalidation

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

	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
)

// Result holds the detection outcome for one candidate URL.
type Result struct {
	URL       string
	Payload   string
	Reflected bool
	Executed  bool
	Evidence  string
}

func (r *Result) Print() {
	switch {
	case r.Executed:
		fmt.Printf("%s[VULNERABLE]%s %s\n", colorRed, colorReset, r.URL)
		if r.Evidence != "" {
			fmt.Printf("    evidence : %s\n", r.Evidence)
		}
	case r.Reflected:
		fmt.Printf("[REFLECTED]  %s\n", r.URL)
		fmt.Printf("    note     : payload reflected but NOT executed — verify manually\n")
	default:
		fmt.Printf("%s[SAFE]%s       %s  (payload not reflected)\n", colorGreen, colorReset, r.URL)
	}
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
	Payload string
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
// already contains encoded HTML (e.g. %3Ciframe%20...).
func decodePayloadValue(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.QueryUnescape(value)
	if err != nil || decoded == value {
		return value
	}
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

// parseQueryPayload accepts lines like "?user=<img src=x onerror=alert(1)>" or "user=...".
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
	return []string{rewritten, rawURL}
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

func (s *Scanner) dialogFired(chrome *chromeProcess, targetURL string) (bool, error) {
	var lastErr error
	for _, candidate := range browserURLCandidates(targetURL) {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout+10*time.Second)
		fired, err := chrome.dialogFired(ctx, candidate)
		cancel()
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "[warn] headless: %v\n", err)
			continue
		}
		if fired {
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

	s.logf("baseline check: %s", rawURL)
	baseline, baseErr := s.dialogFired(chrome, rawURL)
	if baseErr != nil {
		s.logf("baseline check error: %v", baseErr)
	}
	if baseline {
		s.logf("baseline triggers alert — marking all reflected targets as unconfirmed")
		for _, r := range needHeadless {
			r.Evidence = "page triggers alert() without payload; cannot confirm XSS"
		}
		return results, nil
	}

	for _, r := range needHeadless {
		s.logf("headless check: %s", r.URL)
		fired, dialErr := s.dialogFired(chrome, r.URL)
		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "[warn] headless error for %s: %v\n", r.URL, dialErr)
			continue
		}
		r.Executed = fired
		if fired {
			r.Evidence = "alert()/confirm()/prompt() called in browser after payload injection"
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

// ReflectedXSS injects each payload from payloadFile into every query parameter
// of rawURL and confirms JavaScript execution via headless browser (native CDP).
func ReflectedXSS(rawURL, payloadFile string) {
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
