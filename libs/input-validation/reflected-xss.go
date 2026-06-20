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

func injectTargets(rawURL, payload string) ([]string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	params := parsed.Query()
	if len(params) == 0 {
		params.Set("q", payload)
		parsed.RawQuery = params.Encode()
		return []string{parsed.String()}, nil
	}
	out := make([]string, 0, len(params))
	for key := range params {
		mod := cloneValues(params)
		mod.Set(key, payload)
		c := *parsed
		c.RawQuery = mod.Encode()
		out = append(out, c.String())
	}
	return out, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout+10*time.Second)
	defer cancel()

	for _, candidate := range browserURLCandidates(targetURL) {
		fired, err := chrome.dialogFired(ctx, candidate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] headless: %v\n", err)
			continue
		}
		if fired {
			return true, nil
		}
	}
	return false, nil
}

func isExpectedNavError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "net::ERR") ||
		strings.Contains(msg, "ERR_ABORTED") ||
		strings.Contains(msg, "context deadline exceeded")
}

func (s *Scanner) Scan(rawURL, payload string) ([]*Result, error) {
	targets, err := injectTargets(rawURL, payload)
	if err != nil {
		return nil, err
	}

	results := make([]*Result, 0, len(targets))
	var needHeadless []*Result

	for _, t := range targets {
		r := &Result{URL: t, Payload: payload}

		if s.reflective {
			s.logf("reflective mode — skipping HTTP pre-filter for %s", t)
			results = append(results, r)
			needHeadless = append(needHeadless, r)
			continue
		}

		s.logf("HTTP check: %s", t)
		r.Reflected, err = s.isReflected(t, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] HTTP error for %s: %v\n", t, err)
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
