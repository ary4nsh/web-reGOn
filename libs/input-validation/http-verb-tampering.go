package inputvalidation

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	httpVerbDefaultPort    = "80"
	httpVerbDefaultThreads = 5
	httpVerbTimeout        = 15 * time.Second
	httpVerbMaxBody        = 64 * 1024

	colorWhite  = "\033[37m"
	colorCyan   = "\033[36m"
	colorOrange = "\033[33m"
	colorYellow = "\033[93m"
)

var standardHTTPMethods = []string{
	"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
}

var webdavMethods = []string{
	"COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "UNLOCK",
}

var defaultCustomMethods = []string{
	"BAMBOOZLE", "CHECKIN", "CHECKOUT", "INDEX", "LINK", "NOEXISTE", "ORDERPATCH",
	"REPORT", "SEARCH", "SHOWMETHOD", "SPACEJUMP", "TEXTSEARCH", "TRACK",
	"UNCHECKOUT", "UNLINK", "VERSION-CONTROL",
}

var dangerousHTTPMethods = []string{"DELETE", "COPY", "PUT", "PATCH", "UNCHECKOUT"}

type methodResult struct {
	statusCode     int
	reason         string
	redirectCode   int
	redirectReason string
}

// HTTPVerbTampering enumerates HTTP methods against a target URL.
func HTTPVerbTampering(urlStr, port string, threads int, cookies string, headers []string, wordlistPath string, followRedirects, webdavEnabled bool) {
	targetURL, err := normalizeHTTPVerbURL(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	if threads <= 0 {
		threads = httpVerbDefaultThreads
	}

	methods, err := resolveHTTPMethods(wordlistPath, webdavEnabled)
	if err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		return
	}
	methods = uniqueUpperSorted(methods)
	methods = confirmDangerousMethods(methods)

	if len(methods) == 0 {
		fmt.Println("No methods selected for testing.")
		return
	}

	fmt.Println()

	client := newHTTPVerbClient(false)
	reqHeaders := parseHTTPVerbHeaders(headers)
	if cookies != "" {
		if reqHeaders == nil {
			reqHeaders = make(http.Header)
		}
		reqHeaders.Set("Cookie", strings.TrimSpace(cookies))
	}

	if containsMethod(methods, "OPTIONS") {
		optionsAllow := probeOptionsAllow(client, targetURL, reqHeaders)
		if optionsAllow != "" {
			fmt.Printf("output of method OPTIONS: %s\n\n", optionsAllow)
		} else {
			fmt.Println("output of method OPTIONS:")
			fmt.Println()
		}
	}

	printHTTPVerbNotes()
	fmt.Println()

	results := runMethodTests(targetURL, methods, threads, reqHeaders, followRedirects)
	printGroupedResults(methods, results, followRedirects)
}

func normalizeHTTPVerbURL(rawURL, port string) (string, error) {
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return "", fmt.Errorf("empty URL")
	}
	if port == "" {
		port = httpVerbDefaultPort
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		if u.Host == "" {
			return "", fmt.Errorf("no host in URL")
		}
		host := u.Hostname()
		path := u.EscapedPath()
		if u.RawQuery != "" {
			if path == "" {
				path = "/"
			}
			path += "?" + u.RawQuery
		}
		if u.Fragment != "" {
			path += "#" + u.Fragment
		}
		switch port {
		case "80":
			return "http://" + host + path, nil
		case "443":
			return "https://" + host + path, nil
		default:
			return fmt.Sprintf("http://%s:%s%s", host, port, path), nil
		}
	}

	hostPart := raw
	path := ""
	if idx := strings.Index(hostPart, "/"); idx >= 0 {
		path = hostPart[idx:]
		hostPart = hostPart[:idx]
	}

	switch port {
	case "80":
		return "http://" + hostPart + path, nil
	case "443":
		return "https://" + hostPart + path, nil
	default:
		return fmt.Sprintf("http://%s:%s%s", hostPart, port, path), nil
	}
}

func resolveHTTPMethods(wordlistPath string, webdavEnabled bool) ([]string, error) {
	if wordlistPath != "" {
		return loadHTTPMethodsWordlist(wordlistPath)
	}
	methods := make([]string, 0, len(standardHTTPMethods)+len(defaultCustomMethods)+len(webdavMethods))
	methods = append(methods, standardHTTPMethods...)
	methods = append(methods, defaultCustomMethods...)
	if webdavEnabled {
		methods = append(methods, webdavMethods...)
	}
	return methods, nil
}

func loadHTTPMethodsWordlist(wordlistPath string) ([]string, error) {
	data, err := os.ReadFile(wordlistPath)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return nil, fmt.Errorf("wordlist is empty")
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, strings.ToUpper(f))
		}
	}
	return out, nil
}

func methodCategory(method string) string {
	switch method {
	case "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK":
		return "webdav"
	case "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE":
		return "http"
	default:
		return "custom"
	}
}

func printGroupedResults(methods []string, results map[string]methodResult, followRedirects bool) {
	groups := []struct {
		title string
		cat   string
	}{
		{"HTTP Methods:", "http"},
		{"WebDav Methods:", "webdav"},
		{"Custom Methods:", "custom"},
	}

	first := true
	for _, g := range groups {
		var inGroup []string
		for _, m := range methods {
			if methodCategory(m) == g.cat {
				inGroup = append(inGroup, m)
			}
		}
		if len(inGroup) == 0 {
			continue
		}
		if !first {
			fmt.Println()
		}
		fmt.Println(g.title)
		for _, m := range inGroup {
			res, ok := results[m]
			if !ok {
				continue
			}
			printMethodResult(m, res, followRedirects)
		}
		first = false
	}
}

func uniqueUpperSorted(methods []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func confirmDangerousMethods(methods []string) []string {
	set := make(map[string]bool, len(methods))
	for _, m := range methods {
		set[m] = true
	}

	reader := bufio.NewReader(os.Stdin)
	for _, dangerous := range dangerousHTTPMethods {
		if !set[dangerous] {
			continue
		}
		fmt.Printf("Do you really want to test method %s (can be dangerous)? [y/n] ", dangerous)
		answer, err := reader.ReadString('\n')
		if err != nil {
			delete(set, dangerous)
			continue
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			delete(set, dangerous)
		}
	}

	var filtered []string
	for _, m := range methods {
		if set[m] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func printHTTPVerbNotes() {
	fmt.Println("Note:")
	fmt.Println("* status code 200 means the method is accepted")
	fmt.Println("* status code 400-499 means the method is disabled in most cases")
	fmt.Println("* status code 500-599 (except 502) means the method is not implemented in most cases")
	fmt.Println("* status code 502 means the method is probably accepted but the request was malformed")
}

func containsMethod(methods []string, name string) bool {
	for _, m := range methods {
		if m == name {
			return true
		}
	}
	return false
}

func parseHTTPVerbHeaders(headers []string) http.Header {
	if len(headers) == 0 {
		return nil
	}
	h := make(http.Header)
	for _, line := range headers {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		h.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	return h
}

func newHTTPVerbClient(followRedirects bool) *http.Client {
	client := &http.Client{
		Timeout: httpVerbTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func probeOptionsAllow(client *http.Client, targetURL string, headers http.Header) string {
	res, err := doMethodRequest(client, "OPTIONS", targetURL, headers)
	if err != nil {
		return ""
	}
	allow := res.Header.Get("Allow")
	if allow == "" {
		allow = res.Header.Get("allow")
	}
	return strings.TrimSpace(allow)
}

func runMethodTests(targetURL string, methods []string, threads int, headers http.Header, followRedirects bool) map[string]methodResult {
	results := make(map[string]methodResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	if threads > len(methods) {
		threads = len(methods)
	}
	sem := make(chan struct{}, threads)

	for _, method := range methods {
		wg.Add(1)
		sem <- struct{}{}
		go func(m string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := probeMethod(targetURL, m, headers, followRedirects)
			mu.Lock()
			results[m] = res
			mu.Unlock()
		}(method)
	}
	wg.Wait()
	return results
}

func probeMethod(targetURL, method string, headers http.Header, followRedirects bool) methodResult {
	noRedirect := newHTTPVerbClient(false)
	initialRes, err := doMethodRequest(noRedirect, method, targetURL, headers)
	if err != nil {
		return methodResult{reason: err.Error()}
	}
	initial := responseToResult(initialRes)

	if !followRedirects || !isRedirectStatus(initial.statusCode) {
		return initial
	}

	followClient := newHTTPVerbClient(true)
	finalRes, err := doMethodRequest(followClient, method, targetURL, headers)
	if err != nil {
		return initial
	}
	final := responseToResult(finalRes)
	return methodResult{
		statusCode:     initial.statusCode,
		reason:         initial.reason,
		redirectCode:   final.statusCode,
		redirectReason: final.reason,
	}
}

func responseToResult(res *http.Response) methodResult {
	reason := res.Status
	if idx := strings.Index(reason, " "); idx >= 0 {
		reason = strings.TrimSpace(reason[idx+1:])
	}
	return methodResult{statusCode: res.StatusCode, reason: reason}
}

func isRedirectStatus(code int) bool {
	return code >= 300 && code <= 399
}

func doMethodRequest(client *http.Client, method, targetURL string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	_, _ = io.CopyN(io.Discard, res.Body, httpVerbMaxBody)
	return res, nil
}

func printMethodResult(method string, res methodResult, followRedirects bool) {
	if res.statusCode == 0 {
		fmt.Printf("- %s: %s%s%s\n", method, colorRed, res.reason, colorReset)
		return
	}
	if followRedirects && res.redirectCode > 0 && res.redirectCode != res.statusCode {
		initialColor := statusColor(res.statusCode)
		finalColor := statusColor(res.redirectCode)
		fmt.Printf("- %s: %s%d (%s)%s -> %s%d (%s)%s\n",
			method,
			initialColor, res.statusCode, res.reason, colorReset,
			finalColor, res.redirectCode, res.redirectReason, colorReset,
		)
		return
	}
	color := statusColor(res.statusCode)
	fmt.Printf("- %s: %s%d (%s)%s\n", method, color, res.statusCode, res.reason, colorReset)
}

func statusColor(code int) string {
	switch {
	case code >= 100 && code <= 199:
		return colorWhite
	case code >= 200 && code <= 299:
		return colorGreen
	case code >= 300 && code <= 399:
		return colorCyan
	case code >= 400 && code <= 499:
		return colorRed
	case code == 502:
		return colorYellow
	case code >= 500 && code <= 599:
		return colorOrange
	default:
		return colorReset
	}
}
