package identitymanagement

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	colorReset2  = "\033[0m"
	colorGreen2  = "\033[32m"
	colorYellow2 = "\033[33m"
)

var sensitiveKeywords = []string{
	"admin", "role", "user", "privilege", "access",
	"auth", "session", "token", "isAdmin",
}

func CookieAndAccount(website string, wordlistPath string, threads int) {
	if !strings.HasPrefix(website, "http://") && !strings.HasPrefix(website, "https://") {
		website = "https://" + website
	}

	// Extract cookies
	cookies := extractCookiesForAccount(website)
	if cookies != "" {
		fmt.Printf("Cookies extracted: %s\n", cookies)
		checkSensitiveCookies(cookies)
	} else {
		fmt.Println("No cookies found")
	}

	// Test CMS paths
	paths := []string{"author", "user"}
	validPaths := testPaths(website, paths, cookies)

	if len(validPaths) == 0 {
		fmt.Println("No valid paths found for fuzzing")
		return
	}

	// Load wordlist
	wordlist, err := loadWordlist(wordlistPath)
	if err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		return
	}

	// Perform fuzzing
	for _, path := range validPaths {
		fmt.Printf("\nFuzzing %s/%s/...\n", website, path)
		fuzzPath(website, path, wordlist, cookies, threads)
	}
}

func createClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func addHeaders(req *http.Request, cookies string) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,fa-IR;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Te", "trailers")

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
}

func extractCookiesForAccount(website string) string {
	client := createClient()

	req, err := http.NewRequest("HEAD", website, nil)
	if err != nil {
		return ""
	}

	addHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var cookieParts []string
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		// Extract cookie name=value (before first semicolon)
		parts := strings.Split(cookie, ";")
		if len(parts) > 0 {
			cookieParts = append(cookieParts, strings.TrimSpace(parts[0]))
		}
	}

	return strings.Join(cookieParts, "; ")
}

func checkSensitiveCookies(cookies string) {
	cookiesLower := strings.ToLower(cookies)
	var foundKeywords []string

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(cookiesLower, strings.ToLower(keyword)) {
			foundKeywords = append(foundKeywords, keyword)
		}
	}

	if len(foundKeywords) > 0 {
		fmt.Printf("%sPotentially sensitive cookie parameter detected: %v%s\n",
			colorYellow2, foundKeywords, colorReset2)
	}
}

func testPaths(website string, paths []string, cookies string) []string {
	client := createClient()
	var validPaths []string

	for _, path := range paths {
		url := fmt.Sprintf("%s/%s", strings.TrimRight(website, "/"), path)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		addHeaders(req, cookies)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			fmt.Printf("Found valid path: %s (Status: 200)\n", path)
			validPaths = append(validPaths, path)
		}
	}

	return validPaths
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

func fuzzPath(website, path string, wordlist []string, cookies string, threads int) {

	client := createClient()
	sem := make(chan struct{}, threads) // Limit concurrent requests
	var wg sync.WaitGroup

	for _, word := range wordlist {
		wg.Add(1)
		sem <- struct{}{}

		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf("%s/%s/%s", strings.TrimRight(website, "/"), path, w)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}

			addHeaders(req, cookies)

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode == 200 {
				fmt.Printf("%s%s (200)%s\n", colorGreen2, url, colorReset2)
			}
		}(word)
	}

	wg.Wait()
}
