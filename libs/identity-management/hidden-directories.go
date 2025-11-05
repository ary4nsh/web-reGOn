package identitymanagement

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

const (
	phase1File = "phase1.txt"
)

var (
	headers = map[string]string{
		"User-Agent":                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Accept":                     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language":            "en-US,fa-IR;q=0.5",
		"Accept-Encoding":            "gzip, deflate, br, zstd",
		"Connection":                 "keep-alive",
		"Upgrade-Insecure-Requests":  "1",
		"Sec-Fetch-Dest":             "document",
		"Sec-Fetch-Mode":             "navigate",
		"Sec-Fetch-Site":             "cross-site",
		"DNT":                        "1",
		"Sec-GPC":                    "1",
		"Priority":                   "u=0, i",
		"Te":                         "trailers",
	}
)

func HiddenDirectories(website, wordlist string, threads int) {
	timeout := 10 // timeout in seconds

	// Add https:// if not present
	if !strings.HasPrefix(website, "http://") && !strings.HasPrefix(website, "https://") {
		website = "https://" + website
	}

	// Remove trailing slash from website
	website = strings.TrimSuffix(website, "/")

	fmt.Printf("[*] Starting fuzzer on: %s\n", website)
	fmt.Printf("[*] Wordlist: %s\n", wordlist)
	fmt.Printf("[*] Threads: %d\n", threads)

	// Extract cookies
	cookies := extractCookies(website, timeout)
	if cookies != "" {
		fmt.Printf("[*] Cookies extracted: %s\n", cookies)
		headers["Cookie"] = cookies
	} else {
		fmt.Println("[*] No cookies found")
	}

	// Phase 1: Fuzz WEBSITE/FUZZ
	fmt.Println("\n[*] Starting Phase 1...")
	phase1Results, totalPhase1 := fuzzPhase1(website, wordlist, threads, timeout)

	if len(phase1Results) == 0 {
		fmt.Println("[*] No results found in Phase 1. Exiting.")
		return
	}

	fmt.Printf("[*] Phase 1 complete. Found %d paths out of %d tested.\n", len(phase1Results), totalPhase1)

	// Phase 2: Fuzz WEBSITE/WORD/FUZZ
	fmt.Println("\n[*] Starting Phase 2...")
	fuzzPhase2(website, wordlist, phase1Results, threads, timeout)

	fmt.Println("\n[*] Fuzzing complete!")
}

func extractCookies(url string, timeout int) string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return ""
	}

	for key, value := range headers {
		if key != "Cookie" {
			req.Header.Set(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var cookieParts []string
	for _, cookie := range resp.Cookies() {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
	}

	return strings.Join(cookieParts, "; ")
}

func fuzzPhase1(baseURL, wordlistPath string, threads, timeout int) ([]string, int) {
	words := readWordlist(wordlistPath)
	results := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, threads)

	// Count total words to be tested
	totalWords := len(words)
	fmt.Printf("[*] Total URLs to test in Phase 1: %d\n\n", totalWords)

	for _, word := range words {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf("%s/%s", baseURL, w)
			fmt.Printf("[TESTING] %s\n", url)
			
			if checkURL(url, timeout) {
				mu.Lock()
				results = append(results, w)
				fmt.Printf("%s[200]%s %s\n", colorGreen, colorReset, url)
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()

	// Save results to phase1.txt
	if len(results) > 0 {
		saveToFile(phase1File, results)
	}

	return results, totalWords
}

func fuzzPhase2(baseURL, wordlistPath string, phase1Results []string, threads, timeout int) {
	words := readWordlist(wordlistPath)
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	// Count total words to be tested for phase 2
	totalWordsPhase2 := len(words) * len(phase1Results)
	fmt.Printf("[*] Total URLs to test in Phase 2: %d\n\n", totalWordsPhase2)

	for _, word := range phase1Results {
		for _, fuzz := range words {
			wg.Add(1)
			go func(w, f string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				url := fmt.Sprintf("%s/%s/%s", baseURL, w, f)
				fmt.Printf("[TESTING] %s\n", url)

				if checkURL(url, timeout) {
					fmt.Printf("%s[200]%s %s\n", colorGreen, colorReset, url)
				}
			}(word, fuzz)
		}
	}

	wg.Wait()
}

func checkURL(url string, timeout int) bool {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Decompress response body if needed
	var reader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return false
		}
		defer reader.(*gzip.Reader).Close()
	case "br":
		reader = brotli.NewReader(resp.Body)
	default:
		reader = resp.Body
	}

	// Discard body to reuse connection
	io.Copy(io.Discard, reader)

	return resp.StatusCode == 200
}

func readWordlist(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening wordlist: %v\n", err)
		os.Exit(1)
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

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading wordlist: %v\n", err)
		os.Exit(1)
	}

	return words
}

func saveToFile(filename string, data []string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range data {
		fmt.Fprintln(writer, line)
	}
	writer.Flush()
}
