package http

import (
	"fmt"
	"net/http"
	"strings"
)

// HttpOptions performs an HTTP OPTIONS request based on your original implementation
func HttpOptions(URL string) {
	// Ensure the target has a protocol scheme
	if !strings.HasPrefix(URL, "http://") && !strings.HasPrefix(URL, "https://") {
		URL = "http://" + URL
	}

	// Create HTTP client
	client := &http.Client{}

	// Create OPTIONS request
	req, err := http.NewRequest("OPTIONS", URL, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Print HTTP status line
	fmt.Printf("%s %d %s\n", resp.Proto, resp.StatusCode, resp.Status[4:])

	// If status is 200, check for Allow header
	if resp.StatusCode == 200 {
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			fmt.Printf("Allow: %s\n", allowHeader)
		} else {
			fmt.Println("No Allow header found in response")
		}
	}
}
