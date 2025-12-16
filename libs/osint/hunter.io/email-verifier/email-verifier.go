package emailVerifier

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type EmailVerifierResponse struct {
	Data struct {
		Status         string `json:"status"`
		Result         string `json:"result"`
		Score          int    `json:"score"`
		Email          string `json:"email"`
		Regexp         bool   `json:"regexp"`
		Gibberish      bool   `json:"gibberish"`
		Disposable     bool   `json:"disposable"`
		Webmail        bool   `json:"webmail"`
		MXRecords      bool   `json:"mx_records"`
		SMTPServer     bool   `json:"smtp_server"`
		SMTPCheck      bool   `json:"smtp_check"`
		AcceptAll      bool   `json:"accept_all"`
		Block          bool   `json:"block"`
		Sources        []struct {
			Domain      string `json:"domain"`
			URI         string `json:"uri"`
			ExtractedOn string `json:"extracted_on"`
			LastSeenOn  string `json:"last_seen_on"`
			StillOnPage bool   `json:"still_on_page"`
		} `json:"sources"`
	} `json:"data"`
	Meta struct {
		Params struct {
			Email string `json:"email"`
		} `json:"params"`
	} `json:"meta"`
}

// EmailVerifier verifies the email address using the provided API key.
func EmailVerifier(apiKey, email string) {
	// Create the request URL
	url := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s", email, apiKey)

	// Create an HTTP client
	client := &http.Client{}

	// Make the HTTP GET request
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Error making the request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading the response body:", err)
		return
	}

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: received status code %d\n", resp.StatusCode)
		fmt.Println(string(body))
		return
	}

	// Parse the JSON response
	var response EmailVerifierResponse
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	// Print the results
	fmt.Printf("Email: %s\n", response.Data.Email)
	fmt.Printf("Status: %s\n", response.Data.Status)
	fmt.Printf("Score: %d\n", response.Data.Score)
	fmt.Printf("Deliverable: %t\n", response.Data.Result == "deliverable")
	fmt.Printf("Disposable: %t\n", response.Data.Disposable)
	fmt.Printf("Webmail: %t\n", response.Data.Webmail)
	fmt.Printf("MX Records: %t\n", response.Data.MXRecords)
	fmt.Printf("SMTP Server: %t\n", response.Data.SMTPServer)
	fmt.Printf("SMTP Check: %t\n", response.Data.SMTPCheck)
	fmt.Printf("Accept All: %t\n", response.Data.AcceptAll)
	fmt.Printf("Block: %t\n", response.Data.Block)

	// Print sources if available
	if len(response.Data.Sources) > 0 {
		fmt.Println("Sources:")
		for _, source := range response.Data.Sources {
			fmt.Printf("- Domain: %s, URI: %s\n", source.Domain, source.URI)
		}
	}
}
