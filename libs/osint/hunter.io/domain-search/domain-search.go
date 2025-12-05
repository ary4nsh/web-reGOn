package domainSearch

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Email struct {
	Value      string `json:"value"`
	Type       string `json:"type"`
	Confidence int    `json:"confidence"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Position   string `json:"position"`
}

type DomainData struct {
	Domain      string  `json:"domain"`
	Disposable  bool    `json:"disposable"`
	Webmail     bool    `json:"webmail"`
	AcceptAll   bool    `json:"accept_all"`
	Organization string  `json:"organization"`
	Description string  `json:"description"`
	Industry    string  `json:"industry"`
	Emails      []Email `json:"emails"`
}

type ApiResponse struct {
	Data DomainData `json:"data"`
	Meta struct {
		Results int `json:"results"`
	} `json:"meta"`
}

// DomainSearch performs a domain search using the Hunter.io API
func DomainSearch(apiKey, domain string) {
	// Construct the API URL
	url := fmt.Sprintf("https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s", domain, apiKey)

	// Make the HTTP GET request
	resp, err := http.Get(url)
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
		fmt.Println("Error: received non-200 response code:", resp.StatusCode)
		fmt.Println(string(body))
		return
	}

	// Parse the JSON response
	var apiResponse ApiResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	// Print the results
	fmt.Printf("Domain: %s\n", apiResponse.Data.Domain)
	fmt.Printf("Organization: %s\n", apiResponse.Data.Organization)
	fmt.Printf("Description: %s\n", apiResponse.Data.Description)
	fmt.Printf("Emails:\n")
	for _, email := range apiResponse.Data.Emails {
		fmt.Printf(" - %s (%s, Confidence: %d%%)\n", email.Value, email.Position, email.Confidence)
	}
}
