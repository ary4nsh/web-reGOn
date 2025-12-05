package emailFinder

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type EmailFinderResponse struct {
	Data struct {
		FirstName   string `json:"first_name"`
		LastName    string `json:"last_name"`
		Email       string `json:"email"`
		Score       int    `json:"score"`
		Domain      string `json:"domain"`
		AcceptAll   bool   `json:"accept_all"`
		Position    string `json:"position"`
		Company     string `json:"company"`
		Sources     []struct {
			Domain       string `json:"domain"`
			URI          string `json:"uri"`
			ExtractedOn  string `json:"extracted_on"`
			LastSeenOn   string `json:"last_seen_on"`
			StillOnPage  bool   `json:"still_on_page"`
		} `json:"sources"`
		Verification struct {
			Date   string `json:"date"`
			Status string `json:"status"`
		} `json:"verification"`
	} `json:"data"`
	Meta struct {
		Params struct {
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Domain    string `json:"domain"`
		} `json:"params"`
	} `json:"meta"`
}

func EmailFinder(apiKey, firstName, lastName, domain string) {
	// Construct the API URL
	url := fmt.Sprintf("https://api.hunter.io/v2/email-finder?domain=%s&first_name=%s&last_name=%s&api_key=%s", domain, firstName, lastName, apiKey)

	// Make the API request
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

	// Parse the JSON response
	var response EmailFinderResponse
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	// Print the results
	fmt.Printf("First Name: %s\n", response.Data.FirstName)
	fmt.Printf("Last Name: %s\n", response.Data.LastName)
	fmt.Printf("Email: %s\n", response.Data.Email)
	fmt.Printf("Score: %d\n", response.Data.Score)
	fmt.Printf("Domain: %s\n", response.Data.Domain)
	fmt.Printf("Position: %s\n", response.Data.Position)
	fmt.Printf("Company: %s\n", response.Data.Company)
	fmt.Printf("Verification Status: %s\n", response.Data.Verification.Status)
}
