package companyEnrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CompanyData struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	LegalName   string   `json:"legalName"`
	Domain      string   `json:"domain"`
	Phone       string   `json:"phone"`
	Email       []string `json:"emailAddresses"`
	Description string   `json:"description"`
	FoundedYear int      `json:"foundedYear"`
	Location    string   `json:"location"`
}

type ApiResponse struct {
	Data CompanyData `json:"data"`
	Meta struct {
		Domain string `json:"domain"`
	} `json:"meta"`
}

// CompanyEnrichment fetches company data based on the provided API key and domain.
func CompanyEnrichment(apiKey, domain string) error {
	// Construct the API URL
	url := fmt.Sprintf("https://api.hunter.io/v2/companies/find?domain=%s&api_key=%s", domain, apiKey)
	// Create an HTTP client with a timeout
	client := &http.Client{
		Timeout: 10 * time.Second, // Set a timeout for the request
	}

	// Make the HTTP GET request
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("error making the request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error: received status code %d", resp.StatusCode)
	}

	// Parse the JSON response
	var apiResponse ApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return fmt.Errorf("error parsing JSON response: %w", err)
	}

	// Print the company data
	fmt.Printf("Company Name: %s\n", apiResponse.Data.Name)
	fmt.Printf("Legal Name: %s\n", apiResponse.Data.LegalName)
	fmt.Printf("Domain: %s\n", apiResponse.Data.Domain)
	fmt.Printf("Phone: %s\n", apiResponse.Data.Phone)
	fmt.Printf("Emails: %v\n", apiResponse.Data.Email)
	fmt.Printf("Description: %s\n", apiResponse.Data.Description)
	fmt.Printf("Founded Year: %d\n", apiResponse.Data.FoundedYear)
	fmt.Printf("Location: %s\n", apiResponse.Data.Location)

	return nil
}
