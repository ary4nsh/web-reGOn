package emailEnrichment

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Response struct {
	Data struct {
		ID          string `json:"id"`
		FullName    string `json:"fullName"`
		Email       string `json:"email"`
		Location    string `json:"location"`
		TimeZone    string `json:"timeZone"`
		Employment  struct {
			Domain string `json:"domain"`
			Name   string `json:"name"`
			Title  string `json:"title"`
		} `json:"employment"`
		Twitter struct {
			Handle string `json:"handle"`
		} `json:"twitter"`
	} `json:"data"`
	Meta struct {
		Email string `json:"email"`
	} `json:"meta"`
}

func EmailEnrichment(apiKey, email string) {
	// Construct the API URL
	url := fmt.Sprintf("https://api.hunter.io/v2/people/find?email=%s&api_key=%s", email, apiKey)

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
		fmt.Println("Error: received non-200 response status:", resp.Status)
		return
	}

	// Parse the JSON response
	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Println("Error parsing JSON response:", err)
		return
	}

	// Check if the data is present
	if response.Data.FullName == "" {
		fmt.Println("No data found for the provided email.")
		return
	}

	// Print the enriched data
	fmt.Println("Enriched Data:")
	fmt.Printf("Full Name: %s\n", response.Data.FullName)
	fmt.Printf("Email: %s\n", response.Data.Email)
	fmt.Printf("Location: %s\n", response.Data.Location)
	fmt.Printf("Time Zone: %s\n", response.Data.TimeZone)
	fmt.Printf("Employment: %s at %s (%s)\n", response.Data.Employment.Title, response.Data.Employment.Name, response.Data.Employment.Domain)
	fmt.Printf("Twitter Handle: %s\n", response.Data.Twitter.Handle)
}
