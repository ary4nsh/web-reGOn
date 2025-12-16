package osint

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const shodanAPIURL = "https://api.shodan.io/shodan/host/"

type ShodanResponse struct {
	// Define the fields you want to extract from the response
	IP        string   `json:"ip_str"`
	Org       string   `json:"org"`
	Hostnames []string `json:"hostnames"`
	// Add more fields as needed
}

// Update the function signature to accept the API key as a parameter
func HostIPQuery(URL string, apiKey string) {
	// Create the request URL
	createdUrl := fmt.Sprintf("%s%s?key=%s", shodanAPIURL, URL, apiKey)

	// Make the HTTP GET request
	resp, err := http.Get(createdUrl)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Error: %s\n", body)
		return
	}

	// Parse the JSON response
	var shodanResponse ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&shodanResponse); err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}

	// Print the results
	fmt.Printf("IP: %s\n", shodanResponse.IP)
	fmt.Printf("Organization: %s\n", shodanResponse.Org)
	fmt.Printf("Hostnames: %v\n", shodanResponse.Hostnames)
}
