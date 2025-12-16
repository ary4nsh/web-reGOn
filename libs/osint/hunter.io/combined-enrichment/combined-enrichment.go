package combinedEnrichment

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Response struct {
	Data struct {
		Person struct {
			ID         string `json:"id"`
			FullName   string `json:"fullName"`
			Email      string `json:"email"`
			Location   string `json:"location"`
			Employment struct {
				Domain string `json:"domain"`
				Name   string `json:"name"`
				Title  string `json:"title"`
			} `json:"employment"`
		} `json:"person"`
		Company struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Location    string `json:"location"`
		} `json:"company"`
	} `json:"data"`
	Meta struct {
		Email string `json:"email"`
	} `json:"meta"`
}

// CombinedEnrichment takes an API key and an email as parameters
func CombinedEnrichment(apiKey, email string) {
	url := fmt.Sprintf("https://api.hunter.io/v2/combined/find?email=%s&api_key=%s", email, apiKey)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error making the request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Error: received non-200 response code:", resp.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}

	// Print the results
	fmt.Printf("Person ID: %s\n", response.Data.Person.ID)
	fmt.Printf("Full Name: %s\n", response.Data.Person.FullName)
	fmt.Printf("Email: %s\n", response.Data.Person.Email)
	fmt.Printf("Location: %s\n", response.Data.Person.Location)
	fmt.Printf("Company Name: %s\n", response.Data.Company.Name)
	fmt.Printf("Company Description: %s\n", response.Data.Company.Description)
	fmt.Printf("Company Location: %s\n", response.Data.Company.Location)
}
