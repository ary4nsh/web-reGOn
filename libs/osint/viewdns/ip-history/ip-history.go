package ipHistory

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func IpHistory(apiKey, domain string) {

	u := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json",
		domain, apiKey)

	resp, err := http.Get(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read failed:", err)
		os.Exit(1)
	}

	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		fmt.Fprintln(os.Stderr, "invalid JSON:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(raw, "", "  ")
	fmt.Println(string(out))
}
