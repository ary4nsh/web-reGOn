package dnsPropagation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func DnsPropagation(apiKey, domain string) {

	url := fmt.Sprintf("https://api.viewdns.info/propagation/?domain=%s&apikey=%s&output=json",
		domain, apiKey)

	resp, err := http.Get(url)
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