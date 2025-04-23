package libs

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const dnsDumpsterAPI = "https://api.dnsdumpster.com/domain/"

type IPInfo struct {
	ASN         string `json:"asn"`
	ASNName     string `json:"asn_name"`
	ASNRange    string `json:"asn_range"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	IP          string `json:"ip"`
	PTR         string `json:"ptr"`
}

type ARecord struct {
	Host string   `json:"host"`
	IPs  []IPInfo `json:"ips"`
}

type NSRecord struct {
	Host string   `json:"host"`
	IPs  []IPInfo `json:"ips"`
}

type MXRecord struct {
	Host string   `json:"host"`
	IPs  []IPInfo `json:"ips"`
}

type DNSRecords struct {
	ARecords     []ARecord `json:"a"`
	CNAMERecords  []string  `json:"cname"`
	MXRecords     []MXRecord `json:"mx"`
	NSRecords     []NSRecord `json:"ns"`
	TXTRecords    []string  `json:"txt"`
	TotalARecs    int       `json:"total_a_recs"`
}

func DnsDumpster(URL string, apiKey string) {

	// Call the DNSDumpster API
	records, err := getDNSRecords(URL, apiKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print the records
	printRecords(records)
}

func getDNSRecords(URL, apiKey string) (*DNSRecords, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", dnsDumpsterAPI+URL, nil)
	if err != nil {
		return nil, err
	}

	// Set the API key in the request header
	req.Header.Set("X-API-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get records: %s", resp.Status)
	}

	var records DNSRecords
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}

	return &records, nil
}

func printRecords(records *DNSRecords) {
	fmt.Println("Total A Records:", records.TotalARecs)
	fmt.Println()

	for _, aRecord := range records.ARecords {
		fmt.Println("A Record Host:", aRecord.Host)
		for _, ip := range aRecord.IPs {
			fmt.Printf("- IP: %s\n- ASN: %s\n- ASN Name: %s\n- Country: %s (%s)\n",
				ip.IP, ip.ASN, ip.ASNName, ip.Country, ip.CountryCode)
			fmt.Println()
		}
	}

	fmt.Println("CNAME Records:", records.CNAMERecords)
	fmt.Println()
	
	fmt.Println("MX Records:")
	for _, mxRecord := range records.MXRecords {
		fmt.Println("- MX Record Host:", mxRecord.Host)
		for _, ip := range mxRecord.IPs {
			fmt.Printf("- IP: %s\n- ASN: %s\n- ASN Name: %s\n- Country: %s (%s)\n",
				ip.IP, ip.ASN, ip.ASNName, ip.Country, ip.CountryCode)
			fmt.Println()
		}
	}

	fmt.Println("NS Records:")
	for _, nsRecord := range records.NSRecords {
		fmt.Println("- NS Record Host:", nsRecord.Host)
		for _, ip := range nsRecord.IPs {
			fmt.Printf("- IP: %s\n- ASN: %s\n- ASN Name: %s\n- Country: %s (%s)\n",
				ip.IP, ip.ASN, ip.ASNName, ip.Country, ip.CountryCode)
			fmt.Println()
		}
	}

	fmt.Println("TXT Records:")
	for _, txtRecord := range records.TXTRecords {
		fmt.Printf("- %s\n", txtRecord)
	}
}
