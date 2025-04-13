package libs

import(
	"fmt"
	"net"
	"sync"
	"log"

	"github.com/miekg/dns"
)

func DnsRecords(URL string, wg *sync.WaitGroup){

	//Look up ip address
	fmt.Println()
	fmt.Printf("IP Addresses:\n")
	ip, err := net.LookupIP(URL)
	if err != nil {
		fmt.Printf("Error retrieving IP address: %v\n", err)
	} else {
		for _, addr := range ip{
			fmt.Printf("- %s\n", addr.String())
		}
	}
	

	//Look up CNAME record
	fmt.Println()
	fmt.Printf("CNAME Record:\n")
	cname, err1 := net.LookupCNAME(URL)
	if err1 != nil {
		fmt.Printf("Error retrieving CNAME record: %v\n", err1)
	} else {
		fmt.Printf("- %s\n", cname)
	}
	

	//Lokup MX record
	fmt.Println()
	fmt.Printf("MX Records:\n")
	MX, err2 := net.LookupMX(URL)
	if err2 != nil {
		fmt.Printf("Error retrieving MX records: %v\n", err2)
	} else {
		for _, mx := range MX {
			fmt.Printf("- Host: %s, Priority: %d\n", mx.Host, mx.Pref)
		}
	}


	//Look up NS record
	fmt.Println()
	fmt.Printf("NS Records:\n")
	NS, err3 := net.LookupNS(URL)
	if err3 != nil {
		fmt.Printf("Error retrieving NS record: %v\n", err3)
	} else {
		for _, ns := range NS {
			fmt.Printf("- %s\n", ns.Host)
		}
	}
	
	
	//Look up TXT record
	fmt.Println()
	fmt.Printf("TXT records:\n")
	TXT, err4 := net.LookupTXT(URL)
	if err4 != nil {
		fmt.Printf("Error retrieving TXT record: %v\n", err4)
	} else {
		for _, txt := range TXT {
			fmt.Printf("- %s\n", txt)
		}
	}
	
	
	//Look up PTR record
	fmt.Println()
	fmt.Printf("PTR records:\n")
	// For each IP address, perform a reverse lookup to get PTR records
	for _, ipAddr := range ip {
		PTR, err5 := net.LookupAddr(ipAddr.String())
		if err5 != nil {
			fmt.Printf("Error looking up PTR record: %v\n", err5)
		continue
		} else {
			for _, ptr := range PTR {
				fmt.Printf("- %s\n", ptr)
			}
 		}
	}

	//Look up SOA record
	fmt.Println()
	fmt.Printf("SOA records:\n")
	
	// Create a new DNS client
	client := new(dns.Client)

	// Create a new DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(URL), dns.TypeSOA)

	// Send the query to the default DNS server
	resp, _, err6 := client.Exchange(msg, "1.1.1.1:53") // Using Cloudflare's public DNS server
	if err6 != nil {
		fmt.Printf("Failed to get SOA record: %v", err6)
	}

	// Check if we received an answer
	if len(resp.Answer) == 0 {
		fmt.Println("No answer received")
	}

	// Iterate through the answers and print SOA records
	for _, answer := range resp.Answer {
		if soa, ok := answer.(*dns.SOA); ok {
			fmt.Printf("- MNAME: %s\n", soa.Ns)      // Name server
			fmt.Printf("- RNAME: %s\n", soa.Mbox)    // Responsible person's email
			fmt.Printf("- Serial: %d\n", soa.Serial) // Serial number
			fmt.Printf("- Refresh: %d\n", soa.Refresh)
			fmt.Printf("- Retry: %d\n", soa.Retry)
			fmt.Printf("- Expire: %d\n", soa.Expire)
			fmt.Printf("- Minimum: %d\n", soa.Minttl) // Minimum TTL
		}
	}
	
	
	//Look up HINFO record
	fmt.Println()
	fmt.Printf("HINFO record:\n")
	
	// Create a new DNS message for HINFO
	msgHINFO := new(dns.Msg)
	msgHINFO.SetQuestion(dns.Fqdn(URL), dns.TypeHINFO)

	// Send the DNS query for HINFO
	responseHINFO, _, err7 := client.Exchange(msgHINFO, "1.1.1.1:53") // Using Cloudflare's public DNS server
	if err != nil {
		fmt.Printf("Failed to query DNS for HINFO: %v", err7)
	}

	// Check if we received an answer
	if responseHINFO.Rcode != dns.RcodeSuccess {
		log.Fatalf("Failed to get HINFO records: %v", responseHINFO.Rcode)
	}

	// Iterate through the answer section and print HINFO records
	for _, answer := range responseHINFO.Answer {
		if hinfo, ok := answer.(*dns.HINFO); ok {
			fmt.Printf("- HINFO Record: CPU=%s, OS=%s\n", hinfo.Cpu, hinfo.Os) // Use hinfo.Os instead of hinfo.OS
		}
	}
	
	
	//Look up SRV records
	fmt.Println()
	fmt.Printf("SRV records:\n")
	
	// Define the service, protocol, and domain
	service := "_sip"
	protocol := "_tcp"

	// Create a new DNS message for SRV
	msgSRV := new(dns.Msg)
	msgSRV.SetQuestion(dns.Fqdn(fmt.Sprintf("_%s._%s.%s", service, protocol, URL)), dns.TypeSRV)

	// Send the DNS query for SRV
	responseSRV, _, err8 := client.Exchange(msgSRV, "1.1.1.1:53") // Using Cloudflare's public DNS server
	if err8 != nil {
		fmt.Printf("Failed to query DNS for SRV: %v", err8)
	}

	// Check if we received an answer
	if responseSRV.Rcode != dns.RcodeSuccess {
		log.Fatalf("Failed to get SRV records: %v", responseSRV.Rcode)
	}

	// Iterate through the answer section and print SRV records
	for _, answer := range responseSRV.Answer {
		if srv, ok := answer.(*dns.SRV); ok {
		fmt.Printf("- Name: %s, Port: %d, Priority: %d, Weight: %d\n", srv.Target, srv.Port, srv.Priority, srv.Weight)
		}
	}
}
