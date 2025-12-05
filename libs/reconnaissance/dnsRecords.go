package reconnaissance

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// DnsRecords queries multiple DNS servers for various DNS record types for a given URL or IP address
// If wg is not nil, the caller is responsible for calling Done()
func DnsRecords(input string, wg *sync.WaitGroup) {
	// No wg.Done() call at the beginning - let the caller handle it

	// Determine if input is an IP address or domain name
	URL := input
	isIP := net.ParseIP(input) != nil
	
	if isIP {
		// If it's an IP, we'll use it for PTR lookup but need a domain for other lookups
		// Print a message that we're only performing PTR lookups for IPs
		fmt.Printf("\nDetected IP address input: %s\n", input)
		fmt.Printf("Performing only PTR lookup for IP addresses\n\n")
		
		// Perform PTR lookup for the IP
		performPTRLookup(input)
		return
	}

	fmt.Printf("\nDNS Records for %s:\n", URL)
	fmt.Printf("====================\n")

	// Create a new DNS client
	client := new(dns.Client)

	// Define the default DNS resolvers
	dnsResolvers := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", 
				"9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
				"84.200.69.80", "84.200.70.40", "2001:4860:4860::8888", "2001:4860:4860::8844",
				"213.196.191.96", "149.112.112.9"}

	// Create a mutex to protect map access
	var mutex sync.Mutex

	// Use maps for each record type to track unique records
	recordSets := map[uint16]map[string]bool{
		dns.TypeA:      make(map[string]bool),
		dns.TypeAAAA:   make(map[string]bool),
		dns.TypeCNAME:  make(map[string]bool),
		dns.TypeMX:     make(map[string]bool),
		dns.TypeNS:     make(map[string]bool),
		dns.TypeTXT:    make(map[string]bool),
		dns.TypeSOA:    make(map[string]bool),
		dns.TypeHINFO:  make(map[string]bool),
		dns.TypeSRV:    make(map[string]bool),
		dns.TypeCAA:    make(map[string]bool),
		dns.TypeLOC:    make(map[string]bool),
		dns.TypeDS:     make(map[string]bool),
		dns.TypeDNSKEY: make(map[string]bool),
	}
	
	// Map to store IPs for PTR lookups
	ipSet := make(map[string]bool)

	// Function to query DNS records
	queryDNS := func(recordType uint16, resolver string) {
		msg := new(dns.Msg)
		
		// Modify the query for SRV records
		if recordType == dns.TypeSRV {
			msg.SetQuestion(dns.Fqdn(fmt.Sprintf("_sip._tcp.%s", URL)), recordType)
		} else {
			msg.SetQuestion(dns.Fqdn(URL), recordType)
		}

		response, _, err := client.Exchange(msg, resolver+":53")
		if err != nil {
			// Silently fail to avoid cluttering output with errors
			return
		}

		for _, answer := range response.Answer {
			mutex.Lock() // Lock before accessing shared maps
			
			var key string
			
			switch recordType {
			case dns.TypeA:
				if a, ok := answer.(*dns.A); ok {
					ipStr := a.A.String()
					key = ipStr
					ipSet[ipStr] = true // Store IPs for PTR lookups
				}
			case dns.TypeAAAA:
				if aaaa, ok := answer.(*dns.AAAA); ok {
					key = aaaa.AAAA.String()
					ipSet[key] = true // Store IPv6 for PTR lookups
				}
			case dns.TypeCNAME:
				if cname, ok := answer.(*dns.CNAME); ok {
					key = cname.Target
				}
			case dns.TypeMX:
				if mx, ok := answer.(*dns.MX); ok {
					key = fmt.Sprintf("%d %s", mx.Preference, mx.Mx)
				}
			case dns.TypeNS:
				if ns, ok := answer.(*dns.NS); ok {
					key = ns.Ns
				}
			case dns.TypeTXT:
				if txt, ok := answer.(*dns.TXT); ok {
					key = strings.Join(txt.Txt, " ")
				}
			case dns.TypeSOA:
				if soa, ok := answer.(*dns.SOA); ok {
					key = fmt.Sprintf("%s %s %d %d %d %d %d", 
						soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
				}
			case dns.TypeHINFO:
				if hinfo, ok := answer.(*dns.HINFO); ok {
					key = fmt.Sprintf("%s %s", hinfo.Cpu, hinfo.Os)
				}
			case dns.TypeSRV:
				if srv, ok := answer.(*dns.SRV); ok {
					key = fmt.Sprintf("%s %d %d %d", srv.Target, srv.Port, srv.Priority, srv.Weight)
				}
			case dns.TypeCAA:
				if caa, ok := answer.(*dns.CAA); ok {
					key = fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value)
				}
			case dns.TypeLOC:
				if loc, ok := answer.(*dns.LOC); ok {
					key = fmt.Sprintf("%.6f %.6f %.6f %f %f %f", 
						loc.Latitude, loc.Longitude, loc.Altitude, loc.Size, loc.HorizPre, loc.VertPre)
				}
			case dns.TypeDS:
				if ds, ok := answer.(*dns.DS); ok {
					key = fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
				}
			case dns.TypeDNSKEY:
				if dnskey, ok := answer.(*dns.DNSKEY); ok {
					key = fmt.Sprintf("%d %d %d %s", 
						dnskey.KeyTag(), dnskey.Algorithm, dnskey.Flags, dnskey.PublicKey)
				}
			}
			
			if key != "" {
				recordSets[recordType][key] = true
			}
			
			mutex.Unlock() // Unlock after accessing shared maps
		}
	}

	// Create a WaitGroup for DNS queries
	var queryWg sync.WaitGroup

	// Query each record type from each resolver concurrently
	for recordType := range recordSets {
		for _, resolver := range dnsResolvers {
			queryWg.Add(1)
			go func(rt uint16, rs string) {
				defer queryWg.Done()
				queryDNS(rt, rs)
			}(recordType, resolver)
		}
	}

	// Wait for all DNS queries to complete
	queryWg.Wait()

	// Print results
	printRecordSet("A Records", recordSets[dns.TypeA])
	printRecordSet("AAAA Records", recordSets[dns.TypeAAAA])
	printRecordSet("CNAME Records", recordSets[dns.TypeCNAME])
	printRecordSet("MX Records", recordSets[dns.TypeMX])
	printRecordSet("NS Records", recordSets[dns.TypeNS])
	printRecordSet("TXT Records", recordSets[dns.TypeTXT])
	printRecordSet("SOA Records", recordSets[dns.TypeSOA], formatSOA)
	printRecordSet("HINFO Records", recordSets[dns.TypeHINFO], formatHINFO)
	printRecordSet("SRV Records", recordSets[dns.TypeSRV], formatSRV)
	printRecordSet("CAA Records", recordSets[dns.TypeCAA], formatCAA)
	printRecordSet("LOC Records", recordSets[dns.TypeLOC], formatLOC)
	printRecordSet("DS Records", recordSets[dns.TypeDS], formatDS)
	printRecordSet("DNSKEY Records", recordSets[dns.TypeDNSKEY], formatDNSKEY)

	// Now perform PTR lookups for all discovered IPs
	if len(ipSet) > 0 {
		fmt.Println("\nPTR Records:")
		
		var ptrWg sync.WaitGroup
		ptrResults := make(map[string]string)
		var ptrMutex sync.Mutex
		
		for ip := range ipSet {
			ptrWg.Add(1)
			go func(ipAddr string) {
				defer ptrWg.Done()
				
				for _, resolver := range dnsResolvers {
					reverseIP, err := dns.ReverseAddr(ipAddr)
					if err != nil {
						continue
					}
					
					msgPTR := new(dns.Msg)
					msgPTR.SetQuestion(reverseIP, dns.TypePTR)
					
					responsePTR, _, err := client.Exchange(msgPTR, resolver+":53")
					if err != nil {
						continue
					}
					
					for _, answer := range responsePTR.Answer {
						if ptr, ok := answer.(*dns.PTR); ok {
							ptrMutex.Lock()
							ptrResults[ipAddr] = ptr.Ptr
							ptrMutex.Unlock()
							return // Found a result, no need to try other resolvers
						}
					}
				}
			}(ip)
		}
		
		ptrWg.Wait()
		
		if len(ptrResults) > 0 {
			for ip, ptr := range ptrResults {
				fmt.Printf("- %s -> %s\n", ip, ptr)
			}
		} else {
			fmt.Println("- No PTR records found")
		}
	}
}

// Perform PTR lookup specifically for IP addresses
func performPTRLookup(ip string) {
	client := new(dns.Client)
	dnsResolvers := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", 
				"9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
				"84.200.69.80", "84.200.70.40", "2001:4860:4860::8888", "2001:4860:4860::8844",
				"213.196.191.96", "149.112.112.9"}
	
	fmt.Println("PTR Records:")
	
	reverseIP, err := dns.ReverseAddr(ip)
	if err != nil {
		fmt.Printf("Error creating reverse IP for %s: %v\n", ip, err)
		return
	}
	
	found := false
	
	for _, resolver := range dnsResolvers {
		msgPTR := new(dns.Msg)
		msgPTR.SetQuestion(reverseIP, dns.TypePTR)
		
		responsePTR, _, err := client.Exchange(msgPTR, resolver+":53")
		if err != nil {
			continue
		}
		
		for _, answer := range responsePTR.Answer {
			if ptr, ok := answer.(*dns.PTR); ok {
				fmt.Printf("- %s -> %s (from %s)\n", ip, ptr.Ptr, resolver)
				found = true
			}
		}
	}
	
	if !found {
		fmt.Println("- No PTR records found for this IP address")
	}
}

// Helper function to print record sets with optional custom formatter
func printRecordSet(title string, records map[string]bool, formatter ...func(string) string) {
	fmt.Printf("\n%s:\n", title)
	if len(records) == 0 {
		fmt.Println("- No records found")
		return
	}
	
	// Convert map to sorted slice for consistent output
	var recordList []string
	for record := range records {
		recordList = append(recordList, record)
	}
	
	// If a formatter is provided, use it
	if len(formatter) > 0 && formatter[0] != nil {
		for _, record := range recordList {
			fmt.Println(formatter[0](record))
		}
	} else {
		// Otherwise just print the records
		for _, record := range recordList {
			fmt.Printf("- %s\n", record)
		}
	}
}

// Format functions for different record types
func formatSOA(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 7 {
		return fmt.Sprintf("- Primary NS: %s\n  Email: %s\n  Serial: %s\n  Refresh: %s\n  Retry: %s\n  Expire: %s\n  Minimum TTL: %s",
			parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6])
	}
	return "- " + record
}

func formatHINFO(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 2 {
		return fmt.Sprintf("- CPU: %s, OS: %s", parts[0], parts[1])
	}
	return "- " + record
}

func formatSRV(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 4 {
		return fmt.Sprintf("- Target: %s, Port: %s, Priority: %s, Weight: %s", 
			parts[0], parts[1], parts[2], parts[3])
	}
	return "- " + record
}

func formatCAA(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 3 {
		return fmt.Sprintf("- Flag: %s, Tag: %s, Value: %s", parts[0], parts[1], parts[2])
	}
	return "- " + record
}

func formatLOC(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 6 {
		return fmt.Sprintf("- Latitude: %s°\n  Longitude: %s°\n  Altitude: %sm\n  Size: %sm\n  Horizontal Precision: %sm\n  Vertical Precision: %sm",
			parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
	}
	return "- " + record
}

func formatDS(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 4 {
		return fmt.Sprintf("- Key Tag: %s\n  Algorithm: %s\n  Digest Type: %s\n  Digest: %s",
			parts[0], parts[1], parts[2], parts[3])
	}
	return "- " + record
}

func formatDNSKEY(record string) string {
	parts := strings.Split(record, " ")
	if len(parts) >= 4 {
		return fmt.Sprintf("- Key Tag: %s\n  Algorithm: %s\n  Flags: %s\n  Public Key: %s",
			parts[0], parts[1], parts[2], parts[3])
	}
	return "- " + record
}
