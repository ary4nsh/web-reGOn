package libs

import(
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

func DnsRecords(URL string, dnsResolver string, wg *sync.WaitGroup){

	// Create a new DNS client
	client := new(dns.Client)

	//Look up IP address ---------------------------------------------------------------------------
	fmt.Printf("IP Address:\n")
	
	var ip []net.IP
	var err error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		msgIP := new(dns.Msg)
		msgIP.SetQuestion(dns.Fqdn(URL), dns.TypeA) // Query for A records

		// Send the query to the specified DNS server
		response, _, err := client.Exchange(msgIP, dnsResolver+":53")
		if err != nil {
			fmt.Printf("Error retrieving IP address using resolver %s: %v\n", dnsResolver, err)
		} else {
			for _, answer := range response.Answer {
				if aRecord, ok := answer.(*dns.A); ok {
					ip = append(ip, net.ParseIP(aRecord.A.String()))
				}
			}
		}
	} else {
		// Use the system's default resolver
		ip, err = net.LookupIP(URL)
		if err != nil {
			fmt.Printf("Error retrieving IP address: %v\n", err)
		}
	}

	// Print the results
	if len(ip) == 0 {
		fmt.Println("- No A record was found")
	} else {
		for _, addr := range ip {
			fmt.Printf("- %s\n", addr.String())
		}
	}


	//Look up CNAME record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("CNAME Record:\n")

	var cname string
	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		msgCNAME := new(dns.Msg)
		msgCNAME.SetQuestion(dns.Fqdn(URL), dns.TypeCNAME)

		// Send the query to the specified DNS server
		responseCNAME, _, err := client.Exchange(msgCNAME, dnsResolver+":53")
		if err != nil {
			fmt.Printf("Error retrieving CNAME record using resolver %s: %v\n", dnsResolver, err)
		} else {
			for _, answer := range responseCNAME.Answer {
				if cnameRecord, ok := answer.(*dns.CNAME); ok {
					cname = cnameRecord.Target
					break
				}
			}
		}
	} else {
		// Use the system's default resolver
		cname, err = net.LookupCNAME(URL)
		if err != nil {
			fmt.Printf("Error retrieving CNAME record: %v\n", err)
		}
	}

	if cname == "" {
		fmt.Println("- No CNAME record was found")
	} else {
		fmt.Printf("- %s\n", cname)
	}


	//Lokup MX record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("MX Records:\n")

	var MX []*net.MX
	var err2 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		msgMX := new(dns.Msg)
		msgMX.SetQuestion(dns.Fqdn(URL), dns.TypeMX)

		// Send the query to the specified DNS server
		responseMX, _, err := client.Exchange(msgMX, dnsResolver+":53")
		if err != nil {
			fmt.Printf("Error retrieving MX records using resolver %s: %v\n", dnsResolver, err)
		} else {
			for _, answer := range responseMX.Answer {
				if mxRecord, ok := answer.(*dns.MX); ok {
					MX = append(MX, &net.MX{Host: mxRecord.Mx, Pref: mxRecord.Preference})
				}
			}
		}
	} else {
		// Use the system's default resolver
		MX, err2 = net.LookupMX(URL)
		if err2 != nil {
			fmt.Printf("Error retrieving MX records: %v\n", err2)
		}
	}

	// Print the results
	if len(MX) == 0 {
		fmt.Println("- No MX record was found")
	} else {
		for _, mx := range MX {
			fmt.Printf("- Host: %s, Priority: %d\n", mx.Host, mx.Pref)
		}
	}


	//Look up NS record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("NS Records:\n")

	var NSRecords []*net.NS
	var err3 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		msgNS := new(dns.Msg)
		msgNS.SetQuestion(dns.Fqdn(URL), dns.TypeNS)

		// Send the query to the specified DNS server
		responseNS, _, err := client.Exchange(msgNS, dnsResolver+":53")
		if err != nil {
			fmt.Printf("Error retrieving NS records using resolver %s: %v\n", dnsResolver, err)
		} else {
			for _, answer := range responseNS.Answer {
				if nsRecord, ok := answer.(*dns.NS); ok {
					NSRecords = append(NSRecords, &net.NS{Host: nsRecord.Ns}) // Use nsRecord.Ns
				}
			}
		}
	} else {
		// Use the system's default resolver
		NSRecords, err3 = net.LookupNS(URL)
		if err3 != nil {
			fmt.Printf("Error retrieving NS records: %v\n", err3)
		}
	}

	// Print the results
	if len(NSRecords) == 0 {
		fmt.Println("- No NS record was found")
	} else {
		for _, ns := range NSRecords {
			fmt.Printf("- %s\n", ns.Host)
		}
	}
	
	
	//Look up TXT record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("TXT records:\n")

	var TXTRecords []string
	var err4 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		msgTXT := new(dns.Msg)
		msgTXT.SetQuestion(dns.Fqdn(URL), dns.TypeTXT)

		// Send the query to the specified DNS server
		responseTXT, _, err := client.Exchange(msgTXT, dnsResolver+":53")
		if err != nil {
			fmt.Printf("Error retrieving TXT records using resolver %s: %v\n", dnsResolver, err)
		} else {
			for _, answer := range responseTXT.Answer {
				if txtRecord, ok := answer.(*dns.TXT); ok {
					TXTRecords = append(TXTRecords, txtRecord.Txt...) // Append all TXT records
				}
			}
		}
	} else {
		// Use the system's default resolver
		TXTRecords, err4 = net.LookupTXT(URL)
		if err4 != nil {
			fmt.Printf("Error retrieving TXT records: %v\n", err4)
		}
	}

	// Print the results
	if len(TXTRecords) == 0 {
		fmt.Println("- No TXT record was found")
	} else {
		for _, txt := range TXTRecords {
			fmt.Printf("- %s\n", txt)
		}
	}	
	
	
	//Look up PTR record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("PTR records:\n")
	foundPTR := false // Flag to track if any PTR records are found

	if len(ip) == 0 {
		fmt.Println("- No IP addresses available for PTR lookup")
	}

	for _, ipAddr := range ip {
		if dnsResolver != "" {
			// Use the user-provided DNS resolver
			msgPTR := new(dns.Msg)
			msgPTR.SetQuestion(dns.Fqdn(ipAddr.String()), dns.TypePTR)

			// Send the query to the specified DNS server
			responsePTR, _, err := client.Exchange(msgPTR, dnsResolver+":53")
			if err != nil {
				fmt.Printf("Error looking up PTR record using resolver %s: %v\n", dnsResolver, err)
				continue
			}

			for _, answer := range responsePTR.Answer {
				if ptrRecord, ok := answer.(*dns.PTR); ok {
					foundPTR = true
					fmt.Printf("- %s\n", ptrRecord.Ptr)
				}
			}
		} else {
			// Use the system's default resolver
			PTR, err5 := net.LookupAddr(ipAddr.String())
			if err5 != nil {
				fmt.Printf("Error looking up PTR record: %v\n", err5)
				continue
			} else {
				foundPTR = true // Set the flag to true if at least one PTR record is found
				for _, ptr := range PTR {
					fmt.Printf("- %s\n", ptr)
				}
			}
		}
	}

	if !foundPTR {
		fmt.Println("- No PTR record was found")
	}

	
	//Look up SOA record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("SOA records:\n")

	// Create a new DNS message
	msgSOA := new(dns.Msg)
	msgSOA.SetQuestion(dns.Fqdn(URL), dns.TypeSOA)

	// Determine the DNS server to use
	var responseSOA *dns.Msg
	var err6 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		responseSOA, _, err6 = client.Exchange(msgSOA, dnsResolver+":53")
		if err6 != nil {
			fmt.Printf("Failed to get SOA record using resolver %s: %v\n", dnsResolver, err6)
		} else if responseSOA == nil || len(responseSOA.Answer) == 0 {
			fmt.Println("- No SOA record was found")
		} else {
			// Iterate through the answers and print SOA records
			for _, answer := range responseSOA.Answer {
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
		}
	} else {
		// Use the Google's default resolver
		responseSOA, _, err6 = client.Exchange(msgSOA, "8.8.8.8:53")
		if err6 != nil {
			fmt.Printf("Failed to get SOA record using system resolver: %v\n", err6)
		} else if responseSOA == nil || len(responseSOA.Answer) == 0 {
			fmt.Println("- No SOA record was found")
		} else {
			// Iterate through the answers and print SOA records
			for _, answer := range responseSOA.Answer {
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
		}
	}
	
	
	//Look up HINFO record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("HINFO record:\n")
	
	// Create a new DNS message for HINFO
	msgHINFO := new(dns.Msg)
	msgHINFO.SetQuestion(dns.Fqdn(URL), dns.TypeHINFO)

	// Determine the DNS server to use
	var responseHINFO *dns.Msg
	var err7 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		responseHINFO, _, err7 = client.Exchange(msgHINFO, dnsResolver+":53")
		if err7 != nil {
			fmt.Printf("Failed to query DNS for HINFO using resolver %s: %v\n", dnsResolver, err7)
		} else if responseHINFO == nil || responseHINFO.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get HINFO records: %v\n", responseHINFO.Rcode)
		} else {
			// Flag to track if any HINFO records were found
			foundHINFO := false

			// Iterate through the answer section and print HINFO records
			for _, answer := range responseHINFO.Answer {
				if hinfo, ok := answer.(*dns.HINFO); ok {
					fmt.Printf("- HINFO Record: CPU=%s, OS=%s\n", hinfo.Cpu, hinfo.Os)
					foundHINFO = true // Set the flag to true if at least one HINFO record is found
				}
			}

			if !foundHINFO {
				fmt.Println("- No HINFO record was found")
			}
		}
	} else {
		// Use the Google's default resolver
		responseHINFO, _, err7 = client.Exchange(msgHINFO, "8.8.8.8:53")
		if err7 != nil {
			fmt.Printf("Failed to query DNS for HINFO using system resolver: %v\n", err7)
		} else if responseHINFO == nil || responseHINFO.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get HINFO records: %v\n", responseHINFO.Rcode)
		} else {
			// Flag to track if any HINFO records were found
			foundHINFO := false

			// Iterate through the answer section and print HINFO records
			for _, answer := range responseHINFO.Answer {
				if hinfo, ok := answer.(*dns.HINFO); ok {
					fmt.Printf("- HINFO Record: CPU=%s, OS=%s\n", hinfo.Cpu, hinfo.Os)
					foundHINFO = true // Set the flag to true if at least one HINFO record is found
				}
			}

			if !foundHINFO {
				fmt.Println("- No HINFO record was found")
			}
		}
	}

	
	
	//Look up SRV records ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("SRV records:\n")
	
	// Define the service, protocol, and domain
	service := "_sip"
	protocol := "_tcp"

	// Create a new DNS message for SRV
	msgSRV := new(dns.Msg)
	msgSRV.SetQuestion(dns.Fqdn(fmt.Sprintf("_%s._%s.%s", service, protocol, URL)), dns.TypeSRV)

	// Determine the DNS server to use
	var responseSRV *dns.Msg
	var err8 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		responseSRV, _, err8 = client.Exchange(msgSRV, dnsResolver+":53")
		if err8 != nil {
			fmt.Printf("Failed to query DNS for SRV using resolver %s: %v\n", dnsResolver, err8)
		} else if responseSRV == nil || responseSRV.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get SRV records: %v\n", responseSRV.Rcode)
		} else {
			// Flag to track if any SRV records were found
			foundSRV := false

			// Iterate through the answer section and print SRV records
			for _, answer := range responseSRV.Answer {
				if srv, ok := answer.(*dns.SRV); ok {
					fmt.Printf("- Name: %s, Port: %d, Priority: %d, Weight: %d\n", srv.Target, srv.Port, srv.Priority, srv.Weight)
					foundSRV = true // Set the flag to true if at least one SRV record is found
				}
			}

			if !foundSRV {
				fmt.Println("- No SRV record was found")
			}
		}
	} else {
		// Use the Google's default resolver
		responseSRV, _, err8 = client.Exchange(msgSRV, "8.8.8.8:53")
		if err8 != nil {
			fmt.Printf("Failed to query DNS for SRV using system resolver: %v\n", err8)
		} else if responseSRV == nil || responseSRV.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get SRV records: %v\n", responseSRV.Rcode)
		} else {
			// Flag to track if any SRV records were found
			foundSRV := false

			// Iterate through the answer section and print SRV records
			for _, answer := range responseSRV.Answer {
				if srv, ok := answer.(*dns.SRV); ok {
					fmt.Printf("- Name: %s, Port: %d, Priority: %d, Weight: %d\n", srv.Target, srv.Port, srv.Priority, srv.Weight)
					foundSRV = true // Set the flag to true if at least one SRV record is found
				}
			}

			if !foundSRV {
				fmt.Println("- No SRV record was found")
			}
		}
	}

	
	
	//Look up CAA records ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("CAA Records:\n")

	// Create a new DNS message for CAA
	msgCAA := new(dns.Msg)
	msgCAA.SetQuestion(dns.Fqdn(URL), dns.TypeCAA)

	// Determine the DNS server to use
	var responseCAA *dns.Msg
	var err9 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		responseCAA, _, err9 = client.Exchange(msgCAA, dnsResolver+":53")
		if err9 != nil {
			fmt.Printf("Failed to query DNS for CAA using resolver %s: %v\n", dnsResolver, err9)
		} else if responseCAA == nil || responseCAA.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get CAA records: %v\n", responseCAA.Rcode)
		} else {
			// Flag to track if any CAA records were found
			foundCAA := false

			// Iterate through the answer section and print CAA records
			for _, answer := range responseCAA.Answer {
				if caa, ok := answer.(*dns.CAA); ok {
					fmt.Printf("- Tag: %s, Value: %s\n", caa.Tag, caa.Value)
					foundCAA = true // Set the flag to true if at least one CAA record is found
				}
			}

			if !foundCAA {
				fmt.Println("- No CAA record was found")
			}
		}
	} else {
		// Use the Google's default resolver
		responseCAA, _, err9 = client.Exchange(msgCAA, "8.8.8.8:53")
		if err9 != nil {
			fmt.Printf("Failed to query DNS for CAA using system resolver: %v\n", err9)
		} else if responseCAA == nil || responseCAA.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get CAA records: %v\n", responseCAA.Rcode)
		} else {
			// Flag to track if any CAA records were found
			foundCAA := false

			// Iterate through the answer section and print CAA records
			for _, answer := range responseCAA.Answer {
				if caa, ok := answer.(*dns.CAA); ok {
					fmt.Printf("- Tag: %s, Value: %s\n", caa.Tag, caa.Value)
					foundCAA = true // Set the flag to true if at least one CAA record is found
				}
			}

			if !foundCAA {
				fmt.Println("- No CAA record was found")
			}
		}
	}
	
	
	//Look up LOC record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("LOC Records:\n")

	var locRecords []dns.RR

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		msgLOC := new(dns.Msg)
		msgLOC.SetQuestion(dns.Fqdn(URL), dns.TypeLOC)

		responseLOC, _, err10 := client.Exchange(msgLOC, dnsResolver+":53")
		if err10 != nil {
			fmt.Printf("Failed to query DNS for LOC using resolver %s: %v\n", dnsResolver, err10)
		} else if responseLOC.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get LOC records: %v\n", responseLOC.Rcode)
		} else {
			locRecords = responseLOC.Answer
		}
	} else {
		// Use the system's default resolver
		msgLOC := new(dns.Msg)
		msgLOC.SetQuestion(dns.Fqdn(URL), dns.TypeLOC)

		// Send the query to the Google's DNS server
		responseLOC, _, err10 := client.Exchange(msgLOC, "8.8.8.8:53")
		if err10 != nil {
			fmt.Printf("Failed to query DNS for LOC using system default resolver: %v\n", err10)
		} else if responseLOC.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get LOC records: %v\n", responseLOC.Rcode)
		} else {
			locRecords = responseLOC.Answer
		}
	}

	// Flag to track if any LOC records were found
	foundLOC := false

	// Iterate through the answer section and print LOC records
	for _, answer := range locRecords {
		if loc, ok := answer.(*dns.LOC); ok {
			fmt.Printf("- Latitude: %f\n- Longitude: %f\n- Altitude: %f\n- Size: %f\n- Horizontal Precision: %f\n- Vertical Precision: %f\n", loc.Latitude, loc.Longitude, loc.Altitude, loc.Size, loc.HorizPre, loc.VertPre)
			foundLOC = true // Set the flag to true if at least one LOC record is found
		}
	}

	if !foundLOC {
		fmt.Println("- No LOC record was found")
	}
	
	
	//Look up DS record ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("DS Records:\n")

	// Create a new DNS message for DS
	msgDS := new(dns.Msg)
	msgDS.SetQuestion(dns.Fqdn(URL), dns.TypeDS)

	// Determine the DNS server to use
	var responseDS *dns.Msg
	var err11 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		responseDS, _, err11 = client.Exchange(msgDS, dnsResolver+":53")
		if err11 != nil {
			fmt.Printf("Failed to query DNS for DS using resolver %s: %v\n", dnsResolver, err11)
		} else if responseDS == nil || responseDS.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get DS records: %v\n", responseDS.Rcode)
		} else {
			// Flag to track if any DS records were found
			foundDS := false

			// Iterate through the answer section and print DS records
			for _, answer := range responseDS.Answer {
				if ds, ok := answer.(*dns.DS); ok {
					fmt.Printf("- Key Tag: %d\n- Algorithm: %d\n- Digest Type: %d\n- Digest: %s\n", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
					foundDS = true // Set the flag to true if at least one DS record is found
				}
			}

			if !foundDS {
				fmt.Println("- No DS record was found")
			}
		}
	} else {
		// Use Google's default resolver
		responseDS, _, err11 = client.Exchange(msgDS, "8.8.8.8:53")
		if err != nil {
			fmt.Printf("Failed to query DNS for DS using system resolver: %v\n", err11)
		} else if responseDS == nil || responseDS.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get DS records: %v\n", responseDS.Rcode)
		} else {
			// Flag to track if any DS records were found
			foundDS := false

			// Iterate through the answer section and print DS records
			for _, answer := range responseDS.Answer {
				if ds, ok := answer.(*dns.DS); ok {
					fmt.Printf("- Key Tag: %d\n- Algorithm: %d\n- Digest Type: %d\n- Digest: %s\n", ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest)
					foundDS = true // Set the flag to true if at least one DS record is found
				}
			}

			if !foundDS {
				fmt.Println("- No DS record was found")
			}
		}
	}
	
	
	//Look up DNSKEY records ---------------------------------------------------------------------------
	fmt.Println()
	fmt.Printf("DNSKEY Records:\n")

	// Create a new DNS message for DNSKEY
	msgDNSKEY := new(dns.Msg)
	msgDNSKEY.SetQuestion(dns.Fqdn(URL), dns.TypeDNSKEY)

	// Determine the DNS server to use
	var responseDNSKEY *dns.Msg
	var err12 error

	if dnsResolver != "" {
		// Use the user-provided DNS resolver
		responseDNSKEY, _, err12 = client.Exchange(msgDNSKEY, dnsResolver+":53")
		if err12 != nil {
			fmt.Printf("Failed to query DNS for DNSKEY using resolver %s: %v\n", dnsResolver, err12)
		} else if responseDNSKEY == nil || responseDNSKEY.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get DNSKEY records: %v\n", responseDNSKEY.Rcode)
		} else {
			// Flag to track if any DNSKEY records were found
			foundDNSKEY := false

			// Iterate through the answer section and print DNSKEY records
			for _, answer := range responseDNSKEY.Answer {
				if dnskey, ok := answer.(*dns.DNSKEY); ok {
					fmt.Printf("- Key Tag: %d\n- Algorithm: %d\n- Flags: %d\n- Public Key: %s\n", dnskey.KeyTag, dnskey.Algorithm, dnskey.Flags, dnskey.PublicKey)
					foundDNSKEY = true // Set the flag to true if at least one DNSKEY record is found
				}
			}

			if !foundDNSKEY {
				fmt.Println("- No DNSKEY record was found")
			}
		}
	} else {
		// Use Google's default resolver
		responseDNSKEY, _, err12 = client.Exchange(msgDNSKEY, "8.8.8.8:53")
		if err12 != nil {
			fmt.Printf("Failed to query DNS for DNSKEY using system resolver: %v\n", err12)
		} else if responseDNSKEY == nil || responseDNSKEY.Rcode != dns.RcodeSuccess {
			fmt.Printf("Failed to get DNSKEY records: %v\n", responseDNSKEY.Rcode)
		} else {
			// Flag to track if any DNSKEY records were found
			foundDNSKEY := false

			// Iterate through the answer section and print DNSKEY records
			for _, answer := range responseDNSKEY.Answer {
				if dnskey, ok := answer.(*dns.DNSKEY); ok {
					fmt.Printf("- Key Tag: %d\n- Algorithm: %d\n- Flags: %d\n- Public Key: %s\n", dnskey.KeyTag, dnskey.Algorithm, dnskey.Flags, dnskey.PublicKey)
					foundDNSKEY = true // Set the flag to true if at least one DNSKEY record is found
				}
			}

			if !foundDNSKEY {
				fmt.Println("- No DNSKEY record was found")
			}
		}
	}
}
