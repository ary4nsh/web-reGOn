package libs

import(
	"fmt"
	"net"
	"sync"
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
}
