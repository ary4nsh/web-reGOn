package main

import(
	"fmt"
	"flag"
	"os"
	"sync"
	"Project/libs"
)

const maxURLLength = 100

func main(){
	httpFlag := flag.String("h", "", "HTTP Status Code")
	dnsFlag := flag.String("d", "", "DNS Records")
	flag.Parse()
	
	var wg sync.WaitGroup
	
	if *httpFlag != ""{
		if len(*httpFlag) > maxURLLength {
			fmt.Printf("Error: URL for -d exceeds %d characters\n", maxURLLength)
			os.Exit(1)
		}
		wg.Add(1)
		go libs.HttpResponse(*httpFlag, &wg)
	}
	if *dnsFlag != ""{
		if len(*dnsFlag) > maxURLLength {
			fmt.Printf("Error: URL for -h exceeds %d characters\n", maxURLLength)
			os.Exit(1)
		}
		wg.Add(1)
		go libs.DnsRecords(*dnsFlag, &wg)
	}
	
	if *httpFlag == "" && *dnsFlag == ""{
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	wg.Wait()
}
