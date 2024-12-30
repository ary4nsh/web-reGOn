package main

import(
	"fmt"
	"net"
	"net/http"
	"net/url"
	"bufio"
	"os"
)

const (
	Reset = "\033[0m" //reset colors back to default after printing the colored texts
	Red = "\033[31m"
	Blue = "\033[34m"
	Green = "\033[32m"
	Orange = "\033[38;5;214m" //using 256-color mode
)

func HTTPResponse(URL string) {
	fmt.Println()
	resp, err := http.Get(URL)
	if err != nil {
		fmt.Println("Connection was not establiched")
	}

	defer resp.Body.Close()
	
	switch resp.StatusCode {

	//Informational Responses
	case 100:
		fmt.Printf("%s [100]: Continue\n", URL)
	case 101:
		fmt.Printf("%s [101]: Switching Protocols\n", URL)
	case 103:
		fmt.Printf("%s [103]: Early Hints\n", URL)


	//Successful Responses
	case 200:
		fmt.Printf("%s %s[200]: OK%s\n", URL, Green, Reset)
	case 201:
		fmt.Printf("%s %s[201]: Created%s\n", URL, Green, Reset)
	case 202:
		fmt.Printf("%s %s[202]: Accepted%s\n", URL, Green, Reset)
	case 203:
		fmt.Printf("%s %s[203]: Non-Authoritative Information%s\n", URL, Green, Reset)
	case 204:
		fmt.Printf("%s %s[204]: No Content%s\n", URL, Green, Reset)
	case 205:
		fmt.Printf("%s %s[205]: Reset Content%s\n", URL, Green, Reset)
	case 206:
		fmt.Printf("%s %s[206]: Partial Content%s\n", URL, Green, Reset)
	case 207:
		fmt.Printf("%s %s[207]: Multi-Status (WebDAV)%s\n", URL, Green, Reset)
	case 208:
		fmt.Printf("%s %s[208]: Already Reported (WebDAV)%s\n", URL, Green, Reset)


	//Redirection Messages
	case 300:
		fmt.Printf("%s %s[300]: Multiple Choices%s\n", URL, Blue, Reset)
	case 301:
		fmt.Printf("%s %s[301]: Moved Permanently%s\n", URL, Blue, Reset)
	case 302:
		fmt.Printf("%s %s[302]: Found%s\n", URL, Blue, Reset)
	case 303:
		fmt.Printf("%s %s[303]: See Other%s\n", URL, Blue, Reset)
	case 304:
		fmt.Printf("%s %s[304]: Not Modified%s\n", URL, Blue, Reset)
	case 307:
		fmt.Printf("%s %s[307]: Temporary Redirect%s\n", URL, Blue, Reset)
	case 308:
		fmt.Printf("%s %s[308]: Permanent Redirect%s\n", URL, Blue, Reset)


	//Client Error Responses
	case 400:
		fmt.Printf("%s %s[400]: Bad Request%s\n", URL, Red, Reset)
	case 401:
		fmt.Printf("%s %s[401]: Unauthorized%s\n", URL, Red, Reset)
	case 403:
		fmt.Printf("%s %s[403]: Forbidden%s\n", URL, Red, Reset)
	case 404:
		fmt.Printf("%s %s[404]: Not Found%s\n", URL, Red, Reset)
	case 405:
		fmt.Printf("%s %s[405]: Method Not Allowed%s\n", URL, Red, Reset)
	case 406:
		fmt.Printf("%s %s[406]: Not Acceptable%s\n", URL, Red, Reset)
	case 407:
		fmt.Printf("%s %s[407]: Proxy Authentication Required%s\n", URL, Red, Reset)
	case 408:
		fmt.Printf("%s %s[408]: Request Timeout%s\n", URL, Red, Reset)
	case 409:
		fmt.Printf("%s %s[409]: Conflict%s\n", URL, Red, Reset)
	case 410:
		fmt.Printf("%s %s[410]: Gone%s\n", URL, Red, Reset)
	case 411:
		fmt.Printf("%s %s[411]: Length Required%s\n", URL, Red, Reset)
	case 412:
		fmt.Printf("%s %s[412]: Precondition Failed%s\n", URL, Red, Reset)
	case 413:
		fmt.Printf("%s %s[413]: Content Too Large%s\n", URL, Red, Reset)
	case 414:
		fmt.Printf("%s %s[414]: URI Too Long%s\n", URL, Red, Reset)
	case 415:
		fmt.Printf("%s %s[415]: Unsupported Media Type%s\n", URL, Red, Reset)
	case 416:
		fmt.Printf("%s %s[416]: Range Not Satisfiable%s\n", URL, Red, Reset)
	case 417:
		fmt.Printf("%s %s[417]: Expectation Failed%s\n", URL, Red, Reset)
	case 421:
		fmt.Printf("%s %s[421]: Misdirected Request%s\n", URL, Red, Reset)
	case 422:
		fmt.Printf("%s %s[422]: Unprocessable Content (WebDAV)%s\n", URL, Red, Reset)
	case 423:
		fmt.Printf("%s %s[423]: Locked (WebDAV)%s\n", URL, Red, Reset)
	case 424:
		fmt.Printf("%s %s[424]: Failed Dependency (WebDAV)%s\n", URL, Red, Reset)
	case 426:
		fmt.Printf("%s %s[426]: Upgrade Required%s\n", URL, Red, Reset)
	case 428:
		fmt.Printf("%s %s[428]: Precondition Required%s\n", URL, Red, Reset)
	case 429:
		fmt.Printf("%s %s[429]: Too Many Requests%s\n", URL, Red, Reset)
	case 431:
		fmt.Printf("%s %s[431]: Request Header Fields Too Large%s\n", URL, Red, Reset)
	case 451:
		fmt.Printf("%s %s[451]: Unavailable For Legal Reasons%s\n", URL, Red, Reset)


	//Server Error Responses
	case 500:
		fmt.Printf("%s %s[500]: Internal Server Error%s\n", URL, Orange, Reset)
	case 501:
		fmt.Printf("%s %s[501]: Not Implemented%s\n", URL, Orange, Reset)
	case 502:
		fmt.Printf("%s %s[502]: Bad Gateway%s\n", URL, Orange, Reset)
	case 503:
		fmt.Printf("%s %s[503]: Service Unavailable%s\n", URL, Orange, Reset)
	case 504:
		fmt.Printf("%s %s[504]: Gateway Timeout%s\n", URL, Orange, Reset)
	case 505:
		fmt.Printf("%s %s[505]: HTTP Version Not Supported%s\n", URL, Orange, Reset)
	case 506:
		fmt.Printf("%s %s[506]: Variant Also Negotiates%s\n", URL, Orange, Reset)
	case 507:
		fmt.Printf("%s %s[507]: Insufficient Storage (WebDAV)%s\n", URL, Orange, Reset)
	case 508:
		fmt.Printf("%s %s[508]: Loop Detected (WebDAV)%s\n", URL, Orange, Reset)
	case 511:
		fmt.Printf("%s %s[511]: Network Authentication Required%s\n", URL, Orange, Reset)

	
	default:
		fmt.Println("---")
	}
}

func DNSRecords(URL string){

	//Look up ip address
	fmt.Println()
	ip, err := net.LookupIP(URL)
	if err != nil {
		fmt.Println("Error retrieving IP address")
	}
	fmt.Printf("IP Address: %s\n", ip)
	

	//Look up CNAME record
	fmt.Println()
	cname, err1 := net.LookupCNAME(URL)
	if err1 != nil {
		fmt.Println("Error retrieving CNAME record")
	}
	fmt.Printf("CNAME Record: %s\n", cname)


	//Lokup MX record
	fmt.Println()
	MX, err2 := net.LookupMX(URL)
	if err2 != nil {
		fmt.Printf("Error retrieving MX record: %v\n", err2)
	} else {
		fmt.Printf("MX Records:\n")
		for _, mx := range MX {
			fmt.Printf("Host: %s, Priority: %d\n", mx.Host, mx.Pref)
		}
	}


	//Look up NS record
	fmt.Println()
	NS, err3 := net.LookupNS(URL)
	if err3 != nil {
		fmt.Println("Error retrieving NS record: %v\n", err3)
	} else {
		fmt.Printf("NS Records:\n")
		for _, ns := range NS {
			fmt.Println(ns.Host)
		}
	}
}


// checkURL validates the URL and checks if it exists.
func checkURL(URL string) (bool, error) {
	// Parse the URL
	parsedURL, err := url.Parse(URL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false, fmt.Errorf("invalid URL: %v", err)
	}

	// Check if the URL exists by sending a HEAD request
	resp, err := http.Head(parsedURL.String())
	if err != nil {
		return false, fmt.Errorf("error checking URL existence: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, nil // URL is valid and exists
	}
	return false, fmt.Errorf("the URL returned status code: %d", resp.StatusCode)
}


func main(){
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter a URL (http(s)://url.com): ")

	// Read the input from the user
	URL, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}

	// Remove any trailing newline character
	URL = URL[:len(URL)-1]

	// Call the checkURL function
	exists, err := checkURL(URL)
	if err != nil {
		fmt.Println(err)
		return
	}

	if exists {
		fmt.Println("The URL is valid and exists.")
	} else {
		fmt.Println("The URL is valid but does not exist.")
	}

	fmt.Println()
	var number int

	fmt.Println("Choose your option:")
	fmt.Println("1 (HTTP response status code)")
	fmt.Println("2 (DNS records)")
	_, err = fmt.Scanf("%d", &number)
	if err != nil {
		fmt.Println("Invalid input. Please enter a valid number.")
		return
	}

	switch number {
	case 1:
		HTTPResponse(URL)
	case 2:
		DNSRecords(URL)
	default:
		fmt.Println("Invalid option selected")
	}
}





