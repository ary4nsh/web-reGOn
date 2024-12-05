package main
import(
	"fmt"
	"net/http"
	"os"
	"bufio"
	"strings"
)

const (
	Reset = "\033[0m" //reset colors back to default after printing the colored texts
	Red = "\033[31m"
	Blue = "\033[34m"
	Green = "\033[32m"
	Orange = "\033[38;5;214m" //using 256-color mode
)

func main(){
	fmt.Println("Enter the URL (http://url.com): ")
	read := bufio.NewReader(os.Stdin)
	url, _ := read.ReadString('\n')
	
	url = strings.TrimSpace(url) //trim whitespace from url
	
	if url == ""{
		fmt.Println("Enter a valid URL: ")
		return
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Connection was not establiched")
		return
	}

	defer resp.Body.Close()
	
	switch resp.StatusCode {
	//Successful Responses
	case 200:
		fmt.Printf("%s %s[200]: OK%s", url, Green, Reset)
		
	//Client Error Responses
	case 400:
		fmt.Printf("%s %s[400]: Bad Request", url, Orange, Reset)
	case 401:
		fmt.Printf("%s %s[401]: Unauthorized", url, Red, Reset)
	case 403:
		fmt.Printf("%s %s[403]: Forbidden", url, Red, Reset)
	case 404:
		fmt.Printf("%s %s[404]: Not Found%s", url, Red, Reset)
		
	//Server Error Responses
	case 502:
		fmt.Printf("%s %s[502]: Bad Gateway", url, Orange, Reset)
	case 503:
		fmt.Printf("%s %s[503]: Service Unavailable", url, Orange, Reset)
	default:
		fmt.Println("---")
	}


}






