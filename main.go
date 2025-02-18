package main

import(
	"fmt"
	"os"
	"sync"

	"Project/libs"

	"github.com/spf13/cobra"
)

const maxURLLength = 100

func main(){
	var dnsFlag bool
	var httpFlag bool
	var shodanFlag bool

	var rootCmd = &cobra.Command{
		Use: "linux-reGOn [url]",
		Short: "a simple recon tool",
		Long: "linux-reGOn is a recon tool",
		Run: func(cmd *cobra.Command, args []string){
			if len(args) == 0 {
				fmt.Println("Please provide a URL.")
				return
			}

			httpFlag, _ := cmd.Flags().GetBool("http")
			dnsFlag, _ := cmd.Flags().GetBool("dns")
			URL := args[0]

			if len(URL) == 0{
				fmt.Println("Please Provide a URL.")
				return
			}

			if len(URL) > maxURLLength {
				fmt.Printf("Maximum URL size is %d", maxURLLength)
				return
			}

			var wg sync.WaitGroup

			if httpFlag {
				wg.Add(1)
				go func() {
					defer wg.Done()
					libs.HttpResponse(URL, &wg)
				}()
			}

			if dnsFlag {
				wg.Add(1)
				go func() {
					defer wg.Done()
					libs.DnsRecords(URL, &wg)
				}()
			}

			if shodanFlag {
					libs.HostIPQuery(URL)
			}

			if !httpFlag && !dnsFlag && !shodanFlag {
				fmt.Println("Please provide at least one flag: --http or --dns or --shodan")
				return
			}

			wg.Wait()
		},
	}

	rootCmd.Flags().BoolVarP(&dnsFlag, "dns", "D", false, "HTTP Status Code")
	rootCmd.Flags().BoolVarP(&httpFlag, "http", "H", false, "DNS Records")
	rootCmd.Flags().BoolVarP(&shodanFlag, "shodan", "S", false, "Shodan Host IP Query")

	err := rootCmd.Execute()
	if err != nil{
		fmt.Println(err)
		os.Exit(1)
	}




}
