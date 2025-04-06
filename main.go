package main

import (
	"fmt"
	"os"
	"sync"

	"web-reGOn/libs"
	"web-reGOn/hunter.io/combined-enrichment"
	"web-reGOn/hunter.io/company-enrichment"
	"web-reGOn/hunter.io/domain-search"
	"web-reGOn/hunter.io/email-enrichment"
	"web-reGOn/hunter.io/email-finder"
	"web-reGOn/hunter.io/email-verifier"

	"github.com/spf13/cobra"
)

const maxURLLength = 100

type Flags struct {
	dnsFlag             bool
	httpFlag            bool
	shodanFlag          bool
	combinedEnrichment  bool
	companyEnrichment   bool
	domainSearch        bool
	emailEnrichment     bool
	emailFinder         bool
	emailVerifier       bool
	apiKey		    string
	domain              string
	firstName           string
	lastName            string
	email		    string
}

func anyFlagSet(flags Flags) bool {
	return flags.dnsFlag || flags.httpFlag || flags.shodanFlag ||
		flags.combinedEnrichment || flags.companyEnrichment ||
		flags.domainSearch || flags.emailEnrichment ||
		flags.emailFinder || flags.emailVerifier
}

func main() {
	var flags Flags

	var rootCmd = &cobra.Command{
		Use:   "linux-reGOn [url]",
		Short: "A simple recon tool",
		Long:  "linux-reGOn is a recon tool",
		Run: func(cmd *cobra.Command, args []string) {
			// Check if no flags are set
			if !anyFlagSet(flags) {
				fmt.Println("Please provide at least one flag")
				return
			}
			
			// Check if emailFinder flag is set and required fields are provided
			if flags.emailFinder {
				if flags.apiKey == "" || flags.domain == "" || flags.firstName == "" || flags.lastName == "" {
					fmt.Println("Please provide Hunter.io API key, domain, first name, and last name")
					return
				}
			}
			
			// Check if emailVerifier flag is set and email is provided
			if flags.emailVerifier {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io api-key and email")
					return
				}
			}
			
			// Check if emailEnrichment flag is set and apiKey and email are provided
			if flags.emailEnrichment {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io API key and email")
					return
				}
			}
			
			// Check if domainSearch flag is set and required fields are provided
			if flags.domainSearch {
				if flags.apiKey == "" || flags.domain == "" {
					fmt.Println("Please provide Hunter.io API key and domain name")
					return
				}
			}
			
			// Check if companyEnrichment flag is set and required fields are provided
			if flags.companyEnrichment {
				if flags.apiKey == "" || flags.domain == "" {
					fmt.Println("Please provide Hunter.io API key and domain name")
					return
				}
			}
			
			// Check if combinedEnrichment flag is set and required fields are provided
			if flags.combinedEnrichment {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io API key and email")
					return
				}
			}
			
			// Check if shodanFlag is set and required fields are provided
			if flags.shodanFlag {
				if flags.apiKey == "" || len(args) == 0 {
					fmt.Println("Please provide Shodan.io api key and URL")
					return
				}
			}

			// Check if URL is provided when at least one flag is set
			if len(args) == 0 {
				fmt.Println("Please provide a URL")
				return
			}

			URL := args[0]
			/*if err := validateURL(URL); err != nil {
				fmt.Println(err)
				return
			}*/

			var wg sync.WaitGroup
			functions := map[bool]func(){
				flags.httpFlag: func() {
					wg.Add(1)
					defer wg.Done()
					libs.HttpResponse(URL, &wg)
				},
				flags.dnsFlag: func() {
					wg.Add(1)
					defer wg.Done()
					libs.DnsRecords(URL, &wg)
				},
				flags.shodanFlag: func() {
					wg.Add(1)
					defer wg.Done()
					libs.HostIPQuery(flags.apiKey, URL)
				},
				flags.combinedEnrichment: func() {
					wg.Add(1)
					defer wg.Done()
					combinedEnrichment.CombinedEnrichment(flags.apiKey, flags.email)
				},
				flags.companyEnrichment: func() {
					wg.Add(1)
					defer wg.Done()
					companyEnrichment.CompanyEnrichment(flags.apiKey, flags.domain)
				},
				flags.domainSearch: func() {
					wg.Add(1)
					defer wg.Done()
					domainSearch.DomainSearch(flags.apiKey, flags.domain)
				},
				flags.emailEnrichment: func() {
					wg.Add(1)
					defer wg.Done()
					emailEnrichment.EmailEnrichment(flags.apiKey, flags.email)
				},
				flags.emailFinder: func() {
					wg.Add(1)
					defer wg.Done()
					emailFinder.EmailFinder(flags.apiKey, flags.domain, flags.firstName, flags.lastName)
				},
				flags.emailVerifier: func() {
					wg.Add(1)
					defer wg.Done()
					emailVerifier.EmailVerifier(flags.apiKey, flags.email)
				},
			}

			for flag, function := range functions {
				if flag {
					function()
				}
			}

			wg.Wait()
		},
	}

	rootCmd.Flags().BoolVarP(&flags.dnsFlag, "dns", "D", false, "DNS Records")
	rootCmd.Flags().BoolVarP(&flags.httpFlag, "http", "H", false, "HTTP Status Code")
	rootCmd.Flags().BoolVarP(&flags.shodanFlag, "shodan", "S", false, "Shodan Host IP Query")
	rootCmd.Flags().BoolVarP(&flags.combinedEnrichment, "combined-enrichment", "", false, "Company and Email enrichment information")
	rootCmd.Flags().BoolVarP(&flags.companyEnrichment, "company-enrichment", "", false, "Company enrichment information")
	rootCmd.Flags().BoolVarP(&flags.domainSearch, "domain-search", "", false, "Domain search for email addresses")
	rootCmd.Flags().BoolVarP(&flags.emailEnrichment, "email-enrichment", "", false, "Email enrichment information")
	rootCmd.Flags().BoolVarP(&flags.emailFinder, "email-finder", "", false, "Find email address from domain and person names")
	rootCmd.Flags().BoolVarP(&flags.emailVerifier, "email-verifier", "", false, "Verify email address deliverability")
	rootCmd.Flags().StringVarP(&flags.domain, "domain", "", "", "Domain to search for email")
	rootCmd.Flags().StringVarP(&flags.firstName, "first-name", "", "", "First name of the person")
	rootCmd.Flags().StringVarP(&flags.lastName, "last-name", "", "", "Last name of the person")
	rootCmd.Flags().StringVarP(&flags.apiKey, "api-key", "", "", "Hunter.io API key")
	rootCmd.Flags().StringVarP(&flags.email, "email", "", "", "Email address to verify")


	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
