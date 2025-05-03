package main

import (
	"fmt"
	"os"
	"sync"

	"web-reGOn/libs"
	"web-reGOn/libs/snmp"
	"web-reGOn/libs/ftp"
	"web-reGOn/libs/memcached"
	"web-reGOn/libs/dns"
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
	memcachedScan	    bool
	snmpWalk	    bool
	snmpEnumUsers	    bool
	snmpEnumShares	    bool
	ftpScan		    bool
	dnsDumpster	    bool
	zoneTransfer	    bool
	whois		    bool
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
		flags.emailFinder || flags.emailVerifier || flags.snmpWalk ||
		flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
		flags.memcachedScan || flags.dnsDumpster || flags.zoneTransfer ||
		flags.whois
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
					fmt.Println("Please provide Hunter.io API key, domain, first name, and last name (--api-key string --domain string --first-name string --last-name string)")
					return
				}
			}
			
			// Check if emailVerifier flag is set and email is provided
			if flags.emailVerifier {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io api-key and email (--api-key string --email string)")
					return
				}
			}
			
			// Check if emailEnrichment flag is set and apiKey and email are provided
			if flags.emailEnrichment {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io API key and email (--api-key string --email string)")
					return
				}
			}
			
			// Check if domainSearch flag is set and required fields are provided
			if flags.domainSearch {
				if flags.apiKey == "" || flags.domain == "" {
					fmt.Println("Please provide Hunter.io API key and domain name (--api-key string --domain string)")
					return
				}
			}
			
			// Check if companyEnrichment flag is set and required fields are provided
			if flags.companyEnrichment {
				if flags.apiKey == "" || flags.domain == "" {
					fmt.Println("Please provide Hunter.io API key and domain name (--api-key string --domain string)")
					return
				}
			}
			
			// Check if combinedEnrichment flag is set and required fields are provided
			if flags.combinedEnrichment {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io API key and email (--api-key string --email string)")
					return
				}
			}
			
			// Check if shodanFlag is set and required fields are provided
			if flags.shodanFlag {
				if flags.apiKey == "" {
					fmt.Println("Please provide Shodan.io api key and URL (--api-key string)")
					return
				}
			}
			
			if flags.dnsDumpster {
				if flags.apiKey == "" {
					fmt.Println("Please provide dnsdumpster.com api key and URL (--api-key string)")
				}
			}

			// Check if URL is provided when at least one flag is set
			if len(args) == 0 {
				fmt.Println("Please provide a URL or an IP address")
				return
			}

			URL := args[0]
			ipAddress := args[0]

			var wg sync.WaitGroup
			functions := map[bool]func(){
				flags.httpFlag: func() {
					// Execute HTTP response check sequentially
					libs.HttpResponse(URL)
				},
				flags.dnsFlag: func() {
					wg.Add(1) // Increment the WaitGroup counter for the DNS function
					go func() {
						dns.DnsRecords(URL, &wg)
						wg.Done()
					}()
				},
				flags.shodanFlag: func() {
					// Execute Shodan query sequentially
					libs.HostIPQuery(flags.apiKey, URL)
				},
				flags.combinedEnrichment: func() {
					// Execute combined enrichment sequentially
					combinedEnrichment.CombinedEnrichment(flags.apiKey, flags.email)
				},
				flags.companyEnrichment: func() {
					// Execute company enrichment sequentially
					companyEnrichment.CompanyEnrichment(flags.apiKey, flags.domain)
				},
				flags.domainSearch: func() {
					// Execute domain search sequentially
					domainSearch.DomainSearch(flags.apiKey, flags.domain)
				},
				flags.emailEnrichment: func() {
					// Execute email enrichment sequentially
					emailEnrichment.EmailEnrichment(flags.apiKey, flags.email)
				},
				flags.emailFinder: func() {
					// Execute email finder sequentially
					emailFinder.EmailFinder(flags.apiKey, flags.domain, flags.firstName, flags.lastName)
				},
				flags.emailVerifier: func() {
					// Execute email verifier sequentially
					emailVerifier.EmailVerifier(flags.apiKey, flags.email)
				},
				flags.snmpWalk: func() {
					// Execute SNMP walk sequentially
					snmp.SNMPWalk(ipAddress)
				},
				flags.snmpEnumUsers: func() {
					// Execute SNMP user enumeration sequentially
					snmp.SNMPEnumUsers(ipAddress)
				},
				flags.snmpEnumShares: func() {
					// Execute SNMP share enumeration sequentially
					snmp.SNMPEnumShares(ipAddress)
				},
				flags.ftpScan: func() {
					// Execute FTP scan sequentially
					ftp.FTPScan(ipAddress)
				},
				flags.memcachedScan: func() {
					// Execute Memcached scan sequentially
					memcached.MemcachedScan(ipAddress)
				},
				flags.dnsDumpster: func() {
					// Execute DNS dumpster secuentially
					dns.DnsDumpster(URL, flags.apiKey)
				},
				flags.zoneTransfer: func() {
					// Execute DNS zone transfer secuentially
					dns.ZoneTransfer(URL)
				},
				flags.whois: func() {
					// Execute Whois secuentially
					libs.Whois(URL)
				},
			}

			for flag, function := range functions {
				if flag {
					wg.Add(1)
					go func(fn func()) {
						defer wg.Done()
						fn()
					}(function)
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
	rootCmd.Flags().BoolVarP(&flags.snmpWalk, "snmp-walk", "", false, "Perform SNMP walk on IP address")
	rootCmd.Flags().BoolVarP(&flags.snmpEnumUsers, "snmp-enumusers", "", false, "Enumerate SNMP Windows users")
	rootCmd.Flags().BoolVarP(&flags.snmpEnumShares, "snmp-enumshares", "", false, "Enumerate SNMP Windows SMB Share")
	rootCmd.Flags().BoolVarP(&flags.ftpScan, "ftp", "", false, "Scan FTP server")
	rootCmd.Flags().BoolVarP(&flags.memcachedScan, "memcached", "", false, "Scan Memcached server")
	rootCmd.Flags().BoolVarP(&flags.dnsDumpster, "dns-dumpster", "", false, "Find & look up DNS records from dnsdumpster.com")
	rootCmd.Flags().BoolVarP(&flags.zoneTransfer, "zone-transfer", "", false, "Perform zone transfer on a domain")
	rootCmd.Flags().BoolVarP(&flags.whois, "whois", "", false, "Query for Whois records")
	rootCmd.Flags().StringVarP(&flags.domain, "domain", "", "", "Domain to search for email")
	rootCmd.Flags().StringVarP(&flags.firstName, "first-name", "", "", "First name of the person")
	rootCmd.Flags().StringVarP(&flags.lastName, "last-name", "", "", "Last name of the person")
	rootCmd.Flags().StringVarP(&flags.apiKey, "api-key", "", "", "API key")
	rootCmd.Flags().StringVarP(&flags.email, "email", "", "", "Email address to verify")


	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
