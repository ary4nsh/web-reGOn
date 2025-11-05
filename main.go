package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/ary4nsh/web-reGOn/libs"
	"github.com/ary4nsh/web-reGOn/libs/http"
	"github.com/ary4nsh/web-reGOn/libs/snmp"
	"github.com/ary4nsh/web-reGOn/libs/ftp"
	"github.com/ary4nsh/web-reGOn/libs/memcached"
	"github.com/ary4nsh/web-reGOn/libs/dns"
	"github.com/ary4nsh/web-reGOn/libs/waf"
	"github.com/ary4nsh/web-reGOn/libs/identity-management"
	"github.com/ary4nsh/web-reGOn/hunter.io/combined-enrichment"
	"github.com/ary4nsh/web-reGOn/hunter.io/company-enrichment"
	"github.com/ary4nsh/web-reGOn/hunter.io/domain-search"
	"github.com/ary4nsh/web-reGOn/hunter.io/email-enrichment"
	"github.com/ary4nsh/web-reGOn/hunter.io/email-finder"
	"github.com/ary4nsh/web-reGOn/hunter.io/email-verifier"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const maxURLLength = 100

type Flags struct {
	dnsFlag             bool
	httpFlag            bool
	httpOptions	    bool
	hstsHeader	    bool
	cspHeader	    bool
	riaHeader	    bool
	shodanFlag          bool
	combinedEnrichment  bool
	companyEnrichment   bool
	domainSearch        bool
	emailEnrichment     bool
	emailFinder         bool
	emailVerifier       bool
	memcachedScan	    bool
	pathConfusion	    bool
	snmpWalk	    bool
	snmpEnumUsers	    bool
	snmpEnumShares	    bool
	ftpScan		    bool
	dnsDumpster	    bool
	zoneTransfer	    bool
	whois		    bool
	waf	 	    bool
	hiddenDirectories   bool
	apiKey		    string
	domain              string
	firstName           string
	lastName            string
	email		    string
	port		    string
	wordlist            string
	threads             int
}

var flagGroups = map[string]string{
	"dns":                "Reconnaissance",
	"http":               "Reconnaissance",
	"dns-dumpster":       "Reconnaissance",
	"zone-transfer":      "Reconnaissance",
	"whois":              "Reconnaissance",
	"waf":		      "Reconnaissance",
	
	"shodan":              "Open Source Intelligence",
	"combined-enrichment": "Open Source Intelligence",
	"company-enrichment":  "Open Source Intelligence",
	"domain-search":       "Open Source Intelligence",
	"email-enrichment":    "Open Source Intelligence",
	"email-finder":        "Open Source Intelligence",
	"email-verifier":      "Open Source Intelligence",

	"ftp":                "Misconfiguration",
	"memcached":          "Misconfiguration",
	"snmp-walk":          "Misconfiguration",
	"snmp-enumusers":     "Misconfiguration",
	"snmp-enumshares":    "Misconfiguration",
	"http-options":       "Misconfiguration",
	"hsts-header":        "Misconfiguration",
	"ria":                "Misconfiguration",
	"csp":                "Misconfiguration",
	"path-confusion":     "Misconfiguration",
	
	"hidden-directories": "Identity Management",
}

func anyFlagSet(flags Flags) bool {
	return flags.dnsFlag || flags.httpFlag || flags.httpOptions || flags.hstsHeader ||
		flags.shodanFlag || flags.combinedEnrichment || flags.companyEnrichment ||
		flags.domainSearch || flags.emailEnrichment ||
		flags.emailFinder || flags.emailVerifier || flags.snmpWalk ||
		flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
		flags.memcachedScan || flags.dnsDumpster || flags.zoneTransfer ||
		flags.whois || flags.cspHeader || flags.riaHeader || flags.pathConfusion ||
		flags.waf || flags.hiddenDirectories
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
				cmd.Help()
				return
			}
			
			// Check if httpOptions is set and port is provided
			if flags.httpOptions {
				if flags.port == "" {
					fmt.Println("Please provide port number when using --http-options (--port string)")
					return
				}
			}
			
			// Check if dirTraversal is set and wordlist is provided
			if flags.pathConfusion {
				if flags.wordlist == "" {
					fmt.Println("Please provide wordlist path when using --path-confusion (--wordlist string)")
					return
				}
			}
			
			if flags.hiddenDirectories {
				if flags.wordlist == "" {
					fmt.Println("Please provide wordlist path when using --hidden-directories (--wordlist string)")
					return
				}
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
					http.HttpResponse(URL, &wg)
				},
				flags.httpOptions: func() {
					// Execute HTTP OPTIONS check with port
					http.HttpOptionsWithPort(URL, flags.port)
				},
				flags.hstsHeader: func() {
					http.HstsHeaderWithPort(URL, flags.port)
				},
				flags.cspHeader: func() {
					http.CspHeader(URL) 
				},
				flags.riaHeader: func() {
					// Execute crossdomain.xml check sequentially
					http.RichInternetApplication(URL, flags.port)
				},
				flags.pathConfusion: func() {
					// Execute path confusion testing
					http.PathConfusion(URL, flags.wordlist, flags.threads)
				},
				flags.dnsFlag: func() {
					wg.Add(1) // Increment the WaitGroup counter for the DNS function
					go func() {
						dns.DnsRecords(URL, &wg)
						wg.Done()
					}()
				},
				flags.waf: func() {
					found, name := waf.WafDetect(URL)
					if found {
						fmt.Printf("WAF detected: %s\n", name)
					} else {
						fmt.Println("No WAF recognised")
					}
				},
				flags.hiddenDirectories: func() {
					// Execute hidden directories scan
					identitymanagement.HiddenDirectories(URL, flags.wordlist, flags.threads)
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

	// Allow flags to be specified anywhere in the command line
	rootCmd.Flags().SetInterspersed(true)

	rootCmd.Flags().BoolVarP(&flags.dnsFlag, "dns", "D", false, "DNS Records")
	rootCmd.Flags().BoolVarP(&flags.httpFlag, "http", "H", false, "HTTP Status Code")
	rootCmd.Flags().BoolVarP(&flags.httpOptions, "http-options", "", false, "HTTP OPTIONS Method Check")
	rootCmd.Flags().BoolVarP(&flags.hstsHeader, "hsts-header", "", false, "Check HSTS and security headers")
	rootCmd.Flags().BoolVarP(&flags.cspHeader, "csp", "", false, "Analyse Content-Security-Policy header")
	rootCmd.Flags().BoolVarP(&flags.pathConfusion, "path-confusion", "", false, "Path Confusion testing with wordlist and optional threads")

	rootCmd.Flags().BoolVarP(&flags.riaHeader, "ria", "", false, "Check crossdomain.xml and clientaccesspolicy.xml")
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
	rootCmd.Flags().BoolVar(&flags.waf, "waf", false, "Detect Web Application Firewall")
	rootCmd.Flags().BoolVarP(&flags.hiddenDirectories, "hidden-directories", "", false, "Discover hidden directories using wordlist")
	rootCmd.Flags().StringVarP(&flags.domain, "domain", "", "", "Domain to search for email")
	rootCmd.Flags().StringVarP(&flags.firstName, "first-name", "", "", "First name of the person")
	rootCmd.Flags().StringVarP(&flags.lastName, "last-name", "", "", "Last name of the person")
	rootCmd.Flags().StringVarP(&flags.apiKey, "api-key", "", "", "API key")
	rootCmd.Flags().StringVarP(&flags.email, "email", "", "", "Email address to verify")
	rootCmd.Flags().StringVarP(&flags.port, "port", "p", "", "Port number to use with HTTP OPTIONS")
	rootCmd.Flags().StringVarP(&flags.wordlist, "wordlist", "w", "", "Wordlist file path")
	rootCmd.Flags().IntVarP(&flags.threads, "threads", "t", 50, "Number of concurrent threads (default: 50)")
	
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
	fmt.Println("Usage:")
	fmt.Println("  linux-reGOn [url] [flags]")
	fmt.Println()

	groups := make(map[string][]string)

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		group := flagGroups[f.Name]
		if group == "" {
			group = "Other"
		}
		line := fmt.Sprintf("      --%-20s %s", f.Name, f.Usage)
		if f.Shorthand != "" {
			line = fmt.Sprintf("  -%s, --%-20s %s", f.Shorthand, f.Name, f.Usage)
		}
		groups[group] = append(groups[group], line)
	})

	order := []string{"Reconnaissance", "Misconfiguration", "Open Source Intelligence", "Identity Management", "Other"}
	for _, group := range order {
		if lines, ok := groups[group]; ok {
			fmt.Printf("[%s]\n", group)
			for _, line := range lines {
				fmt.Println(line)
			}
			fmt.Println()
		}
	}

	return nil
})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
