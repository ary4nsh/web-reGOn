package main

import (
	"fmt"
	"os"
	"sync"

	"github.com/ary4nsh/web-reGOn/libs/reconnaissance"

	"github.com/ary4nsh/web-reGOn/libs/osint"
	combinedEnrichment "github.com/ary4nsh/web-reGOn/libs/osint/hunter.io/combined-enrichment"
	companyEnrichment "github.com/ary4nsh/web-reGOn/libs/osint/hunter.io/company-enrichment"
	domainSearch "github.com/ary4nsh/web-reGOn/libs/osint/hunter.io/domain-search"
	emailEnrichment "github.com/ary4nsh/web-reGOn/libs/osint/hunter.io/email-enrichment"
	emailFinder "github.com/ary4nsh/web-reGOn/libs/osint/hunter.io/email-finder"
	emailVerifier "github.com/ary4nsh/web-reGOn/libs/osint/hunter.io/email-verifier"
	dnsLookup "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/dns-lookup"
	dnsPropagation "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/dns-propagation"
	ipHistory "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/ip-history"
	ipLocation "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/ip-location"
	macLookup "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/mac-address-lookup"
	multiplePing "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/multiple-ping"
	reverseDns "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/reverse-dns"
	subdomainDiscovery "github.com/ary4nsh/web-reGOn/libs/osint/viewdns/subdomain-discovery"
	"github.com/ary4nsh/web-reGOn/libs/osint/viewdns/traceroute"

	//"github.com/ary4nsh/web-reGOn/libs/misconfiguration/smb"
	"github.com/ary4nsh/web-reGOn/libs/misconfiguration/ftp"
	"github.com/ary4nsh/web-reGOn/libs/misconfiguration/http"
	"github.com/ary4nsh/web-reGOn/libs/misconfiguration/memcached"
	"github.com/ary4nsh/web-reGOn/libs/misconfiguration/snmp"

	identitymanagement "github.com/ary4nsh/web-reGOn/libs/identity-management"

	brokenauthorization "github.com/ary4nsh/web-reGOn/libs/broken-authentication"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Flags struct {
	// Open Source Intelligence
	shodanFlag         bool
	combinedEnrichment bool
	companyEnrichment  bool
	domainSearch       bool
	emailEnrichment    bool
	emailFinder        bool
	emailVerifier      bool
	dnsLookup          bool
	dnsPropagation     bool
	ipHistory          bool
	ipLocation         bool
	macAddressLookup   bool
	multiplePing       bool
	reverseDns         bool
	subdomainDiscovery bool
	traceroute         bool

	// Misconfiguration
	dnsFlag        bool
	httpFlag       bool
	httpOptions    bool
	hstsHeader     bool
	cspHeader      bool
	riaHeader      bool
	memcachedScan  bool
	pathConfusion  bool
	snmpWalk       bool
	snmpEnumUsers  bool
	snmpEnumShares bool
	ftpScan        bool
	dnsDumpster    bool
	zoneTransfer   bool
	whois          bool
	waf            bool

	// Identity Management
	hiddenDirectories   bool
	cookieAndAccount    bool
	statusCodeEnum      bool
	errorMessageEnum    bool
	nonexistentUserEnum bool

	// Broken Authentication
	tls               bool
	rememberPassword  bool
	cacheWeakness     bool

	// Others
	apiKey    string
	domain    string
	firstName string
	lastName  string
	email     string
	port      string
	wordlist  string
	userlist  string
	passlist  string
	mac       string
	threads   int
}

var flagGroups = map[string]string{
	"dns":           "Reconnaissance",
	"http":          "Reconnaissance",
	"zone-transfer": "Reconnaissance",
	"whois":         "Reconnaissance",
	"waf":           "Reconnaissance",

	"shodan":              "Open Source Intelligence",
	"combined-enrichment": "Open Source Intelligence",
	"company-enrichment":  "Open Source Intelligence",
	"domain-search":       "Open Source Intelligence",
	"email-enrichment":    "Open Source Intelligence",
	"email-finder":        "Open Source Intelligence",
	"email-verifier":      "Open Source Intelligence",
	"dns-lookup":          "Open Source Intelligence",
	"dns-propagation":     "Open Source Intelligence",
	"dns-dumpster":        "Open Source Intelligence",
	"ip-history":          "Open Source Intelligence",
	"ip-location":         "Open Source Intelligence",
	"mac-address-lookup":  "Open Source Intelligence",
	"multiple-ping":       "Open Source Intelligence",
	"reverse-dns":         "Open Source Intelligence",
	"subdomain-discovery": "Open Source Intelligence",
	"traceroute":          "Open Source Intelligence",

	"ftp":             "Misconfiguration",
	"memcached":       "Misconfiguration",
	"snmp-walk":       "Misconfiguration",
	"snmp-enumusers":  "Misconfiguration",
	"snmp-enumshares": "Misconfiguration",
	"http-options":    "Misconfiguration",
	"hsts-header":     "Misconfiguration",
	"ria":             "Misconfiguration",
	"csp":             "Misconfiguration",
	"path-confusion":  "Misconfiguration",

	"hidden-directories":    "Identity Management",
	"cookie-and-account":    "Identity Management",
	"status-code-enum":      "Identity Management",
	"error-message-enum":    "Identity Management",
	"nonexistent-user-enum": "Identity Management",

	"tls":               "Broken Authentication",
	"remember-password": "Broken Authentication",
	"cache-weakness":   "Broken Authentication",
}

func anyFlagSet(flags Flags) bool {
	return flags.dnsFlag || flags.httpFlag || flags.httpOptions || flags.hstsHeader ||
		flags.shodanFlag || flags.combinedEnrichment || flags.companyEnrichment ||
		flags.domainSearch || flags.emailEnrichment ||
		flags.emailFinder || flags.emailVerifier || flags.snmpWalk ||
		flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
		flags.memcachedScan || flags.dnsDumpster || flags.zoneTransfer ||
		flags.whois || flags.cspHeader || flags.riaHeader || flags.pathConfusion ||
		flags.waf || flags.hiddenDirectories || flags.cookieAndAccount ||
		flags.statusCodeEnum || flags.errorMessageEnum || flags.nonexistentUserEnum ||
		flags.dnsLookup || flags.dnsPropagation || flags.ipHistory || flags.macAddressLookup ||
		flags.multiplePing || flags.reverseDns || flags.subdomainDiscovery || flags.traceroute ||
		flags.tls || flags.rememberPassword || flags.cacheWeakness
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

			if flags.cookieAndAccount {
				if flags.wordlist == "" {
					fmt.Println("Please provide wordlist path when using --cookie-and-account (--wordlist string)")
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

			if flags.statusCodeEnum {
				if flags.userlist == "" || flags.passlist == "" {
					fmt.Println("Please provide userlist and passlist paths when using --status-code-enum (--userlist string --passlist string)")
					return
				}
			}

			if flags.errorMessageEnum {
				if flags.userlist == "" || flags.passlist == "" {
					fmt.Println("Please provide userlist and passlist paths when using --error-message-enum (--userlist string --passlist string)")
					return
				}
			}

			if flags.nonexistentUserEnum {
				if flags.userlist == "" {
					fmt.Println("Please provide userlist path when using --nonexistent-user-enum (--userlist string)")
					return
				}
			}

			// Check if dnsLookup flag is set and required fields are provided
			if flags.dnsLookup {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			// Check if dnsPropagation flag is set and required fields are provided
			if flags.dnsPropagation {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			// Check if ipHistory flag is set and required fields are provided
			if flags.ipHistory {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			// Check if macAddressLookup flag is set and required fields are provided
			if flags.macAddressLookup {
				if flags.apiKey == "" || flags.mac == "" {
					fmt.Println("Please provide viewdns.info API key and mac address (--api-key string --mac string)")
					return
				}
			}

			// Check if multiplePing flag is set and required fields are provided
			if flags.multiplePing {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			// Check if reverseDns flag is set and required fields are provided
			if flags.reverseDns {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			// Check if subdomainDiscovery flag is set and required fields are provided
			if flags.subdomainDiscovery {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			// Check if traceroute flag is set and required fields are provided
			if flags.traceroute {
				if flags.apiKey == "" {
					fmt.Println("Please provide viewdns.info API key (--api-key string)")
					return
				}
			}

			requiresTarget := flags.dnsFlag || flags.httpFlag || flags.httpOptions || flags.hstsHeader ||
				flags.snmpWalk || flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
				flags.memcachedScan || flags.pathConfusion || flags.hiddenDirectories ||
				flags.cookieAndAccount || flags.statusCodeEnum || flags.errorMessageEnum ||
				flags.nonexistentUserEnum || flags.tls || flags.rememberPassword || flags.cacheWeakness || flags.waf || flags.zoneTransfer ||
				flags.whois || flags.cspHeader || flags.riaHeader

			var URL, ipAddress string
			if requiresTarget {
				if len(args) == 0 {
					fmt.Println("Please provide a URL or an IP address")
					return
				}
				URL = args[0]
				ipAddress = args[0]
			}

			var wg sync.WaitGroup
			functions := map[bool]func(){

				// Reconnaissance
				flags.httpFlag: func() {
					// Execute HTTP response check sequentially
					reconnaissance.HttpResponse(URL, &wg)
				},
				flags.dnsFlag: func() {
					wg.Add(1) // Increment the WaitGroup counter for the DNS function
					go func() {
						reconnaissance.DnsRecords(URL, &wg)
						wg.Done()
					}()
				},
				flags.waf: func() {
					found, name := reconnaissance.WafDetect(URL, flags.port)
					if found {
						fmt.Printf("WAF detected: %s\n", name)
					} else {
						fmt.Println("No WAF recognised")
					}
				},
				flags.zoneTransfer: func() {
					// Execute DNS zone transfer secuentially
					reconnaissance.ZoneTransfer(URL)
				},
				flags.whois: func() {
					// Execute Whois secuentially
					reconnaissance.Whois(URL)
				},

				// Open Source Intelligence
				flags.dnsDumpster: func() {
					// Execute DNS dumpster secuentially
					osint.DnsDumpster(URL, flags.apiKey)
				},
				flags.shodanFlag: func() {
					// Execute Shodan query sequentially
					osint.HostIPQuery(flags.apiKey, URL)
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
				flags.dnsLookup: func() {
					// Execute email verifier sequentially
					dnsLookup.DnsLookup(flags.apiKey, flags.email)
				},
				flags.dnsPropagation: func() {
					// Execute email verifier sequentially
					dnsPropagation.DnsPropagation(flags.apiKey, flags.email)
				},
				flags.ipHistory: func() {
					// Execute email verifier sequentially
					ipHistory.IpHistory(flags.apiKey, flags.email)
				},
				flags.ipLocation: func() {
					// Execute email verifier sequentially
					ipLocation.IpLocation(flags.apiKey, flags.email)
				},
				flags.macAddressLookup: func() {
					// Execute email verifier sequentially
					macLookup.MacLookup(flags.apiKey, flags.email)
				},
				flags.multiplePing: func() {
					// Execute email verifier sequentially
					multiplePing.MultiplePing(flags.apiKey, flags.email)
				},
				flags.reverseDns: func() {
					// Execute email verifier sequentially
					reverseDns.ReverseDns(flags.apiKey, flags.email)
				},
				flags.subdomainDiscovery: func() {
					// Execute email verifier sequentially
					subdomainDiscovery.SubdomainDiscovery(flags.apiKey, flags.email)
				},
				flags.traceroute: func() {
					// Execute email verifier sequentially
					traceroute.Traceroute(flags.apiKey, flags.email)
				},

				// Misconfiguration
				flags.httpOptions: func() {
					// Execute HTTP OPTIONS check with port
					http.HttpOptions(URL, flags.port)
				},
				flags.hstsHeader: func() {
					http.HstsHeaderWithPort(URL, flags.port)
				},
				flags.cspHeader: func() {
					http.CspHeader(URL, flags.port)
				},
				flags.riaHeader: func() {
					// Execute crossdomain.xml check sequentially
					http.RichInternetApplication(URL, flags.port)
				},
				flags.pathConfusion: func() {
					// Execute path confusion testing
					http.PathConfusion(URL, flags.wordlist, flags.threads)
				},
				flags.hiddenDirectories: func() {
					// Execute hidden directories scan
					identitymanagement.HiddenDirectories(URL, flags.wordlist, flags.threads)
				},
				flags.cookieAndAccount: func() {
					identitymanagement.CookieAndAccount(URL, flags.wordlist, flags.threads)
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

				// Identity Manegement
				flags.statusCodeEnum: func() {
					// Execute login fuzzer
					identitymanagement.StatusCodeEnum(URL, flags.userlist, flags.passlist, flags.threads)
				},
				flags.errorMessageEnum: func() {
					// Execute error message enumeration
					identitymanagement.ErrorMessageEnum(URL, flags.userlist, flags.passlist, flags.threads)
				},
				flags.nonexistentUserEnum: func() {
					// Execute nonexistent user enumeration
					identitymanagement.NonexistentUserEnum(URL, flags.userlist, flags.threads)
				},

				// Broken Authentication
				flags.tls: func() {
					brokenauthorization.TlsTest(URL, flags.port)
				},
				flags.rememberPassword: func() {
					brokenauthorization.ResetPassword(URL, flags.port)
				},
				flags.cacheWeakness: func() {
					brokenauthorization.CacheWeakness(URL, flags.port)
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

	// Reconnaissance
	rootCmd.Flags().BoolVarP(&flags.dnsFlag, "dns", "D", false, "DNS Records")
	rootCmd.Flags().BoolVarP(&flags.httpFlag, "http", "H", false, "HTTP Status Code")
	rootCmd.Flags().BoolVarP(&flags.zoneTransfer, "zone-transfer", "", false, "Perform zone transfer on a domain")
	rootCmd.Flags().BoolVarP(&flags.whois, "whois", "", false, "Query for Whois records")
	rootCmd.Flags().BoolVar(&flags.waf, "waf", false, "Detect Web Application Firewall")

	// Open Source Intelligence
	rootCmd.Flags().BoolVarP(&flags.shodanFlag, "shodan", "S", false, "Shodan Host IP Query")
	rootCmd.Flags().BoolVarP(&flags.combinedEnrichment, "combined-enrichment", "", false, "Company and Email enrichment information")
	rootCmd.Flags().BoolVarP(&flags.companyEnrichment, "company-enrichment", "", false, "Company enrichment information")
	rootCmd.Flags().BoolVarP(&flags.domainSearch, "domain-search", "", false, "Domain search for email addresses")
	rootCmd.Flags().BoolVarP(&flags.emailEnrichment, "email-enrichment", "", false, "Email enrichment information")
	rootCmd.Flags().BoolVarP(&flags.emailFinder, "email-finder", "", false, "Find email address from domain and person names")
	rootCmd.Flags().BoolVarP(&flags.emailVerifier, "email-verifier", "", false, "Verify email address deliverability")
	rootCmd.Flags().BoolVarP(&flags.dnsDumpster, "dns-dumpster", "", false, "Find & look up DNS records from dnsdumpster.com")
	rootCmd.Flags().BoolVarP(&flags.dnsLookup, "dns-lookup", "", false, "Find & look up DNS records from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.dnsPropagation, "dns-propagation", "", false, "Check if recent changes to DNS records have propagated from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.ipHistory, "ip-history", "", false, "Show historical IP addresses associated with a specific domain from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.ipLocation, "ip-location", "", false, "Return the geographical location of an IP address from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.multiplePing, "multiple-ping", "", false, "Check the latency and packet loss to a given host from multiple locations globally from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.reverseDns, "reverse-dns", "", false, "Return DNS Pointer (PTR) record for a given IP address from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.subdomainDiscovery, "subdomain-discovery", "", false, "Provide a comprehensive list of subdomains associated with a given domain from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.macAddressLookup, "mac-address-lookup", "", false, "Search the OUI database to determine which manufacturer a given MAC address belongs to, from viewdns.info")
	rootCmd.Flags().BoolVarP(&flags.traceroute, "tracerout", "", false, "Trace the network path from our test location to a given host from viewdns.info")

	// Misconfiguration
	rootCmd.Flags().BoolVarP(&flags.httpOptions, "http-options", "", false, "HTTP OPTIONS Method Check")
	rootCmd.Flags().BoolVarP(&flags.hstsHeader, "hsts-header", "", false, "Check HSTS and security headers")
	rootCmd.Flags().BoolVarP(&flags.cspHeader, "csp", "", false, "Analyse Content-Security-Policy header")
	rootCmd.Flags().BoolVarP(&flags.pathConfusion, "path-confusion", "", false, "Path Confusion testing with wordlist and optional threads")
	rootCmd.Flags().BoolVarP(&flags.riaHeader, "ria", "", false, "Check crossdomain.xml and clientaccesspolicy.xml")
	rootCmd.Flags().BoolVarP(&flags.snmpWalk, "snmp-walk", "", false, "Perform SNMP walk on IP address")
	rootCmd.Flags().BoolVarP(&flags.snmpEnumUsers, "snmp-enumusers", "", false, "Enumerate SNMP Windows users")
	rootCmd.Flags().BoolVarP(&flags.snmpEnumShares, "snmp-enumshares", "", false, "Enumerate SNMP Windows SMB Share")
	rootCmd.Flags().BoolVarP(&flags.ftpScan, "ftp", "", false, "Scan FTP server")
	rootCmd.Flags().BoolVarP(&flags.memcachedScan, "memcached", "", false, "Scan Memcached server")

	// Identity Management
	rootCmd.Flags().BoolVarP(&flags.hiddenDirectories, "hidden-directories", "", false, "Discover hidden directories using wordlist")
	rootCmd.Flags().BoolVarP(&flags.statusCodeEnum, "status-code-enum", "", false, "Enumerate users via brute forcing login forms with username and password lists by status code")
	rootCmd.Flags().BoolVarP(&flags.errorMessageEnum, "error-message-enum", "", false, "Enumerate users via brute forcing login forms with username and password lists by analyzing error messages and status codes")
	rootCmd.Flags().BoolVarP(&flags.nonexistentUserEnum, "nonexistent-user-enum", "", false, "Enumerate users via brute forcing login forms with username list and fake password by analyzing error messages and status codes")

	// Broken Authentication
	rootCmd.Flags().BoolVar(&flags.tls, "tls", false, "Test for TLS/SSL vulnerabilities")
	rootCmd.Flags().BoolVar(&flags.rememberPassword, "remember-password", false, "Check reset password security")
	rootCmd.Flags().BoolVar(&flags.cacheWeakness, "cache-weakness", false, "Check cache-related headers and meta tags for browser cache weakness")

	// Others
	rootCmd.Flags().BoolVarP(&flags.cookieAndAccount, "cookie-and-account", "", false, "Cookie analysis and CMS account enumeration using wordlist")
	rootCmd.Flags().StringVarP(&flags.domain, "domain", "", "", "Domain to search for email")
	rootCmd.Flags().StringVarP(&flags.firstName, "first-name", "", "", "First name of the person")
	rootCmd.Flags().StringVarP(&flags.lastName, "last-name", "", "", "Last name of the person")
	rootCmd.Flags().StringVarP(&flags.userlist, "userlist", "", "", "Username list file path")
	rootCmd.Flags().StringVarP(&flags.passlist, "passlist", "", "", "Password list file path")
	rootCmd.Flags().StringVarP(&flags.apiKey, "api-key", "", "", "API key")
	rootCmd.Flags().StringVarP(&flags.email, "email", "", "", "Email address to verify")
	rootCmd.Flags().StringVarP(&flags.port, "port", "p", "", "Port number to use with HTTP OPTIONS")
	rootCmd.Flags().StringVarP(&flags.wordlist, "wordlist", "w", "", "Wordlist file path")
	rootCmd.Flags().StringVarP(&flags.mac, "mac", "", "", "MAC address")
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

		order := []string{"Reconnaissance", "Open Source Intelligence", "Misconfiguration", "Identity Management", "Broken Authentication", "Other"}
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
