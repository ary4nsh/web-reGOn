package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/ary4nsh/web-reGOn/libs"
	"github.com/ary4nsh/web-reGOn/libs/snmp"
	"github.com/ary4nsh/web-reGOn/libs/smb"
	"github.com/ary4nsh/web-reGOn/libs/ftp"
	"github.com/ary4nsh/web-reGOn/libs/memcached"
	"github.com/ary4nsh/web-reGOn/libs/dns"
	"github.com/ary4nsh/web-reGOn/hunter.io/combined-enrichment"
	"github.com/ary4nsh/web-reGOn/hunter.io/company-enrichment"
	"github.com/ary4nsh/web-reGOn/hunter.io/domain-search"
	"github.com/ary4nsh/web-reGOn/hunter.io/email-enrichment"
	"github.com/ary4nsh/web-reGOn/hunter.io/email-finder"
	"github.com/ary4nsh/web-reGOn/hunter.io/email-verifier"
)

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
	memcachedScan       bool
	snmpWalk            bool
	snmpEnumUsers       bool
	snmpEnumShares      bool
	ftpScan             bool
	dnsDumpster         bool
	zoneTransfer        bool
	whois               bool
	smbEnumUsers	    bool
	domain              string
	firstName           string
	lastName            string
	email               string
	apiKey              string
}

func anyFlagSet(flags Flags) bool {
	return flags.dnsFlag || flags.httpFlag || flags.shodanFlag ||
		flags.combinedEnrichment || flags.companyEnrichment ||
		flags.domainSearch || flags.emailEnrichment ||
		flags.emailFinder || flags.emailVerifier || flags.snmpWalk ||
		flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
		flags.memcachedScan || flags.dnsDumpster || flags.zoneTransfer ||
		flags.whois || flags.smbEnumUsers
}

func printUsage() {
	fmt.Println("Usage: linux-reGOn [options] URL/IP")
	fmt.Println("\nFlags:")
	fmt.Println("      --api-key string       API key")
	fmt.Println("      --combined-enrichment  Company and Email enrichment information")
	fmt.Println("      --company-enrichment   Company enrichment information")
	fmt.Println("      --dns                  DNS Records")
	fmt.Println("      --dns-dumpster         Find & look up DNS records from dnsdumpster.com")
	fmt.Println("      --domain string        Domain to search for email")
	fmt.Println("      --domain-search        Domain search for email addresses")
	fmt.Println("      --email string         Email address to verify")
	fmt.Println("      --email-enrichment     Email enrichment information")
	fmt.Println("      --email-finder         Find email address from domain and person names")
	fmt.Println("      --email-verifier       Verify email address deliverability")
	fmt.Println("      --first-name string    First name of the person")
	fmt.Println("      --ftp                  Scan FTP server")
	fmt.Println("      --http                 HTTP Status Code")
	fmt.Println("      --last-name string     Last name of the person")
	fmt.Println("      --memcached            Scan Memcached server")
	fmt.Println("      --shodan               Shodan Host IP Query")
	fmt.Println("      --smb-enumusers        Enumerate SMB users")
	fmt.Println("      --snmp-enumshares      Enumerate SNMP Windows SMB Share")
	fmt.Println("      --snmp-enumusers       Enumerate SNMP Windows users")
	fmt.Println("      --snmp-walk            Perform SNMP walk on IP address")
	fmt.Println("      --whois                Query for Whois records")
	fmt.Println("      --zone-transfer        Perform zone transfer on a domain")
}

func main() {
	var flags Flags

	// Define command line flags
	flag.BoolVar(&flags.dnsFlag, "dns", false, "DNS Records")
	flag.BoolVar(&flags.httpFlag, "http", false, "HTTP Status Code")
	flag.BoolVar(&flags.shodanFlag, "shodan", false, "Shodan Host IP Query")
	flag.BoolVar(&flags.combinedEnrichment, "combined-enrichment", false, "Company and Email enrichment information")
	flag.BoolVar(&flags.companyEnrichment, "company-enrichment", false, "Company enrichment information")
	flag.BoolVar(&flags.domainSearch, "domain-search", false, "Domain search for email addresses")
	flag.BoolVar(&flags.emailEnrichment, "email-enrichment", false, "Email enrichment information")
	flag.BoolVar(&flags.emailFinder, "email-finder", false, "Find email address from domain and person names")
	flag.BoolVar(&flags.emailVerifier, "email-verifier", false, "Verify email address deliverability")
	flag.BoolVar(&flags.snmpWalk, "snmp-walk", false, "Perform SNMP walk on IP address")
	flag.BoolVar(&flags.snmpEnumUsers, "snmp-enumusers", false, "Enumerate SNMP Windows users")
	flag.BoolVar(&flags.snmpEnumShares, "snmp-enumshares", false, "Enumerate SNMP Windows SMB Share")
	flag.BoolVar(&flags.ftpScan, "ftp", false, "Scan FTP server")
	flag.BoolVar(&flags.memcachedScan, "memcached", false, "Scan Memcached server")
	flag.BoolVar(&flags.dnsDumpster, "dns-dumpster", false, "Find & look up DNS records from dnsdumpster.com")
	flag.BoolVar(&flags.zoneTransfer, "zone-transfer", false, "Perform zone transfer on a domain")
	flag.BoolVar(&flags.whois, "whois", false, "Query for Whois records")
	flag.BoolVar(&flags.smbEnumUsers, "smb-enumusers", false, "Enumerate SMB users")
	flag.StringVar(&flags.domain, "domain", "", "Domain to search for email")
	flag.StringVar(&flags.firstName, "first-name", "", "First name of the person")
	flag.StringVar(&flags.lastName, "last-name", "", "Last name of the person")
	flag.StringVar(&flags.apiKey, "api-key", "", "API key")
	flag.StringVar(&flags.email, "email", "", "Email address to verify")

	// Custom usage function
	flag.Usage = printUsage

	// Parse the flags
	flag.Parse()

	// Check if no flags are set
	if !anyFlagSet(flags) {
		fmt.Println("Please provide at least one flag")
		printUsage()
		os.Exit(1)
	}

	// Check if URL/IP is provided
	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Please provide a URL or an IP address")
		printUsage()
		os.Exit(1)
	}

	URL := args[0]
	ipAddress := args[0]

	// Validate flag combinations and required parameters
	if flags.emailFinder && (flags.apiKey == "" || flags.domain == "" || flags.firstName == "" || flags.lastName == "") {
		fmt.Println("Please provide Hunter.io API key, domain, first name, and last name (--api-key string --domain string --first-name string --last-name string)")
		os.Exit(1)
	}

	if flags.emailVerifier && (flags.apiKey == "" || flags.email == "") {
		fmt.Println("Please provide Hunter.io api-key and email (--api-key string --email string)")
		os.Exit(1)
	}

	if flags.emailEnrichment && (flags.apiKey == "" || flags.email == "") {
		fmt.Println("Please provide Hunter.io API key and email (--api-key string --email string)")
		os.Exit(1)
	}

	if flags.domainSearch && (flags.apiKey == "" || flags.domain == "") {
		fmt.Println("Please provide Hunter.io API key and domain name (--api-key string --domain string)")
		os.Exit(1)
	}

	if flags.companyEnrichment && (flags.apiKey == "" || flags.domain == "") {
		fmt.Println("Please provide Hunter.io API key and domain name (--api-key string --domain string)")
		os.Exit(1)
	}

	if flags.combinedEnrichment && (flags.apiKey == "" || flags.email == "") {
		fmt.Println("Please provide Hunter.io API key and email (--api-key string --email string)")
		os.Exit(1)
	}

	if flags.shodanFlag && flags.apiKey == "" {
		fmt.Println("Please provide Shodan.io api key and URL (--api-key string)")
		os.Exit(1)
	}

	if flags.dnsDumpster && flags.apiKey == "" {
		fmt.Println("Please provide dnsdumpster.com api key and URL (--api-key string)")
		os.Exit(1)
	}

	// Create a wait group to manage goroutines
	var wg sync.WaitGroup

	// Create a mapping of flags to their corresponding functions
	functions := map[bool]func(){
		flags.httpFlag: func() {
			libs.HttpResponse(URL)
		},
		flags.dnsFlag: func() {
			dns.DnsRecords(URL, &wg)
		},
		flags.shodanFlag: func() {
			libs.HostIPQuery(flags.apiKey, URL)
		},
		flags.combinedEnrichment: func() {
			combinedEnrichment.CombinedEnrichment(flags.apiKey, flags.email)
		},
		flags.companyEnrichment: func() {
			companyEnrichment.CompanyEnrichment(flags.apiKey, flags.domain)
		},
		flags.domainSearch: func() {
			domainSearch.DomainSearch(flags.apiKey, flags.domain)
		},
		flags.emailEnrichment: func() {
			emailEnrichment.EmailEnrichment(flags.apiKey, flags.email)
		},
		flags.emailFinder: func() {
			emailFinder.EmailFinder(flags.apiKey, flags.domain, flags.firstName, flags.lastName)
		},
		flags.emailVerifier: func() {
			emailVerifier.EmailVerifier(flags.apiKey, flags.email)
		},
		flags.snmpWalk: func() {
			snmp.SNMPWalk(ipAddress)
		},
		flags.snmpEnumUsers: func() {
			snmp.SNMPEnumUsers(ipAddress)
		},
		flags.snmpEnumShares: func() {
			snmp.SNMPEnumShares(ipAddress)
		},
		flags.ftpScan: func() {
			ftp.FTPScan(ipAddress)
		},
		flags.memcachedScan: func() {
			memcached.MemcachedScan(ipAddress)
		},
		flags.dnsDumpster: func() {
			dns.DnsDumpster(URL, flags.apiKey)
		},
		flags.zoneTransfer: func() {
			dns.ZoneTransfer(URL)
		},
		flags.whois: func() {
			libs.Whois(URL)
		},
		flags.smbEnumUsers: func() {
			smb.SMBEnumUsers(ipAddress)
		},
	}

	// Execute the functions based on the flags
	for flag, function := range functions {
		if flag {
			wg.Add(1)
			go func(fn func()) {
				defer wg.Done()
				fn()
			}(function)
		}
	}

	// Wait for all goroutines to complete
	wg.Wait()
}
