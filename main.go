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

	brokenauthentication "github.com/ary4nsh/web-reGOn/libs/broken-authentication"
	brokenauthorization "github.com/ary4nsh/web-reGOn/libs/broken-authorization"
	clientside "github.com/ary4nsh/web-reGOn/libs/client-side"
	identitymanagement "github.com/ary4nsh/web-reGOn/libs/identity-management"
	inputvalidation "github.com/ary4nsh/web-reGOn/libs/input-validation"
	sessionmanagement "github.com/ary4nsh/web-reGOn/libs/session-management"
	weakcryptography "github.com/ary4nsh/web-reGOn/libs/weak-cryptography"

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

	// Authentication
	tls              bool
	rememberPassword bool
	cacheWeakness    bool

	// Broken Authorization
	dirTraversal        bool
	bypassAuth          bool
	dirTraversalDstPath string
	dirTraversalDepth   int
	dirTraversalTimeout int
	dirTraversalURL     string
	dirTraversalPattern string

	// Session Management
	sessionCookie bool
	cacheControl  bool

	// Input Validation
	reflectedXSS            bool
	httpVerbTampering       bool
	httpVerbCookies         string
	httpVerbHeaders         []string
	httpVerbThread          int
	httpVerbFollowRedirects bool
	httpVerbWebDAVMethods   bool

	// Client-side
	htmlInjection bool

	// Weak Cryptography / TLS
	drown                 bool
	lucky13               bool
	beast                 bool
	anonymousCiphers      bool
	freak                 bool
	nomore                bool
	nullCiphers           bool
	crime                 bool
	insecureRenegotiation bool
	logjam                bool
	breach                bool
	sweet32               bool
	heartbleed            bool
	poodle                bool
	tlsFallbackSCSV       bool
	winshock              bool
	ticketbleed           bool
	ccsInjection          bool
	testAll               bool

	// Padding oracle
	paddingOracle        bool
	paddingOracleToken   string
	paddingOracleEnc     int
	paddingOracleErrMsg  string
	paddingOracleBlock   int
	paddingOracleCookies []string

	// Others
	apiKey      string
	payloadFile string
	domain      string
	firstName   string
	lastName    string
	email       string
	port        string
	wordlist    string
	userlist    string
	passlist    string
	mac         string
	threads     int
}

// task pairs an enable flag with the function to run.
type task struct {
	on bool
	fn func()
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

	"tls":               "Authentication",
	"remember-password": "Authentication",
	"cache-weakness":    "Authentication",

	"dir-traversal": "Broken Authorization",
	"bypass-auth":   "Broken Authorization",
	"depth":         "Broken Authorization",
	"timeout":       "Broken Authorization",
	"url":           "Broken Authorization",
	"pattern":       "Broken Authorization",

	"session-cookie": "Session Management",
	"cache-control":  "Session Management",

	"reflected-xss":       "Input Validation",
	"http-verb-tampering": "Input Validation",
	"cookies":             "Input Validation",
	"thread":              "Input Validation",
	"follow-redirects":    "Input Validation",
	"webdav-methods":      "Input Validation",

	"html-injection": "Client-side",

	"drown":                  "Weak Cryptography",
	"lucky13":                "Weak Cryptography",
	"beast":                  "Weak Cryptography",
	"anonymous-ciphers":      "Weak Cryptography",
	"freak":                  "Weak Cryptography",
	"nomore":                 "Weak Cryptography",
	"null-ciphers":           "Weak Cryptography",
	"crime":                  "Weak Cryptography",
	"insecure-renegotiation": "Weak Cryptography",
	"logjam":                 "Weak Cryptography",
	"breach":                 "Weak Cryptography",
	"sweet32":                "Weak Cryptography",
	"heartbleed":             "Weak Cryptography",
	"poodle":                 "Weak Cryptography",
	"tls-fallback-scsv":      "Weak Cryptography",
	"winshock":               "Weak Cryptography",
	"ticketbleed":            "Weak Cryptography",
	"ccs-injection":          "Weak Cryptography",
	"test-all":               "Weak Cryptography",

	"padding-oracle": "Weak Cryptography",
	"token":          "Weak Cryptography",
	"encoding":       "Weak Cryptography",
	"error-msg":      "Weak Cryptography",
	"block-size":     "Weak Cryptography",
	"po-cookie":      "Weak Cryptography",

	// Shared across multiple feature groups
	"dst-path":     "Shared",
	"payload-file": "Shared",
	"header":       "Shared",
	"port":         "Shared",
	"wordlist":     "Shared",
	"threads":      "Shared",
	"api-key":      "Shared",
	"email":        "Shared",
	"domain":       "Shared",
	"userlist":     "Shared",
	"passlist":     "Shared",
}

func anyFlagSet(flags Flags) bool {
	return flags.dnsFlag || flags.httpFlag || flags.httpOptions || flags.hstsHeader ||
		flags.shodanFlag || flags.combinedEnrichment || flags.companyEnrichment ||
		flags.domainSearch || flags.emailEnrichment ||
		flags.emailFinder || flags.emailVerifier ||
		flags.snmpWalk || flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
		flags.memcachedScan || flags.dnsDumpster || flags.zoneTransfer ||
		flags.whois || flags.cspHeader || flags.riaHeader || flags.pathConfusion ||
		flags.waf || flags.hiddenDirectories || flags.cookieAndAccount ||
		flags.statusCodeEnum || flags.errorMessageEnum || flags.nonexistentUserEnum ||
		flags.dnsLookup || flags.dnsPropagation || flags.ipHistory || flags.macAddressLookup ||
		flags.multiplePing || flags.reverseDns || flags.subdomainDiscovery || flags.traceroute ||
		flags.tls || flags.rememberPassword || flags.cacheWeakness || flags.sessionCookie || flags.cacheControl ||
		flags.drown || flags.lucky13 || flags.beast || flags.anonymousCiphers || flags.freak || flags.nomore ||
		flags.nullCiphers || flags.crime || flags.insecureRenegotiation || flags.logjam || flags.breach ||
		flags.sweet32 || flags.heartbleed || flags.poodle || flags.tlsFallbackSCSV || flags.winshock ||
		flags.ticketbleed || flags.ccsInjection || flags.testAll || flags.paddingOracle ||
		flags.reflectedXSS || flags.httpVerbTampering || flags.htmlInjection ||
		flags.dirTraversal || flags.bypassAuth
}

func main() {
	var flags Flags

	var rootCmd = &cobra.Command{
		Use:   "web-reGOn [url]",
		Short: "A simple recon tool",
		Long:  "web-reGOn is a reconnaissance tool",
		Run: func(cmd *cobra.Command, args []string) {
			if !anyFlagSet(flags) {
				cmd.Help()
				return
			}

			// ---- Argument validation ----

			if flags.reflectedXSS && flags.payloadFile == "" {
				fmt.Println("Please provide payload file path when using --reflected-xss (--payload-file string)")
				return
			}

			if flags.htmlInjection && flags.payloadFile == "" {
				fmt.Println("Please provide payload file path when using --html-injection (--payload-file string)")
				return
			}

			if flags.dirTraversal {
				if flags.dirTraversalDstPath == "" {
					fmt.Println("Please provide destination path when using --dir-traversal (--dst-path string)")
					return
				}
				hasURL := flags.dirTraversalURL != ""
				hasPayload := flags.payloadFile != ""
				if hasURL == hasPayload {
					fmt.Println("Please provide exactly one of --url or --payload-file when using --dir-traversal")
					return
				}
			}

			if flags.bypassAuth && flags.dirTraversalDstPath == "" {
				fmt.Println("Please provide destination path(s) when using --bypass-auth (--dst-path string)")
				return
			}

			if flags.pathConfusion && flags.wordlist == "" {
				fmt.Println("Please provide wordlist path when using --path-confusion (--wordlist string)")
				return
			}

			if flags.hiddenDirectories && flags.wordlist == "" {
				fmt.Println("Please provide wordlist path when using --hidden-directories (--wordlist string)")
				return
			}

			if flags.cookieAndAccount && flags.wordlist == "" {
				fmt.Println("Please provide wordlist path when using --cookie-and-account (--wordlist string)")
				return
			}

			if flags.emailFinder {
				if flags.apiKey == "" || flags.domain == "" || flags.firstName == "" || flags.lastName == "" {
					fmt.Println("Please provide Hunter.io API key, domain, first name, and last name (--api-key string --domain string --first-name string --last-name string)")
					return
				}
			}

			if flags.emailVerifier || flags.emailEnrichment || flags.combinedEnrichment {
				if flags.apiKey == "" || flags.email == "" {
					fmt.Println("Please provide Hunter.io API key and email (--api-key string --email string)")
					return
				}
			}

			if flags.domainSearch || flags.companyEnrichment {
				if flags.apiKey == "" || flags.domain == "" {
					fmt.Println("Please provide Hunter.io API key and domain name (--api-key string --domain string)")
					return
				}
			}

			if flags.shodanFlag && flags.apiKey == "" {
				fmt.Println("Please provide Shodan.io API key and URL (--api-key string)")
				return
			}

			if flags.dnsDumpster && flags.apiKey == "" {
				fmt.Println("Please provide dnsdumpster.com API key and URL (--api-key string)")
				return
			}

			if flags.statusCodeEnum || flags.errorMessageEnum {
				if flags.userlist == "" || flags.passlist == "" {
					fmt.Println("Please provide userlist and passlist paths when using --status-code-enum / --error-message-enum (--userlist string --passlist string)")
					return
				}
			}

			if flags.nonexistentUserEnum && flags.userlist == "" {
				fmt.Println("Please provide userlist path when using --nonexistent-user-enum (--userlist string)")
				return
			}

			if flags.macAddressLookup && (flags.apiKey == "" || flags.mac == "") {
				fmt.Println("Please provide viewdns.info API key and MAC address (--api-key string --mac string)")
				return
			}

			if (flags.dnsLookup || flags.dnsPropagation || flags.ipHistory || flags.multiplePing ||
				flags.reverseDns || flags.subdomainDiscovery || flags.traceroute) && flags.apiKey == "" {
				fmt.Println("Please provide viewdns.info API key (--api-key string)")
				return
			}

			if flags.paddingOracle && flags.paddingOracleToken == "" {
				fmt.Println("Please provide the captured ciphertext sample when using --padding-oracle (--token string)")
				return
			}

			requiresTarget := flags.dnsFlag || flags.httpFlag || flags.httpOptions || flags.hstsHeader ||
				flags.snmpEnumUsers || flags.snmpEnumShares || flags.ftpScan ||
				flags.memcachedScan || flags.pathConfusion || flags.hiddenDirectories ||
				flags.cookieAndAccount || flags.statusCodeEnum || flags.errorMessageEnum ||
				flags.nonexistentUserEnum || flags.tls || flags.rememberPassword || flags.cacheWeakness ||
				flags.sessionCookie || flags.cacheControl || flags.drown || flags.lucky13 || flags.beast ||
				flags.anonymousCiphers || flags.freak || flags.nomore || flags.nullCiphers || flags.waf ||
				flags.zoneTransfer || flags.whois || flags.cspHeader || flags.riaHeader || flags.crime ||
				flags.insecureRenegotiation || flags.logjam || flags.breach || flags.sweet32 ||
				flags.heartbleed || flags.poodle || flags.tlsFallbackSCSV || flags.winshock ||
				flags.ticketbleed || flags.ccsInjection || flags.testAll || flags.paddingOracle ||
				flags.reflectedXSS || flags.httpVerbTampering || flags.htmlInjection ||
				flags.dirTraversal || flags.bypassAuth

			var URL, ipAddress string
			if requiresTarget {
				if len(args) == 0 {
					fmt.Println("Please provide a URL or an IP address")
					return
				}
				URL = args[0]
				ipAddress = args[0]
			}

			// ---- Sequential tasks (run on main goroutine) ----

			if flags.reflectedXSS {
				inputvalidation.ReflectedXSS(URL, flags.payloadFile)
			}

			if flags.htmlInjection {
				clientside.HTMLInjection(URL, flags.payloadFile)
			}

			if flags.dirTraversal {
				port := brokenauthorization.ParsePort(flags.port)
				brokenauthorization.DirectoryTraversal(brokenauthorization.Options{
					Host:        URL,
					Port:        port,
					DstPath:     flags.dirTraversalDstPath,
					Depth:       flags.dirTraversalDepth,
					TimeoutMs:   flags.dirTraversalTimeout,
					URL:         flags.dirTraversalURL,
					PayloadFile: flags.payloadFile,
					Pattern:     flags.dirTraversalPattern,
				})
			}

			if flags.bypassAuth {
				port := brokenauthorization.ParsePort(flags.port)
				brokenauthorization.BypassAuth(brokenauthorization.BypassAuthOptions{
					Host:    URL,
					Port:    port,
					DstPath: flags.dirTraversalDstPath,
					Headers: flags.httpVerbHeaders,
				})
			}

			if flags.httpVerbTampering {
				port := flags.port
				if port == "" {
					port = "80"
				}
				inputvalidation.HTTPVerbTampering(URL, port, flags.httpVerbThread, flags.httpVerbCookies, flags.httpVerbHeaders, flags.wordlist, flags.httpVerbFollowRedirects, flags.httpVerbWebDAVMethods)
			}

			if weakcryptography.AnyFlag(toWeakCryptoFlags(flags)) {
				weakcryptography.RunTests(toWeakCryptoFlags(flags), URL, flags.port)
			}

			if flags.paddingOracle {
				weakcryptography.PaddingOracle(URL, flags.port, weakcryptography.PaddingOracleOptions{
					Token:     flags.paddingOracleToken,
					Encoding:  flags.paddingOracleEnc,
					ErrorMsg:  flags.paddingOracleErrMsg,
					BlockSize: flags.paddingOracleBlock,
					Cookies:   flags.paddingOracleCookies,
				})
			}

			// ---- Concurrent tasks ----

			var wg sync.WaitGroup
			tasks := []task{
				// Reconnaissance
				{flags.httpFlag, func() {
					reconnaissance.HttpResponse(URL, &wg)
				}},
				{flags.dnsFlag, func() {
					wg.Add(1)
					go func() {
						reconnaissance.DnsRecords(URL, &wg)
						wg.Done()
					}()
				}},
				{flags.waf, func() {
					found, name := reconnaissance.WafDetect(URL, flags.port)
					if found {
						fmt.Printf("WAF detected: %s\n", name)
					} else {
						fmt.Println("No WAF recognised")
					}
				}},
				{flags.zoneTransfer, func() { reconnaissance.ZoneTransfer(URL) }},
				{flags.whois, func() { reconnaissance.Whois(URL) }},

				// Open Source Intelligence
				{flags.dnsDumpster, func() { osint.DnsDumpster(URL, flags.apiKey) }},
				{flags.shodanFlag, func() { osint.HostIPQuery(flags.apiKey, URL) }},
				{flags.combinedEnrichment, func() { combinedEnrichment.CombinedEnrichment(flags.apiKey, flags.email) }},
				{flags.companyEnrichment, func() { companyEnrichment.CompanyEnrichment(flags.apiKey, flags.domain) }},
				{flags.domainSearch, func() { domainSearch.DomainSearch(flags.apiKey, flags.domain) }},
				{flags.emailEnrichment, func() { emailEnrichment.EmailEnrichment(flags.apiKey, flags.email) }},
				{flags.emailFinder, func() {
					emailFinder.EmailFinder(flags.apiKey, flags.domain, flags.firstName, flags.lastName)
				}},
				{flags.emailVerifier, func() { emailVerifier.EmailVerifier(flags.apiKey, flags.email) }},
				{flags.dnsLookup, func() { dnsLookup.DnsLookup(flags.apiKey, flags.email) }},
				{flags.dnsPropagation, func() { dnsPropagation.DnsPropagation(flags.apiKey, flags.email) }},
				{flags.ipHistory, func() { ipHistory.IpHistory(flags.apiKey, flags.email) }},
				{flags.ipLocation, func() { ipLocation.IpLocation(flags.apiKey, flags.email) }},
				{flags.macAddressLookup, func() { macLookup.MacLookup(flags.apiKey, flags.mac) }},
				{flags.multiplePing, func() { multiplePing.MultiplePing(flags.apiKey, flags.email) }},
				{flags.reverseDns, func() { reverseDns.ReverseDns(flags.apiKey, flags.email) }},
				{flags.subdomainDiscovery, func() { subdomainDiscovery.SubdomainDiscovery(flags.apiKey, flags.email) }},
				{flags.traceroute, func() { traceroute.Traceroute(flags.apiKey, flags.email) }},

				// Misconfiguration
				{flags.httpOptions, func() { http.HttpOptions(URL, flags.port) }},
				{flags.hstsHeader, func() { http.HstsHeaderWithPort(URL, flags.port) }},
				{flags.cspHeader, func() { http.CspHeader(URL, flags.port) }},
				{flags.riaHeader, func() { http.RichInternetApplication(URL, flags.port) }},
				{flags.pathConfusion, func() { http.PathConfusion(URL, flags.wordlist, flags.threads) }},
				{flags.snmpWalk, func() { snmp.SNMPWalk(ipAddress, flags.port) }},
				{flags.snmpEnumUsers, func() { snmp.SNMPEnumUsers(ipAddress, flags.port) }},
				{flags.snmpEnumShares, func() { snmp.SNMPEnumShares(ipAddress, flags.port) }},
				{flags.ftpScan, func() { ftp.FTPScan(ipAddress, flags.port) }},
				{flags.memcachedScan, func() { memcached.MemcachedScan(ipAddress, flags.port) }},

				// Identity Management
				{flags.hiddenDirectories, func() { identitymanagement.HiddenDirectories(URL, flags.wordlist, flags.threads) }},
				{flags.cookieAndAccount, func() { identitymanagement.CookieAndAccount(URL, flags.wordlist, flags.threads) }},
				{flags.statusCodeEnum, func() { identitymanagement.StatusCodeEnum(URL, flags.userlist, flags.passlist, flags.threads) }},
				{flags.errorMessageEnum, func() { identitymanagement.ErrorMessageEnum(URL, flags.userlist, flags.passlist, flags.threads) }},
				{flags.nonexistentUserEnum, func() { identitymanagement.NonexistentUserEnum(URL, flags.userlist, flags.threads) }},

				// Authentication
				{flags.tls, func() { brokenauthentication.TlsTest(URL, flags.port) }},
				{flags.rememberPassword, func() { brokenauthentication.ResetPassword(URL, flags.port) }},
				{flags.cacheWeakness, func() { brokenauthentication.CacheWeakness(URL, flags.port) }},

				// Session Management
				{flags.sessionCookie, func() { sessionmanagement.SessionCookie(URL, flags.port) }},
				{flags.cacheControl, func() { sessionmanagement.CacheControl(URL, flags.port) }},
			}

			for _, t := range tasks {
				if t.on {
					wg.Add(1)
					go func(fn func()) {
						defer wg.Done()
						fn()
					}(t.fn)
				}
			}

			wg.Wait()
		},
	}

	rootCmd.Flags().SetInterspersed(true)

	// Reconnaissance
	rootCmd.Flags().BoolVarP(&flags.dnsFlag, "dns", "D", false, "DNS Records")
	rootCmd.Flags().BoolVarP(&flags.httpFlag, "http", "H", false, "HTTP Status Code")
	rootCmd.Flags().BoolVar(&flags.zoneTransfer, "zone-transfer", false, "Perform zone transfer on a domain")
	rootCmd.Flags().BoolVar(&flags.whois, "whois", false, "Query for Whois records")
	rootCmd.Flags().BoolVar(&flags.waf, "waf", false, "Detect Web Application Firewall")

	// Open Source Intelligence
	rootCmd.Flags().BoolVarP(&flags.shodanFlag, "shodan", "S", false, "Shodan Host IP Query")
	rootCmd.Flags().BoolVar(&flags.combinedEnrichment, "combined-enrichment", false, "Company and Email enrichment information")
	rootCmd.Flags().BoolVar(&flags.companyEnrichment, "company-enrichment", false, "Company enrichment information")
	rootCmd.Flags().BoolVar(&flags.domainSearch, "domain-search", false, "Domain search for email addresses")
	rootCmd.Flags().BoolVar(&flags.emailEnrichment, "email-enrichment", false, "Email enrichment information")
	rootCmd.Flags().BoolVar(&flags.emailFinder, "email-finder", false, "Find email address from domain and person names")
	rootCmd.Flags().BoolVar(&flags.emailVerifier, "email-verifier", false, "Verify email address deliverability")
	rootCmd.Flags().BoolVar(&flags.dnsDumpster, "dns-dumpster", false, "Find & look up DNS records from dnsdumpster.com")
	rootCmd.Flags().BoolVar(&flags.dnsLookup, "dns-lookup", false, "Find & look up DNS records from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.dnsPropagation, "dns-propagation", false, "Check if recent DNS changes have propagated from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.ipHistory, "ip-history", false, "Show historical IP addresses for a domain from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.ipLocation, "ip-location", false, "Return the geographical location of an IP address from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.multiplePing, "multiple-ping", false, "Check latency and packet loss from multiple locations from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.reverseDns, "reverse-dns", false, "Return DNS PTR record for an IP address from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.subdomainDiscovery, "subdomain-discovery", false, "List subdomains for a domain from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.macAddressLookup, "mac-address-lookup", false, "Look up the manufacturer of a MAC address from viewdns.info")
	rootCmd.Flags().BoolVar(&flags.traceroute, "traceroute", false, "Trace the network path to a host from viewdns.info")

	// Misconfiguration
	rootCmd.Flags().BoolVar(&flags.httpOptions, "http-options", false, "HTTP OPTIONS Method Check")
	rootCmd.Flags().BoolVar(&flags.hstsHeader, "hsts-header", false, "Check HSTS and security headers")
	rootCmd.Flags().BoolVar(&flags.cspHeader, "csp", false, "Analyse Content-Security-Policy header")
	rootCmd.Flags().BoolVar(&flags.pathConfusion, "path-confusion", false, "Path Confusion testing with wordlist and optional threads")
	rootCmd.Flags().BoolVar(&flags.riaHeader, "ria", false, "Check crossdomain.xml and clientaccesspolicy.xml")
	rootCmd.Flags().BoolVar(&flags.snmpWalk, "snmp-walk", false, "Perform SNMP walk on IP address")
	rootCmd.Flags().BoolVar(&flags.snmpEnumUsers, "snmp-enumusers", false, "Enumerate SNMP Windows users")
	rootCmd.Flags().BoolVar(&flags.snmpEnumShares, "snmp-enumshares", false, "Enumerate SNMP Windows SMB shares")
	rootCmd.Flags().BoolVar(&flags.ftpScan, "ftp", false, "Scan FTP server")
	rootCmd.Flags().BoolVar(&flags.memcachedScan, "memcached", false, "Scan Memcached server")

	// Identity Management
	rootCmd.Flags().BoolVar(&flags.hiddenDirectories, "hidden-directories", false, "Discover hidden directories using wordlist")
	rootCmd.Flags().BoolVar(&flags.statusCodeEnum, "status-code-enum", false, "Enumerate users by status code using username and password lists")
	rootCmd.Flags().BoolVar(&flags.errorMessageEnum, "error-message-enum", false, "Enumerate users by error messages and status codes using username and password lists")
	rootCmd.Flags().BoolVar(&flags.nonexistentUserEnum, "nonexistent-user-enum", false, "Enumerate users with username list and fake password")
	rootCmd.Flags().BoolVar(&flags.cookieAndAccount, "cookie-and-account", false, "Cookie analysis and CMS account enumeration using wordlist")

	// Authentication
	rootCmd.Flags().BoolVar(&flags.tls, "tls", false, "Test for TLS/SSL cipher suites security")
	rootCmd.Flags().BoolVar(&flags.rememberPassword, "remember-password", false, "Check reset password security")
	rootCmd.Flags().BoolVar(&flags.cacheWeakness, "cache-weakness", false, "Check cache-related headers and meta tags for browser cache weakness")

	// Broken Authorization
	rootCmd.Flags().BoolVar(&flags.dirTraversal, "dir-traversal", false, "Fuzz directory traversal using TRAVERSAL marker in --url or --payload-file")
	rootCmd.Flags().BoolVar(&flags.bypassAuth, "bypass-auth", false, "Test authorization bypass via rewrite-URL and client-IP headers")
	rootCmd.Flags().StringVar(&flags.dirTraversalDstPath, "dst-path", "", "Destination path(s): file for --dir-traversal (e.g. /etc/passwd), or protected path(s) for --bypass-auth (e.g. /admin,/secret)")
	rootCmd.Flags().IntVar(&flags.dirTraversalDepth, "depth", 1, "Traversal depth (e.g. 1 => ../ ; default: 1)")
	rootCmd.Flags().IntVar(&flags.dirTraversalTimeout, "timeout", 500, "Delay in milliseconds between each traversal probe")
	rootCmd.Flags().StringVar(&flags.dirTraversalURL, "url", "", "URL containing TRAVERSAL marker to fuzz (mutually exclusive with --payload-file)")
	rootCmd.Flags().StringVar(&flags.dirTraversalPattern, "pattern", "", "Optional response match pattern (auto-detected from --dst-path when omitted)")

	// Session Management
	rootCmd.Flags().BoolVar(&flags.sessionCookie, "session-cookie", false, "Analyse session cookie security")
	rootCmd.Flags().BoolVar(&flags.cacheControl, "cache-control", false, "Check Cache-Control, Expires, and Strict-Transport-Security headers")

	// Input Validation
	rootCmd.Flags().BoolVar(&flags.reflectedXSS, "reflected-xss", false, "Test for reflected XSS via headless browser")
	rootCmd.Flags().StringVar(&flags.payloadFile, "payload-file", "", "Path to payload file (XSS/HTML injection payloads, or raw HTTP request template with TRAVERSAL for --dir-traversal)")
	rootCmd.Flags().BoolVar(&flags.httpVerbTampering, "http-verb-tampering", false, "Enumerate and test HTTP methods for verb tampering")
	rootCmd.Flags().StringVar(&flags.httpVerbCookies, "cookies", "", "Cookies for HTTP verb tampering requests (e.g. \"cookie1=value; cookie2=value\")")
	rootCmd.Flags().StringArrayVar(&flags.httpVerbHeaders, "header", nil, "HTTP header \"Name: value\" (repeatable)")
	rootCmd.Flags().IntVar(&flags.httpVerbThread, "thread", 0, "Number of threads for HTTP verb tampering (default: 5)")
	rootCmd.Flags().BoolVar(&flags.httpVerbFollowRedirects, "follow-redirects", false, "Follow HTTP redirects when testing methods")
	rootCmd.Flags().BoolVar(&flags.httpVerbWebDAVMethods, "webdav-methods", false, "Include WebDAV methods in verb tampering tests")

	// Client-side
	rootCmd.Flags().BoolVar(&flags.htmlInjection, "html-injection", false, "Test for HTML injection via headless browser")

	// Weak Cryptography / TLS
	rootCmd.Flags().BoolVar(&flags.drown, "drown", false, "Test for SSLv2 DROWN vulnerabilities (CVE-2015-3197, CVE-2016-0703, CVE-2016-0800)")
	rootCmd.Flags().BoolVar(&flags.lucky13, "lucky13", false, "Test for Lucky13 (CVE-2013-0169) TLS CBC vulnerability")
	rootCmd.Flags().BoolVar(&flags.beast, "beast", false, "Test for BEAST (CVE-2011-3389) SSLv3/TLS 1.0 CBC vulnerability")
	rootCmd.Flags().BoolVar(&flags.anonymousCiphers, "anonymous-ciphers", false, "Test for anonymous cipher suites")
	rootCmd.Flags().BoolVar(&flags.freak, "freak", false, "Test for FREAK (CVE-2015-0204) export RSA cipher suites")
	rootCmd.Flags().BoolVar(&flags.nomore, "nomore", false, "Test for NOMORE (CVE-2013-2566) RC4 cipher suites")
	rootCmd.Flags().BoolVar(&flags.nullCiphers, "null-ciphers", false, "Test for NULL cipher suites")
	rootCmd.Flags().BoolVar(&flags.crime, "crime", false, "Test for CRIME (CVE-2012-4929) TLS compression")
	rootCmd.Flags().BoolVar(&flags.insecureRenegotiation, "insecure-renegotiation", false, "Test for insecure TLS renegotiation (RFC 5746 / CVE-2011-1473)")
	rootCmd.Flags().BoolVar(&flags.logjam, "logjam", false, "Test for LOGJAM (CVE-2015-4000) DH EXPORT")
	rootCmd.Flags().BoolVar(&flags.breach, "breach", false, "Test for BREACH (CVE-2013-3587) HTTP compression")
	rootCmd.Flags().BoolVar(&flags.sweet32, "sweet32", false, "Test for SWEET32 (CVE-2016-2183) 64-bit block ciphers")
	rootCmd.Flags().BoolVar(&flags.heartbleed, "heartbleed", false, "Test for Heartbleed (CVE-2014-0160)")
	rootCmd.Flags().BoolVar(&flags.poodle, "poodle", false, "Test for POODLE SSL (CVE-2014-3566) and TLS (CVE-2014-8730)")
	rootCmd.Flags().BoolVar(&flags.tlsFallbackSCSV, "tls-fallback-scsv", false, "Check TLS_FALLBACK_SCSV (RFC 7507) downgrade protection")
	rootCmd.Flags().BoolVar(&flags.winshock, "winshock", false, "Test for Winshock (CVE-2014-6321)")
	rootCmd.Flags().BoolVar(&flags.ticketbleed, "ticketbleed", false, "Test for Ticketbleed (CVE-2016-9244)")
	rootCmd.Flags().BoolVar(&flags.ccsInjection, "ccs-injection", false, "Test for CCS injection (CVE-2014-0224)")
	rootCmd.Flags().BoolVar(&flags.testAll, "test-all", false, "Run all TLS vulnerability checks in order")

	// Padding oracle (PadBuster decrypt mode)
	rootCmd.Flags().BoolVar(&flags.paddingOracle, "padding-oracle", false, "Decrypt a CBC token through a padding oracle (target URL is the positional argument, e.g. http://host/encrypt?data=...)")
	rootCmd.Flags().StringVar(&flags.paddingOracleToken, "token", "", "Captured ciphertext sample token to decrypt")
	rootCmd.Flags().IntVar(&flags.paddingOracleEnc, "encoding", 0, "Token encoding: 0=Base64 1=Lower HEX 2=Upper HEX 3=.NET UrlToken 4=WebSafe Base64")
	rootCmd.Flags().StringVar(&flags.paddingOracleErrMsg, "error-msg", "", "String present in responses with a padding error (skips automatic oracle detection)")
	rootCmd.Flags().IntVar(&flags.paddingOracleBlock, "block-size", 16, "Cipher block size in bytes")
	rootCmd.Flags().StringArrayVar(&flags.paddingOracleCookies, "po-cookie", nil, "Cookie \"name=value\" containing the token, sent with each oracle request (repeatable)")

	// Others
	rootCmd.Flags().StringVar(&flags.domain, "domain", "", "Domain to search for email")
	rootCmd.Flags().StringVar(&flags.firstName, "first-name", "", "First name of the person")
	rootCmd.Flags().StringVar(&flags.lastName, "last-name", "", "Last name of the person")
	rootCmd.Flags().StringVar(&flags.userlist, "userlist", "", "Username list file path")
	rootCmd.Flags().StringVar(&flags.passlist, "passlist", "", "Password list file path")
	rootCmd.Flags().StringVar(&flags.apiKey, "api-key", "", "API key")
	rootCmd.Flags().StringVar(&flags.email, "email", "", "Email address to verify")
	rootCmd.Flags().StringVarP(&flags.port, "port", "p", "", "Port number (e.g. for HTTP OPTIONS or FTP scan)")
	rootCmd.Flags().StringVarP(&flags.wordlist, "wordlist", "w", "", "Wordlist file path")
	rootCmd.Flags().StringVar(&flags.mac, "mac", "", "MAC address")
	rootCmd.Flags().IntVarP(&flags.threads, "threads", "t", 50, "Number of concurrent threads (default: 50)")

	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Println("Usage:")
		fmt.Println("  web-reGOn [url] [flags]")
		fmt.Println()

		groups := make(map[string][]string)

		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			group := flagGroups[f.Name]
			if group == "" {
				group = "Shared"
			}
			line := fmt.Sprintf("      --%-20s %s", f.Name, f.Usage)
			if f.Shorthand != "" {
				line = fmt.Sprintf("  -%s, --%-20s %s", f.Shorthand, f.Name, f.Usage)
			}
			groups[group] = append(groups[group], line)
		})

		order := []string{
			"Reconnaissance", "Open Source Intelligence", "Misconfiguration",
			"Identity Management", "Authentication", "Broken Authorization",
			"Session Management", "Input Validation", "Weak Cryptography",
			"Client-side", "Shared",
		}
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

func toWeakCryptoFlags(f Flags) weakcryptography.RunnerFlags {
	return weakcryptography.RunnerFlags{
		TestAll:               f.testAll,
		AnonymousCiphers:      f.anonymousCiphers,
		Beast:                 f.beast,
		Drown:                 f.drown,
		Freak:                 f.freak,
		Lucky13:               f.lucky13,
		Nomore:                f.nomore,
		NullCiphers:           f.nullCiphers,
		InsecureRenegotiation: f.insecureRenegotiation,
		Breach:                f.breach,
		Crime:                 f.crime,
		CCSInjection:          f.ccsInjection,
		Heartbleed:            f.heartbleed,
		Logjam:                f.logjam,
		Poodle:                f.poodle,
		Sweet32:               f.sweet32,
		Ticketbleed:           f.ticketbleed,
		TLSFallbackSCSV:       f.tlsFallbackSCSV,
		Winshock:              f.winshock,
	}
}
