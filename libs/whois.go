package libs

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// WHOIS servers for different TLDs and IP addresses
var whoisServers = map[string]string{
	// Generic TLDs
	".com":     "whois.verisign-grs.com",
	".net":     "whois.verisign-grs.com",
	".org":     "whois.pir.org",
	".info":    "whois.afilias.net",
	".biz":     "whois.biz",
	".io":      "whois.nic.io",
	".mobi":    "whois.dotmobiregistry.net",
	".name":    "whois.nic.name",
	".co":      "whois.nic.co",
	".tv":      "whois.nic.tv",
	".me":      "whois.nic.me",
	".asia":    "whois.nic.asia",
	".edu":     "whois.educause.edu",
	".gov":     "whois.dotgov.gov",
	".jobs":    "whois.nic.jobs",
	".travel":  "whois.nic.travel",
	".tel":     "whois.nic.tel",
	".mil":     "whois.nic.mil",
	".xxx":     "whois.nic.xxx",
	".pro":     "whois.registrypro.pro",
	".cat":     "whois.nic.cat",
	".aero":    "whois.aero",
	".coop":    "whois.nic.coop",
	".museum":  "whois.museum",
	".int":     "whois.iana.org",
	".app":     "whois.nic.google",
	".blog":    "whois.nic.blog",
	".cloud":   "whois.nic.cloud",
	".dev":     "whois.nic.google",
	".online":  "whois.nic.online",
	".shop":    "whois.nic.shop",
	".store":   "whois.nic.store",
	".tech":    "whois.nic.tech",
	".site":    "whois.nic.site",
	".xyz":     "whois.nic.xyz",
	
	// Country TLDs
	".ac":      "whois.nic.ac",
	".ad":      "whois.ripe.net",
	".ae":      "whois.aeda.net.ae",
	".af":      "whois.nic.af",
	".ag":      "whois.nic.ag",
	".ai":      "whois.nic.ai",
	".al":      "whois.ripe.net",
	".am":      "whois.amnic.net",
	".ao":      "whois.nic.ao",
	".aq":      "whois.aq",
	".ar":      "whois.nic.ar",
	".as":      "whois.nic.as",
	".at":      "whois.nic.at",
	".au":      "whois.auda.org.au",
	".aw":      "whois.nic.aw",
	".ax":      "whois.ax",
	".az":      "whois.ripe.net",
	".ba":      "whois.ripe.net",
	".bb":      "whois.nic.bb",
	".bd":      "whois.btcl.net.bd",
	".be":      "whois.dns.be",
	".bf":      "whois.nic.bf",
	".bg":      "whois.register.bg",
	".bh":      "whois.nic.bh",
	".bi":      "whois.nic.bi",
	".bj":      "whois.nic.bj",
	".bm":      "whois.afilias-srs.net",
	".bn":      "whois.bnnic.bn",
	".bo":      "whois.nic.bo",
	".br":      "whois.registro.br",
	".bs":      "whois.nic.bs",
	".bt":      "whois.nic.bt",
	".bw":      "whois.nic.net.bw",
	".by":      "whois.cctld.by",
	".bz":      "whois.afilias-grs.info",
	".ca":      "whois.cira.ca",
	".cc":      "whois.nic.cc",
	".cd":      "whois.nic.cd",
	".cf":      "whois.dot.cf",
	".cg":      "whois.nic.cg",
	".ch":      "whois.nic.ch",
	".ci":      "whois.nic.ci",
	".ck":      "whois.nic.ck",
	".cl":      "whois.nic.cl",
	".cm":      "whois.netcom.cm",
	".cn":      "whois.cnnic.cn",
	".cr":      "whois.nic.cr",
	".cu":      "whois.nic.cu",
	".cv":      "whois.nic.cv",
	".cw":      "whois.nic.cw",
	".cx":      "whois.nic.cx",
	".cy":      "whois.ripe.net",
	".cz":      "whois.nic.cz",
	".de":      "whois.denic.de",
	".dj":      "whois.nic.dj",
	".dk":      "whois.dk-hostmaster.dk",
	".dm":      "whois.nic.dm",
	".do":      "whois.nic.do",
	".dz":      "whois.nic.dz",
	".ec":      "whois.nic.ec",
	".ee":      "whois.tld.ee",
	".eg":      "whois.ripe.net",
	".es":      "whois.nic.es",
	".et":      "whois.ethiotelecom.et",
	".eu":      "whois.eu",
	".fi":      "whois.fi",
	".fj":      "whois.nic.fj",
	".fk":      "whois.nic.fk",
	".fm":      "whois.nic.fm",
	".fo":      "whois.nic.fo",
	".fr":      "whois.nic.fr",
	".ga":      "whois.dot.ga",
	".gd":      "whois.nic.gd",
	".ge":      "whois.nic.ge",
	".gf":      "whois.mediaserv.net",
	".gg":      "whois.gg",
	".gh":      "whois.nic.gh",
	".gi":      "whois2.afilias-grs.net",
	".gl":      "whois.nic.gl",
	".gm":      "whois.nic.gm",
	".gn":      "whois.nic.gn",
	".gp":      "whois.nic.gp",
	".gq":      "whois.dominio.gq",
	".gr":      "whois.nic.gr",
	".gs":      "whois.nic.gs",
	".gt":      "whois.nic.gt",
	".gu":      "whois.nic.gu",
	".gw":      "whois.nic.gw",
	".gy":      "whois.registry.gy",
	".hk":      "whois.hkirc.hk",
	".hm":      "whois.registry.hm",
	".hn":      "whois.nic.hn",
	".hr":      "whois.dns.hr",
	".ht":      "whois.nic.ht",
	".hu":      "whois.nic.hu",
	".id":      "whois.id",
	".ie":      "whois.weare.ie",
	".il":      "whois.isoc.org.il",
	".im":      "whois.nic.im",
	".in":      "whois.registry.in",
	".iq":      "whois.cmc.iq",
	".ir":      "whois.nic.ir",
	".is":      "whois.isnic.is",
	".it":      "whois.nic.it",
	".je":      "whois.je",
	".jm":      "whois.nic.jm",
	".jo":      "whois.dns.jo",
	".jp":      "whois.jprs.jp",
	".ke":      "whois.kenic.or.ke",
	".kg":      "whois.kg",
	".kh":      "whois.nic.kh",
	".ki":      "whois.nic.ki",
	".km":      "whois.nic.km",
	".kn":      "whois.nic.kn",
	".kp":      "whois.kcce.kp",
	".kr":      "whois.kr",
	".kw":      "whois.nic.kw",
	".ky":      "whois.kyregistry.ky",
	".kz":      "whois.nic.kz",
	".la":      "whois.nic.la",
	".lb":      "whois.lbdr.org.lb",
	".lc":      "whois.nic.lc",
	".li":      "whois.nic.li",
	".lk":      "whois.nic.lk",
	".lr":      "whois.nic.lr",
	".ls":      "whois.nic.ls",
	".lt":      "whois.domreg.lt",
	".lu":      "whois.dns.lu",
	".lv":      "whois.nic.lv",
	".ly":      "whois.nic.ly",
	".ma":      "whois.registre.ma",
	".mc":      "whois.ripe.net",
	".md":      "whois.nic.md",
	".mg":      "whois.nic.mg",
	".mh":      "whois.nic.mh",
	".mk":      "whois.marnet.mk",
	".ml":      "whois.dot.ml",
	".mm":      "whois.nic.mm",
	".mn":      "whois.nic.mn",
	".mo":      "whois.monic.mo",
	".mp":      "whois.nic.mp",
	".mq":      "whois.mediaserv.net",
	".mr":      "whois.nic.mr",
	".ms":      "whois.nic.ms",
	".mt":      "whois.nic.mt",
	".mu":      "whois.nic.mu",
	".mv":      "whois.nic.mv",
	".mw":      "whois.nic.mw",
	".mx":      "whois.mx",
	".my":      "whois.mynic.my",
	".mz":      "whois.nic.mz",
	".na":      "whois.na-nic.com.na",
	".nc":      "whois.nc",
	".ne":      "whois.nic.ne",
	".nf":      "whois.nic.nf",
	".ng":      "whois.nic.net.ng",
	".ni":      "whois.nic.ni",
	".nl":      "whois.domain-registry.nl",
	".no":      "whois.norid.no",
	".np":      "whois.nic.np",
	".nr":      "whois.nic.nr",
	".nu":      "whois.iis.nu",
	".nz":      "whois.nic.nz",
	".om":      "whois.registry.om",
	".pa":      "whois.nic.pa",
	".pe":      "kero.yachay.pe",
	".pf":      "whois.registry.pf",
	".pg":      "whois.nic.pg",
	".ph":      "whois.dot.ph",
	".pk":      "whois.pknic.net.pk",
	".pl":      "whois.dns.pl",
	".pm":      "whois.nic.pm",
	".pn":      "whois.nic.pn",
	".pr":      "whois.nic.pr",
	".ps":      "whois.pnina.ps",
	".pt":      "whois.dns.pt",
	".pw":      "whois.nic.pw",
	".py":      "whois.nic.py",
	".qa":      "whois.registry.qa",
	".re":      "whois.nic.re",
	".ro":      "whois.rotld.ro",
	".rs":      "whois.rnids.rs",
	".ru":      "whois.tcinet.ru",
	".rw":      "whois.ricta.org.rw",
	".sa":      "whois.nic.net.sa",
	".sb":      "whois.nic.sb",
	".sc":      "whois.nic.sc",
	".sd":      "whois.nic.sd",
	".se":      "whois.iis.se",
	".sg":      "whois.sgnic.sg",
	".sh":      "whois.nic.sh",
	".si":      "whois.register.si",
	".sj":      "whois.nic.sj",
	".sk":      "whois.sk-nic.sk",
	".sl":      "whois.nic.sl",
	".sm":      "whois.nic.sm",
	".sn":      "whois.nic.sn",
	".so":      "whois.nic.so",
	".sr":      "whois.nic.sr",
	".ss":      "whois.nic.ss",
	".st":      "whois.nic.st",
	".su":      "whois.tcinet.ru",
	".sv":      "whois.nic.sv",
	".sx":      "whois.sx",
	".sy":      "whois.tld.sy",
	".sz":      "whois.nic.sz",
	".tc":      "whois.nic.tc",
	".td":      "whois.nic.td",
	".tf":      "whois.nic.tf",
	".tg":      "whois.nic.tg",
	".th":      "whois.thnic.co.th",
	".tj":      "whois.nic.tj",
	".tk":      "whois.dot.tk",
	".tl":      "whois.nic.tl",
	".tm":      "whois.nic.tm",
	".tn":      "whois.ati.tn",
	".to":      "whois.tonic.to",
	".tr":      "whois.nic.tr",
	".tt":      "whois.nic.tt",
	".tw":      "whois.twnic.net.tw",
	".tz":      "whois.tznic.or.tz",
	".ua":      "whois.ua",
	".ug":      "whois.co.ug",
	".uk":      "whois.nic.uk",
	".us":      "whois.nic.us",
	".uy":      "whois.nic.org.uy",
	".uz":      "whois.cctld.uz",
	".va":      "whois.ripe.net",
	".vc":      "whois.nic.vc",
	".ve":      "whois.nic.ve",
	".vg":      "whois.nic.vg",
	".vi":      "whois.nic.vi",
	".vn":      "whois.vnnic.vn",
	".vu":      "whois.nic.vu",
	".wf":      "whois.nic.wf",
	".ws":      "whois.website.ws",
	".ye":      "whois.y.net.ye",
	".yt":      "whois.nic.yt",
	".za":      "whois.registry.net.za",
	".zm":      "whois.zicta.zm",
	".zw":      "whois.nic.zw",
	
	// IP addresses
	"ipv4":     "whois.arin.net",
	"ipv6":     "whois.arin.net",
}

// Default WHOIS server if TLD not found
const defaultWhoisServer = "whois.iana.org"

// Timeout for WHOIS connections
const timeout = 10 * time.Second

func Whois(URL string) {
	// Trim whitespace and newlines
	query := strings.TrimSpace(URL)
	
	if query == "" {
		fmt.Println("No input provided")
		return
	}
	
	// Remove protocol prefixes if present (http://, https://, etc.)
	query = cleanURL(query)
	
	result, err := performWhoisLookup(query)
	if err != nil {
		fmt.Println("Error performing WHOIS lookup:", err)
		return
	}

	fmt.Println(result)
}

// cleanURL removes protocol prefixes and paths from URLs
func cleanURL(url string) string {
	// Remove http:// or https://
	url = strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
	
	// Remove path and query parameters (everything after first '/')
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	
	return url
}

// performWhoisLookup determines whether the query is an IP or domain and performs the lookup
func performWhoisLookup(query string) (string, error) {
	var server string
	
	// Check if the query is an IP address
	if ip := net.ParseIP(query); ip != nil {
		if ip.To4() != nil {
			server = whoisServers["ipv4"]
		} else {
			server = whoisServers["ipv6"]
		}
	} else {
		// It's a domain, find the appropriate WHOIS server based on TLD
		server = findWhoisServer(query)
	}
	
	return queryWhoisServer(server, query)
}

// findWhoisServer determines the appropriate WHOIS server for a domain
func findWhoisServer(domain string) string {
	for tld, server := range whoisServers {
		if strings.HasSuffix(domain, tld) {
			return server
		}
	}
	
	// If no specific server found, use IANA to get the right one
	result, err := queryWhoisServer(defaultWhoisServer, domain)
	if err != nil {
		return defaultWhoisServer
	}
	
	// Try to extract the whois server from IANA's response
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "whois:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				server := strings.TrimSpace(parts[1])
				if server != "" {
					return server
				}
			}
		}
	}
	
	return defaultWhoisServer
}

// queryWhoisServer connects to a WHOIS server and retrieves information
func queryWhoisServer(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %v", server, err)
	}
	defer conn.Close()
	
	// Set read/write deadlines
	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))
	
	// Send query (with newline)
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", fmt.Errorf("failed to send query to WHOIS server: %v", err)
	}
	
	// Read response
	var response strings.Builder
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				return "", fmt.Errorf("error reading response from WHOIS server: %v", err)
			}
			break
		}
		response.Write(buffer[:n])
	}
	
	return response.String(), nil
}
