# web-reGOn
This is a simple web reconnaissance and security testing tool built in Go for web application security assessment

## Requirements
- [Go](https://go.dev/doc/install) 1.19 or higher

## Build from source
```
# Clone the repository
git clone https://github.com/ary4nsh/web-reGOn.git
cd web-reGOn

# Install dependencies
go mod download

# Build the binary
go build -o web-reGOn

# Run the tool
./web-reGOn --help
```

## Documentation
The documentation of this tool is available [here](https://github.com/ary4nsh/web-reGOn/tree/main/Documentation)

## Usage
```bash
[Reconnaissance]
  -D, --dns                  DNS Records
  -H, --http                 HTTP Status Code
      --waf                  Detect Web Application Firewall
      --whois                Query for Whois records
      --zone-transfer        Perform zone transfer on a domain

[Open Source Intelligence]
      --combined-enrichment  Company and Email enrichment information
      --company-enrichment   Company enrichment information
      --dns-dumpster         Find & look up DNS records from dnsdumpster.com
      --dns-lookup           Find & look up DNS records from viewdns.info
      --dns-propagation      Check if recent DNS changes have propagated from viewdns.info
      --domain-search        Domain search for email addresses
      --email-enrichment     Email enrichment information
      --email-finder         Find email address from domain and person names
      --email-verifier       Verify email address deliverability
      --ip-history           Show historical IP addresses for a domain from viewdns.info
      --ip-location          Return the geographical location of an IP address from viewdns.info
      --mac-address-lookup   Look up the manufacturer of a MAC address from viewdns.info
      --multiple-ping        Check latency and packet loss from multiple locations from viewdns.info
      --reverse-dns          Return DNS PTR record for an IP address from viewdns.info
  -S, --shodan               Shodan Host IP Query
      --subdomain-discovery  List subdomains for a domain from viewdns.info
      --traceroute           Trace the network path to a host from viewdns.info

[Misconfiguration]
      --csp                  Analyse Content-Security-Policy header
      --ftp                  Scan FTP server
      --hsts-header          Check HSTS and security headers
      --http-options         HTTP OPTIONS Method Check
      --memcached            Scan Memcached server
      --path-confusion       Path Confusion testing with wordlist and optional threads
      --ria                  Check crossdomain.xml and clientaccesspolicy.xml
      --snmp-enumshares      Enumerate SNMP Windows SMB shares
      --snmp-enumusers       Enumerate SNMP Windows users
      --snmp-walk            Perform SNMP walk on IP address

[Identity Management]
      --cookie-and-account   Cookie analysis and CMS account enumeration using wordlist
      --error-message-enum   Enumerate users by error messages and status codes using username and password lists
      --hidden-directories   Discover hidden directories using wordlist
      --nonexistent-user-enum Enumerate users with username list and fake password
      --status-code-enum     Enumerate users by status code using username and password lists

[Authentication]
      --cache-weakness       Check cache-related headers and meta tags for browser cache weakness
      --remember-password    Check reset password security
      --tls                  Test for TLS/SSL cipher suites security

[Broken Authorization]
      --bypass-auth          Test authorization bypass via rewrite-URL and client-IP headers
      --depth                Traversal depth (e.g. 1 => ../ ; default: 1)
      --dir-traversal        Fuzz directory traversal using TRAVERSAL marker in --url or --payload-file
      --pattern              Optional response match pattern (auto-detected from --dst-path when omitted)
      --timeout              Delay in milliseconds between each traversal probe
      --url                  URL containing TRAVERSAL marker to fuzz (mutually exclusive with --payload-file)

[Session Management]
      --cache-control        Check Cache-Control, Expires, and Strict-Transport-Security headers
      --session-cookie       Analyse session cookie security

[Input Validation]
      --cookies              Cookies for HTTP verb tampering requests (e.g. "cookie1=value; cookie2=value")
      --follow-redirects     Follow HTTP redirects when testing methods
      --http-verb-tampering  Enumerate and test HTTP methods for verb tampering
      --reflected-xss        Test for reflected XSS via headless browser
      --thread               Number of threads for HTTP verb tampering (default: 5)
      --webdav-methods       Include WebDAV methods in verb tampering tests

[Weak Cryptography]
      --anonymous-ciphers    Test for anonymous cipher suites
      --beast                Test for BEAST (CVE-2011-3389) SSLv3/TLS 1.0 CBC vulnerability
      --block-size           Cipher block size in bytes
      --breach               Test for BREACH (CVE-2013-3587) HTTP compression
      --ccs-injection        Test for CCS injection (CVE-2014-0224)
      --crime                Test for CRIME (CVE-2012-4929) TLS compression
      --drown                Test for SSLv2 DROWN vulnerabilities (CVE-2015-3197, CVE-2016-0703, CVE-2016-0800)
      --encoding             Token encoding: 0=Base64 1=Lower HEX 2=Upper HEX 3=.NET UrlToken 4=WebSafe Base64
      --error-msg            String present in responses with a padding error (skips automatic oracle detection)
      --freak                Test for FREAK (CVE-2015-0204) export RSA cipher suites
      --heartbleed           Test for Heartbleed (CVE-2014-0160)
      --insecure-renegotiation Test for insecure TLS renegotiation (RFC 5746 / CVE-2011-1473)
      --logjam               Test for LOGJAM (CVE-2015-4000) DH EXPORT
      --lucky13              Test for Lucky13 (CVE-2013-0169) TLS CBC vulnerability
      --nomore               Test for NOMORE (CVE-2013-2566) RC4 cipher suites
      --null-ciphers         Test for NULL cipher suites
      --padding-oracle       Decrypt a CBC token through a padding oracle (target URL is the positional argument, e.g. http://host/encrypt?data=...)
      --po-bruteforce        Recover the first three intermediate bytes by brute force (PadBuster -bruteforce)
      --po-ciphertext        Hex ciphertext to start forging from (PadBuster -ciphertext)
      --po-cookie            Cookie "name=value" containing the token, sent with each oracle request (repeatable)
      --po-encodedtext       Forge a token for this already-encoded plaintext (PadBuster -encodedtext)
      --po-header            Custom header (repeatable) sent with each oracle request (PadBuster -headers)
      --po-ignore-body       Ignore the response body during oracle detection (PadBuster -ignorecontent)
      --po-interactive       Prompt before accepting each recovered byte (PadBuster -interactive)
      --po-intermediate      Hex intermediate bytes; skips recovery of the first block (PadBuster -intermediate)
      --po-noencode          Do not URL-encode the forged sample (PadBuster -noencode)
      --po-noiv              The sample carries no IV; prepend a null block before attacking (PadBuster -noiv)
      --po-plaintext         Forge a token that decrypts to this plaintext (PadBuster -plaintext)
      --po-post              Request body for POST oracles; the token is substituted into it (PadBuster -post)
      --po-prefix            Encoded bytes prepended to every forged sample (PadBuster -prefix)
      --po-resume            Resume decryption or brute force at this block or attempt (PadBuster -resume)
      --po-url               Oracle request URL containing the token; overrides endpoint derivation (PadBuster URL argument)
      --po-usebody           Include the response body in the oracle signature (PadBuster -usebody)
      --po-verbose           Print every oracle request and per-byte recovery detail (PadBuster -veryverbose)
      --poodle               Test for POODLE SSL (CVE-2014-3566) and TLS (CVE-2014-8730)
      --sweet32              Test for SWEET32 (CVE-2016-2183) 64-bit block ciphers
      --test-all             Run all TLS vulnerability checks in order
      --ticketbleed          Test for Ticketbleed (CVE-2016-9244)
      --tls-fallback-scsv    Check TLS_FALLBACK_SCSV (RFC 7507) downgrade protection
      --token                Captured ciphertext sample token to decrypt
      --winshock             Test for Winshock (CVE-2014-6321)

[Client-side]
      --html-injection       Test for HTML injection via headless browser

[Shared]
      --api-key              API key
      --domain               Domain to search for email
      --dst-path             Destination path(s): file for --dir-traversal (e.g. /etc/passwd), or protected path(s) for --bypass-auth (e.g. /admin,/secret)
      --email                Email address to verify
      --first-name           First name of the person
      --header               HTTP header "Name: value" (repeatable)
  -h, --help                 help for web-reGOn
      --last-name            Last name of the person
      --mac                  MAC address
      --passlist             Password list file path
      --payload-file         Path to payload file (XSS/HTML injection payloads, or raw HTTP request template with TRAVERSAL for --dir-traversal)
  -p, --port                 Port number (e.g. for HTTP OPTIONS or FTP scan)
  -t, --threads              Number of concurrent threads (default: 50)
      --userlist             Username list file path
  -w, --wordlist             Wordlist file path
```
## Input
For Linux:
```bash
sudo chmod +x web-reGOn
./web-reGOn [Flag(s)] $URL
```

## Examples
```
# DNS records lookup
./web-reGOn --dns example.com

# Discover hidden directories
./web-reGOn --hidden-directories --wordlist wordlist.txt example.com

# SNMP enumeration
./web-reGOn --snmp-walk 192.168.1.1 --port 20161
```
