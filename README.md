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
      --dns-propagation      Check if recent changes to DNS records have propagated from viewdns.info
      --domain-search        Domain search for email addresses
      --email-enrichment     Email enrichment information
      --email-finder         Find email address from domain and person names
      --email-verifier       Verify email address deliverability
      --ip-history           Show historical IP addresses associated with a specific domain from viewdns.info
      --ip-location          Return the geographical location of an IP address from viewdns.info
      --mac-address-lookup   Search the OUI database to determine which manufacturer a given MAC address belongs to, from viewdns.info
      --multiple-ping        Check the latency and packet loss to a given host from multiple locations globally from viewdns.info
      --reverse-dns          Return DNS Pointer (PTR) record for a given IP address from viewdns.info
  -S, --shodan               Shodan Host IP Query
      --subdomain-discovery  Provide a comprehensive list of subdomains associated with a given domain from viewdns.info
      --traceroute           Trace the network path from our test location to a given host from viewdns.info

[Misconfiguration]
      --csp                  Analyse Content-Security-Policy header
      --ftp                  Scan FTP server
      --hsts-header          Check HSTS and security headers
      --http-options         HTTP OPTIONS Method Check
      --memcached            Scan Memcached server
      --path-confusion       Path Confusion testing with wordlist and optional threads
      --ria                  Check crossdomain.xml and clientaccesspolicy.xml
      --snmp-enumshares      Enumerate SNMP Windows SMB Share
      --snmp-enumusers       Enumerate SNMP Windows users
      --snmp-walk            Perform SNMP walk on IP address

[Identity Management]
      --cookie-and-account   Cookie analysis and CMS account enumeration using wordlist
      --error-message-enum   Enumerate users via brute forcing login forms with username and password lists by analyzing error messages and status codes
      --hidden-directories   Discover hidden directories using wordlist
      --nonexistent-user-enum Enumerate users via brute forcing login forms with username list and fake password by analyzing error messages and status codes
      --status-code-enum     Enumerate users via brute forcing login forms with username and password lists by status code

[Broken Authentication]
      --cache-weakness       Check cache-related headers and meta tags for browser cache weakness
      --remember-password    Check reset password security
      --tls                  Test for TLS/SSL cipher suites security

[Session Management]
      --cache-control        Check Cache-Control, Expires, and Strict-Transport-Security headers
      --session-cookie       Analyse session cookie security

[Weak Cryptography]
      --anonymous-ciphers    Test for anonymous (anon) cipher suites vulnerability
      --beast                Test for BEAST (CVE-2011-3389) SSLv3/TLS 1.0 CBC vulnerability
      --crime                Test for CRIME (CVE-2012-4929) TLS compression vulnerability
      --drown                Test for SSLv2 (CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 DROWN) vulnerabilities
      --freak                Test for FREAK (CVE-2015-0204) export RSA cipher suites vulnerability
      --lucky13              Test for Lucky 13 (CVE-2013-0169) TLS CBC vulnerability
      --nomore               Test for NOMORE (CVE-2013-2566) RC4 cipher suites vulnerability
      --null-ciphers         Test for NULL cipher suites vulnerability

[Other]
      --api-key              API key
      --domain               Domain to search for email
      --email                Email address to verify
      --first-name           First name of the person
  -h, --help                 help for web-reGOn
      --last-name            Last name of the person
      --mac                  MAC address
      --passlist             Password list file path
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
