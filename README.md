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
go build -o linux-reGOn

# Run the tool
./linux-reGOn --help
```

## Usage
```bash
[Reconnaissance]
  -D, --dns                  DNS Records
      --dns-dumpster         Find & look up DNS records from dnsdumpster.com
  -H, --http                 HTTP Status Code
      --waf                  Detect Web Application Firewall
      --whois                Query for Whois records
      --zone-transfer        Perform zone transfer on a domain

[Open Source Intelligence]
      --combined-enrichment  Company and Email enrichment information
      --company-enrichment   Company enrichment information
      --domain-search        Domain search for email addresses
      --email-enrichment     Email enrichment information
      --email-finder         Find email address from domain and person names
      --email-verifier       Verify email address deliverability
  -S, --shodan               Shodan Host IP Query

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

[Other]
      --api-key              API key
      --domain               Domain to search for email
      --email                Email address to verify
      --first-name           First name of the person
  -h, --help                 help for linux-reGOn
      --last-name            Last name of the person
      --passlist             Password list file path
  -p, --port                 Port number to use with HTTP OPTIONS
  -t, --threads              Number of concurrent threads (default: 50)
      --userlist             Username list file path
  -w, --wordlist             Wordlist file path
```
## Input
For Linux:
```bash
sudo chmod +x linux-reGOn
./linux-reGOn [Flag(s)] $URL
```

## Examples
```
# DNS records lookup
./linux-reGOn --dns example.com

# Discover hidden directories
./linux-reGOn --hidden-directories --wordlist wordlist.txt example.com

# SNMP enumeration
./linux-reGOn 192.168.1.1 --snmp-walk
```
