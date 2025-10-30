# web-reGOn
This is a simple web reconnaissance tool written in golang

## [Requirements]
You should install [go](https://go.dev/doc/install)
## [Usage]
```bash
[Reconnaissance]
  -D, --dns                  DNS Records
      --dns-dumpster         Find & look up DNS records from dnsdumpster.com
  -H, --http                 HTTP Status Code
      --whois                Query for Whois records
      --zone-transfer        Perform zone transfer on a domain

[Misconfiguration]
      --csp                  Analyse Content-Security-Policy header
      --ftp                  Scan FTP server
      --hsts-header          Check HSTS and security headers
      --http-options         HTTP OPTIONS Method Check
      --memcached            Scan Memcached server
      --ria                  Check crossdomain.xml and clientaccesspolicy.xml
      --snmp-enumshares      Enumerate SNMP Windows SMB Share
      --snmp-enumusers       Enumerate SNMP Windows users
      --snmp-walk            Perform SNMP walk on IP address

[Open Source Intelligence]
      --combined-enrichment  Company and Email enrichment information
      --company-enrichment   Company enrichment information
      --domain-search        Domain search for email addresses
      --email-enrichment     Email enrichment information
      --email-finder         Find email address from domain and person names
      --email-verifier       Verify email address deliverability
  -S, --shodan               Shodan Host IP Query

[Other]
      --api-key              API key
      --domain               Domain to search for email
      --email                Email address to verify
      --first-name           First name of the person
  -h, --help                 help for linux-reGOn
      --last-name            Last name of the person
  -p, --port                 Port number to use with HTTP OPTIONS
```
## [Input]
For Linux:
```bash
sudo chmod +x linux-reGOn
./linux-reGOn [Flag(s)] $URL
```
