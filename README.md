# web-reGOn


## [Requirements]
You should install [go](https://go.dev/doc/install)
## [Usage]
```bash
Flags:
      --api-key string        API key
      --combined-enrichment   Company and Email enrichment information
      --company-enrichment    Company enrichment information
  -D, --dns                   DNS Records
      --domain string         Domain to search for email
      --domain-search         Domain search for email addresses
      --email string          Email address to verify
      --email-enrichment      Email enrichment information
      --email-finder          Find email address from domain and person names
      --email-verifier        Verify email address deliverability
      --first-name string     First name of the person
      --ftp                   Scan FTP server
  -h, --help                  help for linux-reGOn
  -H, --http                  HTTP Status Code
      --last-name string      Last name of the person
      --memcached             Scan Memcached server
  -S, --shodan                Shodan Host IP Query
      --snmp-enumshares       Enumerate SNMP Windows SMB Share
      --snmp-enumusers        Enumerate SNMP Windows users
      --snmp-walk             Perform SNMP walk on IP address
```
## [Input]
For Linux:
```bash
sudo chmod +x linux-reGOn
./linux-reGOn [Flag] $URL
```
