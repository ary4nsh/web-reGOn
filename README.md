# web-reGOn


## [Requirements]
You should install [go](https://go.dev/doc/install)
## [Usage]
```bash
Flags:
      --api-key string        Hunter.io API key
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
  -h, --help                  help for linux-reGOn
  -H, --http                  HTTP Status Code
      --last-name string      Last name of the person
  -S, --shodan                Shodan Host IP Query
```
## [Input]
For Linux:
```bash
sudo chmod +x linux-reGOn
./linux-reGOn [Flag] $URL
```
