## Combined Enrichment (https://hunter.io)
Use the `--combined-enrichment` to gather all the information associated with an email address and its domain name:
```
./linux-reGOn --combined-enrichment --api-key [hunter.io api key] --email [target email]
```

## Company Enrichment (https://hunter.io)
Use the `--company-enrichment` flag to gather all the information associated with a domain name, such as the industry, the description, or headquarters' location:
```
./linux-reGOn --company-enrichment --api-key [hunter.io api key] --domain [domain name]
```

## Email Enrichment (https://hunter.io)
Use the `--email-enrichment` flag to gather all the information associated with an email address or LinkedIn handle, such as a person's name, location and social handles:
```
./linux-reGOn --email-enrichment --api-key [hunter.io api key] --email [target email]
```

## Email Finder (https://hunter.io)
Use the `--email-finder` flag to find the most likely email address from a domain name, a first name and a last name:
```
./linux-reGOn --email-finder --api-key [hunter.io api key] --domain [domain name] --first-name [string] --last-name [string]
```

## Email Verifier (https://hunter.io)
Use the `--email-verifier` flag to verify the deliverability of an email address:
```
./linux-reGOn --email-verifier --api-key [hunter.io api key] --email [target email]
```

## Domain Search (https://hunter.io)
Use the `--domain-search` flag to search all the email addresses corresponding to one website. You give one domain name and it returns all the email addresses using this domain name found on the internet:
```
./linux-reGOn --domain-search --api-key [hunter.io api key] --domain [domain name]
```

## DNS Dumpster (https://dnsdumpster.com)
Use the `--dns-dumpster` flag to obtain responses data that includes all found DNS records, ASN network owner, netblocks and Banner records found in dnsdumpster.com's databases:
```
./linux-reGOn --dns-dumpster [domain name] --api-key [viewdns.info api key]
```

## DNS Record Lookup (https://viewdns.info)
Use the `--dns-lookup` flag to retrieve DNS records for your target Domain or Hostname:
```
./linux-reGOn --dns-lookup [domain name] --api-key [viewdns.info api key]
```

## DNS Propagation (https://viewdns.info)
Use the `--dns-propagation` flag to check if recent changes to DNS records have propagated:
```
./linux-reGOn --dns-propagation [domain name] --api-key [viewdns.info api key]
```

## IP History (https://viewdns.info)
Use the `--ip-history` flag to obtain historical IP addresses associated with a specific domain:
```
./linux-reGOn --ip-history [domain name] --api-key [viewdns.info api key]
```

## IP Location (https://viewdns.info)
Use the `--ip-location` flag to recieve the geographical location of an IP address:
```
./linux-reGOn --ip-location [ip address] --api-key [viewdns.info api key]
```

## MAC Address Lookup (https://viewdns.info)
Use the `--mac-address-lookup` flag to search the OUI database to determine which manufacturer a given MAC address belongs to (MAC address format should be like 11-22-33-44-55-66):
```
./linux-reGOn --mac-address-lookup [mac address] --api-key [viewdns.info api key]
```

## Ping (https://viewdns.info)
Use the `--multiple-ping` flag to check the latency and packet loss to a given host from multiple locations globally:
```
./linux-reGOn --multiple-ping [domain name] --api-key [viewdns.info api key]
```

## Reverse DNS (https://viewdns.info)
Use the `--reverse-dns` flag to recieve DNS Pointer (PTR) record for a given IP address:
```
./linux-reGOn --reverse-dns [ip address] --api-key [viewdns.info api key]
```

## Subdomain Discovery (https://viewdns.info)
Use the `--subdomain-discovery` flag to recieve a comprehensive list of subdomains associated with a given domain, leveraging our industry-leading domain name data:
```
./linux-reGOn --subdomain-discovery [domain name] --api-key [viewdns.info api key]
```

## Host Information (https://shodan.io)
Use the `--shodan` or the `-S` flag to recieve all services that have been found on the given host IP:
```
./linux-reGOn --subdomain-discovery [domain name] --api-key [viewdns.info api key]
```