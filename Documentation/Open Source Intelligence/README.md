## Combined Enrichment (https://hunter.io)
Use the `--combined-enrichment` flag to gather information associated with an email address and its domain name:
```
./web-reGOn --combined-enrichment --api-key [hunter.io api key] --email [target email]
```

## Company Enrichment (https://hunter.io)
Use the `--company-enrichment` flag to gather information associated with a domain name (industry, description, headquarters location, and related data):
```
./web-reGOn --company-enrichment --api-key [hunter.io api key] --domain [domain name]
```

## Email Enrichment (https://hunter.io)
Use the `--email-enrichment` flag to gather information associated with an email address (name, location, social handles, and related data):
```
./web-reGOn --email-enrichment --api-key [hunter.io api key] --email [target email]
```

## Email Finder (https://hunter.io)
Use the `--email-finder` flag to find the most likely email address from a domain name, first name, and last name:
```
./web-reGOn --email-finder --api-key [hunter.io api key] --domain [domain name] --first-name [string] --last-name [string]
```

## Email Verifier (https://hunter.io)
Use the `--email-verifier` flag to verify the deliverability of an email address:
```
./web-reGOn --email-verifier --api-key [hunter.io api key] --email [target email]
```

## Domain Search (https://hunter.io)
Use the `--domain-search` flag to search email addresses corresponding to one website/domain:
```
./web-reGOn --domain-search --api-key [hunter.io api key] --domain [domain name]
```

## DNS Dumpster (https://dnsdumpster.com)
Use the `--dns-dumpster` flag to look up DNS records, ASN/network owner, netblocks, and related data from dnsdumpster.com. Provide the target as the positional argument:
```
./web-reGOn example.com --dns-dumpster --api-key [dnsdumpster.com api key]
```

## DNS Record Lookup (https://viewdns.info)
Use the `--dns-lookup` flag to retrieve DNS records for a domain or hostname. The query target is passed with `--email`:
```
./web-reGOn --dns-lookup --api-key [viewdns.info api key] --email [domain name]
```

## DNS Propagation (https://viewdns.info)
Use the `--dns-propagation` flag to check whether recent DNS record changes have propagated. The query target is passed with `--email`:
```
./web-reGOn --dns-propagation --api-key [viewdns.info api key] --email [domain name]
```

## IP History (https://viewdns.info)
Use the `--ip-history` flag to obtain historical IP addresses associated with a domain. The query target is passed with `--email`:
```
./web-reGOn --ip-history --api-key [viewdns.info api key] --email [domain name]
```

## IP Location (https://viewdns.info)
Use the `--ip-location` flag to receive the geographical location of an IP address. The query target is passed with `--email`:
```
./web-reGOn --ip-location --api-key [viewdns.info api key] --email [ip address]
```

## MAC Address Lookup (https://viewdns.info)
Use the `--mac-address-lookup` flag to search the OUI database for a MAC address manufacturer. MAC format should be like `11-22-33-44-55-66`. Provide the address with both `--mac` and `--email` (the lookup currently reads the value from `--email`):
```
./web-reGOn --mac-address-lookup --api-key [viewdns.info api key] --mac 11-22-33-44-55-66 --email 11-22-33-44-55-66
```

## Ping (https://viewdns.info)
Use the `--multiple-ping` flag to check latency and packet loss to a host from multiple global locations. The query target is passed with `--email`:
```
./web-reGOn --multiple-ping --api-key [viewdns.info api key] --email [domain name]
```

## Reverse DNS (https://viewdns.info)
Use the `--reverse-dns` flag to receive the DNS Pointer (PTR) record for an IP address. The query target is passed with `--email`:
```
./web-reGOn --reverse-dns --api-key [viewdns.info api key] --email [ip address]
```

## Subdomain Discovery (https://viewdns.info)
Use the `--subdomain-discovery` flag to receive a list of subdomains associated with a domain. The query target is passed with `--email`:
```
./web-reGOn --subdomain-discovery --api-key [viewdns.info api key] --email [domain name]
```

## Traceroute (https://viewdns.info)
Use the `--traceroute` flag to trace the network path from viewdns.info’s test location to a given host. The query target is passed with `--email`:
```
./web-reGOn --traceroute --api-key [viewdns.info api key] --email [domain name]
```

## Host Information (https://shodan.io)
Use the `--shodan` or `-S` flag to receive services found on a given host IP. Provide the IP as the positional argument:
```
./web-reGOn 8.8.8.8 --shodan --api-key [shodan.io api key]
```
