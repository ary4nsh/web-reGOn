## DNS Records
Use the `--dns` or `-D` flag to obtain the A, AAAA, CNAME, MX, NS, TXT, SOA, HINFO, SRV, CAA, LOC, DS, DNSKEY, and PTR DNS records of a target:
```
./web-reGOn --dns example.com
```

## HTTP Status Code
Use the `--http` or `-H` flag to receive the HTTP response status code for a target:
```
./web-reGOn --http example.com
```

## WAF Detection
Use the `--waf` flag to detect a Web Application Firewall. You can also use the optional `--port` flag to specify the port to test (default: `443`):
```
./web-reGOn --waf example.com
./web-reGOn --waf example.com --port 8443
```

## Zone Transfer
Use the `--zone-transfer` flag to attempt a DNS zone transfer (AXFR) against the domain’s nameservers:
```
./web-reGOn --zone-transfer example.com
```

## Whois
Use the `--whois` flag to query Whois records for a domain or IP address:
```
./web-reGOn --whois example.com
./web-reGOn --whois 8.8.8.8
```
