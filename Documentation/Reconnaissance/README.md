## DNS Records
Use the `--dns` or `-D` flag to obtain the DNS records of a target:
```
linux-reGOn --dns example.com
```

## HTTP
Use the `--http` or `-H` flag to receive the response status code:
```
linux-reGOn --http example.com
```

## WAF Detection
Use the `--waf` flag to detect a Web Application Firewall. You can also use the optional `--port` option to specify the port to test (if not specified, the default port is 443):
```
linux-reGOn --waf example.com
linux-reGOn --waf example.com --port [port number]
```

## Zone Transfer
Use the `--zone-transfer` flag to perform a zone transfer on a domain, if applicable:
```
linux-reGOn --zone-transfer example.com
```