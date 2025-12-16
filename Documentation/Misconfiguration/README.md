## Content Security Policy Header
Use the `--csp` flag to recieve and analyse Content-Security-Policy header. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --csp [domain name] --port [port number]
```

## FTP Scan
Use the `--ftp` flag to scan the FTP service of the target and recieve banner, anonymous login status, feature set (FEAT command), available commands (SITE and HELP commands) and Whether the control channel requires TLS (AUTH TLS reply):
```
./linux-reGOn --ftp [ip address]
```

## HTTP Strict Transport Security Header
Use the `--hsts-header` flag to check HSTS and security headers. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --hsts-header [ip address] --port [port number]
```

## HTTP OPTIONS
Use the `--http-options` flag to send HTTP OPTIONS request and recieve it's response. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --http-options [ip address] --port [port number]
```

## Memcached
Use the `--memcached` flag to Scan the Memcached service og the target and recieve server metadata (service version, uptime, ...), Runtime statistics (Hit ratio, bytes used, connection count, ...), Configuration settings (Max bytes, max connections, growth factor, slab sizes, ...) and Every cached key and its raw value (uses port 11211):
```
./linux-reGOn --memcached [ip address]
```

## Path Confusion
Use the `--path-confusion` flag with `--wordlist` flag to test Path Confusion vunerability. Successful results need manual interception on the target webpage because you might find false positive results:
```
./linux-reGOn --path-confusion [domain name] --wordlist [wordlist path]
```

## Rich Internet Application
Use the `--ria` flag to fetch both crossdomain.xml and clientaccesspolicy.xml policy files. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --ria [domain name] --port [port number]
```

## SNMP Enumerate Shares
Use the `--snmp-enumshares` flag to pull Windows network-share information from a target IP using community string “public” in SNMPv2c:
```
./linux-reGOn --snmp-enumshares [ip address]
```

## SNMP Enumerate Users
Use the `--snmp-enumusers` flag to enumerate SNMP users in Windows or Sun platforms using community string “public”:
```
./linux-reGOn --snmp-enumusers [ip address]
```

## SNMP Walk
Use the `--snmp-walk` flag to walk the entire branch of SNMPv2c server sequentially using Get-Next, starting from standard MIB-2 root (.1.3.6.1.2.1):
```
./linux-reGOn --snmp-walk [ip address]
```