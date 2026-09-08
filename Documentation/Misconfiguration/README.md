## Content Security Policy Header
Use the `--csp` flag to receive and analyse the `Content-Security-Policy` header. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --csp example.com
./web-reGOn --csp example.com --port 8443
```

## FTP Scan
Use the `--ftp` flag to scan the FTP service of the target and receive banner, anonymous login status, feature set (`FEAT`), available commands (`SITE` / `HELP`), and whether the control channel requires TLS (`AUTH TLS` reply). You can also use the optional `--port` flag (default: `21`):
```
./web-reGOn --ftp 192.0.2.10
./web-reGOn --ftp 192.0.2.10 --port 2121
```

## HTTP Strict Transport Security Header
Use the `--hsts-header` flag to check HSTS and related security headers. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --hsts-header example.com
./web-reGOn --hsts-header example.com --port 8443
```

## HTTP OPTIONS
Use the `--http-options` flag to send an HTTP `OPTIONS` request and receive the response. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --http-options example.com
./web-reGOn --http-options example.com --port 8080
```

## Memcached
Use the `--memcached` flag to scan a Memcached service and receive server metadata (version, uptime, …), runtime statistics (hit ratio, bytes used, connection count, …), configuration settings (max bytes, max connections, growth factor, slab sizes, …), and cached keys with raw values when accessible. You can also use the optional `--port` flag (default: `11211`):
```
./web-reGOn --memcached 192.0.2.10
./web-reGOn --memcached 192.0.2.10 --port 11211
```

## Path Confusion
Use the `--path-confusion` flag with `--wordlist` to test path confusion. Successful results often need manual verification because false positives are possible. You can also use the optional `--threads` / `-t` flag (default: `50`):
```
./web-reGOn --path-confusion --wordlist [wordlist path] example.com
./web-reGOn --path-confusion --wordlist [wordlist path] example.com --threads 100
```

## Rich Internet Application
Use the `--ria` flag to fetch both `crossdomain.xml` and `clientaccesspolicy.xml` policy files. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --ria example.com
./web-reGOn --ria example.com --port 8443
```

## SNMP Enumerate Shares
Use the `--snmp-enumshares` flag to pull Windows network-share information from a target IP using community string `public` (SNMPv2c). You can also use the optional `--port` flag (default: `161`):
```
./web-reGOn --snmp-enumshares 192.0.2.10
./web-reGOn --snmp-enumshares 192.0.2.10 --port 161
```

## SNMP Enumerate Users
Use the `--snmp-enumusers` flag to enumerate SNMP users on Windows or Sun platforms using community string `public`. You can also use the optional `--port` flag (default: `161`):
```
./web-reGOn --snmp-enumusers 192.0.2.10
./web-reGOn --snmp-enumuser 192.0.2.10s --port 161
```

## SNMP Walk
Use the `--snmp-walk` flag to walk an SNMPv2c branch sequentially using Get-Next, starting from the standard MIB-2 root (`.1.3.6.1.2.1`). You can also use the optional `--port` flag (default: `161`):
```
./web-reGOn --snmp-walk 192.0.2.10
./web-reGOn --snmp-walk 192.0.2.10 --port 161
```
