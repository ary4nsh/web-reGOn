## TLS Cipher Suite Security
Use the `--tls` flag to receive and analyse the security of the TLS cipher suites that the server supports. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --tls example.com
./web-reGOn --tls example.com --port 8443
```

## Vulnerable Remember Password
Use the `--remember-password` flag to check the password-remember feature’s security by examining the `autocomplete` attribute on login form inputs. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --remember-password example.com
./web-reGOn --remember-password example.com --port 8443
```

## Browser Cache Weaknesses
Use the `--cache-weakness` flag to check `Cache-Control`, `Expires`, and `Pragma` HTTP headers, as well as meta tags related to cache control. You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --cache-weakness example.com
./web-reGOn --cache-weakness example.com --port 8443
```
