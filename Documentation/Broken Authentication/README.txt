## TLS cipher suite security
Use the `--tls` flag to receive and analyze the security of the TLS cipher suites that the server supports. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --tls [domain name] --port [port number]
```

## Vulnerable Remember Password
Use the --remember-password flag to check the password remember feature's security by examining the value of the AUTOCOMPLETE attribute in the input tag on the login page. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --remember-password [domain name] --port [port number]
```

## Browser Cache Weaknesses
Use the --cache-weakness flag to check the Cache-Control, Expires, and Pragma HTTP headers, as well as the meta tags containing the cache-control and content attributes. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --cache-weakness [domain name] --port [port number]
```