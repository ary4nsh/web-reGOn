## Reflected XSS
Use the `--reflected-xss` flag with `--payload-file` to test for reflected XSS by injecting payloads into query parameters and confirming execution via headless browser:
```
./web-reGOn [url] --reflected-xss --payload-file [path to the payload file]
```

## HTTP Verb Tampering
Use the `--http-verb-tampering` flag to enumerate HTTP methods against a target URL. This can help identify dangerous enabled methods (such as PUT or DELETE) and test verb tampering to bypass access controls.

By default, standard HTTP methods and custom/non-standard methods are tested. WebDAV methods are available with the optional `--webdav-methods` flag. You can also supply a custom list with `--wordlist`; methods from a wordlist are grouped automatically by type.

Before testing potentially destructive methods (DELETE, COPY, PUT, PATCH, UNCHECKOUT), the tool prompts for confirmation on the same line:
```
Do you really want to test method DELETE (can be dangerous)? [y/n] n
```

You can also use the optional `--port` flag to specify the port to test (the default port is 80). Port 80 uses `http://`, port 443 uses `https://`, and any other port uses `http://host:port`:
```
./web-reGOn --http-verb-tampering [domain name] --port [port number]
```

### Method groups
Results are grouped into three sections:

| Group | Methods |
|-------|---------|
| **HTTP Methods** | CONNECT, DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, TRACE |
| **WebDav Methods** | PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK |
| **Custom Methods** | Any method not in the HTTP or WebDAV sets (e.g. BAMBOOZLE, CHECKIN, TRACE variants, or entries from `--wordlist`) |

WebDAV methods are only included in the built-in test list when `--webdav-methods` is set. Methods from `--wordlist` are always tested and placed in the matching group.

### Optional flags
| Flag | Description |
|------|-------------|
| `--wordlist` / `-w` | File containing HTTP methods to test (one per line or whitespace-separated). If omitted, the built-in wordlist is used. |
| `--webdav-methods` | Include WebDAV methods in the built-in test list. |
| `--thread` | Number of concurrent requests (default: 5). |
| `--cookies` | Cookies to send with each request (e.g. `"session=abc; token=xyz"`). |
| `--header` | Extra HTTP header (repeatable, e.g. `--header "Authorization: Bearer token"`). |
| `--follow-redirects` | Follow HTTP redirects when testing methods. When a method returns a 3xx response, both the initial and final status codes are shown. |

### Examples
Basic enumeration (HTTP + custom methods):
```
./web-reGOn --http-verb-tampering example.com
```

Include WebDAV methods:
```
./web-reGOn --http-verb-tampering example.com --webdav-methods
```

Test with a custom method wordlist and follow redirects:
```
./web-reGOn --http-verb-tampering example.com --wordlist methods.txt --follow-redirects
```

Test over HTTPS with cookies and custom headers:
```
./web-reGOn --http-verb-tampering example.com --port 443 --cookies "session=abc" --header "X-Custom: value"
```
