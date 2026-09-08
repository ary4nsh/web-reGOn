## Directory Traversal
Use the `--dir-traversal` flag to fuzz directory traversal paths. Provide a domain as the positional argument, a destination path with `--dst-path`, and exactly one of `--url` or `--payload-file`. Mark the fuzz position with the `TRAVERSAL` token.

Default port is `443` (HTTPS). Default depth is `1`. Default delay between probes is `500` milliseconds.

### URL mode
Replace the injectable parameter with `TRAVERSAL` in `--url`:
```
./web-reGOn example.com --dir-traversal --dst-path /etc/passwd --url "https://example.com/view?file=TRAVERSAL"
```

With a custom port, depth, delay, and response pattern:
```
./web-reGOn example.com --dir-traversal --port 8080 --dst-path /etc/passwd --depth 3 --timeout 200 --pattern "root:" --url "http://example.com:8080/view?file=TRAVERSAL"
```

### Payload-file mode
Provide a raw HTTP request template that contains `TRAVERSAL`. The tool connects to `domain:port` and sends each fuzzed request:
```
./web-reGOn 127.0.0.1 --dir-traversal --port 8080 --dst-path /etc/passwd --payload-file payload_lab.txt
```

Example `payload_lab.txt`:
```
GET /view?file=TRAVERSAL HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: web-reGOn
Connection: close
Accept: */*


```

### Flags
| Flag | Description |
|------|-------------|
| `--dir-traversal` | Enable directory traversal fuzzing |
| `--dst-path` | File/path to append after traversal patterns (e.g. `/etc/passwd`, `boot.ini`) |
| `--url` | Full URL containing `TRAVERSAL` (mutually exclusive with `--payload-file`) |
| `--payload-file` | Raw HTTP request file containing `TRAVERSAL` (mutually exclusive with `--url`) |
| `--port` | Target port (default: `443`) |
| `--depth` | How many times to repeat traversal patterns (default: `1`) |
| `--timeout` | Milliseconds to wait between probes (default: `500`) |
| `--pattern` | Optional string that must appear in the response (e.g. `root:`). When omitted, a pattern is chosen from `--dst-path` when possible (`passwd` → `root:`, `boot.ini` → `[boot loader]`, `hosts` → `localhost`, …) |

### Notes
- Traversal patterns are generated from dot/slash encodings, special prefixes, and null-byte / extension suffixes.
- `--url` and `--payload-file` cannot be used together.
- Probes are sent as **raw TCP HTTP** so `../` / `..\` are not rewritten by an HTTP client.
- A hit is reported as `[VULNERABLE]` when the **raw response** (headers + body) matches `--pattern` (or the auto pattern). Without a pattern, HTTP `200` with a non-empty body is treated as a candidate.
- On **WSL/Kali**, `localhost` / `127.0.0.1` is rewritten to the Windows host IP automatically when a lab server is running on Windows.

## Authorization Schema Bypass
Use the `--bypass-auth` flag to test whether protected paths can be reached by spoofing rewrite-URL headers (`X-Original-URL`, `X-Rewrite-URL`) or client-IP headers (`X-Forwarded-For`, `X-Real-IP`, …). Provide a domain as the positional argument and one or more protected paths with `--dst-path`.

Default port is `443` (HTTPS).

### Basic usage
```
./web-reGOn example.com --bypass-auth --dst-path /admin
```

Multiple paths (comma-separated):
```
./web-reGOn example.com --bypass-auth --dst-path /admin,/secret --port 8080
```

### Header overrides
Repeatable `--header "Name: value"` overrides the value used when that header name is part of the built-in tests. Matching is case-insensitive on the header name.

Example — force `X-Original-URL` probes to use `/donotexist1` instead of the path under test / probe path:
```
./web-reGOn example.com --bypass-auth --dst-path /admin --header "X-Original-URL: /donotexist1"
```

Example — spoof a custom IP instead of `127.0.0.1` for IP-trust tests:
```
./web-reGOn example.com --bypass-auth --dst-path /admin --header "X-Forwarded-For: 10.0.0.1"
```

Headers that are not in the built-in rewrite/IP test sets are ignored for override purposes (they do not change the probe set).

### Flags
| Flag | Description |
|------|-------------|
| `--bypass-auth` | Enable authorization schema / header bypass checks |
| `--dst-path` | Protected path(s) to probe (`/admin` or `/admin,/secret`) |
| `--port` | Target port (default: `443`) |
| `--header` | Optional `"Name: value"` override for a tested header (repeatable) |

### What it checks
1. Fetches the site root and each `--dst-path` baseline (no extra headers).
2. For `X-Original-URL` and `X-Rewrite-URL`: sends the path (and a nonexistent probe path) to detect whether the server honors rewrite headers, and whether a `4xx` baseline becomes `2xx` (access-control bypass).
3. For common client-IP headers: sends `127.0.0.1` (or your override) and reports when a `4xx` baseline becomes `2xx`.

### Notes
- Redirects are not followed (same behavior as the standalone detector).
- using a port together with the address or hostname may also help bypass protections such as web application firewalls, etc. For example: 127.0.0.4:80, 127.0.0.4:443, 127.0.0.4:43982. So consider using --port switch for these cases.
- On **WSL/Kali**, `localhost` / `127.0.0.1` is rewritten to the Windows host IP when applicable.
