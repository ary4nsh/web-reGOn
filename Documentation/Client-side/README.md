## HTML Injection
Use the `--html-injection` flag with `--payload-file` to test for HTML injection by injecting payloads into query parameters and confirming that the markup is parsed into the DOM via a headless browser:
```
./web-reGOn http://example.com/page --html-injection --payload-file [path to the payload file]
```

HTML injection occurs when user-controlled input is reflected into an HTML response without proper encoding. Unlike reflected XSS, the goal is not necessarily JavaScript execution — any unescaped HTML tags rendered in the page (for example `<b>`, `<img>`, or custom elements) indicate that an attacker can alter page structure or content.

### Payload formats
Each line in `--payload-file` can be either:

1. A named query payload (parameter name included in the file):
```
?user=<h1>mamad</h1>
user=<img data-webregon="htmlinj" src=x>
```
Use this when the URL has no query string. The tool builds `http://example.com/page?user=<payload>`.

2. A raw HTML payload (parameter name in the URL):
```
<div id="webregon-htmlinj">injected</div>
<b>webregon-htmlinj</b>
```
Use this when the URL already includes query parameters. The tool replaces each parameter value with the payload:
```
./web-reGOn "http://example.com/page?user=test" --html-injection --payload-file payloads.txt
```

### How it works
1. Loads payloads from `--payload-file` (one per line).
2. Builds one request URL per payload / query parameter.
3. Opens each URL in a headless Chrome/Chromium browser (native CDP).
4. Confirms vulnerability when the HTML value appears unescaped in the live DOM.

Recommended payloads include a unique `id` or `data-webregon` attribute so the headless check can reliably find the injected element.

Output statuses:
- `[VULNERABLE]` — payload HTML was parsed into the DOM after injection
- `[REFLECTED]` — payload appeared in the response but was not confirmed in the DOM
- `[SAFE]` — payload was not reflected
