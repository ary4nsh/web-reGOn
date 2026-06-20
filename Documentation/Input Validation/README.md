## Reflected XSS
Use the `--reflected-xss` flag with `--payload-file` to test for reflected XSS by injecting payloads into query parameters and confirming execution via headless browser:
```
./web-reGOn [url] --reflected-xss --payload-file [path to the payload file]
```