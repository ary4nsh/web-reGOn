## Test All
Use the `--test-all` flag to run all Weak Cryptography vulnerability checks in order.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --test-all example.com
./web-reGOn --test-all example.com --port 8443
```

## Multiple Flags
You can combine Weak Cryptography flags on one command line. Tests run in the order the flags appear on the command line:
```
./web-reGOn --anonymous-ciphers --breach --logjam example.com
./web-reGOn --anonymous-ciphers --breach --logjam example.com --port 8443
```

## Anonymous Ciphers
Use the `--anonymous-ciphers` flag to test for support of anonymous (anon) cipher suites.

Anonymous ciphers do not provide authentication in the usual sense for TLS peer identity, and according to RFC 7672 they may still appear in some SMTP deployments.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --anonymous-ciphers example.com
./web-reGOn --anonymous-ciphers example.com --port 8443
```

## BEAST (Browser Exploit Against SSL/TLS)
Use the `--beast` flag to test for the BEAST (CVE-2011-3389) vulnerability.

In SSLv3/TLS 1.0 CBC mode encryption, each block of plaintext is XORed with the previous ciphertext block before being encrypted. That chaining can let an attacker who can influence cipher blocks affect subsequent blocks.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --beast example.com
./web-reGOn --beast example.com --port 8443
```

## DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
Use the `--drown` flag to test for SSLv2 (CVE-2015-3197, CVE-2016-0703, and CVE-2016-0800 DROWN) vulnerabilities.

The attack particularly targets RSA keys used in the SSLv2 handshake. If a server supports SSLv2 and uses RSA for encryption, an attacker may be able to decrypt related secure communications by leveraging protocol weaknesses.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --drown example.com
./web-reGOn --drown example.com --port 8443
```

## FREAK (Factoring RSA Export Keys)
Use the `--freak` flag to test for FREAK (CVE-2015-0204) export RSA cipher suites.

During the 1990s, U.S. regulations limited the strength of exportable encryption. Some products implemented “export-grade” cryptography with weaker RSA keys (around 512 bits). With modern compute, those keys can be factored more easily than 2048-bit keys. The attacker typically needs a network position that allows intercepting and modifying communications.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --freak example.com
./web-reGOn --freak example.com --port 8443
```

## LUCKY13
Use the `--lucky13` flag to test for Lucky 13 (CVE-2013-0169) TLS CBC vulnerability.

Lucky 13 leverages timing discrepancies during CBC decryption. Servers may process different lengths of data in variable time while decrypting blocks sequentially, which can leak information about plaintext or padding.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --lucky13 example.com
./web-reGOn --lucky13 example.com --port 8443
```

## NOMORE (Numerous Occurrence MOnitoring & Recovery Exploit)
Use the `--nomore` flag to test for the NOMORE (CVE-2013-2566) vulnerability in RC4 cipher suites.

This is a practical attack against RC4 encryption in TLS/HTTPS. RC4 keystream biases (including Fluhrer-McGrew and ABSAB/Mantin biases) mean that encrypting the same data (such as a cookie) many times produces predictable ciphertext patterns.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --nomore example.com
./web-reGOn --nomore example.com --port 8443
```

## NULL Ciphers
Use the `--null-ciphers` flag to test for NULL cipher suites.

NULL cipher suites provide authentication only and no encryption.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --null-ciphers example.com
./web-reGOn --null-ciphers example.com --port 8443
```

## Insecure Renegotiation
Use the `--insecure-renegotiation` flag to test for insecure TLS renegotiation (RFC 5746 / CVE-2011-1473).

Checks whether the server supports secure renegotiation (RFC 5746) and whether it accepts client-initiated renegotiation, which can be abused for denial-of-service attacks.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --insecure-renegotiation example.com
./web-reGOn --insecure-renegotiation example.com --port 8443
```

## BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
Use the `--breach` flag to test for BREACH (CVE-2013-3587) HTTP compression vulnerability.

BREACH is an HTTP-level compression attack that works against any cipher suite and is agnostic to TLS/SSL version. If the server compresses HTTP responses (gzip, deflate, compress, or br) and the page reflects attacker-influenced input, secrets in the page may be recoverable through compression side channels.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --breach example.com
./web-reGOn --breach example.com --port 8443
```

## CRIME (Compression Ratio Info-leak Made Easy)
Use the `--crime` flag to test for CRIME (CVE-2012-4929) TLS compression vulnerability.

CRIME exploits TLS-level compression (such as DEFLATE) to recover secrets from encrypted traffic when the attacker can control part of the request and observe ciphertext length changes. TLS 1.3 does not support compression.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --crim example.come
./web-reGOn --crime example.com --port 8443
```

## CCS (ChangeCipherSpec Injection)
Use the `--ccs-injection` flag to test for CCS injection (CVE-2014-0224).

CCS injection is an OpenSSL/TLS flaw where a ChangeCipherSpec message sent early in the handshake can skip key material verification. A vulnerable server may accept the message and allow a man-in-the-middle to decrypt or modify traffic.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --ccs-injection example.com
./web-reGOn --ccs-injection example.com --port 8443
```

## Heartbleed
Use the `--heartbleed` flag to test for Heartbleed (CVE-2014-0160).

Heartbleed is a flaw in OpenSSL’s implementation of the TLS heartbeat extension. A malformed heartbeat request can cause the server to leak memory contents, potentially exposing private keys, session tokens, and other sensitive data.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --heartbleed example.com
./web-reGOn --heartbleed example.com --port 8443
```

## LOGJAM
Use the `--logjam` flag to test for LOGJAM (CVE-2015-4000) DH EXPORT vulnerability.

LOGJAM targets weak Diffie-Hellman key exchange, especially export-grade DH cipher suites with small prime sizes. An attacker who can downgrade or force use of these ciphers may be able to break the key exchange and decrypt traffic.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --logjam example.com
./web-reGOn --logjam example.com --port 8443
```

## POODLE (Padding Oracle On Downgraded Legacy Encryption)
Use the `--poodle` flag to test for POODLE SSL (CVE-2014-3566) and TLS (CVE-2014-8730) vulnerabilities.

POODLE SSL exploits CBC padding in SSLv3 to decrypt HTTPS cookies when the server still supports SSLv3. POODLE TLS is an experimental check for similar padding issues in TLS; full coverage may require dedicated timing analysis tools.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --poodle example.com
./web-reGOn --poodle example.com --port 8443
```

## SWEET32
Use the `--sweet32` flag to test for SWEET32 (CVE-2016-2183) 64-bit block cipher vulnerability.

SWEET32 is a birthday attack against 64-bit block ciphers such as 3DES, DES, RC2, and IDEA. Long-lived HTTPS sessions using these ciphers can allow an attacker to recover cookies or other secrets after collecting enough ciphertext blocks.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --sweet32 example.com
./web-reGOn --sweet32 example.com --port 8443
```

## Ticketbleed
Use the `--ticketbleed` flag to test for Ticketbleed (CVE-2016-9244).

Ticketbleed affects some F5 BIG-IP load balancers when session ticket handling leaks memory into the TLS session ID field. The check probes session ticket support and compares repeated handshake responses for inconsistent leaked data.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --ticketbleed example.com
./web-reGOn --ticketbleed example.com --port 8443
```

## TLS_FALLBACK_SCSV
Use the `--tls-fallback-scsv` flag to check TLS_FALLBACK_SCSV (RFC 7507) downgrade attack prevention.

TLS_FALLBACK_SCSV is a cipher suite signal that tells the server the client is intentionally connecting with an older protocol version as a fallback. Compliant servers should reject the connection with an inappropriate fallback alert instead of completing a downgrade that could enable attacks such as POODLE.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --tls-fallback-scsv example.com
./web-reGOn --tls-fallback-scsv example.com --port 8443
```

## Winshock
Use the `--winshock` flag to test for Winshock (CVE-2014-6321).

Winshock is a critical flaw in Microsoft’s Schannel (MS14-066) that can allow remote code execution on unpatched Windows Server 2012 / IIS 8.x systems. The check uses TLS cipher and extension heuristics plus HTTP Server banner analysis to identify likely vulnerable Microsoft stacks.

You can also use the optional `--port` flag (default: `443`):
```
./web-reGOn --winshock example.com
./web-reGOn --winshock example.com --port 8443
```


## Padding Oracle
Use the `--padding-oracle` flag to decrypt a CBC token by exploiting a server-side padding oracle (PadBuster decrypt mode). Every oracle response is classified as padding-valid or padding-invalid, and the target block is then recovered one byte at a time; no key is needed.

Supply the target URL (positional argument), the captured ciphertext sample (`--token`), and the error marker the server returns for bad padding (`--error-msg`). The token must decode to a whole number of blocks (default block size is `16`).

The oracle endpoint is derived from the target URL: a trailing `/encrypt` is swapped for `/decrypt` and the query string is dropped, so pass the encrypt endpoint that produced the token. A URL with no `/encrypt` segment keeps its path unchanged. Use the optional `--port` flag to override the port taken from the URL.

If `--error-msg` is omitted, the tool probes all 256 values of the last byte first and infers the padding-error signature from the most frequent response; that automatic mode is less reliable on noisy endpoints. Use `--encoding` when the token is not standard Base64 (`0`=Base64, `1`=Lower HEX, `2`=Upper HEX, `3`=.NET UrlToken, `4`=WebSafe Base64), and repeat `--po-cookie` for each cookie whose value carries the token.

Note that many servers return a single generic error for every kind of failure: bad padding, a bad UTF-8 sequence in the decrypted plaintext, or a failed integrity check. Such an endpoint is still a usable oracle, because the scan walks from `0xff` down to `0x00` and keeps the first value the server does not flag. It does mean an occasional stray hit is possible; when a decrypted plaintext looks wrong, capture a second sample and confirm the block by hand.

``` 
./web-reGOn "http://127.0.0.1:5000/encrypt?data=user=guest" --padding-oracle --port 5000 --token "YWJjZGVmMDEyMzQ1Njc4OQea74b3T7jnT1u1Yba3/38=" --error-msg padding_error
./web-reGOn "http://10.0.0.5/encrypt?data=user=guest" --padding-oracle --port 8443 --token "ABCD...==" --encoding 0 --error-msg padding_error
./web-reGOn "http://10.0.0.5/encrypt?data=user=guest" --padding-oracle --port 8443 --token "..." --error-msg "Invalid padding" --block-size 16
```

To also send the token inside a cookie, add one `--po-cookie` per cookie:
```
./web-reGOn "http://127.0.0.1:5000/encrypt?data=user=guest" --padding-oracle --port 5000 --token "..." --error-msg padding_error --po-cookie "auth=..."
```
