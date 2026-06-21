## Test All
Use the `--test-all` flag to run all Weak Cryptography vulnerability checks in order.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --test-all [domain name] --port [port number]
```

## Multiple Flags
You can combine Weak Cryptography flags on one command line. Tests run in the order the flags appear on the command line:
```
./linux-reGOn --anonymous-ciphers --breach --logjam [domain name] --port [port number]
```

## Anonymous Ciphers
Use the `--anonymous-ciphers` flag to test for support of anonymous (anon) cipher suites.

Anonymous ciphers do not provide any authentication or encryption methods, and according to RFC 7672, they may be supported in the SMTP protocol.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --anonymous-ciphers [domain name] --port [port number]
```

## BEAST ((Browser Exploit Against SSL/TLS))
Use the `--beast` flag to test for the BEAST (CVE-2011-3389) vulnerability.

in SSLv3/TLS 1.0 CBC mode encryption. In SSLv3/TLS 1.0, cipher suites that use CBC mode encryption cause each block of plaintext to be XORed with the previous ciphertext block before being encrypted. This chaining means that if an attacker can manipulate a cipher block in a specific way, they can affect subsequent blocks.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --beast [domain name] --port [port number]
```

## DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
Use the `--drown` flag to test for SSLv2 (CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 DROWN) vulnerabilities.

The attack particularly targets RSA keys that are used in the SSLv2 handshake process. If a server supports SSLv2 and uses RSA for encryption, an attacker can potentially decrypt certain secure communications by leveraging the weaknesses in the protocol.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --drown [domain name] --port [port number]
```

## FREAK (Factoring RSA Export Keys)
Use the `--freak` flag to test for FREAK (CVE-2015-0204) export RSA cipher suites vulnerability.

During the 1990s, U.S. regulations limited the strength of encryption technology that could be exported. As a result, some products implemented "export-grade" cryptography, which typically used weaker RSA keys (around 512 bits) to comply with these regulations. Using the weaker RSA keys, attackers can use modern computational power to factor the keys and decrypt the traffic. RSA with 512-bit keys can be compromised much more easily than with standard 2048-bit or higher keys. The  attacker must have a position in the network that allows them to intercept and modify communications.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --freak [domain name] --port [port number]
```

## LUCKY13
Use the `--lucky13` flag to test for Lucky 13 (CVE-2013-0169) TLS CBC vulnerability.

The LUCKY13 attack leverages timing discrepancies during the decryption of CBC-encrypted messages. When responding to encrypted messages, servers might process different lengths of data in variable time due to the need to decrypt blocks sequentially. This variance allows attackers to deduce information about the plaintext based on response times. If the padding in TLS is not handled uniformly or securely, an attacker can exploit timing information to recover the plain-text data or padding structure.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --lucky13 [domain name] --port [port number]
```

## NOMORE (Numerous Occurrence MOnitoring & Recovery Exploit)
Use the `--nomore` flag to test for the NOMORE (CVE-2013-2566) vulnerability in RC4 cipher suites.

This is a practical attack against RC4 encryption in TLS/HTTPS that was demonstrated by researchers from KU Leuven in 2015. RC4 has two types of predictable biases in its keystream output. Fluhrer-McGrew biases indicate that two consecutive bytes in the keystream are biased toward certain values, meaning they are not truly random. ABSAB biases (also known as Mantin's biases) suggest that pairs of consecutive bytes are likely to repeat themselves. These biases imply that if you encrypt the same data (such as a web cookie) multiple times with RC4, the resulting ciphertexts will follow predictable patterns.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --nomore [domain name] --port [port number]
```

## NULL Ciphers
Use the `--null-ciphers` flag to test for for NULL cipher suites vulnerability.

NULL cipher suites provide authentication only and no encryption.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --null-ciphers [domain name] --port [port number]
```

## Insecure Renegotiation
Use the `--insecure-renegotiation` flag to test for insecure TLS renegotiation (RFC 5746 / CVE-2011-1473).

Checks whether the server supports secure renegotiation (RFC 5746) and whether it accepts client-initiated renegotiation, which can be abused for denial-of-service attacks.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --insecure-renegotiation [domain name] --port [port number]
```

## BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
Use the `--breach` flag to test for BREACH (CVE-2013-3587) HTTP compression vulnerability.

BREACH is an HTTP-level compression attack that works against any cipher suite and is agnostic to the version of TLS/SSL. If the server compresses HTTP responses (gzip, deflate, compress, or br) and the page reflects attacker-influenced input, secrets in the page may be recoverable through compression side channels.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --breach [domain name] --port [port number]
```

## CRIME (Compression Ratio Info-leak Made Easy)
Use the `--crime` flag to test for CRIME (CVE-2012-4929) TLS compression vulnerability.

CRIME exploits TLS-level compression (such as DEFLATE) to recover secrets from encrypted traffic when the attacker can control part of the request and observe ciphertext length changes. TLS 1.3 does not support compression.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --crime [domain name] --port [port number]
```

## CCS (ChangeCipherSpec Injection)
Use the `--ccs-injection` flag to test for CCS injection (CVE-2014-0224) vulnerability.

CCS injection is an OpenSSL/TLS flaw where a ChangeCipherSpec message sent early in the handshake can skip key material verification. A vulnerable server may accept the message and allow a man-in-the-middle to decrypt or modify traffic.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --ccs-injection [domain name] --port [port number]
```

## Heartbleed
Use the `--heartbleed` flag to test for Heartbleed (CVE-2014-0160) vulnerability.

Heartbleed is a flaw in OpenSSL's implementation of the TLS heartbeat extension. A malformed heartbeat request can cause the server to leak memory contents, potentially exposing private keys, session tokens, and other sensitive data.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --heartbleed [domain name] --port [port number]
```

## LOGJAM
Use the `--logjam` flag to test for LOGJAM (CVE-2015-4000) DH EXPORT vulnerability.

LOGJAM targets weak Diffie-Hellman key exchange, especially export-grade DH cipher suites with small prime sizes. An attacker who can downgrade or force use of these ciphers may be able to break the key exchange and decrypt traffic.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --logjam [domain name] --port [port number]
```

## POODLE (Padding Oracle On Downgraded Legacy Encryption)
Use the `--poodle` flag to test for POODLE SSL (CVE-2014-3566) and TLS (CVE-2014-8730) vulnerabilities.

POODLE SSL exploits CBC padding in SSLv3 to decrypt HTTPS cookies when the server still supports SSLv3. POODLE TLS is an experimental check for similar padding issues in TLS; full coverage may require dedicated timing analysis tools.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --poodle [domain name] --port [port number]
```

## SWEET32
Use the `--sweet32` flag to test for SWEET32 (CVE-2016-2183) 64-bit block cipher vulnerability.

SWEET32 is a birthday attack against 64-bit block ciphers such as 3DES, DES, RC2, and IDEA. Long-lived HTTPS sessions using these ciphers can allow an attacker to recover cookies or other secrets after collecting enough ciphertext blocks.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --sweet32 [domain name] --port [port number]
```

## Ticketbleed
Use the `--ticketbleed` flag to test for Ticketbleed (CVE-2016-9244) vulnerability.

Ticketbleed affects some F5 BIG-IP load balancers when session ticket handling leaks memory into the TLS session ID field. The check probes session ticket support and compares repeated handshake responses for inconsistent leaked data.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --ticketbleed [domain name] --port [port number]
```

## TLS_FALLBACK_SCSV
Use the `--tls-fallback-scsv` flag to check TLS_FALLBACK_SCSV (RFC 7507) downgrade attack prevention.

TLS_FALLBACK_SCSV is a cipher suite signal that tells the server the client is intentionally connecting with an older protocol version as a fallback. Compliant servers should reject the connection with an inappropriate fallback alert instead of completing a downgrade that could enable attacks such as POODLE.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --tls-fallback-scsv [domain name] --port [port number]
```

## Winshock
Use the `--winshock` flag to test for Winshock (CVE-2014-6321) vulnerability.

Winshock is a critical flaw in Microsoft's Schannel (MS14-066) that can allow remote code execution on unpatched Windows Server 2012 / IIS 8.x systems. The check uses TLS cipher and extension heuristics plus HTTP Server banner analysis to identify likely vulnerable Microsoft stacks.

You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --winshock [domain name] --port [port number]
```
