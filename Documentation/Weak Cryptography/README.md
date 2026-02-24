## Anonymous Ciphers
Use the `--anonymous-ciphers` flag to test for support of anonymous (anon) cipher suites. Anonymous ciphers do not provide any authentication or encryption methods, and according to RFC 7672, they may be supported in the SMTP protocol. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --anonymous-ciphers [domain name] --port [port number]
```

## BEAST ((Browser Exploit Against SSL/TLS))
Use the `--beast` flag to test for the BEAST (CVE-2011-3389) vulnerability. in SSLv3/TLS 1.0 CBC mode encryption. In SSLv3/TLS 1.0, cipher suites that use CBC mode encryption cause each block of plaintext to be XORed with the previous ciphertext block before being encrypted. This chaining means that if an attacker can manipulate a cipher block in a specific way, they can affect subsequent blocks. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --beast [domain name] --port [port number]
```

## DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
Use the `--drown` flag to test for SSLv2 (CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 DROWN) vulnerabilities. The attack particularly targets RSA keys that are used in the SSLv2 handshake process. If a server supports SSLv2 and uses RSA for encryption, an attacker can potentially decrypt certain secure communications by leveraging the weaknesses in the protocol. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --drown [domain name] --port [port number]
```

## FREAK (Factoring RSA Export Keys)
Use the `--freak` flag to test for FREAK (CVE-2015-0204) export RSA cipher suites vulnerability. During the 1990s, U.S. regulations limited the strength of encryption technology that could be exported. As a result, some products implemented "export-grade" cryptography, which typically used weaker RSA keys (around 512 bits) to comply with these regulations. Using the weaker RSA keys, attackers can use modern computational power to factor the keys and decrypt the traffic. RSA with 512-bit keys can be compromised much more easily than with standard 2048-bit or higher keys. The  attacker must have a position in the network that allows them to intercept and modify communications. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --freak [domain name] --port [port number]
```

## LUCKY13
Use the `--lucky13` flag to test for Lucky 13 (CVE-2013-0169) TLS CBC vulnerability. The LUCKY13 attack leverages timing discrepancies during the decryption of CBC-encrypted messages. When responding to encrypted messages, servers might process different lengths of data in variable time due to the need to decrypt blocks sequentially. This variance allows attackers to deduce information about the plaintext based on response times. If the padding in TLS is not handled uniformly or securely, an attacker can exploit timing information to recover the plain-text data or padding structure. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --lucky13 [domain name] --port [port number]
```

## NOMORE (Numerous Occurrence MOnitoring & Recovery Exploit)
Use the `--nomore` flag to test for the NOMORE (CVE-2013-2566) vulnerability in RC4 cipher suites. This is a practical attack against RC4 encryption in TLS/HTTPS that was demonstrated by researchers from KU Leuven in 2015. RC4 has two types of predictable biases in its keystream output. Fluhrer-McGrew biases indicate that two consecutive bytes in the keystream are biased toward certain values, meaning they are not truly random. ABSAB biases (also known as Mantin's biases) suggest that pairs of consecutive bytes are likely to repeat themselves. These biases imply that if you encrypt the same data (such as a web cookie) multiple times with RC4, the resulting ciphertexts will follow predictable patterns. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --nomore [domain name] --port [port number]
```

## NULL Ciphers
Use the `--null-ciphers` flag to test for for NULL cipher suites vulnerability. NULL cipher suites provide authentication only and no encryption. You can also use the optional `--port` flag to specify the port to test (the default port is 443):
```
./linux-reGOn --null-ciphers [domain name] --port [port number]
```