package brokenauthorization

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

var cipherSuites = map[uint16]CipherDetails{
	// Insecure
	0x0019: {"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES40 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0017: {"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Rivest Cipher 4 with 40bit key (RC4 40)", "HMAC Message Digest 5 (MD5)"},
	0x001B: {"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC) ", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0034: {"TLS_DH_anon_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x006C: {"TLS_DH_anon_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A6: {"TLS_DH_anon_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x003A: {"TLS_DH_anon_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x006D: {"TLS_DH_anon_WITH_AES_256_CBC_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A7: {"TLS_DH_anon_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC046: {"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC05A: {"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC047: {"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC05B: {"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0046: {"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00BF: {"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC084: {"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0089: {"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00C5: {"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC085: {"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0x001A: {"TLS_DH_anon_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0018: {"TLS_DH_anon_WITH_RC4_128_MD5", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Message Digest 5 (MD5)"},
	0x009B: {"TLS_DH_anon_WITH_SEED_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Anonymous (anon)", "SEED in Cipher Block Chaining mode (SEED CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x000B: {"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES40 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x000C: {"TLS_DH_DSS_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0011: {"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES40 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0012: {"TLS_DHE_DSS_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x002D: {"TLS_DHE_PSK_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B4: {"TLS_DHE_PSK_WITH_NULL_SHA256", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00B5: {"TLS_DHE_PSK_WITH_NULL_SHA384", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0x008E: {"TLS_DHE_PSK_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0014: {"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES40 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0015: {"TLS_DHE_RSA_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x000E: {"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES40 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x000F: {"TLS_DH_RSA_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC017: {"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Anonymous (anon)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC018: {"TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Anonymous (anon)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC019: {"TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Anonymous (anon)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC015: {"TLS_ECDH_anon_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Anonymous (anon)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC016: {"TLS_ECDH_anon_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Anonymous (anon)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC001: {"TLS_ECDH_ECDSA_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC002: {"TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC006: {"TLS_ECDHE_ECDSA_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC007: {"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC039: {"TLS_ECDHE_PSK_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC03A: {"TLS_ECDHE_PSK_WITH_NULL_SHA256", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC03B: {"TLS_ECDHE_PSK_WITH_NULL_SHA384", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC033: {"TLS_ECDHE_PSK_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC010: {"TLS_ECDHE_RSA_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC011: {"TLS_ECDHE_RSA_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC00B: {"TLS_ECDH_RSA_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC00C: {"TLS_ECDH_RSA_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC102: {"TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "Transport Layer Security (TLS)", "Insecure", "Key agreement Function based on GOST R 34.11-2012 (GOSTR341112 256)", "GOST R 34.10-2012 Digital Signature Algorithm (GOSTR341012)", "GOST 28147-89 (28147 CNT)", "HMAC GOST R 34.11-2012 Hash Function (GOSTR341112)"},
	0xC100: {"TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "Transport Layer Security (TLS)", "Insecure", "Key agreement Function based on GOST R 34.11-2012 (GOSTR341112 256)", "GOST R 34.10-2012 Digital Signature Algorithm (GOSTR341012)", "Kuznyechik Block Cipher in Counter Mode (CTR) (KUZNYECHIK CTR)", "HMAC GOST R 34.11-2012 Hash Function (GOSTR341112)"},
	0xC103: {"TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "?", "Kuznyechik Block Cipher in Multilinear Galois Mode (MGM) (KUZNYECHIK MGM L)", "?"},
	0xC105: {"TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "?", "Kuznyechik Block Cipher in Multilinear Galois Mode (MGM) (KUZNYECHIK MGM S)", "?"},
	0xC101: {"TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "Transport Layer Security (TLS)", "Insecure", "Key agreement Function based on GOST R 34.11-2012 (GOSTR341112 256)", "GOST R 34.10-2012 Digital Signature Algorithm (GOSTR341012)", "Magma Block Cipher in Counter Mode (CTR) (MAGMA CTR)", "HMAC GOST R 34.11-2012 Hash Function (GOSTR341112)"},
	0xC104: {"TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "?", "Magma Block Cipher in Multilinear Galois Mode (MGM) (MAGMA MGM L)", "?"},
	0xC106: {"TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", "Transport Layer Security (TLS)", "Insecure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "?", "Magma Block Cipher in Multilinear Galois Mode (MGM) (MAGMA MGM S)", "?"},
	0x0029: {"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES CBC 40)", "HMAC Message Digest 5 (MD5)"},
	0x0026: {"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES CBC 40)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x002A: {"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Rivest Cipher 2 with 40bit key in Cipher Block Chaining mode (RC2 CBC 40)", "HMAC Message Digest 5 (MD5)"},
	0x0027: {"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Rivest Cipher 2 with 40bit key in Cipher Block Chaining mode (RC2 CBC 40)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x002B: {"TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Rivest Cipher 4 with 40bit key (RC4 40)", "HMAC Message Digest 5 (MD5)"},
	0x0028: {"TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Rivest Cipher 4 with 40bit key (RC4 40)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0023: {"TLS_KRB5_WITH_3DES_EDE_CBC_MD5", "Transport Layer Security (TLS)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Message Digest 5 (MD5)"},
	0x0022: {"TLS_KRB5_WITH_DES_CBC_MD5", "Transport Layer Security (TLS)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Message Digest 5 (MD5)"},
	0x001E: {"TLS_KRB5_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0025: {"TLS_KRB5_WITH_IDEA_CBC_MD5", "Transport Layer Security (TLS)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "IDEA in Cipher Block Chaining mode (IDEA CBC)", "HMAC Message Digest 5 (MD5)"},
	0x0024: {"TLS_KRB5_WITH_RC4_128_MD5", "Transport Layer Security (TLS)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Message Digest 5 (MD5)"},
	0x0020: {"TLS_KRB5_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0000: {"TLS_NULL_WITH_NULL_NULL", "Transport Layer Security (TLS)", "Insecure", "NULL Key exchange (NULL)", "Null Authentication (NULL)", "NULL Encryption (NULL)", "NULL Hash (NULL)"},
	0x002C: {"TLS_PSK_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B0: {"TLS_PSK_WITH_NULL_SHA256", "Transport Layer Security (TLS)", "Insecure", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00B1: {"TLS_PSK_WITH_NULL_SHA384", "Transport Layer Security (TLS)", "Insecure", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0x008A: {"TLS_PSK_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0008: {"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Data Encryption Standard with 40bit key in Cipher Block Chaining mode (DES40 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0006: {"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Cipher 2 with 40bit key in Cipher Block Chaining mode (RC2 CBC 40)", "HMAC Message Digest 5 (MD5)"},
	0x0003: {"TLS_RSA_EXPORT_WITH_RC4_40_MD5", "Export-grade Transport Layer Security (TLS EXPORT)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Cipher 4 with 40bit key (RC4 40)", "HMAC Message Digest 5 (MD5)"},
	0x002E: {"TLS_RSA_PSK_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B8: {"TLS_RSA_PSK_WITH_NULL_SHA256", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00B9: {"TLS_RSA_PSK_WITH_NULL_SHA384", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0x0092: {"TLS_RSA_PSK_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0009: {"TLS_RSA_WITH_DES_CBC_SHA", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Data Encryption Standard with 56bit key in Cipher Block Chaining mode (DES CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0001: {"TLS_RSA_WITH_NULL_MD5", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "NULL Encryption (NULL)", "HMAC Message Digest 5 (MD5)"},
	0x0002: {"TLS_RSA_WITH_NULL_SHA", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x003B: {"TLS_RSA_WITH_NULL_SHA256", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x0004: {"TLS_RSA_WITH_RC4_128_MD5", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Message Digest 5 (MD5)"},
	0x0005: {"TLS_RSA_WITH_RC4_128_SHA", "Transport Layer Security (TLS)", "Insecure", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Cipher 4 with 128bit key (RC4 128)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC0B4: {"TLS_SHA256_SHA256", "Transport Layer Security (TLS)", "Insecure", "?", "SHA256", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC0B5: {"TLS_SHA384_SHA384", "Transport Layer Security (TLS)", "Insecure", "?", "SHA384", "NULL Encryption (NULL)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0x00C7: {"TLS_SM4_CCM_SM3", "Transport Layer Security (TLS)", "Insecure", "?", "?", "ShangMi 4 Encryption Algorithm in Counter with CBC-MAC Mode (SM4 CCM)", "ShangMi 3 Hashing Algorithm (SM3)"},
	0x00C6: {"TLS_SM4_GCM_SM3", "Transport Layer Security (TLS)", "Insecure", "?", "?", "ShangMi 4 Encryption Algorithm in Galois/Counter Mode (SM4 GCM)", "ShangMi 3 Hashing Algorithm (SM3)"},

	// Weak
	0x000D: {"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0030: {"TLS_DH_DSS_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x003E: {"TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A4: {"TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0036: {"TLS_DH_DSS_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0068: {"TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A5: {"TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC03E: {"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC058: {"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC03F: {"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC059: {"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0042: {"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00BB: {"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC082: {"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x0085: {"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00C1: {"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC083: {"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0097: {"TLS_DH_DSS_WITH_SEED_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "SEED in Cipher Block Chaining mode (SEED CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0013: {"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0032: {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0040: {"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A2: {"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0038: {"TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x006A: {"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A3: {"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC042: {"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC056: {"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC043: {"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC057: {"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0044: {"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00BD: {"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC080: {"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0087: {"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00C3: {"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC081: {"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0099: {"TLS_DHE_DSS_WITH_SEED_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Digital Signature Standard (DSS)", "SEED in Cipher Block Chaining mode (SEED CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x008F: {"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0090: {"TLS_DHE_PSK_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B2: {"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC0A6: {"TLS_DHE_PSK_WITH_AES_128_CCM", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x00AA: {"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0091: {"TLS_DHE_PSK_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B3: {"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC0A7: {"TLS_DHE_PSK_WITH_AES_256_CCM", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode (AES 256 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x00AB: {"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC066: {"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC06C: {"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC067: {"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC06D: {"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC096: {"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC090: {"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC097: {"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC091: {"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCAD: {"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0016: {"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0033: {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0067: {"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC09E: {"TLS_DHE_RSA_WITH_AES_128_CCM", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0A2: {"TLS_DHE_RSA_WITH_AES_128_CCM_8", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x009E: {"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0039: {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x006B: {"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC09F: {"TLS_DHE_RSA_WITH_AES_256_CCM", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode (AES 256 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0A3: {"TLS_DHE_RSA_WITH_AES_256_CCM_8", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode with an 8-Octet ICV (AES 256 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x009F: {"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC044: {"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC052: {"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC045: {"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC053: {"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0045: {"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00BE: {"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC07C: {"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0088: {"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00C4: {"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC07D: {"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCAA: {"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},
	0x009A: {"TLS_DHE_RSA_WITH_SEED_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Rivest Shamir Adleman algorithm (RSA)", "SEED in Cipher Block Chaining mode (SEED CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0010: {"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0031: {"TLS_DH_RSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x003F: {"TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A0: {"TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0037: {"TLS_DH_RSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0069: {"TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00A1: {"TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC040: {"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC054: {"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC041: {"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC055: {"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0043: {"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00BC: {"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC07E: {"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0086: {"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00C2: {"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC07F: {"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0098: {"TLS_DH_RSA_WITH_SEED_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman (DH)", "Rivest Shamir Adleman algorithm (RSA)", "SEED in Cipher Block Chaining mode (SEED CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC003: {"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC004: {"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC025: {"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC02D: {"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC005: {"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC026: {"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC02E: {"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC04A: {"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC05E: {"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC04B: {"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC05F: {"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC074: {"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC088: {"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC075: {"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC089: {"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC008: {"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC009: {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC023: {"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC00A: {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC024: {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC048: {"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC049: {"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC072: {"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC073: {"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC034: {"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC035: {"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC037: {"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC036: {"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC038: {"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC070: {"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC071: {"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC09A: {"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC09B: {"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC012: {"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC013: {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC027: {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC014: {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC028: {"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC04C: {"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC04D: {"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC076: {"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC077: {"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC00D: {"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC00E: {"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC029: {"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC031: {"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC00F: {"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC02A: {"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC032: {"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC04E: {"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC062: {"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC04F: {"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC063: {"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC078: {"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC08C: {"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC079: {"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC08D: {"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Elliptic Curve Diffie-Hellman (ECDH)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x001F: {"TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0021: {"TLS_KRB5_WITH_IDEA_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Kerberos 5 (KRB5)", "Kerberos 5 (KRB5)", "IDEA in Cipher Block Chaining mode (IDEA CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC0AA: {"TLS_PSK_DHE_WITH_AES_128_CCM_8", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0AB: {"TLS_PSK_DHE_WITH_AES_256_CCM_8", "Transport Layer Security (TLS)", "Weak", "Diffie-Hellman Ephemeral (DHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode with an 8-Octet ICV (AES 256 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x008B: {"TLS_PSK_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x008C: {"TLS_PSK_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00AE: {"TLS_PSK_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC0A4: {"TLS_PSK_WITH_AES_128_CCM", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0A8: {"TLS_PSK_WITH_AES_128_CCM_8", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x00A8: {"TLS_PSK_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x008D: {"TLS_PSK_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00AF: {"TLS_PSK_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC0A5: {"TLS_PSK_WITH_AES_256_CCM", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode (AES 256 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0A9: {"TLS_PSK_WITH_AES_256_CCM_8", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode with an 8-Octet ICV (AES 256 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x00A9: {"TLS_PSK_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC064: {"TLS_PSK_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC06A: {"TLS_PSK_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC065: {"TLS_PSK_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC06B: {"TLS_PSK_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC094: {"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC08E: {"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC095: {"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC08F: {"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCAB: {"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Weak", "Pre-Shared Key (PSK)", "Pre-Shared Key (PSK)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0093: {"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0094: {"TLS_RSA_PSK_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B6: {"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0x00AC: {"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0095: {"TLS_RSA_PSK_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00B7: {"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0x00AD: {"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", " Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC068: {"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC06E: {"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC069: {"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC06F: {"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC098: {"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC092: {"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC099: {"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC093: {"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCAE: {"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Pre-Shared Key (PSK)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},
	0x000A: {"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x002F: {"TLS_RSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x003C: {"TLS_RSA_WITH_AES_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC09C: {"TLS_RSA_WITH_AES_128_CCM", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0A0: {"TLS_RSA_WITH_AES_128_CCM_8", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x009C: {"TLS_RSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0035: {"TLS_RSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x003D: {"TLS_RSA_WITH_AES_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC09D: {"TLS_RSA_WITH_AES_256_CCM", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode (AES 256 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0A1: {"TLS_RSA_WITH_AES_256_CCM_8", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode with an 8-Octet ICV (AES 256 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x009D: {"TLS_RSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC03C: {"TLS_RSA_WITH_ARIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Cipher Block Chaining mode (ARIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC050: {"TLS_RSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC03D: {"TLS_RSA_WITH_ARIA_256_CBC_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Cipher Block Chaining mode (ARIA 256 CBC)", "HMAC Secure Hash Algorithm 384 (SHA384)"},
	0xC051: {"TLS_RSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0041: {"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00BA: {"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Cipher Block Chaining mode (CAMELLIA 128 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC07A: {"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x0084: {"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x00C0: {"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Cipher Block Chaining mode (CAMELLIA 256 CBC)", "HMAC Secure Hash Algorithm 256 (SHA256)"},
	0xC07B: {"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x0007: {"TLS_RSA_WITH_IDEA_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "IDEA in Cipher Block Chaining mode (IDEA CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0096: {"TLS_RSA_WITH_SEED_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Rivest Shamir Adleman algorithm (RSA)", "Rivest Shamir Adleman algorithm (RSA)", "SEED in Cipher Block Chaining mode (SEED CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC01C: {"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 with Digital Signature Standard (SHA DSS)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC01F: {"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 with Digital Signature Standard (SHA DSS)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC022: {"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 with Digital Signature Standard (SHA DSS)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC01B: {"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 with Rivest Shamir Adleman algorithm (SHA RSA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC01E: {"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 with Rivest Shamir Adleman algorithm (SHA RSA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC021: {"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 with Rivest Shamir Adleman algorithm (SHA RSA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC01A: {"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 (SHA)", "Triple-DES (Encrypt Decrypt Encrypt) in Cipher Block Chaining mode (3DES EDE CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC01D: {"TLS_SRP_SHA_WITH_AES_128_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 (SHA)", "Advanced Encryption Standard with 128bit key in Cipher Block Chaining mode (AES 128 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xC020: {"TLS_SRP_SHA_WITH_AES_256_CBC_SHA", "Transport Layer Security (TLS)", "Weak", "Secure Remote Password (SRP)", "Secure Hash Algorithm 1 (SHA)", "Advanced Encryption Standard with 256bit key in Cipher Block Chaining mode (AES 256 CBC)", "HMAC Secure Hash Algorithm 1 (SHA)"},

	// Secure
	0x1305: {"TLS_AES_128_CCM_8_SHA256", "Transport Layer Security (TLS)", "Secure", "?", "?", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0x1304: {"TLS_AES_128_CCM_SHA256", "Transport Layer Security (TLS)", "Secure", "?", "?", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0B2: {"TLS_ECCPWD_WITH_AES_128_CCM_SHA256", "Transport Layer Security (TLS)", "Secure", "ECCPWD", "ECCPWD", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0B3: {"TLS_ECCPWD_WITH_AES_256_CCM_SHA384", "Transport Layer Security (TLS)", "Secure", "ECCPWD", "ECCPWD", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode (AES 256 CCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC0AC: {"TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0AE: {"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0AD: {"TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode (AES 256 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0AF: {"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Counter with CBC-MAC mode with an 8-Octet ICV (AES 256 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0xD003: {"TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode with 8-Octet ICV (AES 128 CCM 8)", "Secure Hash Algorithm 256 (SHA256)"},
	0xD005: {"TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Counter with CBC-MAC mode (AES 128 CCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC02F: {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC030: {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC060: {"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC061: {"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC08A: {"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC08B: {"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCA8: {"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Secure", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Rivest Shamir Adleman algorithm (RSA)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},

	// Recommended
	0x1301: {"TLS_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Recommended", "?", "?", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0x1302: {"TLS_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Recommended", "?", "?", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0x1303: {"TLS_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Recommended", "?", "?", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0B0: {"TLS_ECCPWD_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Recommended", "ECCPWD", "ECCPWD", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC0B1: {"TLS_ECCPWD_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Recommended", "ECCPWD", "ECCPWD", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC02B: {"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC02C: {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC05C: {"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 128bit key in Galois/Counter mode (ARIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC05D: {"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ARIA with 256bit key in Galois/Counter mode (ARIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xC086: {"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 128bit key in Galois/Counter mode (CAMELLIA 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xC087: {"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "CAMELLIA with 256bit key in Galois/Counter mode (CAMELLIA 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCA9: {"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Elliptic Curve Digital Signature Algorithm (ECDSA)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},
	0xD001: {"TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 128bit key in Galois/Counter mode (AES 128 GCM)", "Secure Hash Algorithm 256 (SHA256)"},
	0xD002: {"TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "Advanced Encryption Standard with 256bit key in Galois/Counter mode (AES 256 GCM)", "Secure Hash Algorithm 384 (SHA384)"},
	0xCCAC: {"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", "Transport Layer Security (TLS)", "Recommended", "Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)", "Pre-Shared Key (PSK)", "ChaCha stream cipher and Poly1305 authenticator (CHACHA20 POLY1305)", "Secure Hash Algorithm 256 (SHA256)"},

	// SSLv3 cipher suites
	0x0081:  {"GOST2001-GOST89-GOST89", "SSLv3", "Insecure", "GOST Key Exchange", "GOST 28147-89", "GOST 256 Encryption", "GOST89IMIT Hash"},
	0xFF85:  {"GOST2012256-GOST89-GOST89", "SSLv3", "Insecure", "GOST Key Exchange", "GOST 28147-89", "GOST 256 Encryption", "GOST89IMIT Hash"},
	0x0066:  {"DHE-DSS-RC4-SHA", "SSLv3", "Insecure", "Diffie-Hellman (DH)", "Digital Signature Standard (DSS)", "RC4 (128-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xFEFF:  {"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", "SSLv3", "Insecure", "RSA Key Exchange", "RSA Authentication", "3DES (168-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xFFE0:  {"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", "SSLv3", "Insecure", "RSA Key Exchange", "RSA Authentication", "3DES (168-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0063:  {"EXP1024-DHE-DSS-DES-CBC-SHA", "SSLv3", "Insecure", "Diffie-Hellman (1024-bit)", "Digital Signature Standard (DSS)", "DES (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA) (export)"},
	0x0062:  {"EXP1024-DES-CBC-SHA", "SSLv3", "Insecure", "RSA (1024-bit) Key Exchange", "RSA Authentication", "DES (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA) (export)"},
	0x0061:  {"EXP1024-RC2-CBC-MD5", "SSLv3", "Insecure", "RSA (1024-bit) Key Exchange", "RSA Authentication", "RC2 (56-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5) (export)"},
	0xFEFE:  {"SSL_RSA_FIPS_WITH_DES_CBC_SHA", "SSLv3", "Insecure", "RSA Key Exchange", "RSA Authentication", "DES (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0xFFE1:  {"SSL_RSA_FIPS_WITH_DES_CBC_SHA", "SSLv3", "Insecure", "RSA Key Exchange", "RSA Authentication", "DES (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0065:  {"EXP1024-DHE-DSS-RC4-SHA", "SSLv3", "Insecure", "Diffie-Hellman (1024-bit)", "Digital Signature Standard (DSS)", "RC4 (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA) (export)"},
	0x0064:  {"EXP1024-RC4-SHA", "SSLv3", "Insecure", "RSA (1024-bit) Key Exchange", "RSA Authentication", "RC4 (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA) (export)"},
	0x0060:  {"EXP1024-RC4-MD5", "SSLv3", "Insecure", "RSA (1024-bit) Key Exchange", "RSA Authentication", "RC4 (56-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5) (export)"},
	0x0083:  {"GOST2001-NULL-GOST94", "SSLv3", "Insecure", "GOST Key Exchange", "GOST Authentication", "None Encryption", "GOST94 Hash"},
	0xFF87:  {"GOST2012256-NULL-STREEBOG256", "SSLv3", "Insecure", "GOST Key Exchange", "GOST Authentication", "None Encryption", "STREEBOG256 Hash"},

	// SSLv2 cipher suites
	0x0100: {"RC4-MD5", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "RC4 (128-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5)"},
	0x0700: {"DES-CBC3-MD5", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "3DES (168-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5)"},
	0x0701: {"DES-CBC3-SHA", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "3DES (168-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0800: {"RC4-64-MD5", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "RC4 (64-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5)"},
	0xFF80: {"DES-CFB-M1", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "DES (64-bit) Encryption", "HMAC M1"},
	0x0600: {"DES-CBC-MD5", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "DES (56-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5)"},
	0x0601: {"DES-CBC-SHA", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "DES (56-bit) Encryption", "HMAC Secure Hash Algorithm 1 (SHA)"},
	0x0400: {"EXP-RC2-CBC-MD5", "SSLv2", "Insecure", "RSA (512-bit) Key Exchange", "RSA Authentication", "RC2 (40-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5) (export)"},
	0x0200: {"EXP-RC4-MD5", "SSLv2", "Insecure", "RSA (512-bit) Key Exchange", "RSA Authentication", "RC4 (40-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5) (export)"},
	0x0500: {"IDEA-CBC-MD5", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "IDEA (128-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5)"},
	0x0300: {"RC2-CBC-MD5", "SSLv2", "Insecure", "RSA Key Exchange", "RSA Authentication", "RC2 (128-bit) Encryption", "HMAC Message-Digest Algorithm 5 (MD5)"},
}

type CipherDetails struct {
	Name        string
	Protocol    string
	Security    string
	KeyExchange string
	Auth        string
	Encryption  string
	Hash        string
}

// getCipherSuitesByVersion returns cipher suites compatible with a specific TLS/SSL version
func getCipherSuitesByVersion(version uint16) []uint16 {
	var suites []uint16

	// TLS 1.3 cipher suites (only these 3)
	if version == 0x0304 { // TLS 1.3
		suites = []uint16{0x1301, 0x1302, 0x1303}
		return suites
	}

	// SSLv3 cipher suites (version 0x0300)
	if version == 0x0300 {
		return []uint16{0x0081, 0xFF85, 0x0066, 0xFEFF, 0xFFE0, 0x0063, 0x0062, 0x0061, 0xFEFE, 0xFFE1, 0x0065, 0x0064, 0x0060, 0x0083, 0xFF87}
	}

	// SSLv2 cipher suites (version 0x0200)
	if version == 0x0200 {
		return []uint16{0x0100, 0x0700, 0x0701, 0x0800, 0xFF80, 0x0600, 0x0601, 0x0400, 0x0200, 0x0500, 0x0300}
	}

	// TLS 1.0, 1.1, 1.2 cipher suites (all from map except TLS 1.3 only)
	for id := range cipherSuites {
		if id != 0x1301 && id != 0x1302 && id != 0x1303 {
			suites = append(suites, id)
		}
	}
	return suites
}

// buildClientHello constructs a TLS Client Hello packet
func buildClientHello(version uint16, cipherSuites []uint16, serverName string) []byte {
	var handshakeBuf bytes.Buffer

	// Client Version
	handshakeBuf.WriteByte(byte(version >> 8))
	handshakeBuf.WriteByte(byte(version & 0xFF))

	// Random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i) // Simple random for testing
	}
	handshakeBuf.Write(random)

	// Session ID Length
	handshakeBuf.WriteByte(0x00)

	// Cipher Suites Length
	cipherSuitesLen := len(cipherSuites) * 2
	handshakeBuf.WriteByte(byte(cipherSuitesLen >> 8))
	handshakeBuf.WriteByte(byte(cipherSuitesLen & 0xFF))

	// Cipher Suites
	for _, suite := range cipherSuites {
		handshakeBuf.WriteByte(byte(suite >> 8))
		handshakeBuf.WriteByte(byte(suite & 0xFF))
	}

	// Compression Methods Length
	handshakeBuf.WriteByte(0x01)
	handshakeBuf.WriteByte(0x00) // NULL compression

	// Build Extensions
	var extensionsBuf bytes.Buffer

	// Server Name Indication extension
	if serverName != "" {
		// Extension Type: server_name (0x0000)
		extensionsBuf.WriteByte(0x00)
		extensionsBuf.WriteByte(0x00)

		// Extension Length
		sniLen := 2 + 1 + 2 + len(serverName) // server_name_list length + entry type + host_name length + host_name
		extensionsBuf.WriteByte(byte(sniLen >> 8))
		extensionsBuf.WriteByte(byte(sniLen & 0xFF))

		// Server Name List Length
		listLen := 1 + 2 + len(serverName)
		extensionsBuf.WriteByte(byte(listLen >> 8))
		extensionsBuf.WriteByte(byte(listLen & 0xFF))

		// Name Type: host_name (0)
		extensionsBuf.WriteByte(0x00)

		// Host Name Length
		extensionsBuf.WriteByte(byte(len(serverName) >> 8))
		extensionsBuf.WriteByte(byte(len(serverName) & 0xFF))

		// Host Name
		extensionsBuf.WriteString(serverName)
	}

	// Add Extensions Length to handshake
	extensionsData := extensionsBuf.Bytes()
	extensionsLen := len(extensionsData)
	handshakeBuf.WriteByte(byte(extensionsLen >> 8))
	handshakeBuf.WriteByte(byte(extensionsLen & 0xFF))

	// Add Extensions to handshake
	handshakeBuf.Write(extensionsData)

	// Build Handshake Message
	var handshakeMsg bytes.Buffer
	handshakeMsg.WriteByte(0x01) // Handshake Type: Client Hello (1)

	handshakeData := handshakeBuf.Bytes()
	handshakeDataLen := len(handshakeData)
	handshakeMsg.WriteByte(byte(handshakeDataLen >> 16))
	handshakeMsg.WriteByte(byte((handshakeDataLen >> 8) & 0xFF))
	handshakeMsg.WriteByte(byte(handshakeDataLen & 0xFF))
	handshakeMsg.Write(handshakeData)

	// Build TLS Record
	var record bytes.Buffer
	record.WriteByte(0x16) // Content Type: Handshake (22)
	record.WriteByte(byte(version >> 8))
	record.WriteByte(byte(version & 0xFF))

	recordData := handshakeMsg.Bytes()
	recordLen := len(recordData)
	record.WriteByte(byte(recordLen >> 8))
	record.WriteByte(byte(recordLen & 0xFF))
	record.Write(recordData)

	return record.Bytes()
}

// buildClientHelloSSLv3 builds an SSLv3 Client Hello (no extensions). Same as TLS 1.0 Client Hello but without extensions.
func buildClientHelloSSLv3(version uint16, cipherSuites []uint16) []byte {
	var handshakeBuf bytes.Buffer
	handshakeBuf.WriteByte(byte(version >> 8))
	handshakeBuf.WriteByte(byte(version & 0xFF))
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	handshakeBuf.Write(random)
	handshakeBuf.WriteByte(0x00) // session_id_length
	cipherSuitesLen := len(cipherSuites) * 2
	handshakeBuf.WriteByte(byte(cipherSuitesLen >> 8))
	handshakeBuf.WriteByte(byte(cipherSuitesLen & 0xFF))
	for _, suite := range cipherSuites {
		handshakeBuf.WriteByte(byte(suite >> 8))
		handshakeBuf.WriteByte(byte(suite & 0xFF))
	}
	handshakeBuf.WriteByte(0x01)
	handshakeBuf.WriteByte(0x00) // NULL compression — no extensions in SSLv3

	var handshakeMsg bytes.Buffer
	handshakeMsg.WriteByte(0x01) // Client Hello
	handshakeData := handshakeBuf.Bytes()
	handshakeMsg.WriteByte(byte(len(handshakeData) >> 16))
	handshakeMsg.WriteByte(byte((len(handshakeData) >> 8) & 0xFF))
	handshakeMsg.WriteByte(byte(len(handshakeData) & 0xFF))
	handshakeMsg.Write(handshakeData)

	var record bytes.Buffer
	record.WriteByte(0x16) // Handshake
	record.WriteByte(byte(version >> 8))
	record.WriteByte(byte(version & 0xFF))
	rd := handshakeMsg.Bytes()
	record.WriteByte(byte(len(rd) >> 8))
	record.WriteByte(byte(len(rd) & 0xFF))
	record.Write(rd)
	return record.Bytes()
}

// sendRawClientHelloSSLv3 sends an SSLv3 Client Hello over raw TCP and parses the Server Hello response.
func sendRawClientHelloSSLv3(host, port string, version uint16, suites []uint16) (bool, uint16, uint16) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := buildClientHelloSSLv3(version, suites)
	if _, err := conn.Write(payload); err != nil {
		return false, 0, 0
	}
	data, err := readAllTLSData(conn, 5*time.Second)
	if err != nil || len(data) == 0 {
		return false, 0, 0
	}
	return parseServerHello(data)
}

// buildClientHelloSSLv2 builds an SSLv2 Client Hello. Cipher specs are 3 bytes each (SSLv2 wire format).
func buildClientHelloSSLv2(cipherSpecs [][3]byte) []byte {
	// SSLv2 record: high bit set = no padding. Length (2 bytes), type (1 = Client Hello), payload.
	var payload bytes.Buffer
	payload.WriteByte(0x00) // client_version major
	payload.WriteByte(0x02) // client_version minor (SSLv2)
	specsLen := len(cipherSpecs) * 3
	payload.WriteByte(byte(specsLen >> 8))
	payload.WriteByte(byte(specsLen & 0xFF))
	payload.WriteByte(0x00)
	payload.WriteByte(0x00) // session_id_length
	challengeLen := 16
	payload.WriteByte(byte(challengeLen >> 8))
	payload.WriteByte(byte(challengeLen & 0xFF))
	for _, spec := range cipherSpecs {
		payload.Write(spec[:])
	}
	challenge := make([]byte, challengeLen)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	payload.Write(challenge)

	pl := payload.Bytes()
	var record bytes.Buffer
	recLen := 1 + len(pl) // type + payload
	record.WriteByte(byte(recLen>>8) | 0x80) // high bit set = no padding
	record.WriteByte(byte(recLen & 0xFF))
	record.WriteByte(0x01) // SSLv2 Client Hello
	record.Write(pl)
	return record.Bytes()
}

// sslv2CipherSpec maps our 2-byte cipher ID to SSLv2 3-byte cipher spec (from OpenSSL-style encoding).
var sslv2CipherSpecs = map[uint16][3]byte{
	0x0100: {0x01, 0x00, 0x80}, // RC4-MD5
	0x0700: {0x07, 0x00, 0xC0}, // DES-CBC3-MD5
	0x0701: {0x07, 0x01, 0xC0}, // DES-CBC3-SHA
	0x0800: {0x08, 0x00, 0x80}, // RC4-64-MD5
	0xFF80: {0xFF, 0x80, 0x00}, // DES-CFB-M1
	0x0600: {0x06, 0x00, 0x40}, // DES-CBC-MD5
	0x0601: {0x06, 0x01, 0x40}, // DES-CBC-SHA
	0x0400: {0x04, 0x00, 0x40}, // EXP-RC2-CBC-MD5
	0x0200: {0x02, 0x00, 0x80}, // EXP-RC4-MD5
	0x0500: {0x05, 0x00, 0x80}, // IDEA-CBC-MD5
	0x0300: {0x03, 0x00, 0x80}, // RC2-CBC-MD5
}

// parseServerHelloSSLv2 parses SSLv2 Server Hello; returns true and connection_id/session_id if present.
func parseServerHelloSSLv2(data []byte) (bool, uint16, uint16) {
	if len(data) < 3 {
		return false, 0, 0
	}
	// SSLv2 record: first byte has high bit; length in 2 bytes; type (4 = Server Hello)
	off := 0
	for off < len(data) {
		if off+2 > len(data) {
			break
		}
		b0, b1 := data[off], data[off+1]
		off += 2
		recLen := int(b0&0x7F)<<8 | int(b1)
		if (b0 & 0x80) == 0 {
			if off+1 > len(data) {
				break
			}
			off++ // padding length
		}
		if off+1 > len(data) || off+recLen > len(data) {
			break
		}
		msgType := data[off]
		off++
		recLen--
		if msgType == 0x04 { // Server Hello
			// session_id_hit(1), certificate_type(1), version(2), certificate_length(2), cipher_specs_length(2), connection_id_length(2)
			if recLen >= 11 && off+10 <= len(data) {
				off += 2                                      // session_id_hit, certificate_type
				off += 2                                      // server version
				certLen := int(data[off])<<8 | int(data[off+1])
				off += 2
				cipherSpecsLen := int(data[off])<<8 | int(data[off+1])
				off += 2
				off += 2 // connection_id_length
				if off+certLen+cipherSpecsLen <= len(data) {
					off += certLen + cipherSpecsLen
					return true, 0, 0 // SSLv2 success; cipher not in 2-byte form
				}
			}
		}
		off += recLen
	}
	return false, 0, 0
}

// sendRawClientHelloSSLv2 sends an SSLv2 Client Hello over raw TCP and parses the Server Hello response.
func sendRawClientHelloSSLv2(host, port string, suites []uint16) (bool, uint16, uint16) {
	var specs [][3]byte
	for _, id := range suites {
		if spec, ok := sslv2CipherSpecs[id]; ok {
			specs = append(specs, spec)
		}
	}
	if len(specs) == 0 {
		return false, 0, 0
	}
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := buildClientHelloSSLv2(specs)
	if _, err := conn.Write(payload); err != nil {
		return false, 0, 0
	}
	data, err := readAllTLSData(conn, 5*time.Second)
	if err != nil || len(data) == 0 {
		return false, 0, 0
	}
	ok, _, _ := parseServerHelloSSLv2(data)
	return ok, 0x0200, 0 // SSLv2 version; cipher not in 2-byte form
}

// parseServerHello parses the Server Hello response and returns if certificate exchange occurred
func parseServerHello(data []byte) (bool, uint16, uint16) {
	if len(data) < 5 {
		return false, 0, 0
	}

	offset := 0
	var lastServerVersion uint16
	var lastCipherSuite uint16

	// Parse TLS records
	for offset < len(data) {
		if len(data) < offset+5 {
			break
		}

		// Check TLS Record Header
		contentType := data[offset]
		recordLen := int(data[offset+3])<<8 | int(data[offset+4])

		// Handle Alert messages (0x15) - these indicate errors
		if contentType == 0x15 {
			// Alert message - server rejected the connection
			// This might be normal if cipher suite is not supported
			offset += 5 + recordLen
			continue
		}

		if contentType != 0x16 { // Not a Handshake message
			// Skip to next record
			offset += 5 + recordLen
			continue
		}

		offset += 5

		if len(data) < offset+recordLen {
			break
		}

		recordEnd := offset + recordLen
		handshakeOffset := offset

		// Parse handshake messages in this record
		for handshakeOffset < recordEnd {
			if len(data) < handshakeOffset+4 {
				break
			}

			handshakeType := data[handshakeOffset]
			handshakeLen := int(data[handshakeOffset+1])<<16 | int(data[handshakeOffset+2])<<8 | int(data[handshakeOffset+3])
			handshakeOffset += 4

			if len(data) < handshakeOffset+handshakeLen {
				break
			}

			// Check for Server Hello (type 0x02) or HelloRetryRequest (type 0x06 for TLS 1.3)
			if handshakeType == 0x02 || handshakeType == 0x06 {
				if len(data) < handshakeOffset+2 {
					break
				}

				// Read Server Version
				serverVersion := uint16(data[handshakeOffset])<<8 | uint16(data[handshakeOffset+1])
				handshakeOffset += 2

				// Skip Random (32 bytes)
				if len(data) < handshakeOffset+32 {
					break
				}
				handshakeOffset += 32

				// Skip Session ID
				if len(data) < handshakeOffset+1 {
					break
				}
				sessionIDLen := int(data[handshakeOffset])
				handshakeOffset += 1

				if len(data) < handshakeOffset+sessionIDLen {
					break
				}
				handshakeOffset += sessionIDLen

				// Read Cipher Suite
				if len(data) < handshakeOffset+2 {
					break
				}
				cipherSuite := uint16(data[handshakeOffset])<<8 | uint16(data[handshakeOffset+1])

				// Store for later use
				lastServerVersion = serverVersion
				lastCipherSuite = cipherSuite

				// If we got a valid cipher suite (not 0x0000), certificate exchange will occur
				if cipherSuite != 0 {
					return true, serverVersion, cipherSuite
				}
			}

			// Check for Certificate message (type 0x0B) - indicates certificate exchange
			if handshakeType == 0x0B {
				// Certificate message found - this confirms certificate exchange
				// Use stored version and cipher from Server Hello
				if lastCipherSuite != 0 {
					return true, lastServerVersion, lastCipherSuite
				}
				return true, 0, 0
			}

			handshakeOffset += handshakeLen
		}

		offset = recordEnd
	}

	// If we found a Server Hello with a cipher suite, return it even if we didn't see Certificate message yet
	if lastCipherSuite != 0 {
		return true, lastServerVersion, lastCipherSuite
	}

	return false, 0, 0
}

// testCipherSuiteForVersion tests a single cipher suite for a specific TLS version
func testCipherSuiteForVersion(host, port string, tlsVersion uint16, cipherSuite uint16) (bool, uint16, uint16) {
	// SSLv3: send raw Client Hello with single suite
	if tlsVersion == 0x0300 {
		ok, ver, chosen := sendRawClientHelloSSLv3(host, port, 0x0300, []uint16{cipherSuite})
		if ok && chosen == cipherSuite {
			return true, ver, chosen
		}
		return ok, ver, chosen
	}
	// SSLv2: send raw Client Hello with single suite (server accepts or not; we report cipherSuite as chosen if ok)
	if tlsVersion == 0x0200 {
		ok, _, _ := sendRawClientHelloSSLv2(host, port, []uint16{cipherSuite})
		if ok {
			return true, 0x0200, cipherSuite
		}
		return false, 0, 0
	}

	// Check if this cipher suite is supported by Go
	filtered := filterSupportedCipherSuites([]uint16{cipherSuite})
	if len(filtered) == 0 {
		return false, 0, 0
	}

	addr := net.JoinHostPort(host, port)

	// Map TLS version constants
	var minVersion, maxVersion uint16
	switch tlsVersion {
	case 0x0301: // TLS 1.0
		minVersion = tls.VersionTLS10
		maxVersion = tls.VersionTLS10
	case 0x0302: // TLS 1.1
		minVersion = tls.VersionTLS11
		maxVersion = tls.VersionTLS11
	case 0x0303: // TLS 1.2
		minVersion = tls.VersionTLS12
		maxVersion = tls.VersionTLS12
	case 0x0304: // TLS 1.3
		minVersion = tls.VersionTLS13
		maxVersion = tls.VersionTLS13
	default:
		return false, 0, 0
	}

	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CipherSuites:       []uint16{cipherSuite},
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, config)
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		return false, 0, 0
	}

	// Check if handshake succeeded and get negotiated values
	state := tlsConn.ConnectionState()
	if state.CipherSuite == cipherSuite {
		return true, state.Version, state.CipherSuite
	}

	return false, 0, 0
}

// readAllTLSData reads all available TLS data from the connection
func readAllTLSData(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var allData []byte
	buffer := make([]byte, 4096)

	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			allData = append(allData, buffer[:n]...)
		}
		if err != nil {
			// Check if it's a timeout or EOF (which is normal after reading all data)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			if err.Error() == "EOF" || strings.Contains(err.Error(), "closed") {
				break
			}
			// For other errors, return what we have
			if len(allData) > 0 {
				return allData, nil
			}
			return nil, err
		}
		// Try to read more if we got a full buffer
		if n < len(buffer) {
			break
		}
	}

	return allData, nil
}

// filterSupportedCipherSuites filters cipher suites to only those supported by Go's TLS library
func filterSupportedCipherSuites(suites []uint16) []uint16 {
	// Get all supported cipher suites from Go
	allSupported := tls.CipherSuites()
	supportedMap := make(map[uint16]bool)
	for _, cs := range allSupported {
		supportedMap[cs.ID] = true
	}

	// TLS 1.3 cipher suites (these are standard and should be in CipherSuites() in modern Go)
	// But we'll also check manually for common TLS 1.3 suites
	tls13Suites := []uint16{0x1301, 0x1302, 0x1303} // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
	for _, suite := range tls13Suites {
		supportedMap[suite] = true
	}

	// Filter the input suites
	var filtered []uint16
	for _, suite := range suites {
		if supportedMap[suite] {
			filtered = append(filtered, suite)
		}
	}

	return filtered
}

// sendClientHelloWithAllSuites sends a Client Hello with all cipher suites and checks for Server Hello with certificate
func sendClientHelloWithAllSuites(host, port string, tlsVersion uint16, suites []uint16) (bool, uint16, uint16) {
	// SSLv3: send raw Client Hello (Go's crypto/tls does not support SSLv3)
	if tlsVersion == 0x0300 {
		return sendRawClientHelloSSLv3(host, port, 0x0300, suites)
	}
	// SSLv2: send raw Client Hello (Go's crypto/tls does not support SSLv2)
	if tlsVersion == 0x0200 {
		return sendRawClientHelloSSLv2(host, port, suites)
	}

	addr := net.JoinHostPort(host, port)

	// Filter to only supported cipher suites (Go's TLS library will reject unsupported ones)
	filteredSuites := filterSupportedCipherSuites(suites)
	// If no supported suites, try with all suites anyway - Go will filter internally
	if len(filteredSuites) == 0 {
		filteredSuites = suites
	}

	// Map TLS version constants
	var minVersion, maxVersion uint16
	switch tlsVersion {
	case 0x0301: // TLS 1.0
		minVersion = tls.VersionTLS10
		maxVersion = tls.VersionTLS10
	case 0x0302: // TLS 1.1
		minVersion = tls.VersionTLS11
		maxVersion = tls.VersionTLS11
	case 0x0303: // TLS 1.2
		minVersion = tls.VersionTLS12
		maxVersion = tls.VersionTLS12
	case 0x0304: // TLS 1.3
		minVersion = tls.VersionTLS13
		maxVersion = tls.VersionTLS13
	default:
		return false, 0, 0
	}

	// Try to create config - if it fails due to unsupported suites, try with filtered suites
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		CipherSuites:       filteredSuites,
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, 0, 0
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, config)
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		return false, 0, 0
	}

	// Handshake succeeded - get negotiated values
	state := tlsConn.ConnectionState()
	if state.CipherSuite != 0 {
		return true, state.Version, state.CipherSuite
	}

	return false, 0, 0
}

// testTLSVersion tests all cipher suites for a specific TLS version
func testTLSVersion(host, port string, tlsVersion uint16, versionName string) {
	suites := getCipherSuitesByVersion(tlsVersion)

	fmt.Printf("\n=== Testing %s (0x%04X) ===\n", versionName, tlsVersion)

	// First, send Client Hello with all cipher suites to check if version is supported
	hasCert, serverVersion, _ := sendClientHelloWithAllSuites(host, port, tlsVersion, suites)

	if !hasCert {
		// Even if initial test failed, try individual suites - some might work
		fmt.Printf("Initial handshake test failed for %s, but testing individual cipher suites anyway...\n\n", versionName)
	} else {
		fmt.Printf("Server supports %s (negotiated version: 0x%04X), testing individual cipher suites...\n\n", versionName, serverVersion)
	}

	// Now test each cipher suite individually
	certificateFound := false
	for _, suite := range suites {
		hasCert, _, chosenCipher := testCipherSuiteForVersion(host, port, tlsVersion, suite)

		if hasCert && chosenCipher == suite {
			certificateFound = true
			details, exists := cipherSuites[suite]
			if !exists {
				details = CipherDetails{Name: fmt.Sprintf("Unknown (0x%04X)", suite)}
			}

			fmt.Printf("TLS cipher detected:  0x%04X  %s\n", suite, details.Name)
			fmt.Printf("- TLS version : %s (0x%04X)\n", versionName, serverVersion)

			// Colourise security level
			sec := details.Security
			var coloured string
			switch sec {
			case "Recommended":
				coloured = "\033[32m" + sec + "\033[0m"
			case "Secure":
				coloured = "\033[92m" + sec + "\033[0m"
			case "Weak":
				coloured = "\033[33m" + sec + "\033[0m"
			case "Insecure":
				coloured = "\033[31m" + sec + "\033[0m"
			default:
				coloured = sec
			}
			fmt.Printf("- Security    : %s\n", coloured)
			if details.KeyExchange != "" {
				fmt.Printf("- Key Exchange: %s\n", details.KeyExchange)
			}
			if details.Auth != "" {
				fmt.Printf("- Auth        : %s\n", details.Auth)
			}
			if details.Encryption != "" {
				fmt.Printf("- Encryption  : %s\n", details.Encryption)
			}
			if details.Hash != "" {
				fmt.Printf("- Hash        : %s\n", details.Hash)
			}
			fmt.Println()
		}

		// Small delay to avoid overwhelming the server
		time.Sleep(50 * time.Millisecond)
	}

	if !certificateFound {
		fmt.Printf("No individual cipher suites found for %s\n", versionName)
	}
}

func TlsTest(host, port string) {
	if port == "" {
		port = "443"
	}

	// pretty URL exactly as you want
	URL := host
	if port == "443" && !strings.HasPrefix(host, "https://") {
		URL = "https://" + host
	} else if port != "443" {
		URL = net.JoinHostPort(host, port)
	}

	fmt.Printf("Testing %s  …\n", URL)

	// Test SSLv2
	testTLSVersion(host, port, 0x0200, "SSLv2")

	// Test SSLv3
	testTLSVersion(host, port, 0x0300, "SSLv3")

	// Test TLS 1.0
	testTLSVersion(host, port, 0x0301, "TLS 1.0")

	// Test TLS 1.1
	testTLSVersion(host, port, 0x0302, "TLS 1.1")

	// Test TLS 1.2
	testTLSVersion(host, port, 0x0303, "TLS 1.2")

	// Test TLS 1.3
	testTLSVersion(host, port, 0x0304, "TLS 1.3")
}

