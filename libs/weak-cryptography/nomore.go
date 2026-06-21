package weakcryptography

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// RC4 cipher suites (TLS)
var rc4TLSCipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
	{0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
	{0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA"},
	{0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
	{0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"},
	{0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
	{0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"},
	{0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
	{0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA"},
	{0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"},
	{0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"},
	{0x0024, "TLS_KRB5_WITH_RC4_128_MD5"},
	{0x0020, "TLS_KRB5_WITH_RC4_128_SHA"},
	{0x008A, "TLS_PSK_WITH_RC4_128_SHA"},
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
	{0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"},
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
}

// RC4 cipher suites (SSLv3)
var rc4SSLv3CipherSuites = []struct {
	ID   uint16
	Name string
}{
	{0x0066, "DHE-DSS-RC4-SHA"},
	{0x0065, "EXP1024-DHE-DSS-RC4-SHA"},
	{0x0064, "EXP1024-RC4-SHA"},
	{0x0060, "EXP1024-RC4-MD5"},
}

// rc4TLSList returns TLS RC4 cipher IDs (testssl.sh run_rc4 coverage).
func rc4TLSList() []uint16 {
	ids := make([]uint16, 0, len(rc4TLSCipherSuites))
	for _, c := range rc4TLSCipherSuites {
		ids = append(ids, c.ID)
	}
	return ids
}

// NoMore runs the RC4 cipher check and prints results.
// Detection follows testssl.sh run_rc4: probe RC4 suites on SSLv2, SSLv3, TLS 1.0–1.2.
func NoMore(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("RC4 (No More) - Cipher suites containing RC4 encryption")
		fmt.Println("  OK - No RC4 cipher suites supported")
		fmt.Println("  Supported RC4 cipher(s):")
		fmt.Println("    None")
		return
	}

	var supportedRC4 []string
	rc4List := rc4TLSList()
	rc4Set := cipherSet(rc4List)

	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		challenge = [16]byte{}
	}
	_, _, ssl2Ciphers, ssl2Ok := doSetup(host, portForConn, challenge)
	if ssl2Ok {
		for _, name := range ssl2Ciphers {
			if strings.Contains(name, "RC4") {
				supportedRC4 = append(supportedRC4, "[SSLv2] "+name)
				break
			}
		}
	}

	ssl3IDs := make([]uint16, 0, len(rc4SSLv3CipherSuites))
	for _, c := range rc4SSLv3CipherSuites {
		ssl3IDs = append(ssl3IDs, c.ID)
	}
	if chosen, ok := probeSSL3Batch(host, portForConn, ssl3IDs); ok && rc4Set[chosen] {
		supportedRC4 = append(supportedRC4, "[SSLv3] "+cipherName(chosen))
	} else if chosen, ok := probeSSL3Batch(host, portForConn, ssl3IDs); ok {
		for _, c := range rc4SSLv3CipherSuites {
			if c.ID == chosen {
				supportedRC4 = append(supportedRC4, "[SSLv3] "+c.Name)
				break
			}
		}
	}

	for _, ver := range []uint16{tlsVersion10, tlsVersion11, tlsVersion12} {
		if chosen, ok := probeAnyCipherFromList(host, portForConn, ver, rc4List, host); ok && rc4Set[chosen] {
			supportedRC4 = append(supportedRC4, "[TLS] "+cipherName(chosen))
			break
		}
	}

	fmt.Println("RC4 (No More) - Cipher suites containing RC4 encryption")
	if len(supportedRC4) > 0 {
		fmt.Println("  VULNERABLE - server supports RC4 cipher suites")
		fmt.Println("  Supported RC4 cipher(s):")
		for _, name := range supportedRC4 {
			fmt.Printf("    %s\n", name)
		}
	} else {
		fmt.Println("  OK - No RC4 cipher suites supported")
		fmt.Println("  Supported RC4 cipher(s):")
		fmt.Println("    None")
	}
}
