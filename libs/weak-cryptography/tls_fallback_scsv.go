package weakcryptography

import (
	"fmt"
)

// TLSFallbackSCSV checks RFC 7507 TLS_FALLBACK_SCSV downgrade protection.
// Detection follows testssl.sh run_tls_fallback_scsv.
func TLSFallbackSCSV(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	fmt.Println("TLS_FALLBACK_SCSV (RFC 7507)")

	tls13 := probeTLS13Supported(host, portForConn)
	if tls13 && !probeProtocolSupported(host, portForConn, tlsVersion12) &&
		!probeProtocolSupported(host, portForConn, tlsVersion11) &&
		!probeProtocolSupported(host, portForConn, tlsVersion10) {
		fmt.Println("  OK - no fallback possible, TLS 1.3 is the only protocol")
		return
	}

	highName, highVer, ok := highestSupportedProtocol(host, portForConn)
	if !ok {
		if tls13 {
			fmt.Println("  OK - no fallback possible, TLS 1.3 is the only protocol")
			return
		}
		fmt.Println("  WARN - test failed (couldn't connect)")
		return
	}
	if highVer == 0x0300 {
		fmt.Println("  VULNERABLE - no fallback possible, SSLv3 is the only protocol")
		return
	}
	if highVer == tlsVersion13 {
		fmt.Println("  OK - no fallback possible, TLS 1.3 is the only protocol")
		return
	}

	lowName, lowVer, hasLower := lowerSupportedProtocol(host, portForConn, highVer)
	if !hasLower {
		fmt.Printf("  OK - no fallback possible, no protocol below %s offered\n", highName)
		return
	}

	status, _ := probeFallbackSCSV(host, portForConn, highVer, lowVer)
	switch status {
	case "supported":
		fmt.Println("  OK - downgrade attack prevention supported")
	case "probably_ok":
		fmt.Println("  OK - probably OK (handshake failure instead of inappropriate fallback)")
	case "not_supported":
		fmt.Printf("  VULNERABLE - downgrade attack prevention NOT supported (fallback %s -> %s)\n", highName, lowName)
		fmt.Println("  Server accepted TLS_FALLBACK_SCSV probe without rejecting downgrade.")
	case "medium":
		fmt.Println("  WARN - unexpected handshake failure instead of inappropriate fallback")
	default:
		fmt.Println("  WARN - check failed (couldn't connect or unexpected result)")
	}
}
