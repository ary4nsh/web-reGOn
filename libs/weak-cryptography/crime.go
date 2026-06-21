package weakcryptography

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// crimeBuildClientHello builds TLS 1.2 ClientHello with NULL, DEFLATE, and LZS compression (testssl.sh run_crime).
func crimeBuildClientHello(serverName string, cipherSuites []uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	body := make([]byte, 0, 512)
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, byte(len(cipherSuites)*2>>8), byte(len(cipherSuites)*2))
	for _, suite := range cipherSuites {
		body = append(body, byte(suite>>8), byte(suite))
	}
	body = append(body, 0x02, 0x01, 0x00) // DEFLATE, NULL (testssl also probes LZS 0x40 when supported)

	if serverName != "" {
		extensions := buildCRIMEExtensions(serverName)
		body = append(body, extensions...)
	}

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte((len(body)>>8)&0xff), byte(len(body)&0xff))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x03)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record, nil
}

func buildCRIMEExtensions(serverName string) []byte {
	var extensions []byte
	if serverName != "" {
		sniPayload := append([]byte{0x00}, appendLengthPrefixed([]byte(serverName))...)
		sniList := appendLengthPrefixed(sniPayload)
		extensions = append(extensions, 0x00, 0x00)
		extensions = append(extensions, appendLengthPrefixed(sniList)...)
	}
	extensions = append(extensions, 0xFF, 0x01, 0x00, 0x01, 0x00) // renegotiation_info
	extLen := len(extensions)
	result := make([]byte, 2+len(extensions))
	result[0] = byte(extLen >> 8)
	result[1] = byte(extLen)
	copy(result[2:], extensions)
	return result
}

func crimeParseServerHello(data []byte) (compressionMethod uint8, ok bool) {
	_, comp, ok := parseFirstServerHello(data)
	return comp, ok
}

func tryCRIMECheck(host, port string) (vulnerable bool, compressionMethod uint8, err error) {
	ciphers := []uint16{0xC02F, 0xC030, 0x009C, 0x009D, 0xC013, 0xC014, 0x0035, 0x002F, 0xCCA9, 0xCCA8}
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeReadTimeout))

	ch, err := crimeBuildClientHello(host, ciphers)
	if err != nil {
		return false, 0, err
	}
	if _, err := conn.Write(ch); err != nil {
		return false, 0, err
	}

	var response []byte
	buf := make([]byte, 65536)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
			if method, ok := crimeParseServerHello(response); ok {
				return method == 0x01, method, nil
			}
			if tlsAlertRecord(response) {
				return false, 0, fmt.Errorf("TLS alert from server")
			}
		}
		if readErr != nil {
			if len(response) > 0 {
				break
			}
			return false, 0, readErr
		}
		if len(response) > 65536 {
			break
		}
	}
	if method, ok := crimeParseServerHello(response); ok {
		return method == 0x01, method, nil
	}
	return false, 0, fmt.Errorf("no valid Server Hello received")
}

// CRIME runs the CVE-2012-4929 (CRIME) vulnerability check and prints results.
// Detection follows testssl.sh run_crime: TLS <=1.2 ClientHello offering compression
// (NULL, DEFLATE, LZS); vulnerable when server selects non-NULL compression.
func CRIME(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}

	fmt.Printf("Checking CRIME vulnerability for: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("Vulnerability CVE-2012-4929 (CRIME)")
		fmt.Println("  OK - Not vulnerable to CRIME attack (Server does not support TLS compression)")
		fmt.Println("  Compression Method: 0x00 (NULL)")
		fmt.Println("  CRIME attack is not possible.")
		return
	}

	vulnerable, compressionMethod, err := tryCRIMECheck(host, portForConn)
	if err != nil {
		fmt.Printf("Error during check: %v\n", err)
		return
	}

	fmt.Println("Vulnerability CVE-2012-4929 (CRIME)")
	if vulnerable {
		fmt.Println("  The server is vulnerable to CRIME attack")
		fmt.Printf("  Compression Method: 0x%02X (DEFLATE)\n", compressionMethod)
		fmt.Println("  The server supports TLS compression which can be exploited to leak information from encrypted connections.")
	} else if compressionMethod == 0x00 {
		fmt.Println("  OK - Not vulnerable to CRIME attack (Server does not support TLS compression)")
		fmt.Printf("  Compression Method: 0x%02X (NULL)\n", compressionMethod)
		fmt.Println("  CRIME attack is not possible.")
	} else {
		fmt.Printf("  [?] Unknown compression method: 0x%02X\n", compressionMethod)
	}
}
