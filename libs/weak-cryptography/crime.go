package weakcryptography

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const crimeConnectTimeout = 10 * time.Second
const crimeHandshakeTimeout = 5 * time.Second

const tlsHandshakeTypeServerHello = 0x02

// tls12BuildClientHello builds a TLS 1.2 Client Hello with DEFLATE and NULL compression methods.
func tls12BuildClientHello(serverName string, cipherSuites []uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	// Build body: version(2) + random(32) + session_id_len(1) + cipher_suites(2+len) + compression_methods(2) + extensions
	body := make([]byte, 0, 512)
	
	// Version: TLS 1.2 (0x0303)
	body = append(body, 0x03, 0x03)
	
	// Random (32 bytes)
	body = append(body, random...)
	
	// Session ID Length: 0
	body = append(body, 0x00)
	
	// Cipher Suites
	cipherSuiteBytes := make([]byte, 2+len(cipherSuites)*2)
	cipherSuiteBytes[0] = byte(len(cipherSuites) * 2 >> 8)
	cipherSuiteBytes[1] = byte(len(cipherSuites) * 2)
	for i, suite := range cipherSuites {
		cipherSuiteBytes[2+i*2] = byte(suite >> 8)
		cipherSuiteBytes[2+i*2+1] = byte(suite)
	}
	body = append(body, cipherSuiteBytes...)
	
	// Compression Methods: length(1) + methods
	// Offer both DEFLATE (0x01) and NULL (0x00)
	body = append(body, 0x02) // length: 2 methods
	body = append(body, 0x01) // DEFLATE
	body = append(body, 0x00) // NULL
	
	// Extensions (SNI + Supported Versions)
	if serverName != "" {
		extensions := buildExtensions(serverName)
		body = append(body, extensions...)
	}

	// Handshake header: type(1) + length(3)
	handshakeLen := len(body)
	header := make([]byte, 4)
	header[0] = 0x01 // Client Hello
	header[1] = byte(handshakeLen >> 16)
	header[2] = byte(handshakeLen >> 8)
	header[3] = byte(handshakeLen)
	
	handshake := append(header, body...)

	// Record layer: type(1) version(2) length(2)
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record, nil
}

// buildExtensions builds SNI and Supported Versions extensions.
func buildExtensions(serverName string) []byte {
	var extensions []byte

	if serverName != "" {
		hostname := []byte(serverName)
		hostnameLen := len(hostname)

		// ServerName entry: name_type(1) + length(2) + hostname
		serverNameEntry := make([]byte, 1+2+hostnameLen)
		serverNameEntry[0] = 0x00 // host_name
		serverNameEntry[1] = byte(hostnameLen >> 8)
		serverNameEntry[2] = byte(hostnameLen)
		copy(serverNameEntry[3:], hostname)

		// ServerNameList: length(2) + entry
		serverNameListLen := len(serverNameEntry)
		serverNameList := make([]byte, 2+serverNameListLen)
		serverNameList[0] = byte(serverNameListLen >> 8)
		serverNameList[1] = byte(serverNameListLen)
		copy(serverNameList[2:], serverNameEntry)

		// SNI Extension: type(2) + length(2) + data
		sniExtLen := len(serverNameList)
		sniExtension := make([]byte, 4+len(serverNameList))
		sniExtension[0] = 0x00 // server_name
		sniExtension[1] = 0x00
		sniExtension[2] = byte(sniExtLen >> 8)
		sniExtension[3] = byte(sniExtLen)
		copy(sniExtension[4:], serverNameList)

		extensions = append(extensions, sniExtension...)
	}

	// Supported Versions (TLS 1.2)
	supportedVersions := []byte{
		0x00, 0x2b, // extension type
		0x00, 0x03, // length
		0x02,       // versions length
		0x03, 0x03, // TLS 1.2
	}
	extensions = append(extensions, supportedVersions...)

	// Extension list length prefix
	extLen := len(extensions)
	result := make([]byte, 2+len(extensions))
	result[0] = byte(extLen >> 8)
	result[1] = byte(extLen)
	copy(result[2:], extensions)

	return result
}

// tls12ParseServerHello parses the Server Hello from TLS 1.2 record data.
// Returns compression method (0x00=NULL, 0x01=DEFLATE) and true if parsing succeeded.
func tls12ParseServerHello(data []byte) (compressionMethod uint8, ok bool) {
	if len(data) < 5 {
		return 0, false
	}
	if data[0] != 0x16 {
		return 0, false
	}
	
	payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+payloadLen {
		return 0, false
	}
	
	payload := data[5 : 5+payloadLen]
	pos := 0
	
	// Parse handshake messages (Server Hello might be first, or there might be multiple)
	for pos < len(payload) {
		if pos+4 > len(payload) {
			break
		}
		
		msgType := payload[pos]
		msgLen := int(payload[pos+1])<<16 | int(payload[pos+2])<<8 | int(payload[pos+3])
		
		if msgType == tlsHandshakeTypeServerHello {
			serverHello := payload[pos+4 : pos+4+msgLen]
			if len(serverHello) < 35 {
				return 0, false
			}
			
			// Skip version(2) + random(32)
			idx := 34
			
			// Skip session ID
			sessionIDLen := int(serverHello[idx])
			idx += 1 + sessionIDLen
			
			if idx+2 > len(serverHello) {
				return 0, false
			}
			
			// Skip cipher suite(2)
			idx += 2
			
			if idx >= len(serverHello) {
				return 0, false
			}
			
			// Compression method is here
			return serverHello[idx], true
		}
		
		pos += 4 + msgLen
	}
	
	return 0, false
}

// allTLS12CipherSuites returns all TLS 1.2 cipher suite IDs.
func allTLS12CipherSuites() []uint16 {
	return []uint16{
		// TLS 1.3 (for compatibility)
		0x1301, 0x1302, 0x1303,
		
		// ECDHE with AES-GCM
		0xc02b, 0xc02c, 0xc02f, 0xc030,
		
		// ECDHE with ChaCha20
		0xcca9, 0xcca8, 0xccaa,
		
		// ECDHE with AES-CBC
		0xc023, 0xc024, 0xc027, 0xc028,
		
		// DHE with AES
		0x0067, 0x006b, 0x009e, 0x009f,
		
		// ECDHE with AES-CBC (legacy SHA)
		0xc009, 0xc00a, 0xc013, 0xc014,
		
		// DHE/RSA with AES-CBC
		0x0033, 0x0039, 0x002f, 0x0035,
		
		// RSA with AES-GCM
		0x009c, 0x009d,
		
		// Camellia
		0xc072, 0xc073, 0xc076, 0xc077,
		
		// ARIA
		0xc048, 0xc049, 0xc04c, 0xc04d,
		
		// SEED
		0xc096,
		
		// IDEA
		0x0007,
		
		// RC4 (legacy)
		0xc007, 0xc011, 0x0005, 0x0004,
		
		// DES
		0x0009,
		
		// Export
		0x0003, 0x0006, 0x0008, 0x0014, 0x0015,
		
		// Anonymous
		0x0018, 0x001b, 0x0034, 0x003a, 0x006c, 0x006d,
		
		// PSK
		0x008b, 0x008c, 0x008d, 0x008e, 0x008f, 0x0090,
		0x00a8, 0x00a9, 0x00aa, 0x00ab,
		0x00ae, 0x00af, 0x00b0, 0x00b1,
		
		// ECDHE_PSK
		0xc035, 0xc036, 0xc037, 0xc038, 0xc039, 0xc03a,
		
		// SRP
		0xc01a, 0xc01b, 0xc01c, 0xc01d, 0xc01e, 0xc01f,
		0xc020, 0xc021, 0xc022,
		
		// ECDH
		0xc001, 0xc002, 0xc003, 0xc004, 0xc005,
		0xc029, 0xc02a, 0xc02d, 0xc02e,
		
		// DH
		0x000d, 0x0010, 0x0015, 0x0016,
		0x0030, 0x0031, 0x0036, 0x0037,
		0x003e, 0x003f, 0x0068, 0x0069,
		
		// DSS
		0x0012, 0x0040, 0x006a,
		
		// GOST
		0x0080, 0x0081, 0x0082, 0x0083,
		
		// CCM
		0xc0ac, 0xc0ad, 0xc0ae, 0xc0af,
		0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3,
		0xc0a4, 0xc0a5, 0xc0a6, 0xc0a7,
		0xc0a8, 0xc0a9, 0xc0aa, 0xc0ab,
		
		// ChaCha20 (old draft)
		0xcc13, 0xcc14, 0xcc15,
		
		// RSA_PSK
		0x0092, 0x0093, 0x0094, 0x00ac, 0x00ad, 0x00b6, 0x00b7,
		
		// Additional ECDH
		0xc025, 0xc026, 0xc031, 0xc032, 0xc033, 0xc034,
		0xc074, 0xc075, 0xc078, 0xc079,
		
		// Additional Camellia
		0x0041, 0x0042, 0x0043, 0x0044, 0x0045,
		0x0084, 0x0085, 0x0086, 0x0087, 0x0088,
		0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be,
		0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4,
		0xc07a, 0xc07b, 0xc07c, 0xc07d, 0xc07e, 0xc07f,
		0xc080, 0xc081, 0xc082, 0xc083,
		
		// Additional SEED
		0x0096, 0x0097, 0x0098, 0x0099, 0x009a,
		
		// Additional ARIA
		0xc03e, 0xc03f, 0xc040, 0xc041, 0xc042, 0xc043,
		0xc044, 0xc045, 0xc046, 0xc047,
		0xc04e, 0xc04f, 0xc050, 0xc051,
		0xc052, 0xc053, 0xc054, 0xc055, 0xc056, 0xc057,
		0xc058, 0xc059, 0xc05a, 0xc05b,
		0xc05c, 0xc05d, 0xc05e, 0xc05f,
		0xc060, 0xc061, 0xc062, 0xc063,
		
		// NULL/anon
		0x0001, 0x0002, 0x003b, 0xc006, 0xc010,
	}
}

// tryCRIMECheck attempts to connect with TLS 1.2 offering DEFLATE compression.
// Returns true if server selects DEFLATE (vulnerable), false if NULL (safe) or error.
func tryCRIMECheck(host, port string) (vulnerable bool, compressionMethod uint8, err error) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, crimeConnectTimeout)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(crimeHandshakeTimeout))

	cipherSuites := allTLS12CipherSuites()
	clientHello, err := tls12BuildClientHello(host, cipherSuites)
	if err != nil {
		return false, 0, err
	}

	if _, err := conn.Write(clientHello); err != nil {
		return false, 0, err
	}

	// Read response with buffer for large responses
	var response []byte
	buf := make([]byte, 65536)
	
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if len(response) > 0 {
				break
			}
			return false, 0, err
		}
		if n == 0 {
			break
		}
		response = append(response, buf[:n]...)
		
		// Check if we have Server Hello
		if len(response) >= 43 {
			if method, ok := tls12ParseServerHello(response); ok {
				return method == 0x01, method, nil
			}
		}
		
		// Prevent infinite loop, limit total read
		if len(response) > 65536 {
			break
		}
	}

	// Try parsing what we have
	if method, ok := tls12ParseServerHello(response); ok {
		return method == 0x01, method, nil
	}

	return false, 0, fmt.Errorf("no valid Server Hello received")
}

// CRIME runs the CVE-2012-4929 (CRIME) vulnerability check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
func CRIME(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}

	fmt.Printf("Checking CRIME vulnerability for: %s (host=%s port=%s)\n", displayURL, host, portForConn)

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
	} else {
		if compressionMethod == 0x00 {
			fmt.Println("  OK - Not vulnerable to CRIME attack (Server does not support TLS compression)")
			fmt.Printf("  Compression Method: 0x%02X (NULL)\n", compressionMethod)
			fmt.Println("  CRIME attack is not possible.")
		} else {
			fmt.Printf("  [?] Unknown compression method: 0x%02X\n", compressionMethod)
		}
	}
}