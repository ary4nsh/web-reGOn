package weakcryptography

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// SSLv2 message types
const (
	sslMsgError           = 0
	sslMsgClientHello     = 1
	sslMsgClientMasterKey = 2
	sslMsgServerHello     = 4
)

// SSLv2 cipher: 3-byte code, key length, encrypted key length (effective strength in bytes)
type ssl2Cipher struct {
	code                [3]byte
	name                string
	keyLength           int
	encryptedKeyLength  int
}

// Build general DROWN ciphers: 40 bits or less (encrypted_key_length <= 5), or single-DES (DES_64)
func generalDROWNCiphers() map[string]bool {
	out := make(map[string]bool)
	for _, c := range ssl2Ciphers {
		if c.encryptedKeyLength <= 5 || strings.Contains(c.name, "DES_64") {
			out[c.name] = true
		}
	}
	return out
}

// SSLv2 ciphers
var ssl2Ciphers = []ssl2Cipher{
	{[3]byte{0x01, 0x00, 0x80}, "SSL2_RC4_128_WITH_MD5", 16, 16},
	{[3]byte{0x02, 0x00, 0x80}, "SSL2_RC4_128_EXPORT40_WITH_MD5", 16, 5},
	{[3]byte{0x03, 0x00, 0x80}, "SSL2_RC2_128_CBC_WITH_MD5", 16, 16},
	{[3]byte{0x04, 0x00, 0x80}, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5", 16, 5},
	{[3]byte{0x05, 0x00, 0x80}, "SSL2_IDEA_128_CBC_WITH_MD5", 16, 16},
	{[3]byte{0x06, 0x00, 0x40}, "SSL2_DES_64_CBC_WITH_MD5", 8, 8},
	{[3]byte{0x07, 0x00, 0xc0}, "SSL2_DES_192_EDE3_CBC_WITH_MD5", 24, 24},
	{[3]byte{0x00, 0x00, 0x00}, "SSL2_NULL_WITH_MD5", 0, 0},
	{[3]byte{0x08, 0x00, 0x80}, "SSL2_RC4_64_WITH_MD5", 16, 8},
}

var ssl2CipherByCode map[[3]byte]*ssl2Cipher
var ssl2CipherByName map[string]*ssl2Cipher

func init() {
	ssl2CipherByCode = make(map[[3]byte]*ssl2Cipher)
	ssl2CipherByName = make(map[string]*ssl2Cipher)
	for i := range ssl2Ciphers {
		c := &ssl2Ciphers[i]
		ssl2CipherByCode[c.code] = c
		ssl2CipherByName[c.name] = c
	}
}

// normalizeTarget parses urlStr and optional port (e.g. from --port).
// Returns display URL and (host, port) for connection.
// - No port specified -> https:// prefix if none; default port 443.
// - Port 80 -> http:// prefix if none.
// - Other port -> http:// and :port (e.g. http://example.com:5026).
func normalizeTarget(urlStr, port string) (displayURL, host, portForConn string, err error) {
	raw := strings.TrimSpace(urlStr)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty URL")
	}
	var hostname string
	if !strings.Contains(raw, "://") {
		hostname, portForConn = splitHostPort(raw)
		if port != "" {
			portForConn = port
		}
		if portForConn == "" {
			portForConn = "443"
		}
	} else {
		u, parseErr := url.Parse(raw)
		if parseErr != nil {
			return "", "", "", parseErr
		}
		hostname = u.Hostname()
		if port != "" {
			portForConn = port
		} else {
			portForConn = u.Port()
			if portForConn == "" {
				if u.Scheme == "https" {
					portForConn = "443"
				} else {
					portForConn = "80"
				}
			}
		}
	}
	if hostname == "" {
		return "", "", "", fmt.Errorf("no host in URL")
	}
	switch portForConn {
	case "443", "":
		displayURL = "https://" + hostname
		if portForConn == "" {
			portForConn = "443"
		}
	case "80":
		displayURL = "http://" + hostname
	default:
		displayURL = "http://" + hostname + ":" + portForConn
	}
	return displayURL, hostname, portForConn, nil
}

func splitHostPort(s string) (host, port string) {
	if idx := strings.LastIndex(s, ":"); idx != -1 {
		host = s[:idx]
		port = s[idx+1:]
		if port != "" && isAllDigits(port) {
			return host, port
		}
	}
	return s, ""
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// --- SSLv2 record layer ---

func ssl2RecordWrite(payload []byte, padding int) []byte {
	length := len(payload)
	var hdr []byte
	if padding == 0 {
		// 2-byte header: length | 0x8000
		hdr = make([]byte, 2)
		binary.BigEndian.PutUint16(hdr, uint16(length)|0x8000)
	} else {
		hdr = make([]byte, 3)
		binary.BigEndian.PutUint16(hdr, uint16(length)&0x3FFF)
		hdr[2] = byte(padding)
	}
	return append(hdr, payload...)
}

func ssl2RecordRead(data []byte, start int) (msgType byte, body []byte, next int, ok bool) {
	if start+2 > len(data) {
		return 0, nil, start, false
	}
	lenWord := binary.BigEndian.Uint16(data[start:])
	start += 2
	msb := (lenWord & 0x8000) != 0
	var recLen int
	var pad byte
	if msb {
		recLen = int(lenWord & 0x7FFF)
	} else {
		if start+1 > len(data) {
			return 0, nil, start - 2, false
		}
		recLen = int(lenWord & 0x3FFF)
		pad = data[start]
		start++
	}
	if start+recLen > len(data) {
		return 0, nil, start, false
	}
	payload := data[start : start+recLen]
	start += recLen
	if len(payload) < 1 {
		return 0, nil, start, false
	}
	msgType = payload[0]
	bodyLen := recLen - 1 - int(pad)
	if bodyLen < 0 {
		bodyLen = 0
	}
	body = payload[1 : 1+bodyLen]
	return msgType, body, start, true
}

// Build SSLv2 client hello offering all ciphers. Challenge 16 bytes random.
func ssl2ClientHello(challenge [16]byte) []byte {
	cipherBytes := make([]byte, 0, 3*len(ssl2Ciphers))
	for _, c := range ssl2Ciphers {
		cipherBytes = append(cipherBytes, c.code[0], c.code[1], c.code[2])
	}
	// CLIENT_HELLO: type=1, version=0x0002, cipher_specs_len, session_id_len=0, challenge_len=16
	payload := make([]byte, 0, 1+2+2+2+2+len(cipherBytes)+16)
	payload = append(payload, sslMsgClientHello)
	payload = append(payload, 0x00, 0x02) // SSL 2.0
	payload = append(payload, byte(len(cipherBytes)>>8), byte(len(cipherBytes)))
	payload = append(payload, 0, 0) // session id length
	payload = append(payload, 0, 16) // challenge length
	payload = append(payload, cipherBytes...)
	payload = append(payload, challenge[:]...)
	return ssl2RecordWrite(payload, 0)
}

// Build SSLv2 client_master_key (dummy key for testing)
func ssl2ClientMasterKey(cipherCode [3]byte, clearKey, encryptedKey, keyArg []byte) []byte {
	payload := make([]byte, 0, 1+3+2+2+2+len(clearKey)+len(encryptedKey)+len(keyArg))
	payload = append(payload, sslMsgClientMasterKey)
	payload = append(payload, cipherCode[0], cipherCode[1], cipherCode[2])
	payload = append(payload, byte(len(clearKey)>>8), byte(len(clearKey)))
	payload = append(payload, byte(len(encryptedKey)>>8), byte(len(encryptedKey)))
	payload = append(payload, byte(len(keyArg)>>8), byte(len(keyArg)))
	payload = append(payload, clearKey...)
	payload = append(payload, encryptedKey...)
	payload = append(payload, keyArg...)
	return ssl2RecordWrite(payload, 0)
}

// Parse SERVER_HELLO body: SID_hit, cert_type, version, cert_len, ciphers_len, conn_id_len, cert, ciphers (3 each), conn_id
func parseServerHello(body []byte) (ciphers []string, ok bool) {
	if len(body) < 10 {
		return nil, false
	}
	_ = body[0]  // SID_hit
	_ = body[1]  // cert_type
	_ = body[2:4] // version
	certLen := int(binary.BigEndian.Uint16(body[4:6]))
	ciphersLen := int(binary.BigEndian.Uint16(body[6:8]))
	connIDLen := int(binary.BigEndian.Uint16(body[8:10]))
	pos := 10
	if pos+certLen+ciphersLen+connIDLen > len(body) {
		return nil, false
	}
	pos += certLen
	end := pos + ciphersLen
	for pos+3 <= end {
		var code [3]byte
		copy(code[:], body[pos:pos+3])
		pos += 3
		if c := ssl2CipherByCode[code]; c != nil {
			ciphers = append(ciphers, c.name)
		} else {
			ciphers = append(ciphers, fmt.Sprintf("0x%02x%02x%02x", code[0], code[1], code[2]))
		}
	}
	return ciphers, true
}

const dialTimeout = 10 * time.Second
const readTimeout = 5 * time.Second

func doSetup(host, port string, challenge [16]byte) (net.Conn, []byte, []string, bool) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, nil, nil, false
	}
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	hello := ssl2ClientHello(challenge)
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return nil, nil, nil, false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		conn.Close()
		return nil, nil, nil, false
	}
	buf = buf[:n]
	msgType, body, _, ok := ssl2RecordRead(buf, 0)
	if !ok || msgType != sslMsgServerHello {
		conn.Close()
		return nil, nil, nil, false
	}
	ciphers, ok := parseServerHello(body)
	if !ok {
		conn.Close()
		return nil, nil, nil, false
	}
	return conn, buf, ciphers, true
}

// tryForceCipher: send CLIENT_MASTER_KEY with dummy key; if server does not return ERROR, cipher was forced (CVE-2015-3197).
func tryForceCipher(host, port string, cipherName string) bool {
	var challenge [16]byte
	conn, _, _, ok := doSetup(host, port, challenge)
	if !ok || conn == nil {
		return false
	}
	// Try to force the requested cipher
	cipher := ssl2CipherByName[cipherName]
	if cipher == nil {
		conn.Close()
		return false
	}
	keyLen := cipher.keyLength
	encKeyLen := cipher.encryptedKeyLength
	clearLen := keyLen - encKeyLen
	if clearLen < 0 {
		clearLen = 0
	}
	clearKey := make([]byte, clearLen)
	encKey := make([]byte, encKeyLen)
	keyArg := []byte{}
	if strings.Contains(cipherName, "DES") || strings.Contains(cipherName, "RC2") || strings.Contains(cipherName, "IDEA") {
		keyArg = make([]byte, 8)
	}
	cmk := ssl2ClientMasterKey(cipher.code, clearKey, encKey, keyArg)
	if _, err := conn.Write(cmk); err != nil {
		conn.Close()
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	conn.Close()
	if n < 2 {
		return false
	}
	msgType, _, _, ok := ssl2RecordRead(buf, 0)
	if !ok {
		return false
	}
	// If server returns ERROR, it rejected the forced cipher
	return msgType != sslMsgError
}

// hasExtraClearBug: send CLIENT_MASTER_KEY with wrong (too long) clear key length; if accepted, CVE-2016-0703.
func hasExtraClearBug(host, port string, cipherName string) bool {
	var challenge [16]byte
	conn, _, ciphers, ok := doSetup(host, port, challenge)
	if !ok || conn == nil || len(ciphers) == 0 {
		return false
	}
	cipher := ssl2CipherByName[cipherName]
	if cipher == nil {
		conn.Close()
		return false
	}
	keyLen := cipher.keyLength
	encKeyLen := cipher.encryptedKeyLength
	// Wrong: clear_key one byte longer than intended (bug probe)
	clearLen := keyLen - encKeyLen + 1
	if clearLen < 0 {
		clearLen = 1
	}
	clearKey := make([]byte, clearLen)
	encKey := make([]byte, encKeyLen)
	keyArg := []byte{}
	if strings.Contains(cipherName, "DES") || strings.Contains(cipherName, "RC2") || strings.Contains(cipherName, "IDEA") {
		keyArg = make([]byte, 8)
	}
	cmk := ssl2ClientMasterKey(cipher.code, clearKey, encKey, keyArg)
	if _, err := conn.Write(cmk); err != nil {
		conn.Close()
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	conn.Close()
	if n < 2 {
		return false
	}
	msgType, _, _, ok := ssl2RecordRead(buf, 0)
	if !ok {
		return false
	}
	return msgType != sslMsgError
}

// DROWN runs the SSLv2 DROWN vulnerability check and prints results.
// urlStr is the target URL (e.g. from args[0]); port is optional (e.g. from --port).
// URL/port normalization is handled here: no port -> https/443; 80 -> http; other -> http://host:port.
func DROWN(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	// 1) Test SSLv2 support and get offered ciphers
	var challenge [16]byte
	conn, _, offeredList, ok := doSetup(host, portForConn, challenge)
	if !ok {
		fmt.Println("SSLv2: Not supported or connection failed.")
		return
	}
	if conn != nil {
		conn.Close()
	}

	offered := make(map[string]bool)
	for _, c := range offeredList {
		offered[c] = true
	}
	fmt.Println("SSLv2 supported. Offered ciphers:", offeredList)

	// 2) CVE-2015-3197: try to force disabled ciphers
	var forced []string
	for name := range ssl2CipherByName {
		if offered[name] {
			continue
		}
		if tryForceCipher(host, portForConn, name) {
			forced = append(forced, name)
			offered[name] = true
		}
	}
	if len(forced) > 0 {
		fmt.Println("CVE-2015-3197 (OpenSSL: SSLv2 doesn't block disabled ciphers): VULNERABLE")
		fmt.Println("  Forced ciphers:", forced)
	} else {
		fmt.Println("CVE-2015-3197: Not vulnerable")
	}

	// 3) CVE-2016-0703: extra clear key bug (Bleichenbacher oracle)
	cve0703Vuln := false
	for name := range offered {
		if hasExtraClearBug(host, portForConn, name) {
			cve0703Vuln = true
			break
		}
	}
	if cve0703Vuln {
		fmt.Println("CVE-2016-0703 (OpenSSL: Divide-and-conquer session key recovery in SSLv2): VULNERABLE")
	} else {
		fmt.Println("CVE-2016-0703: Not vulnerable")
	}

	// 4) CVE-2016-0800 (DROWN): weak ciphers or CVE-2016-0703
	generalDROWN := generalDROWNCiphers()
	hasWeak := false
	for name := range offered {
		if generalDROWN[name] {
			hasWeak = true
			break
		}
	}
	cve0800Vuln := hasWeak || cve0703Vuln
	if cve0800Vuln {
		fmt.Println("CVE-2016-0800 (DROWN - Cross-protocol attack on TLS using SSLv2): VULNERABLE")
	} else {
		fmt.Println("CVE-2016-0800 (DROWN): Not vulnerable")
	}
}
