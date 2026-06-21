package weakcryptography

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	renegoConnectTimeout  = 10 * time.Second
	renegoHandshakeTimeout = 15 * time.Second
	renegoExtInfo         = 0xFF01
	sslRenegAttempts      = 10
)

// InsecureRenegotiation runs RFC 5746 secure renegotiation and CVE-2011-1473
// client-initiated renegotiation checks (logic from testssl.sh run_renego).
func InsecureRenegotiation(urlStr, port string) {
	displayURL, host, portForConn, err := normalizeTarget(urlStr, port)
	if err != nil {
		fmt.Printf("Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("Target: %s (host=%s port=%s)\n", displayURL, host, portForConn)

	fmt.Println("Insecure Renegotiation (RFC 5746 / CVE-2011-1473)")

	if isTLS13OnlyServer(host, portForConn) {
		fmt.Println("  Secure Renegotiation (RFC 5746):")
		fmt.Println("    OK - not vulnerable (TLS 1.3 only, no renegotiation)")
		fmt.Println("  Client-Initiated Renegotiation (CVE-2011-1473):")
		fmt.Println("    OK - not vulnerable (TLS 1.3 only, no renegotiation)")
		return
	}

	supported, handshakeOK, err := checkSecureRenegotiation(host, portForConn)
	fmt.Println("  Secure Renegotiation (RFC 5746):")
	switch {
	case err != nil:
		fmt.Printf("    Error during check: %v\n", err)
	case !handshakeOK:
		fmt.Println("    Error during check: TLS handshake did not succeed")
	case supported:
		fmt.Println("    OK - Secure Renegotiation supported")
	default:
		fmt.Println("    VULNERABLE - Secure Renegotiation not supported (RFC 5746)")
		fmt.Println("    Server is vulnerable to insecure renegotiation (CVE-2009-3555)")
	}

	status, detail := checkClientInitiatedRenegotiation(host, portForConn)
	fmt.Println("  Client-Initiated Renegotiation (CVE-2011-1473):")
	switch status {
	case "vulnerable":
		fmt.Println("    VULNERABLE - Client-initiated renegotiation accepted (DoS threat)")
		if detail != "" {
			fmt.Printf("    %s\n", detail)
		}
	case "ok":
		fmt.Println("    OK - Not vulnerable to client-initiated renegotiation")
		if detail != "" {
			fmt.Printf("    %s\n", detail)
		}
	default:
		fmt.Println("    Error during check: " + detail)
	}
}

func buildRenegotiationProbeClientHello(serverName string) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	ciphers := []uint16{
		0xC02F, 0xC030, 0x009C, 0x009D,
		0xC013, 0xC014, 0x0035, 0x002F,
		0xCCA9, 0xCCA8,
	}

	body := make([]byte, 0, 512)
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00)

	var ext []byte
	if serverName != "" {
		sniPayload := append([]byte{0x00}, appendLengthPrefixed([]byte(serverName))...)
		sniList := appendLengthPrefixed(sniPayload)
		ext = append(ext, 0x00, 0x00)
		ext = append(ext, appendLengthPrefixed(sniList)...)
	}
	ext = append(ext, 0xFF, 0x01, 0x00, 0x01, 0x00)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	return wrapClientHelloRecord(body, 0x0303), nil
}

func wrapClientHelloRecord(body []byte, recordVersion uint16) []byte {
	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte((len(body)>>8)&0xff), byte(len(body)&0xff))
	handshake = append(handshake, body...)

	rec := make([]byte, 0, 5+len(handshake))
	rec = append(rec, 0x16, byte(recordVersion>>8), byte(recordVersion&0xff))
	rec = append(rec, byte(len(handshake)>>8), byte(len(handshake)))
	rec = append(rec, handshake...)
	return rec
}

func checkSecureRenegotiation(host, port string) (supported, handshakeOK bool, err error) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, renegoConnectTimeout)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(renegoHandshakeTimeout))

	ch, err := buildRenegotiationProbeClientHello(host)
	if err != nil {
		return false, false, err
	}
	if _, err := conn.Write(ch); err != nil {
		return false, false, err
	}

	data, err := readRenegotiationResponse(conn, 16384)
	if err != nil {
		return false, false, err
	}
	if tlsAlertRecord(data) {
		return false, false, nil
	}

	hasReneg, ok := serverHelloHasRenegotiationInfo(data)
	if !ok {
		return false, false, nil
	}
	return hasReneg, true, nil
}

func readRenegotiationResponse(conn net.Conn, limit int) ([]byte, error) {
	buf := make([]byte, 4096)
	var out []byte
	for len(out) < limit {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			if _, ok := serverHelloHasRenegotiationInfo(out); ok {
				break
			}
			if tlsAlertRecord(out) {
				break
			}
		}
		if err != nil {
			if len(out) > 0 {
				break
			}
			return nil, err
		}
	}
	return out, nil
}

func serverHelloHasRenegotiationInfo(data []byte) (hasRenegInfo, ok bool) {
	for i := 0; i+5 <= len(data); {
		recType := data[i]
		length := int(data[i+3])<<8 | int(data[i+4])
		if i+5+length > len(data) {
			return false, false
		}
		payload := data[i+5 : i+5+length]
		if recType == 0x16 {
			pos := 0
			for pos+4 <= len(payload) {
				msgType := payload[pos]
				msgLen := int(payload[pos+1])<<16 | int(payload[pos+2])<<8 | int(payload[pos+3])
				if pos+4+msgLen > len(payload) {
					break
				}
				msg := payload[pos+4 : pos+4+msgLen]
				if msgType == 0x02 {
					has, parsed := parseServerHelloRenegotiationInfo(msg)
					return has, parsed
				}
				pos += 4 + msgLen
			}
		}
		i += 5 + length
	}
	return false, false
}

func parseServerHelloRenegotiationInfo(msg []byte) (hasRenegInfo, ok bool) {
	if len(msg) < 2+32+1+2+1 {
		return false, false
	}
	pos := 34
	sidLen := int(msg[pos])
	pos += 1 + sidLen + 2 + 1 // session id, cipher, compression
	if pos+2 > len(msg) {
		return false, true // no extensions
	}
	extLen := int(msg[pos])<<8 | int(msg[pos+1])
	pos += 2
	if extLen == 0 {
		return false, true
	}
	end := pos + extLen
	for pos+4 <= end && pos+4 <= len(msg) {
		extType := binary.BigEndian.Uint16(msg[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(msg[pos+2 : pos+4]))
		pos += 4
		if extType == renegoExtInfo {
			return true, true
		}
		pos += extDataLen
	}
	return false, true
}

func findOpenSSL() (string, error) {
	if path, err := exec.LookPath("openssl"); err == nil {
		return path, nil
	}
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "usr", "bin", "openssl.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "usr", "bin", "openssl.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "OpenSSL-Win64", "bin", "openssl.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "OpenSSL-Win32", "bin", "openssl.exe"),
	}
	if runtime.GOOS == "linux" {
		candidates = append(candidates, "/usr/bin/openssl", "/usr/local/bin/openssl")
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("openssl not found in PATH")
}

// checkClientInitiatedRenegotiation mirrors testssl.sh run_renego client renegotiation loop
// using openssl s_client when available.
func checkClientInitiatedRenegotiation(host, port string) (status, detail string) {
	opensslPath, err := findOpenSSL()
	if err != nil {
		return "error", "openssl not found (required for client-initiated renegotiation test)"
	}

	wait := 250 * time.Millisecond
	timeout := time.Duration(sslRenegAttempts*3+3) * time.Second

	args := []string{
		"s_client",
		"-connect", net.JoinHostPort(host, port),
		"-servername", host,
		"-no_tls1_3",
	}

	cmd := exec.Command(opensslPath, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "error", err.Error()
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return "error", err.Error()
	}

	go func() {
		defer stdin.Close()
		deadline := time.Now().Add(30 * wait)
		for time.Now().Before(deadline) {
			if strings.Contains(stdout.String(), "SSL-Session:") {
				break
			}
			time.Sleep(wait)
		}
		for i := 0; i <= sslRenegAttempts; i++ {
			time.Sleep(wait)
			_, _ = io.WriteString(stdin, "R\n")
			target := i + 1
			innerDeadline := time.Now().Add(120 * wait)
			for time.Now().Before(innerDeadline) {
				if strings.Count(stderr.String(), "RENEGOTIATING") >= target {
					break
				}
				if strings.Contains(stdout.String(), "closed") {
					return
				}
				time.Sleep(wait)
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	tmpResult := 0
	timedOut := false
	select {
	case err := <-waitCh:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
				tmpResult = 1
			}
		}
	case <-time.After(timeout):
		timedOut = true
		tmpResult = 2
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-waitCh
	}

	outStr := stdout.String()
	errStr := stderr.String()
	loopReneg := strings.Count(errStr, "RENEGOTIATING")

	if strings.Contains(outStr, "closed") {
		tmpResult = 1
	}
	if timedOut {
		tmpResult = 2
	}
	if tmpResult == 1 && loopReneg == 1 {
		tmpResult = 3
	}

	switch tmpResult {
	case 0:
		if loopReneg >= 2 {
			return "vulnerable", fmt.Sprintf("DoS threat (%d renegotiation attempts)", sslRenegAttempts)
		}
		return "ok", "Server rejected client-initiated renegotiation"
	case 1:
		return "ok", fmt.Sprintf("Mitigated (disconnect after %d/%d attempts)", loopReneg, sslRenegAttempts)
	case 2:
		return "ok", fmt.Sprintf("Likely mitigated (timed out after %s)", timeout)
	case 3:
		return "ok", "Server rejected renegotiation after initial attempt"
	default:
		return "error", fmt.Sprintf("unexpected result (exit=%d, reneg=%d)", tmpResult, loopReneg)
	}
}
