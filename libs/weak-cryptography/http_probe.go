package weakcryptography

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

const httpProbeTimeout = 15 * time.Second

func fetchHTTPServerBanner(host, port, path string) (string, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	addr := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: probeConnectTimeout}, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(httpProbeTimeout))

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: web-reGOn\r\nConnection: close\r\nAccept: */*\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[len("Server:"):]), nil
		}
	}
	return "", nil
}

func breachDetectCompression(host, port, path, acceptEncoding, referer string) (compression string, stalled bool) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if referer == "" {
		referer = "https://google.com/"
	}
	if strings.Contains(strings.ToLower(host), "google") {
		referer = "https://yandex.ru/"
	}

	addr := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: probeConnectTimeout}, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return "", true
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(httpProbeTimeout))

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nReferer: %s\r\nConnection: Close\r\nAccept-Encoding: %s\r\nAccept: */*\r\n\r\n",
		path, host, referer, acceptEncoding)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", true
	}

	scanner := bufio.NewScanner(conn)
	foundHeaders := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			foundHeaders = true
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "content-encoding:") {
			val := strings.TrimSpace(line[len("Content-Encoding:"):])
			if val != "" {
				return strings.ToLower(val), false
			}
		}
	}
	if !foundHeaders {
		return "", true
	}
	return "no_compression", false
}
