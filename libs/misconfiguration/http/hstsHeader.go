package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net"
	"strconv"
	"strings"
	"time"
)

func HstsHeaderWithPort(rawURL, port string) {
	if port == "" { port = "443" }
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Printf("invalid port: %v\n", err)
		return
	}

	// clean host
	host := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if idx := strings.IndexAny(host, "/:"); idx != -1 {
		host = host[:idx]
	}
	addr := net.JoinHostPort(host, port)

	// decide http vs https automatically
	schema := "http"
	if isTLS(addr) { // 2-second probe
		schema = "https"
	}
	target := fmt.Sprintf("%s://%s", schema, addr)

	// request
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Timeout: 8 * time.Second, Transport: tr}

	resp, err := cli.Get(target)
	if err != nil {
		fmt.Printf("network error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("%s %s\n", resp.Proto, resp.Status)

	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		fmt.Printf("Strict-Transport-Security: %s\n", hsts)
	}
}

// isTLS returns true if the port speaks TLS.
func isTLS(addr string) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
