package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HttpOptions performs an HTTP OPTIONS request based on your original implementation
func HttpOptions(URL string) {
	// Ensure the target has a protocol scheme
	if !strings.HasPrefix(URL, "http://") && !strings.HasPrefix(URL, "https://") {
		URL = "http://" + URL
	}
	// Create HTTP client
	client := &http.Client{}
	// Create OPTIONS request
	req, err := http.NewRequest("OPTIONS", URL, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()
	// Print HTTP status line
	fmt.Printf("%s %d %s\n", resp.Proto, resp.StatusCode, resp.Status[4:])
	// If status is 200, check for Allow header
	if resp.StatusCode == 200 {
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			fmt.Printf("Allow: %s\n", allowHeader)
		} else {
			fmt.Println("No Allow header found in response")
		}
	}
}

// HttpOptionsWithPort performs an HTTP OPTIONS request with a specified port
func HttpOptionsWithPort(rawURL, port string) {
	// ---------- sanitise inputs ---------------------------------------------
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Printf("invalid port: %v\n", err)
		return
	}

	var schema string
	var host string

	// 1. respect explicit scheme
	switch {
	case strings.HasPrefix(rawURL, "https://"):
		schema, host = "https", strings.TrimPrefix(rawURL, "https://")
	case strings.HasPrefix(rawURL, "http://"):
		schema, host = "http", strings.TrimPrefix(rawURL, "http://")
	default:
		host = rawURL
		// 2. guess from port
		switch port {
		case "80", "8080", "8008":
			schema = "http"
		default:
			schema = "https"
		}
	}

	// 3. strip existing port / path
	if idx := strings.LastIndex(host, ":"); idx != -1 &&
		!strings.Contains(host[idx:], "/") &&
		!strings.Contains(host[idx:], "]") {
		host = host[:idx]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	addr := net.JoinHostPort(host, port)
	target := fmt.Sprintf("%s://%s", schema, addr)

	// ---------- build HTTP client ------------------------------------------
	var client *http.Client

	if schema == "https" {
		// permissive TLS config for legacy boxes
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionSSL30,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}

		tr := &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				// single TCP + TLS handshake
				plain, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(plain, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					plain.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}
		client = &http.Client{Transport: tr, Timeout: 10 * time.Second}
	} else {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	// ---------- send OPTIONS request ---------------------------------------
	req, err := http.NewRequest("OPTIONS", target, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "connection reset"):
			fmt.Printf("Connection reset – port %s may expect TLS or be closed\n", port)
		case strings.Contains(err.Error(), "connection refused"):
			fmt.Printf("Connection refused – nothing listening on %s\n", port)
		case strings.Contains(err.Error(), "timeout"):
			fmt.Printf("Timeout – port %s may be filtered\n", port)
		default:
			fmt.Printf("Network error: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()

	fmt.Printf("%s %d %s\n", resp.Proto, resp.StatusCode, resp.Status[4:])
	if allow := resp.Header.Get("Allow"); allow != "" {
		fmt.Printf("Allow: %s\n", allow)
	}
}

// options_isTLS returns true if the port speaks TLS.
func options_isTLS(addr string) bool {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return false
		conn.Close()
		}
	return true
}
