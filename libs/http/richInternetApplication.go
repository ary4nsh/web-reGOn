package http

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	redColor   = "\033[31m"
	resetColor = "\033[0m"
)

// RichInternetApplication fetches both policy files and prints them only
// when the server returns HTTP 200.  Wild-card warnings are still issued
// to stderr whenever the pattern is detected.
func RichInternetApplication(host, port string) {
	fetch := func(path, label, wildPattern string) {
		url := fmt.Sprintf("http://%s:%s%s", host, port, path)
		resp, err := http.Get(url)
		if err != nil {
			// network-level errors: silently ignore
			return
		}
		defer resp.Body.Close()

		// silently ignore 404 (and any non-200)
		if resp.StatusCode != http.StatusOK {
			return
		}

		// print XML body + scan for wildcards
		tee := io.TeeReader(resp.Body, os.Stdout)
		scanner := bufio.NewScanner(tee)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), wildPattern) {
				fmt.Fprintf(os.Stderr,
					"\n[%sINSECURE%s] %s\n",
					redColor, resetColor, wildPattern)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] reading body: %v\n", label, err)
		}
	}

	fetch("/crossdomain.xml", "crossdomain", `domain="*"`)
	fetch("/clientaccesspolicy.xml", "clientaccesspolicy", `uri="*"`)
}
