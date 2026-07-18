package inputvalidation

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func startVulnServer(t *testing.T) *http.Server {
	t.Helper()
	body, err := os.ReadFile("../../testdata/vuln-xss.html")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Addr: "127.0.0.1:18082"}
	mux := http.NewServeMux()
	mux.HandleFunc("/vuln-xss.html", func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	srv.Handler = mux
	go srv.ListenAndServe()
	time.Sleep(200 * time.Millisecond)
	return srv
}

func TestInjectTargetsNamedXSSPayload(t *testing.T) {
	targets, err := injectTargets("http://localhost:8000/innerhtml.html", `?user=<img src=x onerror=alert(1)>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Payload != `<img src=x onerror=alert(1)>` {
		t.Fatalf("payload = %q", targets[0].Payload)
	}
	if strings.Contains(targets[0].URL, "+") {
		t.Fatalf("URL should use %%20 not +: %s", targets[0].URL)
	}
	if !strings.Contains(targets[0].URL, "user=") {
		t.Fatalf("missing user param: %s", targets[0].URL)
	}
}

func TestScannerReflectiveVuln(t *testing.T) {
	srv := startVulnServer(t)
	defer srv.Close()

	raw := "http://127.0.0.1:18082/vuln-xss.html?q=test"
	payload := "javascript:alert(1)"
	sc := newScanner(15*time.Second, true, true)
	results, err := sc.Scan(raw, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if !r.Executed {
		t.Fatalf("expected vulnerable, got reflected=%v executed=%v url=%s", r.Reflected, r.Executed, r.URL)
	}
}

func TestScannerReflectiveSafe(t *testing.T) {
	srv := startVulnServer(t)
	defer srv.Close()

	raw := "http://127.0.0.1:18082/vuln-xss.html?q=hello"
	payload := "not-a-script"
	sc := newScanner(15*time.Second, false, true)
	results, err := sc.Scan(raw, payload)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Executed {
		t.Fatal("expected safe")
	}
}

func TestLaunchAndNavigate(t *testing.T) {
	cp, err := launchChrome()
	if err != nil {
		t.Fatal(err)
	}
	defer cp.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	page, err := cp.newPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer page.close(ctx, cp)
	_, err = page.call(ctx, "Page.navigate", map[string]any{"url": "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ok")
}
