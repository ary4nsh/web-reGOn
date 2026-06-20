package inputvalidation

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestDialogFiredVulnPage(t *testing.T) {
	htmlPath := "../../testdata/vuln-xss.html"
	body, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Skip("testdata not found:", err)
	}

	srv := &http.Server{Addr: "127.0.0.1:18081"}
	mux := http.NewServeMux()
	mux.HandleFunc("/vuln-xss.html", func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	srv.Handler = mux
	go srv.ListenAndServe()
	defer srv.Close()

	time.Sleep(200 * time.Millisecond)

	payload := `javascript:alert(1)`
	target := fmt.Sprintf("http://127.0.0.1:18081/vuln-xss.html?q=%s", payload)

	cp, err := launchChrome()
	if err != nil {
		t.Fatal("launch:", err)
	}
	defer cp.close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fired, err := cp.dialogFired(ctx, target)
	if err != nil {
		t.Fatal("dialogFired:", err)
	}
	if !fired {
		t.Fatal("expected alert dialog, got none")
	}
}
