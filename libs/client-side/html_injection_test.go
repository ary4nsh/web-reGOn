package clientside

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestInjectTargetsRequiresQueryParam(t *testing.T) {
	_, err := injectTargets("http://example.com/page", `<b id="webregon">x</b>`)
	if err == nil {
		t.Fatal("expected error when URL has no query parameters and payload is raw HTML")
	}
}

func TestInjectTargetsNamedPayload(t *testing.T) {
	targets, err := injectTargets("http://localhost:8000/innerhtml.html", `?user=<h1>mamad<h1>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Payload != `<h1>mamad<h1>` {
		t.Fatalf("payload = %q, want HTML value only", targets[0].Payload)
	}
	u, err := url.Parse(targets[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("user"); got != `<h1>mamad<h1>` {
		t.Fatalf("user = %q, want injected HTML", got)
	}
}

func TestInjectTargetsPerParam(t *testing.T) {
	targets, err := injectTargets("http://example.com/page?a=1&b=2", `<i>x</i>`)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestInjectTargetsDecodesPreEncodedHTML(t *testing.T) {
	line := `?inject=%3Ciframe%20src%3D%22http://localhost:8001/toplevel.html%22%3E%3C/iframe%3E`
	targets, err := injectTargets("http://localhost:8000/iframe-redirect.html", line)
	if err != nil {
		t.Fatal(err)
	}
	want := `<iframe src="http://localhost:8001/toplevel.html"></iframe>`
	if targets[0].Payload != want {
		t.Fatalf("payload = %q, want %q", targets[0].Payload, want)
	}
	if strings.Contains(targets[0].URL, "%253C") {
		t.Fatalf("URL is double-encoded: %s", targets[0].URL)
	}
	u, err := url.Parse(targets[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("inject"); got != want {
		t.Fatalf("inject = %q, want %q", got, want)
	}
}

func TestEncodeQueryUsesPercent20(t *testing.T) {
	targets, err := injectTargets("http://localhost:8000/innerhtml.html", `?user=<img src=x onerror=alert(1)>`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(targets[0].URL, "+") {
		t.Fatalf("URL should not use + for spaces: %s", targets[0].URL)
	}
	if !strings.Contains(targets[0].URL, "%20") {
		t.Fatalf("URL should use %%20 for spaces: %s", targets[0].URL)
	}
}

func TestMetaRefreshDestination(t *testing.T) {
	payload := `<meta http-equiv="refresh" content="0;url=http://localhost:8000/redirect-target.html">`
	got := metaRefreshDestination(payload)
	want := "http://localhost:8000/redirect-target.html"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestURLIndicatesMetaRefresh(t *testing.T) {
	req := "http://localhost:8000/meta-refresh.html?inject=x"
	cur := "http://localhost:8000/redirect-target.html"
	dest := "http://localhost:8000/redirect-target.html"
	if !urlIndicatesMetaRefresh(req, cur, dest) {
		t.Fatal("expected redirect to be detected")
	}
	if urlIndicatesMetaRefresh(req, req, dest) {
		t.Fatal("same page should not count as meta refresh")
	}
}

func TestPayloadHasDangerousMetaHTTPEquiv(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{`<meta http-equiv="refresh" content="0;url=http://x">`, true},
		{`<meta http-equiv='set-cookie' content="a=b">`, true},
		{`<meta http-equiv=refresh content="5;url=/x">`, true},
		{`<meta http-equiv = "REFRESH" content="0;url=/x">`, true},
		{`<h1>hello</h1>`, false},
		{`<meta charset="utf-8">`, false},
		{`<meta http-equiv="content-type" content="text/html">`, false},
	}
	for _, tc := range cases {
		if got := payloadHasDangerousMetaHTTPEquiv(tc.payload); got != tc.want {
			t.Errorf("payloadHasDangerousMetaHTTPEquiv(%q) = %v, want %v", tc.payload, got, tc.want)
		}
	}
	vals := dangerousMetaHTTPEquivValues(`<meta http-equiv="refresh" content="0;url=x">`)
	if len(vals) != 1 || vals[0] != "refresh" {
		t.Fatalf("dangerousMetaHTTPEquivValues = %v, want [refresh]", vals)
	}
}

func TestReadPayloads(t *testing.T) {
	path := t.TempDir() + "/payloads.txt"
	if err := os.WriteFile(path, []byte("<b>test</b>\n\n<img src=x>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payloads, err := readPayloads(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}
}
