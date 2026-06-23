package inputvalidation

import (
	"os"
	"testing"
)

func TestNormalizeHTTPVerbURL(t *testing.T) {
	tests := []struct {
		raw, port, want string
	}{
		{"example.com", "80", "http://example.com"},
		{"example.com", "443", "https://example.com"},
		{"example.com", "5050", "http://example.com:5050"},
		{"example.com/path", "5050", "http://example.com:5050/path"},
		{"http://example.com", "80", "http://example.com"},
		{"https://example.com", "443", "https://example.com"},
		{"example.com", "", "http://example.com"},
	}
	for _, tc := range tests {
		got, err := normalizeHTTPVerbURL(tc.raw, tc.port)
		if err != nil {
			t.Fatalf("normalizeHTTPVerbURL(%q, %q): %v", tc.raw, tc.port, err)
		}
		if got != tc.want {
			t.Errorf("normalizeHTTPVerbURL(%q, %q) = %q, want %q", tc.raw, tc.port, got, tc.want)
		}
	}
}

func TestResolveHTTPMethodsWordlistOnly(t *testing.T) {
	path := t.TempDir() + "/methods.txt"
	if err := os.WriteFile(path, []byte("GET\nPOST\nOPTIONS\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	methods, err := resolveHTTPMethods(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(methods))
	}
}

func TestResolveHTTPMethodsBuiltinWebDAV(t *testing.T) {
	without, err := resolveHTTPMethods("", false)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(without, "PROPFIND") {
		t.Fatal("PROPFIND should not be included without --webdav-methods")
	}

	with, err := resolveHTTPMethods("", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range webdavMethods {
		if !containsString(with, m) {
			t.Fatalf("expected %s when webdav enabled", m)
		}
	}
}

func TestMethodCategory(t *testing.T) {
	tests := map[string]string{
		"GET":       "http",
		"TRACE":     "http",
		"PROPFIND":  "webdav",
		"COPY":      "webdav",
		"BAMBOOZLE": "custom",
		"CHECKIN":   "custom",
	}
	for method, want := range tests {
		if got := methodCategory(method); got != want {
			t.Errorf("methodCategory(%q) = %q, want %q", method, got, want)
		}
	}
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
