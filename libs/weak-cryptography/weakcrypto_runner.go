package weakcryptography

import (
	"os"
	"strings"
)

// RunnerFlags selects which weak-cryptography checks to run.
type RunnerFlags struct {
	TestAll               bool
	AnonymousCiphers      bool
	Beast                 bool
	Drown                 bool
	Freak                 bool
	Lucky13               bool
	Nomore                bool
	NullCiphers           bool
	InsecureRenegotiation bool
	Breach                bool
	Crime                 bool
	CCSInjection          bool
	Heartbleed            bool
	Logjam                bool
	Poodle                bool
	Sweet32               bool
	Ticketbleed           bool
	TLSFallbackSCSV       bool
	Winshock              bool
}

type weakCryptoSpec struct {
	flagName string
	enabled  func(RunnerFlags) bool
	run      func(string, string)
}

// weakCryptoSpecs is the canonical order used by --test-all (matches README section order).
var weakCryptoSpecs = []weakCryptoSpec{
	{"anonymous-ciphers", func(f RunnerFlags) bool { return f.AnonymousCiphers }, AnonymousCiphers},
	{"beast", func(f RunnerFlags) bool { return f.Beast }, BEAST},
	{"drown", func(f RunnerFlags) bool { return f.Drown }, DROWN},
	{"freak", func(f RunnerFlags) bool { return f.Freak }, FREAK},
	{"lucky13", func(f RunnerFlags) bool { return f.Lucky13 }, Lucky13},
	{"nomore", func(f RunnerFlags) bool { return f.Nomore }, NoMore},
	{"null-ciphers", func(f RunnerFlags) bool { return f.NullCiphers }, NullCiphers},
	{"insecure-renegotiation", func(f RunnerFlags) bool { return f.InsecureRenegotiation }, InsecureRenegotiation},
	{"breach", func(f RunnerFlags) bool { return f.Breach }, BREACH},
	{"crime", func(f RunnerFlags) bool { return f.Crime }, CRIME},
	{"ccs-injection", func(f RunnerFlags) bool { return f.CCSInjection }, CCSInjection},
	{"heartbleed", func(f RunnerFlags) bool { return f.Heartbleed }, Heartbleed},
	{"logjam", func(f RunnerFlags) bool { return f.Logjam }, LOGJAM},
	{"poodle", func(f RunnerFlags) bool { return f.Poodle }, POODLE},
	{"sweet32", func(f RunnerFlags) bool { return f.Sweet32 }, SWEET32},
	{"ticketbleed", func(f RunnerFlags) bool { return f.Ticketbleed }, Ticketbleed},
	{"tls-fallback-scsv", func(f RunnerFlags) bool { return f.TLSFallbackSCSV }, TLSFallbackSCSV},
	{"winshock", func(f RunnerFlags) bool { return f.Winshock }, Winshock},
}

// AnyFlag reports whether any weak-cryptography check (or --test-all) is enabled.
func AnyFlag(flags RunnerFlags) bool {
	if flags.TestAll {
		return true
	}
	for _, spec := range weakCryptoSpecs {
		if spec.enabled(flags) {
			return true
		}
	}
	return false
}

// RunTests runs enabled weak-cryptography checks sequentially.
// When multiple flags are set (without --test-all), they run in command-line order.
func RunTests(flags RunnerFlags, url, port string) {
	for _, spec := range orderedWeakCryptoSpecs(flags) {
		spec.run(url, port)
	}
}

func orderedWeakCryptoSpecs(flags RunnerFlags) []weakCryptoSpec {
	if flags.TestAll {
		return weakCryptoSpecs
	}

	enabled := make(map[string]weakCryptoSpec)
	for _, spec := range weakCryptoSpecs {
		if spec.enabled(flags) {
			enabled[spec.flagName] = spec
		}
	}

	var ordered []weakCryptoSpec
	seen := make(map[string]bool)
	for _, arg := range os.Args[1:] {
		name := strings.TrimPrefix(arg, "--")
		if spec, ok := enabled[name]; ok && !seen[name] {
			ordered = append(ordered, spec)
			seen[name] = true
		}
	}
	if len(ordered) == 0 {
		for _, spec := range weakCryptoSpecs {
			if spec.enabled(flags) {
				ordered = append(ordered, spec)
			}
		}
	}
	return ordered
}
