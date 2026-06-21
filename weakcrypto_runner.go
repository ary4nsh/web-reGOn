package main

import (
	"os"
	"strings"

	weakcryptography "github.com/ary4nsh/web-reGOn/libs/weak-cryptography"
)

type weakCryptoSpec struct {
	flagName string
	enabled  func(Flags) bool
	run      func(string, string)
}

// weakCryptoSpecs is the canonical order used by --test-all (matches README section order).
var weakCryptoSpecs = []weakCryptoSpec{
	{"anonymous-ciphers", func(f Flags) bool { return f.anonymousCiphers }, weakcryptography.AnonymousCiphers},
	{"beast", func(f Flags) bool { return f.beast }, weakcryptography.BEAST},
	{"drown", func(f Flags) bool { return f.drown }, weakcryptography.DROWN},
	{"freak", func(f Flags) bool { return f.freak }, weakcryptography.FREAK},
	{"lucky13", func(f Flags) bool { return f.lucky13 }, weakcryptography.Lucky13},
	{"nomore", func(f Flags) bool { return f.nomore }, weakcryptography.NoMore},
	{"null-ciphers", func(f Flags) bool { return f.nullCiphers }, weakcryptography.NullCiphers},
	{"insecure-renegotiation", func(f Flags) bool { return f.insecureRenegotiation }, weakcryptography.InsecureRenegotiation},
	{"breach", func(f Flags) bool { return f.breach }, weakcryptography.BREACH},
	{"crime", func(f Flags) bool { return f.crime }, weakcryptography.CRIME},
	{"ccs-injection", func(f Flags) bool { return f.ccsInjection }, weakcryptography.CCSInjection},
	{"heartbleed", func(f Flags) bool { return f.heartbleed }, weakcryptography.Heartbleed},
	{"logjam", func(f Flags) bool { return f.logjam }, weakcryptography.LOGJAM},
	{"poodle", func(f Flags) bool { return f.poodle }, weakcryptography.POODLE},
	{"sweet32", func(f Flags) bool { return f.sweet32 }, weakcryptography.SWEET32},
	{"ticketbleed", func(f Flags) bool { return f.ticketbleed }, weakcryptography.Ticketbleed},
	{"tls-fallback-scsv", func(f Flags) bool { return f.tlsFallbackSCSV }, weakcryptography.TLSFallbackSCSV},
	{"winshock", func(f Flags) bool { return f.winshock }, weakcryptography.Winshock},
}

func anyWeakCryptoFlag(flags Flags) bool {
	if flags.testAll {
		return true
	}
	for _, spec := range weakCryptoSpecs {
		if spec.enabled(flags) {
			return true
		}
	}
	return false
}

func runWeakCryptoTests(flags Flags, url, port string) {
	specs := orderedWeakCryptoSpecs(flags)
	for _, spec := range specs {
		spec.run(url, port)
	}
}

func orderedWeakCryptoSpecs(flags Flags) []weakCryptoSpec {
	if flags.testAll {
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
