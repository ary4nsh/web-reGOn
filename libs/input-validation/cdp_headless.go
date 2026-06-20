package inputvalidation

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ── minimal WebSocket client (stdlib only, based on go-rod/lib/cdp/websocket) ──

type wsConn struct {
	writeMu sync.Mutex // serializes outbound frames; reads run only in readLoop
	conn    net.Conn
	r       *bufio.Reader
}

func (ws *wsConn) connect(ctx context.Context, wsURL string) error {
	u, err := url.Parse(wsURL)
	if err != nil {
		return err
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return err
	}
	ws.conn = conn
	ws.r = bufio.NewReader(conn)
	return ws.handshake(ctx, u)
}

func (ws *wsConn) handshake(ctx context.Context, u *url.URL) error {
	secKey := base64.StdEncoding.EncodeToString([]byte("web-regOn-cdp-key!!"))
	req := (&http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: http.Header{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-WebSocket-Key":     {secKey},
			"Sec-WebSocket-Version": {"13"},
		},
	}).WithContext(ctx)
	if err := req.Write(ws.conn); err != nil {
		return err
	}
	res, err := http.ReadResponse(ws.r, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("websocket handshake failed: %s %s", res.Status, body)
	}
	expected := secKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.Sum([]byte(expected))
	if res.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(hash[:]) {
		return errors.New("websocket accept mismatch")
	}
	return nil
}

func (ws *wsConn) sendText(msg []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()
	mask := []byte{1, 2, 3, 4}
	size := len(msg)
	header := make([]byte, 0, 14+size)
	header = append(header, 0x81)
	switch {
	case size <= 125:
		header = append(header, 0x80|byte(size))
	case size < 65536:
		header = append(header, 0x80|126, byte(size>>8), byte(size))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, byte(size>>24), byte(size>>16), byte(size>>8), byte(size))
	}
	header = append(header, mask...)
	payload := make([]byte, size)
	for i := range msg {
		payload[i] = msg[i] ^ mask[i%4]
	}
	header = append(header, payload...)
	_, err := ws.conn.Write(header)
	return err
}

func (ws *wsConn) readText() ([]byte, error) {
	if _, err := ws.r.ReadByte(); err != nil {
		return nil, err
	}
	b, err := ws.r.ReadByte()
	if err != nil {
		return nil, err
	}
	b &= 0x7f
	size, fieldLen := 0, 0
	switch {
	case b <= 125:
		size = int(b)
	case b == 126:
		fieldLen = 2
	case b == 127:
		fieldLen = 8
	}
	for i := 0; i < fieldLen; i++ {
		x, err := ws.r.ReadByte()
		if err != nil {
			return nil, err
		}
		size = size<<8 + int(x)
	}
	data := make([]byte, size)
	_, err = io.ReadFull(ws.r, data)
	return data, err
}

func (ws *wsConn) close() error {
	if ws.conn == nil {
		return nil
	}
	return ws.conn.Close()
}

// ── Chrome DevTools Protocol client ──────────────────────────────────────────

type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type cdpConn struct {
	ws         wsConn
	nextID     int64
	pending    map[int]chan cdpMessage
	events     map[string][]func(json.RawMessage)
	sessEvents map[string]map[string][]func(json.RawMessage)
	mu         sync.Mutex
	closed     chan struct{}
	readDone   chan struct{}
}

func newCDPConn(ctx context.Context, wsURL string) (*cdpConn, error) {
	c := &cdpConn{
		pending:    make(map[int]chan cdpMessage),
		events:     make(map[string][]func(json.RawMessage)),
		sessEvents: make(map[string]map[string][]func(json.RawMessage)),
		closed:     make(chan struct{}),
		readDone:   make(chan struct{}),
	}
	if err := c.ws.connect(ctx, wsURL); err != nil {
		return nil, err
	}
	go c.readLoop()
	return c, nil
}

func (c *cdpConn) readLoop() {
	defer close(c.readDone)
	for {
		raw, err := c.ws.readText()
		if err != nil {
			return
		}
		var msg cdpMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		if msg.Method != "" {
			c.mu.Lock()
			handlers := append([]func(json.RawMessage){}, c.events[msg.Method]...)
			if msg.SessionID != "" {
				if m, ok := c.sessEvents[msg.SessionID]; ok {
					handlers = append(handlers, m[msg.Method]...)
				}
			}
			c.mu.Unlock()
			for _, h := range handlers {
				go h(msg.Params)
			}
		}
	}
}

func (c *cdpConn) onSession(sessionID, method string, fn func(json.RawMessage)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sessEvents[sessionID] == nil {
		c.sessEvents[sessionID] = make(map[string][]func(json.RawMessage))
	}
	c.sessEvents[sessionID][method] = append(c.sessEvents[sessionID][method], fn)
}

func (c *cdpConn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := int(atomic.AddInt64(&c.nextID, 1))
	payload := map[string]any{"id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ch := make(chan cdpMessage, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()

	if err := c.ws.sendText(raw); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}

	select {
	case msg := <-ch:
		if msg.Error != nil {
			return nil, errors.New(msg.Error.Message)
		}
		return msg.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("cdp connection closed")
	}
}

func (c *cdpConn) callAsync(method string, params any) error {
	id := int(atomic.AddInt64(&c.nextID, 1))
	payload := map[string]any{"id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.ws.sendText(raw)
}

func (c *cdpConn) close() {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	_ = c.ws.close()
	<-c.readDone
}

const cdpHTTPTimeout = 10 * time.Second

var cdpHTTPClient = &http.Client{Timeout: cdpHTTPTimeout}

type chromeProcess struct {
	cmd       *exec.Cmd
	dataDir   string
	debugBase string
	browser   *cdpConn
}

func resolveBrowserWS(base string) (string, error) {
	resp, err := cdpHTTPClient.Get(base + "/json/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var info struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}
	if info.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("no browser websocket in: %s", body)
	}
	return info.WebSocketDebuggerURL, nil
}

func chromeLookPath() (string, bool) {
	candidates := map[string][]string{
		"windows": {
			"chrome", "msedge",
			filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
			filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		},
		"linux": {
			"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
			"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		},
		"darwin": {
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		},
	}[runtime.GOOS]
	for _, p := range candidates {
		if path, err := exec.LookPath(p); err == nil {
			return path, true
		}
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func launchChrome() (*chromeProcess, error) {
	bin, ok := chromeLookPath()
	if !ok {
		return nil, errors.New("chrome/chromium not installed")
	}

	dataDir, err := os.MkdirTemp("", "web-regOn-chrome-*")
	if err != nil {
		return nil, err
	}

	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, err
	}

	args := []string{
		"--headless",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir=" + dataDir,
		"--disable-gpu",
		"--disable-crash-reporter",
		"--ignore-certificate-errors",
		"--mute-audio",
		"--hide-scrollbars",
		"--disable-dev-shm-usage",
		"--no-first-run",
		"--no-default-browser-check",
	}
	if runtime.GOOS == "linux" {
		args = append(args, "--no-sandbox")
	}

	cmd := exec.Command(bin, args...)
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = procHideWindow()
	}
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, fmt.Errorf("browser launch failed: %w", err)
	}

	debugBase := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitDebugEndpoint(debugBase, 15*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(dataDir)
		return nil, err
	}

	wsURL, err := resolveBrowserWS(debugBase)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	browser, err := newCDPConn(context.Background(), wsURL)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = browser.call(discoverCtx, "Target.setDiscoverTargets", map[string]any{"discover": true})
	discoverCancel()

	return &chromeProcess{cmd: cmd, dataDir: dataDir, debugBase: debugBase, browser: browser}, nil
}

func waitDebugEndpoint(base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := cdpHTTPClient.Get(base + "/json/version")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("timed out waiting for chrome debug endpoint")
}

func (cp *chromeProcess) close() {
	if cp.browser != nil {
		cp.browser.close()
	}
	if cp.cmd != nil && cp.cmd.Process != nil {
		_ = cp.cmd.Process.Kill()
		done := make(chan struct{})
		go func() {
			_ = cp.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	if cp.dataDir != "" {
		_ = os.RemoveAll(cp.dataDir)
	}
}

type pageTarget struct {
	sessionID string
	targetID  string
	browser   *cdpConn
}

func (p *pageTarget) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := int(atomic.AddInt64(&p.browser.nextID, 1))
	payload := map[string]any{"id": id, "method": method, "sessionId": p.sessionID}
	if params != nil {
		payload["params"] = params
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ch := make(chan cdpMessage, 1)
	p.browser.mu.Lock()
	p.browser.pending[id] = ch
	p.browser.mu.Unlock()
	if err := p.browser.ws.sendText(raw); err != nil {
		p.browser.mu.Lock()
		delete(p.browser.pending, id)
		p.browser.mu.Unlock()
		return nil, err
	}
	select {
	case msg := <-ch:
		if msg.Error != nil {
			return nil, errors.New(msg.Error.Message)
		}
		return msg.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.browser.closed:
		return nil, errors.New("cdp connection closed")
	}
}

func (p *pageTarget) callAsync(method string, params any) error {
	id := int(atomic.AddInt64(&p.browser.nextID, 1))
	payload := map[string]any{"id": id, "method": method, "sessionId": p.sessionID}
	if params != nil {
		payload["params"] = params
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return p.browser.ws.sendText(raw)
}

func (cp *chromeProcess) newPage(ctx context.Context) (*pageTarget, error) {
	ctxRaw, err := cp.browser.call(ctx, "Target.createBrowserContext", map[string]any{})
	if err != nil {
		return nil, err
	}
	var ctxRes struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := json.Unmarshal(ctxRaw, &ctxRes); err != nil {
		return nil, err
	}

	targetRaw, err := cp.browser.call(ctx, "Target.createTarget", map[string]any{
		"url":              "about:blank",
		"browserContextId": ctxRes.BrowserContextID,
	})
	if err != nil {
		return nil, err
	}
	var targetRes struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(targetRaw, &targetRes); err != nil {
		return nil, err
	}

	attachRaw, err := cp.browser.call(ctx, "Target.attachToTarget", map[string]any{
		"targetId": targetRes.TargetID,
		"flatten":  true,
	})
	if err != nil {
		return nil, err
	}
	var attachRes struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(attachRaw, &attachRes); err != nil {
		return nil, err
	}

	page := &pageTarget{
		sessionID: attachRes.SessionID,
		targetID:  targetRes.TargetID,
		browser:   cp.browser,
	}
	if _, err := page.call(ctx, "Page.enable", nil); err != nil {
		return nil, err
	}
	if _, err := page.call(ctx, "Runtime.enable", nil); err != nil {
		return nil, err
	}
	return page, nil
}

func (p *pageTarget) close(ctx context.Context, cp *chromeProcess) {
	if p.targetID != "" && cp.browser != nil {
		_, _ = cp.browser.call(ctx, "Target.closeTarget", map[string]any{"targetId": p.targetID})
	}
}

const interactionEvalScript = `() => {
	function tryJS(val) {
		val = (val || '').trim();
		if (/^javascript:/i.test(val)) {
			try { eval(val.replace(/^javascript:/i, '')); } catch(_) {}
		}
	}
	document.querySelectorAll('a[href]').forEach(function(a) {
		tryJS(a.getAttribute('href'));
	});
	document.querySelectorAll('form').forEach(function(f) {
		tryJS(f.getAttribute('action'));
	});
	document.querySelectorAll('[formaction]').forEach(function(e) {
		tryJS(e.getAttribute('formaction'));
	});
	document.querySelectorAll('button, input[type=submit], input[type=image]').forEach(function(b) {
		try { b.click(); } catch(_) {}
	});
	document.querySelectorAll('input:not([type=submit]):not([type=button]):not([type=image]):not([type=hidden]), textarea').forEach(function(e) {
		try { e.focus(); } catch(_) {}
	});
}`

func (cp *chromeProcess) dialogFired(ctx context.Context, targetURL string) (bool, error) {
	page, err := cp.newPage(ctx)
	if err != nil {
		return false, fmt.Errorf("new page: %w", err)
	}
	defer page.close(ctx, cp)

	dialogCh := make(chan bool, 1)
	page.browser.onSession(page.sessionID, "Page.javascriptDialogOpening", func(_ json.RawMessage) {
		select {
		case dialogCh <- true:
		default:
		}
		_ = page.callAsync("Page.handleJavaScriptDialog", map[string]any{"accept": true})
	})

	loadCh := make(chan struct{}, 1)
	page.browser.onSession(page.sessionID, "Page.loadEventFired", func(_ json.RawMessage) {
		select {
		case loadCh <- struct{}{}:
		default:
		}
	})

	if _, err := page.call(ctx, "Page.navigate", map[string]any{"url": targetURL}); err != nil {
		if !isExpectedNavError(err) {
			return false, err
		}
	}

	select {
	case <-loadCh:
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return false, ctx.Err()
	}

	select {
	case fired := <-dialogCh:
		return fired, nil
	default:
	}

	if runtime.GOOS == "windows" {
		_, _ = page.triggerCDP(ctx)
		select {
		case fired := <-dialogCh:
			return fired, nil
		default:
		}
	}

	if _, err := page.call(ctx, "Runtime.evaluate", map[string]any{
		"expression":    "(" + interactionEvalScript + ")()",
		"awaitPromise":  false,
		"returnByValue": true,
	}); err != nil {
		return false, err
	}

	select {
	case fired := <-dialogCh:
		return fired, nil
	case <-time.After(3 * time.Second):
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (p *pageTarget) triggerCDP(ctx context.Context) (bool, error) {
	clickJS := `(sel) => {
		const el = document.querySelector(sel);
		if (!el) return false;
		el.scrollIntoView();
		el.click();
		return true;
	}`
	for _, sel := range []string{"button", "input[type=submit]", "input[type=image]"} {
		_, _ = p.call(ctx, "Runtime.evaluate", map[string]any{
			"expression": fmt.Sprintf(`(%s)(%q)`, clickJS, sel),
		})
	}
	links, err := p.call(ctx, "Runtime.evaluate", map[string]any{
		"expression":    `Array.from(document.querySelectorAll('a[href]')).filter(a => /^javascript:/i.test((a.getAttribute('href')||'').trim())).length`,
		"returnByValue": true,
	})
	if err == nil {
		var res struct {
			Value float64 `json:"value"`
		}
		_ = json.Unmarshal(links, &res)
		if res.Value > 0 {
			_, _ = p.call(ctx, "Runtime.evaluate", map[string]any{
				"expression": `document.querySelectorAll('a[href]').forEach(a => { if (/^javascript:/i.test((a.getAttribute('href')||'').trim())) { a.scrollIntoView(); a.click(); }})`,
			})
			return true, nil
		}
	}
	return false, nil
}
