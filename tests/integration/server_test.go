package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	stdhtml "html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/config"
	"fileshare/internal/files"
	"fileshare/internal/security"
	"fileshare/internal/server"
	"fileshare/internal/telemetry"
)

const testPassword = "correct test password"
const sessionName = "__Host-fileshare_session"

var tokenPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

type verifier struct {
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (v *verifier) Verify(p []byte) bool {
	v.calls.Add(1)
	if v.entered != nil {
		v.entered <- struct{}{}
		<-v.release
	}
	return string(p) == testPassword
}

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *synchronizedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

type harness struct {
	ts       *httptest.Server
	client   *http.Client
	store    *auth.Store
	guard    *security.Guard
	verifier *verifier
	metrics  *telemetry.Metrics
	log      *synchronizedBuffer
	root     string
	handler  *server.Server
}

func newHarness(t *testing.T, edit func(*config.Config), v *verifier) *harness {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{"public.txt": "hello world", ".secret": "hidden", "excluded.key": "key"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "a folder & more"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a folder & more", "a % #+.txt"), []byte("special"), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.Directory = root
	c.Excludes = []string{"*.key"}
	c.IPBurst = 1000
	c.GlobalAuthBurst = 1000
	c.IPRate = 1000
	c.GlobalAuthRate = 1000
	if edit != nil {
		edit(&c)
	}
	fs, err := files.New(root, files.Policy{Excludes: c.Excludes}, c.MaxEntries)
	if err != nil {
		t.Fatal(err)
	}
	if v == nil {
		v = &verifier{}
	}
	h := &harness{root: root, store: auth.NewStore(c.MaxSessions, c.SessionIdle, c.SessionAbsolute), guard: security.NewGuard(c, time.Now()), verifier: v, metrics: &telemetry.Metrics{}, log: &synchronizedBuffer{}}
	s, err := server.New(c, server.Dependencies{Authenticator: v, Sessions: h.store, Guard: h.guard, Files: fs, Log: slog.New(slog.NewJSONHandler(h.log, nil)), Metrics: h.metrics})
	if err != nil {
		t.Fatal(err)
	}
	h.handler = s
	h.ts = httptest.NewTLSServer(s.Handler())
	h.client = h.ts.Client()
	h.client.Jar, _ = cookiejar.New(nil)
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(func() { h.ts.Close(); s.StopAdmissions(); s.Wait(); fs.Close() })
	return h
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func do(t *testing.T, c *http.Client, method, address string, values url.Values, headers map[string]string) *http.Response {
	t.Helper()
	var b io.Reader
	if values != nil {
		b = strings.NewReader(values.Encode())
	}
	r, err := http.NewRequest(method, address, b)
	if err != nil {
		t.Fatal(err)
	}
	if values != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
func (h *harness) csrf(t *testing.T) string {
	t.Helper()
	res := do(t, h.client, "GET", h.ts.URL+"/login", nil, nil)
	html := body(t, res)
	m := tokenPattern.FindStringSubmatch(html)
	if res.StatusCode != 200 || len(m) != 2 {
		t.Fatal("missing login form", res.StatusCode, html)
	}
	return m[1]
}
func (h *harness) login(t *testing.T, password string) *http.Response {
	t.Helper()
	csrf := h.csrf(t)
	return do(t, h.client, "POST", h.ts.URL+"/login", url.Values{"csrf": {csrf}, "password": {password}}, nil)
}
func (h *harness) authenticate(t *testing.T) string {
	t.Helper()
	r := h.login(t, testPassword)
	body(t, r)
	if r.StatusCode != 303 {
		t.Fatal("login failed", r.StatusCode)
	}
	for _, c := range r.Cookies() {
		if c.Name == sessionName {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Fatal("insecure cookie", c)
			}
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestHTTPSAuthenticationBrowseAndLogout(t *testing.T) {
	h := newHarness(t, nil, nil)
	for _, p := range []string{"/api/files", "/api/download/public.txt"} {
		r := do(t, h.client, "GET", h.ts.URL+p, nil, nil)
		b := body(t, r)
		if r.StatusCode != 401 || strings.Contains(b, "hello world") {
			t.Fatal("unauthenticated bypass", p, r.StatusCode)
		}
	}
	r := do(t, h.client, "GET", h.ts.URL+"/", nil, nil)
	body(t, r)
	if r.StatusCode != 303 || r.Header.Get("Location") != "/login" {
		t.Fatal("no login redirect")
	}
	r = h.login(t, "incorrect")
	body(t, r)
	if r.StatusCode != 401 {
		t.Fatal("wrong password accepted")
	}
	token := h.authenticate(t)
	r = do(t, h.client, "GET", h.ts.URL+"/api/files", nil, nil)
	listing := body(t, r)
	if r.StatusCode != 200 || !strings.Contains(listing, "public.txt") || strings.Contains(listing, ".secret") || strings.Contains(listing, "excluded.key") {
		t.Fatal("invalid listing", listing)
	}
	r = do(t, h.client, "GET", h.ts.URL+"/", nil, nil)
	html := body(t, r)
	if r.StatusCode != 200 || !strings.Contains(html, "a%20folder%20%26%20more") {
		t.Fatal("folder URL is incorrectly escaped", html)
	}
	for _, p := range []string{"/api/download/.secret", "/api/download/excluded.key", "/api/download/../.secret", "/api/download/%2e%2e/.secret", "/api/download/a%2fb", "/api/download/a%5cb"} {
		r = do(t, h.client, "GET", h.ts.URL+p, nil, nil)
		body(t, r)
		if r.StatusCode < 400 {
			t.Fatal("accepted malicious path", p, r.StatusCode)
		}
	}
	r = do(t, h.client, "GET", h.ts.URL+"/api/download/public.txt", nil, map[string]string{"Range": "bytes=0-4"})
	if b := body(t, r); r.StatusCode != 206 || b != "hello" || !strings.Contains(r.Header.Get("Content-Disposition"), "attachment") || r.Header.Get("X-Content-Type-Options") != "nosniff" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("invalid ranged download", r.StatusCode, b, r.Header)
	}
	r = do(t, h.client, "HEAD", h.ts.URL+"/api/download/public.txt", nil, nil)
	if b := body(t, r); r.StatusCode != 200 || b != "" || r.ContentLength != 11 {
		t.Fatal("HEAD failed", r.StatusCode, b)
	}
	r = do(t, h.client, "GET", h.ts.URL+"/api/download/public.txt", nil, map[string]string{"Range": "bytes=999-1000"})
	body(t, r)
	if r.StatusCode != 416 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("range errors lost privacy headers", r.StatusCode, r.Header)
	}
	r = do(t, h.client, "POST", h.ts.URL+"/logout", url.Values{"csrf": {"bad"}}, nil)
	body(t, r)
	if r.StatusCode != 403 {
		t.Fatal("CSRF logout accepted")
	}
	hash := sha256.Sum256([]byte("fileshare-csrf:" + token))
	csrf := base64.RawURLEncoding.EncodeToString(hash[:])
	r = do(t, h.client, "POST", h.ts.URL+"/logout", url.Values{"csrf": {csrf}}, map[string]string{"Origin": "https://evil.example"})
	body(t, r)
	if r.StatusCode != 403 {
		t.Fatal("cross-origin logout accepted")
	}
	r = do(t, h.client, "POST", h.ts.URL+"/logout", url.Values{"csrf": {csrf}}, nil)
	body(t, r)
	if r.StatusCode != 303 {
		t.Fatal("logout failed")
	}
	r = do(t, h.client, "GET", h.ts.URL+"/api/download/public.txt", nil, map[string]string{"Cookie": sessionName + "=" + token})
	body(t, r)
	if r.StatusCode != 401 {
		t.Fatal("revoked session accepted")
	}
	logs := h.log.String()
	if strings.Contains(logs, testPassword) || strings.Contains(logs, token) || strings.Contains(logs, "incorrect") {
		t.Fatal("credentials leaked in logs")
	}
}

func TestCooldownSkipsHashAndPreservesExistingSession(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.authenticate(t)
	for i := 0; i < 5; i++ {
		r := h.login(t, "bad")
		body(t, r)
		want := 401
		if i == 4 {
			want = 429
		}
		if r.StatusCode != want {
			t.Fatalf("attempt %d: %d", i, r.StatusCode)
		}
	}
	calls := h.verifier.calls.Load()
	r := h.login(t, testPassword)
	body(t, r)
	if r.StatusCode != 429 || r.Header.Get("Retry-After") == "" || h.verifier.calls.Load() != calls {
		t.Fatal("cooldown performed hashing")
	}
	r = do(t, h.client, "GET", h.ts.URL+"/api/files", nil, nil)
	body(t, r)
	if r.StatusCode != 200 {
		t.Fatal("cooldown terminated established session")
	}
}

func TestConcurrentLoginAdmission(t *testing.T) {
	v := &verifier{entered: make(chan struct{}, 1), release: make(chan struct{})}
	h := newHarness(t, nil, v)
	csrf := h.csrf(t)
	result := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		r, err := h.client.PostForm(h.ts.URL+"/login", url.Values{"csrf": {csrf}, "password": {testPassword}})
		if err != nil {
			errCh <- err
			return
		}
		result <- r
	}()
	select {
	case <-v.entered:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("verification did not start")
	}
	// Always release on assertion failure, so test cleanup cannot deadlock.
	defer func() {
		select {
		case <-v.release:
		default:
			close(v.release)
		}
	}()
	var wg sync.WaitGroup
	var rejected atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := h.client.PostForm(h.ts.URL+"/login", url.Values{"csrf": {csrf}, "password": {testPassword}})
			if err != nil {
				t.Error(err)
				return
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == 429 {
				rejected.Add(1)
			} else {
				t.Errorf("parallel login got %d", r.StatusCode)
			}
		}()
	}
	wg.Wait()
	if rejected.Load() != 20 || v.calls.Load() != 1 {
		t.Fatal("parallel bypass", rejected.Load(), v.calls.Load())
	}
	close(v.release)
	select {
	case r := <-result:
		body(t, r)
		if r.StatusCode != 303 {
			t.Fatal("initial login failed")
		}
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("initial login stuck")
	}
}

func TestSessionExpiryAndRequestValidation(t *testing.T) {
	h := newHarness(t, nil, nil)
	token := h.authenticate(t)
	if _, ok := h.store.Validate(token, time.Now().Add(time.Hour)); ok {
		t.Fatal("session should idle-expire")
	}
	r := do(t, h.client, "GET", h.ts.URL+"/api/files", nil, nil)
	body(t, r)
	if r.StatusCode != 401 {
		t.Fatal("expired session accepted")
	}
	csrf := h.csrf(t)
	r = do(t, h.client, "POST", h.ts.URL+"/login", url.Values{"csrf": {csrf}, "password": {testPassword}}, map[string]string{"Origin": "http://127.0.0.1"})
	body(t, r)
	if r.StatusCode != 403 {
		t.Fatal("insecure origin accepted")
	}
	r = do(t, h.client, "POST", h.ts.URL+"/login", url.Values{"csrf": {csrf}, "password": {strings.Repeat("x", 5000)}}, nil)
	body(t, r)
	if r.StatusCode != 413 {
		t.Fatal("oversized login form accepted", r.StatusCode)
	}
	request, err := http.NewRequest("GET", h.ts.URL+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "evil.example"
	r, err = h.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body(t, r)
	if r.StatusCode != 400 {
		t.Fatal("DNS rebinding host accepted")
	}
	h.handler.StopAdmissions()
	r = do(t, h.client, "GET", h.ts.URL+"/login", nil, nil)
	body(t, r)
	if r.StatusCode != 503 {
		t.Fatal("accepted after shutdown")
	}
}

func TestLargeFileStreamingAndSpecialNames(t *testing.T) {
	h := newHarness(t, nil, nil)
	h.authenticate(t)
	const size = int64(64 << 20)
	f, err := os.Create(filepath.Join(h.root, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
	r := do(t, h.client, "GET", h.ts.URL+"/api/download/large.bin", nil, nil)
	n, err := io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if err != nil || n != size || r.StatusCode != 200 {
		t.Fatal("large streaming failed", n, err)
	}
	r = do(t, h.client, "GET", h.ts.URL+"/?path="+url.QueryEscape("a folder & more"), nil, nil)
	html := body(t, r)
	m := regexp.MustCompile(`href="(/api/download/[^"]+)"`).FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatal("missing special filename link", html)
	}
	r = do(t, h.client, "GET", h.ts.URL+stdhtml.UnescapeString(m[1]), nil, nil)
	if b := body(t, r); r.StatusCode != 200 || b != "special" {
		t.Fatal("special filename download failed", r.StatusCode, b, m[1])
	}
	if h.metrics.Bytes.Load() < size {
		t.Fatal("byte accounting missing")
	}
}

func TestTransferAndRequestBounds(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.MaxTransfers = 1; c.MaxRequests = 4 }, nil)
	h.authenticate(t)
	f, err := os.Create(filepath.Join(h.root, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(512 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", h.ts.URL+"/api/download/large.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	r := do(t, h.client, "GET", h.ts.URL+"/api/download/public.txt", nil, nil)
	body(t, r)
	if r.StatusCode != 503 {
		t.Fatal("transfer concurrency bypass", r.StatusCode)
	}
	cancel()
	first.Body.Close()
	deadline := time.Now().Add(3 * time.Second)
	for h.metrics.ActiveDownloads.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("cancelled download leaked permit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r = do(t, h.client, "GET", h.ts.URL+"/api/download/public.txt", nil, nil)
	if b := body(t, r); r.StatusCode != 200 || b != "hello world" {
		t.Fatal("permit not reusable")
	}
}

func TestGlobalRequestAdmission(t *testing.T) {
	v := &verifier{entered: make(chan struct{}, 1), release: make(chan struct{})}
	h := newHarness(t, func(c *config.Config) { c.MaxRequests = 1 }, v)
	csrf := h.csrf(t)
	finished := make(chan error, 1)
	go func() {
		r, err := h.client.PostForm(h.ts.URL+"/login", url.Values{"csrf": {csrf}, "password": {testPassword}})
		if err == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
		finished <- err
	}()
	select {
	case <-v.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("login did not start")
	}
	defer func() {
		select {
		case <-v.release:
		default:
			close(v.release)
		}
	}()
	r := do(t, h.client, "GET", h.ts.URL+"/login", nil, nil)
	body(t, r)
	if r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Fatal("request admission cap bypass", r.StatusCode)
	}
	close(v.release)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("login did not finish")
	}
}
