package app

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"fileshare/internal/config"
	"fileshare/internal/testutil"
)

func TestRealTLSLoginAndShutdown(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "deadline"}[forced], func(t *testing.T) {
			root := t.TempDir()
			cert := testutil.Cert(t, nil)
			c := config.Default()
			c.Directory = root
			c.CertFile = cert.CertFile
			c.KeyFile = cert.KeyFile
			c.ShutdownTimeout = 2 * time.Second
			if forced {
				c.ShutdownTimeout = 50 * time.Millisecond
			}
			f, err := os.Create(filepath.Join(root, "large.bin"))
			if err != nil {
				t.Fatal(err)
			}
			const size = int64(64 << 20)
			if err = f.Truncate(size); err != nil {
				t.Fatal(err)
			}
			f.Close()
			a, err := New(c, []byte("actual login password"), slog.New(slog.NewJSONHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- a.Serve(ctx, listener) }()
			base := "https://" + listener.Addr().String()
			jar, _ := cookiejar.New(nil)
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cert.Roots}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			r, err := client.Get(base + "/login")
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(r.Body)
			r.Body.Close()
			match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(data)
			if len(match) != 2 {
				t.Fatal("no login token")
			}
			r, err = client.PostForm(base+"/login", url.Values{"csrf": {string(match[1])}, "password": {"actual login password"}})
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode != 303 {
				t.Fatal("Argon2/TLS end-to-end login failed", r.StatusCode)
			}
			r, err = client.Get(base + "/api/download/large.bin")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			if a.metrics.ActiveDownloads.Load() != 1 {
				t.Fatal("download should be in progress")
			}
			cancel()
			if !forced {
				n, err := io.Copy(io.Discard, r.Body)
				if err != nil || n != size {
					t.Fatal("graceful shutdown interrupted transfer", n, err)
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("shutdown failed to return")
			}
			if a.metrics.ActiveDownloads.Load() != 0 || a.metrics.ActiveRequests.Load() != 0 {
				t.Fatal("shutdown leaked work")
			}
			if forced {
				if n, err := io.Copy(io.Discard, r.Body); err == nil || n == size {
					t.Fatal("deadline did not interrupt outstanding transfer", n, err)
				}
			}
		})
	}
}

func TestPrepareProtectsOwnerSecrets(t *testing.T) {
	root := t.TempDir()
	cert := testutil.Cert(t, nil)
	c := config.Default()
	c.Directory = root
	c.CertFile = cert.CertFile
	c.KeyFile = cert.KeyFile
	if _, err := Prepare(c); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "password")
	if err := os.WriteFile(secret, []byte("do not expose"), 0600); err != nil {
		t.Fatal(err)
	}
	c.PasswordFile = secret
	if _, err := Prepare(c); err == nil {
		t.Fatal("password file inside shared directory accepted")
	}
	c.PasswordFile = ""
	key, err := os.ReadFile(cert.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	c.KeyFile = filepath.Join(root, "private.key")
	if err := os.WriteFile(c.KeyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(c); err == nil {
		t.Fatal("TLS key inside shared directory accepted")
	}
}
