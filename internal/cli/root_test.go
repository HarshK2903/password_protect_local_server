package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseShare(t *testing.T) {
	c, err := ParseShare([]string{"./documents", "--port", "8443", "--cert", "cert.pem", "--key", "key.pem", "--auth", "--read-only", "--exclude", "*.key", "--trusted-proxy", "127.0.0.1/32"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Directory != "./documents" || c.Port != 8443 || c.Bind != "127.0.0.1" || len(c.TrustedProxies) != 1 {
		t.Fatalf("bad config: %+v", c)
	}
	for _, extra := range [][]string{{"--auth=false"}, {"--read-only=false"}, {"--bind", "0.0.0.0"}, {"--login-rate", "NaN"}, {"--port", "0"}, {"--auth-concurrency", "33"}, {"--exclude", "["}, {"--session-idle", "9h"}, {"--cooldown", "0s"}} {
		args := append([]string{"docs", "--cert", "cert.pem", "--key", "key.pem"}, extra...)
		if _, err := ParseShare(args, io.Discard); err == nil {
			t.Errorf("accepted %v", extra)
		}
	}
}

func TestPasswordFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(file, []byte(" secret password \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := ReadPassword(file, os.Stdin, io.Discard)
	if err != nil || string(p) != " secret password " {
		t.Fatalf("password whitespace damaged: %q %v", p, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(file, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadPassword(file, os.Stdin, io.Discard); err == nil {
			t.Fatal("accepted world readable password")
		}
	}
}
