package files

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(t testing.TB) (*Service, string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "shared")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{root, filepath.Join(root, "nested folder"), filepath.Join(root, ".hidden"), filepath.Join(root, "private"), outside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"public.txt": "public", "nested folder/hello %.txt": "public", ".secret": "secret", ".hidden/token": "secret", "private/data": "secret", "server.key": "secret"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for name, target := range map[string]string{"escape": outside, "alias": ".hidden", "file-link": "public.txt"} {
			if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err := New(root, Policy{Excludes: []string{"private", "*.key"}}, 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, root, outside
}

func TestConfinedAccessAndPolicies(t *testing.T) {
	s, _, _ := fixture(t)
	for _, name := range []string{"../outside/secret", "/etc/passwd", "nested folder/../../outside/secret", ".secret", ".hidden/token", "private/data", "server.key", "escape/secret", "alias/token", "file-link", "public.txt/", "a\\b", "a:b", "a\x00b", "a/../public.txt"} {
		if f, _, err := s.Open(context.Background(), name); err == nil {
			f.Close()
			t.Errorf("opened denied path %q", name)
		}
	}
	for _, name := range []string{"public.txt", "nested folder/hello %.txt"} {
		f, info, err := s.Open(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(f)
		f.Close()
		if err != nil || string(body) != "public" || !info.Mode().IsRegular() {
			t.Fatal("bad authorized read")
		}
	}
	entries, err := s.List(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || !entries[0].Directory || entries[1].Name != "public.txt" {
		t.Fatalf("unexpected listing: %+v", entries)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Open(ctx, "public.txt"); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestDirectoryBound(t *testing.T) {
	s, _, _ := fixture(t)
	s.maxEntries = 1
	if _, err := s.List(context.Background(), "."); err != ErrTooLarge {
		t.Fatalf("unbounded listing: %v", err)
	}
}

func TestExactEntrySpelling(t *testing.T) {
	s, root, _ := fixture(t)
	for _, name := range []string{".SECRET", "PRIVATE/data", "excluded.KEY", "PUBLIC.TXT"} {
		if f, _, err := s.Open(context.Background(), name); err == nil {
			f.Close()
			t.Fatalf("accepted alternate spelling %q", name)
		}
	}
	// Mixed-case names remain accessible when the spelling is exact.
	if err := os.WriteFile(filepath.Join(root, "MixedCase.txt"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := s.Open(context.Background(), "MixedCase.txt"); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
}

func FuzzConfinedPaths(f *testing.F) {
	s, _, _ := fixture(f)
	for _, p := range []string{"public.txt", "nested folder/hello %.txt", "../outside/secret", "escape/secret", ".hidden/token", "a\\b", "a/../public.txt", "%2e%2e/secret", "\x00", "C:/Windows", "/etc/passwd", "a//b"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		clean, err := Normalize(p)
		if err == nil {
			if strings.HasPrefix(clean, "/") || strings.Contains(clean, "\\") || strings.Contains(clean, "\x00") {
				t.Fatal("unsafe normalization")
			}
		}
		file, _, err := s.Open(context.Background(), p)
		if err != nil {
			return
		}
		defer file.Close()
		body, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "public" {
			t.Fatalf("policy/confinement bypass for %q: %q", p, body)
		}
	})
}
