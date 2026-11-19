//go:build unix

package files

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSymlinkSwapNeverEscapes(t *testing.T) {
	s, root, outside := fixture(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "replacement"))
			_ = os.Rename(filepath.Join(root, "replacement"), filepath.Join(root, "race"))
			_ = os.Remove(filepath.Join(root, "race"))
			_ = os.WriteFile(filepath.Join(root, "race"), []byte("public"), 0600)
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	for i := 0; i < 1000; i++ {
		f, _, err := s.Open(context.Background(), "race")
		if err != nil {
			continue
		}
		body, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) == "outside" {
			t.Fatal("escaped root during replacement")
		}
	}
}

func TestSpecialFileDoesNotBlock(t *testing.T) {
	s, root, _ := fixture(t)
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, _, err := s.Open(context.Background(), "fifo")
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("opened FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked on special file")
	}
}
