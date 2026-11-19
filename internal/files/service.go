package files

import (
	"context"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Directory bool      `json:"directory"`
	Size      int64     `json:"size"`
	Modified  time.Time `json:"modified"`
}

type FileService interface {
	List(context.Context, string) ([]Entry, error)
	Open(context.Context, string) (*os.File, os.FileInfo, error)
}

type Service struct {
	root       *os.Root
	policy     Policy
	maxEntries int
}

func New(directory string, policy Policy, maxEntries int) (*Service, error) {
	r, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &Service{root: r, policy: policy, maxEntries: maxEntries}, nil
}
func (s *Service) Close() error { return s.root.Close() }

// open walks retained directory handles, comparing Lstat identity with the
// opened descriptor at each step. Symlinks (even inside the root) are refused,
// so aliases cannot bypass hidden-file/exclusion policy. os.Root independently
// enforces confinement if the host concurrently changes the directory tree.
func (s *Service) open(ctx context.Context, name string, checkNames bool) (*os.File, os.FileInfo, error) {
	name, err := Normalize(name)
	if err != nil || !s.policy.Allow(name) {
		return nil, nil, ErrDenied
	}
	current := s.root
	defer func() {
		if current != s.root {
			_ = current.Close()
		}
	}()
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if checkNames && part != "." {
			if err := s.exactName(ctx, current, part); err != nil {
				return nil, nil, err
			}
		}
		before, err := current.Lstat(part)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || (!before.IsDir() && !before.Mode().IsRegular()) {
			return nil, nil, ErrDenied
		}
		if i < len(parts)-1 {
			if !before.IsDir() {
				return nil, nil, ErrDenied
			}
			next, err := current.OpenRoot(part)
			if err != nil {
				return nil, nil, ErrDenied
			}
			after, err := next.Stat(".")
			if err != nil || !os.SameFile(before, after) {
				_ = next.Close()
				return nil, nil, ErrDenied
			}
			if current != s.root {
				_ = current.Close()
			}
			current = next
			continue
		}
		f, err := openRead(current, part)
		if err != nil {
			return nil, nil, ErrDenied
		}
		after, err := f.Stat()
		if err != nil || !os.SameFile(before, after) || (!after.IsDir() && !after.Mode().IsRegular()) {
			_ = f.Close()
			return nil, nil, ErrDenied
		}
		return f, after, nil
	}
	return nil, nil, ErrDenied
}

func (s *Service) Open(ctx context.Context, name string) (*os.File, os.FileInfo, error) {
	f, info, err := s.open(ctx, name, true)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, ErrDenied
	}
	return f, info, nil
}

func (s *Service) List(ctx context.Context, name string) ([]Entry, error) {
	f, info, err := s.open(ctx, name, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if !info.IsDir() {
		return nil, ErrDenied
	}
	entries := make([]Entry, 0)
	scanned := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, err := f.ReadDir(128)
		for _, d := range batch {
			scanned++
			if scanned > s.maxEntries {
				return nil, ErrTooLarge
			}
			logical := path.Join(name, d.Name())
			if !s.policy.Allow(logical) || d.Type()&os.ModeSymlink != 0 {
				continue
			}
			// Metadata comes from the confined descriptor, never DirEntry.Info
			// (whose parent may have been renamed after ReadDir).
			// These spellings came from ReadDir under an already checked parent;
			// avoid rescanning the same parent for every entry in a listing.
			child, stat, e := s.open(ctx, logical, false)
			if e != nil {
				continue
			}
			_ = child.Close()
			entries = append(entries, Entry{Name: d.Name(), Path: logical, Directory: stat.IsDir(), Size: stat.Size(), Modified: stat.ModTime().UTC()})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Directory != entries[j].Directory {
			return entries[i].Directory
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// exactName rejects filesystem aliases (case folding, Unicode normalization,
// Windows short names) before opening client-supplied components. Policy sees
// only the real entry spelling. Scans are bounded even for direct downloads.
func (s *Service) exactName(ctx context.Context, root *os.Root, name string) error {
	f, err := root.Open(".")
	if err != nil {
		return ErrDenied
	}
	defer f.Close()
	scanned := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch, err := f.ReadDir(128)
		for _, entry := range batch {
			scanned++
			if scanned > s.maxEntries {
				return ErrTooLarge
			}
			if entry.Name() == name {
				return nil
			}
		}
		if err != nil {
			return ErrDenied
		}
	}
}
