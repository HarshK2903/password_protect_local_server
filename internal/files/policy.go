package files

import (
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

var ErrDenied = errors.New("file is unavailable")
var ErrTooLarge = errors.New("directory exceeds configured entry limit")

// Normalize accepts logical relative slash paths, never operating-system paths.
// Reject rather than clean traversal; every component is checked again on open.
func Normalize(name string) (string, error) {
	if name == "" || name == "." {
		return ".", nil
	}
	if len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return "", ErrDenied
	}
	parts := strings.Split(name, "/")
	if len(parts) > 128 {
		return "", ErrDenied
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasSuffix(p, ".") || strings.HasSuffix(p, " ") {
			return "", ErrDenied
		}
		for _, c := range p {
			if c < 32 || c == 127 {
				return "", ErrDenied
			}
		}
	}
	return name, nil
}

type Policy struct{ Excludes []string }

func (p Policy) Allow(name string) bool {
	clean, err := Normalize(name)
	if err != nil {
		return false
	}
	if clean == "." {
		return true
	}
	parts := strings.Split(clean, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, ".") {
			return false
		}
		// Check ancestors too: excluding a directory excludes every descendant.
		prefix := strings.Join(parts[:i+1], "/")
		for _, pattern := range p.Excludes {
			if match, _ := path.Match(pattern, prefix); match {
				return false
			}
			if !strings.Contains(pattern, "/") {
				if match, _ := path.Match(pattern, part); match {
					return false
				}
			}
		}
	}
	return true
}
