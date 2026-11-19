package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

func ReadPassword(file string, input *os.File, output io.Writer) ([]byte, error) {
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("password file must be a regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("password file must have owner-only permissions (chmod 600)")
		}
		p, err := io.ReadAll(io.LimitReader(f, 1027))
		if err != nil {
			return nil, err
		}
		p = trimLineEnding(p)
		if len(p) < 12 || len(p) > 1024 {
			clear(p)
			return nil, errors.New("password must contain 12 to 1024 bytes")
		}
		return p, nil
	}
	if !term.IsTerminal(int(input.Fd())) {
		return nil, errors.New("a terminal is required for a hidden password prompt; use --password-file for unattended operation")
	}
	fmt.Fprint(output, "Sharing password (12+ bytes): ")
	p, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(output)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(output, "Confirm password: ")
	confirmation, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(output)
	defer clear(confirmation)
	if err != nil {
		clear(p)
		return nil, err
	}
	if string(p) != string(confirmation) {
		clear(p)
		return nil, errors.New("passwords do not match")
	}
	if len(p) < 12 || len(p) > 1024 {
		clear(p)
		return nil, errors.New("password must contain 12 to 1024 bytes")
	}
	return p, nil
}

func trimLineEnding(p []byte) []byte {
	if len(p) > 0 && p[len(p)-1] == '\n' {
		p = p[:len(p)-1]
		if len(p) > 0 && p[len(p)-1] == '\r' {
			p = p[:len(p)-1]
		}
	}
	return p
}
