package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/config"
	"fileshare/internal/files"
	"fileshare/internal/security"
	"fileshare/internal/server"
	"fileshare/internal/telemetry"
)

// Prepare validates owner-controlled resources before acquiring a password.
func Prepare(c config.Config) (config.Config, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	dir, err := filepath.Abs(c.Directory)
	if err != nil {
		return c, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return c, fmt.Errorf("resolve shared directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return c, errors.New("shared path must be an accessible directory")
	}
	c.Directory = dir
	for _, name := range []string{c.KeyFile, c.PasswordFile} {
		if name == "" {
			continue
		}
		full, e := filepath.Abs(name)
		if e != nil {
			return c, e
		}
		full, e = filepath.EvalSymlinks(full)
		if e != nil {
			return c, e
		}
		if config.Contains(dir, full) {
			return c, errors.New("TLS private key and password file must be stored outside the shared directory")
		}
	}
	if _, err := security.TLSConfig(c); err != nil {
		return c, err
	}
	return c, nil
}

func New(c config.Config, password []byte, log *slog.Logger) (*App, error) {
	prepared, err := Prepare(c)
	if err != nil {
		return nil, err
	}
	c = prepared
	tlsConfig, err := security.TLSConfig(c)
	if err != nil {
		return nil, err
	}
	fs, err := files.New(c.Directory, files.Policy{Excludes: c.Excludes}, c.MaxEntries)
	if err != nil {
		return nil, err
	}
	verifier, err := auth.NewPassword(password)
	if err != nil {
		_ = fs.Close()
		return nil, err
	}
	sessions := auth.NewStore(c.MaxSessions, c.SessionIdle, c.SessionAbsolute)
	guard := security.NewGuard(c, time.Now())
	guard.Log = log
	metrics := &telemetry.Metrics{}
	handler, err := server.New(c, server.Dependencies{Authenticator: verifier, Sessions: sessions, Guard: guard, Files: fs, Log: log, Metrics: metrics})
	if err != nil {
		_ = fs.Close()
		return nil, err
	}
	return &App{cfg: c, server: handler, files: fs, sessions: sessions, guard: guard, metrics: metrics, tls: tlsConfig, log: log}, nil
}
