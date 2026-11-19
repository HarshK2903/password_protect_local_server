package app

import (
	"crypto/tls"
	"log/slog"

	"fileshare/internal/auth"
	"fileshare/internal/config"
	"fileshare/internal/files"
	"fileshare/internal/security"
	"fileshare/internal/server"
	"fileshare/internal/telemetry"
)

type App struct {
	cfg      config.Config
	server   *server.Server
	files    *files.Service
	sessions *auth.Store
	guard    *security.Guard
	metrics  *telemetry.Metrics
	tls      *tls.Config
	log      *slog.Logger
}
