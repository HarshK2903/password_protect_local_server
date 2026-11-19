package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"

	"fileshare/internal/maintenance"
	"fileshare/internal/server"
)

func (a *App) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(a.cfg.Bind, strconv.Itoa(a.cfg.Port)))
	if err != nil {
		_ = a.files.Close()
		return fmt.Errorf("listen: %w", err)
	}
	return a.Serve(ctx, listener)
}

// Serve owns listener and the filesystem until shutdown. Exposing it separately
// lets integration tests use an OS-assigned port with the real TLS lifecycle.
func (a *App) Serve(ctx context.Context, listener net.Listener) error {
	defer a.files.Close()
	requestCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	maintenanceCtx, cancelMaintenance := context.WithCancel(context.Background())
	var maintenanceWG sync.WaitGroup
	maintenanceWG.Add(1)
	go func() {
		defer maintenanceWG.Done()
		maintenance.Run(maintenanceCtx, a.cfg.MaintenanceInterval, a.sessions, a.guard, a.metrics, a.log)
	}()
	defer func() { cancelMaintenance(); maintenanceWG.Wait() }()
	h := &http.Server{
		Handler: a.server.Handler(), TLSConfig: a.tls,
		ReadHeaderTimeout: a.cfg.ReadHeaderTimeout, ReadTimeout: a.cfg.ReadTimeout,
		WriteTimeout: a.cfg.WriteTimeout, IdleTimeout: a.cfg.IdleTimeout, MaxHeaderBytes: 16 * 1024,
		BaseContext:  func(net.Listener) context.Context { return requestCtx },
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ErrorLog:     slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
	}
	result := make(chan error, 1)
	bounded := server.LimitListener(listener, a.cfg.MaxConnections)
	go func() { result <- h.Serve(tls.NewListener(bounded, a.tls)) }()
	identity := a.cfg.Hostname
	if identity == "" {
		identity = a.cfg.Bind
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	a.log.Info("server_started", "url", "https://"+net.JoinHostPort(identity, port), "directory", a.cfg.Directory, "read_only", true, "max_connections", a.cfg.MaxConnections)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-result:
	}
	a.log.Info("shutdown_started")
	a.server.StopAdmissions()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), a.cfg.ShutdownTimeout)
	err := h.Shutdown(shutdownCtx)
	cancelShutdown()
	if err != nil {
		a.log.Warn("shutdown_deadline_reached")
		cancelRequests()
		_ = h.Close()
	}
	// An in-progress Argon2 call cannot be interrupted; its global bounded work
	// finishes before dependencies close. No new verifications are admitted.
	a.server.Wait()
	cancelRequests()
	cancelMaintenance()
	maintenanceWG.Wait()
	a.metrics.Log(a.log, a.sessions.Count(), a.guard.Count())
	a.log.Info("server_stopped")
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
