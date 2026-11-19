package telemetry

import (
	"io"
	"log/slog"
	"runtime"
	"sync/atomic"
)

func Logger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type Metrics struct {
	Requests, LoginSuccess, LoginFailure, Rejected, Bytes atomic.Int64
	ActiveRequests, ActiveDownloads                       atomic.Int64
}

func (m *Metrics) Log(log *slog.Logger, sessions, ips int) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	log.Info("resource_snapshot", "requests", m.Requests.Load(), "active_requests", m.ActiveRequests.Load(), "active_downloads", m.ActiveDownloads.Load(), "bytes_sent", m.Bytes.Load(), "login_success", m.LoginSuccess.Load(), "login_failure", m.LoginFailure.Load(), "admission_rejections", m.Rejected.Load(), "sessions", sessions, "tracked_ips", ips, "heap_bytes", mem.HeapAlloc, "goroutines", runtime.NumGoroutine())
}
