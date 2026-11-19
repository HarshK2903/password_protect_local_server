package maintenance

import (
	"context"
	"log/slog"
	"time"

	"fileshare/internal/auth"
	"fileshare/internal/security"
	"fileshare/internal/telemetry"
)

func Run(ctx context.Context, interval time.Duration, sessions auth.SessionStore, guard security.IPGuard, metrics *telemetry.Metrics, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := sessions.Cleanup(now)
			removed := guard.Cleanup(now)
			log.Info("maintenance", "expired_sessions", expired, "removed_ips", removed)
			metrics.Log(log, sessions.Count(), guard.Count())
		}
	}
}
