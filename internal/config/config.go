package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Directory, Bind, Hostname, CertFile, KeyFile, PasswordFile              string
	Port                                                                    int
	Excludes                                                                []string
	TrustedProxies                                                          []netip.Prefix
	MaxFailures, PerIPConcurrent, GlobalAuthConcurrent, MaxIPs, MaxSessions int
	MaxConnections, MaxRequests, MaxTransfers, MaxEntries                   int
	IPRate, GlobalAuthRate                                                  float64 // attempts per second
	IPBurst, GlobalAuthBurst                                                int
	FailureWindow, Cooldown, MaxCooldown, ViolationTTL, IPTTL               time.Duration
	SessionIdle, SessionAbsolute, MaintenanceInterval, ShutdownTimeout      time.Duration
	ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout               time.Duration
}

func Default() Config {
	return Config{
		Bind: "127.0.0.1", Port: 8000,
		MaxFailures: 5, PerIPConcurrent: 1, GlobalAuthConcurrent: 2,
		MaxIPs: 4096, MaxSessions: 1024, MaxConnections: 128, MaxRequests: 64,
		MaxTransfers: 8, MaxEntries: 10000,
		IPRate: 10.0 / 60, IPBurst: 5, GlobalAuthRate: 30.0 / 60, GlobalAuthBurst: 5,
		FailureWindow: 10 * time.Minute, Cooldown: 15 * time.Minute, MaxCooldown: time.Hour,
		ViolationTTL: 24 * time.Hour, IPTTL: 24 * time.Hour,
		SessionIdle: 30 * time.Minute, SessionAbsolute: 8 * time.Hour,
		MaintenanceInterval: time.Minute, ShutdownTimeout: 15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Minute, IdleTimeout: time.Minute,
	}
}

func (c Config) Validate() error {
	ip, err := netip.ParseAddr(c.Bind)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
		return errors.New("--bind must be a specific IP address (use loopback or a selected LAN interface)")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if c.Directory == "" {
		return errors.New("a shared directory is required")
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("HTTPS requires --cert and --key; clients must trust the issuing CA")
	}
	if c.Hostname != "" && (strings.ContainsAny(c.Hostname, "/\\: \t\r\n") || strings.HasSuffix(c.Hostname, ".")) {
		return errors.New("hostname must be a plain DNS hostname")
	}
	counts := []int{c.MaxFailures, c.PerIPConcurrent, c.GlobalAuthConcurrent, c.MaxIPs, c.MaxSessions, c.MaxConnections, c.MaxRequests, c.MaxTransfers, c.MaxEntries, c.IPBurst, c.GlobalAuthBurst}
	for _, n := range counts {
		if n <= 0 || n > 1_000_000 {
			return errors.New("resource limits must be positive and at most 1000000")
		}
	}
	if c.MaxFailures > 100 || c.GlobalAuthConcurrent > 32 || c.PerIPConcurrent > c.MaxFailures {
		return errors.New("invalid authentication concurrency or failure limit (maximum 100 failures, 32 global verifications)")
	}
	for _, d := range []time.Duration{c.FailureWindow, c.Cooldown, c.MaxCooldown, c.ViolationTTL, c.IPTTL, c.SessionIdle, c.SessionAbsolute, c.MaintenanceInterval, c.ShutdownTimeout, c.ReadHeaderTimeout, c.ReadTimeout, c.WriteTimeout, c.IdleTimeout} {
		if d <= 0 || d > 365*24*time.Hour {
			return errors.New("durations must be positive and at most one year")
		}
	}
	if c.MaxCooldown < c.Cooldown || c.ViolationTTL < c.MaxCooldown || c.IPTTL < c.ViolationTTL || c.SessionIdle > c.SessionAbsolute {
		return errors.New("inconsistent cooldown, history, IP lifetime, or session durations")
	}
	if !(c.IPRate > 0 && c.IPRate <= 10000 && c.GlobalAuthRate > 0 && c.GlobalAuthRate <= 10000) {
		return errors.New("rates must be positive and at most 10000 per second")
	}
	for _, pattern := range c.Excludes {
		if pattern == "" || strings.HasPrefix(pattern, "/") || strings.Contains(pattern, "\\") {
			return fmt.Errorf("invalid exclude pattern %q", pattern)
		}
		if _, err := path.Match(pattern, "check"); err != nil {
			return fmt.Errorf("invalid exclude pattern: %w", err)
		}
	}
	return nil
}

// Contains is used only to reject owner-supplied secret locations, never to open client paths.
func Contains(directory, name string) bool {
	rel, err := filepath.Rel(directory, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
