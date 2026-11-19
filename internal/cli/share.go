package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"fileshare/internal/config"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func ParseShare(args []string, output io.Writer) (config.Config, error) {
	c := config.Default()
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintln(output, "Usage: fileshare share DIRECTORY --cert FILE --key FILE [options]")
		fs.PrintDefaults()
	}
	authEnabled, readOnly := true, true
	var excludes, proxies stringsFlag
	fs.StringVar(&c.Bind, "bind", c.Bind, "specific interface IP (never a wildcard)")
	fs.IntVar(&c.Port, "port", c.Port, "HTTPS port")
	fs.StringVar(&c.Hostname, "hostname", "", "certificate DNS hostname instead of the bind IP")
	fs.StringVar(&c.CertFile, "cert", "", "PEM server certificate and intermediate chain")
	fs.StringVar(&c.KeyFile, "key", "", "PEM private key, outside the shared directory")
	fs.StringVar(&c.PasswordFile, "password-file", "", "owner-only password file; otherwise prompt without echo")
	fs.BoolVar(&authEnabled, "auth", true, "require authentication (mandatory)")
	fs.BoolVar(&readOnly, "read-only", true, "read-only access (mandatory)")
	fs.Var(&excludes, "exclude", "exclude a path or component glob; repeatable, e.g. '*.key' or 'private'")
	fs.Var(&proxies, "trusted-proxy", "trusted reverse proxy CIDR; repeatable (X-Forwarded-For only)")
	fs.IntVar(&c.MaxFailures, "max-failures", c.MaxFailures, "failed logins before cooldown")
	fs.DurationVar(&c.FailureWindow, "failure-window", c.FailureWindow, "sliding failed-login window")
	fs.DurationVar(&c.Cooldown, "cooldown", c.Cooldown, "initial login cooldown")
	fs.DurationVar(&c.MaxCooldown, "max-cooldown", c.MaxCooldown, "maximum escalated cooldown")
	fs.DurationVar(&c.ViolationTTL, "violation-ttl", c.ViolationTTL, "time since last violation before escalation resets")
	fs.DurationVar(&c.IPTTL, "ip-ttl", c.IPTTL, "inactive IP record retention (at least violation-ttl)")
	fs.IntVar(&c.PerIPConcurrent, "auth-per-ip", c.PerIPConcurrent, "concurrent password verifications per IP")
	fs.IntVar(&c.GlobalAuthConcurrent, "auth-concurrency", c.GlobalAuthConcurrent, "global concurrent verifications (64 MiB each)")
	ipPerMinute, globalPerMinute := c.IPRate*60, c.GlobalAuthRate*60
	fs.Float64Var(&ipPerMinute, "login-rate", ipPerMinute, "login attempts per minute per IP")
	fs.IntVar(&c.IPBurst, "login-burst", c.IPBurst, "per-IP login burst")
	fs.Float64Var(&globalPerMinute, "global-login-rate", globalPerMinute, "global password verifications per minute")
	fs.IntVar(&c.GlobalAuthBurst, "global-login-burst", c.GlobalAuthBurst, "global verification burst")
	fs.IntVar(&c.MaxIPs, "max-ips", c.MaxIPs, "maximum tracked IP records; fail closed at capacity")
	fs.IntVar(&c.MaxSessions, "max-sessions", c.MaxSessions, "maximum active sessions")
	fs.IntVar(&c.MaxConnections, "max-connections", c.MaxConnections, "maximum accepted TCP connections")
	fs.IntVar(&c.MaxRequests, "max-requests", c.MaxRequests, "maximum concurrent HTTP handlers")
	fs.IntVar(&c.MaxTransfers, "max-transfers", c.MaxTransfers, "maximum concurrent downloads")
	fs.IntVar(&c.MaxEntries, "max-entries", c.MaxEntries, "maximum scanned entries per directory listing")
	fs.DurationVar(&c.SessionIdle, "session-idle", c.SessionIdle, "session idle timeout")
	fs.DurationVar(&c.SessionAbsolute, "session-lifetime", c.SessionAbsolute, "absolute session lifetime")
	fs.DurationVar(&c.ReadHeaderTimeout, "header-timeout", c.ReadHeaderTimeout, "request header / TLS handshake timeout")
	fs.DurationVar(&c.ReadTimeout, "read-timeout", c.ReadTimeout, "complete request read timeout")
	fs.DurationVar(&c.WriteTimeout, "transfer-timeout", c.WriteTimeout, "maximum response/transfer duration")
	fs.DurationVar(&c.IdleTimeout, "idle-timeout", c.IdleTimeout, "HTTP connection idle timeout")
	fs.DurationVar(&c.MaintenanceInterval, "cleanup-interval", c.MaintenanceInterval, "session/IP cleanup and metrics interval")
	fs.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", c.ShutdownTimeout, "grace period before cancelling active requests")
	// flag supports interspersed options after a leading directory explicitly.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		c.Directory = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.Directory == "" && fs.NArg() == 1 {
		c.Directory = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return c, errors.New("provide exactly one directory; place options together before or after it")
	}
	if !authEnabled || !readOnly {
		return c, errors.New("authentication and read-only access cannot be disabled")
	}
	c.Excludes = excludes
	c.IPRate = ipPerMinute / 60
	c.GlobalAuthRate = globalPerMinute / 60
	for _, s := range proxies {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return c, fmt.Errorf("invalid trusted proxy CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return c, errors.New("invalid mapped IPv4 proxy prefix")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		c.TrustedProxies = append(c.TrustedProxies, p.Masked())
	}
	return c, c.Validate()
}
