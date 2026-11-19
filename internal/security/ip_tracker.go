package security

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"fileshare/internal/config"
)

type AdmissionError struct {
	Retry    time.Duration
	Capacity bool
}

func (e *AdmissionError) Error() string { return "authentication admission denied" }

type ipState struct {
	failures                 []time.Time
	until, violationAt, last time.Time
	violations, inFlight     int
	rate                     bucket
}

type IPGuard interface {
	Begin(context.Context, netip.Addr, time.Time) (*Attempt, error)
	Cleanup(time.Time) int
	Count() int
	Stop()
}

type Guard struct {
	Log     *slog.Logger // Set once during bootstrap, before requests begin.
	mu      sync.Mutex
	cfg     config.Config
	ips     map[netip.Addr]*ipState
	global  bucket
	active  int
	stopped bool
}

func NewGuard(c config.Config, now time.Time) *Guard {
	return &Guard{cfg: c, ips: make(map[netip.Addr]*ipState), global: newBucket(now, c.GlobalAuthBurst)}
}

// Attempt reserves both per-IP and global capacity until Finish. No lock is
// held across password hashing. sync.Once makes release safe on every exit path.
type Attempt struct {
	guard *Guard
	ip    netip.Addr
	once  sync.Once
}

func (g *Guard) Begin(ctx context.Context, ip netip.Addr, now time.Time) (*Attempt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ip = ip.Unmap()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped || !ip.IsValid() {
		return nil, &AdmissionError{Retry: time.Second, Capacity: true}
	}
	s := g.ips[ip]
	if s == nil {
		if len(g.ips) >= g.cfg.MaxIPs {
			g.cleanup(now)
		}
		if len(g.ips) >= g.cfg.MaxIPs {
			return nil, &AdmissionError{Retry: time.Minute, Capacity: true}
		}
		s = &ipState{last: now, rate: newBucket(now, g.cfg.IPBurst)}
		g.ips[ip] = s
	}
	s.last = now
	g.prune(ip, s, now)
	if now.Before(s.until) {
		return nil, &AdmissionError{Retry: s.until.Sub(now)}
	}
	if !s.rate.allow(now, g.cfg.IPRate, g.cfg.IPBurst) {
		return nil, &AdmissionError{Retry: time.Duration(float64(time.Second)/g.cfg.IPRate) + time.Second}
	}
	// Reserve remaining failure budget, so parallel requests cannot exceed it.
	if s.inFlight >= g.cfg.PerIPConcurrent || len(s.failures)+s.inFlight >= g.cfg.MaxFailures {
		return nil, &AdmissionError{Retry: time.Second}
	}
	if g.active >= g.cfg.GlobalAuthConcurrent {
		return nil, &AdmissionError{Retry: time.Second, Capacity: true}
	}
	if !g.global.allow(now, g.cfg.GlobalAuthRate, g.cfg.GlobalAuthBurst) {
		return nil, &AdmissionError{Retry: time.Duration(float64(time.Second)/g.cfg.GlobalAuthRate) + time.Second}
	}
	s.inFlight++
	g.active++
	return &Attempt{guard: g, ip: ip}, nil
}

// Finish returns a newly activated cooldown duration. nil means aborted before
// a credential decision (for example a disconnected client or malformed form).
func (a *Attempt) Finish(success *bool, now time.Time) time.Duration {
	var cooldown time.Duration
	a.once.Do(func() {
		g := a.guard
		g.mu.Lock()
		defer g.mu.Unlock()
		s := g.ips[a.ip]
		s.inFlight--
		g.active--
		s.last = now
		g.prune(a.ip, s, now)
		if success == nil {
			return
		}
		if *success {
			s.failures = nil
			return
		}
		s.failures = append(s.failures, now)
		if len(s.failures) >= g.cfg.MaxFailures && !now.Before(s.until) {
			cooldown = g.cfg.Cooldown
			for i := 0; i < s.violations && cooldown < g.cfg.MaxCooldown; i++ {
				if cooldown > g.cfg.MaxCooldown/2 {
					cooldown = g.cfg.MaxCooldown
					break
				}
				cooldown *= 2
			}
			cooldown = min(cooldown, g.cfg.MaxCooldown)
			s.until = now.Add(cooldown)
			s.violations++
			s.violationAt = now
			s.failures = nil
		}
	})
	return cooldown
}

func (g *Guard) prune(ip netip.Addr, s *ipState, now time.Time) {
	// Concurrent completions can arrive in a different order from the times
	// sampled by callers; do not rely on timestamps being sorted.
	kept := s.failures[:0]
	for _, failure := range s.failures {
		if failure.After(now.Add(-g.cfg.FailureWindow)) {
			kept = append(kept, failure)
		}
	}
	clear(s.failures[len(kept):])
	s.failures = kept
	if !s.until.IsZero() && !now.Before(s.until) {
		s.until = time.Time{}
		if g.Log != nil {
			g.Log.Info("cooldown_expired", "ip", ip)
		}
	}
	if s.violations > 0 && now.Sub(s.violationAt) >= g.cfg.ViolationTTL {
		s.violations = 0
		s.violationAt = time.Time{}
	}
}
func (g *Guard) cleanup(now time.Time) int {
	n := 0
	for ip, s := range g.ips {
		g.prune(ip, s, now)
		if s.inFlight == 0 && s.until.IsZero() && s.violations == 0 && now.Sub(s.last) >= g.cfg.IPTTL {
			delete(g.ips, ip)
			n++
		}
	}
	return n
}
func (g *Guard) Cleanup(now time.Time) int { g.mu.Lock(); defer g.mu.Unlock(); return g.cleanup(now) }
func (g *Guard) Count() int                { g.mu.Lock(); defer g.mu.Unlock(); return len(g.ips) }
func (g *Guard) Stop()                     { g.mu.Lock(); g.stopped = true; g.mu.Unlock() }
