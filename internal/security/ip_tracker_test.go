package security

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"fileshare/internal/config"
)

func testGuard(now time.Time) *Guard {
	c := config.Default()
	c.IPBurst = 1000
	c.GlobalAuthBurst = 1000
	c.IPRate = 1000
	c.GlobalAuthRate = 1000
	return NewGuard(c, now)
}
func failAttempt(t *testing.T, g *Guard, ip netip.Addr, now time.Time) time.Duration {
	t.Helper()
	a, err := g.Begin(context.Background(), ip, now)
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	return a.Finish(&ok, now)
}

func TestCooldownEscalationAndExpiration(t *testing.T) {
	now := time.Unix(1000, 0)
	g := testGuard(now)
	ip := netip.MustParseAddr("192.0.2.1")
	for _, want := range []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, time.Hour} {
		for i := 0; i < 4; i++ {
			if d := failAttempt(t, g, ip, now); d != 0 {
				t.Fatal("early cooldown")
			}
		}
		if d := failAttempt(t, g, ip, now); d != want {
			t.Fatalf("got cooldown %v want %v", d, want)
		}
		_, err := g.Begin(context.Background(), ip, now.Add(time.Second))
		var denied *AdmissionError
		if !errors.As(err, &denied) || denied.Retry != want-time.Second {
			t.Fatalf("bad retry: %v", err)
		}
		now = now.Add(want)
	}
	now = now.Add(24 * time.Hour)
	for i := 0; i < 4; i++ {
		failAttempt(t, g, ip, now)
	}
	if d := failAttempt(t, g, ip, now); d != 15*time.Minute {
		t.Fatalf("history did not expire: %v", d)
	}
}

func TestFailureWindowAndSuccess(t *testing.T) {
	now := time.Now()
	g := testGuard(now)
	ip := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 4; i++ {
		failAttempt(t, g, ip, now)
	}
	now = now.Add(10 * time.Minute)
	if d := failAttempt(t, g, ip, now); d != 0 {
		t.Fatal("old failures not pruned")
	}
	a, err := g.Begin(context.Background(), ip, now)
	if err != nil {
		t.Fatal(err)
	}
	ok := true
	a.Finish(&ok, now)
	for i := 0; i < 4; i++ {
		if d := failAttempt(t, g, ip, now); d != 0 {
			t.Fatal("success did not clear failures")
		}
	}
}

func TestConcurrentReservationsAndGlobalBound(t *testing.T) {
	now := time.Now()
	g := testGuard(now)
	g.cfg.PerIPConcurrent = 5
	g.cfg.GlobalAuthConcurrent = 5
	ip := netip.MustParseAddr("192.0.2.1")
	var wg sync.WaitGroup
	attempts := make(chan *Attempt, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := g.Begin(context.Background(), ip, now)
			if err == nil {
				attempts <- a
			}
		}()
	}
	wg.Wait()
	close(attempts)
	if len(attempts) != 5 {
		t.Fatalf("parallel bypass: admitted %d", len(attempts))
	}
	if _, err := g.Begin(context.Background(), netip.MustParseAddr("192.0.2.2"), now); err == nil {
		t.Fatal("global bound exceeded")
	}
	var durationsMu sync.Mutex
	cooldowns := 0
	for a := range attempts {
		wg.Add(1)
		go func(a *Attempt) {
			defer wg.Done()
			ok := false
			d := a.Finish(&ok, now)
			a.Finish(&ok, now)
			if d > 0 {
				durationsMu.Lock()
				cooldowns++
				durationsMu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	if cooldowns != 1 || g.active != 0 {
		t.Fatalf("transition/release broken: %d cooldowns, %d active", cooldowns, g.active)
	}
	if _, err := g.Begin(context.Background(), ip, now); err == nil {
		t.Fatal("cooldown bypassed")
	}
}

func TestBoundedStateAndCleanup(t *testing.T) {
	now := time.Now()
	g := testGuard(now)
	g.cfg.MaxIPs = 1
	ip := netip.MustParseAddr("192.0.2.1")
	a, err := g.Begin(context.Background(), ip, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Begin(context.Background(), netip.MustParseAddr("192.0.2.2"), now); err == nil {
		t.Fatal("IP cap exceeded")
	}
	if g.Cleanup(now.Add(48*time.Hour)) != 0 {
		t.Fatal("removed in-flight state")
	}
	a.Finish(nil, now)
	if g.Cleanup(now.Add(48*time.Hour)) != 1 || g.Count() != 0 {
		t.Fatal("stale state retained")
	}
	g.Stop()
	if _, err := g.Begin(context.Background(), ip, now); err == nil {
		t.Fatal("admitted during shutdown")
	}
}

func TestIPAndGlobalRates(t *testing.T) {
	now := time.Now()
	g := testGuard(now)
	g.cfg.IPBurst = 1
	g.cfg.IPRate = 1
	g.cfg.GlobalAuthBurst = 1
	g.global = newBucket(now, 1)
	g.cfg.GlobalAuthRate = 1
	ip := netip.MustParseAddr("192.0.2.1")
	a, err := g.Begin(context.Background(), ip, now)
	if err != nil {
		t.Fatal(err)
	}
	a.Finish(nil, now)
	if _, err := g.Begin(context.Background(), ip, now); err == nil {
		t.Fatal("IP rate bypassed")
	}
	if _, err := g.Begin(context.Background(), netip.MustParseAddr("192.0.2.2"), now); err == nil {
		t.Fatal("global rate bypassed")
	}
	a, err = g.Begin(context.Background(), ip, now.Add(time.Second))
	if err != nil {
		t.Fatal("did not refill", err)
	}
	a.Finish(nil, now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Begin(ctx, ip, now); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
}
