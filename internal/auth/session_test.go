package auth

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	now := time.Unix(1000, 0)
	store := NewStore(2, time.Minute, 3*time.Minute)
	token, session, err := store.Create(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 || !session.ReadOnly {
		t.Fatal("invalid session")
	}
	if _, ok := store.sessions[sha256.Sum256([]byte(token))]; !ok {
		t.Fatal("store must index hashed tokens")
	}
	if _, ok := store.Validate("forged", now); ok {
		t.Fatal("accepted forged token")
	}
	for _, offset := range []time.Duration{30 * time.Second, time.Minute, 90 * time.Second, 2 * time.Minute, 150 * time.Second} {
		if _, ok := store.Validate(token, now.Add(offset)); !ok {
			t.Fatalf("expired early at %v", offset)
		}
	}
	if _, ok := store.Validate(token, now.Add(3*time.Minute)); ok {
		t.Fatal("absolute expiry must override activity")
	}
	token, _, _ = store.Create(now)
	if _, ok := store.Validate(token, now.Add(time.Minute)); ok {
		t.Fatal("idle timeout must be enforced synchronously")
	}
	token, _, _ = store.Create(now)
	store.Revoke(token)
	if _, ok := store.Validate(token, now); ok {
		t.Fatal("revoked token accepted")
	}
}

func TestSessionCapacityConcurrent(t *testing.T) {
	s := NewStore(10, time.Minute, time.Hour)
	now := time.Now()
	var made atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.Create(now)
			if err == nil {
				made.Add(1)
			} else if err != ErrSessionCapacity {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if made.Load() != 10 || s.Count() != 10 {
		t.Fatalf("unbounded sessions: %d / %d", made.Load(), s.Count())
	}
	if _, _, err := s.Create(now.Add(time.Minute)); err != nil {
		t.Fatal("expired sessions must be reclaimed at capacity", err)
	}
	if n := s.Cleanup(now.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("cleanup removed %d", n)
	}
}

func TestArgonPassword(t *testing.T) {
	password := []byte("a secure test password")
	a, err := NewPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if a.salt == b.salt {
		t.Fatal("salt reused")
	}
	if !a.Verify(password) || a.Verify([]byte("wrong password")) {
		t.Fatal("verification failed")
	}
	if _, err := NewPassword([]byte("short")); err == nil {
		t.Fatal("accepted short password")
	}
}
