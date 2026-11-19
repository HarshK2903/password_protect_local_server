package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var ErrSessionCapacity = errors.New("session capacity reached")

type Session struct {
	Created, LastSeen, Expires time.Time
	ReadOnly                   bool
}

type SessionStore interface {
	Create(time.Time) (string, Session, error)
	Validate(string, time.Time) (Session, bool)
	Revoke(string)
	Cleanup(time.Time) int
	Count() int
}

type Store struct {
	mu             sync.Mutex
	sessions       map[[32]byte]Session
	max            int
	idle, absolute time.Duration
}

func NewStore(max int, idle, absolute time.Duration) *Store {
	return &Store{sessions: make(map[[32]byte]Session), max: max, idle: idle, absolute: absolute}
}

func (s *Store) Create(now time.Time) (string, Session, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", Session{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	clear(raw[:])
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.max {
		s.cleanup(now)
	}
	if len(s.sessions) >= s.max {
		return "", Session{}, ErrSessionCapacity
	}
	v := Session{Created: now, LastSeen: now, Expires: now.Add(s.absolute), ReadOnly: true}
	s.sessions[hash] = v
	return token, v, nil
}

func (s *Store) Validate(token string, now time.Time) (Session, bool) {
	if len(token) != 43 {
		return Session{}, false
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[hash]
	if !ok {
		return Session{}, false
	}
	if !now.Before(v.Expires) || now.Sub(v.LastSeen) >= s.idle || !v.ReadOnly {
		delete(s.sessions, hash)
		return Session{}, false
	}
	v.LastSeen = now
	s.sessions[hash] = v
	return v, true
}

func (s *Store) Revoke(token string) {
	hash := sha256.Sum256([]byte(token))
	s.mu.Lock()
	delete(s.sessions, hash)
	s.mu.Unlock()
}

func (s *Store) cleanup(now time.Time) int {
	n := 0
	for k, v := range s.sessions {
		if !now.Before(v.Expires) || now.Sub(v.LastSeen) >= s.idle {
			delete(s.sessions, k)
			n++
		}
	}
	return n
}
func (s *Store) Cleanup(now time.Time) int { s.mu.Lock(); defer s.mu.Unlock(); return s.cleanup(now) }
func (s *Store) Count() int                { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sessions) }
