package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/argon2"
)

type Authenticator interface{ Verify([]byte) bool }

// Password keeps only the salted verifier. Each verification consumes 64 MiB;
// callers must acquire the global admission permit before invoking Verify.
type Password struct {
	salt [16]byte
	hash []byte
}

func NewPassword(password []byte) (*Password, error) {
	if len(password) < 12 || len(password) > 1024 {
		return nil, errors.New("password must contain 12 to 1024 bytes")
	}
	p := &Password{}
	if _, err := rand.Read(p.salt[:]); err != nil {
		return nil, err
	}
	p.hash = argon2.IDKey(password, p.salt[:], 3, 64*1024, 2, 32)
	return p, nil
}

func (p *Password) Verify(password []byte) bool {
	if len(password) > 1024 {
		return false
	}
	hash := argon2.IDKey(password, p.salt[:], 3, 64*1024, 2, 32)
	defer clear(hash)
	return subtle.ConstantTimeCompare(hash, p.hash) == 1
}
