package security

import "time"

// bucket is protected by its owner's mutex. Rejected attempts do not extend refill time.
type bucket struct {
	tokens  float64
	updated time.Time
}

func newBucket(now time.Time, burst int) bucket { return bucket{tokens: float64(burst), updated: now} }
func (b *bucket) allow(now time.Time, rate float64, burst int) bool {
	if now.After(b.updated) {
		b.tokens = min(float64(burst), b.tokens+now.Sub(b.updated).Seconds()*rate)
		b.updated = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
