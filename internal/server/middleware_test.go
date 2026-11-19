package server

import (
	"fileshare/internal/config"
	"testing"
)

func TestHostValidation(t *testing.T) {
	for _, tc := range []struct {
		bind, hostname, host string
		want                 bool
	}{
		{"127.0.0.1", "", "127.0.0.1:8000", true},
		{"127.0.0.1", "", "evil.example:8000", false},
		{"::1", "", "[::1]:8000", true},
		{"::1", "", "[::1]", true},
		{"::1", "", "[::2]", false},
		{"127.0.0.1", "fileshare.test", "FILESHARE.TEST:443", true},
		{"127.0.0.1", "fileshare.test", "127.0.0.1:8000", false},
		{"127.0.0.1", "", "127.0.0.1:bad", false},
		{"127.0.0.1", "", "127.0.0.1:", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			c := config.Default()
			c.Bind = tc.bind
			c.Hostname = tc.hostname
			s := &Server{cfg: c}
			if got := s.validHost(tc.host); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
