package security

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPTrustBoundary(t *testing.T) {
	cases := []struct {
		peer, forwarded string
		trust           []netip.Prefix
		want            string
		bad             bool
	}{
		{"192.0.2.1:22", "198.51.100.1", nil, "192.0.2.1", false},
		{"[::ffff:192.0.2.1]:22", "spoof", nil, "192.0.2.1", false},
		{"[2001:db8::1]:22", "", nil, "2001:db8::1", false},
		{"127.0.0.1:22", "198.51.100.9, 192.0.2.1, 127.0.0.2", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, "192.0.2.1", false},
		{"127.0.0.1:22", "forged", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, "", true},
		{"invalid", "", nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.peer+tc.forwarded, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://localhost/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			got, err := (ClientIPs{Trusted: tc.trust}).Resolve(r)
			if tc.bad {
				if err == nil {
					t.Fatal("expected rejection")
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("got %v %v", got, err)
			}
		})
	}
}
