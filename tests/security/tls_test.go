package security_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"fileshare/internal/config"
	"fileshare/internal/security"
	"fileshare/internal/testutil"
)

func TestTLSIdentityAndValidity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*x509.Certificate)
		host  string
		valid bool
	}{
		{"IP SAN", nil, "", true},
		{"DNS SAN", nil, "fileshare.test", true},
		{"wrong hostname", nil, "other.test", false},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, "", false},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, "", false},
		{"wrong usage", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := testutil.Cert(t, tc.edit)
			c := config.Default()
			c.CertFile = cert.CertFile
			c.KeyFile = cert.KeyFile
			c.Hostname = tc.host
			cfg, err := security.TLSConfig(c)
			if (err == nil) != tc.valid {
				t.Fatal("unexpected validation", err)
			}
			if err == nil && cfg.MinVersion != tls.VersionTLS13 {
				t.Fatal("weak TLS floor")
			}
		})
	}
	cert := testutil.Cert(t, nil)
	other := testutil.Cert(t, nil)
	c := config.Default()
	c.CertFile = cert.CertFile
	c.KeyFile = other.KeyFile
	if _, err := security.TLSConfig(c); err == nil {
		t.Fatal("mismatched private key accepted")
	}
}
