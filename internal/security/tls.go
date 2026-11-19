package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"fileshare/internal/config"
)

func TLSConfig(c config.Config) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("TLS certificate is not currently valid")
	}
	identity := c.Hostname
	if identity == "" {
		identity = c.Bind
	}
	if err := leaf.VerifyHostname(identity); err != nil {
		return nil, fmt.Errorf("TLS certificate must cover %s: %w", identity, err)
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				ok = true
			}
		}
		if !ok {
			return nil, errors.New("TLS certificate does not permit server authentication")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}, nil
}
