package security

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type ClientIPs struct{ Trusted []netip.Prefix }

func (c ClientIPs) trusted(ip netip.Addr) bool {
	for _, p := range c.Trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (c ClientIPs) Resolve(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errors.New("invalid peer address")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	ip = ip.Unmap()
	if !c.trusted(ip) {
		return ip, nil
	} // Forwarded and X-Real-IP are deliberately ignored.
	raw := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if raw == "" {
		return ip, nil
	}
	if len(raw) > 1024 {
		return netip.Addr{}, errors.New("forwarded chain too long")
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 16 {
		return netip.Addr{}, errors.New("forwarded chain too long")
	}
	chain := make([]netip.Addr, len(parts))
	for i, s := range parts {
		a, e := netip.ParseAddr(strings.TrimSpace(s))
		if e != nil || a.Zone() != "" {
			return netip.Addr{}, errors.New("invalid forwarded address")
		}
		chain[i] = a.Unmap()
	}
	for i := len(chain) - 1; i >= 0 && c.trusted(ip); i-- {
		ip = chain[i]
	}
	return ip, nil
}
