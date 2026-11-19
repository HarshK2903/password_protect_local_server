package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fileshare/internal/security"
)

type contextKey int

const (
	ipKey contextKey = iota
	tokenKey
)

type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	// ServeContent removes some headers on range errors; private responses must
	// retain their cache policy on every status, including 304 and 416.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.ResponseWriter.WriteHeader(code)
}
func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w}
		registered := false
		s.d.Metrics.Requests.Add(1)
		defer func() {
			if registered {
				// Include the final synchronous request log in shutdown waiting.
				defer s.active.Done()
			}
			if v := recover(); v != nil {
				s.d.Log.Error("handler_panic")
				if rw.status == 0 {
					http.Error(rw, "Internal server error", 500)
				} else {
					panic(http.ErrAbortHandler)
				}
			}
			s.d.Metrics.Bytes.Add(rw.bytes)
			status := rw.status
			if status == 0 {
				status = 200
			}
			// Route patterns exclude user file names, query strings and credentials.
			s.d.Log.Info("request", "method", r.Method, "route", r.Pattern, "ip", r.Context().Value(ipKey), "status", status, "bytes", rw.bytes, "latency_ms", time.Since(start).Milliseconds())
		}()
		s.admissionMu.Lock()
		if s.stopping.Load() {
			s.admissionMu.Unlock()
			http.Error(rw, "Server is shutting down", 503)
			return
		}
		s.active.Add(1)
		registered = true
		s.admissionMu.Unlock()
		select {
		case s.requests <- struct{}{}:
			defer func() { <-s.requests }()
		default:
			s.d.Metrics.Rejected.Add(1)
			retry(rw, time.Second, 503)
			return
		}
		s.d.Metrics.ActiveRequests.Add(1)
		defer s.d.Metrics.ActiveRequests.Add(-1)
		if r.TLS == nil || r.URL.IsAbs() || r.URL.Host != "" || !s.validHost(r.Host) {
			http.Error(rw, "Invalid HTTPS host", 400)
			return
		}
		if len(r.URL.RawQuery) > 4096 || len(r.URL.Path) > 8192 || strings.ContainsAny(r.URL.Path, "\\\x00") {
			http.Error(rw, "Invalid request path", 400)
			return
		}
		for _, p := range strings.Split(r.URL.Path, "/") {
			if p == ".." || p == "." {
				http.Error(rw, "Invalid request path", 400)
				return
			}
		}
		escaped := strings.ToLower(r.URL.EscapedPath())
		if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
			http.Error(rw, "Encoded separators are forbidden", 400)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(rw, "Cross-site requests are forbidden", 403)
			return
		}
		ip, err := (security.ClientIPs{Trusted: s.cfg.TrustedProxies}).Resolve(r)
		if err != nil {
			http.Error(rw, "Invalid client address", 400)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ipKey, ip))
		if r.Method == "POST" && !s.sameOrigin(r) {
			http.Error(rw, "Invalid request origin", 403)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (s *Server) validHost(host string) bool {
	h := host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		// Browsers omit :443, including for bracketed IPv6 hosts.
		h = host[1 : len(host)-1]
		if _, err := netip.ParseAddr(h); err != nil {
			return false
		}
	} else if strings.Contains(host, ":") {
		var port string
		var err error
		h, port, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	expected := s.cfg.Hostname
	if expected == "" {
		expected = s.cfg.Bind
	}
	if a, err := netip.ParseAddr(h); err == nil {
		b, e := netip.ParseAddr(expected)
		return e == nil && a.Unmap() == b.Unmap()
	}
	return strings.EqualFold(h, expected)
}

func (s *Server) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // Non-browser clients still need the CSRF token.
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Host, r.Host) && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err == nil {
			if session, ok := s.d.Sessions.Validate(cookie.Value, time.Now()); ok && session.ReadOnly {
				s.d.Log.Info("session_activity", "ip", clientIP(r), "created", session.Created)
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey, cookie.Value)))
				return
			}
		}
		clearCookie(w, sessionCookie)
		if r.URL.Path == "/" && r.Method == "GET" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "Authentication required", http.StatusUnauthorized)
	})
}

func clientIP(r *http.Request) netip.Addr { ip, _ := r.Context().Value(ipKey).(netip.Addr); return ip }
func csrfFor(token string) string {
	hash := sha256.Sum256([]byte("fileshare-csrf:" + token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
func equalToken(a, b string) bool {
	return len(a) == 43 && len(b) == 43 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func writeContextError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		http.Error(w, "Request cancelled", http.StatusRequestTimeout)
		return true
	}
	return false
}
