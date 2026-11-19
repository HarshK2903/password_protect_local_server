package server

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"fileshare/internal/auth"
	"fileshare/internal/config"
	"fileshare/internal/files"
	"fileshare/internal/security"
	"fileshare/internal/telemetry"
	"fileshare/web"
)

const sessionCookie = "__Host-fileshare_session"
const loginCookie = "__Host-fileshare_login"

type Dependencies struct {
	Authenticator auth.Authenticator
	Sessions      auth.SessionStore
	Guard         security.IPGuard
	Files         files.FileService
	Log           *slog.Logger
	Metrics       *telemetry.Metrics
}

type Server struct {
	cfg                 config.Config
	d                   Dependencies
	pages               *template.Template
	style               []byte
	requests, transfers chan struct{}
	stopping            atomic.Bool
	admissionMu         sync.Mutex
	active              sync.WaitGroup
	handler             http.Handler
}

func New(c config.Config, d Dependencies) (*Server, error) {
	if d.Authenticator == nil || d.Sessions == nil || d.Guard == nil || d.Files == nil || d.Log == nil || d.Metrics == nil {
		return nil, fmt.Errorf("all server dependencies are required")
	}
	funcs := template.FuncMap{"escape": func(p string) string {
		parts := strings.Split(p, "/")
		for i := range parts {
			parts[i] = url.PathEscape(parts[i])
		}
		return strings.Join(parts, "/")
	}, "size": func(n int64) string {
		if n < 1024 {
			return fmt.Sprintf("%d B", n)
		}
		if n < 1024*1024 {
			return fmt.Sprintf("%.1f KB", float64(n)/1024)
		}
		if n < 1024*1024*1024 {
			return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
		}
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}}
	t, err := template.New("pages").Funcs(funcs).ParseFS(web.Assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	style, err := web.Assets.ReadFile("static/style.css")
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: c, d: d, pages: t, style: style, requests: make(chan struct{}, c.MaxRequests), transfers: make(chan struct{}, c.MaxTransfers)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != "HEAD" {
			_, _ = w.Write(s.style)
		}
	})
	mux.Handle("GET /{$}", s.requireSession(http.HandlerFunc(s.browse)))
	mux.Handle("GET /api/files", s.requireSession(http.HandlerFunc(s.list)))
	mux.Handle("GET /api/download/{path...}", s.requireSession(http.HandlerFunc(s.download)))
	mux.Handle("POST /logout", s.requireSession(http.HandlerFunc(s.logout)))
	s.handler = security.Headers(s.middleware(mux))
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.handler }
func (s *Server) StopAdmissions() {
	s.admissionMu.Lock()
	s.stopping.Store(true)
	s.admissionMu.Unlock()
	s.d.Guard.Stop()
}
func (s *Server) Wait() { s.active.Wait() }
