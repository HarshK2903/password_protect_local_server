package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"fileshare/internal/files"
	"fileshare/internal/security"
)

type loginData struct{ CSRF, Error string }

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.pages.ExecuteTemplate(&buf, name, data); err != nil {
		s.d.Log.Error("template_error", "template", name)
		http.Error(w, "Internal server error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		_, _ = w.Write(buf.Bytes())
	}
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		http.Error(w, "Service unavailable", 503)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
	s.render(w, r, 200, "login", loginData{CSRF: token})
}

func readForm(w http.ResponseWriter, r *http.Request) error {
	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || t != "application/x-www-form-urlencoded" {
		return errors.New("expected a URL-encoded form")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	return r.ParseForm()
}

func retry(w http.ResponseWriter, duration time.Duration, status int) {
	seconds := max(1, int(math.Ceil(duration.Seconds())))
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	http.Error(w, http.StatusText(status)+". Try again later.", status)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	attempt, err := s.d.Guard.Begin(r.Context(), clientIP(r), time.Now())
	if err != nil {
		s.d.Metrics.Rejected.Add(1)
		var denied *security.AdmissionError
		if errors.As(err, &denied) {
			status := 429
			if denied.Capacity {
				status = 503
			}
			retry(w, denied.Retry, status)
		} else {
			writeContextError(w, err)
		}
		return
	}
	defer func() { attempt.Finish(nil, time.Now()) }()
	if err := readForm(w, r); err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			http.Error(w, "Login form is too large", 413)
		} else {
			http.Error(w, "Invalid login form", 400)
		}
		return
	}
	csrf, err := r.Cookie(loginCookie)
	if err != nil || !equalToken(csrf.Value, r.PostForm.Get("csrf")) || len(r.PostForm["csrf"]) != 1 {
		http.Error(w, "Invalid form token; reload the login page", 403)
		return
	}
	password := []byte(r.PostForm.Get("password"))
	passwordFields := len(r.PostForm["password"])
	r.PostForm.Del("password")
	r.Form.Del("password")
	defer clear(password)
	if passwordFields != 1 || len(password) > 1024 {
		http.Error(w, "Invalid password length", 400)
		return
	}
	if writeContextError(w, r.Context().Err()) {
		return
	}
	ok := s.d.Authenticator.Verify(password)
	cooldown := attempt.Finish(&ok, time.Now())
	if !ok {
		s.d.Metrics.LoginFailure.Add(1)
		s.d.Log.Warn("login_failed", "ip", clientIP(r))
		if cooldown > 0 {
			s.d.Log.Warn("cooldown_started", "ip", clientIP(r), "duration_seconds", cooldown.Seconds())
			retry(w, cooldown, 429)
			return
		}
		s.render(w, r, 401, "login", loginData{CSRF: csrf.Value, Error: "Incorrect password. Please try again."})
		return
	}
	if writeContextError(w, r.Context().Err()) {
		return
	}
	token, session, err := s.d.Sessions.Create(time.Now())
	if err != nil {
		s.d.Log.Warn("session_creation_rejected", "ip", clientIP(r))
		retry(w, time.Minute, 503)
		return
	}
	if previous, e := r.Cookie(sessionCookie); e == nil {
		s.d.Sessions.Revoke(previous.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Expires: session.Expires, MaxAge: int(s.cfg.SessionAbsolute.Seconds())})
	clearCookie(w, loginCookie)
	s.d.Metrics.LoginSuccess.Add(1)
	s.d.Log.Info("login_succeeded", "ip", clientIP(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		http.Error(w, "Invalid logout form", 400)
		return
	}
	token, _ := r.Context().Value(tokenKey).(string)
	if !equalToken(csrfFor(token), r.PostForm.Get("csrf")) || len(r.PostForm["csrf"]) != 1 {
		http.Error(w, "Invalid form token", 403)
		return
	}
	s.d.Sessions.Revoke(token)
	clearCookie(w, sessionCookie)
	s.d.Log.Info("session_revoked", "ip", clientIP(r))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type crumb struct{ Name, Path string }
type browseData struct {
	Entries      []files.Entry
	Crumbs       []crumb
	Parent, CSRF string
}

func requestedPath(r *http.Request) (string, error) {
	query, err := urlQuery(r)
	if err != nil {
		return "", err
	}
	if len(query) > 1 {
		return "", files.ErrDenied
	}
	return files.Normalize(query.Get("path"))
}

func (s *Server) browse(w http.ResponseWriter, r *http.Request) {
	name, err := requestedPath(r)
	if err != nil {
		http.Error(w, "Invalid path", 400)
		return
	}
	entries, err := s.d.Files.List(r.Context(), name)
	if err != nil {
		s.fileError(w, err)
		return
	}
	token, _ := r.Context().Value(tokenKey).(string)
	data := browseData{Entries: entries, CSRF: csrfFor(token)}
	if name != "." {
		data.Parent = path.Dir(name)
		prefix := ""
		for _, part := range strings.Split(name, "/") {
			prefix = path.Join(prefix, part)
			data.Crumbs = append(data.Crumbs, crumb{Name: part, Path: prefix})
		}
	}
	s.render(w, r, 200, "files", data)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	name, err := requestedPath(r)
	if err != nil {
		http.Error(w, "Invalid path", 400)
		return
	}
	entries, err := s.d.Files.List(r.Context(), name)
	if err != nil {
		s.fileError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != "HEAD" {
		_ = json.NewEncoder(w).Encode(struct {
			Path    string        `json:"path"`
			Entries []files.Entry `json:"entries"`
		}{name, entries})
	}
}

func (s *Server) fileError(w http.ResponseWriter, err error) {
	if writeContextError(w, err) {
		return
	}
	if errors.Is(err, files.ErrTooLarge) {
		http.Error(w, "Directory exceeds configured entry limit", 413)
		return
	}
	http.Error(w, "File or directory unavailable", 404)
}

// contextReadSeeker prevents ServeContent from reading after cancellation. It
// deliberately does not implement WriterTo, keeping streaming buffers bounded.
type contextReadSeeker struct {
	request *http.Request
	file    interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	}
}

func (c contextReadSeeker) Read(p []byte) (int, error) {
	if err := c.request.Context().Err(); err != nil {
		return 0, err
	}
	return c.file.Read(p)
}
func (c contextReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if err := c.request.Context().Err(); err != nil {
		return 0, err
	}
	return c.file.Seek(offset, whence)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	select {
	case s.transfers <- struct{}{}:
		defer func() { <-s.transfers }()
	default:
		s.d.Metrics.Rejected.Add(1)
		retry(w, time.Second, 503)
		return
	}
	f, info, err := s.d.Files.Open(r.Context(), r.PathValue("path"))
	if err != nil {
		s.fileError(w, err)
		return
	}
	defer f.Close()
	s.d.Metrics.ActiveDownloads.Add(1)
	defer s.d.Metrics.ActiveDownloads.Add(-1)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name()}))
	// Bound slow downloads as well as idle connections. ServeContent provides
	// HEAD, Range, If-Range and conditional metadata without whole-file buffering.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
	http.ServeContent(w, r, info.Name(), info.ModTime(), contextReadSeeker{request: r, file: f})
}
