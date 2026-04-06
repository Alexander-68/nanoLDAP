package web

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/directory"
	"nanoldap/internal/session"
	"nanoldap/internal/store"
)

const sessionCookieName = "nanoldap_session"

//go:embed assets/* templates/*
var assetsFS embed.FS

type Server struct {
	cfg       config.Config
	settings  *directory.Settings
	store     *store.Store
	sessions  *session.Store
	audit     *audit.Logger
	certPEM   []byte
	templates *template.Template
}

type pageData struct {
	Title       string
	Error       string
	CurrentUser store.User
	Users       []store.User
	Groups      []store.Group
	BaseDN      string
	View        string
}

func New(cfg config.Config, settings *directory.Settings, dataStore *store.Store, sessions *session.Store, auditLog *audit.Logger, certPEM []byte) *Server {
	funcs := template.FuncMap{
		"userInGroup": func(user store.User, name string) bool {
			return store.IsMemberOf(user, name)
		},
		"groupNames": func(groups []store.Group) []string {
			names := make([]string, 0, len(groups))
			for _, group := range groups {
				names = append(names, group.Name)
			}
			return names
		},
		"join": strings.Join,
	}
	templates := template.Must(template.New("all").Funcs(funcs).ParseFS(assetsFS, "templates/*.html"))
	return &Server{
		cfg:       cfg,
		settings:  settings,
		store:     dataStore,
		sessions:  sessions,
		audit:     auditLog,
		certPEM:   certPEM,
		templates: templates,
	}
}

func (s *Server) PublicMux() http.Handler {
	return s.buildMux(false)
}

func (s *Server) SecureMux() http.Handler {
	return s.buildMux(true)
}

func (s *Server) buildMux(secure bool) http.Handler {
	mux := http.NewServeMux()
	assetFiles, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServerFS(assetFiles)
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", fileServer))
	mux.HandleFunc("GET /ca.crt", s.handleCACert)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.withAdminAuth(s.handleLogout))
	mux.HandleFunc("GET /", s.withAdminAuth(func(w http.ResponseWriter, r *http.Request, currentUser store.User) {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
	}))
	mux.HandleFunc("GET /users", s.withAdminAuth(s.handleUsersPage))
	mux.HandleFunc("POST /users", s.withAdminAuth(s.handleCreateUser))
	mux.HandleFunc("PUT /users/{id}", s.withAdminAuth(s.handleUpdateUser))
	mux.HandleFunc("DELETE /users/{id}", s.withAdminAuth(s.handleDeleteUser))
	mux.HandleFunc("GET /groups", s.withAdminAuth(s.handleGroupsPage))
	mux.HandleFunc("POST /groups", s.withAdminAuth(s.handleCreateGroup))
	mux.HandleFunc("PUT /groups/{id}", s.withAdminAuth(s.handleUpdateGroup))
	mux.HandleFunc("DELETE /groups/{id}", s.withAdminAuth(s.handleDeleteGroup))
	mux.HandleFunc("PUT /settings/base-dn", s.withAdminAuth(s.handleUpdateBaseDN))
	return s.withHeaders(secure, mux)
}

func (s *Server) handleCACert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.certPEM)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.currentUser(r); ok {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", pageData{Title: "Login"}, http.StatusOK)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	sourceIP := remoteIP(r.RemoteAddr)

	user, err := s.store.AuthenticateUser(r.Context(), username, password)
	switch {
	case err != nil:
		s.audit.WebLogin(sourceIP, username, "invalid_credentials")
		s.render(w, "login.html", pageData{Title: "Login", Error: "Invalid credentials."}, http.StatusUnauthorized)
		return
	case user.Disabled:
		s.audit.WebLogin(sourceIP, username, "user_disabled")
		s.render(w, "login.html", pageData{Title: "Login", Error: "User is disabled."}, http.StatusForbidden)
		return
	case !store.IsMemberOf(user, "admins"):
		s.audit.WebLogin(sourceIP, username, "forbidden")
		s.render(w, "login.html", pageData{Title: "Login", Error: "Only members of the admins group may access the web UI."}, http.StatusForbidden)
		return
	}

	sess, err := s.sessions.Create(user.Username)
	if errors.Is(err, session.ErrSessionLimit) {
		s.audit.WebLogin(sourceIP, username, "session_limit")
		s.render(w, "login.html", pageData{Title: "Login", Error: "The global session limit has been reached."}, http.StatusTooManyRequests)
		return
	}
	if err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}
	s.audit.WebLogin(sourceIP, username, "success")
	s.setSessionCookie(w, r, sess.ID)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ store.User) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.Delete(cookie.Value)
	}
	s.clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleUsersPage(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	s.renderUsersPanel(w, r, currentUser, http.StatusOK)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	_, err := s.store.CreateUser(r.Context(), store.UserInput{
		Username:    r.Form.Get("username"),
		Password:    r.Form.Get("password"),
		DisplayName: r.Form.Get("display_name"),
		Disabled:    r.Form.Get("disabled") == "on",
		GroupNames:  r.Form["group"],
	})
	if err != nil {
		s.renderUsersPanelError(w, r, currentUser, err.Error(), http.StatusBadRequest)
		return
	}
	s.renderUsersPanel(w, r, currentUser, http.StatusCreated)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	updated, err := s.store.UpdateUser(r.Context(), id, store.UserInput{
		Password:    r.Form.Get("password"),
		DisplayName: r.Form.Get("display_name"),
		Disabled:    r.Form.Get("disabled") == "on",
		GroupNames:  r.Form["group"],
	})
	if err != nil {
		s.renderUsersPanelError(w, r, currentUser, err.Error(), http.StatusBadRequest)
		return
	}
	s.sessions.RevokeUser(updated.Username)
	s.renderUsersPanel(w, r, currentUser, http.StatusOK)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err == nil {
		s.sessions.RevokeUser(user.Username)
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		s.renderUsersPanelError(w, r, currentUser, err.Error(), http.StatusBadRequest)
		return
	}
	s.renderUsersPanel(w, r, currentUser, http.StatusOK)
}

func (s *Server) handleGroupsPage(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	s.renderGroupsPanel(w, r, currentUser, http.StatusOK)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	_, err := s.store.CreateGroup(r.Context(), store.GroupInput{
		Name:        r.Form.Get("name"),
		Description: r.Form.Get("description"),
	})
	if err != nil {
		s.renderGroupsPanelError(w, r, currentUser, err.Error(), http.StatusBadRequest)
		return
	}
	s.renderGroupsPanel(w, r, currentUser, http.StatusCreated)
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	updated, err := s.store.UpdateGroup(r.Context(), id, store.GroupInput{
		Name:        r.Form.Get("name"),
		Description: r.Form.Get("description"),
	})
	if err != nil {
		s.renderGroupsPanelError(w, r, currentUser, err.Error(), http.StatusBadRequest)
		return
	}
	for _, member := range updated.MemberUIDs {
		s.sessions.RevokeUser(member)
	}
	s.renderGroupsPanel(w, r, currentUser, http.StatusOK)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid group id", http.StatusBadRequest)
		return
	}
	group, err := s.store.GetGroupByID(r.Context(), id)
	if err == nil {
		for _, member := range group.MemberUIDs {
			s.sessions.RevokeUser(member)
		}
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		s.renderGroupsPanelError(w, r, currentUser, err.Error(), http.StatusBadRequest)
		return
	}
	s.renderGroupsPanel(w, r, currentUser, http.StatusOK)
}

func (s *Server) handleUpdateBaseDN(w http.ResponseWriter, r *http.Request, currentUser store.User) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	if err := s.store.SetBaseDN(r.Context(), r.Form.Get("base_dn")); err != nil {
		s.renderPanelForView(w, r, currentUser, r.Form.Get("view"), err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.settings.SetBaseDN(r.Form.Get("base_dn")); err != nil {
		s.renderPanelForView(w, r, currentUser, r.Form.Get("view"), err.Error(), http.StatusBadRequest)
		return
	}
	s.renderPanelForView(w, r, currentUser, r.Form.Get("view"), "", http.StatusOK)
}

func (s *Server) renderUsersPanel(w http.ResponseWriter, r *http.Request, currentUser store.User, status int) {
	ctx := r.Context()
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		http.Error(w, "failed to load users", http.StatusInternalServerError)
		return
	}
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		http.Error(w, "failed to load groups", http.StatusInternalServerError)
		return
	}
	templateName := "users.html"
	if htmxRequest(r) {
		templateName = "users_panel.html"
	}
	s.render(w, templateName, pageData{Title: "Users", CurrentUser: currentUser, Users: users, Groups: groups, BaseDN: s.baseDN(), View: "users"}, status)
}

func (s *Server) renderUsersPanelError(w http.ResponseWriter, r *http.Request, currentUser store.User, message string, status int) {
	ctx := r.Context()
	users, _ := s.store.ListUsers(ctx)
	groups, _ := s.store.ListGroups(ctx)
	templateName := "users.html"
	if htmxRequest(r) {
		templateName = "users_panel.html"
	}
	s.render(w, templateName, pageData{Title: "Users", CurrentUser: currentUser, Users: users, Groups: groups, BaseDN: s.baseDN(), View: "users", Error: message}, status)
}

func (s *Server) renderGroupsPanel(w http.ResponseWriter, r *http.Request, currentUser store.User, status int) {
	ctx := r.Context()
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		http.Error(w, "failed to load groups", http.StatusInternalServerError)
		return
	}
	s.render(w, chooseTemplate(r, "groups.html", "groups_panel.html"), pageData{Title: "Groups", CurrentUser: currentUser, Groups: groups, BaseDN: s.baseDN(), View: "groups"}, status)
}

func (s *Server) renderGroupsPanelError(w http.ResponseWriter, r *http.Request, currentUser store.User, message string, status int) {
	ctx := r.Context()
	groups, _ := s.store.ListGroups(ctx)
	s.render(w, chooseTemplate(r, "groups.html", "groups_panel.html"), pageData{Title: "Groups", CurrentUser: currentUser, Groups: groups, BaseDN: s.baseDN(), View: "groups", Error: message}, status)
}

func (s *Server) renderPanelForView(w http.ResponseWriter, r *http.Request, currentUser store.User, view, message string, status int) {
	switch strings.ToLower(strings.TrimSpace(view)) {
	case "groups":
		if message == "" {
			s.renderGroupsPanel(w, r, currentUser, status)
			return
		}
		s.renderGroupsPanelError(w, r, currentUser, message, status)
	default:
		if message == "" {
			s.renderUsersPanel(w, r, currentUser, status)
			return
		}
		s.renderUsersPanelError(w, r, currentUser, message, status)
	}
}

func (s *Server) withAdminAuth(next func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, sessionID, ok := s.currentUser(r)
		if !ok || !store.IsMemberOf(user, "admins") {
			s.clearSessionCookie(w, r)
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.setSessionCookie(w, r, sessionID)
		next(w, r, user)
	}
}

func (s *Server) currentUser(r *http.Request) (store.User, string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return store.User{}, "", false
	}
	sess, ok := s.sessions.Get(cookie.Value)
	if !ok {
		return store.User{}, "", false
	}
	user, err := s.store.GetUserByUsername(r.Context(), sess.Username)
	if err != nil || user.Disabled {
		s.sessions.RevokeUser(sess.Username)
		return store.User{}, "", false
	}
	return user, sess.ID, true
}

func (s *Server) render(w http.ResponseWriter, name string, data pageData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = s.templates.ExecuteTemplate(w, name, data)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Secure:   requestIsSecure(r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(s.cfg.SessionIdleTimeout),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   requestIsSecure(r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) withHeaders(secure bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if secure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func requestIsSecure(r *http.Request) bool {
	return r.TLS != nil
}

func chooseTemplate(r *http.Request, full, partial string) string {
	if htmxRequest(r) {
		return partial
	}
	return full
}

func htmxRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("HX-Request"), "true")
}

func (s *Server) baseDN() string {
	return s.settings.BaseDN()
}
