package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/directory"
	"nanoldap/internal/session"
	"nanoldap/internal/store"
)

func TestUpdateBaseDNFromGroupsPage(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	form := url.Values{
		"base_dn": {"dc=corp,dc=local"},
		"view":    {"groups"},
	}
	req := httptest.NewRequest(http.MethodPut, "/settings/base-dn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSession.ID})
	res := httptest.NewRecorder()

	server.SecureMux().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("PUT /settings/base-dn status = %d; want %d", res.Code, http.StatusOK)
	}
	if body := res.Body.String(); !strings.Contains(body, "dc=corp,dc=local") {
		t.Fatalf("PUT /settings/base-dn body missing updated base DN: %s", body)
	}
	if got, err := dataStore.BaseDN(req.Context()); err != nil || got != "dc=corp,dc=local" {
		t.Fatalf("dataStore.BaseDN() = %q, %v; want %q, nil", got, err, "dc=corp,dc=local")
	}
}

func TestUsersPageIncludesModalTriggers(t *testing.T) {
	server, _, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSession.ID})
	res := httptest.NewRecorder()

	server.SecureMux().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("GET /users status = %d; want %d", res.Code, http.StatusOK)
	}
	body := res.Body.String()
	for _, snippet := range []string{
		`data-dialog-id="user-create-modal"`,
		`data-dialog-id="base-dn-modal"`,
		`id="user-edit-modal-`,
		`Logout admin`,
	} {
		if !strings.Contains(body, snippet) {
			t.Fatalf("GET /users body missing %q", snippet)
		}
	}
}

func TestPanelTemplatesUseInnerHTMLSwapTargets(t *testing.T) {
	server, _, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	for _, tc := range []struct {
		name    string
		path    string
		target  string
		snippet string
	}{
		{
			name:    "users",
			path:    "/users",
			target:  "#users-panel",
			snippet: `hx-post="/users"`,
		},
		{
			name:    "groups",
			path:    "/groups",
			target:  "#groups-panel",
			snippet: `hx-post="/groups"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSession.ID})
			res := httptest.NewRecorder()

			server.SecureMux().ServeHTTP(res, req)

			if res.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d; want %d", tc.path, res.Code, http.StatusOK)
			}
			body := res.Body.String()
			if !strings.Contains(body, tc.snippet) {
				t.Fatalf("GET %s body missing %q", tc.path, tc.snippet)
			}
			if !strings.Contains(body, `hx-target="`+tc.target+`" hx-swap="innerHTML"`) {
				t.Fatalf("GET %s body missing stable innerHTML swap target for %s", tc.path, tc.target)
			}
			if strings.Contains(body, `hx-target="`+tc.target+`" hx-swap="outerHTML"`) {
				t.Fatalf("GET %s body still contains outerHTML swap target for %s", tc.path, tc.target)
			}
		})
	}
}

func TestLoginSuccessSetsSessionCookie(t *testing.T) {
	server, _, sessions, cleanup := newTestServer(t)
	defer cleanup()

	res := postLogin(server, "admin", "admin", false)

	if res.Code != http.StatusSeeOther {
		t.Fatalf("POST /login status = %d; want %d", res.Code, http.StatusSeeOther)
	}
	cookie := findCookie(res.Result().Cookies(), sessionCookieName)
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("POST /login did not set session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie missing security attributes: %#v", cookie)
	}
	if _, ok := sessions.Get(cookie.Value); !ok {
		t.Fatalf("session %q not registered with store", cookie.Value)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	server, _, _, cleanup := newTestServer(t)
	defer cleanup()

	res := postLogin(server, "admin", "wrong", false)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("POST /login status = %d; want %d", res.Code, http.StatusUnauthorized)
	}
	if findCookie(res.Result().Cookies(), sessionCookieName) != nil {
		t.Fatalf("wrong password should not set session cookie")
	}
	if !strings.Contains(res.Body.String(), "Invalid credentials") {
		t.Fatalf("response missing invalid credentials message: %s", res.Body.String())
	}
}

func TestLoginRejectsDisabledUser(t *testing.T) {
	server, dataStore, _, cleanup := newTestServer(t)
	defer cleanup()

	user, err := dataStore.GetUserByUsername(t.Context(), "admin")
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}
	if _, err := dataStore.UpdateUser(t.Context(), user.ID, store.UserInput{
		Password:    "admin",
		DisplayName: user.DisplayName,
		Disabled:    true,
		GroupNames:  []string{"admins", "users"},
	}); err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}

	res := postLogin(server, "admin", "admin", false)

	if res.Code != http.StatusForbidden {
		t.Fatalf("POST /login disabled status = %d; want %d", res.Code, http.StatusForbidden)
	}
	if !strings.Contains(res.Body.String(), "disabled") {
		t.Fatalf("response missing disabled message: %s", res.Body.String())
	}
}

func TestLoginRejectsNonAdmin(t *testing.T) {
	server, dataStore, _, cleanup := newTestServer(t)
	defer cleanup()

	if _, err := dataStore.CreateUser(t.Context(), store.UserInput{
		Username:    "bob",
		Password:    "secret",
		DisplayName: "Bob",
		GroupNames:  []string{"users"},
	}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	res := postLogin(server, "bob", "secret", false)

	if res.Code != http.StatusForbidden {
		t.Fatalf("POST /login non-admin status = %d; want %d", res.Code, http.StatusForbidden)
	}
	if findCookie(res.Result().Cookies(), sessionCookieName) != nil {
		t.Fatalf("non-admin login should not set session cookie")
	}
}

func TestLoginRejectsBeyondSessionLimit(t *testing.T) {
	server, _, sessions, cleanup := newTestServer(t)
	defer cleanup()

	for range 3 {
		if _, err := sessions.Create("admin"); err != nil {
			t.Fatalf("sessions.Create() error = %v", err)
		}
	}

	res := postLogin(server, "admin", "admin", false)

	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("POST /login over limit status = %d; want %d", res.Code, http.StatusTooManyRequests)
	}
	if !strings.Contains(res.Body.String(), "session limit") {
		t.Fatalf("response missing session limit message: %s", res.Body.String())
	}
}

func TestLogoutClearsSessionAndCookie(t *testing.T) {
	server, _, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSession.ID})
	res := httptest.NewRecorder()
	server.SecureMux().ServeHTTP(res, req)

	if res.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout status = %d; want %d", res.Code, http.StatusSeeOther)
	}
	if _, ok := sessions.Get(adminSession.ID); ok {
		t.Fatalf("session %q still present after logout", adminSession.ID)
	}
	cookie := findCookie(res.Result().Cookies(), sessionCookieName)
	if cookie == nil || cookie.MaxAge >= 0 {
		t.Fatalf("logout response cookie not cleared: %#v", cookie)
	}
}

func TestUnauthenticatedGetRedirectsToLogin(t *testing.T) {
	server, _, _, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	res := httptest.NewRecorder()
	server.SecureMux().ServeHTTP(res, req)

	if res.Code != http.StatusSeeOther {
		t.Fatalf("GET /users unauth status = %d; want %d", res.Code, http.StatusSeeOther)
	}
	if loc := res.Header().Get("Location"); loc != "/login" {
		t.Fatalf("redirect target = %q; want /login", loc)
	}
}

func TestUnauthenticatedMutationReturnsForbidden(t *testing.T) {
	server, _, _, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodDelete, "/users/1", nil)
	res := httptest.NewRecorder()
	server.SecureMux().ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("DELETE /users/1 unauth status = %d; want %d", res.Code, http.StatusForbidden)
	}
}

func TestCreateUserViaWeb(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	form := url.Values{
		"username":     {"carol"},
		"password":     {"secret"},
		"display_name": {"Carol"},
		"group":        {"users"},
	}
	res := submitForm(server, http.MethodPost, "/users", form, adminSession.ID)

	if res.Code != http.StatusCreated {
		t.Fatalf("POST /users status = %d; want %d", res.Code, http.StatusCreated)
	}
	user, err := dataStore.GetUserByUsername(t.Context(), "carol")
	if err != nil {
		t.Fatalf("GetUserByUsername() error = %v", err)
	}
	if user.DisplayName != "Carol" || !store.IsMemberOf(user, "users") {
		t.Fatalf("created user = %#v; want Carol in users group", user)
	}
}

func TestUpdateUserRevokesActiveSessions(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}
	user, err := dataStore.CreateUser(t.Context(), store.UserInput{
		Username:    "dave",
		Password:    "secret",
		DisplayName: "Dave",
		GroupNames:  []string{"users"},
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	daveSession, err := sessions.Create("dave")
	if err != nil {
		t.Fatalf("sessions.Create(dave) error = %v", err)
	}

	form := url.Values{
		"display_name": {"Dave Updated"},
		"group":        {"users"},
	}
	res := submitForm(server, http.MethodPut, "/users/"+strconv.FormatInt(user.ID, 10), form, adminSession.ID)
	if res.Code != http.StatusOK {
		t.Fatalf("PUT /users status = %d; want %d", res.Code, http.StatusOK)
	}
	if _, ok := sessions.Get(daveSession.ID); ok {
		t.Fatalf("dave's session was not revoked after update")
	}
}

func TestDeleteUserRevokesActiveSessions(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}
	user, err := dataStore.CreateUser(t.Context(), store.UserInput{
		Username:    "erin",
		Password:    "secret",
		DisplayName: "Erin",
		GroupNames:  []string{"users"},
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	erinSession, err := sessions.Create("erin")
	if err != nil {
		t.Fatalf("sessions.Create(erin) error = %v", err)
	}

	res := submitForm(server, http.MethodDelete, "/users/"+strconv.FormatInt(user.ID, 10), nil, adminSession.ID)
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE /users status = %d; want %d", res.Code, http.StatusOK)
	}
	if _, err := dataStore.GetUserByUsername(t.Context(), "erin"); err == nil {
		t.Fatalf("user erin still present after delete")
	}
	if _, ok := sessions.Get(erinSession.ID); ok {
		t.Fatalf("erin's session was not revoked after delete")
	}
}

func TestCreateGroupViaWeb(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	form := url.Values{
		"name":        {"engineers"},
		"description": {"Eng team"},
	}
	res := submitForm(server, http.MethodPost, "/groups", form, adminSession.ID)
	if res.Code != http.StatusCreated {
		t.Fatalf("POST /groups status = %d; want %d", res.Code, http.StatusCreated)
	}
	group, err := dataStore.GetGroupByName(t.Context(), "engineers")
	if err != nil {
		t.Fatalf("GetGroupByName() error = %v", err)
	}
	if group.Description != "Eng team" {
		t.Fatalf("group.Description = %q; want %q", group.Description, "Eng team")
	}
}

func TestUpdateGroupRevokesMemberSessions(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}
	group, err := dataStore.CreateGroup(t.Context(), store.GroupInput{Name: "ops", Description: "Ops"})
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}
	if _, err := dataStore.CreateUser(t.Context(), store.UserInput{
		Username:    "frank",
		Password:    "secret",
		DisplayName: "Frank",
		GroupNames:  []string{"ops"},
	}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	frankSession, err := sessions.Create("frank")
	if err != nil {
		t.Fatalf("sessions.Create(frank) error = %v", err)
	}

	form := url.Values{
		"name":        {"platform"},
		"description": {"Platform"},
	}
	res := submitForm(server, http.MethodPut, "/groups/"+strconv.FormatInt(group.ID, 10), form, adminSession.ID)
	if res.Code != http.StatusOK {
		t.Fatalf("PUT /groups status = %d; want %d", res.Code, http.StatusOK)
	}
	if _, ok := sessions.Get(frankSession.ID); ok {
		t.Fatalf("frank's session was not revoked after group update")
	}
}

func TestDeleteGroupRevokesMemberSessions(t *testing.T) {
	server, dataStore, sessions, cleanup := newTestServer(t)
	defer cleanup()

	adminSession, err := sessions.Create("admin")
	if err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}
	group, err := dataStore.CreateGroup(t.Context(), store.GroupInput{Name: "qa", Description: "QA"})
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}
	if _, err := dataStore.CreateUser(t.Context(), store.UserInput{
		Username:    "gina",
		Password:    "secret",
		DisplayName: "Gina",
		GroupNames:  []string{"qa"},
	}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	ginaSession, err := sessions.Create("gina")
	if err != nil {
		t.Fatalf("sessions.Create(gina) error = %v", err)
	}

	res := submitForm(server, http.MethodDelete, "/groups/"+strconv.FormatInt(group.ID, 10), nil, adminSession.ID)
	if res.Code != http.StatusOK {
		t.Fatalf("DELETE /groups status = %d; want %d", res.Code, http.StatusOK)
	}
	if _, ok := sessions.Get(ginaSession.ID); ok {
		t.Fatalf("gina's session was not revoked after group delete")
	}
}

func TestPublicMuxServesCACertOnly(t *testing.T) {
	server, _, _, cleanup := newTestServer(t)
	defer cleanup()

	publicMux := server.PublicMux()

	res := httptest.NewRecorder()
	publicMux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/ca.crt", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("GET /ca.crt status = %d; want %d", res.Code, http.StatusOK)
	}
	if ct := res.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Fatalf("GET /ca.crt content-type = %q; want %q", ct, "application/x-pem-file")
	}
	if got := res.Body.String(); got != "CERT" {
		t.Fatalf("GET /ca.crt body = %q; want %q", got, "CERT")
	}
	if res.Header().Get("Strict-Transport-Security") != "" {
		t.Fatalf("PublicMux set HSTS header on plaintext listener")
	}
	if res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("PublicMux missing X-Content-Type-Options header")
	}

	for _, path := range []string{"/", "/login", "/users", "/groups", "/settings/base-dn"} {
		res := httptest.NewRecorder()
		publicMux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))
		if res.Code != http.StatusNotFound {
			t.Fatalf("PublicMux GET %s status = %d; want 404", path, res.Code)
		}
	}
}

func TestSecureMuxAddsHSTSHeader(t *testing.T) {
	server, _, _, cleanup := newTestServer(t)
	defer cleanup()

	res := httptest.NewRecorder()
	server.SecureMux().ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/login", nil))

	if hsts := res.Header().Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=") {
		t.Fatalf("SecureMux response missing HSTS header: %q", hsts)
	}
}

func TestSecureCookieFlagSetWhenRequestIsTLS(t *testing.T) {
	server, _, sessions, cleanup := newTestServer(t)
	defer cleanup()

	if _, err := sessions.Create("placeholder-not-used"); err != nil {
		t.Fatalf("sessions.Create() error = %v", err)
	}

	res := postLogin(server, "admin", "admin", true)
	if res.Code != http.StatusSeeOther {
		t.Fatalf("POST /login TLS status = %d; want %d", res.Code, http.StatusSeeOther)
	}
	cookie := findCookie(res.Result().Cookies(), sessionCookieName)
	if cookie == nil {
		t.Fatalf("POST /login over TLS did not set session cookie")
	}
	if !cookie.Secure {
		t.Fatalf("session cookie missing Secure flag over TLS: %#v", cookie)
	}
}

func postLogin(server *Server, username, password string, useTLS bool) *httptest.ResponseRecorder {
	form := url.Values{
		"username": {username},
		"password": {password},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if useTLS {
		req.TLS = &tls.ConnectionState{}
	}
	res := httptest.NewRecorder()
	server.SecureMux().ServeHTTP(res, req)
	return res
}

func submitForm(server *Server, method, path string, form url.Values, sessionID string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	res := httptest.NewRecorder()
	server.SecureMux().ServeHTTP(res, req)
	return res
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == name {
			found = c
		}
	}
	return found
}

func newTestServer(t *testing.T) (*Server, *store.Store, *session.Store, func()) {
	t.Helper()

	dataStore, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	if err := dataStore.SeedDefaults(t.Context()); err != nil {
		t.Fatalf("SeedDefaults() error = %v", err)
	}
	baseDN, err := dataStore.EnsureBaseDN(t.Context(), "dc=example,dc=com")
	if err != nil {
		t.Fatalf("EnsureBaseDN() error = %v", err)
	}
	settings, err := directory.NewSettings(baseDN)
	if err != nil {
		t.Fatalf("directory.NewSettings() error = %v", err)
	}
	auditLog, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}
	sessions := session.New(15*time.Minute, 3)

	server := New(config.Config{
		BaseDN:             "dc=example,dc=com",
		SessionIdleTimeout: 15 * time.Minute,
		SessionMax:         3,
	}, settings, dataStore, sessions, auditLog, []byte("CERT"))

	return server, dataStore, sessions, func() {
		_ = auditLog.Close()
		_ = dataStore.Close()
	}
}
