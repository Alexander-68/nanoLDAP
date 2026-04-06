package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
