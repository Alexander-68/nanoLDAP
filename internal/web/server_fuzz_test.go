package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/session"
	"nanoldap/internal/store"
)

func FuzzSecureMux(f *testing.F) {
	dir := f.TempDir()
	dataStore, err := store.Open(context.Background(), filepath.Join(dir, "nanoldap.db"))
	if err != nil {
		f.Fatalf("store.Open() error = %v", err)
	}
	f.Cleanup(func() {
		_ = dataStore.Close()
	})
	if err := dataStore.SeedDefaults(context.Background()); err != nil {
		f.Fatalf("SeedDefaults() error = %v", err)
	}
	auditLog, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		f.Fatalf("audit.New() error = %v", err)
	}
	f.Cleanup(func() {
		_ = auditLog.Close()
	})
	server := New(config.Config{
		BaseDN:             "dc=example,dc=com",
		SessionIdleTimeout: 15 * time.Minute,
		SessionMax:         3,
	}, dataStore, session.New(15*time.Minute, 3), auditLog, []byte("CERT"))
	handler := server.SecureMux()

	f.Add("bogus", []byte("username=admin&password=admin"))
	f.Fuzz(func(t *testing.T, cookieValue string, body []byte) {
		loginReq := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		loginReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieValue})
		loginRes := httptest.NewRecorder()
		handler.ServeHTTP(loginRes, loginReq)

		usersReq := httptest.NewRequest(http.MethodGet, "/users", nil)
		usersReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookieValue})
		usersRes := httptest.NewRecorder()
		handler.ServeHTTP(usersRes, usersReq)
	})
}
