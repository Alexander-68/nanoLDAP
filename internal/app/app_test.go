package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"nanoldap/internal/config"
)

func TestNewAndCloseInitializesAllComponents(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		BaseDN:             "dc=example,dc=com",
		DBPath:             filepath.Join(dir, "nanoldap.db"),
		AuditLog:           filepath.Join(dir, "audit.log"),
		CertFile:           filepath.Join(dir, "cert.pem"),
		KeyFile:            filepath.Join(dir, "key.pem"),
		SessionIdleTimeout: 15 * time.Minute,
		SessionMax:         3,
		LDAPIdleTimeout:    5 * time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      3,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	}

	instance, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if instance.Store() == nil {
		t.Fatalf("Store() is nil")
	}
	if instance.Audit() == nil {
		t.Fatalf("Audit() is nil")
	}
	if instance.Settings() == nil {
		t.Fatalf("Settings() is nil")
	}
	if instance.Settings().BaseDN() != "dc=example,dc=com" {
		t.Fatalf("Settings().BaseDN() = %q; want %q", instance.Settings().BaseDN(), "dc=example,dc=com")
	}
	if instance.PublicMux() == nil {
		t.Fatalf("PublicMux() is nil")
	}
	if instance.SecureMux() == nil {
		t.Fatalf("SecureMux() is nil")
	}
	if instance.Config().BaseDN != cfg.BaseDN {
		t.Fatalf("Config().BaseDN = %q; want %q", instance.Config().BaseDN, cfg.BaseDN)
	}

	users, err := instance.Store().ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 4 {
		t.Fatalf("ListUsers() seeded users = %d; want 4", len(users))
	}

	instance.Close()
}

func TestNewFailsForInvalidPaths(t *testing.T) {
	cfg := config.Config{
		BaseDN:   "dc=example,dc=com",
		DBPath:   "/nonexistent/path/that/does/not/exist/db.sqlite",
		AuditLog: "stdout",
		CertFile: filepath.Join(t.TempDir(), "cert.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "key.pem"),
	}
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatalf("New() with bad DB path should fail")
	}
}
