package session

import (
	"errors"
	"testing"
	"time"
)

func TestStoreLimitAndRevoke(t *testing.T) {
	store := New(time.Minute, 3)
	for range 3 {
		if _, err := store.Create("admin"); err != nil {
			t.Fatalf("Create() unexpected error = %v", err)
		}
	}
	if _, err := store.Create("admin"); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("Create() error = %v; want %v", err, ErrSessionLimit)
	}
	store.RevokeUser("admin")
	if _, err := store.Create("admin"); err != nil {
		t.Fatalf("Create() after revoke error = %v", err)
	}
}

func TestStoreExpiry(t *testing.T) {
	store := New(20*time.Millisecond, 3)
	session, err := store.Create("admin")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := store.Get(session.ID); ok {
		t.Fatalf("Get() = ok; want expired session")
	}
}
