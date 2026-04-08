package session

import (
	"errors"
	"sync"
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

func TestStoreGetUnknownReturnsFalse(t *testing.T) {
	store := New(time.Minute, 3)
	if _, ok := store.Get("missing"); ok {
		t.Fatalf("Get(missing) = ok; want false")
	}
}

func TestStoreGetExtendsExpiryAndLastSeen(t *testing.T) {
	store := New(time.Minute, 3)
	session, err := store.Create("admin")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	originalExpires := session.ExpiresAt
	originalLastSeen := session.LastSeen
	time.Sleep(2 * time.Millisecond)
	refreshed, ok := store.Get(session.ID)
	if !ok {
		t.Fatalf("Get() = !ok; want existing session")
	}
	if !refreshed.ExpiresAt.After(originalExpires) {
		t.Fatalf("Get() ExpiresAt = %s; want after %s", refreshed.ExpiresAt, originalExpires)
	}
	if !refreshed.LastSeen.After(originalLastSeen) {
		t.Fatalf("Get() LastSeen = %s; want after %s", refreshed.LastSeen, originalLastSeen)
	}
}

func TestStoreDeleteRemovesSession(t *testing.T) {
	store := New(time.Minute, 3)
	session, err := store.Create("admin")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	store.Delete(session.ID)
	if _, ok := store.Get(session.ID); ok {
		t.Fatalf("Get() after Delete() = ok; want false")
	}
}

func TestStoreCreatePrunesExpiredBeforeRejecting(t *testing.T) {
	store := New(20*time.Millisecond, 2)
	if _, err := store.Create("admin"); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	if _, err := store.Create("admin"); err != nil {
		t.Fatalf("second Create() error = %v", err)
	}
	if _, err := store.Create("admin"); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("third Create() error = %v; want ErrSessionLimit", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := store.Create("admin"); err != nil {
		t.Fatalf("Create() after expiry error = %v; want pruning to free a slot", err)
	}
}

func TestStoreConcurrentCreateAndRevoke(t *testing.T) {
	store := New(time.Minute, 100)
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range 16 {
				if _, err := store.Create("admin"); err != nil && !errors.Is(err, ErrSessionLimit) {
					t.Errorf("worker %d: Create() error = %v", id, err)
					return
				}
				store.RevokeUser("admin")
			}
		}(worker)
	}
	wg.Wait()
}
