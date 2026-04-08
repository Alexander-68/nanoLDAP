package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestStoreCRUD(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if err := store.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults() error = %v", err)
	}
	if _, err := store.CreateGroup(ctx, GroupInput{Name: "devops", Description: "Operators"}); err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}

	user, err := store.CreateUser(ctx, UserInput{
		Username:    "alice",
		Password:    "secret",
		DisplayName: "Alice",
		GroupNames:  []string{"users", "devops"},
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if !IsMemberOf(user, "users", "devops") {
		t.Fatalf("CreateUser() groups = %#v; want users and devops", user.Groups)
	}

	user, err = store.UpdateUser(ctx, user.ID, UserInput{
		DisplayName: "Alice Smith",
		Disabled:    true,
		GroupNames:  []string{"devops"},
	})
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	if user.DisplayName != "Alice Smith" || !user.Disabled || IsMemberOf(user, "users") {
		t.Fatalf("UpdateUser() = %#v; want updated display name, disabled, and devops-only membership", user)
	}

	group, err := store.GetGroupByName(ctx, "devops")
	if err != nil {
		t.Fatalf("GetGroupByName() error = %v", err)
	}
	if len(group.MemberUIDs) != 1 || group.MemberUIDs[0] != "alice" {
		t.Fatalf("GetGroupByName() members = %#v; want [alice]", group.MemberUIDs)
	}

	if err := store.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	for _, candidate := range users {
		if candidate.Username == "alice" {
			t.Fatalf("ListUsers() still contains deleted user alice")
		}
	}
}

func TestStoreBaseDNSettingPersists(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	baseDN, err := store.EnsureBaseDN(ctx, "dc=example,dc=com")
	if err != nil {
		t.Fatalf("EnsureBaseDN() error = %v", err)
	}
	if baseDN != "dc=example,dc=com" {
		t.Fatalf("EnsureBaseDN() = %q; want %q", baseDN, "dc=example,dc=com")
	}

	if err := store.SetBaseDN(ctx, "DC=corp, DC=local"); err != nil {
		t.Fatalf("SetBaseDN() error = %v", err)
	}

	updated, err := store.BaseDN(ctx)
	if err != nil {
		t.Fatalf("BaseDN() error = %v", err)
	}
	if updated != "dc=corp,dc=local" {
		t.Fatalf("BaseDN() = %q; want %q", updated, "dc=corp,dc=local")
	}
}

func TestStoreBaseDNNotSetReturnsErrNoRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := store.BaseDN(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("BaseDN() error = %v; want sql.ErrNoRows", err)
	}
}

func TestStoreBaseDNPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nanoldap.db")
	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := first.EnsureBaseDN(ctx, "dc=example,dc=com"); err != nil {
		t.Fatalf("EnsureBaseDN() error = %v", err)
	}
	if err := first.SetBaseDN(ctx, "dc=corp,dc=local"); err != nil {
		t.Fatalf("SetBaseDN() error = %v", err)
	}
	if err := first.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults() error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	second, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("re-Open() error = %v", err)
	}
	defer second.Close()
	got, err := second.BaseDN(ctx)
	if err != nil {
		t.Fatalf("BaseDN() error = %v", err)
	}
	if got != "dc=corp,dc=local" {
		t.Fatalf("BaseDN() after reopen = %q; want %q", got, "dc=corp,dc=local")
	}
	users, err := second.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 4 {
		t.Fatalf("ListUsers() after reopen = %d; want 4", len(users))
	}
}

func TestStoreCreateUserRejectsEmptyInput(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	for name, input := range map[string]UserInput{
		"empty username": {Username: " ", Password: "secret"},
		"empty password": {Username: "alice", Password: " "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.CreateUser(ctx, input); err == nil {
				t.Fatalf("CreateUser(%v) error = nil; want validation error", input)
			}
		})
	}
}

func TestStoreCreateUserRejectsDuplicateUsername(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := store.CreateUser(ctx, UserInput{Username: "alice", Password: "secret"}); err != nil {
		t.Fatalf("first CreateUser() error = %v", err)
	}
	if _, err := store.CreateUser(ctx, UserInput{Username: "alice", Password: "other"}); err == nil {
		t.Fatalf("second CreateUser() error = nil; want UNIQUE constraint failure")
	}
}

func TestStoreCreateUserRejectsUnknownGroup(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := store.CreateUser(ctx, UserInput{
		Username:   "alice",
		Password:   "secret",
		GroupNames: []string{"nonexistent"},
	}); err == nil {
		t.Fatalf("CreateUser() error = nil; want unknown-group failure")
	}
	if _, err := store.GetUserByUsername(ctx, "alice"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserByUsername() = %v; want sql.ErrNoRows (transaction rolled back)", err)
	}
}

func TestStoreGetUserByUsernameNotFound(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := store.GetUserByUsername(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetUserByUsername() error = %v; want sql.ErrNoRows", err)
	}
}

func TestStoreUpdateGroupRenameAndDelete(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	group, err := store.CreateGroup(ctx, GroupInput{Name: "ops", Description: "operators"})
	if err != nil {
		t.Fatalf("CreateGroup() error = %v", err)
	}
	updated, err := store.UpdateGroup(ctx, group.ID, GroupInput{Name: "platform", Description: "platform team"})
	if err != nil {
		t.Fatalf("UpdateGroup() error = %v", err)
	}
	if updated.Name != "platform" || updated.Description != "platform team" {
		t.Fatalf("UpdateGroup() = %#v; want renamed/redescribed", updated)
	}
	if err := store.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatalf("DeleteGroup() error = %v", err)
	}
	if _, err := store.GetGroupByID(ctx, group.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetGroupByID() after delete error = %v; want sql.ErrNoRows", err)
	}
}

func TestStoreIsMemberOfMatchesCaseInsensitively(t *testing.T) {
	user := User{
		Groups: []Group{
			{Name: "Admins"},
			{Name: "users"},
		},
	}
	if !IsMemberOf(user, "admins") {
		t.Fatalf("IsMemberOf(admins) = false; want true (case-insensitive)")
	}
	if !IsMemberOf(user, "USERS") {
		t.Fatalf("IsMemberOf(USERS) = false; want true (case-insensitive)")
	}
	if IsMemberOf(user, "guests") {
		t.Fatalf("IsMemberOf(guests) = true; want false")
	}
}

func TestStoreAuthenticateUserWrongPassword(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "nanoldap.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	if _, err := store.CreateUser(ctx, UserInput{Username: "alice", Password: "secret"}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if _, err := store.AuthenticateUser(ctx, "alice", "wrong"); err == nil {
		t.Fatalf("AuthenticateUser(wrong) error = nil; want failure")
	}
	if _, err := store.AuthenticateUser(ctx, "alice", "secret"); err != nil {
		t.Fatalf("AuthenticateUser(correct) error = %v; want success", err)
	}
}
