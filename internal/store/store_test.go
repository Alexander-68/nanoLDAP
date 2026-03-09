package store

import (
	"context"
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
