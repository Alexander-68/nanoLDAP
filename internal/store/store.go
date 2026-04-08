package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"nanoldap/internal/auth"
	"nanoldap/internal/directory"
)

type Store struct {
	db *sql.DB
}

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	DisplayName  string
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Groups       []Group
}

type Group struct {
	ID          int64
	Name        string
	Description string
	MemberUIDs  []string
}

type UserInput struct {
	Username    string
	Password    string
	DisplayName string
	Disabled    bool
	GroupNames  []string
}

type GroupInput struct {
	Name        string
	Description string
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	stmts := []string{
		`PRAGMA foreign_keys = ON;`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			display_name TEXT NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, group_id)
		);`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SeedDefaults(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	defaultGroups := []GroupInput{
		{Name: "admins", Description: "Administrative users"},
		{Name: "mvradmins", Description: "Privileged LDAP service accounts"},
		{Name: "users", Description: "Standard users"},
		{Name: "guests", Description: "Guest users"},
	}
	for _, group := range defaultGroups {
		if _, err := s.CreateGroup(ctx, group); err != nil {
			return err
		}
	}

	defaultUsers := []UserInput{
		{Username: "admin", Password: "admin", DisplayName: "Administrator", GroupNames: []string{"admins"}},
		{Username: "mvradmin", Password: "mvradmin", DisplayName: "MVR Administrator", GroupNames: []string{"mvradmins"}},
		{Username: "user", Password: "user", DisplayName: "Standard User", GroupNames: []string{"users"}},
		{Username: "guest", Password: "guest", DisplayName: "Guest User", GroupNames: []string{"guests"}},
	}
	for _, user := range defaultUsers {
		if _, err := s.CreateUser(ctx, user); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) EnsureBaseDN(ctx context.Context, fallback string) (string, error) {
	current, err := s.BaseDN(ctx)
	switch {
	case err == nil:
		return current, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}

	normalized, err := directory.NormalizeBaseDN(fallback)
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES ('base_dn', ?)
		ON CONFLICT(key) DO NOTHING
	`, normalized); err != nil {
		return "", err
	}
	return s.BaseDN(ctx)
}

func (s *Store) BaseDN(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'base_dn'`).Scan(&value)
	if err != nil {
		return "", err
	}
	return directory.NormalizeBaseDN(value)
}

func (s *Store) SetBaseDN(ctx context.Context, baseDN string) error {
	normalized, err := directory.NormalizeBaseDN(baseDN)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value) VALUES ('base_dn', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, normalized)
	return err
}

func (s *Store) AuthenticateUser(ctx context.Context, username, password string) (User, error) {
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return User{}, err
	}
	ok, err := auth.VerifyPassword(user.PasswordHash, password)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, sql.ErrNoRows
	}
	return user, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users WHERE username = ?`, username)
	return s.scanUser(ctx, row)
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users WHERE id = ?`, id)
	return s.scanUser(ctx, row)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}

	var users []User
	for rows.Next() {
		var user User
		var createdAt, updatedAt string
		var disabled int
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.DisplayName, &disabled, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		user.Disabled = disabled == 1
		user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range users {
		users[i].Groups, err = s.userGroups(ctx, users[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func (s *Store) CreateUser(ctx context.Context, input UserInput) (User, error) {
	if strings.TrimSpace(input.Username) == "" || strings.TrimSpace(input.Password) == "" {
		return User{}, errors.New("username and password are required")
	}
	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, display_name, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(input.Username), passwordHash, displayOrUsername(input.DisplayName, input.Username), boolInt(input.Disabled), now, now,
	)
	if err != nil {
		return User{}, err
	}
	userID, err := result.LastInsertId()
	if err != nil {
		return User{}, err
	}
	if err := assignGroupsTx(ctx, tx, userID, input.GroupNames); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUserByID(ctx, userID)
}

func (s *Store) UpdateUser(ctx context.Context, id int64, input UserInput) (User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	current, err := s.getUserTx(ctx, tx, id)
	if err != nil {
		return User{}, err
	}
	passwordHash := current.PasswordHash
	if strings.TrimSpace(input.Password) != "" {
		passwordHash, err = auth.HashPassword(input.Password)
		if err != nil {
			return User{}, err
		}
	}
	displayName := current.DisplayName
	if trimmed := strings.TrimSpace(input.DisplayName); trimmed != "" {
		displayName = trimmed
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE users SET display_name = ?, password_hash = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		displayName, passwordHash, boolInt(input.Disabled), time.Now().UTC().Format(time.RFC3339Nano), id,
	)
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ?`, id); err != nil {
		return User{}, err
	}
	if err := assignGroupsTx(ctx, tx, id, input.GroupNames); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUserByID(ctx, id)
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}

	var groups []Group
	for rows.Next() {
		var group Group
		if err := rows.Scan(&group.ID, &group.Name, &group.Description); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range groups {
		groups[i].MemberUIDs, err = s.groupMembers(ctx, groups[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func (s *Store) CreateGroup(ctx context.Context, input GroupInput) (Group, error) {
	if strings.TrimSpace(input.Name) == "" {
		return Group{}, errors.New("group name is required")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO groups (name, description) VALUES (?, ?)`, strings.TrimSpace(input.Name), strings.TrimSpace(input.Description))
	if err != nil {
		return Group{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Group{}, err
	}
	return s.GetGroupByID(ctx, id)
}

func (s *Store) UpdateGroup(ctx context.Context, id int64, input GroupInput) (Group, error) {
	if strings.TrimSpace(input.Name) == "" {
		return Group{}, errors.New("group name is required")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE groups SET name = ?, description = ? WHERE id = ?`, strings.TrimSpace(input.Name), strings.TrimSpace(input.Description), id)
	if err != nil {
		return Group{}, err
	}
	return s.GetGroupByID(ctx, id)
}

func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	return err
}

func (s *Store) GetGroupByName(ctx context.Context, name string) (Group, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, description FROM groups WHERE name = ?`, name)
	return s.scanGroup(ctx, row)
}

func (s *Store) GetGroupByID(ctx context.Context, id int64) (Group, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, description FROM groups WHERE id = ?`, id)
	return s.scanGroup(ctx, row)
}

func (s *Store) scanUser(ctx context.Context, scanner interface{ Scan(dest ...any) error }) (User, error) {
	var user User
	var createdAt, updatedAt string
	var disabled int
	if err := scanner.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.DisplayName, &disabled, &createdAt, &updatedAt); err != nil {
		return User{}, err
	}
	user.Disabled = disabled == 1
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	groups, err := s.userGroups(ctx, user.ID)
	if err != nil {
		return User{}, err
	}
	user.Groups = groups
	return user, nil
}

func (s *Store) scanGroup(ctx context.Context, scanner interface{ Scan(dest ...any) error }) (Group, error) {
	var group Group
	if err := scanner.Scan(&group.ID, &group.Name, &group.Description); err != nil {
		return Group{}, err
	}
	members, err := s.groupMembers(ctx, group.ID)
	if err != nil {
		return Group{}, err
	}
	group.MemberUIDs = members
	return group, nil
}

func (s *Store) userGroups(ctx context.Context, userID int64) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, g.description
		FROM groups g
		INNER JOIN user_groups ug ON ug.group_id = g.id
		WHERE ug.user_id = ?
		ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var group Group
		if err := rows.Scan(&group.ID, &group.Name, &group.Description); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (s *Store) groupMembers(ctx context.Context, groupID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.username
		FROM users u
		INNER JOIN user_groups ug ON ug.user_id = u.id
		WHERE ug.group_id = ?
		ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		members = append(members, username)
	}
	return members, rows.Err()
}

func (s *Store) getUserTx(ctx context.Context, tx *sql.Tx, id int64) (User, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, username, password_hash, display_name, disabled, created_at, updated_at FROM users WHERE id = ?`, id)
	var user User
	var createdAt, updatedAt string
	var disabled int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.DisplayName, &disabled, &createdAt, &updatedAt); err != nil {
		return User{}, err
	}
	user.Disabled = disabled == 1
	return user, nil
}

func assignGroupsTx(ctx context.Context, tx *sql.Tx, userID int64, groupNames []string) error {
	for _, name := range uniqueNames(groupNames) {
		var groupID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM groups WHERE name = ?`, name).Scan(&groupID); err != nil {
			return fmt.Errorf("group %q: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)`, userID, groupID); err != nil {
			return err
		}
	}
	return nil
}

func IsMemberOf(user User, names ...string) bool {
	for _, group := range user.Groups {
		for _, candidate := range names {
			if strings.EqualFold(group.Name, candidate) {
				return true
			}
		}
	}
	return false
}

func displayOrUsername(displayName, username string) string {
	if strings.TrimSpace(displayName) == "" {
		return strings.TrimSpace(username)
	}
	return strings.TrimSpace(displayName)
}

func uniqueNames(names []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
