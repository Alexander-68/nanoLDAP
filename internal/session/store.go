package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrSessionLimit = errors.New("session limit reached")

type Session struct {
	ID        string
	Username  string
	ExpiresAt time.Time
	LastSeen  time.Time
}

type Store struct {
	mu       sync.Mutex
	sessions map[string]Session
	timeout  time.Duration
	max      int
}

func New(timeout time.Duration, max int) *Store {
	return &Store{
		sessions: make(map[string]Session),
		timeout:  timeout,
		max:      max,
	}
}

func (s *Store) Create(username string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(time.Now())
	if len(s.sessions) >= s.max {
		return Session{}, ErrSessionLimit
	}

	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return Session{}, err
	}
	now := time.Now()
	session := Session{
		ID:        hex.EncodeToString(token[:]),
		Username:  username,
		LastSeen:  now,
		ExpiresAt: now.Add(s.timeout),
	}
	s.sessions[session.ID] = session
	return session, nil
}

func (s *Store) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(time.Now())
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	now := time.Now()
	session.LastSeen = now
	session.ExpiresAt = now.Add(s.timeout)
	s.sessions[id] = session
	return session, true
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Store) RevokeUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, id)
		}
	}
}

func (s *Store) cleanupLocked(now time.Time) {
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}
