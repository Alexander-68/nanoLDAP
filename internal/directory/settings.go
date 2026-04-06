package directory

import (
	"errors"
	"strings"
	"sync"
)

type Settings struct {
	mu     sync.RWMutex
	baseDN string
}

func NewSettings(baseDN string) (*Settings, error) {
	normalized, err := NormalizeBaseDN(baseDN)
	if err != nil {
		return nil, err
	}
	return &Settings{baseDN: normalized}, nil
}

func (s *Settings) BaseDN() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.baseDN
}

func (s *Settings) SetBaseDN(baseDN string) error {
	normalized, err := NormalizeBaseDN(baseDN)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.baseDN = normalized
	s.mu.Unlock()
	return nil
}

func NormalizeBaseDN(input string) (string, error) {
	parts := strings.Split(input, ",")
	if len(parts) == 0 {
		return "", errors.New("base DN is required")
	}

	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		attr, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "", errors.New("base DN must use domain components like dc=example,dc=com")
		}
		if !strings.EqualFold(strings.TrimSpace(attr), "dc") {
			return "", errors.New("base DN must use domain components like dc=example,dc=com")
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", errors.New("base DN must use non-empty domain components")
		}
		normalized = append(normalized, "dc="+value)
	}
	return strings.Join(normalized, ","), nil
}
