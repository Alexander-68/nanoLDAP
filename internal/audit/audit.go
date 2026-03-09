package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu sync.Mutex
	w  io.WriteCloser
}

func New(destination string) (*Logger, error) {
	if destination == "" || destination == "stdout" {
		return &Logger{w: nopCloser{Writer: os.Stdout}}, nil
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{w: file}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.w == nil {
		return nil
	}
	return l.w.Close()
}

func (l *Logger) Event(kind string, fields map[string]any) {
	if l == nil {
		return
	}
	record := map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
		"event": kind,
	}
	for key, value := range fields {
		record[key] = value
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(payload, '\n'))
}

func (l *Logger) WebLogin(sourceIP, username, result string) {
	l.Event("web_login", map[string]any{
		"source_ip": sourceIP,
		"username":  username,
		"result":    result,
	})
}

func (l *Logger) LDAPBind(sourceIP, username, result string) {
	l.Event("ldap_bind", map[string]any{
		"source_ip": sourceIP,
		"username":  username,
		"result":    result,
	})
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }
