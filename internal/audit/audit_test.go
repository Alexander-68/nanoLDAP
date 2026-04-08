package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLoggerWritesEventToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := New(path)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logger.WebLogin("10.0.0.1", "admin", "success")
	logger.LDAPBind("10.0.0.2", "user", "invalid_credentials")
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(audit.log) error = %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var records []map[string]any
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("json.Unmarshal(%q) error = %v", scanner.Text(), err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d; want 2", len(records))
	}

	for index, want := range []map[string]string{
		{"event": "web_login", "source_ip": "10.0.0.1", "username": "admin", "result": "success"},
		{"event": "ldap_bind", "source_ip": "10.0.0.2", "username": "user", "result": "invalid_credentials"},
	} {
		for key, expected := range want {
			if got, _ := records[index][key].(string); got != expected {
				t.Fatalf("record %d %q = %q; want %q", index, key, got, expected)
			}
		}
		ts, _ := records[index]["time"].(string)
		if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			t.Fatalf("record %d time %q is not RFC3339Nano: %v", index, ts, err)
		}
	}
}

func TestLoggerStdoutFallback(t *testing.T) {
	logger, err := New("stdout")
	if err != nil {
		t.Fatalf("New(stdout) error = %v", err)
	}
	if logger.w == nil {
		t.Fatalf("logger.w is nil for stdout")
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() should be a no-op for stdout, got error = %v", err)
	}
}

func TestLoggerConcurrentEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := New(path)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer logger.Close()

	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range 32 {
				logger.LDAPBind("10.0.0.1", "user", "success")
			}
			_ = id
		}(worker)
	}
	wg.Wait()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("json.Unmarshal(%q) error = %v", scanner.Text(), err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error = %v", err)
	}
	if count != 16*32 {
		t.Fatalf("event count = %d; want %d", count, 16*32)
	}
}

func TestLoggerNilReceiverIsNoop(t *testing.T) {
	var logger *Logger
	logger.WebLogin("10.0.0.1", "admin", "success")
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() on nil logger error = %v", err)
	}
}
