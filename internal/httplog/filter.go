package httplog

import (
	"io"
	"log"
	"strings"
	"sync"
)

func NewServerErrorLogger(dst io.Writer) *log.Logger {
	return log.New(&filterWriter{dst: dst}, "", log.LstdFlags)
}

type filterWriter struct {
	mu      sync.Mutex
	dst     io.Writer
	pending string
}

func (w *filterWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending += string(p)
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			return len(p), nil
		}
		line := w.pending[:idx+1]
		w.pending = w.pending[idx+1:]
		if shouldSuppress(line) {
			continue
		}
		if _, err := io.WriteString(w.dst, line); err != nil {
			return 0, err
		}
	}
}

func shouldSuppress(line string) bool {
	return strings.Contains(line, "http: TLS handshake error") &&
		strings.Contains(line, "remote error: tls: unknown certificate")
}
