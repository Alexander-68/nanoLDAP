package httplog

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestServerErrorLoggerSuppressesUnknownCertificateHandshakeNoise(t *testing.T) {
	var buf bytes.Buffer
	logger := NewServerErrorLogger(&buf)

	logger.Print("http: TLS handshake error from 127.0.0.1:55957: remote error: tls: unknown certificate")
	logger.Print("http: TLS handshake error from 127.0.0.1:55957: EOF")
	logger.Print("http: proxy error: dial tcp 127.0.0.1:1: connectex: actively refused")

	output := buf.String()
	if strings.Contains(output, "unknown certificate") {
		t.Fatalf("logger output still contains suppressed handshake noise: %q", output)
	}
	for _, snippet := range []string{
		"http: TLS handshake error from 127.0.0.1:55957: EOF",
		"http: proxy error: dial tcp 127.0.0.1:1: connectex: actively refused",
	} {
		if !strings.Contains(output, snippet) {
			t.Fatalf("logger output missing %q: %q", snippet, output)
		}
	}
}

func TestFilterWriterHandlesSplitWrites(t *testing.T) {
	var buf bytes.Buffer
	writer := &filterWriter{dst: &buf}

	parts := []string{
		log.Prefix(),
		"2026/04/07 10:00:00 http: TLS handshake error from 127.0.0.1:1: remote error: tls: unknown certificate",
		"\n",
		"2026/04/07 10:00:01 http: server gave HTTP response to HTTPS client\n",
	}
	for _, part := range parts {
		if _, err := writer.Write([]byte(part)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	output := buf.String()
	if strings.Contains(output, "unknown certificate") {
		t.Fatalf("split-write output still contains suppressed line: %q", output)
	}
	if !strings.Contains(output, "server gave HTTP response to HTTPS client") {
		t.Fatalf("split-write output missing non-suppressed line: %q", output)
	}
}
