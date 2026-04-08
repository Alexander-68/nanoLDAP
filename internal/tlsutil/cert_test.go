package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestEnsurePairGeneratesNewCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certPEM, tlsCert, err := EnsurePair(certPath, keyPath)
	if err != nil {
		t.Fatalf("EnsurePair() error = %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatalf("EnsurePair() returned empty PEM")
	}
	if tlsCert.Leaf == nil {
		if len(tlsCert.Certificate) == 0 {
			t.Fatalf("EnsurePair() returned empty TLS certificate")
		}
		parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			t.Fatalf("x509.ParseCertificate() error = %v", err)
		}
		tlsCert.Leaf = parsed
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("EnsurePair() PEM is not a certificate block: %s", certPEM)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	if !slices.Contains(parsed.DNSNames, "localhost") {
		t.Fatalf("certificate DNSNames %v missing localhost", parsed.DNSNames)
	}
	if !containsIP(parsed.IPAddresses, net.ParseIP("127.0.0.1")) {
		t.Fatalf("certificate IPAddresses %v missing 127.0.0.1", parsed.IPAddresses)
	}
	if !containsIP(parsed.IPAddresses, net.ParseIP("::1")) {
		t.Fatalf("certificate IPAddresses %v missing ::1", parsed.IPAddresses)
	}
	if parsed.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Fatalf("certificate NotAfter = %s; expected at least 9 years in the future", parsed.NotAfter)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := keyInfo.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key file permissions = %o; want 0600", perm)
		}
	}
}

func TestEnsurePairReusesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	first, _, err := EnsurePair(certPath, keyPath)
	if err != nil {
		t.Fatalf("first EnsurePair() error = %v", err)
	}
	second, _, err := EnsurePair(certPath, keyPath)
	if err != nil {
		t.Fatalf("second EnsurePair() error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("EnsurePair() regenerated certificate on second call")
	}
}

func containsIP(haystack []net.IP, needle net.IP) bool {
	for _, candidate := range haystack {
		if candidate.Equal(needle) {
			return true
		}
	}
	return false
}
