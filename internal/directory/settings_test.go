package directory

import "testing"

func TestNormalizeBaseDN(t *testing.T) {
	got, err := NormalizeBaseDN(" DC=Example , dc=COM ")
	if err != nil {
		t.Fatalf("NormalizeBaseDN() error = %v", err)
	}
	if got != "dc=Example,dc=COM" {
		t.Fatalf("NormalizeBaseDN() = %q; want %q", got, "dc=Example,dc=COM")
	}
}

func TestNormalizeBaseDNRejectsNonDomainDN(t *testing.T) {
	if _, err := NormalizeBaseDN("ou=people,dc=example,dc=com"); err == nil {
		t.Fatalf("NormalizeBaseDN() error = nil; want validation error")
	}
}
