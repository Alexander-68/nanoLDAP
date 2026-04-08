package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if ok, err := VerifyPassword(hash, "secret"); err != nil || !ok {
		t.Fatalf("VerifyPassword() = %v, %v; want true, nil", ok, err)
	}
	if ok, err := VerifyPassword(hash, "wrong"); err != nil || ok {
		t.Fatalf("VerifyPassword() = %v, %v; want false, nil", ok, err)
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	first, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	second, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if first == second {
		t.Fatalf("HashPassword() produced identical hashes for the same password; salt is not random")
	}
}

func TestVerifyPasswordRejectsEmptyPasswordAgainstNonEmptyHash(t *testing.T) {
	hash, err := HashPassword("not-empty")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if ok, err := VerifyPassword(hash, ""); err != nil || ok {
		t.Fatalf("VerifyPassword(empty) = %v, %v; want false, nil", ok, err)
	}
}

func TestVerifyPasswordRejectsMalformedPHC(t *testing.T) {
	cases := map[string]string{
		"not a hash":                    "not a hash",
		"wrong segment count":           "$argon2id$v=19$m=64,t=1,p=4$abc",
		"wrong variant":                 "$argon2i$v=19$m=64,t=1,p=4$YWFh$YmJi",
		"wrong version":                 "$argon2id$v=18$m=64,t=1,p=4$YWFh$YmJi",
		"unknown parameter":             "$argon2id$v=19$m=64,t=1,p=4,x=1$YWFh$YmJi",
		"non-numeric parameter value":   "$argon2id$v=19$m=abc,t=1,p=4$YWFh$YmJi",
		"missing parameter equals sign": "$argon2id$v=19$mishap$YWFh$YmJi",
		"bad base64 salt":               "$argon2id$v=19$m=64,t=1,p=4$!!!$YmJi",
		"bad base64 hash":               "$argon2id$v=19$m=64,t=1,p=4$YWFh$!!!",
	}
	for name, phc := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword(phc, "anything")
			if err == nil {
				t.Fatalf("VerifyPassword(%q) = %v, nil; want non-nil error", phc, ok)
			}
			if ok {
				t.Fatalf("VerifyPassword(%q) returned ok=true on malformed input", phc)
			}
		})
	}
}

func TestHashPasswordPHCFormat(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("HashPassword() = %q; expected argon2id PHC prefix", hash)
	}
	if strings.Count(hash, "$") != 5 {
		t.Fatalf("HashPassword() = %q; expected 5 dollar separators", hash)
	}
}
