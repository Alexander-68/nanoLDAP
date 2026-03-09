package auth

import "testing"

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
