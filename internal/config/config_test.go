package config

import "testing"

func TestEnvStringFallback(t *testing.T) {
	const key = "NANOLDAP_TEST_STRING"
	t.Setenv(key, "")
	if got := envString(key, "fallback"); got != "fallback" {
		t.Fatalf("envString(empty) = %q; want %q", got, "fallback")
	}
	t.Setenv(key, "value")
	if got := envString(key, "fallback"); got != "value" {
		t.Fatalf("envString(value) = %q; want %q", got, "value")
	}
}

func TestEnvIntFallbackAndParse(t *testing.T) {
	const key = "NANOLDAP_TEST_INT"
	t.Setenv(key, "")
	if got := envInt(key, 7); got != 7 {
		t.Fatalf("envInt(empty) = %d; want 7", got)
	}
	t.Setenv(key, "42")
	if got := envInt(key, 7); got != 42 {
		t.Fatalf("envInt(42) = %d; want 42", got)
	}
	t.Setenv(key, "not-a-number")
	if got := envInt(key, 7); got != 7 {
		t.Fatalf("envInt(garbage) = %d; want fallback 7", got)
	}
}

func TestConfigAddrFormat(t *testing.T) {
	cfg := Config{BindAddr: "127.0.0.1"}
	if got := cfg.Addr(389); got != "127.0.0.1:389" {
		t.Fatalf("Addr() = %q; want %q", got, "127.0.0.1:389")
	}
}
