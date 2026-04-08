package directory

import (
	"sync"
	"testing"
)

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

func TestNormalizeBaseDNRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"empty value":         "dc=,dc=com",
		"missing equals sign": "dc=example,dccom",
		"non-dc attribute":    "cn=Users,dc=example,dc=com",
		"only commas":         ",,",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeBaseDN(input); err == nil {
				t.Fatalf("NormalizeBaseDN(%q) error = nil; want validation error", input)
			}
		})
	}
}

func TestSettingsConcurrentReadWrite(t *testing.T) {
	settings, err := NewSettings("dc=example,dc=com")
	if err != nil {
		t.Fatalf("NewSettings() error = %v", err)
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := range 32 {
				if iter%2 == 0 {
					if err := settings.SetBaseDN("dc=corp,dc=local"); err != nil {
						t.Errorf("worker %d SetBaseDN error = %v", id, err)
						return
					}
				}
				_ = settings.BaseDN()
			}
		}(worker)
	}
	wg.Wait()
	if got := settings.BaseDN(); got != "dc=corp,dc=local" {
		t.Fatalf("BaseDN() final = %q; want dc=corp,dc=local", got)
	}
}
