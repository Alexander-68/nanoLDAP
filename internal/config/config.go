package config

import (
	"flag"
	"os"
	"strconv"
	"time"
)

type Config struct {
	BindAddr           string
	BaseDN             string
	DBPath             string
	AuditLog           string
	CertFile           string
	KeyFile            string
	LDAPDebug          bool
	HTTPPort           int
	HTTPSPort          int
	LDAPPort           int
	LDAPSPort          int
	SessionIdleTimeout time.Duration
	SessionMax         int
	LDAPIdleTimeout    time.Duration
	LDAPBindWindow     time.Duration
	LDAPBindLimit      int
	LDAPSearchRate     int
	LDAPMaxConnections int
}

func Load() Config {
	cfg := Config{
		BindAddr:           envString("NANOLDAP_BIND_ADDR", "0.0.0.0"),
		BaseDN:             envString("NANOLDAP_BASE_DN", "dc=example,dc=com"),
		DBPath:             envString("NANOLDAP_DB_PATH", "nanoldap.db"),
		AuditLog:           envString("NANOLDAP_AUDIT_LOG", "stdout"),
		CertFile:           envString("NANOLDAP_CERT_FILE", "cert.pem"),
		KeyFile:            envString("NANOLDAP_KEY_FILE", "key.pem"),
		HTTPPort:           envInt("NANOLDAP_HTTP_PORT", 0),
		HTTPSPort:          envInt("NANOLDAP_HTTPS_PORT", 0),
		LDAPPort:           envInt("NANOLDAP_LDAP_PORT", 0),
		LDAPSPort:          envInt("NANOLDAP_LDAPS_PORT", 0),
		SessionIdleTimeout: 15 * time.Minute,
		SessionMax:         3,
		LDAPIdleTimeout:    5 * time.Second,
		LDAPBindWindow:     10 * time.Second,
		LDAPBindLimit:      3,
		LDAPSearchRate:     50,
		LDAPMaxConnections: 16,
	}

	flag.StringVar(&cfg.BindAddr, "bind-addr", cfg.BindAddr, "listener bind address")
	flag.StringVar(&cfg.BaseDN, "base-dn", cfg.BaseDN, "directory base DN")
	flag.StringVar(&cfg.DBPath, "db-path", cfg.DBPath, "sqlite database path")
	flag.StringVar(&cfg.AuditLog, "audit-log", cfg.AuditLog, "audit log destination path or stdout")
	flag.StringVar(&cfg.CertFile, "cert-file", cfg.CertFile, "certificate file path")
	flag.StringVar(&cfg.KeyFile, "key-file", cfg.KeyFile, "private key file path")
	flag.BoolVar(&cfg.LDAPDebug, "ldap-debug", cfg.LDAPDebug, "enable LDAP request/response debug logging")
	flag.IntVar(&cfg.HTTPPort, "http-port", cfg.HTTPPort, "HTTP web UI and public certificate endpoint port")
	flag.IntVar(&cfg.HTTPSPort, "https-port", cfg.HTTPSPort, "HTTPS web UI port")
	flag.IntVar(&cfg.LDAPPort, "ldap-port", cfg.LDAPPort, "LDAP port")
	flag.IntVar(&cfg.LDAPSPort, "ldaps-port", cfg.LDAPSPort, "LDAPS port")
	flag.Parse()
	return cfg
}

func (c Config) Addr(port int) string {
	return c.BindAddr + ":" + strconv.Itoa(port)
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
