package app

import (
	"context"
	"crypto/tls"
	"net/http"

	"nanoldap/internal/audit"
	"nanoldap/internal/config"
	"nanoldap/internal/directory"
	"nanoldap/internal/session"
	"nanoldap/internal/store"
	"nanoldap/internal/tlsutil"
	"nanoldap/internal/web"
)

type App struct {
	cfg       config.Config
	store     *store.Store
	audit     *audit.Logger
	sessions  *session.Store
	settings  *directory.Settings
	certPEM   []byte
	tlsCert   tls.Certificate
	webServer *web.Server
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	certPEM, tlsCert, err := tlsutil.EnsurePair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	dataStore, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}
	if err := dataStore.SeedDefaults(ctx); err != nil {
		_ = dataStore.Close()
		return nil, err
	}
	baseDN, err := dataStore.EnsureBaseDN(ctx, cfg.BaseDN)
	if err != nil {
		_ = dataStore.Close()
		return nil, err
	}
	settings, err := directory.NewSettings(baseDN)
	if err != nil {
		_ = dataStore.Close()
		return nil, err
	}
	auditLog, err := audit.New(cfg.AuditLog)
	if err != nil {
		_ = dataStore.Close()
		return nil, err
	}
	sessions := session.New(cfg.SessionIdleTimeout, cfg.SessionMax)
	instance := &App{
		cfg:      cfg,
		store:    dataStore,
		audit:    auditLog,
		sessions: sessions,
		settings: settings,
		certPEM:  certPEM,
		tlsCert:  tlsCert,
	}
	instance.webServer = web.New(cfg, settings, dataStore, sessions, auditLog, certPEM)
	return instance, nil
}

func (a *App) Close() {
	if a == nil {
		return
	}
	_ = a.store.Close()
	_ = a.audit.Close()
}

func (a *App) Config() config.Config           { return a.cfg }
func (a *App) Store() *store.Store             { return a.store }
func (a *App) Audit() *audit.Logger            { return a.audit }
func (a *App) Settings() *directory.Settings   { return a.settings }
func (a *App) TLSCertificate() tls.Certificate { return a.tlsCert }
func (a *App) PublicMux() http.Handler         { return a.webServer.PublicMux() }
func (a *App) SecureMux() http.Handler         { return a.webServer.SecureMux() }
