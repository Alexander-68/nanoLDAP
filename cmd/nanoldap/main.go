package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	internalapp "nanoldap/internal/app"
	"nanoldap/internal/config"
	"nanoldap/internal/httplog"
	"nanoldap/internal/ldapserver"
)

func main() {
	if err := run(os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "nanoldap: %v\n", err)
		os.Exit(1)
	}
}

func run(stderr *os.File) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()
	if !hasEnabledListener(cfg) {
		return errors.New("no listeners enabled; specify at least one of --http-port, --https-port, --ldap-port, or --ldaps-port")
	}

	instance, err := internalapp.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer instance.Close()

	var (
		wg        sync.WaitGroup
		errCh     = make(chan error, 4)
		shutdowns []func(context.Context) error
	)
	serverErrorLog := httplog.NewServerErrorLogger(stderr)

	if cfg.HTTPPort > 0 {
		server := &http.Server{
			Addr:              cfg.Addr(cfg.HTTPPort),
			Handler:           instance.PublicMux(),
			ErrorLog:          serverErrorLog,
			ReadHeaderTimeout: 5 * time.Second,
		}
		if err := startHTTPServer(&wg, errCh, server, nil); err != nil {
			return err
		}
		shutdowns = append(shutdowns, server.Shutdown)
		_, _ = fmt.Fprintf(stderr, "HTTP listening on %s\n", server.Addr)
	}

	if cfg.HTTPSPort > 0 {
		server := &http.Server{
			Addr:              cfg.Addr(cfg.HTTPSPort),
			Handler:           instance.SecureMux(),
			ErrorLog:          serverErrorLog,
			ReadHeaderTimeout: 5 * time.Second,
		}
		if err := startHTTPServer(&wg, errCh, server, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{instance.TLSCertificate()},
		}); err != nil {
			return err
		}
		shutdowns = append(shutdowns, server.Shutdown)
		_, _ = fmt.Fprintf(stderr, "HTTPS listening on %s\n", server.Addr)
	}

	ldap := ldapserver.New(cfg, instance.Settings(), instance.Store(), instance.Audit())

	if cfg.LDAPPort > 0 {
		listener, err := net.Listen("tcp", cfg.Addr(cfg.LDAPPort))
		if err != nil {
			return err
		}
		startLDAPServer(&wg, errCh, ldap, listener)
		shutdowns = append(shutdowns, func(context.Context) error { return listener.Close() })
		_, _ = fmt.Fprintf(stderr, "LDAP listening on %s\n", listener.Addr())
	}

	if cfg.LDAPSPort > 0 {
		listener, err := net.Listen("tcp", cfg.Addr(cfg.LDAPSPort))
		if err != nil {
			return err
		}
		tlsListener, err := ldap.TLSListener(listener)
		if err != nil {
			_ = listener.Close()
			return err
		}
		startLDAPServer(&wg, errCh, ldap, tlsListener)
		shutdowns = append(shutdowns, func(context.Context) error { return tlsListener.Close() })
		_, _ = fmt.Fprintf(stderr, "LDAPS listening on %s\n", tlsListener.Addr())
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		stop()
		if err != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			shutdownAll(shutdownCtx, shutdowns)
			wg.Wait()
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownAll(shutdownCtx, shutdowns)
	wg.Wait()
	return nil
}

func hasEnabledListener(cfg config.Config) bool {
	return slices.ContainsFunc([]int{cfg.HTTPPort, cfg.HTTPSPort, cfg.LDAPPort, cfg.LDAPSPort}, func(port int) bool {
		return port > 0
	})
}

func startHTTPServer(wg *sync.WaitGroup, errCh chan<- error, server *http.Server, tlsConfig *tls.Config) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			errCh <- err
		}
	}()
	return nil
}

func startLDAPServer(wg *sync.WaitGroup, errCh chan<- error, server *ldapserver.Server, listener net.Listener) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			errCh <- err
		}
	}()
}

func shutdownAll(ctx context.Context, shutdowns []func(context.Context) error) {
	for i := len(shutdowns) - 1; i >= 0; i-- {
		_ = shutdowns[i](ctx)
	}
}
