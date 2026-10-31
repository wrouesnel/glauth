package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/idp"
)

// runOIDC serves the OIDC provider until the process is told to stop.
func runOIDC() {
	cfg := activeConfig.OIDC
	auth, err := oidcAuthenticator(activeConfig)
	if err != nil {
		log.Error().Err(err).Msg("could not configure OIDC")
		os.Exit(1)
	}
	// The OIDC library logs through slog's default logger.
	slog.SetDefault(slog.New(idp.SlogHandler(log)))
	provider, err := idp.New(cfg, auth, log)
	if err != nil {
		log.Error().Err(err).Msg("could not create OIDC provider")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := provider.Run(ctx); err != nil {
		log.Error().Err(err).Msg("could not start OIDC provider")
		os.Exit(1)
	}
}

// oidcAuthenticator checks passwords against oidc.ldap, or else this process's own
// LDAP listener.
func oidcAuthenticator(c *config.Config) (*idp.LDAPAuthenticator, error) {
	a := &idp.LDAPAuthenticator{URL: c.OIDC.LDAP, BaseDN: c.OIDC.BaseDN, NameAttribute: c.OIDC.NameAttribute}
	if len(c.Backends) > 0 {
		if a.BaseDN == "" {
			a.BaseDN = c.Backends[0].BaseDN
		}
		if a.NameAttribute == "" && len(c.Backends[0].NameFormatAsArray) > 0 {
			a.NameAttribute = c.Backends[0].NameFormatAsArray[0]
		}
	}
	if a.NameAttribute == "" {
		a.NameAttribute = "cn"
	}
	if a.BaseDN == "" {
		return nil, fmt.Errorf("oidc: set baseDN, since there is no backend to take it from")
	}
	a.TLSConfig = &tls.Config{InsecureSkipVerify: c.OIDC.LDAPInsecure} //nolint:gosec // opted into by config
	if a.URL == "" {
		switch {
		case c.LDAP.Enabled:
			a.URL = "ldap://" + loopback(c.LDAP.Listen)
		case c.LDAPS.Enabled:
			a.URL = "ldaps://" + loopback(c.LDAPS.Listen)
			// This is our own listener, whose certificate needn't name the loopback address.
			a.TLSConfig.InsecureSkipVerify = true
		}
	}
	return a, nil
}

// loopback turns a listen address like 0.0.0.0:389 into one to connect to.
func loopback(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func printOIDCSecret(cfg *config.Config, clientID string) {
	secret, err := idp.DerivedSecret(cfg.OIDC, clientID)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(secret)
}
