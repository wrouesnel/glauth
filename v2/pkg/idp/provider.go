// Package idp is glauth's OpenID Connect provider. It signs users in against glauth's
// LDAP server and lets applications under the domains it trusts use it without being
// registered first.
package idp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/glauth/glauth/v2/pkg/config"
)

const defaultSessionLifetime = 12 * time.Hour

// Provider is an OpenID Connect provider, served as an http.Handler.
type Provider struct {
	cfg        config.OIDC
	log        zerolog.Logger
	auth       Authenticator
	keys       *keys
	store      *storage
	op         *op.Provider
	issuer     *url.URL
	basePath   string
	settings   atomic.Pointer[settings]
	adminPath  string
	adminMu    sync.Mutex
	adminMtime time.Time
	ui         *ui
	throttle   *throttle
	handler    http.Handler
}

// Issuer returns the issuer URL for cfg: Issuer if set, otherwise https://auth.<Domain>.
func Issuer(cfg config.OIDC) (string, error) {
	if cfg.Issuer != "" {
		return strings.TrimSuffix(cfg.Issuer, "/"), nil
	}
	if cfg.Domain == "" {
		return "", errors.New("oidc: set domain or issuer")
	}
	return "https://auth." + strings.ToLower(cfg.Domain), nil
}

// New creates a provider that signs users in with auth.
func New(cfg config.OIDC, auth Authenticator, log zerolog.Logger) (*Provider, error) {
	issuer, err := Issuer(cfg)
	if err != nil {
		return nil, err
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.Host == "" || (issuerURL.Scheme != "https" && issuerURL.Scheme != "http") {
		return nil, fmt.Errorf("oidc: issuer %q is not an http(s) URL", issuer)
	}
	switch cfg.ClientSecrets {
	case "":
		cfg.ClientSecrets = secretsIgnore
	case secretsIgnore, secretsDerived:
	default:
		return nil, fmt.Errorf("oidc: clientSecrets must be %q or %q", secretsIgnore, secretsDerived)
	}
	p := &Provider{
		cfg:      cfg,
		log:      log,
		auth:     auth,
		issuer:   issuerURL,
		basePath: strings.TrimSuffix(issuerURL.Path, "/"),
		throttle: newThrottle(),
	}
	p.adminPath = cfg.AdminFile
	if p.adminPath == "" && cfg.StateDir != "" {
		p.adminPath = filepath.Join(cfg.StateDir, adminFileName)
	}
	if len(cfg.AdminGroups) > 0 && p.adminPath == "" {
		return nil, errors.New("oidc: adminGroups needs stateDir or adminFile, to save what admins change")
	}
	admin, mtime, err := loadAdminSettings(p.adminPath)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	s, err := p.buildSettings(admin)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	p.settings.Store(s)
	p.adminMtime = mtime
	if p.keys, err = loadKeys(cfg.StateDir); err != nil {
		return nil, fmt.Errorf("oidc: loading keys: %w", err)
	}
	if cfg.StateDir == "" {
		log.Warn().Msg("oidc: no stateDir, so signing keys change on every restart and applications will reject older tokens")
	}
	if p.ui, err = newUI(cfg.Branding); err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	p.store = newStorage(p)

	opts := []op.Option{op.WithLogger(slog.New(zerologHandler{log}))}
	if issuerURL.Scheme == "http" {
		opts = append(opts, op.WithAllowInsecure())
	}
	p.op, err = op.NewProvider(&op.Config{
		CryptoKey:                p.keys.cryptoKey(),
		DefaultLogoutRedirectURI: p.basePath + "/logged-out",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedUILocales:       []language.Tag{language.English},
		SupportedScopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail,
			oidc.ScopeOfflineAccess, groupsScope},
		SupportedClaims: []string{"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "azp",
			"preferred_username", "name", "given_name", "family_name", "email", "email_verified", groupsClaim},
	}, p.store, op.StaticIssuer(issuer), opts...)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", p.loginPage)
	mux.HandleFunc("POST /login", p.loginSubmit)
	mux.HandleFunc("GET /logout", p.logout)
	mux.HandleFunc("GET /logged-out", p.loggedOut)
	p.adminRoutes(mux)
	mux.Handle("GET /static/", p.ui.static())
	mux.Handle("/end_session", p.endSession(p.op))
	mux.Handle("/", p.op)
	var h http.Handler = mux
	if p.basePath != "" {
		h = http.StripPrefix(p.basePath, h)
	}
	p.handler = securityHeaders(h)
	return p, nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.handler.ServeHTTP(w, r)
}

// Run serves the provider on cfg.Listen until ctx ends, and expires old state as it goes.
func (p *Provider) Run(ctx context.Context) error {
	listen := p.cfg.Listen
	if listen == "" {
		listen = "0.0.0.0:8080"
	}
	srv := &http.Server{Addr: listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdown)
				return
			case now := <-ticker.C:
				p.store.expire(now)
				p.throttle.expire(now)
				p.reloadAdmin()
			}
		}
	}()
	p.log.Info().Str("listen", listen).Str("issuer", p.issuer.String()).Strs("trustedDomains", p.settings.Load().trustedDomains).Msg("OIDC provider starting")
	var err error
	if p.cfg.TLSCertPath != "" {
		err = srv.ListenAndServeTLS(p.cfg.TLSCertPath, p.cfg.TLSKeyPath)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// DerivedSecret is the secret an application must present when clientSecrets is "derived".
func DerivedSecret(cfg config.OIDC, clientID string) (string, error) {
	if cfg.StateDir == "" {
		return "", errors.New("oidc: derived secrets need a stateDir to keep the key they come from")
	}
	k, err := loadKeys(cfg.StateDir)
	if err != nil {
		return "", err
	}
	return k.derivedSecret(clientID), nil
}

func (p *Provider) loginURL(id string) string {
	return p.basePath + "/login?id=" + url.QueryEscape(id)
}

func (p *Provider) secureCookies() bool {
	return p.issuer.Scheme == "https"
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
