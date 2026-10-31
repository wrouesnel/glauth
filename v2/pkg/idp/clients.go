package idp

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	secretsIgnore  = "ignore"
	secretsDerived = "derived"
)

var errUnknownClient = errors.New("unknown client: register it, or use the host name of an application under a trusted domain as its client ID")

// client is an application allowed to sign users in. Configured clients come from
// [[oidc.clients]] or the admin page; any other client ID is accepted when it is a
// host name under a trusted domain, and then may only receive tokens at that host.
type client struct {
	id           string
	name         string
	secret       string
	secretSHA256 string
	redirectURIs []string
	groups       []string
	loginURL     func(string) string
}

// lookupClient returns the configured client with this ID, or an implicit client
// when the ID names a host under a trusted domain.
func (p *Provider) lookupClient(id string) (*client, error) {
	s := p.settings.Load()
	host := strings.ToLower(id)
	if c, ok := s.clients[id]; ok {
		configured := &client{
			id:           c.id,
			name:         firstOf(c.name, host),
			secret:       c.secret,
			secretSHA256: c.secretSHA256,
			redirectURIs: c.redirectURIs,
			groups:       c.groups,
			loginURL:     p.loginURL,
		}
		if len(configured.redirectURIs) == 0 {
			configured.redirectURIs = hostRedirects(host)
		}
		return configured, nil
	}
	if !trustedHost(s.trustedDomains, host) {
		return nil, errUnknownClient
	}
	return &client{id: id, name: host, redirectURIs: hostRedirects(host), loginURL: p.loginURL}, nil
}

// hostRedirects lets an application receive tokens on any path and port of its own
// host, but only over HTTPS.
func hostRedirects(host string) []string {
	return []string{"https://" + host + "/**", "https://" + host + ":*/**"}
}

// trustedHost reports whether host is a valid DNS name under one of the domains.
func trustedHost(domains []string, host string) bool {
	if !validHostname(host) {
		return false
	}
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// errBlocked is returned for an application an admin has blocked.
var errBlocked = errors.New("application is blocked")

// checkBlocked fails if an admin has blocked the application.
func (p *Provider) checkBlocked(clientID string) error {
	if _, ok := p.settings.Load().blocked(clientID, time.Now()); ok {
		return errBlocked
	}
	return nil
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// checkSecret authenticates a client at the token endpoint.
func (p *Provider) checkSecret(c *client, secret string) error {
	if err := p.checkBlocked(c.id); err != nil {
		return err
	}
	switch {
	case c.secret != "":
		return compareSecret(c.secret, secret)
	case c.secretSHA256 != "":
		return compareSecret(c.secretSHA256, hashSecret(secret))
	case p.cfg.ClientSecrets == secretsDerived:
		return compareSecret(p.keys.derivedSecret(c.id), secret)
	default:
		// Implicit clients are trusted because tokens only go to hosts we control.
		return nil
	}
}

func compareSecret(want, got string) error {
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("invalid client secret")
	}
	return nil
}

// derivedSecret is the client secret required for clientID when secrets are derived.
func (k *keys) derivedSecret(clientID string) string {
	mac := hmac.New(sha256.New, k.subkey("client-secret"))
	mac.Write([]byte(clientID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// allows reports whether a user in groups may sign in to the client.
func (c *client) allows(groups []string) bool {
	if len(c.groups) == 0 {
		return true
	}
	for _, g := range groups {
		if slices.Contains(c.groups, g) {
			return true
		}
	}
	return false
}

var _ op.HasRedirectGlobs = (*client)(nil)

func (c *client) GetID() string                    { return c.id }
func (c *client) RedirectURIs() []string           { return nil }
func (c *client) RedirectURIGlobs() []string       { return c.redirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return nil }
func (c *client) PostLogoutRedirectURIGlobs() []string {
	return c.redirectURIs
}
func (c *client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }

// AuthMethod is basic, which also covers secrets sent in the form body and, while
// secrets aren't checked, public clients that send none.
func (c *client) AuthMethod() oidc.AuthMethod { return oidc.AuthMethodBasic }
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *client) LoginURL(id string) string            { return c.loginURL(id) }
func (c *client) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeJWT }
func (c *client) IDTokenLifetime() time.Duration       { return time.Hour }
func (c *client) DevMode() bool                        { return false }
func (c *client) IsScopeAllowed(string) bool           { return true }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *client) ClockSkew() time.Duration             { return 0 }
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
