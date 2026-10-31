package idp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/glauth/ldap"
)

// Identity is what a successful sign-in tells us about a user.
type Identity struct {
	Username  string
	Name      string
	GivenName string
	Surname   string
	Email     string
	Groups    []string
}

// ErrInvalidCredentials is returned for a wrong user name or password.
var ErrInvalidCredentials = errors.New("invalid user name or password")

// Authenticator checks a user's password and looks up who they are.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
}

// usernamePattern limits user names to characters that need no escaping in a DN or
// filter, which covers POSIX names and the names glauth's backends produce.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)

// LDAPAuthenticator signs in by binding to an LDAP server as the user, then reads the
// user's own entry. It needs no service account: glauth lets any user read themselves.
type LDAPAuthenticator struct {
	URL           string // ldap://host:port or ldaps://host:port
	BaseDN        string
	NameAttribute string
	TLSConfig     *tls.Config
	Timeout       time.Duration
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	if !usernamePattern.MatchString(username) || password == "" {
		return nil, ErrInvalidCredentials
	}
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// The client has no request timeouts, so closing the connection ends a stalled exchange.
	stop := context.AfterFunc(ctx, conn.Close)
	defer stop()
	timer := time.AfterFunc(a.timeout(), conn.Close)
	defer timer.Stop()

	dn := fmt.Sprintf("%s=%s,%s", a.NameAttribute, username, a.BaseDN)
	if err := conn.Bind(dn, password); err != nil {
		var lerr *ldap.Error
		if errors.As(err, &lerr) && (lerr.ResultCode == ldap.LDAPResultInvalidCredentials ||
			lerr.ResultCode == ldap.LDAPResultUnwillingToPerform) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("binding to %s: %w", a.URL, err)
	}

	filter := fmt.Sprintf("(&(objectClass=posixAccount)(%s=%s))", a.NameAttribute, username)
	res, err := conn.Search(ldap.NewSearchRequest(a.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false, filter,
		[]string{"uid", "cn", "displayName", "givenName", "sn", "mail", "memberOf"}, nil))
	if err != nil {
		return nil, fmt.Errorf("reading %s's entry: %w", username, err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("reading %s's entry: found %d entries", username, len(res.Entries))
	}
	return identityFromEntry(username, res.Entries[0]), nil
}

func (a *LDAPAuthenticator) dial() (*ldap.Conn, error) {
	u, err := url.Parse(a.URL)
	if err != nil {
		return nil, fmt.Errorf("LDAP URL %q: %w", a.URL, err)
	}
	timeout := a.timeout()
	switch u.Scheme {
	case "ldap":
		return ldap.DialTimeout("tcp", u.Host, timeout)
	case "ldaps":
		return ldap.DialTLSDialer("tcp", u.Host, a.TLSConfig, &net.Dialer{Timeout: timeout})
	default:
		return nil, fmt.Errorf("LDAP URL %q: scheme must be ldap or ldaps", a.URL)
	}
}

func (a *LDAPAuthenticator) timeout() time.Duration {
	if a.Timeout == 0 {
		return 10 * time.Second
	}
	return a.Timeout
}

func identityFromEntry(username string, e *ldap.Entry) *Identity {
	id := &Identity{
		Username:  username,
		Name:      firstOf(e.GetAttributeValue("displayName"), e.GetAttributeValue("cn")),
		GivenName: e.GetAttributeValue("givenName"),
		Surname:   e.GetAttributeValue("sn"),
		Email:     e.GetAttributeValue("mail"),
	}
	for _, dn := range e.GetAttributeValues("memberOf") {
		if name := firstRDNValue(dn); name != "" {
			id.Groups = append(id.Groups, name)
		}
	}
	return id
}

// firstRDNValue returns "admins" for "ou=admins,ou=groups,dc=example,dc=com".
func firstRDNValue(dn string) string {
	rdn, _, _ := strings.Cut(dn, ",")
	_, value, ok := strings.Cut(rdn, "=")
	if !ok {
		return ""
	}
	return value
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
