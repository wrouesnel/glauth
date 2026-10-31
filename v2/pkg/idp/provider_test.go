package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/pkg/config"
)

const (
	testIssuer   = "https://auth.example.test"
	testApp      = "app.example.test"
	testRedirect = "https://app.example.test/oauth2/callback"
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-the-verifier"
)

type fakeAuth map[string]Identity

func (f fakeAuth) Authenticate(_ context.Context, username, password string) (*Identity, error) {
	id, ok := f[username]
	if !ok || password != "correct horse" {
		return nil, ErrInvalidCredentials
	}
	return &id, nil
}

var users = fakeAuth{
	"alice": {Username: "alice", Name: "Alice Example", GivenName: "Alice", Surname: "Example",
		Email: "alice@example.test", Groups: []string{"users", "admins"}},
	"bob": {Username: "bob", Name: "Bob", Groups: []string{"users"}},
}

// harness drives a provider like a browser and an application would.
type harness struct {
	t   *testing.T
	p   *Provider
	srv *httptest.Server
	c   *http.Client
}

func newHarness(t *testing.T, cfg config.OIDC) *harness {
	t.Helper()
	if cfg.Domain == "" {
		cfg.Domain = "example.test"
	}
	p, err := New(cfg, users, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	srv := httptest.NewTLSServer(p)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &harness{t: t, p: p, srv: srv, c: c}
}

// url maps a URL on the issuer to the test server.
func (h *harness) url(u string) string {
	return h.srv.URL + strings.TrimPrefix(u, testIssuer)
}

func (h *harness) do(req *http.Request) (*http.Response, string) {
	h.t.Helper()
	resp, err := h.c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// getResp is get without the body, for chaining into followToApp.
func (h *harness) getResp(u string) *http.Response {
	h.t.Helper()
	resp, _ := h.get(u)
	return resp
}

func (h *harness) get(u string) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.url(u), nil)
	return h.do(req)
}

func (h *harness) post(u string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.url(u), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(req)
}

func authorizeURL(clientID, redirect string, extra url.Values) string {
	sum := sha256.Sum256([]byte(testVerifier))
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {"openid profile email groups offline_access"},
		"state":                 {"the-state"},
		"nonce":                 {"the-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return "/authorize?" + q.Encode()
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// startLogin sends the browser to the authorize endpoint and returns the sign-in page's request ID and CSRF token.
func (h *harness) startLogin(clientID, redirect string) (loginPath string, _ string) {
	h.t.Helper()
	resp, _ := h.get(authorizeURL(clientID, redirect, nil))
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?id=") {
		h.t.Fatalf("authorize: got %d to %q, want a redirect to the sign-in page", resp.StatusCode, resp.Header.Get("Location"))
	}
	return resp.Header.Get("Location"), ""
}

func (h *harness) submitLogin(loginPath, username, password string) *http.Response {
	h.t.Helper()
	resp, body := h.get(loginPath)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
		h.t.Fatalf("sign-in page: %d %s", resp.StatusCode, body)
	}
	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("no CSRF token in %s", body)
	}
	id, _ := url.Parse(loginPath)
	resp, _ = h.post("/login", url.Values{
		"id": {id.Query().Get("id")}, "next": {id.Query().Get("next")},
		"csrf": {m[1]}, "username": {username}, "password": {password},
	})
	return resp
}

// followToApp follows redirects within the provider until one leaves for the application.
func (h *harness) followToApp(resp *http.Response) *url.URL {
	h.t.Helper()
	for i := 0; i < 5; i++ {
		if resp.StatusCode != http.StatusFound {
			h.t.Fatalf("got %d, want a redirect", resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			h.t.Fatal(err)
		}
		if loc.Host != "" && loc.Host != "auth.example.test" {
			return loc
		}
		resp, _ = h.get(loc.RequestURI())
	}
	h.t.Fatal("too many redirects")
	return nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
}

func (h *harness) token(form url.Values) (int, tokenResponse) {
	h.t.Helper()
	resp, body := h.post("/oauth/token", form)
	var tr tokenResponse
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		h.t.Fatalf("token response %d: %s", resp.StatusCode, body)
	}
	return resp.StatusCode, tr
}

func (h *harness) exchange(clientID, secret, code string) (int, tokenResponse) {
	return h.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect},
		"client_id": {clientID}, "client_secret": {secret}, "code_verifier": {testVerifier},
	})
}

// claims verifies a token's signature against the provider's published keys.
func (h *harness) claims(token string) map[string]any {
	h.t.Helper()
	_, body := h.get("/keys")
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(body), &set); err != nil {
		h.t.Fatal(err)
	}
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		h.t.Fatal(err)
	}
	keys := set.Key(sig.Signatures[0].Header.KeyID)
	if len(keys) != 1 {
		h.t.Fatalf("token signed by unpublished key %q", sig.Signatures[0].Header.KeyID)
	}
	payload, err := sig.Verify(keys[0])
	if err != nil {
		h.t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		h.t.Fatal(err)
	}
	return claims
}

func audience(claims map[string]any) []string {
	var aud []string
	list, _ := claims["aud"].([]any)
	for _, a := range list {
		aud = append(aud, a.(string))
	}
	return aud
}

func groupsClaimOf(claims map[string]any) []string {
	var groups []string
	list, _ := claims["groups"].([]any)
	for _, g := range list {
		groups = append(groups, g.(string))
	}
	return groups
}

func TestSignInFlow(t *testing.T) {
	h := newHarness(t, config.OIDC{})

	_, body := h.get("/.well-known/openid-configuration")
	var discovery map[string]any
	if err := json.Unmarshal([]byte(body), &discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["issuer"] != testIssuer || discovery["token_endpoint"] != testIssuer+"/oauth/token" {
		t.Fatalf("discovery: %s", body)
	}

	login, _ := h.startLogin(testApp, testRedirect)
	if resp := h.submitLogin(login, "alice", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d", resp.StatusCode)
	}
	app := h.followToApp(h.submitLogin(login, "alice", "correct horse"))
	if app.Host != testApp || app.Query().Get("state") != "the-state" || app.Query().Get("code") == "" {
		t.Fatalf("redirect to app: %s", app)
	}
	code := app.Query().Get("code")

	// Any secret will do for an application under the domain.
	status, tokens := h.exchange(testApp, "anything", code)
	if status != http.StatusOK || tokens.IDToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("token exchange: %d %+v", status, tokens)
	}
	id := h.claims(tokens.IDToken)
	if id["iss"] != testIssuer || id["sub"] != "alice" || !slices.Equal(audience(id), []string{testApp}) || id["nonce"] != "the-nonce" ||
		id["email"] != "alice@example.test" || id["email_verified"] != true || id["preferred_username"] != "alice" ||
		id["name"] != "Alice Example" || !slices.Equal(groupsClaimOf(id), []string{"users", "admins"}) {
		t.Fatalf("ID token claims: %v", id)
	}
	if access := h.claims(tokens.AccessToken); !slices.Equal(groupsClaimOf(access), []string{"users", "admins"}) {
		t.Fatalf("access token claims: %v", access)
	}

	// Codes are single use.
	if status, _ := h.exchange(testApp, "anything", code); status == http.StatusOK {
		t.Fatal("code was accepted twice")
	}

	req, _ := http.NewRequest(http.MethodGet, h.url("/userinfo"), nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp, body := h.do(req)
	var info map[string]any
	_ = json.Unmarshal([]byte(body), &info)
	if resp.StatusCode != http.StatusOK || info["sub"] != "alice" || !slices.Equal(groupsClaimOf(info), []string{"users", "admins"}) {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, body)
	}

	// Refresh tokens rotate.
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
		"client_id": {testApp}, "client_secret": {"anything"}}
	status, refreshed := h.token(refresh)
	if status != http.StatusOK || refreshed.AccessToken == "" || refreshed.RefreshToken == tokens.RefreshToken {
		t.Fatalf("refresh: %d %+v", status, refreshed)
	}
	if status, _ := h.token(refresh); status == http.StatusOK {
		t.Fatal("an old refresh token was accepted")
	}

	// A second application signs in without asking for the password again.
	app = h.followToApp(h.getResp(authorizeURL("other.example.test", "https://other.example.test/cb", nil)))
	if app.Host != "other.example.test" || app.Query().Get("code") == "" {
		t.Fatalf("single sign-on: %s", app)
	}

	// prompt=login asks again.
	resp, _ = h.get(authorizeURL(testApp, testRedirect, url.Values{"prompt": {"login"}}))
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?") {
		t.Fatalf("prompt=login: redirected to %q", loc)
	} else if resp, body := h.get(loc); resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="password"`) {
		t.Fatalf("prompt=login: %d, no password form", resp.StatusCode)
	}

	// Signing out ends single sign-on.
	h.get("/logout")
	resp, _ = h.get(authorizeURL(testApp, testRedirect, nil))
	if resp, body := h.get(resp.Header.Get("Location")); resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="password"`) {
		t.Fatalf("after sign-out: %d, no password form", resp.StatusCode)
	}
}

func TestPromptNoneWithoutSession(t *testing.T) {
	h := newHarness(t, config.OIDC{})
	app := h.followToApp(h.getResp(authorizeURL(testApp, testRedirect, url.Values{"prompt": {"none"}})))
	if app.Host != testApp || app.Query().Get("error") != "login_required" || app.Query().Get("state") != "the-state" {
		t.Fatalf("prompt=none: %s", app)
	}
}

func TestRedirectPolicy(t *testing.T) {
	h := newHarness(t, config.OIDC{TrustedDomains: []string{"lab.example.org"}})
	for _, tc := range []struct {
		clientID, redirect string
		ok                 bool
	}{
		{testApp, testRedirect, true},
		{testApp, "https://app.example.test:8443/cb", true},
		{"example.test", "https://example.test/cb", true},
		{"wiki.lab.example.org", "https://wiki.lab.example.org/cb", true},
		// Tokens only go to the host named by the client ID...
		{testApp, "https://other.example.test/cb", false},
		{testApp, "https://app.example.test.evil.org/cb", false},
		{testApp, "https://app.example.test@evil.org/cb", false},
		// ...over HTTPS...
		{testApp, "http://app.example.test/cb", false},
		// ...and only under a trusted domain.
		{"app.example.org", "https://app.example.org/cb", false},
		{"badexample.test", "https://badexample.test/cb", false},
		{"my app", "https://app.example.test/cb", false},
	} {
		resp, body := h.get(authorizeURL(tc.clientID, tc.redirect, nil))
		got := resp.StatusCode == http.StatusFound && strings.HasPrefix(resp.Header.Get("Location"), "/login?")
		if got != tc.ok {
			t.Errorf("client %q redirect %q: got %d %q %s, want allowed=%v", tc.clientID, tc.redirect,
				resp.StatusCode, resp.Header.Get("Location"), strings.TrimSpace(body), tc.ok)
		}
		if !tc.ok && strings.Contains(resp.Header.Get("Location"), "evil") {
			t.Errorf("client %q redirect %q: sent the browser to %q", tc.clientID, tc.redirect, resp.Header.Get("Location"))
		}
	}
}

func TestClientGroups(t *testing.T) {
	h := newHarness(t, config.OIDC{Clients: []config.OIDCClient{{ID: testApp, Name: "Admin tool", Groups: []string{"admins"}}}})
	login, _ := h.startLogin(testApp, testRedirect)
	if resp := h.submitLogin(login, "bob", "correct horse"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob, not an admin: got %d", resp.StatusCode)
	}
	// Bob's session doesn't stop Alice signing in on the same browser.
	login, _ = h.startLogin(testApp, testRedirect)
	if resp, body := h.get(login); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "bob isn&#39;t allowed") {
		t.Fatalf("bob's session: %d %s", resp.StatusCode, body)
	}
	if app := h.followToApp(h.submitLogin(login, "alice", "correct horse")); app.Query().Get("code") == "" {
		t.Fatalf("alice, an admin: %s", app)
	}
}

func TestClientSecrets(t *testing.T) {
	h := newHarness(t, config.OIDC{
		ClientSecrets: secretsDerived,
		StateDir:      t.TempDir(),
		Clients:       []config.OIDCClient{{ID: "fixed.example.test", Secret: "s3cret"}},
	})
	signIn := func(clientID, redirect string) string {
		h.c.Jar, _ = cookiejar.New(nil) // sign in afresh each time
		login, _ := h.startLogin(clientID, redirect)
		return h.followToApp(h.submitLogin(login, "alice", "correct horse")).Query().Get("code")
	}
	derived, err := DerivedSecret(h.p.cfg, testApp)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := h.exchange(testApp, "anything", signIn(testApp, testRedirect)); status == http.StatusOK {
		t.Fatal("wrong derived secret accepted")
	}
	if status, tr := h.exchange(testApp, derived, signIn(testApp, testRedirect)); status != http.StatusOK {
		t.Fatalf("derived secret refused: %d %+v", status, tr)
	}
	code := signIn("fixed.example.test", "https://fixed.example.test/cb")
	status, _ := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://fixed.example.test/cb"}, "client_id": {"fixed.example.test"},
		"client_secret": {"s3cret"}, "code_verifier": {testVerifier}})
	if status != http.StatusOK {
		t.Fatalf("configured secret refused: %d", status)
	}
}

func TestLoginCSRF(t *testing.T) {
	h := newHarness(t, config.OIDC{})
	login, _ := h.startLogin(testApp, testRedirect)
	id, _ := url.Parse(login)
	resp, _ := h.post("/login", url.Values{"id": {id.Query().Get("id")}, "csrf": {"forged"},
		"username": {"alice"}, "password": {"correct horse"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged CSRF token: got %d", resp.StatusCode)
	}
}

func TestThrottle(t *testing.T) {
	h := newHarness(t, config.OIDC{})
	login, _ := h.startLogin(testApp, testRedirect)
	for i := 0; i < throttleFailures; i++ {
		h.submitLogin(login, "alice", "wrong")
	}
	if resp := h.submitLogin(login, "alice", "correct horse"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: got %d", throttleFailures, resp.StatusCode)
	}
}

func TestKeysPersist(t *testing.T) {
	dir := t.TempDir()
	a, err := loadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.signingID != b.signingID || string(a.secretKey) != string(b.secretKey) {
		t.Fatal("keys changed between loads")
	}
}
