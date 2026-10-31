package idp

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/pkg/config"
)

func adminConfig(t *testing.T) config.OIDC {
	return config.OIDC{StateDir: t.TempDir(), AdminGroups: []string{"admins"}}
}

// browser returns another browser using the same provider, with cookies of its own.
func (h *harness) browser() *harness {
	jar, _ := cookiejar.New(nil)
	c := *h.c
	c.Jar = jar
	return &harness{t: h.t, p: h.p, srv: h.srv, c: &c}
}

// signInTo signs in to an application and returns its tokens.
func (h *harness) signInTo(clientID, username string) tokenResponse {
	h.t.Helper()
	redirect := "https://" + clientID + "/cb"
	login, _ := h.startLogin(clientID, redirect)
	resp, _ := h.get(login)
	if resp.StatusCode == http.StatusOK {
		resp = h.submitLogin(login, username, "correct horse")
	} // otherwise already signed in
	app := h.followToApp(resp)
	status, tokens := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {app.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {clientID}, "code_verifier": {testVerifier}})
	if status != http.StatusOK {
		h.t.Fatalf("signing %s in to %s: %d %+v", username, clientID, status, tokens)
	}
	return tokens
}

// adminSignIn signs in to the admin page.
func (h *harness) adminSignIn(username string) {
	h.t.Helper()
	resp, _ := h.get("/admin")
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "/login?next=%2Fadmin" {
		h.t.Fatalf("admin page without a session: %d to %q", resp.StatusCode, loc)
	}
	resp = h.submitLogin("/login?next=%2Fadmin", username, "correct horse")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin" {
		h.t.Fatalf("signing in to the admin page: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// adminPost submits an admin form with the browser's CSRF token.
func (h *harness) adminPost(path string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	u, _ := url.Parse(h.srv.URL + "/")
	for _, c := range h.c.Jar.Cookies(u) {
		if c.Name == csrfCookie {
			form.Set("csrf", c.Value)
		}
	}
	return h.post(path, form)
}

func (h *harness) userinfoStatus(accessToken string) int {
	req, _ := http.NewRequest(http.MethodGet, h.url("/userinfo"), nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, _ := h.do(req)
	return resp.StatusCode
}

func (h *harness) refreshStatus(clientID, refreshToken string) int {
	status, _ := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID}})
	return status
}

func TestAdminAccess(t *testing.T) {
	if resp, _ := newHarness(t, config.OIDC{}).get("/admin"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("admin page without admin groups: got %d", resp.StatusCode)
	}
	h := newHarness(t, adminConfig(t))
	bob := h.browser()
	bob.adminSignIn("bob")
	if resp, _ := bob.get("/admin"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob isn't an admin: got %d", resp.StatusCode)
	}
	if resp, _ := bob.adminPost("/admin/sessions/end-user", url.Values{"username": {"alice"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob ending sessions: got %d", resp.StatusCode)
	}
	h.adminSignIn("alice")
	if resp, body := h.get("/admin"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Signed in as <strong>alice") {
		t.Fatalf("alice's admin page: %d", resp.StatusCode)
	}
	if resp, _ := h.post("/admin/sessions/end-user", url.Values{"username": {"bob"}, "csrf": {"forged"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged CSRF token: got %d", resp.StatusCode)
	}
	if resp, _ := h.get("/login?next=https%3A%2F%2Fevil.example.org%2F"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("sign-in returning to another site: got %d", resp.StatusCode)
	}
}

var handlePattern = regexp.MustCompile(`name="session" value="([^"]+)"`)

func TestAdminEndsSessions(t *testing.T) {
	h := newHarness(t, adminConfig(t))
	h.adminSignIn("alice")
	bob := h.browser()
	tokens := bob.signInTo(testApp, "bob")

	_, page := h.get("/admin")
	if !strings.Contains(page, "<strong>bob</strong>") || !strings.Contains(page, testApp) {
		t.Fatalf("admin page doesn't list bob's session: %s", page)
	}
	// End the first session listed that isn't alice's own: bob's.
	var bobHandle string
	for _, sess := range h.p.store.listSessions(timeNow()) {
		if sess.User.Username == "bob" {
			bobHandle = sess.Handle
		}
	}
	if !strings.Contains(page, bobHandle) || len(handlePattern.FindAllString(page, -1)) != 2 {
		t.Fatal("admin page doesn't name both sessions")
	}
	if resp, _ := h.adminPost("/admin/sessions/end", url.Values{"session": {bobHandle}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("ending bob's session: got %d", resp.StatusCode)
	}
	if status := h.userinfoStatus(tokens.AccessToken); status == http.StatusOK {
		t.Fatal("bob's access token still works")
	}
	if status := h.refreshStatus(testApp, tokens.RefreshToken); status == http.StatusOK {
		t.Fatal("bob's refresh token still works")
	}
	resp, _ := bob.get(authorizeURL(testApp, testRedirect, nil))
	if resp, body := bob.get(resp.Header.Get("Location")); !strings.Contains(body, `name="password"`) {
		t.Fatalf("bob isn't asked for his password again: %d", resp.StatusCode)
	}
	// Alice is still signed in.
	if resp, _ := h.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice's session ended too: %d", resp.StatusCode)
	}

	bob.signInTo(testApp, "bob")
	h.browser().signInTo("other.example.test", "bob")
	h.adminPost("/admin/sessions/end-user", url.Values{"username": {"bob"}})
	for _, sess := range h.p.store.listSessions(timeNow()) {
		if sess.User.Username == "bob" {
			t.Fatal("ending all of bob's sessions left one")
		}
	}
}

func TestAdminBlocksApps(t *testing.T) {
	cfg := adminConfig(t)
	h := newHarness(t, cfg)
	h.adminSignIn("alice")
	bob := h.browser()
	tokens := bob.signInTo(testApp, "bob")

	if resp, _ := h.adminPost("/admin/apps/block", url.Values{"client": {testApp}, "for": {"1h"}, "reason": {"upgrading"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("blocking: got %d", resp.StatusCode)
	}
	if status := h.userinfoStatus(tokens.AccessToken); status == http.StatusOK {
		t.Fatal("a blocked application's access token still works")
	}
	if status := h.refreshStatus(testApp, tokens.RefreshToken); status == http.StatusOK {
		t.Fatal("a blocked application's refresh token still works")
	}
	resp, _ := bob.get(authorizeURL(testApp, testRedirect, nil))
	if resp, body := bob.get(resp.Header.Get("Location")); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "upgrading") {
		t.Fatalf("signing in to a blocked application: %d %s", resp.StatusCode, body)
	}
	// Other applications still work.
	bob.signInTo("other.example.test", "bob")

	// The block is saved, so it outlasts a restart.
	data, err := os.ReadFile(filepath.Join(cfg.StateDir, adminFileName))
	if err != nil || !strings.Contains(string(data), `client = "app.example.test"`) {
		t.Fatalf("admin file: %v %s", err, data)
	}
	restarted, err := New(h.p.cfg, users, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if _, blocked := restarted.settings.Load().blocked(testApp, timeNow()); !blocked {
		t.Fatal("block lost on restart")
	}

	h.adminPost("/admin/apps/unblock", url.Values{"client": {testApp}})
	bob.signInTo(testApp, "bob")
}

var secretPattern = regexp.MustCompile(`client secret to ([A-Za-z0-9_-]+) `)

func TestAdminSetsUpApps(t *testing.T) {
	h := newHarness(t, adminConfig(t))
	h.adminSignIn("alice")
	if resp, body := h.get("/admin/apps/edit"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Add an application") {
		t.Fatalf("new application form: %d", resp.StatusCode)
	}
	resp, body := h.adminPost("/admin/apps/save", url.Values{"id": {testApp}, "name": {"The App"},
		"groups": {"admins"}, "secret": {"new"}})
	m := secretPattern.FindStringSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("saving an application: %d %s", resp.StatusCode, body)
	}
	secret := m[1]

	exchange := func(secret string) int {
		h.c.Jar, _ = cookiejar.New(nil)
		login, _ := h.startLogin(testApp, testRedirect)
		app := h.followToApp(h.submitLogin(login, "alice", "correct horse"))
		status, _ := h.exchange(testApp, secret, app.Query().Get("code"))
		return status
	}
	if exchange("wrong") == http.StatusOK {
		t.Fatal("wrong secret accepted")
	}
	if status := exchange(secret); status != http.StatusOK {
		t.Fatalf("secret refused: %d", status)
	}
	bob := h.browser()
	login, _ := bob.startLogin(testApp, testRedirect)
	if resp := bob.submitLogin(login, "bob", "correct horse"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob isn't in admins: got %d", resp.StatusCode)
	}

	// Callback URLs must name a fixed host.
	if resp, _ := h.adminPost("/admin/apps/save", url.Values{"id": {"wild"}, "redirectURIs": {"https://*.example.org/**"}, "secret": {"none"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wildcard host: got %d", resp.StatusCode)
	}
	// Removing the application lets bob in again.
	h.adminPost("/admin/apps/delete", url.Values{"id": {testApp}})
	bob.signInTo(testApp, "bob")
}

func TestAdminSettings(t *testing.T) {
	cfg := adminConfig(t)
	h := newHarness(t, cfg)
	h.adminSignIn("alice")
	if resp, _ := h.adminPost("/admin/settings", url.Values{"sessionLifetime": {"soon"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad lifetime: got %d", resp.StatusCode)
	}
	resp, _ := h.adminPost("/admin/settings", url.Values{"brandName": {"Lab"}, "sessionLifetime": {"2h"}, "trustedDomains": {"lab.example.org"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("saving settings: got %d", resp.StatusCode)
	}
	h.browser().signInTo("wiki.lab.example.org", "bob")
	if _, body := h.get("/admin"); !strings.Contains(body, `<p class="brand">Lab`) {
		t.Fatal("brand name not applied")
	}

	// Edits made to the file by hand are picked up.
	path := filepath.Join(cfg.StateDir, adminFileName)
	if err := os.WriteFile(path, []byte("brandName = \"By hand\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.p.adminMtime = h.p.adminMtime.Add(-1) // in case the clock didn't move
	h.p.reloadAdmin()
	if s := h.p.settings.Load(); s.brand != "By hand" || trustedHost(s.trustedDomains, "wiki.lab.example.org") {
		t.Fatalf("hand edit not applied: %+v", s)
	}
	// A broken file is ignored, keeping the settings in effect.
	if err := os.WriteFile(path, []byte("clients = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.p.adminMtime = h.p.adminMtime.Add(-1)
	h.p.reloadAdmin()
	if h.p.settings.Load().brand != "By hand" {
		t.Fatal("broken admin file replaced the settings")
	}
}

func timeNow() time.Time { return time.Now() }

func TestAdminWantsRecentPassword(t *testing.T) {
	cfg := adminConfig(t)
	cfg.AdminReauthAfter = "10m"
	h := newHarness(t, cfg)
	h.adminSignIn("alice")
	tokens := h.signInTo(testApp, "alice")
	age := func(h *harness) {
		for _, sess := range h.p.store.sessions {
			sess.authTime = sess.authTime.Add(-11 * time.Minute)
		}
	}
	age(h)

	again := "/login?next=%2Fadmin"
	if resp, _ := h.get("/admin"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != again {
		t.Fatalf("admin page with an old sign-in: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := h.adminPost("/admin/sessions/end-user", url.Values{"username": {"bob"}}); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != again {
		t.Fatalf("admin form with an old sign-in: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := h.get(again); resp.StatusCode != http.StatusOK || !strings.Contains(body, `value="alice"`) || !strings.Contains(body, "password again") {
		t.Fatalf("asking for the password again: %d %s", resp.StatusCode, body)
	}
	if resp := h.submitLogin(again, "alice", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d", resp.StatusCode)
	}
	if resp := h.submitLogin(again, "alice", "correct horse"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin" {
		t.Fatalf("giving the password again: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := h.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page after giving the password again: %d", resp.StatusCode)
	}
	// The same session was renewed, so the application's tokens still work.
	if n := len(h.p.store.listSessions(timeNow())); n != 1 {
		t.Fatalf("got %d sessions, want 1", n)
	}
	if status := h.userinfoStatus(tokens.AccessToken); status != http.StatusOK {
		t.Fatalf("app's token after renewing the session: %d", status)
	}

	// Signing in as someone else on the same browser starts a new session.
	h.adminPost("/login", url.Values{"next": {"/admin"}, "username": {"bob"}, "password": {"correct horse"}})
	if n := len(h.p.store.listSessions(timeNow())); n != 2 {
		t.Fatalf("got %d sessions after another user signed in, want 2", n)
	}

	cfg = adminConfig(t)
	cfg.AdminReauthAfter = "never"
	h = newHarness(t, cfg)
	h.adminSignIn("alice")
	age(h)
	if resp, _ := h.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page with an old sign-in and adminReauthAfter = never: %d", resp.StatusCode)
	}
	if resp, _ := h.get("/login?next=%2Fadmin"); resp.StatusCode != http.StatusFound {
		t.Fatalf("admin sign-in with adminReauthAfter = never: %d", resp.StatusCode)
	}

	for _, bad := range []string{"soon", "0s", "-5m"} {
		cfg.AdminReauthAfter = bad
		if _, err := New(cfg, users, zerolog.Nop()); err == nil {
			t.Errorf("adminReauthAfter %q was accepted", bad)
		}
	}
}
