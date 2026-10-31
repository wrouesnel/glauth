package idp

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// restart replaces the provider with a new one on the same config, as a restart
// would, keeping the browser's cookies.
func (h *harness) restart() *harness {
	h.t.Helper()
	h.p.Close()
	p, err := New(h.p.cfg, users, zerolog.Nop())
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(p.Close)
	srv := httptest.NewTLSServer(p)
	h.t.Cleanup(srv.Close)
	oldURL, _ := url.Parse(h.srv.URL + "/")
	newURL, _ := url.Parse(srv.URL + "/")
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(newURL, h.c.Jar.Cookies(oldURL))
	c := srv.Client()
	c.Jar = jar
	c.CheckRedirect = h.c.CheckRedirect
	return &harness{t: h.t, p: p, srv: srv, c: c}
}

func TestSessionsOutlastRestarts(t *testing.T) {
	cfg := adminConfig(t)
	h := newHarness(t, cfg)
	tokens := h.signInTo(testApp, "alice")

	h = h.restart()
	// The browser is still signed in, so the next application doesn't ask for a password.
	if app := h.followToApp(h.getResp(authorizeURL("other.example.test", "https://other.example.test/cb", nil))); app.Query().Get("code") == "" {
		t.Fatalf("single sign-on after a restart: %s", app)
	}
	if status := h.userinfoStatus(tokens.AccessToken); status != http.StatusOK {
		t.Fatalf("access token after a restart: %d", status)
	}
	status, refreshed := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {testApp}})
	if status != http.StatusOK {
		t.Fatalf("refresh token after a restart: %d", status)
	}
	sessions := h.p.store.listSessions(timeNow())
	if len(sessions) != 1 || !slices.Equal(sessions[0].Clients, []string{"app.example.test", "other.example.test"}) {
		t.Fatalf("sessions after a restart: %+v", sessions)
	}
	if _, ok := h.p.store.recentApps()[testApp]; !ok {
		t.Fatal("recent applications lost on restart")
	}

	// The state file holds no cookie or token a thief could use.
	cookie := ""
	u, _ := url.Parse(h.srv.URL + "/")
	for _, c := range h.c.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			cookie = c.Value
		}
	}
	data, err := os.ReadFile(filepath.Join(cfg.StateDir, stateDBFile))
	if err != nil {
		t.Fatal(err)
	}
	wal, _ := os.ReadFile(filepath.Join(cfg.StateDir, stateDBFile+"-wal"))
	for _, secret := range []string{cookie, tokens.RefreshToken, refreshed.RefreshToken} {
		if secret == "" || strings.Contains(string(data)+string(wal), secret) {
			t.Fatalf("state file contains a secret (or the test lost it: %q)", secret)
		}
	}

	// Ending a session is saved too.
	h.p.store.endSessions(func(*session) bool { return true })
	h = h.restart()
	if len(h.p.store.listSessions(timeNow())) != 0 {
		t.Fatal("an ended session came back after a restart")
	}
	if status := h.refreshStatus(testApp, refreshed.RefreshToken); status == http.StatusOK {
		t.Fatal("an ended session's refresh token works after a restart")
	}
}
