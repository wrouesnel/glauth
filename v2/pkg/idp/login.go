package idp

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	sessionCookie = "glauth_session"
	csrfCookie    = "glauth_csrf"
)

// loginPage signs the user in to an application: straight away if they already have
// a session, otherwise by asking for their password. Without an auth request, it
// signs the user in to one of the provider's own pages, named by next.
func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := time.Now()
	sess := p.currentSession(r, now)
	if q.Get("id") == "" {
		next, ok := p.localNext(q.Get("next"))
		if !ok {
			p.message(w, http.StatusBadRequest, "Nothing to sign in to", "Go to the application you want to use, and sign in from there.")
			return
		}
		if sess == nil {
			p.showLogin(w, r, http.StatusOK, nil, nil, next, "", "")
			return
		}
		if p.adminFreshEnough(sess, now) {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		// The admin pages need a recent password, not just a session.
		p.render(w, http.StatusOK, "login", pageData{
			Title:    "Sign in",
			Message:  "Enter your password again to manage sign-ins.",
			CSRF:     p.csrfToken(w, r),
			Username: sess.user.Username,
			Next:     next,
		})
		return
	}
	req, c, ok := p.loginRequest(w, r, q.Get("id"))
	if !ok {
		return
	}
	if sess != nil && !slices.Contains(req.prompt, oidc.PromptLogin) &&
		(req.maxAge == nil || now.Sub(sess.authTime) <= *req.maxAge) {
		p.finish(w, r, req, c, sess)
		return
	}
	if slices.Contains(req.prompt, oidc.PromptNone) {
		op.AuthRequestError(w, r, req, oidc.ErrLoginRequired(), p.op)
		return
	}
	p.showLogin(w, r, http.StatusOK, req, c, "", "", "")
}

func (p *Provider) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !p.parseForm(w, r) {
		return
	}
	var (
		req  *authRequest
		c    *client
		next string
	)
	if id := r.PostForm.Get("id"); id != "" {
		var ok bool
		if req, c, ok = p.loginRequest(w, r, id); !ok {
			return
		}
	} else {
		var ok bool
		if next, ok = p.localNext(r.PostForm.Get("next")); !ok {
			p.message(w, http.StatusBadRequest, "Nothing to sign in to", "Go to the application you want to use, and sign in from there.")
			return
		}
	}
	if !p.checkCSRF(r) {
		p.showLogin(w, r, http.StatusForbidden, req, c, next, "", "Your sign-in form expired. Please try again.")
		return
	}

	username, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	clientID := ""
	if c != nil {
		clientID = c.id
	}
	now := time.Now()
	if !p.throttle.allowed(username, now) {
		p.log.Warn().Str("username", username).Str("client", clientID).Msg("oidc: sign-in refused: too many failed attempts")
		p.showLogin(w, r, http.StatusTooManyRequests, req, c, next, username, "Too many failed attempts. Wait a few minutes and try again.")
		return
	}
	user, err := p.auth.Authenticate(r.Context(), username, password)
	if errors.Is(err, ErrInvalidCredentials) {
		p.throttle.failed(username, now)
		p.log.Info().Str("username", username).Str("client", clientID).Msg("oidc: sign-in failed")
		p.showLogin(w, r, http.StatusUnauthorized, req, c, next, username, "Wrong user name or password.")
		return
	}
	if err != nil {
		p.log.Error().Err(err).Str("username", username).Msg("oidc: could not check password")
		p.showLogin(w, r, http.StatusServiceUnavailable, req, c, next, username, "Signing in isn't working right now. Please try again later.")
		return
	}
	p.throttle.succeeded(username)
	p.log.Info().Str("username", user.Username).Str("client", clientID).Msg("oidc: signed in")

	// Signing in again as the same user renews the browser's session, keeping the
	// applications' tokens; anyone else gets a session of their own.
	var sess *session
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		sess = p.store.renewSession(cookie.Value, user, now)
	}
	if sess == nil {
		var value string
		sess, value = p.store.newSession(user, now, clientAddress(r), r.UserAgent())
		cookie = &http.Cookie{Value: value}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    cookie.Value,
		Path:     p.basePath + "/",
		Expires:  sess.expires,
		HttpOnly: true,
		Secure:   p.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	if req == nil {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	p.finish(w, r, req, c, sess)
}

// localNext accepts a page of the provider's own to return to after signing in.
func (p *Provider) localNext(next string) (string, bool) {
	admin := p.basePath + "/admin"
	if next == admin || strings.HasPrefix(next, admin+"/") || strings.HasPrefix(next, admin+"?") {
		return next, true
	}
	return "", false
}

// loginRequest finds the auth request a sign-in page is for, or shows an error.
func (p *Provider) loginRequest(w http.ResponseWriter, r *http.Request, id string) (*authRequest, *client, bool) {
	req, err := p.store.authRequest(id)
	if err != nil {
		p.message(w, http.StatusBadRequest, "Sign-in expired", "This sign-in link has expired. Go back to the application and start again.")
		return nil, nil, false
	}
	c, err := p.lookupClient(req.clientID)
	if err != nil {
		p.message(w, http.StatusBadRequest, "Unknown application", "This application can't sign in here.")
		return nil, nil, false
	}
	if b, blocked := p.settings.Load().blocked(c.id, time.Now()); blocked {
		msg := c.name + " has been turned off by an administrator"
		if !b.Until.IsZero() {
			msg += " until " + b.Until.Local().Format("Mon 2 Jan 15:04 MST")
		}
		if b.Reason != "" {
			msg += ": " + b.Reason
		}
		p.message(w, http.StatusForbidden, "Application turned off", msg+".")
		return nil, nil, false
	}
	return req, c, true
}

// finish completes the auth request with the session's user, and sends the browser
// back to the application.
func (p *Provider) finish(w http.ResponseWriter, r *http.Request, req *authRequest, c *client, sess *session) {
	if !c.allows(sess.user.Groups) {
		// Offer the form, so someone else can sign in on this browser.
		p.log.Info().Str("username", sess.user.Username).Str("client", c.id).Msg("oidc: sign-in refused: not in an allowed group")
		p.showLogin(w, r, http.StatusForbidden, req, c, "", "", sess.user.Username+" isn't allowed to use "+c.name+". Sign in with another account.")
		return
	}
	if err := p.store.completeAuthRequest(req.id, sess, time.Now()); err != nil {
		p.message(w, http.StatusBadRequest, "Sign-in expired", "This sign-in link has expired. Go back to the application and start again.")
		return
	}
	ctx := op.ContextWithIssuer(r.Context(), p.issuer.String())
	http.Redirect(w, r, op.AuthCallbackURL(p.op)(ctx, req.id), http.StatusFound)
}

func (p *Provider) showLogin(w http.ResponseWriter, r *http.Request, status int, req *authRequest, c *client, next, username, message string) {
	data := pageData{
		Title:    "Sign in",
		Error:    message,
		CSRF:     p.csrfToken(w, r),
		Username: username,
		Next:     next,
	}
	if req != nil {
		data.RequestID, data.App = req.id, c.name
	}
	p.render(w, status, "login", data)
}

// csrfToken returns the browser's CSRF token, which every form must send back.
func (p *Provider) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookie); err == nil && len(cookie.Value) >= 32 {
		return cookie.Value
	}
	token := randomID()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     p.basePath + "/",
		HttpOnly: true,
		Secure:   p.secureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func (p *Provider) checkCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.PostForm.Get("csrf"))) == 1
}

func (p *Provider) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return false
	}
	return true
}

func (p *Provider) render(w http.ResponseWriter, status int, page string, data pageData) {
	data.Brand = p.settings.Load().brand
	data.Base = p.basePath
	p.ui.render(w, status, page, data)
}

func (p *Provider) message(w http.ResponseWriter, status int, title, message string) {
	p.render(w, status, "message", pageData{Title: title, Message: message})
}

func (p *Provider) currentSession(r *http.Request, now time.Time) *session {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	return p.store.session(cookie.Value, now)
}

func (p *Provider) clearSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		p.store.endSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Path:     p.basePath + "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   p.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

// logout ends the browser's session, so the next application asks for the password.
func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	p.clearSession(w, r)
	http.Redirect(w, r, p.basePath+"/logged-out", http.StatusFound)
}

func (p *Provider) loggedOut(w http.ResponseWriter, _ *http.Request) {
	p.message(w, http.StatusOK, "Signed out", "You have been signed out.")
}

// endSession ends the browser's session as well as the application's tokens when an
// application signs the user out through the end_session endpoint.
func (p *Provider) endSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.clearSession(w, r)
		next.ServeHTTP(w, r)
	})
}

// clientAddress is where a request came from, as the reverse proxy reports it. It is
// only shown to admins, to help them recognise sessions, so it needn't be trusted.
func clientAddress(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
