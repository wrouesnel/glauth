package idp

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	sessionCookie = "glauth_session"
	csrfCookie    = "glauth_csrf"
)

// loginPage signs the user in to an application: straight away if they already have
// a session, otherwise by asking for their password.
func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request) {
	req, c, ok := p.loginRequest(w, r, r.URL.Query().Get("id"))
	if !ok {
		return
	}
	now := time.Now()
	if sess := p.currentSession(r, now); sess != nil && !slices.Contains(req.prompt, oidc.PromptLogin) &&
		(req.maxAge == nil || now.Sub(sess.authTime) <= *req.maxAge) {
		p.finish(w, r, req, c, sess)
		return
	}
	if slices.Contains(req.prompt, oidc.PromptNone) {
		op.AuthRequestError(w, r, req, oidc.ErrLoginRequired(), p.op)
		return
	}
	p.showLogin(w, r, http.StatusOK, req, c, "", "")
}

func (p *Provider) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	req, c, ok := p.loginRequest(w, r, r.PostForm.Get("id"))
	if !ok {
		return
	}
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
		p.showLogin(w, r, http.StatusForbidden, req, c, "", "Your sign-in form expired. Please try again.")
		return
	}

	username, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	now := time.Now()
	if !p.throttle.allowed(username, now) {
		p.log.Warn().Str("username", username).Str("client", c.id).Msg("oidc: sign-in refused: too many failed attempts")
		p.showLogin(w, r, http.StatusTooManyRequests, req, c, username, "Too many failed attempts. Wait a few minutes and try again.")
		return
	}
	user, err := p.auth.Authenticate(r.Context(), username, password)
	if errors.Is(err, ErrInvalidCredentials) {
		p.throttle.failed(username, now)
		p.log.Info().Str("username", username).Str("client", c.id).Msg("oidc: sign-in failed")
		p.showLogin(w, r, http.StatusUnauthorized, req, c, username, "Wrong user name or password.")
		return
	}
	if err != nil {
		p.log.Error().Err(err).Str("username", username).Msg("oidc: could not check password")
		p.showLogin(w, r, http.StatusServiceUnavailable, req, c, username, "Signing in isn't working right now. Please try again later.")
		return
	}
	p.throttle.succeeded(username)
	p.log.Info().Str("username", user.Username).Str("client", c.id).Msg("oidc: signed in")

	sess := p.store.newSession(user, now)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.id,
		Path:     p.basePath + "/",
		Expires:  sess.expires,
		HttpOnly: true,
		Secure:   p.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	p.finish(w, r, req, c, sess)
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
	return req, c, true
}

// finish completes the auth request with the session's user, and sends the browser
// back to the application.
func (p *Provider) finish(w http.ResponseWriter, r *http.Request, req *authRequest, c *client, sess *session) {
	if !c.allows(sess.user.Groups) {
		// Offer the form, so someone else can sign in on this browser.
		p.log.Info().Str("username", sess.user.Username).Str("client", c.id).Msg("oidc: sign-in refused: not in an allowed group")
		p.showLogin(w, r, http.StatusForbidden, req, c, "", sess.user.Username+" isn't allowed to use "+c.name+". Sign in with another account.")
		return
	}
	if err := p.store.completeAuthRequest(req.id, sess.user, sess.authTime); err != nil {
		p.message(w, http.StatusBadRequest, "Sign-in expired", "This sign-in link has expired. Go back to the application and start again.")
		return
	}
	ctx := op.ContextWithIssuer(r.Context(), p.issuer.String())
	http.Redirect(w, r, op.AuthCallbackURL(p.op)(ctx, req.id), http.StatusFound)
}

func (p *Provider) showLogin(w http.ResponseWriter, r *http.Request, status int, req *authRequest, c *client, username, message string) {
	csrf := ""
	if cookie, err := r.Cookie(csrfCookie); err == nil && len(cookie.Value) >= 32 {
		csrf = cookie.Value
	} else {
		csrf = randomID()
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookie,
			Value:    csrf,
			Path:     p.basePath + "/login",
			HttpOnly: true,
			Secure:   p.secureCookies(),
			SameSite: http.SameSiteStrictMode,
		})
	}
	p.ui.render(w, status, "login", pageData{
		Title:     "Sign in",
		Base:      p.basePath,
		App:       c.name,
		Error:     message,
		RequestID: req.id,
		CSRF:      csrf,
		Username:  username,
	})
}

func (p *Provider) message(w http.ResponseWriter, status int, title, message string) {
	p.ui.render(w, status, "message", pageData{Title: title, Base: p.basePath, Message: message})
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
