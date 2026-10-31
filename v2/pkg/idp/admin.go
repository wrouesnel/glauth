package idp

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// templateFuncs are available to every page template.
var templateFuncs = template.FuncMap{
	"when": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2 Jan 15:04")
	},
	"join": strings.Join,
}

// notices are the messages the admin page can show after a change, by code, so that
// a link can't put words of its own on the page.
var notices = map[string]string{
	"ended":     "The session has ended.",
	"ended-all": "Those sessions have ended.",
	"blocked":   "The application is blocked, and its tokens are revoked.",
	"unblocked": "The application is unblocked.",
	"saved":     "Saved.",
	"deleted":   "The application is removed.",
}

type adminView struct {
	User     string
	Notice   string
	Error    string
	Sessions []sessionInfo
	Apps     []appRow
	Settings settingsForm
	App      appForm
}

type appRow struct {
	ID         string
	Name       string
	Source     string
	Groups     []string
	LastSignIn time.Time
	Block      *block
	Editable   bool
}

type settingsForm struct {
	BrandName       string
	SessionLifetime string
	TrustedDomains  string
	ConfigDomains   []string
}

type appForm struct {
	New          bool
	Original     string
	ID           string
	Name         string
	Groups       string
	RedirectURIs string
	HasSecret    bool
}

func (p *Provider) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", p.admin(p.adminPage))
	mux.HandleFunc("POST /admin/sessions/end", p.admin(p.adminEndSession))
	mux.HandleFunc("POST /admin/sessions/end-user", p.admin(p.adminEndUser))
	mux.HandleFunc("POST /admin/apps/block", p.admin(p.adminBlock))
	mux.HandleFunc("POST /admin/apps/unblock", p.admin(p.adminUnblock))
	mux.HandleFunc("GET /admin/apps/edit", p.admin(p.adminEditApp))
	mux.HandleFunc("POST /admin/apps/save", p.admin(p.adminSaveApp))
	mux.HandleFunc("POST /admin/apps/delete", p.admin(p.adminDeleteApp))
	mux.HandleFunc("POST /admin/settings", p.admin(p.adminSaveSettings))
}

type adminHandler func(w http.ResponseWriter, r *http.Request, admin *session)

// admin lets members of the admin groups through, sending anyone else to sign in.
// Changes must come from the provider's own forms.
func (p *Provider) admin(next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(p.cfg.AdminGroups) == 0 {
			http.NotFound(w, r)
			return
		}
		sess := p.currentSession(r, time.Now())
		if sess == nil {
			http.Redirect(w, r, p.basePath+"/login?next="+url.QueryEscape(p.basePath+"/admin"), http.StatusFound)
			return
		}
		if !slices.ContainsFunc(sess.user.Groups, func(g string) bool { return slices.Contains(p.cfg.AdminGroups, g) }) {
			p.message(w, http.StatusForbidden, "No access", sess.user.Username+" isn't an administrator. Sign out at "+p.issuer.String()+"/logout to use another account.")
			return
		}
		if r.Method == http.MethodPost {
			if !p.parseForm(w, r) {
				return
			}
			if !p.checkCSRF(r) {
				p.message(w, http.StatusForbidden, "Form expired", "That form had expired. Go back, reload the page and try again.")
				return
			}
		}
		next(w, r, sess)
	}
}

func (p *Provider) adminDone(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, p.basePath+"/admin?notice="+notice, http.StatusSeeOther)
}

func (p *Provider) adminPage(w http.ResponseWriter, r *http.Request, admin *session) {
	p.renderAdmin(w, r, admin, http.StatusOK, notices[r.URL.Query().Get("notice")], "", nil)
}

// renderAdmin shows the admin page, with form, if given, standing in for the
// settings so that a rejected change can be corrected.
func (p *Provider) renderAdmin(w http.ResponseWriter, r *http.Request, admin *session, status int, notice, errMsg string, form *settingsForm) {
	now := time.Now()
	s := p.settings.Load()
	view := adminView{
		User:     admin.user.Username,
		Notice:   notice,
		Error:    errMsg,
		Sessions: p.store.listSessions(now),
		Apps:     p.appRows(s, now),
	}
	if form != nil {
		view.Settings = *form
	} else {
		view.Settings = settingsForm{
			BrandName:      s.admin.BrandName,
			TrustedDomains: strings.Join(s.admin.TrustedDomains, "\n"),
		}
		view.Settings.SessionLifetime = s.admin.SessionLifetime
	}
	view.Settings.ConfigDomains = slices.DeleteFunc(slices.Clone(s.trustedDomains), func(d string) bool {
		return slices.Contains(s.admin.TrustedDomains, d)
	})
	p.render(w, status, "admin", pageData{Title: "Administration", CSRF: p.csrfToken(w, r), Admin: view})
}

// appRows lists the applications that are configured, blocked or recently used.
func (p *Provider) appRows(s *settings, now time.Time) []appRow {
	recent := p.store.recentApps()
	ids := map[string]bool{}
	for id := range s.clients {
		ids[id] = true
	}
	for id := range s.blocks {
		ids[id] = true
	}
	for id := range recent {
		ids[id] = true
	}
	var rows []appRow
	for id := range ids {
		row := appRow{ID: id, Source: "Not set up", LastSignIn: recent[id], Editable: true}
		if c, ok := s.clients[id]; ok {
			row.Name, row.Groups = c.name, c.groups
			row.Source, row.Editable = "Config file", c.fromAdmin
			if c.fromAdmin {
				row.Source = "Admin page"
			}
		}
		if b, ok := s.blocked(id, now); ok {
			row.Block = &b
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b appRow) int { return strings.Compare(a.ID, b.ID) })
	return rows
}

func (p *Provider) adminEndSession(w http.ResponseWriter, r *http.Request, admin *session) {
	handle := r.PostForm.Get("session")
	n := p.store.endSessions(func(s *session) bool { return s.handle == handle })
	p.log.Info().Str("admin", admin.user.Username).Int("sessions", n).Msg("oidc admin: ended a session")
	p.adminDone(w, r, "ended")
}

func (p *Provider) adminEndUser(w http.ResponseWriter, r *http.Request, admin *session) {
	username := r.PostForm.Get("username")
	n := p.store.endSessions(func(s *session) bool { return s.user.Username == username })
	p.log.Info().Str("admin", admin.user.Username).Str("username", username).Int("sessions", n).Msg("oidc admin: ended a user's sessions")
	p.adminDone(w, r, "ended-all")
}

// blockDurations are the choices for how long to block an application.
var blockDurations = map[string]time.Duration{"1h": time.Hour, "1d": 24 * time.Hour, "1w": 7 * 24 * time.Hour, "": 0}

func (p *Provider) adminBlock(w http.ResponseWriter, r *http.Request, admin *session) {
	id := strings.TrimSpace(r.PostForm.Get("client"))
	duration, ok := blockDurations[r.PostForm.Get("for")]
	if id == "" || !ok {
		p.renderAdmin(w, r, admin, http.StatusBadRequest, "", "Choose an application and how long to block it for.", nil)
		return
	}
	now := time.Now()
	b := block{Client: id, Reason: strings.TrimSpace(r.PostForm.Get("reason")), By: admin.user.Username, At: now.UTC()}
	if duration > 0 {
		b.Until = now.Add(duration).UTC()
	}
	err := p.updateAdmin(func(a *adminSettings) error {
		a.Blocks = append(slices.DeleteFunc(a.Blocks, func(old block) bool { return old.Client == id || !old.active(now) }), b)
		return nil
	})
	if err != nil {
		p.renderAdmin(w, r, admin, http.StatusInternalServerError, "", err.Error(), nil)
		return
	}
	p.store.revokeClient(id)
	p.log.Info().Str("admin", admin.user.Username).Str("client", id).Time("until", b.Until).Str("reason", b.Reason).Msg("oidc admin: blocked an application")
	p.adminDone(w, r, "blocked")
}

func (p *Provider) adminUnblock(w http.ResponseWriter, r *http.Request, admin *session) {
	id := r.PostForm.Get("client")
	err := p.updateAdmin(func(a *adminSettings) error {
		a.Blocks = slices.DeleteFunc(a.Blocks, func(old block) bool { return old.Client == id })
		return nil
	})
	if err != nil {
		p.renderAdmin(w, r, admin, http.StatusInternalServerError, "", err.Error(), nil)
		return
	}
	p.log.Info().Str("admin", admin.user.Username).Str("client", id).Msg("oidc admin: unblocked an application")
	p.adminDone(w, r, "unblocked")
}

func (p *Provider) adminEditApp(w http.ResponseWriter, r *http.Request, admin *session) {
	id := r.URL.Query().Get("id")
	form := appForm{New: true, ID: id}
	for _, c := range p.settings.Load().admin.Clients {
		if c.ID == id {
			form = appForm{Original: c.ID, ID: c.ID, Name: c.Name, Groups: strings.Join(c.Groups, ", "),
				RedirectURIs: strings.Join(c.RedirectURIs, "\n"), HasSecret: c.SecretSHA256 != ""}
		}
	}
	p.renderApp(w, r, http.StatusOK, form, "")
}

func (p *Provider) renderApp(w http.ResponseWriter, r *http.Request, status int, form appForm, errMsg string) {
	title := "Edit " + form.Original
	if form.New {
		title = "Add an application"
	}
	p.render(w, status, "app", pageData{Title: title, CSRF: p.csrfToken(w, r), Error: errMsg, Admin: form})
}

func (p *Provider) adminSaveApp(w http.ResponseWriter, r *http.Request, admin *session) {
	f := r.PostForm
	form := appForm{
		New:          f.Get("original") == "",
		Original:     f.Get("original"),
		ID:           strings.TrimSpace(f.Get("id")),
		Name:         strings.TrimSpace(f.Get("name")),
		Groups:       f.Get("groups"),
		RedirectURIs: f.Get("redirectURIs"),
	}
	c := adminClient{ID: form.ID, Name: form.Name, Groups: splitList(form.Groups), RedirectURIs: splitList(form.RedirectURIs)}
	if c.ID == "" || strings.ContainsAny(c.ID, " \t\r\n") {
		p.renderApp(w, r, http.StatusBadRequest, form, "The client ID can't be empty or contain spaces.")
		return
	}
	secret := ""
	err := p.updateAdmin(func(a *adminSettings) error {
		i := slices.IndexFunc(a.Clients, func(old adminClient) bool { return old.ID == form.Original })
		if form.Original != "" && i < 0 {
			return errors.New("that application is no longer on the admin page")
		}
		if c.ID != form.Original && slices.ContainsFunc(a.Clients, func(old adminClient) bool { return old.ID == c.ID }) {
			return fmt.Errorf("%s is already set up", c.ID)
		}
		switch f.Get("secret") {
		case "new":
			secret = randomID()
			c.SecretSHA256 = hashSecret(secret)
		case "keep":
			if i >= 0 {
				c.SecretSHA256 = a.Clients[i].SecretSHA256
			}
		}
		if i >= 0 {
			a.Clients[i] = c
		} else {
			a.Clients = append(a.Clients, c)
		}
		return nil
	})
	if err != nil {
		form.HasSecret = f.Get("secret") == "keep"
		p.renderApp(w, r, http.StatusBadRequest, form, err.Error())
		return
	}
	p.log.Info().Str("admin", admin.user.Username).Str("client", c.ID).Strs("groups", c.Groups).Msg("oidc admin: saved an application")
	if secret != "" {
		p.render(w, http.StatusOK, "message", pageData{Title: "Client secret",
			Message: "Set " + c.ID + "'s client secret to " + secret + " . It won't be shown again."})
		return
	}
	p.adminDone(w, r, "saved")
}

func (p *Provider) adminDeleteApp(w http.ResponseWriter, r *http.Request, admin *session) {
	id := r.PostForm.Get("id")
	err := p.updateAdmin(func(a *adminSettings) error {
		a.Clients = slices.DeleteFunc(a.Clients, func(c adminClient) bool { return c.ID == id })
		return nil
	})
	if err != nil {
		p.renderAdmin(w, r, admin, http.StatusInternalServerError, "", err.Error(), nil)
		return
	}
	p.log.Info().Str("admin", admin.user.Username).Str("client", id).Msg("oidc admin: removed an application")
	p.adminDone(w, r, "deleted")
}

func (p *Provider) adminSaveSettings(w http.ResponseWriter, r *http.Request, admin *session) {
	f := r.PostForm
	form := settingsForm{
		BrandName:       strings.TrimSpace(f.Get("brandName")),
		SessionLifetime: strings.TrimSpace(f.Get("sessionLifetime")),
		TrustedDomains:  f.Get("trustedDomains"),
	}
	if form.SessionLifetime != "" {
		if lifetime, err := time.ParseDuration(form.SessionLifetime); err != nil || lifetime < 5*time.Minute {
			p.renderAdmin(w, r, admin, http.StatusBadRequest, "", "The session lifetime must be a duration of at least 5m, such as 8h.", &form)
			return
		}
	}
	domains := splitList(strings.ToLower(form.TrustedDomains))
	for _, d := range domains {
		if !validHostname(strings.Trim(d, ".")) || !strings.Contains(strings.Trim(d, "."), ".") {
			p.renderAdmin(w, r, admin, http.StatusBadRequest, "", d+" isn't a domain name.", &form)
			return
		}
	}
	err := p.updateAdmin(func(a *adminSettings) error {
		a.BrandName, a.SessionLifetime, a.TrustedDomains = form.BrandName, form.SessionLifetime, domains
		return nil
	})
	if err != nil {
		p.renderAdmin(w, r, admin, http.StatusBadRequest, "", err.Error(), &form)
		return
	}
	p.log.Info().Str("admin", admin.user.Username).Str("brandName", form.BrandName).Str("sessionLifetime", form.SessionLifetime).
		Strs("trustedDomains", domains).Msg("oidc admin: changed settings")
	p.adminDone(w, r, "saved")
}

// splitList splits a list typed one per line or separated by commas.
func splitList(s string) []string {
	var list []string
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}
