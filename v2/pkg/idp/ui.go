package idp

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"github.com/glauth/glauth/v2/pkg/config"
)

//go:embed ui
var builtinUI embed.FS

var pageNames = []string{"login", "message"}

// ui renders the sign-in pages, with any branding applied.
type ui struct {
	pages    map[string]*template.Template
	brand    string
	branding config.OIDCBranding
}

// pageData is what every template gets; templates in a branding directory can use it.
type pageData struct {
	Title     string
	Brand     string
	Base      string
	Logo      bool
	CustomCSS bool

	Message   string
	App       string
	Error     string
	RequestID string
	CSRF      string
	Username  string
}

func newUI(branding config.OIDCBranding, brand string) (*ui, error) {
	u := &ui{pages: map[string]*template.Template{}, brand: brand, branding: branding}
	builtin, err := fs.Sub(builtinUI, "ui/templates")
	if err != nil {
		return nil, err
	}
	for _, name := range pageNames {
		layout, err := u.templateSource(builtin, "layout.html")
		if err != nil {
			return nil, err
		}
		page, err := u.templateSource(builtin, name+".html")
		if err != nil {
			return nil, err
		}
		t, err := template.New(name).Parse(layout)
		if err == nil {
			_, err = t.Parse(page)
		}
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		u.pages[name] = t
	}
	for _, path := range []string{branding.Logo, branding.CSS} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("branding: %w", err)
		}
	}
	return u, nil
}

// templateSource reads a template from the branding directory if it has one,
// otherwise the built-in one.
func (u *ui) templateSource(builtin fs.FS, file string) (string, error) {
	if u.branding.Templates != "" {
		data, err := os.ReadFile(filepath.Join(u.branding.Templates, file))
		if err == nil {
			return string(data), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	data, err := fs.ReadFile(builtin, file)
	return string(data), err
}

func (u *ui) render(w http.ResponseWriter, status int, page string, data pageData) {
	data.Brand = u.brand
	data.Logo = u.branding.Logo != ""
	data.CustomCSS = u.branding.CSS != ""
	var buf bytes.Buffer
	if err := u.pages[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "could not render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// static serves the built-in stylesheet and the branding logo and stylesheet.
func (u *ui) static() http.Handler {
	builtin, _ := fs.Sub(builtinUI, "ui")
	files := http.FileServerFS(builtin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "logo":
			serveFile(w, r, u.branding.Logo)
		case "custom.css":
			serveFile(w, r, u.branding.CSS)
		default:
			files.ServeHTTP(w, r)
		}
	})
}

func serveFile(w http.ResponseWriter, r *http.Request, path string) {
	if path == "" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}
