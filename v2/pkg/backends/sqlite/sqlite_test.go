package sqlite

import (
	"database/sql"
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/crypto/bcrypt"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
)

// A user without the search capability reads their own entry, as the OIDC
// provider does after binding as them.
func TestSearchSelf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "glauth.db")
	backend := config.Backend{Datastore: "sqlite", BaseDN: "dc=example,dc=com", Database: path,
		NameFormat: "cn", NameFormatAsArray: []string{"cn"}, GroupFormat: "ou", GroupFormatAsArray: []string{"ou"}}
	cfg := &config.Config{Backends: []config.Backend{backend}}
	log := zerolog.Nop()
	tracer := noop.NewTracerProvider().Tracer("sqlite-test")
	h := NewSQLiteHandler(handler.Backend(backend), handler.Config(cfg), handler.Logger(&log),
		handler.LDAPHelper(handler.NewLDAPOpsHelper(tracer)), handler.Tracer(tracer))

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		`INSERT INTO ldapgroups (name, gidnumber) VALUES ('people', 5501)`,
		`INSERT INTO users (name, uidnumber, primarygroup, passbcrypt, mail) VALUES ('alice', 5001, 5501, '` + hex.EncodeToString(hash) + `', 'alice@example.com')`,
		`INSERT INTO users (name, uidnumber, primarygroup, passbcrypt) VALUES ('bob', 5002, 5501, '` + hex.EncodeToString(hash) + `')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}

	found, user, err := h.FindUser(t.Context(), "alice", false)
	if err != nil || !found || user.Name != "alice" {
		t.Fatalf("FindUser: %v %+v %v", found, user, err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	bindDN := "cn=alice,dc=example,dc=com"
	if code, err := h.Bind(bindDN, "secret", server); code != ldap.LDAPResultSuccess {
		t.Fatalf("bind: %v %v", code, err)
	}
	res, err := h.Search(bindDN, ldap.SearchRequest{BaseDN: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree,
		Filter: "(&(objectClass=posixAccount)(cn=alice))"}, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("mail") != "alice@example.com" {
		t.Fatalf("alice reads %d entries: %+v", len(res.Entries), res.Entries)
	}
	res, err = h.Search(bindDN, ldap.SearchRequest{BaseDN: "dc=example,dc=com", Scope: ldap.ScopeWholeSubtree,
		Filter: "(objectClass=posixAccount)"}, server)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("cn") != "alice" {
		t.Fatalf("alice, without the search capability, reads others: %+v", res.Entries)
	}
}
