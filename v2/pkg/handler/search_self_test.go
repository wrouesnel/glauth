package handler

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"

	"github.com/GeertJohan/yubigo"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

// searchTestHandler serves a fixed set of users, all in the "people" group.
type searchTestHandler struct {
	backend config.Backend
	cfg     config.Config
	log     zerolog.Logger
	users   []config.User
}

func (h *searchTestHandler) GetBackend() config.Backend { return h.backend }
func (h *searchTestHandler) GetLog() *zerolog.Logger    { return &h.log }
func (h *searchTestHandler) GetCfg() *config.Config     { return &h.cfg }
func (h *searchTestHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return nil
}

func (h *searchTestHandler) FindUser(_ context.Context, userName string, _ bool) (bool, config.User, error) {
	for _, u := range h.users {
		if u.Name == userName {
			return true, u, nil
		}
	}
	return false, config.User{}, nil
}

func (h *searchTestHandler) FindGroup(context.Context, string) (bool, config.Group, error) {
	return true, config.Group{Name: "people", GIDNumber: 5000}, nil
}

func (h *searchTestHandler) FindPosixAccounts(_ context.Context, hierarchy string) ([]*ldap.Entry, error) {
	entries := []*ldap.Entry{}
	for _, u := range h.users {
		dn := fmt.Sprintf("cn=%s,ou=people,%s", u.Name, h.backend.BaseDN)
		if hierarchy != "" {
			dn = fmt.Sprintf("cn=%s,ou=people,%s,%s", u.Name, hierarchy, h.backend.BaseDN)
		}
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{u.Name}},
			{Name: "uidNumber", Values: []string{fmt.Sprint(u.UIDNumber)}},
			{Name: "objectClass", Values: []string{"posixAccount"}},
		}})
	}
	return entries, nil
}

func (h *searchTestHandler) FindPosixGroups(_ context.Context, hierarchy string) ([]*ldap.Entry, error) {
	return []*ldap.Entry{{DN: fmt.Sprintf("ou=people,%s,%s", hierarchy, h.backend.BaseDN), Attributes: []*ldap.EntryAttribute{
		{Name: "ou", Values: []string{"people"}},
		{Name: "objectClass", Values: []string{"posixGroup"}},
	}}}, nil
}

func TestSearchWithoutCapabilityReturnsOnlySelf(t *testing.T) {
	h := &searchTestHandler{
		backend: config.Backend{
			BaseDN:             "dc=glauth,dc=com",
			NameFormatAsArray:  []string{"cn"},
			GroupFormatAsArray: []string{"ou"},
		},
		log: zerolog.Nop(),
		users: []config.User{
			{Name: "alice", UIDNumber: 5001, PrimaryGroup: 5000},
			{Name: "bob", UIDNumber: 5002, PrimaryGroup: 5000},
			{Name: "searcher", UIDNumber: 5003, PrimaryGroup: 5000, Capabilities: []config.Capability{{Action: "search", Object: "*"}}},
		},
	}
	helper := NewLDAPOpsHelper(noop.NewTracerProvider().Tracer("search-test"))

	tests := []struct {
		name   string
		bindDN string
		base   string
		scope  int
		want   []string
	}{
		{
			name:   "own entry by base scope",
			bindDN: "cn=alice,ou=people,dc=glauth,dc=com",
			base:   "cn=alice,ou=people,ou=users,dc=glauth,dc=com",
			scope:  ldap.ScopeBaseObject,
			want:   []string{"cn=alice,ou=people,ou=users,dc=glauth,dc=com"},
		},
		{
			name:   "subtree search only finds self",
			bindDN: "cn=alice,ou=people,dc=glauth,dc=com",
			base:   "dc=glauth,dc=com",
			scope:  ldap.ScopeWholeSubtree,
			want:   []string{"cn=alice,ou=people,ou=users,dc=glauth,dc=com"},
		},
		{
			name:   "someone else's entry is invisible",
			bindDN: "cn=alice,ou=people,dc=glauth,dc=com",
			base:   "cn=bob,ou=people,ou=users,dc=glauth,dc=com",
			scope:  ldap.ScopeBaseObject,
			want:   []string{},
		},
		{
			name:   "search capability sees everyone",
			bindDN: "cn=searcher,ou=people,dc=glauth,dc=com",
			base:   "ou=people,ou=users,dc=glauth,dc=com",
			scope:  ldap.ScopeSingleLevel,
			want: []string{
				"cn=alice,ou=people,ou=users,dc=glauth,dc=com",
				"cn=bob,ou=people,ou=users,dc=glauth,dc=com",
				"cn=searcher,ou=people,ou=users,dc=glauth,dc=com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()

			result, err := helper.Search(context.Background(), h, tt.bindDN, ldap.SearchRequest{
				BaseDN: tt.base,
				Scope:  tt.scope,
				Filter: "(objectClass=*)",
			}, conn)
			if err != nil {
				t.Fatalf("Search returned error: %v", err)
			}
			if result.ResultCode != ldap.LDAPResultSuccess {
				t.Fatalf("Search result = %v, want success", result.ResultCode)
			}
			got := []string{}
			for _, e := range result.Entries {
				if slices.Contains(e.GetAttributeValues("objectClass"), "posixAccount") {
					got = append(got, e.DN)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("accounts = %v, want %v", got, tt.want)
			}
			if tt.bindDN != "cn=searcher,ou=people,dc=glauth,dc=com" && len(result.Entries) != len(tt.want) {
				t.Errorf("got %d entries, want only the account entries %v", len(result.Entries), tt.want)
			}
		})
	}
}
