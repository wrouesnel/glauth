package handler

import (
	"context"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

func TestAnonymousSearches(t *testing.T) {
	helper := NewLDAPOpsHelper(noop.NewTracerProvider().Tracer("anonymous-test"))
	tests := []struct {
		name         string
		anonymousDSE bool
		base         string
		scope        int
		want         ldap.LDAPResultCode
	}{
		{"root DSE, closed", false, "", ldap.ScopeBaseObject, ldap.LDAPResultInsufficientAccessRights},
		{"schema, closed", false, "cn=schema", ldap.ScopeBaseObject, ldap.LDAPResultInsufficientAccessRights},
		{"root DSE, open", true, "", ldap.ScopeBaseObject, ldap.LDAPResultSuccess},
		{"schema, open", true, "cn=schema", ldap.ScopeBaseObject, ldap.LDAPResultSuccess},
		{"directory, open", true, "dc=glauth,dc=com", ldap.ScopeWholeSubtree, ldap.LDAPResultInsufficientAccessRights},
		{"a user, open", true, "cn=alice,ou=people,ou=users,dc=glauth,dc=com", ldap.ScopeBaseObject, ldap.LDAPResultInsufficientAccessRights},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &searchTestHandler{
				backend: config.Backend{
					BaseDN:             "dc=glauth,dc=com",
					NameFormatAsArray:  []string{"cn"},
					GroupFormatAsArray: []string{"ou"},
					AnonymousDSE:       tt.anonymousDSE,
				},
				log:   zerolog.Nop(),
				users: []config.User{{Name: "alice", UIDNumber: 5001, PrimaryGroup: 5000}},
			}
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()

			result, _ := helper.Search(context.Background(), h, "", ldap.SearchRequest{
				BaseDN: tt.base,
				Scope:  tt.scope,
				Filter: "(objectClass=*)",
			}, conn)
			if result.ResultCode != tt.want {
				t.Fatalf("anonymous search of %q: result %v, want %v", tt.base, result.ResultCode, tt.want)
			}
			if tt.want == ldap.LDAPResultSuccess && len(result.Entries) != 1 {
				t.Fatalf("anonymous search of %q: got %d entries, want 1", tt.base, len(result.Entries))
			}
		})
	}
}
