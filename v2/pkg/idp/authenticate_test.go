package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/server"
)

// startLDAP runs a glauth LDAP server with a config backend and returns its URL.
func startLDAP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	sum := sha256.Sum256([]byte("correct horse"))
	pass := hex.EncodeToString(sum[:])
	cfg := &config.Config{
		LDAP: config.LDAP{Enabled: true, Listen: addr},
		Backends: []config.Backend{{
			BaseDN: "dc=example,dc=com", Datastore: "config",
			NameFormat: "cn", NameFormatAsArray: []string{"cn"},
			GroupFormat: "ou", GroupFormatAsArray: []string{"ou"},
		}},
		Users: []config.User{
			{Name: "alice", UIDNumber: 5001, PrimaryGroup: 5501, OtherGroups: []int{5502}, PassSHA256: pass,
				GivenName: "Alice", SN: "Example", Mail: "alice@example.com"},
			{Name: "carol", UIDNumber: 5003, PrimaryGroup: 5501, PassSHA256: pass, Disabled: true},
		},
		Groups: []config.Group{{Name: "users", GIDNumber: 5501}, {Name: "admins", GIDNumber: 5502}},
	}
	log := zerolog.Nop()
	s, err := server.NewServer(server.Logger(log), server.Config(cfg),
		server.Monitor(monitoring.NewMonitor(&log)), server.Tracer(noop.NewTracerProvider().Tracer("")))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.ListenAndServe() }()
	t.Cleanup(s.Shutdown)
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return "ldap://" + addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("LDAP server didn't start")
	return ""
}

func TestLDAPAuthenticator(t *testing.T) {
	a := &LDAPAuthenticator{URL: startLDAP(t), BaseDN: "dc=example,dc=com", NameAttribute: "cn"}
	ctx := context.Background()

	id, err := a.Authenticate(ctx, "alice", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "alice" || id.GivenName != "Alice" || id.Surname != "Example" ||
		id.Email != "alice@example.com" || !slices.Equal(id.Groups, []string{"admins", "users"}) && !slices.Equal(id.Groups, []string{"users", "admins"}) {
		t.Fatalf("identity: %+v", id)
	}

	for _, tc := range []struct{ user, password string }{
		{"alice", "wrong"},
		{"alice", ""},
		{"nobody", "correct horse"},
		{"carol", "correct horse"}, // disabled
		{"alice,ou=admins", "correct horse"},
		{"*", "correct horse"},
	} {
		if _, err := a.Authenticate(ctx, tc.user, tc.password); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%q/%q: got %v, want invalid credentials", tc.user, tc.password, err)
		}
	}

	down := &LDAPAuthenticator{URL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=com", NameAttribute: "cn"}
	if _, err := down.Authenticate(ctx, "alice", "correct horse"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("server down: got %v, want a connection error", err)
	}
}
