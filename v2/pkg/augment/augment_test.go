package augment_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/pkg/augment"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/server"
	"github.com/glauth/ldap"
)

// site adds siteRole to alice's entry, as a site's own field: by its DN, as
// the entry has only the attributes the client asked for.
type site struct{}

func (site) Augment(_ context.Context, req *augment.Request) error {
	if !req.Wants("siteRole") {
		return nil
	}
	for _, e := range req.Entries {
		if strings.HasPrefix(strings.ToLower(e.DN), "cn=alice,") {
			e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "siteRole", Values: []string{"engineer"}})
		}
	}
	return nil
}

func init() {
	augment.Register("test-site", func(config.Backend) (augment.Augmenter, error) { return site{}, nil })
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func serve(t *testing.T, cfg *config.Config) {
	t.Helper()
	log := zerolog.Nop()
	s, err := server.NewServer(server.Logger(log), server.Config(cfg),
		server.Monitor(monitoring.NewMonitor(&log)), server.Tracer(noop.NewTracerProvider().Tracer("")))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.ListenAndServe() }()
	t.Cleanup(s.Shutdown)
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", cfg.LDAP.Listen); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never listened", cfg.LDAP.Listen)
}

// The ldap backend forwards a search to the directory, as the bound user, and
// adds what its augmenters give to the directory's answers.
func TestLDAPBackendAugments(t *testing.T) {
	sum := sha256.Sum256([]byte("correct horse"))
	upstream := freeAddr(t)
	serve(t, &config.Config{
		LDAP: config.LDAP{Enabled: true, Listen: upstream},
		Backends: []config.Backend{{BaseDN: "dc=example,dc=com", Datastore: "config",
			NameFormat: "cn", NameFormatAsArray: []string{"cn"}, GroupFormat: "ou", GroupFormatAsArray: []string{"ou"}}},
		Users:  []config.User{{Name: "alice", UIDNumber: 5001, PrimaryGroup: 5501, PassSHA256: hex.EncodeToString(sum[:]), Mail: "alice@example.com"}},
		Groups: []config.Group{{Name: "users", GIDNumber: 5501}},
	})
	proxy := freeAddr(t)
	serve(t, &config.Config{
		LDAP: config.LDAP{Enabled: true, Listen: proxy},
		Backends: []config.Backend{{BaseDN: "dc=example,dc=com", Datastore: "ldap", Servers: []string{"ldap://" + upstream},
			NameFormat: "cn", NameFormatAsArray: []string{"cn"}, GroupFormat: "ou", GroupFormatAsArray: []string{"ou"},
			Augment: []string{"test-site"}}},
	})

	conn, err := ldap.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=alice,dc=example,dc=com", "wrong"); err == nil {
		t.Fatal("the proxy took a wrong password")
	}
	if err := conn.Bind("cn=alice,dc=example,dc=com", "correct horse"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		attrs []string
		want  string
	}{
		{nil, "engineer"},
		{[]string{"mail", "siteRole"}, "engineer"},
		{[]string{"mail"}, ""},
	} {
		res, err := conn.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=posixAccount)(cn=alice))", tc.attrs, nil))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("%v: %d entries", tc.attrs, len(res.Entries))
		}
		e := res.Entries[0]
		if got := e.GetAttributeValue("siteRole"); got != tc.want {
			t.Errorf("%v: siteRole %q, want %q", tc.attrs, got, tc.want)
		}
		if got := e.GetAttributeValue("mail"); got != "alice@example.com" {
			t.Errorf("%v: the directory's mail is %q", tc.attrs, got)
		}
	}
}

func TestUnknownAugmenter(t *testing.T) {
	if _, err := augment.New(config.Backend{Augment: []string{"nope"}}); err == nil {
		t.Fatal("no error for an augmenter not registered")
	}
	chain, err := augment.New(config.Backend{})
	if err != nil || len(chain) != 0 {
		t.Fatalf("no augmenters: %v %v", chain, err)
	}
}
