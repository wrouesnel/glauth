package unix

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/glauth/ldap"
	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
)

// The hashes of "correct horse", made with mkpasswd(1) and openssl.
const (
	hashYescrypt = "$y$j9T$n6YygP9ErXgnQiIQIL7Ua1$xpjEZ74x0ObwhwGigadd/djs1lix3BnuLlTm/5SZ/NB"
	hashSHA512   = "$6$lHi4QmQYFMLo2h1s$SPsRcDrPiK1aEskbMZ33xc6fZb8vsyIAEK1T./is/dui0LX.mP9HhHWiPuZDBmRY6XwRlCem2QmZ5WaTN9TQz/"
	hashSHA256   = "$5$C8YL7A315ypQGwil$UfiFfICmRaEqQjCB/IrUwZ5JnxLFzQeab.HlAkJNoB2"
	hashMD5      = "$1$QnqhwSZQ$kSJKxdl9CKUf0YSkDJla91"
	hashBcrypt   = "$2b$05$ZfAdWwLuyMgj8TWeRm15reSRtKKBpR9/JsCFPFa4a5btf7ucX7pUK"
)

func TestVerifyPassword(t *testing.T) {
	for name, hash := range map[string]string{
		"yescrypt": hashYescrypt,
		"sha512":   hashSHA512,
		"sha256":   hashSHA256,
		"md5":      hashMD5,
		"bcrypt":   hashBcrypt,
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyPassword(hash, "correct horse"); err != nil {
				t.Errorf("right password rejected: %v", err)
			}
			if err := verifyPassword(hash, "battery staple"); err == nil {
				t.Error("wrong password accepted")
			}
			if err := verifyPassword(hash, ""); err == nil {
				t.Error("empty password accepted")
			}
		})
	}

	for name, hash := range map[string]string{
		"locked":   "!" + hashSHA512,
		"disabled": "*",
		"empty":    "",
		"des":      "abJnggxhB/yWI",
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyPassword(hash, "correct horse"); err == nil {
				t.Error("password accepted")
			}
		})
	}
}

const testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
svc-search:x:998:998:Search service,,,:/nonexistent:/usr/sbin/nologin
alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/zsh
broken line
carol:x:1002:1002:Carol:/home/carol:/bin/bash
`

var testShadow = `root:` + hashSHA512 + `:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
svc-search:` + hashSHA256 + `:19000:0:99999:7:::
alice:` + hashYescrypt + `:19000:0:99999:7:::
bob:!` + hashSHA512 + `:19000:0:99999:7:::
carol:` + hashSHA512 + `:19000:0:99999:7::1:
`

const testGroup = `root:x:0:
daemon:x:1:
sudo:x:27:alice
ldap-search:x:997:svc-search
svc-search:x:998:
alice:x:1000:
bob:x:1001:
carol:x:1002:
`

func writeFiles(t *testing.T, dir, passwd, shadow, group string) {
	t.Helper()
	for name, content := range map[string]string{"passwd": passwd, "shadow": shadow, "group": group} {
		// Write and rename, as shadow-utils does.
		tmp := filepath.Join(dir, name+"+")
		if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func newTestHandler(t *testing.T, backend config.Backend) (unixHandler, string) {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, testPasswd, testShadow, testGroup)

	backend.BaseDN = "dc=example,dc=com"
	backend.UnixFilesDir = dir
	backend.NameFormatAsArray = []string{"cn"}
	backend.GroupFormatAsArray = []string{"ou"}
	log := zerolog.Nop()
	h := NewUnixHandler(
		handler.Backend(backend),
		handler.Logger(&log),
		handler.Config(&config.Config{}),
	).(unixHandler)
	return h, dir
}

func attr(e *ldap.Entry, name string) []string {
	for _, a := range e.Attributes {
		if a.Name == name {
			return a.Values
		}
	}
	return nil
}

func entryDNs(entries []*ldap.Entry) []string {
	dns := []string{}
	for _, e := range entries {
		dns = append(dns, e.DN)
	}
	return dns
}

func TestFindUser(t *testing.T) {
	h, _ := newTestHandler(t, config.Backend{GroupWithSearchCapability: "ldap-search"})
	ctx := context.Background()

	found, u, err := h.FindUser(ctx, "alice", false)
	if err != nil || !found {
		t.Fatalf("alice not found: %v", err)
	}
	if u.UIDNumber != 1000 || u.PrimaryGroup != 1000 || u.GivenName != "Alice Example" || u.Disabled {
		t.Errorf("unexpected user: %+v", u)
	}
	if !slices.Equal(u.OtherGroups, []int{27}) {
		t.Errorf("OtherGroups = %v, want [27]", u.OtherGroups)
	}
	if len(u.Capabilities) != 0 {
		t.Errorf("alice should have no capabilities, got %v", u.Capabilities)
	}
	if err := u.PassAppCustom(&u, "correct horse"); err != nil {
		t.Errorf("right password rejected: %v", err)
	}
	if err := u.PassAppCustom(&u, "wrong"); err == nil {
		t.Error("wrong password accepted")
	}

	_, svc, _ := h.FindUser(ctx, "svc-search", false)
	if len(svc.Capabilities) != 1 || svc.Capabilities[0].Action != "search" {
		t.Errorf("svc-search should have search capability, got %v", svc.Capabilities)
	}

	_, bob, _ := h.FindUser(ctx, "bob", false)
	if !bob.Disabled {
		t.Error("bob's locked account should be disabled")
	}
	_, carol, _ := h.FindUser(ctx, "carol", false)
	if !carol.Disabled {
		t.Error("carol's expired account should be disabled")
	}

	if found, _, _ := h.FindUser(ctx, "nobody", false); found {
		t.Error("unknown user found")
	}
}

func TestMinUIDNumber(t *testing.T) {
	h, _ := newTestHandler(t, config.Backend{MinUIDNumber: 1000, GroupWithSearchCapability: "ldap-search"})
	ctx := context.Background()

	for name, want := range map[string]bool{"root": false, "daemon": false, "svc-search": true, "alice": true} {
		if found, _, _ := h.FindUser(ctx, name, false); found != want {
			t.Errorf("FindUser(%s) found = %v, want %v", name, found, want)
		}
	}

	accounts, err := h.FindPosixAccounts(ctx, "ou=users")
	if err != nil {
		t.Fatal(err)
	}
	wantDNs := []string{
		"cn=svc-search,ou=svc-search,ou=users,dc=example,dc=com",
		"cn=alice,ou=alice,ou=users,dc=example,dc=com",
		"cn=bob,ou=bob,ou=users,dc=example,dc=com",
		"cn=carol,ou=carol,ou=users,dc=example,dc=com",
	}
	if got := entryDNs(accounts); !slices.Equal(got, wantDNs) {
		t.Errorf("accounts = %v, want %v", got, wantDNs)
	}

	groups, err := h.FindPosixGroups(ctx, "ou=groups")
	if err != nil {
		t.Fatal(err)
	}
	// sudo and ldap-search are below the threshold but have visible members.
	wantDNs = []string{
		"ou=sudo,ou=groups,dc=example,dc=com",
		"ou=ldap-search,ou=groups,dc=example,dc=com",
		"ou=svc-search,ou=groups,dc=example,dc=com",
		"ou=alice,ou=groups,dc=example,dc=com",
		"ou=bob,ou=groups,dc=example,dc=com",
		"ou=carol,ou=groups,dc=example,dc=com",
	}
	if got := entryDNs(groups); !slices.Equal(got, wantDNs) {
		t.Errorf("groups = %v, want %v", got, wantDNs)
	}

	h, _ = newTestHandler(t, config.Backend{MinUIDNumber: 1000, ExposeGroups: []string{"daemon"}})
	if found, _, _ := h.FindUser(ctx, "daemon", false); !found {
		t.Error("daemon should be exposed through ExposeGroups")
	}
	if found, _, _ := h.FindUser(ctx, "svc-search", false); found {
		t.Error("svc-search should be hidden without a search capability group")
	}
}

func TestEntries(t *testing.T) {
	h, _ := newTestHandler(t, config.Backend{MinUIDNumber: 1000})
	ctx := context.Background()

	accounts, err := h.FindPosixAccounts(ctx, "ou=users")
	if err != nil {
		t.Fatal(err)
	}
	alice := accounts[0]
	if alice.DN != "cn=alice,ou=alice,ou=users,dc=example,dc=com" {
		t.Fatalf("first account is %s", alice.DN)
	}
	for name, want := range map[string][]string{
		"cn":            {"alice"},
		"uid":           {"alice"},
		"uidNumber":     {"1000"},
		"gidNumber":     {"1000"},
		"givenName":     {"Alice Example"},
		"gecos":         {"Alice Example,,,"},
		"homeDirectory": {"/home/alice"},
		"loginShell":    {"/bin/bash"},
		"accountStatus": {"active"},
		"objectClass":   {"posixAccount", "shadowAccount"},
		"memberOf":      {"ou=alice,ou=groups,dc=example,dc=com", "ou=sudo,ou=groups,dc=example,dc=com"},
		"shadowMax":     {"99999"},
	} {
		if got := attr(alice, name); !slices.Equal(got, want) {
			t.Errorf("alice %s = %v, want %v", name, got, want)
		}
	}
	if got := attr(accounts[1], "accountStatus"); !slices.Equal(got, []string{"inactive"}) {
		t.Errorf("bob accountStatus = %v, want inactive", got)
	}

	groups, err := h.FindPosixGroups(ctx, "ou=groups")
	if err != nil {
		t.Fatal(err)
	}
	sudo := groups[0]
	if sudo.DN != "ou=sudo,ou=groups,dc=example,dc=com" {
		t.Fatalf("first group is %s", sudo.DN)
	}
	if got := attr(sudo, "uid"); got != nil {
		t.Errorf("groups must not carry uid, got %v", got)
	}
	if got := attr(sudo, "uniqueMember"); !slices.Equal(got, []string{"cn=alice,ou=alice,ou=users,dc=example,dc=com"}) {
		t.Errorf("sudo uniqueMember = %v", got)
	}
}

func TestReloadOnRename(t *testing.T) {
	h, dir := newTestHandler(t, config.Backend{})
	ctx := context.Background()

	if found, _, _ := h.FindUser(ctx, "dave", false); found {
		t.Fatal("dave exists before being added")
	}

	writeFiles(t, dir,
		testPasswd+"dave:x:1003:1003::/home/dave:/bin/bash\n",
		testShadow+"dave:"+hashBcrypt+":19000:0:99999:7:::\n",
		testGroup+"dave:x:1003:\n")
	// Make sure the change is visible even on filesystems with coarse mtimes.
	future := time.Now().Add(time.Minute)
	for _, name := range []string{"passwd", "shadow", "group"} {
		if err := os.Chtimes(filepath.Join(dir, name), future, future); err != nil {
			t.Fatal(err)
		}
	}

	found, u, err := h.FindUser(ctx, "dave", false)
	if err != nil || !found {
		t.Fatalf("dave not found after the files changed: %v", err)
	}
	if err := u.PassAppCustom(&u, "correct horse"); err != nil {
		t.Errorf("dave's password rejected: %v", err)
	}
}

func TestMalformedLinesSkipped(t *testing.T) {
	h, _ := newTestHandler(t, config.Backend{})
	snap, err := h.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.warnings) != 1 {
		t.Errorf("warnings = %v, want the one broken passwd line", snap.warnings)
	}
	if _, found := snap.accountByName["carol"]; !found {
		t.Error("lines after a malformed one should still be read")
	}
}
