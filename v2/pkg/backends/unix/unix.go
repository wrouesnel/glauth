// Package unix serves the accounts and groups in a set of Unix account files
// (passwd, shadow and group) as an LDAP directory.
//
// Passwords are checked against the shadow hashes in pure Go, so the backend
// needs read access to shadow but no PAM or cgo. The pam backend reuses this
// one and checks passwords with PAM instead.
package unix

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/ldap"
	"github.com/rs/zerolog"

	"github.com/glauth/glauth/v2/pkg/backends"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
)

func init() {
	backends.Register("unix", NewUnixHandler)
}

// Authenticator checks a password for a named account. It is given the shadow
// hash, which is empty when shadow isn't readable.
type Authenticator func(userName, hash, password string) error

// ShadowAuthenticator checks passwords against the shadow hash.
func ShadowAuthenticator(_ string, hash, password string) error {
	return verifyPassword(hash, password)
}

type unixHandler struct {
	backend   config.Backend
	log       *zerolog.Logger
	cfg       *config.Config
	ldohelper handler.LDAPOpsHelper
	files     *accountFiles
	auth      Authenticator
	now       func() time.Time
}

// NewUnixHandler creates a backend that checks passwords against shadow.
func NewUnixHandler(opts ...handler.Option) handler.Handler {
	return New(ShadowAuthenticator, opts...)
}

// New creates a backend serving the account files, checking passwords with auth.
func New(auth Authenticator, opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)
	h := unixHandler{
		backend:   options.Backend,
		log:       options.Logger,
		cfg:       options.Config,
		ldohelper: options.LDAPHelper,
		files:     newAccountFiles(options.Backend.UnixFilesDir),
		auth:      auth,
		now:       time.Now,
	}

	if snap, err := h.snapshot(); err != nil {
		h.log.Error().Err(err).Str("dir", h.files.dir).Msg("unable to read account files")
	} else if h.backend.GroupWithSearchCapability != "" {
		if _, found := snap.groupByName[h.backend.GroupWithSearchCapability]; found {
			h.log.Info().Str("group", h.backend.GroupWithSearchCapability).Msg("members of this group get search capability")
		} else {
			h.log.Error().Str("group", h.backend.GroupWithSearchCapability).Msg("groupWithSearchCapability names a group that doesn't exist")
		}
	}
	return h
}

// snapshot returns the current account data, logging when it was re-read.
func (h unixHandler) snapshot() (*snapshot, error) {
	snap, reloaded, err := h.files.load()
	if err != nil {
		if snap == nil {
			return nil, err
		}
		h.log.Error().Err(err).Str("dir", h.files.dir).Msg("unable to re-read account files, serving the previous copy")
	}
	if reloaded {
		for _, w := range snap.warnings {
			h.log.Warn().Str("line", w).Msg("skipped malformed account file line")
		}
		h.log.Debug().Int("accounts", len(snap.accounts)).Int("groups", len(snap.groups)).Str("dir", h.files.dir).Msg("loaded account files")
	}
	return snap, nil
}

func (h unixHandler) GetBackend() config.Backend {
	return h.backend
}
func (h unixHandler) GetLog() *zerolog.Logger {
	return h.log
}
func (h unixHandler) GetCfg() *config.Config {
	return h.cfg
}
func (h unixHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return nil
}

func (h unixHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return h.ldohelper.Bind(context.Background(), h, bindDN, bindSimplePw, conn)
}

func (h unixHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	return h.ldohelper.Search(context.Background(), h, bindDN, searchReq, conn)
}

// Add is not supported: the account files are managed by the host.
func (h unixHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not supported: the account files are managed by the host.
func (h unixHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not supported: the account files are managed by the host.
func (h unixHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h unixHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

// inGroup reports whether the named account is a member of the named group.
func (h unixHandler) inGroup(snap *snapshot, userName, groupName string) bool {
	g, found := snap.groupByName[groupName]
	return found && containsInt(snap.memberOf[userName], g.GID)
}

// accountVisible reports whether an account is served: accounts below
// MinUIDNumber are hidden unless they belong to an exposed group or the group
// with search capability.
func (h unixHandler) accountVisible(snap *snapshot, a *account) bool {
	if a.UID >= h.backend.MinUIDNumber {
		return true
	}
	if h.backend.GroupWithSearchCapability != "" && h.inGroup(snap, a.Name, h.backend.GroupWithSearchCapability) {
		return true
	}
	for _, name := range h.backend.ExposeGroups {
		if h.inGroup(snap, a.Name, name) {
			return true
		}
	}
	return false
}

// groupVisible reports whether a group is served: groups below MinUIDNumber
// are hidden unless one of their members is visible, so memberOf never points
// at a missing entry.
func (h unixHandler) groupVisible(snap *snapshot, g *group) bool {
	if g.GID >= h.backend.MinUIDNumber {
		return true
	}
	for _, m := range snap.members[g.GID] {
		if h.accountVisible(snap, snap.accountByName[m]) {
			return true
		}
	}
	return false
}

func (h unixHandler) groupName(snap *snapshot, gid int) string {
	if g, found := snap.groupByGID[gid]; found {
		return g.Name
	}
	return strconv.Itoa(gid)
}

func (h unixHandler) disabled(a *account) bool {
	return a.HasShadow && (a.Locked() || a.Expired(h.now()))
}

// FindUser with the given username. Called by the ldap backend to authenticate the bind.
func (h unixHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (found bool, ldapUser config.User, err error) {
	if searchByUPN {
		return false, config.User{}, nil
	}
	snap, err := h.snapshot()
	if err != nil {
		return false, config.User{}, err
	}
	a, found := snap.accountByName[userName]
	if !found || !h.accountVisible(snap, a) {
		return false, config.User{}, nil
	}

	ldapUser = config.User{
		Name:         a.Name,
		UIDNumber:    a.UID,
		UnixID:       a.UID,
		PrimaryGroup: a.GID,
		Homedir:      a.Home,
		LoginShell:   a.Shell,
		Disabled:     h.disabled(a),
	}
	ldapUser.GivenName = a.FullName()
	if ldapUser.GivenName == "" {
		ldapUser.GivenName = a.Name
	}
	ldapUser.OtherGroups = append(ldapUser.OtherGroups, snap.memberOf[a.Name][1:]...)
	if h.backend.GroupWithSearchCapability != "" && h.inGroup(snap, a.Name, h.backend.GroupWithSearchCapability) {
		ldapUser.Capabilities = []config.Capability{{Action: "search", Object: "*"}}
	}

	name, hash := a.Name, a.Hash
	ldapUser.PassAppCustom = func(_ *config.User, password string) error {
		return h.auth(name, hash, password)
	}
	return true, ldapUser, nil
}

// FindGroup with the given name.
func (h unixHandler) FindGroup(ctx context.Context, groupName string) (found bool, ldapGroup config.Group, err error) {
	snap, err := h.snapshot()
	if err != nil {
		return false, config.Group{}, err
	}
	g, found := snap.groupByName[groupName]
	if !found || !h.groupVisible(snap, g) {
		return false, config.Group{}, nil
	}
	return true, config.Group{Name: g.Name, GIDNumber: g.GID, UnixID: g.GID}, nil
}

func (h unixHandler) userDN(snap *snapshot, a *account, hierarchy string) string {
	if hierarchy == "" {
		return fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormatAsArray[0], a.Name, h.backend.GroupFormatAsArray[0], h.groupName(snap, a.GID), h.backend.BaseDN)
	}
	return fmt.Sprintf("%s=%s,%s=%s,%s,%s", h.backend.NameFormatAsArray[0], a.Name, h.backend.GroupFormatAsArray[0], h.groupName(snap, a.GID), hierarchy, h.backend.BaseDN)
}

func (h unixHandler) groupDN(g *group) string {
	return fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormatAsArray[0], g.Name, h.backend.BaseDN)
}

func (h unixHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	snap, err := h.snapshot()
	if err != nil {
		return nil, err
	}
	entries := []*ldap.Entry{}
	for _, a := range snap.accounts {
		if !h.accountVisible(snap, a) {
			continue
		}
		attrs := []*ldap.EntryAttribute{}
		for _, nameAttr := range h.backend.NameFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: nameAttr, Values: []string{a.Name}})
		}
		if !containsString(h.backend.NameFormatAsArray, "uid") {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{a.Name}})
		}

		displayName := a.FullName()
		if displayName == "" {
			displayName = a.Name
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{displayName}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{displayName}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{h.groupName(snap, a.GID)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{strconv.Itoa(a.UID)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{strconv.Itoa(a.GID)}})
		if h.disabled(a) {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"inactive"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
		}
		objectClasses := []string{"posixAccount"}
		if a.HasShadow {
			objectClasses = append(objectClasses, "shadowAccount")
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: objectClasses})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{a.Name}})
		if a.Gecos != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{a.Gecos}})
		}
		if a.Home != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{a.Home}})
		}
		if a.Shell != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "loginShell", Values: []string{a.Shell}})
		}

		memberOf := []string{}
		for _, gid := range snap.memberOf[a.Name] {
			if g, found := snap.groupByGID[gid]; found && h.groupVisible(snap, g) {
				memberOf = append(memberOf, h.groupDN(g))
			}
		}
		if len(memberOf) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: memberOf})
		}

		if a.HasShadow {
			for _, f := range []struct {
				name  string
				value int
			}{
				{"shadowLastChange", a.LastChange},
				{"shadowMin", a.Min},
				{"shadowMax", a.Max},
				{"shadowWarning", a.Warn},
				{"shadowInactive", a.Inactive},
				{"shadowExpire", a.Expire},
			} {
				if f.value >= 0 {
					attrs = append(attrs, &ldap.EntryAttribute{Name: f.name, Values: []string{strconv.Itoa(f.value)}})
				}
			}
		}

		entries = append(entries, &ldap.Entry{DN: h.userDN(snap, a, hierarchy), Attributes: attrs})
	}
	return entries, nil
}

func (h unixHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	snap, err := h.snapshot()
	if err != nil {
		return nil, err
	}
	asGroupOfUniqueNames := hierarchy == "ou=groups"

	entries := []*ldap.Entry{}
	for _, g := range snap.groups {
		if !h.groupVisible(snap, g) {
			continue
		}
		attrs := []*ldap.EntryAttribute{}
		for _, groupAttr := range h.backend.GroupFormatAsArray {
			attrs = append(attrs, &ldap.EntryAttribute{Name: groupAttr, Values: []string{g.Name}})
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{g.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{strconv.Itoa(g.GID)}})

		memberDNs, memberUids := []string{}, []string{}
		for _, m := range snap.members[g.GID] {
			a := snap.accountByName[m]
			if !h.accountVisible(snap, a) {
				continue
			}
			memberDNs = append(memberDNs, h.userDN(snap, a, "ou=users"))
			memberUids = append(memberUids, a.Name)
		}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: memberDNs})
		if asGroupOfUniqueNames {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: memberUids})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
		}

		var dn string
		if hierarchy == "" {
			dn = fmt.Sprintf("%s=%s,%s", h.backend.GroupFormatAsArray[0], g.Name, h.backend.BaseDN)
		} else {
			dn = fmt.Sprintf("%s=%s,%s,%s", h.backend.GroupFormatAsArray[0], g.Name, hierarchy, h.backend.BaseDN)
		}
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}
	return entries, nil
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
