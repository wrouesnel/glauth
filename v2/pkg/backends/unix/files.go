package unix

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultFilesDir is where the account files are read from unless the backend
// sets unixFilesDir.
const DefaultFilesDir = "/etc"

// account is one line of passwd, joined with its shadow entry if there is one.
type account struct {
	Name  string
	UID   int
	GID   int
	Gecos string
	Home  string
	Shell string

	// Hash is the password hash from shadow, or from passwd when it holds one
	// there rather than "x". It is empty when neither is readable.
	Hash string
	// HasShadow is true when a shadow entry was found for this account.
	HasShadow bool
	// LastChange, Min, Max, Warn, Inactive and Expire are the shadow aging fields,
	// in days. -1 means the field is empty.
	LastChange int
	Min        int
	Max        int
	Warn       int
	Inactive   int
	Expire     int
}

// FullName returns the first comma-separated GECOS field, which by convention
// is the user's full name.
func (a *account) FullName() string {
	name, _, _ := strings.Cut(a.Gecos, ",")
	return name
}

// Locked reports whether the password field disables password logins: shadow
// marks locked accounts with a leading "!" and accounts without a password
// with "*".
func (a *account) Locked() bool {
	return strings.HasPrefix(a.Hash, "!") || strings.HasPrefix(a.Hash, "*")
}

// Expired reports whether the shadow account expiry date has passed.
func (a *account) Expired(now time.Time) bool {
	if a.Expire < 0 {
		return false
	}
	return now.Unix()/86400 >= int64(a.Expire)
}

type group struct {
	Name    string
	GID     int
	Members []string
}

// snapshot is a parsed copy of the account files.
type snapshot struct {
	accounts []*account
	groups   []*group

	accountByName map[string]*account
	groupByName   map[string]*group
	groupByGID    map[int]*group
	// memberOf maps a user name to the gids of all of its groups, primary first.
	memberOf map[string][]int
	// members maps a gid to the names of all of its members, primary and secondary.
	members map[int][]string

	// warnings lists the malformed lines that were skipped.
	warnings []string
}

// fileStamp identifies one version of a file, so that a file replaced by rename
// (as shadow-utils does) is noticed as well as one rewritten in place.
type fileStamp struct {
	info fs.FileInfo
	err  error
}

func (s fileStamp) same(o fileStamp) bool {
	if s.err != nil || o.err != nil {
		return errors.Is(s.err, fs.ErrNotExist) && errors.Is(o.err, fs.ErrNotExist)
	}
	return os.SameFile(s.info, o.info) && s.info.ModTime().Equal(o.info.ModTime()) && s.info.Size() == o.info.Size()
}

// accountFiles reads passwd, shadow and group from a directory, and re-reads
// them whenever one of them changes.
type accountFiles struct {
	dir string

	mu      sync.Mutex
	stamps  [3]fileStamp
	current *snapshot
}

func newAccountFiles(dir string) *accountFiles {
	if dir == "" {
		dir = DefaultFilesDir
	}
	return &accountFiles{dir: dir}
}

func (f *accountFiles) paths() [3]string {
	return [3]string{
		filepath.Join(f.dir, "passwd"),
		filepath.Join(f.dir, "shadow"),
		filepath.Join(f.dir, "group"),
	}
}

// load returns the current snapshot, re-reading the files if any of them
// changed since the last call. reloaded is true when it re-read them.
func (f *accountFiles) load() (snap *snapshot, reloaded bool, err error) {
	paths := f.paths()
	var stamps [3]fileStamp
	for i, p := range paths {
		info, statErr := os.Stat(p)
		stamps[i] = fileStamp{info: info, err: statErr}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.current != nil && stamps[0].same(f.stamps[0]) && stamps[1].same(f.stamps[1]) && stamps[2].same(f.stamps[2]) {
		return f.current, false, nil
	}

	snap, err = parseAccountFiles(paths[0], paths[1], paths[2])
	if err != nil {
		if f.current != nil {
			// Keep serving the last good copy rather than failing every request
			// while the files are being replaced.
			return f.current, false, err
		}
		return nil, false, err
	}
	f.stamps = stamps
	f.current = snap
	return snap, true, nil
}

func parseAccountFiles(passwdPath, shadowPath, groupPath string) (*snapshot, error) {
	snap := &snapshot{
		accountByName: map[string]*account{},
		groupByName:   map[string]*group{},
		groupByGID:    map[int]*group{},
		memberOf:      map[string][]int{},
		members:       map[int][]string{},
	}

	err := readColonFile(passwdPath, &snap.warnings, func(fields []string) error {
		// name:password:uid:gid:gecos:home:shell
		if len(fields) != 7 {
			return fmt.Errorf("expected 7 fields, got %d", len(fields))
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return fmt.Errorf("bad uid: %w", err)
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return fmt.Errorf("bad gid: %w", err)
		}
		if _, dup := snap.accountByName[fields[0]]; dup {
			return nil
		}
		a := &account{
			Name: fields[0], UID: uid, GID: gid, Gecos: fields[4], Home: fields[5], Shell: fields[6],
			LastChange: -1, Min: -1, Max: -1, Warn: -1, Inactive: -1, Expire: -1,
		}
		if fields[1] != "x" {
			a.Hash = fields[1]
		}
		snap.accounts = append(snap.accounts, a)
		snap.accountByName[a.Name] = a
		return nil
	})
	if err != nil {
		return nil, err
	}

	// shadow is optional: it is unreadable when the backend authenticates with
	// PAM as an unprivileged user, and absent on some systems.
	err = readColonFile(shadowPath, &snap.warnings, func(fields []string) error {
		// name:hash:lastchange:min:max:warn:inactive:expire:reserved
		if len(fields) < 8 {
			return fmt.Errorf("expected 9 fields, got %d", len(fields))
		}
		a, found := snap.accountByName[fields[0]]
		if !found {
			return nil
		}
		a.Hash = fields[1]
		a.HasShadow = true
		for i, dst := range []*int{&a.LastChange, &a.Min, &a.Max, &a.Warn, &a.Inactive, &a.Expire} {
			*dst = optionalInt(fields[2+i])
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
		return nil, err
	}

	err = readColonFile(groupPath, &snap.warnings, func(fields []string) error {
		// name:password:gid:members
		if len(fields) != 4 {
			return fmt.Errorf("expected 4 fields, got %d", len(fields))
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			return fmt.Errorf("bad gid: %w", err)
		}
		if _, dup := snap.groupByName[fields[0]]; dup {
			return nil
		}
		g := &group{Name: fields[0], GID: gid}
		for _, m := range strings.Split(fields[3], ",") {
			if m != "" {
				g.Members = append(g.Members, m)
			}
		}
		snap.groups = append(snap.groups, g)
		snap.groupByName[g.Name] = g
		if _, dup := snap.groupByGID[g.GID]; !dup {
			snap.groupByGID[g.GID] = g
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, a := range snap.accounts {
		snap.memberOf[a.Name] = []int{a.GID}
		snap.members[a.GID] = append(snap.members[a.GID], a.Name)
	}
	for _, g := range snap.groups {
		for _, m := range g.Members {
			if _, known := snap.accountByName[m]; !known || containsInt(snap.memberOf[m], g.GID) {
				continue
			}
			snap.memberOf[m] = append(snap.memberOf[m], g.GID)
			snap.members[g.GID] = append(snap.members[g.GID], m)
		}
	}
	for gid := range snap.members {
		sort.Strings(snap.members[gid])
	}

	return snap, nil
}

// readColonFile calls fn with the fields of each non-empty, non-comment line.
// Lines fn rejects are skipped and reported in warnings, so that one bad line
// doesn't take down every account.
func readColonFile(path string, warnings *[]string, fn func(fields []string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// NIS compat entries ("+" and "-" lines) have no local data to serve.
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		if err := fn(strings.Split(line, ":")); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("%s:%d: %s", path, lineNo, err))
		}
	}
	return scanner.Err()
}

func optionalInt(s string) int {
	if s == "" {
		return -1
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return v
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
