package idp

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	_ "modernc.org/sqlite"
)

const stateDBFile = "oidc-state.db"

// Tables of records, each a JSON document under a key, with an expiry time so that
// old records can be purged without decoding them.
const (
	tableSessions      = "sessions"
	tableAccessTokens  = "access_tokens"
	tableRefreshTokens = "refresh_tokens"
	tableApps          = "apps"
)

var tables = []string{tableSessions, tableAccessTokens, tableRefreshTokens, tableApps}

// stateDB keeps sessions and tokens across restarts. Writes go through to it as the
// in-memory state changes; it is only read at start. A failed write is logged and
// otherwise ignored, leaving the provider working from memory.
type stateDB struct {
	db  *sql.DB
	log zerolog.Logger
}

func openStateDB(path string, log zerolog.Logger) (*stateDB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, table := range tables {
		_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + table + ` (key TEXT PRIMARY KEY, data TEXT NOT NULL, expires INTEGER NOT NULL)`)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return &stateDB{db: db, log: log}, nil
}

func (d *stateDB) put(table, key string, record any, expires time.Time) {
	if d == nil {
		return
	}
	data, err := json.Marshal(record)
	if err == nil {
		_, err = d.db.Exec(`INSERT OR REPLACE INTO `+table+` (key, data, expires) VALUES (?, ?, ?)`, key, string(data), expires.Unix())
	}
	if err != nil {
		d.log.Error().Err(err).Str("table", table).Msg("oidc: could not save state")
	}
}

func (d *stateDB) del(table string, keys ...string) {
	if d == nil {
		return
	}
	for _, key := range keys {
		if _, err := d.db.Exec(`DELETE FROM `+table+` WHERE key = ?`, key); err != nil {
			d.log.Error().Err(err).Str("table", table).Msg("oidc: could not delete state")
		}
	}
}

func (d *stateDB) purge(now time.Time) {
	if d == nil {
		return
	}
	for _, table := range tables {
		if _, err := d.db.Exec(`DELETE FROM `+table+` WHERE expires < ?`, now.Unix()); err != nil {
			d.log.Error().Err(err).Str("table", table).Msg("oidc: could not purge state")
		}
	}
}

// load decodes each unexpired record in a table and passes it to add.
func load[T any](d *stateDB, table string, now time.Time, add func(key string, record *T)) error {
	if d == nil {
		return nil
	}
	rows, err := d.db.Query(`SELECT key, data FROM `+table+` WHERE expires >= ?`, now.Unix())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, data string
		if err := rows.Scan(&key, &data); err != nil {
			return err
		}
		record := new(T)
		if err := json.Unmarshal([]byte(data), record); err != nil {
			d.log.Warn().Err(err).Str("table", table).Msg("oidc: skipping unreadable state")
			continue
		}
		add(key, record)
	}
	return rows.Err()
}

func (d *stateDB) close() {
	if d != nil {
		d.db.Close()
	}
}

// secretKey is how a bearer secret, such as a session cookie or refresh token, is
// stored: hashed, so that the state file can't be used to take over sessions.
func secretKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Records, as stored.

type sessionRecord struct {
	Handle    string               `json:"handle"`
	User      Identity             `json:"user"`
	AuthTime  time.Time            `json:"authTime"`
	Expires   time.Time            `json:"expires"`
	LastSeen  time.Time            `json:"lastSeen"`
	Address   string               `json:"address,omitempty"`
	UserAgent string               `json:"userAgent,omitempty"`
	Clients   map[string]time.Time `json:"clients,omitempty"`
}

type accessTokenRecord struct {
	SessionKey string    `json:"session"`
	ClientID   string    `json:"client"`
	User       Identity  `json:"user"`
	Audience   []string  `json:"audience"`
	Scopes     []string  `json:"scopes"`
	Expires    time.Time `json:"expires"`
}

type refreshTokenRecord struct {
	SessionKey string    `json:"session"`
	ClientID   string    `json:"client"`
	User       Identity  `json:"user"`
	Audience   []string  `json:"audience"`
	Scopes     []string  `json:"scopes"`
	AMR        []string  `json:"amr"`
	AuthTime   time.Time `json:"authTime"`
	Expires    time.Time `json:"expires"`
	AccessID   string    `json:"accessToken"`
}

type appRecord struct {
	LastSignIn time.Time `json:"lastSignIn"`
}

func (s *session) record() sessionRecord {
	return sessionRecord{Handle: s.handle, User: *s.user, AuthTime: s.authTime, Expires: s.expires,
		LastSeen: s.lastSeen, Address: s.address, UserAgent: s.userAgent, Clients: s.clients}
}

func (r *sessionRecord) session(key string) *session {
	user := r.User
	clients := r.Clients
	if clients == nil {
		clients = map[string]time.Time{}
	}
	return &session{key: key, handle: r.Handle, user: &user, authTime: r.AuthTime, expires: r.Expires,
		lastSeen: r.LastSeen, address: r.Address, userAgent: r.UserAgent, clients: clients}
}

func (t *accessToken) record() accessTokenRecord {
	return accessTokenRecord{SessionKey: t.sessionKey, ClientID: t.clientID, User: *t.user,
		Audience: t.audience, Scopes: t.scopes, Expires: t.expires}
}

func (r *accessTokenRecord) token(id string) *accessToken {
	user := r.User
	return &accessToken{id: id, sessionKey: r.SessionKey, clientID: r.ClientID, user: &user,
		audience: r.Audience, scopes: r.Scopes, expires: r.Expires}
}

func (t *refreshToken) record() refreshTokenRecord {
	return refreshTokenRecord{SessionKey: t.sessionKey, ClientID: t.clientID, User: *t.user, Audience: t.audience,
		Scopes: t.scopes, AMR: t.amr, AuthTime: t.authTime, Expires: t.expires, AccessID: t.accessID}
}

func (r *refreshTokenRecord) token(key string) *refreshToken {
	user := r.User
	return &refreshToken{key: key, sessionKey: r.SessionKey, clientID: r.ClientID, user: &user, audience: r.Audience,
		scopes: r.Scopes, amr: r.AMR, authTime: r.AuthTime, expires: r.Expires, accessID: r.AccessID}
}

// restore loads the saved state into memory.
func (s *storage) restore(now time.Time) error {
	err := load(s.db, tableSessions, now, func(key string, r *sessionRecord) {
		s.sessions[key] = r.session(key)
	})
	if err == nil {
		err = load(s.db, tableAccessTokens, now, func(id string, r *accessTokenRecord) {
			s.accessTokens[id] = r.token(id)
		})
	}
	if err == nil {
		err = load(s.db, tableRefreshTokens, now, func(key string, r *refreshTokenRecord) {
			s.refreshTokens[key] = r.token(key)
		})
	}
	if err == nil {
		err = load(s.db, tableApps, now, func(id string, r *appRecord) {
			s.apps[id] = r.LastSignIn
		})
	}
	return err
}
