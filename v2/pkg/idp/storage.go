package idp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	authRequestLifetime = 10 * time.Minute
	accessTokenLifetime = time.Hour
	recentAppsLifetime  = 90 * 24 * time.Hour
	groupsScope         = "groups"
	groupsClaim         = "groups"
)

var (
	errNotFound = errors.New("not found or expired")
	errNoGrant  = errors.New("not supported")
)

// storage keeps the provider's sign-in requests, tokens and sessions in memory, and
// sessions and tokens in db as well, if there is one, so that they outlast a restart.
// Sign-ins in progress are short-lived, so only kept in memory.
type storage struct {
	p  *Provider
	db *stateDB

	mu            sync.Mutex
	authRequests  map[string]*authRequest
	codes         map[string]string // code -> auth request ID
	accessTokens  map[string]*accessToken
	refreshTokens map[string]*refreshToken // by secretKey of the token
	sessions      map[string]*session      // by secretKey of the cookie
	apps          map[string]time.Time     // client ID -> last sign-in, for the admin page
}

func newStorage(p *Provider, db *stateDB) *storage {
	return &storage{
		p:             p,
		db:            db,
		authRequests:  map[string]*authRequest{},
		codes:         map[string]string{},
		accessTokens:  map[string]*accessToken{},
		refreshTokens: map[string]*refreshToken{},
		sessions:      map[string]*session{},
		apps:          map[string]time.Time{},
	}
}

// expire drops everything that has expired.
func (s *storage) expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.authRequests {
		if now.Sub(r.created) > authRequestLifetime {
			delete(s.authRequests, id)
		}
	}
	for code, id := range s.codes {
		if _, ok := s.authRequests[id]; !ok {
			delete(s.codes, code)
		}
	}
	for id, t := range s.accessTokens {
		if now.After(t.expires) {
			delete(s.accessTokens, id)
		}
	}
	for id, t := range s.refreshTokens {
		if now.After(t.expires) {
			delete(s.refreshTokens, id)
		}
	}
	for id, sess := range s.sessions {
		if now.After(sess.expires) {
			delete(s.sessions, id)
		}
	}
	for id, at := range s.apps {
		if now.Sub(at) > recentAppsLifetime {
			delete(s.apps, id)
		}
	}
	s.db.purge(now)
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// identified is implemented by requests and tokens that carry the signed-in user.
type identified interface {
	identity() *Identity
}

// authRequest is an application's request to sign a user in.
type authRequest struct {
	id            string
	created       time.Time
	clientID      string
	redirectURI   string
	state         string
	nonce         string
	scopes        []string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	codeChallenge *oidc.CodeChallenge
	prompt        []string
	maxAge        *time.Duration

	user       *Identity // set once the user has signed in
	authTime   time.Time
	sessionKey string
}

func (r *authRequest) GetID() string                         { return r.id }
func (r *authRequest) GetACR() string                        { return "" }
func (r *authRequest) GetAMR() []string                      { return []string{"pwd"} }
func (r *authRequest) GetAudience() []string                 { return []string{r.clientID} }
func (r *authRequest) GetAuthTime() time.Time                { return r.authTime }
func (r *authRequest) GetClientID() string                   { return r.clientID }
func (r *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return r.codeChallenge }
func (r *authRequest) GetNonce() string                      { return r.nonce }
func (r *authRequest) GetRedirectURI() string                { return r.redirectURI }
func (r *authRequest) GetResponseType() oidc.ResponseType    { return r.responseType }
func (r *authRequest) GetResponseMode() oidc.ResponseMode    { return r.responseMode }
func (r *authRequest) GetScopes() []string                   { return r.scopes }
func (r *authRequest) GetState() string                      { return r.state }
func (r *authRequest) Done() bool                            { return r.user != nil }
func (r *authRequest) identity() *Identity                   { return r.user }
func (r *authRequest) GetSubject() string {
	if r.user == nil {
		return ""
	}
	return r.user.Username
}

type accessToken struct {
	id         string
	sessionKey string
	clientID   string
	user       *Identity
	audience   []string
	scopes     []string
	expires    time.Time
}

type refreshToken struct {
	key        string // secretKey of the token, which only the application has
	sessionKey string
	clientID   string
	user       *Identity
	audience   []string
	scopes     []string
	amr        []string
	authTime   time.Time
	expires    time.Time
	accessID   string
}

func (t *refreshToken) GetAMR() []string                 { return t.amr }
func (t *refreshToken) GetAudience() []string            { return t.audience }
func (t *refreshToken) GetAuthTime() time.Time           { return t.authTime }
func (t *refreshToken) GetClientID() string              { return t.clientID }
func (t *refreshToken) GetScopes() []string              { return t.scopes }
func (t *refreshToken) GetSubject() string               { return t.user.Username }
func (t *refreshToken) SetCurrentScopes(scopes []string) { t.scopes = scopes }
func (t *refreshToken) identity() *Identity              { return t.user }

// session is a signed-in browser, remembered by a cookie so that each application
// doesn't ask for the password again. Tokens issued through a session end with it.
type session struct {
	key       string // secretKey of the cookie, which only the browser has
	handle    string // names the session on the admin page
	user      *Identity
	authTime  time.Time
	expires   time.Time
	lastSeen  time.Time
	address   string
	userAgent string
	clients   map[string]time.Time // applications signed in to, and when
}

// sessionInfo is a copy of a session for the admin page.
type sessionInfo struct {
	Handle    string
	User      Identity
	AuthTime  time.Time
	Expires   time.Time
	LastSeen  time.Time
	Address   string
	UserAgent string
	Clients   []string
}

// newSession starts a session, and returns it with the cookie that names it.
func (s *storage) newSession(user *Identity, now time.Time, address, userAgent string) (*session, string) {
	cookie := randomID()
	sess := &session{
		key: secretKey(cookie), handle: randomID()[:16], user: user, authTime: now, lastSeen: now,
		expires: now.Add(s.p.settings.Load().sessionLifetime),
		address: address, userAgent: userAgent, clients: map[string]time.Time{},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.key] = sess
	s.db.put(tableSessions, sess.key, sess.record(), sess.expires)
	return sess, cookie
}

// session returns the session a cookie names.
func (s *storage) session(cookie string, now time.Time) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[secretKey(cookie)]
	if !ok || now.After(sess.expires) {
		return nil
	}
	return sess
}

// endSessions ends the sessions match selects, and the tokens issued through them.
func (s *storage) endSessions(match func(*session) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	ended := map[string]bool{}
	for key, sess := range s.sessions {
		if match(sess) {
			ended[key] = true
			delete(s.sessions, key)
			s.db.del(tableSessions, key)
		}
	}
	s.dropTokens(func(t tokenOwner) bool { return ended[t.sessionKey] })
	return len(ended)
}

// endSession ends the session a cookie names.
func (s *storage) endSession(cookie string) {
	key := secretKey(cookie)
	s.endSessions(func(sess *session) bool { return sess.key == key })
}

// tokenOwner says whom a token was issued to, for dropTokens.
type tokenOwner struct {
	sessionKey string
	clientID   string
	username   string
}

// dropTokens deletes the tokens match selects. The caller holds s.mu.
func (s *storage) dropTokens(match func(tokenOwner) bool) {
	for id, t := range s.accessTokens {
		if match(tokenOwner{t.sessionKey, t.clientID, t.user.Username}) {
			delete(s.accessTokens, id)
			s.db.del(tableAccessTokens, id)
		}
	}
	for key, t := range s.refreshTokens {
		if match(tokenOwner{t.sessionKey, t.clientID, t.user.Username}) {
			delete(s.refreshTokens, key)
			s.db.del(tableRefreshTokens, key)
		}
	}
}

// revokeClient deletes every token issued to an application.
func (s *storage) revokeClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropTokens(func(t tokenOwner) bool { return t.clientID == clientID })
}

func (s *storage) listSessions(now time.Time) []sessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []sessionInfo
	for _, sess := range s.sessions {
		if now.After(sess.expires) {
			continue
		}
		info := sessionInfo{Handle: sess.handle, User: *sess.user, AuthTime: sess.authTime,
			Expires: sess.expires, LastSeen: sess.lastSeen, Address: sess.address, UserAgent: sess.userAgent}
		for c := range sess.clients {
			info.Clients = append(info.Clients, c)
		}
		slices.Sort(info.Clients)
		list = append(list, info)
	}
	slices.SortFunc(list, func(a, b sessionInfo) int { return b.LastSeen.Compare(a.LastSeen) })
	return list
}

// recentApps returns when each application last signed someone in.
func (s *storage) recentApps() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	apps := make(map[string]time.Time, len(s.apps))
	for id, at := range s.apps {
		apps[id] = at
	}
	return apps
}

// completeAuthRequest records who signed in for an auth request, through which session.
func (s *storage) completeAuthRequest(id string, sess *session, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.authRequests[id]
	if !ok {
		return errNotFound
	}
	live, ok := s.sessions[sess.key]
	if !ok {
		return errNotFound
	}
	r.user, r.authTime, r.sessionKey = live.user, live.authTime, live.key
	live.lastSeen = now
	live.clients[r.clientID] = now
	s.apps[r.clientID] = now
	s.db.put(tableSessions, live.key, live.record(), live.expires)
	s.db.put(tableApps, r.clientID, appRecord{LastSignIn: now}, now.Add(recentAppsLifetime))
	return nil
}

func (s *storage) authRequest(id string) (*authRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.authRequests[id]
	if !ok || time.Since(r.created) > authRequestLifetime {
		return nil, errNotFound
	}
	return r, nil
}

// op.Storage

var _ op.Storage = (*storage)(nil)

func (s *storage) CreateAuthRequest(_ context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	r := &authRequest{
		id:           randomID(),
		created:      time.Now(),
		clientID:     req.ClientID,
		redirectURI:  req.RedirectURI,
		state:        req.State,
		nonce:        req.Nonce,
		scopes:       req.Scopes,
		responseType: req.ResponseType,
		responseMode: req.ResponseMode,
		prompt:       req.Prompt,
	}
	if req.CodeChallenge != "" {
		r.codeChallenge = &oidc.CodeChallenge{Challenge: req.CodeChallenge, Method: req.CodeChallengeMethod}
	}
	if req.MaxAge != nil {
		maxAge := time.Duration(*req.MaxAge) * time.Second
		r.maxAge = &maxAge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authRequests[r.id] = r
	return r, nil
}

func (s *storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	return s.authRequest(id)
}

func (s *storage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	id, ok := s.codes[code]
	s.mu.Unlock()
	if !ok {
		return nil, errNotFound
	}
	return s.authRequest(id)
}

func (s *storage) SaveAuthCode(_ context.Context, id, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = id
	return nil
}

// DeleteAuthRequest is called once a code has been exchanged, so codes are single use.
func (s *storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authRequests, id)
	for code, reqID := range s.codes {
		if reqID == id {
			delete(s.codes, code)
		}
	}
	return nil
}

// newAccessToken records an access token. The caller holds s.mu.
func (s *storage) newAccessToken(sessionKey, clientID string, user *Identity, audience, scopes []string) *accessToken {
	t := &accessToken{
		id:         randomID(),
		sessionKey: sessionKey,
		clientID:   clientID,
		user:       user,
		audience:   audience,
		scopes:     scopes,
		expires:    time.Now().Add(accessTokenLifetime),
	}
	s.accessTokens[t.id] = t
	s.db.put(tableAccessTokens, t.id, t.record(), t.expires)
	return t
}

func requestIdentity(req op.TokenRequest) (*Identity, error) {
	if r, ok := req.(identified); ok && r.identity() != nil {
		return r.identity(), nil
	}
	return nil, errors.New("request has no signed-in user")
}

func (s *storage) CreateAccessToken(_ context.Context, req op.TokenRequest) (string, time.Time, error) {
	user, err := requestIdentity(req)
	if err != nil {
		return "", time.Time{}, err
	}
	r, ok := req.(*authRequest)
	if !ok {
		return "", time.Time{}, errNoGrant
	}
	if err := s.p.checkBlocked(r.clientID); err != nil {
		return "", time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[r.sessionKey]; !ok {
		return "", time.Time{}, errNotFound
	}
	t := s.newAccessToken(r.sessionKey, r.clientID, user, req.GetAudience(), req.GetScopes())
	return t.id, t.expires, nil
}

// CreateAccessAndRefreshTokens issues tokens for a code exchange, or rotates a
// refresh token. A refresh token never outlives the sign-in it came from.
func (s *storage) CreateAccessAndRefreshTokens(_ context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	user, err := requestIdentity(req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if c, ok := req.(interface{ GetClientID() string }); !ok {
		return "", "", time.Time{}, errNoGrant
	} else if err := s.p.checkBlocked(c.GetClientID()); err != nil {
		return "", "", time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var rt *refreshToken
	switch r := req.(type) {
	case *authRequest:
		if _, ok := s.sessions[r.sessionKey]; !ok {
			return "", "", time.Time{}, errNotFound
		}
		rt = &refreshToken{
			sessionKey: r.sessionKey,
			clientID:   r.clientID,
			user:       user,
			audience:   r.GetAudience(),
			scopes:     r.scopes,
			amr:        r.GetAMR(),
			authTime:   r.authTime,
			expires:    r.authTime.Add(s.p.settings.Load().sessionLifetime),
		}
	case *refreshToken:
		old, ok := s.refreshTokens[secretKey(current)]
		if !ok || old != r {
			return "", "", time.Time{}, errNotFound
		}
		delete(s.refreshTokens, old.key)
		delete(s.accessTokens, old.accessID)
		s.db.del(tableRefreshTokens, old.key)
		s.db.del(tableAccessTokens, old.accessID)
		rt = r
	default:
		return "", "", time.Time{}, errNoGrant
	}
	at := s.newAccessToken(rt.sessionKey, rt.clientID, user, rt.audience, rt.scopes)
	token := randomID()
	rt.key = secretKey(token)
	rt.accessID = at.id
	s.refreshTokens[rt.key] = rt
	s.db.put(tableRefreshTokens, rt.key, rt.record(), rt.expires)
	return at.id, token, at.expires, nil
}

func (s *storage) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[secretKey(token)]
	if !ok || time.Now().After(rt.expires) {
		return nil, op.ErrInvalidRefreshToken
	}
	return rt, nil
}

func (s *storage) TerminateSession(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropTokens(func(t tokenOwner) bool { return t.clientID == clientID && t.username == userID })
	return nil
}

func (s *storage) GetRefreshTokenInfo(_ context.Context, clientID, token string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[secretKey(token)]
	if !ok || rt.clientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.user.Username, rt.key, nil
}

// RevokeToken revokes an access token, by ID, or a refresh token, by its value.
func (s *storage) RevokeToken(_ context.Context, tokenOrID, _, clientID string) *oidc.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.accessTokens[tokenOrID]; ok {
		if t.clientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		delete(s.accessTokens, tokenOrID)
		s.db.del(tableAccessTokens, tokenOrID)
		return nil
	}
	if t, ok := s.refreshTokens[secretKey(tokenOrID)]; ok {
		if t.clientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		delete(s.refreshTokens, t.key)
		delete(s.accessTokens, t.accessID)
		s.db.del(tableRefreshTokens, t.key)
		s.db.del(tableAccessTokens, t.accessID)
	}
	return nil
}

func (s *storage) SigningKey(context.Context) (op.SigningKey, error) {
	return signingKey{s.p.keys}, nil
}

func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *storage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{s.p.keys}}, nil
}

func (s *storage) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	return s.p.lookupClient(id)
}

func (s *storage) AuthorizeClientIDSecret(_ context.Context, id, secret string) error {
	c, err := s.p.lookupClient(id)
	if err != nil {
		return err
	}
	return s.p.checkSecret(c, secret)
}

// SetUserinfoFromScopes is deprecated in favour of SetUserinfoFromRequest.
func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

func (s *storage) SetUserinfoFromRequest(_ context.Context, info *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	r, ok := req.(identified)
	if !ok || r.identity() == nil {
		return errors.New("request has no signed-in user")
	}
	setUserinfo(info, r.identity(), scopes)
	return nil
}

func (s *storage) SetUserinfoFromToken(_ context.Context, info *oidc.UserInfo, tokenID, _, _ string) error {
	t, err := s.accessToken(tokenID)
	if err != nil {
		return err
	}
	setUserinfo(info, t.user, t.scopes)
	return nil
}

func (s *storage) SetIntrospectionFromToken(_ context.Context, resp *oidc.IntrospectionResponse, tokenID, _, clientID string) error {
	t, err := s.accessToken(tokenID)
	if err != nil {
		return err
	}
	if !slices.Contains(t.audience, clientID) {
		return errors.New("token was not issued to this client")
	}
	info := new(oidc.UserInfo)
	setUserinfo(info, t.user, t.scopes)
	resp.SetUserInfo(info)
	resp.Scope = t.scopes
	resp.ClientID = t.clientID
	resp.Expiration = oidc.FromTime(t.expires)
	return nil
}

func (s *storage) accessToken(id string) (*accessToken, error) {
	s.mu.Lock()
	t, ok := s.accessTokens[id]
	s.mu.Unlock()
	if !ok || time.Now().After(t.expires) {
		return nil, errNotFound
	}
	if err := s.p.checkBlocked(t.clientID); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}

// GetPrivateClaimsFromRequest puts the user's groups in JWT access tokens too, for
// services that authorise API calls by them.
func (s *storage) GetPrivateClaimsFromRequest(_ context.Context, req op.TokenRequest, _ []string) (map[string]any, error) {
	user, err := requestIdentity(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{groupsClaim: groupsOf(user)}, nil
}

func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errNoGrant
}

func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errNoGrant
}

func (s *storage) Health(context.Context) error { return nil }

// setUserinfo fills in the claims for a user. Groups are always included, whether or
// not the application asked for the groups scope, since most use them for roles.
func setUserinfo(info *oidc.UserInfo, user *Identity, scopes []string) {
	info.Subject = user.Username
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			info.PreferredUsername = user.Username
			info.Name = firstOf(user.Name, user.Username)
			info.GivenName = user.GivenName
			info.FamilyName = user.Surname
		case oidc.ScopeEmail:
			if user.Email != "" {
				info.Email = user.Email
				// Addresses come from the directory, not from the user.
				info.EmailVerified = true
			}
		}
	}
	info.AppendClaims(groupsClaim, groupsOf(user))
}

func groupsOf(user *Identity) []string {
	if user.Groups == nil {
		return []string{}
	}
	return user.Groups
}
