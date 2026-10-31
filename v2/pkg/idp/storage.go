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
	groupsScope         = "groups"
	groupsClaim         = "groups"
)

var (
	errNotFound = errors.New("not found or expired")
	errNoGrant  = errors.New("not supported")
)

// storage keeps the provider's sign-in requests, tokens and sessions in memory.
type storage struct {
	p *Provider

	mu            sync.Mutex
	authRequests  map[string]*authRequest
	codes         map[string]string // code -> auth request ID
	accessTokens  map[string]*accessToken
	refreshTokens map[string]*refreshToken
	sessions      map[string]*session
}

func newStorage(p *Provider) *storage {
	return &storage{
		p:             p,
		authRequests:  map[string]*authRequest{},
		codes:         map[string]string{},
		accessTokens:  map[string]*accessToken{},
		refreshTokens: map[string]*refreshToken{},
		sessions:      map[string]*session{},
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

	user     *Identity // set once the user has signed in
	authTime time.Time
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
	id       string
	clientID string
	user     *Identity
	audience []string
	scopes   []string
	expires  time.Time
}

type refreshToken struct {
	token    string
	clientID string
	user     *Identity
	audience []string
	scopes   []string
	amr      []string
	authTime time.Time
	expires  time.Time
	accessID string
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
// doesn't ask for the password again.
type session struct {
	id       string
	user     *Identity
	authTime time.Time
	expires  time.Time
}

func (s *storage) newSession(user *Identity, now time.Time) *session {
	sess := &session{id: randomID(), user: user, authTime: now, expires: now.Add(s.p.sessionLifetime)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.id] = sess
	return sess
}

func (s *storage) session(id string, now time.Time) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || now.After(sess.expires) {
		return nil
	}
	return sess
}

func (s *storage) endSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// completeAuthRequest records who signed in for an auth request.
func (s *storage) completeAuthRequest(id string, user *Identity, authTime time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.authRequests[id]
	if !ok {
		return errNotFound
	}
	r.user, r.authTime = user, authTime
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

func (s *storage) newAccessToken(clientID string, user *Identity, audience, scopes []string) *accessToken {
	t := &accessToken{
		id:       randomID(),
		clientID: clientID,
		user:     user,
		audience: audience,
		scopes:   scopes,
		expires:  time.Now().Add(accessTokenLifetime),
	}
	s.accessTokens[t.id] = t
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
	clientID := ""
	if r, ok := req.(*authRequest); ok {
		clientID = r.clientID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.newAccessToken(clientID, user, req.GetAudience(), req.GetScopes())
	return t.id, t.expires, nil
}

// CreateAccessAndRefreshTokens issues tokens for a code exchange, or rotates a
// refresh token. A refresh token never outlives the sign-in it came from.
func (s *storage) CreateAccessAndRefreshTokens(_ context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	user, err := requestIdentity(req)
	if err != nil {
		return "", "", time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var rt *refreshToken
	switch r := req.(type) {
	case *authRequest:
		rt = &refreshToken{
			clientID: r.clientID,
			user:     user,
			audience: r.GetAudience(),
			scopes:   r.scopes,
			amr:      r.GetAMR(),
			authTime: r.authTime,
			expires:  r.authTime.Add(s.p.sessionLifetime),
		}
	case *refreshToken:
		old, ok := s.refreshTokens[current]
		if !ok || old != r {
			return "", "", time.Time{}, errNotFound
		}
		delete(s.refreshTokens, current)
		delete(s.accessTokens, old.accessID)
		rt = r
	default:
		return "", "", time.Time{}, errNoGrant
	}
	at := s.newAccessToken(rt.clientID, user, rt.audience, rt.scopes)
	rt.token = randomID()
	rt.accessID = at.id
	s.refreshTokens[rt.token] = rt
	return at.id, rt.token, at.expires, nil
}

func (s *storage) TokenRequestByRefreshToken(_ context.Context, token string) (op.RefreshTokenRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	if !ok || time.Now().After(rt.expires) {
		return nil, op.ErrInvalidRefreshToken
	}
	return rt, nil
}

func (s *storage) TerminateSession(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.accessTokens {
		if t.clientID == clientID && t.user.Username == userID {
			delete(s.accessTokens, id)
		}
	}
	for id, t := range s.refreshTokens {
		if t.clientID == clientID && t.user.Username == userID {
			delete(s.refreshTokens, id)
		}
	}
	return nil
}

func (s *storage) GetRefreshTokenInfo(_ context.Context, clientID, token string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	if !ok || rt.clientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rt.user.Username, rt.token, nil
}

func (s *storage) RevokeToken(_ context.Context, tokenOrID, _, clientID string) *oidc.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.accessTokens[tokenOrID]; ok {
		if t.clientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		delete(s.accessTokens, tokenOrID)
		return nil
	}
	if t, ok := s.refreshTokens[tokenOrID]; ok {
		if t.clientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		delete(s.refreshTokens, tokenOrID)
		delete(s.accessTokens, t.accessID)
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
	defer s.mu.Unlock()
	t, ok := s.accessTokens[id]
	if !ok || time.Now().After(t.expires) {
		return nil, errNotFound
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
