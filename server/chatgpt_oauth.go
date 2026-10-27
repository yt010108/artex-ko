package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (s *Server) attachChatGPTAuth(cfg *agent.Config) bool {
	if !cfg.ChatGPT {
		return true
	}
	if s.chatGPTAuth == nil || !s.chatGPTAuth.available() {
		return false
	}
	cfg.APIKey = db.ChatGPTProfileKey
	cfg.ChatGPTTokens = s.chatGPTAuth
	cfg.BaseURL = chatGPTAPIBase
	return true
}

const (
	chatGPTAuthBase      = "https://auth.openai.com"
	chatGPTAPIBase       = "https://api.openai.com/v1"
	chatGPTCredentialKey = "chatgpt_oauth_credentials"
	chatGPTHostKey       = "chatgpt_oauth_host_id"
	chatGPTScope         = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
	chatGPTCallbackPath  = "/api/auth/chatgpt/callback"
)

type chatGPTCredentials struct {
	ClientID     string    `json:"client_id"`
	Subject      string    `json:"subject"`
	Email        string    `json:"email"`
	IDToken      string    `json:"id_token"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (c chatGPTCredentials) planEnabled() bool {
	for _, scope := range strings.Fields(c.Scope) {
		if scope == "chatgpt.tokens.use.direct" {
			return true
		}
	}
	return false
}

type chatGPTAttempt struct {
	Verifier    string
	Nonce       string
	ClientID    string
	Subject     string
	RedirectURI string
	ReturnTo    string
	ExpiresAt   time.Time
}

// Credentials live only in the local PostgreSQL settings table, which is not
// returned by the settings API. The mutex serializes rotating-token refreshes.
type chatGPTAuth struct {
	pg      chatGPTSettings
	client  *http.Client
	baseURL string // fixed in production; overridden by local HTTP tests
	mu      sync.Mutex
	pending map[string]chatGPTAttempt
}

type chatGPTSettings interface {
	GetSetting(string) (string, bool, error)
	SetSetting(string, string) error
	InsertSettingIfAbsent(string, string) (bool, error)
}

func newChatGPTAuth(pg chatGPTSettings) *chatGPTAuth {
	return &chatGPTAuth{pg: pg, client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, baseURL: chatGPTAuthBase, pending: make(map[string]chatGPTAttempt)}
}

func (a *chatGPTAuth) credentials() (chatGPTCredentials, error) {
	var c chatGPTCredentials
	if a == nil || a.pg == nil {
		return c, errors.New("ChatGPT 연결 저장소를 사용할 수 없습니다")
	}
	value, ok, err := a.pg.GetSetting(chatGPTCredentialKey)
	if err != nil {
		return c, err
	}
	if !ok || value == "" {
		return c, nil
	}
	if err := json.Unmarshal([]byte(value), &c); err != nil {
		return chatGPTCredentials{}, errors.New("ChatGPT 연결 정보를 읽을 수 없습니다")
	}
	return c, nil
}

func (a *chatGPTAuth) save(c chatGPTCredentials) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return a.pg.SetSetting(chatGPTCredentialKey, string(data))
}

func (a *chatGPTAuth) available() bool {
	c, err := a.credentials()
	return err == nil && c.ClientID != "" && c.RefreshToken != "" && c.planEnabled()
}

func (a *chatGPTAuth) hostID() (string, error) {
	value, ok, err := a.pg.GetSetting(chatGPTHostKey)
	if err != nil {
		return "", err
	}
	if ok && value != "" {
		return value, nil
	}
	value = "urn:uuid:" + uuid.NewString()
	if _, err := a.pg.InsertSettingIfAbsent(chatGPTHostKey, value); err != nil {
		return "", err
	}
	value, _, err = a.pg.GetSetting(chatGPTHostKey)
	return value, err
}

func chatGPTRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func chatGPTLoopbackRedirect(host string) (string, error) {
	u, err := url.Parse("http://" + host)
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return "", errors.New("ChatGPT 연결은 이 컴퓨터의 127.0.0.1 주소에서만 시작할 수 있습니다")
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return "http://127.0.0.1:" + port + chatGPTCallbackPath, nil
}

func chatGPTReturnTo(raw, redirectURI string) string {
	fallback := strings.TrimSuffix(redirectURI, chatGPTCallbackPath) + "/system/llm"
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fallback
	}
	return u.Scheme + "://" + u.Host + "/system/llm"
}

func (s *Server) chatGPTStart(w http.ResponseWriter, r *http.Request) {
	redirectURI, err := chatGPTLoopbackRedirect(r.Host)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a := s.chatGPTAuth
	var body struct {
		ReturnTo string `json:"return_to"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	}
	returnTo := chatGPTReturnTo(body.ReturnTo, redirectURI)
	if a == nil {
		writeErr(w, 503, "ChatGPT 연결을 사용할 수 없습니다")
		return
	}
	hostID, err := a.hostID()
	if err != nil {
		writeErr(w, 503, "ChatGPT 호스트 정보를 저장할 수 없습니다")
		return
	}
	state, err := chatGPTRandom()
	if err != nil {
		writeErr(w, 500, "ChatGPT 인증을 시작할 수 없습니다")
		return
	}
	nonce, err := chatGPTRandom()
	if err != nil {
		writeErr(w, 500, "ChatGPT 인증을 시작할 수 없습니다")
		return
	}
	verifier, err := chatGPTRandom()
	if err != nil {
		writeErr(w, 500, "ChatGPT 인증을 시작할 수 없습니다")
		return
	}
	c, err := a.credentials()
	if err != nil {
		writeErr(w, 503, "ChatGPT 연결 정보를 읽을 수 없습니다")
		return
	}
	clientID := c.ClientID
	if clientID == "" {
		clientID = "dynamic_agent_client"
	}
	a.mu.Lock()
	for k, pending := range a.pending {
		if time.Now().After(pending.ExpiresAt) {
			delete(a.pending, k)
		}
	}
	a.pending[state] = chatGPTAttempt{Verifier: verifier, Nonce: nonce, ClientID: clientID, Subject: c.Subject, RedirectURI: redirectURI, ReturnTo: returnTo, ExpiresAt: time.Now().Add(10 * time.Minute)}
	a.mu.Unlock()
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {redirectURI},
		"scope": {chatGPTScope}, "resource": {chatGPTAPIBase}, "state": {state}, "nonce": {nonce},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"ext_agent_host_id": {hostID},
	}
	if clientID == "dynamic_agent_client" {
		q.Set("agent_name_hint", "ARTEX")
	} else {
		if !c.planEnabled() {
			q.Set("prompt", "consent")
		}
		if c.IDToken != "" {
			q.Set("id_token_hint", c.IDToken)
		}
		if c.Email != "" {
			q.Set("login_hint", c.Email)
		}
	}
	writeJSON(w, 200, map[string]string{"authorize_url": a.baseURL + "/api/accounts/authorize?" + q.Encode()})
}

type chatGPTTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

func (a *chatGPTAuth) exchange(ctx context.Context, form url.Values) (chatGPTTokenResponse, error) {
	var token chatGPTTokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/api/accounts/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return token, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return token, errors.New("ChatGPT 인증 서버에 연결할 수 없습니다")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return token, fmt.Errorf("ChatGPT 인증이 거부되었습니다 (HTTP %d)", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil {
		return token, errors.New("ChatGPT 인증 응답을 읽을 수 없습니다")
	}
	if token.AccessToken == "" || token.ExpiresIn <= 0 || (token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer")) {
		return token, errors.New("ChatGPT 인증 응답이 올바르지 않습니다")
	}
	return token, nil
}

type chatGPTIDClaims struct {
	Email string `json:"email"`
	Nonce string `json:"nonce"`
	jwt.RegisteredClaims
}

func (a *chatGPTAuth) validateIDToken(ctx context.Context, raw, clientID, nonce string) (*chatGPTIDClaims, error) {
	// Discovery and JWKS are fetched from OpenAI's fixed issuer, never a caller URL.
	discoveryReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/.well-known/openid-configuration", nil)
	discoveryResp, err := a.client.Do(discoveryReq)
	if err != nil {
		return nil, errors.New("OpenAI 인증 키를 조회할 수 없습니다")
	}
	defer discoveryResp.Body.Close()
	if discoveryResp.StatusCode != http.StatusOK {
		return nil, errors.New("OpenAI 인증 키를 조회할 수 없습니다")
	}
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(discoveryResp.Body, 1<<20)).Decode(&discovery); err != nil {
		return nil, err
	}
	if discovery.Issuer != a.baseURL {
		return nil, errors.New("OpenAI 인증 발급자가 일치하지 않습니다")
	}
	jwksURL, err := url.Parse(discovery.JWKSURI)
	if err != nil || jwksURL.Scheme != "https" || jwksURL.Host != "auth.openai.com" {
		// Local HTTP fixtures are used only by package tests.
		if a.baseURL == chatGPTAuthBase || err != nil || jwksURL.Host != strings.TrimPrefix(a.baseURL, "http://") {
			return nil, errors.New("OpenAI 인증 키 주소가 올바르지 않습니다")
		}
	}
	jwksReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, discovery.JWKSURI, nil)
	jwksResp, err := a.client.Do(jwksReq)
	if err != nil {
		return nil, errors.New("OpenAI 인증 키를 조회할 수 없습니다")
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		return nil, errors.New("OpenAI 인증 키를 조회할 수 없습니다")
	}
	var keys struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			ALG string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(jwksResp.Body, 1<<20)).Decode(&keys); err != nil {
		return nil, err
	}
	claims := new(chatGPTIDClaims)
	parsed, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(a.baseURL), jwt.WithAudience(clientID), jwt.WithExpirationRequired()).ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		for _, key := range keys.Keys {
			if key.KID != kid || key.KTY != "RSA" || (key.ALG != "" && key.ALG != "RS256") {
				continue
			}
			n, errN := base64.RawURLEncoding.DecodeString(key.N)
			e, errE := base64.RawURLEncoding.DecodeString(key.E)
			if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
				break
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
		}
		return nil, errors.New("OpenAI 인증 키를 찾을 수 없습니다")
	})
	if err != nil || !parsed.Valid || claims.Subject == "" || claims.Nonce != nonce {
		return nil, errors.New("ChatGPT 계정 신원을 확인할 수 없습니다")
	}
	return claims, nil
}

func (s *Server) chatGPTCallback(w http.ResponseWriter, r *http.Request) {
	a := s.chatGPTAuth
	state := r.URL.Query().Get("state")
	a.mu.Lock()
	attempt, ok := a.pending[state]
	delete(a.pending, state)
	a.mu.Unlock()
	if !ok || time.Now().After(attempt.ExpiresAt) {
		writeErr(w, 400, "ChatGPT 인증 요청이 만료되었거나 유효하지 않습니다")
		return
	}
	finish := func(result string) { http.Redirect(w, r, attempt.ReturnTo+"?chatgpt="+result, http.StatusSeeOther) }
	if r.URL.Query().Get("error") != "" {
		finish("denied")
		return
	}
	code := r.URL.Query().Get("code")
	clientID := r.URL.Query().Get("client_id")
	if attempt.ClientID == "dynamic_agent_client" {
		if clientID == "" || clientID == "dynamic_agent_client" {
			finish("error")
			return
		}
	} else {
		if clientID != "" && clientID != attempt.ClientID {
			finish("error")
			return
		}
		clientID = attempt.ClientID
	}
	if code == "" {
		finish("error")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {attempt.Verifier}, "redirect_uri": {attempt.RedirectURI}, "resource": {chatGPTAPIBase}}
	token, err := a.exchange(r.Context(), form)
	if err != nil || token.IDToken == "" || token.RefreshToken == "" {
		finish("error")
		return
	}
	claims, err := a.validateIDToken(r.Context(), token.IDToken, clientID, attempt.Nonce)
	if err != nil || (attempt.Subject != "" && attempt.Subject != claims.Subject) {
		finish("error")
		return
	}
	c := chatGPTCredentials{ClientID: clientID, Subject: claims.Subject, Email: claims.Email, IDToken: token.IDToken, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, Scope: token.Scope, ExpiresAt: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)}
	a.mu.Lock()
	err = a.save(c)
	a.mu.Unlock()
	if err != nil {
		finish("error")
		return
	}
	s.invalidateProfileAgents()
	if !c.planEnabled() {
		s.disableChatGPTActive()
		finish("no-plan")
		return
	}
	s.reapplyActiveProfile()
	finish("connected")
}

func (a *chatGPTAuth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, err := a.credentials()
	if err != nil || c.ClientID == "" || !c.planEnabled() {
		return "", errors.New("ChatGPT 플랜이 연결되지 않았습니다")
	}
	if c.AccessToken != "" && time.Until(c.ExpiresAt) > 2*time.Minute {
		return c.AccessToken, nil
	}
	if c.RefreshToken == "" {
		return "", errors.New("ChatGPT에 다시 로그인해 주세요")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "refresh_token": {c.RefreshToken}, "resource": {chatGPTAPIBase}}
	token, err := a.exchange(ctx, form)
	if err != nil || token.RefreshToken == "" {
		return "", errors.New("ChatGPT 토큰 갱신에 실패했습니다. 다시 로그인해 주세요")
	}
	if token.Scope == "" {
		token.Scope = c.Scope
	}
	c.AccessToken, c.RefreshToken, c.Scope = token.AccessToken, token.RefreshToken, token.Scope
	if token.IDToken != "" {
		c.IDToken = token.IDToken
	}
	c.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	if !c.planEnabled() {
		return "", errors.New("ChatGPT 플랜 사용 권한이 없습니다")
	}
	if err := a.save(c); err != nil {
		return "", errors.New("갱신된 ChatGPT 토큰을 저장할 수 없습니다")
	}
	return c.AccessToken, nil
}

func (s *Server) chatGPTStatus(w http.ResponseWriter, r *http.Request) {
	c, err := s.chatGPTAuth.credentials()
	if err != nil {
		writeErr(w, 503, "ChatGPT 연결 정보를 읽을 수 없습니다")
		return
	}
	writeJSON(w, 200, map[string]any{"connected": c.ClientID != "", "plan_enabled": c.planEnabled(), "email": c.Email})
}

func (s *Server) chatGPTDisconnect(w http.ResponseWriter, r *http.Request) {
	a := s.chatGPTAuth
	a.mu.Lock()
	defer a.mu.Unlock()
	c, err := a.credentials()
	if err != nil {
		writeErr(w, 503, "ChatGPT 연결 정보를 읽을 수 없습니다")
		return
	}
	remoteRevoked := c.RefreshToken == ""
	if c.RefreshToken != "" {
		form := url.Values{"token": {c.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {c.ClientID}}
		req, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, a.baseURL+"/api/accounts/oauth/revoke", strings.NewReader(form.Encode()))
		if reqErr == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, doErr := a.client.Do(req)
			if doErr == nil {
				remoteRevoked = resp.StatusCode == http.StatusOK
				resp.Body.Close()
			}
		}
	}
	if err := a.pg.SetSetting(chatGPTCredentialKey, ""); err != nil {
		writeErr(w, 503, "ChatGPT 연결을 지울 수 없습니다")
		return
	}
	s.disableChatGPTActive()
	s.invalidateProfileAgents()
	writeJSON(w, 200, map[string]any{"disconnected": true, "remote_revoked": remoteRevoked})
}

func (s *Server) disableChatGPTActive() {
	s.cfgMu.Lock()
	if s.llmCfg.ChatGPT {
		s.llmOn = false
		s.llmProv = nil
		s.llmDirect = nil
		s.chatAgent = nil
	}
	s.cfgMu.Unlock()
}

func (a *chatGPTAuth) models(ctx context.Context) ([]string, error) {
	token, err := a.Token(ctx)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, chatGPTAPIBase+"/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, errors.New("ChatGPT 모델 목록을 조회할 수 없습니다")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChatGPT 모델 목록 조회 실패 (HTTP %d)", resp.StatusCode)
	}
	var catalog struct {
		Models []struct {
			Slug       string `json:"slug"`
			Visibility string `json:"visibility"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&catalog); err != nil {
		return nil, errors.New("ChatGPT 모델 목록 응답을 읽을 수 없습니다")
	}
	models := make([]string, 0, len(catalog.Models))
	for _, model := range catalog.Models {
		if model.Slug != "" && model.Visibility == "list" {
			models = append(models, model.Slug)
		}
	}
	return models, nil
}

func (s *Server) chatGPTModels(w http.ResponseWriter, r *http.Request) {
	models, err := s.chatGPTAuth.models(r.Context())
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "models": models})
}

func (s *Server) chatGPTEnsureProfile(w http.ResponseWriter, r *http.Request) {
	s.chatGPTProfileMu.Lock()
	defer s.chatGPTProfileMu.Unlock()
	if !s.chatGPTAuth.available() {
		writeErr(w, 400, "ChatGPT 계정을 먼저 연결해 주세요")
		return
	}
	profiles, err := s.m.pg.ListProfiles()
	if err != nil {
		writeErr(w, 500, "모델 설정을 읽을 수 없습니다")
		return
	}
	usedNames := map[string]bool{}
	hasActive := false
	for _, p := range profiles {
		if p.Format == "chatgpt-oauth" {
			writeJSON(w, 200, map[string]any{"id": p.ID, "model": p.Model, "created": false})
			return
		}
		usedNames[p.Name] = true
		hasActive = hasActive || p.IsDefault
	}
	models, err := s.chatGPTAuth.models(r.Context())
	if err != nil || len(models) == 0 {
		writeErr(w, 502, "ChatGPT 계정의 모델 목록을 가져올 수 없습니다")
		return
	}
	model := models[0]
	for _, candidate := range models {
		if candidate == "gpt-6-sol" {
			model = candidate
			break
		}
	}
	name := "ChatGPT"
	if usedNames[name] {
		name = "ChatGPT OAuth"
	}
	for i := 2; usedNames[name]; i++ {
		name = fmt.Sprintf("ChatGPT OAuth %d", i)
	}
	id, err := s.m.pg.SaveProfile(&db.LLMProfile{Name: name, Format: "chatgpt-oauth", Model: model, Streaming: true, PoolExclude: true})
	if err != nil {
		writeErr(w, 500, "ChatGPT 모델 카드를 저장할 수 없습니다")
		return
	}
	if !hasActive {
		if err := s.m.pg.SetActiveProfile(id); err != nil {
			writeErr(w, 500, "ChatGPT 모델을 활성화할 수 없습니다")
			return
		}
	}
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	writeJSON(w, 200, map[string]any{"id": id, "model": model, "created": true})
}
