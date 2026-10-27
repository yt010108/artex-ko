package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type oauthSettings struct {
	mu     sync.Mutex
	values map[string]string
}

func (s *oauthSettings) GetSetting(k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[k]
	return v, ok, nil
}
func (s *oauthSettings) SetSetting(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[k] = v
	return nil
}
func (s *oauthSettings) InsertSettingIfAbsent(k, v string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.values[k]; ok {
		return false, nil
	}
	s.values[k] = v
	return true, nil
}

func TestChatGPTStartUsesPKCEAndLoopback(t *testing.T) {
	a := newChatGPTAuth(&oauthSettings{values: map[string]string{}})
	s := &Server{chatGPTAuth: a}
	req := httptest.NewRequest(http.MethodPost, "/api/llm/chatgpt/start", strings.NewReader(`{"return_to":"http://127.0.0.1:3000"}`))
	req.Host = "localhost:18787"
	w := httptest.NewRecorder()
	s.chatGPTStart(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		URL string `json:"authorize_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != "dynamic_agent_client" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != "http://127.0.0.1:18787"+chatGPTCallbackPath || q.Get("ext_agent_host_id") == "" || q.Get("agent_name_hint") != "ARTEX" {
		t.Fatalf("invalid authorization parameters: %v", q)
	}
	if _, ok := a.pending[q.Get("state")]; !ok {
		t.Fatal("state not retained")
	}
	if a.pending[q.Get("state")].ReturnTo != "http://127.0.0.1:3000/system/llm" {
		t.Fatal("return URL not retained")
	}
	bad := httptest.NewRequest(http.MethodPost, "/api/llm/chatgpt/start", nil)
	bad.Host = "public.example:8787"
	w = httptest.NewRecorder()
	s.chatGPTStart(w, bad)
	if w.Code != 400 {
		t.Fatalf("remote host accepted: %d", w.Code)
	}
}

func TestChatGPTRefreshRotatesToken(t *testing.T) {
	settings := &oauthSettings{values: map[string]string{}}
	a := newChatGPTAuth(settings)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/accounts/oauth/token" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("client_id") != "issued-id" || r.Form.Get("refresh_token") != "old-refresh" || r.Form.Get("scope") != "" {
			t.Errorf("refresh request = %v", r.Form)
		}
		_ = json.NewEncoder(w).Encode(chatGPTTokenResponse{AccessToken: "new-access", RefreshToken: "new-refresh", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer srv.Close()
	a.baseURL = srv.URL
	if err := a.save(chatGPTCredentials{ClientID: "issued-id", AccessToken: "old-access", RefreshToken: "old-refresh", Scope: chatGPTScope, ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	token, err := a.Token(context.Background())
	if err != nil || token != "new-access" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	c, err := a.credentials()
	if err != nil || c.RefreshToken != "new-refresh" || !c.planEnabled() {
		t.Fatalf("replacement not saved: %v", err)
	}
}

func TestChatGPTIDTokenValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kid": "test-key", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	issuer = srv.URL
	a := newChatGPTAuth(&oauthSettings{values: map[string]string{}})
	a.baseURL = issuer
	claims := chatGPTIDClaims{Nonce: "expected", RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "account", Audience: jwt.ClaimStrings{"issued-id"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	id := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	id.Header["kid"] = "test-key"
	raw, err := id.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.validateIDToken(context.Background(), raw, "issued-id", "expected")
	if err != nil || got.Subject != "account" {
		t.Fatalf("valid ID token rejected: %v", err)
	}
	if _, err := a.validateIDToken(context.Background(), raw, "issued-id", "different"); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}
