package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
)

func Test_azureOAuth2AuthHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name         string
		oauth2Config *oauth2.Config
		handler      http.Handler
		req          *http.Request
		session      *Session
		wantStatus   int
	}{
		{
			name:       "no session",
			req:        httptest.NewRequest("GET", "/", nil),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "authenticated",
			handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			req:        httptest.NewRequest("GET", "/", nil),
			session:    &Session{Email: "foo@example.com"},
			wantStatus: http.StatusOK,
		},
		{
			name: "unauthenticated",
			oauth2Config: &oauth2.Config{
				ClientID:    "client ID",
				RedirectURL: "https://example.com/redirect",
				Scopes:      []string{"scope"},
			},
			req:        httptest.NewRequest("GET", "/foo", nil),
			session:    &Session{},
			wantStatus: http.StatusTemporaryRedirect,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := fakeSessionStore{}
			a := azureOAuth2Provider{config: tt.oauth2Config, sessionStore: &sessionStore}
			h := a.WithAuth(tt.handler)
			w := httptest.NewRecorder()
			ctx := context.Background()
			if tt.session != nil {
				ctx = NewContextWithSession(ctx, tt.session)
			}
			req := tt.req.WithContext(ctx)
			h.ServeHTTP(w, req)
			res := w.Result()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("expected status code %d, got %d", tt.wantStatus, w.Result().StatusCode)
			}
			if tt.wantStatus != http.StatusTemporaryRedirect {
				return
			}

			url, err := res.Location()
			if err != nil {
				t.Fatal(err)
			}
			query := url.Query()
			if query.Get("client_id") != tt.oauth2Config.ClientID {
				t.Errorf("expected client_id in the authorization request URI to be %q, got %q", tt.oauth2Config.ClientID, query.Get("client_id"))
			}
			if query.Get("response_type") != "code" {
				t.Errorf(`expected response_type in the authorization request URI to be "code", got %q`, query.Get("response_type"))
			}
			if query.Get("redirect_uri") != tt.oauth2Config.RedirectURL {
				t.Errorf("expected redirect_uri in the authorization request URI to be %q, got %q", tt.oauth2Config.RedirectURL, query.Get("redirect_uri"))
			}
			if query.Get("scope") != strings.Join(tt.oauth2Config.Scopes, " ") {
				t.Errorf("expected scope in the authorization request URI to be %q, got %q", strings.Join(tt.oauth2Config.Scopes, " "), query.Get("scope"))
			}
			if query.Get("state") == "" {
				t.Errorf("missing state parameter in the authorization request URI")
			}

			session := sessionStore.session
			if session.AzureOAuth2State != query.Get("state") {
				t.Errorf("expected state in the session to be %q, got %q", query.Get("state"), session.AzureOAuth2State)
			}
			if session.AzureOAuth2RedirectURL != tt.req.URL.String() {
				t.Errorf("expected redirect URL in the session to be %q, got %q", tt.req.URL.String(), session.AzureOAuth2RedirectURL)
			}
		})
	}
}

func Test_azureOAuth2CallbackHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name         string
		session      *Session
		req          *http.Request
		token        map[string]string
		claims       jwt.Claims
		wantStatus   int
		wantLocation string
		wantSession  Session
	}{
		{
			name:       "no session",
			req:        httptest.NewRequest("GET", "/", nil),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "no state in session",
			req:        httptest.NewRequest("GET", "/", nil),
			session:    &Session{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "states don't match",
			req:        httptest.NewRequest("GET", "/?state=foo", nil),
			session:    &Session{AzureOAuth2State: "bar"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no ID token",
			req:        httptest.NewRequest("GET", "/?state=foo", nil),
			session:    &Session{AzureOAuth2State: "foo"},
			token:      map[string]string{"access_token": "access token"},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "invalid ID token",
			req:        httptest.NewRequest("GET", "/?state=foo", nil),
			session:    &Session{AzureOAuth2State: "foo"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:    "no redirection URL in session",
			req:     httptest.NewRequest("GET", "/?state=foo", nil),
			session: &Session{AzureOAuth2State: "foo"},
			claims: jwt.MapClaims{
				"aud": "client ID",
				"exp": time.Now().Add(10 * time.Second).Unix(),
			},
			wantStatus:   http.StatusTemporaryRedirect,
			wantLocation: "/",
			wantSession:  Session{AzureOAuth2State: "foo"},
		},
		{
			name:    "redirection URL in session",
			req:     httptest.NewRequest("GET", "/?state=foo", nil),
			session: &Session{AzureOAuth2State: "foo", AzureOAuth2RedirectURL: "/foo"},
			claims: jwt.MapClaims{
				"aud":   "client ID",
				"exp":   time.Now().Add(10 * time.Second).Unix(),
				"email": "foo@example.com",
				"roles": []string{"role"},
			},
			wantStatus:   http.StatusTemporaryRedirect,
			wantLocation: "/foo",
			wantSession: Session{
				AzureOAuth2State:       "foo",
				AzureOAuth2RedirectURL: "/foo",
				Email:                  "foo@example.com",
				Roles:                  []string{"role"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := tt.token
				if token == nil {
					privateKey, err := rsa.GenerateKey(rand.Reader, 512)
					if err != nil {
						t.Fatal(err)
					}
					idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.claims).SignedString(privateKey)
					if err != nil {
						t.Fatal(err)
					}
					token = map[string]string{"access_token": "access token", "id_token": idToken}
				}
				j, err := json.Marshal(token)
				if err != nil {
					t.Fatal(err)
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write(j); err != nil {
					t.Fatal(err)
				}
			}))
			c := oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: s.URL}}
			sessionStore := fakeSessionStore{}
			a := azureOAuth2Provider{
				config:       &c,
				sessionStore: &sessionStore,
				verifier:     oidc.NewVerifier("", testKeySet{}, &oidc.Config{ClientID: "client ID"}),
			}
			h := a.NewCallbackHandler()
			w := httptest.NewRecorder()
			ctx := context.Background()
			if tt.session != nil {
				ctx = NewContextWithSession(context.Background(), tt.session)
			}
			req := tt.req.WithContext(ctx)
			h.ServeHTTP(w, req)
			res := w.Result()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("expected status code %d, got %d", tt.wantStatus, w.Result().StatusCode)
			}
			if tt.wantStatus != http.StatusTemporaryRedirect {
				return
			}

			url, err := res.Location()
			if err != nil {
				t.Fatal(err)
			}
			if url.String() != tt.wantLocation {
				t.Errorf("expected the Location header to be %q, got %q", tt.wantLocation, url.String())
			}

			if !reflect.DeepEqual(sessionStore.session, tt.wantSession) {
				t.Errorf("expected session to be %v, got %v", tt.wantSession, sessionStore.session)
			}
		})
	}
}

type testKeySet struct{}

func (testKeySet) VerifySignature(_ context.Context, token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	return jwt.DecodeSegment(parts[1])
}
