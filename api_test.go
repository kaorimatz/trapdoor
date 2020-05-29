package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestNewAPIHandler_GetTargets(t *testing.T) {
	tests := []struct {
		name        string
		targets     targets
		session     *Session
		wantStatus  int
		wantTargets targets
	}{
		{
			name:       "no session",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unauthenticated",
			session:    &Session{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "accessible targets",
			targets: []*target{
				{Roles: []string{"role1"}},
				{Roles: []string{"role2", "role3"}},
				{Roles: []string{"role4"}},
			},
			session:    &Session{Email: "foo@example.com", Roles: []string{"role1", "role2"}},
			wantStatus: http.StatusOK,
			wantTargets: []*target{
				{Roles: []string{"role1"}},
				{Roles: []string{"role2", "role3"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAPIHandler(tt.targets, nil, nil)
			w := httptest.NewRecorder()
			ctx := context.Background()
			if tt.session != nil {
				ctx = NewContextWithSession(context.Background(), tt.session)
			}
			req := httptest.NewRequest("GET", "/targets", nil).WithContext(ctx)
			h.ServeHTTP(w, req)
			res := w.Result()

			if res.StatusCode != tt.wantStatus {
				t.Fatalf("expected status code %d, got %d", tt.wantStatus, w.Result().StatusCode)
			}
			if tt.wantStatus != http.StatusOK {
				return
			}

			contentType := res.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf(`expected "application/json", got %q`, contentType)
			}

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			var targets targets
			if err := json.Unmarshal(body, &targets); err != nil {
				t.Fatal(err)
			}
			if len(targets) != len(tt.wantTargets) {
				t.Fatalf("expected %d targets, got %d targets", len(tt.wantTargets), len(targets))
			}
			if reflect.DeepEqual(targets, tt.wantTargets) {
				t.Fatalf("expected %v, got %v", tt.wantTargets, targets)
			}
		})
	}
}

func TestNewAPIHandler_CreateToken(t *testing.T) {
	csrfTokenBytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(csrfTokenBytes); err != nil {
		t.Fatal(err)
	}
	csrfToken := base64.StdEncoding.EncodeToString(csrfTokenBytes)

	tests := []struct {
		name        string
		targets     targets
		session     *Session
		targetID    int
		targetIndex int
		wantStatus  int
	}{
		{
			name:       "no session",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unauthenticated",
			session:    &Session{CSRFToken: csrfToken},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "non-existent target",
			session: &Session{
				CSRFToken: csrfToken,
				Email:     "foo@example.com",
				Roles:     []string{"role"},
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:    "unauthorized",
			targets: []*target{{ID: 1, Roles: []string{"role1"}}},
			session: &Session{
				CSRFToken: csrfToken,
				Email:     "foo@example.com",
				Roles:     []string{"role2"},
			},
			targetID:   1,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "accessible target",
			targets: []*target{
				{
					ID:          1,
					Endpoint:    "wss://example.com/foo",
					Roles:       []string{"role1"},
					IdleTimeout: 1 * time.Second,
					SessionTTL:  2 * time.Second,
					TokenTTL:    10 * time.Second,
				},
			},
			session: &Session{
				CSRFToken: csrfToken,
				Email:     "foo@example.com",
				Roles:     []string{"role1"},
			},
			targetID:    1,
			targetIndex: 0,
			wantStatus:  http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 512)
			if err != nil {
				t.Fatal(err)
			}
			csrfProtection := NewCSRFProtection(nil)
			h := NewAPIHandler(tt.targets, privateKey, csrfProtection)
			w := httptest.NewRecorder()
			ctx := context.Background()
			if tt.session != nil {
				ctx = NewContextWithSession(context.Background(), tt.session)
			}
			req := httptest.NewRequest("POST", fmt.Sprintf("/targets/%d/tokens", tt.targetID), nil).WithContext(ctx)
			maskedCSRFTokenBytes, err := maskCSRFTokenBytes(rand.Reader, csrfTokenBytes)
			if err != nil {
				t.Fatal(err)
			}
			maskedCSRFToken := base64.StdEncoding.EncodeToString(maskedCSRFTokenBytes)
			req.Header.Set(csrfTokenHTTPHeader, maskedCSRFToken)
			h.ServeHTTP(w, req)
			res := w.Result()

			if res.StatusCode != tt.wantStatus {
				t.Fatalf("expected status code %d, got %d", tt.wantStatus, res.StatusCode)
			}
			if tt.wantStatus != http.StatusOK {
				return
			}

			body, err := ioutil.ReadAll(w.Result().Body)
			if err != nil {
				t.Fatal(err)
			}
			var jsonBody struct{ Token string }
			if err := json.Unmarshal(body, &jsonBody); err != nil {
				t.Fatal(err)
			}
			claims, err := ClaimsFromToken(jsonBody.Token, &privateKey.PublicKey, "proxy")
			if err != nil {
				t.Fatalf("error decoding token: %v", err)
			}
			if claims.Audience != "proxy" {
				t.Errorf(`expected "proxy", got %q`, claims.Audience)
			}
			if claims.Issuer != "console" {
				t.Errorf(`expected "console", got %q`, claims.Issuer)
			}
			if claims.User != tt.session.Email {
				t.Errorf("expected %q, got %q", tt.session.Email, claims.User)
			}
			target := tt.targets[tt.targetIndex]
			if claims.Endpoint != target.Endpoint {
				t.Errorf("expected %q, got %q", target.Endpoint, claims.Endpoint)
			}
			if claims.IdleTimeout != target.IdleTimeout {
				t.Errorf("expected %q, got %q", target.IdleTimeout, claims.IdleTimeout)
			}
			if claims.SessionTTL != target.SessionTTL {
				t.Errorf("expected %q, got %q", target.SessionTTL, claims.SessionTTL)
			}
		})
	}
}
