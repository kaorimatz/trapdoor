package main

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type fakeSessionStore struct {
	session Session
}

func (s *fakeSessionStore) Load(_ *http.Request) (*Session, error) {
	return &s.session, nil
}

func (s *fakeSessionStore) Save(_ http.ResponseWriter, session *Session) error {
	s.session = *session
	return nil
}

func Test_sessionHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.Handler
		r           *http.Request
		cookie      *http.Cookie
		wantStatus  int
		wantSession Session
	}{
		{
			name: "no cookie",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				session, ok := SessionFromRequest(r)
				if !ok {
					t.Fatal("request doesn't have session")
				}
				if !reflect.DeepEqual(session, &Session{}) {
					t.Errorf("expected session to be empty, got %+v", session)
				}
			}),
			r:          httptest.NewRequest("", "/", nil),
			wantStatus: http.StatusOK,
		},
		{
			name: "invalid cookie",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				session, ok := SessionFromRequest(r)
				if !ok {
					t.Fatal("request doesn't have session")
				}
				if !reflect.DeepEqual(session, &Session{}) {
					t.Errorf("expected session to be empty, got %+v", session)
				}
			}),
			r:          httptest.NewRequest("", "/", nil),
			cookie:     &http.Cookie{Name: sessionCookieName, Value: "invalid"},
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyGenerator, err := NewKeyGenerator(hex.EncodeToString([]byte("secret key base")))
			if err != nil {
				t.Fatal(err)
			}
			sessionStore := NewCookieSessionStore(keyGenerator, 1*time.Second, false)
			h := NewSessionHandler(sessionStore, tt.handler)
			w := httptest.NewRecorder()
			if tt.cookie != nil {
				tt.r.AddCookie(tt.cookie)
			}
			h.ServeHTTP(w, tt.r)
			res := w.Result()
			if res.StatusCode != tt.wantStatus {
				t.Errorf("expected status code %d, got %d", tt.wantStatus, res.StatusCode)
			}
		})
	}
}
