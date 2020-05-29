package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFProtection_CSRFToken(t *testing.T) {
	tests := []struct {
		name      string
		session   *Session
		csrfToken []byte
		pad       []byte
		want      string
		wantErr   bool
	}{
		{
			name:    "no session",
			wantErr: true,
		},
		{
			name:      "no CSRF token",
			session:   &Session{},
			csrfToken: []byte{0xda, 0xa3, 0x1d, 0xe6, 0x5c, 0xb4, 0x4c, 0xf, 0x13, 0x4d, 0x6f, 0xcf, 0xb2, 0x8a, 0x0, 0xc9, 0xdd, 0x10, 0x83, 0x32, 0x5c, 0xf5, 0x3, 0x93, 0x4d, 0x14, 0x5d, 0x7e, 0xf8, 0x55, 0x62, 0x3c},
			pad:       []byte{0xf5, 0x29, 0xdc, 0x82, 0x4a, 0x8, 0xa0, 0xff, 0x6, 0x3c, 0x1c, 0xe8, 0x92, 0xfe, 0x65, 0xe3, 0x44, 0xc6, 0x8a, 0x9, 0x32, 0x97, 0x1b, 0xf3, 0x6f, 0xe3, 0x91, 0xe2, 0xff, 0x18, 0xed, 0x31},
			want:      "9SncgkoIoP8GPBzokv5l40TGigkylxvzb+OR4v8Y7TEvisFkFrzs8BVxcycgdGUqmdYJO25iGGAi98ycB02PDQ==",
		},
		{
			name:    "invalid CSRF token",
			session: &Session{CSRFToken: "invalid CSRF token"},
			wantErr: true,
		},
		{
			name:    "valid CSRF token",
			session: &Session{CSRFToken: "2qMd5ly0TA8TTW/PsooAyd0QgzJc9QOTTRRdfvhVYjw="},
			pad:     []byte{0xf5, 0x29, 0xdc, 0x82, 0x4a, 0x8, 0xa0, 0xff, 0x6, 0x3c, 0x1c, 0xe8, 0x92, 0xfe, 0x65, 0xe3, 0x44, 0xc6, 0x8a, 0x9, 0x32, 0x97, 0x1b, 0xf3, 0x6f, 0xe3, 0x91, 0xe2, 0xff, 0x18, 0xed, 0x31},
			want:    "9SncgkoIoP8GPBzokv5l40TGigkylxvzb+OR4v8Y7TEvisFkFrzs8BVxcycgdGUqmdYJO25iGGAi98ycB02PDQ==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionStore := fakeSessionStore{}
			p := NewCSRFProtection(&sessionStore)
			p.rand = bytes.NewReader(tt.csrfToken)
			p.randPad = bytes.NewReader(tt.pad)
			w := httptest.NewRecorder()
			r := &http.Request{}
			if tt.session != nil {
				r = r.WithContext(NewContextWithSession(context.Background(), tt.session))
			}
			got, err := p.CSRFToken(w, r)
			if (err != nil) != tt.wantErr {
				t.Errorf("CSRFToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CSRFToken() got = %v, want %v", got, tt.want)
				return
			}
			if tt.wantErr || tt.session.CSRFToken != "" {
				return
			}

			session := sessionStore.session
			if session.CSRFToken != base64.StdEncoding.EncodeToString(tt.csrfToken) {
				t.Errorf("expected %q in session, got %q", tt.csrfToken, session.CSRFToken)
			}
		})
	}
}

func TestCSRFProtectionHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.Handler
		r          *http.Request
		csrfToken  string
		session    *Session
		wantStatus int
	}{
		{
			name:       "GET request",
			handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			r:          httptest.NewRequest("GET", "/", nil),
			wantStatus: http.StatusOK,
		},
		{
			name:       "no CSRF token in header",
			r:          httptest.NewRequest("POST", "/", nil),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no session",
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "9SncgkoIoP8GPBzokv5l40TGigkylxvzb+OR4v8Y7TEvisFkFrzs8BVxcycgdGUqmdYJO25iGGAi98ycB02PDQ==",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "no CSRF token in session",
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "9SncgkoIoP8GPBzokv5l40TGigkylxvzb+OR4v8Y7TEvisFkFrzs8BVxcycgdGUqmdYJO25iGGAi98ycB02PDQ==",
			session:    &Session{},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "CSRF token in session is not base64 encoded",
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "9SncgkoIoP8GPBzokv5l40TGigkylxvzb+OR4v8Y7TEvisFkFrzs8BVxcycgdGUqmdYJO25iGGAi98ycB02PDQ==",
			session:    &Session{CSRFToken: "non base64 encoded"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "CSRF token in header is not base64 encoded",
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "non base64 encoded",
			session:    &Session{CSRFToken: "2qMd5ly0TA8TTW/PsooAyd0QgzJc9QOTTRRdfvhVYjw="},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "CSRF token in header has invalid length",
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "VeERHiEnZVpVJBHzs3369w==",
			session:    &Session{CSRFToken: "2qMd5ly0TA8TTW/PsooAyd0QgzJc9QOTTRRdfvhVYjw="},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "CSRF tokens don't match",
			handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "A3681JUfpCtDQT+EQjkpbEMKaHZJaZqPcENRU7lmR4pGWVuvCBgf42s/tRa4wjz4x8yfiiy63m1w+VWQLsvuRQ==",
			session:    &Session{CSRFToken: "2qMd5ly0TA8TTW/PsooAyd0QgzJc9QOTTRRdfvhVYjw="},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "valid CSRF token",
			handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			r:          httptest.NewRequest("POST", "/", nil),
			csrfToken:  "9SncgkoIoP8GPBzokv5l40TGigkylxvzb+OR4v8Y7TEvisFkFrzs8BVxcycgdGUqmdYJO25iGGAi98ycB02PDQ==",
			session:    &Session{CSRFToken: "2qMd5ly0TA8TTW/PsooAyd0QgzJc9QOTTRRdfvhVYjw="},
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewCSRFProtection(nil).Protect(tt.handler)
			w := httptest.NewRecorder()
			ctx := context.Background()
			if tt.session != nil {
				ctx = NewContextWithSession(context.Background(), tt.session)
			}
			r := tt.r.WithContext(ctx)
			if tt.csrfToken != "" {
				r.Header.Set(csrfTokenHTTPHeader, tt.csrfToken)
			}
			h.ServeHTTP(w, r)
			res := w.Result()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("expected status code %d, got %d", tt.wantStatus, w.Result().StatusCode)
			}
		})
	}
}
