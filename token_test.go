package main

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"
)

func TestClaimsFromToken(t *testing.T) {
	tests := []struct {
		name    string
		claims  *Claims
		aud     string
		want    *Claims
		wantErr bool
	}{
		{
			name:    "no exp claim",
			wantErr: true,
		},
		{
			name: "expired token",
			claims: &Claims{
				ExpiresAt: time.Now().Add(-1 * time.Minute).Unix(),
			},
			wantErr: true,
		},
		{
			name: "no iat claim",
			claims: &Claims{
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
			},
			wantErr: true,
		},
		{
			name: "invalid iat claim",
			claims: &Claims{
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
				IssuedAt:  time.Now().Add(1 * time.Minute).Unix(),
			},
			wantErr: true,
		},
		{
			name: "no aud claim",
			claims: &Claims{
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
				IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
			},
			wantErr: true,
		},
		{
			name: "mismatched audience",
			claims: &Claims{
				Audience:  "audience1",
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
				IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
			},
			aud:     "audience2",
			wantErr: true,
		},
		{
			name: "valid token",
			claims: &Claims{
				Audience:  "audience",
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
				IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
			},
			aud: "audience",
			want: &Claims{
				Audience:  "audience",
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
				IssuedAt:  time.Now().Add(-1 * time.Minute).Unix(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 512)
			if err != nil {
				t.Fatal(err)
			}
			token, err := tt.claims.Token(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ClaimsFromToken(token, &privateKey.PublicKey, tt.aud)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClaimsFromToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ClaimsFromToken() got = %v, want %v", got, tt.want)
			}
		})
	}
}
