package main

import (
	"crypto/rsa"
	"crypto/subtle"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// Claims represents claims about the authorization of the access to the target.
type Claims struct {
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss"`

	Endpoint    string        `json:"endpoint,omitempty"`
	IdleTimeout time.Duration `json:"idleTimeout,omitempty"`
	SessionTTL  time.Duration `json:"sessionTTL,omitempty"`
	User        string        `json:"user,omitempty"`
}

// ClaimsFromToken verifies the given JWT and returns claims.
func ClaimsFromToken(token string, publicKey *rsa.PublicKey, aud string) (*Claims, error) {
	parser := jwt.Parser{ValidMethods: []string{"RS256"}}
	keyFunc := func(token *jwt.Token) (interface{}, error) { return publicKey, nil }
	var claims Claims
	if _, err := parser.ParseWithClaims(token, &claims, keyFunc); err != nil {
		return nil, errors.Wrap(err, "error parsing token")
	}
	if err := claims.verifyAudience(aud); err != nil {
		return nil, err
	}
	return &claims, nil
}

// Token returns a JWT that represents the claims.
func (c *Claims) Token(privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "error signing token")
	}
	return signedToken, nil
}

// Valid implements the jwt.Claims interface.
func (c *Claims) Valid() error {
	now := time.Now().Unix()
	if err := c.verifyExpiresAt(now); err != nil {
		return err
	} else if err := c.verifyIssuedAt(now); err != nil {
		return err
	}
	return nil
}

func (c *Claims) verifyAudience(aud string) error {
	if c.Audience == "" {
		return jwt.NewValidationError("aud is missing", jwt.ValidationErrorAudience)
	} else if subtle.ConstantTimeCompare([]byte(c.Audience), []byte(aud)) != 1 {
		return jwt.NewValidationError("aud is invalid", jwt.ValidationErrorAudience)
	}
	return nil
}

func (c *Claims) verifyExpiresAt(now int64) error {
	if c.ExpiresAt == 0 {
		return jwt.NewValidationError("exp is missing", jwt.ValidationErrorExpired)
	} else if c.ExpiresAt <= now {
		return jwt.NewValidationError("token has expired", jwt.ValidationErrorExpired)
	}
	return nil
}

func (c *Claims) verifyIssuedAt(now int64) error {
	if c.IssuedAt == 0 {
		return jwt.NewValidationError("iat is missing", jwt.ValidationErrorIssuedAt)
	} else if c.IssuedAt > now {
		return jwt.NewValidationError("iat is invalid", jwt.ValidationErrorIssuedAt)
	}
	return nil
}
