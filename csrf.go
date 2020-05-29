package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const csrfTokenHTTPHeader = "X-CSRF-Token"
const csrfTokenLength = 32

// NewCSRFProtection returns a new CSRFProtection.
func NewCSRFProtection(sessionStore SessionStore) *CSRFProtection {
	return &CSRFProtection{sessionStore: sessionStore, rand: rand.Reader, randPad: rand.Reader}
}

// CSRFProtection
type CSRFProtection struct {
	sessionStore SessionStore
	rand         io.Reader
	randPad      io.Reader
}

// Protect returns a request handler that protects the given handler from CSRF
// attacks by verifying a token sent in the X-CSRF-Token header with a token in
// the session. GET requests and HEAD requests are not protected.
func (p *CSRFProtection) Protect(handler http.Handler) http.Handler {
	return &csrfProtectionHandler{handler: handler}
}

// CSRFToken returns a token that can be sent in the X-CSRF-Token header in
// requests to be verified with the token stored in the session.
func (p *CSRFProtection) CSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	session, ok := SessionFromRequest(r)
	if !ok {
		return "", errors.New("session doesn't exist")
	}

	var tokenBytes []byte
	var err error
	if session.CSRFToken != "" {
		tokenBytes, err = base64.StdEncoding.DecodeString(session.CSRFToken)
	}
	if session.CSRFToken == "" || err != nil {
		tokenBytes = make([]byte, csrfTokenLength)
		if _, err = p.rand.Read(tokenBytes); err != nil {
			return "", err
		}

		session.CSRFToken = base64.StdEncoding.EncodeToString(tokenBytes)
		if err := p.sessionStore.Save(w, session); err != nil {
			return "", err
		}
	}

	maskedTokenBytes, err := maskCSRFTokenBytes(p.randPad, tokenBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(maskedTokenBytes), nil
}

type csrfProtectionHandler struct {
	handler http.Handler
}

// ServeHTTP implements the http.Handler interface.
func (h *csrfProtectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		h.handler.ServeHTTP(w, r)
		return
	}

	token := r.Header.Get(csrfTokenHTTPHeader)
	if token == "" {
		logrus.Warn("CSRF token is missing")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	session, ok := SessionFromRequest(r)
	if !ok {
		logrus.Error("session doesn't exist")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if session.CSRFToken == "" {
		logrus.Warn("Session doesn't contain CSRF token")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	if err := validateCSRFToken(token, session.CSRFToken); err != nil {
		logrus.WithError(err).Warn("Error validating CSRF token")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	h.handler.ServeHTTP(w, r)
}

func maskCSRFTokenBytes(rand io.Reader, tokenBytes []byte) ([]byte, error) {
	maskedTokenBytes := make([]byte, 2*csrfTokenLength)
	if _, err := rand.Read(maskedTokenBytes[:csrfTokenLength]); err != nil {
		return nil, err
	}
	xorBytes(maskedTokenBytes[csrfTokenLength:], maskedTokenBytes[:csrfTokenLength], tokenBytes)
	return maskedTokenBytes, nil
}

func xorBytes(dst, a, b []byte) {
	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
}

func validateCSRFToken(maskedToken, realToken string) error {
	maskedTokenBytes, err := base64.StdEncoding.DecodeString(maskedToken)
	if err != nil {
		return err
	}

	tokenBytes, err := unmaskCSRFTokenBytes(maskedTokenBytes)
	if err != nil {
		return err
	}

	realTokenBytes, err := base64.StdEncoding.DecodeString(realToken)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(tokenBytes, realTokenBytes) != 1 {
		return errors.New("token doesn't match")
	}
	return nil
}

func unmaskCSRFTokenBytes(maskedTokenBytes []byte) ([]byte, error) {
	if len(maskedTokenBytes) != csrfTokenLength*2 {
		return nil, errors.New("token length is invalid")
	}
	tokenBytes := make([]byte, csrfTokenLength)
	xorBytes(tokenBytes, maskedTokenBytes[:csrfTokenLength], maskedTokenBytes[csrfTokenLength:])
	return tokenBytes, nil
}
