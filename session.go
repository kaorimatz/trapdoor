package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/sirupsen/logrus"
)

// Session represents a browser session.
type Session struct {
	AzureOAuth2State       string   `json:"azureOAuth2State"`
	AzureOAuth2RedirectURL string   `json:"azureOAuth2RedirectURL"`
	CSRFToken              string   `json:"csrfToken"`
	Email                  string   `json:"email"`
	Roles                  []string `json:"roles"`
}

// SessionStore is an interface for loading and storing session.
type SessionStore interface {
	// Load returns the session associated with the request.
	Load(r *http.Request) (*Session, error)
	// Save saves the session in the response.
	Save(w http.ResponseWriter, session *Session) error
}

type cookieSessionStore struct {
	maxAge       time.Duration
	secure       bool
	secureCookie *securecookie.SecureCookie
}

// NewCookieSessionStore returns a new cookie-based session store.
func NewCookieSessionStore(keyGenerator *KeyGenerator, maxAge time.Duration, secure bool) SessionStore {
	hashKey := keyGenerator.Generate("cookie signing key")
	blockKey := keyGenerator.Generate("cookie encryption key")
	secureCookie := securecookie.New(hashKey, blockKey)
	secureCookie.MaxAge(int(maxAge.Seconds()))
	secureCookie.SetSerializer(securecookie.JSONEncoder{})
	return &cookieSessionStore{maxAge: maxAge, secure: secure, secureCookie: secureCookie}
}

const sessionCookieName = "_trapdoor_session"

// Load implements the SessionStore interface.
func (s *cookieSessionStore) Load(r *http.Request) (*Session, error) {
	var session Session

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return &session, nil
	}

	err = s.secureCookie.Decode(sessionCookieName, cookie.Value, &session)
	if err, ok := err.(securecookie.Error); ok && err.IsDecode() {
		return &session, nil
	} else if err != nil {
		return nil, err
	}

	return &session, nil
}

// Save implements the SessionStore interface.
func (s *cookieSessionStore) Save(w http.ResponseWriter, session *Session) error {
	value, err := s.secureCookie.Encode(sessionCookieName, session)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.maxAge.Seconds()),
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if s.maxAge != 0 {
		cookie.Expires = time.Now().Add(s.maxAge)
	}
	http.SetCookie(w, cookie)
	return nil
}

// NewSessionHandler returns a request handler that sets the session in the
// request context.
func NewSessionHandler(sessionStore SessionStore, handler http.Handler) http.Handler {
	return &sessionHandler{
		handler:      handler,
		sessionStore: sessionStore,
	}
}

type sessionHandler struct {
	handler      http.Handler
	sessionStore SessionStore
}

type requestContextKey struct{}

// ServeHTTP implements the http.Handler interface.
func (h *sessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionStore.Load(r)
	if err != nil {
		logrus.WithError(err).Info("Error restoring session from cookie")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	ctx := NewContextWithSession(r.Context(), session)
	h.handler.ServeHTTP(w, r.WithContext(ctx))
}

// NewContextWithSession returns a new context with session.
func NewContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, requestContextKey{}, session)
}

// SessionFromRequest retrieves the session from the request.
func SessionFromRequest(r *http.Request) (*Session, bool) {
	session, ok := r.Context().Value(requestContextKey{}).(*Session)
	return session, ok
}
