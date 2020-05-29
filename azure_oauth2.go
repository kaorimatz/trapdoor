package main

import (
	"context"
	"encoding/base64"
	"math/rand"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// NewAzureOAuth2Provider returns a new OAuth 2.0 provider that provides
// authentication via OpenID Connect with Azure AD.
func NewAzureOAuth2Provider(clientID, clientSecret, redirectURL, tenantID string, sessionStore SessionStore) (*azureOAuth2Provider, error) {
	provider, err := oidc.NewProvider(context.Background(), "https://login.microsoftonline.com/"+tenantID+"/v2.0")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create OpenID Connect provider's configuration")
	}

	return &azureOAuth2Provider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "email"},
			Endpoint:     provider.Endpoint(),
		},
		sessionStore: sessionStore,
		verifier:     provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

type azureOAuth2Provider struct {
	config       *oauth2.Config
	sessionStore SessionStore
	verifier     *oidc.IDTokenVerifier
}

// WithAuth implements the OAuth2Provider interface.
func (a *azureOAuth2Provider) WithAuth(handler http.Handler) http.Handler {
	return &azureOAuth2AuthHandler{
		config:       a.config,
		handler:      handler,
		sessionStore: a.sessionStore,
	}
}

type azureOAuth2AuthHandler struct {
	config       *oauth2.Config
	handler      http.Handler
	sessionStore SessionStore
}

// ServeHTTP implements the http.Handler interface.
func (h *azureOAuth2AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, ok := SessionFromRequest(r)
	if !ok {
		logrus.Error("session doesn't exist")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if session.Email != "" {
		h.handler.ServeHTTP(w, r)
		return
	}

	state, err := generateState()
	if err != nil {
		logrus.WithError(err).Error("Error generating state")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	session.AzureOAuth2State = state
	session.AzureOAuth2RedirectURL = r.URL.String()

	if err := h.sessionStore.Save(w, session); err != nil {
		logrus.WithError(err).Error("Error saving session to cookie")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	url := h.config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func generateState() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// NewCallbackHandler implements the OAuth2Provider interface.
func (a *azureOAuth2Provider) NewCallbackHandler() http.Handler {
	return &azureOAuth2CallbackHandler{
		config:       a.config,
		sessionStore: a.sessionStore,
		verifier:     a.verifier,
	}
}

type azureOAuth2CallbackHandler struct {
	config       *oauth2.Config
	sessionStore SessionStore
	verifier     *oidc.IDTokenVerifier
}

// ServeHTTP implements the http.Handler interface.
func (h *azureOAuth2CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, ok := SessionFromRequest(r)
	if !ok {
		logrus.Error("session doesn't exist")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	state, code := r.FormValue("state"), r.FormValue("code")
	if session.AzureOAuth2State == "" {
		logrus.Warn("State doesn't exist in session")
		http.Error(w, "", http.StatusBadRequest)
		return
	} else if session.AzureOAuth2State != state {
		logrus.Warn("State parameter doesn't match")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	token, err := h.config.Exchange(r.Context(), code)
	if err != nil {
		logrus.WithError(err).Error("Error exchanging authorization code and token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	idTokenString, ok := token.Extra("id_token").(string)
	if !ok {
		logrus.Error("Token doesn't include ID token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	idToken, err := h.verifier.Verify(r.Context(), idTokenString)
	if err != nil {
		logrus.WithError(err).Warn("Invalid ID token")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	var claims struct {
		Roles []string `json:"roles"`
		Email string   `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		logrus.WithError(err).Error("Error unmarshalling ID token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	session.Email = claims.Email
	session.Roles = claims.Roles
	if err := h.sessionStore.Save(w, session); err != nil {
		logrus.WithError(err).Error("Error saving session to cookie")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	url := session.AzureOAuth2RedirectURL
	if url == "" {
		url = "/"
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
