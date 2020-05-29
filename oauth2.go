package main

import "net/http"

// OAuth2Provider represents OAuth 2.0 provider.
type OAuth2Provider interface {
	// WithAuth returns a request handler that initiates the OAuth 2.0 authorization
	// code flow if a user is not signed in.
	WithAuth(handler http.Handler) http.Handler
	// NewCallbackHandler returns a callback handler for the OAuth 2.0 authorization
	// code flow.
	NewCallbackHandler() http.Handler
}
