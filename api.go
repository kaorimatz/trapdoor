package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
)

// NewAPIHandler returns a new request handler that serves the API endpoints.
func NewAPIHandler(targets targets, privateKey *rsa.PrivateKey, csrfProtection *CSRFProtection) http.Handler {
	router := httprouter.New()
	router.Handler("GET", "/targets", &targetsHandler{targets: targets})
	router.Handler("POST", "/targets/:targetID/tokens", &tokensHandler{privateKey: privateKey, targets: targets})
	return requireSignIn(csrfProtection.Protect(router))
}

type targetsHandler struct {
	targets targets
}

func (h *targetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, ok := SessionFromRequest(r)
	if !ok {
		logrus.Error("session doesn't exist")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	j, err := json.Marshal(h.targets.accessibleBy(session.Roles))
	if err != nil {
		logrus.WithError(err).Error("Error marshaling targets to JSON")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(j); err != nil {
		logrus.WithError(err).Error("Error writing response JSON")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

type tokensHandler struct {
	privateKey *rsa.PrivateKey
	targets    targets
}

func (h *tokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	params := httprouter.ParamsFromContext(r.Context())
	targetID := params.ByName("targetID")
	var target *target
	if id, err := strconv.Atoi(targetID); err != nil {
		logrus.WithError(err).WithField("targetID", targetID).Warn("target_id is invalid")
		http.Error(w, "target_id is invalid", http.StatusBadRequest)
		return
	} else if t := h.targets.findByID(id); t == nil {
		logrus.WithField("targetID", id).Warn("target not found")
		http.Error(w, "target not found", http.StatusNotFound)
		return
	} else {
		target = t
	}

	session, ok := SessionFromRequest(r)
	if !ok {
		logrus.Error("session doesn't exist")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if !target.isAccessibleBy(session.Roles) {
		logrus.WithField("target", target.Name).Warn("user doesn't have access")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	claims := Claims{
		Audience:    "proxy",
		ExpiresAt:   time.Now().Add(target.TokenTTL).Unix(),
		IssuedAt:    time.Now().Unix(),
		Issuer:      "console",
		User:        session.Email,
		Endpoint:    target.Endpoint,
		IdleTimeout: target.IdleTimeout,
		SessionTTL:  target.SessionTTL,
	}
	token, err := claims.Token(h.privateKey)
	if err != nil {
		logrus.WithError(err).Error("Error creating token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	j, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		logrus.WithError(err).Error("Error marshaling token to JSON")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(j); err != nil {
		logrus.WithError(err).Error("Error writing response JSON")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func requireSignIn(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFromRequest(r)
		if !ok {
			logrus.Error("session doesn't exist")
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		if session.Email == "" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(w, r)
	})
}
