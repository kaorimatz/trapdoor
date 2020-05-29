package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/shurcooL/httpfs/html/vfstemplate"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var consoleCommand = &cli.Command{
	Name:  "console",
	Usage: "start a console",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "assets-base-url",
			Usage:   "Base URL to be used for assets",
			EnvVars: []string{"TRAPDOOR_ASSETS_BASE_URL"},
		},
		&cli.StringFlag{
			Name:    "azure-tenant-id",
			Usage:   "Azure tenant ID",
			EnvVars: []string{"TRAPDOOR_AZURE_TENANT_ID"},
		},
		&cli.StringFlag{
			Name:    "base-url",
			Value:   "http://localhost:3000",
			Usage:   "Base URL",
			EnvVars: []string{"TRAPDOOR_BASE_URL"},
		},
		&cli.DurationFlag{
			Name:    "cookie-max-age",
			Value:   1 * time.Hour,
			Usage:   "Maximum lifetime of cookie",
			EnvVars: []string{"TRAPDOOR_COOKIE_MAX_AGE"},
		},
		&cli.StringFlag{
			Name:        "cookie-secret",
			Usage:       "Secret for encrypting and signing cookie",
			EnvVars:     []string{"TRAPDOOR_COOKIE_SECRET"},
			Required:    true,
			DefaultText: `""`,
		},
		&cli.DurationFlag{
			Name:    "idle-timeout",
			Value:   10 * time.Minute,
			Usage:   "Timeout to close idle connection",
			EnvVars: []string{"TRAPDOOR_IDLE_TIMEOUT"},
		},
		&cli.StringFlag{
			Name:    "listen-address",
			Value:   ":3000",
			Usage:   "Listen address",
			EnvVars: []string{"TRAPDOOR_LISTEN_ADDRESS"},
		},
		&cli.StringFlag{
			Name:     "oauth2-provider",
			Usage:    "OAuth 2.0 provider",
			Required: true,
			EnvVars:  []string{"TRAPDOOR_OAUTH2_PROVIDER"},
		},
		&cli.StringFlag{
			Name:     "oauth2-client-id",
			Usage:    "OAuth 2.0 client ID",
			Required: true,
			EnvVars:  []string{"TRAPDOOR_OAUTH2_CLIENT_ID"},
		},
		&cli.StringFlag{
			Name:        "oauth2-client-secret",
			Usage:       "OAuth 2.0 client secret",
			EnvVars:     []string{"TRAPDOOR_OAUTH2_CLIENT_SECRET"},
			Required:    true,
			DefaultText: `""`,
		},
		&cli.StringFlag{
			Name:    "proxy-endpoint",
			Value:   "ws://127.0.0.1:3001",
			Usage:   "Proxy URL",
			EnvVars: []string{"TRAPDOOR_PROXY_ENDPOINT"},
		},
		&cli.DurationFlag{
			Name:    "session-ttl",
			Value:   1 * time.Hour,
			Usage:   "TTL for session",
			EnvVars: []string{"TRAPDOOR_SESSION_TTL"},
		},
		&cli.StringFlag{
			Name:        "token-private-key",
			Usage:       "Private key for signing token",
			EnvVars:     []string{"TRAPDOOR_TOKEN_PRIVATE_KEY"},
			Required:    true,
			DefaultText: `""`,
		},
		&cli.DurationFlag{
			Name:    "token-ttl",
			Value:   1 * time.Hour,
			Usage:   "TTL for token",
			EnvVars: []string{"TRAPDOOR_TOKEN_TTL"},
		},
		&cli.StringFlag{
			Name:    "targets-file",
			Value:   "targets.yml",
			Usage:   "Load targets from YAML file",
			EnvVars: []string{"TRAPDOOR_TARGETS_FILE"},
		},
	},
	Action: func(ctx *cli.Context) error {
		baseURL, err := url.Parse(ctx.String("base-url"))
		if err != nil {
			return errors.Wrap(err, "base-url is invalid")
		}

		keyGenerator, err := NewKeyGenerator(ctx.String("cookie-secret"))
		if err != nil {
			return errors.Wrap(err, "error creating key generator")
		}

		sessionStore := NewCookieSessionStore(keyGenerator, ctx.Duration("cookie-max-age"), baseURL.Scheme == "https")

		csrfProtection := NewCSRFProtection(sessionStore)

		var oauth2Provider OAuth2Provider
		provider := ctx.String("oauth2-provider")
		if provider == "azure" {
			tenantID := ctx.String("azure-tenant-id")
			if tenantID == "" {
				return errors.New("azure-tenant-id is required when OAuth 2.0 provider is 'azure'")
			}

			redirectURL, _ := url.Parse(baseURL.String())
			redirectURL.Path = path.Join(redirectURL.Path, "/oauth2/callback")

			oauth2Provider, err = NewAzureOAuth2Provider(
				ctx.String("oauth2-client-id"),
				ctx.String("oauth2-client-secret"),
				redirectURL.String(),
				tenantID,
				sessionStore,
			)
			if err != nil {
				return errors.Wrap(err, "failed to setup OAuth 2.0")
			}
		} else {
			return errors.Errorf("unknown OAuth 2.0 provider %q", provider)
		}

		proxyEndpoint, err := url.Parse(ctx.String("proxy-endpoint"))
		if err != nil {
			return errors.Wrap(err, "proxy-endpoint is invalid")
		}

		targetsFile := ctx.String("targets-file")
		var targets targets
		if f, err := os.Open(targetsFile); err != nil {
			return errors.Wrap(err, "failed to open targets file")
		} else if err := yaml.NewDecoder(f).Decode(&targets); err != nil {
			return errors.Wrap(err, "failed to read targets file")
		}
		for _, t := range targets {
			if t.Proxy.Endpoint == "" {
				t.Proxy.Endpoint = proxyEndpoint.String()
			}
			if t.IdleTimeout == 0 {
				t.IdleTimeout = ctx.Duration("idle-timeout")
			}
			if t.SessionTTL == 0 {
				t.SessionTTL = ctx.Duration("session-ttl")
			}
			if t.TokenTTL == 0 {
				t.TokenTTL = ctx.Duration("token-ttl")
			}
			tokensURL, _ := url.Parse(baseURL.String())
			tokensURL.Path = path.Join(tokensURL.Path, fmt.Sprintf("/api/targets/%d/tokens", t.ID))
			t.TokensURL = tokensURL.String()
		}

		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(ctx.String("token-private-key")))
		if err != nil {
			return errors.Wrap(err, "error parsing private key")
		}

		assetsBaseURL, err := url.Parse(ctx.String("assets-base-url"))
		if err != nil {
			return errors.Wrap(err, "assets-base-url is invalid")
		}
		indexHandler := indexHandler{
			assetsBaseURL:  assetsBaseURL,
			csrfProtection: csrfProtection,
		}

		mux := http.NewServeMux()
		mux.Handle("/api/", http.StripPrefix("/api", NewSessionHandler(sessionStore, NewAPIHandler(targets, privateKey, csrfProtection))))
		mux.Handle("/oauth2/callback", NewSessionHandler(sessionStore, oauth2Provider.NewCallbackHandler()))
		mux.Handle("/health", newHealthHandler())
		mux.Handle("/js/", http.FileServer(Assets))
		mux.Handle("/", NewSessionHandler(sessionStore, oauth2Provider.WithAuth(&indexHandler)))
		server := &http.Server{Addr: ctx.String("listen-address"), Handler: mux}
		return runServer(server)
	},
}

type indexHandler struct {
	assetsBaseURL  *url.URL
	csrfProtection *CSRFProtection
}

func (h *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl, err := vfstemplate.ParseFiles(Assets, nil, "index.html.tmpl")
	if err != nil {
		logrus.WithError(err).Info("Error parsing index.html.tmpl")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	csrfToken, err := h.csrfProtection.CSRFToken(w, r)
	if err != nil {
		logrus.WithError(err).Info("Error obtaining CSRF token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")

	data := map[string]string{
		"assetsBaseURL": h.assetsBaseURL.String(),
		"assetsVersion": GitCommit,
		"csrfToken":     csrfToken,
	}
	if err := tmpl.Execute(w, data); err != nil {
		logrus.WithError(err).Info("Error executing template")
	}
}
