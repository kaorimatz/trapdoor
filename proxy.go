package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/dgrijalva/jwt-go"
	"github.com/fluent/fluent-logger-golang/fluent"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var proxyCommand = &cli.Command{
	Name:  "proxy",
	Usage: "start a proxy",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "fluentd-address",
			Usage:   "Address to connect to fluentd",
			EnvVars: []string{"TRAPDOOR_FLUENTD_ADDRESS"},
		},
		&cli.StringFlag{
			Name:    "fluentd-data-tag",
			Value:   "trapdoor.data",
			Usage:   "Tag for fluentd data message",
			EnvVars: []string{"TRAPDOOR_FLUENTD_DATA_TAG"},
		},
		&cli.StringFlag{
			Name:    "fluentd-event-tag",
			Value:   "trapdoor.event",
			Usage:   "Tag for fluentd event message",
			EnvVars: []string{"TRAPDOOR_FLUENTD_EVENT_TAG"},
		},
		&cli.StringFlag{
			Name:    "listen-address",
			Value:   ":3001",
			Usage:   "Listen address",
			EnvVars: []string{"TRAPDOOR_LISTEN_ADDRESS"},
		},
		&cli.StringFlag{
			Name:        "token-private-key",
			Usage:       "Private key for signing token",
			EnvVars:     []string{"TRAPDOOR_TOKEN_PRIVATE_KEY"},
			Required:    true,
			DefaultText: `""`,
		},
		&cli.StringFlag{
			Name:    "websocket-origin",
			Value:   "http://localhost:3000",
			Usage:   "Origin to accept WebSocket connections",
			EnvVars: []string{"TRAPDOOR_WEBSOCKET_ORIGIN"},
		},
	},
	Action: func(ctx *cli.Context) error {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(ctx.String("token-private-key")))
		if err != nil {
			return errors.Wrap(err, "error parsing private key")
		}

		fluentdAddress, err := parseFluentdAddress(ctx.String("fluentd-address"))
		if err != nil {
			return errors.Wrap(err, "fluentd-address is invalid")
		}
		recorder, err := newRecorder(fluentdAddress, ctx.String("fluentd-data-tag"), ctx.String("fluentd-event-tag"))
		if err != nil {
			return errors.Wrap(err, "failed to create recorder")
		}

		mux := http.NewServeMux()
		mux.Handle("/health", newHealthHandler())
		handler := newProxyHandler(privateKey, ctx.String("websocket-origin"), recorder)
		mux.Handle("/", handler)
		server := &http.Server{Addr: ctx.String("listen-address"), Handler: mux}
		return runServer(server)
	},
}

func parseFluentdAddress(address string) (*fluentdAddress, error) {
	if address == "" {
		return &fluentdAddress{}, nil
	}

	var network string
	if strings.HasPrefix(address, "tcp://") || strings.HasPrefix(address, "unix://") {
		u, err := url.Parse(address)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "unix" {
			return &fluentdAddress{network: u.Scheme, socketPath: u.Path}, nil
		}
		network = u.Scheme
		address = u.Host
	}

	host, portString, err := net.SplitHostPort(address)
	if err, ok := err.(*net.AddrError); ok && err.Err == "missing port in address" {
		return &fluentdAddress{network: network, host: address}, nil
	} else if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}

	return &fluentdAddress{network: network, host: host, port: port}, nil
}

type fluentdAddress struct {
	network    string
	host       string
	port       int
	socketPath string
}

func newRecorder(fluentdAddress *fluentdAddress, dataTag, eventTag string) (*recorder, error) {
	config := fluent.Config{
		FluentPort:       fluentdAddress.port,
		FluentHost:       fluentdAddress.host,
		FluentNetwork:    fluentdAddress.network,
		FluentSocketPath: fluentdAddress.socketPath,
		Async:            true,
	}
	f, err := fluent.New(config)
	if err != nil {
		return nil, err
	}

	return &recorder{
		fluent:   f,
		dataTag:  dataTag,
		eventTag: eventTag,
	}, nil
}

type recorder struct {
	dataTag, eventTag string
	fluent            *fluent.Fluent
}

func (r *recorder) recordData(sessionID, source string, data []byte) error {
	return r.fluent.Post(r.dataTag, map[string]interface{}{
		"data":       data,
		"session_id": sessionID,
		"source":     source,
	})
}

func (r *recorder) recordEvent(eventType string, fields map[string]interface{}) error {
	fields["type"] = eventType
	return r.fluent.Post(r.eventTag, fields)
}

func newProxyHandler(privateKey *rsa.PrivateKey, websocketOrigin string, recorder *recorder) *proxyHandler {
	var upgrader websocket.Upgrader
	if websocketOrigin != "" {
		upgrader = websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origins := r.Header["Origin"]
				return len(origins) == 0 || origins[0] == websocketOrigin
			},
		}
	}

	return &proxyHandler{
		privateKey: privateKey,
		recorder:   recorder,
		upgrader:   &upgrader,
	}
}

type proxyHandler struct {
	privateKey *rsa.PrivateKey
	recorder   *recorder
	upgrader   *websocket.Upgrader
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientConn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.WithError(err).WithField("url", r.URL.String()).Error("Error upgrading to WebSocket protocol")
		return
	}
	defer func() {
		if err := clientConn.Close(); err != nil {
			logrus.WithFields(logrus.Fields{
				"url":        r.URL.String(),
				"localAddr":  clientConn.LocalAddr(),
				"remoteAddr": clientConn.RemoteAddr(),
			}).Debug("Error closing connection")
		}
	}()
	logrus.WithFields(logrus.Fields{
		"url":        r.URL.String(),
		"localAddr":  clientConn.LocalAddr(),
		"remoteAddr": clientConn.RemoteAddr(),
	}).Debug("Upgraded to WebSocket protocol")

	_, clientToken, err := clientConn.ReadMessage()
	if err != nil {
		logrus.WithError(err).Error("Error receiving token")
		return
	} else if clientToken[0] != tokenMessage {
		logrus.Error("Received unexpected message")
		return
	}

	clientClaims, err := ClaimsFromToken(string(clientToken[1:]), &h.privateKey.PublicKey, "proxy")
	if err != nil {
		logrus.WithError(err).Error("Token is invalid")
		return
	}

	serverConn, _, err := websocket.DefaultDialer.DialContext(r.Context(), clientClaims.Endpoint, nil)
	if err != nil {
		logrus.WithError(err).Error("Error connecting to agent")
		return
	}
	defer func() {
		if err := serverConn.Close(); err != nil {
			logrus.WithFields(logrus.Fields{
				"url":        r.URL.String(),
				"localAddr":  serverConn.LocalAddr(),
				"remoteAddr": serverConn.RemoteAddr(),
			}).Debug("Error closing connection")
		}
	}()
	logrus.WithFields(logrus.Fields{
		"url":        clientClaims.Endpoint,
		"localAddr":  serverConn.LocalAddr(),
		"remoteAddr": serverConn.RemoteAddr(),
	}).Debug("Upgraded to WebSocket protocol")

	sessionID := uuid.New().String()

	fields := map[string]interface{}{
		"session_id":           sessionID,
		"endpoint":             clientClaims.Endpoint,
		"user":                 clientClaims.User,
		"idle_timeout_seconds": clientClaims.IdleTimeout.Seconds(),
		"session_ttl_seconds":  clientClaims.SessionTTL.Seconds(),
		"client_local_addr":    clientConn.LocalAddr().String(),
		"client_remote_addr":   clientConn.RemoteAddr().String(),
		"server_local_addr":    serverConn.LocalAddr().String(),
		"server_remote_addr":   serverConn.RemoteAddr().String(),
	}
	if err = h.recorder.recordEvent("session.start", fields); err != nil {
		logrus.WithError(err).Error("Error recording event")
		return
	}

	serverClaims := Claims{
		Audience:  "agent",
		ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
		IssuedAt:  time.Now().Unix(),
		Issuer:    "proxy",
	}
	serverToken, err := serverClaims.Token(h.privateKey)
	if err != nil {
		logrus.WithError(err).Error("Error creating token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if err := writeTokenMessage(serverConn, serverToken); err != nil {
		logrus.WithError(err).Error("Error sending token")
		return
	}

	proxy := newProxy(sessionID, clientConn, serverConn, time.Unix(clientClaims.ExpiresAt, 0), clientClaims.IdleTimeout, h.recorder, h.privateKey)

	timeout := clientClaims.SessionTTL
	if timeout == 0 {
		timeout = math.MaxInt64
	}
	ctx, cancelFunc := context.WithTimeout(r.Context(), timeout)
	defer cancelFunc()

	err = proxy.start(ctx)

	fields = map[string]interface{}{
		"session_id": sessionID,
		"endpoint":   clientClaims.Endpoint,
		"user":       clientClaims.User,
	}
	if err := h.recorder.recordEvent("session.end", fields); err != nil {
		logrus.WithError(err).Error("Error recording event")
		return
	}

	if err != nil {
		logrus.WithError(err).Error("Error while running proxy")
		return
	}

	logrus.WithFields(logrus.Fields{
		"url":        r.URL.String(),
		"localAddr":  clientConn.LocalAddr(),
		"remoteAddr": clientConn.RemoteAddr(),
	}).Debug("Closing connection")
	logrus.WithFields(logrus.Fields{
		"url":        r.URL.String(),
		"localAddr":  serverConn.LocalAddr(),
		"remoteAddr": serverConn.RemoteAddr(),
	}).Debug("Closing connection")
}

func writeTokenMessage(conn *websocket.Conn, token string) error {
	_, err := writeMessage(conn, websocket.TextMessage, append([]byte{tokenMessage}, token...))
	return errors.Wrap(err, "failed to send token message")
}

func newProxy(sessionID string, clientConn, serverConn *websocket.Conn, tokenExpiry time.Time, idleTimeout time.Duration, recorder *recorder, privateKey *rsa.PrivateKey) *proxy {
	if idleTimeout == 0 {
		idleTimeout = math.MaxInt64
	}

	return &proxy{
		clientConn:       clientConn,
		idleTimeout:      idleTimeout,
		logger:           logrus.WithField("component", "proxy"),
		privateKey:       privateKey,
		recorder:         recorder,
		serverConn:       serverConn,
		sessionID:        sessionID,
		tokenExpiry:      tokenExpiry,
		tokenExpiryTimer: time.NewTimer(tokenExpiry.Sub(time.Now())),
	}
}

type proxy struct {
	clientConn, serverConn  *websocket.Conn
	idleTimeout             time.Duration
	recorder                *recorder
	privateKey              *rsa.PrivateKey
	sessionID               string
	tokenExpiry             time.Time
	tokenExpiryTimer        *time.Timer
	tokenExpiryMessageTimer *time.Timer
	g                       errgroup.Group
	logger                  *logrus.Entry
	tokenExpiryMutex        sync.Mutex
}

func (p *proxy) start(ctx context.Context) error {
	go p.ping(ctx, p.clientConn)
	go p.ping(ctx, p.serverConn)

	p.notifyTokenExpiry(p.tokenExpiry)
	defer p.tokenExpiryMessageTimer.Stop()

	p.g.Go(func() error { return p.handleInput(ctx) })
	p.g.Go(func() error { return p.handleOutput() })

	return p.g.Wait()
}

func (p *proxy) ping(ctx context.Context, conn *websocket.Conn) {
	if err := ping(ctx, conn, pingInterval); err != nil {
		p.logger.WithError(err).WithField("remoteAddr", conn.RemoteAddr()).Warn("error pinging")
	}
}

func (p *proxy) notifyTokenExpiry(tokenExpiry time.Time) {
	if p.tokenExpiryMessageTimer != nil {
		p.tokenExpiryMessageTimer.Stop()
	}
	p.tokenExpiryMessageTimer = time.AfterFunc(tokenExpiry.Add(-1*time.Minute).Sub(time.Now()), func() {
		p.tokenExpiryMutex.Lock()
		defer p.tokenExpiryMutex.Unlock()
		if tokenExpiry != p.tokenExpiry {
			return
		}
		logrus.WithField("tokenExpiry", tokenExpiry).Debug("Writing token expiry message")
		if err := writeTokenExpiry(p.clientConn, tokenExpiry); err != nil {
			logrus.WithError(err).Warn("Error writing token expiry message")
		}
	})
}

func writeTokenExpiry(conn *websocket.Conn, tokenExpiry time.Time) error {
	_, err := writeMessage(conn, websocket.TextMessage, append([]byte{tokenExpiryMessage}, tokenExpiry.Format(time.RFC3339)...))
	return errors.Wrap(err, "failed to send token expiry message")
}

func (p *proxy) handleInput(ctx context.Context) error {
	readErr, err := func() (error, error) {
		idleTimer := time.NewTimer(p.idleTimeout)
		var buf bytes.Buffer
		for {
			if err := p.readTimeout(ctx, p.clientConn, &buf, idleTimer); err != nil {
				return errors.Wrapf(err, "failed to read message from %s", p.clientConn.RemoteAddr()), nil
			}
			data := buf.Bytes()
			buf.Reset()

			if err := p.handleInputMessage(data); err != nil {
				return nil, err
			}

			resetTimer(idleTimer, p.idleTimeout)
		}
	}()

	if readErr != nil {
		p.writeCloseMessage(p.serverConn, readErr)
		err = readErr
	}

	p.logger.WithError(err).Debug("Stopped handling input")

	if !isClosedConnError(err) && !isExpectedCloseError(err) {
		return err
	}
	return nil
}

func (p *proxy) handleInputMessage(data []byte) error {
	messageType, payload := data[0], data[1:]

	switch messageType {
	case inputMessage, resizeMessage:
		n, err := writeMessage(p.serverConn, websocket.TextMessage, data)
		if err != nil {
			return errors.Wrap(err, "failed to write input data to agent")
		}
		logrus.WithField("size", n).Debug("Wrote input data to agent")
	case tokenMessage:
		claims, err := ClaimsFromToken(string(payload), &p.privateKey.PublicKey, "proxy")
		if err != nil {
			return errors.Wrap(err, "token is invalid")
		}
		tokenExpiry := time.Unix(claims.ExpiresAt, 0)
		p.updateTokenExpiry(tokenExpiry)
		logrus.WithField("tokenExpiry", tokenExpiry).Debug("Updated token expiry")
	default:
		return errors.Errorf("unknown message type '%d'", messageType)
	}

	if err := p.recorder.recordData(p.sessionID, "client", data); err != nil {
		return errors.Wrap(err, "failed to record WebSocket data")
	}

	return nil
}

func (p *proxy) updateTokenExpiry(tokenExpiry time.Time) {
	p.tokenExpiryMutex.Lock()
	defer p.tokenExpiryMutex.Unlock()

	p.tokenExpiry = tokenExpiry
	p.notifyTokenExpiry(tokenExpiry)
	resetTimer(p.tokenExpiryTimer, tokenExpiry.Sub(time.Now()))
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		<-timer.C
	}
	timer.Reset(d)
}

func (p *proxy) writeCloseMessage(conn *websocket.Conn, err error) {
	closeCode, closeText := websocket.CloseGoingAway, ""
	if closeErr, ok := errors.Cause(err).(*websocket.CloseError); ok && isReceivedCloseError(closeErr) {
		closeCode, closeText = closeErr.Code, closeErr.Text
	}
	p.logger.WithField("remoteAddr", conn.RemoteAddr()).Debug("Writing close message")
	if e := writeCloseMessage(conn, closeCode, closeText); e != nil {
		p.logger.WithError(e).WithField("remoteAddr", conn.RemoteAddr()).Warn("Error writing close message")
	}
}

func (p *proxy) handleOutput() error {
	readErr, err := func() (error, error) {
		var buf bytes.Buffer
		for {
			err := p.read(p.serverConn, &buf)
			if err != nil {
				return errors.Wrapf(err, "failed to read message from %s", p.clientConn.RemoteAddr()), nil
			}
			data := buf.Bytes()
			buf.Reset()

			if err := p.handleOutputMessage(data); err != nil {
				return nil, err
			}
		}
	}()

	if readErr != nil {
		p.writeCloseMessage(p.clientConn, readErr)
		err = readErr
	}

	p.logger.WithError(err).Debug("Stopped handling output")

	if !isClosedConnError(err) && !isExpectedCloseError(err) {
		return err
	}
	return nil
}

func (p *proxy) handleOutputMessage(data []byte) error {
	messageType := data[0]

	switch messageType {
	case outputMessage, windowTitleMessage:
		n, err := writeMessage(p.clientConn, websocket.TextMessage, data)
		if err != nil {
			return errors.Wrap(err, "failed to write input data to client")
		}
		logrus.WithField("size", n).Debug("Wrote input data to client")
	default:
		return errors.Errorf("unknown message type '%d'", messageType)
	}

	if err := p.recorder.recordData(p.sessionID, "server", data); err != nil {
		return errors.Wrap(err, "failed to record WebSocket data")
	}

	return nil
}

func (p *proxy) readTimeout(ctx context.Context, conn *websocket.Conn, buf *bytes.Buffer, idleTimer *time.Timer) error {
	errCh := make(chan error)
	go func() { errCh <- p.read(conn, buf) }()

	var err error
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		err = ctx.Err()
	case <-idleTimer.C:
		err = errors.New("idle timeout exceeded")
	case <-p.tokenExpiryTimer.C:
		err = errors.New("token expired")
	}

	if e := writeCloseMessage(conn, websocket.CloseNormalClosure, ""); e != nil {
		p.logger.WithError(e).WithField("remoteAddr", conn.RemoteAddr()).Warn("Error writing close message")
	}
	return err
}

func (p *proxy) read(conn *websocket.Conn, buf *bytes.Buffer) error {
	_, r, err := conn.NextReader()
	if err != nil {
		return err
	}

	if _, err := buf.ReadFrom(r); err != nil {
		return err
	}
	return nil
}
