package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

var agentCommand = &cli.Command{
	Name:      "agent",
	Usage:     "start an agent",
	ArgsUsage: "COMMAND ARG...",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "listen-address",
			Value:   ":3002",
			Usage:   "Listen address",
			EnvVars: []string{"TRAPDOOR_LISTEN_ADDRESS"},
		},
		&cli.IntFlag{
			Name:    "stop-signal",
			Value:   int(syscall.SIGTERM),
			Usage:   "Signal to stop command",
			EnvVars: []string{"TRAPDOOR_STOP_SIGNAL"},
		},
		&cli.DurationFlag{
			Name:    "stop-timeout",
			Value:   10 * time.Second,
			Usage:   "Timeout to stop command",
			EnvVars: []string{"TRAPDOOR_STOP_TIMEOUT"},
		},
		&cli.StringFlag{
			Name:     "token-public-key",
			Usage:    "Public key for verifying token",
			EnvVars:  []string{"TRAPDOOR_TOKEN_PUBLIC_KEY"},
			Required: true,
		},
		&cli.StringFlag{
			Name:    "window-title",
			Usage:   "Window title",
			EnvVars: []string{"TRAPDOOR_WINDOW_TITLE"},
		},
	},
	Action: func(ctx *cli.Context) error {
		if ctx.NArg() == 0 {
			return errors.New("command is required")
		}

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(ctx.String("token-public-key")))
		if err != nil {
			return errors.Wrap(err, "error parsing public key")
		}

		command, args := ctx.Args().First(), ctx.Args().Tail()
		config := agentConfig{
			args:        args,
			command:     command,
			publicKey:   publicKey,
			stopSignal:  syscall.Signal(ctx.Int("stop-signal")),
			stopTimeout: ctx.Duration("stop-timeout"),
			windowTitle: ctx.String("window-title"),
		}

		mux := http.NewServeMux()
		mux.Handle("/health", newHealthHandler())
		handler := newAgentHandler(&config)
		mux.Handle("/", handler)
		server := &http.Server{Addr: ctx.String("listen-address"), Handler: mux}
		return runServer(server)
	},
}

type agentConfig struct {
	args        []string
	command     string
	publicKey   *rsa.PublicKey
	stopSignal  syscall.Signal
	stopTimeout time.Duration
	windowTitle string
}

func newAgentHandler(config *agentConfig) *agentHandler {
	return &agentHandler{
		config:   config,
		upgrader: &websocket.Upgrader{},
	}
}

type agentHandler struct {
	config   *agentConfig
	upgrader *websocket.Upgrader
}

func (h *agentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.WithError(err).WithField("url", r.URL.String()).Error("Error upgrading to WebSocket protocol")
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logrus.WithFields(logrus.Fields{
				"url":        r.URL.String(),
				"localAddr":  conn.LocalAddr(),
				"remoteAddr": conn.RemoteAddr(),
			}).Debug("Error closing connection")
		}
	}()
	logrus.WithFields(logrus.Fields{
		"url":        r.URL.String(),
		"localAddr":  conn.LocalAddr(),
		"remoteAddr": conn.RemoteAddr(),
	}).Debug("Upgraded to WebSocket protocol")

	_, token, err := conn.ReadMessage()
	if err != nil {
		logrus.WithError(err).Error("Error reading token")
		return
	} else if token[0] != tokenMessage {
		logrus.Error("Received unexpected message")
		return
	}

	if _, err := ClaimsFromToken(string(token[1:]), h.config.publicKey, "agent"); err != nil {
		logrus.WithError(err).Error("Token is invalid")
		return
	}

	agent := newAgent(conn, h.config)
	if err := agent.start(r.Context()); err != nil {
		logrus.WithError(err).Error("Error while running agent")
		return
	}

	logrus.WithFields(logrus.Fields{
		"url":        r.URL.String(),
		"localAddr":  conn.LocalAddr(),
		"remoteAddr": conn.RemoteAddr(),
	}).Debug("Closing connection")
}

func newAgent(conn *websocket.Conn, config *agentConfig) *agent {
	logger := logrus.WithFields(logrus.Fields{
		"component":  "agent",
		"remoteAddr": conn.RemoteAddr(),
	})
	return &agent{
		config:    config,
		conn:      conn,
		doneCh:    make(chan struct{}, 3),
		inputBuf:  make([]byte, 32*1024),
		logger:    logger,
		outputBuf: make([]byte, 32*1024),
	}
}

const (
	inputMessage  = 1
	resizeMessage = 2
	tokenMessage  = 3

	outputMessage      = 1
	windowTitleMessage = 2
	tokenExpiryMessage = 3
)

type agent struct {
	config    *agentConfig
	conn      *websocket.Conn
	doneCh    chan struct{}
	g         errgroup.Group
	inputBuf  []byte
	logger    *logrus.Entry
	outputBuf []byte
}

func (a *agent) start(ctx context.Context) (err error) {
	ctx, cancelFunc := context.WithCancel(ctx)

	go a.ping(ctx, a.conn)

	cmd := exec.CommandContext(ctx, a.config.command, a.config.args...)
	p, err := pty.Start(cmd)
	if err != nil {
		return errors.Wrap(err, "failed to start command")
	}
	defer func() {
		if e := p.Close(); err == nil {
			err = errors.Wrap(e, "error closing pty")
		}
	}()

	if err := a.writeWindowTitle(a.config.windowTitle); err != nil {
		return errors.Wrap(err, "failed to set window title")
	}

	a.g.Go(func() error { return a.waitCommand(cmd) })
	a.g.Go(func() error { return a.handleInput(p) })
	a.g.Go(func() error { return a.handleOutput(p) })

	<-a.doneCh

	if cmd.ProcessState == nil {
		if err := cmd.Process.Signal(a.config.stopSignal); err != nil {
			a.logger.WithError(err).WithField("stopSignal", a.config.stopSignal).Warn("Error sending stop signal to command")
		}
	}

	waitCh := make(chan error)
	go func() { waitCh <- a.g.Wait() }()

	timer := time.NewTimer(a.config.stopTimeout)
	select {
	case <-timer.C:
		a.logger.Info("Stop timeout is exceeded. Killing command...")
		cancelFunc()
		return nil
	case err := <-waitCh:
		timer.Stop()
		return err
	}
}

func (a *agent) ping(ctx context.Context, conn *websocket.Conn) {
	if err := ping(ctx, conn, pingInterval); err != nil {
		a.logger.WithError(err).WithField("remoteAddr", conn.RemoteAddr()).Warn("error pinging")
	}
}

func (a *agent) writeWindowTitle(windowTitle string) error {
	_, err := writeMessage(a.conn, websocket.TextMessage, append([]byte{windowTitleMessage}, windowTitle...))
	return errors.Wrap(err, "error sending window title message")
}

func (a *agent) waitCommand(cmd *exec.Cmd) error {
	defer a.done()

	err := cmd.Wait()
	a.logger.WithError(err).Debug("Command exited")

	a.logger.Debug("Writing close message")
	if e := writeCloseMessage(a.conn, websocket.CloseNormalClosure, ""); e != nil {
		a.logger.WithError(e).Warn("Error writing close message")
	}

	return err
}

func (a *agent) done() {
	a.doneCh <- struct{}{}
}

func (a *agent) handleInput(pty *os.File) error {
	defer a.done()

	err := func() error {
		for {
			_, r, err := a.conn.NextReader()
			if err != nil {
				return errors.Wrap(err, "failed to read message")
			}

			if err := a.handleInputMessage(pty, r); err != nil {
				return err
			}
		}
	}()

	a.logger.WithError(err).Debug("Stopped handling input")

	if isClosedConnError(err) || isExpectedCloseError(err) {
		return nil
	}
	return err
}

func (a *agent) handleInputMessage(pty *os.File, r io.Reader) error {
	if _, err := r.Read(a.inputBuf[:1]); err != nil {
		return errors.Wrap(err, "failed to read message type")
	}
	messageType := a.inputBuf[0]

	switch messageType {
	case inputMessage:
		n, err := io.CopyBuffer(pty, r, a.inputBuf)
		if err != nil {
			return errors.Wrap(err, "failed to copy input data to command")
		}
		logrus.WithField("size", n).Debug("Wrote input data to command")
	case resizeMessage:
		var args []uint16
		if err := json.NewDecoder(r).Decode(&args); err != nil {
			return errors.Wrap(err, "failed to parse resize message")
		}
		if len(args) != 2 {
			return errors.Errorf("wrong number of arguments for resize message: %d", len(args))
		}

		rows, cols := args[0], args[1]
		if err := a.resizePty(pty, rows, cols); err != nil {
			return err
		}
		logrus.WithField("rows", rows).WithField("cols", cols).Debug("Resized PTY")
	default:
		return errors.Errorf("unknown message type '%d'", messageType)
	}

	return nil
}

func (a *agent) resizePty(p *os.File, rows uint16, cols uint16) error {
	err := pty.Setsize(p, &pty.Winsize{Rows: rows, Cols: cols})
	return errors.Wrap(err, "failed to resize pty")
}

func (a *agent) handleOutput(pty *os.File) error {
	defer a.done()

	err := func() error {
		for {
			n, err := pty.Read(a.outputBuf)
			if err != nil {
				return errors.Wrap(err, "failed to read command output")
			}

			if err := a.writeOutputMessage(a.outputBuf[:n]); err != nil {
				return err
			}
			logrus.WithField("size", n).Debug("Wrote output data to WebSocket connection")
		}
	}()

	a.logger.WithError(err).Debug("Stopped handling command output")

	if errors.Cause(err) == io.EOF {
		return nil
	}
	return err
}

func (a *agent) writeOutputMessage(data []byte) error {
	data = []byte(base64.StdEncoding.EncodeToString(data))
	_, err := writeMessage(a.conn, websocket.TextMessage, append([]byte{outputMessage}, data...))
	return errors.Wrap(err, "error sending output message")
}
