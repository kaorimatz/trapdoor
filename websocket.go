package main

import (
	"context"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	pingInterval = 10 * time.Second
	writeTimeout = 10 * time.Second
)

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(errors.Cause(err).Error(), "use of closed network connection")
}

func isExpectedCloseError(err error) bool {
	return websocket.IsCloseError(
		errors.Cause(err),
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
	)
}

func isReceivedCloseError(err error) bool {
	return websocket.IsUnexpectedCloseError(
		errors.Cause(err),
		websocket.CloseNoStatusReceived,
		websocket.CloseAbnormalClosure,
		websocket.CloseTLSHandshake,
	)
}

func writeCloseMessage(conn *websocket.Conn, code int, text string) error {
	data := websocket.FormatCloseMessage(code, text)
	deadline := time.Now().Add(writeTimeout)
	err := conn.WriteControl(websocket.CloseMessage, data, deadline)
	if err != nil && err != websocket.ErrCloseSent {
		return errors.Wrapf(err, "failed to write close message to %s", conn.RemoteAddr())
	}
	return nil
}

func writeMessage(conn *websocket.Conn, messageType int, data []byte) (n int, err error) {
	w, err := conn.NextWriter(messageType)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create writer")
	}
	defer func() {
		if e := w.Close(); err != nil {
			err = errors.Wrap(e, "error closing writer")
		}
	}()

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return 0, errors.Wrap(err, "error setting write deadline")
	}
	return w.Write(data)
}

func ping(ctx context.Context, conn *websocket.Conn, interval time.Duration) error {
	readTimeout := interval * 10 / 9
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return errors.Wrap(err, "error setting read deadline")
	}
	conn.SetPongHandler(func(string) error {
		err := conn.SetReadDeadline(time.Now().Add(readTimeout))
		return errors.Wrap(err, "error setting read deadline")
	})
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			deadline := time.Now().Add(writeTimeout)
			if err := conn.WriteControl(websocket.PingMessage, []byte{}, deadline); err != nil {
				logrus.WithError(err).WithField("remoteAddr", conn.RemoteAddr()).Warn("Error writing ping message")
			}
		case <-ctx.Done():
			return nil
		}
	}
}
