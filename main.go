package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// Build information.
var (
	GitCommit string
	Version   string
)

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Usage = "trapdoor"
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "Log level",
		},
	}
	app.HideHelp = true
	app.Commands = []*cli.Command{
		agentCommand,
		consoleCommand,
		proxyCommand,
	}
	app.Before = func(ctx *cli.Context) error {
		level, err := logrus.ParseLevel(ctx.String("log-level"))
		if err != nil {
			return errors.Errorf("unknown log level '%s'", ctx.String("log-level"))
		}
		logrus.SetLevel(level)
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func runServer(server *http.Server) error {
	errCh := make(chan error)
	go func() {
		logrus.WithField("addr", server.Addr).Info("Listening")
		errCh <- server.ListenAndServe()
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case s := <-signalCh:
		logrus.WithField("signal", s).Info("Received a shutdown signal")
		return server.Shutdown(context.Background())
	}
}

func newHealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.MarshalIndent(map[string]string{
			"gitCommit": GitCommit,
			"version":   Version,
		}, "", "  ")
		if err != nil {
			logrus.WithError(err).Error("error marshaling health check response to JSON")
		}
		if _, err := w.Write(body); err != nil {
			logrus.WithError(err).Error("error writing health check response")
		}
	})
}
