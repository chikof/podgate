// Command yaegi-host runs one Traefik middleware plugin, interpreted by Yaegi, as an
// out-of-process podgate plugin (docs/ref/plugin-yaegi.md). It serves the protocol of
// docs/ref/mw-plugin.md on a unix socket and is meant to be a managed plugin of PLUGINS_FILE:
//
//	yaegi-host --plugin /opt/plugins/headeradder --name headeradder
//
// The socket comes from --socket or PODGATE_PLUGIN_SOCKET, which podgate sets for a managed
// plugin.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("yaegi-host: ")
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	dir := flag.String("plugin", "", "directory of the vendored Traefik plugin: its sources and .traefik.yml")
	name := flag.String("name", os.Getenv("PODGATE_PLUGIN_NAME"), "the plugin's name for logs and Describe")
	socket := flag.String("socket", os.Getenv("PODGATE_PLUGIN_SOCKET"), "unix socket to serve on")
	flag.Parse()
	if *dir == "" || *socket == "" {
		return errors.New("usage: yaegi-host --plugin <dir> [--name <name>] [--socket <path>] (the socket defaults to $PODGATE_PLUGIN_SOCKET)")
	}
	if *name == "" {
		*name = "yaegi"
	}
	source, err := LoadSource(*dir)
	if err != nil {
		return fmt.Errorf("%s: %w", *dir, err)
	}
	host, err := NewHost(*name, source)
	if err != nil {
		return fmt.Errorf("%s: %w", *dir, err)
	}

	// A socket file left by a host that was killed would refuse the bind.
	if err := os.Remove(*socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Handler:           &grpcServer{host: host, name: *name},
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 1024},
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if server.Shutdown(ctx) != nil {
			_ = server.Close()
		}
	}()
	log.Printf("serving %s from %s on %s", *name, *dir, *socket)
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
