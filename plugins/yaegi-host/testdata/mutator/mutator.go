// Package mutator does what the protocol cannot carry, chosen by the `mode` config.
package mutator

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// Config is the plugin configuration.
type Config struct {
	Mode string `json:"mode"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config { return &Config{Mode: "none"} }

type mutator struct {
	next http.Handler
	mode string
}

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &mutator{next: next, mode: cfg.Mode}, nil
}

func (m *mutator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch m.mode {
	case "path":
		req.URL.Path = "/rewritten" + req.URL.Path
	case "query":
		req.URL.RawQuery = "rewritten=1"
	case "host":
		req.Host = "other.test"
	case "method":
		req.Method = http.MethodPut
	case "body-replace":
		req.Body = io.NopCloser(strings.NewReader("replaced"))
	case "body-read":
		_, _ = io.ReadAll(req.Body)
	case "header-host":
		req.Header.Set("Host", "other.test")
	case "header-framing":
		req.Header.Set("Content-Length", "5")
	case "multi-value":
		req.Header.Add("X-Multi", "a")
		req.Header.Add("X-Multi", "b")
	case "clone":
		// A plugin that forwards a modified clone is judged by the clone.
		clone := req.Clone(req.Context())
		clone.URL.Path = "/cloned"
		m.next.ServeHTTP(rw, clone)
		return
	case "wrap":
		// Wrapping the writer to change the response has no effect; the host says so once.
		m.next.ServeHTTP(&wrapped{rw}, req)
		return
	case "write-then-next":
		rw.WriteHeader(http.StatusTeapot)
	case "twice":
		m.next.ServeHTTP(rw, req)
	}
	m.next.ServeHTTP(rw, req)
}

type wrapped struct{ http.ResponseWriter }

func (w *wrapped) WriteHeader(status int) { w.ResponseWriter.WriteHeader(status + 1) }
