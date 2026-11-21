// Package blocker answers requests that carry the configured header, without calling next.
package blocker

import (
	"context"
	"net/http"
)

// Config is the plugin configuration.
type Config struct {
	Header string `mapstructure:"header"`
	Status int    `mapstructure:"status"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{Header: "X-Block", Status: http.StatusForbidden}
}

type blocker struct {
	next http.Handler
	cfg  *Config
}

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &blocker{next: next, cfg: cfg}, nil
}

func (b *blocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get(b.cfg.Header) == "" {
		b.next.ServeHTTP(rw, req)
		return
	}
	rw.Header().Set("Content-Type", "text/plain")
	rw.Header().Set("X-Blocked-By", "blocker")
	rw.WriteHeader(b.cfg.Status)
	_, _ = rw.Write([]byte("blocked by plugin\n"))
}
