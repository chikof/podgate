// Package chaos panics or never returns when asked to, and is fine otherwise.
package chaos

import (
	"context"
	"net/http"
)

// Config is the plugin configuration.
type Config struct{}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config { return &Config{} }

type chaos struct{ next http.Handler }

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &chaos{next: next}, nil
}

func (c *chaos) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("X-Panic") != "" {
		panic("plugin went wrong on purpose")
	}
	if req.Header.Get("X-Loop") != "" {
		n := 0
		for {
			n++
		}
	}
	c.next.ServeHTTP(rw, req)
}
