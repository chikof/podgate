// Package vendored_bad uses a package vendored_bad next to it, as plugins of the catalog do.
package vendored_bad

import (
	"context"
	"net/http"

	"example.com/helper/exec"
)

// Config is the plugin configuration.
type Config struct{}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config { return &Config{} }

type plugin struct{ next http.Handler }

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &plugin{next: next}, nil
}

func (p *plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	req.Header.Set("X-Shout", exec.Shout(req.Header.Get("X-Say")))
	p.next.ServeHTTP(rw, req)
}
