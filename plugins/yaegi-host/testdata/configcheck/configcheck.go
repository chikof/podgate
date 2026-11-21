// Package configcheck copies every config field into a request header, so a test sees how the
// host decoded the snapshot's config into the struct.
package configcheck

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Inner is a nested struct.
type Inner struct {
	Depth int `json:"depth"`
	Label string
}

// Config is the plugin configuration. Fields are matched by tag or by name, ignoring case.
type Config struct {
	Name    string            `json:"name"`
	Count   int               `mapstructure:"count"`
	Enabled bool              `json:"enabled,omitempty"`
	Tags    []string          `json:"tags"`
	Labels  map[string]string `json:"labels"`
	Nested  Inner             `json:"nested"`
	Ptr     *Inner
	Secret  string `json:"-"`
	Plain   string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{Name: "default", Count: 1, Secret: "kept"}
}

type plugin struct {
	next http.Handler
	cfg  *Config
}

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return &plugin{next: next, cfg: cfg}, nil
}

func (p *plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	c := p.cfg
	ptr := "nil"
	if c.Ptr != nil {
		ptr = fmt.Sprintf("%d/%s", c.Ptr.Depth, c.Ptr.Label)
	}
	req.Header.Set("X-Cfg", fmt.Sprintf("name=%s count=%d enabled=%v tags=%s labels=%d nested=%d/%s ptr=%s secret=%s plain=%s",
		c.Name, c.Count, c.Enabled, strings.Join(c.Tags, "+"), len(c.Labels), c.Nested.Depth, c.Nested.Label, ptr, c.Secret, c.Plain))
	p.next.ServeHTTP(rw, req)
}
