// Package headeradder adds one request header, as Traefik's plugin catalog examples do.
package headeradder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
)

// Config is the plugin configuration.
type Config struct {
	Header string `json:"header,omitempty"`
	Value  string `json:"value,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{Header: "X-Example", Value: "default"}
}

type adder struct {
	next   http.Handler
	cfg    *Config
	name   string
	nonce  string
	served int
}

// New creates the plugin. Its nonce tells instances apart: every instance has its own.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if cfg.Header == "" {
		return nil, fmt.Errorf("header cannot be empty")
	}
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return &adder{next: next, cfg: cfg, name: name, nonce: hex.EncodeToString(raw)}, nil
}

func (a *adder) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	a.served++
	req.Header.Set(a.cfg.Header, a.cfg.Value)
	req.Header.Set("X-Instance", a.nonce)
	req.Header.Set("X-Served", fmt.Sprint(a.served))
	rw.Header().Set("X-Plugin-Name", a.name)
	a.next.ServeHTTP(rw, req)
}
