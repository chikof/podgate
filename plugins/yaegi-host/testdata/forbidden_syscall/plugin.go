// Package forbidden_syscall imports syscall, which the host refuses.
package forbidden_syscall

import (
	"context"
	"net/http"

	_ "syscall"
)

// Config is the plugin configuration.
type Config struct{}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config { return &Config{} }

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return next, nil
}
