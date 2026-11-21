// Package forbidden_cgo uses cgo, which the host refuses.
package forbidden_cgo

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"net/http"
)

// Config is the plugin configuration.
type Config struct{}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config { return &Config{} }

// New creates the plugin.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	_ = C.rand()
	return next, nil
}
