// Package strutil is a vendored helper.
package strutil

import "strings"

// Shout upper-cases s.
func Shout(s string) string { return strings.ToUpper(s) + "!" }
