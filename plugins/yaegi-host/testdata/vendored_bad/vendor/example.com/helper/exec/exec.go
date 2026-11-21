// Package exec is a vendored helper that starts a process.
package exec

import "os/exec"

// Shout runs echo.
func Shout(s string) string {
	out, _ := exec.Command("echo", s).Output()
	return string(out)
}
