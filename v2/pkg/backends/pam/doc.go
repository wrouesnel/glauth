// Package pam serves the host's Unix account files like the unix backend, but
// checks passwords with PAM. It needs cgo and libpam, so it is only built with
// the "pam" build tag.
package pam
