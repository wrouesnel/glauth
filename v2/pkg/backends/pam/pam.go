//go:build pam && cgo

package pam

import (
	"errors"

	"github.com/msteinert/pam"

	"github.com/glauth/glauth/v2/pkg/backends"
	"github.com/glauth/glauth/v2/pkg/backends/unix"
	"github.com/glauth/glauth/v2/pkg/handler"
)

func init() {
	backends.Register("pam", NewPamHandler)
}

// NewPamHandler creates a new instance of the pam backend.
func NewPamHandler(opts ...handler.Option) handler.Handler {
	return unix.New(authenticatePAM, opts...)
}

// authenticatePAM checks a password with the "glauth" PAM service, falling
// back to "other" as PAM does when there is no such service.
//
// Only root, or a member of the shadow group, can check passwords other than
// its own with pam_unix.
func authenticatePAM(userName, _ string, password string) error {
	if password == "" {
		return errors.New("empty password")
	}
	t, err := pam.StartFunc("glauth", userName, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return password, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("unrecognized PAM message style")
	})
	if err != nil {
		return err
	}
	if err := t.Authenticate(0); err != nil {
		return err
	}
	return t.AcctMgmt(0)
}
