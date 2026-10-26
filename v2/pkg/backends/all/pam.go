//go:build pam && cgo

package all

import (
	_ "github.com/glauth/glauth/v2/pkg/backends/pam"
)
