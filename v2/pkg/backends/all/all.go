// Package all imports every backend that builds without cgo, registering it
// with the backends package.
package all

import (
	_ "github.com/glauth/glauth/v2/pkg/backends/mysql"
	_ "github.com/glauth/glauth/v2/pkg/backends/postgres"
	_ "github.com/glauth/glauth/v2/pkg/backends/sqlite"
	_ "github.com/glauth/glauth/v2/pkg/backends/unix"
)
