Use README.md files to understand program intent and structure. This is a fork
inspired by glauth/glauth, developed as its own software: changes aren't meant to go
back upstream. Upstream changes can still be merged in when they're useful, so prefer
changes that don't needlessly rewrite upstream code.

The Go module is in `v2/` (module `github.com/glauth/glauth/v2`). The repository
root holds a separate module for the build system (`magefile.go`), joined by
`go.work`.

Build without CGO. Only the `pam` backend needs cgo, behind the `pam` build tag.

Backends live in `v2/pkg/backends/<name>`, register themselves by datastore name
from `init()`, and are imported by `v2/pkg/backends/all`.

## Build commands

Run all build commands from the repository root. `go run mage.go -l` lists every target.

* `go run mage.go binary` - build for the current platform into `bin/` and symlink it
  as `./glauth`. Set `GO_BUILD_TAGS=pam` to include the PAM backend (needs cgo and libpam).
* `go run mage.go test` - build the binary and run the tests, including the integration
  tests in `v2/glauth_test.go`, which need `ldapsearch`.
* `go run mage.go lint` - run golangci-lint (configured by `.golangci.yml`).
* `go run mage.go style` - check formatting. `go run mage.go fmt` fixes it.

`lint` and `style` only report problems in code changed since the upstream commit in
`lintBaseRev` in `magefile.go`, so upstream's existing lint debt doesn't fail CI. Move
it forward when merging upstream.

CI runs `style`, `lint`, `test` and `binary`, all of which must pass.

## Releases and versions

Releases are tagged `wrouesnel-v<semver>`, e.g. `wrouesnel-v2.6.0`; pushing such a tag
builds release archives and a container image. Upstream's `GLAuth-v*` tags are ignored.
The version stamped into binaries is the semver with `+wrouesnel` appended as build
metadata, e.g. `v2.6.0+wrouesnel`, or `v2.6.0-3-gabc1234+wrouesnel` between releases.
