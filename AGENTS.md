Use README.md files to understand program intent and structure. This is a fork of
glauth/glauth that aims to contribute changes upstream, so keep changes to upstream
code minimal and in upstream's style, and keep fork-only changes (build system,
CI, container) separate from changes meant for upstream.

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
