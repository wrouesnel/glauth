//go:build mage

// Self-contained go-project magefile.

//nolint:deadcode,gochecknoglobals,gochecknoinits,wrapcheck,varnamelen,gomnd,forcetypeassert,forbidigo,funlen,gocognit,cyclop,nolintlint
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	archiver "github.com/mholt/archiver"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	"github.com/integralist/go-findroot/find"
	"github.com/pkg/errors"

	"github.com/samber/lo"
	"golang.org/x/mod/modfile"
)

var (
	errAutogenMultipleScriptSections       = errors.New("found multiple managed script sections")
	errAutogenUnknownPreCommitScriptFormat = errors.New("unknown pre-commit script format")
	errPlatformNotSupported                = errors.New("current platform is not supported")
	errParallelBuildFailed                 = errors.New("parallel build failed")
	errLintBisect                          = errors.New("error during lint bisect")
)

var curDir = func() string {
	name, _ := os.Getwd()
	return name
}()

//nolint:revive,stylecheck
const (
	OS_READ        = 04
	OS_WRITE       = 02
	OS_EX          = 01
	OS_USER_SHIFT  = 6
	OS_GROUP_SHIFT = 3
	OS_OTH_SHIFT   = 0

	OS_USER_R   = OS_READ << OS_USER_SHIFT
	OS_USER_W   = OS_WRITE << OS_USER_SHIFT
	OS_USER_X   = OS_EX << OS_USER_SHIFT
	OS_USER_RW  = OS_USER_R | OS_USER_W
	OS_USER_RWX = OS_USER_RW | OS_USER_X

	OS_GROUP_R   = OS_READ << OS_GROUP_SHIFT
	OS_GROUP_W   = OS_WRITE << OS_GROUP_SHIFT
	OS_GROUP_X   = OS_EX << OS_GROUP_SHIFT
	OS_GROUP_RW  = OS_GROUP_R | OS_GROUP_W
	OS_GROUP_RWX = OS_GROUP_RW | OS_GROUP_X

	OS_OTH_R   = OS_READ << OS_OTH_SHIFT
	OS_OTH_W   = OS_WRITE << OS_OTH_SHIFT
	OS_OTH_X   = OS_EX << OS_OTH_SHIFT
	OS_OTH_RW  = OS_OTH_R | OS_OTH_W
	OS_OTH_RWX = OS_OTH_RW | OS_OTH_X

	OS_ALL_R   = OS_USER_R | OS_GROUP_R | OS_OTH_R
	OS_ALL_W   = OS_USER_W | OS_GROUP_W | OS_OTH_W
	OS_ALL_X   = OS_USER_X | OS_GROUP_X | OS_OTH_X
	OS_ALL_RW  = OS_ALL_R | OS_ALL_W
	OS_ALL_RWX = OS_ALL_RW | OS_ALL_X
)

const (
	constCoverageDir = ".coverage"
	constToolBinDir  = ".bin"
	constGitHookDir  = "githooks"
	constBinDir      = "bin"
	constReleaseDir  = "release"
	constCoverFile   = ".cover.out"
	constJunitDir    = ".junit"
	constModuleDir   = "v2"
)

const (
	constManagedScriptSectionHead = "## ++ BUILD SYSTEM MANAGED - DO NOT EDIT ++ ##"
	constManagedScriptSectionFoot = "## -- BUILD SYSTEM MANAGED - DO NOT EDIT -- ##"
)

// normalizePath turns a path into an absolute path and removes symlinks.
func normalizePath(name string) string {
	absPath := must(filepath.Abs(name))
	return absPath
}

// binRootName is set to the name of the directory by default.
var binRootName = func() string {
	repo, err := find.Repo()
	if err != nil {
		// Couldn't find a repo. Look for mage.go instead which should be at
		// the root of the source tree.
		currentDir := must(filepath.Abs(must(os.Getwd())))
		for {
			if _, err := os.Stat(filepath.Join(currentDir, "mage.go")); os.IsNotExist(err) {
				currentDir = filepath.Dir(currentDir)
			} else {
				return currentDir
			}
			if strings.HasSuffix(currentDir, strconv.QuoteRune(os.PathSeparator)) {
				panic("Could not locate repo root nor mage.go")
			}
		}
	}
	return repo.Path
}()

// dockerImageName is set to the name of the directory by default.
//
//nolint:unused,varcheck
var dockerImageName = func() string {
	return binRootName
}()

var coverageDir = normalizePath(path.Join(curDir, constCoverageDir))
var toolsBinDir = normalizePath(path.Join(curDir, constToolBinDir))
var gitHookDir = normalizePath(path.Join(curDir, constGitHookDir))
var binDir = normalizePath(path.Join(curDir, constBinDir))
var releaseDir = normalizePath(path.Join(curDir, constReleaseDir))
// moduleDir holds the glauth Go module. Go commands for the module run there.
var moduleDir = normalizePath(path.Join(curDir, constModuleDir))

// moduleBinDir is where the upstream Makefile builds to.
var moduleBinDir = path.Join(moduleDir, "bin")
var junitDir = normalizePath(path.Join(curDir, constJunitDir))

var outputDirs = []string{binDir, releaseDir, coverageDir, junitDir}

//nolint:unused,varcheck
var containerName = func() string {
	if name := os.Getenv("CONTAINER_NAME"); name != "" {
		return name
	}
	return dockerImageName
}()

type Platform struct {
	OS        string
	Arch      string
	BinSuffix string
}

func (p *Platform) String() string {
	return fmt.Sprintf("%s-%s", p.OS, p.Arch)
}

func (p *Platform) PlatformDir() string {
	platformDir := path.Join(binDir, p.ArchiveDir())
	return platformDir
}

func (p *Platform) PlatformBin(cmd string) string {
	platformBin := fmt.Sprintf("%s%s", cmd, p.BinSuffix)
	return path.Join(p.PlatformDir(), platformBin)
}

// buildVariant names builds with extra GO_BUILD_TAGS, e.g. "_pam", so they don't
// overwrite or masquerade as the default build.
func buildVariant() string {
	if goBuildTags == "" {
		return ""
	}
	return "_" + strings.ReplaceAll(goBuildTags, ",", "-")
}

func (p *Platform) ArchiveDir() string {
	return fmt.Sprintf("%s_%s_%s%s", productName, versionShort, p.String(), buildVariant())
}

func (p *Platform) ReleaseBase() string {
	return path.Join(releaseDir, p.ArchiveDir())
}

// platforms is the list of platforms we build for.
var platforms []Platform = []Platform{
	{"linux", "arm", ""},
	{"linux", "arm64", ""},
	{"linux", "amd64", ""},
	{"linux", "386", ""},
	{"linux", "riscv64", ""},
	{"darwin", "amd64", ""},
	{"darwin", "arm64", ""},
	{"windows", "amd64", ".exe"},
	{"windows", "386", ".exe"},
	{"freebsd", "amd64", ""},
}

// platformsLookup is the lookup map of the above list by <OS>/<Arch>.
var platformsLookup map[string]Platform = func() map[string]Platform {
	ret := make(map[string]Platform, len(platforms))
	for _, platform := range platforms {
		ret[platform.String()] = platform
	}
	return ret
}()

// productName names release archives. It can be overridden by PRODUCT_NAME.
var productName = func() string {
	if name := os.Getenv("PRODUCT_NAME"); name != "" {
		return name
	}
	return "glauth"
}()

// Source files.
var goSrc []string
var goDirs []string

// Due to go:generate and asset embedding interaction, this is now an on demand function
var goPkgs func() []string

// goCmds maps each binary to its package, relative to moduleDir.
var goCmds = map[string]string{
	"glauth": ".",
}

// goBuildTags are extra build tags from GO_BUILD_TAGS, e.g. "pam" for the cgo PAM
// backend.
var goBuildTags = os.Getenv("GO_BUILD_TAGS")

// cgoEnabled is "1" only when a build tag needs cgo: the default build is cgo-free.
var cgoEnabled = func() string {
	for _, tag := range strings.Split(goBuildTags, ",") {
		if strings.TrimSpace(tag) == "pam" {
			return "1"
		}
	}
	return "0"
}()

// goCmd runs go in moduleDir with the given extra environment.
func goCmd(env map[string]string, args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if mg.Verbose() {
		fmt.Println("exec: go", strings.Join(args, " "))
	}
	return cmd.Run()
}

// runIn runs a command in moduleDir.
func runIn(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = moduleDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Function to calculate the version symbol
var versionSymbol = func() string {
	gomodPath := path.Join(moduleDir, "go.mod")
	gomodBytes := lo.Must(os.ReadFile(gomodPath))
	parsedGoMod := lo.Must(modfile.ParseLax(gomodPath, gomodBytes, nil))
	return parsedGoMod.Module.Mod.Path + "/internal/version.Version"
}

// gitOutput runs git and returns its trimmed stdout, or "" on failure. Unlike sh.Output
// it discards stderr, since a repository without tags is a normal state for git describe.
func gitOutput(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// versionTagPrefix is the prefix of upstream GLAuth's release tags, e.g.
// GLAuth-v2.5.4. It is stripped from versions. The fork's own releases are tagged
// v*, and git describe picks whichever release tag is nearest.
const versionTagPrefix = "GLAuth-"

// describeVersion runs git describe over release tags and strips versionTagPrefix.
func describeVersion(args ...string) string {
	args = append([]string{"describe", "--tags", "--match", versionTagPrefix + "v*", "--match", "v*"}, args...)
	return strings.TrimPrefix(gitOutput(args...), versionTagPrefix)
}

var version = func() string {
	if v := os.Getenv("VERSION"); v != "" {
		return v
	}
	out := describeVersion("--dirty")

	if out == "" {
		// Try and at least describe the git commit.
		out = gitOutput("describe", "--dirty", "--always")
		if out != "" {
			//nolint:perfsprint
			return fmt.Sprintf("v0.0.0-0-%s", out)
		}
		return "v0.0.0"
	}

	return out
}()

var versionShort = func() string {
	if v := os.Getenv("VERSION_SHORT"); v != "" {
		return v
	}
	out := describeVersion("--abbrev=0")

	if out == "" {
		return "v0.0.0"
	}

	return out
}()

var concurrency = func() int {
	if v := os.Getenv("CONCURRENCY"); v != "" {
		pv, err := strconv.ParseUint(v, 10, bits.UintSize)
		if err != nil {
			panic(err)
		}

		// Ensure we always have at least 1 process
		if int(pv) < 1 {
			return 1
		}

		return int(pv)
	}
	return runtime.NumCPU()
}()

var linterDeadline = func() time.Duration {
	if v := os.Getenv("LINTER_DEADLINE"); v != "" {
		d, _ := time.ParseDuration(v)
		if d != 0 {
			return d
		}
	}
	return time.Minute
}()

func Log(args ...interface{}) {
	if mg.Verbose() {
		fmt.Println(args...)
	}
}

var concurrencyQueue chan struct{}
var concurrencyWg *sync.WaitGroup

// concurrentRun calls a function while respecting concurrency limits, and
// returns a promise-like function which will resolve to the value.
func concurrentRun[T any](fn func() T) func() T {
	concurrencyQueue <- struct{}{} // Acquire a job
	concurrencyWg.Add(1)           // Ensure we can wait

	rCh := make(chan T)
	go func() {
		rCh <- fn()
		<-concurrencyQueue   // Release a job
		concurrencyWg.Done() // Mark job finished
	}()

	return func() T {
		return <-rCh
	}
}

// waitResults accepts a map of operations and waits for them all to complete.
func waitResults(m map[string]func() error) func() error {
	type dispatch struct {
		k string
		v error
	}

	resultQueue := make(chan dispatch, len(m))
	for k, fn := range m {
		go func(k string, fn func() error) {
			resultQueue <- dispatch{
				k: k,
				v: fn(),
			}
		}(k, fn)
	}

	return func() error {
		buildError := false

		for range len(m) {
			result := <-resultQueue
			if result.v != nil {
				buildError = true
				fmt.Printf("Error: %s: %s\n", result.k, result.v)
			}
		}

		if buildError {
			return errParallelBuildFailed
		}
		return nil
	}
}

func init() {
	// Initialize concurrency queue
	concurrencyQueue = make(chan struct{}, concurrency)
	concurrencyWg = &sync.WaitGroup{}

	// Set environment
	os.Setenv("PATH", fmt.Sprintf("%s:%s", toolsBinDir, os.Getenv("PATH")))
	os.Setenv("GOBIN", toolsBinDir)
	Log("Build PATH: ", os.Getenv("PATH"))
	Log("Concurrency:", concurrency)
	goSrc = func() []string {
		results := new([]string)
		err := filepath.Walk(moduleDir, func(relpath string, info os.FileInfo, _ error) error {
			// Ensure absolute path so globs work
			path, err := filepath.Abs(relpath)
			if err != nil {
				panic(err)
			}

			// Look for files
			if info.IsDir() {
				return nil
			}

			// Exclusions
			for _, exclusion := range []string{toolsBinDir, binDir, releaseDir, coverageDir, moduleBinDir} {
				if strings.HasPrefix(path, exclusion) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}

			if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if strings.Contains(path, ".git") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			*results = append(*results, path)
			return nil
		})
		if err != nil {
			panic(err)
		}
		return *results
	}()
	goDirs = func() []string {
		resultMap := make(map[string]struct{})
		for _, path := range goSrc {
			absDir, err := filepath.Abs(filepath.Dir(path))
			if err != nil {
				panic(err)
			}
			resultMap[absDir] = struct{}{}
		}
		results := []string{}
		for k := range resultMap {
			results = append(results, k)
		}
		return results
	}()
	goPkgs = func() []string {
		results := []string{}
		cmd := exec.Command("go", "list", "./...")
		cmd.Dir = moduleDir
		cmd.Stderr = os.Stderr
		outBytes, err := cmd.Output()
		out := strings.TrimSpace(string(outBytes))
		if err != nil {
			panic(err)
		}
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "/vendor/") {
				results = append(results, line)
			}
		}
		return results
	}
	// Ensure output dirs exist
	for _, dir := range outputDirs {
		panicOnError(os.MkdirAll(dir, os.FileMode(OS_ALL_RWX)))
	}
}

// must consumes an error from a function.
func must[T any](result T, err error) T {
	if err != nil {
		panic(err)
	}
	return result
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// concurrencyLimitedBuild executes a certain number of commands limited by concurrency.
func concurrencyLimitedBuild(buildCmds ...interface{}) error {
	resultsCh := make(chan error, len(buildCmds))
	concurrencyControl := make(chan struct{}, concurrency)
	for _, buildCmd := range buildCmds {
		go func(buildCmd interface{}) {
			concurrencyControl <- struct{}{}
			resultsCh <- buildCmd.(func() error)()
			<-concurrencyControl
		}(buildCmd)
	}
	// Doesn't work at the moment
	//	mg.Deps(buildCmds...)
	results := []error{}
	var resultErr error = nil
	for len(results) < len(buildCmds) {
		err := <-resultsCh
		results = append(results, err)
		if err != nil {
			fmt.Println(err)
			resultErr = errors.Wrap(errParallelBuildFailed, "concurrencyLimitedBuild command failure")
		}
		fmt.Printf("Finished %v of %v\n", len(results), len(buildCmds))
	}

	return resultErr
}

// mockgen generates the mocks the tests use, matching go.uber.org/mock in v2/go.mod.
const mockgenTool = "go.uber.org/mock/mockgen@v0.4.0"

// Tools builds build tools of the project and is depended on by all other build targets.
func Tools() (err error) {
	// Catch panics and convert to errors
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()

	toolBuild := func(toolType string, tools ...[]string) error {
		toolTargets := []interface{}{}
		for _, toolImport := range tools {
			binName := toolImport[0]
			localToolImport := toolImport[1]

			if binName != "" {
				if _, err := os.Stat(path.Join(toolsBinDir, binName)); err == nil {
					// Skip named binary which we already have
					continue
				}
			}

			f := func() error {
				return sh.Run("go", "install", "-v", localToolImport)
			}
			toolTargets = append(toolTargets, f)
		}

		Log("Build", toolType, "tools")
		if berr := concurrencyLimitedBuild(toolTargets...); berr != nil {
			return berr
		}
		return nil
	}

	if berr := toolBuild("static", []string{"golangci-lint", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0"},
		[]string{"gocovmerge", "github.com/wadey/gocovmerge@latest"},
		[]string{"mockgen", mockgenTool},
	); berr != nil {
		return berr
	}

	return nil
}

// lintBaseRev is the upstream commit this fork is based on. Linters only report
// problems in code changed since then, so upstream's own lint debt doesn't fail
// CI. Move it forward when merging upstream, or override it with LINT_BASE_REV.
var lintBaseRev = func() string {
	if rev := os.Getenv("LINT_BASE_REV"); rev != "" {
		return rev
	}
	return "251ec3ef667e7e51f4b38c3f52c048f7f20dfc32"
}()

//nolint:perfsprint
func lintArgs(args ...string) []string {
	returnedArgs := []string{"-j", strconv.Itoa(concurrency), fmt.Sprintf(
		"--timeout=%s", linterDeadline.String()), "--new-from-rev=" + lintBaseRev}
	returnedArgs = append(returnedArgs, args...)
	return returnedArgs
}

// Lint runs golangci-lint for code quality. CI will run this before accepting PRs.
func Lint() error {
	mg.Deps(Tools)
	return runIn("golangci-lint", lintArgs("run", "./...")...)
}

// LintBisect runs the linters one directory at a time.
// It is useful for finding problems where golangci-lint won't compile and
// doesn't emit an error message.
func LintBisect() error {
	errs := []error{}
	for _, goDir := range goDirs {
		fmt.Println("Linting:", goDir)
		err := runIn("golangci-lint", lintArgs("run", goDir)...)
		if err != nil {
			fmt.Println("LINT ERROR IN:", goDir)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errLintBisect
	}
	return nil
}

// listLinters gets the golangci-lint config
func listLinters() ([]string, error) {
	cmd := exec.Command("golangci-lint", "linters")
	cmd.Dir = moduleDir
	output, err := cmd.Output()
	if err != nil {
		return []string{}, errors.Wrap(err, "golangci-lint linters failed to run")
	}
	bio := bufio.NewReader(bytes.NewBuffer(output))
	linters := []string{}
	for {
		line, _ := bio.ReadString('\n')
		line = strings.Trim(line, " \n\t")
		if line == "" {
			continue
		}
		if line == "Enabled by your configuration linters:" {
			continue
		}
		if line == "Disabled by your configuration linters:" {
			// Done
			break
		}
		linter := strings.Split(line, ":")[0]
		linter = strings.Split(linter, "(")[0]
		linter = strings.Trim(linter, " \n\t")
		linters = append(linters, linter)
	}
	return linters, nil
}

// LintersBisect runs all linters in golangci-lint one at a time.
// It is useful find broken linters.
func LintersBisect() error {
	linters, err := listLinters()
	if err != nil {
		return errors.Wrap(err, "LintersBisect: listLinters failed")
	}
	errs := map[string]error{}

	//nolint:perfsprint
	for _, linter := range linters {
		// --enable-only overrides the configured linter set while keeping
		// the rest of the configuration.
		err := runIn("golangci-lint", lintArgs("run", fmt.Sprintf("--enable-only=%s", linter), "./...")...)
		if err != nil {
			errs[linter] = err
		}
	}

	if len(errs) > 0 {
		for linter := range errs {
			fmt.Println("FAILED LINTER:", linter)
		}

		return errLintBisect
	}
	return nil
}

// formattingLinter runs the golangci-lint formatters and style linters,
// either reporting or fixing problems.
func formattingLinter(doFixes bool) error {
	mg.Deps(Tools)
	fmtArgs := []string{"fmt", "--no-config", "--enable=gofmt", "--enable=goimports"}
	runArgs := []string{"run", "--no-config", "--new-from-rev=" + lintBaseRev, "--default=none", "--enable=godot", "--enable=tagalign"}
	if doFixes {
		runArgs = append(runArgs, "--fix")
	} else {
		fmtArgs = append(fmtArgs, "--diff")
	}
	// golangci-lint fmt has no --new-from-rev, so only format the Go files changed
	// since lintBaseRev.
	changed := []string{}
	for _, name := range strings.Split(gitOutput("diff", "--name-only", "--diff-filter=d", lintBaseRev, "--", constModuleDir), "\n") {
		if strings.HasSuffix(name, ".go") {
			changed = append(changed, must(filepath.Rel(constModuleDir, name)))
		}
	}
	if len(changed) > 0 {
		if err := runIn("golangci-lint", append(fmtArgs, changed...)...); err != nil {
			return err
		}
	}
	return runIn("golangci-lint", append(runArgs, "./...")...)
}

// Style checks formatting of the file. CI will run this before acceptiing PRs.
func Style() error {
	return formattingLinter(false)
}

// Fmt automatically formats all source code files.
func Fmt() error {
	return formattingLinter(true)
}

func listCoverageFiles() ([]string, error) {
	result := []string{}
	finfos, derr := os.ReadDir(coverageDir)
	if derr != nil {
		return result, derr
	}
	for _, finfo := range finfos {
		result = append(result, path.Join(coverageDir, finfo.Name()))
	}
	return result, nil
}

// Test run test suite. The integration tests in the root package run the binary
// built by Binary.
func Test() error {
	mg.Deps(Tools)
	mg.Deps(GoGenerate)
	mg.Deps(Binary)
	curPlatform := getCurrentPlatform()

	// Ensure coverage directory exists
	if err := os.MkdirAll(coverageDir, os.FileMode(OS_ALL_RWX)); err != nil {
		return err
	}

	// Clean up coverage directory
	coverFiles, derr := listCoverageFiles()
	if derr != nil {
		return derr
	}
	for _, coverFile := range coverFiles {
		if err := sh.Rm(coverFile); err != nil {
			return err
		}
	}

	// Run tests
	//coverProfiles := []string{}
	//nolint:perfsprint
	for _, pkg := range goPkgs() {
		coverProfile := path.Join(coverageDir,
			fmt.Sprintf("%s%s", strings.ReplaceAll(pkg, "/", "-"), ".out"))
		testErr := goCmd(map[string]string{"CGO_ENABLED": cgoEnabled, "GLAUTH_TEST_BINARY": curPlatform.PlatformBin("glauth")},
			"test", "-v", "-tags", goBuildTags, "-covermode", "count", fmt.Sprintf("-coverprofile=%s", coverProfile),
			pkg)
		if testErr != nil {
			return testErr
		}
		//coverProfiles = append(coverProfiles, coverProfile)
	}

	return nil
}

// Coverage sums up the coverage profiles in .coverage. It does not clean up after itself or before.
func Coverage() error {
	// Clean up coverage directory
	coverFiles, derr := listCoverageFiles()
	if derr != nil {
		return derr
	}

	mergedCoverage, err := sh.Output("gocovmerge", coverFiles...)
	if err != nil {
		return err
	}
	return os.WriteFile(constCoverFile, []byte(mergedCoverage), os.FileMode(OS_ALL_RWX))
}

// All runs a full suite suitable for CI
//
//nolint:unparam
func All() error {
	mg.SerialDeps(Style, Lint, Test, Coverage, ReleaseAll)
	return nil
}

// GithubReleaseMatrix emits a line to setup build matrix jobs for release builds.
//
//nolint:unparam
func GithubReleaseMatrix() error {
	output := make([]string, 0, len(platforms))
	for _, platform := range platforms {
		output = append(output, platform.String())
	}
	jsonData := must(json.Marshal(output))
	line := fmt.Sprintf("release-matrix=%s\n", string(jsonData))

	// GitHub Actions reads step outputs from the file named by GITHUB_OUTPUT.
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		fmt.Print(line)
		return nil
	}
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// GoGenerate runs go generate. It only installs mockgen, rather than depending
// on Tools, so release builds don't build golangci-lint.
func GoGenerate() error {
	if _, err := os.Stat(path.Join(toolsBinDir, "mockgen")); err != nil {
		if err := sh.Run("go", "install", "-v", mockgenTool); err != nil {
			return err
		}
	}
	return goCmd(nil, "generate", "./...")
}

func makeBuilder(cmd string, pkg string, platform Platform) func() error {
	f := func() error {
		Log("Make platform binary directory:", platform.PlatformDir())
		if err := os.MkdirAll(platform.PlatformDir(), os.FileMode(OS_ALL_RWX)); err != nil {
			return errors.Wrapf(err, "error making directory: cmd: %s", cmd)
		}

		Log("Checking for changes:", platform.PlatformBin(cmd))
		if changed, err := target.Path(platform.PlatformBin(cmd), goSrc...); !changed {
			if err != nil {
				if !os.IsNotExist(err) {
					return errors.Wrapf(err, "error while checking for changes: cmd: %s", cmd)
				}
			} else {
				return nil
			}
		}

		ldflags := fmt.Sprintf("-buildid='' -X %s=%s", versionSymbol(), version)
		if cgoEnabled == "0" {
			ldflags += " -extldflags '-static'"
		}

		fmt.Println("Building", platform.PlatformBin(cmd))
		return goCmd(map[string]string{"CGO_ENABLED": cgoEnabled, "GOOS": platform.OS, "GOARCH": platform.Arch},
			"build", "-a", "-tags", goBuildTags, "-ldflags", ldflags,
			"-trimpath", "-o", platform.PlatformBin(cmd), pkg)
	}
	return f
}

func getCurrentPlatform() *Platform {
	var curPlatform *Platform
	for _, p := range platforms {
		if p.OS == runtime.GOOS && p.Arch == runtime.GOARCH {
			storedP := p
			curPlatform = &storedP
		}
	}
	Log("Determined current platform:", curPlatform)
	return curPlatform
}

// Binary build a binary for the current platform.
func Binary() error {
	curPlatform := getCurrentPlatform()
	if curPlatform == nil {
		return errPlatformNotSupported
	}

	if err := ReleaseBin(curPlatform.String()); err != nil {
		return err
	}

	buildResults := map[string]func() error{}

	for cmd := range goCmds {
		buildResults[cmd] = concurrentRun(func() error {
			// Make a root symlink to the build
			cmdPath := path.Join(curDir, cmd)
			os.Remove(cmdPath)
			if err := os.Symlink(curPlatform.PlatformBin(cmd), cmdPath); err != nil {
				return err
			}
			return nil
		})
	}

	return waitResults(buildResults)()
}

// doReleaseBin handles the deferred building of an actual release binary.
//
//nolint:gocritic
func doReleaseBin(OSArch string) func() error {
	mg.Deps(GoGenerate)

	platform, ok := platformsLookup[OSArch]
	if !ok {
		return func() error { return errors.Wrapf(errPlatformNotSupported, "ReleaseBin: %s", OSArch) }
	}

	buildResults := map[string]func() error{}

	for cmd, pkg := range goCmds {
		buildResults[cmd] = concurrentRun(makeBuilder(cmd, pkg, platform))
	}

	return waitResults(buildResults)
}

// ReleaseBin builds cross-platform release binaries under the bin/ directory.
//
//nolint:gocritic
func ReleaseBin(OSArch string) error {
	return doReleaseBin(OSArch)()
}

// ReleaseBinAll builds cross-platform release binaries under the bin/ directory.
func ReleaseBinAll() error {
	buildResults := map[string]func() error{}
	for OSArch := range platformsLookup {
		buildResults[fmt.Sprintf("build-%s", OSArch)] = doReleaseBin(OSArch)
	}

	return waitResults(buildResults)()
}

// Release builds release archives under the release/ directory.
//
//nolint:gocritic
func doRelease(OSArch string) func() error {
	platform, ok := platformsLookup[OSArch]
	if !ok {
		return func() error { return errors.Wrapf(errPlatformNotSupported, "ReleaseBin: %s", OSArch) }
	}

	return func() error {
		if err := ReleaseBin(OSArch); err != nil {
			return err
		}

		archiveCmds := map[string]func() error{}
		if platform.OS == "windows" {
			// build a zip binary as well
			archiveName := fmt.Sprintf("%s.zip", platform.ReleaseBase())
			archiveCmds[archiveName] = concurrentRun(func() error {
				if _, err := os.Stat(archiveName); err == nil {
					_ = os.Remove(archiveName)
				}
				archiveDir := path.Join(binDir, platform.ArchiveDir())
				fmt.Println("Archiving", archiveName)
				return archiver.NewZip().Archive([]string{archiveDir}, archiveName)
			})
		}

		// build tar gz
		archiveName := fmt.Sprintf("%s.tar.gz", platform.ReleaseBase())
		archiveCmds[archiveName] = concurrentRun(func() error {
			if _, err := os.Stat(archiveName); err == nil {
				_ = os.Remove(archiveName)
			}
			archiveDir := path.Join(binDir, platform.ArchiveDir())
			fmt.Println("Archiving", archiveName)
			return archiver.NewTarGz().Archive([]string{archiveDir}, archiveName)
		})

		return waitResults(archiveCmds)()
	}
}

// PlatformTargets prints the list of target platforms
func PlatformTargets() error {
	platforms := make([]string, 0, len(platformsLookup))
	for platform := range platformsLookup {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	for _, platform := range platforms {
		fmt.Println(platform)
	}
	return nil
}

// Release a binary archive for a specific platform
//
//nolint:gocritic
func Release(OSArch string) error {
	return doRelease(OSArch)()
}

// Release builds release archives under the release/ directory.
func ReleaseAll() error {
	buildResults := map[string]func() error{}
	for OSArch := range platformsLookup {
		buildResults[fmt.Sprintf("release-%s", OSArch)] = doRelease(OSArch)
	}

	return waitResults(buildResults)()
}

// Clean deletes build output and cleans up the working directory.
func Clean() error {
	// Remove the root symlinks made by Binary
	for name := range goCmds {
		if err := sh.Rm(path.Join(curDir, name)); err != nil {
			return err
		}
	}

	for _, name := range outputDirs {
		if err := sh.Rm(name); err != nil {
			return err
		}
	}
	return nil
}

// Debug prints the value of internal state variables
//
//nolint:unparam
func Debug() error {
	mg.Deps(GoGenerate)

	fmt.Println("Source Files:", goSrc)
	fmt.Println("Packages:", goPkgs())
	fmt.Println("Directories:", goDirs)
	fmt.Println("Command Paths:", goCmds)
	fmt.Println("Output Dirs:", outputDirs)
	fmt.Println("PATH:", os.Getenv("PATH"))

	fmt.Println("Version:", version)
	fmt.Println("Version short:", versionShort)
	fmt.Println("Version symbol:", versionSymbol())
	return nil
}

// Autogen configure local git repository with commit hooks.
func Autogen() error {
	if _, err := os.Stat(gitHookDir); errors.Is(err, os.ErrNotExist) {
		fmt.Println("No", constGitHookDir, "directory: no git hooks to install")
		return nil
	}
	fmt.Println("Installing git hooks in local repository...")

	for _, fname := range must(os.ReadDir(gitHookDir)) {
		hookName := fname.Name()
		if !fname.IsDir() {
			continue
		}

		gitHookPath := fmt.Sprintf(".git/hooks/%s", hookName)
		repoHookPath := path.Join(gitHookDir, fname.Name())

		scripts := []string{}
		for _, scriptName := range must(os.ReadDir(repoHookPath)) {
			if scriptName.IsDir() {
				continue
			}
			fullHookPath := path.Join(gitHookDir, hookName, scriptName.Name())
			relHookPath := must(filepath.Rel(binRootName, fullHookPath))

			scripts = append(scripts, relHookPath)

			data, err := os.ReadFile(gitHookPath)
			if err != nil {
				data = []byte("#!/bin/bash\n")
			}

			splitHook := strings.Split(string(data), "\n")
			if strings.TrimRight(splitHook[0], " \t") != "#!/bin/bash" {
				fmt.Printf("Don't know how to update your %s script.\n", hookName)
				return errAutogenUnknownPreCommitScriptFormat
			}

			headAt := -1
			tailAt := -1
			for idx, line := range splitHook {
				// Search until header.
				if strings.TrimPrefix(line, " ") == constManagedScriptSectionHead {
					if headAt != -1 {
						fmt.Println("Found multiple managed script sections in ", fname.Name(), "first was at line ", headAt, "second was at line ", idx)
						return errAutogenMultipleScriptSections
					}
					headAt = idx
					continue
				} else if strings.TrimPrefix(line, " ") == constManagedScriptSectionFoot {
					if tailAt != -1 {
						fmt.Println("Found multiple managed script sections in ", fname.Name(), "first was at line ", headAt, "second was at line ", idx)
						return errAutogenMultipleScriptSections
					}
					tailAt = idx + 1
					continue
				}
			}

			if headAt == -1 {
				headAt = 1
			}

			if tailAt == -1 {
				tailAt = len(splitHook)
			}

			scriptPackage := []string{constManagedScriptSectionHead}
			scriptPackage = append(scriptPackage, "# These lines were added by go run mage.go autogen.", "")
			for _, scriptPath := range scripts {
				scriptPackage = append(scriptPackage, fmt.Sprintf("\"./%s\" || exit $?", scriptPath))
			}
			scriptPackage = append(scriptPackage, "", constManagedScriptSectionFoot)

			updatedScript := splitHook[:headAt]
			updatedScript = append(updatedScript, scriptPackage...)
			updatedScript = append(updatedScript, splitHook[tailAt:]...)

			err = os.WriteFile(gitHookPath, []byte(strings.Join(updatedScript, "\n")),
				os.FileMode(OS_ALL_RW|OS_USER_X))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
