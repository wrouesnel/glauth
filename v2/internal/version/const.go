package version

// Version is the tag of the latest release, it gets changed by the ci
// process when a release is happening. Builds from git override it at link
// time with git describe.
var Version = "v2.5.4" // x-release-please-version
