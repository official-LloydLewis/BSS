package version

import "fmt"

// These variables are injected at build time via -ldflags.
var (
	Version   = "alpha-test 1.0.0v"
	Commit    = "none"
	BuildDate = "unknown"
	BuiltBy   = "source"
)

func String() string {
	return fmt.Sprintf("%s (commit %s, built %s by %s)", Version, Commit, BuildDate, BuiltBy)
}
