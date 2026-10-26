// Package vault443 exposes the release version shared with CMake and packaging.
package vault443

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var releaseVersion string

func Version() string { return strings.TrimSpace(releaseVersion) }
