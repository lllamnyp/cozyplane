/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package version

import (
	"runtime/debug"
)

// These variables are set via -ldflags at build time.
var (
	gitCommit = "unknown"
	gitTag    = "unknown"
)

// GitCommit returns the git commit the binary was built from.
func GitCommit() string { return gitCommit }

// GitTag returns the git tag the binary was built from.
func GitTag() string { return gitTag }

// String returns a human-readable multi-line version string.
func String() string {
	s := "git commit: " + gitCommit + "\ngit tag:    " + gitTag
	if info, ok := debug.ReadBuildInfo(); ok {
		s += "\ngo version: " + info.GoVersion
	}

	return s
}
