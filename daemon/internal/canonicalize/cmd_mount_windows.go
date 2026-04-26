//go:build windows

package canonicalize

import (
	"path/filepath"
	"strings"
)

func sameMount(left string, right string) bool {
	leftVolume := strings.ToLower(filepath.VolumeName(left))
	rightVolume := strings.ToLower(filepath.VolumeName(right))
	return leftVolume == rightVolume
}
