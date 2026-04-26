//go:build !windows

package canonicalize

import (
	"os"
	"syscall"
)

func sameMount(left string, right string) bool {
	linkInfo, err := os.Lstat(left)
	if err != nil {
		return true
	}
	targetInfo, err := os.Stat(right)
	if err != nil {
		return true
	}
	linkStat, ok := linkInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	targetStat, ok := targetInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return linkStat.Dev == targetStat.Dev
}
