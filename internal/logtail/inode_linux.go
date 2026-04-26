package logtail

import (
	"os"
	"syscall"
)

// fileInode returns the inode number for the given path.
func fileInode(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, nil
	}
	return stat.Ino, nil
}
