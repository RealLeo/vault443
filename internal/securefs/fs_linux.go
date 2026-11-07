package securefs

import (
	"errors"
	"os"
	"syscall"
)

const NoFollow = syscall.O_NOFOLLOW
const NonBlock = syscall.O_NONBLOCK

func Owner(testing bool) (int, error) {
	if testing {
		return os.Geteuid(), nil
	}
	if os.Geteuid() != 0 {
		return 0, errors.New("the system daemon must run as root")
	}
	return 0, nil
}
func Check(info os.FileInfo, path string, owner int, private bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	if !ok || int(stat.Uid) != owner || info.Mode().Perm()&mask != 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path ownership or permissions are unsafe")
	}
	return nil
}
func OpenFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, mode)
}
func MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func Lock(file *os.File) error                     { return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func SyncDir(file *os.File) error                  { return file.Sync() }
func Replace(from, to string) error                { return os.Rename(from, to) }
