package passworddb

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func tryLock(f *os.File, exclusive bool) (bool, error) {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	err := unix.Flock(int(f.Fd()), mode|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return err == nil, err
}
func unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func availableSpace(path string) (uint64, error) {
	var s unix.Statfs_t
	e := unix.Statfs(path, &s)
	if e != nil {
		return 0, e
	}
	return s.Bavail * uint64(s.Bsize), nil
}
func supportedRoot(path string) error {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return err
	}
	if s.Type == 0x6969 || s.Type == 0xff534d42 {
		return problem("unsupported_filesystem")
	}
	return nil
}
