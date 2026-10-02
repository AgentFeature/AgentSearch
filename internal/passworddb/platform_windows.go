package passworddb

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"strings"
)

func tryLock(f *os.File, exclusive bool) (bool, error) {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}
func unlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}

// File.Sync flushes file handles. Windows directory-entry persistence has no
// claimed equivalent here to Unix directory fsync; power-loss behavior is unverified.
func syncDirectory(string) error { return nil }
func availableSpace(path string) (uint64, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	var available, total, free uint64
	e = windows.GetDiskFreeSpaceEx(p, &available, &total, &free)
	return available, e
}
func supportedRoot(path string) error {
	if strings.HasPrefix(path, `\\`) {
		return problem("unsupported_filesystem")
	}
	return nil
}
