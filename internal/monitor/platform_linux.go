package monitor

import (
	"golang.org/x/sys/unix"
	"os"
)

func safeOpenFlags() int         { return unix.O_NOFOLLOW | unix.O_NONBLOCK }
func lockStore(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func renameWithin(root *os.Root, from, to string) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.Renameat(int(f.Fd()), from, int(f.Fd()), to)
}
