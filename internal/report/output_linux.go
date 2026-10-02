package report

import (
	"golang.org/x/sys/unix"
	"os"
)

func publish(root *os.Root, from, to string) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	if err = unix.Renameat(int(f.Fd()), from, int(f.Fd()), to); err != nil {
		return err
	}
	return f.Sync()
}
