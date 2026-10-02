//go:build !linux

package monitor

import (
	"errors"
	"os"
)

func safeOpenFlags() int       { return 0 }
func lockStore(*os.File) error { return errors.New("monitor durable storage currently requires Linux") }
func renameWithin(*os.Root, string, string) error {
	return errors.New("monitor durable storage currently requires Linux")
}
