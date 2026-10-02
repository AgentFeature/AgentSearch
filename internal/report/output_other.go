//go:build !linux

package report

import (
	"os"
	"path/filepath"
)

// This portability path is not a claim of tested platform interoperability.
func publish(root *os.Root, from, to string) error {
	return os.Rename(filepath.Join(root.Name(), from), filepath.Join(root.Name(), to))
}
