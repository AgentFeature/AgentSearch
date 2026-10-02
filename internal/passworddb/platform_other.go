//go:build !linux && !windows

package passworddb

import "os"

func tryLock(*os.File, bool) (bool, error)  { return false, problem("unsupported_platform") }
func unlock(*os.File) error                 { return problem("unsupported_platform") }
func syncDirectory(string) error            { return problem("unsupported_platform") }
func availableSpace(string) (uint64, error) { return 0, problem("unsupported_platform") }
func supportedRoot(string) error            { return problem("unsupported_platform") }
