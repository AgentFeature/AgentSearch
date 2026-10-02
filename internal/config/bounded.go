package config

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Operator-supplied configuration, database and target-list files are trusted
// content, but reading them is still bounded so a mistaken path or an oversized
// file cannot exhaust memory.
const (
	MaxConfigBytes  = 64 << 20 // Sites/database and services YAML/JSON.
	MaxTargetsBytes = 16 << 20 // One line-per-target CLI input file.
)

func readFileLimit(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("file must be a regular file no larger than %d bytes", limit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("file exceeds the %d byte limit", limit)
	}
	return raw, nil
}

// ReadTargetList reads a bounded one-line-per-target file, ignoring blank lines
// and comments exactly like the legacy CLI. It returns no partial list on error.
func ReadTargetList(path string) ([]string, error) {
	raw, err := readFileLimit(path, MaxTargetsBytes)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}
