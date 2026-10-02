package tests

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Check maintained text, not Git history or externally installed dependencies.
// unicode.Cyrillic covers the Unicode script, not only the Russian alphabet.
func TestRepositoryTextIsEnglishOnly(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "node_modules", ".cache":
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !utf8.Valid(data) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(data), "\n") {
			for _, r := range line {
				if unicode.Is(unicode.Cyrillic, r) {
					t.Errorf("unexpected Cyrillic text in %s:%d", rel, n+1)
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
