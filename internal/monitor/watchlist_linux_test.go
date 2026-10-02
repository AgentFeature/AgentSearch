package monitor

import (
	"golang.org/x/sys/unix"
	"path/filepath"
	"testing"
)

func TestWatchlistRefusesFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWatchlist(path, parseTarget); err == nil {
		t.Fatal("nonregular watchlist accepted")
	}
}
