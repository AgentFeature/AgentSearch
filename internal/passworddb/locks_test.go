package passworddb

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestUpdaterProcessLock(t *testing.T) {
	if root := os.Getenv("AGENTSEARCH_LOCK_TEST_ROOT"); root != "" {
		held, e := lock(context.Background(), filepath.Join(root, "update.lock"), true, false)
		if e == nil {
			held.Close()
			os.Exit(2)
		}
		if ErrorKind(e) != "busy" {
			os.Exit(3)
		}
		return
	}
	root, e := initialize(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	held, e := lock(context.Background(), filepath.Join(root, "update.lock"), true, false)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpdaterProcessLock$")
	cmd.Env = append(os.Environ(), "AGENTSEARCH_LOCK_TEST_ROOT="+root)
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatal("cross-process exclusion failed", string(output))
	}
	if e = held.Close(); e != nil {
		t.Fatal(e)
	}
	again, e := lock(context.Background(), filepath.Join(root, "update.lock"), true, false)
	if e != nil {
		t.Fatal("released updater lock unavailable")
	}
	again.Close()
}
