package passworddb

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

type fileLock struct{ f *os.File }

func (l *fileLock) Close() error {
	e := unlock(l.f)
	c := l.f.Close()
	if e != nil {
		return SafeError(e)
	}
	return SafeError(c)
}
func lock(ctx context.Context, path string, exclusive, wait bool) (*fileLock, error) {
	mode := os.O_RDONLY
	if exclusive {
		mode = os.O_RDWR
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, problem("invalid_file")
	}
	f, err := os.OpenFile(path, mode, 0)
	if err != nil {
		return nil, err
	}
	for {
		if err = ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		ok, e := tryLock(f, exclusive)
		if e != nil {
			f.Close()
			return nil, e
		}
		if ok {
			return &fileLock{f}, nil
		}
		if !wait {
			f.Close()
			return nil, problem("busy")
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func rootPath(path string) (string, error) {
	if path == "" {
		return "", problem("database_path_required")
	}
	p, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	if e = supportedRoot(p); e != nil {
		return "", e
	}
	return p, nil
}
func createFile(path string) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	e = f.Sync()
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
func initialize(path string) (string, error) {
	if path == "" {
		return "", problem("database_path_required")
	}
	p, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	if e = os.MkdirAll(p, 0700); e != nil {
		return "", e
	}
	if e = supportedRoot(p); e != nil {
		return "", e
	}
	if e = os.MkdirAll(filepath.Join(p, "versions"), 0700); e != nil {
		return "", e
	}
	for _, name := range []string{"update.lock", "control.lock"} {
		e = createFile(filepath.Join(p, name))
		if e != nil && !os.IsExist(e) {
			return "", e
		}
	}
	if e = syncDirectory(p); e != nil {
		return "", e
	}
	return p, nil
}
func versionDir(root, id string) (string, error) {
	if !validID(id) {
		return "", problem("invalid_dataset_id")
	}
	dir := filepath.Join(root, "versions", id)
	st, e := os.Lstat(dir)
	if e != nil {
		return "", e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", problem("invalid_file")
	}
	return dir, nil
}
