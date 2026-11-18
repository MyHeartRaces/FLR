// Package privatefile persists bounded private state with durable atomic writes.
package privatefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func SafePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("private path must be clean and absolute")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot inspect private path")
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private path cannot contain symlinks")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
func Read(path string, limit int) ([]byte, error) {
	if err := SafePath(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	parent, parentErr := os.Stat(filepath.Dir(path))
	if limit < 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > int64(limit) || parentErr != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("private file type, permissions or size rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open private file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, fmt.Errorf("private file read rejected")
	}
	return raw, nil
}
func Write(path string, raw []byte) error {
	if err := SafePath(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create private directory")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("private directory must be 0700")
	}
	if info, err = os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("private file must be regular and 0600")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect private file")
	}
	file, err := os.CreateTemp(dir, ".private-*")
	if err != nil {
		return fmt.Errorf("cannot create private temporary file")
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("cannot write private state")
	}
	if closeErr != nil {
		return fmt.Errorf("cannot close private state")
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cannot publish private state")
	}
	return SyncDir(dir)
}
func SyncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("cannot open private state directory")
	}
	defer file.Close()
	if err = file.Sync(); err != nil {
		return fmt.Errorf("cannot sync private state directory")
	}
	return nil
}
