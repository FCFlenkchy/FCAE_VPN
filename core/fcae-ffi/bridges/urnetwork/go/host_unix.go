//go:build fcae_urnetwork && !windows

package main

import (
	"os"
	"path/filepath"
)

func urPrivate(path string) error {
	info, e := os.Stat(path)
	if e != nil {
		return e
	}
	mode := os.FileMode(0600)
	if info.IsDir() {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
func urReplace(from, to string) error {
	if e := os.Rename(from, to); e != nil {
		return e
	}
	// Commit both the account entry and a newly created account directory before
	// a versioned registration request can cross the physical request boundary.
	for _, dir := range []string{filepath.Dir(to), filepath.Dir(filepath.Dir(to))} {
		f, e := os.Open(dir)
		if e != nil {
			return e
		}
		e = f.Sync()
		_ = f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
