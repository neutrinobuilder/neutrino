// Copyright 2013 @atotto. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd || linux || netbsd || openbsd || solaris || dragonfly

package clipboard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// lookPathSafe is a drop-in replacement for exec.LookPath that avoids
// internal/syscall/unix.Eaccess (the Faccessat2 syscall on Linux): that
// syscall is blocked by Android's seccomp filter and kills the whole process
// with SIGSYS "bad system call" on Termux — even though the very same binary
// runs fine under a plain Linux kernel (e.g. Raspberry Pi). See
// golang/go#57393 and golang/go#60125. Checking
// the file mode's execute bits after a plain Stat (no Eaccess/Faccessat2
// involved) is less precise for ACL/capability edge cases than the real
// exec.LookPath, but is more than enough to detect a clipboard helper binary
// in PATH, and never triggers the crash on any platform.
func lookPathSafe(file string) (string, error) {
	if strings.ContainsRune(file, os.PathSeparator) {
		if isExecutableFile(file) {
			return file, nil
		}
		return "", errors.New("clipboard: " + file + ": not an executable file")
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, file)
		if isExecutableFile(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("clipboard: \"" + file + "\": executable file not found in $PATH")
}

func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Mode()&0111 != 0
}
