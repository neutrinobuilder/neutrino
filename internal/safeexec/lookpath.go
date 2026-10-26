// Copyright (C) 2026 Neutrino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Package safeexec provides a replacement for os/exec.LookPath that avoids
// the Faccessat2 syscall. On Android/Termux that syscall is blocked by
// Android's seccomp filter and kills the entire process with SIGSYS "bad
// system call" instead of returning a handleable error (golang/go#57393,
// #60125 — a known, unresolved Go issue). The same replacement is applied
// separately in internal/clipboardfix to the github.com/atotto/clipboard
// third-party dependency; this package covers callers within this project
// (internal/i2pnode, internal/tornode) that invoke exec.LookPath directly.
package safeexec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// LookPath searches for file in $PATH (or verifies it directly if it
// contains a path separator), checking the executable bits with os.Stat
// instead of internal/syscall/unix.Eaccess: less precise than exec.LookPath
// for ACL/capability edge cases, but sufficient to find an executable in
// PATH and never at risk of the syscall that crashes on Android.
func LookPath(file string) (string, error) {
	if strings.ContainsRune(file, os.PathSeparator) {
		if isExecutableFile(file) {
			return file, nil
		}
		return "", errors.New("safeexec: " + file + ": not an executable file")
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
	return "", errors.New("safeexec: \"" + file + "\": executable file not found in $PATH")
}

func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Mode()&0111 != 0
}
