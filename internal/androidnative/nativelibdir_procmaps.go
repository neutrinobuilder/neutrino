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

//go:build linux

package androidnative

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// nativeLibraryDirViaProcMaps inspects this process's /proc/self/maps: the
// app's binary (lib/<abi>/libNeutrino.so) is loaded by Android from
// nativeLibraryDir, it will appear among the mappings. A cgo/JNI-free
// fallback to nativeLibraryDirViaJNI. GOOS=android implies the "linux"
// build tag in Go, so this file compiles both on real Android and on an
// ordinary Linux development machine (used only as a fallback in the
// latter case).
func nativeLibraryDirViaProcMaps() (string, error) {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '/')
		if i < 0 || !strings.HasSuffix(line, ".so") {
			continue
		}
		path := line[i:]
		if !strings.Contains(path, "/lib/") {
			continue
		}
		return filepath.Dir(path), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("androidnative: no */lib/*.so mapping found in /proc/self/maps")
}
