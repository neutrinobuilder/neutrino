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

package androidnative

import "fmt"

// Resolve returns the app's nativeLibraryDir (where Android extracts
// jniLibs/'s .so files, including libtor.so), trying the JNI path first
// (more robust, uses the public SDK API Context.getApplicationInfo()),
// then /proc/self/maps as a cgo-free fallback. method reports which path
// succeeded, useful for log/debug.
func Resolve() (dir, method string, err error) {
	if dir, err = nativeLibraryDirViaJNI(); err == nil {
		return dir, "JNI", nil
	}
	jniErr := err
	if dir, err = nativeLibraryDirViaProcMaps(); err == nil {
		return dir, "/proc/self/maps (fallback; JNI: " + jniErr.Error() + ")", nil
	}
	return "", "", fmt.Errorf("JNI: %v; /proc/self/maps: %v", jniErr, err)
}
