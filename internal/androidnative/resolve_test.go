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

import "testing"

// On this host (Linux desktop, not Android) nativeLibraryDirViaJNI is
// always the "!android" stub (fixed error) and nativeLibraryDirViaProcMaps
// depends on this process's real /proc/self/maps content — not
// controllable from a test (depends on whether the test binary is
// dynamically linked against something under */lib/*.so). The tests are
// therefore smoke tests: no panic, a consistent result shape across both
// possible outcomes.

func TestNativeLibraryDirViaJNIStubAlwaysErrors(t *testing.T) {
	if _, err := nativeLibraryDirViaJNI(); err == nil {
		t.Fatal("nativeLibraryDirViaJNI: want an error outside Android")
	}
}

func TestNativeLibraryDirViaProcMapsNoPanic(t *testing.T) {
	dir, err := nativeLibraryDirViaProcMaps()
	if err != nil {
		// Legitimate outcome: no */lib/*.so mapping in the test process.
		return
	}
	if dir == "" {
		t.Fatal("nativeLibraryDirViaProcMaps: empty dir with nil err")
	}
}

func TestResolveNoPanic(t *testing.T) {
	dir, method, err := Resolve()
	if err != nil {
		// JNI always fails (stub), ProcMaps can also legitimately fail on
		// this host: the combined error just needs to exist, not be empty.
		if err.Error() == "" {
			t.Fatal("Resolve: empty error")
		}
		return
	}
	if dir == "" {
		t.Fatal("Resolve: empty dir with nil err")
	}
	if method == "" {
		t.Fatal("Resolve: empty method with nil err")
	}
}
