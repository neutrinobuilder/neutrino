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

package i2pnode

import (
	"fmt"
	"os"
	"testing"

	"neutrino/internal/i18n"
)

func TestDrainLogEmpty(t *testing.T) {
	ch := make(chan string, 4)
	if got := drainLog(ch); got != "" {
		t.Fatalf("drainLog(empty channel) = %q, want \"\"", got)
	}
}

func TestDrainLogJoinsBufferedLines(t *testing.T) {
	ch := make(chan string, 4)
	ch <- "riga1"
	ch <- "riga2"
	ch <- "riga3"

	got := drainLog(ch)
	want := fmt.Sprintf(i18n.T("i2pnode.log_dump"), "riga1\nriga2\nriga3")
	if got != want {
		t.Fatalf("drainLog = %q, want %q", got, want)
	}
}

func TestExtractBinaryWritesExecutable(t *testing.T) {
	if len(i2pdBinary) == 0 {
		t.Skip("no embedded i2pd binary for this target")
	}
	path, cleanup, err := extractBinary()
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	defer cleanup()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if fi.Mode()&0100 == 0 {
		t.Fatalf("%q is not executable (mode %v)", path, fi.Mode())
	}
	if fi.Size() != int64(len(i2pdBinary)) {
		t.Fatalf("file size = %d, want %d (i2pdBinary)", fi.Size(), len(i2pdBinary))
	}

	cleanup()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("cleanup: the file should have been removed")
	}
}

func TestResolveBinaryEmbeddedOrPATH(t *testing.T) {
	path, cleanup, err := resolveBinary()
	if cleanup != nil {
		defer cleanup()
	}
	if len(i2pdBinary) > 0 {
		if err != nil {
			t.Fatalf("resolveBinary: %v, want success with the embedded binary", err)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("resolveBinary: path %q doesn't exist: %v", path, statErr)
		}
		return
	}
	// No embedded binary for this target: success only if "i2pd" is on
	// the runner's system PATH, otherwise an error is the expected outcome.
	if err == nil {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("resolveBinary: path %q doesn't exist: %v", path, statErr)
		}
	}
}
