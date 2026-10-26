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

package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSlotContainerWriteReadRoundTrip(t *testing.T) {
	c, _, _, realKi, duressKi, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keystore.json")

	if err := WriteSlotContainer(path, c); err != nil {
		t.Fatalf("WriteSlotContainer: %v", err)
	}
	got, err := ReadSlotContainer(path)
	if err != nil {
		t.Fatalf("ReadSlotContainer: %v", err)
	}
	if len(got.Slots) != len(c.Slots) {
		t.Fatalf("expected %d slots after round-trip, got %d", len(c.Slots), len(got.Slots))
	}

	realK, ok := unwrapKi(got.Slots[0], "pf", "real-secret")
	if !ok || string(realK) != string(realKi) {
		t.Fatal("real slot does not unwrap to the original K_i after a disk round-trip")
	}
	duressK, ok := unwrapKi(got.Slots[1], "pf", "duress-secret")
	if !ok || string(duressK) != string(duressKi) {
		t.Fatal("duress slot does not unwrap to the original K_i after a disk round-trip")
	}
}

func TestReadSlotContainerRejectsUnrecognizedFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := os.WriteFile(path, []byte("not a neutrino keystore file"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadSlotContainer(path); err == nil {
		t.Fatal("expected an error reading a file that isn't a slot container")
	}
}

func TestReadSlotContainerMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := ReadSlotContainer(path); err == nil {
		t.Fatal("expected an error reading a missing file")
	}
}

func TestWriteSlotContainerDoesNotLeakTempFile(t *testing.T) {
	c, _, _, _, _, _, err := newSlotContainer("pf", "real-secret", "duress-secret")
	if err != nil {
		t.Fatalf("newSlotContainer: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	if err := WriteSlotContainer(path, c); err != nil {
		t.Fatalf("WriteSlotContainer: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "keystore.json" {
		t.Fatalf("expected exactly one file (keystore.json) in the directory, got %v", entries)
	}
}
