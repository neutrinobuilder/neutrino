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

package safeexec

import (
	"path/filepath"
	"testing"
)

func TestCommandResolvesFromPATH(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "myprobe")
	t.Setenv("PATH", dir)

	cmd := Command("myprobe", "arg1", "arg2")
	if cmd.Err != nil {
		t.Fatalf("Command.Err = %v, want nil", cmd.Err)
	}
	if cmd.Path != path {
		t.Fatalf("Command.Path = %q, want %q", cmd.Path, path)
	}
	wantArgs := []string{"myprobe", "arg1", "arg2"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("Command.Args = %v, want %v", cmd.Args, wantArgs)
	}
	for i, a := range wantArgs {
		if cmd.Args[i] != a {
			t.Fatalf("Command.Args[%d] = %q, want %q", i, cmd.Args[i], a)
		}
	}
}

func TestCommandNotFoundSetsErr(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	cmd := Command("does-not-exist")
	if cmd.Err == nil {
		t.Fatal("Command.Err: want non-nil for a command missing from PATH")
	}
}

func TestCommandWithExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "direct")

	cmd := Command(path)
	if cmd.Err != nil {
		t.Fatalf("Command.Err = %v, want nil", cmd.Err)
	}
	if cmd.Path != path {
		t.Fatalf("Command.Path = %q, want %q", cmd.Path, path)
	}
	if filepath.Base(cmd.Path) != "direct" {
		t.Fatalf("Command.Path base = %q, want direct", filepath.Base(cmd.Path))
	}
}

func TestCommandRuns(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "true")
	t.Setenv("PATH", dir)

	cmd := Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}
