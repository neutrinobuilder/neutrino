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
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeExecutable creates an empty executable file in dir and returns its path.
func writeExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLookPathFindsInPATH(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "myprobe")
	t.Setenv("PATH", dir)

	got, err := LookPath("myprobe")
	if err != nil {
		t.Fatalf("LookPath: %v", err)
	}
	want := filepath.Join(dir, "myprobe")
	if got != want {
		t.Fatalf("LookPath = %q, want %q", got, want)
	}
}

func TestLookPathNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	if _, err := LookPath("does-not-exist"); err == nil {
		t.Fatal("LookPath: want an error for a command missing from PATH")
	}
}

func TestLookPathSkipsNonExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notexec")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)

	if _, err := LookPath("notexec"); err == nil {
		t.Fatal("LookPath: want an error for a non-executable file")
	}
}

func TestLookPathSkipsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Setenv("PATH", dir)

	if _, err := LookPath("adir"); err == nil {
		t.Fatal("LookPath: want an error, a directory is not an executable")
	}
}

func TestLookPathWithSeparatorDirect(t *testing.T) {
	dir := t.TempDir()
	path := writeExecutable(t, dir, "direct")

	got, err := LookPath(path)
	if err != nil {
		t.Fatalf("LookPath: %v", err)
	}
	if got != path {
		t.Fatalf("LookPath = %q, want %q", got, path)
	}
}

func TestLookPathWithSeparatorNotExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notexec")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LookPath(path); err == nil {
		t.Fatal("LookPath: want an error for a non-executable explicit path")
	}
}

func TestLookPathEmptyPATHEntryMeansCurrentDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH separator/semantics differ on Windows")
	}
	dir := t.TempDir()
	writeExecutable(t, dir, "fromcwd")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	// An empty PATH entry (e.g. "::") means "current directory", the same
	// semantics as os/exec.LookPath.
	t.Setenv("PATH", ":")

	got, err := LookPath("fromcwd")
	if err != nil {
		t.Fatalf("LookPath: %v", err)
	}
	want := filepath.Join(".", "fromcwd")
	if got != want {
		t.Fatalf("LookPath = %q, want %q", got, want)
	}
}
