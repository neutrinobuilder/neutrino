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

package termuxenv

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestAcquireWakeLockNoOpWithoutTermux(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // no termux-wake-lock in PATH

	release := AcquireWakeLock()
	if release == nil {
		t.Fatal("AcquireWakeLock: release must never be nil")
	}
	release() // must not panic
}

func TestAcquireWakeLockRunsWhenPresent(t *testing.T) {
	dir := t.TempDir()
	// ": > file" is a shell builtin (no external binary like touch): the
	// script runs with the same restricted PATH as the test.
	marker := filepath.Join(dir, "locked")
	lockScript := "#!/bin/sh\n: > " + marker + "\n"
	if err := os.WriteFile(filepath.Join(dir, "termux-wake-lock"), []byte(lockScript), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	unlockMarker := filepath.Join(dir, "unlocked")
	unlockScript := "#!/bin/sh\n: > " + unlockMarker + "\n"
	if err := os.WriteFile(filepath.Join(dir, "termux-wake-unlock"), []byte(unlockScript), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)

	release := AcquireWakeLock()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("termux-wake-lock was not run: %v", err)
	}
	release()
	if _, err := os.Stat(unlockMarker); err != nil {
		t.Fatalf("termux-wake-unlock was not run: %v", err)
	}
}

func TestFixLocalTimezoneNoOpWithoutGetprop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	before := time.Local

	FixLocalTimezone()

	if time.Local != before {
		t.Fatal("FixLocalTimezone: time.Local must not change if getprop is missing")
	}
}

func TestFixLocalTimezoneSetsValidZone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script not applicable on Windows")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'Europe/Rome\\n'\n"
	if err := os.WriteFile(filepath.Join(dir, "getprop"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })

	FixLocalTimezone()

	if time.Local == nil || time.Local.String() != "Europe/Rome" {
		got := "nil"
		if time.Local != nil {
			got = time.Local.String()
		}
		t.Fatalf("time.Local = %s, want Europe/Rome", got)
	}
}

func TestFixLocalTimezoneIgnoresUnknownZone(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'Not/AZone\\n'\n"
	if err := os.WriteFile(filepath.Join(dir, "getprop"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)

	before := time.Local
	FixLocalTimezone()
	if time.Local != before {
		t.Fatal("FixLocalTimezone: time.Local must not change for an unknown zone")
	}
}

func TestFixLocalTimezoneIgnoresEmptyOutput(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf ''\n"
	if err := os.WriteFile(filepath.Join(dir, "getprop"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)

	before := time.Local
	FixLocalTimezone()
	if time.Local != before {
		t.Fatal("FixLocalTimezone: time.Local must not change for an empty output")
	}
}

func TestRunGetprop(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'Europe/Sofia'\n"
	if err := os.WriteFile(filepath.Join(dir, "getprop"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("PATH", dir)

	out, err := runGetprop()
	if err != nil {
		t.Fatalf("runGetprop: %v", err)
	}
	if string(out) != "Europe/Sofia" {
		t.Fatalf("runGetprop = %q, want Europe/Sofia", out)
	}
}

func TestRunGetpropNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	if _, err := runGetprop(); err == nil {
		t.Fatal("runGetprop: want an error when getprop is available neither in PATH nor at the absolute Android path")
	}
}
