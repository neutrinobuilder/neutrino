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

// Package termuxenv handles Android/Termux environment specifics that would
// otherwise require manual configuration: wake-lock (keeping the CPU awake
// with the process in the background or the screen off) and local timezone
// resolution.
package termuxenv

import (
	"errors"
	"os"
	"strings"
	"time"

	"neutrino/internal/safeexec"
)

// AcquireWakeLock runs termux-wake-lock (bundled with Termux itself, no
// separate Termux:API app required) and returns a release function for
// termux-wake-unlock. Best-effort and silent outside Termux or if the
// command isn't installed: both calls are simply skipped, release is
// always safe to invoke.
//
// Without a wake-lock, Doze/App Standby can suspend Termux for an
// unpredictable time while it's in the background or the screen is off;
// messages exchanged meanwhile stay unacknowledged, and past the message TTL
// their senders rotate the sender_key and re-encrypt them (see
// Client.RetryDue), while our own retired DH ephemerals expire in
// two-member rooms.
func AcquireWakeLock() (release func()) {
	if _, err := safeexec.LookPath("termux-wake-lock"); err != nil {
		return func() {}
	}
	_ = safeexec.Command("termux-wake-lock").Run()
	return func() {
		_ = safeexec.Command("termux-wake-unlock").Run()
	}
}

// FixLocalTimezone corrects time.Local on Android/Termux, where neither the
// TZ variable nor a valid /etc/localtime is usually set: in that case Go
// doesn't even attempt a name-based resolution and silently falls back to
// UTC regardless of time/tzdata (which only resolves an already-known zone
// NAME, it doesn't discover one). Reads the real zone via "getprop
// persist.sys.timezone" (an Android system property, no Termux:API
// required) and assigns it explicitly. Best-effort and silent on any
// failure (command missing, not on Android, unknown zone name), leaves
// time.Local untouched in that case.
func FixLocalTimezone() {
	out, err := runGetprop()
	if err != nil {
		return
	}
	zone := strings.TrimSpace(string(out))
	if zone == "" {
		return
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return
	}
	time.Local = loc
}

// runGetprop runs getprop, looking for it first in $PATH, then (Termux
// normally doesn't include /system/bin in its own PATH) at the standard
// Android absolute path, best-effort, silent if neither exists.
func runGetprop() ([]byte, error) {
	if _, err := safeexec.LookPath("getprop"); err == nil {
		return safeexec.Command("getprop", "persist.sys.timezone").Output()
	}
	const sysGetprop = "/system/bin/getprop"
	if fi, err := os.Stat(sysGetprop); err == nil && !fi.IsDir() {
		return safeexec.Command(sysGetprop, "persist.sys.timezone").Output()
	}
	return nil, errors.New("termuxenv: getprop not found")
}
