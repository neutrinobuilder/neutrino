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

package i18n

import (
	"fmt"
	"time"
)

// ContactTimestampWidth is the fixed width (in runes) of every string
// returned by FormatContactTimestamp — "mmm dd hh:mm", 3+1+2+1+5 — used to
// align the column even when there's no real timestamp (see
// tui.go:renderContactLine).
const ContactTimestampWidth = 12

// ContactTimestampPlaceholder replaces FormatContactTimestamp's output
// when a contact has never been successfully probed — the same "mmm dd
// hh:mm" shape but with dashes, not just "--:--" padded with spaces: on
// screen, the two kinds of lines (a real timestamp and this placeholder)
// stay visually in the same shape, not just the same character width
// (already guaranteed, 12 as ContactTimestampWidth).
const ContactTimestampPlaceholder = "--- -- --:--"

// FormatContactTimestamp formats t as "Month Day HH:MM" — ONLY for the
// Contacts list, on both platforms. Different from shared.TimeLayout (used
// everywhere else in the app, the Tor log format with seconds/
// milliseconds, month always in English since Go's time.Format never
// localizes on its own) — here the month name instead follows Active(),
// resolved from the catalog (keys month.01..month.12, always 3 runes per
// language). Day always two digits (%02d, not %d): a constant width
// (ContactTimestampWidth) regardless of the day of the month, needed for
// the Contacts list's column alignment.
func FormatContactTimestamp(t time.Time) string {
	name := T(fmt.Sprintf("month.%02d", int(t.Month())))
	return fmt.Sprintf("%s %02d %02d:%02d", name, t.Day(), t.Hour(), t.Minute())
}
