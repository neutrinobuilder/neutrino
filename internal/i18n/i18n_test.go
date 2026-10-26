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
	"testing"
	"time"
)

// TestFormatContactTimestampFixedWidth checks that every returned string
// always has the same width (ContactTimestampWidth), whether the day of
// the month is one or two digits, needed for the Contacts list's column
// alignment (tui.go:renderContactLine).
func TestFormatContactTimestampFixedWidth(t *testing.T) {
	orig := active
	t.Cleanup(func() { SetActive(orig) })
	SetActive(LangIT)

	singleDigitDay := time.Date(2026, time.September, 3, 9, 5, 0, 0, time.UTC)
	doubleDigitDay := time.Date(2026, time.September, 16, 17, 31, 0, 0, time.UTC)

	got1 := FormatContactTimestamp(singleDigitDay)
	got2 := FormatContactTimestamp(doubleDigitDay)
	if len([]rune(got1)) != ContactTimestampWidth {
		t.Errorf("width of %q = %d, want %d", got1, len([]rune(got1)), ContactTimestampWidth)
	}
	if len([]rune(got2)) != ContactTimestampWidth {
		t.Errorf("width of %q = %d, want %d", got2, len([]rune(got2)), ContactTimestampWidth)
	}
	if got1 != "set 03 09:05" {
		t.Errorf("FormatContactTimestamp(single-digit day) = %q, want %q", got1, "set 03 09:05")
	}
}

// TestContactTimestampPlaceholderWidth checks that the placeholder used
// for a never-probed contact has the same width as a real timestamp
// (ContactTimestampWidth), otherwise the online/seenByPeer dot column in
// the Contacts list would misalign (tui.go:renderContactLine).
func TestContactTimestampPlaceholderWidth(t *testing.T) {
	if len([]rune(ContactTimestampPlaceholder)) != ContactTimestampWidth {
		t.Errorf("width of %q = %d, want %d", ContactTimestampPlaceholder, len([]rune(ContactTimestampPlaceholder)), ContactTimestampWidth)
	}
}

func TestParseLang(t *testing.T) {
	cases := map[string]Lang{
		"it": LangIT,
		"en": LangEN,
		"fr": LangFR,
		"de": LangDE,
		"es": LangES,
		"ro": LangRO,
		"ru": LangRU,
		"":   LangEN,
		"xx": LangEN, // unrecognized value falls back to LangEN
	}
	for in, want := range cases {
		if got := ParseLang(in); got != want {
			t.Errorf("ParseLang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetActive(t *testing.T) {
	orig := active
	t.Cleanup(func() { SetActive(orig) })

	SetActive(LangEN)
	if active != LangEN {
		t.Fatal("SetActive: want LangEN after SetActive(LangEN)")
	}
	SetActive(LangIT)
	if active != LangIT {
		t.Fatal("SetActive: want LangIT after SetActive(LangIT)")
	}
}

func TestTUnknownKeyFallsBackToKeyItself(t *testing.T) {
	const key = "test.zzz_missing_key_12345"
	if got := T(key); got != key {
		t.Fatalf("T(%q) = %q, want the key itself as a safety net", key, got)
	}
}

func TestTFallsBackToEnglishWhenMissingInActive(t *testing.T) {
	orig := active
	t.Cleanup(func() { SetActive(orig) })

	register(LangEN, map[string]string{"test.solo_en": "english value"})
	SetActive(LangFR)
	if got := T("test.solo_en"); got != "english value" {
		t.Fatalf("T: want fallback to the English catalog, got %q", got)
	}
}

func TestTWithArgs(t *testing.T) {
	orig := active
	t.Cleanup(func() { SetActive(orig) })

	register(LangIT, map[string]string{"test.con_args": "valore: %d e %s"})
	SetActive(LangIT)
	if got := T("test.con_args", 42, "ciao"); got != "valore: 42 e ciao" {
		t.Fatalf("T with arguments: want 'valore: 42 e ciao', got %q", got)
	}
}
