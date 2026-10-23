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

package transport

import (
	"strings"
	"testing"
)

func TestParseKind(t *testing.T) {
	cases := map[string]Kind{
		"":      KindTor,
		"tor":   KindTor,
		"TOR":   KindTor,
		" Tor ": KindTor,
		"i2p":   KindI2P,
		"I2P":   KindI2P,
	}
	for in, want := range cases {
		got, err := ParseKind(in)
		if err != nil {
			t.Fatalf("ParseKind(%q): unexpected error %v", in, err)
		}
		if got != want {
			t.Errorf("ParseKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseKindUnknown(t *testing.T) {
	if _, err := ParseKind("carrier-pigeon"); err == nil {
		t.Fatal("ParseKind: unknown network accepted without error")
	}
}

func TestLooksLikeI2PDestinationBlob(t *testing.T) {
	short := "example.b32.i2p"
	if looksLikeI2PDestinationBlob(short) {
		t.Errorf("looksLikeI2PDestinationBlob(%q): want false for a short address", short)
	}
	long := strings.Repeat("A", 520)
	if !looksLikeI2PDestinationBlob(long) {
		t.Error("looksLikeI2PDestinationBlob: want true for a 520-character blob")
	}
}

func TestI2PB64Encode(t *testing.T) {
	// bytes chosen to produce both '+' and '/' in standard base64 encoding.
	data := []byte{0xfb, 0xff, 0xbf}
	got := i2pB64Encode(data)
	if strings.ContainsAny(got, "+/") {
		t.Errorf("i2pB64Encode: the I2P alphabet must not contain '+' or '/': %q", got)
	}
}

func TestSanitizeSAMID(t *testing.T) {
	got := sanitizeSAMID("valid-ID_123 with spaces!")
	want := "valid-ID_123_with_spaces_"
	if got != want {
		t.Errorf("sanitizeSAMID = %q, want %q", got, want)
	}
}
