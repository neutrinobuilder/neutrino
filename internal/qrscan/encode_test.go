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

package qrscan

import (
	"testing"

	"github.com/skip2/go-qrcode"
)

// undecodableAtAutoVersion is a content whose automatically chosen QR
// (version 4, level M) contains a false finder pattern in its data area:
// its pristine render never decodes.
const undecodableAtAutoVersion = "nu://user/hepLDOvqPDO4JkhPAGvh7i0GN96jrQBupAnQC4aCv1I="

// TestEncodeVerifiedEscapesUndecodableRender: the plain encoding of
// undecodableAtAutoVersion doesn't read back, EncodeVerified returns a
// larger version that does, with the exact content.
func TestEncodeVerifiedEscapesUndecodableRender(t *testing.T) {
	plain, err := qrcode.New(undecodableAtAutoVersion, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeQRFromImage(plain.Image(PixelsPerModule)); err == nil {
		t.Fatal("test vector no longer fails at the automatic version: pick a new one")
	}

	q, err := EncodeVerified(undecodableAtAutoVersion, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	if q.VersionNumber <= plain.VersionNumber {
		t.Errorf("version %d, want larger than the automatic %d", q.VersionNumber, plain.VersionNumber)
	}
	text, err := DecodeQRFromImage(q.Image(PixelsPerModule))
	if err != nil {
		t.Fatalf("verified QR doesn't decode: %v", err)
	}
	if text != undecodableAtAutoVersion {
		t.Fatalf("decoded %q, want %q", text, undecodableAtAutoVersion)
	}
}

// TestEncodeVerifiedKeepsAutoVersionWhenItReads: a content that decodes
// at the automatic version keeps it.
func TestEncodeVerifiedKeepsAutoVersionWhenItReads(t *testing.T) {
	const content = "nu://user/abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq="
	plain, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	q, err := EncodeVerified(content, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	if q.VersionNumber != plain.VersionNumber {
		t.Errorf("version %d, want the automatic %d", q.VersionNumber, plain.VersionNumber)
	}
}

// TestDecodeKeepsMixedSegments: go-qrcode encodes long runs of
// digits/uppercase as alphanumeric or numeric segments between byte
// segments; decoding returns every segment in order, including raw
// bytes above 0x7F in the byte segments.
func TestDecodeKeepsMixedSegments(t *testing.T) {
	for _, content := range []string{
		"nu://singlefileuser//ff2PYBqROs+0HMAYDPSTJRFo3F0JEKHcDb4Ik1ZTQU=",
		"nu://user/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"\x00\xff\x80héllo" + "0123456789012345678901234567890123456789" + "\xfe\xc3\x28" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "\x01\x9f",
	} {
		q, err := qrcode.New(content, qrcode.Medium)
		if err != nil {
			t.Fatal(err)
		}
		text, err := DecodeQRFromImage(q.Image(PixelsPerModule))
		if err != nil {
			t.Fatalf("%q: %v", content, err)
		}
		if text != content {
			t.Errorf("decoded %q, want %q", text, content)
		}
	}
}
