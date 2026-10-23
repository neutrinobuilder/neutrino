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
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/skip2/go-qrcode"
)

// encodeQR generates a PNG containing a QR code with the given text — uses
// the same library the project already uses to generate the QR codes shown
// to the user (identity, backup, sync), here in the opposite direction to
// build test cases.
func encodeQR(t *testing.T, text string) []byte {
	t.Helper()
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		t.Fatalf("qrcode.Encode: %v", err)
	}
	return png
}

func TestDecodeQRImageRoundTrip(t *testing.T) {
	const want = "nu://alice/dGVzdHB1YmtleWJhc2U2NGVuY29kZWQxMjM0NTY="
	data := encodeQR(t, want)

	got, err := DecodeQRImage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeQRImage: %v", err)
	}
	if got != want {
		t.Fatalf("DecodeQRImage = %q, want %q", got, want)
	}
}

// TestDecodeQRFromImageRawBinaryContent: without an explicit charset,
// gozxing decodes byte-mode QR content through a GUESSED character set
// (Shift-JIS/UTF-8/...) when the QR carries no ECI marker — lossy for
// binary content. Every NTR3 chunk (backup/sync/identity) includes a
// 4-byte random session_id that can be any value 0x00-0xFF; a guessed
// charset can map one encoded byte to a DIFFERENT number of decoded
// bytes (e.g. a lone high-bit byte expanding into a multi-byte UTF-8
// sequence), corrupting the chunk with no decoding error.
// DecodeQRFromImage decodes as ISO-8859-1, one byte per code point, and
// maps the text back to the original bytes.
//
// Content shape mirrors a real NTR3 chunk: a short binary prefix (magic
// + part/total + random session_id, every value 0x00-0xFF possible),
// followed by a long mixed-case base64-ish payload.
func TestDecodeQRFromImageRawBinaryContent(t *testing.T) {
	header := []byte{'N', 'T', 'R', '3', 0x00, 0x03, 0xff, 0x8a, 0x01, 0x7e}
	payload := []byte("YQfzA3n9/mK2w8sTbVxE1z0pL6rNcHiJdB4oUgXkFvYqMtSePw5aR+hGl7uCjIy==ZQrL9mN3oP6bK1sT8vE0xH2fY4jG5")
	want := append(header, payload...)

	q, err := qrcode.New(string(want), qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	img := q.Image(-4)
	got, err := DecodeQRFromImage(img)
	if err != nil {
		t.Fatalf("DecodeQRFromImage: %v", err)
	}
	if got != string(want) {
		t.Fatalf("DecodeQRFromImage returned %d bytes != %d bytes encoded — byte-for-byte mismatch at the charset-guessing layer", len(got), len(want))
	}
}

func TestDecodeQRFromImageRoundTrip(t *testing.T) {
	const want = "hello neutrino"
	data := encodeQR(t, want)

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("image.Decode: %v", err)
	}

	got, err := DecodeQRFromImage(img)
	if err != nil {
		t.Fatalf("DecodeQRFromImage: %v", err)
	}
	if got != want {
		t.Fatalf("DecodeQRFromImage = %q, want %q", got, want)
	}
}

func TestDecodeQRFromImageNoQRCode(t *testing.T) {
	// A uniform white image contains no QR code.
	img := image.NewGray(image.Rect(0, 0, 64, 64))
	for y := range 64 {
		for x := range 64 {
			img.SetGray(x, y, color.Gray{Y: 255})
		}
	}

	if _, err := DecodeQRFromImage(img); err == nil {
		t.Fatal("DecodeQRFromImage: want an error on an image without a QR code")
	}
}

func TestDecodeQRImageInvalidData(t *testing.T) {
	if _, err := DecodeQRImage(bytes.NewReader([]byte("not an image"))); err == nil {
		t.Fatal("DecodeQRImage: want an error on non-image data")
	}
}

func TestDecodeQRFile(t *testing.T) {
	const want = "nu://bob/YW5vdGhlcnRlc3RwdWJrZXliYXNlNjQ="
	data := encodeQR(t, want)

	dir := t.TempDir()
	path := filepath.Join(dir, "qr.png")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := DecodeQRFile(path)
	if err != nil {
		t.Fatalf("DecodeQRFile: %v", err)
	}
	if got != want {
		t.Fatalf("DecodeQRFile = %q, want %q", got, want)
	}
}

func TestDecodeQRFileMissing(t *testing.T) {
	if _, err := DecodeQRFile(filepath.Join(t.TempDir(), "missing.png")); err == nil {
		t.Fatal("DecodeQRFile: want an error for a missing file")
	}
}

func TestDecodeQRFileNotAnImage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notimg.png")
	if err := os.WriteFile(path, []byte("garbage"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := DecodeQRFile(path); err == nil {
		t.Fatal("DecodeQRFile: want an error for a non-image file")
	}
}

// sanity check: png.Decode is registered (import _ "image/png" in the package)
func TestPNGDecoderRegistered(t *testing.T) {
	data := encodeQR(t, "x")
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
}
