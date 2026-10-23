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

// Package qrscan decodes QR codes from images — used by the TUI's
// /cnt-read-qrcode command and by `neutrino add-bridges`. Pure Go
// (github.com/makiuchi-d/gozxing), no system dependency.
package qrscan

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// DecodeQRFile decodes the first (only one expected) QR code found in a
// PNG/JPEG image on disk, returning the raw encoded text (for a contact's
// identity: the URI nu://username/base64pubkey[/mlkemPub[/mldsaPub]]). On
// Android, prefer DecodeQRImage directly on the file picker's reader: a
// fyne.URI chosen via Storage Access Framework isn't guaranteed to be a
// path openable with os.Open (content://...).
func DecodeQRFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening the file: %w", err)
	}
	defer f.Close()
	return DecodeQRImage(f)
}

// DecodeQRImage decodes the first QR code found by reading a PNG/JPEG
// image from any io.Reader (a local file, or a fyne.URIReadCloser from the
// Android file picker — no real filesystem path required).
func DecodeQRImage(r io.Reader) (string, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return "", fmt.Errorf("decoding the image: %w", err)
	}
	return DecodeQRFromImage(img)
}

// DecodeQRFromImage decodes the first QR code found in an already-decoded
// image.Image — factored out of DecodeQRImage so it's also reusable by
// callers that build the image by hand instead of reading it from a
// file/reader (see camera_linux.go: a webcam's YUYV frame is converted
// directly to image.Gray, never going through PNG/JPEG).
func DecodeQRFromImage(img image.Image) (string, error) {
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("reading the image: %w", err)
	}

	// TRY_HARDER disables the finder-pattern search's row-skipping
	// heuristic (which scales with image size, meant for a tight live
	// camera/screen frame) — without it, a high-resolution phone photo
	// (several thousand pixels wide, finder patterns only a small
	// fraction of the frame) can skip past the pattern entirely and
	// report no QR found at all, or misdetect a bogus one (seen as a
	// corrupt/out-of-range QR version). Slower, but DecodeQRFile/Image
	// only ever runs once per user action (file picker, camera frame),
	// never in a hot loop — worth the cost for reliability.
	//
	// CHARACTER_SET ISO-8859-1 makes byte-mode segments decode one byte to
	// one code point (U+0000-U+00FF) instead of going through gozxing's
	// charset guess (Shift-JIS/UTF-8/...), which can turn a byte into a
	// different number of characters. Alphanumeric and numeric segments
	// (go-qrcode uses them for long runs of digits/uppercase) decode to
	// ASCII either way, so the text keeps every segment in order.
	hints := map[gozxing.DecodeHintType]any{
		gozxing.DecodeHintType_TRY_HARDER:    true,
		gozxing.DecodeHintType_CHARACTER_SET: "ISO-8859-1",
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, hints)
	if err != nil {
		return "", fmt.Errorf("no QR code found in the image: %w", err)
	}
	return latin1Bytes(result.GetText()), nil
}

// latin1Bytes turns text decoded as ISO-8859-1 back into the original
// bytes, one per code point. A code point above U+00FF can only come from
// a segment not decoded as ISO-8859-1 (an explicit ECI marker, or Kanji
// mode — never in a QR this app generates): then the text is returned
// as is.
func latin1Bytes(text string) string {
	b := make([]byte, 0, len(text))
	for _, r := range text {
		if r > 0xFF {
			return text
		}
		b = append(b, byte(r))
	}
	return string(b)
}
