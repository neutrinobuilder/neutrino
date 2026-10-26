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
	"github.com/skip2/go-qrcode"
)

// PixelsPerModule is the size argument for go-qrcode's Image/WriteFile:
// a negative value means "this many pixels per module, whatever the
// version". A fixed total size divides unevenly across the modules of a
// large version, rendering some module rows/columns one pixel wider than
// others, which confuses the decoder's grid sampling.
const PixelsPerModule = -4

// EncodeVerified builds a QR for content at the given level and checks,
// by decoding its own render back, that it actually reads. Some contents
// fail to decode even from a pristine render: the data area can contain
// a block with the 1:1:3:1:1 proportions of a finder pattern, and when
// it lies above the real bottom-left finder, gozxing stops scanning
// with three confirmed candidates before ever reaching it. The failure
// depends only on content, level, version and mask, so it repeats on
// every render of that QR. A larger version for the same content places
// the data, and the mask, differently: EncodeVerified tries the
// automatically chosen version first, then each larger one up to 40,
// and returns the first that verifies — or the last attempt if none
// does, so the caller always has something to show.
func EncodeVerified(content string, level qrcode.RecoveryLevel) (*qrcode.QRCode, error) {
	q, err := qrcode.New(content, level)
	if err != nil {
		return nil, err
	}
	if verify(q, content) {
		return q, nil
	}
	last := q
	for v := q.VersionNumber + 1; v <= 40; v++ {
		candidate, cerr := qrcode.NewWithForcedVersion(content, v, level)
		if cerr != nil {
			continue
		}
		last = candidate
		if verify(candidate, content) {
			return candidate, nil
		}
	}
	return last, nil
}

// verify renders q at PixelsPerModule, decodes it in memory and compares
// the result with the original content — not just the absence of an
// error: Reed-Solomon can correct an error pattern into a different,
// self-consistent codeword, so a decode can succeed with the wrong text.
func verify(q *qrcode.QRCode, content string) bool {
	text, err := DecodeQRFromImage(q.Image(PixelsPerModule))
	return err == nil && text == content
}
