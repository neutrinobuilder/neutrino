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

//go:build !linux || android

package qrscan

import (
	"context"
	"errors"
	"image"
)

// ScanCamera is not available outside of "desktop" Linux, V4L2 is a
// Linux-specific API, excluded here on Android too (which still satisfies
// the "linux" constraint, hence "!linux || android" rather than just
// "!linux"): camera QR reading there goes through an entirely separate
// path (Camera2 via JNI), not this package.
func ScanCamera(ctx context.Context, onFrame func(image.Image)) (string, error) {
	return "", errors.New("reading a QR code from the camera is only available on Linux")
}

// ScanCameraContinuous, same exclusion as ScanCamera outside of "desktop"
// Linux.
func ScanCameraContinuous(ctx context.Context, onFrame func(image.Image), onDecoded func(text string) (done bool)) error {
	return errors.New("reading a QR code from the camera is only available on Linux")
}
