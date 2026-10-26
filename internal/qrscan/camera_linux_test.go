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

//go:build linux && !android

package qrscan

import (
	"testing"

	"github.com/blackjack/webcam"
)

func TestPickFormatPrefersYUYV(t *testing.T) {
	formats := map[webcam.PixelFormat]string{
		v4l2PixFmtYUYV:  "YUYV",
		v4l2PixFmtMJPEG: "MJPG",
	}
	format, isYUYV := pickFormat(formats)
	if format != v4l2PixFmtYUYV || !isYUYV {
		t.Fatalf("pickFormat = (%v, %v), want (YUYV, true)", format, isYUYV)
	}
}

func TestPickFormatFallsBackToMJPEG(t *testing.T) {
	formats := map[webcam.PixelFormat]string{
		v4l2PixFmtMJPEG: "MJPG",
	}
	format, isYUYV := pickFormat(formats)
	if format != v4l2PixFmtMJPEG || isYUYV {
		t.Fatalf("pickFormat = (%v, %v), want (MJPEG, false)", format, isYUYV)
	}
}

func TestPickFormatNoneUsable(t *testing.T) {
	formats := map[webcam.PixelFormat]string{
		0xdeadbeef: "unknown",
	}
	format, isYUYV := pickFormat(formats)
	if format != 0 || isYUYV {
		t.Fatalf("pickFormat = (%v, %v), want (0, false)", format, isYUYV)
	}
}

func TestYUYVToGrayExtractsLuminance(t *testing.T) {
	// 2x1 YUYV: two pixels, 4 bytes Y0 U Y1 V.
	frame := []byte{10, 128, 200, 128}
	img := yuyvToGray(frame, 2, 1)
	if img.Bounds().Dx() != 2 || img.Bounds().Dy() != 1 {
		t.Fatalf("bounds = %v, want 2x1", img.Bounds())
	}
	if got := img.GrayAt(0, 0).Y; got != 10 {
		t.Fatalf("pixel(0,0) = %d, want 10", got)
	}
	if got := img.GrayAt(1, 0).Y; got != 200 {
		t.Fatalf("pixel(1,0) = %d, want 200", got)
	}
}

func TestYUYVToGrayMultiRow(t *testing.T) {
	// 2x2 YUYV: two rows of 4 bytes each.
	frame := []byte{
		1, 0, 2, 0, // row 0: Y=1,2
		3, 0, 4, 0, // row 1: Y=3,4
	}
	img := yuyvToGray(frame, 2, 2)
	want := [2][2]uint8{{1, 2}, {3, 4}}
	for y := range 2 {
		for x := range 2 {
			if got := img.GrayAt(x, y).Y; got != want[y][x] {
				t.Fatalf("pixel(%d,%d) = %d, want %d", x, y, got, want[y][x])
			}
		}
	}
}

func TestYUYVToGrayTruncatedFrame(t *testing.T) {
	// Frame shorter than expected for 2x2: the missing rows stay black
	// (zero), no panic for index out of range.
	frame := []byte{5, 0, 6, 0} // only the first row
	img := yuyvToGray(frame, 2, 2)
	if got := img.GrayAt(0, 0).Y; got != 5 {
		t.Fatalf("pixel(0,0) = %d, want 5", got)
	}
	if got := img.GrayAt(0, 1).Y; got != 0 {
		t.Fatalf("pixel(0,1) = %d, want 0 (truncated row)", got)
	}
}

func TestVideoDevicePathsNoPanic(t *testing.T) {
	// Test environment with no guaranteed webcam: only checks that it
	// doesn't panic and returns a list (even empty) with no glob error.
	paths, err := videoDevicePaths()
	if err != nil {
		t.Fatalf("videoDevicePaths: %v", err)
	}
	_ = paths
}
