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

// "&& !android": GOOS=android also satisfies the "linux" constraint (same
// reason internal/tornode must exclude it explicitly in its own
// embed_linux_*.go files). Without this exclusion, this file would still
// end up compiled into the Android APK, where it makes no sense (no
// V4L2/dev/video* access without root) and would never be reached anyway:
// camera QR reading on Android goes through an entirely separate path
// (Camera2 via JNI).

package qrscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"path/filepath"
	"sort"

	"github.com/blackjack/webcam"
)

// V4L2 FourCC codes (v4l2_fourcc(a,b,c,d) = a | b<<8 | c<<16 | d<<24, same
// as the linux/videodev2.h header), blackjack/webcam doesn't predefine
// them by name (webcam.PixelFormat is a raw uint32, discovered only at
// runtime via GetSupportedFormats), the same pattern used in its official
// examples.
const (
	v4l2PixFmtYUYV  webcam.PixelFormat = 0x56595559 // 'YUYV'
	v4l2PixFmtMJPEG webcam.PixelFormat = 0x47504A4D // 'MJPG'
)

// ScanCamera captures frames from the first available V4L2 webcam
// (/dev/video*) and tries to decode a QR code from each one, until it
// finds a valid code or ctx expires. onFrame, if not nil, is called with
// EVERY captured frame (even before attempting to decode it), meant for a
// live preview on the caller's side (see internal/client/tui,
// cmdReadQRCamera): called on the same goroutine as this function, never
// blocking for the caller, who should route it to a non-blocking
// buffer/channel (as cmdReadQRCamera actually does, blocking here would
// slow down capture itself).
//
// Pure Go (github.com/blackjack/webcam, no "import \"C\"", only ioctl
// calls via golang.org/x/sys/unix), no external process, consistent
// with the project's single-binary, no-external-service design, and
// compatible with CGO_ENABLED=0 (static binaries, portable across
// distributions).
//
// Prefers YUYV (uncompressed, the Y channel is already pure luminance,
// extracted directly without going through any image library) over MJPEG
// (compressed; some UVC webcams omit the standard Huffman tables from the
// stream, which the standard library's image/jpeg does not synthesize on
// its own, avoiding MJPEG when not needed removes one decoding failure
// mode).
func ScanCamera(ctx context.Context, onFrame func(image.Image)) (string, error) {
	var result string
	stopAtFirst := func(text string) bool {
		result = text
		return true
	}
	if err := scanCameraLoop(ctx, onFrame, stopAtFirst); err != nil {
		return "", err
	}
	return result, nil
}

// ScanCameraContinuous captures frames from the first available V4L2
// webcam and decodes EVERY QR code found, unlike ScanCamera, it doesn't
// stop at the first one: calls onDecoded for each successfully decoded QR
// text, until onDecoded returns true (done) or ctx expires. Meant for a
// stream of animated QR codes (see internal/qroptical): the same frame,
// read repeatedly while it stays on screen, produces multiple onDecoded
// calls with the same text, deduplicating is the caller's responsibility
// (qroptical.Receiver already does it via its own symbol ID).
func ScanCameraContinuous(ctx context.Context, onFrame func(image.Image), onDecoded func(text string) (done bool)) error {
	return scanCameraLoop(ctx, onFrame, onDecoded)
}

// scanCameraLoop is the core shared by ScanCamera/ScanCameraContinuous:
// tries each /dev/video* in order, stopping at the first one that makes
// onDecoded return true.
func scanCameraLoop(ctx context.Context, onFrame func(image.Image), onDecoded func(text string) bool) error {
	paths, err := videoDevicePaths()
	if err != nil || len(paths) == 0 {
		return errors.New("no webcam found (no /dev/video*)")
	}
	var lastErr error
	for _, path := range paths {
		err := scanCameraDevice(ctx, path, onFrame, onDecoded)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// videoDevicePaths lists /dev/video* in order, using V4L2's standard
// naming scheme on Linux.
func videoDevicePaths() ([]string, error) {
	matches, err := filepath.Glob("/dev/video*")
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

// pickFormat chooses YUYV if available, otherwise MJPEG, see the comment
// on ScanCamera for why.
func pickFormat(formats map[webcam.PixelFormat]string) (format webcam.PixelFormat, isYUYV bool) {
	if _, ok := formats[v4l2PixFmtYUYV]; ok {
		return v4l2PixFmtYUYV, true
	}
	if _, ok := formats[v4l2PixFmtMJPEG]; ok {
		return v4l2PixFmtMJPEG, false
	}
	return 0, false
}

func scanCameraDevice(ctx context.Context, path string, onFrame func(image.Image), onDecoded func(text string) bool) error {
	cam, err := webcam.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer cam.Close()

	format, isYUYV := pickFormat(cam.GetSupportedFormats())
	if format == 0 {
		return fmt.Errorf("%s: no usable format (YUYV or MJPEG required)", path)
	}

	// Moderate resolution: enough to read a QR code at close range,
	// without overloading the CPU with the YUYV→greyscale conversion on
	// every frame. The driver can negotiate a different size if it
	// doesn't support exactly this one, the values ACTUALLY returned are
	// always used, never the requested ones.
	_, width, height, err := cam.SetImageFormat(format, 1280, 720)
	if err != nil {
		return fmt.Errorf("%s: setting the format: %w", path, err)
	}
	if err := cam.SetBufferCount(2); err != nil {
		return fmt.Errorf("%s: allocating buffers: %w", path, err)
	}
	if err := cam.StartStreaming(); err != nil {
		return fmt.Errorf("%s: starting streaming: %w", path, err)
	}
	defer cam.StopStreaming()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// Short timeout (1s) on a single frame: the ctx.Done() check above
		// stays responsive within that order of magnitude, no finer
		// timeout is needed.
		if err := cam.WaitForFrame(1); err != nil {
			if _, isTimeout := err.(*webcam.Timeout); isTimeout {
				continue
			}
			return fmt.Errorf("%s: waiting for frame: %w", path, err)
		}
		frame, err := cam.ReadFrame()
		if err != nil || len(frame) == 0 {
			continue // empty/malformed frame: the next one is almost always fine
		}

		var img image.Image
		if isYUYV {
			img = yuyvToGray(frame, width, height)
		} else {
			decoded, decErr := jpeg.Decode(bytes.NewReader(frame))
			if decErr != nil {
				continue // corrupt/partial MJPEG frame: retry with the next one
			}
			img = decoded
		}

		if onFrame != nil {
			onFrame(img)
		}

		if text, decErr := DecodeQRFromImage(img); decErr == nil {
			if onDecoded(text) {
				return nil
			}
		}
	}
}

// yuyvToGray extracts only the luminance channel (Y) from a YUYV frame,
// enough to read a QR code (black/white), avoiding any color conversion.
// YUYV layout: for each pixel pair, 4 bytes Y0 U Y1 V, pixel x's Y byte is
// always at position x*2 of the row, whether x is even or odd.
func yuyvToGray(data []byte, width, height uint32) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, int(width), int(height)))
	stride := int(width) * 2
	for y := 0; y < int(height); y++ {
		rowStart := y * stride
		if rowStart+stride > len(data) {
			break // truncated frame: the rest of the image stays black
		}
		row := data[rowStart : rowStart+stride]
		dst := img.Pix[y*img.Stride : y*img.Stride+int(width)]
		for x := range dst {
			dst[x] = row[x*2]
		}
	}
	return img
}
