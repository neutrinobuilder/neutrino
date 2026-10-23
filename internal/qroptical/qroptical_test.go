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

package qroptical

import (
	"bytes"
	"image"
	"testing"

	"github.com/skip2/go-qrcode"

	"neutrino/internal/qrscan"
)

// TestSenderReceiverRoundTrip covers the purely logical path (no real QR
// image involved): Sender generates frames, Receiver accumulates them until
// Done().
func TestSenderReceiverRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("out-of-band file exchange "), 40) // ~1KB
	sender, err := NewSender(payload, 0)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}

	recv := NewReceiver()
	var frames int
	for !recv.Done() && frames < sender.K()*3+50 {
		recv.AddFrameText(sender.NextFrame())
		frames++
	}
	if !recv.Done() {
		t.Fatalf("Receiver not complete after %d frames (k=%d)", frames, sender.K())
	}
	if got := recv.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("round-trip corrupted")
	}
}

// TestRoundTripThroughRealQRImages checks that a frame's text survives a
// real QR round trip (text -> PNG -> image -> decode) using the same
// libraries already used elsewhere in the project for identity/backup/sync
// — direct proof that choosing pure ASCII (base32) over raw bytes in the
// frame loses nothing on the real camera path.
//
// A frame that gozxing fails to decode (observed empirically on a minority
// of frames, even at 512px — a limitation of the library pair in use, not
// introduced by this package) is simply discarded, exactly as
// ScanCameraContinuous would do with a blurry frame read from a real
// camera: this is precisely the case fountain coding exists to tolerate.
// The test therefore checks that the TEXT, whenever decoding succeeds, is
// always byte-for-byte identical to the original (no silent corruption) —
// not that every single frame always decodes.
func TestRoundTripThroughRealQRImages(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 1, 2, 3, 254, 255, 128, 127}, 40) // non-ASCII bytes in the original PAYLOAD
	sender, err := NewSender(payload, 0)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}

	recv := NewReceiver()
	decodeFailures := 0
	const maxAttempts = 500
	attempts := 0
	for ; !recv.Done() && attempts < maxAttempts; attempts++ {
		frameText := sender.NextFrame()

		png, err := qrcode.Encode(frameText, qrcode.Medium, 512)
		if err != nil {
			t.Fatalf("qrcode.Encode: %v", err)
		}
		img, _, err := image.Decode(bytes.NewReader(png))
		if err != nil {
			t.Fatalf("image.Decode: %v", err)
		}
		decodedText, err := qrscan.DecodeQRFromImage(img)
		if err != nil {
			decodeFailures++
			continue // "unreadable" frame: discarded, as with a real camera
		}
		if decodedText != frameText {
			t.Fatalf("the frame text doesn't survive the real QR round-trip:\nsent:  %q\nread:  %q", frameText, decodedText)
		}
		recv.AddFrameText(decodedText)
	}
	if !recv.Done() {
		t.Fatalf("Receiver not complete after %d attempts (k=%d, %d failed decodes)", attempts, sender.K(), decodeFailures)
	}
	if got := recv.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("round-trip corrupted through real QR codes")
	}
	t.Logf("k=%d, attempts=%d, failed decodes=%d", sender.K(), attempts, decodeFailures)
}

// TestReceiverIgnoresForeignQR checks that a QR code not belonging to this
// protocol (e.g. an identity URI) is silently discarded, without triggering
// a phantom transfer or a panic.
func TestReceiverIgnoresForeignQR(t *testing.T) {
	recv := NewReceiver()
	recv.AddFrameText("nu://alice/dGVzdHB1YmtleWJhc2U2NGVuY29kZWQ=")
	recv.AddFrameText("some other random text")
	recv.AddFrameText("")
	if recv.Started() {
		t.Fatalf("Started() = true after non-qroptical text only")
	}
	if recv.Done() {
		t.Fatalf("Done() = true after non-qroptical text only")
	}
}

// TestReceiverIgnoresDifferentTransfer checks that, once locked onto a
// transferID, the Receiver ignores frames from a different transfer (e.g. a
// second animated QR code that ended up in the same field of view by
// mistake) instead of corrupting the state of the one already in progress.
func TestReceiverIgnoresDifferentTransfer(t *testing.T) {
	payloadA := bytes.Repeat([]byte("A"), 500)
	payloadB := bytes.Repeat([]byte("B"), 500)
	senderA, err := NewSender(payloadA, 0)
	if err != nil {
		t.Fatalf("NewSender A: %v", err)
	}
	senderB, err := NewSender(payloadB, 0)
	if err != nil {
		t.Fatalf("NewSender B: %v", err)
	}

	recv := NewReceiver()
	recv.AddFrameText(senderA.NextFrame()) // locks onto transfer A
	for range 5 {
		recv.AddFrameText(senderB.NextFrame()) // all discarded: different transferID
	}
	for i := 0; !recv.Done() && i < senderA.K()*3+50; i++ {
		recv.AddFrameText(senderA.NextFrame())
	}
	if !recv.Done() {
		t.Fatalf("Receiver not complete for transfer A")
	}
	if got := recv.Bytes(); !bytes.Equal(got, payloadA) {
		t.Fatalf("round-trip: want payload A, got a mix or payload B")
	}
}

// TestDefaultBlockSizeUsedWhenZeroOrNegative covers NewSender's documented
// fallback.
func TestDefaultBlockSizeUsedWhenZeroOrNegative(t *testing.T) {
	for _, bs := range []int{0, -1} {
		s, err := NewSender([]byte("x"), bs)
		if err != nil {
			t.Fatalf("NewSender(blockSize=%d): %v", bs, err)
		}
		f, err := decodeFrame(s.NextFrame())
		if err != nil {
			t.Fatalf("decodeFrame: %v", err)
		}
		if int(f.blockSize) != DefaultBlockSize {
			t.Fatalf("blockSize=%d: used %d, want DefaultBlockSize=%d", bs, f.blockSize, DefaultBlockSize)
		}
	}
}
