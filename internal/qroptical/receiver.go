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

import "neutrino/internal/fountain"

// Receiver accumulates QR frames until it reconstructs the original
// payload. Not thread-safe: meant to be fed from a single goroutine (the
// camera read loop), consistent with how internal/qrscan.ScanCamera calls
// onFrame.
type Receiver struct {
	haveTransfer bool
	transferID   uint32
	dec          *fountain.Decoder
}

// NewReceiver creates an empty Receiver, ready to recognize the first
// transfer presented to it through AddFrameText.
func NewReceiver() *Receiver {
	return &Receiver{}
}

// AddFrameText processes the text of a frame just decoded from the camera.
// Silently ignores: text that isn't a frame of this protocol (e.g. an
// ordinary QR code that ended up in the field of view by mistake) and
// frames with a transferID different from the one first observed — a
// second sender/animated QR must not be able to corrupt a transfer already
// in progress.
func (r *Receiver) AddFrameText(text string) {
	f, err := decodeFrame(text)
	if err != nil {
		return
	}
	if !r.haveTransfer {
		r.haveTransfer = true
		r.transferID = f.transferID
		r.dec = fountain.NewDecoder(int(f.k), int(f.blockSize), int(f.totalLen))
	} else if f.transferID != r.transferID {
		return
	}
	r.dec.Add(f.sym)
}

// Started reports whether at least one valid frame has already been
// recognized — useful for a UI to distinguish "waiting for the first frame"
// from "transfer in progress, k blocks known so far".
func (r *Receiver) Started() bool { return r.haveTransfer }

// Done reports whether the payload has been fully reconstructed.
func (r *Receiver) Done() bool { return r.haveTransfer && r.dec.Done() }

// Progress returns (blocks known, total blocks) — (0,0) while Started() is
// still false. For a progress UI only.
func (r *Receiver) Progress() (known, total int) {
	if !r.haveTransfer {
		return 0, 0
	}
	return r.dec.Progress()
}

// Bytes returns the reconstructed payload — nil while Done() is still false.
func (r *Receiver) Bytes() []byte {
	if !r.Done() {
		return nil
	}
	return r.dec.Bytes()
}
