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
	"crypto/rand"
	"encoding/binary"
	"errors"

	"neutrino/internal/fountain"
)

// Sender generates a potentially infinite stream of QR frames for a fixed
// payload, the caller scans through it, showing each text as a QR code for
// a fixed time, in a loop, until manually stopped: there is no "end" signal
// in the protocol, the receiver stops on its own (Receiver.Done) once it
// has collected enough symbols.
type Sender struct {
	transferID uint32
	totalLen   uint32
	enc        *fountain.Encoder
	nextID     uint32
}

// NewSender prepares a Sender for data, split into blockSize-byte blocks
// (uses DefaultBlockSize if blockSize <= 0).
func NewSender(data []byte, blockSize int) (*Sender, error) {
	if blockSize <= 0 {
		blockSize = DefaultBlockSize
	}
	enc, err := fountain.NewEncoder(data, blockSize)
	if err != nil {
		return nil, err
	}
	if enc.K() > 1<<16-1 {
		return nil, errors.New("payload too large: increase blockSize or split it into several transfers")
	}
	var idBuf [4]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, err
	}
	return &Sender{
		transferID: binary.BigEndian.Uint32(idBuf[:]),
		totalLen:   uint32(len(data)),
		enc:        enc,
	}, nil
}

// K returns the transfer's number of source blocks, useful for the caller
// to estimate a minimum number of frames to show (K, plus a typical 10-40%
// margin depending on K, see internal/fountain.TestOverheadStaysReasonable)
// before expecting an attentive receiver to already have completed.
func (s *Sender) K() int { return s.enc.K() }

// NextFrame produces the text of the next QR frame, each call advances an
// internal counter, never the same ID twice within the same Sender.
func (s *Sender) NextFrame() string {
	id := s.nextID
	s.nextID++
	sym := s.enc.Next(id)
	return EncodeFrame(s.transferID, s.totalLen, uint16(s.enc.K()), uint16(s.enc.BlockSize()), sym)
}
