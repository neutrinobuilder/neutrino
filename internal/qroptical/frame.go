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

// Package qroptical generates and reconstructs a fountain-coded transfer
// (internal/fountain) over a sequence of animated QR codes, sender and
// receiver need no network: one screen cycles through QR frames, the other
// reads them with a camera until it has collected enough.
package qroptical

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"

	"neutrino/internal/fountain"
)

// frameEncoding is base32 (RFC4648, no padding) rather than base64:
// base32's alphabet (A-Z, 2-7) is a strict subset of the QR code
// standard's own "alphanumeric mode" character set (0-9, A-Z, space,
// $%*+-./:), so go-qrcode always encodes the whole frame as a single
// alphanumeric-mode segment, never byte mode. That is the densest
// encoding for the frame's content (5.5 bits per character instead of
// 8), and its decoding never depends on a character set.
var frameEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// framePrefix distinguishes a frame of this protocol from any QR code that
// ends up in the camera's field of view by mistake (e.g. an identity QR or
// another contact's), silently discarded by DecodeFrame, never a fatal
// error for the caller.
const framePrefix = "NQF1:"

// headerLen = TransferID(4) + TotalLen(4) + K(2) + BlockSize(2) + SymbolID(4).
const headerLen = 4 + 4 + 2 + 2 + 4

// DefaultBlockSize is the default block size: header(16) + data(120) = 136
// raw bytes, ~218 characters after base32 plus the prefix, comfortably
// within a moderate-version QR code (readable at typical webcam distance)
// while leaving margin for Medium error correction.
const DefaultBlockSize = 120

// EncodeFrame produces the text of a QR frame, pure ASCII (prefix +
// base32, see frameEncoding above), never raw bytes: the QR decoding
// library (gozxing) returns a Go string whose byte representation is not
// guaranteed identical to the original content for values beyond 7-bit
// ASCII (the same reason the contact list/backup already use base64 text
// in QR codes, not raw bytes, base32 here instead of base64 for the
// additional, frame-specific reason in frameEncoding's own comment).
func EncodeFrame(transferID, totalLen uint32, k, blockSize uint16, sym fountain.Symbol) string {
	buf := make([]byte, headerLen+len(sym.Data))
	binary.BigEndian.PutUint32(buf[0:4], transferID)
	binary.BigEndian.PutUint32(buf[4:8], totalLen)
	binary.BigEndian.PutUint16(buf[8:10], k)
	binary.BigEndian.PutUint16(buf[10:12], blockSize)
	binary.BigEndian.PutUint32(buf[12:16], sym.ID)
	copy(buf[16:], sym.Data)
	return framePrefix + frameEncoding.EncodeToString(buf)
}

// decodedFrame is a frame's content after parsing, fields kept separate
// from Symbol because TransferID/TotalLen/K/BlockSize are transfer
// metadata, not part of the fountain symbol itself.
type decodedFrame struct {
	transferID   uint32
	totalLen     uint32
	k, blockSize uint16
	sym          fountain.Symbol
}

// DecodeFrame inverts EncodeFrame. Returns an error for any text that isn't
// a frame of this protocol (missing prefix, invalid base32, truncated
// header, or data size inconsistent with blockSize), the caller
// (Receiver.AddFrameText) treats it as "ignore and continue", never as a
// fatal transfer error.
func decodeFrame(text string) (decodedFrame, error) {
	rest, ok := strings.CutPrefix(text, framePrefix)
	if !ok {
		return decodedFrame{}, errors.New("not a qroptical frame")
	}
	raw, err := frameEncoding.DecodeString(rest)
	if err != nil {
		return decodedFrame{}, errors.New("invalid base32")
	}
	if len(raw) <= headerLen {
		return decodedFrame{}, errors.New("truncated frame")
	}
	f := decodedFrame{
		transferID: binary.BigEndian.Uint32(raw[0:4]),
		totalLen:   binary.BigEndian.Uint32(raw[4:8]),
		k:          binary.BigEndian.Uint16(raw[8:10]),
		blockSize:  binary.BigEndian.Uint16(raw[10:12]),
	}
	symID := binary.BigEndian.Uint32(raw[12:16])
	data := raw[16:]
	if uint16(len(data)) != f.blockSize {
		return decodedFrame{}, errors.New("block size inconsistent with the header")
	}
	f.sym = fountain.Symbol{ID: symID, Data: data}
	return f, nil
}
