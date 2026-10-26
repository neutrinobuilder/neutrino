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

package shared

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/ulikunitz/xz"

	"neutrino/internal/i18n"
)

// NowTS returns the current instant in RFC3339 UTC format — generic
// timestamp used to sign messages/files (RelMsgSigPayload, DeviceSigMsg,
// PQCSigMsg...).
func NowTS() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// packRaw/packXZ mark the first byte of the plaintext produced by PackData.
// The pack happens BEFORE encryption, on the plaintext.
const (
	packRaw byte = 0x00
	packXZ  byte = 0x01
)

// PackData compresses data with LZMA2/XZ when strongCompression is true and
// the result is actually smaller than the original (otherwise falls back to
// raw, never worse than not compressing). The one-byte marker at the head of
// the result lets UnpackData exactly reverse the operation chosen here, with
// no need for prior coordination between sender and recipient. Used for
// file/contact-card transfer (ContentKey-per-relationship, symmetric
// encryption).
func PackData(data []byte, strongCompression bool) ([]byte, error) {
	if !strongCompression {
		return append([]byte{packRaw}, data...), nil
	}
	var buf bytes.Buffer
	buf.WriteByte(packXZ)
	w, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_pack_compress", err))
	}
	if _, err := w.Write(data); err != nil {
		return nil, errors.New(i18n.T("shared.err_pack_compress", err))
	}
	if err := w.Close(); err != nil {
		return nil, errors.New(i18n.T("shared.err_pack_compress", err))
	}
	if buf.Len() >= len(data)+1 {
		// LZMA2/XZ wasn't worth it (data already high-entropy, or payload
		// too small for the .xz container overhead to pay off) —
		// transparent fallback to raw, never worse than not compressing.
		return append([]byte{packRaw}, data...), nil
	}
	return buf.Bytes(), nil
}

// UnpackData reverses PackData based on the one-byte marker — correct
// regardless of how the sender set strongCompression, since the marker
// declares it explicitly.
func UnpackData(tagged []byte) ([]byte, error) {
	if len(tagged) == 0 {
		return nil, errors.New(i18n.T("shared.err_pack_empty"))
	}
	tag, body := tagged[0], tagged[1:]
	switch tag {
	case packRaw:
		return body, nil
	case packXZ:
		r, err := xz.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, errors.New(i18n.T("shared.err_pack_decompress", err))
		}
		plain, err := io.ReadAll(r)
		if err != nil {
			return nil, errors.New(i18n.T("shared.err_pack_decompress", err))
		}
		return plain, nil
	default:
		return nil, errors.New(i18n.T("shared.err_pack_unknown_tag"))
	}
}
