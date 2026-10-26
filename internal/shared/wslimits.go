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

// DefaultFileWarpChunkSizeKiB is the default of the "warp" preset for the
// file-transfer chunk size (see
// internal/config.Config.FileWarpChunkSizeKiBOrDefault, internal/client/tui).
// Lives here and not in internal/config because the server, which does not
// read config.json and knows nothing about a user's chosen presets, still
// needs it to compute an adequate WebSocket read limit (see
// MaxFileChunkWireBytes).
const DefaultFileWarpChunkSizeKiB = 64

// MaxFileChunkWireBytes computes the maximum size in bytes a file_chunk
// WebSocket frame (wsFileChunkFwd, internal/server/ws.go) can reach once
// rawChunkBytes bytes of ciphertext are base64-encoded, encoding/json does
// this automatically for []byte fields, inside the message's JSON envelope.
//
// Used to set websocket.Conn.SetReadLimit: the coder/websocket library's
// default is 32768 bytes (read.go: defaultReadLimit), insufficient for the
// default "warp" preset (64 KiB raw ≈ 87KB after base64 encoding), without
// this, the sender's connection closes with "StatusMessageTooBig" mid-transfer,
// right after the recipient accepts.
func MaxFileChunkWireBytes(rawChunkBytes int) int64 {
	base64Len := ((rawChunkBytes + 2) / 3) * 4
	const jsonEnvelopeOverhead = 1024 // type/from_user_id/transfer_id/seq/quotes/other frame fields
	return int64(base64Len + jsonEnvelopeOverhead)
}
