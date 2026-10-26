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

package server

import (
	"encoding/json"
	"fmt"
	"sync"
)

// dbgMu/dbgFn — optional debug hook, same role as client.Dbg
// (internal/client/debug.go) but DEFINED HERE and not imported from there:
// internal/client (client_test.go/handshake_test.go) already imports
// internal/server for handshake end-to-end tests — a direct import of
// internal/client from this package would create a cycle ("import cycle not
// allowed in test"). The caller (cmd/main.go) wires
// SetDebug(client.Dbg) from outside both packages, where no cycle exists.
var (
	dbgMu sync.Mutex
	dbgFn func(msg string)
)

// SetDebug installs (or removes, with nil) this package's debug sink —
// receives an already-formatted line (never a format string, to avoid
// risking an unintended reinterpretation of '%' in the message).
// Thread-safe, no default: without an explicit call, dbg() is a silent
// no-op.
func SetDebug(fn func(msg string)) {
	dbgMu.Lock()
	dbgFn = fn
	dbgMu.Unlock()
}

// dbg emits a debug line if a sink is installed — see handleKnock, which
// uses it to make the KnockDHTag mutuality filter and any DecryptKnock
// failure visible (internal/client's `neutrino debug` mechanism only logs
// client-side, after a knock has already passed this filter).
func dbg(format string, args ...any) {
	dbgMu.Lock()
	fn := dbgFn
	dbgMu.Unlock()
	if fn == nil {
		return
	}
	fn(fmt.Sprintf(format, args...))
}

// dbgActive reports whether a sink is installed — used by the WS channel
// trace (hub.go) to avoid paying for fmt.Sprintf/json.Unmarshal on every
// frame when debug isn't active.
func dbgActive() bool {
	dbgMu.Lock()
	active := dbgFn != nil
	dbgMu.Unlock()
	return active
}

// shortUID returns the first 8 characters of a userID for logs — same
// convention as client.ShortUID, duplicated here because this package can't
// import internal/client (see the comment on dbgFn above).
func shortUID(uid string) string {
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}

// peekFrameType reads only the "type" field from an already-serialized
// frame, for the WS channel trace — never called when dbgActive() is false.
func peekFrameType(data []byte) string {
	var t struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(data, &t)
	return t.Type
}
