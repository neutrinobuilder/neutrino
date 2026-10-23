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
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// hubWriteTimeout limits how long ONE peer's dedicated write goroutine can
// stay blocked on a single Write — a dead but not-yet-detected connection
// (Tor dropped without a clean RST, for example) must not keep that
// goroutine busy forever: after the timeout the write fails, treated like
// any other write error (see writeLoop: the peer is removed from the hub).
const hubWriteTimeout = 15 * time.Second

// outboundQueueSize: how many frames can stay queued toward ONE single
// peer before subsequent ones are dropped instead of making the producer
// wait — ample for a room's real traffic (control frames + file chunks in
// a sliding window, never thousands in flight at once toward the same
// peer).
const outboundQueueSize = 256

// statusQueueOverloaded is the WS close code dedicated to the kick for a
// saturated delivery queue (roomDelivery, see delivery.go) — RFC 6455
// private range (4000-4999), never websocket.StatusPolicyViolation: that
// one is reserved for /grp-ban (Hub.Kick below) and is interpreted by
// ws.go as "banned" for every other member. An overload kick revokes no
// secret — the peer can reconnect right away, resuming delivery of the
// backlog like any other reconnection.
const statusQueueOverloaded = websocket.StatusCode(4001)

// outConn pairs a connection with its dedicated write goroutine and the
// queue that feeds it — see the comment on Hub for why this indirection
// exists instead of writing directly.
type outConn struct {
	conn   *websocket.Conn
	outCh  chan []byte
	hub    *Hub
	userID string
}

// Hub manages active WebSocket connections and routes messages between them.
//
// Every registered peer has a dedicated write goroutine (outConn.writeLoop),
// instead of being written to directly by the goroutine that generates the
// frame (the per-connection "message loop" in ws.go, which reads an
// incoming frame from the SENDER and forwards it before reading the next
// one). Writing in-line and synchronously would mean a peer slow to read (a
// congested Tor circuit — the cost is round-trip latency, not payload size)
// blocks that goroutine until the write completes, and with it reading the
// NEXT frame from the same sender — any frame, not just the one addressed
// to the slow peer: a second transfer started while the first is still
// delivering to a slow peer would stall, indistinguishable to the user from
// a general app freeze, even for a tiny transfer (a contact card, a few
// hundred bytes). Routing every write through a dedicated per-connection
// goroutine decouples the two: a slow peer only fills its own queue
// (non-blocking drop past outboundQueueSize), never another peer's queue
// nor the frame-producing goroutine. Frame order toward the SAME peer stays
// guaranteed (required for the SenderKey ratchet, which needs messages from
// the same sender in order) because each outConn has a single FIFO queue
// and a single writer.
type Hub struct {
	mu    sync.RWMutex
	conns map[string]*outConn
}

func NewHub() *Hub {
	return &Hub{conns: make(map[string]*outConn)}
}

func (h *Hub) Register(userID string, conn *websocket.Conn) {
	oc := &outConn{conn: conn, outCh: make(chan []byte, outboundQueueSize), hub: h, userID: userID}
	go oc.writeLoop()
	h.mu.Lock()
	h.conns[userID] = oc
	h.mu.Unlock()
}

// Unregister removes userID and closes its write queue, ending writeLoop
// once the already-queued frames have been drained. Idempotent: if userID
// isn't (no longer) registered it does nothing — both that connection's
// read loop (ws.go, on disconnection) and writeLoop itself (on the first
// write error, below) may call it for the same peer, only the first of the
// two has any effect.
func (h *Hub) Unregister(userID string) {
	h.mu.Lock()
	oc, ok := h.conns[userID]
	delete(h.conns, userID)
	h.mu.Unlock()
	if ok {
		close(oc.outCh)
	}
}

// writeLoop writes toward this single peer in arrival order, on a goroutine
// independent from whoever generates the frames — see the comment on Hub
// for why. Independent context for every write (never the original
// caller's, which may no longer exist by this point) — same principle
// already used elsewhere in this file for disconnection-related
// broadcasts. A write error (dead connection or timeout) removes the peer
// from the hub right away, instead of waiting for its read loop to notice
// on its own — faster, and also covers the case where that read loop stays
// blocked waiting for a frame that will never arrive from a connection
// already effectively dead on the write side.
func (oc *outConn) writeLoop() {
	for data := range oc.outCh {
		active := dbgActive()
		var ft string
		if active {
			ft = peekFrameType(data)
		}
		wctx, cancel := context.WithTimeout(context.Background(), hubWriteTimeout)
		err := oc.conn.Write(wctx, websocket.MessageText, data)
		cancel()
		zeroBytes(data)
		if active {
			dbg("ws_trace: wrote type=%q to uid=%s… err=%v", ft, shortUID(oc.userID), err)
		}
		if err != nil {
			oc.hub.Unregister(oc.userID)
			// Unregister has already closed oc.outCh (under the same lock
			// that removed oc from the map, so no new enqueue can reach it
			// anymore) — but frames already queued BEFORE this error stay
			// in the channel buffer, never written or zeroed: only the
			// frame that just failed got zeroed above, the others (e.g.
			// during a burst of file chunks) would stay unzeroed on the
			// heap until garbage collection, contradicting zeroBytes's
			// stated goal ("sensitive payload bytes do not linger"). Drains
			// and zeroes the rest before exiting, without trying to write
			// it: the connection is already considered dead.
			for leftover := range oc.outCh {
				zeroBytes(leftover)
			}
			return
		}
	}
}

// enqueue queues data — exclusively owned by this call from here on, the
// caller must not touch it anymore — toward oc, never blocking: a full
// queue means the peer is too slow to keep up, the frame is dropped
// (zeroed either way) instead of making the producer wait, same treatment
// as a frame lost on the network for protocols that already tolerate
// loss/duplication (ack+resume for file chunks; for an isolated control
// frame, equivalent to a network blip).
func enqueue(oc *outConn, data []byte) {
	active := dbgActive()
	var ft string
	if active {
		ft = peekFrameType(data)
	}
	select {
	case oc.outCh <- data:
		if active {
			dbg("ws_trace: queued type=%q to uid=%s… queue=%d/%d", ft, shortUID(oc.userID), len(oc.outCh), cap(oc.outCh))
		}
	default:
		if active {
			dbg("ws_trace: DROPPED (queue full) type=%q to uid=%s… queue=%d/%d", ft, shortUID(oc.userID), len(oc.outCh), cap(oc.outCh))
		}
		zeroBytes(data)
	}
}

// Broadcast sends v as JSON to all connections except excludeUserID.
// Use this for control frames (init, user_joined, user_left, server_shutdown)
// that do not carry ciphertext — message payloads go through roomDelivery's
// per-member queues instead, never a Hub-level broadcast.
// ctx is not used for the actual write (see writeLoop).
func (h *Hub) Broadcast(ctx context.Context, v any, excludeUserID string) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.broadcastRaw(data, excludeUserID)
}

func (h *Hub) broadcastRaw(data []byte, excludeUserID string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, oc := range h.conns {
		if id == excludeUserID {
			continue
		}
		enqueue(oc, append([]byte(nil), data...))
	}
	zeroBytes(data)
}

// MulticastBytes sends pre-serialized JSON to the connections listed in
// userIDs only, then zeros data. Used for file-transfer chunks: the
// sender uploads the blob once, the hub fans it out to the accepted
// recipients.
func (h *Hub) MulticastBytes(ctx context.Context, userIDs []string, data []byte) {
	h.multicastRaw(data, userIDs)
}

func (h *Hub) multicastRaw(data []byte, userIDs []string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, id := range userIDs {
		if oc, ok := h.conns[id]; ok {
			enqueue(oc, append([]byte(nil), data...))
		}
	}
	zeroBytes(data)
}

// Send sends v as JSON to a single connection.
// Use this for control frames that do not carry ciphertext. The returned
// error only covers serialization: the actual delivery is asynchronous
// (see writeLoop) and existing callers discard its outcome anyway.
func (h *Hub) Send(ctx context.Context, userID string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	// enqueue INSIDE the critical section, never after a separate
	// RUnlock: releasing the lock before enqueue opens a window where
	// another goroutine can call Unregister(userID) and close oc.outCh
	// right between the two operations — enqueue would then write to a
	// closed channel, an immediate panic ("send on closed channel"), not
	// interceptable from its own select/default. Same pattern already used
	// by broadcastRaw/multicastRaw above, applied here for consistency.
	h.mu.RLock()
	defer h.mu.RUnlock()
	oc, ok := h.conns[userID]
	if !ok {
		zeroBytes(data)
		return nil
	}
	enqueue(oc, data)
	return nil
}

// SendBytes sends pre-serialized JSON to a single connection; data passes
// into this function's exclusive ownership (it will be zeroed).
func (h *Hub) SendBytes(ctx context.Context, userID string, data []byte) error {
	// enqueue under the same RLock, never after — same reason as Send above.
	h.mu.RLock()
	defer h.mu.RUnlock()
	oc, ok := h.conns[userID]
	if !ok {
		zeroBytes(data)
		return nil
	}
	enqueue(oc, data)
	return nil
}

// Kick forcibly closes userID's connection, if currently registered —
// used by /grp-ban (host only). A dedicated close code
// (StatusPolicyViolation, never used elsewhere in this project) lets that
// connection's own read loop (ws.go, its own goroutine, not this call)
// distinguish "removed" from "connection lost"/"left voluntarily" in the
// user_left frame that its normal cleanup path transmits to everyone else
// regardless — no new frame on the wire, the same exact mechanism as any
// other disconnection. Returns false if the user isn't currently connected
// (already gone, or never online — the caller removes the secret
// separately regardless, see RoomRegistry.RemoveSecret, independent of
// this outcome).
func (h *Hub) Kick(userID string) bool {
	h.mu.RLock()
	oc, ok := h.conns[userID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	_ = oc.conn.Close(websocket.StatusPolicyViolation, "banned")
	return true
}

func (h *Hub) ConnCount() int {
	h.mu.RLock()
	n := len(h.conns)
	h.mu.RUnlock()
	return n
}

// KickOverloaded forcibly closes userID's connection with the dedicated
// overload code (statusQueueOverloaded), never StatusPolicyViolation — see
// the comment on that constant. Used by roomDelivery when the pending
// delivery queue toward a contact reaches outboundQueueSize: free
// reconnection, no secret revocation (unlike Kick above, reserved for
// /grp-ban).
func (h *Hub) KickOverloaded(userID string) bool {
	h.mu.RLock()
	oc, ok := h.conns[userID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	_ = oc.conn.Close(statusQueueOverloaded, "queue overloaded")
	return true
}

// zeroBytes overwrites b with zeros so sensitive payload bytes do not linger in heap.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
