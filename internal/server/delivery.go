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
	"sync"
	"time"
)

// roomDelivery implements the server-side reliable delivery of a room's
// broadcast messages: a global sequence number (gseq) assigned on arrival,
// and for each KNOWN MEMBER of the room (stable root identityPub,
// RoomRegistry.MemberIdentities, never an ephemeral session userID) an
// independent FIFO queue (contactQueue) of messages not yet acknowledged
// by them. A member stays a recipient even while temporarily offline: the
// queue survives their disconnection and is delivered on reconnection
// (live, below, resolves whichever session is connected at this instant).
// Each server↔member pair lives on its own, the same "pairwise
// flattening" already used client-side for direct relationships (see
// pending.go): a slow or isolated member accumulates messages in its own
// queue without blocking or delaying anyone else, strict order for THEM
// still guaranteed by the FIFO (gseqs enter it in increasing order). No
// synchronization between different queues.
type roomDelivery struct {
	mu       sync.Mutex
	nextGSeq uint64
	queues   map[string]*contactQueue // root identityPub (string) → queue
	// live maps root identityPub → the session userID currently connected
	// for that identity, updated by SetLive/ClearLive (called from
	// roomState.ClaimIdentitySlot/ReleaseIdentitySlot, the same identity
	// already used for "one device per identity per room"). Absent = the
	// member is offline at this instant: Dispatch/RetryAndEvict leave the
	// entry queued without attempting delivery, never an error.
	live map[string]string

	// dispatched remembers, per msgID, the gseq already assigned, a
	// retransmission of the same msgID (the sender didn't receive its own
	// self-echo/self_relay_ack in time and retries, or re-encrypted it
	// under a new generation past the message TTL, pending.go) reuses the
	// same gseq instead of consuming a new one for an already-dispatched
	// message. Cleaned up in RetryAndEvict (dispatchDedupWindow, counted
	// from the latest Dispatch of that msgID), not needed beyond a retry's
	// useful lifetime.
	dispatched map[string]dispatchRecord
}

// dispatchRecord is roomDelivery.dispatched's entry.
type dispatchRecord struct {
	gseq uint64
	at   time.Time
}

// dispatchDedupWindow, past this age a dispatched entry is forgotten:
// wider than the typical retransmission backoffs (doubling
// deliveryRetryDelay), so it covers the common case without retaining
// memory for messages long since acknowledged or abandoned.
const dispatchDedupWindow = 5 * time.Minute

// relayItem is a broadcast message, already serialized with gseq included,
// awaiting ONE specific member's ack, each queue holds its own copy of
// data, replaced (under contactQueue.mu) only by a later Dispatch of the
// same msgID.
type relayItem struct {
	gseq            uint64
	msgID           string
	fromIdentityPub []byte // original sender (root identityPub), informational, to route any kick/cleanup
	data            []byte
	queuedAt        time.Time
	nextRetry       time.Time
	backoff         time.Duration
}

// contactQueue is ONE member's FIFO queue, items ordered by increasing
// gseq (insertion order always matches gseq order, since
// roomDelivery.Dispatch appends to all queues at the same moment it
// assigns the gseq).
type contactQueue struct {
	mu    sync.Mutex
	items []*relayItem
}

// deliveryRetryDelay, same scheme (20s doubling) already established
// client-side for the direct sender→recipient relationship
// (config.MessageRetryDelay), reused identically here for the server→contact
// last mile.
const deliveryRetryDelay = 20 * time.Second

func newRoomDelivery() *roomDelivery {
	return &roomDelivery{queues: make(map[string]*contactQueue)}
}

// SetLive registers that identityPub is now reachable at userID (connection
// just registered), called from roomState.ClaimIdentitySlot, the same
// root identity already used for "one device per identity per room". No-op
// if identityPub is empty.
func (rd *roomDelivery) SetLive(identityPub []byte, userID string) {
	if len(identityPub) == 0 {
		return
	}
	rd.mu.Lock()
	if rd.live == nil {
		rd.live = make(map[string]string)
	}
	rd.live[string(identityPub)] = userID
	rd.mu.Unlock()
}

// ClearLive removes identityPub from live ONLY if userID still owns it,
// same guard as roomState.ReleaseIdentitySlot: a more recent reconnection
// of the same identity may have already replaced the entry, a late release
// of the old session must not erase it. No-op if identityPub is empty.
func (rd *roomDelivery) ClearLive(identityPub []byte, userID string) {
	if len(identityPub) == 0 {
		return
	}
	rd.mu.Lock()
	key := string(identityPub)
	if rd.live[key] == userID {
		delete(rd.live, key)
	}
	rd.mu.Unlock()
}

// Dispatch assigns the next gseq (or reuses the one already assigned to
// msgID, see dispatched), builds the frame (buildFrame receives gseq and
// returns the JSON ready for that recipient, identical for everyone in
// this protocol, a single parameter instead of a per-recipient closure),
// queues it for each KNOWN member of the room in recipients (SENDER
// included, see below) and sends it right away to whoever is connected at
// this instant (live). Returns the assigned gseq.
//
// recipients is the list of known root identityPubs (RoomRegistry.
// MemberIdentities), not just those connected at this instant: an
// offline member still remains a recipient, the backlog is delivered to
// them on reconnection (RetryAndEvict, when they reappear in live),
// without this, a message arriving while a member is temporarily offline
// would be lost to them forever, with no fast-forward ever possible.
//
// The SENDER is a member like any other in its own queue: without this, a
// self-echo lost because its connection dies exactly between gseq
// assignment and delivery would never be retransmitted (unlike any other
// recipient), and the client's own retry would trigger a second Dispatch.
// The
// sender's queue empties via the "self_relay_ack" frame it sends to the
// server itself as soon as it recognizes its own self-echo
// (parseMessage/TakeSentText, see ws.go/tui.go), same mechanism as
// msg_ack, never a substitute.
func (rd *roomDelivery) Dispatch(hub *Hub, recipients [][]byte, msgID string, fromIdentityPub []byte, buildFrame func(gseq uint64) []byte) uint64 {
	rd.mu.Lock()
	var gseq uint64
	if msgID != "" {
		if rec, ok := rd.dispatched[msgID]; ok {
			gseq = rec.gseq
			rd.dispatched[msgID] = dispatchRecord{gseq: gseq, at: time.Now()}
		}
	}
	if gseq == 0 {
		rd.nextGSeq++
		gseq = rd.nextGSeq
		if msgID != "" {
			if rd.dispatched == nil {
				rd.dispatched = make(map[string]dispatchRecord)
			}
			rd.dispatched[msgID] = dispatchRecord{gseq: gseq, at: time.Now()}
		}
	}
	rd.mu.Unlock()

	data := buildFrame(gseq)
	now := time.Now()
	for _, idPub := range recipients {
		key := string(idPub)
		cq := rd.queueFor(key)
		cq.mu.Lock()
		duplicate := false
		for _, it := range cq.items {
			if it.msgID == msgID {
				// The latest frame for a msgID supersedes the queued one:
				// a copy re-encrypted under a new generation must replace
				// the ciphertext the recipient refused, keeping its gseq
				// and its place in the queue.
				zeroBytes(it.data)
				it.data = append([]byte(nil), data...)
				it.nextRetry = now.Add(deliveryRetryDelay)
				it.backoff = deliveryRetryDelay
				duplicate = true
				break
			}
		}
		if !duplicate {
			cq.items = append(cq.items, &relayItem{
				gseq:            gseq,
				msgID:           msgID,
				fromIdentityPub: append([]byte(nil), fromIdentityPub...),
				data:            append([]byte(nil), data...),
				queuedAt:        now,
				nextRetry:       now.Add(deliveryRetryDelay),
				backoff:         deliveryRetryDelay,
			})
		}
		cq.mu.Unlock()

		rd.mu.Lock()
		uid, ok := rd.live[key]
		rd.mu.Unlock()
		if ok {
			_ = hub.SendBytes(context.Background(), uid, append([]byte(nil), data...))
		}
	}
	zeroBytes(data)
	return gseq
}

// queueFor returns (creating it if absent) key's queue (root identityPub,
// as a string).
func (rd *roomDelivery) queueFor(key string) *contactQueue {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	cq, ok := rd.queues[key]
	if !ok {
		cq = &contactQueue{}
		rd.queues[key] = cq
	}
	return cq
}

// Ack removes identityPub's entry matching msgID, if present, called from
// ws.go when a msg_ack or self_relay_ack arrives from a member (its root
// identity, never its ephemeral session userID), before the ack is
// forwarded to the original sender.
func (rd *roomDelivery) Ack(identityPub []byte, msgID string) {
	key := string(identityPub)
	rd.mu.Lock()
	cq, ok := rd.queues[key]
	rd.mu.Unlock()
	if !ok {
		return
	}
	cq.mu.Lock()
	defer cq.mu.Unlock()
	for i, it := range cq.items {
		if it.msgID == msgID {
			zeroBytes(it.data)
			cq.items = append(cq.items[:i], cq.items[i+1:]...)
			return
		}
	}
}

// Forget removes identityPub's entire queue, called when a member is
// kicked for overload (the queue that caused the kick must not survive: a
// return starts from scratch, consistent with "no history") or banned
// (RemoveSecret, /grp-ban: no future delivery makes sense anymore).
func (rd *roomDelivery) Forget(identityPub []byte) {
	key := string(identityPub)
	rd.mu.Lock()
	cq, ok := rd.queues[key]
	delete(rd.queues, key)
	rd.mu.Unlock()
	if !ok {
		return
	}
	cq.mu.Lock()
	for _, it := range cq.items {
		zeroBytes(it.data)
	}
	cq.mu.Unlock()
}

// RetryAndEvict scans every queue: retransmits (verbatim, never a new
// frame) entries whose backoff has expired TO WHOEVER IS CONNECTED AT THIS
// INSTANT (live), an offline member stays queued with no delivery attempt,
// never an error, and kicks (hub.KickOverloaded + Forget) whoever has a
// queue that reached outboundQueueSize (only if currently connected: a
// long-offline member has no session to close, just Forget). Meant for a
// periodic ticker on server.RunOnListener's side, same principle already
// used for CleanupStaleSessions/ping.
func (rd *roomDelivery) RetryAndEvict(hub *Hub) {
	rd.mu.Lock()
	keys := make([]string, 0, len(rd.queues))
	for key := range rd.queues {
		keys = append(keys, key)
	}
	// Cleanup of dispatched (see dispatchDedupWindow) in the same pass:
	// without this the map would grow indefinitely, one entry per msgID
	// that ever passed through Dispatch.
	cutoff := time.Now().Add(-dispatchDedupWindow)
	for msgID, rec := range rd.dispatched {
		if rec.at.Before(cutoff) {
			delete(rd.dispatched, msgID)
		}
	}
	rd.mu.Unlock()

	now := time.Now()
	for _, key := range keys {
		cq := rd.queueFor(key)
		cq.mu.Lock()
		overloaded := len(cq.items) >= outboundQueueSize
		var due []*relayItem
		var dueData [][]byte
		if !overloaded {
			for _, it := range cq.items {
				if !now.Before(it.nextRetry) {
					due = append(due, it)
					dueData = append(dueData, append([]byte(nil), it.data...))
				}
			}
		}
		cq.mu.Unlock()

		rd.mu.Lock()
		uid, live := rd.live[key]
		rd.mu.Unlock()

		if overloaded {
			if live {
				hub.KickOverloaded(uid)
			}
			rd.Forget([]byte(key))
			continue
		}
		if !live {
			continue // stays queued: no recipient reachable right now
		}
		for i, it := range due {
			_ = hub.SendBytes(context.Background(), uid, dueData[i])
			cq.mu.Lock()
			it.backoff *= 2
			it.nextRetry = time.Now().Add(it.backoff)
			cq.mu.Unlock()
		}
	}
}
