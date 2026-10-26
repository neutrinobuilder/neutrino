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
	"bytes"
	"sync"
	"time"

	"neutrino/internal/shared"
)

// roomState is the hub + session store for a single room.
type roomState struct {
	hub      *Hub
	sessions *SessionStore

	// delivery is this room's server-side reliable delivery queue for
	// broadcast messages (gseq + per-contact queue, see delivery.go),
	// lives for the same duration as hub/sessions, zeroed together with
	// them when the room empties out (releaseRoomIfEmptyLocked).
	delivery *roomDelivery

	// slotMu/slots enforce "one device per identity per room", key
	// string(root identityPub, STABLE, never the one that rotates), value
	// the device+session currently occupying that slot. Dedicated lock
	// (not RoomRegistry.mu): this structure lives for the duration of the
	// runtime room, read/written by every incoming/outgoing connection
	// independently of operations on secrets (Add/Replace/RemoveSecret),
	// which stay under RoomRegistry.mu.
	slotMu sync.Mutex
	slots  map[string]identitySlot
}

// identitySlot registers which session currently occupies an identity's
// slot in a room, see roomState.ClaimIdentitySlot.
type identitySlot struct {
	userID    string
	devicePub []byte
}

// ClaimIdentitySlot enforces "one device per identity per room": if a
// DIFFERENT device of the same identityPub already occupies the slot,
// rejects (ok=false), the caller (ws.go) must close the just-arrived
// connection without registering it, never let it in. If the slot is free,
// or occupied by the SAME device (same devicePub, a genuine reconnection:
// new session user_id, same physical device), claims it for userID and
// returns a non-empty evictUserID when a previous session already existed
// and needs to be explicitly replaced (Hub.conns is keyed by userID: a new
// userID doesn't overwrite the old one in the Hub's map on its own, it must
// be kicked). Also registers identityPub as reachable at userID in
// rs.delivery (SetLive), roomDelivery.Dispatch/RetryAndEvict use it to
// know who to immediately deliver the backlog to for a member who just
// (re)connected. Empty identityPub (should never happen for a real member,
// but missing data must never block a connection) → no enforcement,
// always ok, and no registration in live (SetLive is a no-op on an empty
// identity). devicePub compared byte-by-byte: both empty counts as "same
// device" (defensive case, no information to distinguish them,
// better to not reject than to wrongly reject).
func (rs *roomState) ClaimIdentitySlot(identityPub, devicePub []byte, userID string) (evictUserID string, ok bool) {
	if len(identityPub) == 0 {
		return "", true
	}
	key := string(identityPub)
	rs.slotMu.Lock()
	if rs.slots == nil {
		rs.slots = make(map[string]identitySlot)
	}
	existing, has := rs.slots[key]
	if has && !bytes.Equal(existing.devicePub, devicePub) {
		rs.slotMu.Unlock()
		return "", false
	}
	if has {
		evictUserID = existing.userID
	}
	rs.slots[key] = identitySlot{userID: userID, devicePub: append([]byte(nil), devicePub...)}
	rs.slotMu.Unlock()
	rs.delivery.SetLive(identityPub, userID)
	return evictUserID, true
}

// ReleaseIdentitySlot frees identityPub's slot ONLY if userID still owns
// it, a more recent reconnection of the SAME identity (already "evicted"
// by ClaimIdentitySlot above, with a new userID) may have already replaced
// this entry before the OLD session's disconnection defer gets here:
// without this check it would erase the new, just-registered session's
// slot instead of its own. Same guard applied to rs.delivery.ClearLive: a
// late release must not erase the already-replaced session from live.
func (rs *roomState) ReleaseIdentitySlot(identityPub []byte, userID string) {
	if len(identityPub) == 0 {
		return
	}
	key := string(identityPub)
	rs.slotMu.Lock()
	if cur, ok := rs.slots[key]; ok && cur.userID == userID {
		delete(rs.slots, key)
	}
	rs.slotMu.Unlock()
	rs.delivery.ClearLive(identityPub, userID)
}

// memberSecret is a valid secret for a room member, with an opaque label
// (the username assigned by whoever distributed the secret). The server
// never interprets label, it carries it along only so the application can
// override the username self-declared in ClientHello (see ws.go).
// identityPub is the peer's STABLE (root) identity; devicePub is the
// peer's device pubkey, both only informational here (no lookup uses
// them, see below).
//
// resolveKeys resolves LIVE, on every call, the PEER's
// IdentityKey-per-relationship (to verify ClientHello.Sig) and OUR OWN
// toward that same peer (to sign ServerHello.Sig), never a value cached at
// registration time, so a relationship rotation needs no refresh at any
// call site. Can be nil (the host's self-entry toward itself with a fixed
// ephemeral pair, or a caller that provides no resolver), treated as "no
// key available".
type memberSecret struct {
	secret      []byte
	label       string
	identityPub []byte
	devicePub   []byte
	resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)
}

// roomEntry groups all the valid secrets for the same room (roomID) and
// the shared runtime state, created lazily on the first successful
// connection.
type roomEntry struct {
	secrets []memberSecret
	state   *roomState
}

// RoomRegistry manages isolated chat rooms on a single server. Each room is
// identified by a stable roomID, not by the secret used to authenticate,
// multiple secrets (one per invited member) can authenticate toward the
// same room. Isolation between different rooms stays guaranteed by the HMAC
// room_proof computed on the specific secret presented.
type RoomRegistry struct {
	mu    sync.RWMutex
	rooms map[string]*roomEntry // roomID → entry
}

// NewRoomRegistry creates an empty registry.
func NewRoomRegistry() *RoomRegistry {
	return &RoomRegistry{
		rooms: make(map[string]*roomEntry),
	}
}

// AddSecret registers a valid secret for roomID (creates the entry if it
// doesn't exist). identityPub/devicePub are the peer's stable identity and
// device pubkey (nil for a caller that doesn't know them yet, e.g. the
// host's self-registration toward itself), only informational. resolveKeys
// can be nil (no key available), see memberSecret above.
func (r *RoomRegistry) AddSecret(roomID string, secret []byte, label string, identityPub []byte, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.rooms[roomID]
	if !ok {
		e = &roomEntry{}
		r.rooms[roomID] = e
	}
	e.secrets = append(e.secrets, memberSecret{secret: secret, label: label, identityPub: identityPub, devicePub: devicePub, resolveKeys: resolveKeys})
}

// ReplaceSecret removes oldSecret (if present) from roomID and adds
// newSecret, used when a member is re-invited: the previous secret stops
// authenticating instead of staying valid indefinitely. identityPub/
// devicePub/resolveKeys: see AddSecret.
func (r *RoomRegistry) ReplaceSecret(roomID string, oldSecret, newSecret []byte, label string, identityPub []byte, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.rooms[roomID]
	if !ok {
		e = &roomEntry{}
		r.rooms[roomID] = e
	}
	if len(oldSecret) > 0 {
		kept := e.secrets[:0]
		for _, ms := range e.secrets {
			if !bytes.Equal(ms.secret, oldSecret) {
				kept = append(kept, ms)
			}
		}
		e.secrets = kept
	}
	e.secrets = append(e.secrets, memberSecret{secret: newSecret, label: label, identityPub: identityPub, devicePub: devicePub, resolveKeys: resolveKeys})
}

// RemoveSecret permanently removes secret from roomID, if present, unlike
// ReplaceSecret (which substitutes it with a new one, for a re-invite)
// nothing takes its place here: whoever presents it can no longer
// authenticate toward this room until invited again with a fresh secret.
// Used by /grp-ban. Also releases the room's runtime state (see
// releaseRoomIfEmptyLocked) if, at this moment, it has no more active
// connections, in the edge case where this was also the last secret left,
// the entire entry is removed from the registry: a group banned down to
// the last member must not stay in RAM for the rest of the process's life.
func (r *RoomRegistry) RemoveSecret(roomID string, secret []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.rooms[roomID]
	if !ok {
		return
	}
	kept := e.secrets[:0]
	for _, ms := range e.secrets {
		if bytes.Equal(ms.secret, secret) {
			// Also forgets any backlog queued for this identity
			// (roomDelivery, see Dispatch/MemberIdentities): a member whose
			// only valid secret disappears must not remain a recipient,
			// connected or not.
			if e.state != nil && len(ms.identityPub) > 0 {
				e.state.delivery.Forget(ms.identityPub)
			}
			continue
		}
		kept = append(kept, ms)
	}
	e.secrets = kept
	r.releaseRoomIfEmptyLocked(roomID, e)
}

// releaseRoomIfEmptyLocked is the common body of ReleaseRoomIfEmpty and
// RemoveSecret, run under r.mu already held by the caller (Lock, not
// RLock), exists to be callable from RemoveSecret too, which already
// holds the same lock (a second Lock() from the same goroutine would
// deadlock, sync.Mutex isn't reentrant in Go). If the room still has
// active connections it does nothing (secrets and runtime state both stay
// intact); otherwise, if it has no valid secret left, the whole entry is
// removed from the registry (no way left to authenticate, the entry serves
// no purpose anymore); otherwise only the runtime state (hub+sessions,
// already empty with zero connections) is zeroed, secrets stay intact,
// GetOrCreateRoom lazily recreates an empty one on the next connection,
// exactly like for a room never yet used.
func (r *RoomRegistry) releaseRoomIfEmptyLocked(roomID string, e *roomEntry) {
	if e.state != nil && e.state.hub.ConnCount() > 0 {
		return
	}
	if len(e.secrets) == 0 {
		delete(r.rooms, roomID)
		return
	}
	e.state = nil
}

// ReleaseRoomIfEmpty releases roomID's runtime state if, at this moment, it
// has no more active connections, called from ws.go's message loop right
// after a member disconnects from a room (see releaseRoomIfEmptyLocked for
// the logic). No-op if roomID doesn't exist or still has active
// connections.
func (r *RoomRegistry) ReleaseRoomIfEmpty(roomID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.rooms[roomID]
	if !ok {
		return
	}
	r.releaseRoomIfEmptyLocked(roomID, e)
}

// KickMember forcibly disconnects userID from room roomID, if currently
// connected, see Hub.Kick for the mechanism. Returns false if the room
// doesn't have a runtime state yet (nobody ever connected) or the user
// isn't among the active connections right now: not an error, the caller
// removes the secret with RemoveSecret regardless.
func (r *RoomRegistry) KickMember(roomID, userID string) bool {
	r.mu.RLock()
	e, ok := r.rooms[roomID]
	r.mu.RUnlock()
	if !ok || e.state == nil {
		return false
	}
	// Resolves the root identity from userID (roomDelivery keeps the
	// queue per identity, not per session userID), if the session
	// has already disappeared on its own, there's no queue to forget here:
	// RemoveSecret (called together with this from BanMember) handles it
	// anyway via the removed secret's identityPub.
	if sess, ok := e.state.sessions.Get(userID); ok && len(sess.RootIdentityPub) > 0 {
		e.state.delivery.Forget(sess.RootIdentityPub)
	}
	return e.state.hub.Kick(userID)
}

// MemberIdentities returns the (stable) root identityPubs of all known
// members of roomID, deduped, excludes secrets with no known identityPub
// (defensive case, should never happen for a real member).
// Used by roomDelivery.Dispatch (ws.go) as the recipient list for a
// broadcast: a known member stays a recipient even while temporarily
// offline, see the comment on Dispatch. nil if roomID has no entry.
func (r *RoomRegistry) MemberIdentities(roomID string) [][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.rooms[roomID]
	if !ok {
		return nil
	}
	seen := make(map[string]bool, len(e.secrets))
	out := make([][]byte, 0, len(e.secrets))
	for _, ms := range e.secrets {
		if len(ms.identityPub) == 0 {
			continue
		}
		key := string(ms.identityPub)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ms.identityPub)
	}
	return out
}

// LookupSecret verifies the room_proof against all known secrets of all
// rooms. Returns the secret that produced a match, the roomID it belongs
// to, the associated label (empty if unassigned), the peer's root
// (stable) identityPub and devicePub (for ClaimIdentitySlot), the peer's
// IdentityKey-per-relationship (to verify ClientHello.Sig), and our own
// IdentityKey-per-relationship toward them (to sign ServerHello.Sig),
// resolved LIVE via memberSecret.resolveKeys, called here and not earlier,
// outside r.mu: no RoomRegistry lock stays held during resolution, which
// typically touches an independent lock (e.g. keystore.Keystore.mu).
// Compatible with the signature required by DoServerHandshake.
func (r *RoomRegistry) LookupSecret(nonceClient, proof []byte) (secret []byte, roomID string, label string, identityPub []byte, devicePub []byte, peerKey shared.RelPeerKey, mySigningKey shared.RelSigningKey, ok bool) {
	type candidate struct {
		roomID string
		ms     memberSecret
	}
	r.mu.RLock()
	var candidates []candidate
	for rid, e := range r.rooms {
		for _, ms := range e.secrets {
			candidates = append(candidates, candidate{roomID: rid, ms: ms})
		}
	}
	r.mu.RUnlock()

	for _, c := range candidates {
		if _, matched := shared.VerifyRoomProof(c.ms.secret, nonceClient, proof); matched {
			if c.ms.resolveKeys != nil {
				peerKey, mySigningKey, _ = c.ms.resolveKeys()
			}
			return c.ms.secret, c.roomID, c.ms.label, c.ms.identityPub, c.ms.devicePub, peerKey, mySigningKey, true
		}
	}
	return nil, "", "", nil, nil, shared.RelPeerKey{}, shared.RelSigningKey{}, false
}

// GetOrCreateRoom returns the room for the given roomID, creating it if it doesn't exist.
func (r *RoomRegistry) GetOrCreateRoom(roomID string) *roomState {
	r.mu.RLock()
	e, ok := r.rooms[roomID]
	var fastState *roomState
	if ok {
		fastState = e.state
	}
	r.mu.RUnlock()
	if fastState != nil {
		return fastState
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok = r.rooms[roomID]
	if !ok {
		e = &roomEntry{}
		r.rooms[roomID] = e
	}
	if e.state == nil {
		e.state = &roomState{hub: NewHub(), sessions: NewSessionStore(), delivery: newRoomDelivery()}
	}
	return e.state
}

// CleanupStaleSessions removes, across all rooms, the sessions that
// SessionStore.CleanupStale considers idle for more than timeout, a
// backup safety net, not the primary cleanup mechanism: that remains the
// per-connection ping/pong watchdog (ws.go, handleWS, a failed ping
// cancels ctx, which unblocks the message loop and triggers the defer that
// already calls room.sessions.Remove) and covers almost all normal
// disconnection cases, clean or silent, on its own. This exists only for a
// session whose removal via defer never fired for some reason. Returns
// the total number of sessions removed across all rooms.
func (r *RoomRegistry) CleanupStaleSessions(timeout time.Duration) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	removed := 0
	for _, e := range r.rooms {
		if e.state != nil {
			removed += e.state.sessions.CleanupStale(timeout)
		}
	}
	return removed
}

// RetryDelivery runs roomDelivery.RetryAndEvict on every room with active
// runtime state, meant for a periodic ticker on RunOnListener's side,
// same cadence as the retry cycle already used client-side
// (retryPendingInterval, tui.go) to stay consistent with the same backoff.
func (r *RoomRegistry) RetryDelivery() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.rooms {
		if e.state != nil {
			e.state.delivery.RetryAndEvict(e.state.hub)
		}
	}
}

// TotalSessions counts the active sessions across all rooms.
func (r *RoomRegistry) TotalSessions() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, e := range r.rooms {
		if e.state != nil {
			n += e.state.sessions.Count()
		}
	}
	return n
}
