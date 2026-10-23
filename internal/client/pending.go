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

package client

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"neutrino/internal/shared"
)

// ErrPendingBackpressure is returned by Send when too many messages
// remain unconfirmed BY THE SERVER (roomDelivery.Dispatch/wsMsgRelayAck)
// — see PendingSlotLimit (config.Config.PendingSlotLimit). Not
// per-recipient: the server handles the last mile toward each contact,
// so the sender only waits for the server's own pickup, a single
// channel. The caller (the UI) must block writing
// and show it to the user, never ignore it: the threshold is
// deliberately low (human conversation coherence, not a technical
// constraint).
var ErrPendingBackpressure = errors.New("pending_backpressure")

// BackpressureError — a distinct type (instead of just
// ErrPendingBackpressure) to stay recoverable by the caller with
// errors.As, never by parsing Error()'s text; Is satisfies
// errors.Is(err, ErrPendingBackpressure). Carries no UserID: backpressure
// applies to the server's single channel, not to a specific
// recipient (see the comment above).
type BackpressureError struct{}

func (e *BackpressureError) Error() string {
	return ErrPendingBackpressure.Error()
}

func (e *BackpressureError) Is(target error) bool {
	return target == ErrPendingBackpressure
}

// pendingOutMsg is a broadcast message already written to the wire but
// not yet picked up by the server (serverAcked) or, independently of
// that, not yet confirmed by every recipient that was a known member at
// send time (waiting). frame is the EXACT payload written — a
// retransmission within the message TTL resends it verbatim, never
// re-encrypts it: a new step of the same chain for a message the
// recipient might already have would create the kind of gap this queue
// exists to eliminate. Past the TTL, the message is re-encrypted under a
// NEW generation instead (reencryptExpired), keeping its msgID.
type pendingOutMsg struct {
	msgID       uint64
	frame       map[string]any
	src         *pendingSource // nil for a sender_key frame, never re-encrypted
	sentAt      time.Time      // last encryption — never touched by verbatim retransmissions, used for the TTL and the oldest unconfirmed message's age
	nextRetry   time.Time
	backoff     time.Duration // doubles on every successful retransmission
	serverAcked bool          // true once we recognize our own self-echo (parseMessage/TakeSentText, never a separate frame): the SERVER assigned a gseq and queued the message toward each recipient — from here on, last-mile delivery (retry included) is its responsibility, no longer ours. Unblocks backpressure/RetryDue; waiting below stays populated only for the UI (chatLine.ackedBy) and for RotateSenderKey, never to block writing.
	gseq        uint64        // room-global sequence number assigned by the server — 0 until serverAcked is true
	kid         string        // sender_key generation the message is encrypted under — empty for a sender_key frame itself
	waiting     map[string]bool
}

// pendingSource is what re-encrypting a chat message needs: its
// plaintext, reply reference, content-signing keys and its per-sender
// sequence number (mseq, kept across re-encryptions).
type pendingSource struct {
	text        string
	replyTo     uint64
	contentKeys map[string][]shared.RelSigningKey
	mseq        uint64
}

// pendingState groups the reliable-delivery queue's fields — not part
// of the main Client struct (client.go is already very large) but
// embedded by value into it, same package.
type pendingState struct {
	mu            sync.Mutex
	out           map[uint64]*pendingOutMsg
	slotLimit     int
	retryDelay    time.Duration
	escalationAge time.Duration
	// ttl — see reencryptExpired. Atomic: also read under peerMu
	// (expireOutEph), never under pending.mu.
	ttl atomic.Int64

	// deferredKeys — see Client.RotateSenderKey/deferKeyDistribution: a
	// new sender_key not yet sent to a peer because it still had
	// unconfirmed messages toward it at rotation time.
	deferredKeys map[string]deferredKeyDist

	// keyServed: peerID → keyID of the latest sender_key already written
	// to that peer or deferred for it (sendSenderKeyTo,
	// deferKeyDistribution) — SendSenderKeyReliable skips a peer whose
	// entry matches the current generation.
	keyServed map[string]string
}

// deferredKeyDist holds everything needed to send a deferred sender_key
// (sendSenderKeyTo) as soon as FlushDeferredKeyDistributions finds that
// peer's queue empty — key is an independent copy, zeroed after sending
// or when replaced by a more recent rotation.
type deferredKeyDist struct {
	pub      *ecdh.PublicKey
	mlkemPub *mlkem.EncapsulationKey768
	key      []byte
	keyID    string // keyID of key — messages already sent under it never hold the distribution back
}

// pendingDefaults mirrors config.Default() exactly — internal/client
// doesn't import internal/config (the caller, the UI, resolves the
// values from config.json and injects them via SetPendingLimits, the
// same principle already used for SenderKeyInterval/
// TUIParams.SenderKeyInterval): these remain the correct behavior even
// if SetPendingLimits is never called.
const (
	pendingDefaultSlotLimit     = 5
	pendingDefaultRetryDelay    = 20 * time.Second
	pendingDefaultEscalationAge = 90 * time.Second
	pendingDefaultTTL           = 3 * time.Minute
)

func newPendingState() pendingState {
	return pendingState{
		out:           make(map[uint64]*pendingOutMsg),
		slotLimit:     pendingDefaultSlotLimit,
		retryDelay:    pendingDefaultRetryDelay,
		escalationAge: pendingDefaultEscalationAge,
	}
}

// SetPendingLimits configures the reliable delivery's four parameters
// (config.json: pending_slot_limit, message_retry_delay,
// pending_escalation_age, message_ttl) — a value <= 0 leaves the current
// one unchanged (never a silent reset of a safety threshold).
func (c *Client) SetPendingLimits(slotLimit int, retryDelay, escalationAge, ttl time.Duration) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	if slotLimit > 0 {
		c.pending.slotLimit = slotLimit
	}
	if retryDelay > 0 {
		c.pending.retryDelay = retryDelay
	}
	if escalationAge > 0 {
		c.pending.escalationAge = escalationAge
	}
	if ttl > 0 {
		c.pending.ttl.Store(int64(ttl))
	}
}

// messageTTL returns the configured message TTL (pendingDefaultTTL until
// SetPendingLimits sets one).
func (c *Client) messageTTL() time.Duration {
	if d := time.Duration(c.pending.ttl.Load()); d > 0 {
		return d
	}
	return pendingDefaultTTL
}

// EscalationAge exposes the configured threshold for the "soft" warning
// in Console about the oldest unconfirmed message — used by the caller
// to decide when to show it, not by this package.
func (c *Client) EscalationAge() time.Duration {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	return c.pending.escalationAge
}

// knownMemberIDs is a snapshot of the recipients currently known in
// this room (members, maintained by RegisterUser/UnregisterUser) —
// used to decide both who must confirm a new send and whether writing
// must be blocked for backpressure.
func (c *Client) knownMemberIDs() []string {
	c.userMapMu.RLock()
	defer c.userMapMu.RUnlock()
	ids := make([]string, 0, len(c.members))
	for id := range c.members {
		ids = append(ids, id)
	}
	return ids
}

// pendingBlockedFor checks how many chat messages remain without the
// server's pickup (serverAcked==false) — if the total reaches the
// configured limit, writing must be blocked. A single channel, not one
// per recipient (see BackpressureError). sender_key deliveries (src ==
// nil) don't count: they are point-to-point frames the server never
// echoes back, so they stay unpicked until each recipient acks, and one
// per peer after a join or a rotation would fill the slots by
// themselves in a room of five or more.
func (c *Client) pendingBlockedFor() bool {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	if c.pending.slotLimit <= 0 {
		return false
	}
	n := 0
	for _, p := range c.pending.out {
		if p.src != nil && !p.serverAcked {
			n++
		}
	}
	return n >= c.pending.slotLimit
}

// registerPending tracks a message just written successfully — a no-op
// if there was no known recipient at send time (nothing to confirm,
// e.g. being alone in the room). kid is the sender_key generation of a
// chat message, empty for a sender_key frame; src is nil for a
// sender_key frame.
func (c *Client) registerPending(msgID uint64, frame map[string]any, recipients []string, kid string, src *pendingSource) {
	if len(recipients) == 0 {
		return
	}
	waiting := make(map[string]bool, len(recipients))
	for _, uid := range recipients {
		waiting[uid] = true
	}
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	c.pending.out[msgID] = &pendingOutMsg{
		msgID:     msgID,
		frame:     frame,
		src:       src,
		sentAt:    time.Now(),
		nextRetry: time.Now().Add(c.pending.retryDelay),
		backoff:   c.pending.retryDelay,
		waiting:   waiting,
		kid:       kid,
	}
}

// HandleServerAck records the server's pickup for msgID — called by the
// caller (the UI) as soon as it recognizes its own self-echo
// (parseMessage/TakeSentText), which travels in the same reliable
// per-contact queue as anyone else's (roomDelivery.Dispatch) and already
// carries the assigned gseq: releases backpressure/RetryDue — from here
// on, last-mile delivery toward each recipient is the server's
// responsibility, no longer ours. Doesn't touch waiting: that stays for
// the UI (chatLine.ackedBy) and for RotateSenderKey, fed only by
// HandleAck when the individual recipients' real acks arrive. gseq
// updates the entry — returns found=false if msgID is no longer
// pending.
func (c *Client) HandleServerAck(msgID, gseq uint64) (found bool) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	p, ok := c.pending.out[msgID]
	if !ok {
		return false
	}
	p.serverAcked = true
	p.gseq = gseq
	return true
}

// dropPendingWaiter removes userID from every pending message waiting
// on its ack — called by UnregisterUser when a member leaves the room:
// waiting for a confirmation from someone no longer present makes no
// sense anymore, and a message that was waiting only on them must be
// considered confirmed by the others. Any sender_key deferred for them
// is dropped too.
func (c *Client) dropPendingWaiter(userID string) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	for msgID, p := range c.pending.out {
		if p.waiting[userID] {
			delete(p.waiting, userID)
			if len(p.waiting) == 0 {
				delete(c.pending.out, msgID)
			}
		}
	}
	if d, ok := c.pending.deferredKeys[userID]; ok {
		zeroKey(d.key)
		delete(c.pending.deferredKeys, userID)
	}
	delete(c.pending.keyServed, userID)
}

// markKeyServed records that keyID has been written to peerID or
// deferred for it — see pendingState.keyServed.
func (c *Client) markKeyServed(peerID, keyID string) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	if c.pending.keyServed == nil {
		c.pending.keyServed = make(map[string]string)
	}
	c.pending.keyServed[peerID] = keyID
}

// keyServedFor reports whether keyID has already been written to peerID
// or deferred for it.
func (c *Client) keyServedFor(peerID, keyID string) bool {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	return c.pending.keyServed[peerID] == keyID
}

// resetKeyServedOnConnect forgets every peer the current sender_key was
// written to, keeping only the deferred ones: after a new connection
// our session userID is new, and peers learn its mapping to our keyID
// from the sender_key sent again at init. A deferred peer gets the
// deferred key once its backlog is acknowledged, never earlier.
func (c *Client) resetKeyServedOnConnect() {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	for peerID := range c.pending.keyServed {
		if _, deferred := c.pending.deferredKeys[peerID]; !deferred {
			delete(c.pending.keyServed, peerID)
		}
	}
}

// forgetKeyServed drops peerID's keyServed entry — used when a peer's
// session userID is superseded by a reconnect.
func (c *Client) forgetKeyServed(peerID string) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	delete(c.pending.keyServed, peerID)
}

// deferKeyDistribution defers sending a sender_key to peerID — see
// Client.RotateSenderKey. Silently replaces any earlier deferred
// distribution still waiting for the same peer (zeroing its key): can
// only happen if a second rotation fires before the first ever reached
// that peer, in which case only the latest generation makes sense to
// deliver.
func (c *Client) deferKeyDistribution(peerID string, pub *ecdh.PublicKey, mlkemPub *mlkem.EncapsulationKey768, key []byte, keyID string) {
	kcopy := append([]byte(nil), key...)
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	if c.pending.deferredKeys == nil {
		c.pending.deferredKeys = make(map[string]deferredKeyDist)
	}
	if old, ok := c.pending.deferredKeys[peerID]; ok {
		zeroKey(old.key)
	}
	c.pending.deferredKeys[peerID] = deferredKeyDist{pub: pub, mlkemPub: mlkemPub, key: kcopy, keyID: keyID}
	if c.pending.keyServed == nil {
		c.pending.keyServed = make(map[string]string)
	}
	c.pending.keyServed[peerID] = keyID
}

// dropSupersededKeys forgets every sender_key still pending or deferred
// toward peerID — called right before sending it a newer one
// immediately (rotateSenderKeyLocked with deferBusy=false): a late
// retransmission of an older key would otherwise replace the newer one
// on their side.
func (c *Client) dropSupersededKeys(peerID string) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	for msgID, p := range c.pending.out {
		if p.src == nil && p.waiting[peerID] {
			delete(c.pending.out, msgID)
		}
	}
	if d, ok := c.pending.deferredKeys[peerID]; ok {
		zeroKey(d.key)
		delete(c.pending.deferredKeys, peerID)
	}
}

// reencryptExpired handles a chat message still unacknowledged by some
// connected recipient past the message TTL: the recipient may have
// refused it (e.g. a DH ephemeral of theirs no longer retained, see
// DecryptMsg) and will keep refusing the same ciphertext, and its chain
// can't skip ahead. The sender_key is rotated, the new key sent to every
// peer right away, and EVERY unacknowledged chat message re-encrypted
// under the new generation, in original order, with the same msgID and
// mseq — the server keeps its gseq, a recipient that already had it
// recognizes the msgID. Caller must hold sendMu.
func (c *Client) reencryptExpired(ctx context.Context) {
	ttl := c.messageTTL()
	now := time.Now()
	c.pending.mu.Lock()
	expired := false
	var stale []*pendingOutMsg
	for _, p := range c.pending.out {
		if p.src == nil || len(p.waiting) == 0 {
			continue
		}
		stale = append(stale, p)
		if now.Sub(p.sentAt) >= ttl {
			expired = true
		}
	}
	c.pending.mu.Unlock()
	if !expired {
		return
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].src.mseq < stale[j].src.mseq })

	Dbg("pending: %d unacknowledged messages past the TTL (%s) → new generation", len(stale), ttl)
	if err := c.rotateSenderKeyLocked(ctx, false); err != nil {
		return
	}
	n := uint64(0)
	for _, p := range stale {
		s, err := c.sealOut(p.msgID, p.src)
		if err != nil {
			continue
		}
		c.rememberSentText(p.msgID, p.src.text, p.src.replyTo)
		if err := c.writeJSON(ctx, s.frame); err != nil {
			// The rest keeps its old ciphertext and expired sentAt: the
			// next round rotates again and re-encrypts it.
			return
		}
		c.commitOut(s)
		n++
		c.pending.mu.Lock()
		p.frame = s.frame
		p.kid = s.kid
		p.sentAt = time.Now()
		p.backoff = c.pending.retryDelay
		p.nextRetry = p.sentAt.Add(p.backoff)
		p.serverAcked = false
		c.pending.mu.Unlock()
	}
	// Re-encrypted messages count toward the new generation's message
	// budget (MessagesSinceRotation) like new ones.
	c.peerMu.Lock()
	if c.outMsgSeq >= n {
		c.lastRotationSeq = c.outMsgSeq - n
	}
	c.peerMu.Unlock()
}

// FlushDeferredKeyDistributions sends every deferred sender_key whose
// peer now has no pending messages of an earlier generation — messages
// already encrypted under the deferred key itself are ignored: the peer
// can't decrypt (and so never acks) them before receiving that key.
// Meant to be called from the same periodic cycle as RetryDue (a
// tea.Tick in the TUI), the same principle, the same cadence.
func (c *Client) FlushDeferredKeyDistributions(ctx context.Context) {
	c.pending.mu.Lock()
	var ready []struct {
		peerID string
		d      deferredKeyDist
	}
	for peerID, d := range c.pending.deferredKeys {
		if c.pendingBeforeGenLocked(peerID, d.keyID) == 0 {
			ready = append(ready, struct {
				peerID string
				d      deferredKeyDist
			}{peerID, d})
			delete(c.pending.deferredKeys, peerID)
		}
	}
	c.pending.mu.Unlock()
	if len(ready) == 0 {
		return
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	for _, r := range ready {
		c.sendSenderKeyTo(ctx, r.peerID, r.d.pub, r.d.mlkemPub, r.d.key)
		zeroKey(r.d.key)
	}
}

// pendingBeforeGenLocked counts the messages still unconfirmed by
// userID that are not encrypted under the generation keyID — the caller
// must already hold pending.mu (used by FlushDeferredKeyDistributions).
func (c *Client) pendingBeforeGenLocked(userID, keyID string) int {
	n := 0
	for _, p := range c.pending.out {
		if p.waiting[userID] && p.kid != keyID {
			n++
		}
	}
	return n
}

// HandleAck records fromUserID's confirmation for msgID — called by
// the UI layer when a msg_ack frame arrives, in addition to updating
// its own view (chatLine.ackedBy): the
// bookkeeping that decides backpressure and retransmission lives here,
// the mere representation for the user lives there.
//
// It reports whether this ack leaves a deferred sender_key toward
// fromUserID ready to send: the caller then runs
// FlushDeferredKeyDistributions right away (off its own frame loop, since
// that writes to the connection) instead of waiting for the next periodic
// cycle.
func (c *Client) HandleAck(fromUserID string, msgID uint64) bool {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	p, ok := c.pending.out[msgID]
	if !ok {
		return false
	}
	delete(p.waiting, fromUserID)
	if len(p.waiting) == 0 {
		delete(c.pending.out, msgID)
	}
	d, deferred := c.pending.deferredKeys[fromUserID]
	return deferred && c.pendingBeforeGenLocked(fromUserID, d.keyID) == 0
}

// RetryDue first re-encrypts the unacknowledged messages if one is past
// the message TTL (reencryptExpired), then retransmits (verbatim, the
// same frame, never a new ratchet step) every message still waiting on
// at least one ack whose backoff has expired — meant to be called
// periodically by the caller (a tea.Tick in the TUI), the same
// principle already used for runSenderKeyRotationLoop. Returns how many
// messages were retransmitted this round (0 is normal when there's
// nothing to retry). Shares sendMu with Send/RotateSenderKey: no
// concurrent writes on the same connection.
func (c *Client) RetryDue(ctx context.Context) int {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.reencryptExpired(ctx)

	now := time.Now()
	c.pending.mu.Lock()
	var due []*pendingOutMsg
	for _, p := range c.pending.out {
		if !p.serverAcked && !now.Before(p.nextRetry) {
			due = append(due, p)
		}
	}
	c.pending.mu.Unlock()

	retried := 0
	for _, p := range due {
		if err := c.writeJSON(ctx, p.frame); err != nil {
			continue // will retry next round, backoff unchanged on a write failure
		}
		c.pending.mu.Lock()
		p.backoff *= 2
		p.nextRetry = time.Now().Add(p.backoff)
		c.pending.mu.Unlock()
		retried++
	}
	return retried
}

// OldestPendingAge returns how long the oldest unconfirmed message has
// been waiting, and whether there's at least one — used by the caller
// to decide when to show Console's soft warning (PendingEscalationAge).
func (c *Client) OldestPendingAge() (time.Duration, bool) {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	var oldest time.Time
	found := false
	for _, p := range c.pending.out {
		if p.serverAcked {
			continue
		}
		if !found || p.sentAt.Before(oldest) {
			oldest = p.sentAt
			found = true
		}
	}
	if !found {
		return 0, false
	}
	return time.Since(oldest), true
}

// PendingCountFor returns how many messages remain unconfirmed toward
// userID — used by the caller for the backpressure UI (e.g. showing
// which specific contact a write block is due to).
func (c *Client) PendingCountFor(userID string) int {
	c.pending.mu.Lock()
	defer c.pending.mu.Unlock()
	n := 0
	for _, p := range c.pending.out {
		if p.waiting[userID] {
			n++
		}
	}
	return n
}

func fmtBackpressureErr() error {
	return &BackpressureError{}
}
