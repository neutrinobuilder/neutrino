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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"neutrino/internal/shared"
)

// TestSendRegistersPendingForKnownRecipients covers the reliable
// delivery queue's base case: a successful send to a known recipient
// (RegisterUser) stays tracked as unconfirmed until its ack arrives.
func TestSendRegistersPendingForKnownRecipients(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))

	if _, err := cli.Send(context.Background(), "ciao", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := cli.PendingCountFor("uid1"); got != 1 {
		t.Errorf("PendingCountFor(uid1): want 1, got %d", got)
	}
	if age, has := cli.OldestPendingAge(); !has || age < 0 {
		t.Errorf("OldestPendingAge: want a value, got has=%v age=%v", has, age)
	}
}

// TestSendBlockedByBackpressureDoesNotAdvanceState covers the pending
// slot cap (PendingSlotLimit): once the threshold toward a recipient is
// exceeded, a new Send must stop BEFORE touching ratchet/outMsgSeq, a
// blocked attempt must never consume a chain step for a message that
// wasn't even written to the wire.
func TestSendBlockedByBackpressureDoesNotAdvanceState(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))
	cli.SetPendingLimits(2, time.Hour, time.Hour, 0) // long backoff/escalation: irrelevant here

	for i := 0; i < 2; i++ {
		if _, err := cli.Send(context.Background(), "msg", nil); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}
	idxBefore := cli.senderMsgIdx
	seqBefore := cli.outMsgSeq

	_, err := cli.Send(context.Background(), "one message too many", nil)
	var bp *BackpressureError
	if !errors.As(err, &bp) {
		t.Fatalf("want *BackpressureError, got %v", err)
	}
	if !errors.Is(err, ErrPendingBackpressure) {
		t.Error("errors.Is(err, ErrPendingBackpressure) must be true")
	}
	if cli.senderMsgIdx != idxBefore || cli.outMsgSeq != seqBefore {
		t.Errorf("ratchet state advanced by a blocked Send: idx %d→%d, outMsgSeq %d→%d",
			idxBefore, cli.senderMsgIdx, seqBefore, cli.outMsgSeq)
	}
}

// TestSenderKeyDeliveriesDontBlockSend: a rotation in a room of six
// sends the new sender_key to every peer, each delivery pending until
// that peer acks; a chat message sent right after must still go out,
// only chat messages count toward the slot limit.
func TestSenderKeyDeliveriesDontBlockSend(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.SetPendingLimits(5, time.Hour, time.Hour, 0)
	for i := 0; i < 6; i++ {
		uid := fmt.Sprintf("uid%d", i)
		peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cli.RegisterSessionPub(uid, base64.StdEncoding.EncodeToString(peerPriv.PublicKey().Bytes()))
		cli.RegisterMLKEMPub(uid, randMLKEMPub(t))
		cli.RegisterUser(uid, fmt.Sprintf("peer%d", i), testIdentity(uid))
	}

	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}
	if got := cli.PendingCountFor("uid0"); got != 1 {
		t.Fatalf("sender_key delivery toward uid0 not pending: PendingCountFor=%d", got)
	}
	if _, err := cli.Send(context.Background(), "right after the rotation", nil); err != nil {
		t.Fatalf("Send after a rotation toward six peers: %v", err)
	}
}

// expectNoFrame fails if a frame arrives within a short window.
func expectNoFrame(t *testing.T, frames <-chan map[string]any, what string) {
	t.Helper()
	select {
	case f := <-frames:
		t.Fatalf("%s: unexpected frame %#v", what, f)
	case <-time.After(50 * time.Millisecond):
	}
}

// nextFrame returns the next captured frame or fails after 2s.
func nextFrame(t *testing.T, frames <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case f := <-frames:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("frame never arrived")
		return nil
	}
}

// TestSendSenderKeyReliableSkipsPeerServedByRotation: a peer that got
// the new sender_key from the rotation itself receives no second copy
// when the distribution retry asks again.
func TestSendSenderKeyReliableSkipsPeerServedByRotation(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))
	cli.RegisterSessionPub("uid1", randPub(t))
	cli.RegisterMLKEMPub("uid1", randMLKEMPub(t))

	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}
	if f := nextFrame(t, frames); f["type"] != "sender_key" {
		t.Fatalf("rotation frame: %#v, want a sender_key", f)
	}
	if err := cli.SendSenderKeyReliable(context.Background(), "uid1"); err != nil {
		t.Fatalf("SendSenderKeyReliable: %v", err)
	}
	expectNoFrame(t, frames, "retry after the rotation")
	if got := cli.PendingCountFor("uid1"); got != 1 {
		t.Errorf("PendingCountFor(uid1): %d, want 1 (the rotation's delivery only)", got)
	}
}

// TestSendSenderKeyReliableRespectsDeferral: a peer whose new
// sender_key was deferred by the rotation (backlog of the previous
// generation still unacknowledged) doesn't get it from the distribution
// retry either, only once the backlog is acknowledged.
func TestSendSenderKeyReliableRespectsDeferral(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))
	cli.RegisterSessionPub("uid1", randPub(t))
	cli.RegisterMLKEMPub("uid1", randMLKEMPub(t))

	msgID, err := cli.Send(context.Background(), "old generation", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	nextFrame(t, frames)
	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}
	expectNoFrame(t, frames, "rotation with a backlog")
	if err := cli.SendSenderKeyReliable(context.Background(), "uid1"); err != nil {
		t.Fatalf("SendSenderKeyReliable: %v", err)
	}
	expectNoFrame(t, frames, "retry while the delivery is deferred")

	if !cli.HandleAck("uid1", msgID) {
		t.Fatal("HandleAck: deferred sender_key not reported ready")
	}
	cli.FlushDeferredKeyDistributions(context.Background())
	if f := nextFrame(t, frames); f["type"] != "sender_key" {
		t.Fatalf("frame after the backlog ack: %#v, want the deferred sender_key", f)
	}
}

// TestSendSenderKeyReliableServesPeerMissedByRotation: a peer whose
// ML-KEM key was still unknown at rotation time is skipped by the
// rotation and served by the distribution retry, exactly once.
func TestSendSenderKeyReliableServesPeerMissedByRotation(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))
	cli.RegisterSessionPub("uid1", randPub(t))

	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}
	expectNoFrame(t, frames, "rotation toward a peer without ML-KEM key")

	cli.RegisterMLKEMPub("uid1", randMLKEMPub(t))
	if err := cli.SendSenderKeyReliable(context.Background(), "uid1"); err != nil {
		t.Fatalf("SendSenderKeyReliable: %v", err)
	}
	if f := nextFrame(t, frames); f["type"] != "sender_key" {
		t.Fatalf("retry frame: %#v, want a sender_key", f)
	}
	if err := cli.SendSenderKeyReliable(context.Background(), "uid1"); err != nil {
		t.Fatalf("second SendSenderKeyReliable: %v", err)
	}
	expectNoFrame(t, frames, "second retry")
}

// TestHandleAckClearsPendingEntry verifies that a received ack removes
// the recipient from the waiting list and, when it's the last one, the
// entire entry.
func TestHandleAckClearsPendingEntry(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))

	msgID, err := cli.Send(context.Background(), "ciao", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := cli.PendingCountFor("uid1"); got != 1 {
		t.Fatalf("PendingCountFor before the ack: want 1, got %d", got)
	}
	if cli.HandleAck("uid1", msgID) {
		t.Error("HandleAck reported a deferred sender_key ready with no rotation pending")
	}
	if got := cli.PendingCountFor("uid1"); got != 0 {
		t.Errorf("PendingCountFor after the ack: want 0, got %d", got)
	}
	if _, has := cli.OldestPendingAge(); has {
		t.Error("OldestPendingAge must be absent after the only pending message was confirmed")
	}
}

// TestUnregisterUserDropsPendingWaiter covers the reason UnregisterUser
// exists (see client.go): a member who left the room must not leave a
// message waiting forever, their departure counts as "confirmed by
// the others", never as a permanent stall.
func TestUnregisterUserDropsPendingWaiter(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))

	if _, err := cli.Send(context.Background(), "ciao", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	cli.UnregisterUser("uid1")
	if got := cli.PendingCountFor("uid1"); got != 0 {
		t.Errorf("PendingCountFor after UnregisterUser: want 0, got %d", got)
	}
	if _, has := cli.OldestPendingAge(); has {
		t.Error("OldestPendingAge must be absent after the only recipient left the room")
	}
}

// TestRetryDueResendsSameFrameVerbatim covers the queue's central design
// constraint: a retransmission resends EXACTLY the frame already written
// the first time (same ciphertext, same idx/kid/mseq), never a new
// ratchet step for a message still unconfirmed.
func TestRetryDueResendsSameFrameVerbatim(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))
	cli.SetPendingLimits(5, 10*time.Millisecond, time.Hour, 0)

	if _, err := cli.Send(context.Background(), "ciao", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var first map[string]any
	select {
	case first = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("first frame never arrived")
	}

	time.Sleep(20 * time.Millisecond) // exceeds the 10ms backoff set above
	if n := cli.RetryDue(context.Background()); n != 1 {
		t.Fatalf("RetryDue: want 1 retransmission, got %d", n)
	}

	var second map[string]any
	select {
	case second = <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("retransmitted frame never arrived")
	}

	for _, field := range []string{"text", "idx", "kid", "mseq", "msg_id"} {
		if first[field] != second[field] {
			t.Errorf("field %q differs between the original send and the retransmission: %#v vs %#v", field, first[field], second[field])
		}
	}

	// A second round, right after, must not retry: the just-doubled
	// backoff hasn't expired yet.
	if n := cli.RetryDue(context.Background()); n != 0 {
		t.Errorf("RetryDue right after a retransmission: want 0 (doubled backoff not expired), got %d", n)
	}
}

// TestRetryDueReencryptsPastTTL covers the message TTL: once an
// unacknowledged message is older than the TTL, RetryDue rotates the
// sender_key, sends the new key right away, and re-encrypts EVERY
// unacknowledged message under the new generation, in original order,
// with the same msg_id and mseq.
func TestRetryDueReencryptsPastTTL(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid1", "alice", testIdentity("uid1"))
	cli.RegisterSessionPub("uid1", randPub(t))
	cli.RegisterMLKEMPub("uid1", randMLKEMPub(t))
	cli.SetPendingLimits(5, time.Hour, time.Hour, 50*time.Millisecond)

	next := func() map[string]any {
		t.Helper()
		select {
		case f := <-frames:
			return f
		case <-time.After(2 * time.Second):
			t.Fatal("frame never arrived")
			return nil
		}
	}

	var orig []map[string]any
	for _, text := range []string{"one", "two"} {
		msgID, err := cli.Send(context.Background(), text, nil)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
		orig = append(orig, next())
		cli.HandleServerAck(msgID, uint64(len(orig)))
	}

	if n := cli.RetryDue(context.Background()); n != 0 {
		t.Fatalf("RetryDue within the TTL: %d retransmissions, want 0", n)
	}
	select {
	case f := <-frames:
		t.Fatalf("unexpected frame within the TTL: %#v", f)
	case <-time.After(20 * time.Millisecond):
	}

	time.Sleep(60 * time.Millisecond)
	cli.RetryDue(context.Background())

	if f := next(); f["type"] != "sender_key" || f["to_user_id"] != "uid1" {
		t.Fatalf("first frame after the TTL: %#v, want the new sender_key for uid1", f)
	}
	for i, o := range orig {
		f := next()
		if f["msg_id"] != o["msg_id"] || f["mseq"] != o["mseq"] {
			t.Errorf("re-encrypted #%d: msg_id/mseq %v/%v, want %v/%v", i, f["msg_id"], f["mseq"], o["msg_id"], o["mseq"])
		}
		if f["kid"] == o["kid"] || f["text"] == o["text"] {
			t.Errorf("re-encrypted #%d still under the old generation", i)
		}
		if f["idx"] != float64(i) {
			t.Errorf("re-encrypted #%d: idx %v, want %d", i, f["idx"], i)
		}
	}
	if got := cli.MessagesSinceRotation(); got != 2 {
		t.Errorf("MessagesSinceRotation after re-encrypting 2 messages: %d, want 2", got)
	}
	if got := cli.PendingCountFor("uid1"); got != 3 {
		t.Errorf("PendingCountFor(uid1): %d, want 3 (2 messages + the new sender_key)", got)
	}
}
