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
	"testing"
	"time"

	"neutrino/internal/shared"
)

// TestMessagesSinceRotationTracksSendAndResetsOnRotation covers the
// count-based rotation criterion (K messages per generation):
// MessagesSinceRotation advances with every successful Send and resets
// to 0 when RotateSenderKey fires.
func TestMessagesSinceRotationTracksSendAndResetsOnRotation(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, _ := newCapturingTestWSConn(t)
	cli.Conn = conn

	for i := 0; i < 3; i++ {
		if _, err := cli.Send(context.Background(), "msg", nil); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}
	if got := cli.MessagesSinceRotation(); got != 3 {
		t.Errorf("MessagesSinceRotation after 3 sends: want 3, got %d", got)
	}

	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}
	if got := cli.MessagesSinceRotation(); got != 0 {
		t.Errorf("MessagesSinceRotation after the rotation: want 0, got %d", got)
	}
}

// TestRotateSenderKeyDistributesImmediatelyWhenQueueEmpty covers the
// normal path: a peer with no pending messages immediately receives the
// new key, over the reliable delivery channel (frame numbered with
// msg_id, tracked in pending.out).
func TestRotateSenderKeyDistributesImmediatelyWhenQueueEmpty(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn

	peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cli.RegisterSessionPub("uid1", base64.StdEncoding.EncodeToString(peerPriv.PublicKey().Bytes()))
	cli.RegisterMLKEMPub("uid1", randMLKEMPub(t))

	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}

	select {
	case f := <-frames:
		if f["type"] != "sender_key" {
			t.Fatalf("want a type=sender_key frame, got %#v", f)
		}
		if f["to_user_id"] != "uid1" {
			t.Errorf("to_user_id: want uid1, got %v", f["to_user_id"])
		}
		if s, _ := f["msg_id"].(string); s == "" {
			t.Error("msg_id missing or empty on the sender_key frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no sender_key frame received")
	}

	if got := cli.PendingCountFor("uid1"); got != 1 {
		t.Errorf("PendingCountFor(uid1) after the distribution: want 1, got %d", got)
	}
}

// TestRotateSenderKeyDefersWhenPeerHasPendingMessages covers why
// RotateSenderKey doesn't distribute unconditionally: if the peer
// still has unconfirmed messages from the PREVIOUS generation, sending
// the new key right away would make it discard (on its side,
// StorePeerSenderKey) exactly the generation it still needs to decrypt
// the backlog. Distribution resumes only once that queue empties
// (FlushDeferredKeyDistributions).
func TestRotateSenderKeyDefersWhenPeerHasPendingMessages(t *testing.T) {
	cli := New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingTestWSConn(t)
	cli.Conn = conn

	peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cli.RegisterSessionPub("uid1", base64.StdEncoding.EncodeToString(peerPriv.PublicKey().Bytes()))
	cli.RegisterMLKEMPub("uid1", randMLKEMPub(t))
	cli.RegisterUser("uid1", "alice", testIdentity("uid1")) // known recipient, so Send tracks it in pending.out

	msgID, err := cli.Send(context.Background(), "ciao", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case <-frames: // drain the chat message frame
	case <-time.After(2 * time.Second):
		t.Fatal("chat message frame never arrived")
	}

	if err := cli.RotateSenderKey(context.Background()); err != nil {
		t.Fatalf("RotateSenderKey: %v", err)
	}

	select {
	case f := <-frames:
		t.Fatalf("sender_key should not go out right away toward a peer with a non-empty queue, got %#v instead", f)
	case <-time.After(200 * time.Millisecond):
	}

	// The queue toward uid1 empties: the original message's ack arrives
	// and reports the deferred key as ready to send.
	if !cli.HandleAck("uid1", msgID) {
		t.Fatal("HandleAck must report the deferred sender_key as ready once the queue toward uid1 is empty")
	}
	cli.FlushDeferredKeyDistributions(context.Background())

	select {
	case f := <-frames:
		if f["type"] != "sender_key" {
			t.Fatalf("want sender_key after the queue drained, got %#v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sender_key never sent after FlushDeferredKeyDistributions")
	}
}
