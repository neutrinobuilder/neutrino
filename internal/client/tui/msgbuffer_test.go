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

package tui

import (
	"crypto/rand"
	"testing"

	"neutrino/internal/client"
	"neutrino/internal/shared"
)

// TestBufferMsgStoreAndTake covers the basic cycle: a frame buffered for
// (keyID, idx) is found again by takeBufferedMsg, and removed after being
// taken — a second take on the same idx finds nothing anymore.
func TestBufferMsgStoreAndTake(t *testing.T) {
	tab := &roomTab{}
	mm := map[string]any{"text": "ciphertext", "idx": float64(5)}

	bufferMsg(tab, "keyA", 5, mm)

	got, ok := takeBufferedMsg(tab, "keyA", 5)
	if !ok {
		t.Fatal("takeBufferedMsg: want ok=true for a frame just buffered")
	}
	if got["text"] != "ciphertext" {
		t.Errorf("takeBufferedMsg: frame differs from the buffered one, got %#v", got)
	}

	if _, ok := takeBufferedMsg(tab, "keyA", 5); ok {
		t.Error("a frame already taken must not be takeable a second time")
	}
}

// TestBufferMsgIndependentPerKeyID covers isolation between different
// senders in the same room — a gap on A's keyID must not interfere with
// B's.
func TestBufferMsgIndependentPerKeyID(t *testing.T) {
	tab := &roomTab{}
	bufferMsg(tab, "keyA", 3, map[string]any{"who": "a"})
	bufferMsg(tab, "keyB", 3, map[string]any{"who": "b"})

	a, ok := takeBufferedMsg(tab, "keyA", 3)
	if !ok || a["who"] != "a" {
		t.Errorf("takeBufferedMsg(keyA,3): want who=a, got %#v ok=%v", a, ok)
	}
	b, ok := takeBufferedMsg(tab, "keyB", 3)
	if !ok || b["who"] != "b" {
		t.Errorf("takeBufferedMsg(keyB,3): want who=b, got %#v ok=%v", b, ok)
	}
}

// TestBufferMsgRespectsCap covers the maxBufferedPerKey safety limit — a
// buggy or malicious sender declaring an idx far ahead must not be able to
// grow the buffer without bound.
func TestBufferMsgRespectsCap(t *testing.T) {
	tab := &roomTab{}
	for i := uint64(0); i < maxBufferedPerKey+10; i++ {
		bufferMsg(tab, "keyA", i, map[string]any{"idx": i})
	}
	if got := len(tab.msgBuffer["keyA"]); got != maxBufferedPerKey {
		t.Errorf("buffer size after exceeding the limit: want %d, got %d", maxBufferedPerKey, got)
	}
}

// TestTakeBufferedMsgUnknownKeyID covers the case where nothing has ever
// arrived for that keyID — must not panic on a nil map.
func TestTakeBufferedMsgUnknownKeyID(t *testing.T) {
	tab := &roomTab{}
	if _, ok := takeBufferedMsg(tab, "never-seen", 0); ok {
		t.Error("takeBufferedMsg on a never-buffered keyID must return ok=false")
	}
}

// TestHandleIncomingMessageUnlocksBufferedCascade covers the end-to-end
// behavior (not just the bufferMsg/takeBufferedMsg storage above): idx 0
// arrives and is processed right away; idx 2 arrives BEFORE its turn and is
// held back without being shown; idx 1 arrives, unlocks itself AND, in a
// cascade within the same round, the already-buffered idx 2 — a single
// handleIncomingMessage call for idx 1 must return BOTH "two" and "three" in
// order, never a fast-forward, never a loss.
func TestHandleIncomingMessageUnlocksBufferedCascade(t *testing.T) {
	senderKey := make([]byte, 32)
	if _, err := rand.Read(senderKey); err != nil {
		t.Fatal(err)
	}
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-cascade"

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.SeedPeerChainForTest(keyID, chain0, 0)

	texts := []string{"one", "two", "three"}
	frames := make([]map[string]any, len(texts))
	chain := chain0
	for i, text := range texts {
		enc, err := client.EncryptTestSealedFrame(chain, uint64(i), "bob", text, nil)
		if err != nil {
			t.Fatalf("EncryptTestSealedFrame(idx=%d): %v", i, err)
		}
		frames[i] = map[string]any{"kid": keyID, "text": enc, "idx": float64(i)}
		_, next := shared.DeriveChainStep(chain)
		chain = next
	}

	tab := &roomTab{cli: cli}
	m := &model{myUsername: "me", tabs: []*roomTab{tab}, active: 0}

	lines0, _ := m.handleIncomingMessage(tab, 0, frames[0])
	if len(lines0) != 1 || lines0[0].text != "one" {
		t.Fatalf("idx0 in order: want 1 line \"one\", got %#v", lines0)
	}

	linesOOO, _ := m.handleIncomingMessage(tab, 0, frames[2])
	if len(linesOOO) != 0 {
		t.Fatalf("idx2 out of order: want 0 lines (buffered), got %d", len(linesOOO))
	}
	if _, buffered := tab.msgBuffer[keyID][2]; !buffered {
		t.Fatal("idx2 should have stayed in the buffer waiting for its turn")
	}

	lines1, _ := m.handleIncomingMessage(tab, 0, frames[1])
	if len(lines1) != 2 {
		t.Fatalf("idx1 must also cascade-unblock idx2: want 2 lines, got %d", len(lines1))
	}
	if lines1[0].text != "two" || lines1[1].text != "three" {
		t.Errorf("wrong cascade order/text: want [two three], got [%q %q]", lines1[0].text, lines1[1].text)
	}
	if _, buffered := tab.msgBuffer[keyID][2]; buffered {
		t.Error("idx2 should have been removed from the buffer after being processed")
	}
}

// TestDrainMsgBufferAfterKeyArrives covers messages that overtook their
// own sender_key: buffered while the keyID is unknown, they are shown,
// in order, by drainMsgBuffer as soon as the key is registered.
func TestDrainMsgBufferAfterKeyArrives(t *testing.T) {
	senderKey := make([]byte, 32)
	if _, err := rand.Read(senderKey); err != nil {
		t.Fatal(err)
	}
	chain0 := shared.InitChainKey(senderKey)
	keyID := "keyid-late-key"

	cli := client.New("127.0.0.1", 0, "me", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	tab := &roomTab{cli: cli}
	m := &model{myUsername: "me", tabs: []*roomTab{tab}, active: 0}

	chain := chain0
	for i, text := range []string{"first", "second"} {
		enc, err := client.EncryptTestSealedFrame(chain, uint64(i), "bob", text, nil)
		if err != nil {
			t.Fatal(err)
		}
		if lines, _ := m.handleIncomingMessage(tab, 0, map[string]any{"kid": keyID, "text": enc, "idx": float64(i)}); len(lines) != 0 {
			t.Fatalf("idx%d shown before its key arrived", i)
		}
		_, chain = shared.DeriveChainStep(chain)
	}

	cli.SeedPeerChainForTest(keyID, chain0, 0)
	lines, _ := m.drainMsgBuffer(tab, 0)
	if len(lines) != 2 || lines[0].text != "first" || lines[1].text != "second" {
		t.Fatalf("after the key: want [first second], got %d lines", len(lines))
	}
	if len(tab.msgBuffer[keyID]) != 0 {
		t.Error("drained frames still in the buffer")
	}
}
