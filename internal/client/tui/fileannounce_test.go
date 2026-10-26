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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"neutrino/internal/client"
	"neutrino/internal/keystore"
	"neutrino/internal/shared"
)

// newCapturingWSConn is like newTestWSConn (tui_test.go) but also returns
// a channel the test server publishes every received JSON frame on —
// needed here to verify WHO receives a file_offer, not just that the
// send does not fail.
func newCapturingWSConn(t *testing.T) (*websocket.Conn, <-chan map[string]any) {
	t.Helper()
	frames := make(chan map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		for {
			var v map[string]any
			if err := wsjson.Read(r.Context(), conn, &v); err != nil {
				return
			}
			select {
			case frames <- v:
			default:
			}
		}
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn, frames
}

// newFileAnnounceTestModel builds a minimal model with a "bob" contact (one
// device, known identity key) linked to the active tab through a
// client.Client with no real network connection — enough to exercise
// handleRoomMsg/contentPeerKeysFor/resolveContactByPub, which never touch the
// connection itself on this path.
func newFileAnnounceTestModel(t *testing.T, devKeyBytes []byte, peerContentPub, peerContentMLDSAPub []byte, confirmed bool) (*model, *roomTab) {
	t.Helper()
	cli := client.New("127.0.0.1", 0, "alice", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	cli.RegisterUser("uid-bob", "bob", testPub("bob"))
	tab := &roomTab{groupID: "g1", cli: cli, ctx: nil}
	contact := ContactInfo{
		Username:    "bob",
		IdentityPub: testPub("bob"),
		Devices: map[string]*keystore.DeviceRelation{
			string(devKeyBytes): {
				PeerRelContentPub:         peerContentPub,
				PeerRelContentMLDSAPub:    peerContentMLDSAPub,
				RelContentConfirmedByPeer: confirmed,
			},
		},
	}
	m := &model{
		tabs:          []*roomTab{tab},
		active:        0,
		consoleIdx:    1,
		myUsername:    "alice",
		myIdentityPub: testPub("alice"),
		contacts:      []ContactInfo{contact},
	}
	return m, tab
}

func announceRaw(fromUserID, transferID string, hash, sig, sigMLDSA []byte, sigTS string) map[string]any {
	raw := map[string]any{
		"type":         "file_announce",
		"from_user_id": fromUserID,
		"transfer_id":  transferID,
		"hash":         base64.StdEncoding.EncodeToString(hash),
		"sig":          base64.StdEncoding.EncodeToString(sig),
		"sig_ts":       sigTS,
	}
	if len(sigMLDSA) > 0 {
		raw["sig_mldsa"] = base64.StdEncoding.EncodeToString(sigMLDSA)
	}
	return raw
}

// TestApplyFileAnnounceValidVerifiesImmediately verifies that a file_announce
// with a valid signature is verified right away — the hash ends up in
// m.verifiedFileHashes (consumed by the following file_offer), no self-heal,
// no entry in pendingFileAnnounces.
func TestApplyFileAnnounceValidVerifiesImmediately(t *testing.T) {
	devKey := make([]byte, ed25519.PublicKeySize)
	_, _ = rand.Read(devKey)
	bobPub, bobPriv, _ := ed25519.GenerateKey(rand.Reader)
	m, _ := newFileAnnounceTestModel(t, devKey, bobPub, nil, true)

	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	sigTS := shared.NowTS()
	sig := shared.SignRelMsg(bobPriv, hex.EncodeToString(hash), sigTS, testKey("alice"))

	const transferID = "t1"
	m.handleRoomMsg(0, announceRaw("uid-bob", transferID, hash, sig, nil, sigTS))

	got, ok := m.verifiedFileHashes[transferID]
	if !ok {
		t.Fatal("expected the announce hash to be recorded in verifiedFileHashes")
	}
	if string(got) != string(hash) {
		t.Errorf("verifiedFileHashes[%s] = %x, want %x", transferID, got, hash)
	}
	if _, pending := m.pendingFileAnnounces[transferID]; pending {
		t.Error("a valid announce must never be held pending for self-heal")
	}
	dev := m.contacts[0].Devices[string(devKey)]
	if !dev.RelContentConfirmedByPeer {
		t.Error("a valid announce must not touch RelContentConfirmedByPeer")
	}
}

// TestApplyFileAnnounceStaleKeyTriggersSelfHeal verifies that a signature
// that fails to verify due to a misaligned ContentKey does NOT discard the
// announce — it holds it pending (pendingFileAnnounces) and clears
// RelContentConfirmedByPeer, so the next rel_init_ack can resync and restart
// verification without retransmitting any byte of the file.
func TestApplyFileAnnounceStaleKeyTriggersSelfHeal(t *testing.T) {
	devKey := make([]byte, ed25519.PublicKeySize)
	_, _ = rand.Read(devKey)
	staleBobPub, _, _ := ed25519.GenerateKey(rand.Reader) // the one WE have in our contact book
	_, realBobPriv, _ := ed25519.GenerateKey(rand.Reader) // the one bob ACTUALLY signed with
	m, _ := newFileAnnounceTestModel(t, devKey, staleBobPub, nil, true)

	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	sigTS := shared.NowTS()
	sig := shared.SignRelMsg(realBobPriv, hex.EncodeToString(hash), sigTS, testKey("alice"))

	const transferID = "t1"
	m.handleRoomMsg(0, announceRaw("uid-bob", transferID, hash, sig, nil, sigTS))

	if _, ok := m.verifiedFileHashes[transferID]; ok {
		t.Fatal("a stale-key announce must not verify")
	}
	pa, ok := m.pendingFileAnnounces[transferID]
	if !ok {
		t.Fatal("expected the announce to be held pending for self-heal, not discarded")
	}
	if pa.fromKey != testKey("bob") || pa.devKey != string(devKey) || string(pa.hash) != string(hash) {
		t.Errorf("unexpected pendingFileAnnounce contents: %+v", pa)
	}
	dev := m.contacts[0].Devices[string(devKey)]
	if dev.RelContentConfirmedByPeer {
		t.Error("expected RelContentConfirmedByPeer reset to false by the self-heal")
	}
}

// TestRetryPendingFileAnnouncesResyncsAfterRelInit covers the second half
// of the self-heal: once applyRelInit resyncs bob's PeerRelContentPub,
// retryPendingFileAnnounces must re-verify the announce already in hand
// (no new data from the network) and make it come out verified.
func TestRetryPendingFileAnnouncesResyncsAfterRelInit(t *testing.T) {
	devKey := make([]byte, ed25519.PublicKeySize)
	_, _ = rand.Read(devKey)
	realBobPub, realBobPriv, _ := ed25519.GenerateKey(rand.Reader)
	m, _ := newFileAnnounceTestModel(t, devKey, nil, nil, true) // PeerRelContentPub still empty/unknown

	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	sigTS := shared.NowTS()
	sig := shared.SignRelMsg(realBobPriv, hex.EncodeToString(hash), sigTS, testKey("alice"))

	const transferID = "t1"
	m.pendingFileAnnounces = map[string]*pendingFileAnnounce{
		transferID: {
			tabIdx:     0,
			fromKey:    testKey("bob"),
			fromUserID: "uid-bob",
			devKey:     string(devKey),
			hash:       hash,
			sig:        sig,
			sigTS:      sigTS,
			deadline:   time.Now().Add(time.Minute),
		},
	}

	// Simulates what applyRelInit does BEFORE calling retryPendingFileAnnounces:
	// PeerRelContentPub updated by the just-arrived rel_init_ack.
	m.contacts[0].Devices[string(devKey)].PeerRelContentPub = realBobPub

	m.retryPendingFileAnnounces(testPub("bob"), devKey)

	if _, stillPending := m.pendingFileAnnounces[transferID]; stillPending {
		t.Fatal("expected the pending announce to be resolved after the key resync")
	}
	got, ok := m.verifiedFileHashes[transferID]
	if !ok || string(got) != string(hash) {
		t.Fatalf("expected verifiedFileHashes[%s] = %x, got %x (ok=%v)", transferID, hash, got, ok)
	}
}

// TestRetryPendingFileAnnouncesDropsExpired covers the wait budget: an
// announce whose deadline has already passed is silently dropped instead of
// being re-verified forever — the sender discovers the timeout on its own,
// same behavior as an offer that was never accepted.
func TestRetryPendingFileAnnouncesDropsExpired(t *testing.T) {
	devKey := make([]byte, ed25519.PublicKeySize)
	_, _ = rand.Read(devKey)
	realBobPub, realBobPriv, _ := ed25519.GenerateKey(rand.Reader)
	m, _ := newFileAnnounceTestModel(t, devKey, nil, nil, true)

	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	sigTS := shared.NowTS()
	sig := shared.SignRelMsg(realBobPriv, hex.EncodeToString(hash), sigTS, testKey("alice"))

	const transferID = "t1"
	m.pendingFileAnnounces = map[string]*pendingFileAnnounce{
		transferID: {
			tabIdx:     0,
			fromKey:    testKey("bob"),
			fromUserID: "uid-bob",
			devKey:     string(devKey),
			hash:       hash,
			sig:        sig,
			sigTS:      sigTS,
			deadline:   time.Now().Add(-time.Second), // already expired
		},
	}
	m.contacts[0].Devices[string(devKey)].PeerRelContentPub = realBobPub

	m.retryPendingFileAnnounces(testPub("bob"), devKey)

	if _, stillPending := m.pendingFileAnnounces[transferID]; stillPending {
		t.Fatal("an expired pending announce must be dropped, not retried forever")
	}
	if _, verified := m.verifiedFileHashes[transferID]; verified {
		t.Fatal("an expired pending announce must not be verified after its own deadline")
	}
}

// TestFileAnnounceAckSendsOfferOnlyToThatRecipient verifies the core of the
// sender-side design: the real file_offer (name/size/file key) goes ONLY to
// the recipient that has already confirmed the announce signature — never
// to a second recipient that has not answered yet, even if its meta_blob
// was already ready.
func TestFileAnnounceAckSendsOfferOnlyToThatRecipient(t *testing.T) {
	cli := client.New("127.0.0.1", 0, "alice", nil, false, nil, nil, nil, shared.RelSigningKey{}, shared.RelPeerKey{})
	conn, frames := newCapturingWSConn(t)
	cli.Conn = conn
	cli.RegisterUser("uid-bob", "bob", testPub("bob"))
	cli.RegisterUser("uid-carol", "carol", testPub("carol"))

	tab := &roomTab{groupID: "g1", cli: cli, ctx: context.Background()}
	m := &model{tabs: []*roomTab{tab}, active: 0, consoleIdx: 1}
	m.outgoingTransfers = map[string]*outgoingFileTransfer{
		"t1": {
			transferID: "t1",
			tabIdx:     0,
			fileName:   "secret.txt",
			pending:    map[string]bool{"bob": true, "carol": true},
			envelopes: map[string]shared.FileOfferEnvelope{
				"uid-bob":   {MetaBlob: "meta-for-bob"},
				"uid-carol": {MetaBlob: "meta-for-carol"},
			},
		},
	}

	raw := map[string]any{"type": "file_announce_ack", "from_user_id": "uid-bob", "transfer_id": "t1"}
	cmds := m.handleRoomMsg(0, raw)
	for _, cmd := range cmds {
		if cmd != nil {
			cmd()
		}
	}

	select {
	case frame := <-frames:
		if frame["type"] != "file_offer" {
			t.Fatalf("expected a file_offer frame, got %v", frame["type"])
		}
		ids, _ := frame["to_user_ids"].([]any)
		if len(ids) != 1 || ids[0] != "uid-bob" {
			t.Fatalf("expected file_offer to only uid-bob, got %v", ids)
		}
		envs, _ := frame["envelopes"].(map[string]any)
		if len(envs) != 1 {
			t.Fatalf("expected exactly one envelope in the offer, got %d", len(envs))
		}
		if _, ok := envs["uid-carol"]; ok {
			t.Fatal("carol's envelope must never be sent before HER OWN announce_ack")
		}
		if _, ok := envs["uid-bob"]; !ok {
			t.Fatal("expected bob's envelope in the offer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no file_offer frame captured")
	}
}
