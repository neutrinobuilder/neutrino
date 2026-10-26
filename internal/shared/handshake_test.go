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

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

var testSecret = []byte("shared-secret-test-256bit-padding-ok!!!!")

func TestComputeAndVerifyRoomProof(t *testing.T) {
	period := CurrentPeriod()
	roomKey, err := DeriveContactRoomKey(testSecret, period)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := RandomBytes(32)
	proof := ComputeRoomProof(roomKey, nonce)

	// must verify with the current period
	got, ok := VerifyRoomProof(testSecret, nonce, proof)
	if !ok {
		t.Fatal("VerifyRoomProof: want ok, got false")
	}
	if got != period && got != period+1 {
		t.Errorf("valid period: want %d or %d, got %d", period, period+1, got)
	}

	// must also verify with period+1 (overlap window)
	roomKeyNext, _ := DeriveContactRoomKey(testSecret, period+1)
	proofNext := ComputeRoomProof(roomKeyNext, nonce)
	_, ok = VerifyRoomProof(testSecret, nonce, proofNext)
	if !ok {
		t.Fatal("VerifyRoomProof period+1: want ok, got false")
	}

	// a wrong proof must fail
	badProof := make([]byte, len(proof))
	copy(badProof, proof)
	badProof[0] ^= 0xFF
	if _, ok := VerifyRoomProof(testSecret, nonce, badProof); ok {
		t.Fatal("VerifyRoomProof: corrupted proof accepted")
	}
}

func TestDeriveSessionKeySymmetric(t *testing.T) {
	nonceClient, _ := RandomBytes(32)
	nonceServer, _ := RandomBytes(32)
	pubClient, _ := RandomBytes(32)
	pubServer, _ := RandomBytes(32)

	// simulates DH + ML-KEM on both sides: secrets identical by construction
	dhSecret, _ := RandomBytes(32)
	mlkemSS, _ := RandomBytes(32)

	keyA, err := DeriveSessionKey(mlkemSS, dhSecret, nonceClient, nonceServer, pubClient, pubServer)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := DeriveSessionKey(mlkemSS, dhSecret, nonceClient, nonceServer, pubClient, pubServer)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(keyA, keyB) {
		t.Fatal("DeriveSessionKey: the two parties get different keys")
	}
	if len(keyA) != 32 {
		t.Errorf("want length 32, got %d", len(keyA))
	}

	// different nonces → different key
	otherNonce, _ := RandomBytes(32)
	keyC, _ := DeriveSessionKey(mlkemSS, dhSecret, otherNonce, nonceServer, pubClient, pubServer)
	if bytes.Equal(keyA, keyC) {
		t.Fatal("DeriveSessionKey: different nonces produce the same key")
	}

	// different session pubs → different key (transcript binding)
	otherPub, _ := RandomBytes(32)
	keyD, _ := DeriveSessionKey(mlkemSS, dhSecret, nonceClient, nonceServer, otherPub, pubServer)
	if bytes.Equal(keyA, keyD) {
		t.Fatal("DeriveSessionKey: a different client session pub produces the same key")
	}

	// different mlkemSS → different key (the hybrid secret is actually used, not ignored)
	otherMLKEMSS, _ := RandomBytes(32)
	keyE, _ := DeriveSessionKey(otherMLKEMSS, dhSecret, nonceClient, nonceServer, pubClient, pubServer)
	if bytes.Equal(keyA, keyE) {
		t.Fatal("DeriveSessionKey: a different mlkemSS produces the same key")
	}
}

// TestDeriveSessionKeyHybridOrder verifies that the combined secret is
// built as mlkemSS‖dhSecret and not dhSecret‖mlkemSS, order mandated by
// NIST SP 800-56Cr2 §2 (the FIPS-approved algorithm's secret precedes the
// non-approved one; ML-KEM is FIPS 203, X25519 is not FIPS-approved), same
// order as the TLS 1.3 X25519MLKEM768 hybrid group
// (draft-ietf-tls-ecdhe-mlkem). Not deducible from the round-trip in
// TestDeriveSessionKeySymmetric alone, since swapping two secrets of equal
// length still produces different keys in both orders, here the combiner
// is rebuilt by hand with the same logic as DeriveSessionKey to explicitly
// compare the two possible orders.
func TestDeriveSessionKeyHybridOrder(t *testing.T) {
	nonceClient, _ := RandomBytes(32)
	nonceServer, _ := RandomBytes(32)
	pubClient, _ := RandomBytes(32)
	pubServer, _ := RandomBytes(32)
	dhSecret, _ := RandomBytes(32)
	mlkemSS, _ := RandomBytes(32)

	got, err := DeriveSessionKey(mlkemSS, dhSecret, nonceClient, nonceServer, pubClient, pubServer)
	if err != nil {
		t.Fatal(err)
	}

	// same exact computation as DeriveSessionKey, but with dhSecret before mlkemSS
	reversed := make([]byte, 0, len(mlkemSS)+len(dhSecret))
	reversed = append(reversed, dhSecret...)
	reversed = append(reversed, mlkemSS...)
	transcript := make([]byte, 0, len(nonceClient)+len(nonceServer)+len(pubClient)+len(pubServer))
	transcript = append(transcript, nonceClient...)
	transcript = append(transcript, nonceServer...)
	transcript = append(transcript, pubClient...)
	transcript = append(transcript, pubServer...)
	r := hkdf.New(sha256.New, reversed, transcript, []byte("neutrino-session-x25519-mlkem768-v1"))
	wrongOrder := make([]byte, 32)
	if _, err := io.ReadFull(r, wrongOrder); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(got, wrongOrder) {
		t.Fatal("DeriveSessionKey: the mlkemSS‖dhSecret order is not the one actually used (collides with dhSecret‖mlkemSS)")
	}
}

func TestSigPayloads(t *testing.T) {
	nC, _ := RandomBytes(32)
	nS, _ := RandomBytes(32)
	pub, _ := RandomBytes(32)

	clientPayload := ClientSigPayload(nC, pub)
	if !bytes.HasPrefix(clientPayload, nC) {
		t.Error("ClientSigPayload: doesn't start with nonce_client")
	}
	if !bytes.HasSuffix(clientPayload, pub) {
		t.Error("ClientSigPayload: doesn't end with session_pub")
	}

	serverPayload := ServerSigPayload(nC, nS, pub)
	if !bytes.HasPrefix(serverPayload, nC) {
		t.Error("ServerSigPayload: doesn't start with nonce_client")
	}
	if !bytes.HasSuffix(serverPayload, pub) {
		t.Error("ServerSigPayload: doesn't end with session_pub")
	}
	if len(serverPayload) != len(nC)+len(nS)+len(pub) {
		t.Errorf("ServerSigPayload: want length %d, got %d",
			len(nC)+len(nS)+len(pub), len(serverPayload))
	}
}
