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
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ── Encrypt / Decrypt (AES-256-GCM) ──────────────────────────────────────────

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key, _ := RandomBytes(32)
	plaintext := []byte("test plaintext message")
	aad := []byte("test-aad")

	encoded, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, encoded, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt: want %q, got %q", plaintext, got)
	}
}

func TestEncryptDecryptNilAAD(t *testing.T) {
	key, _ := RandomBytes(32)
	plaintext := []byte("no aad")

	encoded, err := Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt: want %q, got %q", plaintext, got)
	}
}

func TestEncryptNonceUniqueness(t *testing.T) {
	key, _ := RandomBytes(32)
	plaintext := []byte("same message")

	a, err := Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("Encrypt: two encryptions of the same message produce the same output (nonce reused?)")
	}
}

func TestDecryptAADMismatch(t *testing.T) {
	key, _ := RandomBytes(32)
	encoded, err := Encrypt(key, []byte("payload"), []byte("right-aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(key, encoded, []byte("wrong-aad")); err == nil {
		t.Fatal("Decrypt: wrong aad accepted")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key, _ := RandomBytes(32)
	otherKey, _ := RandomBytes(32)
	encoded, err := Encrypt(key, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(otherKey, encoded, nil); err == nil {
		t.Fatal("Decrypt: wrong key accepted")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key, _ := RandomBytes(32)
	encoded, err := Encrypt(key, []byte("intact payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(encoded)
	// alter the last valid base64 character to corrupt the GCM tag.
	tampered[len(tampered)-2] ^= 0x01
	if _, err := Decrypt(key, string(tampered), nil); err == nil {
		t.Fatal("Decrypt: tampered ciphertext accepted")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key, _ := RandomBytes(32)
	if _, err := Decrypt(key, "AAAA", nil); err == nil {
		t.Fatal("Decrypt: too-short ciphertext accepted")
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	key, _ := RandomBytes(32)
	if _, err := Decrypt(key, "non-e-base64!!!", nil); err == nil {
		t.Fatal("Decrypt: invalid base64 accepted")
	}
}

// ── ECIES (X25519 + AES-256-GCM) ─────────────────────────────────────────────

func TestECIESRoundtrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("secret message for the recipient")

	encoded, err := ECIESEncrypt(priv.PublicKey(), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ECIESDecrypt(priv, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("ECIESDecrypt: want %q, got %q", plaintext, got)
	}
}

func TestECIESWrongRecipient(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	otherPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	encoded, err := ECIESEncrypt(priv.PublicKey(), []byte("secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ECIESDecrypt(otherPriv, encoded); err == nil {
		t.Fatal("ECIESDecrypt: wrong private key accepted")
	}
}

func TestECIESTamperedPayload(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	encoded, err := ECIESEncrypt(priv.PublicKey(), []byte("secrets"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(encoded)
	tampered[len(tampered)-2] ^= 0x01
	if _, err := ECIESDecrypt(priv, string(tampered)); err == nil {
		t.Fatal("ECIESDecrypt: tampered payload accepted")
	}
}

func TestECIESPayloadTooShort(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := ECIESDecrypt(priv, "AAAA"); err == nil {
		t.Fatal("ECIESDecrypt: too-short payload accepted")
	}
}

// ── HybridECIES (X25519 + ML-KEM-768 + AES-256-GCM) ──────────────────────────
// Peer-to-peer delivery of sender_key, same mlkemSS‖dhSecret combiner as
// DeriveSessionKey.

func TestHybridECIESRoundtrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("secret sender_key for the recipient")

	encoded, err := HybridECIESEncrypt(priv.PublicKey(), mlkemDK.EncapsulationKey(), plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := HybridECIESDecrypt(priv, mlkemDK, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("HybridECIESDecrypt: want %q, got %q", plaintext, got)
	}
}

func TestHybridECIESWrongX25519Recipient(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	otherPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()

	encoded, err := HybridECIESEncrypt(priv.PublicKey(), mlkemDK.EncapsulationKey(), []byte("secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HybridECIESDecrypt(otherPriv, mlkemDK, encoded); err == nil {
		t.Fatal("HybridECIESDecrypt: wrong X25519 private key accepted")
	}
}

func TestHybridECIESWrongMLKEMRecipient(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()
	otherMLKEMDK, _ := mlkem.GenerateKey768()

	encoded, err := HybridECIESEncrypt(priv.PublicKey(), mlkemDK.EncapsulationKey(), []byte("secrets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HybridECIESDecrypt(priv, otherMLKEMDK, encoded); err == nil {
		t.Fatal("HybridECIESDecrypt: wrong ML-KEM private key accepted, the hybrid secret doesn't really depend on both components")
	}
}

func TestHybridECIESTamperedPayload(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()
	encoded, err := HybridECIESEncrypt(priv.PublicKey(), mlkemDK.EncapsulationKey(), []byte("secrets"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(encoded)
	tampered[len(tampered)-2] ^= 0x01
	if _, err := HybridECIESDecrypt(priv, mlkemDK, string(tampered)); err == nil {
		t.Fatal("HybridECIESDecrypt: tampered payload accepted")
	}
}

func TestHybridECIESPayloadTooShort(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()
	if _, err := HybridECIESDecrypt(priv, mlkemDK, "AAAA"); err == nil {
		t.Fatal("HybridECIESDecrypt: too-short payload accepted")
	}
}

// ── RandomBytes ───────────────────────────────────────────────────────────────

func TestRandomBytes(t *testing.T) {
	a, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("want length 32, got %d", len(a))
	}
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("RandomBytes: two calls produce the same output")
	}
}

// ── DeriveContactRoomKey ──────────────────────────────────────────────────────

func TestDeriveContactRoomKeyPeriodDependency(t *testing.T) {
	secret := []byte("test-shared-secret")
	k1, err := DeriveContactRoomKey(secret, 100)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveContactRoomKey(secret, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveContactRoomKey: the same secret and period produce different keys")
	}
	k3, err := DeriveContactRoomKey(secret, 101)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("DeriveContactRoomKey: different periods produce the same key")
	}
}

// ── Ed25519 <-> X25519 ────────────────────────────────────────────────────────

// TestEd25519X25519ConversionECDH verifies that the Edwards→Montgomery
// birational map preserves the DH structure: two Ed25519 keys converted to
// X25519 must still agree on a shared secret via standard ECDH, in both
// directions.
func TestEd25519X25519ConversionECDH(t *testing.T) {
	aliceEdPub, aliceEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEdPub, bobEdPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	aliceXPriv, err := Ed25519PrivToX25519(aliceEdPriv)
	if err != nil {
		t.Fatal(err)
	}
	bobXPriv, err := Ed25519PrivToX25519(bobEdPriv)
	if err != nil {
		t.Fatal(err)
	}
	bobXPub, err := Ed25519PubToX25519(bobEdPub)
	if err != nil {
		t.Fatal(err)
	}
	aliceXPub, err := Ed25519PubToX25519(aliceEdPub)
	if err != nil {
		t.Fatal(err)
	}

	// the X25519 pubkey derived from Alice's privkey must match the one
	// obtained by directly converting her Ed25519 pubkey.
	if !bytes.Equal(aliceXPriv.PublicKey().Bytes(), aliceXPub.Bytes()) {
		t.Fatal("Ed25519PrivToX25519/Ed25519PubToX25519: inconsistent derived pubkeys for the same identity")
	}

	sharedA, err := aliceXPriv.ECDH(bobXPub)
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := bobXPriv.ECDH(aliceXPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatal("ECDH on converted keys: the two parties get different secrets")
	}
}

func TestEd25519PubToX25519InvalidLength(t *testing.T) {
	if _, err := Ed25519PubToX25519([]byte{1, 2, 3}); err == nil {
		t.Fatal("Ed25519PubToX25519: invalid length accepted")
	}
}

func TestEd25519PrivToX25519InvalidLength(t *testing.T) {
	if _, err := Ed25519PrivToX25519([]byte{1, 2, 3}); err == nil {
		t.Fatal("Ed25519PrivToX25519: invalid length accepted")
	}
}

// ── Knock (EncryptKnock/DecryptKnock) ────────────────────────────────────────

func TestEncryptDecryptKnockRoundtrip(t *testing.T) {
	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := RandomBytes(32)

	original := KnockPayload{
		FromUsername:    "alice",
		FromIdentityPub: senderPub,
		RoomSecret:      secret,
		GroupID:         "grp-123",
		Members: []MemberInfo{
			{Username: "alice", IdentityPub: senderPub},
		},
	}

	encoded, err := EncryptKnock(recipientPub, nil, original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptKnock(recipientPriv, nil, encoded)
	if err != nil {
		t.Fatal(err)
	}

	if got.FromUsername != original.FromUsername {
		t.Errorf("FromUsername: want %q, got %q", original.FromUsername, got.FromUsername)
	}
	if !bytes.Equal(got.FromIdentityPub, original.FromIdentityPub) {
		t.Error("FromIdentityPub: doesn't match after the roundtrip")
	}
	if !bytes.Equal(got.RoomSecret, original.RoomSecret) {
		t.Error("RoomSecret: doesn't match after the roundtrip")
	}
	if got.GroupID != original.GroupID {
		t.Errorf("GroupID: want %q, got %q", original.GroupID, got.GroupID)
	}
	if len(got.Members) != 1 || got.Members[0].Username != "alice" {
		t.Errorf("Members: unexpected roundtrip %+v", got.Members)
	}
}

func TestDecryptKnockWrongRecipient(t *testing.T) {
	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := EncryptKnock(recipientPub, nil, KnockPayload{FromUsername: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptKnock(otherPriv, nil, encoded); err == nil {
		t.Fatal("DecryptKnock: wrong private key accepted")
	}
}

func TestKnockDHTagSymmetric(t *testing.T) {
	aPub, aPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tagA, err := KnockDHTag(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	tagB, err := KnockDHTag(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tagA, tagB) {
		t.Error("KnockDHTag: static-static DH not symmetric, sender and recipient get different values")
	}
}

func TestKnockDHTagDistinctPerPeer(t *testing.T) {
	_, myPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tagB, err := KnockDHTag(myPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	tagC, err := KnockDHTag(myPriv, cPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tagB, tagC) {
		t.Error("KnockDHTag: identical tag toward two different recipients, no per-pair uniqueness")
	}
}

func TestEncryptKnockWithTagRoundtrip(t *testing.T) {
	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := KnockDHTag(senderPriv, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	envJSON, err := EncryptKnockWithTag(recipientPub, nil, KnockPayload{
		FromUsername:    "alice",
		FromIdentityPub: senderPub,
	}, tag)
	if err != nil {
		t.Fatal(err)
	}
	var env KnockEnvelope
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		t.Fatalf("KnockEnvelope not decodable: %v", err)
	}
	if !bytes.Equal(env.Tag, tag) {
		t.Error("KnockEnvelope.Tag doesn't match the tag computed by the caller")
	}
	// The recipient must be able to recompute the same tag from their own
	// private key + the sender's pubkey (after decryption), consistency
	// check used by handleKnock.
	recipientTag, err := KnockDHTag(recipientPriv, senderPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recipientTag, tag) {
		t.Error("the recipient doesn't get the same tag recomputing it on its side")
	}
	got, err := DecryptKnock(recipientPriv, nil, env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.FromUsername != "alice" {
		t.Errorf("FromUsername: want %q, got %q", "alice", got.FromUsername)
	}
}

// TestEncryptDecryptKnockHybridRoundtrip mirrors TestEncryptDecryptKnockRoundtrip
// but passes a recipient ML-KEM-768 encapsulation key: verifies both the
// roundtrip itself and the on-wire discriminator ("H:" instead of "C:", see
// peerEncFormatHybrid).
func TestEncryptDecryptKnockHybridRoundtrip(t *testing.T) {
	recipientPub, recipientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientMLKEM, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	senderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	original := KnockPayload{
		FromUsername:    "alice",
		FromIdentityPub: senderPub,
		MLKEMPub:        recipientMLKEM.EncapsulationKey().Bytes(),
	}

	encoded, err := EncryptKnock(recipientPub, recipientMLKEM.EncapsulationKey(), original)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, peerEncFormatHybrid) {
		t.Errorf("hybrid payload: want prefix %q, got %q", peerEncFormatHybrid, encoded[:2])
	}
	got, err := DecryptKnock(recipientPriv, recipientMLKEM, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.FromUsername != original.FromUsername {
		t.Errorf("FromUsername: want %q, got %q", original.FromUsername, got.FromUsername)
	}
	if !bytes.Equal(got.MLKEMPub, original.MLKEMPub) {
		t.Error("MLKEMPub: doesn't match after the roundtrip")
	}

	// Without the ML-KEM decapsulation key the recipient can't decrypt a
	// hybrid payload, even with the right Ed25519 key, explicit error, not
	// a silent fallback to the classic form.
	if _, err := DecryptKnock(recipientPriv, nil, encoded); err == nil {
		t.Fatal("DecryptKnock: hybrid payload decrypted without the ML-KEM key")
	}
}

// TestEncryptKnockClassicPrefix verifies that a knock with no recipient
// ML-KEM key (none known for the recipient) stays encrypted in the
// classic form on the wire, permanently, not a transition state, see the
// comment on peerEncFormatClassic/peerEncFormatHybrid.
func TestEncryptKnockClassicPrefix(t *testing.T) {
	recipientPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncryptKnock(recipientPub, nil, KnockPayload{FromUsername: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, peerEncFormatClassic) {
		t.Errorf("classic payload: want prefix %q, got %q", peerEncFormatClassic, encoded[:2])
	}
}

// ── rel_key_rotate cross-certification ────────────────────────────────────────

func TestRelKeyRotationSigVerifyRoundtrip(t *testing.T) {
	certPub, certPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := NowTS()
	sig := SignRelKeyRotation(certPriv, newPub, "alice", ts)
	if !VerifyRelKeyRotation(certPub, newPub, "alice", ts, sig) {
		t.Fatal("VerifyRelKeyRotation: valid signature refused")
	}
}

// TestRelKeyRotationSigTamperedTs verifies that ts is part of the SIGNED
// message, not just the payload, an attacker who rewrites ts on a captured
// message (to make it look fresh) invalidates the signature, not just the
// separate TsFresh check.
func TestRelKeyRotationSigTamperedTs(t *testing.T) {
	certPub, certPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	origTs := "2020-01-01T00:00:00Z"
	sig := SignRelKeyRotation(certPriv, newPub, "alice", origTs)
	if !VerifyRelKeyRotation(certPub, newPub, "alice", origTs, sig) {
		t.Fatal("VerifyRelKeyRotation: valid signature (original ts) refused")
	}
	if VerifyRelKeyRotation(certPub, newPub, "alice", NowTS(), sig) {
		t.Fatal("VerifyRelKeyRotation: a ts rewritten on a captured signature verified, replay-freshening must not work")
	}
}

// TestRelKeyRotationSigWrongLengthPubDoesNotPanic verifies that
// VerifyRelKeyRotation rejects a certifying key of the wrong length (or
// nil) without panicking.
func TestRelKeyRotationSigWrongLengthPubDoesNotPanic(t *testing.T) {
	_, certPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts := NowTS()
	sig := SignRelKeyRotation(certPriv, newPub, "alice", ts)

	for _, badLen := range []int{0, 16, 31, 33, 64} {
		badPub := make(ed25519.PublicKey, badLen)
		if VerifyRelKeyRotation(badPub, newPub, "alice", ts, sig) {
			t.Fatalf("VerifyRelKeyRotation: key of length %d accepted", badLen)
		}
	}
	if VerifyRelKeyRotation(nil, newPub, "alice", ts, sig) {
		t.Fatal("VerifyRelKeyRotation: nil pub accepted")
	}
}

func TestRelKeyRotationSigTamperedUsername(t *testing.T) {
	certPub, certPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts := NowTS()
	sig := SignRelKeyRotation(certPriv, newPub, "alice", ts)
	if VerifyRelKeyRotation(certPub, newPub, "bob", ts, sig) {
		t.Fatal("VerifyRelKeyRotation: username different from the signed one accepted")
	}
}

// ── rel_key_rotate ML-DSA-65 cross-certification ──────────────────────────────

func newTestMLDSASeed(t *testing.T) (seed []byte, pubBytes []byte) {
	t.Helper()
	seed = make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	var s [mldsa65.SeedSize]byte
	copy(s[:], seed)
	pub, _ := mldsa65.NewKeyFromSeed(&s)
	return seed, pub.Bytes()
}

func TestRelKeyRotationSigMLDSAVerifyRoundtrip(t *testing.T) {
	seed, pubBytes := newTestMLDSASeed(t)
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := NowTS()
	sig := SignRelKeyRotationMLDSA(seed, newPub, "alice", ts)
	if !VerifyRelKeyRotationMLDSA(pubBytes, newPub, "alice", ts, sig) {
		t.Fatal("VerifyRelKeyRotationMLDSA: valid signature refused")
	}
}

func TestRelKeyRotationSigMLDSATamperedUsername(t *testing.T) {
	seed, pubBytes := newTestMLDSASeed(t)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts := NowTS()
	sig := SignRelKeyRotationMLDSA(seed, newPub, "alice", ts)
	if VerifyRelKeyRotationMLDSA(pubBytes, newPub, "bob", ts, sig) {
		t.Fatal("VerifyRelKeyRotationMLDSA: username different from the signed one accepted")
	}
}

func TestRelKeyRotationSigMLDSAEmptyInputsRejected(t *testing.T) {
	seed, pubBytes := newTestMLDSASeed(t)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts := NowTS()
	sig := SignRelKeyRotationMLDSA(seed, newPub, "alice", ts)
	if VerifyRelKeyRotationMLDSA(nil, newPub, "alice", ts, sig) {
		t.Fatal("VerifyRelKeyRotationMLDSA: a nil pub must never verify")
	}
	if VerifyRelKeyRotationMLDSA(pubBytes, newPub, "alice", ts, nil) {
		t.Fatal("VerifyRelKeyRotationMLDSA: an empty sig must never verify")
	}
}

// ── rel_revoke self-revocation certificates ───────────────────────────────────

func TestRelRevokeSigVerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := SignRelRevoke(priv, "alice")
	if !VerifyRelRevoke(pub, "alice", sig) {
		t.Fatal("VerifyRelRevoke: valid signature refused")
	}
}

// TestRelRevokeSigStaysValidAfterKeyDisappears explicitly tests the
// property that makes pre-generation useful: verification depends only on
// pub/sig/username, never on priv, a caller can verify a revocation even
// after priv no longer exists (simulates what happens after a nuke, where
// only pub+sig survive, never priv).
func TestRelRevokeSigStaysValidAfterKeyDisappears(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevoke(priv, "alice")
	priv = nil // priv "gone", sig and pub survive on their own
	_ = priv
	if !VerifyRelRevoke(pub, "alice", sig) {
		t.Fatal("VerifyRelRevoke: verification must not depend on priv surviving")
	}
}

func TestRelRevokeSigWrongPubDoesNotVerify(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevoke(priv, "alice")
	if VerifyRelRevoke(otherPub, "alice", sig) {
		t.Fatal("VerifyRelRevoke: signature verified against a public key different from the signing one")
	}
}

func TestRelRevokeSigWrongLengthPubDoesNotPanic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevoke(priv, "alice")
	for _, badLen := range []int{0, 16, 31, 33, 64} {
		badPub := make(ed25519.PublicKey, badLen)
		if VerifyRelRevoke(badPub, "alice", sig) {
			t.Fatalf("VerifyRelRevoke: key of length %d accepted", badLen)
		}
	}
	if VerifyRelRevoke(nil, "alice", sig) {
		t.Fatal("VerifyRelRevoke: nil pub accepted")
	}
}

func TestRelRevokeSigTamperedUsername(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevoke(priv, "alice")
	if VerifyRelRevoke(pub, "bob", sig) {
		t.Fatal("VerifyRelRevoke: username different from the signed one accepted")
	}
}

func TestRelRevokeSigMLDSAVerifyRoundtrip(t *testing.T) {
	seed, pubBytes := newTestMLDSASeed(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevokeMLDSA(seed, pub, "alice")
	if !VerifyRelRevokeMLDSA(pubBytes, pub, "alice", sig) {
		t.Fatal("VerifyRelRevokeMLDSA: valid signature refused")
	}
}

func TestRelRevokeSigMLDSATamperedUsername(t *testing.T) {
	seed, pubBytes := newTestMLDSASeed(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevokeMLDSA(seed, pub, "alice")
	if VerifyRelRevokeMLDSA(pubBytes, pub, "bob", sig) {
		t.Fatal("VerifyRelRevokeMLDSA: username different from the signed one accepted")
	}
}

func TestRelRevokeSigMLDSAEmptyInputsRejected(t *testing.T) {
	seed, pubBytes := newTestMLDSASeed(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignRelRevokeMLDSA(seed, pub, "alice")
	if VerifyRelRevokeMLDSA(nil, pub, "alice", sig) {
		t.Fatal("VerifyRelRevokeMLDSA: a nil pub must never verify")
	}
	if VerifyRelRevokeMLDSA(pubBytes, pub, "alice", nil) {
		t.Fatal("VerifyRelRevokeMLDSA: an empty sig must never verify")
	}
}

// ── Device-level signature ───────────────────────────────────────────────────

func TestDeviceSigVerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := SignDeviceSig(priv, "dummy-ciphertext", "2026-08-10T12:00:00Z")
	if !VerifyDeviceSig(pub, "dummy-ciphertext", "2026-08-10T12:00:00Z", sig) {
		t.Fatal("VerifyDeviceSig: valid signature refused")
	}
}

func TestDeviceSigTamperedCiphertext(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignDeviceSig(priv, "original-ciphertext", "2026-08-10T12:00:00Z")
	if VerifyDeviceSig(pub, "different-ciphertext", "2026-08-10T12:00:00Z", sig) {
		t.Fatal("VerifyDeviceSig: ciphertext different from the signed one accepted")
	}
}

func TestDeviceSigWrongDevice(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignDeviceSig(priv, "ciphertext", "2026-08-10T12:00:00Z")
	if VerifyDeviceSig(otherPub, "ciphertext", "2026-08-10T12:00:00Z", sig) {
		t.Fatal("VerifyDeviceSig: signature verified against the wrong device's public key")
	}
}

func TestDeviceSigEmptyInputsRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := SignDeviceSig(priv, "ciphertext", "ts")
	if VerifyDeviceSig(nil, "ciphertext", "ts", sig) {
		t.Fatal("VerifyDeviceSig: an empty devicePub must never verify")
	}
	if VerifyDeviceSig(pub, "ciphertext", "ts", nil) {
		t.Fatal("VerifyDeviceSig: an empty sig must never verify")
	}
}

// ── Optional per-message PQC signature (hybrid network identity) ─────────────

func TestPQCSigVerifyRoundtrip(t *testing.T) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := SignPQCSig(priv, "dummy-ciphertext", "2026-08-10T12:00:00Z")
	if !VerifyPQCSig(pub, "dummy-ciphertext", "2026-08-10T12:00:00Z", sig) {
		t.Fatal("VerifyPQCSig: valid signature refused")
	}
}

func TestPQCSigTamperedCiphertext(t *testing.T) {
	pub, priv, _ := mldsa65.GenerateKey(rand.Reader)
	sig := SignPQCSig(priv, "original-ciphertext", "2026-08-10T12:00:00Z")
	if VerifyPQCSig(pub, "different-ciphertext", "2026-08-10T12:00:00Z", sig) {
		t.Fatal("VerifyPQCSig: ciphertext different from the signed one accepted")
	}
}

func TestPQCSigWrongKey(t *testing.T) {
	_, priv, _ := mldsa65.GenerateKey(rand.Reader)
	otherPub, _, _ := mldsa65.GenerateKey(rand.Reader)
	sig := SignPQCSig(priv, "ciphertext", "2026-08-10T12:00:00Z")
	if VerifyPQCSig(otherPub, "ciphertext", "2026-08-10T12:00:00Z", sig) {
		t.Fatal("VerifyPQCSig: signature verified against the wrong public key")
	}
}

func TestPQCSigEmptyInputsRejected(t *testing.T) {
	pub, priv, _ := mldsa65.GenerateKey(rand.Reader)
	sig := SignPQCSig(priv, "ciphertext", "ts")
	if VerifyPQCSig(nil, "ciphertext", "ts", sig) {
		t.Fatal("VerifyPQCSig: a nil pub must never verify")
	}
	if VerifyPQCSig(pub, "ciphertext", "ts", nil) {
		t.Fatal("VerifyPQCSig: an empty sig must never verify")
	}
}

func TestPQCSigNilPrivReturnsNil(t *testing.T) {
	if sig := SignPQCSig(nil, "ciphertext", "ts"); sig != nil {
		t.Fatal("SignPQCSig: a nil priv must return nil, not a signature")
	}
}

// ── remote_nuke ────────────────────────────────────────────────────────────────

func TestRemoteNukeSigVerifyRoundtrip(t *testing.T) {
	authorityPub, authorityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()

	sig := SignRemoteNuke(authorityPriv, targetDeviceID, ts)
	if !VerifyRemoteNuke(authorityPub, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNuke: valid signature refused")
	}
}

func TestRemoteNukeSigTamperedTarget(t *testing.T) {
	authorityPub, authorityPriv, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	otherDeviceID := make([]byte, 16)
	rand.Read(otherDeviceID)
	ts := NowTS()

	sig := SignRemoteNuke(authorityPriv, targetDeviceID, ts)
	if VerifyRemoteNuke(authorityPub, otherDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNuke: DeviceID different from the signed one accepted")
	}
}

func TestRemoteNukeSigWrongAuthority(t *testing.T) {
	_, authorityPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()

	sig := SignRemoteNuke(authorityPriv, targetDeviceID, ts)
	if VerifyRemoteNuke(otherPub, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNuke: signature verified against an unauthorized key")
	}
}

// ── RemoteNuke ML-DSA-65 (hybrid PQC network identity) ────────────────────────
// Here the risk covered is more concrete than the other two parallel
// signatures: a remote_nuke command forged with a broken Ed25519 would
// destroy a real device, not just compromise a certification.

func TestRemoteNukeSigMLDSAVerifyRoundtrip(t *testing.T) {
	authorityPub, authorityPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()

	sig := SignRemoteNukeMLDSA(authorityPriv, targetDeviceID, ts)
	if !VerifyRemoteNukeMLDSA(authorityPub, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNukeMLDSA: valid signature refused")
	}
}

func TestRemoteNukeSigMLDSATamperedTarget(t *testing.T) {
	authorityPub, authorityPriv, _ := mldsa65.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	otherDeviceID := make([]byte, 16)
	rand.Read(otherDeviceID)
	ts := NowTS()

	sig := SignRemoteNukeMLDSA(authorityPriv, targetDeviceID, ts)
	if VerifyRemoteNukeMLDSA(authorityPub, otherDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNukeMLDSA: DeviceID different from the signed one accepted")
	}
}

func TestRemoteNukeSigMLDSAWrongAuthority(t *testing.T) {
	_, authorityPriv, _ := mldsa65.GenerateKey(rand.Reader)
	otherPub, _, _ := mldsa65.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()

	sig := SignRemoteNukeMLDSA(authorityPriv, targetDeviceID, ts)
	if VerifyRemoteNukeMLDSA(otherPub, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNukeMLDSA: signature verified against an unauthorized key")
	}
}

func TestRemoteNukeSigMLDSAEmptyInputsRejected(t *testing.T) {
	authorityPub, authorityPriv, _ := mldsa65.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()
	sig := SignRemoteNukeMLDSA(authorityPriv, targetDeviceID, ts)
	if VerifyRemoteNukeMLDSA(nil, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNukeMLDSA: a nil authorityPub must never verify")
	}
	if VerifyRemoteNukeMLDSA(authorityPub, targetDeviceID, ts, nil) {
		t.Fatal("VerifyRemoteNukeMLDSA: an empty sig must never verify")
	}
}

func TestRemoteNukeAckSigVerifyRoundtrip(t *testing.T) {
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()

	sig := SignRemoteNukeAck(devicePriv, targetDeviceID, ts)
	if !VerifyRemoteNukeAck(devicePub, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNukeAck: valid signature refused")
	}
}

// TestRemoteNukeAckWrongDeviceRejected covers the distinction between the
// two keys involved in the protocol: an ack signature made with the
// AUTHORITY's key (instead of the TARGET DEVICE's key) must not verify
// against the device's devicePub, they're two different keys by
// construction, never interchangeable.
func TestRemoteNukeAckWrongDeviceRejected(t *testing.T) {
	devicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, authorityPriv, _ := ed25519.GenerateKey(rand.Reader)
	targetDeviceID := make([]byte, 16)
	rand.Read(targetDeviceID)
	ts := NowTS()

	sig := SignRemoteNukeAck(authorityPriv, targetDeviceID, ts)
	if VerifyRemoteNukeAck(devicePub, targetDeviceID, ts, sig) {
		t.Fatal("VerifyRemoteNukeAck: the authority's signature accepted in place of the device's")
	}
}

func TestTsFreshWithinWindow(t *testing.T) {
	if !TsFresh(NowTS()) {
		t.Fatal("a freshly generated timestamp must be fresh")
	}
}

func TestTsFreshRejectsOldAndFuture(t *testing.T) {
	old := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	if TsFresh(old) {
		t.Error("a timestamp from 10 minutes ago must not be fresh (±5 min window)")
	}
	future := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	if TsFresh(future) {
		t.Error("a timestamp 10 minutes in the future must not be fresh (±5 min window, drift tolerated but not abusable)")
	}
	malformed := "non-un-timestamp"
	if TsFresh(malformed) {
		t.Error("a malformed timestamp must never be fresh")
	}
}

// ── Safety code ───────────────────────────────────────────────────────────────

func TestSafetyCodeSymmetric(t *testing.T) {
	aPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bPub, _, _ := ed25519.GenerateKey(rand.Reader)

	codeAB := SafetyCode(aPub, bPub)
	codeBA := SafetyCode(bPub, aPub)
	if codeAB != codeBA {
		t.Fatalf("SafetyCode: not symmetric, %q vs %q", codeAB, codeBA)
	}
}

func TestSafetyCodeFormat(t *testing.T) {
	aPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bPub, _, _ := ed25519.GenerateKey(rand.Reader)
	code := SafetyCode(aPub, bPub)

	groups := strings.Split(code, " ")
	if len(groups) != 5 {
		t.Fatalf("SafetyCode: want 5 groups, got %d (%q)", len(groups), code)
	}
	for _, g := range groups {
		if len(g) != 8 {
			t.Errorf("SafetyCode: group %q of unexpected length %d", g, len(g))
		}
	}
	if len(code) != 44 { // 5*8 characters + 4 spaces
		t.Errorf("SafetyCode: want total length 44, got %d", len(code))
	}
}

func TestSafetyCodeDifferentForDifferentKeys(t *testing.T) {
	aPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cPub, _, _ := ed25519.GenerateKey(rand.Reader)

	if SafetyCode(aPub, bPub) == SafetyCode(aPub, cPub) {
		t.Fatal("SafetyCode: different key pairs produce the same code")
	}
}

// ── Symmetric ratchet (chain key) ────────────────────────────────────────────

func TestInitChainKeyDeterministic(t *testing.T) {
	senderKey, _ := RandomBytes(32)
	k1 := InitChainKey(senderKey)
	k2 := InitChainKey(senderKey)
	if !bytes.Equal(k1, k2) {
		t.Fatal("InitChainKey: not deterministic for the same senderKey")
	}
	if len(k1) != 32 {
		t.Fatalf("want length 32, got %d", len(k1))
	}
}

func TestDeriveChainStepAdvances(t *testing.T) {
	senderKey, _ := RandomBytes(32)
	chainKey := InitChainKey(senderKey)

	msgKey, nextChainKey := DeriveChainStep(chainKey)
	if bytes.Equal(msgKey, chainKey) {
		t.Error("DeriveChainStep: msgKey equal to chainKey")
	}
	if bytes.Equal(nextChainKey, chainKey) {
		t.Error("DeriveChainStep: nextChainKey equal to chainKey")
	}
	if bytes.Equal(msgKey, nextChainKey) {
		t.Error("DeriveChainStep: msgKey equal to nextChainKey")
	}

	// deterministic for the same input chainKey.
	msgKey2, nextChainKey2 := DeriveChainStep(chainKey)
	if !bytes.Equal(msgKey, msgKey2) || !bytes.Equal(nextChainKey, nextChainKey2) {
		t.Error("DeriveChainStep: not deterministic for the same chainKey")
	}

	// the next step must differ from the current one (advancing chain).
	_, nextChainKey3 := DeriveChainStep(nextChainKey)
	if bytes.Equal(nextChainKey3, nextChainKey) {
		t.Error("DeriveChainStep: two consecutive steps produce the same chain key")
	}
}

func TestDeriveChainStepDHMsgKeyMatchesNonDH(t *testing.T) {
	senderKey, _ := RandomBytes(32)
	chainKey := InitChainKey(senderKey)
	dhShared, _ := RandomBytes(32)

	msgKey, _ := DeriveChainStep(chainKey)
	msgKeyDH, nextChainKeyDH := DeriveChainStepDH(chainKey, dhShared)

	// by design msgKey doesn't depend on the DH (see comment in DeriveChainStepDH).
	if !bytes.Equal(msgKey, msgKeyDH) {
		t.Fatal("DeriveChainStepDH: msgKey diverges from DeriveChainStep for the same chainKey")
	}

	_, nextChainKeyPlain := DeriveChainStep(chainKey)
	if bytes.Equal(nextChainKeyDH, nextChainKeyPlain) {
		t.Fatal("DeriveChainStepDH: nextChainKey doesn't depend on the DH secret")
	}
}

func TestDeriveChainStepDHDependsOnSharedSecret(t *testing.T) {
	senderKey, _ := RandomBytes(32)
	chainKey := InitChainKey(senderKey)
	dhA, _ := RandomBytes(32)
	dhB, _ := RandomBytes(32)

	_, nextA := DeriveChainStepDH(chainKey, dhA)
	_, nextB := DeriveChainStepDH(chainKey, dhB)
	if bytes.Equal(nextA, nextB) {
		t.Fatal("DeriveChainStepDH: different DH secrets produce the same nextChainKey")
	}
}

// ── Derived identifiers ────────────────────────────────────────────────────────

func TestDeriveKeyIDStableAndDistinct(t *testing.T) {
	k1, _ := RandomBytes(32)
	k2, _ := RandomBytes(32)

	id1a, id1b := DeriveKeyID(k1), DeriveKeyID(k1)
	if id1a != id1b {
		t.Fatal("DeriveKeyID: not deterministic")
	}
	if DeriveKeyID(k1) == DeriveKeyID(k2) {
		t.Fatal("DeriveKeyID: different senderKeys produce the same ID")
	}
	if len(DeriveKeyID(k1)) != 8 {
		t.Fatalf("DeriveKeyID: want length 8, got %d", len(DeriveKeyID(k1)))
	}
}

func TestEphIDStableAndDistinct(t *testing.T) {
	p1, _ := RandomBytes(32)
	p2, _ := RandomBytes(32)

	eph1a, eph1b := EphID(p1), EphID(p1)
	if eph1a != eph1b {
		t.Fatal("EphID: not deterministic")
	}
	if EphID(p1) == EphID(p2) {
		t.Fatal("EphID: different pubkeys produce the same ID")
	}
	if len(EphID(p1)) != 8 {
		t.Fatalf("EphID: want length 8, got %d", len(EphID(p1)))
	}
}

// ── Onion address / room ID ───────────────────────────────────────────────────

func TestOnionAddressFromPubFormat(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	addr := OnionAddressFromPub(pub)
	if !strings.HasSuffix(addr, ".onion") {
		t.Fatalf("OnionAddressFromPub: missing the .onion suffix: %q", addr)
	}
	if addr != strings.ToLower(addr) {
		t.Error("OnionAddressFromPub: contains uppercase letters")
	}
}

func TestOnionAddressDeterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr1, addr2 := OnionAddressFromPub(pub), OnionAddressFromPub(pub)
	if addr1 != addr2 {
		t.Fatal("OnionAddressFromPub: not deterministic")
	}
}
