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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"neutrino/internal/i18n"
)

// Encrypt encrypts plaintext with AES-GCM. Returns base64(nonce+ciphertext).
// aad is authenticated additional data bound into the GCM tag (nil = no AAD).
// Pass a big-endian uint64 sequence number as aad for sequenced message streams.
func Encrypt(key, plaintext, aad []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt decrypts a base64(nonce+ciphertext) produced by Encrypt.
// aad must match exactly what was passed to Encrypt; any mismatch causes authentication failure.
func Decrypt(key []byte, encoded string, aad []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New(i18n.T("shared.err_ciphertext_short"))
	}
	return gcm.Open(nil, data[:ns], data[ns:], aad)
}

// ECIESEncrypt encrypts plaintext for recipientPub using ephemeral X25519 + AES-256-GCM.
// Wire format: base64(ephPub[32] ‖ nonce[12] ‖ ciphertext ‖ tag[16])
func ECIESEncrypt(recipientPub *ecdh.PublicKey, plaintext []byte) (string, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return "", err
	}
	channelKey, err := eciesChannelKey(shared, ephPriv.PublicKey().Bytes(), recipientPub.Bytes())
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(channelKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	payload := append(ephPriv.PublicKey().Bytes(), ct...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

// ECIESDecrypt decrypts a payload produced by ECIESEncrypt.
func ECIESDecrypt(myPriv *ecdh.PrivateKey, payloadB64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_ecies_decode", err))
	}
	if len(data) < 32 {
		return nil, errors.New(i18n.T("shared.err_ecies_payload_short"))
	}
	ephPubBytes := data[:32]
	ct := data[32:]
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_ecies_ephemeral_key", err))
	}
	shared, err := myPriv.ECDH(ephPub)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_ecies_ecdh", err))
	}
	channelKey, err := eciesChannelKey(shared, ephPubBytes, myPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(channelKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ct) < ns {
		return nil, errors.New(i18n.T("shared.err_ecies_ciphertext_short"))
	}
	return gcm.Open(nil, ct[:ns], ct[ns:], nil)
}

func eciesChannelKey(sharedSecret, ephPub, recipientPub []byte) ([]byte, error) {
	info := append(append([]byte("neutrino-ecies:"), ephPub...), recipientPub...)
	r := hkdf.New(sha256.New, sharedSecret, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// HybridECIESEncrypt encrypts plaintext for a recipient by combining an
// ephemeral X25519 ECDH (like ECIESEncrypt) with an ML-KEM-768
// encapsulation toward their encapsulation key — used for peer-to-peer
// delivery of sender_key.
// No second X25519/ML-KEM key pair to generate here: recipientPub and
// recipientMLKEMPub are the ones already exchanged in the handshake
// (ClientHello.ECIESPub/MLKEMPub, relayed to other members via
// wsUserJoined/userInfo — see HandshakeResult.PeerMLKEMPub). Safe by
// construction: an ML-KEM encapsulation key can receive Encapsulate() from
// many different parties (server for the handshake, N peers for the
// sender_key) with no loss of security — unlike a DH nonce, that's the
// whole point of a KEM.
// Wire format: base64(ephPub[32] ‖ mlkemCiphertext[1088] ‖ nonce[12] ‖ ciphertext ‖ tag[16])
func HybridECIESEncrypt(recipientPub *ecdh.PublicKey, recipientMLKEMPub *mlkem.EncapsulationKey768, plaintext []byte) (string, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	dhSecret, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return "", err
	}
	mlkemSS, mlkemCiphertext := recipientMLKEMPub.Encapsulate()
	channelKey, err := hybridECIESChannelKey(mlkemSS, dhSecret, ephPriv.PublicKey().Bytes(), recipientPub.Bytes())
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(channelKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	payload := make([]byte, 0, 32+len(mlkemCiphertext)+len(ct))
	payload = append(payload, ephPriv.PublicKey().Bytes()...)
	payload = append(payload, mlkemCiphertext...)
	payload = append(payload, ct...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

// HybridECIESDecrypt decrypts a payload produced by HybridECIESEncrypt.
func HybridECIESDecrypt(myPriv *ecdh.PrivateKey, myMLKEMPriv *mlkem.DecapsulationKey768, payloadB64 string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_hybrid_ecies_decode", err))
	}
	const headerLen = 32 + mlkem.CiphertextSize768
	if len(data) < headerLen {
		return nil, errors.New(i18n.T("shared.err_hybrid_ecies_payload_short"))
	}
	ephPubBytes := data[:32]
	mlkemCiphertext := data[32:headerLen]
	ct := data[headerLen:]
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_hybrid_ecies_ephemeral_key", err))
	}
	dhSecret, err := myPriv.ECDH(ephPub)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_hybrid_ecies_ecdh", err))
	}
	mlkemSS, err := myMLKEMPriv.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, errors.New(i18n.T("shared.err_hybrid_ecies_mlkem_decap", err))
	}
	channelKey, err := hybridECIESChannelKey(mlkemSS, dhSecret, ephPubBytes, myPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(channelKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ct) < ns {
		return nil, errors.New(i18n.T("shared.err_hybrid_ecies_ciphertext_short"))
	}
	return gcm.Open(nil, ct[:ns], ct[ns:], nil)
}

// hybridECIESChannelKey derives the channel key from the combined secret
// mlkemSS‖dhSecret — same order and reasoning as DeriveSessionKey: ML-KEM
// (FIPS 203) precedes X25519 (not FIPS-approved), per NIST SP 800-56Cr2 §2.
func hybridECIESChannelKey(mlkemSS, dhSecret, ephPub, recipientPub []byte) ([]byte, error) {
	combined := make([]byte, 0, len(mlkemSS)+len(dhSecret))
	combined = append(combined, mlkemSS...)
	combined = append(combined, dhSecret...)
	info := append(append([]byte("neutrino-ecies-x25519-mlkem768-v1:"), ephPub...), recipientPub...)
	r := hkdf.New(sha256.New, combined, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// ── Handshake — cryptographic primitives ─────────────────────────────────────

// ComputeRoomProof computes HMAC-SHA256(roomKey, nonceClient).
// The client includes it in ClientHello as proof of knowledge of S.
func ComputeRoomProof(roomKey, nonceClient []byte) []byte {
	mac := hmac.New(sha256.New, roomKey)
	mac.Write(nonceClient)
	return mac.Sum(nil)
}

// VerifyRoomProof verifies proof in constant time against the shared
// secret. Tries the current period and period+1 to cover the overlap
// window. Returns the valid period and true, or 0 and false.
func VerifyRoomProof(secret, nonceClient, proof []byte) (int64, bool) {
	for _, p := range []int64{CurrentPeriod(), CurrentPeriod() + 1} {
		roomKey, err := DeriveContactRoomKey(secret, p)
		if err != nil {
			continue
		}
		expected := ComputeRoomProof(roomKey, nonceClient)
		if hmac.Equal(expected, proof) {
			return p, true
		}
	}
	return 0, false
}

// DeriveSessionKey derives the 32-byte session key from the full transcript:
//
//	transcript  = nonceClient || nonceServer || sessionPubClient || sessionPubServer
//	combined_ss = mlkemSS || dhSecret
//	session_key = HKDF-SHA256(combined_ss, transcript, "neutrino-session-x25519-mlkem768-v1")
//
// Including both session pubs in the salt cryptographically ties the key to
// the connection's specific endpoints, preventing relay/key-confusion
// attacks.
//
// combined_ss: ML-KEM-768 first, then X25519 — same order as the TLS 1.3
// X25519MLKEM768 hybrid group (draft-ietf-tls-ecdhe-mlkem), in turn mandated
// by NIST SP 800-56Cr2 §2 (the first FIPS-approved algorithm's secret
// precedes the non-approved one; X25519 is not FIPS-approved, ML-KEM is).
func DeriveSessionKey(mlkemSS, dhSecret, nonceClient, nonceServer, sessionPubClient, sessionPubServer []byte) ([]byte, error) {
	combined := make([]byte, 0, len(mlkemSS)+len(dhSecret))
	combined = append(combined, mlkemSS...)
	combined = append(combined, dhSecret...)

	transcript := make([]byte, 0, len(nonceClient)+len(nonceServer)+len(sessionPubClient)+len(sessionPubServer))
	transcript = append(transcript, nonceClient...)
	transcript = append(transcript, nonceServer...)
	transcript = append(transcript, sessionPubClient...)
	transcript = append(transcript, sessionPubServer...)
	r := hkdf.New(sha256.New, combined, transcript, []byte("neutrino-session-x25519-mlkem768-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ClientSigPayload returns the bytes the client must sign:
// nonce_client || session_pub_client.
func ClientSigPayload(nonceClient, sessionPub []byte) []byte {
	return append(append([]byte(nil), nonceClient...), sessionPub...)
}

// ServerSigPayload returns the bytes the server must sign:
// nonce_client || nonce_server || session_pub_server.
func ServerSigPayload(nonceClient, nonceServer, sessionPub []byte) []byte {
	out := append(append([]byte(nil), nonceClient...), nonceServer...)
	return append(out, sessionPub...)
}

// ── Tor hidden service — time-based derivation ────────────────────────────────

const periodSeconds = 43200 // 12 hours — rotations at 00:00 and 12:00 UTC

// CurrentPeriod returns the current 12-hour period index.
// Both peers compute the same value independently from UTC time.
func CurrentPeriod() int64 {
	return time.Now().UTC().Unix() / periodSeconds
}

// OnionAddressFromPub computes the Tor v3 .onion hostname from an Ed25519 public key.
// Useful when only the contact's public key is known.
func OnionAddressFromPub(pub ed25519.PublicKey) string {
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pub)
	h.Write([]byte{0x03})
	checksum := h.Sum(nil)[:2]
	payload := make([]byte, 35)
	copy(payload[:32], pub)
	copy(payload[32:34], checksum)
	payload[34] = 0x03
	return strings.ToLower(base32.StdEncoding.EncodeToString(payload)) + ".onion"
}

// ── Knock ────────────────────────────────────────────────────────────────────

// MemberInfo describes a member in a group invite.
type MemberInfo struct {
	Username    string `json:"username"`
	IdentityPub []byte `json:"identity_pub"` // Ed25519 pubkey (32 bytes)
}

// KnockPayload is the encrypted content of a knock, a group invite, a
// public key update, or an update ack. Encrypted with ECIES using the
// recipient's Ed25519 public key.
//
// Type selects the knock's purpose. Among them:
//   - ""                → knock/invite (RoomSecret populated)
//   - "probe_ping"      → periodic reachability ping, answered with "probe_ack"
//   - "rel_init"        → first communication of relationship keys toward a
//     newly added contact (RelBootstrap populated) — see below
//   - "rel_init_ack"    → symmetric counterpart of rel_init (same payload, name
//     differs only for log clarity — see RelBootstrap)
//
// The other types (root_rotate, rel_identity_rotate, rel_revoke,
// remote_nuke, danger_broadcast, danger_end, device_sync,
// contact_tombstone, probe_ping, wake, ...) each carry their own payload
// field; most have an "_ack" counterpart confirming receipt.
//
// Empty GroupID and Members (with Type "") = a private two-party knock; populated = group invite.
type KnockPayload struct {
	Type            string       `json:"type,omitempty"`
	FromUsername    string       `json:"from_username"`
	FromIdentityPub []byte       `json:"from_identity_pub"` // new/current Ed25519 pubkey
	RoomSecret      []byte       `json:"room_secret,omitempty"`
	FromAddr        string       `json:"from_addr,omitempty"`
	GroupID         string       `json:"group_id,omitempty"`
	Members         []MemberInfo `json:"members,omitempty"`
	// MLKEMPub is the sender's current durable ML-KEM-768 encapsulation
	// key (1184 bytes) — lets the recipient reply in hybrid form. Empty
	// when the sender has no ML-KEM key: knocks toward them stay classic
	// until a later rotation or a new QR carries one.
	MLKEMPub []byte `json:"mlkem_pub,omitempty"`

	// RelBootstrap carries the sender's public relationship keys toward the
	// recipient (Type "rel_init"/"rel_init_ack" only) — reuses the same
	// struct already written for the ephemeral in-room bootstrap
	// (RelBootstrapPayload, relbootstrap.go), here in a persistent context:
	// exchanged only once when two users become each other's contact
	// (after /cnt-add), not on every invite to a room. The knock only
	// arrives if KnockDHTag's mutuality already matches, which guarantees
	// the recipient already has the sender as a known contact: no on-the-fly
	// Contact creation is ever needed here.
	RelBootstrap *RelBootstrapPayload `json:"rel_bootstrap,omitempty"`

	// RelRotate carries the rotation of ONE of the two relationship keys
	// toward the recipient — Type "rel_identity_rotate"/
	// "rel_identity_rotate_ack" (IdentityKey-per-relationship) or
	// "rel_content_rotate"/"rel_content_rotate_ack"
	// (ContentKey-per-relationship), never both in the same knock. See
	// RelRotatePayload (relrotate.go).
	RelRotate *RelRotatePayload `json:"rel_rotate,omitempty"`

	// DevicePub/DeviceSig co-sign the knock with the sender's device-level
	// key (see keystore.Keystore.DevicePriv/DevicePub)
	// — verified and shown (TOFU on Contact.KnownDevicePub), never
	// blocking. Unlike chat messages (where the device's public key travels
	// inside the ciphertext, see sealedMsg.DP), here the whole KnockPayload
	// is already inside the knock's encrypted envelope: no bootstrap
	// problem, DevicePub and the signature arrive together. NOT the same
	// field as TargetDeviceID (remote_nuke protocol) — that one
	// identifies the TARGET device (16 random bytes, Keystore.DeviceID),
	// this one the KEY that signs it (32 bytes Ed25519).
	DevicePub []byte `json:"device_pub,omitempty"`
	DeviceSig []byte `json:"device_sig,omitempty"`

	// Fields of the remote_nuke protocol, Type "remote_nuke" /
	// "remote_nuke_ack" / "danger_broadcast". TargetDeviceID has a
	// different meaning depending on Type: for remote_nuke it's the device
	// TO WIPE (target's Keystore.DeviceID); for danger_broadcast it's the
	// device ANNOUNCING ITSELF as compromised (informational, no signature
	// required — see below); absent for remote_nuke_ack (implicit, it's
	// always the responder). NukeTs/NukeSig are used only by remote_nuke
	// (signed by the AUTHORITY, RemoteNukeMsg/SignRemoteNuke) and
	// remote_nuke_ack (signed by the TARGET device,
	// RemoteNukeAckMsg/SignRemoteNukeAck) — two distinct signature schemes
	// on the same field name, never confusable because Type distinguishes
	// them.
	TargetDeviceID []byte `json:"target_device_id,omitempty"`
	NukeTs         string `json:"nuke_ts,omitempty"`
	NukeSig        []byte `json:"nuke_sig,omitempty"`
	// NukeSigMLDSA is the parallel ML-DSA-65 signature of NukeSig (hybrid
	// PQC network identity) — SignRemoteNukeMLDSA, Type
	// "remote_nuke" only (the ack stays signed with DevicePriv, a different
	// key, out of scope here — see SignRemoteNukeAck).
	NukeSigMLDSA []byte `json:"nuke_sig_mldsa,omitempty"`

	// RootRotate carries the announcement of a root IdentityKey rotation
	// toward a contact — Type "root_rotate" (request) / "root_rotate_ack"
	// (confirmation, RootRotate nil in that direction: no new
	// certification, just a fire-and-forget confirmation). See
	// RootRotatePayload.
	RootRotate *RootRotatePayload `json:"root_rotate,omitempty"`

	// DeviceSync carries the my-device→my-device channel — Type
	// "device_sync" (request, addressed via
	// Keystore.NetworkIdentityPrivKeyFor, never through a contact) /
	// "device_sync_ack" (confirmation, same DeviceSync echoed or nil
	// depending on content — see DeviceSyncPayload).
	DeviceSync *DeviceSyncPayload `json:"device_sync,omitempty"`

	// RelRevoke carries the revocation of one or both relationship keys of
	// ONE device toward the recipient — Type "rel_revoke" (announcement,
	// signatures populated) / "rel_revoke_ack" (confirmation, only
	// DevicePub populated). See RelRevokePayload (relrevoke.go).
	RelRevoke *RelRevokePayload `json:"rel_revoke,omitempty"`

	// ContactTombstone carries the contact-deletion reconciliation
	// protocol between sibling devices — Type "contact_tombstone"
	// (Rows populated: JSON-marshaled tombstone rows for a contact the
	// sender just received as live but already knows deleted) /
	// "contact_tombstone_ack" (Acked populated: JSON-marshaled list of
	// IdentityPubs the recipient of Rows has adopted). See
	// ContactTombstonePayload.
	ContactTombstone *ContactTombstonePayload `json:"contact_tombstone,omitempty"`
}

// ContactTombstonePayload is KnockPayload.ContactTombstone's content —
// Rows and Acked are both JSON-marshaled byte blobs rather than typed
// values because this package never imports internal/keystore (the
// Go type for a tombstone row lives there): the caller marshals/
// unmarshals them.
type ContactTombstonePayload struct {
	Rows  []byte `json:"rows,omitempty"`
	Acked []byte `json:"acked,omitempty"`
}

// mldsaSign/mldsaVerify are internal helpers shared by all the network
// identity's parallel ML-DSA-65 signatures (SignRootRotationMLDSA,
// SignRemoteNukeMLDSA) — avoid repeating the buffer-allocation boilerplate
// required by mldsa65.SignTo at every call site.
// randomized=true ("hedged" signature, FIPS 204's default recommendation) —
// no context string (ctx=nil), no extra domain separation needed beyond the
// prefix already present in every *Msg.
func mldsaSign(priv *mldsa65.PrivateKey, msg []byte) []byte {
	sig := make([]byte, mldsa65.SignatureSize)
	// The only possible error from SignTo is a wrong-length buffer
	// (impossible here, explicitly sized above) — ignored to keep the same
	// "returns []byte" shape as the Ed25519 signatures already used in this
	// file (SignRemoteNuke, SignRootRotation, etc.).
	_ = mldsa65.SignTo(priv, msg, nil, true, sig)
	return sig
}

func mldsaVerify(pub *mldsa65.PublicKey, msg, sig []byte) bool {
	return mldsa65.Verify(pub, msg, nil, sig)
}

// mldsaPrivFromSeed/mldsaPubFromBytes derive a complete ML-DSA-65 key from,
// respectively, a raw seed (32 bytes, as already stored on
// Contact.RelIdentityMLDSAPriv/RelContentMLDSAPriv) or a packed public key —
// nil on absent/malformed input, never a panic. Used only by
// SignRelKeyRotationMLDSA/VerifyRelKeyRotationMLDSA: this file's other
// ML-DSA signers (SignRemoteNukeMLDSA...) already receive the derived
// object from the caller, a distinct design choice kept here only where the
// caller (tui.go) always has nothing but raw bytes available anyway.
func mldsaPrivFromSeed(seed []byte) *mldsa65.PrivateKey {
	if len(seed) != mldsa65.SeedSize {
		return nil
	}
	var s [mldsa65.SeedSize]byte
	copy(s[:], seed)
	_, priv := mldsa65.NewKeyFromSeed(&s)
	return priv
}

func mldsaPubFromBytes(b []byte) *mldsa65.PublicKey {
	if len(b) == 0 {
		return nil
	}
	pub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(b)
	if err != nil {
		return nil
	}
	p, _ := pub.(*mldsa65.PublicKey)
	return p
}

// RelKeyRotationMsg is the common signed message for the rotation of ONE
// relationship key (IdentityKey-per-contact or ContentKey-per-contact),
// certified by the stable SIBLING key — the two keys involved are always
// different by construction. Separate signing domain ("rel_key_rotate:") so
// no ambiguity is ever possible with a message signed by another scheme in
// the project. ts is included in the SIGNED message (not just the payload):
// without this, an attacker could rewrite ts on a captured message without
// invalidating the signature, defeating the freshness check (TsFresh) done
// by the receiver. The caller must re-sign with a fresh ts on every single
// send/retry — see probeContacts, which already does this on every probe
// cycle.
// msg = "rel_key_rotate:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ newPub
func RelKeyRotationMsg(newPub ed25519.PublicKey, username string, ts string) []byte {
	return append([]byte("rel_key_rotate:"+username+":"+ts+":"), newPub...)
}

// SignRelKeyRotation signs RelKeyRotationMsg with the sibling relationship
// key (Ed25519).
func SignRelKeyRotation(certifyingPriv ed25519.PrivateKey, newPub ed25519.PublicKey, username string, ts string) []byte {
	return ed25519.Sign(certifyingPriv, RelKeyRotationMsg(newPub, username, ts))
}

// VerifyRelKeyRotation verifies SignRelKeyRotation with the already-known
// sibling public key (Contact.PeerRelIdentityPub/PeerRelContentPub,
// depending on which key is rotating — never one's own). Verifies ONLY the
// message's authenticity (ts‖newPub signed together) — the caller must
// separately verify TsFresh(ts) for replay protection.
func VerifyRelKeyRotation(certifyingPub, newPub ed25519.PublicKey, username string, ts string, sig []byte) bool {
	if len(certifyingPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(certifyingPub, RelKeyRotationMsg(newPub, username, ts), sig)
}

// SignRelKeyRotationMLDSA/VerifyRelKeyRotationMLDSA — parallel ML-DSA-65
// counterpart of SignRelKeyRotation/VerifyRelKeyRotation, never blocking if
// absent (one of the two parties doesn't yet have an ML-DSA companion for
// that relationship key). Unlike SignRemoteNukeMLDSA (which takes an
// already-derived *mldsa65.PrivateKey/PublicKey), here the caller (tui.go)
// always passes raw bytes already present on Contact — seed to sign, packed
// key to verify — the derivation happens here.
func SignRelKeyRotationMLDSA(certifyingMLDSASeed []byte, newPub ed25519.PublicKey, username string, ts string) []byte {
	priv := mldsaPrivFromSeed(certifyingMLDSASeed)
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, RelKeyRotationMsg(newPub, username, ts))
}

func VerifyRelKeyRotationMLDSA(certifyingMLDSAPubBytes []byte, newPub ed25519.PublicKey, username string, ts string, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	pub := mldsaPubFromBytes(certifyingMLDSAPubBytes)
	if pub == nil {
		return false
	}
	return mldsaVerify(pub, RelKeyRotationMsg(newPub, username, ts), sig)
}

// RootRotationMsg is the common signed message for the announcement of a
// root IdentityKey (network address) rotation toward a contact. Continuity
// is certified by the RelIdentityKey-per-contact (stable, independent per
// contact, survives a compromise of the root alone) — never by the old root
// itself. Separate signing domain ("root_rotate:"), ts included in the
// signed message for the same reason as RelKeyRotationMsg (the caller
// re-signs with a fresh ts on every send/retry).
// msg = "root_rotate:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ newIdentityPub
func RootRotationMsg(newIdentityPub ed25519.PublicKey, username string, ts string) []byte {
	return append([]byte("root_rotate:"+username+":"+ts+":"), newIdentityPub...)
}

// SignRootRotation signs RootRotationMsg with the RelIdentityKey-per-contact
// (Ed25519) toward the recipient to whom NewIdentityPub is announced.
func SignRootRotation(certifyingPriv ed25519.PrivateKey, newIdentityPub ed25519.PublicKey, username string, ts string) []byte {
	return ed25519.Sign(certifyingPriv, RootRotationMsg(newIdentityPub, username, ts))
}

// VerifyRootRotation verifies SignRootRotation with the already-known
// RelIdentityKey-per-contact (Contact.Devices[...].PeerRelIdentityPub).
// Verifies ONLY the message's authenticity — the caller must separately
// verify TsFresh(ts) for replay protection.
func VerifyRootRotation(certifyingPub, newIdentityPub ed25519.PublicKey, username string, ts string, sig []byte) bool {
	if len(certifyingPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(certifyingPub, RootRotationMsg(newIdentityPub, username, ts), sig)
}

// SignRootRotationMLDSA/VerifyRootRotationMLDSA — parallel ML-DSA-65
// counterpart of SignRootRotation/VerifyRootRotation, never blocking if
// absent.
func SignRootRotationMLDSA(certifyingMLDSASeed []byte, newIdentityPub ed25519.PublicKey, username string, ts string) []byte {
	priv := mldsaPrivFromSeed(certifyingMLDSASeed)
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, RootRotationMsg(newIdentityPub, username, ts))
}

func VerifyRootRotationMLDSA(certifyingMLDSAPubBytes []byte, newIdentityPub ed25519.PublicKey, username string, ts string, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	pub := mldsaPubFromBytes(certifyingMLDSAPubBytes)
	if pub == nil {
		return false
	}
	return mldsaVerify(pub, RootRotationMsg(newIdentityPub, username, ts), sig)
}

// RelMsgSigPayload is the common signed message to attest a room message
// toward ONE specific recipient, with the ContentKey-per-relationship
// (persistent for a real contact, ephemeral for an introduced stranger). A
// broadcast message in a room with N members carries up to N-1 distinct
// signatures, one per pairwise relationship present — never a key shared by
// more than two parties. ciphertext is the same SenderKey-encrypted text
// broadcast to everyone (never the plaintext: whoever can't decrypt it must
// not be able to infer anything from the signature either), for is the
// recipient's member key (its root identity key, base64) this specific
// signature is computed for — never a username, which two members may
// share.
// msg = "rel_msg:" ‖ for ‖ ":" ‖ ciphertext ‖ ":" ‖ ts
func RelMsgSigPayload(ciphertext, ts, forMember string) []byte {
	return []byte("rel_msg:" + forMember + ":" + ciphertext + ":" + ts)
}

// SignRelMsg/VerifyRelMsg — Ed25519, relationship key (sender's
// RelContentPriv toward forMember / PeerRelContentPub known to the
// recipient).
func SignRelMsg(priv ed25519.PrivateKey, ciphertext, ts, forMember string) []byte {
	return ed25519.Sign(priv, RelMsgSigPayload(ciphertext, ts, forMember))
}

func VerifyRelMsg(pub ed25519.PublicKey, ciphertext, ts, forMember string, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, RelMsgSigPayload(ciphertext, ts, forMember), sig)
}

// SignRelMsgMLDSA/VerifyRelMsgMLDSA — parallel ML-DSA-65 counterpart, never
// blocking if absent (one of the two parties doesn't yet have an ML-DSA
// companion for that ContentKey). Same on-the-fly derivation scheme as
// SignRelKeyRotationMLDSA/VerifyRelKeyRotationMLDSA (mldsaPrivFromSeed/
// mldsaPubFromBytes): the caller (tui.go/client.go) always passes raw bytes
// already present on Contact/ephemeralRel.
func SignRelMsgMLDSA(mldsaSeed []byte, ciphertext, ts, forMember string) []byte {
	priv := mldsaPrivFromSeed(mldsaSeed)
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, RelMsgSigPayload(ciphertext, ts, forMember))
}

func VerifyRelMsgMLDSA(mldsaPubBytes []byte, ciphertext, ts, forMember string, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	pub := mldsaPubFromBytes(mldsaPubBytes)
	if pub == nil {
		return false
	}
	return mldsaVerify(pub, RelMsgSigPayload(ciphertext, ts, forMember), sig)
}

// ContentSigEntry carries, for ONE single recipient of a broadcast room
// message, the message signature with the sender's ContentKey-per-relationship
// toward them (SignRelMsg/SignRelMsgMLDSA above). Exported from
// internal/shared (not just internal/client) because the server must read
// it from the incoming frame and relay it intact to recipients
// (internal/server/ws.go: wsIncoming.ContentSigs / wsRawMsgData.ContentSigs)
// — without this shared type, the "content_sigs" JSON tags written by the
// sender (Client.Send) would be read into a wsIncoming that doesn't declare
// them at all and so would be silently dropped by encoding/json before
// being relayed.
type ContentSigEntry struct {
	For      string `json:"for"`
	Sig      []byte `json:"sig"`
	SigMLDSA []byte `json:"sig_mldsa,omitempty"`
}

// FileOfferEnvelope carries, for ONE single file_offer recipient, the
// meta_blob encrypted specifically for them (EncryptForPeer toward their
// ContentKey: {file_name, file_size, file_key} — file_key is the symmetric
// AES-256-GCM key that encrypts the file content once for everyone,
// distributed one recipient at a time instead of with a native
// multi-recipient format). A file_offer with N recipients carries N of
// these, never a shared envelope. Carries no signature — that lives only
// in FileAnnounceEnvelope, below, verified BEFORE this frame is even built: a
// file_offer reaches the recipient only after its authenticity is already
// established.
type FileOfferEnvelope struct {
	MetaBlob string `json:"meta_blob"`
}

// FileAnnounceEnvelope carries, for ONE single recipient, the signature
// over the HASH of the shared ciphertext (never the ciphertext itself, not
// yet transferred at this point) — an announcement phase that precedes any
// actual file_offer/chunk. Verifiable at near-zero cost as soon as it
// arrives: if the signature doesn't check out (sender's key out of sync),
// self-heal can kick in and resync BEFORE a single byte of the file is
// transferred — unlike a "downstream" verification, a failure here doesn't
// throw away anything expensive. Same signature scheme as chat messages
// (SignRelMsg/SignRelMsgMLDSA, RelMsgSigPayload also ties the signature to
// For, here the username of this envelope's recipient) — only the signed
// "message" is the hex hash, not the whole ciphertext.
type FileAnnounceEnvelope struct {
	Sig      []byte `json:"sig"`
	SigMLDSA []byte `json:"sig_mldsa,omitempty"`
}

// DeviceSigMsg is the message signed by the device-level key — used both
// on ordinary chat messages (ciphertext = enc, ts = timestamp external to
// the ciphertext) and on knocks (ciphertext = the
// knock's encrypted payload). No device identifier inside the signed
// message: the public key used to VERIFY the signature is already the
// identifier itself — including it in the signed text too would be
// circular. Only ties the signature to the moment it was produced, against
// reuse of a signature captured in the past — not a strict anti-replay
// mechanism in itself (that lives in the remote_nuke protocol, not
// here).
// msg = "device_sig:" ‖ ts ‖ ":" ‖ ciphertext
func DeviceSigMsg(ciphertext, ts string) []byte {
	msg := append([]byte("device_sig:"), []byte(ts)...)
	msg = append(msg, ':')
	msg = append(msg, []byte(ciphertext)...)
	return msg
}

// SignDeviceSig signs DeviceSigMsg with the device-level private key.
func SignDeviceSig(devicePriv ed25519.PrivateKey, ciphertext, ts string) []byte {
	return ed25519.Sign(devicePriv, DeviceSigMsg(ciphertext, ts))
}

// VerifyDeviceSig verifies DeviceSigMsg with the device-level public key.
func VerifyDeviceSig(devicePub ed25519.PublicKey, ciphertext, ts string, sig []byte) bool {
	if len(devicePub) == 0 || len(sig) == 0 {
		return false
	}
	return ed25519.Verify(devicePub, DeviceSigMsg(ciphertext, ts), sig)
}

// PQCSigMsg is the message signed by the network identity's ML-DSA-65 key
// when the optional per-room PQC signature (hybrid network identity) is
// active on a chat message — same scheme as DeviceSigMsg, same reasoning:
// no identifier inside the signed message (the public key used to verify
// is already the identifier), only ties the signature to the moment it was
// produced.
// msg = "pqc_sig:" ‖ ts ‖ ":" ‖ ciphertext
func PQCSigMsg(ciphertext, ts string) []byte {
	msg := append([]byte("pqc_sig:"), []byte(ts)...)
	msg = append(msg, ':')
	msg = append(msg, []byte(ciphertext)...)
	return msg
}

// SignPQCSig signs PQCSigMsg with the network identity's ML-DSA-65 private key.
func SignPQCSig(priv *mldsa65.PrivateKey, ciphertext, ts string) []byte {
	if priv == nil {
		return nil
	}
	return mldsaSign(priv, PQCSigMsg(ciphertext, ts))
}

// VerifyPQCSig verifies PQCSigMsg with the sender's network identity
// ML-DSA-65 public key — never blocking for the caller: just an absent or
// unverifiable signature, never a message rejection.
func VerifyPQCSig(pub *mldsa65.PublicKey, ciphertext, ts string, sig []byte) bool {
	if pub == nil || len(sig) == 0 {
		return false
	}
	return mldsaVerify(pub, PQCSigMsg(ciphertext, ts), sig)
}

// ── timestamp freshness (remote_nuke, rel_key_rotate) ─────────────────────────

// TsFreshnessWindow — validity window of a signed timestamp (RFC3339)
// verified with TsFresh, in both directions relative to the verifier's
// local clock: prevents replay of a message intercepted in the past, while
// still tolerating a reasonable clock drift between the two devices (no
// guaranteed NTP sync, especially on Termux). Shared by remote_nuke
// (RemoteNukeMsg) and rel_key_rotate (RelKeyRotationMsg) — same principle,
// same tolerance, a single place to change if the window needs adjusting.
const TsFreshnessWindow = 5 * time.Minute

// TsFresh verifies that ts (RFC3339) is within TsFreshnessWindow of the
// current instant. A malformed ts = not fresh.
func TsFresh(ts string) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	d := time.Since(t)
	if d < 0 {
		d = -d
	}
	return d <= TsFreshnessWindow
}

// RemoteNukeMsg is the signed message for a remote_nuke command: ties the
// target DeviceID to a timestamp (verified with TsFresh by the receiver)
// against replay of a command intercepted in the past.
// msg = "remote_nuke:" ‖ targetDeviceID ‖ ":" ‖ ts
func RemoteNukeMsg(targetDeviceID []byte, ts string) []byte {
	msg := append([]byte("remote_nuke:"), targetDeviceID...)
	msg = append(msg, ':')
	msg = append(msg, []byte(ts)...)
	return msg
}

// SignRemoteNuke signs a remote_nuke command with the Ed25519 private key
// of an identity also held on the target device — the AUTHORITY: no
// separate role, possession of the private key is itself the authorization
// to wipe that device.
func SignRemoteNuke(authorityPriv ed25519.PrivateKey, targetDeviceID []byte, ts string) []byte {
	return ed25519.Sign(authorityPriv, RemoteNukeMsg(targetDeviceID, ts))
}

// VerifyRemoteNuke verifies a remote_nuke command against the public key of
// a sibling identity of the target device (the caller tries it against each
// local identity, both current AND old during an in-progress rotation — no
// list of "authorized devices" to consult: possession is the proof).
func VerifyRemoteNuke(authorityPub ed25519.PublicKey, targetDeviceID []byte, ts string, sig []byte) bool {
	if len(authorityPub) == 0 || len(sig) == 0 {
		return false
	}
	return ed25519.Verify(authorityPub, RemoteNukeMsg(targetDeviceID, ts), sig)
}

// SignRemoteNukeMLDSA signs the same RemoteNukeMsg with the AUTHORITY's
// ML-DSA-65 key — same reasoning and same treatment (never blocking,
// additional verification on top of SignRemoteNuke) as the other parallel
// signatures above. Here the risk covered is more concrete than the other
// two: a remote_nuke command forged with a broken Ed25519 would destroy a
// real device.
func SignRemoteNukeMLDSA(authorityPriv *mldsa65.PrivateKey, targetDeviceID []byte, ts string) []byte {
	return mldsaSign(authorityPriv, RemoteNukeMsg(targetDeviceID, ts))
}

// VerifyRemoteNukeMLDSA verifies SignRemoteNukeMLDSA against the ML-DSA-65
// public key of a sibling identity of the target device.
func VerifyRemoteNukeMLDSA(authorityPub *mldsa65.PublicKey, targetDeviceID []byte, ts string, sig []byte) bool {
	if authorityPub == nil || len(sig) == 0 {
		return false
	}
	return mldsaVerify(authorityPub, RemoteNukeMsg(targetDeviceID, ts), sig)
}

// RemoteNukeAckMsg is the message signed by the target device to confirm
// it received the command and is about to wipe itself — same scheme as
// RemoteNukeMsg but with its own
// ts (fresh at ack time, not the same ts as the received command) and
// verified with the DEVICE-level key, not with an identity: it's the
// device itself confirming, not whoever authorized it.
// msg = "remote_nuke_ack:" ‖ targetDeviceID ‖ ":" ‖ ts
func RemoteNukeAckMsg(targetDeviceID []byte, ts string) []byte {
	msg := append([]byte("remote_nuke_ack:"), targetDeviceID...)
	msg = append(msg, ':')
	msg = append(msg, []byte(ts)...)
	return msg
}

// SignRemoteNukeAck signs RemoteNukeAckMsg with the target's device-level
// private key.
func SignRemoteNukeAck(devicePriv ed25519.PrivateKey, targetDeviceID []byte, ts string) []byte {
	return ed25519.Sign(devicePriv, RemoteNukeAckMsg(targetDeviceID, ts))
}

// VerifyRemoteNukeAck verifies RemoteNukeAckMsg with the target's
// device-level public key (known to the authority only if already
// registered in Keystore.KnownDevices).
func VerifyRemoteNukeAck(devicePub ed25519.PublicKey, targetDeviceID []byte, ts string, sig []byte) bool {
	if len(devicePub) == 0 || len(sig) == 0 {
		return false
	}
	return ed25519.Verify(devicePub, RemoteNukeAckMsg(targetDeviceID, ts), sig)
}

// Ed25519PubToX25519 converts an Ed25519 public key into the corresponding
// X25519 one via the Edwards→Montgomery birational map: u = (1+y)/(1−y) mod p.
func Ed25519PubToX25519(edPub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(edPub) != 32 {
		return nil, errors.New(i18n.T("shared.err_ed25519pub_key_len"))
	}
	yLE := make([]byte, 32)
	copy(yLE, edPub)
	yLE[31] &= 0x7f // strip the sign bit

	// little-endian → big-endian for big.Int
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		yLE[i], yLE[j] = yLE[j], yLE[i]
	}
	y := new(big.Int).SetBytes(yLE)

	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	one := big.NewInt(1)

	num := new(big.Int).Add(one, y)
	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)
	denInv := new(big.Int).ModInverse(den, p)
	if denInv == nil {
		return nil, errors.New(i18n.T("shared.err_ed25519pub_singular"))
	}
	u := new(big.Int).Mul(num, denInv)
	u.Mod(u, p)

	// big-endian → little-endian 32 bytes
	uBE := u.Bytes()
	out := make([]byte, 32)
	for i, b := range uBE {
		out[len(uBE)-1-i] = b
	}
	return ecdh.X25519().NewPublicKey(out)
}

// Ed25519PrivToX25519 derives the X25519 private key from the Ed25519 seed (RFC 8032 §5.1.5).
func Ed25519PrivToX25519(edPriv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	if len(edPriv) != 64 {
		return nil, errors.New(i18n.T("shared.err_ed25519priv_key_len"))
	}
	h := sha512.Sum512(edPriv[:32])
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return ecdh.X25519().NewPrivateKey(h[:32])
}

// peerEncFormatHybrid/peerEncFormatClassic mark the encryption form of a
// blob encrypted toward a single Ed25519-per-relationship key inside
// EncryptForPeer/DecryptFromPeer — generalized beyond knocks alone (see
// EncryptForPeer below). Prefix on the string (not on the payload's raw
// bytes), chosen specifically to avoid touching the base64 already produced
// by ECIESEncrypt/HybridECIESEncrypt. PERMANENT dual-mode, not just a
// transition window: a contact/relationship with no known ML-KEM key
// always stays on the classic form.
const (
	peerEncFormatHybrid  = "H:"
	peerEncFormatClassic = "C:"
)

// EncryptForPeer encrypts an arbitrary plaintext for a single recipient
// identified by their durable or relationship Ed25519 key (converted to
// X25519). If recipientMLKEMPub is non-nil, uses HybridECIESEncrypt
// (X25519+ML-KEM-768) — otherwise falls back to plain ECIESEncrypt, for a
// recipient whose ML-KEM key isn't known yet. Base for EncryptKnock (below)
// and for file transfer (per-recipient meta_blob) — same ContentKey/
// IdentityKey used elsewhere for signing, dual Ed25519/X25519 use.
func EncryptForPeer(recipientEdPub ed25519.PublicKey, recipientMLKEMPub *mlkem.EncapsulationKey768, plaintext []byte) (string, error) {
	xPub, err := Ed25519PubToX25519(recipientEdPub)
	if err != nil {
		return "", err
	}
	if recipientMLKEMPub != nil {
		s, err := HybridECIESEncrypt(xPub, recipientMLKEMPub, plaintext)
		if err != nil {
			return "", err
		}
		return peerEncFormatHybrid + s, nil
	}
	s, err := ECIESEncrypt(xPub, plaintext)
	if err != nil {
		return "", err
	}
	return peerEncFormatClassic + s, nil
}

// DecryptFromPeer decrypts a payload produced by EncryptForPeer. myMLKEMPriv
// can be nil (no ML-KEM key for this identity/relationship) — in that case
// a payload arriving in hybrid form can't be decrypted (explicit error, not
// a silent fallback). A payload with no format prefix is treated as
// classic.
func DecryptFromPeer(myEdPriv ed25519.PrivateKey, myMLKEMPriv *mlkem.DecapsulationKey768, payload string) ([]byte, error) {
	xPriv, err := Ed25519PrivToX25519(myEdPriv)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(payload, peerEncFormatHybrid):
		if myMLKEMPriv == nil {
			return nil, errors.New(i18n.T("shared.err_knock_no_mlkem_key"))
		}
		return HybridECIESDecrypt(xPriv, myMLKEMPriv, payload[len(peerEncFormatHybrid):])
	case strings.HasPrefix(payload, peerEncFormatClassic):
		return ECIESDecrypt(xPriv, payload[len(peerEncFormatClassic):])
	default:
		return ECIESDecrypt(xPriv, payload)
	}
}

// EncryptKnock encrypts a KnockPayload for the recipient (durable Ed25519
// key, converted to X25519) — see EncryptForPeer.
func EncryptKnock(recipientEdPub ed25519.PublicKey, recipientMLKEMPub *mlkem.EncapsulationKey768, p KnockPayload) (string, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return "", errors.New(i18n.T("shared.err_knock_marshal", err))
	}
	s, err := EncryptForPeer(recipientEdPub, recipientMLKEMPub, plain)
	if err != nil {
		return "", errors.New(i18n.T("shared.err_knock_encrypt", err))
	}
	return s, nil
}

// DecryptKnock decrypts a payload produced by EncryptKnock — see DecryptFromPeer.
func DecryptKnock(myEdPriv ed25519.PrivateKey, myMLKEMPriv *mlkem.DecapsulationKey768, payload string) (KnockPayload, error) {
	plain, err := DecryptFromPeer(myEdPriv, myMLKEMPriv, payload)
	if err != nil {
		return KnockPayload{}, errors.New(i18n.T("shared.err_knock_ecies", err))
	}
	var k KnockPayload
	if err := json.Unmarshal(plain, &k); err != nil {
		return KnockPayload{}, errors.New(i18n.T("shared.err_knock_unmarshal", err))
	}
	return k, nil
}

// knockDHTagLabel is the HMAC context of the static-static DH tag attached
// in plaintext to a POST /knock — see KnockDHTag.
const knockDHTagLabel = "neutrino-knock-tag"

// KnockDHTag computes a cheap tag, verifiable BEFORE the actual ECIES
// decryption (DecryptKnock), attached in plaintext to a POST /knock
// (KnockEnvelope). Derived from a static-static DH X25519(myPriv, peerPub)
// — symmetric: sender and recipient get the SAME value, each with their own
// private key and the other's Ed25519 pubkey (Ed25519PrivToX25519/
// Ed25519PubToX25519, same birational map already used for ECIES) — never
// transmitted in plaintext.
//
// A plain hash of the two public pubkeys (SHA256(fromPub‖toPub)) would be
// forgeable by anyone who had simply SEEN both public pubkeys (leaked QR,
// compromised device), without holding either private key — this tag
// instead requires actual possession of a REAL private key of one of the
// two identities.
func KnockDHTag(myPriv ed25519.PrivateKey, peerPub ed25519.PublicKey) ([]byte, error) {
	myX, err := Ed25519PrivToX25519(myPriv)
	if err != nil {
		return nil, err
	}
	peerX, err := Ed25519PubToX25519(peerPub)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := myX.ECDH(peerX)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(knockDHTagLabel))
	return mac.Sum(nil), nil
}

// KnockEnvelope is the plaintext JSON body of a POST /knock: Tag
// (KnockDHTag) lets the recipient discard a non-mutual knock without ever
// running the actual ECIES decryption of Payload (produced by EncryptKnock).
type KnockEnvelope struct {
	Tag     []byte `json:"tag"`
	Payload string `json:"payload"`
}

// DeviceSyncPath is the endpoint for knocks between devices of the same
// identity (device_sync, device_sync_ack, contact_tombstone), whose
// payload can carry the whole address book — too large for POST /knock.
// The sender puts the envelope's tag, base64-encoded, in the
// DeviceSyncTagHeader header, so the receiver checks it is its own
// identity before reading the body.
const (
	DeviceSyncPath      = "/device-sync"
	DeviceSyncTagHeader = "X-Neutrino-Tag"
)

// EncryptKnockWithTag encrypts a KnockPayload like EncryptKnock and wraps
// it in a KnockEnvelope together with the tag already computed by the
// caller (KnockDHTag) — tag passed in, not recomputed here, because the
// client-side caller typically doesn't expose the raw Ed25519 private key
// to this package (it instead goes through a dedicated closure, same
// pattern already used for signing — see dhTagFn in internal/client/tui).
// Returns the JSON body ready for the POST.
func EncryptKnockWithTag(recipientEdPub ed25519.PublicKey, recipientMLKEMPub *mlkem.EncapsulationKey768, p KnockPayload, tag []byte) (string, error) {
	payload, err := EncryptKnock(recipientEdPub, recipientMLKEMPub, p)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(KnockEnvelope{Tag: tag, Payload: payload})
	if err != nil {
		return "", errors.New(i18n.T("shared.err_knock_marshal", err))
	}
	return string(b), nil
}

// DeriveContactRoomKey derives a 32-byte room access key from a shared contact secret and period.
// Used to authenticate a connecting peer inside the node's hidden service.
func DeriveContactRoomKey(secret []byte, period int64) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte(fmt.Sprintf("room_%d", period)))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ── Symmetric HMAC ratchet (chain key) ───────────────────────────────────────

// DeriveKeyID returns an 8-character hex identifier derived from senderKey.
// Stable for the lifetime of a senderKey rotation; changes with each new senderKey.
// Used by receivers to look up the correct ratchet chain without revealing sender identity.
func DeriveKeyID(senderKey []byte) string {
	mac := hmac.New(sha256.New, senderKey)
	mac.Write([]byte("neutrino-key-id-v1"))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:4])
}

// InitChainKey derives the initial 32-byte chain key from a sender key via HKDF.
// Called once each time a new sender_key is received; the chain is then advanced
// per-message with DeriveChainStep.
func InitChainKey(senderKey []byte) []byte {
	r := hkdf.New(sha256.New, senderKey, nil, []byte("neutrino-chain-v1"))
	key := make([]byte, 32)
	io.ReadFull(r, key) //nolint:errcheck // fixed-size read from HKDF cannot fail
	return key
}

// safetyAlphabet is the base62 alphabet used for the safety code.
const safetyAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// SafetyCode derives a 40-character base62 safety code from two Ed25519 identity keys.
// The keys are sorted before hashing so both parties independently compute the same code.
// Returns the code as 5 space-separated groups of 8 base62 characters, to be
// compared in full out of band (never sampled): with 62 symbols and 40
// characters, the probability of two different keys producing the same code
// is negligible.
func SafetyCode(a, b ed25519.PublicKey) string {
	if string(a) > string(b) {
		a, b = b, a
	}
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	seed := h.Sum(nil)
	// HKDF expands the seed to 40 bytes, one byte per output character.
	r := hkdf.New(sha256.New, seed, nil, []byte("neutrino-safety-b62-v1"))
	out := make([]byte, 40)
	_, _ = io.ReadFull(r, out)
	chars := make([]byte, 40)
	for i, v := range out {
		chars[i] = safetyAlphabet[int(v)%62] // bias < 0.4 %, negligible
	}
	s := string(chars)
	return s[:8] + " " + s[8:16] + " " + s[16:24] + " " + s[24:32] + " " + s[32:]
}

// DeriveChainStep advances the symmetric ratchet by one step.
// msgKey is used to encrypt/decrypt exactly one message and must be zeroed after use.
// nextChainKey replaces chainKey in the ratchet state — the step is one-way; past keys
// cannot be rederived from nextChainKey.
func DeriveChainStep(chainKey []byte) (msgKey, nextChainKey []byte) {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte{0x01})
	msgKey = mac.Sum(nil)
	mac2 := hmac.New(sha256.New, chainKey)
	mac2.Write([]byte{0x02})
	nextChainKey = mac2.Sum(nil)
	return
}

// DeriveChainStepDH advances the ratchet like DeriveChainStep, but mixes an
// additional DH secret into the next step — gives post-compromise security
// beyond plain forward secrecy: whoever steals chainKey can't compute
// nextChainKey without also knowing dhShared. dhShared is generically
// []byte to stay algorithm-agnostic (X25519, or a post-quantum hybrid
// with no change to this function). Used
// only for two-member rooms (see Client.ratchetDH) — groups stay on
// DeriveChainStep.
func DeriveChainStepDH(chainKey, dhShared []byte) (msgKey, nextChainKey []byte) {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte{0x01})
	msgKey = mac.Sum(nil) // identical to DeriveChainStep — doesn't depend on the DH
	mac2 := hmac.New(sha256.New, chainKey)
	mac2.Write(dhShared)
	mac2.Write([]byte{0x02})
	nextChainKey = mac2.Sum(nil)
	return
}

// EphID identifies an ephemeral X25519 pubkey with 8 hex characters
// (truncated SHA-256). Not a secret (the pubkey is already public) — only
// used by the receiver to know which of their retired keys
// (Client.outEphRing) to use in the DH mix, without having to try them by
// trial and error.
func EphID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:4])
}
