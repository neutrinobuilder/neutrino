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

package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"neutrino/internal/i18n"
	"neutrino/internal/shared"
)

const (
	// version is the current keystore format; migrateVersion upgrades
	// identities stored in an earlier one.
	version      = 6
	saltLen      = 16
	nonceLen     = 12
	keyLen       = 32
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
)

// Contact represents a contact in the keystore.
// Username is the contact's network name (immutable, used in the protocols).
// LocalName is the personal name the user chose for this contact
// (optional, local only — e.g. "Al" for a contact whose username is "Albert").
type Contact struct {
	Username  string `json:"username"`
	LocalName string `json:"local_name,omitempty"` // personal name, empty = use Username
	// IdentityPub is the contact's TRANSPORT key (Ed25519, 32 bytes) —
	// used ONLY to compute their network address
	// (OnionAddressFromPub/I2PAddressFromPub), never to authenticate a
	// handshake/knock. That role belongs to the four relationship keys
	// below.
	IdentityPub []byte `json:"identity_pub"`

	// Devices holds an independent cryptographic relationship for EVERY
	// device of this contact (D1, D2, ...) — map key: string(DevicePub)
	// of the CONTACT's device (32 raw bytes as a string, never exposed
	// elsewhere as a comparable type). Two devices of the same identity
	// never share the same material, each negotiates its own
	// relationship with us independently. D1 isn't a special case:
	// it's simply the first entry populated, before a second device
	// ever exists. See SoleDevice() below for the common case (a single
	// known device).
	Devices map[string]*DeviceRelation `json:"devices,omitempty"`

	LastAckAt    time.Time `json:"last_ack_at"`             // local clock: last probe_ack received from this contact (zero = never)
	LastSeenAt   time.Time `json:"last_seen_at"`            // local clock: last time reached over TCP in a probe cycle (zero = never)
	Verified     bool      `json:"verified,omitempty"`      // full safety number comparison done out of band and confirmed by the user (see /sec-verify)
	IntroducedBy string    `json:"introduced_by,omitempty"` // display name of whoever introduced this contact via a card, at that time; empty = added directly (knock, QR, manual)
	// IntroducedByPub is the identity key of whoever introduced this
	// contact via a card — the introducer's identity; IntroducedBy only
	// labels it.
	IntroducedByPub []byte `json:"introduced_by_pub,omitempty"`
	// MLKEMPub is the contact's durable ML-KEM-768 encapsulation key
	// (1184 bytes), learned from the nu:// QR/URI at exchange time.
	// Empty when the URI didn't carry it: knocks to them remain
	// encrypted in classic form (X25519 only) until the QR is
	// re-exchanged — see EncryptKnock, internal/shared/crypto.go.
	MLKEMPub []byte `json:"mlkem_pub,omitempty"`

	// MLDSAPub is the contact's durable ML-DSA-65 signing public key
	// (1952 bytes packed). Learned from the nu:// QR/URI at exchange
	// time (same treatment as MLKEMPub above) and propagated via
	// root_rotate. Empty when the URI didn't carry it, until the QR is
	// re-exchanged: the parallel ML-DSA
	// signatures on remote_nuke remain verifiable only with
	// Ed25519 until then — never blocking.
	MLDSAPub []byte `json:"mldsa_pub,omitempty"`

	// KnownDevicePub is the public key of the device seen signing this
	// contact's messages (device_sig, see shared.DeviceSigMsg) — TOFU:
	// updated on every successfully verified message (the device pubkey
	// travels INSIDE the ciphertext along with the text — see
	// sealedMsg.DP — so verification is self-contained in a single
	// message, no additional bootstrap round-trip). A device different
	// from the already-known one only produces a distinct on-screen tag
	// ([DEV:new]), never a rejection. Distinct concept from
	// Keystore.KnownDevices (that one is for ONE'S OWN identity, to
	// choose a remote_nuke target; this one is for recognizing a
	// CONTACT's device).
	KnownDevicePub []byte `json:"known_device_pub,omitempty"`

	// SiblingRevocations is the pool of self-revocation certificates
	// from ALL sibling devices (same identity/username, physically
	// different keystore — NEVER this device's own: those live in
	// Devices above) toward THIS contact's devices — never a private
	// key, only ready-to-use signatures. Propagated via device_sync/
	// indoor sync along with the rest of this Contact (MergeContacts
	// merges it here, zeroed only in the "new contact" branch along
	// with Devices — never inherited like Devices, but for the opposite
	// reason: this one does NOT contain private material, so it should
	// still accumulate). Consulted only if this device must act as a
	// backstop for a nuked sibling. Key:
	// string(SiblingDevicePub)+string(PeerDevicePub) — direct
	// unambiguous concatenation (32+32 fixed bytes), several siblings
	// can have independent relationships with the same device of this
	// contact.
	SiblingRevocations map[string]*SiblingRevocation `json:"sibling_revocations,omitempty"`
}

// SiblingRevocation is ONE sibling device's self-revocation certificate
// toward ONE device of a contact — an entry of Contact.SiblingRevocations
// above. See DeviceRelation.RevokeIdentitySig/RevokeContentSig: the same
// signature pair, here held on behalf of another device.
type SiblingRevocation struct {
	// SiblingDevicePub identifies THE SIBLING that generated this
	// revocation — Keystore.DevicePub, 32 bytes, the SAME value that
	// ends up in a future RelRevokePayload's DevicePub field when this
	// sibling resends the revocation on behalf of the nuked device (not
	// Keystore.DeviceID: that doesn't identify any key reusable on the
	// wire). Not the contact's device (that's PeerDevicePub below).
	SiblingDevicePub []byte `json:"sibling_device_pub"`
	// PeerDevicePub is the CONTACT's device this revocation applies to
	// — the same key used as a Contact.Devices entry.
	PeerDevicePub []byte `json:"peer_device_pub"`

	IdentitySig      []byte `json:"identity_sig,omitempty"`
	IdentitySigMLDSA []byte `json:"identity_sig_mldsa,omitempty"`
	ContentSig       []byte `json:"content_sig,omitempty"`
	ContentSigMLDSA  []byte `json:"content_sig_mldsa,omitempty"`

	// Acked reports whether a rel_revoke_ack has already been received
	// for this specific revocation (from any sibling, not necessarily
	// the one that sent it last) — propagated along with the rest via
	// device_sync, so a dormant sibling that wakes up late inherits the
	// updated state instead of starting over.
	Acked bool `json:"acked,omitempty"`
}

// DeviceRelation is the independent cryptographic relationship with ONE
// device of a contact — an entry of the Contact.Devices map above.
type DeviceRelation struct {
	// Address is the network address this device declared in its
	// rel_init (KnockPayload.FromAddr) — for D1 it matches
	// Contact.NetAddr (root-derived, always computable without
	// negotiation); for an additional device it's the one delivered via
	// bootstrap, never derivable from the contact's IdentityPub alone.
	// Every knock and invite toward this device is addressed here.
	Address string `json:"address,omitempty"`

	// RelIdentityPriv/PeerRelIdentityPub and RelContentPriv/
	// PeerRelContentPub are the four relationship keys with THIS
	// device — generated randomly and independent for each
	// relationship (no master secret), exchanged bidirectionally at
	// bootstrap (rel_init/rel_init_ack).
	//
	// RelIdentityPriv/PeerRelIdentityPub sign and verify the handshake
	// (Sig in ClientHello/ServerHello) with this specific device.
	//
	// RelContentPriv/PeerRelContentPub: native Ed25519 signing +
	// encryption via X25519 conversion
	// (Ed25519PrivToX25519/Ed25519PubToX25519) toward this device, used
	// only inside rooms (messages, files, contact cards) — never
	// recertified out of band.
	RelIdentityPriv    []byte `json:"rel_identity_priv,omitempty"`
	PeerRelIdentityPub []byte `json:"peer_rel_identity_pub,omitempty"`
	RelContentPriv     []byte `json:"rel_content_priv,omitempty"`
	PeerRelContentPub  []byte `json:"peer_rel_content_pub,omitempty"`

	// Hybrid PQC companions of the two relationship keys above — the
	// same principle already mandatory for the global identity
	// (ML-KEM-768 for hybrid encryption, resistant to
	// harvest-now-decrypt-later; ML-DSA-65 as a parallel signature,
	// resistant to a quantum attacker breaking Ed25519 — KnockDHTag
	// doesn't need this, being HMAC-SHA256 already Grover-resistant),
	// here applied per-relationship instead of globally. Always rotate
	// together with their respective Ed25519 key.
	RelIdentityMLKEMPriv    []byte `json:"rel_identity_mlkem_priv,omitempty"`
	PeerRelIdentityMLKEMPub []byte `json:"peer_rel_identity_mlkem_pub,omitempty"`
	RelIdentityMLDSAPriv    []byte `json:"rel_identity_mldsa_priv,omitempty"`
	PeerRelIdentityMLDSAPub []byte `json:"peer_rel_identity_mldsa_pub,omitempty"`
	RelContentMLKEMPriv     []byte `json:"rel_content_mlkem_priv,omitempty"`
	PeerRelContentMLKEMPub  []byte `json:"peer_rel_content_mlkem_pub,omitempty"`
	RelContentMLDSAPriv     []byte `json:"rel_content_mldsa_priv,omitempty"`
	PeerRelContentMLDSAPub  []byte `json:"peer_rel_content_mldsa_pub,omitempty"`

	// RevokeIdentitySig/RevokeContentSig (+ ML-DSA-65 companions) are
	// self-revocation certificates — the CURRENT RelIdentityPriv/
	// RelContentPriv signs its own public key, exactly like a PGP
	// revocation certificate is self-signed by the key it revokes.
	// Generated once, together with the key itself (bootstrap or
	// rotation — never at nuke time: that key is already gone forever
	// by then), by `ensureRelRevocations` (called by UnlockedSlot.
	// SaveSlot/SaveWithDuress before every disk write under the N-slot
	// format, self-healing regardless of which code path generates/
	// rotates the key). They stay inert until transmitted (the
	// "rel_revoke" knock).
	RevokeIdentitySig      []byte `json:"revoke_identity_sig,omitempty"`
	RevokeIdentitySigMLDSA []byte `json:"revoke_identity_sig_mldsa,omitempty"`
	RevokeContentSig       []byte `json:"revoke_content_sig,omitempty"`
	RevokeContentSigMLDSA  []byte `json:"revoke_content_sig_mldsa,omitempty"`

	// IdentityKeyPending/OldRelIdentityPriv and ContentKeyPending/
	// OldRelContentPriv track an in-progress rotation of ONE of the two
	// relationship keys toward THIS device — never both together (the
	// key not being rotated acts as the continuity anchor for the other,
	// see StartRelIdentityRotationByPub/StartRelContentRotationByPub).
	// OldRelIdentityPriv/OldRelContentPriv (vault) also carry the old
	// PQC companions inside (concatenated seeds) — a single vault
	// instead of six, same lifecycle.
	IdentityKeyPending bool       `json:"identity_key_pending,omitempty"`
	OldRelIdentityPriv vaultBytes `json:"old_rel_identity_priv,omitempty"`
	ContentKeyPending  bool       `json:"content_key_pending,omitempty"`
	OldRelContentPriv  vaultBytes `json:"old_rel_content_priv,omitempty"`

	// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer distinguish
	// "I have the peer's relationship public keys" (PeerRelIdentityPub/
	// PeerRelContentPub above, populated either by a spontaneous
	// rel_init from the peer or by a rel_init_ack) from "the peer has
	// confirmed having MINE" — they turn on ONLY on receiving an actual
	// rel_init_ack (never from a rel_init, which is a request, not a
	// confirmation), always TOGETHER (bootstrap carries both keys in the
	// same payload — there's no "identity only" or "content only"
	// rel_init on the wire). It's this pair, not PeerRelIdentityPub/
	// PeerRelContentPub, that decides whether to keep resending one's
	// own rel_init: if the peer received and processed my rel_init but
	// its response was lost, I still need to retry — regardless of
	// whether I've meanwhile already received THEIR keys for an
	// unrelated reason (their own independent spontaneous rel_init,
	// e.g. near-simultaneous onboarding).
	//
	// Split into two fields: a mismatch discovered AFTER bootstrap that
	// concerns only one of the two (self-heal — handshake verification
	// for Identity, message/file signature verification for Content)
	// clears only the relevant flag, instead of forcing a wider
	// re-exchange than necessary (which would also block
	// ReadyDevices()/invites to new rooms for an issue isolated to the
	// ContentKey alone). An actual rel_init_ack always turns both on
	// together; only self-heal decouples them.
	RelIdentityConfirmedByPeer bool `json:"rel_identity_confirmed_by_peer,omitempty"`
	RelContentConfirmedByPeer  bool `json:"rel_content_confirmed_by_peer,omitempty"`

	// LegacyRelInitConfirmedByPeer — read only: format version 5 stores a
	// single flag under this JSON key; migrateVersion copies it to BOTH
	// fields above and zeroes it, so it is never written again. Never read
	// anywhere else.
	LegacyRelInitConfirmedByPeer bool `json:"rel_init_confirmed_by_peer,omitempty"`

	// PendingPeerRelIdentityPub/PendingPeerRelContentPub (+ PQC
	// companions) — relationship keys proposed by a rel_init/
	// rel_init_ack arriving from THIS SAME device while
	// RelIdentityConfirmedByPeer was already true, with BOTH keys
	// different from the already-known PeerRelIdentityPub/
	// PeerRelContentPub — not cryptographically distinguishable between
	// a restore from the contact's bare seed (legitimate) and a
	// replacement of their relationship keys (e.g. a compromised root
	// IdentityKey) — see TrustLevel/TrustDanger below. A rel_init from
	// an UNKNOWN DevicePub never goes through here: it creates a new
	// entry in the map, not a conflict on this one. Never applied
	// automatically to PeerRelIdentityPub/PeerRelContentPub: only an
	// explicit user confirmation (/sec-verify, out of band) promotes
	// them, also zeroing Contact.Verified (the previous trust applied
	// to the old keys, it must be regained). Empty = no conflict in
	// progress on this device.
	PendingPeerRelIdentityPub      []byte `json:"pending_peer_rel_identity_pub,omitempty"`
	PendingPeerRelIdentityMLKEMPub []byte `json:"pending_peer_rel_identity_mlkem_pub,omitempty"`
	PendingPeerRelIdentityMLDSAPub []byte `json:"pending_peer_rel_identity_mldsa_pub,omitempty"`
	PendingPeerRelContentPub       []byte `json:"pending_peer_rel_content_pub,omitempty"`
	PendingPeerRelContentMLKEMPub  []byte `json:"pending_peer_rel_content_mlkem_pub,omitempty"`
	PendingPeerRelContentMLDSAPub  []byte `json:"pending_peer_rel_content_mldsa_pub,omitempty"`

	// RevokedIdentity/RevokedContent are set by a successfully verified
	// "rel_revoke" knock (see shared.VerifyRelRevoke against
	// PeerRelIdentityPub/PeerRelContentPub) — split exactly like
	// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer above,
	// because a device can revoke only one of the two keys (e.g. a nuke
	// of the IdentityKey alone, not yet followed by one of the
	// ContentKey). Set, never cleared: a revocation is final, a second
	// rel_revoke for the same key (a replay or a repeat from a sibling)
	// is a safe no-op. Consulted by the handshake (RelKeysForDevice
	// refuses a revoked IdentityKey), by message signing/verification
	// (a revoked ContentKey is never a candidate) and by
	// RelEstablishedDevice/RelRevoked (contact list [REL:...]/[REVOKED]).
	RevokedIdentity bool `json:"revoked_identity,omitempty"`
	RevokedContent  bool `json:"revoked_content,omitempty"`
}

// hasPendingConflict reports whether this entry has an unresolved
// relationship-key conflict (TrustDanger) — see Contact.TrustLevel().
func (d *DeviceRelation) hasPendingConflict() bool {
	return d != nil && (len(d.PendingPeerRelIdentityPub) > 0 || len(d.PendingPeerRelContentPub) > 0)
}

// ensureRelRevocations computes the missing self-revocation certificates
// for every device of every contact — called by UnlockedSlot.SaveSlot/
// SaveWithDuress before every disk write under the N-slot format, not
// from a specific key generation/rotation point: this way any code path
// that sets RelIdentityPriv/RelContentPriv (initial bootstrap, a probe
// round that generates keys for a contact just come online, a rotation)
// automatically also gets the corresponding revocation, without having
// to remember to call anything. Ed25519.Sign is deterministic (RFC
// 8032): recomputing never produces a different result for the same
// key, so the "already present" check is a pure CPU saving, never a
// correctness matter. A rotation
// (StartRelIdentityRotationByPub/StartRelContentRotationByPub)
// explicitly clears the relevant field before replacing the key, so the
// next save computes a fresh one for the new key — the old one, if
// already distributed, simply stays inert (no longer verifies against
// the current public key known to the contact).
func (ks *Keystore) ensureRelRevocations() {
	for i := range ks.Contacts {
		c := &ks.Contacts[i]
		for _, dev := range c.Devices {
			if len(dev.RelIdentityPriv) > 0 && len(dev.RevokeIdentitySig) == 0 {
				priv := ed25519.PrivateKey(dev.RelIdentityPriv)
				dev.RevokeIdentitySig = shared.SignRelRevoke(priv, ks.Username)
				if len(dev.RelIdentityMLDSAPriv) > 0 {
					pub := priv.Public().(ed25519.PublicKey)
					dev.RevokeIdentitySigMLDSA = shared.SignRelRevokeMLDSA(dev.RelIdentityMLDSAPriv, pub, ks.Username)
				}
			}
			if len(dev.RelContentPriv) > 0 && len(dev.RevokeContentSig) == 0 {
				priv := ed25519.PrivateKey(dev.RelContentPriv)
				dev.RevokeContentSig = shared.SignRelRevoke(priv, ks.Username)
				if len(dev.RelContentMLDSAPriv) > 0 {
					pub := priv.Public().(ed25519.PublicKey)
					dev.RevokeContentSigMLDSA = shared.SignRelRevokeMLDSA(dev.RelContentMLDSAPriv, pub, ks.Username)
				}
			}
		}
	}
}

// SoleDevice returns the single entry of Contact.Devices if there's
// exactly one, false otherwise — no known device or more than one known
// always return false, never an arbitrary/silent pick. Covers the vast
// majority of code paths that reason about "the relationship with this
// contact" in the singular (rotation, safety number, message
// signing/verification, invite readiness check) — correct because a
// contact almost always has exactly one known device; with more than one
// known, these paths return a clear error instead of guessing which
// device to use.
func (c Contact) SoleDevice() (*DeviceRelation, bool) {
	if len(c.Devices) != 1 {
		return nil, false
	}
	for _, dev := range c.Devices {
		return dev, true
	}
	return nil, false
}

// SoleDeviceOrPlaceholder is like SoleDevice, but with an empty Devices
// it returns a new, empty DeviceRelation instead of (nil, false) — used
// by the probe cycle to generate missing relationship keys even toward a
// contact with no known entry yet; the returned value is never written
// into the map here, persistence still goes through the normal update
// path (which creates the "" placeholder entry if absent).
func (c Contact) SoleDeviceOrPlaceholder() (*DeviceRelation, bool) {
	if len(c.Devices) == 0 {
		return &DeviceRelation{}, true
	}
	return c.SoleDevice()
}

// DevicesOrPlaceholder returns c.Devices if it has at least one entry,
// otherwise a map with just the "" placeholder entry — counterpart of
// SoleDeviceOrPlaceholder for callers that iterate over ALL of the
// contact's devices instead of limiting themselves to the single-device
// case.
func (c Contact) DevicesOrPlaceholder() map[string]*DeviceRelation {
	if len(c.Devices) == 0 {
		return map[string]*DeviceRelation{"": {}}
	}
	return c.Devices
}

// SoleDeviceKey is SoleDevice but also returns the DevicePub — the key
// under which the entry lives in Devices — needed by callers that must
// pass it to RoomRegistry (AddSecret/ReplaceSecret/RefreshSigningKeys):
// without it, RefreshSigningKeys couldn't distinguish the right device
// from another device of the same contact.
func (c Contact) SoleDeviceKey() (devicePub []byte, dev *DeviceRelation, ok bool) {
	if len(c.Devices) != 1 {
		return nil, nil, false
	}
	for k, d := range c.Devices {
		return []byte(k), d, true
	}
	return nil, nil, false
}

// RelEstablishedDevice returns the first device (deterministic order)
// with the ContentKey-per-relationship established in both directions —
// unlike SoleDevice() above, it doesn't stop at "exactly one device": a
// contact with several known devices can already have a working
// relationship on one of them while another is still a bootstrap
// placeholder or still negotiating. A device whose IdentityKey or
// ContentKey has been revoked (RevokedIdentity/RevokedContent) never
// counts as established. Used by the [REL:...] fingerprint display.
func (c Contact) RelEstablishedDevice() (*DeviceRelation, bool) {
	keys := make([]string, 0, len(c.Devices))
	for k := range c.Devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dev := c.Devices[k]
		if dev == nil || dev.RevokedIdentity || dev.RevokedContent {
			continue
		}
		if len(dev.RelContentPriv) == ed25519.PrivateKeySize && len(dev.PeerRelContentPub) == ed25519.PublicKeySize {
			return dev, true
		}
	}
	return nil, false
}

// RelRevoked reports whether the contact's relationship is revoked: at
// least one device has a revoked IdentityKey or ContentKey and no other
// device still has an established relationship (RelEstablishedDevice).
// A contact with one revoked device and another still valid is not
// revoked: it remains reachable through the valid one.
func (c Contact) RelRevoked() bool {
	if _, ok := c.RelEstablishedDevice(); ok {
		return false
	}
	for _, dev := range c.Devices {
		if dev != nil && (dev.RevokedIdentity || dev.RevokedContent) {
			return true
		}
	}
	return false
}

// ReadyDevices returns EVERY device of this contact ready to be
// contacted/invited — RelIdentityConfirmedByPeer AND
// RelContentConfirmedByPeer (both, not a single old one: an
// invite/handshake requires the first, but messages/files exchanged
// inside the room still require the second too), complete relationship
// keys, known network address — unlike SoleDevice() above it doesn't
// stop at "exactly one": used by invite fan-out and by
// replying/retrying rel_init/rotation knocks toward a specific device. A
// device with no Address is never included: with no address there's no
// way to reach it, regardless of how complete its keys are.
func (c Contact) ReadyDevices() map[string]*DeviceRelation {
	if len(c.Devices) == 0 {
		return nil
	}
	out := make(map[string]*DeviceRelation, len(c.Devices))
	for key, dev := range c.Devices {
		if dev == nil || !dev.RelIdentityConfirmedByPeer || !dev.RelContentConfirmedByPeer || dev.Address == "" {
			continue
		}
		if len(dev.RelIdentityPriv) != ed25519.PrivateKeySize || len(dev.PeerRelIdentityPub) != ed25519.PublicKeySize {
			continue
		}
		out[key] = dev
	}
	return out
}

// sortedDeviceKeys returns Devices' keys in deterministic order — used
// by AnyReadyDevice/DeviceWithPendingRelKeys below for a stable choice
// across successive runs (direct iteration over a Go map wouldn't be),
// not for an order with any particular meaning.
func sortedDeviceKeys(devices map[string]*DeviceRelation) []string {
	keys := make([]string, 0, len(devices))
	for k := range devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// DeviceByPub resolves the EXACT Devices entry for a DevicePub already
// known to the caller (e.g. an incoming knock's DevicePub field —
// RelBootstrapPayload/RelRotatePayload — or a message sender's device
// pub decoded from it, `dp` in tui.go) — never ambiguous, unlike
// SoleDevice above or a deterministic choice on a partial criterion (see
// contentPeerKeysFor/myContentPrivFor in tui.go, which pick a device by
// filtering only on the field of interest, never on ReadyDevices() as a
// whole: the "ready for invite" criteria — Address/RelIdentityPriv — are
// irrelevant for encrypting/verifying content). ok=false if pub is empty
// or doesn't match any known entry.
func (c Contact) DeviceByPub(pub []byte) (dev *DeviceRelation, ok bool) {
	if len(pub) == 0 {
		return nil, false
	}
	dev, ok = c.Devices[string(pub)]
	return dev, ok && dev != nil
}

// RelKeysForDevice resolves LIVE, under ks.mu, the relationship-key
// pair for an exact contact+device (the contact's STABLE identityPub,
// the devicePub of the Contact.Devices entry) — meant to be used as a
// resolver by RoomRegistry.AddSecret/ReplaceSecret: called on EVERY
// handshake verification, never cached, so a relationship rotation
// (local or peer's) is reflected immediately with no need for an
// explicit refresh. peerKey is the IdentityKey-per-relationship that
// device declared toward us (verifies ClientHello.Sig); mySigningKey is
// OUR OWN toward it (signs ServerHello.Sig). ok=false if the
// contact/device no longer exists or the keys aren't (yet) complete.
func (ks *Keystore) RelKeysForDevice(identityPub, devicePub []byte) (shared.RelPeerKey, shared.RelSigningKey, bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i := range ks.Contacts {
		if !bytes.Equal(ks.Contacts[i].IdentityPub, identityPub) {
			continue
		}
		dev, ok := ks.Contacts[i].Devices[string(devicePub)]
		if !ok || dev == nil {
			return shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		if len(dev.RelIdentityPriv) != ed25519.PrivateKeySize || len(dev.PeerRelIdentityPub) != ed25519.PublicKeySize {
			return shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		// A revoked IdentityKey-per-relationship (a verified "rel_revoke"
		// knock, see applyRelRevoke) must no longer authenticate a
		// handshake — treated as if the key didn't exist at all, the
		// same outcome as a contact/device not found.
		if dev.RevokedIdentity {
			return shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		return shared.RelPeerKey{Pub: ed25519.PublicKey(dev.PeerRelIdentityPub), MLDSAPub: dev.PeerRelIdentityMLDSAPub},
			shared.RelSigningKey{Priv: ed25519.PrivateKey(dev.RelIdentityPriv), MLKEMSeed: dev.RelIdentityMLKEMPriv, MLDSASeed: dev.RelIdentityMLDSAPriv},
			true
	}
	return shared.RelPeerKey{}, shared.RelSigningKey{}, false
}

// DeviceWithPendingRelKeys returns the first device (deterministic
// order) with a pending relationship-key conflict (TrustDanger,
// PendingPeerRelIdentityPub/PendingPeerRelContentPub) — unlike
// SoleDevice(), it works even with 2+ known devices as long as the
// conflict is on ONE of them (the common case: a real conflict is rare,
// two simultaneous ones on the same contact even rarer). No UI to
// choose which device to review if more than one has a pending conflict:
// it stays on the first entry in order.
func (c Contact) DeviceWithPendingRelKeys() (devicePub []byte, dev *DeviceRelation, ok bool) {
	for _, key := range sortedDeviceKeys(c.Devices) {
		d := c.Devices[key]
		if d == nil {
			continue
		}
		if len(d.PendingPeerRelIdentityPub) > 0 || len(d.PendingPeerRelContentPub) > 0 {
			return []byte(key), d, true
		}
	}
	return nil, nil, false
}

// CloneDevices returns an INDEPENDENT copy of the Devices map — a new
// map with new *DeviceRelation values (the []byte fields stay shared
// with the original, never a problem: they're never mutated in place,
// only reassigned). Needed anywhere a Contact is exposed as a mutable
// "mirror" independent of the live keystore (e.g. ContactsSnapshot,
// cmd/main.go:convertContacts) — Devices is a map: copying the Contact struct
// by value does NOT isolate the map, which would stay shared with the
// original (same hashtable), and every mutation of the "clone" would
// silently write into the live keystore too, outside ks.mu.
func (c Contact) CloneDevices() map[string]*DeviceRelation {
	if c.Devices == nil {
		return nil
	}
	out := make(map[string]*DeviceRelation, len(c.Devices))
	for k, dev := range c.Devices {
		if dev == nil {
			continue
		}
		cp := *dev
		out[k] = &cp
	}
	return out
}

// DisplayName returns the name to display: LocalName if set, otherwise Username.
func (c Contact) DisplayName() string {
	if c.LocalName != "" {
		return c.LocalName
	}
	return c.Username
}

// TrustLevel is a small trust level (unknown/marginal/full), derived
// from two independent facts already present on the contact — whether
// it was verified out of band (Verified) and whether it came from a
// third-party introduction (IntroducedBy) — with no transitive trust
// computation: trust in the introducer doesn't automatically propagate
// to Verified, it remains just provenance information.
type TrustLevel int

const (
	// TrustDanger — explicit value -1, below TrustUnknown: an unresolved
	// relationship-key conflict (PendingPeerRelIdentityPub/
	// PendingPeerRelContentPub populated) overrides any other level
	// computed from Verified/IntroducedBy, even the highest
	// (TrustVerifiedIntroduced) — see TrustLevel() below. As a trust
	// VALUE it's the lowest possible; as URGENCY for the user it must be
	// treated with higher priority than a simply unverified contact
	// (TrustUnknown/TrustIntroduced) in every list/picker — a never
	// verified contact is normal, one with a key conflict is an anomaly.
	TrustDanger             TrustLevel = iota - 1
	TrustUnknown                       // never verified, direct provenance (knock, QR, manual)
	TrustIntroduced                    // introduced by another contact, not yet verified in person
	TrustVerified                      // verified in person (/sec-verify), direct provenance
	TrustVerifiedIntroduced            // verified in person, but originally introduced by a third party
)

// TrustLevel computes the contact's trust level from its persisted
// fields. An unresolved relationship-key conflict on ANY known device
// (bubble-up, see DeviceRelation.hasPendingConflict) ALWAYS overrides,
// before evaluating Verified/IntroducedBy — see TrustDanger above.
func (c Contact) TrustLevel() TrustLevel {
	for _, dev := range c.Devices {
		if dev.hasPendingConflict() {
			return TrustDanger
		}
	}
	switch {
	case c.Verified && c.IntroducedBy != "":
		return TrustVerifiedIntroduced
	case c.Verified:
		return TrustVerified
	case c.IntroducedBy != "":
		return TrustIntroduced
	default:
		return TrustUnknown
	}
}

// IdentityRef is a lightweight reference to an identity (username +
// pubkey), used inside DeviceRecord to list the sibling identities
// present on a device at the time of the last "indoor" sync.
type IdentityRef struct {
	Username    string `json:"username"`
	IdentityPub []byte `json:"identity_pub"`        // Ed25519 pubkey (32 bytes)
	MLKEMPub    []byte `json:"mlkem_pub,omitempty"` // durable ML-KEM-768 encapsulation key (1184 bytes) — optional, empty = classic knock toward this identity
}

// DeviceRecord describes a device known to (also) host this same
// identity, learned through "indoor" sync (LAN). SiblingIdentities is
// NOT just the shared identity that led to the registration: it's the
// COMPLETE list of sibling identities present on that device at the
// time of the last sync — whoever sends a remote_nuke command doesn't
// know which of these will be reachable at that moment, but they're all
// the same exact target (the same file), so they must all be tried
// (fan-out). A later sync overwrites SiblingIdentities with the updated
// list.
type DeviceRecord struct {
	DeviceID          []byte        `json:"device_id"`
	DevicePub         []byte        `json:"device_pub"` // device's Ed25519 pubkey (32 bytes)
	Label             string        `json:"label,omitempty"`
	AddedAt           time.Time     `json:"added_at"`
	SiblingIdentities []IdentityRef `json:"sibling_identities,omitempty"`
}

// PendingRemoteNuke records a remote_nuke command issued by this
// identity toward TargetDeviceID and not yet confirmed by an ack — see
// Keystore.PendingRemoteNukes.
type PendingRemoteNuke struct {
	TargetDeviceID []byte    `json:"target_device_id"`
	RequestedAt    time.Time `json:"requested_at"`
}

// DeletedContact is a permanent tombstone for a contact deleted by this
// identity, on any of its sibling devices — see
// Keystore.DeletedContacts.
type DeletedContact struct {
	IdentityPub []byte    `json:"identity_pub"`
	DeletedAt   time.Time `json:"deleted_at"`
	// ConfirmedSiblings lists the DeviceIDs (from KnownDevices) known to
	// have already adopted this same tombstone — never this device's
	// own DeviceID, which is implicitly always confirmed. Grows only.
	ConfirmedSiblings [][]byte `json:"confirmed_siblings,omitempty"`
}

// DangerBroadcastPending lists the identity keys of contacts not yet
// confirmed for the danger_broadcast related to TargetDeviceID — see
// Keystore.PendingDangerBroadcasts.
type DangerBroadcastPending struct {
	TargetDeviceID []byte   `json:"target_device_id"`
	IdentityPubs   [][]byte `json:"identity_pubs"`
}

// SavedGroupMember is a member of a locally saved group.
type SavedGroupMember struct {
	Username    string `json:"username"`
	IdentityPub []byte `json:"identity_pub"` // Ed25519 pubkey (32 bytes)
}

// SavedGroup is a chat group with a known membership, saved locally.
// The secret is NOT saved: it's regenerated on every session.
// LocalName is the user's personal name for this group (may differ between members).
// GroupID is the stable identifier shared by all members.
type SavedGroup struct {
	LocalName string             `json:"local_name"`
	GroupID   string             `json:"group_id"`
	Members   []SavedGroupMember `json:"members"`
}

// Keystore holds the local identity, contacts and saved groups.
// In memory it's plaintext; on disk it's encrypted with Argon2id + AES-256-GCM.
//
// A keystore file can hold several independent identities (each with
// its own Username/IdentityKey/Contacts/SavedGroups), all encrypted
// together under the same password — see LoadAll/AddIdentity. The
// siblings field links a loaded identity to the others in the same
// file, so Save() on any one of them rewrites the whole list instead of
// losing the others.
type Keystore struct {
	Version  int    `json:"version"`
	Username string `json:"username"`
	// IdentityKey/MLKEMKey/MLDSAKey are the global per-identity
	// TRANSPORT key — generates the Tor hidden service and the I2P
	// destination (AddHiddenService/I2PDestinationPriv) and is used for
	// the knock toward a known contact (KnockDHTag mutuality tag,
	// EncryptKnock/DecryptKnock). It never authenticates the WebSocket
	// handshake: that role belongs to the relationship keys on each
	// Contact. On rotation (StartRootRotation) the previous key stays in
	// the Old* vault below until every contact and device has confirmed;
	// each contact is notified of the new key through the stable
	// relationship key it already has with this identity (root_rotate).
	IdentityKey []byte `json:"identity_key"` // current Ed25519 private key (64 bytes)
	MLKEMKey    []byte `json:"mlkem_key,omitempty"`
	MLDSAKey    []byte `json:"mldsa_key,omitempty"`

	// OldIdentityKey/OldMLKEMKey/OldMLDSAKey — temporary vault of the
	// PREVIOUS root, retained ONLY for the propagation window of a
	// continuity root rotation (StartRootRotation) — not for hosting
	// (the new root is already live in IdentityKey/MLKEMKey/MLDSAKey
	// above as soon as rotation starts), but to tag/derive the
	// announcements still outbound toward those who haven't confirmed
	// yet (KnockDHTag with the old key, which the recipient still
	// recognizes — see applyRootRotate/probeContacts) and to propagate
	// the new private material to one's own sibling devices
	// (device_sync). Cleared only by MaybeFinalizeRootRotation when both
	// pending lists below are empty — no time-based expiry.
	OldIdentityKey vaultBytes `json:"old_identity_key,omitempty"`
	OldMLKEMKey    vaultBytes `json:"old_mlkem_key,omitempty"`
	OldMLDSAKey    vaultBytes `json:"old_mldsa_key,omitempty"`

	// RootRotationPendingContacts lists the identity keys of contacts not
	// yet confirmed (root_rotate_ack) for the latest in-progress root
	// rotation — same scheme as PendingDangerBroadcasts: retried on
	// every probe cycle toward whoever appears online, no expiry, no
	// forced closure.
	RootRotationPendingContacts [][]byte `json:"root_rotation_pending_contacts,omitempty"`

	// RootRotationPendingDevices lists the DeviceIDs of one's own
	// sibling devices (KnownDevices) not yet confirmed
	// (device_sync_ack) for the latest in-progress root rotation — they
	// must receive the new private material in full (device_sync), not
	// just an announcement: unlike a contact, they share the exact same
	// root bit-for-bit.
	RootRotationPendingDevices [][]byte `json:"root_rotation_pending_devices,omitempty"`

	// DeviceID/DevicePriv/DevicePub — a device is the keystore FILE, not
	// the physical hardware: generated once when the file is created
	// (New()), shared by all sibling identities in the same file
	// (file-level field, same treatment as
	// duress — set only on the list's first element, read through
	// siblings[0] by every identity in the file, never per-sibling. Two
	// distinct identities in the same file share the same DeviceID;
	// identities in different logins/files, even on the same physical
	// hardware, have distinct DeviceIDs. Never rotates with
	// IdentityKey/MLKEMKey — a device survives an identity rotation.
	// DevicePriv co-signs every outbound message (see
	// shared.DeviceSigMsg, internal/client/client.go Send()) — not a
	// content hardening, an informational tag that's never blocking,
	// the same principle already used for the relationship signature on
	// messages.
	DeviceID   []byte `json:"device_id,omitempty"`
	DevicePriv []byte `json:"device_priv,omitempty"` // Ed25519 private, 64 bytes
	DevicePub  []byte `json:"device_pub,omitempty"`  // Ed25519 public, 32 bytes

	// AdditionalDevice — false for D1 (an identity created here with
	// New(), or restored from a bare 24 words with ImportFromMnemonic —
	// the total-disaster path, canonical address unchanged). true for an
	// additional device (D2, D3...) born from ImportFromBackupFile (24
	// words + file) — the "birth" of THIS device, which at that point
	// receives a fresh DeviceID (never cloned from the backup, see
	// ImportFromBackupFile) and computes its own derived network address
	// instead of the direct root IdentityKey — see
	// NetworkIdentityPrivKey.
	AdditionalDevice bool `json:"additional_device,omitempty"`

	// DeviceLabel is the name the user chose for THIS device (e.g.
	// "Galaxy S22", "work laptop") — the same role as Contact.LocalName
	// but for a device, not a contact. File-level like DeviceID (same
	// propagation treatment to siblings). Asked at first startup
	// (wizard, a new file's first identity — never for a second
	// identity added with add-identity, which shares the same device)
	// and always renamable (`neutrino device-label`/`/sec-device-label`).
	// Without a name chosen by the user, a device's only identifier is
	// its DeviceID (16 random bytes): two or three different devices
	// would become indistinguishable on screen — the reason the name
	// choice isn't optional in the wizard. Transmitted to the other
	// side of an "indoor" sync (DeviceRecord.Label) so a device knows
	// the names of the OTHER devices of the same identity, not just its
	// own.
	DeviceLabel string `json:"device_label,omitempty"`

	// LockSecret/LockSecretIsPIN/LockDuressMarker/LockDuressPosition —
	// the interface lock on inactivity. File-level like
	// DeviceLabel/DeviceID (same propagation treatment to siblings):
	// the lock concerns the whole process's session, not a single
	// identity. Ordinary fields inside the keystore's already-encrypted
	// blob — NOT a separate Argon2id verifier like DuressConfig: the
	// check always happens AFTER the keystore is already decrypted in
	// RAM (never at bootstrap), so a direct comparison is already
	// instant, as needed for a lock unlocked far more often than the
	// keystore's real password.
	//
	// LockSecret is NEVER derived from the keystore's real password or
	// from the duress password — an independent secret (a numeric PIN
	// on Android, a PIN or free-choice password on desktop). Empty =
	// lock not configured (feature disabled).
	LockSecret string `json:"lock_secret,omitempty"`

	// LockSecretIsPIN distinguishes the applicable rules: true for a
	// numeric PIN (native character+position duress, see
	// LockDuressMarker/LockDuressPosition below), false for a desktop
	// free-choice password (no native duress — the lock's duress in
	// that case coincides with the keystore's already-existing duress
	// password, CheckDuress, shared with the initial unlock).
	LockSecretIsPIN bool `json:"lock_secret_is_pin,omitempty"`

	// LockDuressMarker/LockDuressPosition — native duress for a PIN
	// only: one extra character, inserted at the configured position
	// inside LockSecret, triggers duress. LockDuressPosition encoding: 1
	// = before the first character (at the start); 0 = after the last
	// character (at the end); a value N (2..PIN length) = right before
	// the Nth character of the real PIN. Ignored when LockSecretIsPIN
	// is false.
	LockDuressMarker   string `json:"lock_duress_marker,omitempty"`
	LockDuressPosition int    `json:"lock_duress_position,omitempty"`

	// KnownDevices lists the devices known to (also) host this identity
	// (learned through "indoor" sync) — the list a user consults to
	// choose a remote_nuke command's target. Not needed for
	// AUTHORIZING an incoming command (that's based solely on key
	// possession, see the receiving side's verification): it's
	// sender-side bookkeeping.
	KnownDevices []DeviceRecord `json:"known_devices,omitempty"`

	// NukedDevicePubs is a grows-only set of Keystore.DevicePub values
	// (never a DeviceID: this is the value that ends up in a
	// RelRevokePayload.DevicePub field) known to belong to a sibling
	// that has been nuked — synced/gossiped transitively like
	// KnownDevices (never pruned, same permanence principle as
	// DeletedContacts below: an unknown-at-the-time sibling could still
	// surface later holding a stale SiblingRevocations entry toward
	// it). Drives the sibling retry queue: for every Contact, every
	// not-yet-Acked SiblingRevocations entry whose SiblingDevicePub
	// appears here gets resent as a "rel_revoke" knock.
	NukedDevicePubs [][]byte `json:"nuked_device_pubs,omitempty"`

	// PendingRemoteNukes lists the remote_nuke commands issued by THIS
	// identity and not yet confirmed by a remote_nuke_ack. The target
	// can remain unreachable for an arbitrary time (powered off, seized
	// but never turned back on...): a single attempt with limited
	// backoff isn't enough, so the command stays queued and is retried
	// on every subsequent startup of this identity until an ack
	// arrives — see
	// AddPendingRemoteNuke/RemovePendingRemoteNuke/PendingRemoteNukeTargets.
	// Per-identity like KnownDevices, not file-level like DeviceID: each
	// identity in the file keeps its own queue, consistent with the
	// fan-out being signed with THIS identity's key.
	PendingRemoteNukes []PendingRemoteNuke `json:"pending_remote_nukes,omitempty"`

	// DeletedContacts is the permanent list of tombstones for contacts
	// this identity has deleted, on any of its sibling devices — never
	// removed, regardless of how many KnownDevices have confirmed one
	// (ConfirmedSiblings): a sibling device unknown at deletion time can
	// surface later still holding a live copy, so a row must stay
	// available to block it indefinitely, not just until the
	// currently-known siblings confirm.
	DeletedContacts []DeletedContact `json:"deleted_contacts,omitempty"`

	// PendingDangerBroadcasts lists, for each target device still in
	// PendingRemoteNukes (or already confirmed — the entry survives
	// regardless until it's empty), the usernames of contacts not yet
	// confirmed for the related danger_broadcast, by identity key. A
	// contact may never be online together with the authority in the
	// same session, so a single attempt bounded to a ~90s window isn't
	// enough —
	// probeContacts (already running periodically for an unrelated
	// reason) resends the danger_broadcast to every contact still in
	// this list that appears online in that cycle, until a
	// danger_broadcast_ack arrives for each — see
	// SetDangerBroadcastPending/ConfirmDangerBroadcast.
	PendingDangerBroadcasts []DangerBroadcastPending `json:"pending_danger_broadcasts,omitempty"`

	// PendingDangerEnds — the exact same scheme/mechanism as
	// PendingDangerBroadcasts above, but for "danger_end": the FINAL
	// notice ("device confirmed destroyed"), sent by the TARGET itself
	// to every contact of ALL its sibling identities (I1, I2, I3...)
	// right before self-deleting — a channel only the target can use in
	// full, since only it holds the keys for every identity present on
	// the file. The AUTHORITY, on receiving the remote_nuke_ack, relays
	// the exact same message to its OWN contacts (those of the
	// identities it holds — I1, I2 in the example, never I3, which it
	// never duplicated) as a safety net: whoever didn't receive the
	// direct danger_end from the target (was offline at that exact
	// moment) still receives it, later, from the authority — a queue
	// separate from PendingDangerBroadcasts because they're two
	// distinct messages (preliminary vs. final), even though the exact
	// same retry-via-probeContacts mechanism applies to both.
	PendingDangerEnds []DangerBroadcastPending `json:"pending_danger_ends,omitempty"`

	Contacts    []Contact    `json:"contacts"`
	SavedGroups []SavedGroup `json:"saved_groups,omitempty"`

	// SlotPendingNoise/ContactPendingIdx/ContactMirrorDuressIdx/
	// DuressAccess are the N-slot keystore's bookkeeping fields — kept
	// inside every real identity's own already-encrypted content,
	// never as file-level plaintext metadata.
	//
	// SlotPendingNoise is the growth pool (see growth_pool.go) over the
	// file-level slot indices (slot_container.go) that are still
	// unassigned noise — on a real identity, the genuine pool; on the
	// shared duress identity, a plausible-looking but unrelated one
	// (never the real one: otherwise a holder of only the duress
	// password could subtract its pending count from the file's total
	// slot count — always visible to anyone with the raw file — and
	// learn exactly how many real identities exist).
	SlotPendingNoise growthPool `json:"slot_pending_noise,omitempty"`

	// ContactPendingIdx is the growth pool over this identity's own
	// still-empty Contact placeholder indices (see
	// slot_mirror_contact.go) — on a real identity, its own pool; on
	// duress, the AGGREGATE pool mirroring every real identity combined
	// (duress is the single shared decoy).
	ContactPendingIdx growthPool `json:"contact_pending_idx,omitempty"`

	// ContactMirrorDuressIdx maps one of THIS identity's own Contacts
	// indices (key) to the duress Contacts index that mirrors it
	// (value) — populated only on real identities, consulted when a
	// real contact is deleted (see slot_mirror_contact.go,
	// EmptyMirroredContact) to find and identically empty the matching
	// duress contact. Meaningless on duress itself (duress has no "its
	// own real contacts" to mirror elsewhere).
	ContactMirrorDuressIdx map[int]int `json:"contact_mirror_duress_idx,omitempty"`

	// DuressAccess is K_i_duress sealed directly under this identity's
	// own K_i on a real identity (available in RAM as soon as this
	// identity's own login succeeds, no further
	// password needed at trigger-time — see duress_access.go). On
	// duress itself, random noise of the identical shape (see
	// DuressAccessField's doc comment) — duress has no further duress
	// to reach.
	DuressAccess DuressAccessField `json:"duress_access,omitempty"`

	// IsDuress marks the shared decoy identity itself, so the running
	// process can tell its own role apart once logged in (real
	// identities carry the default false) — visible only to whoever
	// already decrypted this specific identity's own content with its
	// own password, so it adds nothing to what that password already
	// reveals.
	IsDuress bool `json:"is_duress,omitempty"`

	siblings []*Keystore // other identities in the same file (nil = isolated identity); not serialized

	// duress is the automatic NUKE password's verifier (see duress.go)
	// — shared by every identity in the same file (SetDuress propagates
	// it to the siblings), NEVER serialized in the encrypted JSON
	// payload: it must remain readable from the file's plaintext header
	// even without knowing the real password (see CheckDuress).
	duress *DuressConfig

	// mu protects Contacts and the rotation state (IdentityKey/
	// OldIdentityKey/MLKEMKey/OldMLKEMKey/MLDSAKey/OldMLDSAKey/
	// RootRotationPendingContacts/RootRotationPendingDevices) against
	// concurrent access: the package is reached by concurrent
	// goroutines (the knownContactPubsFn getter passed to
	// server.RunOnListener is invoked by an HTTP goroutine for every
	// incoming knock, while AddContact/DeleteContactByPub/StartRootRotation
	// run on the UI goroutine or an event-driven rotation goroutine).
	// A pointer shared by ALL sibling identities of the same file
	// (propagated in LoadAll/AddIdentity, never per-instance): Save()
	// marshals the whole list together, so a mutation on one sibling
	// must exclude a concurrent save/read on another. Not serialized
	// (like siblings/duress above).
	mu *sync.Mutex
}

// New returns an empty keystore with a new Ed25519 identity key, a new
// durable ML-KEM-768 decapsulation key, and a new device-level
// DeviceID/signing key — the latter generated once per FILE: a second
// New() for a second identity in the same file should be added with
// AddIdentity, which doesn't touch the existing file's
// DeviceID/DevicePriv/DevicePub.
func New(username string) (*Keystore, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_identity_key", err))
	}
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_mlkem_key", err))
	}
	mldsaSeed := make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(mldsaSeed); err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_mldsa_key", err))
	}
	deviceID := make([]byte, 16)
	if _, err := rand.Read(deviceID); err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_device_id", err))
	}
	_, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_device_key", err))
	}
	return &Keystore{
		Version:     version,
		Username:    username,
		IdentityKey: []byte(priv),
		MLKEMKey:    mlkemDK.Bytes(),
		MLDSAKey:    mldsaSeed,
		DeviceID:    deviceID,
		DevicePriv:  []byte(devicePriv),
		DevicePub:   []byte(devicePriv.Public().(ed25519.PublicKey)),
		mu:          &sync.Mutex{},
	}, nil
}

// IdentityPrivKey returns the local identity's Ed25519 private key.
func (ks *Keystore) IdentityPrivKey() ed25519.PrivateKey {
	return ed25519.PrivateKey(ks.IdentityKey)
}

// IdentityPubKey returns the local identity's Ed25519 public key.
func (ks *Keystore) IdentityPubKey() ed25519.PublicKey {
	return ed25519.PrivateKey(ks.IdentityKey).Public().(ed25519.PublicKey)
}

// networkOnionInfo is the HKDF info that derives an additional device's
// network address from the root IdentityKey — a separate domain for
// each derivation type from the same key, never reusable for another
// purpose (the same principle already used for
// "neutrino-backup-v1"/"neutrino-sync-v1").
const networkOnionInfo = "neutrino-device-onion-v1"

// NetworkIdentityPrivKey returns the Ed25519 private key to pass to
// AddHiddenService to publish THIS device's network address — addresses
// a possible address collision with several endpoints of the same
// identity online together. D1 (AdditionalDevice false, the common
// case) stays unchanged: the direct root IdentityKey, the same
// canonical address shared via QR/URI. An additional device
// (AdditionalDevice true, born from ImportFromBackupFile — see the
// comment on that field) instead derives an independent key from
// HKDF-SHA256(IdentityKey[:32], salt=DeviceID, info="neutrino-device-onion-v1")
// — never the same as D1's, no risk of address collision, not
// recoverable from just the mnemonic (a lost device isn't "rebuilt
// identical", it's recreated new with a fresh DeviceID — consistent
// with relationship keys after a bare restore).
func (ks *Keystore) NetworkIdentityPrivKey() ed25519.PrivateKey {
	if !ks.AdditionalDevice || len(ks.DeviceID) == 0 {
		return ks.IdentityPrivKey()
	}
	return ks.NetworkIdentityPrivKeyFor(ks.DeviceID)
}

// NetworkIdentityPrivKeyFor generalizes NetworkIdentityPrivKey to an
// arbitrary DeviceID, always derived (never the direct root) — unlike
// the method above, which decides on its own whether to derive based on
// AdditionalDevice, this one always returns
// HKDF-SHA256(IdentityKey[:32], salt=deviceID, info="neutrino-device-onion-v1")
// for the given deviceID. Allows computing the network address of ANY
// device that shares this root IdentityKey — one's own sibling device
// (continuity root rotation, remote contact-list sync — see
// StartRootRotation/RootRotationPendingDevices) or an additional
// remote_nuke target, never just one's own like the method above. An
// empty deviceID falls back to the direct root (no derivation possible
// without a salt).
func (ks *Keystore) NetworkIdentityPrivKeyFor(deviceID []byte) ed25519.PrivateKey {
	if len(deviceID) == 0 {
		return ks.IdentityPrivKey()
	}
	if priv := networkIdentityPrivKeyForSeed(ks.IdentityKey, deviceID); priv != nil {
		return priv
	}
	return ks.IdentityPrivKey()
}

// networkIdentityPrivKeyForSeed is the common core of
// NetworkIdentityPrivKeyFor and OldNetworkIdentityPrivKeyForRotation —
// HKDF-SHA256(rootSeed[:32], salt=deviceID, info=networkOnionInfo),
// parameterized on the root SEED to use instead of always reading it
// from ks.IdentityKey (the common case). nil if rootSeed is too short or
// the HKDF fails.
func networkIdentityPrivKeyForSeed(rootSeed, deviceID []byte) ed25519.PrivateKey {
	if len(rootSeed) < 32 {
		return nil
	}
	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, rootSeed[:32], deviceID, []byte(networkOnionInfo))
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil
	}
	return ed25519.NewKeyFromSeed(seed)
}

// OldNetworkIdentityPrivKeyForRotation returns the network address
// derived for deviceID using the PREVIOUS root (Keystore.OldIdentityKey,
// retained during an in-progress root rotation — see StartRootRotation)
// instead of the current one — nil if no rotation is in progress or
// deviceID is empty. Needed to reach one's own sibling device that
// hasn't adopted the latest rotation yet: as long as it stays on the old
// root, ITS hidden service remains published at the address derived
// from THAT one, not the new one — see device_sync.
func (ks *Keystore) OldNetworkIdentityPrivKeyForRotation(deviceID []byte) ed25519.PrivateKey {
	if len(deviceID) == 0 {
		return nil
	}
	ks.mu.Lock()
	oldRoot := ks.OldIdentityKey.bytes()
	ks.mu.Unlock()
	if len(oldRoot) == 0 {
		return nil
	}
	return networkIdentityPrivKeyForSeed(oldRoot, deviceID)
}

// StartRootRotation starts a CONTINUITY rotation of the root
// IdentityKey/MLKEMKey/MLDSAKey (from which one's own network address is
// derived) — stashes the previous keys into the Old* vaults above (they
// serve to tag the announcements still in flight toward those who
// haven't confirmed yet — KnockDHTag with the old key, still recognized
// by the recipient until it applies the announcement) and applies the
// new ones as current IMMEDIATELY. Repopulates RootRotationPendingContacts
// with EVERY known username in the contact list and
// RootRotationPendingDevices with every DeviceID from KnownDevices —
// propagation (announcing to contacts + device_sync to siblings) is the
// caller's responsibility (probeContacts/Once(), outside this package).
// Error if a root rotation is already in progress (one at a time, the
// same principle as relationship rotations) — no forced closure: the
// only way out is for every contact/device to confirm, or to wait
// (never a timeout).
func (ks *Keystore) StartRootRotation() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.OldIdentityKey.isSet() {
		return errors.New(i18n.T("keystore.err_root_rotation_already_pending"))
	}
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New(i18n.T("keystore.err_gen_new_key", err))
	}
	newMLKEM, err := mlkem.GenerateKey768()
	if err != nil {
		return errors.New(i18n.T("keystore.err_gen_mlkem_key", err))
	}
	newMLDSASeed := make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(newMLDSASeed); err != nil {
		return errors.New(i18n.T("keystore.err_gen_mldsa_key", err))
	}

	ks.applyNewRootLocked([]byte(newPriv), newMLKEM.Bytes(), newMLDSASeed)
	return nil
}

// applyNewRootLocked is the common core of StartRootRotation (key
// generated here) and AdoptRootRotation (key received from a sibling
// device) — the caller must already hold ks.mu. Stashes the current
// root into the Old* vaults, applies the new one, repopulates
// RootRotationPendingContacts/RootRotationPendingDevices from THIS
// device's own contact list/KnownDevices (independent of the ones held
// by whoever originated the rotation — this device behaves exactly like
// the device that started the rotation).
func (ks *Keystore) applyNewRootLocked(newIdentityKey, newMLKEMKey, newMLDSAKey []byte) {
	ks.OldIdentityKey = newVaultBytes(ks.IdentityKey)
	ks.OldMLKEMKey = newVaultBytes(ks.MLKEMKey)
	ks.OldMLDSAKey = newVaultBytes(ks.MLDSAKey)
	ks.IdentityKey = append([]byte(nil), newIdentityKey...)
	ks.MLKEMKey = append([]byte(nil), newMLKEMKey...)
	ks.MLDSAKey = append([]byte(nil), newMLDSAKey...)

	pendingContacts := make([][]byte, 0, len(ks.Contacts))
	for _, c := range ks.Contacts {
		pendingContacts = append(pendingContacts, append([]byte(nil), c.IdentityPub...))
	}
	ks.RootRotationPendingContacts = pendingContacts

	pendingDevices := make([][]byte, 0, len(ks.KnownDevices))
	for _, d := range ks.KnownDevices {
		pendingDevices = append(pendingDevices, append([]byte(nil), d.DeviceID...))
	}
	ks.RootRotationPendingDevices = pendingDevices
}

// AdoptRootRotation applies an IdentityKey/MLKEMKey/MLDSAKey root
// received from a sibling device (device_sync) — never generated here:
// only ONE device generates it (StartRootRotation), every other one
// adopts the same material, or the shared identity would split into two
// different keys. Idempotent: if newIdentityKey already matches the
// current root (a duplicate/delayed device_sync), a safe no-op — doesn't
// repopulate the pending lists, doesn't lose already-made progress.
func (ks *Keystore) AdoptRootRotation(newIdentityKey, newMLKEMKey, newMLDSAKey []byte) error {
	if len(newIdentityKey) != ed25519.PrivateKeySize {
		return errors.New(i18n.T("keystore.err_root_rotation_invalid_material"))
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if bytes.Equal(ks.IdentityKey, newIdentityKey) {
		return nil
	}
	ks.applyNewRootLocked(newIdentityKey, newMLKEMKey, newMLDSAKey)
	return nil
}

// AckRootRotationContact removes the contact with identity key pub from
// RootRotationPendingContacts
// on receiving a valid root_rotate_ack — returns false if it wasn't
// there (a late/duplicate ack, harmless). Internally calls
// MaybeFinalizeRootRotation.
func (ks *Keystore) AckRootRotationContact(pub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, p := range ks.RootRotationPendingContacts {
		if bytes.Equal(p, pub) {
			ks.RootRotationPendingContacts = append(ks.RootRotationPendingContacts[:i], ks.RootRotationPendingContacts[i+1:]...)
			ks.maybeFinalizeRootRotationLocked()
			return true
		}
	}
	return false
}

// AckRootRotationDevice removes deviceID from RootRotationPendingDevices
// on receiving a valid device_sync_ack — same semantics as
// AckRootRotationContact.
func (ks *Keystore) AckRootRotationDevice(deviceID []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, d := range ks.RootRotationPendingDevices {
		if bytes.Equal(d, deviceID) {
			ks.RootRotationPendingDevices = append(ks.RootRotationPendingDevices[:i], ks.RootRotationPendingDevices[i+1:]...)
			ks.maybeFinalizeRootRotationLocked()
			return true
		}
	}
	return false
}

// MaybeFinalizeRootRotation clears the Old* vaults ONLY when both
// pending lists are empty (rotation confirmed by every contact and
// every sibling device) — no time-based expiry, consistent with the
// absence of a forced closure (see the comment on StartRootRotation).
func (ks *Keystore) MaybeFinalizeRootRotation() {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.maybeFinalizeRootRotationLocked()
}

func (ks *Keystore) maybeFinalizeRootRotationLocked() {
	if len(ks.RootRotationPendingContacts) == 0 && len(ks.RootRotationPendingDevices) == 0 {
		ks.OldIdentityKey = vaultBytes{}
		ks.OldMLKEMKey = vaultBytes{}
		ks.OldMLDSAKey = vaultBytes{}
	}
}

// RootRotationPendingSnapshot returns copies of RootRotationPendingContacts
// and RootRotationPendingDevices — contacts and sibling devices that
// haven't confirmed the latest root rotation yet.
func (ks *Keystore) RootRotationPendingSnapshot() ([][]byte, [][]byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	contacts := make([][]byte, len(ks.RootRotationPendingContacts))
	for i, p := range ks.RootRotationPendingContacts {
		contacts[i] = append([]byte(nil), p...)
	}
	devices := make([][]byte, len(ks.RootRotationPendingDevices))
	for i, d := range ks.RootRotationPendingDevices {
		devices[i] = append([]byte(nil), d...)
	}
	return contacts, devices
}

// OldIdentityPrivKeyForRotation returns the PREVIOUS private root
// retained during an in-progress root rotation (nil if no rotation is
// in progress) — used ONLY to tag (KnockDHTag) root_rotate
// announcements still in flight toward those who haven't confirmed yet:
// the recipient still recognizes this key, because it hasn't applied
// the announcement yet (see StartRootRotation).
func (ks *Keystore) OldIdentityPrivKeyForRotation() ed25519.PrivateKey {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	b := ks.OldIdentityKey.bytes()
	if len(b) == 0 {
		return nil
	}
	return ed25519.PrivateKey(b)
}

// RootRotationInProgress reports whether a continuity root rotation is
// currently in progress (at least one contact or sibling device not yet
// confirmed) — used both by the caller that must decide whether to
// start a new one, and by tests.
func (ks *Keystore) RootRotationInProgress() bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.OldIdentityKey.isSet()
}

// MLDSAPrivKey rebuilds the network identity's ML-DSA-65 private key
// from the seed (nil if MLDSAKey is absent).
func (ks *Keystore) MLDSAPrivKey() *mldsa65.PrivateKey {
	if len(ks.MLDSAKey) != mldsa65.SeedSize {
		return nil
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], ks.MLDSAKey)
	_, priv := mldsa65.NewKeyFromSeed(&seed)
	return priv
}

// MLDSAPubKey returns the network identity's ML-DSA-65 public key (nil
// if MLDSAKey is absent).
func (ks *Keystore) MLDSAPubKey() *mldsa65.PublicKey {
	if len(ks.MLDSAKey) != mldsa65.SeedSize {
		return nil
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], ks.MLDSAKey)
	pub, _ := mldsa65.NewKeyFromSeed(&seed)
	return pub
}

// MLDSAPubBytes returns the network identity's ML-DSA-65 public key
// already packed (1952 bytes, mldsa65.PublicKeySize) — ready for the
// identity URI/QR, the same role as MLKEMPubBytes above. nil if MLDSAKey
// is absent.
func (ks *Keystore) MLDSAPubBytes() []byte {
	pub := ks.MLDSAPubKey()
	if pub == nil {
		return nil
	}
	var buf [mldsa65.PublicKeySize]byte
	pub.Pack(&buf)
	return buf[:]
}

// AllAuthorityPubKeys returns the Ed25519 public keys (current AND old,
// during an in-progress rotation) of EVERY identity present in this
// file — itself plus every sibling. It's exactly the set a remote_nuke
// command's target verifies NukeSig against: possessing the private key
// of any one of these identities, wherever the holder is, is the
// authorization to delete THIS file — no separate "authorized devices"
// list to consult.
func (ks *Keystore) AllAuthorityPubKeys() []ed25519.PublicKey {
	list := ks.siblings
	if list == nil {
		list = []*Keystore{ks}
	}
	out := make([]ed25519.PublicKey, 0, len(list))
	for _, k := range list {
		if len(k.IdentityKey) > 0 {
			out = append(out, k.IdentityPubKey())
		}
	}
	return out
}

// AllAuthorityPubKeysMLDSA is the ML-DSA-65 counterpart of
// AllAuthorityPubKeys above — same role, same structure (itself plus
// every sibling, current AND old during an in-progress rotation).
func (ks *Keystore) AllAuthorityPubKeysMLDSA() []*mldsa65.PublicKey {
	list := ks.siblings
	if list == nil {
		list = []*Keystore{ks}
	}
	out := make([]*mldsa65.PublicKey, 0, len(list))
	for _, k := range list {
		if pub := k.MLDSAPubKey(); pub != nil {
			out = append(out, pub)
		}
	}
	return out
}

// SiblingIdentityRefs returns Username+IdentityPub(+MLKEMPub, if
// present) for EVERY identity of this file — itself plus every sibling
// — used to populate DeviceRecord.SiblingIdentities when announcing
// one's own device to a peer ("indoor" sync): only each identity's
// CURRENT key (unlike AllAuthorityPubKeys, which also includes the old
// one during a rotation — here a currently reachable network address is
// needed, not a historical key).
func (ks *Keystore) SiblingIdentityRefs() []IdentityRef {
	list := ks.siblings
	if list == nil {
		list = []*Keystore{ks}
	}
	out := make([]IdentityRef, 0, len(list))
	for _, k := range list {
		if len(k.IdentityKey) == 0 {
			continue
		}
		out = append(out, IdentityRef{
			Username:    k.Username,
			IdentityPub: k.IdentityPubKey(),
			MLKEMPub:    k.MLKEMPubBytes(),
		})
	}
	return out
}

// SiblingKeystores returns the whole list of sibling identities present
// in the same file (itself included, always at least one element) —
// unlike AllAuthorityPubKeys/SiblingIdentityRefs, which expose only
// public material, this returns the complete *Keystore values (private
// key + contact list of each). Reserved for callers already fully
// trusted, operating on behalf of EVERY identity in the file, not just
// the active one — cmd/main.go, for the danger_end broadcast:
// the target device, before self-deleting, must be able to notify the
// contacts of ALL its sibling identities, not just the one it's running
// as in that session. Never exposed to internal/client (which must
// never see private keys outside the closures already established).
func (ks *Keystore) SiblingKeystores() []*Keystore {
	if ks.siblings == nil {
		return []*Keystore{ks}
	}
	return ks.siblings
}

// MLKEMDecap rebuilds the identity's durable ML-KEM-768 decapsulation
// key from the persisted seed (MLKEMKey). nil if absent.
func (ks *Keystore) MLKEMDecap() *mlkem.DecapsulationKey768 {
	if len(ks.MLKEMKey) == 0 {
		return nil
	}
	dk, err := mlkem.NewDecapsulationKey768(ks.MLKEMKey)
	if err != nil {
		return nil
	}
	return dk
}

// MLKEMPubBytes returns the public ML-KEM-768 encapsulation key (1184
// bytes) derived from the durable decapsulation key — nil if absent.
func (ks *Keystore) MLKEMPubBytes() []byte {
	dk := ks.MLKEMDecap()
	if dk == nil {
		return nil
	}
	return dk.EncapsulationKey().Bytes()
}

// DeviceIDHex returns the file's DeviceID in hexadecimal, for display
// (e.g. /sec-devices) — empty string if absent.
func (ks *Keystore) DeviceIDHex() string {
	if len(ks.DeviceID) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", ks.DeviceID)
}

// DevicePrivKey returns the device-level Ed25519 private key (co-signs
// every outbound message — see shared.DeviceSigMsg).
func (ks *Keystore) DevicePrivKey() ed25519.PrivateKey {
	if len(ks.DevicePriv) == 0 {
		return nil
	}
	return ed25519.PrivateKey(ks.DevicePriv)
}

// DevicePubKey returns the device-level Ed25519 public key.
func (ks *Keystore) DevicePubKey() ed25519.PublicKey {
	if len(ks.DevicePub) == 0 {
		return nil
	}
	return ed25519.PublicKey(ks.DevicePub)
}

// SetDeviceLabel sets THIS device's name (e.g. "Galaxy S22"), propagated
// to every sibling identity of the same file — the same file-level
// treatment as SetDuress/DeviceID. The caller calls Save() afterward.
func (ks *Keystore) SetDeviceLabel(label string) {
	ks.DeviceLabel = label
	for _, s := range ks.siblings {
		s.DeviceLabel = label
	}
}

// SetLockSecret sets (or replaces) the interface lock's secret — isPIN
// true for a numeric PIN (native character+position duress,
// marker/position below), false for a desktop free-choice password
// (marker/position ignored, the lock's duress coincides with
// CheckDuress). File-level like SetDeviceLabel: propagated to every
// sibling identity. The caller calls Save() afterward.
func (ks *Keystore) SetLockSecret(secret string, isPIN bool, duressMarker string, duressPosition int) {
	ks.LockSecret = secret
	ks.LockSecretIsPIN = isPIN
	ks.LockDuressMarker = duressMarker
	ks.LockDuressPosition = duressPosition
	for _, s := range ks.siblings {
		s.LockSecret = secret
		s.LockSecretIsPIN = isPIN
		s.LockDuressMarker = duressMarker
		s.LockDuressPosition = duressPosition
	}
}

// ClearLockSecret disables the interface lock (no secret configured).
func (ks *Keystore) ClearLockSecret() {
	ks.SetLockSecret("", false, "", 0)
}

// HasLockSecret reports whether the interface lock is configured.
func (ks *Keystore) HasLockSecret() bool {
	return ks.LockSecret != ""
}

// LockCheckResult is the outcome of comparing a candidate input against
// the lock's secret — see CheckLockSecret.
type LockCheckResult int

const (
	LockCheckWrong LockCheckResult = iota
	LockCheckOK
	LockCheckDuress
)

// CheckLockSecret compares candidate against the configured lock secret
// (LockSecret) and, if it's a PIN, against its native duress variant
// (candidate with one extra character at the configured position — see
// LockDuressPosition). Never touches CheckDuress (the keystore's
// general duress password) — that comparison stays the caller's
// responsibility, kept separate by design.
func (ks *Keystore) CheckLockSecret(candidate string) LockCheckResult {
	if ks.LockSecret == "" {
		return LockCheckWrong
	}
	if candidate == ks.LockSecret {
		return LockCheckOK
	}
	if !ks.LockSecretIsPIN || ks.LockDuressMarker == "" {
		return LockCheckWrong
	}
	if stripped, ok := stripDuressMarker(candidate, ks.LockDuressMarker, ks.LockDuressPosition); ok && stripped == ks.LockSecret {
		return LockCheckDuress
	}
	return LockCheckWrong
}

// stripDuressMarker removes the marker character from candidate at the
// position encoded by position (1 = at the start, 0 = at the end, N =
// right before the Nth character of candidate WITHOUT the marker — see
// the comment on LockDuressPosition) and returns the resulting string.
// ok is false if candidate doesn't have the expected length
// (len(real)+1) or the character at that position isn't the marker.
func stripDuressMarker(candidate, marker string, position int) (string, bool) {
	cr := []rune(candidate)
	mr := []rune(marker)
	if len(mr) != 1 || len(cr) == 0 {
		return "", false
	}
	var idx int
	switch {
	case position == 1:
		idx = 0
	case position == 0:
		idx = len(cr) - 1
	case position >= 2 && position <= len(cr)-1:
		idx = position - 1
	default:
		return "", false
	}
	if cr[idx] != mr[0] {
		return "", false
	}
	return string(append(append([]rune{}, cr[:idx]...), cr[idx+1:]...)), true
}

// NetworkStabilityOK reports whether at least "required" has elapsed
// since the network became stable (stableSince — typically the moment
// the Tor/I2P bootstrap published the hidden service, never persisted,
// reset on every process restart). Meant as a precondition for a
// relationship key: without this constraint a device just powered on by
// whoever doesn't legitimately own it could rotate the identity in the
// first instants, complicating the real owner's reaction. Not checked
// by StartRootRotation nor by
// StartRelIdentityRotationByPub/StartRelContentRotationByPub.
func NetworkStabilityOK(stableSince time.Time, required time.Duration) bool {
	return !stableSince.IsZero() && time.Since(stableSince) >= required
}

// decryptFile reads and decrypts the keystore's raw payload
// (salt||nonce||ciphertext, preceded by the automatic NUKE password's
// optional plaintext header — see duress.go/readDuressHeader).
func decryptFile(path, password string) ([]byte, *DuressConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, errors.New(i18n.T("keystore.err_read_file", err))
	}
	duress, body, _ := readDuressHeader(data)
	if len(body) < saltLen+nonceLen {
		return nil, duress, errors.New(i18n.T("keystore.err_file_too_short"))
	}

	salt := body[:saltLen]
	nonce := body[saltLen : saltLen+nonceLen]
	ciphertext := body[saltLen+nonceLen:]

	key := deriveKey([]byte(password), salt)
	plain, err := aesgcmDecrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, duress, errors.New(i18n.T("keystore.err_wrong_password"))
	}
	return plain, duress, nil
}

// migrateVersion upgrades a single identity in place to the current
// format version; each case falls through to the next.
func migrateVersion(ks *Keystore) error {
	switch ks.Version {
	case 1:
		// Version 1: generates the IdentityKey if absent.
		if len(ks.IdentityKey) == 0 {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return errors.New(i18n.T("keystore.err_migration_key", err))
			}
			ks.IdentityKey = []byte(priv)
			fmt.Println(i18n.T("keystore.warn_migration_key"))
		}
		fallthrough
	case 2:
		// Version 2: generates the MLKEMKey if absent.
		ks.Version = version
		if len(ks.MLKEMKey) == 0 {
			mlkemDK, err := mlkem.GenerateKey768()
			if err != nil {
				return errors.New(i18n.T("keystore.err_migration_mlkem_key", err))
			}
			ks.MLKEMKey = mlkemDK.Bytes()
			fmt.Println(i18n.T("keystore.warn_migration_mlkem_key"))
		}
		fallthrough
	case 3:
		// Version 3: DeviceID/DevicePriv/DevicePub are file-level, filled
		// in once for the whole file by LoadAll, not here.
		ks.Version = version
		fallthrough
	case 4:
		// Version 4: generates the MLDSAKey if absent.
		ks.Version = version
		if len(ks.MLDSAKey) == 0 {
			seed := make([]byte, mldsa65.SeedSize)
			if _, err := rand.Read(seed); err != nil {
				return errors.New(i18n.T("keystore.err_migration_mldsa_key", err))
			}
			ks.MLDSAKey = seed
			fmt.Println(i18n.T("keystore.warn_migration_mldsa_key"))
		}
		fallthrough
	case 5:
		// Version 5: LegacyRelInitConfirmedByPeer (JSON key
		// `rel_init_confirmed_by_peer`) sets both RelIdentityConfirmedByPeer
		// and RelContentConfirmedByPeer, then is cleared (omitempty: never
		// written again).
		ks.Version = version
		for i := range ks.Contacts {
			for _, dev := range ks.Contacts[i].Devices {
				if dev == nil || !dev.LegacyRelInitConfirmedByPeer {
					continue
				}
				dev.RelIdentityConfirmedByPeer = true
				dev.RelContentConfirmedByPeer = true
				dev.LegacyRelInitConfirmedByPeer = false
			}
		}
	case version:
		// ok
	default:
		return errors.New(i18n.T("keystore.err_unsupported_ver", ks.Version, version))
	}
	return nil
}

// LoadAll decrypts and loads every identity present in the given
// keystore file. A file holds either a list of identities or a single
// identity object, which is wrapped in a one-element list. The returned identities are linked to each
// other (see the siblings field) so Save() on any one of them rewrites
// the whole list.
func LoadAll(path, password string) ([]*Keystore, error) {
	plain, duress, err := decryptFile(path, password)
	if err != nil {
		return nil, err
	}

	var list []*Keystore
	if err := json.Unmarshal(plain, &list); err != nil || len(list) == 0 {
		// not an array (or empty): try a single object
		var single Keystore
		if err2 := json.Unmarshal(plain, &single); err2 != nil {
			return nil, errors.New(i18n.T("keystore.err_parse_json", err))
		}
		list = []*Keystore{&single}
	}

	var prunedAny bool
	for _, ks := range list {
		if err := migrateVersion(ks); err != nil {
			return nil, err
		}
		if pruneOrphanPlaceholderDevices(ks) {
			prunedAny = true
		}
	}
	mu := &sync.Mutex{}
	for _, ks := range list {
		ks.siblings = list
		ks.duress = duress
		ks.mu = mu
	}
	// DeviceID/DevicePriv/DevicePub are file-level, not per-identity —
	// unlike IdentityKey/MLKEMKey (which migrateVersion backfills
	// per-entry, each identity needs its OWN), a device must be
	// generated once for the whole file and shared by every identity it
	// contains. list[0] is the anchor: if it's missing there, a single
	// device is generated and propagated to every identity in the list —
	// never a different device for each. siblings is already
	// set above BEFORE this block: Save() below uses ks.siblings to
	// write the whole list, not just list[0] — a reversed order would
	// silently lose the file's other identities.
	if len(list) > 0 && len(list[0].DeviceID) == 0 {
		deviceID := make([]byte, 16)
		if _, err := rand.Read(deviceID); err != nil {
			return nil, errors.New(i18n.T("keystore.err_gen_device_id", err))
		}
		_, devicePriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errors.New(i18n.T("keystore.err_gen_device_key", err))
		}
		for _, ks := range list {
			ks.DeviceID = deviceID
			ks.DevicePriv = []byte(devicePriv)
			ks.DevicePub = []byte(devicePriv.Public().(ed25519.PublicKey))
		}
		// Persisted IMMEDIATELY, not left only in memory waiting for
		// some other action to save the file later in the session:
		// unlike the IdentityKey/MLKEMKey backfill above (which
		// survives regardless because the network address it derives
		// is already visible/used before the user could exit without
		// ever saving), a DeviceID regenerated on every startup would
		// silently break the feature's whole purpose — no stable
		// targeting for remote_nuke, no stable recognition through
		// indoor sync.
		if err := list[0].Save(path, password); err != nil {
			return nil, err
		}
	} else if prunedAny {
		if err := list[0].Save(path, password); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// pruneOrphanPlaceholderDevices removes, for each contact, the ""
// placeholder device when it coexists with another device already
// confirmed in both directions (RelIdentityConfirmedByPeer and
// RelContentConfirmedByPeer) — a placeholder that never received a
// response from the contact (no PeerRelIdentityPub/PeerRelContentPub)
// carries no useful information once a real relationship already exists
// with them, and its mere presence makes
// SoleDevice()/SoleDeviceOrPlaceholder() ambiguous for that contact.
// Returns true if it removed at least one entry.
func pruneOrphanPlaceholderDevices(ks *Keystore) bool {
	pruned := false
	for i := range ks.Contacts {
		devs := ks.Contacts[i].Devices
		if len(devs) < 2 {
			continue
		}
		ph, hasPh := devs[""]
		if !hasPh || ph == nil || len(ph.PeerRelIdentityPub) > 0 || len(ph.PeerRelContentPub) > 0 {
			continue
		}
		for k, d := range devs {
			if k == "" || d == nil {
				continue
			}
			if d.RelIdentityConfirmedByPeer && d.RelContentConfirmedByPeer {
				delete(devs, "")
				pruned = true
				break
			}
		}
	}
	return pruned
}

// Load decrypts and loads a single identity from the given path — used
// where it doesn't matter which identity is returned (e.g. checking the
// password). Use LoadAll to correctly handle a keystore with several
// identities.
func Load(path, password string) (*Keystore, error) {
	list, err := LoadAll(path, password)
	if err != nil {
		return nil, err
	}
	return list[0], nil
}

// AddIdentity adds newKs to the list of already-loaded identities
// (typically from LoadAll) and relinks the siblings, so Save() on any
// one of them (newKs included) rewrites the whole updated list. Returns
// an error if an identity with the same Username already exists.
func AddIdentity(existing []*Keystore, newKs *Keystore) ([]*Keystore, error) {
	for _, k := range existing {
		if k.Username == newKs.Username {
			return nil, errors.New(i18n.T("keystore.err_identity_exists", newKs.Username))
		}
	}
	// The device belongs to the whole FILE, not the single identity —
	// newKs always inherits DeviceID/DevicePriv/DevicePub from the
	// existing file (whatever New() had generated for it is discarded),
	// otherwise two identities in the same login/file would end up with
	// two distinct devices, contradicting the "one file = one device"
	// model.
	if len(existing) > 0 {
		newKs.DeviceID = existing[0].DeviceID
		newKs.DevicePriv = existing[0].DevicePriv
		newKs.DevicePub = existing[0].DevicePub
		newKs.DeviceLabel = existing[0].DeviceLabel
		// mu: shared by ALL sibling identities of the same file (not its
		// own, generated by New() before knowing it would end up in an
		// already-existing file) — Save() marshals the whole list
		// together, a per-instance mutex would leave two identities of
		// the same file free to mutate concurrently without excluding
		// each other.
		newKs.mu = existing[0].mu
		// duress: like DeviceID above, the automatic NUKE password is
		// shared by the whole FILE, not the single identity (SetDuress
		// already propagates it to every sibling) — but newKs.duress
		// is nil (never set by New(), an unexported/unserialized
		// field) until copied here explicitly. Without this line,
		// Save() called on the new identity (runAddIdentity) would
		// write the plaintext header with duress=nil, silently
		// erasing a protection already configured on the file: a
		// previously set NUKE password would stop working
		// (indistinguishable from a wrong password) with no warning to
		// the user.
		newKs.duress = existing[0].duress
	}
	all := append(existing, newKs)
	for _, k := range all {
		k.siblings = all
	}
	return all, nil
}

// RemoveIdentity removes the username identity from the list and
// relinks the remaining siblings (Save() on any of them will rewrite
// just the updated list). Refuses to empty a file's last identity — a
// keystore must always contain at least one — and to remove a username
// that doesn't exist in the list.
func RemoveIdentity(list []*Keystore, username string) ([]*Keystore, error) {
	if len(list) <= 1 {
		return nil, errors.New(i18n.T("keystore.err_cannot_remove_last_identity"))
	}
	idx := -1
	for i, k := range list {
		if k.Username == username {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, errors.New(i18n.T("keystore.err_identity_not_found", username))
	}
	remaining := append(append([]*Keystore{}, list[:idx]...), list[idx+1:]...)
	for _, k := range remaining {
		k.siblings = remaining
	}
	return remaining, nil
}

// Save encrypts the keystore (the whole list of linked identities, if
// any — see LoadAll/AddIdentity — otherwise just the current identity)
// and writes it to disk atomically. The snapshot and the write happen
// under ks.mu, so concurrent saves never interleave and the file always
// ends up holding the latest one; the key derivation, independent of
// the content, runs before taking it.
func (ks *Keystore) Save(path, password string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return errors.New(i18n.T("keystore.err_salt", err))
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return errors.New(i18n.T("keystore.err_nonce", err))
	}
	key := deriveKey([]byte(password), salt)

	ks.mu.Lock()
	defer ks.mu.Unlock()
	list := ks.siblings
	if list == nil {
		list = []*Keystore{ks}
	}
	for _, k := range list {
		k.ensureRelRevocations()
	}
	plain, err := json.Marshal(list)
	if err != nil {
		return errors.New(i18n.T("keystore.err_marshal", err))
	}

	ciphertext, err := aesgcmEncrypt(key, nonce, plain)
	if err != nil {
		return errors.New(i18n.T("keystore.err_encrypt", err))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New(i18n.T("keystore.err_create_dir", err))
	}

	// atomic write: temp file in the same directory, then rename
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keystore-*.tmp")
	if err != nil {
		return errors.New(i18n.T("keystore.err_tmp_file", err))
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath) // no-op if the rename succeeded
	}()

	if err := tmp.Chmod(0600); err != nil {
		return errors.New(i18n.T("keystore.err_chmod", err))
	}
	if _, err := tmp.Write(writeDuressHeader(ks.duress)); err != nil {
		return err
	}
	if _, err := tmp.Write(salt); err != nil {
		return err
	}
	if _, err := tmp.Write(nonce); err != nil {
		return err
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return errors.New(i18n.T("keystore.err_fsync", err))
	}
	tmp.Close()

	return os.Rename(tmpPath, path)
}

// AddContact adds or updates a contact in the keystore. Deduplication
// by IdentityPub — a contact's real unique identity, never by Username:
// two contacts can legitimately share the same self-declared username
// (e.g. a contact did a nuke and reappeared with a new identity under
// the same name they chose — there can be countless contacts sharing a
// display name in the address book, each with a different URI, and the
// check must be on that, not on the name) — the same convention used by
// MergeContacts (contact-list sync).
func (ks *Keystore) AddContact(c Contact) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, existing := range ks.Contacts {
		if bytes.Equal(existing.IdentityPub, c.IdentityPub) {
			ks.Contacts[i] = c
			return
		}
	}
	ks.Contacts = append(ks.Contacts, c)
}

// ContactsSnapshot returns a copy of Contacts, safe to iterate over
// without holding any lock — for every caller not already guaranteed
// to run in mutual exclusion with AddContact/DeleteContactByPub (e.g.
// event-driven probe/rotation on a network goroutine, or a UI building
// a list while a network goroutine mutates the contact list in
// parallel), instead of iterating ks.Contacts directly. The fields'
// individual []byte values aren't duplicated: a caller must never write
// into one in place — changes go through
// UpdateContactByPub/SetContactDevice/AddContact.
func (ks *Keystore) ContactsSnapshot() []Contact {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([]Contact, len(ks.Contacts))
	copy(out, ks.Contacts)
	// Devices is a map (a reference type): the copy() above duplicates
	// only the Contact struct, not the map itself — without this, every
	// *DeviceRelation would stay the SAME live keystore object, mutable
	// by callers outside ks.mu. See Contact.CloneDevices.
	for i := range out {
		out[i].Devices = out[i].CloneDevices()
	}
	return out
}

// ContactIdentityPubs returns the Ed25519 pubkeys of every known
// contact — used by the "knock mutuality" getter (knownContactPubsFn,
// passed to server.RunOnListener) invoked by an HTTP goroutine for
// every incoming knock, instead of iterating ks.Contacts directly, which
// would race with AddContact/DeleteContactByPub.
func (ks *Keystore) ContactIdentityPubs() [][]byte {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([][]byte, len(ks.Contacts))
	for i, c := range ks.Contacts {
		out[i] = c.IdentityPub
	}
	return out
}

// AppendKnownDevice registers or updates (by DeviceID) a device known
// to also host this identity — learned through "indoor" sync or
// inserted manually. A later sync overwrites the record entirely
// (DevicePub/Label/SiblingIdentities may have changed meanwhile), never
// a simple field-by-field merge. A no-op if rec.DeviceID is this same
// device's own: a device never lists itself among its own KnownDevices.
func (ks *Keystore) AppendKnownDevice(rec DeviceRecord) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.appendKnownDeviceLocked(rec)
}

func (ks *Keystore) appendKnownDeviceLocked(rec DeviceRecord) {
	if bytes.Equal(rec.DeviceID, ks.DeviceID) {
		return
	}
	for i, d := range ks.KnownDevices {
		if bytes.Equal(d.DeviceID, rec.DeviceID) {
			ks.KnownDevices[i] = rec
			return
		}
	}
	ks.KnownDevices = append(ks.KnownDevices, rec)
}

// KnownDevicesSnapshot returns a copy of KnownDevices, safe to read
// while a sync updates the list.
func (ks *Keystore) KnownDevicesSnapshot() []DeviceRecord {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([]DeviceRecord, len(ks.KnownDevices))
	for i, d := range ks.KnownDevices {
		d.DeviceID = append([]byte(nil), d.DeviceID...)
		d.DevicePub = append([]byte(nil), d.DevicePub...)
		d.SiblingIdentities = append([]IdentityRef(nil), d.SiblingIdentities...)
		out[i] = d
	}
	return out
}

// MergeKnownDevices applies AppendKnownDevice to every entry in
// incoming — used to adopt a sibling's own KnownDevices list wholesale
// at sync time, so knowledge of a sibling spreads transitively: if peer
// C already knows sibling B, syncing with C also makes B known here,
// even without ever syncing with B directly. Returns how many entries
// were brand new (added), as opposed to updates of an already-known
// device — ignores any entry for this same device's own DeviceID (see
// AppendKnownDevice).
func (ks *Keystore) MergeKnownDevices(incoming []DeviceRecord) (added int) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, rec := range incoming {
		if bytes.Equal(rec.DeviceID, ks.DeviceID) {
			continue
		}
		isNew := true
		for _, d := range ks.KnownDevices {
			if bytes.Equal(d.DeviceID, rec.DeviceID) {
				isNew = false
				break
			}
		}
		ks.appendKnownDeviceLocked(rec)
		if isNew {
			added++
		}
	}
	return added
}

// IsDeviceNuked reports whether devicePub (a Keystore.DevicePub, not a
// DeviceID) is already known to belong to a nuked sibling.
func (ks *Keystore) IsDeviceNuked(devicePub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.isDeviceNukedLocked(devicePub)
}

func (ks *Keystore) isDeviceNukedLocked(devicePub []byte) bool {
	for _, p := range ks.NukedDevicePubs {
		if bytes.Equal(p, devicePub) {
			return true
		}
	}
	return false
}

// MarkDeviceNuked records devicePub as nuked — idempotent, grows-only
// (never pruned: an unknown-at-the-time sibling could still surface
// later holding a stale SiblingRevocations entry toward it, same
// permanence principle as Keystore.DeletedContacts).
func (ks *Keystore) MarkDeviceNuked(devicePub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.markDeviceNukedLocked(devicePub)
}

func (ks *Keystore) markDeviceNukedLocked(devicePub []byte) bool {
	if len(devicePub) == 0 || ks.isDeviceNukedLocked(devicePub) {
		return false
	}
	ks.NukedDevicePubs = append(ks.NukedDevicePubs, append([]byte(nil), devicePub...))
	return true
}

// MergeNukedDevicePubs unions incoming into NukedDevicePubs — same
// transitive-gossip semantics as MergeKnownDevices: once any sibling
// learns a device was nuked, that knowledge spreads to every sibling it
// syncs with, not only the one that originated it.
func (ks *Keystore) MergeNukedDevicePubs(incoming [][]byte) (added int) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, p := range incoming {
		if ks.markDeviceNukedLocked(p) {
			added++
		}
	}
	return added
}

// NukedDevicePubsSnapshot returns a copy of NukedDevicePubs.
func (ks *Keystore) NukedDevicePubsSnapshot() [][]byte {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([][]byte, len(ks.NukedDevicePubs))
	for i, p := range ks.NukedDevicePubs {
		out[i] = append([]byte(nil), p...)
	}
	return out
}

// AddPendingRemoteNuke registers targetDeviceID as a not-yet-confirmed
// remote_nuke command — a no-op if already present (a repeated request
// before an ack arrives doesn't reset RequestedAt, it stays that of the
// first attempt). The caller calls Save() afterward.
func (ks *Keystore) AddPendingRemoteNuke(targetDeviceID []byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, p := range ks.PendingRemoteNukes {
		if bytes.Equal(p.TargetDeviceID, targetDeviceID) {
			return
		}
	}
	ks.PendingRemoteNukes = append(ks.PendingRemoteNukes, PendingRemoteNuke{
		TargetDeviceID: append([]byte(nil), targetDeviceID...),
		RequestedAt:    time.Now(),
	})
}

// RemovePendingRemoteNuke removes targetDeviceID from the queue (called
// on the first remote_nuke_ack received for that device) — returns true
// if there really was an entry to remove, so the caller knows whether a
// save is needed.
func (ks *Keystore) RemovePendingRemoteNuke(targetDeviceID []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, p := range ks.PendingRemoteNukes {
		if bytes.Equal(p.TargetDeviceID, targetDeviceID) {
			ks.PendingRemoteNukes = slices.Delete(slices.Clone(ks.PendingRemoteNukes), i, i+1)
			return true
		}
	}
	return false
}

// PendingRemoteNukeTargets resolves every PendingRemoteNukes.TargetDeviceID
// against KnownDevices, returning the complete DeviceRecord (with
// SiblingIdentities) needed to redo the fan-out on every startup — a
// TargetDeviceID with no matching entry in KnownDevices anymore (should
// never happen: KnownDevices is never pruned) is silently dropped,
// there's no way to redirect it without knowing where.
func (ks *Keystore) PendingRemoteNukeTargets() []DeviceRecord {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([]DeviceRecord, 0, len(ks.PendingRemoteNukes))
	for _, p := range ks.PendingRemoteNukes {
		for _, d := range ks.KnownDevices {
			if bytes.Equal(d.DeviceID, p.TargetDeviceID) {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

// SetDangerBroadcastPending registers the contacts with identity keys pubs as not yet
// confirmed for the danger_broadcast related to targetDeviceID — called
// once, when the remote_nuke command is issued (cmdRemoteNuke).
// Overwrites any preexisting entry for the same targetDeviceID. The
// caller calls Save() afterward.
func (ks *Keystore) SetDangerBroadcastPending(targetDeviceID []byte, pubs [][]byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.PendingDangerBroadcasts = setDangerPending(ks.PendingDangerBroadcasts, targetDeviceID, pubs)
}

// ConfirmDangerBroadcast removes the contact with identity key pub from targetDeviceID's
// unconfirmed list (called on receiving a danger_broadcast_ack) — if
// the list becomes empty, the whole entry is removed. Returns true if
// something changed, so the caller knows whether a save is needed.
func (ks *Keystore) ConfirmDangerBroadcast(targetDeviceID, pub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var changed bool
	ks.PendingDangerBroadcasts, changed = confirmDangerPending(ks.PendingDangerBroadcasts, targetDeviceID, pub)
	return changed
}

// SetDangerEndPending registers the contacts with identity keys pubs as not yet confirmed
// for the danger_end related to targetDeviceID — same scheme as
// SetDangerBroadcastPending, a separate queue. The caller calls Save()
// afterward.
func (ks *Keystore) SetDangerEndPending(targetDeviceID []byte, pubs [][]byte) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.PendingDangerEnds = setDangerPending(ks.PendingDangerEnds, targetDeviceID, pubs)
}

// ConfirmDangerEnd removes the contact with identity key pub from targetDeviceID's unconfirmed
// list (called on receiving a danger_end_ack) — same scheme as
// ConfirmDangerBroadcast, a separate queue.
func (ks *Keystore) ConfirmDangerEnd(targetDeviceID, pub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var changed bool
	ks.PendingDangerEnds, changed = confirmDangerPending(ks.PendingDangerEnds, targetDeviceID, pub)
	return changed
}

// DangerPendingSnapshot returns copies of PendingDangerBroadcasts and
// PendingDangerEnds.
func (ks *Keystore) DangerPendingSnapshot() (broadcasts, ends []DangerBroadcastPending) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return cloneDangerPending(ks.PendingDangerBroadcasts), cloneDangerPending(ks.PendingDangerEnds)
}

// setDangerPending returns queue with targetDeviceID's entry set to
// pubs, added if missing. Entries are never modified in place: a
// copy handed out earlier keeps its content.
func setDangerPending(queue []DangerBroadcastPending, targetDeviceID []byte, pubs [][]byte) []DangerBroadcastPending {
	out := cloneDangerPending(queue)
	for i, p := range out {
		if bytes.Equal(p.TargetDeviceID, targetDeviceID) {
			out[i].IdentityPubs = clonePubs(pubs)
			return out
		}
	}
	return append(out, DangerBroadcastPending{
		TargetDeviceID: append([]byte(nil), targetDeviceID...),
		IdentityPubs:   clonePubs(pubs),
	})
}

// confirmDangerPending returns queue without pub in
// targetDeviceID's entry, dropping the entry once empty, and whether
// anything changed.
func confirmDangerPending(queue []DangerBroadcastPending, targetDeviceID, pub []byte) ([]DangerBroadcastPending, bool) {
	for i, p := range queue {
		if !bytes.Equal(p.TargetDeviceID, targetDeviceID) {
			continue
		}
		j := slices.IndexFunc(p.IdentityPubs, func(q []byte) bool { return bytes.Equal(q, pub) })
		if j < 0 {
			return queue, false
		}
		out := cloneDangerPending(queue)
		out[i].IdentityPubs = slices.Delete(out[i].IdentityPubs, j, j+1)
		if len(out[i].IdentityPubs) == 0 {
			out = slices.Delete(out, i, i+1)
		}
		return out, true
	}
	return queue, false
}

func cloneDangerPending(queue []DangerBroadcastPending) []DangerBroadcastPending {
	if queue == nil {
		return nil
	}
	out := make([]DangerBroadcastPending, len(queue))
	for i, p := range queue {
		out[i] = DangerBroadcastPending{
			TargetDeviceID: append([]byte(nil), p.TargetDeviceID...),
			IdentityPubs:   clonePubs(p.IdentityPubs),
		}
	}
	return out
}

// clonePubs deep-copies a list of identity keys.
func clonePubs(pubs [][]byte) [][]byte {
	if pubs == nil {
		return nil
	}
	out := make([][]byte, len(pubs))
	for i, p := range pubs {
		out[i] = append([]byte(nil), p...)
	}
	return out
}

// UpdateContactsLastAck updates in bulk the last-ack timestamp for the
// given contacts — map keys are string(IdentityPub), not Username (two
// contacts can share the same Username, never the same IdentityPub).
// Meant to be called once per probe cycle (not per single ack): Save()
// rederives the key with Argon2id on every call, expensive by design,
// so the caller accumulates acks in memory and passes them here in a
// single batch. Returns true if at least one contact was updated (the
// caller saves only in that case).
func (ks *Keystore) UpdateContactsLastAck(acks map[string]time.Time) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	changed := false
	for i := range ks.Contacts {
		if t, ok := acks[string(ks.Contacts[i].IdentityPub)]; ok {
			ks.Contacts[i].LastAckAt = t
			changed = true
		}
	}
	return changed
}

// UpdateContactsLastSeen updates in bulk the last-time-reached-over-TCP
// timestamp from a probe cycle (a weaker signal than LastAckAt: it only
// proves the onion address responds, not an authenticated round-trip) —
// map keys are string(IdentityPub), same reason as UpdateContactsLastAck
// above. Same batching reason: a single Save() per cycle, not one per
// reached contact.
func (ks *Keystore) UpdateContactsLastSeen(seen map[string]time.Time) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	changed := false
	for i := range ks.Contacts {
		if t, ok := seen[string(ks.Contacts[i].IdentityPub)]; ok {
			ks.Contacts[i].LastSeenAt = t
			changed = true
		}
	}
	return changed
}

// GetContactByPub returns a copy of the contact with this exact
// IdentityPub — UNIQUE by construction (see AddContact): a contact is
// identified by its identity key, never by its self-declared username,
// which several contacts can share. The copy (Devices included, see
// CloneDevices) never aliases the keystore: a change must go through
// UpdateContactByPub or AddContact.
func (ks *Keystore) GetContactByPub(pub []byte) (Contact, bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i := range ks.Contacts {
		if bytes.Equal(ks.Contacts[i].IdentityPub, pub) {
			c := ks.Contacts[i]
			c.Devices = c.CloneDevices()
			return c, true
		}
	}
	return Contact{}, false
}

// UpdateContactByPub runs fn on the live contact with this exact
// IdentityPub, under ks.mu — the only way to change a contact's fields
// (or its Devices) in place without racing a concurrent save, read or
// other update. fn must not call any other Keystore method (ks.mu is not
// reentrant) and must not retain c beyond its own call. Returns false,
// without calling fn, if no such contact exists.
func (ks *Keystore) UpdateContactByPub(pub []byte, fn func(c *Contact)) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i := range ks.Contacts {
		if bytes.Equal(ks.Contacts[i].IdentityPub, pub) {
			fn(&ks.Contacts[i])
			return true
		}
	}
	return false
}

// SetContactDevice writes dev as the Devices entry devKey of the contact
// with this exact IdentityPub, under ks.mu — the commit step for a
// caller that worked on a copy of one device (GetContactByPub): the
// contact's other fields and devices stay as they are now, never
// overwritten with the copy's older values. dropPlaceholder also
// removes the "" placeholder entry, when dev is that placeholder
// promoted to devKey. Returns false if no such contact exists.
func (ks *Keystore) SetContactDevice(pub []byte, devKey string, dev DeviceRelation, dropPlaceholder bool) bool {
	return ks.UpdateContactByPub(pub, func(c *Contact) {
		if c.Devices == nil {
			c.Devices = map[string]*DeviceRelation{}
		}
		if dropPlaceholder {
			delete(c.Devices, "")
		}
		c.Devices[devKey] = &dev
	})
}

// relBundleEdLen/relBundleMLKEMLen/relBundleMLDSALen are the fixed
// (never variable) lengths of the three secrets packed together in
// OldRelIdentityPriv/OldRelContentPriv (a single vault instead of three)
// — Ed25519 priv (64), ML-KEM-768 "d||z" seed (64), ML-DSA-65 seed (32).
const (
	relBundleEdLen    = ed25519.PrivateKeySize
	relBundleMLKEMLen = 64
	relBundleMLDSALen = 32
)

func packRelBundle(edPriv, mlkemSeed, mldsaSeed []byte) []byte {
	out := make([]byte, 0, relBundleEdLen+relBundleMLKEMLen+relBundleMLDSALen)
	out = append(out, edPriv...)
	out = append(out, mlkemSeed...)
	out = append(out, mldsaSeed...)
	return out
}

// genRelKeyMaterial generates a new Ed25519 pair + its two PQC
// companions (ML-KEM-768, ML-DSA-65) — the same trio generated together
// for every relationship key (IdentityKey-per-contact or
// ContentKey-per-contact).
func genRelKeyMaterial() (edPriv, mlkemSeed, mldsaSeed []byte, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, errors.New(i18n.T("keystore.err_gen_new_key", err))
	}
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, nil, errors.New(i18n.T("keystore.err_gen_mlkem_key", err))
	}
	seed := make([]byte, mldsa65.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, nil, errors.New(i18n.T("keystore.err_gen_mldsa_key", err))
	}
	return []byte(priv), mlkemDK.Bytes(), seed, nil
}

// findContactIdxByPubLocked assumes ks.mu is already held — used for
// the automatic/knock-driven case (never a command typed by the user)
// where the contact's real IdentityPub is already known in the call's
// context (see GetContactByPub).
func (ks *Keystore) findContactIdxByPubLocked(pub []byte) int {
	for i := range ks.Contacts {
		if bytes.Equal(ks.Contacts[i].IdentityPub, pub) {
			return i
		}
	}
	return -1
}

// StartRelIdentityRotationByPub starts rotation of the
// IdentityKey-per-relationship (+ PQC companions) toward EVERY ready
// device of a contact (Contact.ReadyDevices) — an independent secret
// generated for each, never a guessed choice on just ONE (no UI to
// choose which device to rotate). A device whose ContentKey is already
// rotating is silently skipped (never two keys in flight at once on the
// same relationship, otherwise neither would remain as the continuity
// anchor for the other), without blocking rotation of the OTHER
// devices. With exactly one ready device (the common case) the error
// names that device's specific cause; with 2+ devices and a mixed
// state, it fails only if NONE could be started. Returns the keys
// (DevicePub) actually put into rotation. Never ambiguous: searches by
// IdentityPub, never by username (acceptable only after a picker has
// already disambiguated any namesakes — see
// cmdStartRelRotation, tui.go).
func (ks *Keystore) StartRelIdentityRotationByPub(pub []byte) ([]string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return nil, errors.New(i18n.T("keystore.err_contact_not_found", fmt.Sprintf("%x", pub)))
	}
	c := &ks.Contacts[i]
	ready := c.ReadyDevices()
	if len(ready) == 0 {
		return nil, errors.New(i18n.T("keystore.err_rel_rotation_ambiguous_device"))
	}
	keys := sortedDeviceKeys(ready)
	if len(keys) == 1 {
		dev := ready[keys[0]]
		if dev.ContentKeyPending {
			return nil, errors.New(i18n.T("keystore.err_rel_rotation_other_pending"))
		}
		if dev.IdentityKeyPending {
			return nil, errors.New(i18n.T("keystore.err_rel_rotation_already_pending"))
		}
	}
	var rotated []string
	for _, key := range keys {
		dev := ready[key]
		if dev.ContentKeyPending || dev.IdentityKeyPending {
			continue
		}
		edPriv, mlkemSeed, mldsaSeed, err := genRelKeyMaterial()
		if err != nil {
			continue
		}
		dev.OldRelIdentityPriv = newVaultBytes(packRelBundle(dev.RelIdentityPriv, dev.RelIdentityMLKEMPriv, dev.RelIdentityMLDSAPriv))
		dev.RelIdentityPriv = edPriv
		dev.RelIdentityMLKEMPriv = mlkemSeed
		dev.RelIdentityMLDSAPriv = mldsaSeed
		dev.RevokeIdentitySig = nil
		dev.RevokeIdentitySigMLDSA = nil
		dev.IdentityKeyPending = true
		rotated = append(rotated, key)
	}
	if len(rotated) == 0 {
		return nil, errors.New(i18n.T("keystore.err_rel_rotation_already_pending"))
	}
	return rotated, nil
}

// StartRelContentRotationByPub is the counterpart of
// StartRelIdentityRotationByPub for the ContentKey-per-relationship —
// the same fan-out over every ready device, the same mutual guard per
// device.
func (ks *Keystore) StartRelContentRotationByPub(pub []byte) ([]string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return nil, errors.New(i18n.T("keystore.err_contact_not_found", fmt.Sprintf("%x", pub)))
	}
	c := &ks.Contacts[i]
	ready := c.ReadyDevices()
	if len(ready) == 0 {
		return nil, errors.New(i18n.T("keystore.err_rel_rotation_ambiguous_device"))
	}
	keys := sortedDeviceKeys(ready)
	if len(keys) == 1 {
		dev := ready[keys[0]]
		if dev.IdentityKeyPending {
			return nil, errors.New(i18n.T("keystore.err_rel_rotation_other_pending"))
		}
		if dev.ContentKeyPending {
			return nil, errors.New(i18n.T("keystore.err_rel_rotation_already_pending"))
		}
	}
	var rotated []string
	for _, key := range keys {
		dev := ready[key]
		if dev.IdentityKeyPending || dev.ContentKeyPending {
			continue
		}
		edPriv, mlkemSeed, mldsaSeed, err := genRelKeyMaterial()
		if err != nil {
			continue
		}
		dev.OldRelContentPriv = newVaultBytes(packRelBundle(dev.RelContentPriv, dev.RelContentMLKEMPriv, dev.RelContentMLDSAPriv))
		dev.RelContentPriv = edPriv
		dev.RelContentMLKEMPriv = mlkemSeed
		dev.RelContentMLDSAPriv = mldsaSeed
		dev.RevokeContentSig = nil
		dev.RevokeContentSigMLDSA = nil
		dev.ContentKeyPending = true
		rotated = append(rotated, key)
	}
	if len(rotated) == 0 {
		return nil, errors.New(i18n.T("keystore.err_rel_rotation_already_pending"))
	}
	return rotated, nil
}

// MarkRelIdentityConfirmed closes the IdentityKey-per-relationship
// rotation for ONE device of a contact after its confirmation — clears
// the flag and the old key. devicePub identifies the exact device (the
// incoming ack's RelRotatePayload.DevicePub field, already available to
// the caller): with an empty or non-matching devicePub it falls back to
// Contact.SoleDevice() (a peer that doesn't send it). Returns false if
// no rotation was in progress
// for that device. Searches the contact by IdentityPub (never by
// username): triggered by an incoming "rel_identity_rotate_ack" —
// automatic, never a name typed with a picker available — must stay
// unique even with namesake contacts in the list.
func (ks *Keystore) MarkRelIdentityConfirmed(pub, devicePub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return false
	}
	dev, ok := ks.Contacts[i].DeviceByPub(devicePub)
	if !ok {
		dev, ok = ks.Contacts[i].SoleDevice()
	}
	if !ok || !dev.IdentityKeyPending {
		return false
	}
	dev.IdentityKeyPending = false
	dev.OldRelIdentityPriv = vaultBytes{}
	return true
}

// MarkRelContentConfirmed is the counterpart of MarkRelIdentityConfirmed
// for the ContentKey-per-relationship — the same devicePub resolution
// with the same fallback.
func (ks *Keystore) MarkRelContentConfirmed(pub, devicePub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return false
	}
	dev, ok := ks.Contacts[i].DeviceByPub(devicePub)
	if !ok {
		dev, ok = ks.Contacts[i].SoleDevice()
	}
	if !ok || !dev.ContentKeyPending {
		return false
	}
	dev.ContentKeyPending = false
	dev.OldRelContentPriv = vaultBytes{}
	return true
}

// MarkDeviceRevoked applies a verified revocation (shared.VerifyRelRevoke,
// already checked by the caller — see applyRelRevoke) to ONE device of
// a contact — the same devicePub resolution and the same fallback as
// MarkRelIdentityConfirmed/MarkRelContentConfirmed above. revokeIdentity/
// revokeContent reflect which of the two certificates were present and
// valid in the received knock (RelRevokePayload.IdentitySig/ContentSig,
// never both absent in a valid announcement). Setting an already-true
// flag is a safe no-op (revocation is never regressive) — returns false
// only if the contact or device wasn't found, never for "already
// revoked".
func (ks *Keystore) MarkDeviceRevoked(pub, devicePub []byte, revokeIdentity, revokeContent bool) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return false
	}
	dev, ok := ks.Contacts[i].DeviceByPub(devicePub)
	if !ok {
		dev, ok = ks.Contacts[i].SoleDevice()
	}
	if !ok {
		return false
	}
	if revokeIdentity {
		dev.RevokedIdentity = true
	}
	if revokeContent {
		dev.RevokedContent = true
	}
	return true
}

// AckSiblingRevocation marks Acked=true on every entry of the
// Contact.SiblingRevocations pool referring to peerDevicePub, on
// receiving a "rel_revoke_ack" — best-effort: an ack doesn't carry the
// identity of the sibling that materially sent the revocation (only the
// REVOKED device, peerDevicePub), so it doesn't distinguish between
// different siblings with independent relationships toward the same
// contact device — harmless, Acked is only a retry optimization for the
// nuke sequence, never a security-relevant datum. Returns false only if
// the contact wasn't found or the pool had no relevant entry.
func (ks *Keystore) AckSiblingRevocation(pub, peerDevicePub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return false
	}
	found := false
	for _, sr := range ks.Contacts[i].SiblingRevocations {
		if sr != nil && bytes.Equal(sr.PeerDevicePub, peerDevicePub) {
			sr.Acked = true
			found = true
		}
	}
	return found
}

// ConfirmPendingRelKeys closes a relationship-key conflict (TrustDanger)
// on a contact's device that actually has a pending conflict, after an
// explicit out-of-band user confirmation (/sec-verify) — promotes
// PendingPeerRelIdentityPub/PendingPeerRelContentPub (+ PQC companions)
// to PeerRelIdentityPub/PeerRelContentPub, clears Verified (the
// previous trust applied to the old keys, it must be regained with a
// new safety number) and cleans up the Pending fields. IntroducedBy
// stays unchanged (a historical fact about how the contact was added,
// independent of the keys). Searches the contact by IdentityPub, never
// by username, for the same reason as MarkRelIdentityConfirmed above;
// the device is resolved with Contact.DeviceWithPendingRelKeys() — never
// an arbitrary choice: if more than one device has a simultaneous
// pending conflict (a rare case, no UI to choose which), it stays on
// the first in deterministic order.
// Returns false if there was no pending conflict on any device.
func (ks *Keystore) ConfirmPendingRelKeys(pub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	i := ks.findContactIdxByPubLocked(pub)
	if i < 0 {
		return false
	}
	c := &ks.Contacts[i]
	_, dev, ok := c.DeviceWithPendingRelKeys()
	if !ok {
		return false
	}
	if len(dev.PendingPeerRelIdentityPub) == 0 && len(dev.PendingPeerRelContentPub) == 0 {
		return false
	}
	if len(dev.PendingPeerRelIdentityPub) > 0 {
		dev.PeerRelIdentityPub = dev.PendingPeerRelIdentityPub
		dev.PeerRelIdentityMLKEMPub = dev.PendingPeerRelIdentityMLKEMPub
		dev.PeerRelIdentityMLDSAPub = dev.PendingPeerRelIdentityMLDSAPub
	}
	if len(dev.PendingPeerRelContentPub) > 0 {
		dev.PeerRelContentPub = dev.PendingPeerRelContentPub
		dev.PeerRelContentMLKEMPub = dev.PendingPeerRelContentMLKEMPub
		dev.PeerRelContentMLDSAPub = dev.PendingPeerRelContentMLDSAPub
	}
	dev.PendingPeerRelIdentityPub = nil
	dev.PendingPeerRelIdentityMLKEMPub = nil
	dev.PendingPeerRelIdentityMLDSAPub = nil
	dev.PendingPeerRelContentPub = nil
	dev.PendingPeerRelContentMLKEMPub = nil
	dev.PendingPeerRelContentMLDSAPub = nil
	c.Verified = false
	return true
}

// DeleteContactByPub removes the contact with the given IdentityPub —
// the key is a contact's only truly unique identifier.
func (ks *Keystore) DeleteContactByPub(pub []byte) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, c := range ks.Contacts {
		if bytes.Equal(c.IdentityPub, pub) {
			ks.Contacts = append(ks.Contacts[:i], ks.Contacts[i+1:]...)
			return true
		}
	}
	return false
}

// AddSavedGroup adds or updates a saved group (looked up by GroupID).
func (ks *Keystore) AddSavedGroup(g SavedGroup) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, existing := range ks.SavedGroups {
		if existing.GroupID == g.GroupID {
			ks.SavedGroups[i] = g
			return
		}
	}
	ks.SavedGroups = append(ks.SavedGroups, g)
}

// GetSavedGroup returns a copy of the saved group with this LocalName or
// GroupID (Members included): a change goes through AddSavedGroup.
func (ks *Keystore) GetSavedGroup(nameOrID string) (SavedGroup, bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, g := range ks.SavedGroups {
		if g.LocalName == nameOrID || g.GroupID == nameOrID {
			g.Members = slices.Clone(g.Members)
			return g, true
		}
	}
	return SavedGroup{}, false
}

// SavedGroupsSnapshot returns a copy of SavedGroups (each Members slice
// included), safe to iterate without holding any lock — same role as
// ContactsSnapshot for the saved groups.
func (ks *Keystore) SavedGroupsSnapshot() []SavedGroup {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([]SavedGroup, len(ks.SavedGroups))
	for i, g := range ks.SavedGroups {
		g.Members = slices.Clone(g.Members)
		out[i] = g
	}
	return out
}

// DeleteSavedGroup removes the saved group with the given LocalName or GroupID. Returns true if found.
func (ks *Keystore) DeleteSavedGroup(nameOrID string) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for i, g := range ks.SavedGroups {
		if g.LocalName == nameOrID || g.GroupID == nameOrID {
			ks.SavedGroups = append(ks.SavedGroups[:i], ks.SavedGroups[i+1:]...)
			return true
		}
	}
	return false
}

// ── crypto primitives ─────────────────────────────────────────────────────────

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLen)
}

func aesgcmEncrypt(key, nonce, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plain, nil), nil
}

func aesgcmDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DefaultPath returns the keystore's default path (~/.config/neutrino/keystore).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New(i18n.T("keystore.err_config_dir", err))
	}
	return filepath.Join(dir, "neutrino", "keystore"), nil
}
