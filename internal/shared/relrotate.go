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

import "crypto/ed25519"

// RelRotatePayload travels inside KnockPayload.RelRotate for the
// "rel_identity_rotate"/"rel_content_rotate" knocks (request) and their
// "_ack" counterparts (confirmation). Unlike RelBootstrapPayload
// (bidirectional, both sides generate a pair), here only ONE of the two
// parties is rotating one of its two relationship keys toward the other:
// the payload always carries the public part of the NEW key, never the old
// one (which the other side already knows).
//
// Sig/SigMLDSA certify NewPub with the SIBLING relationship key, which stays
// stable (ContentKey-per-relationship if the IdentityKey is rotating, and
// vice versa) — NEVER with the previous version of the same key being
// rotated: one rotation at a time per relationship (never identity and
// content together) always leaves the sibling as the continuity anchor for
// the other. Populated only in the request: an ack merely echoes NewPub (the
// sender compares it against the key currently being rotated before
// accepting it as confirmation — see applyRelRotate — so a late ack
// referring to a rotation already forced/closed is never applied to a
// subsequent rotation); Sig/SigMLDSA stay empty in that direction — an ack
// certifies nothing new, it only confirms receipt.
type RelRotatePayload struct {
	NewPub      ed25519.PublicKey `json:"new_pub"`
	NewMLKEMPub []byte            `json:"new_mlkem_pub,omitempty"`
	NewMLDSAPub []byte            `json:"new_mldsa_pub,omitempty"`
	Sig         []byte            `json:"sig,omitempty"`
	SigMLDSA    []byte            `json:"sig_mldsa,omitempty"`

	// Ts — signing instant (RFC3339, shared.NowTS()), present ONLY in the
	// request (never in the ack, which carries no signature). Included in
	// the SIGNED message (RelKeyRotationMsg), not just in the payload:
	// verified with shared.TsFresh by the receiver BEFORE applying the
	// rotation, against an old rotation message captured and replayed
	// later — without this check, a silent downgrade to a previous version
	// of the key being rotated would be possible as long as the signing
	// sibling key never changes. The sender re-signs with a fresh ts on
	// every single attempt/retry (never a ts fixed once at the start of the
	// rotation), so the probe cycle's periodic retry always stays valid.
	Ts string `json:"ts,omitempty"`

	// DevicePub — same meaning and reason as RelBootstrapPayload.DevicePub
	// (relbootstrap.go): keys the correct keystore.Contact.Devices entry on
	// the receiving side.
	DevicePub []byte `json:"device_pub,omitempty"`
}
