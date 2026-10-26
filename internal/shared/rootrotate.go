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

// RootRotatePayload travels inside KnockPayload.RootRotate for the
// "root_rotate" knocks (request) and "root_rotate_ack" (confirmation).
// Unlike RelRotatePayload (a relationship key rotates, certified by the
// stable sibling), here it's the ROOT IdentityKey (from which the own
// network address is derived) that rotates, certified by the
// RelIdentityKey-per-contact. The knock itself is tagged (KnockDHTag) with
// the OLD root private key, retained temporarily
// (Keystore.OldIdentityKey): the recipient still recognizes it, because it
// has not yet applied the announcement, no change needed to the server-side
// mutuality filter.
type RootRotatePayload struct {
	NewIdentityPub ed25519.PublicKey `json:"new_identity_pub"`
	NewMLKEMPub    []byte            `json:"new_mlkem_pub,omitempty"`
	NewMLDSAPub    []byte            `json:"new_mldsa_pub,omitempty"`
	Sig            []byte            `json:"sig,omitempty"`
	SigMLDSA       []byte            `json:"sig_mldsa,omitempty"`

	// Ts, signing instant (RFC3339, shared.NowTS()), present ONLY in the
	// request, same reason/use as RelRotatePayload.Ts (RootRotationMsg
	// includes ts in the signed message, verified with TsFresh by the
	// receiver before applying).
	Ts string `json:"ts,omitempty"`

	// DevicePub, the sender's DEVICE-level key (Keystore.DevicePub), same
	// role as RelRotatePayload.DevicePub: keys the correct
	// keystore.Contact.Devices entry on the receiving side (the sender may
	// have multiple devices, each with an independent relationship toward
	// the same contact).
	DevicePub []byte `json:"device_pub,omitempty"`
}

// DeviceSyncPayload travels inside KnockPayload.DeviceSync for the
// "device_sync"/"device_sync_ack" knocks, a my-device→my-device channel,
// addressed via Keystore.NetworkIdentityPrivKeyFor(targetDeviceID) instead
// of through a contact (both sides share the same root
// IdentityKey, no ECDH needed, same principle already used by
// internal/indoor for LAN sync). Carries EXACTLY one of the following two
// things, never both:
//
//   - propagation of the NEW private material of an in-progress root
//     rotation (NewIdentityKey/NewMLKEMKey/NewMLDSAKey, the sibling
//     immediately adopts the new root and republishes its own hidden
//     service);
//   - a remote address-book sync (SyncData, JSON of indoor.SyncPayload,
//     the same payload already used by "indoor" LAN sync, here over a
//     different transport; package internal/shared does not import
//     internal/indoor to avoid an import cycle, the caller
//     marshals/unmarshals it).
//
// No signature of its own: the whole KnockPayload is already inside the
// knock's encrypted+tagged envelope (EncryptKnockWithTag), and the tag's own
// mutuality (computable only by whoever holds the root, old or new) is
// already the proof of authenticity, same principle already used for the
// self-probe knock.
type DeviceSyncPayload struct {
	NewIdentityKey []byte `json:"new_identity_key,omitempty"`
	NewMLKEMKey    []byte `json:"new_mlkem_key,omitempty"`
	NewMLDSAKey    []byte `json:"new_mldsa_key,omitempty"`
	SyncData       []byte `json:"sync_data,omitempty"`
}
