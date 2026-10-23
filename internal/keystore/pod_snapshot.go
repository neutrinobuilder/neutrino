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
	"crypto/ed25519"

	"neutrino/internal/shared"
	"neutrino/internal/transport"
)

// PodRevokeTarget is one contact's device toward which the pod must
// deliver a pre-generated rel_revoke — everything needed to build and
// address that knock, nothing reusable to decrypt or impersonate
// anything: the signatures are already final (SignRelRevoke signs a
// fixed message, no timestamp, computed once at relationship-creation
// time — internal/shared/relrevoke.go).
//
// Siblings are deliberately NOT part of this snapshot: a real
// acknowledgement from a sibling would require
// decrypting its reply with the real identity's private key, which the
// pod never holds — that task belongs to the PARENT process instead
// (still holding the key at trigger time), reusing the already-existing
// device_sync/device_sync_ack mechanism. The pod's only job is the
// direct-to-contact revoke, always, fire-and-forget, never conditioned
// on any sibling outcome.
type PodRevokeTarget struct {
	Address            string `json:"address"`
	ContactIdentityPub []byte `json:"contact_identity_pub"`
	ContactMLKEMPub    []byte `json:"contact_mlkem_pub,omitempty"`
	DevicePub          []byte `json:"device_pub"`
	IdentitySig        []byte `json:"identity_sig,omitempty"`
	IdentitySigMLDSA   []byte `json:"identity_sig_mldsa,omitempty"`
	ContentSig         []byte `json:"content_sig,omitempty"`
	ContentSigMLDSA    []byte `json:"content_sig_mldsa,omitempty"`

	// DHTag is KnockDHTag(identityPriv, ContactIdentityPub) — the
	// plaintext filter the recipient's server checks BEFORE attempting
	// decryption (see internal/shared/crypto.go, handleKnock). Static-
	// static DH, no timestamp: fixed for the lifetime of this
	// relationship, so it's precomputed here by the parent (which still
	// holds identityPriv at snapshot-build time) rather than ever
	// handing that key to the pod. Without a valid tag the recipient's
	// server silently never attempts decryption — this field is not
	// optional.
	DHTag []byte `json:"dh_tag"`

	// FromUsername/FromIdentityPub identify the overwritten identity
	// itself (not the contact) — carried per-target rather than
	// factored out to the snapshot level because BuildPodSnapshot
	// aggregates possibly several identities being overwritten at once.
	FromUsername    string `json:"from_username"`
	FromIdentityPub []byte `json:"from_identity_pub"`
}

// PodSnapshot is everything the pod needs, assembled by the parent
// process while it still holds every key, passed to the spawned pod
// ONLY via stdin/pipe (never argv/env, which other processes can read).
// Deliberately contains no private key of any kind.
type PodSnapshot struct {
	// ProxyAddr is the parent's local proxy/bridge address to reach the
	// network in NetKind — Tor's SOCKS5 "host:port" (tornode.Node.SocksAddr)
	// for KindTor, i2pd's SAM bridge "host:port" (i2pnode.Node.SAMAddr)
	// for KindI2P. Empty = cold bootstrap (no live network inherited).
	ProxyAddr string         `json:"proxy_addr,omitempty"`
	NetKind   transport.Kind `json:"net_kind"`
	Targets   []PodRevokeTarget `json:"targets,omitempty"`
}

// BuildPodSnapshot assembles the pod's payload from every identity
// about to be overwritten (identities), resolving each contact's
// address via addressFromPub (the same address-derivation closure
// already used elsewhere, e.g. cmd/main.go's addressFromPub). Pure data
// assembly — no network call, no process spawned.
func BuildPodSnapshot(identities []*Keystore, addressFromPub func(pub []byte) string, proxyAddr string, netKind transport.Kind) PodSnapshot {
	snap := PodSnapshot{ProxyAddr: proxyAddr, NetKind: netKind}

	for _, ks := range identities {
		if ks == nil {
			continue
		}
		priv := ks.IdentityPrivKey()
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			continue
		}
		for _, c := range ks.Contacts {
			if len(c.IdentityPub) != 32 {
				continue
			}
			addr := addressFromPub(c.IdentityPub)
			if addr == "" {
				continue
			}
			tag, err := shared.KnockDHTag(priv, ed25519.PublicKey(c.IdentityPub))
			if err != nil {
				continue
			}
			for devicePubStr, dev := range c.Devices {
				if dev == nil {
					continue
				}
				if len(dev.RevokeIdentitySig) == 0 && len(dev.RevokeContentSig) == 0 {
					continue
				}
				snap.Targets = append(snap.Targets, PodRevokeTarget{
					Address:            addr,
					ContactIdentityPub: append([]byte(nil), c.IdentityPub...),
					ContactMLKEMPub:    append([]byte(nil), c.MLKEMPub...),
					DevicePub:          []byte(devicePubStr),
					IdentitySig:        dev.RevokeIdentitySig,
					IdentitySigMLDSA:   dev.RevokeIdentitySigMLDSA,
					ContentSig:         dev.RevokeContentSig,
					ContentSigMLDSA:    dev.RevokeContentSigMLDSA,
					DHTag:              tag,
					FromUsername:       ks.Username,
					FromIdentityPub:    append([]byte(nil), pub...),
				})
			}
		}
	}

	return snap
}
