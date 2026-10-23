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

package keystore_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"neutrino/internal/keystore"
	"neutrino/internal/shared"
)

// contactNamed returns the only contact named username — test-only
// helper: production code identifies contacts by identity key.
func contactNamed(ks *keystore.Keystore, username string) (keystore.Contact, bool) {
	for _, c := range ks.ContactsSnapshot() {
		if c.Username == username {
			return c, true
		}
	}
	return keystore.Contact{}, false
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")
	password := "a-very-long-test-password"

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	idPub1 := make([]byte, 32)
	rand.Read(idPub1)
	idPub2 := make([]byte, 32)
	rand.Read(idPub2)

	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: idPub1})
	ks.AddContact(keystore.Contact{Username: "carol", IdentityPub: idPub2})

	if err := ks.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// the file must have 0600 permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("want permissions 0600, got %o", info.Mode().Perm())
	}

	ks2, err := keystore.Load(path, password)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if ks2.Username != "alice" {
		t.Errorf("Username: want alice, got %s", ks2.Username)
	}
	if len(ks2.Contacts) != 2 {
		t.Fatalf("Contacts: want 2, got %d", len(ks2.Contacts))
	}
	bob, ok := contactNamed(ks2, "bob")
	if !ok {
		t.Fatal("contact bob not found")
	}
	if !bytes.Equal(bob.IdentityPub, idPub1) {
		t.Error("bob's identity_pub doesn't match")
	}
}

func TestWrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ks.Save(path, "correct-password"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err = keystore.Load(path, "wrong-password")
	if err == nil {
		t.Fatal("want an error with a wrong password, got none")
	}
}

// TestAddContactUpdate verifies that AddContact deduplicates by
// IdentityPub (the real unique identity), not by Username — same
// username, same IdentityPub is an update (e.g. LocalName changed);
// same IdentityPub with any other field different is still an update of
// the same contact.
func TestAddContactUpdate(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub1 := bytes.Repeat([]byte{0x01}, 32)

	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub1})
	ks.AddContact(keystore.Contact{Username: "bob", LocalName: "Bobby", IdentityPub: pub1}) // update, same IdentityPub

	bob, ok := contactNamed(ks, "bob")
	if !ok {
		t.Fatal("contact bob not found")
	}
	if bob.LocalName != "Bobby" {
		t.Error("AddContact didn't update the existing contact (same IdentityPub)")
	}
	if len(ks.Contacts) != 1 {
		t.Errorf("want 1 contact, found %d", len(ks.Contacts))
	}
}

// TestAddContactSameUsernameDifferentPubCoexist verifies a real case: a
// contact does a nuke and reappears with a new identity under the SAME
// self-declared username — it must not be treated as an update of the
// old contact (it would lose its real identity), the two must coexist,
// distinguished by their real IdentityPub (the real unique identity,
// never the name — see AddContact).
func TestAddContactSameUsernameDifferentPubCoexist(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pubOld := bytes.Repeat([]byte{0x01}, 32)
	pubNew := bytes.Repeat([]byte{0x02}, 32)

	ks.AddContact(keystore.Contact{Username: "G1", IdentityPub: pubOld})
	ks.AddContact(keystore.Contact{Username: "G1", IdentityPub: pubNew})

	if len(ks.Contacts) != 2 {
		t.Fatalf("want 2 distinct homonymous contacts, found %d", len(ks.Contacts))
	}
	oldC, ok := ks.GetContactByPub(pubOld)
	if !ok || !bytes.Equal(oldC.IdentityPub, pubOld) {
		t.Error("the old G1 (pubOld) disappeared or was corrupted")
	}
	newC, ok := ks.GetContactByPub(pubNew)
	if !ok || !bytes.Equal(newC.IdentityPub, pubNew) {
		t.Error("the new G1 (pubNew) was not added correctly")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "keystore") // sub directory doesn't exist yet

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ks.Save(path, "pwd"); err != nil {
		t.Fatalf("Save with a missing directory: %v", err)
	}
	if _, err := keystore.Load(path, "pwd"); err != nil {
		t.Fatalf("Load after Save with a missing directory: %v", err)
	}
}

// ── DeviceID / device key ───────────────────────────────────────────────────────

func TestNewGeneratesDeviceIdentity(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(ks.DeviceID) != 16 {
		t.Fatalf("DeviceID len = %d, want 16", len(ks.DeviceID))
	}
	if len(ks.DeviceIDHex()) != 32 {
		t.Fatalf("DeviceIDHex len = %d, want 32", len(ks.DeviceIDHex()))
	}
	priv := ks.DevicePrivKey()
	pub := ks.DevicePubKey()
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("DevicePrivKey len = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("DevicePubKey len = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("DevicePubKey doesn't match the pubkey derived from DevicePrivKey")
	}
}

// TestAddIdentitySharesDevice verifies the "one file = one device"
// principle: a second identity added to the same file always inherits
// DeviceID/DevicePriv/DevicePub from the first, discarding the ones
// New() generated on its own for the second identity.
func TestAddIdentitySharesDevice(t *testing.T) {
	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	if bytes.Equal(first.DeviceID, second.DeviceID) {
		t.Fatal("two independent New() generated the same DeviceID by pure chance (RNG suspect)")
	}

	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("AddIdentity: want 2 identities, found %d", len(all))
	}
	if !bytes.Equal(all[0].DeviceID, all[1].DeviceID) {
		t.Error("the two identities of the same file have different DeviceIDs")
	}
	if !bytes.Equal(all[0].DevicePriv, all[1].DevicePriv) {
		t.Error("the two identities of the same file have different DevicePrivs")
	}
	if !bytes.Equal(all[0].DevicePub, all[1].DevicePub) {
		t.Error("the two identities of the same file have different DevicePubs")
	}
}

// TestAddIdentityPreservesDuress verifies that AddIdentity copies the
// unexported duress field from existing[0] to newKs, so Save() called
// on the new identity (the exact real path of runAddIdentity,
// cmd/main.go) never rewrites the file with
// duress=nil, which would silently disable an already-configured
// automatic NUKE password. Verified end-to-end (not just HasDuress() in
// memory): SetDuress+Save on the first identity, then AddIdentity+Save
// on the NEW one — CheckDuress must still recognize the previously
// configured NUKE password.
func TestAddIdentityPreservesDuress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")
	password := "a-very-long-test-password"
	nukePassword := "a-very-different-nuke-password"

	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	if err := first.SetDuress(nukePassword); err != nil {
		t.Fatalf("SetDuress: %v", err)
	}
	if err := first.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	if !all[1].HasDuress() {
		t.Fatal("the new identity doesn't inherit the existing file's NUKE password")
	}
	// Save on the NEW identity — exactly the real path of
	// runAddIdentity (cmd/main.go).
	if err := all[1].Save(path, password); err != nil {
		t.Fatalf("Save (new identity): %v", err)
	}
	if !keystore.CheckDuress(path, nukePassword) {
		t.Fatal("after add-identity, the previously configured NUKE password is no longer recognized")
	}
}

// TestLoadAllBackfillsDeviceID: for a file with no DeviceID (format
// version 3), LoadAll must generate
// DeviceID/DevicePriv/DevicePub once and propagate them to every
// identity in the list, not just the first.
func TestLoadAllBackfillsDeviceID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")
	password := "a-very-long-test-password"

	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	// A file with no device assigned.
	first.DeviceID, first.DevicePriv, first.DevicePub = nil, nil, nil
	second.DeviceID, second.DevicePriv, second.DevicePub = nil, nil, nil

	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	if err := all[0].Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := keystore.LoadAll(path, password)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("LoadAll: want 2 identities, found %d", len(loaded))
	}
	for i, ks := range loaded {
		if len(ks.DeviceID) != 16 {
			t.Errorf("identity %d: DeviceID not backfilled, len = %d", i, len(ks.DeviceID))
		}
		if len(ks.DevicePrivKey()) != ed25519.PrivateKeySize {
			t.Errorf("identity %d: DevicePriv not backfilled", i)
		}
	}
	if !bytes.Equal(loaded[0].DeviceID, loaded[1].DeviceID) {
		t.Error("the backfill generated different DeviceIDs for the two identities of the same file")
	}

	// The critical point: the backfill must be written to disk
	// IMMEDIATELY, not left only in memory — a second LoadAll
	// (simulating an app restart) must find the SAME DeviceID, not
	// generate a new one. Without immediate persistence,
	// /sec-remote-nuke and /sec-indoor-sync would never converge on a
	// stable identifier for a keystore that had none.
	reloaded, err := keystore.LoadAll(path, password)
	if err != nil {
		t.Fatalf("second LoadAll: %v", err)
	}
	if !bytes.Equal(reloaded[0].DeviceID, loaded[0].DeviceID) {
		t.Fatal("the DeviceID generated by the backfill was not persisted: a second LoadAll (restart) generated a different one")
	}
	if !bytes.Equal(reloaded[0].DevicePriv, loaded[0].DevicePriv) {
		t.Error("DevicePriv not persisted by the backfill: a second LoadAll generated a different one")
	}
}

// ── KnownDevices / AllAuthorityPubKeys ───────────────────────────────────────────

func TestAppendKnownDeviceUpsert(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID := make([]byte, 16)
	rand.Read(devID)
	pub1 := make([]byte, 32)
	rand.Read(pub1)

	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: devID, DevicePub: pub1, Label: "first"})
	if len(ks.KnownDevices) != 1 {
		t.Fatalf("want 1 known device, found %d", len(ks.KnownDevices))
	}

	// Same DeviceID, updated data (e.g. after a new indoor sync): must
	// overwrite, not accumulate a second record.
	pub2 := make([]byte, 32)
	rand.Read(pub2)
	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: devID, DevicePub: pub2, Label: "updated"})
	if len(ks.KnownDevices) != 1 {
		t.Fatalf("want still 1 known device after the update, found %d", len(ks.KnownDevices))
	}
	if ks.KnownDevices[0].Label != "updated" || !bytes.Equal(ks.KnownDevices[0].DevicePub, pub2) {
		t.Error("AppendKnownDevice didn't overwrite the existing record for the same DeviceID")
	}
}

func TestAddPendingRemoteNukeIdempotent(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID := make([]byte, 16)
	rand.Read(devID)

	ks.AddPendingRemoteNuke(devID)
	if len(ks.PendingRemoteNukes) != 1 {
		t.Fatalf("want 1 pending nuke, found %d", len(ks.PendingRemoteNukes))
	}
	firstRequestedAt := ks.PendingRemoteNukes[0].RequestedAt

	// A second request for the same device, before an ack, is a no-op:
	// must not accumulate a second record nor update RequestedAt.
	ks.AddPendingRemoteNuke(devID)
	if len(ks.PendingRemoteNukes) != 1 {
		t.Fatalf("want still 1 pending nuke after the repeated request, found %d", len(ks.PendingRemoteNukes))
	}
	if !ks.PendingRemoteNukes[0].RequestedAt.Equal(firstRequestedAt) {
		t.Error("AddPendingRemoteNuke should not have updated RequestedAt on a repeated request")
	}
}

func TestRemovePendingRemoteNuke(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID1 := make([]byte, 16)
	rand.Read(devID1)
	devID2 := make([]byte, 16)
	rand.Read(devID2)

	ks.AddPendingRemoteNuke(devID1)
	ks.AddPendingRemoteNuke(devID2)

	if !ks.RemovePendingRemoteNuke(devID1) {
		t.Error("RemovePendingRemoteNuke should have returned true for a present device")
	}
	if len(ks.PendingRemoteNukes) != 1 || !bytes.Equal(ks.PendingRemoteNukes[0].TargetDeviceID, devID2) {
		t.Fatalf("want only devID2 left in the queue, found: %+v", ks.PendingRemoteNukes)
	}

	// Removing the same one again (already removed) or one that never
	// existed: false, no panic, no change.
	if ks.RemovePendingRemoteNuke(devID1) {
		t.Error("RemovePendingRemoteNuke should have returned false for an already-removed device")
	}
}

func TestPendingRemoteNukeTargetsResolvesAgainstKnownDevices(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID := make([]byte, 16)
	rand.Read(devID)
	pub := make([]byte, 32)
	rand.Read(pub)

	// Pending but not (yet) resolvable: no matching KnownDevices entry.
	unknownDevID := make([]byte, 16)
	rand.Read(unknownDevID)
	ks.AddPendingRemoteNuke(unknownDevID)
	if targets := ks.PendingRemoteNukeTargets(); len(targets) != 0 {
		t.Fatalf("want 0 targets resolved for an unknown device, found %d", len(targets))
	}

	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: devID, DevicePub: pub, Label: "laptop"})
	ks.AddPendingRemoteNuke(devID)

	targets := ks.PendingRemoteNukeTargets()
	if len(targets) != 1 {
		t.Fatalf("want 1 target resolved, found %d", len(targets))
	}
	if !bytes.Equal(targets[0].DeviceID, devID) || targets[0].Label != "laptop" {
		t.Errorf("unexpected resolved target: %+v", targets[0])
	}
}

func TestSetDangerBroadcastPendingAndConfirm(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID := make([]byte, 16)
	rand.Read(devID)

	ks.SetDangerBroadcastPending(devID, [][]byte{namePub("bob"), namePub("carol"), namePub("dave")})
	if len(ks.PendingDangerBroadcasts) != 1 || len(ks.PendingDangerBroadcasts[0].IdentityPubs) != 3 {
		t.Fatalf("unexpected state after SetDangerBroadcastPending: %+v", ks.PendingDangerBroadcasts)
	}

	if !ks.ConfirmDangerBroadcast(devID, namePub("carol")) {
		t.Error("ConfirmDangerBroadcast should have returned true for a present key")
	}
	if len(ks.PendingDangerBroadcasts[0].IdentityPubs) != 2 {
		t.Fatalf("want 2 keys left, found %d", len(ks.PendingDangerBroadcasts[0].IdentityPubs))
	}

	// A second ack for the same username (duplicate/late): false, no panic.
	if ks.ConfirmDangerBroadcast(devID, namePub("carol")) {
		t.Error("ConfirmDangerBroadcast should have returned false for an already-confirmed key")
	}

	// Emptying the list removes the whole entry, not just the usernames.
	ks.ConfirmDangerBroadcast(devID, namePub("bob"))
	ks.ConfirmDangerBroadcast(devID, namePub("dave"))
	if len(ks.PendingDangerBroadcasts) != 0 {
		t.Fatalf("want 0 pending entries after confirming all, found %d", len(ks.PendingDangerBroadcasts))
	}

	// An ack for a device that was never registered: false, no panic.
	unknownDevID := make([]byte, 16)
	rand.Read(unknownDevID)
	if ks.ConfirmDangerBroadcast(unknownDevID, namePub("bob")) {
		t.Error("ConfirmDangerBroadcast should have returned false for a never-registered device")
	}
}

func TestSetDangerBroadcastPendingOverwritesExisting(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID := make([]byte, 16)
	rand.Read(devID)

	ks.SetDangerBroadcastPending(devID, [][]byte{namePub("bob")})
	ks.SetDangerBroadcastPending(devID, [][]byte{namePub("carol"), namePub("dave")})

	if len(ks.PendingDangerBroadcasts) != 1 {
		t.Fatalf("want 1 entry (overwritten, not accumulated), found %d", len(ks.PendingDangerBroadcasts))
	}
	if len(ks.PendingDangerBroadcasts[0].IdentityPubs) != 2 {
		t.Fatalf("want 2 keys after the overwrite, found %d", len(ks.PendingDangerBroadcasts[0].IdentityPubs))
	}
}

func TestSetDangerEndPendingAndConfirm(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	devID := make([]byte, 16)
	rand.Read(devID)

	ks.SetDangerEndPending(devID, [][]byte{namePub("bob"), namePub("carol")})
	if len(ks.PendingDangerEnds) != 1 || len(ks.PendingDangerEnds[0].IdentityPubs) != 2 {
		t.Fatalf("unexpected state after SetDangerEndPending: %+v", ks.PendingDangerEnds)
	}

	if !ks.ConfirmDangerEnd(devID, namePub("bob")) {
		t.Error("ConfirmDangerEnd should have returned true for a present key")
	}
	if len(ks.PendingDangerEnds[0].IdentityPubs) != 1 || !bytes.Equal(ks.PendingDangerEnds[0].IdentityPubs[0], namePub("carol")) {
		t.Fatalf("want only 'carol' left, found: %+v", ks.PendingDangerEnds)
	}

	ks.ConfirmDangerEnd(devID, namePub("carol"))
	if len(ks.PendingDangerEnds) != 0 {
		t.Fatalf("want 0 pending entries after confirming all, found %d", len(ks.PendingDangerEnds))
	}

	// PendingDangerBroadcasts and PendingDangerEnds are independent
	// queues: confirming one must not touch the other.
	ks.SetDangerBroadcastPending(devID, [][]byte{namePub("dave")})
	ks.SetDangerEndPending(devID, [][]byte{namePub("dave")})
	ks.ConfirmDangerEnd(devID, namePub("dave"))
	if len(ks.PendingDangerEnds) != 0 {
		t.Error("ConfirmDangerEnd didn't empty its own queue")
	}
	if len(ks.PendingDangerBroadcasts) != 1 {
		t.Error("ConfirmDangerEnd must not touch PendingDangerBroadcasts")
	}
}

func TestSiblingKeystoresIncludesAllIdentities(t *testing.T) {
	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No sibling linked yet: returns itself.
	if sibs := first.SiblingKeystores(); len(sibs) != 1 || sibs[0] != first {
		t.Fatalf("want only itself without siblings, found: %+v", sibs)
	}

	second, err := keystore.New("bob")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	sibs := all[0].SiblingKeystores()
	if len(sibs) != 2 {
		t.Fatalf("want 2 sibling identities, found %d", len(sibs))
	}
	names := map[string]bool{}
	for _, s := range sibs {
		names[s.Username] = true
	}
	if !names["alice"] || !names["bob"] {
		t.Errorf("SiblingKeystores must include both identities: %v", names)
	}
}

func TestAllAuthorityPubKeysIncludesAllSiblings(t *testing.T) {
	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}

	keys := all[0].AllAuthorityPubKeys()
	if len(keys) != 2 {
		t.Fatalf("want 2 authority keys (one per identity), found %d", len(keys))
	}
	foundFirst, foundSecond := false, false
	for _, k := range keys {
		if bytes.Equal(k, all[0].IdentityPubKey()) {
			foundFirst = true
		}
		if bytes.Equal(k, all[1].IdentityPubKey()) {
			foundSecond = true
		}
	}
	if !foundFirst || !foundSecond {
		t.Error("AllAuthorityPubKeys must include the pubkey of EVERY identity in the file, not just the caller's")
	}
}

func TestSiblingIdentityRefsIncludesAllSiblings(t *testing.T) {
	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}

	refs := all[0].SiblingIdentityRefs()
	if len(refs) != 2 {
		t.Fatalf("want 2 IdentityRefs, found %d", len(refs))
	}
	names := map[string]bool{}
	for _, r := range refs {
		names[r.Username] = true
		if len(r.IdentityPub) != 32 {
			t.Errorf("IdentityRef %q: IdentityPub len = %d, want 32", r.Username, len(r.IdentityPub))
		}
	}
	if !names["alice"] || !names["alice1"] {
		t.Errorf("want usernames alice+alice1, found %v", names)
	}
}

// TestSetDeviceLabelPropagatesToSiblings covers the "one device = one
// file" requirement: renaming the device from any identity in the file
// must also update the sibling identities in memory, not just the one
// that called SetDeviceLabel.
func TestSetDeviceLabelPropagatesToSiblings(t *testing.T) {
	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}

	all[0].SetDeviceLabel("Galaxy S22")
	if all[1].DeviceLabel != "Galaxy S22" {
		t.Errorf("DeviceLabel not propagated to the sibling: %q", all[1].DeviceLabel)
	}
}

// TestAddIdentityInheritsDeviceLabel covers the same principle from the
// opposite side: a NEW identity added to a file that already has a
// DeviceLabel set must inherit it immediately, not start with no name.
func TestAddIdentityInheritsDeviceLabel(t *testing.T) {
	first, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New(alice): %v", err)
	}
	first.SetDeviceLabel("work laptop")

	second, err := keystore.New("alice1")
	if err != nil {
		t.Fatalf("New(alice1): %v", err)
	}
	all, err := keystore.AddIdentity([]*keystore.Keystore{first}, second)
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	if all[1].DeviceLabel != "work laptop" {
		t.Errorf("the new identity should have inherited DeviceLabel from the existing file, got %q", all[1].DeviceLabel)
	}
}

// TestNewGeneratesMLDSAIdentity verifies that New() always generates a
// durable ML-DSA-65 key for the network identity, reconstructible from
// the seed via the exposed accessors.
func TestNewGeneratesMLDSAIdentity(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(ks.MLDSAKey) != mldsa65.SeedSize {
		t.Fatalf("MLDSAKey len = %d, want %d", len(ks.MLDSAKey), mldsa65.SeedSize)
	}
	priv := ks.MLDSAPrivKey()
	pub := ks.MLDSAPubKey()
	if priv == nil || pub == nil {
		t.Fatal("MLDSAPrivKey()/MLDSAPubKey() = nil on a freshly created keystore")
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("MLDSAPubKey() doesn't match the pubkey derived from MLDSAPrivKey()")
	}
}

// TestConcurrentContactAccessNoRace verifies that knownContactPubsFn
// (invoked by an HTTP goroutine for every knock), reading through
// ContactIdentityPubs()/ContactsSnapshot() rather than iterating
// ks.Contacts directly, stays safe against concurrent AddContact/
// DeleteContact on the TUI/UI goroutine — both accessors are mutex
// protected. Under -race, this test fails on a data race even if no
// panic manifests.
func TestConcurrentContactAccessNoRace(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: continuously add/remove contacts.
	for i := range 4 {
		wg.Go(func() {
			username := fmt.Sprintf("contact-%d", i)
			pub := make([]byte, 32)
			for {
				select {
				case <-stop:
					return
				default:
				}
				rand.Read(pub)
				ks.AddContact(keystore.Contact{Username: username, IdentityPub: append([]byte(nil), pub...)})
				ks.DeleteContactByPub(pub)
			}
		})
	}

	// Readers: the same pattern as knownContactPubsFn/ContactsSnapshot in
	// production (cmd/main.go).
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = ks.ContactIdentityPubs()
				_ = ks.ContactsSnapshot()
				_, _ = contactNamed(ks, "contact-0")
			}
		})
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestTrustLevelDangerPrevailsOverAnything verifies that a
// relationship-key conflict (PendingPeerRelIdentityPub/
// PendingPeerRelContentPub populated) always makes TrustDanger win, even
// over the highest possible trust level (TrustVerifiedIntroduced).
func TestTrustLevelDangerPrevailsOverAnything(t *testing.T) {
	c := keystore.Contact{
		Verified:     true,
		IntroducedBy: "carol",
		Devices: map[string]*keystore.DeviceRelation{
			"dev1": {PendingPeerRelIdentityPub: []byte("pending-identity-key")},
		},
	}
	if lvl := c.TrustLevel(); lvl != keystore.TrustDanger {
		t.Errorf("TrustLevel = %v, want TrustDanger even with Verified+IntroducedBy", lvl)
	}
	if keystore.TrustDanger >= keystore.TrustUnknown {
		t.Errorf("TrustDanger (%d) must stay below TrustUnknown (%d)", keystore.TrustDanger, keystore.TrustUnknown)
	}

	// No conflict: the computation goes back to normal.
	c2 := keystore.Contact{Verified: true, IntroducedBy: "carol"}
	if lvl := c2.TrustLevel(); lvl != keystore.TrustVerifiedIntroduced {
		t.Errorf("TrustLevel without conflict = %v, want TrustVerifiedIntroduced", lvl)
	}
}

// TestConfirmPendingRelKeys verifies keystore.ConfirmPendingRelKeys:
// applies the pending keys to Peer*, clears Verified (it must be
// regained with a new safety number) and cleans up the Pending fields —
// IntroducedBy stays unchanged.
func TestConfirmPendingRelKeys(t *testing.T) {
	bobPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newIdentPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newContentPub, _, _ := ed25519.GenerateKey(rand.Reader)

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(keystore.Contact{
		Username:    "bob",
		IdentityPub: []byte(bobPub),
		Devices: map[string]*keystore.DeviceRelation{
			"dev1": {
				PeerRelIdentityPub:        []byte(oldIdentPub),
				PendingPeerRelIdentityPub: []byte(newIdentPub),
				PendingPeerRelContentPub:  []byte(newContentPub),
			},
		},
		Verified:     true,
		IntroducedBy: "carol",
	})

	if !ks.ConfirmPendingRelKeys([]byte(bobPub)) {
		t.Fatal("ConfirmPendingRelKeys returned false, want true (conflict present)")
	}

	c, ok := ks.GetContactByPub([]byte(bobPub))
	if !ok {
		t.Fatal("contact not found after the confirmation")
	}
	dev, ok := c.SoleDevice()
	if !ok {
		t.Fatal("SoleDevice not found after the confirmation")
	}
	if !bytes.Equal(dev.PeerRelIdentityPub, []byte(newIdentPub)) {
		t.Errorf("PeerRelIdentityPub = %x, want the new %x", dev.PeerRelIdentityPub, newIdentPub)
	}
	if !bytes.Equal(dev.PeerRelContentPub, []byte(newContentPub)) {
		t.Errorf("PeerRelContentPub = %x, want the new %x", dev.PeerRelContentPub, newContentPub)
	}
	if len(dev.PendingPeerRelIdentityPub) != 0 || len(dev.PendingPeerRelContentPub) != 0 {
		t.Error("the Pending fields should have been cleared after the confirmation")
	}
	if c.Verified {
		t.Error("Verified must be reset after the confirmation — it has to be earned again with a new Safety Number")
	}
	if c.IntroducedBy != "carol" {
		t.Errorf("IntroducedBy = %q, must stay unchanged (a historical fact independent of the keys)", c.IntroducedBy)
	}
	if c.TrustLevel() != keystore.TrustIntroduced {
		t.Errorf("TrustLevel after the confirmation = %v, want TrustIntroduced (Verified just reset, IntroducedBy unchanged)", c.TrustLevel())
	}

	// A second attempt, with no pending conflict, must fail.
	if ks.ConfirmPendingRelKeys([]byte(bobPub)) {
		t.Error("ConfirmPendingRelKeys on a contact without a pending conflict should have returned false")
	}
}

// TestMultiDeviceTrustDangerIsolatedPerDevice verifies the per-device
// data model: a contact with several known devices — one with a
// pending conflict (TrustDanger), another clean — bubbles TrustDanger
// up to the contact (the conflict always wins), but the conflict stays
// written ONLY on the entry of the device that generated it, never
// propagated/readable on the other. A genuinely new device (no
// preexisting entry for its DevicePub) can never generate a conflict by
// construction — verified here indirectly: devB never had
// PendingPeerRel* written, exactly like an entry created from scratch
// for a rel_init from an unknown DevicePub (applyRelInit, tui.go).
func TestMultiDeviceTrustDangerIsolatedPerDevice(t *testing.T) {
	devAPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devAPendingPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devBPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)

	c := keystore.Contact{
		Username: "bob",
		Devices: map[string]*keystore.DeviceRelation{
			"devA": {
				PeerRelIdentityPub:         []byte(devAPeerPub),
				PendingPeerRelIdentityPub:  []byte(devAPendingPub),
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
			},
			"devB": {
				PeerRelIdentityPub:         []byte(devBPeerPub),
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
			},
		},
	}

	if lvl := c.TrustLevel(); lvl != keystore.TrustDanger {
		t.Errorf("TrustLevel = %v, want TrustDanger (a single device in conflict is enough to win for the contact)", lvl)
	}

	devB := c.Devices["devB"]
	if len(devB.PendingPeerRelIdentityPub) != 0 || len(devB.PendingPeerRelContentPub) != 0 {
		t.Error("devA's conflict must never appear in devB's Pending fields")
	}
	if !bytes.Equal(devB.PeerRelIdentityPub, []byte(devBPeerPub)) {
		t.Error("devB's PeerRelIdentityPub must not be touched by a conflict on a different device")
	}

	// With more than one known device, ConfirmPendingRelKeys resolves
	// the right device via DeviceWithPendingRelKeys() — devA (which
	// really has a pending conflict), never devB (which has none): it
	// must succeed, and touch ONLY devA.
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	c.IdentityPub = []byte(bobPub)
	ks.AddContact(c)
	if !ks.ConfirmPendingRelKeys([]byte(bobPub)) {
		t.Fatal("ConfirmPendingRelKeys must succeed by resolving the device with a real pending conflict (devA)")
	}
	updated, ok := ks.GetContactByPub([]byte(bobPub))
	if !ok {
		t.Fatal("contact not found again after the confirmation")
	}
	if !bytes.Equal(updated.Devices["devA"].PeerRelIdentityPub, []byte(devAPendingPub)) {
		t.Error("ConfirmPendingRelKeys should have promoted devA's PendingPeerRelIdentityPub")
	}
	if len(updated.Devices["devA"].PendingPeerRelIdentityPub) != 0 {
		t.Error("devA's Pending field should have been cleared after the confirmation")
	}
	if !bytes.Equal(updated.Devices["devB"].PeerRelIdentityPub, []byte(devBPeerPub)) {
		t.Error("devB must not be touched by the confirmation of devA's conflict")
	}
}

// TestContactReadyDevices verifies Contact.ReadyDevices(): unlike
// SoleDevice(), it returns EVERY ready device
// (RelIdentityConfirmedByPeer+RelContentConfirmedByPeer, complete keys,
// known Address), excluding not-yet-confirmed ones, ones with
// incomplete keys, or ones with no address — never an error on "more
// than one", never a guessed choice on one that isn't ready.
func TestContactReadyDevices(t *testing.T) {
	readyPub, readyPriv, _ := ed25519.GenerateKey(rand.Reader)
	noAddrPub, noAddrPriv, _ := ed25519.GenerateKey(rand.Reader)

	c := keystore.Contact{
		Username: "bob",
		Devices: map[string]*keystore.DeviceRelation{
			// Ready: confirmed, complete keys, known address.
			"ready": {
				RelIdentityPriv:            []byte(readyPriv),
				PeerRelIdentityPub:         []byte(readyPub),
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
				Address:                    "readyaddr.onion",
			},
			// Not confirmed — just a spontaneous rel_init request from the
			// peer, never a rel_init_ack: not ready to be invited yet.
			"notconfirmed": {
				RelIdentityPriv:    []byte(readyPriv),
				PeerRelIdentityPub: []byte(readyPub),
				Address:            "notconfirmed.onion",
			},
			// Confirmed but with no declared address (a legacy/defensive
			// case): no way to reach it, excluded regardless of the keys.
			"noaddr": {
				RelIdentityPriv:            []byte(noAddrPriv),
				PeerRelIdentityPub:         []byte(noAddrPub),
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
			},
			// Pre-bootstrap placeholder: our keys generated, but no peer
			// key has arrived yet — never ready.
			"": {
				RelIdentityPriv: []byte(readyPriv),
			},
		},
	}

	devs := c.ReadyDevices()
	if len(devs) != 1 {
		t.Fatalf("ReadyDevices() = %d devices, want 1 (only \"ready\")", len(devs))
	}
	if _, ok := devs["ready"]; !ok {
		t.Error("ReadyDevices() must include the \"ready\" device")
	}

	// No known device → an empty (nil) map, never a panic.
	empty := keystore.Contact{Username: "carol"}
	if got := empty.ReadyDevices(); len(got) != 0 {
		t.Errorf("ReadyDevices() on a contact without devices = %d, want 0", len(got))
	}

	// Two devices both ready → both returned (unlike SoleDevice(),
	// which would refuse with more than one).
	secondPub, secondPriv, _ := ed25519.GenerateKey(rand.Reader)
	c.Devices["ready2"] = &keystore.DeviceRelation{
		RelIdentityPriv:            []byte(secondPriv),
		PeerRelIdentityPub:         []byte(secondPub),
		RelIdentityConfirmedByPeer: true,
		RelContentConfirmedByPeer:  true,
		Address:                    "ready2addr.onion",
	}
	devs2 := c.ReadyDevices()
	if len(devs2) != 2 {
		t.Fatalf("ReadyDevices() with two ready devices = %d, want 2", len(devs2))
	}
	if _, ok := c.SoleDevice(); ok {
		t.Error("SoleDevice() with two known devices must return false — ReadyDevices() is the right path here, not SoleDevice()")
	}
}

// contactWithTwoReadyDevicesForRotationTests builds a contact with two
// devices, both ready (Contact.ReadyDevices) — used by the rotation
// fan-out tests below.
func contactWithTwoReadyDevicesForRotationTests() (keystore.Contact, ed25519.PublicKey) {
	bobPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devAPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devAPriv := make([]byte, ed25519.PrivateKeySize)
	rand.Read(devAPriv)
	devBPeerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	devBPriv := make([]byte, ed25519.PrivateKeySize)
	rand.Read(devBPriv)
	c := keystore.Contact{
		Username:    "bob",
		IdentityPub: []byte(bobPub),
		Devices: map[string]*keystore.DeviceRelation{
			"devA": {
				Address:                    "devA.onion",
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
				RelIdentityPriv:            devAPriv,
				PeerRelIdentityPub:         []byte(devAPeerPub),
			},
			"devB": {
				Address:                    "devB.onion",
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
				RelIdentityPriv:            devBPriv,
				PeerRelIdentityPub:         []byte(devBPeerPub),
			},
		},
	}
	return c, bobPub
}

// TestStartRelIdentityRotationByPubFanOutMultiDevice verifies that
// rotating the IdentityKey-per-relationship fans out over EVERY ready
// device of a contact, not just the first — an independent key
// generated for each, both marked IdentityKeyPending, never a guessed
// choice on just one.
func TestStartRelIdentityRotationByPubFanOutMultiDevice(t *testing.T) {
	c, bobPub := contactWithTwoReadyDevicesForRotationTests()
	oldPrivA := append([]byte(nil), c.Devices["devA"].RelIdentityPriv...)
	oldPrivB := append([]byte(nil), c.Devices["devB"].RelIdentityPriv...)

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(c)

	rotated, err := ks.StartRelIdentityRotationByPub([]byte(bobPub))
	if err != nil {
		t.Fatalf("StartRelIdentityRotationByPub: %v", err)
	}
	if len(rotated) != 2 {
		t.Fatalf("rotated = %d devices, want 2 (fan-out over both)", len(rotated))
	}
	for _, key := range []string{"devA", "devB"} {
		found := false
		for _, r := range rotated {
			if r == key {
				found = true
			}
		}
		if !found {
			t.Errorf("device %q is not among the rotated ones: %v", key, rotated)
		}
	}

	updated, ok := ks.GetContactByPub([]byte(bobPub))
	if !ok {
		t.Fatal("contact not found again after the rotation")
	}
	devA, devB := updated.Devices["devA"], updated.Devices["devB"]
	if !devA.IdentityKeyPending || !devB.IdentityKeyPending {
		t.Error("IdentityKeyPending must be true on BOTH devices after the fan-out")
	}
	if bytes.Equal(devA.RelIdentityPriv, oldPrivA) {
		t.Error("devA must have a new RelIdentityPriv, different from the previous one")
	}
	if bytes.Equal(devB.RelIdentityPriv, oldPrivB) {
		t.Error("devB must have a new RelIdentityPriv, different from the previous one")
	}
	if bytes.Equal(devA.RelIdentityPriv, devB.RelIdentityPriv) {
		t.Error("devA and devB must receive INDEPENDENT keys, never the same one")
	}
}

// TestSaveGeneratesRelRevocationCerts verifies that Save computes the
// missing self-revocation certificates for every device with an
// already-set RelIdentityPriv/RelContentPriv, and that the resulting
// signatures verify against their respective public keys — with no
// need for any explicit action at key generation time (self-healing).
func TestSaveGeneratesRelRevocationCerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")
	password := "a-very-long-test-password"

	c, bobPub := contactWithTwoReadyDevicesForRotationTests()
	// contactWithTwoReadyDevicesForRotationTests fills RelIdentityPriv
	// with random bytes (enough to compare "it changed", the only use
	// made elsewhere) — not a real valid Ed25519 pair: .Public() on
	// those bytes wouldn't match the key actually used by ed25519.Sign.
	// Replaced here with a real pair, needed to verify the produced
	// revocation signature. RelContentPriv is never set by that helper
	// — added here to cover that branch too in the same test.
	_, devAIdentPriv, _ := ed25519.GenerateKey(rand.Reader)
	c.Devices["devA"].RelIdentityPriv = devAIdentPriv
	_, devAContentPriv, _ := ed25519.GenerateKey(rand.Reader)
	c.Devices["devA"].RelContentPriv = devAContentPriv

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(c)

	if err := ks.Save(path, password); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := keystore.Load(path, password)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	reloaded, ok := loaded.GetContactByPub([]byte(bobPub))
	if !ok {
		t.Fatal("contact not found again after the reload")
	}
	devA := reloaded.Devices["devA"]
	if len(devA.RevokeIdentitySig) == 0 {
		t.Fatal("RevokeIdentitySig not generated by Save")
	}
	if len(devA.RevokeContentSig) == 0 {
		t.Fatal("RevokeContentSig not generated by Save")
	}
	identPub := ed25519.PrivateKey(devA.RelIdentityPriv).Public().(ed25519.PublicKey)
	if !shared.VerifyRelRevoke(identPub, "alice", devA.RevokeIdentitySig) {
		t.Error("RevokeIdentitySig doesn't verify against the current RelIdentityPriv")
	}
	contentPub := ed25519.PrivateKey(devA.RelContentPriv).Public().(ed25519.PublicKey)
	if !shared.VerifyRelRevoke(contentPub, "alice", devA.RevokeContentSig) {
		t.Error("RevokeContentSig doesn't verify against the current RelContentPriv")
	}

	devB := reloaded.Devices["devB"]
	if len(devB.RevokeContentSig) != 0 {
		t.Error("devB never had a RelContentPriv — it must not have a RevokeContentSig")
	}
}

// TestRotationRegeneratesRelRevocationCert verifies that a rotation
// clears the replaced key's revocation certificate, and that the
// following Save generates a fresh one valid for the NEW key (never for
// the old one).
func TestRotationRegeneratesRelRevocationCert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore")
	password := "a-very-long-test-password"

	c, bobPub := contactWithTwoReadyDevicesForRotationTests()
	// Same reason as the twin test above: a real Ed25519 pair is
	// needed, not the shared helper's random bytes.
	_, devAIdentPriv, _ := ed25519.GenerateKey(rand.Reader)
	c.Devices["devA"].RelIdentityPriv = devAIdentPriv

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(c)
	if err := ks.Save(path, password); err != nil {
		t.Fatalf("Save (before the rotation): %v", err)
	}
	before, _ := ks.GetContactByPub([]byte(bobPub))
	oldSig := append([]byte(nil), before.Devices["devA"].RevokeIdentitySig...)
	if len(oldSig) == 0 {
		t.Fatal("precondition: RevokeIdentitySig must already exist before the rotation")
	}

	if _, err := ks.StartRelIdentityRotationByPub([]byte(bobPub)); err != nil {
		t.Fatalf("StartRelIdentityRotationByPub: %v", err)
	}
	mid, _ := ks.GetContactByPub([]byte(bobPub))
	if len(mid.Devices["devA"].RevokeIdentitySig) != 0 {
		t.Fatal("the rotation must clear RevokeIdentitySig, not keep the old key's")
	}

	if err := ks.Save(path, password); err != nil {
		t.Fatalf("Save (after the rotation): %v", err)
	}
	after, _ := ks.GetContactByPub([]byte(bobPub))
	devA := after.Devices["devA"]
	if len(devA.RevokeIdentitySig) == 0 {
		t.Fatal("Save after the rotation must generate a new RevokeIdentitySig")
	}
	if bytes.Equal(devA.RevokeIdentitySig, oldSig) {
		t.Error("the new RevokeIdentitySig must not equal the replaced key's")
	}
	newPub := ed25519.PrivateKey(devA.RelIdentityPriv).Public().(ed25519.PublicKey)
	if !shared.VerifyRelRevoke(newPub, "alice", devA.RevokeIdentitySig) {
		t.Error("the new RevokeIdentitySig doesn't verify against the new RelIdentityPriv")
	}
}

// TestStartRelIdentityRotationByPubSkipsPendingDeviceKeepsOthers verifies
// that a device whose ContentKey is already rotating (never two keys in
// flight together on the same relationship) is silently skipped,
// without blocking rotation of the OTHER ready devices — behavior
// explicitly documented in StartRelIdentityRotationByPub.
func TestStartRelIdentityRotationByPubSkipsPendingDeviceKeepsOthers(t *testing.T) {
	c, bobPub := contactWithTwoReadyDevicesForRotationTests()
	c.Devices["devA"].ContentKeyPending = true // devA: content rotation already in flight

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(c)

	rotated, err := ks.StartRelIdentityRotationByPub([]byte(bobPub))
	if err != nil {
		t.Fatalf("StartRelIdentityRotationByPub: %v", err)
	}
	if len(rotated) != 1 || rotated[0] != "devB" {
		t.Fatalf("rotated = %v, want only [\"devB\"] (devA skipped for ContentKeyPending)", rotated)
	}
	updated, ok := ks.GetContactByPub([]byte(bobPub))
	if !ok {
		t.Fatal("contact not found again")
	}
	if updated.Devices["devA"].IdentityKeyPending {
		t.Error("devA must never enter IdentityKeyPending while ContentKeyPending is already true")
	}
	if !updated.Devices["devB"].IdentityKeyPending {
		t.Error("devB should have been rotated normally, not blocked by devA's state")
	}
}

// TestStartRelContentRotationByPubFanOutMultiDevice is the equivalent
// for the ContentKey-per-relationship of the twin test above on the
// IdentityKey — same fan-out, same independence between the two
// devices.
func TestStartRelContentRotationByPubFanOutMultiDevice(t *testing.T) {
	c, bobPub := contactWithTwoReadyDevicesForRotationTests()

	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(c)

	rotated, err := ks.StartRelContentRotationByPub([]byte(bobPub))
	if err != nil {
		t.Fatalf("StartRelContentRotationByPub: %v", err)
	}
	if len(rotated) != 2 {
		t.Fatalf("rotated = %d devices, want 2 (fan-out over both)", len(rotated))
	}
	updated, ok := ks.GetContactByPub([]byte(bobPub))
	if !ok {
		t.Fatal("contact not found again after the rotation")
	}
	devA, devB := updated.Devices["devA"], updated.Devices["devB"]
	if !devA.ContentKeyPending || !devB.ContentKeyPending {
		t.Error("ContentKeyPending must be true on BOTH devices after the fan-out")
	}
	if len(devA.RelContentPriv) != ed25519.PrivateKeySize || len(devB.RelContentPriv) != ed25519.PrivateKeySize {
		t.Fatal("both devices must have a newly generated RelContentPriv")
	}
	if bytes.Equal(devA.RelContentPriv, devB.RelContentPriv) {
		t.Error("devA and devB must receive INDEPENDENT ContentKeys, never the same one")
	}
}

// TestNetworkIdentityPrivKeyD1Unchanged verifies that D1
// (AdditionalDevice false, the common case — an identity created with
// New() or restored from bare 24 words) keeps using the direct,
// unchanged root IdentityKey for the network address.
func TestNetworkIdentityPrivKeyD1Unchanged(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got := ks.NetworkIdentityPrivKey(); !bytes.Equal(got, ks.IdentityPrivKey()) {
		t.Error("NetworkIdentityPrivKey for D1 must return exactly the root IdentityPrivKey")
	}
}

// TestNetworkIdentityPrivKeyAdditionalDeviceDeterministic verifies that
// an additional device (AdditionalDevice true) derives an address
// different from the root, but deterministic (same IdentityKey+DeviceID
// → same derived key on every call) — needed for the hidden service to
// remain reachable at the same address across restarts of the same
// device.
func TestNetworkIdentityPrivKeyAdditionalDeviceDeterministic(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AdditionalDevice = true
	ks.DeviceID = bytes.Repeat([]byte{0x42}, 16)

	got1 := ks.NetworkIdentityPrivKey()
	got2 := ks.NetworkIdentityPrivKey()
	if !bytes.Equal(got1, got2) {
		t.Error("NetworkIdentityPrivKey is not deterministic: two calls produced different keys")
	}
	if bytes.Equal(got1, ks.IdentityPrivKey()) {
		t.Error("NetworkIdentityPrivKey for an additional device must not equal the root IdentityPrivKey")
	}

	// A different DeviceID must produce a different derived key —
	// distinct additional devices must never collide on the same address.
	ks2 := *ks
	ks2.DeviceID = bytes.Repeat([]byte{0x43}, 16)
	if bytes.Equal(ks.NetworkIdentityPrivKey(), ks2.NetworkIdentityPrivKey()) {
		t.Error("different DeviceIDs produced the same derived network key")
	}
}

// TestNetworkIdentityPrivKeyForMatchesWrapper verifies that
// NetworkIdentityPrivKeyFor(ks.DeviceID), called on an additional
// device, produces exactly the same result as the NetworkIdentityPrivKey()
// wrapper, and that a DeviceID other than one's own produces a
// different derived address (needed to reach a sibling device).
func TestNetworkIdentityPrivKeyForMatchesWrapper(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AdditionalDevice = true
	ks.DeviceID = bytes.Repeat([]byte{0x42}, 16)

	if got, want := ks.NetworkIdentityPrivKeyFor(ks.DeviceID), ks.NetworkIdentityPrivKey(); !bytes.Equal(got, want) {
		t.Error("NetworkIdentityPrivKeyFor(ks.DeviceID) must equal NetworkIdentityPrivKey()")
	}

	otherDeviceID := bytes.Repeat([]byte{0x99}, 16)
	if bytes.Equal(ks.NetworkIdentityPrivKeyFor(otherDeviceID), ks.NetworkIdentityPrivKey()) {
		t.Error("a DeviceID different from our own must produce a different derived address")
	}
}

// TestStartRootRotationStashesOldKeysAndPopulatesPending verifies that
// StartRootRotation generates a new root, retains the previous one in
// the Old* vaults, applies the new one as current immediately, and
// repopulates both pending lists with every known contact/device.
func TestStartRootRotationStashesOldKeysAndPopulatesPending(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	oldIdentity := append([]byte(nil), ks.IdentityKey...)
	oldMLKEM := append([]byte(nil), ks.MLKEMKey...)
	oldMLDSA := append([]byte(nil), ks.MLDSAKey...)

	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: bytes.Repeat([]byte{0x01}, 32)})
	ks.AddContact(keystore.Contact{Username: "carol", IdentityPub: bytes.Repeat([]byte{0x02}, 32)})
	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: bytes.Repeat([]byte{0xaa}, 16)})
	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: bytes.Repeat([]byte{0xbb}, 16)})

	if err := ks.StartRootRotation(); err != nil {
		t.Fatalf("StartRootRotation: %v", err)
	}

	if bytes.Equal(ks.IdentityKey, oldIdentity) {
		t.Error("IdentityKey must change right after StartRootRotation")
	}
	if bytes.Equal(ks.MLKEMKey, oldMLKEM) {
		t.Error("MLKEMKey must change right after StartRootRotation")
	}
	if bytes.Equal(ks.MLDSAKey, oldMLDSA) {
		t.Error("MLDSAKey must change right after StartRootRotation")
	}
	if !ks.RootRotationInProgress() {
		t.Error("OldIdentityKey must stay populated during propagation")
	}

	if len(ks.RootRotationPendingContacts) != 2 {
		t.Fatalf("RootRotationPendingContacts = %v, want 2 contacts", ks.RootRotationPendingContacts)
	}
	if len(ks.RootRotationPendingDevices) != 2 {
		t.Fatalf("RootRotationPendingDevices = %d, want 2 devices", len(ks.RootRotationPendingDevices))
	}

	if err := ks.StartRootRotation(); err == nil {
		t.Error("a second StartRootRotation while one is already in progress must fail")
	}
}

// TestRootRotationPendingSnapshotIsACopy verifies that the snapshot
// lists what is still pending, follows acks, and can't alter the
// keystore through the returned slices.
func TestRootRotationPendingSnapshotIsACopy(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	if c, d := ks.RootRotationPendingSnapshot(); len(c) != 0 || len(d) != 0 {
		t.Fatalf("snapshot before any rotation = %v, %v", c, d)
	}
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: bytes.Repeat([]byte{0x01}, 32)})
	ks.AddContact(keystore.Contact{Username: "carol", IdentityPub: bytes.Repeat([]byte{0x02}, 32)})
	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: bytes.Repeat([]byte{0xaa}, 16)})
	if err := ks.StartRootRotation(); err != nil {
		t.Fatal(err)
	}

	contacts, devices := ks.RootRotationPendingSnapshot()
	if len(contacts) != 2 || len(devices) != 1 {
		t.Fatalf("snapshot = %v, %d devices; want 2 contacts, 1 device", contacts, len(devices))
	}
	contacts[0][0] = 0xff
	devices[0][0] = 0x00
	again, devAgain := ks.RootRotationPendingSnapshot()
	if again[0][0] == 0xff || devAgain[0][0] != 0xaa {
		t.Error("changing the snapshot changed the keystore")
	}

	ks.AckRootRotationContact(bytes.Repeat([]byte{0x01}, 32))
	if contacts, _ := ks.RootRotationPendingSnapshot(); len(contacts) != 1 || !bytes.Equal(contacts[0], bytes.Repeat([]byte{0x02}, 32)) {
		t.Errorf("snapshot after bob's ack = %v, want [carol]", contacts)
	}
}

// TestAckRootRotationContactAndDeviceFinalizes verifies that each
// contact/device ack removes its pending entry, is idempotent (a
// duplicate ack → false), and that the Old* vaults are cleared ONLY
// when both lists are empty.
func TestAckRootRotationContactAndDeviceFinalizes(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: bytes.Repeat([]byte{0x01}, 32)})
	deviceID := bytes.Repeat([]byte{0xaa}, 16)
	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: deviceID})

	if err := ks.StartRootRotation(); err != nil {
		t.Fatalf("StartRootRotation: %v", err)
	}

	if ks.AckRootRotationContact(bytes.Repeat([]byte{0x02}, 32)) {
		t.Error("the ack of a contact never pending must return false")
	}
	if !ks.AckRootRotationContact(bytes.Repeat([]byte{0x01}, 32)) {
		t.Error("bob's ack must return true")
	}
	if ks.AckRootRotationContact(bytes.Repeat([]byte{0x01}, 32)) {
		t.Error("a second ack from the same contact (duplicate) must return false")
	}
	if !ks.RootRotationInProgress() {
		t.Error("the Old* vaults must not be zeroed while a device is still pending")
	}

	if !ks.AckRootRotationDevice(deviceID) {
		t.Error("the device's ack must return true")
	}

	if ks.RootRotationInProgress() {
		t.Error("the Old* vaults must be zeroed as soon as both pending lists are empty")
	}
}

// TestMaybeFinalizeRootRotationNoopWithoutRotation verifies that
// MaybeFinalizeRootRotation is a safe no-op when no root rotation was
// ever started.
func TestMaybeFinalizeRootRotationNoopWithoutRotation(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	ks.MaybeFinalizeRootRotation() // must not panic nor change anything
	if ks.RootRotationInProgress() {
		t.Error("OldIdentityKey must never be populated without a started rotation")
	}
}

// TestSoleDeviceOrPlaceholderEmptyDevices verifies that a contact with
// no Devices entry still returns a usable DeviceRelation (never (nil,
// false) like SoleDevice) — the probe cycle relies on this to generate
// relationship keys even toward such a contact.
func TestSoleDeviceOrPlaceholderEmptyDevices(t *testing.T) {
	c := keystore.Contact{Username: "bob"}
	dev, ok := c.SoleDeviceOrPlaceholder()
	if !ok || dev == nil {
		t.Fatal("want a usable DeviceRelation for a contact without Devices")
	}
	if len(dev.RelIdentityPriv) != 0 || len(dev.RelContentPriv) != 0 {
		t.Error("the placeholder must have empty keys, ready for generation")
	}
}

// TestSoleDeviceOrPlaceholderMatchesSoleDevice verifies that, with
// exactly one entry already present, the behavior matches SoleDevice.
func TestSoleDeviceOrPlaceholderMatchesSoleDevice(t *testing.T) {
	existing := &keystore.DeviceRelation{RelIdentityPriv: []byte("x")}
	c := keystore.Contact{Devices: map[string]*keystore.DeviceRelation{"d1": existing}}
	dev, ok := c.SoleDeviceOrPlaceholder()
	if !ok || dev != existing {
		t.Fatal("with a single known entry it must return exactly that one")
	}
}

// TestSoleDeviceOrPlaceholderAmbiguousStillFalse verifies that with 2+
// known devices it remains ambiguous (no random choice), the same
// behavior as SoleDevice.
func TestSoleDeviceOrPlaceholderAmbiguousStillFalse(t *testing.T) {
	c := keystore.Contact{Devices: map[string]*keystore.DeviceRelation{
		"d1": {}, "d2": {},
	}}
	if _, ok := c.SoleDeviceOrPlaceholder(); ok {
		t.Error("with 2+ known devices it must never pick one automatically")
	}
}

// TestDevicesOrPlaceholderEmptyDevices verifies that a contact with no
// Devices returns a map with just the "" placeholder entry.
func TestDevicesOrPlaceholderEmptyDevices(t *testing.T) {
	c := keystore.Contact{Username: "bob"}
	devices := c.DevicesOrPlaceholder()
	if len(devices) != 1 {
		t.Fatalf("want exactly 1 placeholder entry, got %d", len(devices))
	}
	dev, ok := devices[""]
	if !ok || dev == nil {
		t.Fatal("the placeholder entry must live under the empty key")
	}
}

// TestDevicesOrPlaceholderReturnsExisting verifies that, with entries
// already present, DevicesOrPlaceholder returns exactly the existing
// map (no substitution).
func TestDevicesOrPlaceholderReturnsExisting(t *testing.T) {
	existing := map[string]*keystore.DeviceRelation{"d1": {}, "d2": {}}
	c := keystore.Contact{Devices: existing}
	devices := c.DevicesOrPlaceholder()
	if len(devices) != 2 {
		t.Fatalf("want the 2 existing entries to stay intact, got %d", len(devices))
	}
}

// TestGetContactByPubReturnsCopy covers the copy semantics: changing the
// returned contact or its devices leaves the keystore untouched; only
// UpdateContactByPub changes it.
func TestGetContactByPubReturnsCopy(t *testing.T) {
	ks, err := keystore.New("me")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub, Devices: map[string]*keystore.DeviceRelation{"d": {Address: "a"}}})

	c, _ := ks.GetContactByPub(pub)
	c.LocalName = "changed"
	c.Devices["d"].Address = "changed"
	if got, _ := ks.GetContactByPub(pub); got.LocalName != "" || got.Devices["d"].Address != "a" {
		t.Fatalf("a change to the returned copy reached the keystore: %+v", got)
	}

	if !ks.UpdateContactByPub(pub, func(c *keystore.Contact) {
		c.LocalName = "bobby"
		c.Devices["d"].Address = "b"
	}) {
		t.Fatal("UpdateContactByPub: contact not found")
	}
	if got, _ := ks.GetContactByPub(pub); got.LocalName != "bobby" || got.Devices["d"].Address != "b" {
		t.Errorf("UpdateContactByPub not applied: %+v", got)
	}
}

// TestUpdateContactByPubConcurrentWithSave runs updates of the same
// contact concurrently with saves: run with -race, no access may be
// unsynchronized and no update may be lost.
func TestUpdateContactByPubConcurrentWithSave(t *testing.T) {
	ks, err := keystore.New("me")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub, Devices: map[string]*keystore.DeviceRelation{"d": {}}})
	path := filepath.Join(t.TempDir(), "ks")

	const n = 50
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			ks.UpdateContactByPub(pub, func(c *keystore.Contact) {
				c.LastAckAt = c.LastAckAt.Add(time.Second)
				c.Devices["d"].Address = fmt.Sprint(i)
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			if err := ks.Save(path, "pw"); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
	if got, _ := ks.GetContactByPub(pub); got.LastAckAt.Sub(time.Time{}) != n*time.Second {
		t.Errorf("LastAckAt advanced by %v, want %v", got.LastAckAt.Sub(time.Time{}), n*time.Second)
	}
}

// TestGetSavedGroupReturnsCopy covers the saved groups' copy semantics:
// changing the returned group's members leaves the keystore untouched.
func TestGetSavedGroupReturnsCopy(t *testing.T) {
	ks, err := keystore.New("me")
	if err != nil {
		t.Fatal(err)
	}
	ks.AddSavedGroup(keystore.SavedGroup{LocalName: "g", GroupID: "id", Members: []keystore.SavedGroupMember{{Username: "bob"}}})

	g, ok := ks.GetSavedGroup("g")
	if !ok {
		t.Fatal("GetSavedGroup: not found")
	}
	g.Members[0].Username = "changed"
	snap := ks.SavedGroupsSnapshot()
	snap[0].Members[0].Username = "changed too"
	if got, _ := ks.GetSavedGroup("id"); got.Members[0].Username != "bob" {
		t.Errorf("a change to a returned copy reached the keystore: %+v", got)
	}
}

// TestKnownDevicesSnapshotIsACopy verifies that the snapshot follows the
// devices learned by a sync and that changing it leaves the keystore
// untouched.
func TestKnownDevicesSnapshotIsACopy(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got := ks.KnownDevicesSnapshot(); len(got) != 0 {
		t.Fatalf("snapshot of a fresh keystore = %v", got)
	}
	ks.AppendKnownDevice(keystore.DeviceRecord{DeviceID: bytes.Repeat([]byte{0xaa}, 16), Label: "phone"})
	ks.MergeKnownDevices([]keystore.DeviceRecord{{DeviceID: bytes.Repeat([]byte{0xbb}, 16), Label: "laptop"}})

	snap := ks.KnownDevicesSnapshot()
	if len(snap) != 2 || snap[0].Label != "phone" || snap[1].Label != "laptop" {
		t.Fatalf("snapshot = %+v, want phone and laptop", snap)
	}
	snap[0].Label = "changed"
	snap[0].DeviceID[0] = 0
	if again := ks.KnownDevicesSnapshot(); again[0].Label != "phone" || again[0].DeviceID[0] != 0xaa {
		t.Error("changing the snapshot changed the keystore")
	}
}

// TestRemoteNukeQueuesConcurrentAccess runs the remote_nuke and danger
// queue updates concurrently with snapshot reads — under -race any
// unlocked access shows up — and checks a snapshot taken earlier keeps
// its content after a confirmation.
func TestRemoteNukeQueuesConcurrentAccess(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	target := bytes.Repeat([]byte{0xcc}, 16)
	ks.SetDangerEndPending(target, [][]byte{namePub("bob"), namePub("carol")})
	_, endsBefore := ks.DangerPendingSnapshot()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ks.SetDangerBroadcastPending(target, [][]byte{namePub("bob")})
				ks.ConfirmDangerBroadcast(target, namePub("bob"))
				ks.AddPendingRemoteNuke(target)
				ks.RemovePendingRemoteNuke(target)
				ks.MarkDeviceNuked([]byte{byte(j)})
				ks.MergeNukedDevicePubs([][]byte{{byte(j), 1}})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ks.DangerPendingSnapshot()
				ks.NukedDevicePubsSnapshot()
				ks.PendingRemoteNukeTargets()
				ks.IsDeviceNuked([]byte{byte(j)})
			}
		}()
	}
	wg.Wait()

	if !ks.ConfirmDangerEnd(target, namePub("bob")) {
		t.Fatal("ConfirmDangerEnd(bob) found nothing to confirm")
	}
	if len(endsBefore) != 1 || len(endsBefore[0].IdentityPubs) != 2 {
		t.Errorf("snapshot taken earlier changed: %+v", endsBefore)
	}
	_, ends := ks.DangerPendingSnapshot()
	if len(ends) != 1 || len(ends[0].IdentityPubs) != 1 || !bytes.Equal(ends[0].IdentityPubs[0], namePub("carol")) {
		t.Errorf("after confirming bob: %+v, want only carol pending", ends)
	}
	if !ks.ConfirmDangerEnd(target, namePub("carol")) {
		t.Fatal("ConfirmDangerEnd(carol) found nothing to confirm")
	}
	if _, ends := ks.DangerPendingSnapshot(); len(ends) != 0 {
		t.Errorf("entry kept after its last confirmation: %+v", ends)
	}
}

// namePub is a deterministic 32-byte identity key per name — test-only.
func namePub(name string) []byte {
	h := sha256.Sum256([]byte("test-identity:" + name))
	return h[:]
}
