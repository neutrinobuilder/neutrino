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
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"neutrino/internal/keystore"
	bip39 "github.com/tyler-smith/go-bip39"
)

// addManyContacts adds n contacts with a random IdentityPub (32
// high-entropy bytes, not compressible), used to deliberately exceed a
// single QR's threshold (2953 bytes) and exercise the
// ExportQRMulti/AssembleQRMulti paths.
func addManyContacts(t *testing.T, ks *keystore.Keystore, n int) {
	t.Helper()
	for i := range n {
		pub := make([]byte, 32)
		if _, err := rand.Read(pub); err != nil {
			t.Fatal(err)
		}
		ks.AddContact(keystore.Contact{
			Username:    fmt.Sprintf("user-%d-%x", i, pub[:6]),
			IdentityPub: pub,
		})
	}
}

// ── Mnemonic / SeedFromMnemonic ──────────────────────────────────────────────

func TestMnemonicRoundtrip(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 24 {
		t.Fatalf("Mnemonic: want 24 words, got %d", len(words))
	}

	seed, err := keystore.SeedFromMnemonic(words)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, ks.IdentityKey[:32]) {
		t.Fatal("SeedFromMnemonic: the seed doesn't match the first 32 bytes of IdentityKey")
	}
}

func TestMnemonicInvalidIdentityKey(t *testing.T) {
	ks := &keystore.Keystore{}
	if _, err := ks.Mnemonic(); err == nil {
		t.Fatal("Mnemonic: IdentityKey missing but no error")
	}
}

func TestSeedFromMnemonicInvalidWord(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	words[0] = "notavalidword"
	if _, err := keystore.SeedFromMnemonic(words); err == nil {
		t.Fatal("SeedFromMnemonic: word outside the wordlist accepted")
	}
}

func TestSeedFromMnemonicWrongWordCount(t *testing.T) {
	entropy := make([]byte, 16) // 128 bits → 12 words, not the expected 24 (a 32-byte seed)
	if _, err := rand.Read(entropy); err != nil {
		t.Fatal(err)
	}
	m, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(m)
	if _, err := keystore.SeedFromMnemonic(words); err == nil {
		t.Fatal("SeedFromMnemonic: 12-word mnemonic (16-byte seed) accepted")
	}
}

// ── ExportBackupFile / ImportFromBackupFile ──────────────────────────────────

func TestExportImportBackupFileRoundtrip(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub})

	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}

	data, err := ks.ExportBackupFile()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("NTRINO01")) {
		t.Fatal("ExportBackupFile: magic NTRINO01 missing")
	}

	got, err := keystore.ImportFromBackupFile(words, data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" {
		t.Errorf("Username: want 'alice', got %q", got.Username)
	}
	if len(got.Contacts) != 1 || got.Contacts[0].Username != "bob" {
		t.Fatalf("unexpected Contacts: %+v", got.Contacts)
	}
	if !bytes.Equal(got.IdentityKey, ks.IdentityKey) {
		t.Error("ImportFromBackupFile: IdentityKey doesn't match after the roundtrip")
	}
}

// TestImportFromBackupFileGeneratesFreshDeviceID verifies that a
// restore from 24 words + file is the birth of an ADDITIONAL device,
// it must receive its own DeviceID/DevicePriv, never clone the
// backup's origin device's one (otherwise two devices would end up
// sharing the same device identity and colliding on the same derived
// network address).
func TestImportFromBackupFileGeneratesFreshDeviceID(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	if ks.AdditionalDevice {
		t.Fatal("New(): AdditionalDevice must be false (D1)")
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	data, err := ks.ExportBackupFile()
	if err != nil {
		t.Fatal(err)
	}

	got, err := keystore.ImportFromBackupFile(words, data)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AdditionalDevice {
		t.Error("ImportFromBackupFile: AdditionalDevice must be true (additional device)")
	}
	if len(got.DeviceID) != 16 {
		t.Fatalf("ImportFromBackupFile: want a 16-byte DeviceID, got %d", len(got.DeviceID))
	}
	if bytes.Equal(got.DeviceID, ks.DeviceID) {
		t.Error("ImportFromBackupFile: DeviceID cloned from the source device, want a new one")
	}
	if bytes.Equal(got.DevicePriv, ks.DevicePriv) {
		t.Error("ImportFromBackupFile: DevicePriv cloned from the source device, want a new one")
	}
	// The root IdentityKey instead stays the same (same identity, by design).
	if !bytes.Equal(got.IdentityKey, ks.IdentityKey) {
		t.Error("ImportFromBackupFile: IdentityKey must not change, it stays the same identity")
	}
	// The derived network address for the additional device must differ
	// from the origin device's (D1, direct root IdentityKey), that's
	// exactly the point: no collision.
	if bytes.Equal(got.NetworkIdentityPrivKey(), ks.NetworkIdentityPrivKey()) {
		t.Error("NetworkIdentityPrivKey: an additional device and D1 must not share the same network address")
	}
}

// TestImportFromBackupFileClearsRelationKeys verifies that an
// additional device must not inherit relationship keys already
// confirmed by the origin device, otherwise it would be
// cryptographically indistinguishable from D1 toward every
// already-verified contact, and whoever holds just the backup file
// (legitimate or stolen) would inherit already-established trust
// without ever passing through the TrustDanger gate.
func TestImportFromBackupFileClearsRelationKeys(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	contactPub := make([]byte, 32)
	if _, err := rand.Read(contactPub); err != nil {
		t.Fatal(err)
	}
	devicePub := make([]byte, 32)
	if _, err := rand.Read(devicePub); err != nil {
		t.Fatal(err)
	}
	ks.AddContact(keystore.Contact{
		Username:    "bob",
		IdentityPub: contactPub,
		Devices: map[string]*keystore.DeviceRelation{
			string(devicePub): {
				RelIdentityPriv:            []byte("rel-identity-priv-material-1234"),
				PeerRelIdentityPub:         []byte("peer-rel-identity-pub-material12"),
				RelContentPriv:             []byte("rel-content-priv-material-1234"),
				PeerRelContentPub:          []byte("peer-rel-content-pub-material12"),
				RelIdentityConfirmedByPeer: true,
				RelContentConfirmedByPeer:  true,
				PendingPeerRelIdentityPub:  []byte("pending-identity"),
				PendingPeerRelContentPub:   []byte("pending-content"),
			},
		},
		Verified:       true,
		IntroducedBy:   "carol",
		KnownDevicePub: []byte("known-device-pub-material-12345"),
	})
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	data, err := ks.ExportBackupFile()
	if err != nil {
		t.Fatal(err)
	}

	got, err := keystore.ImportFromBackupFile(words, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 1 {
		t.Fatalf("want 1 contact, got %d", len(got.Contacts))
	}
	c := got.Contacts[0]
	if len(c.Devices) != 0 {
		t.Error("Devices not cleared, an additional device must not inherit relationships already negotiated by another")
	}
	if c.Verified {
		t.Error("Verified must go back to false, it has to be earned again on this device")
	}
	if len(c.KnownDevicePub) != 0 {
		t.Error("KnownDevicePub not cleared")
	}
	// The contact's identity/provenance fields remain intact.
	if c.Username != "bob" || !bytes.Equal(c.IdentityPub, contactPub) {
		t.Error("contact identity altered by the clearing")
	}
	if c.IntroducedBy != "carol" {
		t.Error("IntroducedBy must not be touched by clearing the relationship keys")
	}
}

func TestImportFromBackupFileWrongWords(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	data, err := ks.ExportBackupFile()
	if err != nil {
		t.Fatal(err)
	}

	otherKs, err := keystore.New("mallory")
	if err != nil {
		t.Fatal(err)
	}
	otherWords, err := otherKs.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := keystore.ImportFromBackupFile(otherWords, data); err == nil {
		t.Fatal("ImportFromBackupFile: words of another identity accepted")
	}
}

func TestImportFromBackupFileUnrecognizedFormat(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte("BADMAGIC"), make([]byte, 20)...)
	if _, err := keystore.ImportFromBackupFile(words, bad); err == nil {
		t.Fatal("ImportFromBackupFile: unknown magic accepted")
	}
}

func TestImportFromBackupFileTooShort(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.ImportFromBackupFile(words, []byte("too short")); err == nil {
		t.Fatal("ImportFromBackupFile: too-short data accepted")
	}
}

// ── ImportFromMnemonic ───────────────────────────────────────────────────────

func TestImportFromMnemonicRoundtrip(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}

	got, err := keystore.ImportFromMnemonic(words, "alice-restored")
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice-restored" {
		t.Errorf("Username: want 'alice-restored', got %q", got.Username)
	}
	if !bytes.Equal(got.IdentityKey, ks.IdentityKey) {
		t.Error("ImportFromMnemonic: IdentityKey doesn't match the original")
	}
	if len(got.Contacts) != 0 {
		t.Error("ImportFromMnemonic: must not restore the contacts (that requires ImportFromBackupFile)")
	}
}

// ── ExportQR / ExportQRMulti / AssembleQRMulti ───────────────────────────────

func TestExportQRRoundtripSmallKeystore(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}

	data, err := ks.ExportQR()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("NTRINO02")) {
		t.Fatal("ExportQR: magic NTRINO02 missing")
	}
	if len(data) > 2953 {
		t.Fatalf("ExportQR: a %d-byte payload exceeds the single-QR limit for a minimal keystore", len(data))
	}

	got, err := keystore.ImportFromBackupFile(words, data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" {
		t.Errorf("Username: want 'alice', got %q", got.Username)
	}
	if !bytes.Equal(got.IdentityKey, ks.IdentityKey) {
		t.Error("ImportFromBackupFile on a QR export: IdentityKey doesn't match")
	}
}

func TestExportQRTooLarge(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks, 150)

	if _, err := ks.ExportQR(); !errors.Is(err, keystore.ErrQRTooLarge) {
		t.Fatalf("ExportQR: want ErrQRTooLarge, got %v", err)
	}
}

func TestExportQRMultiAndAssemble(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks, 150)

	chunks, err := ks.ExportQRMulti()
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("ExportQRMulti: want more than one chunk, got %d", len(chunks))
	}

	assembled, err := keystore.AssembleQRMulti(chunks)
	if err != nil {
		t.Fatal(err)
	}

	got, err := keystore.ImportFromBackupFile(words, assembled)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 150 {
		t.Fatalf("Contacts after reassembly: want 150, got %d", len(got.Contacts))
	}
}

func TestAssembleQRMultiOutOfOrder(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks, 150)

	chunks, err := ks.ExportQRMulti()
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 3 {
		t.Skip("at least 3 chunks are needed for a meaningful reordering test")
	}

	reversed := make([][]byte, len(chunks))
	for i, c := range chunks {
		reversed[len(chunks)-1-i] = c
	}

	assembled, err := keystore.AssembleQRMulti(reversed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keystore.ImportFromBackupFile(words, assembled)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Contacts) != 150 {
		t.Fatalf("Contacts after out-of-order reassembly: want 150, got %d", len(got.Contacts))
	}
}

func TestAssembleQRMultiNoChunks(t *testing.T) {
	if _, err := keystore.AssembleQRMulti(nil); err == nil {
		t.Fatal("AssembleQRMulti: no chunk given but no error")
	}
}

func TestAssembleQRMultiBadMagic(t *testing.T) {
	bad := [][]byte{[]byte("XXXX0100001122")}
	if _, err := keystore.AssembleQRMulti(bad); err == nil {
		t.Fatal("AssembleQRMulti: wrong magic accepted")
	}
}

func TestAssembleQRMultiCountMismatch(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks, 150)
	chunks, err := ks.ExportQRMulti()
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Skip("at least 2 chunks are needed")
	}
	if _, err := keystore.AssembleQRMulti(chunks[:len(chunks)-1]); err == nil {
		t.Fatal("AssembleQRMulti: chunk missing from the declared total not detected")
	}
}

func TestAssembleQRMultiDifferentSessionsRejected(t *testing.T) {
	ks1, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks1, 200)
	chunks1, err := ks1.ExportQRMulti()
	if err != nil {
		t.Fatal(err)
	}

	ks2, err := keystore.New("bob")
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks2, 200)
	chunks2, err := ks2.ExportQRMulti()
	if err != nil {
		t.Fatal(err)
	}

	if len(chunks1) != len(chunks2) || len(chunks1) < 2 {
		t.Skip("the two sessions didn't produce the same number of chunks in this run")
	}

	mixed := make([][]byte, len(chunks1))
	copy(mixed, chunks1)
	mixed[len(mixed)-1] = chunks2[len(chunks2)-1]

	if _, err := keystore.AssembleQRMulti(mixed); err == nil {
		t.Fatal("AssembleQRMulti: chunks from different sessions mixed without error")
	}
}

// TestAssembleQRMultiDifferentTotalRejected verifies that
// AssembleQRMulti checks that every chunk declares the same total, not
// just the same session_id: the total field of every OTHER chunk (byte
// 5 of the header, present on each one) must be compared against
// chunks[0]'s, not just used to size the output and validate "part". A
// single corrupted byte there must not go unnoticed, with the error
// surfacing only indirectly later (AES-GCM on the badly concatenated
// result).
func TestAssembleQRMultiDifferentTotalRejected(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	addManyContacts(t, ks, 200)
	chunks, err := ks.ExportQRMulti()
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Skip("the export didn't produce enough chunks in this run")
	}

	tampered := make([][]byte, len(chunks))
	copy(tampered, chunks)
	corrupted := append([]byte(nil), chunks[1]...)
	corrupted[5]++ // byte 5 = total declared by THIS chunk
	tampered[1] = corrupted

	if _, err := keystore.AssembleQRMulti(tampered); err == nil {
		t.Fatal("AssembleQRMulti: chunk with a total different from the others accepted without error")
	}
}

// ── ExportSync / ImportSync / ExportSyncQR(Multi) ────────────────────────────

func TestExportSyncImportSyncRoundtrip(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub})

	data, err := ks.ExportSync()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("NTRINO03")) {
		t.Fatal("ExportSync: magic NTRINO03 missing")
	}

	contacts, err := keystore.ImportSync(words, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 || contacts[0].Username != "bob" {
		t.Fatalf("ImportSync: unexpected contacts %+v", contacts)
	}
}

func TestImportSyncWrongWords(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	data, err := ks.ExportSync()
	if err != nil {
		t.Fatal(err)
	}

	otherKs, err := keystore.New("mallory")
	if err != nil {
		t.Fatal(err)
	}
	otherWords, err := otherKs.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := keystore.ImportSync(otherWords, data); err == nil {
		t.Fatal("ImportSync: words of another identity accepted")
	}
}

func TestImportSyncBadMagic(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte("BADMAGIC0"), make([]byte, 20)...)
	if _, err := keystore.ImportSync(words, bad); err == nil {
		t.Fatal("ImportSync: unknown magic accepted")
	}
}

func TestImportSyncTooShort(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.ImportSync(words, []byte("short")); err == nil {
		t.Fatal("ImportSync: too-short data accepted")
	}
}

func TestExportSyncQRRoundtripAndMulti(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	words, err := ks.Mnemonic()
	if err != nil {
		t.Fatal(err)
	}

	data, err := ks.ExportSyncQR()
	if err != nil {
		t.Fatal(err)
	}
	contacts, err := keystore.ImportSync(words, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 0 {
		t.Fatalf("want 0 contacts on an empty address book, got %d", len(contacts))
	}

	addManyContacts(t, ks, 150)
	if _, err := ks.ExportSyncQR(); !errors.Is(err, keystore.ErrSyncQRTooLarge) {
		t.Fatalf("ExportSyncQR: want ErrSyncQRTooLarge, got %v", err)
	}

	chunks, err := ks.ExportSyncQRMulti()
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("ExportSyncQRMulti: want more than one chunk, got %d", len(chunks))
	}
	assembled, err := keystore.AssembleQRMulti(chunks)
	if err != nil {
		t.Fatal(err)
	}
	gotContacts, err := keystore.ImportSync(words, assembled)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotContacts) != 150 {
		t.Fatalf("Contacts after reassembly: want 150, got %d", len(gotContacts))
	}
}

// ── MergeContacts ─────────────────────────────────────────────────────────────

func TestMergeContactsAddsNew(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)

	added, updated := ks.MergeContacts([]keystore.Contact{{Username: "bob", IdentityPub: pub}}, nil)
	if added != 1 || updated != 0 {
		t.Fatalf("want added=1 updated=0, got added=%d updated=%d", added, updated)
	}
	if len(ks.Contacts) != 1 {
		t.Fatalf("Contacts: want 1, got %d", len(ks.Contacts))
	}
}

func TestMergeContactsUpdatesLocalNameAndMLKEM(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub, Verified: true, MLKEMPub: []byte("OLD")})

	added, updated := ks.MergeContacts([]keystore.Contact{
		{Username: "bob", IdentityPub: pub, LocalName: "Bobby", MLKEMPub: []byte("NEW")},
	}, nil)
	if added != 0 || updated != 1 {
		t.Fatalf("want added=0 updated=1, got added=%d updated=%d", added, updated)
	}

	bob, ok := contactNamed(ks, "bob")
	if !ok {
		t.Fatal("bob not found after the merge")
	}
	if bob.LocalName != "Bobby" {
		t.Errorf("LocalName: want 'Bobby', got %q", bob.LocalName)
	}
	if string(bob.MLKEMPub) != "NEW" {
		t.Errorf("MLKEMPub: want 'NEW', got %q", bob.MLKEMPub)
	}
}

func TestMergeContactsEmptyIncomingFieldsDoNotOverwrite(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub, LocalName: "Roberto", MLKEMPub: []byte("ABCD")})

	added, updated := ks.MergeContacts([]keystore.Contact{
		{Username: "bob", IdentityPub: pub}, // LocalName and MLKEMPub empty in incoming
	}, nil)
	if added != 0 || updated != 0 {
		t.Fatalf("empty incoming fields must not overwrite: added=%d updated=%d", added, updated)
	}
	bob, _ := contactNamed(ks, "bob")
	if bob.LocalName != "Roberto" || string(bob.MLKEMPub) != "ABCD" {
		t.Errorf("existing fields unexpectedly overwritten: %+v", bob)
	}
}

func TestMergeContactsNoChangeWhenIdentical(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	rand.Read(pub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: pub, LocalName: "Bobby", MLKEMPub: []byte("ABCD")})

	added, updated := ks.MergeContacts([]keystore.Contact{
		{Username: "bob", IdentityPub: pub, LocalName: "Bobby", MLKEMPub: []byte("ABCD")},
	}, nil)
	if added != 0 || updated != 0 {
		t.Fatalf("incoming values identical to the existing ones: want added=0 updated=0, got added=%d updated=%d", added, updated)
	}
}

// ── Sibling revocation pool ──────────────────────────────────────────────────

// TestMergeContactsExtractsSiblingRevocationFromDevicesNewContact verifies
// that a revocation carried in the OWN relationship of the sibling
// device that sent the sync (incDevices) ends up in the contact's
// SiblingRevocations pool, correctly attributed to fromDevicePub,
// while Devices itself stays nil (private keys are never inherited).
func TestMergeContactsExtractsSiblingRevocationFromDevicesNewContact(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	bobPub := make([]byte, 32)
	rand.Read(bobPub)
	peerDevicePub := make([]byte, 32)
	rand.Read(peerDevicePub)
	siblingDevicePub := make([]byte, 32)
	rand.Read(siblingDevicePub)

	incoming := []keystore.Contact{{
		Username:    "bob",
		IdentityPub: bobPub,
		Devices: map[string]*keystore.DeviceRelation{
			string(peerDevicePub): {
				RevokeIdentitySig: []byte("identity-sig"),
				RevokeContentSig:  []byte("content-sig"),
			},
		},
	}}

	added, _ := ks.MergeContacts(incoming, siblingDevicePub)
	if added != 1 {
		t.Fatalf("added: want 1, got %d", added)
	}
	bob, ok := contactNamed(ks, "bob")
	if !ok {
		t.Fatal("bob not found after the merge")
	}
	if bob.Devices != nil {
		t.Error("Devices must never be inherited for a new contact")
	}
	key := string(siblingDevicePub) + string(peerDevicePub)
	sr, ok := bob.SiblingRevocations[key]
	if !ok {
		t.Fatal("SiblingRevocations not populated for the new contact")
	}
	if string(sr.IdentitySig) != "identity-sig" || string(sr.ContentSig) != "content-sig" {
		t.Errorf("unexpected signatures in the pool: %+v", sr)
	}
	if !bytes.Equal(sr.SiblingDevicePub, siblingDevicePub) || !bytes.Equal(sr.PeerDevicePub, peerDevicePub) {
		t.Errorf("wrong device attribution: %+v", sr)
	}
}

// TestMergeContactsExtractsSiblingRevocationForExistingContact verifies
// that the same mechanism also applies to a contact ALREADY known
// locally, a later update (a sibling's rotation) must propagate there
// too, not just on first encounter.
func TestMergeContactsExtractsSiblingRevocationForExistingContact(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	bobPub := make([]byte, 32)
	rand.Read(bobPub)
	peerDevicePub := make([]byte, 32)
	rand.Read(peerDevicePub)
	siblingDevicePub := make([]byte, 32)
	rand.Read(siblingDevicePub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: bobPub})

	incoming := []keystore.Contact{{
		Username:    "bob",
		IdentityPub: bobPub,
		Devices: map[string]*keystore.DeviceRelation{
			string(peerDevicePub): {RevokeIdentitySig: []byte("identity-sig")},
		},
	}}
	ks.MergeContacts(incoming, siblingDevicePub)

	bob, _ := contactNamed(ks, "bob")
	key := string(siblingDevicePub) + string(peerDevicePub)
	if _, ok := bob.SiblingRevocations[key]; !ok {
		t.Fatal("SiblingRevocations not populated for an already-known contact")
	}
}

// TestMergeContactsSiblingRevocationAckNeverRegresses verifies that a
// later round with Acked=true must never regress, and a version
// lacking the signature must never erase an already-known one.
func TestMergeContactsSiblingRevocationAckNeverRegresses(t *testing.T) {
	ks, err := keystore.New("alice")
	if err != nil {
		t.Fatal(err)
	}
	bobPub := make([]byte, 32)
	rand.Read(bobPub)
	peerDevicePub := make([]byte, 32)
	rand.Read(peerDevicePub)
	siblingDevicePub := make([]byte, 32)
	rand.Read(siblingDevicePub)
	ks.AddContact(keystore.Contact{Username: "bob", IdentityPub: bobPub})

	// Round 1: the revocation arrives directly from the sibling that generated it.
	ks.MergeContacts([]keystore.Contact{{
		Username:    "bob",
		IdentityPub: bobPub,
		Devices: map[string]*keystore.DeviceRelation{
			string(peerDevicePub): {RevokeIdentitySig: []byte("identity-sig")},
		},
	}}, siblingDevicePub)

	// Round 2: a THIRD sibling relays the same entry, now with the ack.
	ks.MergeContacts([]keystore.Contact{{
		Username:    "bob",
		IdentityPub: bobPub,
		SiblingRevocations: map[string]*keystore.SiblingRevocation{
			string(siblingDevicePub) + string(peerDevicePub): {
				SiblingDevicePub: siblingDevicePub,
				PeerDevicePub:   peerDevicePub,
				Acked:           true,
			},
		},
	}}, nil)

	bob, _ := contactNamed(ks, "bob")
	key := string(siblingDevicePub) + string(peerDevicePub)
	sr := bob.SiblingRevocations[key]
	if sr == nil {
		t.Fatal("pool entry gone after the second round")
	}
	if !sr.Acked {
		t.Error("Acked not propagated by the second round")
	}
	if string(sr.IdentitySig) != "identity-sig" {
		t.Error("the already-known signature must not disappear when a later round arrives without it")
	}
}
