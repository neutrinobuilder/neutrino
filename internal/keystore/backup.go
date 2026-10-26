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
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"

	"neutrino/internal/i18n"
)

const (
	backupMagic   = "NTRINO01" // uncompressed backup file
	exportQRMagic = "NTRINO02" // single QR export (gzip)
	exportQRMulti = "NTR3"     // multi-QR export chunk: 4B magic + 1B part + 1B total + 4B session_id + data
	syncMagic     = "NTRINO03" // contact list sync (contacts only, gzip)
	// qrChunkSize stays well below the 2331-byte maximum at level M: near
	// the maximum QR version gozxing's detector fails on ~5-10% of valid
	// renders (mask-dependent), and qrscan.EncodeVerified's
	// self-verify-and-retry needs higher versions left to try. At 1500 a
	// full identity splits into 3 chunks around version 31, leaving ~9
	// versions of retry headroom.
	qrChunkSize = 1500
)

// Mnemonic returns the 24 BIP-39 words that encode the identity key.
// The seed (first 32 bytes of the Ed25519 key) → 24 BIP-39 words.
// The words never change as long as the key doesn't rotate.
func (ks *Keystore) Mnemonic() ([]string, error) {
	if len(ks.IdentityKey) < 32 {
		return nil, errors.New(i18n.T("keystore.err_invalid_identity_key"))
	}
	seed := ks.IdentityKey[:32]
	m, err := bip39.NewMnemonic(seed)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_bip39_encode", err))
	}
	return strings.Fields(m), nil
}

// SeedFromMnemonic decodes 24 BIP-39 words → a 32-byte seed.
func SeedFromMnemonic(words []string) ([]byte, error) {
	seed, err := bip39.EntropyFromMnemonic(strings.Join(words, " "))
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_invalid_words", err))
	}
	if len(seed) != 32 {
		return nil, errors.New(i18n.T("keystore.err_seed_length", len(seed)))
	}
	return seed, nil
}

// ExportBackupFile encrypts the whole keystore with a key derived from
// the BIP-39 seed.
// Binary format: magic[8] | nonce[12] | AES-256-GCM(json(keystore))
// The file is useless without the 24 words, it doesn't contain the encryption key.
func (ks *Keystore) ExportBackupFile() ([]byte, error) {
	if len(ks.IdentityKey) < 32 {
		return nil, errors.New(i18n.T("keystore.err_invalid_identity_key"))
	}
	seed := ks.IdentityKey[:32]

	plain, err := json.Marshal(ks)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_marshal", err))
	}

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, nil, []byte("neutrino-backup-v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New(i18n.T("keystore.err_hkdf", err))
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New(i18n.T("keystore.err_nonce", err))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(backupMagic)+12+len(plain)+gcm.Overhead())
	out = append(out, backupMagic...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, nil)
	return out, nil
}

// ImportFromMnemonic creates a minimal keystore (identity only) from
// the 24 BIP-39 words. Restores the .onion address but not the
// contacts, use ImportFromBackupFile for a full restore.
//
// The durable ML-KEM-768 key CANNOT be reconstructed from the BIP-39
// seed (which encodes only the Ed25519 seed, never extended to cover
// ML-KEM too), it's generated fresh, always new on every restore from
// just the 24 words. A "bare" restore from just the 24 words starts over
// from scratch anyway, with no existing contacts it could fall out of
// sync with.
func ImportFromMnemonic(words []string, username string) (*Keystore, error) {
	seed, err := SeedFromMnemonic(words)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_mlkem_key", err))
	}
	return &Keystore{
		Version:     version,
		Username:    username,
		IdentityKey: []byte(priv),
		MLKEMKey:    mlkemDK.Bytes(),
	}, nil
}

// encryptCompressed encrypts the keystore's JSON with gzip+AES-256-GCM.
// Returns bytes in the NTRINO02 format.
func (ks *Keystore) encryptCompressed() ([]byte, error) {
	if len(ks.IdentityKey) < 32 {
		return nil, errors.New(i18n.T("keystore.err_invalid_identity_key"))
	}
	seed := ks.IdentityKey[:32]

	plain, err := json.Marshal(ks)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_marshal", err))
	}

	// gzip compression
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		return nil, errors.New(i18n.T("keystore.err_gzip", err))
	}
	gz.Close()
	compressed := buf.Bytes()

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, nil, []byte("neutrino-backup-v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New(i18n.T("keystore.err_hkdf", err))
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New(i18n.T("keystore.err_nonce", err))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(exportQRMagic)+12+len(compressed)+gcm.Overhead())
	out = append(out, exportQRMagic...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, compressed, nil)
	return out, nil
}

// ExportQR encrypts the keystore with gzip+AES-256-GCM optimized for a
// single QR. Returns ErrQRTooLarge if the payload exceeds 2953 bytes
// (max QR level L capacity). In that case use ExportQRMulti to get
// multiple chunks.
// The text is an internal identifier for errors.Is, never shown to the
// user (callers print a dedicated i18n message when they intercept this
// sentinel): it must not be evaluated with i18n.T here, or it would
// freeze at the language active at init().
var ErrQRTooLarge = errors.New("qr too large")

func (ks *Keystore) ExportQR() ([]byte, error) {
	data, err := ks.encryptCompressed()
	if err != nil {
		return nil, err
	}
	if len(data) > 2953 {
		return nil, ErrQRTooLarge
	}
	return data, nil
}

// ExportQRAnimated returns the same encrypted payload as ExportQR,
// without the 2953-byte limit of a single QR frame, meant for transfer
// via animated QR (fountain code, internal/qroptical), which has no
// per-frame size constraint. An additional mode alongside
// ExportQR/ExportQRMulti, not a replacement for them: the caller decides
// which to use.
func (ks *Keystore) ExportQRAnimated() ([]byte, error) {
	return ks.encryptCompressed()
}

// ExportQRMulti splits the encrypted payload into chunks ready for
// multiple QR codes.
// Each chunk: "NTR3"(4B) + part(1B) + total(1B) + session_id(4B) + data(≤qrChunkSize B)
// The receiver reassembles the chunks in order and decrypts as a single QR.
func (ks *Keystore) ExportQRMulti() ([][]byte, error) {
	data, err := ks.encryptCompressed()
	if err != nil {
		return nil, err
	}
	return ChunkBlob(data)
}

// ChunkBlob splits data into NTR3 chunks for multiple QR codes,
// format-agnostic, doesn't require data to be an encrypted
// keystore/contact list: also reused for the identity URI when it
// exceeds a single QR's capacity, exactly as it already does for
// backup/sync above.
//
// Bytes are spread EVENLY across the chunks, not greedily filled
// chunk-by-chunk: with an uneven split, the leading chunks sit pinned at
// qrChunkSize, the exact ceiling of level M's per-frame capacity, every
// time, landing on the highest QR version that capacity allows. Measured
// directly (encode a chunk at that size, decode it back immediately, no
// corruption/recompression involved): roughly 1 in 10 otherwise-valid
// renders at that version fails to decode at all, a gozxing detection
// limitation at near-maximum versions, not a rendering or error-
// correction margin problem (Medium's own ~15% redundancy is unused
// here, there's no damage to recover from). An even split keeps `total`
// identical to a greedy split (it never raises or lowers how many QR
// images data needs) while keeping every chunk
// comfortably under that ceiling, moving every one of them off the
// highest-risk version band.
func ChunkBlob(data []byte) ([][]byte, error) {
	sessionID := make([]byte, 4)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, errors.New(i18n.T("keystore.err_session_id", err))
	}

	total := (len(data) + qrChunkSize - 1) / qrChunkSize
	if total > 255 {
		return nil, errors.New(i18n.T("keystore.err_data_too_large"))
	}
	// Ceiling of an even split, never exceeds qrChunkSize, since total
	// was already computed as the ceiling of len(data)/qrChunkSize.
	chunkSize := qrChunkSize
	if total > 0 {
		chunkSize = (len(data) + total - 1) / total
	}

	chunks := make([][]byte, total)
	for i := range total {
		start := i * chunkSize
		end := min(start+chunkSize, len(data))
		payload := data[start:end]
		chunk := make([]byte, 0, 10+len(payload))
		chunk = append(chunk, exportQRMulti...)
		chunk = append(chunk, byte(i), byte(total))
		chunk = append(chunk, sessionID...)
		chunk = append(chunk, payload...)
		chunks[i] = chunk
	}
	return chunks, nil
}

// ── sync QR ───────────────────────────────────────────────────────────────────

// ErrSyncQRTooLarge is returned by ExportSyncQR when the encrypted
// contact list exceeds a single QR's 2953-byte capacity (level L). Use
// ExportSyncQRMulti. Same reason as ErrQRTooLarge: only for errors.Is,
// never shown to the user.
var ErrSyncQRTooLarge = errors.New("sync qr too large")

// ExportSyncQR returns the encrypted NTRINO03 bytes ready for a single
// QR. Returns ErrSyncQRTooLarge if the payload exceeds 2953 bytes.
func (ks *Keystore) ExportSyncQR() ([]byte, error) {
	data, err := ks.ExportSync()
	if err != nil {
		return nil, err
	}
	if len(data) > 2953 {
		return nil, ErrSyncQRTooLarge
	}
	return data, nil
}

// ExportSyncQRMulti splits the encrypted contact list into NTR3 chunks
// ready for multiple QR codes.
// Same structure as ExportQRMulti; AssembleQRMulti reassembles the NTRINO03 blob.
func (ks *Keystore) ExportSyncQRMulti() ([][]byte, error) {
	data, err := ks.ExportSync()
	if err != nil {
		return nil, err
	}
	return ChunkBlob(data)
}

// IsMultiQRChunk reports whether data is a single chunk of the NTR3
// format (ChunkBlob/AssembleQRMulti) instead of a complete single-frame
// QR content, used by the caller to decide whether to accumulate more
// scans before proceeding (e.g. reading an identity URI) instead of
// treating the content as already complete.
func IsMultiQRChunk(data []byte) bool {
	return len(data) >= 4 && string(data[:4]) == exportQRMulti
}

// QRMultiPartTotal reads part/total from an NTR3 chunk's header (already
// verified with IsMultiQRChunk), (0, 0, false) if the chunk is malformed.
func QRMultiPartTotal(data []byte) (part, total int, ok bool) {
	if len(data) < 10 || string(data[:4]) != exportQRMulti {
		return 0, 0, false
	}
	return int(data[4]), int(data[5]), true
}

// AssembleQRMulti reassembles multi-QR chunks into the original
// encrypted blob.
// Each chunk must have the format produced by ExportQRMulti.
// Chunks can be passed in any order; they're reordered internally.
func AssembleQRMulti(chunks [][]byte) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, errors.New(i18n.T("keystore.err_no_chunks"))
	}
	const hdrLen = 10 // "NTR3"(4) + part(1) + total(1) + session_id(4)
	for _, c := range chunks {
		if len(c) < hdrLen || string(c[:4]) != exportQRMulti {
			return nil, errors.New(i18n.T("keystore.err_chunk_bad_magic"))
		}
	}
	total := int(chunks[0][5])
	sessionID := chunks[0][6:10]
	if len(chunks) != total {
		return nil, errors.New(i18n.T("keystore.err_chunk_count_mismatch", total, len(chunks)))
	}
	ordered := make([][]byte, total)
	for _, c := range chunks {
		part := int(c[4])
		if part >= total {
			return nil, errors.New(i18n.T("keystore.err_chunk_out_of_range", part, total))
		}
		// Every chunk carries its own total field (byte 5), only
		// chunks[0]'s is used above to size ordered/validate part;
		// without this check a chunk with a different total (corrupted,
		// or swapped in from another session with a matching
		// session_id by coincidence) would go unnoticed here, the
		// error would only surface later, indirectly, from AES-GCM
		// failing on the badly concatenated result, instead of a direct
		// message here.
		if chunkTotal := int(c[5]); chunkTotal != total {
			return nil, errors.New(i18n.T("keystore.err_chunk_diff_total", part, chunkTotal, total))
		}
		if string(c[6:10]) != string(sessionID) {
			return nil, errors.New(i18n.T("keystore.err_chunk_diff_session"))
		}
		ordered[part] = c[hdrLen:]
	}
	var out []byte
	for _, payload := range ordered {
		out = append(out, payload...)
	}
	return out, nil
}

// ImportFromBackupFile decrypts a backup file (NTRINO01) or QR export
// (NTRINO02) using the seed derived from the 24 BIP-39 words.
// Restores the full keystore: identity, contacts, groups.
func ImportFromBackupFile(words []string, data []byte) (*Keystore, error) {
	seed, err := SeedFromMnemonic(words)
	if err != nil {
		return nil, err
	}
	if len(data) < 8+12 {
		return nil, errors.New(i18n.T("keystore.err_file_too_short"))
	}

	magic := string(data[:8])
	compressed := false
	switch magic {
	case backupMagic:
		// standard uncompressed format
	case exportQRMagic:
		compressed = true
	default:
		return nil, errors.New(i18n.T("keystore.err_format_unrecognized"))
	}

	nonce := data[8:20]
	ct := data[20:]

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, nil, []byte("neutrino-backup-v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New(i18n.T("keystore.err_hkdf", err))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_wrong_words"))
	}

	if compressed {
		gr, err := gzip.NewReader(bytes.NewReader(plain))
		if err != nil {
			return nil, errors.New(i18n.T("keystore.err_gzip_decompress", err))
		}
		plain, err = io.ReadAll(gr)
		if err != nil {
			return nil, errors.New(i18n.T("keystore.err_gzip_read", err))
		}
	}

	var ks Keystore
	if err := json.Unmarshal(plain, &ks); err != nil {
		return nil, errors.New(i18n.T("keystore.err_parse_json", err))
	}

	// This restore (24 words + file) is the BIRTH of an additional
	// device, unlike ImportFromMnemonic (just the 24 words, the total
	// disaster path, never touched here), here the file carries a
	// DeviceID/DevicePriv/DevicePub that belong to the backup's ORIGIN
	// device, never to this one: without regenerating them, two devices
	// would end up sharing the same DeviceID (duplicate device identity,
	// contrary to "one file = one device") and colliding on the same
	// derived network address (NetworkIdentityPrivKey). Regenerated
	// ALWAYS, unconditionally: even a restore done on the exact same
	// origin device (e.g. after a reinstall) is still a "new" device
	// from the keystore file's point of view.
	deviceID := make([]byte, 16)
	if _, err := rand.Read(deviceID); err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_device_id", err))
	}
	_, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gen_device_key", err))
	}
	ks.DeviceID = deviceID
	ks.DevicePriv = []byte(devicePriv)
	ks.DevicePub = []byte(devicePriv.Public().(ed25519.PublicKey))
	ks.AdditionalDevice = true

	// Already-confirmed relationship keys must NOT be cloned from the
	// backup, without this zeroing, an additional device would be born
	// cryptographically indistinguishable from the origin device toward
	// every already-confirmed contact: whoever obtains the 24 words PLUS
	// the backup file (legitimate or stolen, the two situations aren't
	// distinguishable) would silently inherit already-established trust,
	// never passing through the TrustDanger gate. The additional device
	// must renegotiate its relationship with each contact from scratch,
	// exactly like a new device meeting it for the first time, the
	// periodic probe cycle already generates the missing keys on the fly
	// and resends a rel_init, no additional action required here. There
	// is a priori no way to know whether the origin device is broken,
	// lost, stolen, or the user simply wants a second device, none of
	// these hypotheses is assumed: every contact starts from a blank
	// slate, uniformly.
	// Zeroing empties the whole Devices map of each contact, an
	// additional device never
	// inherits an entry already negotiated by another device.
	for i := range ks.Contacts {
		c := &ks.Contacts[i]
		c.Devices = nil
		c.Verified = false
		c.KnownDevicePub = nil
	}

	return &ks, nil
}

// ── contact list sync ────────────────────────────────────────────────────────

// MergeContacts merges incoming into the keystore's contact list.
// Deduplication by IdentityPub (the contact's unique key).
// For duplicate entries: Username from the protocol is always equal;
// LocalName: the non-empty value is preferred,
// incoming wins on conflict (more recent source device).
//
// fromDevicePub identifies the SIBLING device that produced incoming
// (32 bytes, Keystore.DevicePub, not DeviceID: it's the value that
// ends up in a future RelRevokePayload's DevicePub field if this
// sibling has to resend the revocation), used to correctly attribute
// every self-revocation certificate found in incoming[i].Devices to the
// Contact.SiblingRevocations pool (see mergeSiblingRevocationsLocked
// below). Empty for a source that carries no device identifier (e.g.
// manual sync via file/QR, NTRINO03/ImportSync, no revocation is
// attributed in that case: that format carries no Device wrapper).
func (ks *Keystore) MergeContacts(incoming []Contact, fromDevicePub []byte) (added, updated int) {
	for _, inc := range incoming {
		incDevices := inc.Devices
		incSiblingRevocations := inc.SiblingRevocations
		found := false
		idx := -1
		for i, ex := range ks.Contacts {
			if string(ex.IdentityPub) == string(inc.IdentityPub) {
				found = true
				idx = i
				changed := false
				if inc.LocalName != "" && inc.LocalName != ex.LocalName {
					ks.Contacts[i].LocalName = inc.LocalName
					changed = true
				}
				if len(inc.MLKEMPub) > 0 && string(inc.MLKEMPub) != string(ex.MLKEMPub) {
					ks.Contacts[i].MLKEMPub = inc.MLKEMPub
					changed = true
				}
				if changed {
					updated++
				}
				break
			}
		}
		if !found {
			// Same as ImportFromBackupFile: a contact synced from
			// ANOTHER device of the same identity never inherits
			// relationship keys or trust state already negotiated by
			// that device, this device must negotiate them itself
			// (rel_init) and verify them itself.
			inc.Devices = nil
			inc.SiblingRevocations = nil
			inc.Verified = false
			inc.KnownDevicePub = nil
			ks.Contacts = append(ks.Contacts, inc)
			idx = len(ks.Contacts) - 1
			added++
		}
		ks.mergeSiblingRevocationsLocked(idx, fromDevicePub, incDevices, incSiblingRevocations)
	}
	return
}

// mergeSiblingRevocationsLocked merges into the local contact's pool
// (index idx in ks.Contacts) the sibling device revocations found in
// incoming, both the DIRECT ones (incDevices, the sending sibling
// device's OWN relationship, attributed to fromDevicePub) and the ones
// already RELAYED transitively from other siblings
// (incSiblingRevocations, propagated along with the rest of the contact
// list), never a private key, only ready-made signatures. Called by
// MergeContacts both for a new contact and for an already-known one: a
// later update (a sibling's new rotation, or an ack that arrived in the
// meantime) must also propagate to an already-present contact, not just
// on first encounter.
func (ks *Keystore) mergeSiblingRevocationsLocked(idx int, fromDevicePub []byte, incDevices map[string]*DeviceRelation, incSiblingRevocations map[string]*SiblingRevocation) {
	if idx < 0 || idx >= len(ks.Contacts) {
		return
	}
	c := &ks.Contacts[idx]
	upsert := func(sr SiblingRevocation) {
		// Doesn't require a non-empty signature: a relay can propagate
		// just an ack (Acked=true) for an entry already known elsewhere,
		// without resending the signatures every time, the merge below
		// still preserves the already-known ones. Only requires a valid
		// device identity on both sides of the pair, otherwise the entry
		// isn't indexable.
		if len(sr.SiblingDevicePub) == 0 || len(sr.PeerDevicePub) == 0 {
			return
		}
		if c.SiblingRevocations == nil {
			c.SiblingRevocations = make(map[string]*SiblingRevocation)
		}
		key := string(sr.SiblingDevicePub) + string(sr.PeerDevicePub)
		if existing, ok := c.SiblingRevocations[key]; ok {
			// Never lose an already-known signature for a version
			// lacking that field arriving in a later round, nor ever
			// regress an already-true Acked back to false.
			if len(sr.IdentitySig) == 0 {
				sr.IdentitySig, sr.IdentitySigMLDSA = existing.IdentitySig, existing.IdentitySigMLDSA
			}
			if len(sr.ContentSig) == 0 {
				sr.ContentSig, sr.ContentSigMLDSA = existing.ContentSig, existing.ContentSigMLDSA
			}
			sr.Acked = sr.Acked || existing.Acked
		}
		c.SiblingRevocations[key] = &sr
	}

	if len(fromDevicePub) > 0 {
		for peerDevicePubStr, dev := range incDevices {
			if dev == nil || (len(dev.RevokeIdentitySig) == 0 && len(dev.RevokeContentSig) == 0) {
				continue
			}
			upsert(SiblingRevocation{
				SiblingDevicePub: append([]byte(nil), fromDevicePub...),
				PeerDevicePub:    []byte(peerDevicePubStr),
				IdentitySig:      dev.RevokeIdentitySig,
				IdentitySigMLDSA: dev.RevokeIdentitySigMLDSA,
				ContentSig:       dev.RevokeContentSig,
				ContentSigMLDSA:  dev.RevokeContentSigMLDSA,
			})
		}
	}
	for _, sr := range incSiblingRevocations {
		if sr == nil {
			continue
		}
		upsert(*sr)
	}
}

// ExportSync encrypts only the contact list (no identity key) for
// syncing between devices.
// Format: "NTRINO03" + nonce[12] + AES-256-GCM(gzip(json([]Contact)))
// Same key derived from the BIP-39 seed: both devices share the same backup key.
func (ks *Keystore) ExportSync() ([]byte, error) {
	if len(ks.IdentityKey) < 32 {
		return nil, errors.New(i18n.T("keystore.err_invalid_identity_key"))
	}
	seed := ks.IdentityKey[:32]

	plain, err := json.Marshal(ks.Contacts)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_marshal", err))
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		return nil, errors.New(i18n.T("keystore.err_gzip", err))
	}
	gz.Close()

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, nil, []byte("neutrino-sync-v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New(i18n.T("keystore.err_hkdf", err))
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New(i18n.T("keystore.err_nonce", err))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(syncMagic)+12+buf.Len()+gcm.Overhead())
	out = append(out, syncMagic...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, buf.Bytes(), nil)
	return out, nil
}

// ImportSync decrypts a sync file and returns the plaintext contact
// list. The caller decides whether and how to merge it with the
// existing contact list (via MergeContacts).
func ImportSync(words []string, data []byte) ([]Contact, error) {
	seed, err := SeedFromMnemonic(words)
	if err != nil {
		return nil, err
	}
	if len(data) < len(syncMagic)+12 {
		return nil, errors.New(i18n.T("keystore.err_sync_file_too_short"))
	}
	if string(data[:len(syncMagic)]) != syncMagic {
		return nil, errors.New(i18n.T("keystore.err_sync_format"))
	}

	nonce := data[len(syncMagic) : len(syncMagic)+12]
	ct := data[len(syncMagic)+12:]

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, seed, nil, []byte("neutrino-sync-v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.New(i18n.T("keystore.err_hkdf", err))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_wrong_words"))
	}

	gr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gzip", err))
	}
	decompressed, err := io.ReadAll(gr)
	if err != nil {
		return nil, errors.New(i18n.T("keystore.err_gzip_read", err))
	}

	var contacts []Contact
	if err := json.Unmarshal(decompressed, &contacts); err != nil {
		return nil, errors.New(i18n.T("keystore.err_parse_json", err))
	}
	return contacts, nil
}
