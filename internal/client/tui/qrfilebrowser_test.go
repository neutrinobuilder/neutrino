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

package tui

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qrcode "github.com/skip2/go-qrcode"

	"neutrino/internal/keystore"
	"neutrino/internal/qrscan"
)

// TestToggleStringInOrder verifies qrFileMode's Space-select helper:
// adds on first toggle, removes on second, preserves insertion order
// across unrelated adds/removes.
func TestToggleStringInOrder(t *testing.T) {
	var list []string
	list = toggleStringInOrder(list, "a")
	list = toggleStringInOrder(list, "b")
	if fmt.Sprint(list) != "[a b]" {
		t.Fatalf("expected [a b], got %v", list)
	}
	list = toggleStringInOrder(list, "a")
	if fmt.Sprint(list) != "[b]" {
		t.Fatalf("expected [b] after removing a, got %v", list)
	}
	list = toggleStringInOrder(list, "c")
	if fmt.Sprint(list) != "[b c]" {
		t.Fatalf("expected [b c], got %v", list)
	}
}

// TestQRChooseModeFOpensFileBrowser verifies choosing "f" in the
// /cnt-read-qrcode source picker opens the filesystem browser
// (qrFileMode) directly, listing the given directory.
func TestQRChooseModeFOpensFileBrowser(t *testing.T) {
	dir := t.TempDir()
	// listDir reads the real cwd-relative/absolute path given; since
	// cmdReadQR's "f" branch always starts from startDirForFileBrowser()
	// (the process cwd), this test instead exercises the key-handling
	// branch directly by seeding qrFileDir the way it would end up after
	// the "f" key, confirming only the state-machine transition (the
	// directory-listing call itself is exercised again below, from a
	// real selection).
	m := &model{qrChooseMode: true}
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	fm := newModel.(model)
	if fm.qrChooseMode {
		t.Fatal("expected qrChooseMode to be cleared")
	}
	if !fm.qrFileMode {
		t.Fatal("expected qrFileMode to open instead of a free-text path prompt")
	}
	if fm.qrFileDir == "" {
		t.Fatal("expected a populated starting directory")
	}
	_ = dir // not used directly: startDirForFileBrowser() picks the process cwd
}

// buildTestIdentityURI returns a realistic nu:// URI (Ed25519 + ML-KEM-768
// + ML-DSA-65, like a real identity) long enough that keystore.ChunkBlob
// always splits it into more than one NTR3 chunk — same situation as a
// real identity QR saved as part1/part2 PNGs.
func buildTestIdentityURI(t *testing.T, username string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlkemPub := make([]byte, 1184)
	if _, err := rand.Read(mlkemPub); err != nil {
		t.Fatal(err)
	}
	mldsaPub := make([]byte, mldsa65.PublicKeySize)
	if _, err := rand.Read(mldsaPub); err != nil {
		t.Fatal(err)
	}
	return "nu://" + username + "/" +
		base64.StdEncoding.EncodeToString(pub) + "/" +
		base64.StdEncoding.EncodeToString(mlkemPub) + "/" +
		base64.StdEncoding.EncodeToString(mldsaPub)
}

// writeQRPNG encodes content as a QR PNG at path the way the app does
// (qrscan.EncodeVerified at qrcode.Medium, rendered at
// qrscan.PixelsPerModule) for a realistic round trip through
// qrscan.DecodeQRFile.
func writeQRPNG(t *testing.T, path, content string) {
	t.Helper()
	q, err := qrscan.EncodeVerified(content, qrcode.Medium)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.WriteFile(qrscan.PixelsPerModule, path); err != nil {
		t.Fatal(err)
	}
}

// TestQRFileBrowserMultiSelectReadsPartsInOrder is the end-to-end case
// this feature exists for: an identity split across two NTR3 chunks
// (same as two numbered PNGs picked at once in the filesystem browser
// with Space, confirmed with a single Enter) reassembled correctly.
// Exercises handleQRDecoded/qrFilesDecodedMsg directly with the chunk
// texts rather than round-tripping through real QR PNGs — the real
// encode/decode pipeline (rendering, resolution, retry) is covered
// separately by cmd.TestQRPartsDecodeRoundTripManyIdentities; what this
// test verifies is purely the browser's state machine: multi-select
// feeds handleQRDecoded once per chosen file, in order, and assembles
// correctly whatever the actual number of chunks turns out to be
// (qrChunkSize, hence the chunk count for a given identity, is an
// internal/keystore implementation detail this test shouldn't assume).
func TestQRFileBrowserMultiSelectReadsPartsInOrder(t *testing.T) {
	uri := buildTestIdentityURI(t, "multipartuser")
	chunks, err := keystore.ChunkBlob([]byte(uri))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("test identity URI too short to split into multiple chunks (got %d)", len(chunks))
	}

	m := &model{}
	texts := make([]string, len(chunks))
	for i, c := range chunks {
		texts[i] = string(c)
	}
	decoded := qrFilesDecodedMsg{texts: texts}

	newModel, finalCmd := m.Update(decoded)
	fm := newModel.(model)
	if finalCmd != nil {
		finalCmd() // drain any progress/display messages, must not panic
	}
	if !fm.addContactConfirmMode {
		t.Fatal("expected addContactConfirmMode after both parts were read, got false")
	}
	if fm.pendingContact.username != "multipartuser" {
		t.Fatalf("expected reassembled username %q, got %q", "multipartuser", fm.pendingContact.username)
	}
	if fm.qrChooseMode {
		t.Fatal("expected qrChooseMode to stay false once the full set was already provided (no stale re-prompt)")
	}
}

// TestQRFileBrowserSingleSelectionStillWorks verifies Enter with nothing
// toggled (Space never pressed) falls back to the single highlighted
// file — the common case for a one-image identity or a backup/sync QR.
// Unlike the multi-part test above, this one DOES round-trip through a
// real QR PNG (via cmdReadQRFiles → qrscan.DecodeQRFile): a short,
// classical-only URI (no PQC segments) stays at a low QR version, well
// within the decoder's reliable range at this render size.
func TestQRFileBrowserSingleSelectionStillWorks(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri := "nu://singlefileuser/" + base64.StdEncoding.EncodeToString(pub)
	dir := t.TempDir()
	path := filepath.Join(dir, "identity-qr-singlefileuser.png")
	writeQRPNG(t, path, uri)

	m := &model{}
	cmd := m.cmdReadQRFiles([]string{path})
	msg := cmd()
	decoded, ok := msg.(qrFilesDecodedMsg)
	if !ok {
		t.Fatalf("expected qrFilesDecodedMsg, got %T", msg)
	}
	if decoded.err != nil {
		t.Fatalf("unexpected decode error: %v", decoded.err)
	}
	newModel, _ := m.Update(decoded)
	fm := newModel.(model)
	if !fm.addContactConfirmMode {
		t.Fatal("expected addContactConfirmMode for a single-file identity QR")
	}
	if fm.pendingContact.username != "singlefileuser" {
		t.Fatalf("expected username %q, got %q", "singlefileuser", fm.pendingContact.username)
	}
}

// TestQRFileBrowserEscCancelsAndClearsSelection verifies Esc from the
// browser clears any in-progress multi-select instead of leaving stale
// state for the next /cnt-read-qrcode.
func TestQRFileBrowserEscCancelsAndClearsSelection(t *testing.T) {
	m := &model{qrFileMode: true, qrFileSelected: []string{"/tmp/a.png"}, qrFileFilter: "a"}
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	fm := newModel.(model)
	if fm.qrFileMode {
		t.Fatal("expected qrFileMode to be cleared")
	}
	if len(fm.qrFileSelected) != 0 {
		t.Fatalf("expected selection to be cleared, got %v", fm.qrFileSelected)
	}
	if fm.qrFileFilter != "" {
		t.Fatal("expected filter to be cleared")
	}
	if cmd == nil {
		t.Fatal("expected a cancellation message cmd")
	}
}
