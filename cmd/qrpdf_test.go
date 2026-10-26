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

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"neutrino/internal/qrscan"
)

// TestPrintAndSaveQRGeneratesPDF verifies that saving an identity QR
// also produces a PDF alongside the .txt/.png files, one page with the
// plain URI text, one page per QR part image.
func TestPrintAndSaveQRGeneratesPDF(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlkem := make([]byte, 1184)
	mldsa := make([]byte, 1952)
	if _, err := rand.Read(mlkem); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(mldsa); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	qrPath := dir + "/identity-qr-testuser.png"
	if err := printAndSaveQR("testuser", pub, mlkem, mldsa, qrPath, false); err != nil {
		t.Fatal(err)
	}

	pdfPath := dir + "/identity-qr-testuser.pdf"
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("PDF not found: %v", err)
	}
	if len(data) < 5 || string(data[:5]) != "%PDF-" {
		t.Fatalf("not a valid PDF header: %q", data[:min(5, len(data))])
	}
}

// TestSaveIdentityQRForTUIIncludesPDF verifies the TUI-facing save path
// (saveIdentityQRForTUI, behind /show-qr's "image" choice) returns the
// PDF path alongside the .txt/.png paths.
func TestSaveIdentityQRForTUIIncludesPDF(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlkem := make([]byte, 1184)
	mldsa := make([]byte, 1952)
	if _, err := rand.Read(mlkem); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(mldsa); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	qrPath := dir + "/identity-qr-bob.png"
	paths, err := saveIdentityQRForTUI("bob", pub, mlkem, mldsa, qrPath)
	if err != nil {
		t.Fatal(err)
	}

	var hasPDF bool
	for _, p := range paths {
		if p == dir+"/identity-qr-bob.pdf" {
			hasPDF = true
		}
	}
	if !hasPDF {
		t.Fatalf("expected a .pdf path among %v", paths)
	}
}

// TestSaveQRPagesAsPDFNoPartsIsNoop verifies no file is written when
// there are no QR parts to include.
func TestSaveQRPagesAsPDFNoPartsIsNoop(t *testing.T) {
	dir := t.TempDir()
	pdfPath := dir + "/empty.pdf"
	if err := saveQRPagesAsPDF("nobody", "nu://nobody/x", nil, pdfPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pdfPath); err == nil {
		t.Fatal("expected no file to be written")
	}
}

// TestQRPartsDecodeRoundTripManyIdentities regenerates and decodes
// several full identities (both PQC keys, near-maximum QR version,
// well over 150 modules per part) back to back. A single identity isn't
// a reliable check here: measured directly, gozxing
// (internal/qrscan) fails to decode roughly 1 in 10 otherwise-valid
// renders at this density purely from a content/version-dependent
// detection limitation (no damage or recompression involved, a
// pristine render can still fail), a single random sample has too
// high a chance of landing on a part that happens to decode fine either
// way. qrscan.EncodeVerified handles this: it
// decodes its own render back before returning, stepping to the next QR
// version (same content, different mask, go-qrcode scores masks on
// visual penalty rules, not decodability) until one verifies. Enough
// identities that, without EncodeVerified, at least one failure would be
// expected with very high probability (1-0.9^30 ≈ 96%).
func TestQRPartsDecodeRoundTripManyIdentities(t *testing.T) {
	dir := t.TempDir()
	for i := range 15 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		mlkem := make([]byte, 1184)
		mldsa := make([]byte, 1952)
		if _, err := rand.Read(mlkem); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(mldsa); err != nil {
			t.Fatal(err)
		}
		username := fmt.Sprintf("user%d", i)
		qrPath := fmt.Sprintf("%s/identity-qr-%s.png", dir, username)
		if err := printAndSaveQR(username, pub, mlkem, mldsa, qrPath, false); err != nil {
			t.Fatal(err)
		}
		for _, part := range []string{"part1", "part2"} {
			p := fmt.Sprintf("%s/identity-qr-%s-%s.png", dir, username, part)
			text, err := qrscan.DecodeQRFile(p)
			if err != nil {
				t.Fatalf("identity %d, %s: decode failed: %v", i, part, err)
			}
			if text == "" {
				t.Fatalf("identity %d, %s: decoded empty text", i, part)
			}
		}
	}
}

// TestQRPartsDecodeRoundTripAtMaxVersion verifies the saved part PNGs of
// a full identity (both PQC keys, near-maximum QR version, around
// version 37-40, well over 170 modules) actually decode back. A fixed
// WriteFile(256, ...) divides unevenly across that many modules
// (nearest-neighbor sampling then renders some module rows/columns 1px
// wide and the next 2px), which breaks /cnt-read-qrcode on a
// non-recompressed identity PNG, so parts are rendered at an exact
// pixels-per-module size (qrscan.PixelsPerModule, a negative size per
// go-qrcode's own variable-size convention) instead of a fixed total
// image size.
func TestQRPartsDecodeRoundTripAtMaxVersion(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlkem := make([]byte, 1184)
	mldsa := make([]byte, 1952)
	if _, err := rand.Read(mlkem); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(mldsa); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	qrPath := dir + "/identity-qr-carol.png"
	if err := printAndSaveQR("carol", pub, mlkem, mldsa, qrPath, false); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"part1", "part2"} {
		p := dir + "/identity-qr-carol-" + part + ".png"
		text, err := qrscan.DecodeQRFile(p)
		if err != nil {
			t.Fatalf("decode %s failed: %v", part, err)
		}
		if text == "" {
			t.Fatalf("decode %s returned empty text", part)
		}
	}
}
