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
	"encoding/base64"
	"strings"
	"testing"
)

// TestMyIdentityURIIncludesAllKeySegments: the nu:// URI shown by
// cmdInfo("self")/cmdShowQR must carry every key segment, ML-DSA-65
// included, like cmd/main.go's identityQRContent, otherwise a contact
// added by scanning it would miss PQC signature verification.
func TestMyIdentityURIIncludesAllKeySegments(t *testing.T) {
	m := model{
		myUsername:    "alice",
		myIdentityPub: []byte("identity-pub-bytes"),
		myMLKEMPub:    []byte("mlkem-pub-bytes"),
		myMLDSAPub:    []byte("mldsa-pub-bytes"),
	}
	uri := m.myIdentityURI()

	wantIdentity := base64.StdEncoding.EncodeToString(m.myIdentityPub)
	wantMLKEM := base64.StdEncoding.EncodeToString(m.myMLKEMPub)
	wantMLDSA := base64.StdEncoding.EncodeToString(m.myMLDSAPub)

	if !strings.HasPrefix(uri, "nu://alice/"+wantIdentity+"/") {
		t.Fatalf("unexpected URI prefix: %q", uri)
	}
	if !strings.Contains(uri, wantMLKEM) {
		t.Errorf("URI missing MLKEM segment: %q", uri)
	}
	if !strings.Contains(uri, wantMLDSA) {
		t.Errorf("URI missing MLDSA segment: %q", uri)
	}
}

// TestMyIdentityURIOmitsEmptySegments verifies no "//" artifact appears
// when MLKEM/MLDSA aren't set.
func TestMyIdentityURIOmitsEmptySegments(t *testing.T) {
	m := model{
		myUsername:    "bob",
		myIdentityPub: []byte("identity-pub-bytes"),
	}
	uri := m.myIdentityURI()
	want := "nu://bob/" + base64.StdEncoding.EncodeToString(m.myIdentityPub)
	if uri != want {
		t.Fatalf("got %q, want %q", uri, want)
	}
}
