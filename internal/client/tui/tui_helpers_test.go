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
	"bytes"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"neutrino/internal/client"
	"neutrino/internal/keystore"
)

// testPub is a stable root identity key for a named test member.
func testPub(name string) ed25519.PublicKey {
	seed := sha256.Sum256([]byte("test-identity:" + name))
	return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
}

// testKey is the member key of a named test member.
func testKey(name string) string {
	return client.MemberKeyOf(testPub(name))
}

// testOnline returns the member keys of the named members, with their
// labels recorded on tab.
func testOnline(tab *roomTab, names ...string) []string {
	keys := make([]string, 0, len(names))
	for _, n := range names {
		tab.setMemberLabel(testKey(n), n)
		keys = append(keys, testKey(n))
	}
	return keys
}

func TestParseNuURIValid(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)

	t.Run("without optional segments", func(t *testing.T) {
		uri := "nu://alice/" + b64
		username, pubBytes, mlkemPubBytes, mldsaPubBytes, err := parseNuURI(uri)
		if err != nil {
			t.Fatalf("parseNuURI: %v", err)
		}
		if username != "alice" {
			t.Fatalf("username = %q, want alice", username)
		}
		if len(pubBytes) != 32 || pubBytes[0] != 0 || pubBytes[31] != 31 {
			t.Fatalf("pubBytes = %v, want the decoded 32-byte key", pubBytes)
		}
		if mlkemPubBytes != nil {
			t.Fatalf("mlkemPubBytes = %v, want nil (URI without an ML-KEM segment)", mlkemPubBytes)
		}
		if mldsaPubBytes != nil {
			t.Fatalf("mldsaPubBytes = %v, want nil (URI without an ML-DSA segment)", mldsaPubBytes)
		}
	})

	t.Run("with ML-KEM segment", func(t *testing.T) {
		mlkemRaw := make([]byte, mlkem.EncapsulationKeySize768)
		for i := range mlkemRaw {
			mlkemRaw[i] = byte(i)
		}
		mlkemB64 := base64.StdEncoding.EncodeToString(mlkemRaw)
		uri := "nu://carol/" + b64 + "/" + mlkemB64
		username, pubBytes, mlkemPubBytes, mldsaPubBytes, err := parseNuURI(uri)
		if err != nil {
			t.Fatalf("parseNuURI: %v", err)
		}
		if username != "carol" {
			t.Fatalf("username = %q, want carol", username)
		}
		if len(pubBytes) != 32 {
			t.Fatalf("pubBytes len = %d, want 32", len(pubBytes))
		}
		if !bytes.Equal(mlkemPubBytes, mlkemRaw) {
			t.Fatalf("mlkemPubBytes doesn't match the decoded segment")
		}
		if mldsaPubBytes != nil {
			t.Fatalf("mldsaPubBytes = %v, want nil (URI without an ML-DSA segment)", mldsaPubBytes)
		}
	})

	t.Run("with ML-KEM and ML-DSA segments", func(t *testing.T) {
		mlkemRaw := make([]byte, mlkem.EncapsulationKeySize768)
		mlkemB64 := base64.StdEncoding.EncodeToString(mlkemRaw)
		mldsaRaw := make([]byte, mldsa65.PublicKeySize)
		for i := range mldsaRaw {
			mldsaRaw[i] = byte(i)
		}
		mldsaB64 := base64.StdEncoding.EncodeToString(mldsaRaw)
		uri := "nu://erin/" + b64 + "/" + mlkemB64 + "/" + mldsaB64
		username, pubBytes, mlkemPubBytes, mldsaPubBytes, err := parseNuURI(uri)
		if err != nil {
			t.Fatalf("parseNuURI: %v", err)
		}
		if username != "erin" {
			t.Fatalf("username = %q, want erin", username)
		}
		if len(pubBytes) != 32 {
			t.Fatalf("pubBytes len = %d, want 32", len(pubBytes))
		}
		if !bytes.Equal(mlkemPubBytes, mlkemRaw) {
			t.Fatalf("mlkemPubBytes doesn't match the decoded segment")
		}
		if !bytes.Equal(mldsaPubBytes, mldsaRaw) {
			t.Fatalf("mldsaPubBytes doesn't match the decoded segment")
		}
	})
}

func TestParseNuURIInvalid(t *testing.T) {
	pub := make([]byte, 32)
	b64 := base64.StdEncoding.EncodeToString(pub)

	cases := map[string]string{
		"no scheme":                   "http://alice/" + b64,
		"no slash after scheme":       "nu://alicewithoutkey",
		"key too short":               "nu://alice/short",
		"key not base64":              "nu://alice/" + string(make([]byte, 44)),
		"legacy trailing 4th segment": "nu://bob/" + b64 + "/DEADBEEF01234567",
	}
	for name, uri := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, err := parseNuURI(uri); err == nil {
				t.Fatalf("parseNuURI(%q): want an error", uri)
			}
		})
	}
}

func TestDaysSinceZero(t *testing.T) {
	if got := daysSince(time.Time{}); got != 0 {
		t.Fatalf("daysSince(zero) = %d, want 0", got)
	}
}

func TestDaysSinceToday(t *testing.T) {
	if got := daysSince(time.Now()); got != 0 {
		t.Fatalf("daysSince(now) = %d, want 0", got)
	}
}

func TestDaysSinceYesterday(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1)
	if got := daysSince(yesterday); got != 1 {
		t.Fatalf("daysSince(yesterday) = %d, want 1", got)
	}
}

func TestFormatLocalTimestamp(t *testing.T) {
	ts := time.Date(2026, 8, 2, 21, 55, 0, 0, time.UTC).Local()
	got := formatLocalTimestamp(ts)
	want := ts.Format("2006-01-02 15:04")
	if got != want {
		t.Fatalf("formatLocalTimestamp = %q, want %q", got, want)
	}
}

func TestStartDirForFileBrowserReturnsExistingDir(t *testing.T) {
	dir := startDirForFileBrowser()
	if dir == "" {
		t.Fatal("startDirForFileBrowser: empty result")
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("startDirForFileBrowser = %q is not an existing directory: %v", dir, err)
	}
}

func TestListDirSortsFoldersFirstThenAlphabetical(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zeta.txt", "Alpha.txt", "beta_dir"} {
		if name == "beta_dir" {
			os.Mkdir(filepath.Join(dir, name), 0o755)
		} else {
			os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "Adir"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	entries, err := listDir(dir)
	if err != nil {
		t.Fatalf("listDir: %v", err)
	}
	want := []string{"Adir", "beta_dir", "Alpha.txt", "zeta.txt"}
	if len(entries) != len(want) {
		t.Fatalf("listDir = %v, want %v", entries, want)
	}
	for i, w := range want {
		if entries[i].name != w {
			t.Fatalf("listDir[%d] = %q, want %q (full: %v)", i, entries[i].name, w, entries)
		}
	}
	if !entries[0].isDir || !entries[1].isDir {
		t.Fatalf("the first two entries must be directories: %v", entries)
	}
}

func TestListDirMissing(t *testing.T) {
	if _, err := listDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("listDir: want an error for a missing directory")
	}
}

// TestListDirFollowsSymlinkedDirectories verifies a symlink pointing at
// a directory (e.g. Termux's ~/storage/pictures, pointing at Android's
// real storage) is listed as a directory — os.DirEntry.IsDir() alone
// reflects the symlink itself, never its target, and would otherwise
// show it as an unopenable plain file.
func TestListDirFollowsSymlinkedDirectories(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real_dir")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(dir, "link_to_dir")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported in this environment: %v", err)
	}
	brokenLink := filepath.Join(dir, "broken_link")
	if err := os.Symlink(filepath.Join(dir, "does_not_exist"), brokenLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	entries, err := listDir(dir)
	if err != nil {
		t.Fatalf("listDir: %v", err)
	}
	var foundLink, foundBroken bool
	for _, e := range entries {
		switch e.name {
		case "link_to_dir":
			foundLink = true
			if !e.isDir {
				t.Fatalf("link_to_dir (symlink to a directory) should be reported as isDir=true, got %+v", e)
			}
		case "broken_link":
			foundBroken = true
			if e.isDir {
				t.Fatalf("broken_link (dangling symlink) should be reported as isDir=false, got %+v", e)
			}
		}
	}
	if !foundLink {
		t.Fatal("expected link_to_dir in listDir's output")
	}
	if !foundBroken {
		t.Fatal("expected broken_link in listDir's output")
	}
}

func TestFilterDirsOnly(t *testing.T) {
	entries := []fsEntry{
		{name: "a.txt", isDir: false},
		{name: "sub", isDir: true},
		{name: "b.txt", isDir: false},
		{name: "other", isDir: true},
	}
	got := filterDirsOnly(entries)
	if len(got) != 2 || got[0].name != "sub" || got[1].name != "other" {
		t.Fatalf("filterDirsOnly = %v, want [sub other]", got)
	}
}

func TestUniqueDestPathNoCollision(t *testing.T) {
	dir := t.TempDir()
	got := uniqueDestPath(dir, "file.txt")
	want := filepath.Join(dir, "file.txt")
	if got != want {
		t.Fatalf("uniqueDestPath = %q, want %q", got, want)
	}
}

func TestUniqueDestPathAvoidsCollision(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := uniqueDestPath(dir, "file.txt")
	want := filepath.Join(dir, "file (1).txt")
	if got != want {
		t.Fatalf("uniqueDestPath = %q, want %q", got, want)
	}
}

func TestUniqueDestPathSkipsMultipleCollisions(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "file (1).txt"), []byte("x"), 0o644)
	got := uniqueDestPath(dir, "file.txt")
	want := filepath.Join(dir, "file (2).txt")
	if got != want {
		t.Fatalf("uniqueDestPath = %q, want %q", got, want)
	}
}

func TestTruncName(t *testing.T) {
	if got := truncName("hello", 10); got != "hello" {
		t.Fatalf("truncName(short) = %q, want hello", got)
	}
	if got := truncName("hello world", 5); got != "hello" {
		t.Fatalf("truncName(long) = %q, want hello", got)
	}
	// Rune-safe: never truncates in the middle of a multi-byte character.
	if got := truncName("héllo", 2); got != "hé" {
		t.Fatalf("truncName(unicode) = %q, want hé", got)
	}
}

func TestMemberNameDisambiguatesHomonyms(t *testing.T) {
	m := &model{myUsername: "me", myIdentityPub: testPub("me")}
	tab := &roomTab{}
	tab.setMemberLabel(testKey("bob-1"), "bob")
	tab.setMemberLabel(testKey("bob-2"), "bob")
	tab.setMemberLabel(testKey("carol"), "carol")

	if got := m.memberName(tab, testKey("carol")); got != "carol" {
		t.Errorf("memberName(carol) = %q, want carol", got)
	}
	a, b := m.memberName(tab, testKey("bob-1")), m.memberName(tab, testKey("bob-2"))
	if a == b || !strings.HasPrefix(a, "bob ·") || !strings.HasPrefix(b, "bob ·") {
		t.Errorf("homonyms not told apart: %q / %q", a, b)
	}
	if got := m.memberName(tab, m.myKey()); got != "me" {
		t.Errorf("memberName(self) = %q, want me", got)
	}
	// A member named like us is told apart from us too.
	tab.setMemberLabel(testKey("me-other"), "me")
	if got := m.memberName(tab, testKey("me-other")); !strings.HasPrefix(got, "me ·") {
		t.Errorf("memberName(namesake of self) = %q, want a fingerprint suffix", got)
	}
}

func TestSendFileFilteredEntries(t *testing.T) {
	m := model{
		sendFileEntries: []fsEntry{
			{name: "report.pdf"}, {name: "photo.jpg"}, {name: "Report2.txt"},
		},
	}
	if got := m.sendFileFilteredEntries(); len(got) != 3 {
		t.Fatalf("no filter: len = %d, want 3", len(got))
	}
	m.sendFileFilter = "report"
	got := m.sendFileFilteredEntries()
	if len(got) != 2 || got[0].name != "report.pdf" || got[1].name != "Report2.txt" {
		t.Fatalf("filter 'report' = %v, want [report.pdf Report2.txt]", got)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestReachabilityRank(t *testing.T) {
	m := &model{
		contactStates: map[string]contactState{
			"seenByPeer":               {online: boolPtr(true), seenByPeer: boolPtr(true)},
			"onlineOnly":               {online: boolPtr(true), seenByPeer: nil},
			"onlineNotSeenByPeer":      {online: boolPtr(true), seenByPeer: boolPtr(false)},
			"offline":                  {online: boolPtr(false)},
			"offlineButSeenByPeer":     {online: boolPtr(false), seenByPeer: boolPtr(true)},
			"neverProbedButSeenByPeer": {online: nil, seenByPeer: boolPtr(true)},
			"offlineAndNotSeenByPeer":  {online: boolPtr(false), seenByPeer: boolPtr(false)},
		},
	}
	cases := []struct {
		user string
		want int
	}{
		{"seenByPeer", 0},
		{"onlineOnly", 1},
		{"onlineNotSeenByPeer", 2},
		{"neverProbedButSeenByPeer", 3},
		{"unknown", 4},
		{"offlineButSeenByPeer", 6},
		{"offline", 7},
		{"offlineAndNotSeenByPeer", 8},
	}
	for _, c := range cases {
		if got := m.reachabilityRank([]byte(c.user)); got != c.want {
			t.Fatalf("reachabilityRank(%q) = %d, want %d", c.user, got, c.want)
		}
	}
}

func TestGroupContactsByTrust(t *testing.T) {
	m := &model{
		contacts: []ContactInfo{
			{Username: "unknown1"},
			{Username: "verified1", Verified: true},
			{Username: "introduced1", IntroducedBy: "someone"},
			{Username: "verifiedIntroduced1", Verified: true, IntroducedBy: "someone"},
		},
	}
	groups := m.groupContactsByTrust()
	if len(groups[TrustUnknown]) != 1 || groups[TrustUnknown][0].Username != "unknown1" {
		t.Fatalf("TrustUnknown = %v", groups[TrustUnknown])
	}
	if len(groups[TrustVerified]) != 1 || groups[TrustVerified][0].Username != "verified1" {
		t.Fatalf("TrustVerified = %v", groups[TrustVerified])
	}
	if len(groups[TrustIntroduced]) != 1 || groups[TrustIntroduced][0].Username != "introduced1" {
		t.Fatalf("TrustIntroduced = %v", groups[TrustIntroduced])
	}
	if len(groups[TrustVerifiedIntroduced]) != 1 || groups[TrustVerifiedIntroduced][0].Username != "verifiedIntroduced1" {
		t.Fatalf("TrustVerifiedIntroduced = %v", groups[TrustVerifiedIntroduced])
	}
}

func TestGroupContactsByTrustOrdersByRelEstablishedThenReachability(t *testing.T) {
	fullPriv := make([]byte, ed25519.PrivateKeySize)
	fullPub := make([]byte, ed25519.PublicKeySize)
	m := &model{
		contacts: []ContactInfo{
			{Username: "zebra", Verified: true, Devices: map[string]*keystore.DeviceRelation{"d": {RelContentPriv: fullPriv, PeerRelContentPub: fullPub}}},
			{Username: "alpha", Verified: true},
		},
		contactStates: map[string]contactState{},
	}
	groups := m.groupContactsByTrust()
	list := groups[TrustVerified]
	if len(list) != 2 || list[0].Username != "zebra" {
		t.Fatalf("want established-relationship first despite alphabetical order: %v", list)
	}
}

// newContentRelFixture reproduces the ContentKey relationship state
// combinations relevant to contentRelEstablished/eligibleFileRecipients:
// alice has the relationship established in BOTH directions (our
// RelContentPriv toward her + her PeerRelContentPub known to us); bob is a
// contact with only our half (rel_init bootstrap not yet confirmed from
// the other side); carol is a contact with no ContentKey exchanged at all;
// dave is not even a saved contact. The key contents do not matter for
// these tests (only the length, verified by
// contentPeerPubFor/myContentPrivFor), so zero-valued slices suffice.
func newContentRelFixture() (*model, int) {
	fullPriv := make([]byte, ed25519.PrivateKeySize)
	fullPub := make([]byte, ed25519.PublicKeySize)
	tab := &roomTab{}
	tab.online = testOnline(tab, "alice", "bob", "carol", "dave")
	m := &model{
		contacts: []ContactInfo{
			{Username: "alice", IdentityPub: testPub("alice"), Devices: map[string]*keystore.DeviceRelation{"d": {RelContentPriv: fullPriv, PeerRelContentPub: fullPub}}},
			{Username: "bob", IdentityPub: testPub("bob"), Devices: map[string]*keystore.DeviceRelation{"d": {RelContentPriv: fullPriv}}},
			{Username: "carol", IdentityPub: testPub("carol")},
		},
		tabs: []*roomTab{tab},
	}
	return m, 0
}

func TestEligibleFileRecipientsAndComplement(t *testing.T) {
	m, tabIdx := newContentRelFixture()

	eligible := m.eligibleFileRecipients(tabIdx)
	if len(eligible) != 1 || eligible[0] != testKey("alice") {
		t.Fatalf("eligibleFileRecipients = %v, want [alice]", eligible)
	}

	missing := m.namesWithoutContentRel(tabIdx)
	want := map[string]bool{"bob": true, "carol": true, "dave": true}
	if len(missing) != len(want) {
		t.Fatalf("namesWithoutContentRel = %v, want 3 items (%v)", missing, want)
	}
	for _, n := range missing {
		if !want[n] {
			t.Fatalf("namesWithoutContentRel contains unexpected %q: %v", n, missing)
		}
	}
}

func TestNoContentRecipientsMsgNamesTheMissing(t *testing.T) {
	m, tabIdx := newContentRelFixture()
	msg := m.noContentRecipientsMsg(tabIdx)
	if msg == "" {
		t.Fatal("noContentRecipientsMsg: empty")
	}
	// must name at least one of the missing ones, not a generic message empty of names
	if !containsAny(msg, "bob", "carol", "dave") {
		t.Fatalf("noContentRecipientsMsg = %q, want it to name at least one of bob/carol/dave", msg)
	}
}

func TestNoContentRecipientsMsgGenericWhenAllEstablished(t *testing.T) {
	fullPriv := make([]byte, ed25519.PrivateKeySize)
	fullPub := make([]byte, ed25519.PublicKeySize)
	tab := &roomTab{}
	tab.online = testOnline(tab, "alice")
	m := &model{
		contacts: []ContactInfo{{Username: "alice", IdentityPub: testPub("alice"), Devices: map[string]*keystore.DeviceRelation{"d": {RelContentPriv: fullPriv, PeerRelContentPub: fullPub}}}},
		tabs:     []*roomTab{tab},
	}
	if got := m.namesWithoutContentRel(0); len(got) != 0 {
		t.Fatalf("namesWithoutContentRel = %v, want empty", got)
	}
	if msg := m.noContentRecipientsMsg(0); msg == "" {
		t.Fatal("noContentRecipientsMsg: empty in the generic case too")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
