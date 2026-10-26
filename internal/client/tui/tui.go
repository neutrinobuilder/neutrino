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
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qrcode "github.com/skip2/go-qrcode"

	"neutrino/internal/client"
	"neutrino/internal/i18n"
	"neutrino/internal/keystore"
	"neutrino/internal/qroptical"
	"neutrino/internal/qrscan"
	"neutrino/internal/shared"
	"neutrino/internal/termuxenv"
	"neutrino/internal/version"
)

// ── styles ────────────────────────────────────────────────────────────────────

var (
	styleOwnMsg  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	stylePeerMsg = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	styleMeta    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleErr     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleBorder  = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).Padding(0, 1)
	styleActiveTab = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).Bold(true).Padding(0, 1)
	styleTab           = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Padding(0, 1)
	styleTabChat       = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Padding(0, 1)
	styleTabChatActive = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).
				Background(lipgloss.Color("62")).Bold(true).Padding(0, 1)
	// styleWarnName: yellow inline name, connected but without an
	// established ContentKey relationship (only Safety Number
	// available). Used in a group's member list, never in the top tab bar.
	styleWarnName = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	// stylePQCOn/stylePQCOff color the "[PQC]" tag always present on
	// every message line (chatLine.render), green if this specific
	// message carries an active ML-DSA-65 signature (our own or the
	// sender's verified one), red otherwise. Dedicated (not reusing
	// styleOwnMsg/styleErr directly) so this signal's meaning doesn't
	// depend on a future tweak to the username/error colors.
	stylePQCOn  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	stylePQCOff = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))

	stylePaletteSel  = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Bold(true).Padding(0, 1)
	stylePaletteCmd  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)
	stylePaletteArg  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	stylePaletteDesc = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
)

// maxLocalNameLen is the maximum length (in runes) of a local name,
// deliberately kept short so the Contacts tab aligns the name column to the
// same width every time, instead of a different row-by-row offset
// ("accordion effect").
const maxLocalNameLen = 14

// maxUsernameDisplayLen is the width (in runes) of the real username
// column in the Contacts tab. It equals maxLocalNameLen but is a
// deliberately separate constant: the network username has no length
// constraint of its own (free text, no validation elsewhere), so its
// table width must not depend on a future change to the local name's
// limit, an independent concept.
const maxUsernameDisplayLen = 14

// maxOffbandHintLen is the maximum length (in runes) of the out-of-band
// contact info entered in /grp-contact-send, wide enough for a phone
// number, an email address, or a Telegram handle, without becoming a
// free-text notes field.
const maxOffbandHintLen = 80

// maxFileNameLen is the maximum length (in runes) of the file name
// during a rename in saveRenameMode, well under the 255 bytes typical
// of filesystems even counting multi-byte characters, no need to
// validate further.
const maxFileNameLen = 200

// ── command palette ───────────────────────────────────────────────────────────

// The command table (client.PaletteItem) is defined in commands.go
// (CommandList) and depends on the active language.

// ── sigStatus ─────────────────────────────────────────────────────────────────

type sigStatus int

const (
	sigNone sigStatus = iota
	sigPending
	sigOK
	sigFailed
	sigOwn // our own message, no meaningful self-verification (multi-signature per recipient, no single "our" ContentKey)
)

// ContactInfo describes a contact reachable via Tor or I2P.
type ContactInfo struct {
	Username     string
	LocalName    string // personal name (empty = use Username)
	NetAddr      string // contact's .onion or .b32.i2p (without port)
	IdentityPub  ed25519.PublicKey
	LastAckAt    time.Time // local clock: last probe_ack received (zero = never)
	LastSeenAt   time.Time // local clock: last time reached via TCP in a probe cycle (zero = never)
	Verified     bool      // full safety number comparison done out-of-band and confirmed (/sec-verify)
	IntroducedBy string    // display name of whoever introduced this contact via a card, at that time; empty = added directly
	// IntroducedByPub, identity key of whoever introduced this contact
	// via a card: the introducer's identity, IntroducedBy only labels it.
	IntroducedByPub ed25519.PublicKey
	// MLKEMPub is the contact's durable ML-KEM-768 encapsulation key
	// (1184 bytes), learned from the QR/URI at exchange time. Empty if
	// that QR/URI carried no ML-KEM key: knocks toward the contact stay
	// classic (X25519 only) until a QR with the key is exchanged, see
	// encryptKnockTagged/resolveMLKEMPubFor.
	MLKEMPub []byte

	// MLDSAPub is the contact's durable ML-DSA-65 signing public key
	// (1952 bytes packed), hybrid PQC network identity. Same treatment
	// as MLKEMPub above: empty until the QR is (re-)exchanged, the
	// parallel ML-DSA signatures stay unverifiable (never blocking)
	// until then.
	MLDSAPub []byte

	// KnownDevicePub, the device-level Ed25519 public key of this
	// contact's last successfully verified message (TOFU, remote_nuke).
	// A distinct concept from Keystore.KnownDevices (that one concerns
	// OUR OWN identity, remote_nuke targeting); this one recognizes a
	// CONTACT's device, a change doesn't block or invalidate anything,
	// it only produces a distinct on-screen tag ([DEV:new]).
	KnownDevicePub []byte

	// Devices, mirrors keystore.Contact.Devices, same type
	// (keystore.DeviceRelation) and exact same meaning: an independent
	// per-device relationship (relationship keys, confirmation/rotation/
	// conflict state), keyed by string(DevicePub). SoleDevice() below
	// remains the conversion path for the vast majority of callers (a
	// single known device).
	Devices map[string]*keystore.DeviceRelation

	// SiblingRevocations mirrors keystore.Contact.SiblingRevocations,
	// read-only here (probeContacts' sibling retry queue only reads
	// it, Acked is written back through AckSiblingRevocation on the
	// real keystore, never through this mirror).
	SiblingRevocations map[string]*keystore.SiblingRevocation
}

// SoleDevice mirrors keystore.Contact.SoleDevice, returns the map's
// only entry if the contact has exactly one known device, false
// otherwise (never a silent pick when there's more than one).
func (c ContactInfo) SoleDevice() (*keystore.DeviceRelation, bool) {
	if len(c.Devices) != 1 {
		return nil, false
	}
	for _, dev := range c.Devices {
		return dev, true
	}
	return nil, false
}

// SoleDeviceOrPlaceholder mirrors
// keystore.Contact.SoleDeviceOrPlaceholder, like SoleDevice, but with
// an empty Devices it returns a new, empty DeviceRelation instead of (nil, false).
func (c ContactInfo) SoleDeviceOrPlaceholder() (*keystore.DeviceRelation, bool) {
	if len(c.Devices) == 0 {
		return &keystore.DeviceRelation{}, true
	}
	return c.SoleDevice()
}

// EnsureSoleDevice is like SoleDeviceOrPlaceholder, but with an empty
// Devices it CREATES the "" placeholder entry in the map instead of
// just returning a local copy, requires a pointer
// (SoleDeviceOrPlaceholder has a value receiver, can't write into the
// caller's map). Used to apply to the local mirror (m.contacts) the
// keys generated by the probe cycle: without this, Devices would stay
// empty in memory for the whole session even after keystore persistence
// created the entry, causing a new generation (different keys) on every
// subsequent cycle.
func (c *ContactInfo) EnsureSoleDevice() (*keystore.DeviceRelation, bool) {
	if dev, ok := c.SoleDevice(); ok {
		return dev, true
	}
	if len(c.Devices) != 0 {
		return nil, false
	}
	if c.Devices == nil {
		c.Devices = map[string]*keystore.DeviceRelation{}
	}
	dev := &keystore.DeviceRelation{}
	c.Devices[""] = dev
	return dev, true
}

// SoleDeviceKey is SoleDevice but also returns the contact's DevicePub
// the key the entry lives under in Devices, needed by callers that
// must pass it to RoomRegistry (AddSecret/ReplaceSecret/
// RefreshSigningKeys): without it, RefreshSigningKeys couldn't
// distinguish the right device from a possible other device of the same contact.
func (c ContactInfo) SoleDeviceKey() (devicePub []byte, dev *keystore.DeviceRelation, ok bool) {
	if len(c.Devices) != 1 {
		return nil, nil, false
	}
	for k, d := range c.Devices {
		return []byte(k), d, true
	}
	return nil, nil, false
}

// ReadyDevices mirrors keystore.Contact.ReadyDevices, every device of
// this contact ready to be contacted/invited (confirmed, complete keys,
// known address), unlike SoleDevice() it doesn't stop at "exactly one"
// used by the invite's fan-out.
func (c ContactInfo) ReadyDevices() map[string]*keystore.DeviceRelation {
	if len(c.Devices) == 0 {
		return nil
	}
	out := make(map[string]*keystore.DeviceRelation, len(c.Devices))
	for key, dev := range c.Devices {
		if dev == nil || !dev.RelIdentityConfirmedByPeer || !dev.RelContentConfirmedByPeer || dev.Address == "" {
			continue
		}
		if len(dev.RelIdentityPriv) != ed25519.PrivateKeySize || len(dev.PeerRelIdentityPub) != ed25519.PublicKeySize {
			continue
		}
		out[key] = dev
	}
	return out
}

// DeviceByPub mirrors keystore.Contact.DeviceByPub, EXACT resolution
// for a DevicePub already known to the caller (e.g. an incoming ack's
// RelRotatePayload.DevicePub), never ambiguous.
func (c ContactInfo) DeviceByPub(pub []byte) (dev *keystore.DeviceRelation, ok bool) {
	if len(pub) == 0 {
		return nil, false
	}
	dev, ok = c.Devices[string(pub)]
	return dev, ok && dev != nil
}

// DeviceWithPendingRelKeys mirrors
// keystore.Contact.DeviceWithPendingRelKeys, the first device
// (deterministic order) with a pending relationship key conflict
// (TrustDanger), not necessarily the only known device.
func (c ContactInfo) DeviceWithPendingRelKeys() (devicePub []byte, dev *keystore.DeviceRelation, ok bool) {
	keys := make([]string, 0, len(c.Devices))
	for k := range c.Devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d := c.Devices[k]
		if d == nil {
			continue
		}
		if len(d.PendingPeerRelIdentityPub) > 0 || len(d.PendingPeerRelContentPub) > 0 {
			return []byte(k), d, true
		}
	}
	return nil, nil, false
}

// RelEstablishedDevice returns the first device (deterministic order)
// with the ContentKey-per-relationship established in both directions,
// unlike SoleDevice(), it doesn't stop at "exactly one device": a
// contact with multiple known devices can have a relationship already
// working on one of them while another is still a bootstrap placeholder
// or still negotiating, used by the Contacts list for the [REL:...] fingerprint.
// A device with a revoked IdentityKey or ContentKey never counts as
// established (see keystore.Contact.RelEstablishedDevice).
func (c ContactInfo) RelEstablishedDevice() (*keystore.DeviceRelation, bool) {
	keys := make([]string, 0, len(c.Devices))
	for k := range c.Devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dev := c.Devices[k]
		if dev == nil || dev.RevokedIdentity || dev.RevokedContent {
			continue
		}
		if len(dev.RelContentPriv) == ed25519.PrivateKeySize && len(dev.PeerRelContentPub) == ed25519.PublicKeySize {
			return dev, true
		}
	}
	return nil, false
}

// RelRevoked reports whether the relationship is revoked: a device with a
// revoked key and no other device with an established relationship (see
// keystore.Contact.RelRevoked).
func (c ContactInfo) RelRevoked() bool {
	if _, ok := c.RelEstablishedDevice(); ok {
		return false
	}
	for _, dev := range c.Devices {
		if dev != nil && (dev.RevokedIdentity || dev.RevokedContent) {
			return true
		}
	}
	return false
}

// PendingRelKeys carries the relationship keys PROPOSED by a
// conflicting rel_init/rel_init_ack (see applyRelInit), never applied
// directly, only held pending until /sec-verify confirms them
// explicitly (TUIParams.ConfirmPendingRelKeys).
type PendingRelKeys struct {
	// DevicePub identifies the keystore.Contact.Devices entry this
	// conflict belongs to, never the empty string (the bootstrap
	// placeholder, see RelKeyUpdate below): a conflict, by construction,
	// can only happen on an already-confirmed device, never one still negotiating.
	DevicePub []byte

	IdentityPub      []byte
	IdentityMLKEMPub []byte
	IdentityMLDSAPub []byte
	ContentPub       []byte
	ContentMLKEMPub  []byte
	ContentMLDSAPub  []byte
}

// RelKeyUpdate carries a PARTIAL update of the relationship keys toward
// ONE device of a contact, only the non-empty fields get applied by
// the caller (TUIParams.UpdateContactRelKeys), the others stay whatever
// was already there. Used by the rel_init/rel_init_ack cycle
// (applyRelInit): one side may carry only "my just-generated keys" or
// only "their just-received keys", without needing to know/repeat the rest.
//
// DevicePub identifies the keystore.Contact.Devices entry to update,
// string(DevicePub) is the map's key. The empty string ("") is the
// bootstrap placeholder: no peer device known yet, a single provisional
// entry with OUR already-generated keys awaiting the first
// rel_init/rel_init_ack (see keystore.Contact.AddContact/applyRelInit).
// PromoteFromPlaceholder, if true, indicates this call must RENAME that
// placeholder entry to the DevicePub key instead of creating a new one
// only the first time the peer's device pub becomes known.
type RelKeyUpdate struct {
	DevicePub              []byte
	PromoteFromPlaceholder bool

	// Address is the network address declared by THIS device in its
	// rel_init (KnockPayload.FromAddr), where knocks and invites toward
	// this device are sent.
	Address string

	RelIdentityPriv         []byte
	RelIdentityMLKEMPriv    []byte
	RelIdentityMLDSAPriv    []byte
	PeerRelIdentityPub      []byte
	PeerRelIdentityMLKEMPub []byte
	PeerRelIdentityMLDSAPub []byte
	RelContentPriv          []byte
	RelContentMLKEMPriv     []byte
	RelContentMLDSAPriv     []byte
	PeerRelContentPub       []byte
	PeerRelContentMLKEMPub  []byte
	PeerRelContentMLDSAPub  []byte
	// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer, if true, mark
	// confirmation (a genuine rel_init_ack), never turned back to false
	// by a partial patch, only ever turned on. rel_init/rel_init_ack
	// always carries both keys in a single exchange, so they always turn
	// on together on a real ack.
	RelIdentityConfirmedByPeer bool
	RelContentConfirmedByPeer  bool
}

// DisplayName returns LocalName if set, otherwise Username.
func (c ContactInfo) DisplayName() string {
	if c.LocalName != "" {
		return c.LocalName
	}
	return c.Username
}

// NameWithUsername returns "LocalName (Username)" if a local name is
// set, otherwise just Username (no redundant parentheses). Used in
// messages concerning a single contact, to always keep the real network
// name visible even when the user set an alias, see also the dense
// multi-contact lists (e.g. a group's member bar), which deliberately
// do NOT use it, to stay compact.
func (c ContactInfo) NameWithUsername() string {
	if c.LocalName != "" {
		return c.LocalName + " (" + c.Username + ")"
	}
	return c.Username
}

// TrustLevel mirrors keystore.Contact.TrustLevel (same computation, a
// local type so internal/client doesn't depend on internal/keystore
// just for a small enum).
type TrustLevel int

const (
	// TrustDanger, see keystore.TrustDanger (exact same meaning):
	// unresolved relationship key conflict, prevails over any other
	// level computed from Verified/IntroducedBy.
	TrustDanger  TrustLevel = iota - 1
	TrustUnknown            // never verified, direct addition
	TrustIntroduced
	TrustVerified
	TrustVerifiedIntroduced
)

// TrustLevel computes the contact's trust level (see
// keystore.Contact.TrustLevel). An unresolved relationship key conflict
// always prevails, see TrustDanger above.
func (c ContactInfo) TrustLevel() TrustLevel {
	for _, dev := range c.Devices {
		if len(dev.PendingPeerRelIdentityPub) > 0 || len(dev.PendingPeerRelContentPub) > 0 {
			return TrustDanger
		}
	}
	switch {
	case c.Verified && c.IntroducedBy != "":
		return TrustVerifiedIntroduced
	case c.Verified:
		return TrustVerified
	case c.IntroducedBy != "":
		return TrustIntroduced
	default:
		return TrustUnknown
	}
}

// TrustTag returns the label to display for the contact's trust level.
func (c ContactInfo) TrustTag() string {
	switch c.TrustLevel() {
	case TrustDanger:
		return i18n.T("tui.contact_danger_tag")
	case TrustVerifiedIntroduced:
		return fmt.Sprintf(i18n.T("tui.trust_verified_introduced"), c.IntroducedBy)
	case TrustVerified:
		return i18n.T("tui.contact_verified_tag")
	case TrustIntroduced:
		return fmt.Sprintf(i18n.T("tui.trust_introduced"), c.IntroducedBy)
	default:
		return i18n.T("tui.contact_unverified_tag")
	}
}

// memberState describes the departure state of a disconnected member.
type memberState int

const (
	memberCrashed  memberState = iota // crash or never connected → red name
	memberLeft                        // left with /grp-exit → gray name
	memberDeclined                    // declined the invite before ever joining → gray name, like memberLeft
	memberBanned                      // removed with /grp-ban (host only) → gray name, like memberLeft/memberDeclined
)

// GroupMember is a member of a locally saved group.
type GroupMember struct {
	Username    string
	IdentityPub ed25519.PublicKey
}

// GroupInfo describes a locally saved group.
type GroupInfo struct {
	LocalName string
	GroupID   string
	Members   []GroupMember
}

// DeviceIdentityRef mirrors keystore.IdentityRef, an identity present
// on a known device (remote_nuke).
type DeviceIdentityRef struct {
	Username    string
	IdentityPub ed25519.PublicKey
	MLKEMPub    []byte
}

// DeviceRecordInfo mirrors keystore.DeviceRecord, a known device
// hosting (also) our own identity, toward which a remote_nuke command
// can be directed (fan-out across all SiblingIdentities, not just the
// one that led to registration).
type DeviceRecordInfo struct {
	DeviceID          []byte
	DevicePub         ed25519.PublicKey
	Label             string
	AddedAt           time.Time
	SiblingIdentities []DeviceIdentityRef
}

// DangerBroadcastPendingInfo mirrors keystore.DangerBroadcastPending,
// see TUIParams.PendingDangerBroadcasts.
type DangerBroadcastPendingInfo struct {
	TargetDeviceID []byte
	IdentityPubs   [][]byte // identity keys of the contacts not yet confirmed
}

// AllIdentityContactsInfo exposes, for ONE sibling identity present in
// the keystore (including itself), its contacts and a closure to
// sign/tag as THAT specific identity. Used only by the danger_end
// broadcast: the target device, before wiping itself, must notify the
// contacts of ALL its sibling identities (I1, I2, I3...), not just the
// one it's running as in this session, internal/client never sees the
// private keys directly, only this per-identity closure built in
// cmd/main.go (the only place with access to Keystore.SiblingKeystores).
type AllIdentityContactsInfo struct {
	Username    string
	IdentityPub ed25519.PublicKey
	Contacts    []ContactInfo
	DHTagFn     func(peerPub ed25519.PublicKey) ([]byte, error)
}

// ── tea messages ──────────────────────────────────────────────────────────────

type roomServerMsg struct {
	idx int
	raw map[string]any
}
type roomErrMsg struct {
	idx int
	err error
	// gen is the connection generation (roomTab.pingGen) active when
	// THIS specific attempt (read or ping) started, compared against
	// the CURRENT value of tab.pingGen when the message arrives (see
	// case roomErrMsg in Update). A late failure tied to a connection
	// already replaced by a reconnect in the meantime (waitForRoom stuck
	// on the old ctx, or a pingWatchdog probe started before the
	// reconnect) must not be treated as a fresh failure: it would reset
	// tab.reconnecting while a more recent reconnect is still in
	// progress, or would restart an unnecessary reconnect on an
	// already-healthy connection. Constructors concerning a connection
	// that doesn't exist yet (a new tab's first connection, never a
	// reconnection) leave gen at zero: it always matches a freshly
	// created tab's starting pingGen.
	gen int
}
type roomConnectedMsg struct{ idx int }

// pingWatchdogInterval/pingWatchdogTimeout regulate the active
// reachability probe for every connected tab (see pingWatchdogTickMsg):
// detects a silently stuck connection, no read error, but no data
// flowing anymore, a known Tor failure mode, that would otherwise
// never trigger the automatic reconnect, which depends only on an
// explicit ReadMsg error that never arrives in this scenario. A single
// unanswered ping within pingWatchdogTimeout is not enough to
// declare the connection dead (pingWatchdogMissThreshold consecutive
// cycles, same principle and same values as pingMissThreshold on the
// server side in internal/server/ws.go): a delayed pong is common on a
// Tor circuit under stress, not a reliable sign of a truly dead connection.
const (
	pingWatchdogInterval      = time.Minute
	pingWatchdogTimeout       = pingWatchdogInterval / 2
	pingWatchdogMissThreshold = 2
)

// wakeScanInterval, how often room members are scanned looking for
// someone "red" to send a wake to (case pingWatchdogTickMsg), and the
// receiving-side cooldown on the same mechanism (case "wake" in
// applyKnock/case knockMsg). Deliberately independent of
// pingWatchdogInterval, which is slower and more tolerant.
const wakeScanInterval = 30 * time.Second

// groupNoJoinTimeout, how long to wait after opening a group
// (cmdInvite/cmdRecall) before prompting the host if no invitee has
// joined yet (see groupNoJoinTimeoutMsg). Longer than
// pingWatchdogInterval because this doesn't measure a transport failure
// but the other side's human reaction time (Tor circuit build + the
// invitee noticing the popup and deciding).
const groupNoJoinTimeout = 2 * time.Minute

// pingWatchdogTickMsg triggers a probe round for tab idx, at generation
// gen (see roomTab.pingGen). The actual probe starts from its handler
// in Update, reading the model's state as it is THEN, not what was
// captured at scheduling time: tea.Tick only returns after the
// interval, so any data captured before (tab.ctx, tab.cli) would
// already be stale if the tab had reconnected in the meantime.
type pingWatchdogTickMsg struct {
	idx int
	gen int
}

// pingProbeFailedMsg signals a single probe cycle with no response
// within pingWatchdogTimeout, not yet an error to propagate: its
// handler in Update increments roomTab.pingMisses and only raises
// roomErrMsg once pingWatchdogMissThreshold is reached, see the comment
// on the constant.
type pingProbeFailedMsg struct {
	idx int
	gen int
	err error
}

// pingProbeOKMsg signals that the probe succeeded, resets
// roomTab.pingMisses. Scheduling the next round doesn't depend on
// this message: the external tick at wakeScanInterval (case
// pingWatchdogTickMsg) always handles it, probe succeeded or not.
type pingProbeOKMsg struct {
	idx int
	gen int
}

// groupNoJoinTimeoutMsg fires groupNoJoinTimeout after opening a group:
// if by then no invitee has joined yet, it offers the host the closing
// popup (see queueGroupNoJoinPrompt/showNextGroupNoJoinModal). groupID
// instead of just idx because the tab may have been closed in the
// meantime and the index reassigned to another tab.
type groupNoJoinTimeoutMsg struct {
	idx     int
	groupID string
}

type sendErrMsg struct{ err error }

// replySentMsg signals that a send with an explicit reply reference
// (/msg N) succeeded, used only to reset roomTab.pendingReplyTo
// (one-shot, on success only: a send blocked by backpressure or failed
// must leave the target intact, the user can simply retry). The
// mutation happens here in Update() (the main goroutine), never inside
// sendMessage's async closure that runs on its own goroutine.
type replySentMsg struct{ tabIdx int }
type probeResultMsg struct {
	tabIdx  int
	results []contactProbeResult
	silent  bool // if true shows output only if someone is online
}
type contactProbeResult struct {
	netUsername string // network username (display/debug only, NEVER a lookup key, two contacts can share it)
	netPub      []byte // IdentityPub of the probed contact, the real lookup key in m.contactStates/m.contacts
	username    string // displayName shown in the UI
	online      bool
	// generatedRelKeys, non-nil if this cycle had to generate ON THE
	// FLY our missing relationship keys toward this contact (see
	// probeContacts): applied to m.contacts and persisted by case
	// probeResultMsg, never mutated directly by the probe goroutine that
	// produces it (runs outside Update(), no safe access to m.contacts).
	generatedRelKeys *RelKeyUpdate
}

// contactState is a contact's reachability state, updated by the
// /active probe.
type contactState struct {
	online *bool // nil=never probed, true=online, false=offline (TCP dial, unchanged on every cycle)
	// seenByPeer is independent of online, not subordinate to it:
	// nil=unknown, true=the contact sees us, false=no confirmation
	// despite repeated attempts (not a diagnosis, see below).
	//
	// true is obtained through TWO independent paths, both stronger
	// than "online": (a) full round-trip, we receive their probe_ack in
	// response to our probe_ping; (b) direct proof, we receive their
	// probe_ping, the mere receipt proves they reach
	// us, regardless of whether OUR response manages to reach them.
	// Set by applyProbeAck and by probeAckCmdFor respectively. Once
	// true it never decays automatically (see seenByPeerAt below for
	// freshness, shown by /cnt-info).
	//
	// false is obtained ONLY if we reach them continuously (online=true
	// for at least probeRetryCount CONSECUTIVE cycles, the same counter
	// as dialWithRetry for dot1, reused here for conceptual consistency)
	// without ever either of the two proofs above, NEVER while online
	// is false or nil: if we don't reach them, we never even gave them
	// the chance to respond to us, the absence of proof in that case
	// says nothing about the opposite direction. Even once false, it
	// never resets back to nil on its own (no reset when the contact
	// goes offline: losing reachability doesn't invalidate the missing
	// confirmation observed while they were reachable).
	//
	// false is NEVER a diagnosis, it doesn't imply NAT/firewall on
	// their side: the exact same observation (no confirmation ever
	// arrived, despite repeated attempts) is indistinguishable from at
	// least three other causes, none of which the protocol can or
	// should reveal: they removed us from their address book (their
	// server still always responds 202, so as not to reveal a mismatch
	// revealing it would be a side channel exposing membership in
	// someone else's address book); our own ping never reaches its
	// destination (a failure of the application-level POST, not just
	// the TCP dial that governs online); a genuine asymmetric network
	// issue (NAT/firewall, on either side).
	seenByPeer *bool
	// seenByPeerAt is the moment of the last transition to
	// seenByPeer=true (never updated for a transition to false, which
	// isn't a confirmation), lets /cnt-info show "how long ago" instead
	// of a static dot that never decays (see seenByPeer above).
	seenByPeerAt time.Time
	// onlineStreak counts the CONSECUTIVE probe cycles in which this
	// contact came back online, reset on every cycle it comes back
	// offline. Used only to decide when to let seenByPeer expire from
	// nil to false; irrelevant if seenByPeer is already true or already false.
	onlineStreak int
	probedAt     time.Time
}
type tickActiveMsg struct{}
type torProbeResultMsg struct{ ok bool }
type tickTorProbeMsg struct{}
type warmupMsg struct{}
type rotateSenderKeyMsg struct{}

// senderKeyRotatedMsg signals that RotateSenderKey succeeded for tabIdx
// resets tab.keySentTo (a successful send for the previous key
// doesn't count for the new one). A dedicated tea.Msg because
// RotateSenderKey runs inside an async closure (func() tea.Msg):
// tab.keySentTo, a plain map with no mutex of its own, must only be
// touched by Update's single thread, never from there.
type senderKeyRotatedMsg struct{ tabIdx int }

// senderKeySentMsg signals that SendSenderKeyReliable succeeded in
// AT LEAST ONE send toward the member with key member in tabIdx, see the comment on
// roomTab.keySentTo for exactly what this means (not a network ack,
// just "writing the frame didn't fail right away").
type senderKeySentMsg struct {
	tabIdx int
	member string
}

// retryPendingTickMsg triggers a round of RetryDue on every connected
// tab, see retryPendingInterval and cmdRetryPending.
type retryPendingTickMsg struct{}

// retryPendingInterval is how often it's checked whether some pending
// message has exceeded its own backoff, independent of
// messageRetryDelay (which is ONE message's backoff, not the check's
// cadence): a fixed, short interval, since RetryDue is a cheap no-op
// when there's nothing to retry.
const retryPendingInterval = 5 * time.Second

type retryPendingRemoteNukesMsg struct{}

// tickInterfaceLockCheckMsg triggers the periodic check of the
// interface lock's inactivity threshold, not a tea.KeyMsg, so it
// reaches its own case even when m.interfaceLocked is already true (the
// gate on Update() intercepts only tea.KeyMsg, not other message types).
type tickInterfaceLockCheckMsg struct{}

// interfaceLockCheckInterval is the cadence of the periodic check of
// the inactivity threshold, fine enough not to be perceived as a
// delay, coarse enough not to weigh on the event loop.
const interfaceLockCheckInterval = 5 * time.Second

type knockMsg shared.KnockPayload

// sysLockMsg fires each time the host OS reports an explicit session
// lock, see sysLockCh/waitForSysLock.
type sysLockMsg struct{}

// pendingKnock is a knock awaiting a response, with the local receipt
// time (not part of the network payload: it only serves to distinguish
// in the UI two knocks from the same sender, e.g. an old one still
// pending and a new one).
type pendingKnock struct {
	shared.KnockPayload
	At time.Time
}

type torLogMsg struct{ line string }
type debugLogMsg struct{ line string }

// qrDecodedMsg signals that a QR (file or camera, /cnt-read-qrcode) was
// decoded successfully, routed as a message, not applied directly by
// the decoding goroutine, because it must touch m.pendingContact via
// startAddContactFromURI, never safe from another goroutine.
type qrDecodedMsg struct{ uri string }

// qrShowTickMsg advances the animated /show-qr popup's frame, gen must
// match model.qrShowGen when it arrives, otherwise it's a tick from an
// already-closed session (Esc) and must be ignored, same principle as
// tab.pingGen on roomErrMsg.
type qrShowTickMsg struct{ gen int }

// fileAcceptRetryMsg, every file_accept sent must correspond either to
// receipt of the first chunk or to an explicit timeout, never an
// indefinite wait: if it fires and no chunk has arrived yet for
// transferID (incomingFileTransfer.written == 0), the file_accept is
// resent and a new tick rescheduled, until
// incomingFileTransfer.acceptRetryDeadline expires, see
// model.fileAcceptRetryInterval.
type fileAcceptRetryMsg struct {
	transferID string
	toUserID   string
	tabIdx     int
}

// contactsSyncedMsg reports that a sync with one of our own devices
// merged its address book into the keystore: Update adopts the new
// contacts and devices (adoptSyncedContacts) and shows text, if any.
type contactsSyncedMsg struct {
	text string
}

// passwordChangedMsg reports a successful /sec-passwd: newPwd replaces
// keystorePassword, the password every later check in this session
// (backup, interface unlock, duress and lock PIN setup) compares against.
type passwordChangedMsg struct {
	newPwd string
}

type localDisplayMsg struct {
	tabIdx int
	text   string
	// consoleInfo: if true, also duplicates the message into the
	// Console tab without lighting up the red indicator (an
	// informational outcome, not an error, e.g. a file transfer
	// completing). A genuine ERROR message never uses this double
	// send: it always goes only to Console (tabIdx:
	// m.consoleIdx, isError: true), never into the tab/room the
	// command came from, so errors don't end up scattered across chats.
	consoleInfo bool
	isError     bool // true = lights up the red indicator if it ends up in the Console tab

	// transferID: empty for every other use of this message (the vast
	// majority), set only by startSendingChunks's three final outcomes
	// to remove the entry from model.outgoingTransfersSending when the transfer
	// terminates (success or fatal error), so it doesn't stay there forever.
	transferID string
}

// fileReadyToSaveMsg signals that a received file was decrypted and the
// signature verified, opens the filesystem browser to choose where to save it.
type fileReadyToSaveMsg struct {
	tabIdx   int
	fileName string
	data     []byte
}

// fileOfferMetaDecryptedMsg signals the outcome of background-decrypting
// the {file_name, file_size, file_key} blob of an incoming file_offer,
// runs in a separate goroutine (tea.Cmd) to avoid blocking the Update()
// loop while it does the hybrid ECIES work.
type fileOfferMetaDecryptedMsg struct {
	transferID string
	fileName   string
	fileSize   int64
	fileKey    []byte
	chunkCount uint64
	err        error
}

// fileOfferTimeoutMsg fires fileTransferOfferTimeout after a file_offer:
// if the transfer still exists in m.outgoingTransfers (someone hasn't
// responded yet), the send proceeds anyway with whoever already
// accepted, a forgotten or disconnected recipient must not block the
// send for everyone else.
type fileOfferTimeoutMsg struct {
	transferID string
}

// fileOfferBatchWindowMsg fires fileOfferBatchWindow after the offer is
// SENT (not after the first accept, see the comment on the tea.Tick
// that generates it): collects in a single round whoever accepts within
// this short window, instead of starting the send at the very first
// accept and having to chase down anyone who arrives even a moment
// later. If nobody has accepted yet when it expires, the case below
// does nothing: it simply keeps waiting until fileTransferOfferTimeout.
// Whoever accepts AFTER this window is still covered, during the send
// by the (concurrent) resume mechanism, after the send by
// startSendingChunks' grace window.
type fileOfferBatchWindowMsg struct {
	transferID string
}

// fileEncryptedMsg is the result of the heavy work (reading the file
// from disk + encrypting+compressing + one envelope per recipient,
// ContentKey-per-relationship) done in the background by
// onFilePresetChosen, see the comment there for why it must NEVER run
// synchronously inside Update(). err is set only on failure (file too
// large for available RAM, no relationship established yet with any
// recipient, etc.); all other fields are valid only if err is nil.
type fileEncryptedMsg struct {
	tabIdx            int
	transferID        string
	fileName          string
	ciphertext        []byte
	hash              []byte                                 // sha256(ciphertext), signed during the announcement phase, compared at the end of the transfer
	announceEnvelopes map[string]shared.FileAnnounceEnvelope // user_id → signature-only envelope (announcement phase)
	envelopes         map[string]shared.FileOfferEnvelope    // user_id → meta_blob envelope (real offer, sent only after the announcement's ack)
	sigTS             string                                 // common to all envelopes
	toUserIDs         []string
	pending           map[string]bool
	preset            string
	recipients        []string
	err               error
}

// tickFileProgressMsg refreshes the "File" tab's render while at least
// one transfer is active. fileTransferProgress is written by goroutines
// outside the Update loop (sending/receiving chunks), so an explicit
// tick is needed to force the View to redraw, bubbletea doesn't
// redraw on its own from mutations external to the Update/Msg cycle.
// Only reactivated when a transfer starts (not a perpetual ticker like
// tickActive, to avoid burning CPU for nothing).
type tickFileProgressMsg struct{}

func (m model) tickFileProgress() tea.Cmd {
	return tea.Tick(300*time.Millisecond, func(time.Time) tea.Msg { return tickFileProgressMsg{} })
}

type contactAddedMsg struct {
	tabIdx      int
	displayText string
	identityPub ed25519.PublicKey
	contact     ContactInfo
	isTabPeer   bool // true if the contact just added is tabIdx's room peer (not a third party introduced via a card)
}

// relRotationStartedMsg signals that StartRelIdentityRotationByPub/
// StartRelContentRotationByPub succeeded, which is "identity" or "content".
type relRotationStartedMsg struct {
	username string
	// contactPub is the chosen contact's IdentityPub, never ambiguous,
	// unlike username (two contacts can share it, e.g. after a /nukex):
	// the case consuming this message must find exactly the same contact
	// resolved by cmdStartRelRotation, not the first one with the same name.
	contactPub []byte
	which      string
	// newKeys, devicePub (string(pub)) → new key, one for EVERY device
	// the rotation actually started for (fan-out), never a single
	// device picked at random.
	newKeys map[string]shared.RelSigningKey
}

// contactCard is the contact card shared via /grp-contact-send,
// transmitted as a small file (same pipeline as /grp-file-send,
// per-recipient encryption with ContentKey-per-relationship, one frame
// per recipient). The plaintext is contactCardPrefix + JSON(contactCard),
// so the receiving side recognizes a contact card instead of a regular
// file without needing a dedicated field on the wire.
const contactCardPrefix = "\x00CC\x00"

type contactCard struct {
	Username    string `json:"username"`
	LocalName   string `json:"local_name,omitempty"`
	IdentityPub string `json:"identity_pub"`        // standard base64 (32-byte Ed25519)
	MLKEMPub    []byte `json:"mlkem_pub,omitempty"` // contact's durable ML-KEM-768 encapsulation key (1184 bytes)
	MLDSAPub    []byte `json:"mldsa_pub,omitempty"` // contact's durable ML-DSA-65 signing key (1952 bytes)
	// OffbandHint: free text written by the introducer (phone, email,
	// telegram id...) so the recipient can contact the card's subject
	// out-of-band and compare the safety code, verification is
	// impossible without an independent channel. Mandatory when sending
	// (cmdSendContact never leaves it empty); never persisted on a
	// saved contact, only shown at receipt time, then discarded.
	OffbandHint string `json:"offband_hint"`
}

// pqcToggleAnnouncePrefix marks a system broadcast message (the same
// normal SenderKey channel, Client.Send) that announces the sender
// activating or deactivating the optional ML-DSA-65 signature
// (/sec-pqc-sign) in this room. Unlike groupMemberAddedPrefix below, no
// special authority check: anyone can announce THEIR OWN PQC state (not
// someone else's), and "from" here is already the identity authenticated
// by the SenderKey that decrypted the message (parseMessage), not a
// self-declared field inside the payload.
const pqcToggleAnnouncePrefix = "\x00PQ\x00"

type pqcToggleAnnouncePayload struct {
	On bool `json:"on"`
}

// groupMemberAddedPrefix marks a system broadcast message (the normal
// SenderKey channel, Client.Send, not contactCard's file pipeline)
// that announces a new member added to an already-open group via
// /grp-add-member. The broadcast plaintext is groupMemberAddedPrefix +
// JSON(groupMemberAddedPayload). A receiving client accepts the update
// only if the WS-authenticated sender (tab.cli.LookupMemberKey(fromUserID),
// tied to which per-member secret authenticated the session) matches
// tab.hostKey: any other sender is silently discarded, only the
// host can change the group's trusted composition (the "from" field
// inside the encrypted payload is self-declared by the sender, not
// authenticated, and must never be used for this decision).
const groupMemberAddedPrefix = "\x00GM\x00"

type groupMemberAddedPayload struct {
	Member shared.MemberInfo `json:"member"`
}

// ── chatLine ──────────────────────────────────────────────────────────────────

type chatLine struct {
	username  string // display name of the sender
	fromKey   string // sender's member key, "" for system lines
	text      string
	rawText   string
	timestamp string
	isSystem  bool
	plain     bool // isSystem without a bullet or leading timestamp, only Console startup lines, which already embed their own time in the text (see consoleLines below)
	// contentKeyTag, "REL:xxxxxxxx" (last 8 hex chars of the sender's
	// ContentKey-per-relationship toward us) if sigStatus==sigOK, "" otherwise.
	contentKeyTag string
	// contentKeyEphemeral distinguishes a relationship born only from a
	// room introduction (ephemeral bootstrap) from one with a contact
	// persisted in the address book, used only to color the REL tag in
	// chat (yellow for ephemeral), never to decide whether the signature
	// is valid. Significant only if sigStatus==sigOK.
	contentKeyEphemeral bool
	sigStatus           sigStatus
	msgID               uint64 // non-zero only for our own sent broadcast messages; used to track ACKs
	// msgSeq, the sender's external sequence (Client.outMsgSeq on their
	// side, "mseq" on the wire): never reset by a sender_key rotation,
	// unlike the ratchet's idx. Carried with the line, not read by the
	// TUI itself.
	msgSeq uint64
	// gseq, the room's global sequence number (wsRawMsgData.GSeq,
	// roomDelivery), assigned by the server on arrival, unique within
	// the room regardless of who wrote it. For our own messages it
	// arrives with our own self-echo (recognized via TakeSentText),
	// updated after the fact on the already-displayed line (see
	// pendingAckLines), stays 0 until the self-echo arrives. Shown in the header ("#N") and used
	// by the /msg N command for the explicit reply reference: only a
	// message with a known gseq can be chosen as a target.
	gseq uint64
	// replyTo, gseq of the message this is a reply to (sealedMsg.RT), 0
	// if none. Never inferred: always an explicit user choice (/msg N
	// before sending).
	replyTo uint64
	// ackers lists the member keys of members who confirmed receipt
	// ("msg_ack" frame, resolved from from_user_id via
	// tab.cli.LookupMemberKey), not just a counter: lets /grp-msg-acks
	// show WHO confirmed and who didn't, not just how many.
	ackers map[string]bool

	// deviceTag, the device tag's text (remote_nuke), already ready for
	// rendering: "" if no valid device_sig (no tag shown, never a
	// message rejection); "DEV:xxxxxxxx" (already-known device or first
	// TOFU adoption) or "DEV:new" (a device different from the one
	// already known for this contact, informational only). deviceTagNew
	// distinguishes the style (yellow, not red: it's not an error).
	deviceTag    string
	deviceTagNew bool

	// pqcActive, whether this message carries an active ML-DSA-65
	// signature (hybrid PQC network identity): for our own message,
	// simply whether pqc_sig was present in the frame at send time (no
	// verification needed, it's ours); for someone else's message, only
	// if pqc_sig is present AND verifies against Contact.MLDSAPub, a
	// sender who declares pqc_sig but doesn't verify counts as "not
	// active", never a rejection of the message itself. Always shown in
	// chatLine.render (green/red), never omitted when absent, the
	// signal must always be visible, not only when positive.
	pqcActive bool
}

// replyPreview, already resolved by the caller (refreshViewport, which
// has visibility into the whole tab.lines for the gseq lookup, never
// here: render stays pure, a single message), "username: preview" of
// the message referenced by l.replyTo, or "" if l.replyTo==0 or the
// referenced message isn't (or is no longer) in the displayed history
// (can only happen on a freshly opened/truncated tab: the reference can
// only point to a message already seen at the time it was chosen).
// maxReplyPreviewLen, how much of the referenced message's text fits
// in the explicit reply reference's preview, truncated with "…" beyond
// this threshold, just a visual reminder, the number (#N) remains the
// exact reference.
const maxReplyPreviewLen = 40

func truncateReplyPreview(text string) string {
	r := []rune(text)
	if len(r) <= maxReplyPreviewLen {
		return text
	}
	return string(r[:maxReplyPreviewLen]) + "…"
}

func (l chatLine) render(myKey string, replyPreview string) string {
	if l.isSystem {
		if l.plain {
			return styleMeta.Render(l.text)
		}
		if l.timestamp != "" {
			return styleMeta.Render(l.timestamp + " • " + l.text)
		}
		return styleMeta.Render("• " + l.text)
	}
	ts := styleMeta.Render(l.timestamp + " ")
	var nameS string
	if l.fromKey != "" && l.fromKey == myKey {
		// Cyan for our own name, green for everyone else's, inverted
		// relative to the styleOwnMsg/stylePeerMsg constants (which
		// elsewhere stay green=us/cyan=others), deliberate only here and
		// in the member bar (renderGroupBar): the entire group room
		// panel (bar + chat area) uses this inverted scheme, the rest of
		// the TUI doesn't.
		nameS = stylePeerMsg.Render(l.username)
	} else {
		nameS = styleOwnMsg.Render(l.username)
	}
	// Same convention as cmdRoomInfo: status tags always inside square
	// brackets, each in its own pair (never mixed with a comma), an
	// actionable hint in parens right after.
	var body string
	style := styleMeta
	switch l.sigStatus {
	case sigNone:
		body = i18n.T("tui.tag_no_sig")
	case sigOK:
		body = l.contentKeyTag
		// Yellow (styleWarnName) for a relationship born only from a
		// room introduction (no direct contact), gray (styleMeta,
		// default) for a persisted contact, lets one tell a
		// "temporary" REL from one with someone actually in the address
		// book at a glance.
		if l.contentKeyEphemeral {
			style = styleWarnName
		}
	case sigFailed:
		body = i18n.T("tui.tag_sig_invalid")
		style = styleErr
	case sigPending:
		body = i18n.T("tui.tag_sig_pending")
	case sigOwn:
		body = i18n.T("tui.tag_own")
	}
	sigTag := style.Render(" [" + body + "]")
	// ALWAYS present (never omitted), same placeholder style as REL
	// under verification ("DEV:........") when l.deviceTag is empty:
	// message headers must all have the same format.
	devTag := l.deviceTag
	devStyle := styleMeta
	if devTag == "" {
		devTag = "DEV:........"
	} else if l.deviceTagNew {
		devStyle = styleWarnName
	}
	sigTag += devStyle.Render(" [" + devTag + "]")
	pqcStyle := stylePQCOff
	if l.pqcActive {
		pqcStyle = stylePQCOn
	}
	sigTag += pqcStyle.Render(" [PQC]")
	var ackTag string
	if l.msgID != 0 {
		if len(l.ackers) == 0 {
			ackTag = styleMeta.Render(" ○")
		} else {
			ackTag = styleOwnMsg.Render(fmt.Sprintf(" ✓%d", len(l.ackers)))
		}
	}
	// gseqTag, the room's global sequence number, the target of the
	// /msg N command: omitted until known (0 = self-echo not yet
	// confirmed by the server, or a system message).
	var gseqTag string
	if l.gseq != 0 {
		gseqTag = styleMeta.Render(fmt.Sprintf(" #%d", l.gseq))
	}
	// replyLine, explicit reply reference: extra line above the text,
	// always present if l.replyTo!=0 even without a resolved preview
	// (referenced message no longer in the displayed history).
	var replyLine string
	if l.replyTo != 0 {
		if replyPreview != "" {
			replyLine = styleMeta.Render(fmt.Sprintf("  ↩ #%d %s", l.replyTo, replyPreview)) + "\n"
		} else {
			replyLine = styleMeta.Render(fmt.Sprintf("  ↩ #%d", l.replyTo)) + "\n"
		}
	}
	// Two lines: header (time, name, all tags, ACK) above, message text
	// below, indented, ansi.Wrap (refreshViewport) respects the "\n"
	// already embedded in the string, so the lines wrap independently
	// if too long for the viewport's width, never merged into one.
	return ts + nameS + sigTag + ackTag + gseqTag + "\n" + replyLine + "  " + l.text
}

// ── roomTab ───────────────────────────────────────────────────────────────────

type roomTab struct {
	name       string
	isConsole  bool // true = system console tab (read-only)
	isContacts bool // true = address book tab (can't be closed)
	isGroups   bool // true = saved groups list tab (can't be closed)
	isTor      bool // true = Tor process log tab
	isFiles    bool // true = "File" tab, file transfer progress bars
	cli        *client.Client
	ctx        context.Context
	cancel     context.CancelFunc
	lines      []chatLine
	// online, member keys (client.MemberKeyOf of the root identity key)
	// of the members currently connected. A member is identified only
	// by its key; memberLabels holds the username label each was invited
	// under, for display only (see memberName).
	online       []string
	memberLabels map[string]string
	// ephRels holds, per member key, the EPHEMERAL relationship
	// (point-to-point bootstrap, rel_bootstrap channel) with a room
	// member with no prior direct contact ("introduced"), never
	// persisted, discarded when the room closes. nil until needed (lazy init).
	ephRels map[string]*ephemeralRel
	// keySentTo, per member key, true if SendSenderKeyReliable has
	// already succeeded in AT LEAST ONE send toward this peer for OUR
	// current sender_key. Not a network ack (that already exists:
	// sendSenderKeyTo uses the generic reliable channel,
	// msg_id+msg_ack+RetryDue, same as every chat message), it only
	// serves to know whether the FIRST write ever succeeded:
	// SendSenderKeyReliable can fail right away if
	// peerSessionPubs/peerMLKEMPubs aren't yet populated for that peer
	// (if not retried, the peer never decrypts ANY of our messages for
	// the entire session). Reset to nil (never a plain "all false": a
	// peer already present but not yet revisited by the retry must be
	// treated as "not sent yet", not "send failed") every time we
	// generate a NEW sender_key (senderKeyRotatedMsg), a successful
	// send for the previous key says nothing about the new one. nil
	// until needed (lazy init, same scheme as ephRels).
	keySentTo map[string]bool
	unread    int
	hasError  bool // true = an error was written here while the tab wasn't active (red indicator)
	// pendingEscalated, true if the Console's soft warning (an
	// unconfirmed message older than pendingEscalationAge) has already
	// been shown for the CURRENT stall, avoids repeating it on every
	// round of retryPendingTickMsg until the queue empties completely;
	// goes back to false as soon as OldestPendingAge no longer reports
	// anything pending, so a future new stall generates a new warning.
	pendingEscalated bool

	// pendingReplyTo, explicit reply reference (/msg N) for the
	// NEXT send on this tab, one-shot: consumed and reset by
	// sendMessage/replySentMsg only on a successful send (a send blocked
	// by backpressure or failed leaves the target intact). 0 = none.
	pendingReplyTo uint64

	// msgBuffer, receive-side reordering: ciphertexts (the full raw
	// frame, not just the text, the whole parseMessage must be replayed
	// once unblocked) that arrived out of sequence, held until their
	// turn really comes, see handleIncomingMessage. keyID → idx → frame.
	msgBuffer    map[string]map[uint64]map[string]any
	seenMsgIDs   map[uint64]struct{} // msgIDs already shown, see parseMessage
	groupID      string              // non-empty if a group room
	groupMembers []GroupMember       // the group's members (for /grp-save)
	roomSecret   []byte              // our own secret (the one this client used to connect to the room's server)
	hostKey      string              // member key of whoever opened the group (the WS server's host)

	// secretsByMember, host tab only: the currently valid per-member
	// secret, by member key AND by device (member key →
	// string(devicePub) → secret). A contact with multiple invited
	// devices (fan-out) has an independent entry for each, never one
	// overwriting the other. Needed by /grp-reinvite (which secret(s)
	// to replace) and /grp-ban (revoke all of them, not just one).
	secretsByMember map[string]map[string][]byte

	// invitedKeys, host tab only: member keys of who was invited when the group
	// was opened (cmdInvite/cmdRecall), self excluded. Compared
	// against tab.online (who actually joined) and
	// departures[.]==memberDeclined (who explicitly declined, see
	// case "invite_declined") to know whether "nobody has accepted
	// yet". Empty for invited members' tabs (non-host).
	invitedKeys    []string
	reconnecting   bool // true if an automatic reconnect is in progress
	serverShutdown bool // true if the server sent server_shutdown, don't reconnect

	// rekeyOnNextInit: true between a manual /grp-reconnect and the
	// first subsequent "init" frame, RotateSenderKey needs
	// peerSessionPubs already populated (the members' session pubs,
	// known only after init) to be able to distribute the new key, so
	// it can't be called right after cli.Connect(). Consumed once by
	// the "init" case in handleRoomMsg. Not set by the silent automatic
	// reconnect (reconnectTab): a full rotation has a cost (new ECIES
	// delivery to every member) that only makes sense when the user
	// explicitly asks for it, not on every transient network blip.
	rekeyOnNextInit bool

	// awaitingJoin: true between /grp-join and the first outcome
	// (connected or final error, after any automatic retries),
	// controls when to dismiss the "Connecting…" popup opened by
	// cmdJoin. Via Tor/I2P the first connection can take several
	// seconds, especially over I2P: without this popup the TUI looks
	// stuck right after pressing Enter.
	awaitingJoin bool

	// departures tracks, per member key, how non-connected members left the room.
	// Missing key = never connected or host crash (treated as memberCrashed).
	departures map[string]memberState

	// Incoming contact card, set by a contact_card DM; cleared by
	// /cnt-save or /cnt-ignore. pendingCardFrom is the real sender's
	// member key (resolved via LookupMemberKey on the transfer's
	// from_user_id, NEVER the card's own content, that one only
	// describes WHO the card's subject is, not who sent it).
	pendingCard     *contactCard
	pendingCardFrom string

	// Safety Numbers
	peerIdentityPub ed25519.PublicKey // the peer's identity key; nil if not yet known
	safetyCode      string            // SafetyCode(...) precomputed; empty if peerIdentityPub is nil
	peerIsContact   bool              // true if peerIdentityPub comes from the local keystore (verified)

	// pingGen distinguishes pingWatchdog cycles across successive
	// connections: incremented on every roomConnectedMsg. A
	// pingProbeOKMsg with a no-longer-current gen (from the previous
	// connection's watchdog, still in flight at reconnect time) is
	// discarded instead of scheduling a second parallel cycle.
	pingGen int

	// lastActivityAt: time of the last frame successfully received on
	// this tab, a stronger liveness proof than an explicit ping/pong
	// because it also exercises both sides' application loops, not just
	// the WS protocol-level auto-pong. pingWatchdogTickMsg skips the
	// ping if this is recent enough (see above).
	lastActivityAt time.Time

	// lastPingProbeAt: last active probe attempt (or equivalent, see
	// lastActivityAt above), the external tick runs at wakeScanInterval's
	// cadence (more frequent, for wakes) but the actual probe should
	// only be attempted every pingWatchdogInterval: this field says
	// whether it's time yet or not.
	lastPingProbeAt time.Time

	// pingMisses: consecutive ping cycles with no response for the
	// current connection, reset by any pong or activity received, a
	// reconnect only triggers once pingWatchdogMissThreshold is reached
	// (see the comment on the constant).
	pingMisses int

	// lastWakeActedAt: last time an incoming wake-up packet for this
	// groupID actually triggered a reconnectTab, an anti-abuse,
	// anti-redundancy cooldown on the receiving side (multiple members
	// may detect the same outage and send the wake in parallel, or a
	// malicious/buggy sender could flood more than one). See case
	// "wake" in case knockMsg.
	lastWakeActedAt time.Time
}

// isStandardTab is true for the "service" tabs (Console, Contacts,
// Groups, Tor, File), everything that isn't a real chat room. Free
// text is never a valid action in these tabs.
func (t *roomTab) isStandardTab() bool {
	return t.isConsole || t.isContacts || t.isGroups || t.isTor || t.isFiles
}

// registerMember records one member from an init/user_joined entry,
// session userID, root identity key, session keys and display label,
// and returns its member key ("" if the entry carries no identity key:
// such an entry is never registered).
func (t *roomTab) registerMember(um map[string]any) string {
	uid, _ := um["user_id"].(string)
	name, _ := um["username"].(string)
	identityPub := decodeIdentityPubField(um)
	key := client.MemberKeyOf(identityPub)
	if uid == "" || key == "" {
		return ""
	}
	t.cli.RegisterUser(uid, name, identityPub)
	if sessionPub, _ := um["session_pub"].(string); sessionPub != "" {
		t.cli.RegisterSessionPub(uid, sessionPub)
	}
	if mlkemPub := decodeMLKEMPubField(um); mlkemPub != nil {
		t.cli.RegisterMLKEMPub(uid, mlkemPub)
	}
	t.setMemberLabel(key, name)
	return key
}

// setMemberLabel records the username label a member is known under in
// this room, display only.
func (t *roomTab) setMemberLabel(key, name string) {
	if key == "" || name == "" {
		return
	}
	if t.memberLabels == nil {
		t.memberLabels = make(map[string]string)
	}
	t.memberLabels[key] = name
}

// isOnline reports whether the member with the given key is connected.
func (t *roomTab) isOnline(key string) bool {
	return slices.Contains(t.online, key)
}

// removeOnline drops key from the connected members.
func (t *roomTab) removeOnline(key string) {
	t.online = slices.DeleteFunc(t.online, func(k string) bool { return k == key })
}

// addOnline adds key to the connected members, once.
func (t *roomTab) addOnline(key string) {
	if key != "" && !t.isOnline(key) {
		t.online = append(t.online, key)
	}
}

// memberKey is the member key of a group member.
func memberKey(gm GroupMember) string {
	return client.MemberKeyOf(gm.IdentityPub)
}

// memberKeyPub decodes a member key back into the identity key, nil if
// malformed.
func memberKeyPub(key string) ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}

// decodeIdentityPubField reads the "identity_pub" field of an
// init/user_joined entry.
func decodeIdentityPubField(raw map[string]any) []byte {
	s, _ := raw["identity_pub"].(string)
	if s == "" {
		return nil
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return dec
}

// ── TUIParams ─────────────────────────────────────────────────────────────────

// TUIParams collects every parameter needed by the multi-room TUI.
type TUIParams struct {
	// Username, passed here directly by the caller, which already knows it.
	Username string
	Contacts []ContactInfo
	DialTor  func(context.Context, string, string) (net.Conn, error)
	// IsolatedDialer, if non-nil, returns a DialContext with a dedicated
	// Tor circuit for the given token (typically the chat name or the
	// groupID). Connections with the same token share the circuit;
	// different tokens use separate circuits. ctx only covers the
	// creation of the dialer/isolated session itself (for I2P, a real
	// blocking SAM round-trip), not the connections opened afterward.
	IsolatedDialer func(ctx context.Context, token string) func(context.Context, string, string) (net.Conn, error)
	KnockCh        <-chan shared.KnockPayload
	TorLogCh       <-chan string // network process log (Tor or I2P); nil = no dedicated tab
	// SysLockCh receives one value each time the host OS reports an
	// explicit session lock (systemd-logind on Linux desktop,
	// see internal/syslock), nil where unavailable (other platforms,
	// or no logind/D-Bus session to watch). Triggers the same immediate
	// lock as cmdLock, never an unlock: the interface unlock always
	// goes through its own configured secret.
	SysLockCh <-chan struct{}
	// NetworkName is the name shown on the log tab and in messages that
	// mention the active network ("Tor", "I2P", ...). Empty = default
	// "Tor" (compatibility with callers/tests that don't set it).
	NetworkName string
	BootLog     []string // startup lines (network bootstrap, hidden service/destination) to show in the Console tab
	MyAddr      string
	// AddressFromPub computes the network address reachable from an
	// Ed25519 public key, OnionAddressFromPub or I2PAddressFromPub
	// depending on the active network, decided by cmd/main.go. Needs
	// only the public key, never the private one: applies to our own
	// address (MyAddr, already computed) as well as contacts' addresses.
	AddressFromPub func(pub ed25519.PublicKey) string
	MyIdentityPub  ed25519.PublicKey
	// MyMLKEMPub is our own durable ML-KEM-768 encapsulation key (1184
	// bytes, ks.MLKEMPubBytes()). See model.myMLKEMPub.
	MyMLKEMPub []byte
	LocalHost  string
	LocalPort  int
	// identityPub (both) can be nil if not yet known at call time,
	// propagated to already-connected members via wsUserJoined/userInfo.
	// AddRoom/ReplaceRoomSecret register a per-member secret on OUR OWN
	// local server (RoomRegistry.AddSecret/ReplaceSecret), peerKey is
	// the IdentityKey-per-relationship of the member who will present
	// this secret (to verify ClientHello.Sig), mySigningKey is OUR OWN
	// toward that same member (to sign ServerHello.Sig). For a real
	// contact: derived from Contact.PeerRelIdentityPub/RelIdentityPriv
	// (+ PQC companions). For the host's connection to its own server
	// (loopback, no real contact involved): an ad-hoc ephemeral pair,
	// the same one passed as mySigningKey to that connection's client.New.
	// devicePub (in all three functions below) is the member/contact's
	// device pubkey, the key their entry lives under in Contact.Devices.
	// Nil for the host's self-registration.
	// resolveKeys, passed from tui.go to both, is never called here nor
	// cached by the caller, RoomRegistry calls it back on EVERY
	// handshake verification, so no key pair is ever stored by value
	// and no call site has to refresh it after a mutation.
	AddRoom           func(roomID string, secret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool))
	ReplaceRoomSecret func(roomID string, oldSecret, newSecret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool))
	// ResolveRelKeysForDevice (keystore.Keystore.RelKeysForDevice) LIVE
	// resolves the relationship key pair for an exact contact+device,
	// the source used by model.relKeysResolver to build the resolveKeys
	// passed to AddRoom/ReplaceRoomSecret above, never for direct use elsewhere.
	ResolveRelKeysForDevice func(identityPub, devicePub []byte) (shared.RelPeerKey, shared.RelSigningKey, bool)
	// BanMember permanently removes a member's secret from roomID
	// (RoomRegistry.RemoveSecret) and disconnects them if currently
	// connected (RoomRegistry.KickMember), /grp-ban, host only. userID
	// can be empty (member offline at ban time): the secret is still
	// removed, KickMember simply becomes a no-op. Returns whether an
	// active connection was actually closed (for a diagnostic message
	// only, doesn't change the command's outcome).
	BanMember   func(roomID string, secret []byte, userID string) bool
	SavedGroups []GroupInfo
	SaveGroup   func(g GroupInfo) error
	// OnContactDevicePub, called when a contact's observed device
	// pubkey differs from ContactInfo.KnownDevicePub (including first
	// TOFU adoption), remote_nuke. Never blocking: persistence only.
	OnContactDevicePub func(contactPub []byte, devicePub []byte) error
	DeleteContact      func(pub []byte) error
	DeleteGroup        func(nameOrID string) error
	// AddContact saves a new contact and IMMEDIATELY generates their two
	// relationship keys (IdentityKey/ContentKey-per-contact toward
	// them), returned here so the caller (contactAddedMsg) can
	// immediately populate the local ContactInfo mirror, without
	// waiting for an extra round of I/O. The counterparts (PeerRel*)
	// only arrive later, via rel_init/rel_init_ack.
	AddContact func(username, localName string, identityPub, mlkemPub, mldsaPub []byte, introducedBy string, introducedByPub []byte) (myIdentKey, myContentKey shared.RelSigningKey, err error)
	// UpdateContactRelKeys persists a partial update of an existing
	// contact's relationship keys, only upd's non-empty fields get
	// written, the others stay whatever was already in the address
	// book. Used by the rel_init/rel_init_ack cycle (see applyRelInit):
	// both to generate OUR OWN keys on the fly if they didn't exist yet
	// (rare case), and to register the PEER's just-received public
	// keys. Identifies the contact by IdentityPub (never by username,
	// which can repeat across different contacts, a namesake after a
	// nuke+recreation by someone else): automatic/knock-driven, never a
	// typed name available to a picker, must stay unambiguous.
	UpdateContactRelKeys func(pub []byte, upd RelKeyUpdate) error
	// ResetRelInitConfirmed resets to false ONLY the relevant flag
	// (RelIdentityConfirmedByPeer or RelContentConfirmedByPeer, chosen
	// by which, "identity"|"content") for ONE device of a contact,
	// the ONLY way to do this (UpdateContactRelKeys/RelKeyUpdate only
	// ever turn them on together, never off, by design, see the
	// comment on the field). Kept separate precisely because the
	// self-heal always concerns exactly ONE of the two: the host's
	// IdentityKey-per-relationship local copy ending up out of sync
	// from a regeneration that never propagated (case roomErrMsg/
	// client.ErrInvalidServerSig in tui.go, which="identity"), or the
	// same mismatch on the ContentKey that signs MESSAGES/FILES
	// (which="content"), resetting only the relevant one never blocks
	// ReadyDevices()/invites over an issue isolated to the other key. devicePub identifies the exact device (empty or
	// non-matching falls back to SoleDevice for compatibility).
	// Identifies the contact by IdentityPub, same reason as
	// UpdateContactRelKeys above.
	ResetRelInitConfirmed func(pub, devicePub []byte, which string) error
	// PromoteEphemeralContact persists as a new real Contact an
	// ephemeral relationship already established and promoted by both
	// sides (see finalizePromotion), unlike AddContact, it generates no
	// new key: myIdentKey/myContentKey and the peer's pubkeys are
	// already the ones exchanged in the room's ephemeral bootstrap, only
	// persisted here.
	PromoteEphemeralContact func(username string, transportPub, transportMLKEMPub, transportMLDSAPub []byte, myIdentKey, myContentKey shared.RelSigningKey, peerIdent shared.RelPeerKey, peerIdentMLKEMPub []byte, peerContent shared.RelPeerKey, peerContentMLKEMPub []byte) error
	// StartRelIdentityRotationByPub/StartRelContentRotationByPub start
	// rotating one of the two relationship keys toward EVERY ready
	// device of a contact (fan-out), generate an independent new key
	// for each, put the old one in the vault (for continuity during the
	// pending window), and return the devicePub→new key map to
	// immediately update the local ContactInfo mirror (same scheme as
	// AddContact). A device whose SIBLING key is already rotating is
	// skipped silently, never blocking the others
	// (keystore.StartRelIdentityRotationByPub/StartRelContentRotationByPub);
	// the error only returns if NO device could be started. By
	// IdentityPub, not Username: the contact arrives already
	// disambiguated by cmdStartRelRotation (resolveNameOrPickerKey),
	// never a second ambiguous lookup here (two contacts can share the
	// same Username, e.g. after a /nukex).
	StartRelIdentityRotationByPub func(pub []byte) (map[string]shared.RelSigningKey, error)
	StartRelContentRotationByPub  func(pub []byte) (map[string]shared.RelSigningKey, error)
	// MarkRelRotationConfirmed closes the rotation, which is "identity"
	// or "content", after a real rel_*_rotate_ack, for ONE exact device
	// (devicePub, from the ack's RelRotatePayload.DevicePub field):
	// clears the pending flag and the old key in the vault ONLY for that
	// device. Returns false if there was no rotation of that type in
	// progress for that device (a late/duplicate ack, harmless).
	// Identifies the contact by IdentityPub, same reason as
	// UpdateContactRelKeys above (automatic/knock-driven).
	MarkRelRotationConfirmed func(pub, devicePub []byte, which string) bool
	// MarkDeviceRevoked applies a verified revocation (knock
	// "rel_revoke", see applyRelRevoke) to ONE device of a contact,
	// revokeIdentity/revokeContent reflect which of the two
	// certificates were present and verified. Returns false only if the
	// contact or device weren't found, never for "already revoked"
	// (idempotent by design, see keystore.Keystore.MarkDeviceRevoked).
	// By IdentityPub, same reason as UpdateContactRelKeys above.
	MarkDeviceRevoked func(pub, devicePub []byte, revokeIdentity, revokeContent bool) bool
	// AckSiblingRevocation marks Acked=true in the
	// Contact.SiblingRevocations pool for every entry referring to
	// peerDevicePub, on receipt of a "rel_revoke_ack", best-effort,
	// no-op if the pool has no entry for that device. Doesn't
	// distinguish between different siblings with independent
	// relationships toward the same contact device (the ack carries no
	// identifier of the sending sibling), harmless, Acked is only a
	// retry optimization, never a security-relevant value.
	AckSiblingRevocation func(pub, peerDevicePub []byte) bool
	// IsDeviceNuked reports whether devicePub (a sibling device's own
	// Keystore.DevicePub, never a DeviceID) is known to have been
	// nuked, drives the sibling retry queue in probeContacts: a
	// not-yet-Acked SiblingRevocations entry only gets resent once its
	// SiblingDevicePub passes this check, never unconditionally.
	IsDeviceNuked func(devicePub []byte) bool
	// SetPendingRelKeys registers a relationship key conflict
	// (TrustDanger), keys PROPOSED by a rel_init/rel_init_ack, never
	// applied directly (see applyRelInit). Identifies by IdentityPub,
	// same reason as UpdateContactRelKeys above.
	SetPendingRelKeys func(pub []byte, pending PendingRelKeys) error
	// ConfirmPendingRelKeys closes the conflict above after an explicit
	// out-of-band user confirmation (/sec-verify): applies the pending
	// keys, resets Verified (must be regained with a new Safety
	// Number). Returns false if there was no pending conflict.
	ConfirmPendingRelKeys func(pub []byte) bool
	ChangePassword        func(oldPwd, newPwd string) error
	// SetDuress changes the decoy identity's own identity password
	// (always non-empty, the decoy identity exists structurally and
	// can never be removed), see cmdDuress and model.pwdMode 5/6.
	SetDuress        func(newPwd string) error
	KeystorePassword string

	// SetLockSecret sets/replaces the interface lock's optional PIN, see
	// cmdLockPIN. The identity password always unlocks the lock regardless
	// (compared directly against KeystorePassword below, in RAM), so a PIN
	// is never required for the lock to be usable.
	SetLockSecret func(secret string, isPIN bool, duressMarker string, duressPosition int) error
	// CheckLockSecret compares a candidate input against the configured
	// lock PIN, if any, never against the keystore's real password
	// (always a distinct value, checked separately in the TUI itself).
	CheckLockSecret func(candidate string) keystore.LockCheckResult
	// CheckDuressPassword compares candidate against the decoy identity's
	// own identity password, recognized ALSO at the lock prompt, a
	// fallback path independent of the PIN's native duress
	// (CheckLockSecret above).
	CheckDuressPassword func(candidate string) bool
	// InterfaceLockTimeout is the inactivity threshold after which the
	// interface re-locks itself, zero disables the automatic lock (the
	// manual command remains always available regardless).
	InterfaceLockTimeout time.Duration
	// SaveInterfaceLockTimeout persists the threshold to config.json
	// when changed live by /sec-lock-timeout, so it survives a restart.
	SaveInterfaceLockTimeout func(time.Duration) error
	// TimeNukeTimeout is how long the interface may stay LOCKED before
	// an automatic nukex-equivalent secure erasure triggers, zero
	// disables it. See config.TimeNukeTimeoutDuration.
	TimeNukeTimeout time.Duration
	// SaveTimeNukeTimeout persists the threshold to config.json when
	// changed live by /sec-nuke-timeout, same reason as
	// SaveInterfaceLockTimeout above.
	SaveTimeNukeTimeout    func(time.Duration) error
	UpdateContactLocalName func(pub []byte, localName string) error
	// CheckCircuits, if non-nil, synchronously checks whether Tor has
	// active circuits. Uses the control port and is fast (< 1 ms). If
	// nil the check is skipped.
	CheckCircuits func() bool
	// HSPublished indicates that the hidden service descriptor was
	// already published to the Tor directory servers before the TUI started.
	// bine/tor.Listen internally waits for HS_DESC UPLOADED before
	// returning, so this flag is true every time AddHiddenService succeeded.
	HSPublished bool

	// GetBackupMnemonic recomputes the 24 BIP-39 words encoding the
	// identity key on demand, a closure instead of a precomputed value
	// so they aren't kept in plaintext in RAM for the whole session:
	// called only at the moment the user passes the password check for
	// /sec-backup (case 4, pwdMode), the result is zeroed by the model
	// as soon as the popup closes. A closure rather than a direct
	// dependency on internal/keystore, for the same reason as above
	// (this package must not depend on the keystore package).
	GetBackupMnemonic func() ([]string, error)

	// SaveIdentityQR writes this identity's QR (plain .txt + multi-part
	// PNG, same format as `neutrino show-qr`'s "image" choice) to disk
	// and returns every path written, called only from /show-qr's own
	// "save as image" choice. A closure rather than a direct dependency
	// on internal/keystore, for the same reason as GetBackupMnemonic
	// above (this package must not depend on the keystore package); and
	// unlike GetBackupMnemonic, this package must never call fmt.Print
	// directly either, that would corrupt bubbletea's alt-screen buffer
	// while the TUI is running, so the file-writing itself (which does
	// print) stays on the cmd/main.go side of this closure.
	SaveIdentityQR func() ([]string, error)

	// SenderKeyInterval is the senderKey's rotation interval for
	// intra-session forward secrecy. Zero disables automatic rotation.
	SenderKeyInterval time.Duration

	// PendingSlotLimit/MessageRetryDelay/PendingEscalationAge/MessageTTL
	// configure the reliable delivery queue (internal/client/pending.go),
	// resolved from config.json by the caller, never read directly by
	// internal/client, same principle as SenderKeyInterval above. A
	// value <= 0 leaves the client's hardcoded defaults (identical to
	// config.Default()).
	PendingSlotLimit     int
	MessageRetryDelay    time.Duration
	PendingEscalationAge time.Duration
	MessageTTL           time.Duration

	// SenderKeyMessageBudget, count-based rotation criterion (K
	// messages per generation), complementary to SenderKeyInterval,
	// see Client.MessagesSinceRotation.
	SenderKeyMessageBudget int

	// Timing, contact probes
	ActiveInterval       time.Duration // periodic probe interval (default 1m)
	ActiveInitialDelay   time.Duration // first probe delay (default 1m)
	ProbeContactsTimeout time.Duration // probeContacts context timeout (default 90s)
	ProbeRetryCount      int           // dial attempts per contact per cycle (default 3)
	ProbeRetryDelay      time.Duration // backoff between attempts (default 20s)

	// Timing, Tor circuits
	TorProbeInterval     time.Duration // circuit check interval (default 5m)
	TorProbeInitialDelay time.Duration // first check delay (default 10s)
	WarmupInterval       time.Duration // warmup interval (default 5m)
	WarmupInitialDelay   time.Duration // first warmup delay (default 20s)
	WarmupTimeout        time.Duration // cmdWarmupCircuits timeout (default 1m)
	SelfKnockTimeout     time.Duration // probeSelfKnock HTTP timeout (default 1m)

	// Timing, knocks and invites. No field for config.KnockTimeout:
	// that role (an invite's HTTP timeout) is covered here by
	// InviteTimeout; config.KnockTimeout is not used by the TUI.
	KnockHttpTimeout time.Duration // background automatic knocks timeout (default 15s)
	KnockRetryDelay  time.Duration // backoff between knock retries (default 20s)
	InviteTimeout    time.Duration // group invite timeout (default 30s)

	// Limits, file transfer
	FileTransferMaxSizeMiB       int           // maximum original file size for /grp-file-send (default 512)
	FileWarpChunkSizeKiB         int           // chunk size, warp preset (default 64)
	FileSlowChunkSizeKiB         int           // chunk size, slow preset (default 16)
	FileSlowDelayMs              int           // fixed delay between chunks in the slow preset (default 250)
	FileTransferOfferTimeout     time.Duration // how long to wait for responses to a file_offer (default 90s)
	FileOfferBatchWindow         time.Duration // how long to wait after sending the offer before starting the send toward those who already accepted (default 10s)
	FileWarpMaxInFlightChunks    int           // window of unacked chunks, warp preset (default 8)
	FileSlowMaxInFlightChunks    int           // window of unacked chunks, slow preset (default 2)
	FileTransferReconnectTimeout time.Duration // how long to wait for a recipient's ack before isolating them (default 2m)
	FileAcceptRetryInterval      time.Duration // how often a recipient resends their own file_accept if the first chunk still hasn't arrived (default 30s), see config.go for the value's rationale
	// StrongCompressionEnabled enables strong packing (LZMA2/XZ, see
	// shared.PackData) as pre-compression of file/contact-card content
	// before symmetric encryption (ContentKey-per-relationship).
	// Default true (config.json: strong_compression_enabled).
	StrongCompressionEnabled bool

	// MarkContactVerifiedByPub, used by /sec-verify,
	// MarkContactUnverifiedByPub by /sec-unverify, on a contact always
	// resolved by identity key.
	MarkContactVerifiedByPub   func(pub []byte) error
	MarkContactUnverifiedByPub func(pub []byte) error

	// FlushContactsActivity persists in a single Save() both the acks
	// (probe_ack, a strong signal) and the "presences"
	// (reached via TCP in this probe cycle, a weaker signal) accumulated
	// since the last flush (key: username). Called at most once per
	// probe cycle, never per single event: Save() re-derives the key
	// with Argon2id on every call, so writing on every single event
	// would be needlessly costly.
	FlushContactsActivity func(acks map[string]time.Time, seen map[string]time.Time) error
	// DHTagFn computes shared.KnockDHTag(my_identity_priv, peerPub), a
	// static-static DH tag attached in the clear to every POST /knock
	// (pre-decryption filter on the server side, mandatory mutuality).
	// A closure instead of the raw private key: internal/client must
	// never see the identity's private material directly.
	DHTagFn func(peerPub ed25519.PublicKey) ([]byte, error)
	// DHTagFnOld, the same function as DHTagFn but with the OLD
	// root identity key during a root rotation. The DH tag is static-static, so
	// it only matches if the sender signs with the key that EXACTLY
	// matches the pubkey the recipient already has in their address
	// book for them, a recipient still in pendingSet still has the
	// OLD pubkey, so a knock tagged with the new key gets discarded by
	// their server BEFORE being decrypted (identical 202 response,
	// invisible on the sending side). probeContacts chooses per-recipient
	// which of the two to call, the same pendingSet already used for
	// signFn above. nil = no active transition.
	DHTagFnOld func(peerPub ed25519.PublicKey) ([]byte, error)

	// SignRelBootstrap/SignRelBootstrapMLDSA sign a proposal of
	// relationship keys (+ device) with the sender's root IdentityKey,
	// ONLY the persistent rel_init/rel_init_ack channel
	// (sendRelInitAndReport, never the room's ephemeral bootstrap), see
	// the comment on RelBootstrapPayload.Ts/Sig/SigMLDSA in
	// internal/shared/relbootstrap.go. A closure instead of the raw
	// private key, same reason as DHTagFn. SignRelBootstrapMLDSA nil =
	// no ML-DSA counterpart available yet, never blocking (same
	// treatment as the project's other hybrid-PQC signatures).
	SignRelBootstrap      func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte
	SignRelBootstrapMLDSA func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte

	// MyDevicePub/SignDeviceSig, remote_nuke. MyDevicePub is the
	// device-level Ed25519 public key (ks.DevicePubKey(), 32 bytes),
	// inserted into sealedMsg.DP of every message sent in every room.
	// SignDeviceSig signs shared.DeviceSigMsg with the device-level
	// private key (ks.DevicePrivKey()), a closure, same reason as
	// DHTagFn: internal/client must never see the device's private key directly.
	MyDevicePub   []byte
	SignDeviceSig func(ciphertext []byte, ts string) []byte

	// SignPQCSig, hybrid PQC network identity. Signs shared.PQCSigMsg
	// with the network identity's ML-DSA-65 private key
	// (ks.MLDSAPrivKey()), a closure, same reason as SignDeviceSig:
	// internal/client must never see the private key directly. Always
	// passed (never nil): the actual
	// activation is the per-room Client.SetPQCSign toggle, not the
	// absence of this closure.
	SignPQCSig func(ciphertext []byte, ts string) []byte

	// MyDeviceID/AuthorityPubKeys/KnownDevices/SignRemoteNuke/
	// SignRemoteNukeAck, the remote_nuke protocol. MyDeviceID is our
	// own Keystore.DeviceID (the target of a received remote_nuke
	// command). AuthorityPubKeys is the set of Ed25519 public keys
	// (current AND old) of ALL identities in this file
	// (Keystore.AllAuthorityPubKeys), an incoming remote_nuke command
	// is verified against these: possessing the private key of any one
	// of them is itself the authorization, no separate list of
	// "authorized devices" to consult. KnownDevices is the list of
	// devices THIS identity can direct a remote_nuke command toward
	// (populated by "indoor" synchronization, empty until it has ever
	// run), read live (Keystore.KnownDevicesSnapshot) so a sync shows up
	// at once. SignRemoteNuke signs an outgoing command with an identity
	// from this file (the AUTHORITY, who sends the command);
	// SignRemoteNukeAck signs the "about to disappear" confirmation with
	// THIS device's DEVICE-level key (the target, who receives it),
	// two conceptually different keys, never the same closure.
	MyDeviceID        []byte
	AuthorityPubKeys  []ed25519.PublicKey
	KnownDevices      func() []DeviceRecordInfo
	SignRemoteNuke    func(targetDeviceID []byte, ts string) []byte
	SignRemoteNukeAck func(targetDeviceID []byte, ts string) []byte
	// AuthorityPubKeysMLDSA/SignRemoteNukeMLDSA, ML-DSA-65 counterpart
	// of AuthorityPubKeys/SignRemoteNuke above (hybrid PQC network
	// identity), same role. No counterpart for SignRemoteNukeAck: that
	// one signs with the DEVICE-level key (DevicePriv), not the network
	// identity, out of scope here.
	AuthorityPubKeysMLDSA []*mldsa65.PublicKey
	SignRemoteNukeMLDSA   func(targetDeviceID []byte, ts string) []byte

	// NetworkIdentityPubFor, used by the remote_nuke fan-out: a device
	// listed in KnownDevices hosts THIS identity by definition, but if
	// it hosts it as an ADDITIONAL device (not D1) its real network
	// address isn't OnionAddressFromPub applied directly to our own
	// IdentityPub (which only reaches D1), but that same function
	// applied to the derived key
	// Keystore.NetworkIdentityPrivKeyFor(deviceID), computable only by
	// whoever holds THIS identity's private root, i.e. always ourselves
	// (never a third party's sibling identity, those remain the
	// existing case above). Returns only the derived PUBLIC key (never
	// the private one through this closure), cmdRemoteNukeFanOut adds
	// it as an ADDITIONAL candidate, never replacing the existing
	// root-per-sibling-identity candidates.
	NetworkIdentityPubFor func(deviceID []byte) ed25519.PublicKey

	// MyMLDSAPub is our own durable ML-DSA-65 signing public key
	// (ks.MLDSAPubBytes()), a twin of MyIdentityPub/MyMLKEMPub, used to
	// build RootRotatePayload.NewMLDSAPub.
	MyMLDSAPub []byte

	// RootRotationPending returns, read live, the contacts and sibling
	// devices that haven't confirmed the latest root rotation yet
	// (Keystore.RootRotationPendingSnapshot), nil when no rotation is
	// in progress.
	RootRotationPending func() ([][]byte, [][]byte)

	// OldIdentityPub, the PREVIOUS public root, read live
	// (Keystore.OldIdentityPrivKeyForRotation().Public(), nil if no root
	// rotation is in progress). Used to choose FromIdentityPub in knocks
	// toward a contact still pending, see fromPubFor, probeContacts.
	OldIdentityPub func() ed25519.PublicKey

	// AckRootRotationContact/AckRootRotationDevice/MaybeFinalizeRootRotation
	// wrappers of Keystore.AckRootRotationContact/AckRootRotationDevice/
	// MaybeFinalizeRootRotation that also save to disk.
	AckRootRotationContact    func(pub []byte) bool
	AckRootRotationDevice     func(deviceID []byte) bool
	MaybeFinalizeRootRotation func()

	// UpdateContactRootIdentity persists a contact's NEW root
	// IdentityKey/MLKEMPub/MLDSAPub after a verified root_rotate, see
	// applyRootRotate. Also resets Contact.Verified (the previous
	// verification concerned the old key).
	UpdateContactRootIdentity func(pub []byte, newIdentityPub ed25519.PublicKey, newMLKEMPub, newMLDSAPub []byte) error

	// StartRootRotation starts a root rotation WITH CONTINUITY by
	// generating a new root (Keystore.StartRootRotation), IMMEDIATELY
	// publishes a second hidden service with the new key and starts a
	// second server.RunOnListener on it (the old one stays active, no
	// interruption for whoever hasn't received the announcement yet:
	// online contacts migrate right away, offline ones will do so on
	// their own return, no need to keep the old HS alive just for
	// them). Returns the new network address.
	StartRootRotation func() (newIdentityPub ed25519.PublicKey, newMLKEMPub, newMLDSAPub []byte, newAddr string, err error)

	// AdoptRootRotation applies a root received from a sibling device
	// (device_sync), the same new-hidden-service publication as
	// StartRootRotation above, but the key arrives already prepared
	// instead of being generated (Keystore.AdoptRootRotation). Behaves
	// exactly like the device that started the rotation: same
	// republication, only the key's origin changes.
	AdoptRootRotation func(newIdentityKey, newMLKEMKey, newMLDSAKey []byte) (newAddr string, err error)

	// BuildDeviceSyncRotationKnock builds (KnockDHTag tag,
	// EncryptKnockWithTag encryption) a "device_sync" knock that
	// propagates the CURRENT root material (read here, never passed by
	// internal/client) toward a sibling device identified by
	// targetDeviceID. useOldKey picks the OLD root for tag+encryption
	// (the sibling hasn't adopted the latest rotation yet, its hidden
	// service remains reachable only at the address derived from that one).
	BuildDeviceSyncRotationKnock func(useOldKey bool, targetDeviceID []byte) (string, error)

	// BuildDeviceSyncSyncKnock builds a "device_sync" knock that carries
	// ONLY an address-book synchronization, OUR OWN
	// (indoor.SyncPayload, built internally by whoever implements this
	// closure, never passed by internal/client), toward a sibling
	// device, on explicit request (not automatic like the indoor LAN
	// one).
	BuildDeviceSyncSyncKnock func(useOldKey bool, targetDeviceID []byte) (string, error)

	// BuildDeviceSyncAckKnock builds the fire-and-forget
	// "device_sync_ack" knock, always with the CURRENT root (by
	// definition, the ack arrives after already having adopted it).
	// includeSync true also makes it the return leg of an address-book
	// synchronization (OUR OWN address book, built internally,
	// bidirectional exchange).
	BuildDeviceSyncAckKnock func(targetDeviceID []byte, includeSync bool) (string, error)

	// OldNetworkIdentityPubFor, the same derivation as
	// NetworkIdentityPubFor but on the PREVIOUS root
	// (Keystore.OldNetworkIdentityPrivKeyForRotation), nil if no root
	// rotation is in progress. A sibling device that hasn't adopted the
	// latest rotation yet remains reachable ONLY at this address
	// (derived from the root it's still using), the device_sync
	// propagator tries BOTH candidates (old and new), never just one.
	OldNetworkIdentityPubFor func(deviceID []byte) ed25519.PublicKey

	// MergeSyncedContacts applies a remote address-book synchronization
	// received from a sibling device (device_sync, SyncData JSON of
	// indoor.SyncPayload), decode+Keystore.AddMirroredContacts+Save,
	// all here so internal/client doesn't need to import
	// internal/indoor. rejectedRows is JSON-marshaled
	// []keystore.DeletedContact for every incoming contact skipped
	// because a tombstone for it already exists, the caller sends it
	// back to the peer via BuildContactTombstoneKnock when non-empty.
	MergeSyncedContacts func(data []byte) (rejectedRows []byte, err error)
	// ContactsSnapshot returns the address book as stored in the keystore
	// read after a sync between our own devices to show the contacts
	// and devices it brought in (see adoptSyncedContacts).
	ContactsSnapshot func() []ContactInfo

	// BuildContactTombstoneKnock builds a "contact_tombstone" knock
	// carrying rows (JSON-marshaled []keystore.DeletedContact, from
	// MergeSyncedContacts's rejectedRows or from an identical check run
	// directly against a peer's live contacts), sent fire-and-forget
	// toward whoever just sent a contact this identity already deleted.
	BuildContactTombstoneKnock func(rows []byte) (string, error)

	// ApplyContactTombstoneReplies adopts incoming tombstone rows
	// (JSON-marshaled []keystore.DeletedContact, from a received
	// "contact_tombstone" knock's Rows): deletes any matching live
	// contact, merges ConfirmedSiblings, persists immediately. Returns
	// acked (JSON-marshaled [][]byte of the IdentityPubs just adopted),
	// to echo back in a "contact_tombstone_ack" knock.
	ApplyContactTombstoneReplies func(rows []byte) (acked []byte, err error)

	// BuildContactTombstoneAckKnock builds the fire-and-forget
	// "contact_tombstone_ack" knock carrying acked (JSON-marshaled
	// [][]byte of IdentityPubs).
	BuildContactTombstoneAckKnock func(acked []byte) (string, error)

	// ConfirmContactTombstoneAcked records, on this identity's own
	// tombstone rows, that peerDeviceID has adopted every IdentityPub
	// in acked (JSON-marshaled [][]byte, from a received
	// "contact_tombstone_ack" knock).
	ConfirmContactTombstoneAcked func(acked []byte, peerDeviceID []byte)

	// PendingRemoteNukeTargets/AddPendingRemoteNuke/ClearPendingRemoteNuke
	// a remote_nuke's target can stay unreachable for an arbitrary
	// time (powered off, seized but never turned back on...), so the
	// command isn't a single attempt with limited backoff, it stays
	// queued (Keystore.PendingRemoteNukes) and is retried on every
	// subsequent startup of THIS identity until a remote_nuke_ack
	// arrives. PendingRemoteNukeTargets is the already-resolved list
	// (with SiblingIdentities) to retry at startup
	// (Keystore.PendingRemoteNukeTargets()); AddPendingRemoteNuke
	// registers a new command in the queue at issue time
	// (cmdRemoteNuke); ClearPendingRemoteNuke removes it on the first
	// received ack (handleRemoteNukeAck).
	PendingRemoteNukeTargets []DeviceRecordInfo
	AddPendingRemoteNuke     func(targetDeviceID []byte) error
	ClearPendingRemoteNuke   func(targetDeviceID []byte) error

	// MarkOwnDeviceNuked records THIS device's own DevicePub into
	// Keystore.NukedDevicePubs, in RAM, called by cmdNukeX right before
	// its device-sync fan-out, so the very next BuildDeviceSyncSyncKnock
	// sent to every known sibling carries this device in its
	// NukedDevicePubs. Siblings learn it's gone via the existing
	// device_sync/MergeNukedDevicePubs gossip. Once a sibling's own address book
	// learns this device is nuked (via that same gossip, transitively),
	// its existing SiblingRevocations retry queue (probeContacts) starts
	// sending the real rel_revoke to this identity's contacts on this
	// device's behalf, no new sending mechanism needed for that part.
	MarkOwnDeviceNuked func()

	// PendingDangerBroadcasts/SetDangerBroadcastPending/
	// ConfirmDangerBroadcast, the authority's danger_broadcast (toward
	// its OWN contacts, the primary channel) must also reach a contact
	// that isn't online within the authority's ~90s window.
	// PendingDangerBroadcasts is the already-resolved list from
	// Keystore.PendingDangerBroadcasts (identity keys not yet confirmed,
	// per target device); probeContacts
	// (the periodic probe cycle already running, ~every ActiveInterval)
	// resends the danger_broadcast to every contact still on this list
	// that comes back online in that cycle, no new timer, no dedicated
	// time window. SetDangerBroadcastPending registers the initial list
	// at issue time (cmdRemoteNuke); ConfirmDangerBroadcast removes a
	// contact on receipt of their danger_broadcast_ack (handleDangerBroadcastAck).
	PendingDangerBroadcasts   []DangerBroadcastPendingInfo
	SetDangerBroadcastPending func(targetDeviceID []byte, pubs [][]byte) error
	ConfirmDangerBroadcast    func(targetDeviceID, pub []byte) error

	// PendingDangerEnds/SetDangerEndPending/ConfirmDangerEnd, same
	// scheme as PendingDangerBroadcasts above, a separate queue for
	// "danger_end" (the DEFINITIVE "device confirmed destroyed" notice,
	// not just "in progress"). Populated at two distinct points: by the
	// TARGET itself, right before self-destructing (see
	// AllIdentitiesContacts below, covers ALL sibling identities, not
	// just the active one); and by the AUTHORITY, on receipt of the
	// remote_nuke_ack, as a safety net toward its OWN contacts (only
	// those of the identities it holds, never ones never
	// duplicated/synced), a contact who didn't receive the direct
	// danger_end from the target (was offline at that moment) still
	// receives it, later, from here.
	PendingDangerEnds   []DangerBroadcastPendingInfo
	SetDangerEndPending func(targetDeviceID []byte, pubs [][]byte) error
	ConfirmDangerEnd    func(targetDeviceID, pub []byte) error

	// AllIdentitiesContacts, if non-nil, exposes, for EVERY sibling
	// identity present in the keystore (including itself), that
	// specific identity's address book and signing capability (see
	// AllIdentityContactsInfo). Called ONLY by executeRemoteNuke for the
	// danger_end broadcast right before self-destruction: it's the ONLY
	// place in the code that must act on behalf of identities other
	// than the one active in this TUI session (everything else keeps
	// operating only on m.contacts/m.dhTagFn).
	AllIdentitiesContacts func() []AllIdentityContactsInfo

	// RunIndoorSync runs an "indoor" (LAN) synchronization window,
	// remote_nuke, with another instance holding the SAME identity
	// (duplicated via `neutrino restore`): discovery via UDP multicast,
	// encrypted address-book exchange + mutual registration as a known
	// device, entirely in cmd/main.go (the address book and the
	// identity's private key must never pass through internal/client,
	// same principle as every other closure here). Blocking until the
	// first successful exchange or the window expires (~60s), ALWAYS
	// called from a background goroutine (tea.Cmd), never on Update()'s thread.
	RunIndoorSync func(ctx context.Context) error

	// MyDeviceLabel/SetDeviceLabel, the name the user chose for THIS
	// device (Keystore.DeviceLabel, e.g. "Galaxy S22"), asked the first
	// time in the wizard and always renameable with /sec-device-label,
	// without a proper name, the only way to distinguish two or three
	// known devices in /sec-remote-nuke's picker would be the raw
	// DeviceID (16 random bytes in hex), useless for recognizing "this
	// is the phone that got stolen from me".
	MyDeviceLabel  string
	SetDeviceLabel func(label string) error
}

// ── model ─────────────────────────────────────────────────────────────────────

type model struct {
	tabs      []*roomTab
	active    int
	vp        viewport.Model
	ta        textarea.Model
	ready     bool
	quitting  bool
	quitMode  bool
	lastTermH int
	lastTermW int

	// masked password state, replaces the textarea with a hidden prompt
	// 0=off  1=current (passwd)  2=new (passwd)  3=confirm (passwd)  4=verify (backup)
	// 5=new (duress)  6=confirm (duress)  7=new lock PIN  8=confirm
	// lock PIN  9=PIN duress character  10=position of the duress
	// character, see cmdLockPIN.
	pwdMode  int
	pwdBuf   string // current hidden input
	pwdOld   string // current password entered
	pwdFirst string // first new password entered (for comparison)

	// interface lock PIN setup flow state (pwdMode 7-10)
	lockSetupSecret string // confirmed PIN awaiting the duress marker/position
	lockSetupMarker string // the PIN's duress character, a single rune

	// interface lock on inactivity. Neutrino stays fully active while
	// locked (Tor/I2P, rooms, sync, unchanged): the lock is a pure gate
	// on operator input, intercepted BEFORE any other modal in Update()
	// (see the gate at the top of "case tea.KeyMsg:"), no application
	// state touches these fields.
	interfaceLocked      bool
	lastActivityAt       time.Time
	interfaceLockTimeout time.Duration // 0 = automatic lock disabled
	lockUnlockBuf        string
	lockUnlockErr        string
	// lockedSinceAt/timeNukeTimeout: the "time" nuke trigger, set
	// whenever interfaceLocked transitions false→true (cmdLock, the
	// auto-lock tick, sysLockMsg), checked on the same tick as
	// interfaceLockTimeout above but measuring time ALREADY LOCKED, not
	// inactivity before locking. 0 = disabled (default, see
	// config.TimeNukeTimeoutDuration).
	lockedSinceAt   time.Time
	timeNukeTimeout time.Duration

	// confirmation of the data read (username/key/PQC) before the local
	// name, shows the user what is about to be saved and waits for y/n,
	// BEFORE opening addContactMode: both for /cnt-add (pasted URI) and
	// /cnt-read-qrcode (decoded QR), never a silent save of a key read
	// from an external source (QR, pasted text) without an explicit summary.
	addContactConfirmMode bool

	// local name entry state for /cnt-add
	addContactMode bool
	addContactBuf  string
	pendingContact struct {
		username string
		pubBytes []byte
		tabIdx   int
		cardFrom string // member key of whoever sent the accepted contact card; empty if added directly (knock, QR, manual)
		mlkemPub []byte // durable ML-KEM-768 encapsulation key (1184 bytes), from QR/URI, empty if the URI carried none
		mldsaPub []byte // durable ML-DSA-65 signing key (1952 bytes), from QR/URI, empty if the URI carried none
	}

	// local name editing state for /cnt-edit
	editContactMode     bool
	editContactBuf      string
	pendingEditTabIdx   int
	pendingEditUsername string
	// pendingEditContactPub is the IdentityPub of the contact being
	// edited, never ambiguous, unlike pendingEditUsername (display/prompt
	// text only): two contacts can share the same Username (e.g. after
	// a /nukex), so the real resolution must go through this, not a
	// second lookup by name once confirmed.
	pendingEditContactPub []byte

	// source choice state for /cnt-read-qrcode: first asks f/c (file or
	// camera, a dedicated key, no free text), then, only for "file",
	// opens the same filesystem browser as /grp-file-send (qrFileMode),
	// instead of a typed path: an identity QR is often split across
	// several numbered PNGs (part1, part2...), so the browser allows
	// selecting more than one file at once (Space toggles, in selection
	// order, see qrFileSelected) alongside the usual single-file pick
	// (Enter with nothing toggled). Each selected image is decoded and
	// fed through handleQRDecoded in that same order; correctness never
	// actually depends on the order (every NTR3 chunk carries its own
	// part index), this is purely to match how a person naturally picks
	// "part1" before "part2".
	qrChooseMode   bool
	qrFileMode     bool
	qrFileDir      string
	qrFileEntries  []fsEntry
	qrFileIdx      int
	qrFileFilter   string
	qrFileSelected []string // full paths, in selection order

	// qrMultiChunks accumulates the NTR3 chunks of an in-progress
	// multi-QR scan (the URI with all three PQC segments exceeds a
	// single frame's capacity). Key: part index (deduplicates repeated
	// scans of the same frame). qrMultiTotal==0 = no multi-QR session in
	// progress. Reuses keystore.ChunkBlob/AssembleQRMulti, the same
	// format used for backup/sync.
	qrMultiChunks map[int][]byte
	qrMultiTotal  int

	// camera live preview state for /cnt-read-qrcode, without it there
	// is no visual feedback of what the webcam is framing until a
	// result or error arrives. Rendered as ANSI art (half-height blocks,
	// grayscale) directly in the terminal, no separate graphical
	// window, consistent with "works even over SSH/without an X server".
	qrCameraPreviewMode    bool
	qrCameraPreviewContent string
	qrCameraCancel         context.CancelFunc
	qrCameraPreviewCh      chan string
	qrCameraResultCh       chan tea.Msg

	// out-of-band contact info entry state for /grp-contact-send,
	// mandatory free text (phone, email, telegram id...) the introducer
	// writes at send time, NEVER persisted (neither here nor in the
	// recipient's keystore): only serves to let the recipient compare
	// the safety code out-of-band, not to permanently document the
	// subject's real identity.
	sendContactHintMode     bool
	sendContactHintBuf      string
	sendContactHintTabIdx   int
	sendContactHintUsername string
	// sendContactHintContactPub is the chosen contact's IdentityPub,
	// empty for "self" (no ContactInfo involved). Never ambiguous,
	// unlike sendContactHintUsername (display/"self" sentinel only):
	// two contacts can share the same Username (e.g. after a /nukex),
	// so finishSendContact must re-resolve by this, not by the name.
	sendContactHintContactPub []byte

	// 24-word BIP-39 popup, backupWords is populated only after the
	// password check (case 4, pwdMode) and zeroed as soon as the popup
	// closes, never kept in plaintext for the rest of the session (see
	// GetBackupMnemonic).
	backupMode        bool
	backupWords       []string
	getBackupMnemonic func() ([]string, error)

	// /show-qr format choice popup, idx 0 (default) saves a multi-part
	// PNG to disk via saveIdentityQR, idx 1 shows the animated
	// fountain-code QR (cmdShowQR), same two choices as `neutrino
	// show-qr`'s CLI prompt.
	showQRFormatMode bool
	showQRFormatIdx  int
	saveIdentityQR   func() ([]string, error)

	// /cnt-info and /grp-info popup
	textPopupMode    bool
	textPopupContent string
	// URI copyable with the "c" key while the popup is open, set only
	// by cmdInfo (self and contact), empty for every other use of
	// textPopupMode so the key stays "any key closes it" wherever
	// there's nothing to copy.
	textPopupCopyURI string

	// /show-qr popup, fountain-coded animated QR (internal/qroptical),
	// the same mechanism already used by "qr send" (cmd/main.go), here
	// inside a popup instead of a blocking loop: no password (identity
	// isn't a secret), one small frame (~120 bytes of payload) instead
	// of a single huge QR, a single QR with the whole identity
	// (ML-KEM included) easily exceeds a terminal's dimensions, and
	// quadrant compression distorts the aspect ratio
	// (terminal cells are ~2:1 height:width, compressing horizontally
	// too breaks it), not needed here since every frame is already
	// small on its own. qrShowGen invalidates ticks from an
	// already-closed previous session (same pattern as tab.pingGen).
	qrShowActive bool
	qrShowSender *qroptical.Sender
	qrShowFrame  string
	qrShowInfo   string
	qrShowGen    int

	// express nuke: secure deletion on return from the TUI
	nukeOnExit bool

	// duress typed at the interface lock during an already-active
	// session, the caller (RunTUI → runOnce, cmd/main.go) treats this
	// exactly like nukeOnExit above: same contact-overwrite-in-place and
	// promotion to the shared duress identity, same process, Tor/server
	// never torn down.
	duressWipeOnExit bool

	// /sec-clear-all, confirmed: the caller (RunTUI → runOnce, cmd/main.go)
	// wipes the whole config directory (keystore, backup, QR files, see
	// wipeConfigDir) and exits the process, unlike nukeOnExit/
	// duressWipeOnExit above, which keep it alive and swap to duress.
	clearAllOnExit bool

	clearAllConfirmMode bool

	// debug mode: if true, appendToDebug writes messages into the console tab
	debugMode  bool
	debugLogCh chan string // channel shared with debug.go for messages from goroutines

	// compaction mode (/compact on|off, console tab only): if true,
	// refreshViewport collapses consecutive runs of chatLine with the
	// same text (ignoring the timestamp, a separate field, no need to
	// strip it from any string) leaving only the last occurrence: a
	// periodic event (e.g. "probe activation", every minute) after
	// hours produces dozens of identical lines except for the time.
	// Only the VIEW changes, never tab.lines itself: turning compaction
	// off again goes back to seeing everything, nothing was ever discarded.
	compactMode bool

	// /sec-verify confirmation: awaiting a y/n answer after the out-of-band comparison
	verifySafetyConfirmMode   bool
	verifySafetyConfirmTarget string // username of the contact awaiting confirmation (display only)
	// verifySafetyConfirmContactPub is the chosen contact's CURRENT
	// IdentityPub (before any rotation applied by applyVerification),
	// never ambiguous, unlike verifySafetyConfirmTarget: two contacts
	// can share the same Username (e.g. after a /nukex), so
	// applyVerification's real resolution must go through this.
	verifySafetyConfirmContactPub []byte
	verifySafetyPopupContent      string // full code + instructions, shown only in the popup

	// verifySafetyConfirmRelDanger, true when this y/n confirmation
	// resolves a relationship key conflict (TrustDanger) instead of the
	// usual Safety Number: on "yes" it applies the pending keys
	// (m.confirmPendingRelKeys) instead of applyVerification, and does
	// NOT mark Verified=true (must be regained with a second /sec-verify
	// once the conflict is resolved). verifySafetyConfirmContactPub
	// above still refers to the contact in this branch too.
	verifySafetyConfirmRelDanger bool

	// Tor connectivity: out = outbound circuits (self-probe), in = confirmed inbound (knock received)
	torUp         *bool                   // nil=never tested, true=outbound circuits active, false=no circuits
	torIn         *bool                   // nil=never received, true=at least one inbound knock received
	hsUp          *bool                   // nil=never tested, true=HS published, false=ctx canceled
	contactStates map[string]contactState // string(IdentityPub) → state (updated by probeResultMsg)

	// ACK tracking for sent broadcast messages: msg_id → position in the tab
	pendingAckLines map[uint64]struct{ tabIdx, lineIdx int }

	// ping state (one active ping at a time)
	pingPending map[uint64]struct{} // expected seqs; emptied as pongs arrive
	pingRTTs    []float64           // RTT in ms for every received pong
	pingTotal   int                 // how many probes were sent
	pingTabIdx  int                 // tab the /grp-ping started from

	contacts       []ContactInfo
	checkCircuits  func() bool
	dialTor        func(context.Context, string, string) (net.Conn, error)
	isolatedDialer func(ctx context.Context, token string) func(context.Context, string, string) (net.Conn, error)
	myAddr         string
	addressFromPub func(pub ed25519.PublicKey) string
	myIdentityPub  ed25519.PublicKey
	// myMLKEMPub is our own durable ML-KEM-768 encapsulation key (1184
	// bytes), a twin of myIdentityPub. Used for our own identity QR and
	// for the self-probe knock (toward ourselves), NEVER for decrypting
	// (the server does that with its own decapsulation key, see
	// internal/server/handlers.go).
	myMLKEMPub []byte
	dhTagFn    func(peerPub ed25519.PublicKey) ([]byte, error)
	// signRelBootstrapFn/signRelBootstrapMLDSAFn, see TUIParams. Sign a
	// proposal of relationship keys (+ device) with the sender's root
	// IdentityKey, ONLY for the persistent rel_init/rel_init_ack channel
	// (sendRelInitAndReport), never for the room's ephemeral bootstrap.
	signRelBootstrapFn      func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte
	signRelBootstrapMLDSAFn func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte
	localHost               string
	localPort               int
	myUsername              string
	// myDevicePub/signDeviceSig, remote_nuke, see TUIParams.
	myDevicePub   []byte
	signDeviceSig func(ciphertext []byte, ts string) []byte
	// signPQCSig, hybrid PQC network identity, see TUIParams.SignPQCSig.
	signPQCSig func(ciphertext []byte, ts string) []byte
	// myDeviceID/authorityPubKeys/knownDevices/signRemoteNuke/
	// signRemoteNukeAck, remote_nuke protocol, see TUIParams.
	myDeviceID        []byte
	authorityPubKeys  []ed25519.PublicKey
	knownDevices      func() []DeviceRecordInfo
	signRemoteNuke    func(targetDeviceID []byte, ts string) []byte
	signRemoteNukeAck func(targetDeviceID []byte, ts string) []byte
	// authorityPubKeysMLDSA/signRemoteNukeMLDSA, hybrid PQC network
	// identity: ML-DSA-65 counterpart of authorityPubKeys/signRemoteNuke,
	// same role (an additional, independent verification/signature,
	// never the only one checked, see handleRemoteNuke).
	authorityPubKeysMLDSA []*mldsa65.PublicKey
	signRemoteNukeMLDSA   func(targetDeviceID []byte, ts string) []byte
	// networkIdentityPubFor, used by the remote_nuke fan-out, see
	// TUIParams.NetworkIdentityPubFor.
	networkIdentityPubFor func(deviceID []byte) ed25519.PublicKey

	// myMLDSAPub/rootRotationPending/
	// oldIdentityPubForRotation/ackRootRotationContact/
	// ackRootRotationDevice/maybeFinalizeRootRotation/
	// updateContactRootIdentity/startRootRotation/adoptRootRotation/
	// buildDeviceSyncKnock, root rotation with continuity, see the
	// matching TUIParams fields.
	myMLDSAPub                    []byte
	rootRotationPending           func() ([][]byte, [][]byte)
	oldIdentityPubForRotation     func() ed25519.PublicKey
	ackRootRotationContact        func(pub []byte) bool
	ackRootRotationDevice         func(deviceID []byte) bool
	maybeFinalizeRootRotation     func()
	updateContactRootIdentity     func(pub []byte, newIdentityPub ed25519.PublicKey, newMLKEMPub, newMLDSAPub []byte) error
	startRootRotation             func() (ed25519.PublicKey, []byte, []byte, string, error)
	adoptRootRotation             func(newIdentityKey, newMLKEMKey, newMLDSAKey []byte) (string, error)
	buildDeviceSyncRotationKnock  func(useOldKey bool, targetDeviceID []byte) (string, error)
	buildDeviceSyncSyncKnock      func(useOldKey bool, targetDeviceID []byte) (string, error)
	buildDeviceSyncAckKnock       func(targetDeviceID []byte, includeSync bool) (string, error)
	oldNetworkIdentityPubFor      func(deviceID []byte) ed25519.PublicKey
	mergeSyncedContacts           func(data []byte) ([]byte, error)
	contactsSnapshot              func() []ContactInfo
	buildContactTombstoneKnock    func(rows []byte) (string, error)
	applyContactTombstoneReplies  func(rows []byte) ([]byte, error)
	buildContactTombstoneAckKnock func(acked []byte) (string, error)
	confirmContactTombstoneAcked  func(acked []byte, peerDeviceID []byte)
	// remoteNukeCancels/remoteNukeMu, a context.CancelFunc per target
	// DeviceID (hex), active for the duration of an outgoing
	// remote_nuke command's fan-out; canceled on the first received
	// remote_nuke_ack (handleRemoteNukeAck) or on the fan-out's natural
	// completion. Touched both by Update()'s goroutine (the command's
	// author) and by the background tea.Cmd executing the fan-out: a
	// dedicated mutex, not the model's general state (which bubbletea
	// doesn't protect between the two).
	// remoteNukeMu is a *sync.Mutex (not a direct value): model gets
	// continuously copied by value by the bubbletea runtime (Update
	// receives/returns model, not *model, in many places), a
	// by-value-embedded sync.Mutex would get copied every round,
	// breaking mutual exclusion; a shared pointer, created once at the
	// model's construction, stays the same lock regardless of how many
	// copies of model exist.
	// The entry is a pointer (not the raw CancelFunc, which isn't
	// comparable in Go except to nil) precisely so
	// cmdRemoteNukeFanOut's deferred cleanup can distinguish "I'm still
	// the current entry" from "a more recent retry already replaced me"
	// see the comment on remoteNukeEntry.
	remoteNukeCancels map[string]*remoteNukeEntry
	remoteNukeMu      *sync.Mutex
	// pendingRemoteNukeTargets/addPendingRemoteNuke/clearPendingRemoteNuke
	// see TUIParams.
	pendingRemoteNukeTargets []DeviceRecordInfo
	addPendingRemoteNuke     func(targetDeviceID []byte) error
	clearPendingRemoteNuke   func(targetDeviceID []byte) error
	// markOwnDeviceNuked, see TUIParams.MarkOwnDeviceNuked.
	markOwnDeviceNuked func()
	// pendingDangerBroadcasts/setDangerBroadcastPending/
	// confirmDangerBroadcast, see TUIParams. pendingDangerBroadcasts is
	// mutated both here in memory (consulted on every probeContacts
	// cycle) and persisted via the two closures.
	pendingDangerBroadcasts   []DangerBroadcastPendingInfo
	setDangerBroadcastPending func(targetDeviceID []byte, pubs [][]byte) error
	confirmDangerBroadcast    func(targetDeviceID, pub []byte) error
	// pendingDangerEnds/setDangerEndPending/confirmDangerEnd/
	// allIdentitiesContacts, see TUIParams.
	pendingDangerEnds     []DangerBroadcastPendingInfo
	setDangerEndPending   func(targetDeviceID []byte, pubs [][]byte) error
	confirmDangerEnd      func(targetDeviceID, pub []byte) error
	allIdentitiesContacts func() []AllIdentityContactsInfo
	// dangerEndSeen records (hex(TargetDeviceID) → true) the devices for
	// which the DEFINITIVE danger_end has already arrived, a guard
	// against reversed arrival order relative to the preliminary
	// danger_broadcast (the first makes a single target→contact hop,
	// the second a double round authority→target→ack→authority→contact:
	// it can easily arrive first). If a preliminary danger_broadcast
	// arrives AFTER the definitive one for the same device has already
	// been seen, it doesn't generate a second, misleading Console
	// message ("in progress" after "confirmed destroyed"), the ack is
	// still sent regardless, so the sender's queue closes normally.
	dangerEndSeen map[string]bool
	// runIndoorSync/indoorSyncing, remote_nuke, see TUIParams.
	// indoorSyncing prevents two overlapping synchronizations (same
	// principle as model.probing for /active): both would bind the
	// same TCPPort, the second would fail the bind regardless.
	runIndoorSync           func(ctx context.Context) error
	indoorSyncing           bool
	myDeviceLabel           string
	setDeviceLabel          func(label string) error
	addRoom                 func(roomID string, secret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool))
	replaceRoomSecret       func(roomID string, oldSecret, newSecret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool))
	resolveRelKeysForDevice func(identityPub, devicePub []byte) (shared.RelPeerKey, shared.RelSigningKey, bool)
	banMember               func(roomID string, secret []byte, userID string) bool
	knockCh                 <-chan shared.KnockPayload
	pendingKnocks           []pendingKnock
	sysLockCh               <-chan struct{}

	// inviteModalMode/inviteModalKnock, modal popup for an incoming
	// group invite: ALWAYS shows the first unhandled pendingKnocks
	// with GroupID != "", one at a time. Enter = Accept (cmdJoin), Esc
	// = Ignore (ignoreInvite), see showNextInviteModal.
	inviteModalMode  bool
	inviteModalKnock *pendingKnock

	// groupNoJoinConfirmMode/groupNoJoinConfirmTabIdx/pendingNoJoinPrompts
	// the "nobody has accepted the invite to <group> yet, close the
	// room?" popup (host side only), Enter = Yes closes, Esc = No keeps
	// waiting. Same queue+self-healing pattern as
	// pendingKnocks/showNextInviteModal: multiple groups with no
	// response can hit the timeout nearly simultaneously, or the popup
	// may have to wait for another already-open modal to close, see
	// queueGroupNoJoinPrompt/showNextGroupNoJoinModal.
	groupNoJoinConfirmMode   bool
	groupNoJoinConfirmTabIdx int
	pendingNoJoinPrompts     []int

	consoleIdx   int // console tab index (permanent)
	torTabIdx    int // Tor tab index, -1 if absent
	filesTabIdx  int // "File" tab index (permanent)
	fileProgress *fileProgressRegistry
	torLogCh     <-chan string
	showPalette  bool
	paletteIdx   int

	// scrollable help overlay
	helpMode   bool
	helpScroll int

	// filesystem browser for /grp-file-send (choosing the file to send)
	// hand-rolled (not bubbles/filepicker: that library exposes no
	// filter from outside, needed for the typed search below).
	sendFileMode    bool
	sendFileDir     string    // currently shown directory
	sendFileEntries []fsEntry // sendFileDir's contents, folders first, then alphabetical order
	sendFileIdx     int       // selected index within the filtered list
	sendFileFilter  string    // text typed to filter visible names
	sendFileTabIdx  int       // tab /grp-file-send or /grp-contact-send started from
	sendFilePath    string    // chosen file, valid after onFileChosenForSend (empty for /grp-contact-send)
	sendFileSize    int64

	// sendFileData/sendFileDisplayName: an alternative to sendFilePath
	// for content already in memory instead of on disk, used by
	// /grp-contact-send, which reuses /grp-file-send's entire pipeline
	// (recipient picker, preset, encryption, signature) starting from
	// synthesized bytes instead of a file.
	sendFileData        []byte
	sendFileDisplayName string

	// recipients popup for /grp-file-send (group rooms only, in a
	// two-member room the recipient is implicit, no popup)
	sendFileRecipientsMode bool
	sendFileCandidates     []string        // member keys of present members with an established relationship
	sendFileSelected       map[string]bool // opt-out: true = will receive the file (preselected)
	sendFileRecipientsIdx  int
	sendFileRecipients     []string // member keys of the confirmed recipients, carried into the preset step

	// recipients popup for /grp-invite (new group), same mechanism as
	// /grp-file-send's recipient picker, but opt-in: nothing preselected on open.
	invitePickerMode bool
	inviteCandidates []string        // every contact in the address book, as picker keys (contactPickerKey)
	inviteSelected   map[string]bool // opt-in: true = will be invited (by picker key, independent of the filter)
	inviteIdx        int             // highlighted row in the FILTERED list (see inviteFilteredCandidates)
	inviteFilter     string          // text typed to filter, Space stays a selection toggle, doesn't go into the filter

	// participants popup for /grp-ping with no argument, current
	// room's members, self excluded. With exactly one other member, the
	// ping goes directly, skipping the picker.
	pingPickerMode bool
	pingCandidates []string
	pingPickerIdx  int

	// /grp-msg-acks popup, list of our own latest messages in this
	// room (up to msgAcksMaxCandidates, most recent first), Enter on
	// one of them shows which members confirmed receipt and which
	// didn't (msgAcksDetailMode, read-only, any key closes it, same
	// treatment as helpMode). msgAcksCandidates holds indices into
	// tab.lines, not the chatLine values themselves: the line can
	// receive other acks in the meantime, the index stays valid because
	// tab.lines only grows at the tail.
	msgAcksPickerMode    bool
	msgAcksPickerIdx     int
	msgAcksCandidates    []int
	msgAcksDetailMode    bool
	msgAcksDetailLineIdx int

	// /sec-remote-nuke popup, a single-selection picker on
	// the known devices (no sensible textual argument for a device: no
	// name resolution like other picker commands), then an explicit y/n
	// confirmation before actually sending (irreversible, destructive
	// action for the target device, never /nukex's immediate behavior).
	remoteNukePickerMode  bool
	remoteNukePickerIdx   int
	remoteNukeConfirmMode bool
	remoteNukeConfirmIdx  int

	// speed preset popup for /grp-file-send, "slow" is the default
	// (idx 0), "warp" must be chosen explicitly (idx 1).
	sendFilePresetMode bool
	sendFilePresetIdx  int
	// sendFileCompressOn is the compression flag (strong LZMA2/XZ pack)
	// for THIS send, toggleable in the same popup with Tab, initialized
	// to strongCompressionEnabled (config.json) every time the popup
	// opens, not a fixed default: the user sees/changes the actually
	// configured state, not an independent value.
	sendFileCompressOn bool

	// active transfers, sending side and receiving side, keyed by transferID.
	outgoingTransfers map[string]*outgoingFileTransfer
	incomingTransfers map[string]*incomingFileTransfer

	// outgoingTransfersSending, SEPARATE from outgoingTransfers: the
	// latter tracks only the "awaiting accept/reject" phase and gets
	// removed the exact instant the real send starts (the three points
	// that call startSendingChunks). Without this second registry,
	// "file_chunk_ack" (which looks up the transfer to route the ack to
	// the sending goroutine) would NEVER find anything once the send
	// has started, every chunk would always time out, isolating every
	// recipient in the same cycle. Populated at the same three points
	// that remove from outgoingTransfers, cleaned up by
	// localDisplayMsg.transferID when the transfer ends (success or fatal error).
	outgoingTransfersSending map[string]*outgoingFileTransfer

	// verifiedFileHashes, the ciphertext hash already verified during
	// the announcement phase (case "file_announce"), awaiting the real
	// file_offer (case "file_offer" consumes it to populate
	// incomingFileTransfer.hash), used at the end of the transfer for
	// an integrity comparison, not a signature re-check. Keyed by
	// transferID, small value (32 bytes), no explicit cleanup needed
	// beyond natural consumption by "file_offer".
	verifiedFileHashes map[string][]byte

	// pendingFileAnnounces, a file_announce whose signature didn't
	// verify on the first attempt (the sender's key out of sync) stays
	// here instead of being discarded, self-heal, see
	// retryPendingFileAnnounces (called by applyRelInit when a
	// rel_init_ack resynchronizes the device in question). Expires at a
	// deadline (the same fileTransferOfferTimeout the sender uses to
	// stay consistent about when to give up).
	pendingFileAnnounces map[string]*pendingFileAnnounce

	// pendingInvites, an invite (cmdInvite/cmdRecall/cmdReinvite/
	// cmdAddMember) toward a contact still missing BOTH confirmed
	// relationship keys (RelIdentityConfirmedByPeer/
	// RelContentConfirmedByPeer) doesn't fail outright:
	// queuePendingInvite immediately triggers a fresh rel_init
	// (immediate probe) toward each not-ready contact and queues the
	// real invite here, executed automatically by retryPendingInvites
	// as soon as ALL involved contacts come out ready, the same
	// verify-then-heal-then-transfer principle already used for
	// file_announce, extended from a single device to an entire invite.
	// Bound by inviteTimeout (the same timeout already used for the
	// invite knock, never a new dedicated timeout), swept by the
	// periodic probe cycle (case probeResultMsg), not a dedicated ticker.
	pendingInvites []*pendingInvite

	// pendingJoins, the counterpart of pendingInvites for the opposite
	// direction: an invite RECEIVED and accepted (cmdJoin) when the
	// relationship keys toward the inviting host weren't known yet
	// (host just restarted, rel_init still in transit) stays here
	// instead of getting lost. retryPendingJoins (called by applyRelInit, like
	// retryPendingInvites) retries it as soon as hostReadyForJoin(hostPub)
	// returns true. Expiry sweep in the periodic probe cycle (case
	// probeResultMsg), same scheme as pendingInvites.
	pendingJoins []*pendingJoin

	// pendingFileOffers queues file_offers whose metadata has already
	// been decrypted (fileOfferMetaDecryptedMsg) but for which no popup
	// has been shown yet, NEVER write the fileOffer* fields directly
	// from there, only from showNextFileOfferModal(): two close-together
	// file_offers (e.g. a file + a contact card, or two files from the
	// same sender) whose background decryption completed nearly at the
	// same time would overwrite each other's fileOffer* fields with no
	// queue at all: the first offer would stay "orphaned" in
	// m.incomingTransfers (never getting a popup) while only the latest
	// one arrived would be shown, the sender would see it time out as
	// if it had been ignored. The same pattern already used for group
	// invites (pendingKnocks + showNextInviteModal), replicated identically here.
	pendingFileOffers []string

	// file_offer receipt confirmation popup, accept/reject before a single byte moves.
	fileOfferMode            bool
	fileOfferTransferID      string
	fileOfferFromUserID      string
	fileOfferFromKey         string // sender's member key
	fileOfferFileName        string
	fileOfferFileSize        int64
	fileOfferContentKeyKnown bool // ContentKey relationship already established with the sender
	fileOfferTabIdx          int

	// rename + folder choice for saving a received file (already
	// decrypted and verified, see fileReadyToSaveMsg): two sequential
	// steps (same scheme as sendFileMode → sendFileRecipientsMode →
	// sendFilePresetMode), saveRenameMode lets the user correct the
	// sender's proposed name before choosing the folder in saveDirMode.
	saveRenameMode  bool
	saveDirMode     bool
	saveFileDir     string    // directory currently shown in the browser
	saveFileEntries []fsEntry // only saveFileDir's subdirectories (never files: only choosing where to save here)
	saveFileIdx     int       // 0 = the synthetic "save here" entry, 1..n = saveFileEntries[idx-1]
	saveFileTabIdx  int
	savePendingData []byte
	savePendingName string // proposed name, editable in saveRenameMode
	// saveTitle overrides the rename popup's title (tui.recv_file_rename_title
	// otherwise), set by callers other than a received file, e.g.
	// cmdConsoleExport, for which the received-file wording would be
	// wrong. Reset to "" on every exit path of this flow, so it never
	// leaks into the next (ordinary received-file) use.
	saveTitle string

	// address book popup for /cnt-info and /cnt-edit
	contactPickerMode    bool
	contactPickerCmd     client.CmdID // e.g. client.CmdInfo or client.CmdEdit
	contactPickerFilter  string       // text typed to filter
	contactPickerIdx     int          // highlighted row in the filtered list
	savedGroups          []GroupInfo
	saveGroup            func(g GroupInfo) error
	onContactDevicePub   func(contactPub []byte, devicePub []byte) error
	deleteContact        func(pub []byte) error
	deleteGroup          func(nameOrID string) error
	addContact           func(username, localName string, identityPub, mlkemPub, mldsaPub []byte, introducedBy string, introducedByPub []byte) (myIdentKey, myContentKey shared.RelSigningKey, err error)
	updateContactRelKeys func(pub []byte, upd RelKeyUpdate) error
	// setPendingRelKeys/confirmPendingRelKeys, see
	// TUIParams.SetPendingRelKeys/ConfirmPendingRelKeys (TrustDanger).
	setPendingRelKeys     func(pub []byte, pending PendingRelKeys) error
	confirmPendingRelKeys func(pub []byte) bool
	// resetRelInitConfirmed, see TUIParams.ResetRelInitConfirmed.
	resetRelInitConfirmed func(pub, devicePub []byte, which string) error
	// promoteEphemeralContact, see TUIParams.PromoteEphemeralContact.
	promoteEphemeralContact func(username string, transportPub, transportMLKEMPub, transportMLDSAPub []byte, myIdentKey, myContentKey shared.RelSigningKey, peerIdent shared.RelPeerKey, peerIdentMLKEMPub []byte, peerContent shared.RelPeerKey, peerContentMLKEMPub []byte) error
	// startRelIdentityRotationByPub/startRelContentRotationByPub/markRelRotationConfirmed
	// see the matching TUIParams fields.
	startRelIdentityRotationByPub func(pub []byte) (map[string]shared.RelSigningKey, error)
	startRelContentRotationByPub  func(pub []byte) (map[string]shared.RelSigningKey, error)
	markRelRotationConfirmed      func(pub, devicePub []byte, which string) bool
	// markDeviceRevoked/ackSiblingRevocation, see
	// TUIParams.MarkDeviceRevoked/AckSiblingRevocation.
	markDeviceRevoked          func(pub, devicePub []byte, revokeIdentity, revokeContent bool) bool
	ackSiblingRevocation       func(pub, peerDevicePub []byte) bool
	isDeviceNuked              func(devicePub []byte) bool
	changePassword             func(oldPwd, newPwd string) error
	setDuress                  func(newPwd string) error
	keystorePassword           string
	setLockSecret              func(secret string, isPIN bool, duressMarker string, duressPosition int) error
	checkLockSecret            func(candidate string) keystore.LockCheckResult
	checkDuressPassword        func(candidate string) bool
	saveInterfaceLockTimeout   func(time.Duration) error
	saveTimeNukeTimeout        func(time.Duration) error
	updateContactLocalName     func(pub []byte, localName string) error
	markContactVerifiedByPub   func(pub []byte) error
	markContactUnverifiedByPub func(pub []byte) error
	flushContactsActivity      func(acks map[string]time.Time, seen map[string]time.Time) error
	// dhTagFnOld, see TUIParams.DHTagFnOld.
	dhTagFnOld        func(peerPub ed25519.PublicKey) ([]byte, error)
	dirtyLastAck      map[string]time.Time // string(identity key) → local time, accumulated since the last flush (probe_ack)
	senderKeyInterval time.Duration

	// pendingSlotLimit/messageRetryDelay/pendingEscalationAge/messageTTL
	// configure the reliable delivery queue on every connected tab.cli
	// (SetPendingLimits), same principle as senderKeyInterval above.
	pendingSlotLimit       int
	messageRetryDelay      time.Duration
	pendingEscalationAge   time.Duration
	messageTTL             time.Duration
	senderKeyMessageBudget int

	// configurable timing (from config.json)
	activeInterval               time.Duration
	activeInitialDelay           time.Duration
	probeContactsTimeout         time.Duration
	probeRetryCount              int
	probeRetryDelay              time.Duration
	probing                      bool // true while a probe cycle is running
	torProbeInterval             time.Duration
	torProbeInitialDelay         time.Duration
	warmupInterval               time.Duration
	warmupInitialDelay           time.Duration
	warmupTimeout                time.Duration
	selfKnockTimeout             time.Duration
	knockHttpTimeout             time.Duration
	knockRetryDelay              time.Duration
	inviteTimeout                time.Duration
	fileTransferMaxSizeMiB       int
	fileWarpChunkSizeKiB         int
	fileSlowChunkSizeKiB         int
	fileSlowDelayMs              int
	fileTransferOfferTimeout     time.Duration
	fileOfferBatchWindow         time.Duration
	fileWarpMaxInFlightChunks    int
	fileSlowMaxInFlightChunks    int
	fileTransferReconnectTimeout time.Duration
	fileAcceptRetryInterval      time.Duration
	strongCompressionEnabled     bool
}

// fileAcceptRetryIntervalDefault, see config.go FileAcceptRetryInterval
// for the value's full rationale: 30s is less than 1/3 of
// FileTransferReconnectTimeout's default (2m), so it guarantees at
// least 4 file_accept sends before the sender isolates the recipient.
// Not derived automatically from FileTransferReconnectTimeout because
// they're two separate processes (sender and recipient), each with its
// own config.json: no value is ever exchanged on the wire between the
// two sides. If FileTransferReconnectTimeout is changed in config.json,
// file_accept_retry_interval must be updated accordingly on the
// recipient's side too.
const fileAcceptRetryIntervalDefault = 30 * time.Second

// orDur returns d if > 0, otherwise def.
func orDur(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// orInt returns v if > 0, otherwise def.
func orInt(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func newModel(p TUIParams) model {
	ta := textarea.New()
	ta.Placeholder = fmt.Sprintf(i18n.T("tui.input_placeholder"),
		i18n.CommandName(client.CmdInvite), i18n.CommandName(client.CmdJoin), i18n.CommandName(client.CmdSaveGroup),
		i18n.CommandName(client.CmdActive), i18n.CommandName(client.CmdEdit), i18n.CommandName(client.CmdHealth))
	ta.Focus()
	ta.SetHeight(3)
	ta.ShowLineNumbers = false
	// Default CharLimit (0, no limit, see bubbles/textarea), an
	// insufficient fixed cap here would silently truncate a pasted
	// identity URI carrying all three PQC keys
	// (Ed25519+ML-KEM-768+ML-DSA-65, up to ~4300 characters) with no
	// visible error. No equivalent size limit further downstream
	// (SetReadLimit is sized for the "warp" file preset, orders of
	// magnitude more permissive) that would make a cap necessary here,
	// and an arbitrary number would break as the URI format grows.
	ta.KeyMap.InsertNewline.SetEnabled(false)

	contactsTab := &roomTab{
		name:       i18n.T("tui.tab_contacts"),
		isContacts: true,
		lines:      []chatLine{},
	}
	groupsTab := &roomTab{
		name:     i18n.T("tui.tab_groups"),
		isGroups: true,
		lines:    []chatLine{},
	}
	consoleLines := []chatLine{}
	for _, l := range p.BootLog {
		consoleLines = append(consoleLines, chatLine{isSystem: true, plain: true, text: styleMeta.Render(l)})
	}
	consoleTab := &roomTab{
		name:      i18n.T("tui.tab_console"),
		isConsole: true,
		lines:     consoleLines,
	}

	netTabLabel := p.NetworkName
	if netTabLabel == "" {
		netTabLabel = i18n.T("tui.tab_tor")
	}
	torTab := &roomTab{
		name:  netTabLabel,
		isTor: true,
		lines: []chatLine{},
	}
	filesTab := &roomTab{
		name:    i18n.T("tui.tab_files"),
		isFiles: true,
		lines:   []chatLine{},
	}
	// Fixed tab order: Console, Network, Contacts, Groups, File (same
	// order on every platform).
	initialTabs := []*roomTab{consoleTab}
	consoleIdx := 0
	torTabIdx := -1
	if p.TorLogCh != nil {
		torTabIdx = len(initialTabs)
		initialTabs = append(initialTabs, torTab)
	}
	initialTabs = append(initialTabs, contactsTab, groupsTab)
	filesTabIdx := len(initialTabs)
	initialTabs = append(initialTabs, filesTab)

	m := model{
		tabs:                          initialTabs,
		active:                        consoleIdx, // Console is already the active page right after boot
		contactStates:                 make(map[string]contactState),
		ta:                            ta,
		contacts:                      p.Contacts,
		checkCircuits:                 p.CheckCircuits,
		dialTor:                       p.DialTor,
		isolatedDialer:                p.IsolatedDialer,
		myAddr:                        p.MyAddr,
		addressFromPub:                p.AddressFromPub,
		myIdentityPub:                 p.MyIdentityPub,
		myMLKEMPub:                    p.MyMLKEMPub,
		dhTagFn:                       p.DHTagFn,
		signRelBootstrapFn:            p.SignRelBootstrap,
		signRelBootstrapMLDSAFn:       p.SignRelBootstrapMLDSA,
		localHost:                     p.LocalHost,
		localPort:                     p.LocalPort,
		myUsername:                    p.Username,
		myDevicePub:                   p.MyDevicePub,
		signDeviceSig:                 p.SignDeviceSig,
		signPQCSig:                    p.SignPQCSig,
		myDeviceID:                    p.MyDeviceID,
		authorityPubKeys:              p.AuthorityPubKeys,
		authorityPubKeysMLDSA:         p.AuthorityPubKeysMLDSA,
		knownDevices:                  p.KnownDevices,
		signRemoteNuke:                p.SignRemoteNuke,
		signRemoteNukeMLDSA:           p.SignRemoteNukeMLDSA,
		networkIdentityPubFor:         p.NetworkIdentityPubFor,
		myMLDSAPub:                    p.MyMLDSAPub,
		rootRotationPending:           p.RootRotationPending,
		oldIdentityPubForRotation:     p.OldIdentityPub,
		ackRootRotationContact:        p.AckRootRotationContact,
		ackRootRotationDevice:         p.AckRootRotationDevice,
		maybeFinalizeRootRotation:     p.MaybeFinalizeRootRotation,
		updateContactRootIdentity:     p.UpdateContactRootIdentity,
		startRootRotation:             p.StartRootRotation,
		adoptRootRotation:             p.AdoptRootRotation,
		buildDeviceSyncRotationKnock:  p.BuildDeviceSyncRotationKnock,
		buildDeviceSyncSyncKnock:      p.BuildDeviceSyncSyncKnock,
		buildDeviceSyncAckKnock:       p.BuildDeviceSyncAckKnock,
		oldNetworkIdentityPubFor:      p.OldNetworkIdentityPubFor,
		mergeSyncedContacts:           p.MergeSyncedContacts,
		contactsSnapshot:              p.ContactsSnapshot,
		buildContactTombstoneKnock:    p.BuildContactTombstoneKnock,
		applyContactTombstoneReplies:  p.ApplyContactTombstoneReplies,
		buildContactTombstoneAckKnock: p.BuildContactTombstoneAckKnock,
		confirmContactTombstoneAcked:  p.ConfirmContactTombstoneAcked,
		signRemoteNukeAck:             p.SignRemoteNukeAck,
		remoteNukeCancels:             make(map[string]*remoteNukeEntry),
		remoteNukeMu:                  &sync.Mutex{},
		pendingRemoteNukeTargets:      p.PendingRemoteNukeTargets,
		addPendingRemoteNuke:          p.AddPendingRemoteNuke,
		clearPendingRemoteNuke:        p.ClearPendingRemoteNuke,
		markOwnDeviceNuked:            p.MarkOwnDeviceNuked,
		pendingDangerBroadcasts:       p.PendingDangerBroadcasts,
		setDangerBroadcastPending:     p.SetDangerBroadcastPending,
		confirmDangerBroadcast:        p.ConfirmDangerBroadcast,
		pendingDangerEnds:             p.PendingDangerEnds,
		setDangerEndPending:           p.SetDangerEndPending,
		confirmDangerEnd:              p.ConfirmDangerEnd,
		allIdentitiesContacts:         p.AllIdentitiesContacts,
		dangerEndSeen:                 make(map[string]bool),
		runIndoorSync:                 p.RunIndoorSync,
		myDeviceLabel:                 p.MyDeviceLabel,
		setDeviceLabel:                p.SetDeviceLabel,
		addRoom:                       p.AddRoom,
		replaceRoomSecret:             p.ReplaceRoomSecret,
		resolveRelKeysForDevice:       p.ResolveRelKeysForDevice,
		banMember:                     p.BanMember,
		knockCh:                       p.KnockCh,
		sysLockCh:                     p.SysLockCh,
		torTabIdx:                     torTabIdx,
		filesTabIdx:                   filesTabIdx,
		fileProgress:                  newFileProgressRegistry(),
		torLogCh:                      p.TorLogCh,
		savedGroups:                   p.SavedGroups,
		saveGroup:                     p.SaveGroup,

		onContactDevicePub:            p.OnContactDevicePub,
		deleteContact:                 p.DeleteContact,
		deleteGroup:                   p.DeleteGroup,
		addContact:                    p.AddContact,
		updateContactRelKeys:          p.UpdateContactRelKeys,
		setPendingRelKeys:             p.SetPendingRelKeys,
		confirmPendingRelKeys:         p.ConfirmPendingRelKeys,
		resetRelInitConfirmed:         p.ResetRelInitConfirmed,
		promoteEphemeralContact:       p.PromoteEphemeralContact,
		startRelIdentityRotationByPub: p.StartRelIdentityRotationByPub,
		startRelContentRotationByPub:  p.StartRelContentRotationByPub,
		markRelRotationConfirmed:      p.MarkRelRotationConfirmed,
		markDeviceRevoked:             p.MarkDeviceRevoked,
		ackSiblingRevocation:          p.AckSiblingRevocation,
		isDeviceNuked:                 p.IsDeviceNuked,
		changePassword:                p.ChangePassword,
		setDuress:                     p.SetDuress,
		keystorePassword:              p.KeystorePassword,
		setLockSecret:                 p.SetLockSecret,
		checkLockSecret:               p.CheckLockSecret,
		checkDuressPassword:           p.CheckDuressPassword,
		saveInterfaceLockTimeout:      p.SaveInterfaceLockTimeout,
		timeNukeTimeout:               p.TimeNukeTimeout,
		saveTimeNukeTimeout:           p.SaveTimeNukeTimeout,
		interfaceLockTimeout:          p.InterfaceLockTimeout,
		lastActivityAt:                time.Now(),
		updateContactLocalName:        p.UpdateContactLocalName,
		markContactVerifiedByPub:      p.MarkContactVerifiedByPub,
		markContactUnverifiedByPub:    p.MarkContactUnverifiedByPub,
		flushContactsActivity:         p.FlushContactsActivity,
		dhTagFnOld:                    p.DHTagFnOld,
		dirtyLastAck:                  make(map[string]time.Time),
		senderKeyInterval:             p.SenderKeyInterval,
		pendingSlotLimit:              p.PendingSlotLimit,
		messageRetryDelay:             p.MessageRetryDelay,
		pendingEscalationAge:          p.PendingEscalationAge,
		messageTTL:                    p.MessageTTL,
		senderKeyMessageBudget:        p.SenderKeyMessageBudget,
		activeInterval:                orDur(p.ActiveInterval, time.Minute),
		activeInitialDelay:            orDur(p.ActiveInitialDelay, time.Minute),
		probeContactsTimeout:          orDur(p.ProbeContactsTimeout, 90*time.Second),
		probeRetryCount:               orInt(p.ProbeRetryCount, 3),
		probeRetryDelay:               orDur(p.ProbeRetryDelay, 20*time.Second),
		torProbeInterval:              orDur(p.TorProbeInterval, 5*time.Minute),
		torProbeInitialDelay:          orDur(p.TorProbeInitialDelay, 10*time.Second),
		warmupInterval:                orDur(p.WarmupInterval, 5*time.Minute),
		warmupInitialDelay:            orDur(p.WarmupInitialDelay, 20*time.Second),
		warmupTimeout:                 orDur(p.WarmupTimeout, time.Minute),
		selfKnockTimeout:              orDur(p.SelfKnockTimeout, time.Minute),
		knockHttpTimeout:              orDur(p.KnockHttpTimeout, 15*time.Second),
		knockRetryDelay:               orDur(p.KnockRetryDelay, 20*time.Second),
		inviteTimeout:                 orDur(p.InviteTimeout, 30*time.Second),
		fileTransferMaxSizeMiB:        orInt(p.FileTransferMaxSizeMiB, 512),
		fileWarpChunkSizeKiB:          orInt(p.FileWarpChunkSizeKiB, 64),
		fileSlowChunkSizeKiB:          orInt(p.FileSlowChunkSizeKiB, 16),
		fileSlowDelayMs:               orInt(p.FileSlowDelayMs, 250),
		fileTransferOfferTimeout:      orDur(p.FileTransferOfferTimeout, 90*time.Second),
		fileOfferBatchWindow:          orDur(p.FileOfferBatchWindow, 10*time.Second),
		fileWarpMaxInFlightChunks:     orInt(p.FileWarpMaxInFlightChunks, 8),
		fileSlowMaxInFlightChunks:     orInt(p.FileSlowMaxInFlightChunks, 2),
		fileTransferReconnectTimeout:  orDur(p.FileTransferReconnectTimeout, 2*time.Minute),
		fileAcceptRetryInterval:       orDur(p.FileAcceptRetryInterval, fileAcceptRetryIntervalDefault),
		strongCompressionEnabled:      p.StrongCompressionEnabled,
		getBackupMnemonic:             p.GetBackupMnemonic,
		saveIdentityQR:                p.SaveIdentityQR,
		consoleIdx:                    consoleIdx,
		pingPending:                   make(map[uint64]struct{}),
		pendingAckLines:               make(map[uint64]struct{ tabIdx, lineIdx int }),
	}
	if p.HSPublished && p.MyAddr != "" {
		t := true
		m.hsUp = &t
	}
	m.debugLogCh = make(chan string, 500)
	return m
}

// ── init / update / view ──────────────────────────────────────────────────────

func (m model) tickActive() tea.Cmd {
	return tea.Tick(m.activeInterval, func(time.Time) tea.Msg { return tickActiveMsg{} })
}

func (m model) Init() tea.Cmd {
	// Terminal window title, a best-effort bonus for terminals that
	// show it in their own bar/tab: the reliable indication of the
	// active identity is the "fake tab" at the top of renderTabBar
	// (identityPrefix), text inside the TUI's own content, always
	// visible regardless of the terminal's support for this OSC
	// sequence, unlike the window title alone (on some setups it never
	// appears). m.myUsername is already populated at this point
	// (RunTUI is only reached after wizard/unlock).
	title := "Neutrino"
	if m.myUsername != "" {
		title += " - " + m.myUsername
	}
	cmds := []tea.Cmd{textarea.Blink, tea.SetWindowTitle(title)}
	for i := range m.tabs {
		cmds = append(cmds, m.waitForRoom(i))
	}
	if m.knockCh != nil {
		cmds = append(cmds, m.waitForKnock())
	}
	if m.sysLockCh != nil {
		cmds = append(cmds, m.waitForSysLock())
	}
	if m.torLogCh != nil {
		cmds = append(cmds, m.waitForTorLog())
	}
	cmds = append(cmds, m.waitForDebugLog())
	// Unconditional Tor probe after 10s: refreshes the bar even on
	// machines with no contacts. Then reschedules itself every 5
	// minutes via tickTorProbeMsg.
	if m.checkCircuits != nil || m.dialTor != nil {
		cmds = append(cmds, tea.Tick(m.torProbeInitialDelay, func(time.Time) tea.Msg { return tickTorProbeMsg{} }))
	}
	if m.dialTor != nil {
		cmds = append(cmds, tea.Tick(m.warmupInitialDelay, func(time.Time) tea.Msg { return warmupMsg{} }))
		cmds = append(cmds, tea.Tick(m.activeInitialDelay, func(time.Time) tea.Msg { return tickActiveMsg{} }))
	}
	if m.senderKeyInterval > 0 {
		cmds = append(cmds, tea.Tick(m.senderKeyInterval, func(time.Time) tea.Msg { return rotateSenderKeyMsg{} }))
	}
	cmds = append(cmds, tea.Tick(retryPendingInterval, func(time.Time) tea.Msg { return retryPendingTickMsg{} }))
	if len(m.pendingRemoteNukeTargets) > 0 {
		// Same initial delay as the circuits warmup: starting right
		// away would burn the few postWithRetry attempts (3, with
		// backoff) before Tor/I2P even have a single circuit ready.
		cmds = append(cmds, tea.Tick(m.warmupInitialDelay, func(time.Time) tea.Msg { return retryPendingRemoteNukesMsg{} }))
	}
	// Always scheduled, regardless of the current threshold, the
	// threshold can be changed live (/sec-lock-timeout) without
	// restarting the process, so the ticker must keep running
	// regardless; the case below is a no-op if m.interfaceLockTimeout <= 0.
	cmds = append(cmds, tea.Tick(interfaceLockCheckInterval, func(time.Time) tea.Msg { return tickInterfaceLockCheckMsg{} }))
	return tea.Batch(cmds...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if q, ok := msg.(agentQueryMsg); ok {
		q.fn(m)
		return m, nil
	}

	var taCmd, vpCmd, pendingCmd tea.Cmd

	// the red indicator turns off as soon as the user looks at the
	// Console tab (m.tabs holds pointers: the mutation persists even
	// from this by-value receiver).
	if m.active < len(m.tabs) && m.tabs[m.active].isConsole {
		m.tabs[m.active].hasError = false
	}

	// The nine gates below (up to saveDirMode) intercept BEFORE the
	// switch msg := msg.(type) further down, but ONLY if msg is really
	// a tea.KeyMsg. Without this guard, a msg of any OTHER type
	// (roomServerMsg, tickFileProgressMsg, incomingChunkWrittenMsg, ...)
	// that arrived while one of these popups was open would be
	// discarded here with "return m, nil" instead of reaching its own
	// case in the switch below, and these three types are only
	// re-armed by their own case (case roomServerMsg/
	// tickFileProgressMsg/incomingChunkWrittenMsg), never elsewhere: a
	// single message lost this way would stop that "waiter" for the rest
	// of the process's life, for waitForRoom, the whole room would stop
	// receiving any traffic (chat, ack, chunk). Starting a second
	// transfer (even a tiny contact card) always goes through one of
	// these popups (sendFilePresetMode at minimum), and with a first
	// transfer active a roomServerMsg or a tickFileProgressMsg (every
	// 300ms while a transfer is active) almost certainly arrives while
	// the popup is open.
	if _, isKeyMsg := msg.(tea.KeyMsg); isKeyMsg {

		// /grp-file-send filesystem browser, intercepted BEFORE the
		// switch because every key here has a dedicated navigation
		// meaning, never free text.
		if m.sendFileMode {
			keyMsg, ok := msg.(tea.KeyMsg)
			if !ok {
				return m, nil
			}
			items := m.sendFileFilteredEntries()
			switch keyMsg.Type {
			case tea.KeyEsc, tea.KeyCtrlC:
				m.sendFileMode = false
				m.sendFileFilter = ""
				return m, nil
			case tea.KeyUp:
				if m.sendFileIdx > 0 {
					m.sendFileIdx--
				}
				return m, nil
			case tea.KeyDown:
				if m.sendFileIdx < len(items)-1 {
					m.sendFileIdx++
				}
				return m, nil
			case tea.KeyLeft:
				return m.sendFileGoUp(), nil
			case tea.KeyBackspace, tea.KeyDelete:
				if m.sendFileFilter != "" {
					r := []rune(m.sendFileFilter)
					m.sendFileFilter = string(r[:len(r)-1])
					m.sendFileIdx = 0
					return m, nil
				}
				return m.sendFileGoUp(), nil
			case tea.KeyRight, tea.KeyEnter:
				if len(items) == 0 || m.sendFileIdx >= len(items) {
					return m, nil
				}
				sel := items[m.sendFileIdx]
				full := filepath.Join(m.sendFileDir, sel.name)
				if sel.isDir {
					return m.sendFileEnter(full), nil
				}
				m.sendFileMode = false
				m.sendFileFilter = ""
				return m.onFileChosenForSend(full)
			default:
				if keyMsg.Type == tea.KeyRunes {
					m.sendFileFilter += string(keyMsg.Runes)
					m.sendFileIdx = 0
				} else if keyMsg.Type == tea.KeySpace {
					m.sendFileFilter += " "
					m.sendFileIdx = 0
				}
				return m, nil
			}
		}

		// /grp-file-send recipients popup (group only), preselected, Space
		// deselects (opt-out).
		if m.sendFileRecipientsMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.sendFileRecipientsMode = false
					return m, nil
				case tea.KeyUp:
					if m.sendFileRecipientsIdx > 0 {
						m.sendFileRecipientsIdx--
					}
				case tea.KeyDown:
					if m.sendFileRecipientsIdx < len(m.sendFileCandidates)-1 {
						m.sendFileRecipientsIdx++
					}
				case tea.KeySpace:
					if m.sendFileRecipientsIdx < len(m.sendFileCandidates) {
						u := m.sendFileCandidates[m.sendFileRecipientsIdx]
						m.sendFileSelected[u] = !m.sendFileSelected[u]
					}
				case tea.KeyEnter:
					chosen := make([]string, 0, len(m.sendFileCandidates))
					for _, u := range m.sendFileCandidates {
						if m.sendFileSelected[u] {
							chosen = append(chosen, u)
						}
					}
					m.sendFileRecipientsMode = false
					if len(chosen) == 0 {
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_send_file_no_content_recipients")))
					}
					return m.onFileRecipientsChosen(chosen)
				}
			}
			return m, nil
		}

		// /grp-invite (new group) recipients popup, nothing preselected,
		// Space selects (opt-in), typing filters by name (Space stays
		// dedicated to selection, doesn't go into the filter, see
		// inviteFilteredCandidates), the same interaction scheme as
		// /grp-file-send's picker with the filter added.
		if m.invitePickerMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				items := m.inviteFilteredCandidates()
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.invitePickerMode = false
					m.inviteFilter = ""
					return m, nil
				case tea.KeyUp:
					if m.inviteIdx > 0 {
						m.inviteIdx--
					}
				case tea.KeyDown:
					if m.inviteIdx < len(items)-1 {
						m.inviteIdx++
					}
				case tea.KeyBackspace, tea.KeyDelete:
					if len(m.inviteFilter) > 0 {
						r := []rune(m.inviteFilter)
						m.inviteFilter = string(r[:len(r)-1])
						m.inviteIdx = 0
					}
				case tea.KeySpace:
					if m.inviteIdx < len(items) {
						u := items[m.inviteIdx]
						m.inviteSelected[u] = !m.inviteSelected[u]
					}
				case tea.KeyEnter:
					client.Dbg("invite picker: Enter received at %s", shared.Now())
					chosen := make([]string, 0, len(m.inviteCandidates))
					for _, u := range m.inviteCandidates {
						if m.inviteSelected[u] {
							chosen = append(chosen, u)
						}
					}
					m.invitePickerMode = false
					m.inviteFilter = ""
					if len(chosen) == 0 {
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_invite")))
					}
					cmd := m.cmdInvite(strings.Join(chosen, " "))
					client.Dbg("invite picker: cmdInvite returned at %s", shared.Now())
					return m, cmd
				default:
					if keyMsg.Type == tea.KeyRunes {
						m.inviteFilter += string(keyMsg.Runes)
						m.inviteIdx = 0
					}
				}
			}
			return m, nil
		}

		// /grp-ping participants popup.
		if m.pingPickerMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.pingPickerMode = false
					return m, nil
				case tea.KeyUp:
					if m.pingPickerIdx > 0 {
						m.pingPickerIdx--
					}
				case tea.KeyDown:
					if m.pingPickerIdx < len(m.pingCandidates)-1 {
						m.pingPickerIdx++
					}
				case tea.KeyEnter:
					m.pingPickerMode = false
					if m.pingPickerIdx >= len(m.pingCandidates) {
						return m, nil
					}
					peerKey := m.pingCandidates[m.pingPickerIdx]
					return m, m.doPing(m.active, peerKey)
				}
			}
			return m, nil
		}

		// /grp-msg-acks popup, choosing one of our own messages to see
		// who confirmed receipt.
		if m.msgAcksPickerMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.msgAcksPickerMode = false
					return m, nil
				case tea.KeyUp:
					if m.msgAcksPickerIdx > 0 {
						m.msgAcksPickerIdx--
					}
				case tea.KeyDown:
					if m.msgAcksPickerIdx < len(m.msgAcksCandidates)-1 {
						m.msgAcksPickerIdx++
					}
				case tea.KeyEnter:
					m.msgAcksPickerMode = false
					if m.msgAcksPickerIdx >= len(m.msgAcksCandidates) {
						return m, nil
					}
					m.msgAcksDetailLineIdx = m.msgAcksCandidates[m.msgAcksPickerIdx]
					m.msgAcksDetailMode = true
				}
			}
			return m, nil
		}

		// /grp-msg-acks detail, read-only, any key closes it (same
		// treatment as helpMode).
		if m.msgAcksDetailMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC, tea.KeyEnter:
					m.msgAcksDetailMode = false
				}
			}
			return m, nil
		}

		// /sec-remote-nuke popup, single-selection picker on
		// the known devices, Enter moves to the explicit confirmation below
		// (never a direct send from here).
		if m.remoteNukePickerMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.remoteNukePickerMode = false
					return m, nil
				case tea.KeyUp:
					if m.remoteNukePickerIdx > 0 {
						m.remoteNukePickerIdx--
					}
				case tea.KeyDown:
					if m.remoteNukePickerIdx < len(m.knownDevicesNow())-1 {
						m.remoteNukePickerIdx++
					}
				case tea.KeyEnter:
					m.remoteNukePickerMode = false
					if m.remoteNukePickerIdx >= len(m.knownDevicesNow()) {
						return m, nil
					}
					m.remoteNukeConfirmIdx = m.remoteNukePickerIdx
					m.remoteNukeConfirmMode = true
				}
			}
			return m, nil
		}

		// /sec-remote-nuke confirmation, Ctrl+C/Esc always cancel
		// (destructive, irreversible action for the target device,
		// never triggered by mistake); only an explicit "s"/"y" proceeds,
		// never /nukex's immediate behavior.
		if m.remoteNukeConfirmMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyCtrlC, tea.KeyEsc:
					m.remoteNukeConfirmMode = false
					return m, nil
				default:
					if keyMsg.Type == tea.KeyRunes && len(keyMsg.Runes) == 1 {
						r := strings.ToLower(string(keyMsg.Runes[0]))
						if r == i18n.T("common.yes") {
							m.remoteNukeConfirmMode = false
							devices := m.knownDevicesNow()
							if m.remoteNukeConfirmIdx >= len(devices) {
								return m, nil
							}
							rec := devices[m.remoteNukeConfirmIdx]
							return m, m.cmdRemoteNuke(rec)
						} else if r == i18n.T("common.no") {
							m.remoteNukeConfirmMode = false
							return m, nil
						}
					}
				}
			}
			return m, nil
		}

		// /sec-clear-all confirmation, Ctrl+C/Esc always cancel
		// (destructive, irreversible for the whole config directory, never
		// triggered by mistake); only an explicit "s"/"y" proceeds.
		if m.clearAllConfirmMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyCtrlC, tea.KeyEsc:
					m.clearAllConfirmMode = false
					return m, nil
				default:
					if keyMsg.Type == tea.KeyRunes && len(keyMsg.Runes) == 1 {
						r := strings.ToLower(string(keyMsg.Runes[0]))
						if r == i18n.T("common.yes") {
							m.clearAllConfirmMode = false
							return m, m.cmdClearAll()
						} else if r == i18n.T("common.no") {
							m.clearAllConfirmMode = false
							return m, nil
						}
					}
				}
			}
			return m, nil
		}

		// /show-qr format choice popup, same two choices as `neutrino
		// show-qr`'s CLI prompt, Up/Down toggles, Enter confirms.
		if m.showQRFormatMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.showQRFormatMode = false
					return m, nil
				case tea.KeyUp, tea.KeyDown:
					m.showQRFormatIdx = 1 - m.showQRFormatIdx
				case tea.KeyEnter:
					m.showQRFormatMode = false
					if m.showQRFormatIdx == 1 {
						return m, m.cmdShowQR()
					}
					return m, m.cmdShowQRSaveImage()
				}
			}
			return m, nil
		}

		// /grp-file-send speed preset popup, only two options, Up/Down
		// toggles, Enter confirms the highlighted one (slow preselected by default).
		if m.sendFilePresetMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.Type {
				case tea.KeyEsc, tea.KeyCtrlC:
					m.sendFilePresetMode = false
					return m, nil
				case tea.KeyUp, tea.KeyDown:
					m.sendFilePresetIdx = 1 - m.sendFilePresetIdx
				case tea.KeyTab:
					m.sendFileCompressOn = !m.sendFileCompressOn
				case tea.KeyEnter:
					preset := "slow"
					if m.sendFilePresetIdx == 1 {
						preset = "warp"
					}
					m.sendFilePresetMode = false
					return m.onFilePresetChosen(preset)
				}
			}
			return m, nil
		}

		// file_offer receipt confirmation popup, accept/reject before a
		// single byte moves. A "self-healing" gate (same pattern as
		// showNextInviteModal): promotes the next queued offer as soon
		// as nothing else is blocking, without having to touch every
		// other popup's exit points one by one.
		if !m.fileOfferMode {
			m.showNextFileOfferModal()
		}
		if m.fileOfferMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch {
				case keyMsg.Type == tea.KeyEsc || keyMsg.Type == tea.KeyCtrlC ||
					(keyMsg.Type == tea.KeyRunes && (string(keyMsg.Runes) == "n" || string(keyMsg.Runes) == "N")):
					transferID := m.fileOfferTransferID
					toUserID := m.fileOfferFromUserID
					tabIdx := m.fileOfferTabIdx
					if p := m.fileProgress.get(transferID); p != nil {
						p.setComplete(true)
					}
					m.dropIncomingTransfer(transferID)
					m.fileOfferMode = false
					m.showNextFileOfferModal()
					tab := m.tabs[tabIdx]
					cli, ctx := tab.cli, tab.ctx
					return m, func() tea.Msg {
						_ = cli.SendFileReject(ctx, toUserID, transferID)
						return nil
					}
				case keyMsg.Type == tea.KeyEnter ||
					(keyMsg.Type == tea.KeyRunes && (string(keyMsg.Runes) == "s" || string(keyMsg.Runes) == "S" ||
						string(keyMsg.Runes) == "y" || string(keyMsg.Runes) == "Y")):
					transferID := m.fileOfferTransferID
					toUserID := m.fileOfferFromUserID
					tabIdx := m.fileOfferTabIdx
					m.fileOfferMode = false
					m.showNextFileOfferModal()
					tab := m.tabs[tabIdx]
					cli, ctx := tab.cli, tab.ctx
					// acceptRetryDeadline starts here, not when the first
					// chunk arrives: every file_accept sent must
					// correspond either to the file's arrival or to an
					// explicit timeout (never an indefinite wait), a
					// file_accept can be silently lost, see Hub.Send in
					// internal/server/hub.go: no backlog for a recipient
					// not registered at that exact instant.
					if it, ok := m.incomingTransfers[transferID]; ok {
						it.acceptRetryDeadline = time.Now().Add(m.fileTransferReconnectTimeout)
					}
					return m, tea.Batch(
						func() tea.Msg {
							err := cli.SendFileAccept(ctx, toUserID, transferID)
							client.Dbg("file_accept: sent to uid=%s… transfer=%s err=%v", client.ShortUID(toUserID), transferID, err)
							return nil
						},
						m.scheduleFileAcceptRetry(tabIdx, toUserID, transferID),
					)
				}
			}
			return m, nil
		}

		// "nobody has accepted the invite yet, close the room?" popup,
		// a "self-healing" gate, same pattern as fileOfferMode above.
		// Enter/s/y = closes the room (closeTabAt), Esc/n = keeps
		// waiting (a simple dismiss, no new timer: the next useful
		// trigger is another explicit decline or, if still nobody has
		// joined, it's still possible to close manually with /grp-exit
		// at any time).
		if !m.groupNoJoinConfirmMode {
			m.showNextGroupNoJoinModal()
		}
		if m.groupNoJoinConfirmMode {
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch {
				case keyMsg.Type == tea.KeyEnter ||
					(keyMsg.Type == tea.KeyRunes && (string(keyMsg.Runes) == "s" || string(keyMsg.Runes) == "S" ||
						string(keyMsg.Runes) == "y" || string(keyMsg.Runes) == "Y")):
					idx := m.groupNoJoinConfirmTabIdx
					m.groupNoJoinConfirmMode = false
					if idx >= 0 && idx < len(m.tabs) {
						name := m.tabs[idx].name
						m.closeTabAt(idx)
						m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.group_no_join_closed"), name)), false)
					}
					m.showNextGroupNoJoinModal()
					return m, nil
				case keyMsg.Type == tea.KeyEsc || keyMsg.Type == tea.KeyCtrlC ||
					(keyMsg.Type == tea.KeyRunes && (string(keyMsg.Runes) == "n" || string(keyMsg.Runes) == "N")):
					m.groupNoJoinConfirmMode = false
					m.showNextGroupNoJoinModal()
				}
			}
			return m, nil
		}

		// received file rename (step 1/2), name proposed by the sender,
		// editable before choosing the folder; same buffer scheme as
		// editContactMode.
		if m.saveRenameMode {
			keyMsg, ok := msg.(tea.KeyMsg)
			if !ok {
				return m, nil
			}
			switch keyMsg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.saveRenameMode = false
				m.savePendingData = nil
				m.savePendingName = ""
				m.saveTitle = ""
				return m, nil
			case tea.KeyBackspace, tea.KeyDelete:
				if r := []rune(m.savePendingName); len(r) > 0 {
					m.savePendingName = string(r[:len(r)-1])
				}
				return m, nil
			case tea.KeyEnter:
				name := strings.TrimSpace(m.savePendingName)
				if name == "" {
					return m, nil
				}
				m.savePendingName = name
				m.saveRenameMode = false
				m.saveDirMode = true
				return m, nil
			default:
				if keyMsg.Type == tea.KeyRunes && len([]rune(m.savePendingName))+len(keyMsg.Runes) <= maxFileNameLen {
					m.savePendingName += string(keyMsg.Runes)
				} else if keyMsg.Type == tea.KeySpace && len([]rune(m.savePendingName)) < maxFileNameLen {
					m.savePendingName += " "
				}
				return m, nil
			}
		}

		// destination folder choice (step 2/2), a hand-rolled directory
		// browser like sendFileMode, but only subfolders (never files:
		// only choosing where to save here) plus a synthetic entry at
		// the top ("save here") representing the current directory itself.
		if m.saveDirMode {
			keyMsg, ok := msg.(tea.KeyMsg)
			if !ok {
				return m, nil
			}
			switch keyMsg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.saveDirMode = false
				m.savePendingData = nil
				m.savePendingName = ""
				m.saveTitle = ""
				return m, nil
			case tea.KeyUp:
				if m.saveFileIdx > 0 {
					m.saveFileIdx--
				}
				return m, nil
			case tea.KeyDown:
				if m.saveFileIdx < len(m.saveFileEntries) {
					m.saveFileIdx++
				}
				return m, nil
			case tea.KeyLeft, tea.KeyBackspace, tea.KeyDelete:
				return m.saveDirGoUp(), nil
			case tea.KeyRight:
				if m.saveFileIdx > 0 && m.saveFileIdx-1 < len(m.saveFileEntries) {
					return m.saveDirEnter(m.saveFileEntries[m.saveFileIdx-1].name), nil
				}
				return m, nil
			case tea.KeyEnter:
				if m.saveFileIdx > 0 {
					if m.saveFileIdx-1 < len(m.saveFileEntries) {
						return m.saveDirEnter(m.saveFileEntries[m.saveFileIdx-1].name), nil
					}
					return m, nil
				}
				dir := m.saveFileDir
				data := m.savePendingData
				name := m.savePendingName
				tabIdx := m.saveFileTabIdx
				consoleIdx := m.consoleIdx
				m.saveDirMode = false
				m.savePendingData = nil
				m.saveTitle = ""
				return m, func() tea.Msg {
					dest := uniqueDestPath(dir, name)
					if err := os.WriteFile(dest, data, 0600); err != nil {
						return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_send_file_read"), err.Error())), isError: true}
					}
					return localDisplayMsg{tabIdx: tabIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.recv_file_saved"), dest))}
				}
			}
			return m, nil
		}

	} // end of isKeyMsg wrapper (see the comment above if m.sendFileMode)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Interface lock on inactivity, intercepts EVERY key BEFORE
		// any other gate/modal when active: no queued popup (invite,
		// file/contact-card offer) can receive input while the
		// interface is locked, they stay unchanged and become
		// responsive again only after unlocking. No application state
		// is touched here, Tor/I2P, connections, open rooms, the probe
		// cycle all keep running unchanged. The identity password always
		// unlocks (compared directly against keystorePassword, in RAM for
		// the session); an optional PIN (CheckLockSecret) also unlocks if
		// configured. A duress recognized here (CheckLockSecret or
		// CheckDuressPassword) arms the same
		// device-sync fan-out as cmdNukeX (armDuressWipe), which sets
		// duressWipeOnExit and closes the TUI once it completes, the
		// actual overwrite+promote+continue (never a process exit, never
		// back to the wizard) happens afterward, in the caller
		// (RunTUI → cmd/main.go:runOnce), exactly like nukeOnExit/cmdNukeX
		// does for /nukex.
		if m.interfaceLocked {
			switch msg.Type {
			case tea.KeyCtrlC:
				return m, tea.Quit
			case tea.KeyEnter:
				result := keystore.LockCheckWrong
				if m.checkLockSecret != nil {
					result = m.checkLockSecret(m.lockUnlockBuf)
				}
				switch result {
				case keystore.LockCheckOK:
					m.interfaceLocked = false
					m.lockUnlockBuf, m.lockUnlockErr = "", ""
					m.lastActivityAt = time.Now()
					return m, nil
				case keystore.LockCheckDuress:
					// The lock's native duress (character+position),
					// never a silent unlock: arms the device-sync fan-out
					// (armDuressWipe) then closes the TUI; the actual
					// teardown-and-re-entry happens in the caller (see
					// the comment above if m.interfaceLocked).
					return m, m.armDuressWipe()
				default:
					if m.lockUnlockBuf != "" && m.lockUnlockBuf == m.keystorePassword {
						// The identity password always unlocks the lock,
						// whether or not a PIN was also configured, see
						// cmdLock.
						m.interfaceLocked = false
						m.lockUnlockBuf, m.lockUnlockErr = "", ""
						m.lastActivityAt = time.Now()
						return m, nil
					}
					if m.checkDuressPassword != nil && m.checkDuressPassword(m.lockUnlockBuf) {
						// The keystore's already-existing duress password
						// recognized by the lock, same treatment as the
						// branch above.
						return m, m.armDuressWipe()
					}
					m.lockUnlockErr = i18n.T("tui.interface_lock_wrong_secret")
					m.lockUnlockBuf = ""
					return m, nil
				}
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.lockUnlockBuf) > 0 {
					r := []rune(m.lockUnlockBuf)
					m.lockUnlockBuf = string(r[:len(r)-1])
				}
				return m, nil
			case tea.KeyRunes:
				m.lockUnlockBuf += string(msg.Runes)
				return m, nil
			case tea.KeySpace:
				m.lockUnlockBuf += " "
				return m, nil
			default:
				return m, nil
			}
		}
		m.lastActivityAt = time.Now()

		// queued group invite popup, a "self-healing" gate: promotes
		// the next invite as soon as nothing else is blocking (e.g.
		// right after another popup closes), without having to touch
		// every other popup's exit points one by one. Enter = Accept,
		// Esc = Ignore, see showNextInviteModal/ignoreInvite.
		if !m.inviteModalMode {
			m.showNextInviteModal()
		}
		if m.inviteModalMode {
			switch msg.Type {
			case tea.KeyEnter:
				groupID := m.inviteModalKnock.GroupID
				m.inviteModalMode = false
				m.inviteModalKnock = nil
				cmd := m.cmdJoin(groupID)
				m.showNextInviteModal()
				return m, cmd
			case tea.KeyEsc:
				k := m.inviteModalKnock
				m.ignoreInvite(k.GroupID)
				m.inviteModalMode = false
				m.inviteModalKnock = nil
				cmd := m.declineInvite(k)
				m.showNextInviteModal()
				return m, cmd
			}
			return m, nil
		}

		// 24-word backup popup, any key closes it, the words don't stay
		// in RAM beyond this moment (see GetBackupMnemonic).
		if m.backupMode {
			m.backupMode = false
			m.backupWords = nil
			return m, nil
		}

		// generic text popup (/cnt-info, /grp-info, /sec-safety),
		// any key closes it, except "c" when the popup carries a
		// copyable URI (cmdInfo self/contact): there it copies to the
		// clipboard and stays open, any subsequent key closes it as usual.
		if m.textPopupMode {
			if m.textPopupCopyURI != "" && msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && (msg.Runes[0] == 'c' || msg.Runes[0] == 'C') {
				m.copyPopupURIToClipboard()
				return m, nil
			}
			m.textPopupMode = false
			m.textPopupCopyURI = ""
			return m, nil
		}

		// animated /show-qr popup, any key closes it, same scheme as
		// textPopupMode above; qrShowGen incremented so a qrShowTickMsg
		// already in flight for this session is recognized as stale.
		if m.qrShowActive {
			m.qrShowActive = false
			m.qrShowSender = nil
			m.qrShowFrame = ""
			m.qrShowGen++
			return m, nil
		}

		// scrollable help overlay
		if m.helpMode {
			total := len(client.CommandList())
			maxScroll := total - 1
			if maxScroll < 0 {
				maxScroll = 0
			}
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc, tea.KeyEnter:
				m.helpMode = false
			case tea.KeyUp:
				if m.helpScroll > 0 {
					m.helpScroll--
				}
			case tea.KeyDown:
				if m.helpScroll < maxScroll {
					m.helpScroll++
				}
			case tea.KeyPgUp:
				// Pages are measured as renderHelp lays them out, so PgUp
				// and PgDn move exactly one shown page.
				m.helpScroll = m.helpPrevPageStart(m.helpScroll)
			case tea.KeyPgDown:
				if end := m.helpPageEnd(m.helpScroll); end <= maxScroll {
					m.helpScroll = end
				}
			}
			return m, nil
		}

		// address book popup for /cnt-info and /cnt-edit
		if m.contactPickerMode {
			items := m.pickerItems()
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.contactPickerMode = false
				m.contactPickerFilter = ""
				m.contactPickerIdx = 0
				return m, nil
			case tea.KeyUp:
				if m.contactPickerIdx > 0 {
					m.contactPickerIdx--
				}
				return m, nil
			case tea.KeyDown:
				if m.contactPickerIdx < len(items)-1 {
					m.contactPickerIdx++
				}
				return m, nil
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.contactPickerFilter) > 0 {
					r := []rune(m.contactPickerFilter)
					m.contactPickerFilter = string(r[:len(r)-1])
					m.contactPickerIdx = 0
				}
				return m, nil
			case tea.KeyEnter:
				if len(items) > 0 && m.contactPickerIdx < len(items) {
					sel := items[m.contactPickerIdx]
					cmd := m.contactPickerCmd
					m.contactPickerMode = false
					m.contactPickerFilter = ""
					m.contactPickerIdx = 0
					// Direct call to the command's function, never a
					// reconstructed m.handleInput(...): since these
					// commands ALWAYS open the picker (even with an
					// argument already typed, see the respective case in
					// handleInput), a recursion into handleInput here
					// would reopen the picker infinitely instead of
					// executing the action on the entry just chosen.
					switch cmd {
					case client.CmdInfo:
						return m, m.cmdInfo(sel)
					case client.CmdEdit:
						return m, m.cmdEdit(sel)
					case client.CmdDelContact:
						return m, m.cmdDelContact(sel)
					case client.CmdDelGroup:
						return m, m.cmdDelGroup(sel)
					case client.CmdRecall:
						return m, m.cmdRecall(sel)
					case client.CmdJoin:
						return m, m.cmdJoin(sel)
					case client.CmdSendContact:
						return m, m.cmdSendContact(sel)
					case client.CmdReinvite:
						return m, m.cmdReinvite(sel)
					case client.CmdAddMember:
						return m, m.cmdAddMember(sel)
					case client.CmdSafety:
						return m, m.cmdSafety(sel)
					case client.CmdVerifySafety:
						return m, m.cmdVerifySafety(sel)
					case client.CmdUnverifySafety:
						return m, m.cmdUnverify(sel)
					case client.CmdBan:
						return m, m.cmdBan(sel)
					case client.CmdPromote:
						return m, m.cmdPromote(sel)
					case client.CmdRotateRelIdentity:
						return m, m.cmdRotateRelIdentity(sel)
					case client.CmdRotateRelContent:
						return m, m.cmdRotateRelContent(sel)
					}
				}
				return m, nil
			default:
				if msg.Type == tea.KeyRunes {
					m.contactPickerFilter += string(msg.Runes)
					m.contactPickerIdx = 0
				} else if msg.Type == tea.KeySpace {
					m.contactPickerFilter += " "
					m.contactPickerIdx = 0
				}
				return m, nil
			}
		}

		// /quit exit confirmation
		if m.quitMode {
			switch msg.Type {
			case tea.KeyCtrlC:
				for _, t := range m.tabs {
					if t.cancel != nil {
						t.cancel()
					}
				}
				m.flushActivitySync()
				m.quitting = true
				return m, tea.Quit
			case tea.KeyEsc:
				m.quitMode = false
				return m, nil
			default:
				if msg.Type == tea.KeyRunes && len(msg.Runes) == 1 {
					r := strings.ToLower(string(msg.Runes[0]))
					if r == i18n.T("common.yes") {
						for _, t := range m.tabs {
							if t.cancel != nil {
								t.cancel()
							}
						}
						m.flushActivitySync()
						m.quitting = true
						return m, tea.Quit
					} else if r == i18n.T("common.no") {
						m.quitMode = false
						return m, nil
					}
				}
			}
			return m, nil
		}

		// /sec-verify confirmation, after showing the full code, only
		// waits for y/n: the comparison must be done out-of-band BEFORE
		// answering here.
		if m.verifySafetyConfirmMode {
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.verifySafetyConfirmMode = false
				m.verifySafetyConfirmContactPub = nil
				m.verifySafetyConfirmRelDanger = false
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.verify_safety_cancelled")))
			default:
				if msg.Type == tea.KeyRunes && len(msg.Runes) == 1 {
					r := strings.ToLower(string(msg.Runes[0]))
					target := m.verifySafetyConfirmTarget
					relDanger := m.verifySafetyConfirmRelDanger
					if r == i18n.T("common.yes") {
						m.verifySafetyConfirmMode = false
						m.verifySafetyConfirmRelDanger = false
						if relDanger {
							contactPub := m.verifySafetyConfirmContactPub
							m.verifySafetyConfirmContactPub = nil
							return m, m.applyPendingRelKeysConfirmation(target, contactPub)
						}
						contactPub := m.verifySafetyConfirmContactPub
						m.verifySafetyConfirmContactPub = nil
						return m, m.applyVerification(target, contactPub)
					} else if r == i18n.T("common.no") {
						m.verifySafetyConfirmMode = false
						m.verifySafetyConfirmContactPub = nil
						m.verifySafetyConfirmRelDanger = false
						return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.verify_safety_cancelled")))
					}
				}
			}
			return m, nil
		}

		// masked input, intercepts every key
		if m.pwdMode != 0 {
			cancelMsg := i18n.T("tui.pwd_cancel_change")
			switch m.pwdMode {
			case 4:
				cancelMsg = i18n.T("tui.pwd_cancel_backup")
			case 5, 6:
				cancelMsg = i18n.T("tui.duress_cancelled")
			case 7, 8, 9, 10:
				cancelMsg = i18n.T("tui.lock_setup_cancelled")
			}
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
				m.lockSetupSecret, m.lockSetupMarker = "", ""
				return m, localTab(m.active, styleMeta.Render(cancelMsg))
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.pwdBuf) > 0 {
					r := []rune(m.pwdBuf)
					m.pwdBuf = string(r[:len(r)-1])
				}
			case tea.KeyEnter:
				switch m.pwdMode {
				case 1: // current password
					if m.pwdBuf == "" {
						m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.op_cancelled")))
					}
					m.pwdOld, m.pwdBuf, m.pwdMode = m.pwdBuf, "", 2
				case 2: // new password
					if m.pwdBuf == "" {
						m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_empty_cancelled")))
					}
					m.pwdFirst, m.pwdBuf, m.pwdMode = m.pwdBuf, "", 3
				case 3: // confirm new password
					if m.pwdBuf != m.pwdFirst {
						m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_mismatch_cancelled")))
					}
					oldPwd, newPwd := m.pwdOld, m.pwdFirst
					m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
					consoleIdx := m.consoleIdx
					fn := m.changePassword
					if fn == nil {
						return m, consoleErrTab(consoleIdx, styleErr.Render(i18n.T("tui.pwd_change_unavailable")))
					}
					return m, func() tea.Msg {
						if err := fn(oldPwd, newPwd); err != nil {
							return localDisplayMsg{tabIdx: consoleIdx,
								text: styleErr.Render(fmt.Sprintf(i18n.T("tui.pwd_change_error"), err.Error())), isError: true}
						}
						return passwordChangedMsg{newPwd: newPwd}
					}
				case 4: // password check for /sec-backup
					entered := m.pwdBuf
					m.pwdMode, m.pwdBuf = 0, ""
					if entered != m.keystorePassword {
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_wrong_backup_cancelled")))
					}
					if m.getBackupMnemonic == nil {
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_backup_unavailable")))
					}
					words, err := m.getBackupMnemonic()
					if err != nil || len(words) != 24 {
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_backup_unavailable")))
					}
					m.backupWords = words
					m.backupMode = true
					return m, nil
				case 5: // new decoy identity password, the shared decoy
					// identity exists structurally in every file (N-slot
					// format) and can't be removed, only changed: an
					// empty entry is simply invalid, like
					// any other empty new-password field, never a removal.
					if m.pwdBuf == "" {
						m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_empty_cancelled")))
					}
					if m.pwdBuf == m.keystorePassword {
						m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.duress_same_as_real_cancelled")))
					}
					m.pwdFirst, m.pwdBuf, m.pwdMode = m.pwdBuf, "", 6
				case 6: // confirm new decoy identity password
					if m.pwdBuf != m.pwdFirst {
						m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_mismatch_cancelled")))
					}
					newPwd := m.pwdFirst
					m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 0, "", "", ""
					consoleIdx := m.consoleIdx
					locIdx := m.defaultTabIdx()
					fn := m.setDuress
					if fn == nil {
						return m, consoleErrTab(consoleIdx, styleErr.Render(i18n.T("tui.duress_unavailable")))
					}
					return m, func() tea.Msg {
						if err := fn(newPwd); err != nil {
							return localDisplayMsg{tabIdx: consoleIdx,
								text: styleErr.Render(fmt.Sprintf(i18n.T("tui.duress_error"), err.Error())), isError: true}
						}
						return localDisplayMsg{tabIdx: locIdx, text: i18n.T("tui.duress_set")}
					}
				case 7: // new lock PIN (see cmdLockPIN), an additional, optional
					// unlock path: the identity password always unlocks the lock
					// regardless (see cmdLock), so this never needs to differ
					// from it to stay meaningful.
					if m.pwdBuf == "" {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_empty_cancelled")))
					}
					if m.pwdBuf == m.keystorePassword {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.lock_same_as_real_cancelled")))
					}
					if !isDigitsOnly(m.pwdBuf) {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_pin_invalid")))
					}
					if len([]rune(m.pwdBuf)) < 4 {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_pin_too_short")))
					}
					m.lockSetupSecret, m.pwdBuf, m.pwdMode = m.pwdBuf, "", 8
				case 8: // confirm the PIN
					if m.pwdBuf != m.lockSetupSecret {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_mismatch_cancelled")))
					}
					m.pwdMode, m.pwdBuf = 9, ""
				case 9: // PIN duress character, a single digit
					r := []rune(m.pwdBuf)
					if len(r) != 1 || r[0] < '0' || r[0] > '9' {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_duress_marker_invalid")))
					}
					m.lockSetupMarker, m.pwdBuf, m.pwdMode = m.pwdBuf, "", 10
				case 10: // duress character's position, see Keystore.LockDuressPosition
					pinLen := len([]rune(m.lockSetupSecret))
					pos, perr := strconv.Atoi(strings.TrimSpace(m.pwdBuf))
					if perr != nil || pos < 0 || pos > pinLen {
						m.pwdMode, m.pwdBuf = 0, ""
						m.lockSetupSecret, m.lockSetupMarker = "", ""
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_duress_position_invalid")))
					}
					secret, marker := m.lockSetupSecret, m.lockSetupMarker
					m.pwdMode, m.pwdBuf = 0, ""
					m.lockSetupSecret, m.lockSetupMarker = "", ""
					fn := m.setLockSecret
					consoleIdx := m.consoleIdx
					if fn == nil {
						return m, consoleErrTab(consoleIdx, styleErr.Render(i18n.T("tui.err_lock_unavailable")))
					}
					return m, func() tea.Msg {
						if err := fn(secret, true, marker, pos); err != nil {
							return localDisplayMsg{tabIdx: consoleIdx,
								text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_lock_generic"), err.Error())), isError: true}
						}
						return localDisplayMsg{tabIdx: consoleIdx, text: i18n.T("tui.lock_set")}
					}
				}
			default:
				if msg.Type == tea.KeyRunes {
					m.pwdBuf += string(msg.Runes)
				} else if msg.Type == tea.KeySpace {
					m.pwdBuf += " "
				}
			}
			return m, nil // doesn't pass through to the textarea
		}

		// summary of the data read (username/key/PQC) + y/n confirmation,
		// before the local name prompt, same y/n scheme as
		// verifySafetyConfirmMode above.
		if m.addContactConfirmMode {
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.addContactConfirmMode = false
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.add_contact_cancelled")))
			case tea.KeyEnter:
				// Enter alone confirms (affirmative default, see
				// tui.add_contact_confirm_prompt, the active language's
				// affirmative letter, always the uppercase one in the
				// prompt): the user has already seen the
				// summary, the "save?" question is meant for a quick
				// yes, not a 50/50 choice.
				m.addContactConfirmMode = false
				m.addContactMode = true
				m.addContactBuf = ""
				return m, nil
			default:
				if msg.Type == tea.KeyRunes && len(msg.Runes) == 1 {
					r := strings.ToLower(string(msg.Runes[0]))
					if r == i18n.T("common.yes") {
						m.addContactConfirmMode = false
						m.addContactMode = true
						m.addContactBuf = ""
					} else if r == i18n.T("common.no") {
						m.addContactConfirmMode = false
						return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.add_contact_cancelled")))
					}
				}
			}
			return m, nil
		}

		// local name prompt for /cnt-add
		if m.addContactMode {
			switch msg.Type {
			case tea.KeyCtrlC:
				m.addContactMode, m.addContactBuf = false, ""
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.add_contact_cancelled")))
			case tea.KeyEsc:
				m.addContactMode, m.addContactBuf = false, ""
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.add_contact_cancelled")))
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.addContactBuf) > 0 {
					r := []rune(m.addContactBuf)
					m.addContactBuf = string(r[:len(r)-1])
				}
			case tea.KeyEnter:
				localName := m.addContactBuf
				if localName == "" {
					localName = m.pendingContact.username
				}
				pc := m.pendingContact
				m.addContactMode, m.addContactBuf = false, ""
				fn := m.addContact
				consoleIdx := m.consoleIdx
				// If the contact just added is a member of this room
				// (case 1: they present themselves, or case 2:
				// introduced by another member but they're present
				// too), immediately update the room's safety bar. Not a
				// member (case 3, a third party introduced but absent)
				// → no update: computing the code would be meaningless
				// for someone who isn't here.
				var isTabPeer bool
				if pc.tabIdx < len(m.tabs) {
					t := m.tabs[pc.tabIdx]
					for _, mem := range t.groupMembers {
						if bytes.Equal(mem.IdentityPub, pc.pubBytes) && memberKey(mem) != m.myKey() {
							isTabPeer = true
							break
						}
					}
				}
				// introducedBy: who sent the card, only if it describes
				// someone else (a card that "describes itself", an
				// edge case, counts as a direct addition).
				var introducedBy string
				var introducedByPub []byte
				if pc.cardFrom != "" {
					introducedByPub = memberKeyPub(pc.cardFrom)
					introducedBy = m.memberName(m.tabAt(pc.tabIdx), pc.cardFrom)
				}
				if bytes.Equal(introducedByPub, pc.pubBytes) {
					introducedBy, introducedByPub = "", nil
				}
				return m, func() tea.Msg {
					if fn == nil {
						return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(i18n.T("tui.add_contact_unavailable")), isError: true}
					}
					myIdentKey, myContentKey, err := fn(pc.username, localName, pc.pubBytes, pc.mlkemPub, pc.mldsaPub, introducedBy, introducedByPub)
					if err != nil {
						return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error_for"), pc.username, err.Error())), isError: true}
					}
					newContact := ContactInfo{
						Username:        pc.username,
						LocalName:       localName,
						NetAddr:         m.computeAddress(ed25519.PublicKey(pc.pubBytes)),
						IdentityPub:     ed25519.PublicKey(pc.pubBytes),
						MLKEMPub:        pc.mlkemPub,
						MLDSAPub:        pc.mldsaPub,
						IntroducedBy:    introducedBy,
						IntroducedByPub: introducedByPub,
						// No peer device known yet, "" placeholder
						// entry (see TUIParams.AddContact/RelKeyUpdate),
						// promoted by the first real rel_init/rel_init_ack.
						Devices: map[string]*keystore.DeviceRelation{
							"": {
								RelIdentityPriv:      myIdentKey.Priv,
								RelIdentityMLKEMPriv: myIdentKey.MLKEMSeed,
								RelIdentityMLDSAPriv: myIdentKey.MLDSASeed,
								RelContentPriv:       myContentKey.Priv,
								RelContentMLKEMPriv:  myContentKey.MLKEMSeed,
								RelContentMLDSAPriv:  myContentKey.MLDSASeed,
							},
						},
					}
					display := localName + " (" + pc.username + ")"
					return contactAddedMsg{
						tabIdx:      pc.tabIdx,
						displayText: fmt.Sprintf(i18n.T("tui.contact_added"), display),
						identityPub: ed25519.PublicKey(pc.pubBytes),
						contact:     newContact,
						isTabPeer:   isTabPeer,
					}
				}
			default:
				if msg.Type == tea.KeyRunes && len([]rune(m.addContactBuf))+len(msg.Runes) <= maxLocalNameLen {
					m.addContactBuf += string(msg.Runes)
				} else if msg.Type == tea.KeySpace && len([]rune(m.addContactBuf)) < maxLocalNameLen {
					m.addContactBuf += " "
				}
			}
			return m, nil
		}

		// source choice for /cnt-read-qrcode: a single dedicated key
		// (f/c), never free text, avoids any ambiguity with a file
		// path that could start with "f" or "c".
		if m.qrChooseMode {
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.qrChooseMode = false
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.read_qr_cancelled")))
			case tea.KeyRunes:
				switch string(msg.Runes) {
				case "f", "F":
					dir := startDirForFileBrowser()
					entries, err := listDir(dir)
					if err != nil {
						m.qrChooseMode = false
						return m, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error"), err.Error())))
					}
					m.qrChooseMode = false
					m.qrFileMode = true
					m.qrFileDir = dir
					m.qrFileEntries = entries
					m.qrFileIdx = 0
					m.qrFileFilter = ""
					m.qrFileSelected = nil
				case "c", "C":
					m.qrChooseMode = false
					return m, m.cmdReadQRCamera()
				}
			}
			return m, nil
		}

		// camera live preview for /cnt-read-qrcode, Esc cancels the
		// capture (m.qrCameraCancel) and closes the popup right away;
		// the capture goroutine's final message, if it arrives later,
		// is silently discarded (see case qrCameraDoneMsg: guarded by qrCameraPreviewMode).
		if m.qrCameraPreviewMode {
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.qrCameraPreviewMode = false
				if m.qrCameraCancel != nil {
					m.qrCameraCancel()
				}
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.read_qr_cancelled")))
			}
			return m, nil
		}

		// filesystem browser for /cnt-read-qrcode (after choosing "file")
		// same component as /grp-file-send's browser (fsEntry/listDir),
		// with Space added for multi-select: an identity QR is often
		// split across several numbered PNGs, Space toggles each onto
		// m.qrFileSelected (in the order toggled) without leaving the
		// browser, Enter then confirms the whole set at once. Enter with
		// nothing toggled keeps the single-file convenience (the common
		// case for a backup/sync QR or a one-image identity).
		if m.qrFileMode {
			items := m.qrFileFilteredEntries()
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.qrFileMode, m.qrFileFilter, m.qrFileSelected = false, "", nil
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.read_qr_cancelled")))
			case tea.KeyUp:
				if m.qrFileIdx > 0 {
					m.qrFileIdx--
				}
				return m, nil
			case tea.KeyDown:
				if m.qrFileIdx < len(items)-1 {
					m.qrFileIdx++
				}
				return m, nil
			case tea.KeyLeft:
				return m.qrFileGoUp(), nil
			case tea.KeyBackspace, tea.KeyDelete:
				if m.qrFileFilter != "" {
					r := []rune(m.qrFileFilter)
					m.qrFileFilter = string(r[:len(r)-1])
					m.qrFileIdx = 0
					return m, nil
				}
				return m.qrFileGoUp(), nil
			case tea.KeySpace:
				if len(items) == 0 || m.qrFileIdx >= len(items) {
					return m, nil
				}
				sel := items[m.qrFileIdx]
				if sel.isDir {
					return m, nil
				}
				full := filepath.Join(m.qrFileDir, sel.name)
				m.qrFileSelected = toggleStringInOrder(m.qrFileSelected, full)
				return m, nil
			case tea.KeyRight, tea.KeyEnter:
				if len(items) == 0 || m.qrFileIdx >= len(items) {
					return m, nil
				}
				sel := items[m.qrFileIdx]
				full := filepath.Join(m.qrFileDir, sel.name)
				if sel.isDir {
					return m.qrFileEnter(full), nil
				}
				chosen := m.qrFileSelected
				if len(chosen) == 0 {
					chosen = []string{full}
				}
				m.qrFileMode, m.qrFileFilter, m.qrFileSelected = false, "", nil
				return m, m.cmdReadQRFiles(chosen)
			default:
				if msg.Type == tea.KeyRunes {
					m.qrFileFilter += string(msg.Runes)
					m.qrFileIdx = 0
				}
			}
			return m, nil
		}

		// out-of-band contact info prompt for /grp-contact-send,
		// mandatory: Enter with an empty buffer does nothing, the
		// prompt itself explains why (see View()).
		if m.sendContactHintMode {
			switch msg.Type {
			case tea.KeyCtrlC, tea.KeyEsc:
				m.sendContactHintMode, m.sendContactHintBuf = false, ""
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.send_contact_hint_cancelled")))
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.sendContactHintBuf) > 0 {
					r := []rune(m.sendContactHintBuf)
					m.sendContactHintBuf = string(r[:len(r)-1])
				}
			case tea.KeyEnter:
				hint := strings.TrimSpace(m.sendContactHintBuf)
				if hint == "" {
					return m, nil
				}
				m.sendContactHintMode, m.sendContactHintBuf = false, ""
				return m, m.finishSendContact(hint)
			default:
				if msg.Type == tea.KeyRunes && len([]rune(m.sendContactHintBuf))+len(msg.Runes) <= maxOffbandHintLen {
					m.sendContactHintBuf += string(msg.Runes)
				} else if msg.Type == tea.KeySpace && len([]rune(m.sendContactHintBuf)) < maxOffbandHintLen {
					m.sendContactHintBuf += " "
				}
			}
			return m, nil
		}

		// local name editing for /cnt-edit
		if m.editContactMode {
			switch msg.Type {
			case tea.KeyCtrlC:
				m.editContactMode, m.editContactBuf = false, ""
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.edit_cancelled")))
			case tea.KeyEsc:
				m.editContactMode, m.editContactBuf = false, ""
				return m, localTab(m.defaultTabIdx(), styleMeta.Render(i18n.T("tui.edit_cancelled")))
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.editContactBuf) > 0 {
					r := []rune(m.editContactBuf)
					m.editContactBuf = string(r[:len(r)-1])
				}
			case tea.KeyEnter:
				newName := strings.TrimSpace(m.editContactBuf)
				username := m.pendingEditUsername
				pub := m.pendingEditContactPub
				locIdx := m.defaultTabIdx()
				consoleIdx := m.consoleIdx
				m.editContactMode, m.editContactBuf = false, ""
				// update in memory
				for i := range m.contacts {
					if bytes.Equal(m.contacts[i].IdentityPub, pub) {
						m.contacts[i].LocalName = newName
						break
					}
				}
				fn := m.updateContactLocalName
				return m, func() tea.Msg {
					if fn != nil {
						if err := fn(pub, newName); err != nil {
							return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error_for"), username, err.Error())), isError: true}
						}
					}
					if newName == "" {
						return localDisplayMsg{tabIdx: locIdx, text: fmt.Sprintf(i18n.T("tui.local_name_removed"), username)}
					}
					return localDisplayMsg{tabIdx: locIdx, text: fmt.Sprintf(i18n.T("tui.local_name_set"), username, newName)}
				}
			default:
				if msg.Type == tea.KeyRunes && len([]rune(m.editContactBuf))+len(msg.Runes) <= maxLocalNameLen {
					m.editContactBuf += string(msg.Runes)
				} else if msg.Type == tea.KeySpace && len([]rune(m.editContactBuf)) < maxLocalNameLen {
					m.editContactBuf += " "
				}
			}
			return m, nil
		}

		if m.showPalette {
			items := m.filteredCommands()
			switch msg.Type {
			case tea.KeyUp:
				if m.paletteIdx > 0 {
					m.paletteIdx--
				}
				return m, nil
			case tea.KeyDown:
				if m.paletteIdx < len(items)-1 {
					m.paletteIdx++
				}
				return m, nil
			case tea.KeyEnter:
				if len(items) > 0 && m.paletteIdx < len(items) {
					sel := items[m.paletteIdx]
					// Always two steps: an Enter after a few letters (or
					// after navigating with the arrows without typing
					// the full name) ONLY completes the field's text,
					// never executes or opens a surprise picker. A
					// command with no parameters still executes right
					// away, since there's nothing else to type; a
					// command with a parameter needs a second Enter on
					// the now-complete name to confirm, at that point
					// handleInput opens the picker if the argument stays
					// empty, exactly as if typed by hand.
					if strings.TrimSpace(m.ta.Value()) != sel.Cmd {
						m.ta.SetValue(sel.Cmd + " ")
						if sel.Arg == "" {
							m.showPalette = false
							m.paletteIdx = 0
							m.ta.Reset()
							return m, m.handleInput(sel.Cmd)
						}
						return m, nil
					}
					m.showPalette = false
					m.paletteIdx = 0
					m.ta.Reset()
					return m, m.handleInput(sel.Cmd)
				}
				m.showPalette = false
				return m, nil
			case tea.KeyEsc, tea.KeyTab:
				m.showPalette = false
				m.paletteIdx = 0
				return m, nil
			case tea.KeyCtrlC:
				return m, nil
			}
			// other keys (e.g. letters to filter): pass through to the textarea
		} else {
			switch msg.Type {
			case tea.KeyCtrlC:
				return m, nil

			case tea.KeyTab:
				if len(m.tabs) > 1 {
					m.active = (m.active + 1) % len(m.tabs)
					m.tabs[m.active].unread = 0
					m.refreshViewport()
				}

			case tea.KeyShiftTab:
				if len(m.tabs) > 1 {
					m.active = (m.active - 1 + len(m.tabs)) % len(m.tabs)
					m.tabs[m.active].unread = 0
					m.refreshViewport()
				}

			case tea.KeyLeft:
				// With text in the textarea, ←/→ move the writing
				// cursor instead of switching tabs, tab switching with
				// the arrows stays active only on an empty line
				// (Shift+Tab/Tab remain always available to switch tabs).
				if m.ta.Value() == "" && len(m.tabs) > 1 {
					m.active = (m.active - 1 + len(m.tabs)) % len(m.tabs)
					m.tabs[m.active].unread = 0
					m.refreshViewport()
				}

			case tea.KeyRight:
				if m.ta.Value() == "" && len(m.tabs) > 1 {
					m.active = (m.active + 1) % len(m.tabs)
					m.tabs[m.active].unread = 0
					m.refreshViewport()
				}

			case tea.KeyEnter:
				text := strings.TrimSpace(m.ta.Value())
				if text == "" {
					break
				}
				m.ta.Reset()
				return m, m.handleInput(text)
			}
			// No other block on typing: any text can be typed in any
			// tab. The only check remains at Enter (handleInput/
			// sendMessage), a command must start with "/", free text
			// is a valid action only inside a real chat room (isStandardTab()).
		}

	case tea.WindowSizeMsg:
		m.lastTermH = msg.Height
		m.lastTermW = msg.Width
		vpH := m.calcVpH()
		if !m.ready {
			m.vp = viewport.New(msg.Width, vpH)
			m.vp.YPosition = 2
			// KeyMap reduced to only PgUp/PgDown (the only documented
			// keyboard scroll, besides the mouse wheel).
			// bubbles/viewport's default keymap also binds
			// j/k/u/d/b/f/h/l/space vim-style, since m.vp.Update(msg)
			// runs on EVERY key, in parallel with m.ta.Update(msg) (see
			// the bottom of Update()), those same letters typed to
			// write a message would scroll the viewport as a side
			// effect. HalfPageUp/HalfPageDown/Up/Down/Left/Right stay at
			// the zero value (key.Binding{}, no key bound, key.Matches
			// never finds a match on an empty binding).
			m.vp.KeyMap = viewport.KeyMap{
				PageDown: key.NewBinding(key.WithKeys("pgdown")),
				PageUp:   key.NewBinding(key.WithKeys("pgup")),
			}
			m.ready = true
		} else {
			m.vp.Width = msg.Width
			m.vp.Height = vpH
		}
		// -4: styleBorder's border (2) + horizontal padding (2), which
		// wraps m.ta.View() at render time, SetWidth must reserve that
		// space, not fill the entire terminal width (otherwise the
		// right border ends up off-screen).
		m.ta.SetWidth(msg.Width - 4)
		m.refreshViewport()

	case roomServerMsg:
		if msg.idx < len(m.tabs) {
			tab := m.tabs[msg.idx]
			tab.lastActivityAt = time.Now()
			typ, _ := msg.raw["type"].(string)
			cmds := m.handleRoomMsg(msg.idx, msg.raw)
			// The indicator only flags real chat messages, not every
			// protocol frame (init, user_joined/left, sender_key,
			// file_offer/accept/reject/chunk/ack, msg_ack...)
			// that still arrives on this channel.
			if msg.idx != m.active && typ == "message" {
				tab.unread++
			}
			m.refreshViewport()
			return m, tea.Batch(append(cmds, m.waitForRoom(msg.idx))...)
		}

	case incomingChunkWrittenMsg:
		// Outcome of ONE chunk written to disk by the dedicated
		// goroutine, see the comment on incomingFileTransfer for why
		// this doesn't run inside handleRoomMsg/case "file_chunk".
		// Updates written/progress, sends the ack, and only here (never
		// in case "file_chunk") decides whether the transfer is complete.
		it := m.incomingTransfers[msg.transferID]
		if it == nil {
			return m, nil // transfer already removed (previous error or late duplicate)
		}
		if msg.err != nil {
			m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.err_send_file_read"), msg.err.Error())), true)
			if it.progress != nil {
				it.progress.setComplete(true)
			}
			// The writer goroutine already exited on its own on this
			// same error (a return inside startIncomingChunkWriter, not
			// a chunkCh close), dropIncomingTransfer closes it here
			// regardless, harmless and consistent with the other
			// abandonment points.
			m.dropIncomingTransfer(msg.transferID)
			return m, nil
		}
		delta := msg.written - it.written
		it.written = msg.written
		it.tmpPath = msg.tmpPath
		if it.progress != nil {
			if delta > 0 {
				it.progress.addDone(delta)
			}
			it.progress.setChunks(int64(msg.nextIndex)+int64(msg.buffered), int64(msg.buffered), int64(it.chunkCount))
		}
		var cmds []tea.Cmd
		if it.tabIdx < len(m.tabs) {
			tab := m.tabs[it.tabIdx]
			fromUserID, toCtx, toCli, seq, transferID := it.fromUserID, tab.ctx, tab.cli, msg.seq, msg.transferID
			cmds = append(cmds, func() tea.Msg {
				err := toCli.SendFileChunkAck(toCtx, fromUserID, transferID, seq)
				client.Dbg("recv_file: transfer=%s ack seq=%d to uid=%s… err=%v", transferID, seq, client.ShortUID(fromUserID), err)
				return nil
			})
		}
		if msg.complete {
			// complete, not written>=fileSize: fileSize is the
			// encrypted blob's size, but a chunk buffered awaiting
			// reordering (see startIncomingChunkWriter) isn't "written"
			// yet despite having already arrived, the only reliable
			// end-of-transfer signal is the contiguous written frontier
			// reaching chunkCount, computed by the writer goroutine
			// itself. Closes chunkCh (never before now): the writer
			// goroutine exits the for-range and closes the file on its
			// own. No race with finalizeIncomingTransfer's os.ReadFile
			// below: Go's os.File doesn't buffer Writes, THIS chunk's
			// content (the frontier's last one) is already visible to a
			// concurrent read even before this same result was sent on
			// chunkResultCh, see the comment on startIncomingChunkWriter.
			close(it.chunkCh)
			cmds = append(cmds, m.finalizeIncomingTransfer(it))
			delete(m.incomingTransfers, msg.transferID)
		} else {
			cmds = append(cmds, waitForIncomingChunkResult(it.chunkResultCh))
		}
		return m, tea.Batch(cmds...)

	case roomErrMsg:
		if msg.idx < len(m.tabs) {
			tab := m.tabs[msg.idx]
			// Generation superseded (see roomErrMsg.gen): a ping or a
			// read started on the previous connection can fail AFTER a
			// reconnect (automatic or manual) has already replaced
			// tab.ctx/tab.pingGen, such a late failure no longer
			// concerns the current attempt and must be ignored,
			// otherwise it would reset tab.reconnecting while a more
			// recent reconnect is still in progress, or would restart
			// an unnecessary reconnect on an already-healthy connection.
			if msg.gen != tab.pingGen {
				break
			}
			// Voluntary exit (/grp-exit): the context is already canceled, the WS error is expected.
			if tab.ctx != nil && tab.ctx.Err() != nil {
				break
			}
			// Slot occupied by another one of OUR OWN devices in this
			// room, "one device per identity per room". Unlike every
			// other failure handled below, this one resolves ONLY when
			// the other device disconnects, never a network issue a
			// growing backoff would help overcome, retries at a fixed
			// interval, indefinitely, never a final error.
			if errors.Is(msg.err, client.ErrAlreadyConnectedElsewhere) {
				tab.reconnecting = true
				msgText := fmt.Sprintf(i18n.T("tui.err_room_slot_busy"), tab.name, int(roomSlotBusyRetryInterval.Seconds()))
				if tab.cli != nil && tab.cli.IsRemote() {
					m.appendToTor(styleMeta.Render(msgText))
				} else {
					m.appendToConsole(styleMeta.Render(msgText), false)
				}
				return m, m.waitAndRetrySlot(msg.idx)
			}
			// Self-heal: a handshake that ALWAYS fails with "invalid
			// signature", never transient, toward an otherwise reachable
			// host means OUR copy of its per-relationship IdentityKey is
			// out of sync with a regeneration of its own that never
			// propagated. errors.Is survives the localized wrapping done
			// by Connect/ConnectWithRetry (see client.ErrInvalidServerSig).
			// Resetting RelInitConfirmedByPeer for this host reactivates
			// the "resend rel_init" branch of the probe cycle (never
			// blindly, only when the host is found online): the host
			// ALWAYS replies to an incoming rel_init with its CURRENT key,
			// regardless of its own RelInitConfirmedByPeer (see
			// applyRelInit), a single round trip is enough to realign,
			// with no manual action (rotation, re-invite) needed from the user.
			if tab.hostKey != "" && errors.Is(msg.err, client.ErrInvalidServerSig) {
				if hc := m.resolveContactByPub(memberKeyPub(tab.hostKey)); hc != nil {
					if devPub, dev, ok := hc.SoleDeviceKey(); ok && dev.RelIdentityConfirmedByPeer {
						dev.RelIdentityConfirmedByPeer = false
						if resetFn := m.resetRelInitConfirmed; resetFn != nil {
							pub := hc.IdentityPub
							go func() { _ = resetFn(pub, devPub, "identity") }()
						}
						m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.err_stale_rel_key_reset"), m.memberName(tab, tab.hostKey))), true)
					}
				}
			}
			// First disconnection: start a silent automatic reconnect
			// (unless the server already notified its own shutdown),
			// BOTH remote AND loopback: the reconnect itself
			// (reconnectTab/Client.Connect) is already transport-
			// independent, so the trigger condition must not exclude
			// loopback either (the host's connection to its own local
			// server has tab.cli.IsRemote()==false, since cmdInvite
			// never calls SetDialer for it).
			if !tab.isConsole && tab.cli != nil && !tab.reconnecting && !tab.serverShutdown {
				tab.reconnecting = true
				if tab.groupID != "" {
					tab.online = nil // fallen host: everyone offline until it reconnects
				}
				if tab.cli.IsRemote() {
					m.appendToTor(styleMeta.Render(fmt.Sprintf(i18n.T("tui.tor_disconnect_reconnecting"), tab.name)))
				} else {
					m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.tor_disconnect_reconnecting"), tab.name)), false)
				}
				m.refreshViewport()
				return m, m.reconnectTab(msg.idx)
			}
			// Non-Tor connection or automatic reconnect already failed: show final error
			tab.reconnecting = false
			if tab.awaitingJoin {
				tab.awaitingJoin = false
				m.textPopupMode = false
				m.textPopupCopyURI = ""
			}
			errText := msg.err.Error()
			if tab.cli != nil && tab.cli.IsRemote() {
				m.appendToTor(styleErr.Render(fmt.Sprintf("✗ %s: %s", tab.name, errText)))
			} else {
				m.appendToConsole(styleErr.Render(fmt.Sprintf("✗ %s: %s", tab.name, errText)), true)
			}
			m.refreshViewport()
		}

	case roomConnectedMsg:
		if msg.idx < len(m.tabs) {
			tab := m.tabs[msg.idx]
			tab.reconnecting = false
			if tab.awaitingJoin {
				tab.awaitingJoin = false
				m.textPopupMode = false
				m.textPopupCopyURI = ""
			}
			if tab.cli != nil && tab.cli.IsRemote() {
				m.appendToTor(fmt.Sprintf(i18n.T("tui.connected"), tab.name))
			} else {
				m.appendToConsole(fmt.Sprintf(i18n.T("tui.connected"), tab.name), false)
			}
			// pingGen incremented on every (re)connection: a
			// pingProbeOKMsg from the previous connection still in
			// flight will be recognized as superseded and discarded,
			// instead of starting a second, parallel probe cycle.
			tab.pingGen++
			tab.pingMisses = 0
			idx, gen := msg.idx, tab.pingGen
			return m, tea.Batch(m.waitForRoom(msg.idx), tea.Tick(wakeScanInterval, func(time.Time) tea.Msg {
				return pingWatchdogTickMsg{idx: idx, gen: gen}
			}))
		}

	case groupNoJoinTimeoutMsg:
		if msg.idx < len(m.tabs) && m.tabs[msg.idx].groupID == msg.groupID {
			m.queueGroupNoJoinPrompt(msg.idx)
		}

	case remoteNukeExecutedMsg:
		// The best-effort sequence (danger_broadcast + ack) has ended,
		// success or timeout, same scheme as cmdNukeX: the actual
		// deletion happens after exiting the TUI, in main().
		m.nukeOnExit = true
		return m, tea.Quit

	case deviceSyncNukeDoneMsg:
		// cmdNukeX's (or armDuressWipe's) device-sync fan-out has ended,
		// success or timeout, only now does the actual overwrite/swap
		// happen, after exiting the TUI, in main().
		if msg.duress {
			m.duressWipeOnExit = true
		} else {
			m.nukeOnExit = true
		}
		return m, tea.Quit

	case indoorSyncDoneMsg:
		m.indoorSyncing = false
		if msg.err != nil {
			return m, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.indoor_sync_failed"), msg.err)))
		}
		m.adoptSyncedContacts()
		m.appendToConsole(i18n.T("tui.indoor_sync_done"), false)
		return m, nil

	case knockMsg:
		k := shared.KnockPayload(msg)
		// any incoming knock proves our HS is reachable
		wasIn := m.torIn != nil && *m.torIn
		t := true
		m.torIn = &t
		m.appendToDebug(fmt.Sprintf(i18n.T("tui.knock_debug"), k.Type, k.FromUsername))
		client.Dbg("knock: received type=%q from=%s groupID=%s", k.Type, k.FromUsername, k.GroupID)
		var cmd tea.Cmd
		switch k.Type {
		case "rel_init", "rel_init_ack":
			// Same branch for both: the cycle's symmetry means whichever
			// side arrives first or second behaves the same way, only the
			// Type changes (see applyRelInit).
			cmd = m.applyRelInit(k)
		case "rel_identity_rotate", "rel_identity_rotate_ack", "rel_content_rotate", "rel_content_rotate_ack":
			// Same scheme as rel_init/rel_init_ack above, applied to the
			// rotation of a single relationship key, see applyRelRotate.
			cmd = m.applyRelRotate(k)
		case "probe_ping":
			cmd = m.applyProbePing(k)
		case "probe_ack":
			cmd = m.applyProbeAck(k)
		case "self_probe":
			// torIn already set on handler entry; no further action
		case "wake":
			// A peer has seen us as "down" and is inviting us to retry the
			// connection, only the network side of /grp-reconnect, no UI
			// effect (see reconnectTab). Per-groupID cooldown on the
			// receiving side: several members can detect the same
			// downtime and send the wake in parallel, or a buggy/
			// malicious sender can flood more than one.
			if k.GroupID != "" {
				for idx, t := range m.tabs {
					if t.groupID != k.GroupID || t.isConsole || t.cli == nil {
						continue
					}
					// Same guard as the self-detection trigger above: no
					// t.cli.IsRemote() check here either, a member
					// (including the host itself in loopback) remains
					// reconnectable via wake regardless of transport.
					if t.reconnecting || t.serverShutdown {
						break
					}
					if time.Since(t.lastWakeActedAt) >= wakeScanInterval {
						t.lastWakeActedAt = time.Now()
						t.reconnecting = true
						cmd = tea.Batch(cmd, m.reconnectTab(idx))
					}
					break
				}
			}
		case "invite_declined":
			// An invitee pressed Esc on the popup (see declineInvite), the
			// host learns of it here, instead of from a silent timeout
			// (indistinguishable from "hasn't seen the invite yet").
			// Looks up its own host tab by GroupID, exactly
			// like "wake" above.
			if k.GroupID != "" {
				for idx, t := range m.tabs {
					if t.groupID != k.GroupID || t.isConsole || t.cli == nil {
						continue
					}
					declinedKey := client.MemberKeyOf(k.FromIdentityPub)
					if !slices.Contains(t.invitedKeys, declinedKey) {
						break
					}
					if t.departures == nil {
						t.departures = make(map[string]memberState)
					}
					t.departures[declinedKey] = memberDeclined
					m.appendToConsole(fmt.Sprintf(i18n.T("tui.invite_declined_received"), m.memberName(t, declinedKey), t.name), false)
					// If even the last still-pending invitee has now
					// responded (joined or declined), there's no need to
					// wait for the timeout: prompt the host right away
					// instead of leaving it to discover the silent timeout.
					allResponded := true
					for _, inv := range t.invitedKeys {
						if t.departures[inv] != memberDeclined && !t.isOnline(inv) {
							allResponded = false
							break
						}
					}
					if allResponded {
						m.queueGroupNoJoinPrompt(idx)
					}
					break
				}
			}
		case "remote_nuke":
			cmd = m.handleRemoteNuke(k)
		case "remote_nuke_ack":
			cmd = m.handleRemoteNukeAck(k)
		case "root_rotate":
			// Announcement of a root IdentityKey rotation from a contact,
			// see applyRootRotate.
			cmd = m.applyRootRotate(k)
		case "root_rotate_ack":
			cmd = m.applyRootRotateAck(k)
		case "device_sync":
			// Own-device-to-own-device channel (root rotation propagation
			// or remote address-book sync), see applyDeviceSync.
			cmd = m.applyDeviceSync(k)
		case "device_sync_ack":
			cmd = m.applyDeviceSyncAck(k)
		case "contact_tombstone":
			cmd = m.applyContactTombstone(k)
		case "contact_tombstone_ack":
			cmd = m.applyContactTombstoneAck(k)
		case "danger_broadcast":
			cmd = m.handleDangerBroadcast(k)
		case "danger_broadcast_ack":
			cmd = m.handleDangerBroadcastAck(k)
		case "danger_end":
			cmd = m.handleDangerEnd(k)
		case "danger_end_ack":
			cmd = m.handleDangerEndAck(k)
		case "rel_revoke":
			// Announcement of a relationship key revocation, see applyRelRevoke.
			cmd = m.applyRelRevoke(k)
		case "rel_revoke_ack":
			cmd = m.applyRelRevokeAck(k)
		default:
			// A more recent knock from the same sender (same two-member
			// room or same group invite) replaces the old one: avoids two
			// indistinguishable pending invites when the room of the
			// first knock has meanwhile been closed without a reply.
			for i := len(m.pendingKnocks) - 1; i >= 0; i-- {
				pk := m.pendingKnocks[i]
				if (k.GroupID != "" && pk.GroupID == k.GroupID) ||
					(k.GroupID == "" && pk.GroupID == "" && bytes.Equal(pk.FromIdentityPub, k.FromIdentityPub)) {
					m.pendingKnocks = append(m.pendingKnocks[:i], m.pendingKnocks[i+1:]...)
				}
			}
			m.pendingKnocks = append(m.pendingKnocks, pendingKnock{KnockPayload: k, At: time.Now()})
			if k.GroupID != "" {
				// Real group invite: queued modal popup (Enter = Accept,
				// Esc = Ignore), see showNextInviteModal.
				m.showNextInviteModal()
			}
			// k.GroupID == "" here can't happen from any live sender: every
			// knock carrying a RoomSecret (knock/invite, Type=="") always
			// sets GroupID. No action in that case: it just stays queued
			// in m.pendingKnocks above, never shown.
		}
		// As soon as both the IN and OUT circuits are confirmed (not just
		// out, which alone isn't enough), don't wait for the next
		// active_interval tick, up to a minute would otherwise be lost,
		// right in the window when contacts want to know we're back
		// online. "In" gets confirmed here, on receiving any knock at all
		// (including the self-knock triggered by probeSelfKnock).
		if !wasIn && m.torUp != nil && *m.torUp && !m.probing {
			m.probing = true
			cmd = tea.Batch(cmd, m.cmdActiveSilent())
		}
		return m, tea.Batch(cmd, m.waitForKnock())

	case sysLockMsg:
		// Always locks: the identity password always unlocks the
		// interface lock (see cmdLock) regardless of whether a PIN was
		// ever configured.
		return m, tea.Batch(m.cmdLock(), m.waitForSysLock())

	case torLogMsg:
		if m.torTabIdx >= 0 && m.torTabIdx < len(m.tabs) {
			tab := m.tabs[m.torTabIdx]
			tab.lines = append(tab.lines, chatLine{isSystem: true, plain: true, text: msg.line})
			if m.active != m.torTabIdx {
				tab.unread++
			} else {
				m.refreshViewport()
			}
		}
		return m, m.waitForTorLog()

	case debugLogMsg:
		if m.debugMode {
			m.appendToConsole(styleMeta.Render("[dbg] "+msg.line), false)
			m.refreshViewport()
		}
		return m, m.waitForDebugLog()

	case warmupMsg:
		m.appendToDebug(fmt.Sprintf(i18n.T("tui.warmup_debug"), len(m.contacts)))
		return m, tea.Batch(
			m.cmdWarmupCircuits(),
			m.probeTorSelf(),
			tea.Tick(m.warmupInterval, func(time.Time) tea.Msg { return warmupMsg{} }),
		)

	case retryPendingRemoteNukesMsg:
		return m, m.retryPendingRemoteNukes()

	case tickTorProbeMsg:
		return m, tea.Batch(
			m.probeTorSelf(),
			tea.Tick(m.torProbeInterval, func(time.Time) tea.Msg { return tickTorProbeMsg{} }),
		)

	case torProbeResultMsg:
		prev := m.torUp
		ok := msg.ok
		m.torUp = &ok
		if !ok {
			m.torIn = nil // circuits lost: reset inbound too
		}
		if prev == nil || *prev != ok {
			if ok {
				m.appendToTor(styleMeta.Render(i18n.T("tui.tor_out_active")))
			} else {
				m.appendToTor(styleErr.Render(i18n.T("tui.tor_no_circuit")))
			}
			m.refreshViewport()
		}
		// verify inbound: self-knock every time out is active and in is not yet confirmed
		if ok && (m.torIn == nil || !*m.torIn) {
			return m, m.probeSelfKnock()
		}

	case senderKeyRotatedMsg:
		if msg.tabIdx >= 0 && msg.tabIdx < len(m.tabs) {
			m.tabs[msg.tabIdx].keySentTo = nil
		}

	case senderKeySentMsg:
		if msg.tabIdx >= 0 && msg.tabIdx < len(m.tabs) {
			tab := m.tabs[msg.tabIdx]
			if tab.keySentTo == nil {
				tab.keySentTo = make(map[string]bool)
			}
			tab.keySentTo[msg.member] = true
		}

	case rotateSenderKeyMsg:
		m.appendToDebug(i18n.T("tui.rotate_sender_key_debug"))
		interval := m.senderKeyInterval
		return m, tea.Batch(
			m.cmdRotateSenderKeys(),
			tea.Tick(interval, func(time.Time) tea.Msg { return rotateSenderKeyMsg{} }),
		)

	case retryPendingTickMsg:
		return m, tea.Batch(
			m.cmdRetryPending(),
			m.cmdRetryEphemeralRelBootstraps(),
			m.cmdRetrySenderKeyDistribution(),
			tea.Tick(retryPendingInterval, func(time.Time) tea.Msg { return retryPendingTickMsg{} }),
		)

	case pingWatchdogTickMsg:
		if msg.idx >= len(m.tabs) {
			return m, nil
		}
		tab := m.tabs[msg.idx]
		if tab.cli == nil || tab.pingGen != msg.gen {
			return m, nil // tab closed, or superseded by a more recent (re)connection
		}
		idx, gen, cli, ctx := msg.idx, msg.gen, tab.cli, tab.ctx

		// Same round: takes advantage of the connection being known-
		// healthy to notice whether any group member has looked "down"
		// for a while and send it a lightweight wake-up packet, it
		// might be alive but with a stuck connection. Cadence
		// wakeScanInterval, UNCHANGED: the outer tick always runs at
		// this speed, regardless of when the actual ping probe below
		// fires (see pingWatchdogInterval, slower).
		var wakeCmd tea.Cmd
		if tab.groupID != "" {
			for _, mem := range tab.groupMembers {
				mk := memberKey(mem)
				if mk == m.myKey() {
					continue
				}
				if tab.isOnline(mk) || tab.departures[mk] == memberLeft {
					continue // online, or voluntarily left via /grp-exit: not a failure
				}
				wakeCmd = m.sendWakeKnock(tab.groupID, mem)
				break // one down is enough per round: the next tick (wakeScanInterval) covers the others
			}
		}

		// The outer tick always stays at wakeScanInterval, whether a
		// probe was attempted or not, rescheduling doesn't depend on
		// either pingProbeOKMsg or pingProbeFailedMsg (see their comments).
		reschedule := tea.Tick(wakeScanInterval, func(time.Time) tea.Msg {
			return pingWatchdogTickMsg{idx: idx, gen: gen}
		})

		// Round trip recently confirmed by another source (any frame
		// received on the tab, or the probe itself not yet due), an
		// explicit ping would share c.writeFrameMu with any concurrent
		// data writes anyway, risking a false positive. Skips this round's probe.
		if time.Since(tab.lastActivityAt) < pingWatchdogInterval {
			tab.lastPingProbeAt = time.Now()
			tab.pingMisses = 0
			return m, tea.Batch(wakeCmd, reschedule)
		}
		if time.Since(tab.lastPingProbeAt) < pingWatchdogInterval {
			return m, tea.Batch(wakeCmd, reschedule) // not yet due, the next tick will retry
		}
		tab.lastPingProbeAt = time.Now()
		return m, tea.Batch(wakeCmd, reschedule, func() tea.Msg {
			pingCtx, cancel := context.WithTimeout(ctx, pingWatchdogTimeout)
			defer cancel()
			if err := cli.Ping(pingCtx); err != nil {
				return pingProbeFailedMsg{idx: idx, gen: gen, err: err}
			}
			return pingProbeOKMsg{idx: idx, gen: gen}
		})

	case pingProbeOKMsg:
		if msg.idx < len(m.tabs) && m.tabs[msg.idx].pingGen == msg.gen {
			m.tabs[msg.idx].pingMisses = 0
		}

	case pingProbeFailedMsg:
		if msg.idx >= len(m.tabs) {
			return m, nil
		}
		tab := m.tabs[msg.idx]
		if tab.pingGen != msg.gen {
			return m, nil // superseded by a more recent (re)connection
		}
		tab.pingMisses++
		if tab.pingMisses < pingWatchdogMissThreshold {
			// Tolerated: a late pong isn't enough on its own, the next
			// tick (wakeScanInterval) will restart the probe by itself.
			return m, nil
		}
		tab.pingMisses = 0
		idx, gen, err := msg.idx, msg.gen, msg.err
		return m, func() tea.Msg { return roomErrMsg{idx: idx, err: err, gen: gen} }

	case tickActiveMsg:
		if m.probing {
			return m, m.tickActive()
		}
		m.probing = true
		return m, tea.Batch(m.cmdActiveSilent(), m.tickActive())

	case tickInterfaceLockCheckMsg:
		reschedule := tea.Tick(interfaceLockCheckInterval, func(time.Time) tea.Msg { return tickInterfaceLockCheckMsg{} })
		if !m.interfaceLocked && m.interfaceLockTimeout > 0 && time.Since(m.lastActivityAt) >= m.interfaceLockTimeout {
			m.interfaceLocked = true
			m.lockedSinceAt = time.Now()
			m.lockUnlockBuf, m.lockUnlockErr = "", ""
		}
		// "time" nuke trigger: the interface has been LOCKED (not just
		// inactive) for longer than timeNukeTimeout, same immediate,
		// no-confirmation erasure as /nukex.
		if m.interfaceLocked && m.timeNukeTimeout > 0 && !m.lockedSinceAt.IsZero() && time.Since(m.lockedSinceAt) >= m.timeNukeTimeout {
			return m, m.cmdNukeX()
		}
		return m, reschedule

	case probeResultMsg:
		m.probing = false
		// Updates the contact state map (always, regardless of any tab).
		now := time.Now()
		seenNow := make(map[string]time.Time)
		var onlineNames, offlineNames []string
		var justCameOnline []string
		for _, r := range msg.results {
			if len(r.netPub) != ed25519.PublicKeySize {
				continue
			}
			pubKey := string(r.netPub)
			prev := m.contactStates[pubKey]
			online := r.online
			streak := 0
			if online {
				if prev.online != nil && *prev.online {
					streak = prev.onlineStreak + 1
				} else {
					streak = 1
				}
			}
			// seenByPeer/seenByPeerAt never get reset just because online
			// turns false in this cycle, see the comment on the field:
			// losing reachability says nothing about whether they can
			// reach us. The only transition that happens
			// here is nil→false, when the online streak (never an ack/
			// ping received within that window) matures past the threshold.
			seenByPeer := prev.seenByPeer
			seenByPeerAt := prev.seenByPeerAt
			if online && seenByPeer == nil && streak >= m.probeRetryCount {
				no := false
				seenByPeer = &no
			}
			m.contactStates[pubKey] = contactState{online: &online, seenByPeer: seenByPeer, seenByPeerAt: seenByPeerAt, onlineStreak: streak, probedAt: now}
			if online {
				onlineNames = append(onlineNames, r.username)
				seenNow[pubKey] = now
				// only notify if it was offline/never probed before
				if prev.online == nil || !*prev.online {
					justCameOnline = append(justCameOnline, r.username)
				}
				// updates m.contacts: "present" in this probe cycle.
				for i := range m.contacts {
					if bytes.Equal(m.contacts[i].IdentityPub, r.netPub) {
						m.contacts[i].LastSeenAt = now
						// generatedRelKeys: the probe goroutine (outside
						// Update(), no safe access to m.contacts) had to
						// generate our missing relationship keys toward
						// this contact on the fly, see probeContacts.
						// Applied here in memory (immediately unblocks the
						// next /grp-invite) and persisted to disk in the
						// background, same scheme already used by
						// applyRelInit for the same kind of update.
						if gk := r.generatedRelKeys; gk != nil {
							if dev, ok := m.contacts[i].EnsureSoleDevice(); ok {
								dev.RelIdentityPriv = gk.RelIdentityPriv
								dev.RelIdentityMLKEMPriv = gk.RelIdentityMLKEMPriv
								dev.RelIdentityMLDSAPriv = gk.RelIdentityMLDSAPriv
								dev.RelContentPriv = gk.RelContentPriv
								dev.RelContentMLKEMPriv = gk.RelContentMLKEMPriv
								dev.RelContentMLDSAPriv = gk.RelContentMLDSAPriv
							}
							if persistFn := m.updateContactRelKeys; persistFn != nil {
								pub := m.contacts[i].IdentityPub
								go func() { _ = persistFn(pub, *gk) }()
							}
						}
						break
					}
				}
			} else {
				offlineNames = append(offlineNames, r.username)
			}
			m.appendToDebug(fmt.Sprintf(i18n.T("tui.probe_user_debug"), r.netUsername, r.online))
		}
		m.appendToDebug(fmt.Sprintf(i18n.T("tui.probe_complete_debug"), len(onlineNames), len(msg.results)))

		if !msg.silent {
			// explicit /active: summary always on the default tab (msg.tabIdx is already defaultTabIdx).
			appendResult := func(text string) {
				if msg.tabIdx < len(m.tabs) {
					m.tabs[msg.tabIdx].lines = append(m.tabs[msg.tabIdx].lines,
						chatLine{isSystem: true, text: text, timestamp: now.Format(shared.TimeLayout)})
				}
			}
			if len(onlineNames) > 0 {
				appendResult(styleOwnMsg.Render("● online: " + strings.Join(onlineNames, ", ")))
			}
			if len(offlineNames) > 0 {
				text := styleErr.Render(fmt.Sprintf(i18n.T("tui.probe_result_offline"), strings.Join(offlineNames, ", ")))
				appendResult(text)
				// not a real error (routine state, recurs on every probe
				// cycle), no error badge, otherwise it would light up constantly.
				m.appendToConsole(text, false)
			}
			if len(onlineNames) == 0 && len(offlineNames) == 0 {
				appendResult(styleMeta.Render(i18n.T("tui.probe_no_contacts")))
			}
			m.refreshViewport()
		} else {
			// silent timer: no write to Console, the badges in the
			// Contacts tab already show the status; the text note would
			// only generate unwanted badges.
			m.refreshViewport()
		}

		// Refreshes the contacts tab if open.
		for _, t := range m.tabs {
			if t.isContacts {
				m.refreshViewport()
				break
			}
		}
		// batched flush: a single Save() per probe cycle, not one per
		// event (Save() re-derives the key with Argon2id on every call,
		// see FlushContactsActivity).
		pendingCmd = m.flushActivityCmd(seenNow)

		// Sweep of expired queued invites, same principle as the
		// timeout for a file offer never accepted: no infinite wait.
		// Done here (periodic probe cycle, main thread), not by a
		// dedicated ticker, reuses the same inviteTimeout already used
		// for the invite knock.
		if len(m.pendingInvites) > 0 {
			expNow := time.Now()
			remaining := m.pendingInvites[:0]
			for _, pi := range m.pendingInvites {
				if expNow.After(pi.deadline) {
					still := make([]string, 0, len(pi.pending))
					for u := range pi.pending {
						still = append(still, u)
					}
					pendingCmd = tea.Batch(pendingCmd, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.invite_queue_timeout"), pi.label, strings.Join(still, ", ")))))
					continue
				}
				remaining = append(remaining, pi)
			}
			m.pendingInvites = remaining
		}

		// Sweep of INCOMING invites accepted but still queued (see
		// model.pendingJoins/joinKnock), same principle and same
		// timeout as the pendingInvites sweep above.
		if len(m.pendingJoins) > 0 {
			expNow := time.Now()
			remainingJoins := m.pendingJoins[:0]
			for _, pj := range m.pendingJoins {
				if expNow.After(pj.deadline) {
					pendingCmd = tea.Batch(pendingCmd, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.join_queue_timeout"), pj.knock.FromUsername))))
					continue
				}
				remainingJoins = append(remainingJoins, pj)
			}
			m.pendingJoins = remainingJoins
		}

	case contactsSyncedMsg:
		m.adoptSyncedContacts()
		if msg.text == "" {
			return m, nil
		}
		return m, localTab(m.consoleIdx, msg.text)

	case passwordChangedMsg:
		m.keystorePassword = msg.newPwd
		return m, localTab(m.defaultTabIdx(), i18n.T("tui.pwd_updated"))

	case localDisplayMsg:
		if msg.transferID != "" {
			delete(m.outgoingTransfersSending, msg.transferID)
		}
		idx := msg.tabIdx
		if idx < len(m.tabs) && (m.tabs[idx].isContacts || m.tabs[idx].isGroups) {
			idx = m.defaultTabIdx()
		}
		if idx < len(m.tabs) {
			m.tabs[idx].lines = append(m.tabs[idx].lines,
				chatLine{isSystem: true, text: msg.text, timestamp: shared.Now()})
			if msg.isError && idx == m.consoleIdx {
				m.tabs[idx].hasError = true
			}
			m.refreshViewport()
		}
		if msg.consoleInfo {
			m.appendToConsole(msg.text, false)
		}

	case fileAcceptRetryMsg:
		it, ok := m.incomingTransfers[msg.transferID]
		if !ok || it.written > 0 {
			break // completed, rejected, or already incoming, no further send needed
		}
		if time.Now().After(it.acceptRetryDeadline) {
			client.Dbg("file_accept retry: transfer=%s expired without receiving any chunk, giving up", msg.transferID)
			break
		}
		if msg.tabIdx >= len(m.tabs) {
			break
		}
		tab := m.tabs[msg.tabIdx]
		cli, ctx := tab.cli, tab.ctx
		toUserID, transferID, tabIdx := msg.toUserID, msg.transferID, msg.tabIdx
		pendingCmd = tea.Batch(pendingCmd,
			func() tea.Msg {
				err := cli.SendFileAccept(ctx, toUserID, transferID)
				client.Dbg("file_accept: resent (no chunk received) to uid=%s… transfer=%s err=%v", client.ShortUID(toUserID), transferID, err)
				return nil
			},
			m.scheduleFileAcceptRetry(tabIdx, toUserID, transferID),
		)

	case fileOfferMetaDecryptedMsg:
		it := m.incomingTransfers[msg.transferID]
		if it == nil {
			return m, nil // transfer already expired/canceled while decryption was in progress
		}
		if msg.err != nil {
			it.progress.setComplete(true)
			m.dropIncomingTransfer(msg.transferID)
			return m, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_recv_file_meta_decrypt"), m.memberName(m.tabAt(it.tabIdx), it.fromKey), msg.err.Error())))
		}
		it.fileName = msg.fileName
		it.fileSize = msg.fileSize
		it.fileKey = msg.fileKey
		it.chunkCount = msg.chunkCount
		it.progress.mu.Lock()
		it.progress.label = msg.fileName
		it.progress.total = msg.fileSize
		it.progress.mu.Unlock()
		// The dedicated writer only starts now: it needs chunkCount (the
		// total chunk count declared by the sender) to know when the
		// contiguous written frontier covers the entire file, see
		// startIncomingChunkWriter and the "file_offer" case above.
		startIncomingChunkWriter(it.transferID, it.chunkCount, it.chunkCh, it.abortCh, it.chunkResultCh)
		m.pendingFileOffers = append(m.pendingFileOffers, it.transferID)
		m.showNextFileOfferModal()
		return m, waitForIncomingChunkResult(it.chunkResultCh)

	case fileReadyToSaveMsg:
		// Contact card received through the file mechanism (marked by
		// the sentinel prefix on the plaintext), skips the "save to
		// disk" prompt, populates
		// pendingCard as for a direct invite.
		if bytes.HasPrefix(msg.data, []byte(contactCardPrefix)) {
			var card contactCard
			if err := json.Unmarshal(bytes.TrimPrefix(msg.data, []byte(contactCardPrefix)), &card); err == nil && card.Username != "" {
				tabIdx := msg.tabIdx
				if tabIdx < len(m.tabs) {
					tab := m.tabs[tabIdx]
					tab.pendingCard = &card
					tab.pendingCardFrom = m.fileOfferFromKey
					displayCard := card.Username
					if card.LocalName != "" {
						displayCard = card.LocalName + " (" + card.Username + ")"
					}
					notice := styleMeta.Render(fmt.Sprintf(i18n.T("tui.contact_card_notice"), m.memberName(tab, m.fileOfferFromKey), styleOwnMsg.Render(displayCard)))
					tab.lines = append(tab.lines, chatLine{isSystem: true, text: notice, timestamp: shared.Now()})
					if card.OffbandHint != "" {
						hintLine := styleMeta.Render(fmt.Sprintf(i18n.T("tui.contact_card_offband_hint"), card.OffbandHint))
						tab.lines = append(tab.lines, chatLine{isSystem: true, text: hintLine, timestamp: shared.Now()})
					}
					m.tabs[tabIdx] = tab
					m.refreshViewport()
				}
			}
			return m, nil
		}
		dir := startDirForFileBrowser()
		all, _ := listDir(dir) // unlikely error, empty list if it happens anyway
		m.saveFileDir = dir
		m.saveFileEntries = filterDirsOnly(all)
		m.saveFileIdx = 0
		m.saveRenameMode = true
		m.saveFileTabIdx = msg.tabIdx
		m.savePendingData = msg.data
		m.savePendingName = msg.fileName
		return m, nil

	case fileEncryptedMsg:
		if msg.err != nil {
			return m, consoleErrTab(m.consoleIdx, styleErr.Render(msg.err.Error()))
		}
		tabIdx := msg.tabIdx
		if tabIdx >= len(m.tabs) {
			return m, nil // tab closed while encryption was in progress
		}
		tab := m.tabs[tabIdx]
		recipientNames := make([]string, 0, len(msg.recipients))
		for _, k := range msg.recipients {
			recipientNames = append(recipientNames, m.memberName(tab, k))
		}

		progress := &fileTransferProgress{
			label:     msg.fileName,
			direction: "↑",
			peer:      strings.Join(recipientNames, ", "),
			total:     int64(len(msg.ciphertext)),
		}
		ft := &outgoingFileTransfer{
			transferID:  msg.transferID,
			tabIdx:      tabIdx,
			fileName:    msg.fileName,
			ciphertext:  msg.ciphertext,
			envelopes:   msg.envelopes,
			preset:      msg.preset,
			pending:     msg.pending,
			progress:    progress,
			pendingDone: make(chan struct{}),
		}
		if m.outgoingTransfers == nil {
			m.outgoingTransfers = make(map[string]*outgoingFileTransfer)
		}
		m.outgoingTransfers[msg.transferID] = ft
		m.fileProgress.add(msg.transferID, progress)

		m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_offer_sent_console"), msg.fileName, strings.Join(recipientNames, ", "))), false)

		cli := tab.cli
		ctx := tab.ctx
		transferID := msg.transferID
		fileName := msg.fileName
		toUserIDs := msg.toUserIDs
		hash := msg.hash
		announceEnvelopes := msg.announceEnvelopes
		sigTS := msg.sigTS
		consoleIdx := m.consoleIdx
		// Sends the ANNOUNCE (hash+signature), not yet the real offer,
		// that only goes out to each recipient after its
		// file_announce_ack (case below). The 90s timeout covers the
		// entire announce→ack→offer→accept round trip as a single
		// budget, not just the wait for the final acceptance.
		return m, tea.Batch(
			localTab(tabIdx, styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_offer_sent"), fileName, len(msg.recipients)))),
			m.tickFileProgress(),
			tea.Tick(m.fileTransferOfferTimeout, func(time.Time) tea.Msg {
				return fileOfferTimeoutMsg{transferID: transferID}
			}),
			// fileOfferBatchWindow starts HERE (from sending the offer),
			// not from the first accept: it must stay a fixed collection
			// window anchored to the invite itself, not a window that
			// reopens from scratch every time someone replies late,
			// otherwise a group that's slow to respond (no one within
			// the first 10s) would never get to gather into a single
			// multicast front, forcing an individual send to each. If
			// nobody has accepted yet when it expires (case
			// fileOfferBatchWindowMsg below), it simply does nothing: it
			// keeps waiting until fileTransferOfferTimeout (90s), which
			// remains the only fallback deadline for "nobody ever responded".
			tea.Tick(m.fileOfferBatchWindow, func(time.Time) tea.Msg {
				return fileOfferBatchWindowMsg{transferID: transferID}
			}),
			func() tea.Msg {
				if err := cli.SendFileAnnounce(ctx, toUserIDs, transferID, hash, announceEnvelopes, sigTS); err != nil {
					return localDisplayMsg{
						tabIdx:  consoleIdx,
						text:    styleErr.Render(fmt.Sprintf(i18n.T("tui.err_send_file_generic"), err.Error())),
						isError: true,
					}
				}
				return nil
			},
		)

	case fileOfferTimeoutMsg:
		// Since the send starts only after the collection window
		// (fileOfferBatchWindow, not at the very first accept), if
		// ft is still here after the offer's general timeout it may be
		// that someone already accepted but the (shorter, still running)
		// collection window hasn't expired yet, this only happens with
		// a fileOfferBatchWindow configured close to or beyond
		// fileTransferOfferTimeout, which should stay well below it. In
		// that case it proceeds anyway with whoever already accepted,
		// instead of canceling a send that's actually about to start.
		ft := m.outgoingTransfers[msg.transferID]
		if ft == nil {
			return m, nil // already started (accepted) or already canceled (all declined) in the meantime
		}
		if len(ft.accepted) > 0 {
			delete(m.outgoingTransfers, msg.transferID)
			if m.outgoingTransfersSending == nil {
				m.outgoingTransfersSending = make(map[string]*outgoingFileTransfer)
			}
			m.outgoingTransfersSending[msg.transferID] = ft
			return m, m.startSendingChunks(ft)
		}
		timedOut := make([]string, 0, len(ft.pending))
		for u := range ft.pending {
			timedOut = append(timedOut, u)
		}
		sort.Strings(timedOut)
		delete(m.outgoingTransfers, msg.transferID)
		var cmds []tea.Cmd
		if len(timedOut) > 0 {
			cmds = append(cmds, localTab(ft.tabIdx, styleMeta.Render(fmt.Sprintf(
				i18n.T("tui.send_file_offer_timeout"), strings.Join(timedOut, ", "), ft.fileName))))
		}
		if ft.progress != nil {
			ft.progress.setComplete(true)
		}
		cmds = append(cmds, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.send_file_none_accepted_timeout"), ft.fileName))))
		return m, tea.Batch(cmds...)

	case fileOfferBatchWindowMsg:
		ft := m.outgoingTransfers[msg.transferID]
		if ft == nil {
			return m, nil // send already started or offer already canceled in the meantime
		}
		if len(ft.accepted) == 0 {
			// Nobody has accepted yet within this fixed window, this
			// isn't "nobody wants the file" (that's only the general 90s
			// deadline, case fileOfferTimeoutMsg): it simply keeps waiting,
			// without attempting a send to zero recipients. If EVERYONE
			// responds before the 90s, the len(ft.pending)==0 branch in
			// the "file_accept" case above starts the send right away.
			return m, nil
		}
		client.Dbg("file_accept: transfer=%s batch window elapsed, sending to %d recipients", msg.transferID, len(ft.accepted))
		delete(m.outgoingTransfers, msg.transferID)
		if m.outgoingTransfersSending == nil {
			m.outgoingTransfersSending = make(map[string]*outgoingFileTransfer)
		}
		m.outgoingTransfersSending[msg.transferID] = ft
		return m, m.startSendingChunks(ft)

	case tickFileProgressMsg:
		if m.fileProgress.hasActive() {
			return m, m.tickFileProgress()
		}
		return m, nil

	case contactAddedMsg:
		// updates m.contacts in the active model (the goroutine can't do it directly)
		if len(msg.contact.IdentityPub) == ed25519.PublicKeySize {
			updated := false
			for i, c := range m.contacts {
				if bytes.Equal(c.IdentityPub, msg.contact.IdentityPub) {
					client.Dbg("contactAddedMsg: %s ALREADY present, OVERWRITING (oldDevices=%d %v → newDevices=%d %v)", msg.contact.Username, len(c.Devices), deviceKeyList(c.Devices), len(msg.contact.Devices), deviceKeyList(msg.contact.Devices))
					m.contacts[i] = msg.contact
					updated = true
					break
				}
			}
			if !updated {
				client.Dbg("contactAddedMsg: %s NEW, append (devices=%d %v)", msg.contact.Username, len(msg.contact.Devices), deviceKeyList(msg.contact.Devices))
				m.contacts = append(m.contacts, msg.contact)
			}
		}
		if msg.tabIdx < len(m.tabs) {
			tab := m.tabs[msg.tabIdx]
			m.appendToConsole(msg.displayText, false)
			// isTabPeer: the just-added contact is really this room's
			// peer (not a third party introduced via a contact card),
			// only in that case does it make sense to update the room's
			// safety bar.
			if msg.isTabPeer && len(msg.identityPub) == 32 && len(m.myIdentityPub) == 32 {
				tab.peerIdentityPub = msg.identityPub
				tab.safetyCode = shared.SafetyCode(m.myIdentityPub, msg.identityPub)
				tab.peerIsContact = true
				m.refreshViewport()
			}
			m.refreshViewport()
		}
		// Relationship key exchange, once per relationship, right after
		// adding the contact (not on every room invite). Fire-and-
		// forget: if the contact isn't reachable yet, the next probe
		// cycle (probeContacts) retries it until PeerRelIdentityPub is
		// populated. At this point the contact always has exactly one
		// device (the placeholder just created with our keys), never a
		// conflict: SoleDevice() is correct here, unlike anywhere that
		// reasons about an already-existing contact.
		if dev, ok := msg.contact.SoleDevice(); ok {
			return m, m.sendRelInitCmd(msg.contact, dev, "rel_init")
		}
		return m, nil

	case rootRotationAdoptedMsg:
		// Refreshes the public keys/address kept in memory, otherwise
		// stale for the process's entire lifetime (no other point in the
		// code reassigns them after startup). Rooms already open before
		// this moment stay on the old identity until reconnected, the
		// same limitation already known for every other rotation in this project.
		if len(msg.newIdentityPub) == ed25519.PublicKeySize {
			m.myIdentityPub = msg.newIdentityPub
		}
		if len(msg.newMLKEMPub) > 0 {
			m.myMLKEMPub = msg.newMLKEMPub
		}
		if len(msg.newMLDSAPub) > 0 {
			m.myMLDSAPub = msg.newMLDSAPub
		}
		if msg.newAddr != "" {
			m.myAddr = msg.newAddr
		}
		key := msg.consoleKey
		if key == "" {
			key = "tui.device_sync_rotation_adopted"
		}
		return m, localTab(m.consoleIdx, styleMeta.Render(i18n.T(key)))

	case relRotationStartedMsg:
		for i := range m.contacts {
			if !bytes.Equal(m.contacts[i].IdentityPub, msg.contactPub) {
				continue
			}
			c := &m.contacts[i]
			knockType := "rel_identity_rotate"
			if msg.which == "content" {
				knockType = "rel_content_rotate"
			}
			// Fan-out: a new, independent key for EVERY device the
			// rotation was started for, an independent rel_*_rotate knock
			// for each one, never a single, arbitrarily-chosen device.
			var cmds []tea.Cmd
			for devKeyStr, newKey := range msg.newKeys {
				dev, ok := c.Devices[devKeyStr]
				if !ok || dev == nil {
					continue
				}
				if msg.which == "identity" {
					dev.IdentityKeyPending = true
					dev.RelIdentityPriv = newKey.Priv
					dev.RelIdentityMLKEMPriv = newKey.MLKEMSeed
					dev.RelIdentityMLDSAPriv = newKey.MLDSASeed
					// No explicit refresh needed here: the new key is
					// already in keystore.Contact (ks.StartRelIdentityRotationByPub
					// wrote it BEFORE dispatching relRotationStartedMsg,
					// see cmdStartRelRotation), any memberSecret already
					// registered for a room open with this contact
					// resolves it on its own at the next handshake
					// (RoomRegistry resolver), never a cached copy to
					// keep manually in sync.
				} else {
					dev.ContentKeyPending = true
					dev.RelContentPriv = newKey.Priv
					dev.RelContentMLKEMPriv = newKey.MLKEMSeed
					dev.RelContentMLDSAPriv = newKey.MLDSASeed
				}

				newPub, newMLKEM, newMLDSA, err := shared.RelSigningKeyPublicParts(newKey)
				if err != nil {
					continue
				}
				// certifyingPriv/certifyingMLDSASeed: the stable SIBLING
				// key (never the same key that was just rotated).
				var certifyingPriv ed25519.PrivateKey
				var certifyingMLDSASeed []byte
				if msg.which == "identity" {
					certifyingPriv = ed25519.PrivateKey(dev.RelContentPriv)
					certifyingMLDSASeed = dev.RelContentMLDSAPriv
				} else {
					certifyingPriv = ed25519.PrivateKey(dev.RelIdentityPriv)
					certifyingMLDSASeed = dev.RelIdentityMLDSAPriv
				}
				if len(certifyingPriv) != ed25519.PrivateKeySize {
					continue // sibling not yet stable for this device, shouldn't happen for a relationship that already completed rel_init
				}
				ts := shared.NowTS()
				payload := shared.RelRotatePayload{
					NewPub:      newPub,
					NewMLKEMPub: newMLKEM,
					NewMLDSAPub: newMLDSA,
					Sig:         shared.SignRelKeyRotation(certifyingPriv, newPub, m.myUsername, ts),
					SigMLDSA:    shared.SignRelKeyRotationMLDSA(certifyingMLDSASeed, newPub, m.myUsername, ts),
					Ts:          ts,
					DevicePub:   m.myDevicePub,
				}
				// First attempt right away (fire-and-forget, like
				// rel_init); if the device isn't reachable now,
				// probeContacts retries it every cycle as long as
				// IdentityKeyPending/ContentKeyPending stays true.
				cmds = append(cmds, m.sendRelRotateCmd(*c, dev, payload, knockType))
			}
			if len(cmds) > 0 {
				m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.rel_rotation_started"), msg.which, c.NameWithUsername())), false)
			}
			return m, tea.Batch(cmds...)
		}
		return m, nil

	case qrDecodedMsg:
		return m, m.handleQRDecoded(msg.uri)

	case qrFilesDecodedMsg:
		if msg.err != nil {
			return m, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_qr_decode_failed"), msg.err.Error())))
		}
		var cmds []tea.Cmd
		for _, text := range msg.texts {
			if cmd := m.handleQRDecoded(text); cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		// An earlier (non-final) handleQRDecoded call in this same loop
		// may have set qrChooseMode=true, meant for the single-scan
		// flow, where that WAS the last thing known at the time. Here
		// every selected file has now been fed in, so the only thing
		// that still matters is whether the whole set is complete:
		// qrMultiTotal==0 means it is (either reassembled just now, or
		// every text was already a complete single-frame URI), force
		// qrChooseMode back off in that case so no stale re-prompt
		// follows a successful read. Left untouched (true) when a
		// multi-part session is still genuinely incomplete.
		if m.qrMultiTotal == 0 {
			m.qrChooseMode = false
		}
		return m, tea.Batch(cmds...)

	case qrShowTickMsg:
		if !m.qrShowActive || msg.gen != m.qrShowGen || m.qrShowSender == nil {
			return m, nil
		}
		m.qrShowNextFrame()
		return m, m.qrShowTick(m.qrShowGen)

	case qrCameraFrameMsg:
		if !m.qrCameraPreviewMode {
			return m, nil // canceled in the meantime (Esc), late frame, ignored
		}
		m.qrCameraPreviewContent = msg.frame
		return m, m.waitForQRCameraFrame()

	case qrCameraDoneMsg:
		if !m.qrCameraPreviewMode {
			return m, nil // already canceled with Esc, late final message, ignored
		}
		m.qrCameraPreviewMode = false
		m.qrCameraPreviewContent = ""
		m.qrCameraCancel = nil
		m.qrCameraPreviewCh = nil
		m.qrCameraResultCh = nil
		inner := msg.msg
		return m, func() tea.Msg { return inner }

	case sendErrMsg:
		m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.send_error"), msg.err.Error())), true)

	case replySentMsg:
		if msg.tabIdx >= 0 && msg.tabIdx < len(m.tabs) {
			m.tabs[msg.tabIdx].pendingReplyTo = 0
		}
	}

	m.ta, taCmd = m.ta.Update(msg)
	// updates palette visibility after every textarea change
	if items := m.filteredCommands(); len(items) > 0 {
		m.showPalette = true
		if m.paletteIdx >= len(items) {
			m.paletteIdx = len(items) - 1
		}
	} else {
		m.showPalette = false
		m.paletteIdx = 0
	}
	m.vp, vpCmd = m.vp.Update(msg)
	return m, tea.Batch(taCmd, vpCmd, pendingCmd)
}

func (m model) View() string {
	if !m.ready {
		return i18n.T("tui.view_connecting") + "\n"
	}
	if m.quitting {
		return i18n.T("tui.view_goodbye") + "\n"
	}
	if m.interfaceLocked {
		return m.renderInterfaceLock()
	}
	tabBar := m.renderTabBar()
	sep := styleMeta.Render(strings.Repeat("─", m.vp.Width))

	// user bar for group tabs; safety bar for two-member rooms
	var header string
	if m.active < len(m.tabs) {
		tab := m.tabs[m.active]
		barSep := styleMeta.Render(strings.Repeat("─", m.vp.Width))
		if tab.isTor {
			outDot := styleErr.Render("●")
			if m.torUp != nil && *m.torUp {
				outDot = styleOwnMsg.Render("●")
			}
			inDot := styleErr.Render("●")
			if m.torIn != nil && *m.torIn {
				inDot = styleOwnMsg.Render("●")
			}
			// tab.name, not a static label: tab is already the network tab
			// (isTor==true) and its name is already the correct one
			// ("Tor" or "I2P", netTabLabel/p.NetworkName at construction time).
			torStr := styleMeta.Render(tab.name+":") + " " + outDot + " out  " + inDot + " in"
			var hsStr string
			if m.myAddr != "" {
				// Label always neutral, like "Tor:" above, only the
				// status symbol changes color, not the whole string.
				label := styleMeta.Render(i18n.T("tui.hs_label"))
				switch {
				case m.hsUp == nil || m.torUp == nil:
					hsStr = label + " " + styleMeta.Render("◌ …")
				case *m.hsUp && *m.torUp:
					hsStr = label + " " + styleOwnMsg.Render("●")
				default:
					hsStr = label + " " + styleErr.Render("✗")
				}
				torStr = torStr + "   " + hsStr
			}
			header = torStr + "\n"
			header += barSep + "\n"
		} else if tab.groupID != "" && len(tab.groupMembers) > 0 {
			userBar := m.renderGroupBar(tab, m.vp.Width)
			header = userBar + "\n" + barSep + "\n"
		}
	}

	if m.backupMode && len(m.backupWords) == 24 {
		var lines [6]string
		for i, w := range m.backupWords {
			lines[i/4] += fmt.Sprintf("%02d. %-12s", i+1, w)
		}
		popupContent := strings.Join([]string{
			i18n.T("tui.backup_popup_title"),
			"",
			i18n.T("tui.backup_popup_hint1"),
			i18n.T("tui.backup_popup_hint2"),
			"",
			lines[0],
			lines[1],
			lines[2],
			lines[3],
			lines[4],
			lines[5],
			"",
			i18n.T("tui.backup_popup_close_hint"),
		}, "\n")
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.inviteModalMode && m.inviteModalKnock != nil {
		k := m.inviteModalKnock
		others := make([]string, 0, len(k.Members))
		for _, mi := range k.Members {
			if !bytes.Equal(mi.IdentityPub, m.myIdentityPub) && !bytes.Equal(mi.IdentityPub, k.FromIdentityPub) {
				others = append(others, mi.Username)
			}
		}
		content := fmt.Sprintf(i18n.T("tui.knock_group_invite"), k.FromUsername, k.GroupID)
		if len(others) > 0 {
			content += fmt.Sprintf(i18n.T("tui.knock_group_invite_with_others"), strings.Join(others, ", "))
		}
		if len(k.FromIdentityPub) == 32 && m.resolveContactByPub(k.FromIdentityPub) == nil {
			uri := "nu://" + k.FromUsername + "/" + base64.StdEncoding.EncodeToString(k.FromIdentityPub)
			content += "\n" + fmt.Sprintf(i18n.T("tui.knock_key_line"), uri)
			content += "\n" + fmt.Sprintf(i18n.T("tui.knock_verify_hint"), k.FromUsername)
		}
		content += "\n\n" + i18n.T("tui.invite_modal_hint")
		popup := m.renderBoxPopup(content)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.textPopupMode {
		hint := i18n.T("tui.backup_popup_close_hint")
		if m.textPopupCopyURI != "" {
			hint = i18n.T("tui.info_copy_uri_hint")
		}
		popupContent := m.textPopupContent + "\n\n" + hint
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.helpMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderHelp()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.contactPickerMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderContactPicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.sendFileMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderBoxPopup(m.renderSendFileBrowser())
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.sendFileRecipientsMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderFileRecipientsPicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.invitePickerMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderInvitePicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.pingPickerMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderPingPicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.remoteNukePickerMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderRemoteNukePicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.remoteNukeConfirmMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		prompt := i18n.T("tui.remote_nuke_confirm_prompt")
		if devices := m.knownDevicesNow(); m.remoteNukeConfirmIdx < len(devices) {
			label := devices[m.remoteNukeConfirmIdx].Label
			if label == "" {
				label = hex.EncodeToString(devices[m.remoteNukeConfirmIdx].DeviceID)
			}
			prompt = fmt.Sprintf(i18n.T("tui.remote_nuke_confirm_prompt_target"), label)
		}
		popup := m.renderBoxPopup(styleErr.Render(prompt))
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.clearAllConfirmMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderBoxPopup(styleErr.Render(i18n.T("tui.clear_all_confirm_prompt")))
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.msgAcksPickerMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderMsgAcksPicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.msgAcksDetailMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderMsgAcksDetail()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.showQRFormatMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderShowQRFormatPicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.sendFilePresetMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderFilePresetPicker()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.fileOfferMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderFileOfferPopup()
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.saveRenameMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderBoxPopup(m.renderSaveRenamePopup())
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.saveDirMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderBoxPopup(m.renderSaveDirBrowser())
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.quitMode {
		prompt := i18n.T("tui.quit_prompt")
		return fmt.Sprintf("%s\n%s%s\n%s\n%s", tabBar, header, m.vp.View(), sep, styleBorder.Render(prompt))
	}
	if m.verifySafetyConfirmMode {
		prompt := fmt.Sprintf(i18n.T("tui.verify_safety_confirm_prompt"), m.verifySafetyConfirmTarget)
		popupContent := m.verifySafetyPopupContent + "\n\n" + prompt
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.pwdMode != 0 {
		stars := strings.Repeat("*", len([]rune(m.pwdBuf)))
		lockNewPrompt, lockConfirmPrompt := i18n.T("tui.lock_prompt_new_pin"), i18n.T("tui.lock_prompt_confirm_pin")
		prompts := []string{"",
			i18n.T("tui.pwd_prompt_current"),
			i18n.T("wizard.password_prompt"),
			i18n.T("common.password_confirm_prompt"),
			i18n.T("tui.pwd_prompt_keystore"),
			i18n.T("tui.pwd_prompt_duress_new"),
			i18n.T("tui.pwd_prompt_duress_confirm"),
			lockNewPrompt,
			lockConfirmPrompt,
			i18n.T("tui.lock_prompt_duress_marker"),
			i18n.T("tui.lock_prompt_duress_position"),
		}
		prompt := prompts[m.pwdMode] + stars + "▌"
		// Strength indicator only while typing a NEW password (not the
		// current one nor a confirmation), purely informational, blocks
		// nothing: the real defense against offline brute-force remains Argon2id.
		if (m.pwdMode == 2 || m.pwdMode == 5) && m.pwdBuf != "" {
			prompt += "  [" + styleMeta.Render(shared.PasswordStrength(m.pwdBuf).Label()) + "]"
		}
		return fmt.Sprintf("%s\n%s%s\n%s\n%s", tabBar, header, m.vp.View(), sep, styleBorder.Render(prompt))
	}
	if m.addContactConfirmMode {
		pqcDisplay := i18n.T("tui.none_label")
		switch {
		case len(m.pendingContact.mlkemPub) > 0 && len(m.pendingContact.mldsaPub) > 0:
			pqcDisplay = "ML-KEM-768 + ML-DSA-65"
		case len(m.pendingContact.mlkemPub) > 0:
			pqcDisplay = "ML-KEM-768"
		case len(m.pendingContact.mldsaPub) > 0:
			pqcDisplay = "ML-DSA-65"
		}
		body := fmt.Sprintf(i18n.T("tui.add_contact_confirm_body"),
			m.pendingContact.username,
			base64.StdEncoding.EncodeToString(m.pendingContact.pubBytes),
			pqcDisplay)
		popupContent := body + "\n\n" + i18n.T("tui.add_contact_confirm_prompt")
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.groupNoJoinConfirmMode {
		name := ""
		if m.groupNoJoinConfirmTabIdx >= 0 && m.groupNoJoinConfirmTabIdx < len(m.tabs) {
			name = m.tabs[m.groupNoJoinConfirmTabIdx].name
		}
		popupContent := fmt.Sprintf(i18n.T("tui.group_no_join_confirm_body"), name)
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.addContactMode {
		prompt := i18n.T("tui.add_contact_prompt", m.pendingContact.username) + m.addContactBuf + "▌"
		return fmt.Sprintf("%s\n%s%s\n%s\n%s", tabBar, header, m.vp.View(), sep, styleBorder.Render(prompt))
	}
	if m.qrChooseMode {
		popupContent := i18n.T("tui.read_qr_choose_prompt") +
			"\n\n" + styleMeta.Render(i18n.T("tui.esc_cancel_hint"))
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.qrCameraPreviewMode {
		content := m.qrCameraPreviewContent
		if content == "" {
			content = styleMeta.Render(i18n.T("tui.read_qr_camera_starting"))
		}
		popupContent := content + "\n\n" + styleMeta.Render(i18n.T("tui.esc_cancel_hint"))
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.qrShowActive {
		content := m.qrShowFrame
		if content == "" {
			content = styleMeta.Render(i18n.T("tui.read_qr_camera_starting"))
		}
		popupContent := m.qrShowInfo + "\n\n" + content + "\n\n" + styleMeta.Render(i18n.T("tui.msg_acks_detail_hint"))
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.qrFileMode {
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		popup := m.renderBoxPopup(m.renderQRFileBrowser())
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.sendContactHintMode {
		popupContent := fmt.Sprintf(i18n.T("tui.send_contact_hint_prompt"), m.sendContactHintUsername) +
			"\n\n" + m.sendContactHintBuf + "▌" +
			"\n\n" + styleMeta.Render(i18n.T("tui.esc_cancel_hint"))
		popup := m.renderBoxPopup(popupContent)
		w, h := m.lastTermW, m.lastTermH
		if w == 0 {
			w = 80
		}
		if h == 0 {
			h = 24
		}
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
	}
	if m.editContactMode {
		current := ""
		for _, c := range m.contacts {
			if bytes.Equal(c.IdentityPub, m.pendingEditContactPub) {
				current = c.LocalName
				break
			}
		}
		var hint string
		if current != "" {
			hint = current
		} else {
			hint = styleMeta.Render(i18n.T("tui.none_label"))
		}
		prompt := i18n.T("tui.edit_contact_prompt", m.pendingEditUsername, hint) + m.editContactBuf + "▌"
		return fmt.Sprintf("%s\n%s%s\n%s\n%s", tabBar, header, m.vp.View(), sep, styleBorder.Render(prompt))
	}
	if m.showPalette {
		return fmt.Sprintf("%s\n%s%s\n%s\n%s\n%s",
			tabBar, header, m.vp.View(), sep, m.renderPalette(), styleBorder.Render(m.ta.View()))
	}
	if m.active < len(m.tabs) && m.tabs[m.active].isFiles {
		// No text-input area here: the Files tab is view-only, not a
		// chat, no box, no border, no separator. Must go AFTER all the
		// popup-mode checks above: otherwise a popup open while this tab
		// is active (e.g. the interface lock) would never get drawn.
		return fmt.Sprintf("%s\n%s", tabBar, m.renderFileProgressView())
	}
	return fmt.Sprintf("%s\n%s%s\n%s\n%s%s", tabBar, header, m.vp.View(), sep, m.renderReplyIndicator(), styleBorder.Render(m.ta.View()))
}

// renderReplyIndicator shows the explicit reply reference set (/msg N)
// for the next send in the active tab, "" if none (no line added).
// Persistent until consumed (replySentMsg) or overwritten by a new
// /msg: unlike a Console message, which would scroll away, the user
// must see it for as long as it stays active.
func (m *model) renderReplyIndicator() string {
	if m.active >= len(m.tabs) {
		return ""
	}
	tab := m.tabs[m.active]
	if tab.pendingReplyTo == 0 {
		return ""
	}
	for _, l := range tab.lines {
		if l.gseq == tab.pendingReplyTo {
			preview := l.username + ": " + truncateReplyPreview(l.text)
			return styleMeta.Render(fmt.Sprintf(i18n.T("tui.reply_target_indicator"), tab.pendingReplyTo, preview)) + "\n"
		}
	}
	return styleMeta.Render(fmt.Sprintf(i18n.T("tui.reply_target_indicator_bare"), tab.pendingReplyTo)) + "\n"
}

// torStatusDot returns a colored dot based on Tor status:
// ● green = out+in active, ● yellow = out only, ● red = no circuit.
func (m model) torStatusDot() string {
	styleWarn := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	switch {
	case m.torUp == nil || !*m.torUp:
		return styleErr.Render("●")
	case m.torIn == nil || !*m.torIn:
		return styleWarn.Render("●")
	default:
		return styleOwnMsg.Render("●")
	}
}

// renderTabLabel returns the styled label for the i-th tab, kept
// separate from renderTabBar because the latter needs to measure each
// one's width before deciding which fit in the visible window.
func (m model) renderTabLabel(i int, styleWarnDot lipgloss.Style) string {
	tab := m.tabs[i]
	showBadge := tab.unread > 0 && !tab.isConsole && !tab.isTor
	if tab.isTor {
		dot := m.torStatusDot()
		if i == m.active {
			return dot + styleActiveTab.Render(tab.name)
		}
		return dot + styleTab.Render(tab.name)
	}
	if tab.isConsole && tab.hasError {
		errDot := styleErr.Render("●")
		if i == m.active {
			return errDot + styleActiveTab.Render(tab.name)
		}
		return errDot + styleTab.Render(tab.name)
	}
	if tab.reconnecting {
		// Unlike every other branch of this function, this one must
		// respect i == m.active instead of always using styleTab (non-
		// active): otherwise the active tab never highlights while
		// reconnecting is stuck true indefinitely (e.g. a handshake that
		// always fails for the same deterministic reason, not a
		// transient network hiccup). reconnecting is only set for a real
		// room (never Console/Tor, see the setter), so
		// styleTabChatActive is always the correct choice for the active case.
		errDot := styleErr.Render("●")
		if i == m.active {
			return errDot + styleTabChatActive.Render(tab.name)
		}
		return errDot + styleTab.Render(tab.name)
	}
	unreadDot := ""
	if showBadge {
		unreadDot = styleWarnDot.Render("●")
	}
	isChatTab := !tab.isConsole && !tab.isTor && !tab.isContacts && !tab.isGroups && !tab.isFiles
	if i == m.active {
		if isChatTab {
			return unreadDot + styleTabChatActive.Render(tab.name)
		}
		return unreadDot + styleActiveTab.Render(tab.name)
	}
	if isChatTab {
		return unreadDot + styleTabChat.Render(tab.name)
	}
	return styleTab.Render(tab.name)
}

// renderTabBar shows the open tabs in a scrolling window centered on the
// active tab, instead of a single ever-growing line: on a narrow
// terminal (e.g. Android/Termux, far fewer columns than a desktop) with
// more than a handful of tabs the full line never fits, without a
// window the terminal breaks it mid-ANSI-sequence on its own, and the
// active tab can end up off-screen with no clue where it is. ‹/›
// markers at the edges indicate tabs hidden beyond the cutoff, changing
// on every move along with the window.
//
// identityPrefix: a "fake tab" carrying the active identity
// ("<username>:"), ALWAYS the first element of the line, never inside
// labels/widths, unlike real tabs it never scrolls out of view and is
// never navigable (no index in m.tabs corresponds to it). Rationale:
// the terminal window title ("Neutrino - <user>", set in Init() via
// tea.SetWindowTitle) depends on the terminal/multiplexer to actually
// be shown, on some setups it never appears. This prefix is text
// inside the TUI's own content, so it's always visible regardless of
// the terminal. tea.SetWindowTitle is still set regardless: harmless,
// a bonus for terminals that do show it.
// m.myUsername is guaranteed non-empty (RunTUI always receives
// TUIParams.Username = ks.Username, a mandatory field of the wizard):
// no guard here, a keystore with an empty username can't exist.
func (m model) renderTabBar() string {
	styleWarnDot := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	n := len(m.tabs)
	if n == 0 {
		return ""
	}
	identityPrefix := styleTab.Render(m.myUsername + ":")
	labels := make([]string, n)
	widths := make([]int, n)
	total := 0
	for i := range m.tabs {
		labels[i] = m.renderTabLabel(i, styleWarnDot)
		widths[i] = lipgloss.Width(labels[i])
		total += widths[i]
	}

	avail := m.vp.Width
	if avail <= 0 {
		avail = m.lastTermW
	}
	if avail <= 0 {
		avail = 80
	}
	avail -= lipgloss.Width(identityPrefix)
	if avail < 0 {
		avail = 0
	}

	if total <= avail {
		var sb strings.Builder
		sb.WriteString(identityPrefix)
		for _, l := range labels {
			sb.WriteString(l)
		}
		return sb.String()
	}

	// Reserve for ‹ and ›: even though in the end only one side may need
	// it, always reserving both avoids having to recompute the window a
	// second time after discovering which side is actually hidden.
	budget := avail - 2
	left, right := m.active, m.active
	width := widths[m.active]
	for {
		grew := false
		if right < n-1 && width+widths[right+1] <= budget {
			right++
			width += widths[right]
			grew = true
		}
		if left > 0 && width+widths[left-1] <= budget {
			left--
			width += widths[left]
			grew = true
		}
		if !grew {
			break
		}
	}

	var sb strings.Builder
	sb.WriteString(identityPrefix)
	if left > 0 {
		sb.WriteString(styleMeta.Render("‹"))
	}
	for i := left; i <= right; i++ {
		sb.WriteString(labels[i])
	}
	if right < n-1 {
		sb.WriteString(styleMeta.Render("›"))
	}
	return sb.String()
}

// ── input handler ─────────────────────────────────────────────────────────────

// splitCmd separates the first word of a text input (the command, if
// any, e.g. "/grp-ping") from the rest of the line, already trimmed of
// spaces. hasArg indicates whether there was a space after the first
// word, distinguishing "/x" from "/x ...", needed because some
// commands behave differently depending on whether an argument was given.
func splitCmd(text string) (head, arg string, hasArg bool) {
	head, rest, hasArg := strings.Cut(text, " ")
	return head, strings.TrimSpace(rest), hasArg
}

// openPicker opens the contact/group picker for cmd, with typed already
// set as the initial filter, used both when a command arrives with no
// argument, and when the typed argument doesn't resolve to a valid
// recipient (instead of a flat error: the user finds it already
// filtered in the list, ready to pick the right one). Typing the
// parameter bypasses the picker ONLY when it actually resolves to
// something, that's the one case where the picker doesn't appear.
func (m *model) openPicker(cmd client.CmdID, typed string) tea.Cmd {
	m.contactPickerMode = true
	m.contactPickerCmd = cmd
	m.contactPickerFilter = typed
	m.contactPickerIdx = 0
	return nil
}

// errCommandNoArgs reports in Console that command id takes no
// arguments, a mistyped command is never sent to the room as a message.
func (m *model) errCommandNoArgs(id client.CmdID) tea.Cmd {
	return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_command_no_args"), i18n.CommandName(id))))
}

func (m *model) handleInput(text string) tea.Cmd {
	head, arg, hasArg := splitCmd(text)
	id, ok := i18n.ResolveCommand(head)
	if !ok {
		if strings.HasPrefix(head, "/") {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_unknown_command"), head)))
		}
		return m.sendMessage(text)
	}

	switch id {
	case client.CmdHelp:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		m.helpMode = true
		m.helpScroll = 0
		return nil

	case client.CmdDebug:
		return m.cmdDebug(arg)

	case client.CmdCompact:
		return m.cmdCompact(arg)

	case client.CmdConsoleExport:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdConsoleExport()

	case client.CmdBackup:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdBackup()

	case client.CmdShowQR:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		m.showQRFormatIdx = 0
		m.showQRFormatMode = true
		return nil

	case client.CmdReadQR:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdReadQR()

	case client.CmdInfoApp:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdInfoApp()

	case client.CmdNukex:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdNukeX()

	case client.CmdClearAll:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		m.clearAllConfirmMode = true
		return nil

	case client.CmdPasswd:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdPasswd()

	case client.CmdDuress:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdDuress()

	case client.CmdLock:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdLock()

	case client.CmdLockPIN:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdLockPIN()

	case client.CmdLockTimeout:
		return m.cmdLockTimeout(arg)

	case client.CmdNukeTimeout:
		return m.cmdNukeTimeout(arg)

	case client.CmdQuit:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdQuit()

	case client.CmdClose:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdExit()

	case client.CmdReconnect:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdReconnect()

	case client.CmdPQCSign:
		return m.cmdPQCSign(arg)

	case client.CmdHealth:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdHealth()

	case client.CmdActive:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		if m.probing {
			return localTab(m.active, styleMeta.Render(i18n.T("tui.probe_in_progress")))
		}
		m.probing = true
		return m.cmdActive()

	case client.CmdInfo:
		return m.cmdInfo(arg)

	case client.CmdRoomInfo:
		return m.cmdRoomInfo()

	case client.CmdInvite:
		if !hasArg {
			candidates := make([]string, 0, len(m.contacts))
			for _, c := range m.contacts {
				candidates = append(candidates, contactPickerKey(c))
			}
			m.inviteCandidates = candidates
			m.inviteSelected = make(map[string]bool, len(candidates))
			m.inviteIdx = 0
			m.inviteFilter = ""
			m.invitePickerMode = true
			return nil
		}
		return m.cmdInvite(arg)

	case client.CmdReinvite:
		if !hasArg {
			tab := m.tabs[m.active]
			if tab.groupID == "" || tab.cli == nil || tab.cli.IsRemote() {
				return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_reinvite_host_only")))
			}
			hasOffline := false
			for _, mem := range tab.groupMembers {
				if mk := memberKey(mem); mk != m.myKey() && !tab.isOnline(mk) {
					hasOffline = true
					break
				}
			}
			if !hasOffline {
				return localTab(m.active, styleMeta.Render(i18n.T("tui.all_members_connected")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdReinvite
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdReinvite(arg)

	case client.CmdAddMember:
		if !hasArg {
			tab := m.tabs[m.active]
			if tab.groupID == "" || tab.cli == nil || tab.cli.IsRemote() {
				return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_add_member_host_only")))
			}
			if tab.cli.RatchetDH() {
				return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_add_member_ratchet_dh")))
			}
			memberSet := make(map[string]bool, len(tab.groupMembers))
			for _, mb := range tab.groupMembers {
				memberSet[memberKey(mb)] = true
			}
			hasCandidate := false
			for _, c := range m.contacts {
				if !memberSet[client.MemberKeyOf(c.IdentityPub)] {
					hasCandidate = true
					break
				}
			}
			if !hasCandidate {
				return localTab(m.active, styleMeta.Render(i18n.T("tui.no_contacts_to_add_group")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdAddMember
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdAddMember(arg)

	case client.CmdBan:
		if !hasArg {
			tab := m.tabs[m.active]
			if tab.groupID == "" || tab.cli == nil || tab.cli.IsRemote() {
				return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ban_host_only")))
			}
			hasCandidate := false
			for _, mem := range tab.groupMembers {
				if memberKey(mem) != m.myKey() {
					hasCandidate = true
					break
				}
			}
			if !hasCandidate {
				return localTab(m.active, styleMeta.Render(i18n.T("tui.no_members_to_ban")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdBan
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdBan(arg)

	case client.CmdPromote:
		if !hasArg {
			tab := m.tabs[m.active]
			if tab.groupID == "" {
				return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_promote_room_only")))
			}
			hasCandidate := false
			for _, mem := range tab.groupMembers {
				if memberKey(mem) != m.myKey() && m.resolveContactByPub(mem.IdentityPub) == nil {
					hasCandidate = true
					break
				}
			}
			if !hasCandidate {
				return localTab(m.active, styleMeta.Render(i18n.T("tui.no_members_to_promote")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdPromote
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdPromote(arg)

	case client.CmdRecall:
		if !hasArg {
			if len(m.savedGroups) == 0 {
				return localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.no_saved_group")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdRecall
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdRecall(arg)

	case client.CmdJoin:
		if !hasArg {
			hasGroupKnocks := false
			for _, k := range m.pendingKnocks {
				if k.GroupID != "" {
					hasGroupKnocks = true
					break
				}
			}
			if !hasGroupKnocks {
				return localTab(m.active, styleMeta.Render(i18n.T("tui.no_pending_group_invite")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdJoin
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdJoin(arg)

	case client.CmdSaveGroup:
		if !hasArg {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_save_group")))
		}
		return m.cmdSaveGroup(arg)

	case client.CmdAddContact:
		if !hasArg {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_add_contact")))
		}
		return m.cmdAddContact(arg)

	case client.CmdDelContact:
		if !hasArg {
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdDelContact
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdDelContact(arg)

	case client.CmdDelGroup:
		if !hasArg {
			if len(m.savedGroups) == 0 {
				return localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.no_saved_group")))
			}
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdDelGroup
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdDelGroup(arg)

	case client.CmdEdit:
		if arg == "" {
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdEdit
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdEdit(arg)

	case client.CmdSafety:
		if arg == "" && m.tabs[m.active].safetyCode == "" {
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdSafety
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdSafety(arg)

	case client.CmdVerifySafety:
		if arg == "" {
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdVerifySafety
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdVerifySafety(arg)

	case client.CmdUnverifySafety:
		return m.cmdUnverify(arg)

	case client.CmdRotateRelIdentity:
		return m.cmdRotateRelIdentity(arg)

	case client.CmdRotateRelContent:
		return m.cmdRotateRelContent(arg)

	case client.CmdRotateKey:
		return m.cmdRotateKey(arg)

	case client.CmdDeviceSync:
		return m.cmdDeviceSyncTrigger(arg)

	case client.CmdPing:
		return m.cmdPing(arg)

	case client.CmdRemoteNuke:
		return m.cmdRemoteNukeTrigger()

	case client.CmdIndoorSync:
		return m.cmdIndoorSync()

	case client.CmdDevices:
		return m.cmdDevices()

	case client.CmdDeviceLabel:
		return m.cmdDeviceLabel(arg)

	case client.CmdMsgAcks:
		return m.cmdMsgAcksTrigger()

	case client.CmdMsg:
		if hasArg {
			return m.cmdMsg(arg)
		}
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_msg_missing_number")))

	case client.CmdSendContact:
		if !hasArg {
			// No "empty address book" guard here, unlike elsewhere:
			// "self" (pickerItems, client.CmdSendContact) is always a
			// valid entry, even with zero saved contacts.
			m.contactPickerMode = true
			m.contactPickerCmd = client.CmdSendContact
			m.contactPickerFilter = ""
			m.contactPickerIdx = 0
			return nil
		}
		return m.cmdSendContact(arg)

	case client.CmdSendFile:
		return m.cmdSendFile()

	case client.CmdSave:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdSaveCard()

	case client.CmdIgnore:
		if hasArg {
			return m.errCommandNoArgs(id)
		}
		return m.cmdIgnoreCard()

	default:
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_unknown_command"), head)))
	}
}

// refreshFileTransferPeer updates incomingFileTransfer.fromUserID and
// announces (file_resume, idempotent) which byte to resume from, for
// every incoming transfer still open on this tab whose sender has just
// become resolvable to a user_id again, either our own (after an
// "init", reconnection of THIS client) or the sender's (after a
// "user_joined", reconnection of the OTHER side while this client stays
// connected). Without this, after the SENDER reconnects, the
// recipient's acks would keep pointing at its old user_id, silently
// dropped by the relay (Hub.Send returns nil on a target not found),
// the chunks would look "never confirmed". Only transfers STILL present
// in m.incomingTransfers count: completed/rejected ones are already
// removed from the map elsewhere.
func (m *model) refreshFileTransferPeer(tabIdx int) []tea.Cmd {
	var cmds []tea.Cmd
	tab := m.tabs[tabIdx]
	for _, it := range m.incomingTransfers {
		if it.tabIdx != tabIdx {
			continue
		}
		newUID := tab.cli.LookupUserID(it.fromKey)
		if newUID == "" {
			continue
		}
		it.fromUserID = newUID
		cli, ctx, toUID, transferID, fromByte := tab.cli, tab.ctx, newUID, it.transferID, it.written
		cmds = append(cmds, func() tea.Msg {
			_ = cli.SendFileResume(ctx, toUID, transferID, fromByte)
			return nil
		})
	}
	return cmds
}

// ── room message handler ──────────────────────────────────────────────────────

// roomMsgSeq numbers each call to handleRoomMsg in EXECUTION order (not
// socket-read order), the two sequences can diverge because every
// roomServerMsg passes through bubbletea's internal queue before
// arriving here. Only used for the WS channel trace below.
var roomMsgSeq atomic.Uint64

func (m *model) handleRoomMsg(tabIdx int, raw map[string]any) []tea.Cmd {
	var cmds []tea.Cmd
	tab := m.tabs[tabIdx]
	typ, _ := raw["type"].(string)

	seq := roomMsgSeq.Add(1)
	client.Dbg("ws_trace: handleRoomMsg#%d tab=%d type=%q transfer=%v from=%v to=%v", seq, tabIdx, typ, raw["transfer_id"], raw["from_user_id"], raw["to_user_id"])

	switch typ {
	case "init":
		users, _ := raw["users"].([]any)
		tab.online = nil
		for _, u := range users {
			um, _ := u.(map[string]any)
			tab.addOnline(tab.registerMember(um))
		}
		names := make([]string, 0, len(tab.online))
		for _, k := range tab.online {
			names = append(names, m.memberName(tab, k))
		}
		m.appendToDebug(fmt.Sprintf(i18n.T("tui.init_debug"), tab.name, strings.Join(names, ",")))
		m.appendToConsole("online", false)
		for _, u := range users {
			um, _ := u.(map[string]any)
			uid, _ := um["user_id"].(string)
			key := tab.cli.LookupMemberKey(uid)
			if uid == "" || key == "" {
				continue
			}
			puid := uid
			display := m.memberName(tab, key)
			initTabIdx := tabIdx
			cmds = append(cmds, func() tea.Msg {
				if err := tab.cli.SendSenderKeyReliable(tab.ctx, puid); err != nil {
					client.Dbg("sender_key: send to %s FAILED: %v", display, err)
					return nil
				}
				return senderKeySentMsg{tabIdx: initTabIdx, member: key}
			})
			if cmd := m.maybeSendRelBootstrap(tabIdx, puid, key); cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		if tab.rekeyOnNextInit {
			// Consumed once: only this first init after a manual
			// /grp-reconnect triggers the rotation, not every subsequent
			// init (e.g. a member reconnecting later in the same session).
			tab.rekeyOnNextInit = false
			cli, ctx := tab.cli, tab.ctx
			rotTabIdx := tabIdx
			cmds = append(cmds, func() tea.Msg {
				if err := cli.RotateSenderKey(ctx); err == nil {
					return senderKeyRotatedMsg{tabIdx: rotTabIdx}
				}
				return nil
			})
		}
		cmds = append(cmds, m.refreshFileTransferPeer(tabIdx)...)

	case "message":
		data, _ := raw["data"].(map[string]any)
		lines, moreCmds := m.handleIncomingMessage(tab, tabIdx, data)
		m.appendRoomLines(tab, tabIdx, lines)
		cmds = append(cmds, moreCmds...)

	case "msg_ack":
		fromUserID, _ := raw["from_user_id"].(string)
		msgID := parseMsgID(raw["msg_id"])
		if fromUserID == "" || msgID == 0 {
			break
		}
		// HandleAck updates the reliable delivery queue (pending.go)
		// regardless of pendingAckLines below (that's only the ackers
		// view for the user, /grp-msg-acks), always called, even if the
		// line is no longer tracked for the UI.
		if tab.cli != nil && tab.cli.HandleAck(fromUserID, msgID) {
			cli, ctx := tab.cli, tab.ctx
			cmds = append(cmds, func() tea.Msg {
				cli.FlushDeferredKeyDistributions(ctx)
				return nil
			})
		}
		loc, ok := m.pendingAckLines[msgID]
		if !ok {
			break
		}
		if loc.tabIdx < len(m.tabs) && loc.lineIdx < len(m.tabs[loc.tabIdx].lines) {
			// Resolved via tab.cli (the same connection this msg_ack
			// arrived on), not a global lookup, from_user_id is
			// authenticated server-side (internal/server/ws.go:
			// FromUserID is populated from the WS session, never a
			// client-declared field), so it's reliable.
			if key := m.tabs[loc.tabIdx].cli.LookupMemberKey(fromUserID); key != "" {
				line := &m.tabs[loc.tabIdx].lines[loc.lineIdx]
				if line.ackers == nil {
					line.ackers = make(map[string]bool)
				}
				line.ackers[key] = true
				client.Dbg("msg_ack: msgID=%d from=%s tab=%d ackers now=%d at %s", msgID, keyFingerprint(key), loc.tabIdx, len(line.ackers), shared.Now())
			}
		}

	case "user_joined":
		uid, _ := raw["user_id"].(string)
		key := tab.registerMember(raw)
		if key == "" {
			break
		}
		uname := m.memberName(tab, key)
		tab.addOnline(key)
		delete(tab.departures, key) // reconnected: reset previous state
		// A reconnected peer has a new session user_id, the previous
		// "send succeeded" outcome (for the old user_id) no longer
		// proves anything about the current channel, must be redone
		// (same principle as departures above).
		delete(tab.keySentTo, key)
		m.appendToDebug(fmt.Sprintf(i18n.T("tui.user_joined_debug"), uname, client.ShortUID(uid), tab.name))
		m.appendToConsole(fmt.Sprintf(i18n.T("tui.user_entered_room"), uname, tab.name), false)
		{
			puid := uid
			joinTabIdx := tabIdx
			cmds = append(cmds, func() tea.Msg {
				if err := tab.cli.SendSenderKeyReliable(tab.ctx, puid); err != nil {
					client.Dbg("sender_key: send to %s FAILED: %v", uname, err)
					return nil
				}
				return senderKeySentMsg{tabIdx: joinTabIdx, member: key}
			})
			if cmd := m.maybeSendRelBootstrap(tabIdx, puid, key); cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		// Covers the case complementary to "init": here it's the OTHER
		// side (e.g. the sender of an ongoing file transfer) that just
		// reconnected with a new user_id, while THIS client stays
		// connected and never receives an "init".
		cmds = append(cmds, m.refreshFileTransferPeer(tabIdx)...)

	case "sender_key":
		fromUserID, _ := raw["from_user_id"].(string)
		payload, _ := raw["payload"].(string)
		if fromUserID != "" && payload != "" {
			err := tab.cli.StorePeerSenderKey(fromUserID, payload)
			m.appendToDebug(fmt.Sprintf(i18n.T("tui.sender_key_debug"), client.ShortUID(fromUserID)))
			// Ack only on successful registration, the sender_key
			// travels on the same reliable channel as chat messages
			// (Client.sendSenderKeyTo): without confirmation the sender
			// retransmits it (RetryDue), exactly like a normal message.
			if err == nil {
				if mid := parseMsgID(raw["msg_id"]); mid != 0 {
					cli, ctx := tab.cli, tab.ctx
					cmds = append(cmds, func() tea.Msg {
						_ = cli.SendMsgAck(ctx, fromUserID, mid)
						return nil
					})
				}
				// Messages under this key may have arrived first and be
				// waiting in msgBuffer: processed now, not at the
				// server's next retransmission.
				lines, moreCmds := m.drainMsgBuffer(tab, tabIdx)
				m.appendRoomLines(tab, tabIdx, lines)
				cmds = append(cmds, moreCmds...)
			}
		}

	case "rel_bootstrap":
		fromUserID, _ := raw["from_user_id"].(string)
		payload, _ := raw["payload"].(string)
		if fromUserID != "" && payload != "" {
			if cmd := m.applyRelBootstrap(tabIdx, fromUserID, payload); cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case "rel_bootstrap_ack":
		fromUserID, _ := raw["from_user_id"].(string)
		if fromUserID != "" {
			if key := tab.cli.LookupMemberKey(fromUserID); key != "" && tab.ephRels != nil {
				if rel := tab.ephRels[key]; rel != nil {
					rel.peerAcked = true
					client.Dbg("rel_bootstrap_ack: confirmed by %s", m.memberName(tab, key))
				}
			}
		}

	case "rel_promote":
		fromUserID, _ := raw["from_user_id"].(string)
		payload, _ := raw["payload"].(string)
		if fromUserID != "" && payload != "" {
			if cmd := m.applyRelPromote(tabIdx, fromUserID, payload); cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case "rel_promote_ack":
		fromUserID, _ := raw["from_user_id"].(string)
		if fromUserID != "" {
			if key := tab.cli.LookupMemberKey(fromUserID); key != "" && tab.ephRels != nil {
				if rel := tab.ephRels[key]; rel != nil {
					rel.peerPromoteAcked = true
					client.Dbg("rel_promote_ack: confirmed by %s", m.memberName(tab, key))
				}
			}
		}

	case "server_shutdown":
		tab.serverShutdown = true
		m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.server_shutdown"), tab.name)), true)

	case "user_left":
		uid, _ := raw["user_id"].(string)
		key := tab.cli.LookupMemberKey(uid)
		// Removes uid from known members and from any pending delivery
		// queue waiting on it (pending.go), after reading key above,
		// not before, since resolving the member still needs it.
		tab.cli.UnregisterUser(uid)
		if key == "" {
			// Unknown or already superseded session (the member has
			// reconnected under a newer userID): nothing to update.
			break
		}
		uname := m.memberName(tab, key)
		reason, _ := raw["reason"].(string)
		m.appendToDebug(fmt.Sprintf(i18n.T("tui.user_left_debug"), uname, client.ShortUID(uid), tab.name, reason))
		// reason ("left"=clean /grp-exit, "lost"=crash/timeout, internal/server/
		// ws.go:wsUserLeft) is shown only for "lost": "left" is a
		// voluntary exit via /grp-exit, already obvious from context, no
		// need to annotate it.
		userLeftKey := "tui.user_left_room"
		switch reason {
		case "lost":
			userLeftKey = "tui.user_left_room_lost"
		case "overloaded":
			// Kick for a saturated delivery queue (roomDelivery), not a
			// ban: no secret revocation, free reconnection. Treated like
			// memberCrashed below (same color/automatic reconnection as
			// "lost"), only the Console text is specific.
			userLeftKey = "tui.user_left_room_overloaded"
		}
		m.appendToConsole(fmt.Sprintf(i18n.T(userLeftKey), uname, tab.name), false)
		tab.removeOnline(key)
		if tab.departures == nil {
			tab.departures = make(map[string]memberState)
		}
		switch reason {
		case "left":
			tab.departures[key] = memberLeft
		case "banned":
			tab.departures[key] = memberBanned
		default:
			tab.departures[key] = memberCrashed
		}

	case "ping_probe":
		// We receive a ping from the peer: respond immediately with pong (same seq, same sent_at).
		fromUID, _ := raw["from_user_id"].(string)
		seqF, _ := raw["seq"].(float64)
		sentAtF, _ := raw["sent_at"].(float64)
		if fromUID == "" {
			break
		}
		seq := uint64(seqF)
		sentAt := int64(sentAtF)
		cli := tab.cli
		cmds = append(cmds, func() tea.Msg {
			_ = cli.SendPongProbe(tab.ctx, fromUID, seq, sentAt)
			return nil
		})

	case "pong_probe":
		// We receive the response to our ping: compute RTT.
		seqF, _ := raw["seq"].(float64)
		sentAtF, _ := raw["sent_at"].(float64)
		seq := uint64(seqF)
		sentAt := int64(sentAtF)
		if _, ok := m.pingPending[seq]; !ok {
			break // stale pong or not ours
		}
		rttMs := float64(time.Now().UnixNano()-sentAt) / 1e6
		delete(m.pingPending, seq)
		m.pingRTTs = append(m.pingRTTs, rttMs)
		n := len(m.pingRTTs)
		m.textPopupContent += "\n" + fmt.Sprintf(i18n.T("tui.ping_probe"), n, m.pingTotal, rttMs)
		if n == m.pingTotal {
			// all pongs received: print statistics
			minR, maxR, sum := m.pingRTTs[0], m.pingRTTs[0], 0.0
			for _, r := range m.pingRTTs {
				sum += r
				if r < minR {
					minR = r
				}
				if r > maxR {
					maxR = r
				}
			}
			avg := sum / float64(n)
			m.textPopupContent += "\n" + fmt.Sprintf(
				i18n.T("tui.ping_stats"),
				minR, avg, maxR, n, m.pingTotal)
			m.pingRTTs = m.pingRTTs[:0]
			m.pingTotal = 0
		}

	case "file_announce":
		// Cryptographic verification phase BEFORE any real data, only
		// hash+signature, no meta_blob/name/size. Verified immediately:
		// immediate ack. Failed: self-heal (instead of dropping),
		// re-verified when applyRelInit resyncs the device
		// (retryPendingFileAnnounces).
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		hashB64, _ := raw["hash"].(string)
		sigB64, _ := raw["sig"].(string)
		sigMLDSAB64, _ := raw["sig_mldsa"].(string)
		sigTS, _ := raw["sig_ts"].(string)
		if fromUserID == "" || transferID == "" || hashB64 == "" {
			break
		}
		fromKey := tab.cli.LookupMemberKey(fromUserID)
		if fromKey == "" {
			break
		}
		fromUser := m.memberName(tab, fromKey)
		hash, _ := base64.StdEncoding.DecodeString(hashB64)
		var sig, sigMLDSA []byte
		if sigB64 != "" {
			sig, _ = base64.StdEncoding.DecodeString(sigB64)
		}
		if sigMLDSAB64 != "" {
			sigMLDSA, _ = base64.StdEncoding.DecodeString(sigMLDSAB64)
		}
		if len(hash) == 0 {
			break
		}
		hashHex := hex.EncodeToString(hash)
		pub, mldsaPub, _, devKey, known := m.contentPeerKeysFor(tab, fromKey)
		valid := known &&
			shared.VerifyRelMsg(pub, hashHex, sigTS, m.myKey(), sig) &&
			(len(mldsaPub) == 0 || len(sigMLDSA) == 0 || shared.VerifyRelMsgMLDSA(mldsaPub, hashHex, sigTS, m.myKey(), sigMLDSA))
		if valid {
			if m.verifiedFileHashes == nil {
				m.verifiedFileHashes = make(map[string][]byte)
			}
			m.verifiedFileHashes[transferID] = hash
			cli := tab.cli
			ctx := tab.ctx
			tid := transferID
			uid := fromUserID
			cmds = append(cmds, func() tea.Msg { _ = cli.SendFileAnnounceAck(ctx, uid, tid); return nil })
			break
		}
		// Self-heal (same core mechanism already used for the
		// ContentKey mismatch on messages, case sigFailed above), with
		// one difference: here it triggers an immediate probe round
		// right away instead of waiting for the next periodic cycle, to
		// make the best use of the fileTransferOfferTimeout window
		// within which the sender waits for this ack.
		if hc := m.resolveContactByPub(memberKeyPub(fromKey)); hc != nil && devKey != "" {
			if dev, ok := hc.DeviceByPub([]byte(devKey)); ok && dev.RelContentConfirmedByPeer {
				dev.RelContentConfirmedByPeer = false
				if resetFn := m.resetRelInitConfirmed; resetFn != nil {
					pub, devPub := hc.IdentityPub, []byte(devKey)
					go func() { _ = resetFn(pub, devPub, "content") }()
				}
				m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.err_stale_rel_key_reset"), fromUser)), true)
				cmds = append(cmds, m.cmdActiveSilent())
			}
		}
		if m.pendingFileAnnounces == nil {
			m.pendingFileAnnounces = make(map[string]*pendingFileAnnounce)
		}
		m.pendingFileAnnounces[transferID] = &pendingFileAnnounce{
			tabIdx:     tabIdx,
			fromKey:    fromKey,
			fromUserID: fromUserID,
			devKey:     devKey,
			hash:       hash,
			sig:        sig,
			sigMLDSA:   sigMLDSA,
			sigTS:      sigTS,
			deadline:   time.Now().Add(m.fileTransferOfferTimeout),
		}

	case "file_offer":
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		metaBlobB64, _ := raw["meta_blob"].(string)
		if fromUserID == "" || transferID == "" {
			break
		}
		fromKey := tab.cli.LookupMemberKey(fromUserID)
		if fromKey == "" {
			break
		}
		fromUser := m.memberName(tab, fromKey)
		// The hash was already verified during the announce phase (case
		// "file_announce" above), without an entry here, the sender
		// sent an offer without our ack, which shouldn't ever happen by
		// construction: dropped as defense in depth.
		hash, hashKnown := m.verifiedFileHashes[transferID]
		if !hashKnown {
			break
		}
		delete(m.verifiedFileHashes, transferID)
		myContentKey, _ := m.myContentPrivFor(tab, fromKey)
		if m.incomingTransfers == nil {
			m.incomingTransfers = make(map[string]*incomingFileTransfer)
		}
		// Name and size are encrypted (meta_blob), not yet known at
		// this point, populated by fileOfferMetaDecryptedMsg when the
		// background decryption completes.
		progress := &fileTransferProgress{
			label:     i18n.T("tui.recv_file_meta_pending"),
			direction: "↓",
			peer:      fromUser,
		}
		chunkCh := make(chan incomingChunkJob, 32)
		chunkResultCh := make(chan incomingChunkResult, 32)
		abortCh := make(chan struct{})
		m.incomingTransfers[transferID] = &incomingFileTransfer{
			transferID:    transferID,
			tabIdx:        tabIdx,
			fromUserID:    fromUserID,
			fromKey:       fromKey,
			hash:          hash,
			progress:      progress,
			chunkCh:       chunkCh,
			chunkResultCh: chunkResultCh,
			abortCh:       abortCh,
		}
		// The writer (startIncomingChunkWriter) only starts in
		// fileOfferMetaDecryptedMsg: it needs chunkCount, known only
		// once the meta_blob decryption completes, never here.
		m.fileProgress.add(transferID, progress)
		cmds = append(cmds, m.tickFileProgress(), decryptFileOfferMeta(myContentKey, transferID, metaBlobB64))

	case "file_announce_ack":
		// Sender side: that recipient has verified the announce, only
		// NOW do we send them the real offer (meta_blob), never before.
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		if fromUserID == "" || transferID == "" {
			break
		}
		ft := m.outgoingTransfers[transferID]
		if ft == nil {
			ft = m.outgoingTransfersSending[transferID]
		}
		if ft == nil {
			break // transfer already concluded/canceled in the meantime
		}
		env, ok := ft.envelopes[fromUserID]
		if !ok {
			break
		}
		cli := tab.cli
		ctx := tab.ctx
		tid := transferID
		uid := fromUserID
		envelopes := map[string]shared.FileOfferEnvelope{uid: env}
		cmds = append(cmds, func() tea.Msg { _ = cli.SendFileOffer(ctx, []string{uid}, tid, envelopes); return nil })

	case "file_accept":
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		fromKey := tab.cli.LookupMemberKey(fromUserID)
		fromUser := m.memberName(tab, fromKey)

		// The transfer has already started toward whoever accepted
		// within fileOfferBatchWindow (see outgoingFileTransfer): an
		// acceptance arriving later must be readmitted into the window
		// already in progress instead of being silently dropped.
		if sending, ok := m.outgoingTransfersSending[transferID]; ok {
			client.Dbg("file_accept: transfer=%s fromUserID=%s… resolved=%q, readmitted into the window already in progress", transferID, client.ShortUID(fromUserID), fromUser)
			m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_accepted_by"), fromUser, sending.fileName)), false)
			if sending.resumeCh != nil {
				select {
				case sending.resumeCh <- fileResumeEvent{memberKey: fromKey, toUserID: fromUserID, fromByte: 0, isNewAccept: true}:
				default:
					client.Dbg("file_accept: transfer=%s resumeCh full, late acceptance from %s lost", transferID, fromUser)
				}
			}
			break
		}

		ft := m.outgoingTransfers[transferID]
		if ft == nil {
			break
		}
		client.Dbg("file_accept: transfer=%s fromUserID=%s… resolved=%q pendingBefore=%d", transferID, client.ShortUID(fromUserID), fromUser, len(ft.pending))
		if fromKey != "" {
			delete(ft.pending, fromKey)
		}
		ft.signalAllResponded()
		ft.accepted = append(ft.accepted, fromUserID)
		m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_accepted_by"), fromUser, ft.fileName)), false)

		if len(ft.pending) == 0 {
			// Everyone invited has now responded (accepted or
			// rejected): no point waiting out the rest of the
			// collection window, nobody else can still join late.
			client.Dbg("file_accept: transfer=%s everyone responded, sending now to %d recipients", transferID, len(ft.accepted))
			delete(m.outgoingTransfers, transferID)
			if m.outgoingTransfersSending == nil {
				m.outgoingTransfersSending = make(map[string]*outgoingFileTransfer)
			}
			m.outgoingTransfersSending[transferID] = ft
			cmds = append(cmds, m.startSendingChunks(ft))
			break
		}
		// No further action here: the collection window
		// (fileOfferBatchWindow) is already armed from sending the
		// offer (case fileEncryptedMsg), not from the first accept,
		// this acceptance just queues onto ft.accepted above, waiting
		// for either the timer to expire (case fileOfferBatchWindowMsg)
		// or for everyone to respond first (len(ft.pending)==0 branch above).

	case "file_reject":
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		fromUser := tab.cli.LookupUsername(fromUserID)

		// Same twin branch as "file_accept" above: a rejection arriving
		// after the send already started toward someone else must not
		// touch anything anymore, just be announced in Console.
		if sending, ok := m.outgoingTransfersSending[transferID]; ok {
			m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_rejected_by"), fromUser, sending.fileName)), false)
			break
		}

		ft := m.outgoingTransfers[transferID]
		if ft == nil {
			break
		}
		if fromUser != "" {
			delete(ft.pending, fromUser)
		}
		ft.signalAllResponded()
		m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_rejected_by"), fromUser, ft.fileName)), false)
		if len(ft.pending) == 0 {
			// With the collection window (fileOfferBatchWindow),
			// ft.accepted is NOT guaranteed empty here: this rejection
			// can be the last missing response while someone else
			// already accepted shortly before, within the same window.
			// Only if ft.accepted is also empty is it really the
			// "everyone explicitly rejected" case, otherwise it
			// proceeds anyway with whoever accepted, exactly as the
			// collection window's natural expiry would.
			if len(ft.accepted) > 0 {
				client.Dbg("file_reject: transfer=%s everyone responded, sending now to %d recipients", transferID, len(ft.accepted))
				delete(m.outgoingTransfers, transferID)
				if m.outgoingTransfersSending == nil {
					m.outgoingTransfersSending = make(map[string]*outgoingFileTransfer)
				}
				m.outgoingTransfersSending[transferID] = ft
				cmds = append(cmds, m.startSendingChunks(ft))
				break
			}
			delete(m.outgoingTransfers, transferID)
			if ft.progress != nil {
				ft.progress.setComplete(true)
			}
			m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.send_file_all_rejected"), ft.fileName)), true)
		}

	case "file_chunk":
		// Only base64 decoding (CPU, not I/O) and non-blocking delivery
		// to the dedicated writer goroutine, NEVER disk I/O here, see
		// the comment on incomingFileTransfer for why. Updating
		// written/progress, sending the ack, and any finalization all
		// move to case incomingChunkWrittenMsg, once the writer
		// goroutine confirms the chunk is really on disk.
		transferID, _ := raw["transfer_id"].(string)
		payloadB64, _ := raw["payload"].(string)
		seqF, _ := raw["seq"].(float64)
		seq := uint64(seqF)
		it := m.incomingTransfers[transferID]
		if it == nil || payloadB64 == "" {
			client.Dbg("recv_file: transfer=%s seq=%d discarded (unknown transfer or empty payload)", transferID, seq)
			break
		}
		client.Dbg("recv_file: transfer=%s seq=%d received", transferID, seq)
		chunk, err := base64.StdEncoding.DecodeString(payloadB64)
		if err != nil {
			break
		}
		select {
		case it.chunkCh <- incomingChunkJob{seq: seq, chunk: chunk}:
		default:
			// Full queue (32, see case "file_offer"): the writer is
			// slower than the network for this chunk, dropped, the
			// sender will retransmit it at the ack timeout (same
			// mechanism as a chunk lost on the network, not a new case
			// to handle here).
			client.Dbg("recv_file: transfer=%s seq=%d discarded, writer queue full", transferID, seq)
		}

	case "file_chunk_ack":
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		seqF, _ := raw["seq"].(float64)
		// outgoingTransfersSending, NOT outgoingTransfers: the latter
		// has already been deleted at the exact moment the real send
		// started (see the comment on the field), looking there would
		// mean no ack ever reaches the sending goroutine, which would
		// then isolate every recipient at the first timeout.
		ft := m.outgoingTransfersSending[transferID]
		if ft == nil || ft.ackCh == nil {
			break
		}
		select {
		case ft.ackCh <- fileChunkAckEvent{seq: uint64(seqF), fromUserID: fromUserID}:
		default:
		}

	case "file_verify_result":
		fromUserID, _ := raw["from_user_id"].(string)
		ok, _ := raw["ok"].(bool)
		fromUser := m.memberName(tab, tab.cli.LookupMemberKey(fromUserID))
		if fromUser == "" {
			fromUser = client.ShortUID(fromUserID)
		}
		if ok {
			m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_verify_ok"), fromUser)), false)
		} else {
			m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.send_file_verify_failed"), fromUser)), true)
		}

	case "file_resume":
		fromUserID, _ := raw["from_user_id"].(string)
		transferID, _ := raw["transfer_id"].(string)
		fromByteF, _ := raw["from_byte"].(float64)
		ft := m.outgoingTransfersSending[transferID]
		if ft == nil || ft.resumeCh == nil {
			break // transfer already concluded (or never existed), announcement ignored
		}
		resumeKey := tab.cli.LookupMemberKey(fromUserID)
		select {
		case ft.resumeCh <- fileResumeEvent{memberKey: resumeKey, toUserID: fromUserID, fromByte: int64(fromByteF)}:
		default:
		}
	}
	return cmds
}

// parseMsgID reads msg_id from the frame decoded into map[string]any.
// On the wire it's a decimal string, not a JSON number, see the
// comment on wsIncoming.MsgID in internal/server/ws.go: a random
// full-width uint64 almost always gets corrupted going through
// map[string]any (JSON numbers always become float64, exact only up to
// 2^53). Best-effort: returns 0 if the field is missing or not a valid string.
func parseMsgID(v any) uint64 {
	s, _ := v.(string)
	id, _ := strconv.ParseUint(s, 10, 64)
	return id
}

// maxBufferedPerKey limits how many out-of-sequence messages can pile
// up waiting for a single keyID, protects memory, not against a real
// loss (which shouldn't ever happen with the sender's reliable delivery
// queue, pending.go): an idx absurdly far from the expected one (buggy
// or malicious peer) must not be able to grow the buffer without limit.
const maxBufferedPerKey = 1000

// bufferMsg holds onto mm (the complete raw frame) waiting for idx to
// become the next one expected for keyID, no-op beyond maxBufferedPerKey.
func bufferMsg(tab *roomTab, keyID string, idx uint64, mm map[string]any) {
	if tab.msgBuffer == nil {
		tab.msgBuffer = make(map[string]map[uint64]map[string]any)
	}
	byIdx := tab.msgBuffer[keyID]
	if byIdx == nil {
		byIdx = make(map[uint64]map[string]any)
		tab.msgBuffer[keyID] = byIdx
	}
	if len(byIdx) >= maxBufferedPerKey {
		return
	}
	byIdx[idx] = mm
}

// takeBufferedMsg retrieves (and removes) the buffered frame for keyID/idx, if present.
func takeBufferedMsg(tab *roomTab, keyID string, idx uint64) (map[string]any, bool) {
	byIdx := tab.msgBuffer[keyID]
	if byIdx == nil {
		return nil, false
	}
	mm, ok := byIdx[idx]
	if ok {
		delete(byIdx, idx)
	}
	return mm, ok
}

// appendRoomLines appends lines to tab, tracking our own messages for
// their acks (pendingAckLines).
func (m *model) appendRoomLines(tab *roomTab, tabIdx int, lines []*chatLine) {
	for _, line := range lines {
		lineIdx := len(tab.lines)
		tab.lines = append(tab.lines, *line)
		client.Dbg("message: appended line tab=%d idx=%d isOwn=%v msgID=%d active=%v at %s", tabIdx, lineIdx, line.fromKey == m.myKey(), line.msgID, tabIdx == m.active, shared.Now())
		if line.msgID != 0 {
			m.pendingAckLines[line.msgID] = struct{ tabIdx, lineIdx int }{tabIdx, lineIdx}
		}
	}
}

// drainMsgBuffer processes, for every keyID now known, the buffered
// frame at its expected idx (handleIncomingMessage then cascades to the
// following ones), called right after a sender_key is registered, so
// messages that overtook their own key don't wait for the server's
// retransmission.
func (m *model) drainMsgBuffer(tab *roomTab, tabIdx int) ([]*chatLine, []tea.Cmd) {
	var lines []*chatLine
	var cmds []tea.Cmd
	keyIDs := make([]string, 0, len(tab.msgBuffer))
	for keyID := range tab.msgBuffer {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	for _, keyID := range keyIDs {
		expected, known := tab.cli.ExpectedIdx(keyID)
		if !known {
			continue
		}
		mm, ok := takeBufferedMsg(tab, keyID, expected)
		if !ok {
			continue
		}
		l, c := m.handleIncomingMessage(tab, tabIdx, mm)
		lines = append(lines, l...)
		cmds = append(cmds, c...)
	}
	return lines, cmds
}

// handleIncomingMessage routes a "message" frame through the per-keyID
// reordering buffer (roomTab.msgBuffer, bufferMsg/takeBufferedMsg):
// an out-of-sequence arrival (idx > expected, from Client.ExpectedIdx)
// is held without being decrypted or acknowledged, never fast-forwarded
// (see the comment on Client.DecryptMsg). An
// arrival in the right order is processed (parseMessage) and cascades
// to unblock every already-buffered successor, up to the first
// remaining gap or a decryption failure. A duplicate (idx < expected)
// is neither re-decrypted nor shown, but still generates an ack: it
// could have been the ORIGINAL ack that got lost, not the message. A
// key not yet known (Client.ExpectedIdx: known=false) is buffered like
// any out-of-sequence arrival, waiting for StorePeerSenderKey to
// register it, drainMsgBuffer resumes it as soon as the key arrives.
func (m *model) handleIncomingMessage(tab *roomTab, tabIdx int, mm map[string]any) ([]*chatLine, []tea.Cmd) {
	keyID, _ := mm["kid"].(string)
	idxF, _ := mm["idx"].(float64)
	idx := uint64(idxF)

	var lines []*chatLine
	var cmds []tea.Cmd

	// Self-echo: our own send always comes back in the order it was
	// sent (no network sequencing involved before the server), and
	// never goes through the receive ratchet (TakeSentText, inside
	// parseMessage). Must be recognized AND processed BEFORE the gate
	// below: ExpectedIdx/msgBuffer only track a PEER's chain-ratchet
	// (StorePeerSenderKey/DecryptMsg), they never know our own
	// senderKeyID, routing a self-echo through there would buffer it
	// forever, with no condition ever unblocking it.
	if msgID := parseMsgID(mm["msg_id"]); msgID != 0 && tab.cli.HasSentText(msgID) {
		line, cmd := m.parseMessage(tab, tabIdx, mm)
		if line != nil {
			lines = append(lines, line)
		}
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return lines, cmds
	}

	for {
		expected, known := tab.cli.ExpectedIdx(keyID)
		if !known || idx > expected {
			bufferMsg(tab, keyID, idx, mm)
			return lines, cmds
		}
		if idx < expected {
			if fromUserID, _ := mm["from_user_id"].(string); fromUserID != "" {
				if mid := parseMsgID(mm["msg_id"]); mid != 0 {
					cli, ctx := tab.cli, tab.ctx
					cmds = append(cmds, func() tea.Msg {
						_ = cli.SendMsgAck(ctx, fromUserID, mid)
						return nil
					})
				}
			}
			return lines, cmds
		}

		// idx == expected: process now, then check whether the next one is already buffered.
		line, cmd := m.parseMessage(tab, tabIdx, mm)
		if line != nil {
			lines = append(lines, line)
		}
		if cmd != nil {
			cmds = append(cmds, cmd)
		}

		next, ok := tab.cli.ExpectedIdx(keyID)
		if !ok {
			return lines, cmds
		}
		nextMM, buffered := takeBufferedMsg(tab, keyID, next)
		if !buffered {
			return lines, cmds
		}
		mm = nextMM
		idx = next
	}
}

func (m *model) parseMessage(tab *roomTab, tabIdx int, mm map[string]any) (*chatLine, tea.Cmd) {
	keyID, _ := mm["kid"].(string)
	rawText, _ := mm["text"].(string)
	idxF, _ := mm["idx"].(float64) // JSON numbers decode as float64 in map[string]any
	idx := uint64(idxF)
	mseqF, _ := mm["mseq"].(float64) // same convention as idx: a small, monotonic counter, never a random full-width value (see msg_id)
	mseq := uint64(mseqF)
	gseqF, _ := mm["gseq"].(float64) // room-wide global sequence number (roomDelivery), used by the explicit reply reference
	gseq := uint64(gseqF)
	tsRaw, _ := mm["timestamp"].(string)
	deviceSigB64, _ := mm["device_sig"].(string)
	deviceTS, _ := mm["device_ts"].(string)
	fromUserID, _ := mm["from_user_id"].(string)
	msgID := parseMsgID(mm["msg_id"])

	ts := ""
	if t, err := time.Parse(time.RFC3339Nano, tsRaw); err == nil {
		ts = t.Local().Format(shared.TimeLayout)
	}

	// Server self-echo (the broadcast always includes the sender too):
	// if msgID matches one of our recent sends, reuses the already-
	// known text instead of running the message through the generic
	// receive ratchet. Necessary with ratchetDH, the dhr field we
	// publish when sending identifies a key of the PEER's, never one of
	// our own; decrypting our own self-echo as if it were "another
	// peer" would look up that EphID in our own outEphRing (which only
	// holds OUR retired ephemerals) without ever finding it, permanently
	// diverging the self-echo chain from the real senderChainKey as
	// soon as the DH mix activates.
	var from, text string
	var dp []byte
	var replyTo uint64
	var selfEcho bool
	if msgID != 0 {
		if cached, rt, ok := tab.cli.TakeSentText(msgID); ok {
			from = m.myUsername
			text = cached
			dp = m.myDevicePub
			replyTo = rt
			selfEcho = true
			client.Dbg("self-echo: msgID=%d recognized (cache hit) at %s", msgID, shared.Now())
		}
	}
	if from == "" {
		// Sender identity (username, device pubkey) is unsealed from inside the ciphertext.
		from, text, dp, replyTo = tab.cli.DecryptMsg(keyID, rawText, idx)
	}
	if from == "" {
		// Not decrypted (e.g. refused by DecryptMsg): no line and no ack,
		// so its sender re-encrypts it under a new generation once the
		// message TTL expires.
		client.Dbg("message: msgID=%d kid=%s idx=%d not decrypted, no ack", msgID, keyID, idx)
		return nil, nil
	}

	// The sender is the member behind the server-authenticated
	// from_user_id, identified by its key, never the name sealed in the
	// payload, which is self-declared and only a fallback label for a
	// session not yet registered.
	fromKey := tab.cli.LookupMemberKey(fromUserID)
	if selfEcho {
		fromKey = m.myKey()
	}
	isOwn := selfEcho || (fromKey != "" && fromKey == m.myKey())
	if fromKey != "" {
		from = m.memberName(tab, fromKey)
	}

	// A message its sender re-encrypted past the TTL (same msgID) that
	// was already shown: confirmed again, never shown twice.
	if msgID != 0 {
		if _, dup := tab.seenMsgIDs[msgID]; dup {
			client.Dbg("message: msgID=%d already shown, acknowledged again", msgID)
			return nil, tea.Batch(deliveryAcks(tab, msgID, gseq, fromUserID, selfEcho, isOwn)...)
		}
		if tab.seenMsgIDs == nil {
			tab.seenMsgIDs = make(map[uint64]struct{})
		}
		tab.seenMsgIDs[msgID] = struct{}{}
	}

	// System announcement "new member added to the group" (/grp-add-member), not
	// a chat message: handled and validated separately, never shown as plain text.
	if strings.HasPrefix(text, groupMemberAddedPrefix) {
		line := m.applyGroupMemberAdded(tab, fromUserID, ts, strings.TrimPrefix(text, groupMemberAddedPrefix))
		return line, tea.Batch(deliveryAcks(tab, msgID, gseq, fromUserID, selfEcho, isOwn)...)
	}

	// System announcement "PQC signature enabled/disabled" (/sec-pqc-sign), not
	// a chat message: see pqcToggleAnnouncePrefix.
	if strings.HasPrefix(text, pqcToggleAnnouncePrefix) {
		line := applyPQCToggleAnnounce(from, ts, strings.TrimPrefix(text, pqcToggleAnnouncePrefix))
		return line, tea.Batch(deliveryAcks(tab, msgID, gseq, fromUserID, selfEcho, isOwn)...)
	}

	// Content signature (per-relationship ContentKey), looks among
	// content_sigs for the entry addressed to US (For == our member key),
	// then verifies it with the SENDER's ContentKey toward us
	// (Contact.PeerRelContentPub for a real contact,
	// ephemeralRel.peerContent for an unknown "introduced" one). The
	// key is already in local memory as soon as the ephemeral bootstrap
	// or rel_init has completed, no network bootstrap to wait for,
	// verification is always synchronous, a single attempt.
	status := sigNone
	var contentKeyTag string
	var contentKeyEphemeral bool
	if isOwn {
		status = sigOwn
	} else {
		if entries := extractContentSigsFor(mm, m.myKey()); len(entries) > 0 {
			candidates := m.contentPeerPubCandidatesFor(tab, fromKey, dp)
			ts := contentSigTS(mm)
			var matched *contentPeerCandidateKey
		matchLoop:
			for _, e := range entries {
				for i := range candidates {
					cand := candidates[i]
					if shared.VerifyRelMsg(cand.pub, rawText, ts, m.myKey(), e.sig) &&
						(len(cand.mldsaPub) == 0 || len(e.sigMLDSA) == 0 || shared.VerifyRelMsgMLDSA(cand.mldsaPub, rawText, ts, m.myKey(), e.sigMLDSA)) {
						matched = &cand
						break matchLoop
					}
				}
			}
			switch {
			case len(candidates) == 0:
				status = sigPending
			case matched != nil:
				status = sigOK
				hex := fmt.Sprintf("%x", matched.pub)
				if len(hex) > 8 {
					hex = hex[len(hex)-8:]
				}
				contentKeyTag = "REL:" + hex
				contentKeyEphemeral = matched.ephemeral
			default:
				status = sigFailed
				// Self-heal, same mechanism already used for the
				// per-relationship IdentityKey mismatch (see the case
				// client.ErrInvalidServerSig further above), here applied
				// to the ContentKey mismatch that signs MESSAGES.
				// Resetting RelInitConfirmedByPeer reactivates resending
				// our rel_init from the next probe cycle; the peer ALWAYS
				// replies with a rel_init_ack carrying its CURRENT
				// bootstrap (identity+content together, see applyRelInit)
				// a single round trip is enough to resync
				// PeerRelContentPub, with no manual action (forced
				// rotation) needed from the user. Guarded on
				// RelInitConfirmedByPeer to avoid repeating the reset
				// (and the disk Save it triggers) on every single message
				// while the probe cycle is already in flight, the same
				// pattern already used for the identity case above. With
				// dp resolved to an exact device, the reset targets ONLY
				// that device, never a guessed choice on a multi-device
				// contact; without dp it falls
				// back to ALL ready devices, each one independently
				// resending its own rel_init anyway.
				if hc := m.resolveContactByPub(memberKeyPub(fromKey)); hc != nil {
					if dev, ok := hc.DeviceByPub(dp); ok && dev.RelContentConfirmedByPeer {
						dev.RelContentConfirmedByPeer = false
						if resetFn := m.resetRelInitConfirmed; resetFn != nil {
							pub, devPub := hc.IdentityPub, dp
							go func() { _ = resetFn(pub, devPub, "content") }()
						}
						m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.err_stale_rel_key_reset"), from)), true)
					} else {
						reset := false
						for devKey, d := range hc.Devices {
							if d == nil || !d.RelContentConfirmedByPeer {
								continue
							}
							d.RelContentConfirmedByPeer = false
							reset = true
							if resetFn := m.resetRelInitConfirmed; resetFn != nil {
								pub, devPub := hc.IdentityPub, []byte(devKey)
								go func() { _ = resetFn(pub, devPub, "content") }()
							}
						}
						if reset {
							m.appendToConsole(styleErr.Render(fmt.Sprintf(i18n.T("tui.err_stale_rel_key_reset"), from)), true)
						}
					}
				}
			}
		}
	}

	// Device tag verification, fully self-
	// contained within this same message (dp arrives already decrypted
	// from unseal, no network bootstrap): no async, no verifySig call.
	// Never a rejection: if device_sig doesn't verify against dp at
	// all, simply no tag is shown.
	var deviceTag string
	var deviceTagNew bool
	if isOwn {
		// For our own message dp is already the device public key we
		// signed with when sending (m.myDevicePub, line above in the
		// self-echo case), no cryptographic verification needed, same
		// reasoning already applied to the PQC tag below. Never a
		// deviceTagNew: it makes no sense to compare our own device
		// against a contact's "known device". The value helps whoever
		// rereads a saved chat later on, to recognize whether one of our
		// own messages was sent from a device other than the current
		// one (e.g. a lost or compromised device).
		if len(dp) == ed25519.PublicKeySize {
			devHex := fmt.Sprintf("%x", dp)
			if len(devHex) > 8 {
				devHex = devHex[len(devHex)-8:]
			}
			deviceTag = "DEV:" + devHex
		}
	} else if len(dp) == ed25519.PublicKeySize && deviceSigB64 != "" {
		if sigBytes, err := base64.StdEncoding.DecodeString(deviceSigB64); err == nil {
			if shared.VerifyDeviceSig(ed25519.PublicKey(dp), rawText, deviceTS, sigBytes) {
				devHex := fmt.Sprintf("%x", dp)
				if len(devHex) > 8 {
					devHex = devHex[len(devHex)-8:]
				}
				deviceTag = "DEV:" + devHex
				if contact := m.resolveContactByPub(memberKeyPub(fromKey)); contact != nil {
					if len(contact.KnownDevicePub) > 0 && !bytes.Equal(contact.KnownDevicePub, dp) {
						deviceTagNew = true
					}
					if !bytes.Equal(contact.KnownDevicePub, dp) {
						contact.KnownDevicePub = dp
						if m.onContactDevicePub != nil {
							_ = m.onContactDevicePub(contact.IdentityPub, dp)
						}
					}
				}
			}
		}
	}

	// PQC tag status (hybrid network identity, optional per-room ML-DSA-65
	// signature), always shown (green/red, never omitted, see
	// chatLine.pqcActive). For our own message it's enough that pqc_sig
	// was in the frame at send time (no verification needed, it's
	// ours); for someone else's message, self-contained like deviceTag
	// (no bootstrap/keyserver) but with the public key coming from
	// Contact.MLDSAPub, not from the message itself, a contact not yet
	// known or without MLDSAPub can never verify, so it shows red even
	// if the sender really did sign.
	pqcSigB64, _ := mm["pqc_sig"].(string)
	pqcTS, _ := mm["pqc_ts"].(string)
	var pqcActive bool
	if isOwn {
		pqcActive = pqcSigB64 != ""
	} else if pqcSigB64 != "" {
		if contact := m.resolveContactByPub(memberKeyPub(fromKey)); contact != nil && len(contact.MLDSAPub) == mldsa65.PublicKeySize {
			if sigBytes, err := base64.StdEncoding.DecodeString(pqcSigB64); err == nil {
				var pubArr [mldsa65.PublicKeySize]byte
				copy(pubArr[:], contact.MLDSAPub)
				var pub mldsa65.PublicKey
				pub.Unpack(&pubArr)
				pqcActive = shared.VerifyPQCSig(&pub, rawText, pqcTS, sigBytes)
			}
		}
	}

	line := &chatLine{
		username:            from,
		fromKey:             fromKey,
		text:                text,
		rawText:             rawText,
		timestamp:           ts,
		contentKeyTag:       contentKeyTag,
		contentKeyEphemeral: contentKeyEphemeral,
		sigStatus:           status,
		deviceTag:           deviceTag,
		deviceTagNew:        deviceTagNew,
		pqcActive:           pqcActive,
		msgSeq:              mseq,
		gseq:                gseq,
		replyTo:             replyTo,
	}
	if isOwn && msgID != 0 {
		line.msgID = msgID // tracks ACKs only for our own messages
	}

	return line, tea.Batch(deliveryAcks(tab, msgID, gseq, fromUserID, selfEcho, isOwn)...)
}

// deliveryAcks confirms a processed broadcast message: a msg_ack to its
// sender for someone else's message. For our own self-echo (a cache hit
// on TakeSentText, never just "isOwn", a sibling device of our own
// identity decrypted via DecryptMsg would have isOwn=true without being
// our own send) it is the server's pickup
// (roomDelivery.Dispatch), never a separate frame: frees client-side
// backpressure right away, then confirms to the server (self_relay_ack)
// that it can remove the entry from its own queue.
func deliveryAcks(tab *roomTab, msgID, gseq uint64, fromUserID string, selfEcho, isOwn bool) []tea.Cmd {
	var cmds []tea.Cmd
	if !isOwn && fromUserID != "" && msgID != 0 {
		cli, ctx := tab.cli, tab.ctx
		cmds = append(cmds, func() tea.Msg {
			_ = cli.SendMsgAck(ctx, fromUserID, msgID)
			return nil
		})
	}
	if selfEcho && msgID != 0 && gseq != 0 && tab.cli != nil {
		tab.cli.HandleServerAck(msgID, gseq)
		cli, ctx := tab.cli, tab.ctx
		cmds = append(cmds, func() tea.Msg {
			_ = cli.SendSelfRelayAck(ctx, msgID)
			return nil
		})
	}
	return cmds
}

// applyGroupMemberAdded validates and applies a "\x00GM\x00" announcement (see
// groupMemberAddedPrefix): accepted only if the sender authenticated at the WS
// session level (LookupMemberKey(fromUserID), not the self-declared "from" field
// in the encrypted payload) is tab.hostKey, any other sender is silently
// dropped, because only the host can change the group's trusted composition.
// Idempotent: if the member is already in tab.groupMembers (redelivery/reconnection),
// does nothing. Returns nil when there's nothing to show in chat.
func (m *model) applyGroupMemberAdded(tab *roomTab, fromUserID, ts, payloadJSON string) *chatLine {
	if tab.hostKey == "" || tab.cli.LookupMemberKey(fromUserID) != tab.hostKey {
		client.Dbg("grp-add-member: announcement discarded, sender %s is not the host", client.ShortUID(fromUserID))
		return nil
	}
	var payload groupMemberAddedPayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil || len(payload.Member.IdentityPub) != ed25519.PublicKeySize {
		return nil
	}
	for _, mb := range tab.groupMembers {
		if bytes.Equal(mb.IdentityPub, payload.Member.IdentityPub) {
			return nil // already present
		}
	}
	added := GroupMember{
		Username:    payload.Member.Username,
		IdentityPub: ed25519.PublicKey(payload.Member.IdentityPub),
	}
	tab.groupMembers = append(tab.groupMembers, added)
	tab.setMemberLabel(memberKey(added), added.Username)
	displayName := m.memberName(tab, memberKey(added))
	if c := m.resolveContactByPub(added.IdentityPub); c != nil {
		displayName = c.NameWithUsername()
	}
	return &chatLine{isSystem: true, timestamp: ts,
		text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.member_added_notice"), displayName))}
}

// applyPQCToggleAnnounce interprets a "\x00PQ\x00" announcement (see
// pqcToggleAnnouncePrefix): a system line visible to all members, no
// state action beyond display, each message's PQC status is already
// readable from its own per-message chatLine.pqcActive, this
// announcement only notifies of the CHANGE at the moment it happens.
func applyPQCToggleAnnounce(from, ts, payloadJSON string) *chatLine {
	var payload pqcToggleAnnouncePayload
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		return nil
	}
	key := "tui.pqc_sign_announce_off"
	if payload.On {
		key = "tui.pqc_sign_announce_on"
	}
	return &chatLine{isSystem: true, timestamp: ts,
		text: styleMeta.Render(fmt.Sprintf(i18n.T(key), from))}
}

// ── commands ───────────────────────────────────────────────────────────────────

// postWithRetry sends an HTTP POST with up to 3 attempts and backoff.
// The delays are needed because Tor takes 30-90s to build a new circuit
// toward an .onion after the previous one has expired. Separate from
// postKnockWithRetry so standalone functions (e.g. sendDangerAckMsg)
// running as detached goroutines with no access to the model can use it.
func postWithRetry(ctx context.Context, httpCli *http.Client, url, payload string, retryDelay time.Duration) (*http.Response, error) {
	var lastErr error
	for i := 1; i <= 3; i++ {
		resp, err := httpCli.Post(url, "text/plain", strings.NewReader(payload))
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if i == 3 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
		retryDelay *= 2
	}
	return nil, lastErr
}

// postKnockWithRetry sends an HTTP knock over the active transport (Tor
// or I2P) with up to 3 attempts and backoff. The delays are needed
// because building a new circuit/tunnel toward the contact's network
// address after the previous one expired can take time (on Tor, typically 30-90s).
func (m model) postKnockWithRetry(ctx context.Context, httpCli *http.Client, url, payload string) (*http.Response, error) {
	return postWithRetry(ctx, httpCli, url, payload, m.knockRetryDelay)
}

// dialWithRetry performs a dial over the active transport (Tor or I2P)
// with up to maxAttempts attempts and backoff, same pattern as
// postWithRetry applied to the simple reachability probe (TCP on :80):
// a single attempt can land in the wrong window of circuit/tunnel
// construction even when the other side's hidden service/destination
// descriptor is already published, otherwise forcing the user to rerun
// /active by hand several times before a contact shows as online.
// maxAttempts <= 0 is equivalent to 1 (no retry). Still bounded by the
// caller's ctx (probe_contacts_timeout).
func dialWithRetry(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, addr string, retryDelay time.Duration, maxAttempts int) (net.Conn, error) {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		conn, err := dial(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if i == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
		retryDelay *= 2
	}
	return nil, lastErr
}

// relKeysResolver builds the resolver to pass to m.addRoom/
// m.replaceRoomSecret (RoomRegistry): called on every handshake
// verification, never cached, always reads the current state of
// identityPub/devicePub (TUIParams.ResolveRelKeysForDevice, in practice
// keystore.Keystore.RelKeysForDevice), never a snapshot taken at invite
// time. identityPub/devicePub are copied by value: they stay stable
// even if the caller mutates its own backing array.
func (m *model) relKeysResolver(identityPub, devicePub []byte) func() (shared.RelPeerKey, shared.RelSigningKey, bool) {
	resolve := m.resolveRelKeysForDevice
	idPub := append(ed25519.PublicKey(nil), identityPub...)
	devPub := append([]byte(nil), devicePub...)
	return func() (shared.RelPeerKey, shared.RelSigningKey, bool) {
		if resolve == nil {
			return shared.RelPeerKey{}, shared.RelSigningKey{}, false
		}
		return resolve(idPub, devPub)
	}
}

// selfRelKeysResolver builds a resolver with a FIXED value, used for
// the host's self-registration toward itself (an ephemeral pair
// generated once for the room's lifetime, never a relationship with a
// contact: no state to resolve again).
func selfRelKeysResolver(pub ed25519.PublicKey, mldsaPub []byte, key shared.RelSigningKey) func() (shared.RelPeerKey, shared.RelSigningKey, bool) {
	peerKey := shared.RelPeerKey{Pub: pub, MLDSAPub: mldsaPub}
	return func() (shared.RelPeerKey, shared.RelSigningKey, bool) { return peerKey, key, true }
}

// cmdInvite creates a new group, connects locally, sends an invite to all recipients.
func (m *model) cmdInvite(args string) tea.Cmd {
	names := strings.Fields(args)
	if len(names) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_invite")))
	}

	// Builds the member list (including myself)
	members := []GroupMember{{Username: m.myUsername, IdentityPub: m.myIdentityPub}}
	var missing, ambiguous []string
	var pending [][]byte
	invited := make([]*ContactInfo, 0, len(names))
	for _, name := range names {
		c, n := m.resolveContactArg(name)
		if n > 1 {
			ambiguous = append(ambiguous, name)
			continue
		}
		if c == nil {
			missing = append(missing, name)
			continue
		}
		if slices.ContainsFunc(members, func(gm GroupMember) bool { return bytes.Equal(gm.IdentityPub, c.IdentityPub) }) {
			continue
		}
		// Relationship key exchange not yet complete (contact added
		// recently, or never reached due to unreachability), better a
		// clear error here than proceeding with a handshake doomed to
		// fail. ReadyDevices(): a contact is invitable if it has AT
		// LEAST one ready device, the invite then extends to all known
		// ones (fan-out), not just the first.
		if len(c.ReadyDevices()) == 0 {
			pending = append(pending, c.IdentityPub)
			continue
		}
		members = append(members, GroupMember{Username: c.Username, IdentityPub: c.IdentityPub})
		invited = append(invited, c)
	}
	if len(ambiguous) > 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_contact_ambiguous"), strings.Join(ambiguous, ", "))))
	}
	if len(missing) > 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_contacts_not_found"), strings.Join(missing, ", "))))
	}
	if len(pending) > 0 {
		// Never a flat error: the invite restarts on its own as soon as
		// ALL pending contacts confirm both relationship keys
		// (retryPendingInvites, called from applyRelInit).
		origArgs := args
		return m.queuePendingInvite(i18n.CommandName(client.CmdInvite), pending, func(m *model) tea.Cmd { return m.cmdInvite(origArgs) })
	}
	client.Dbg("cmdInvite: members resolved at %s", shared.Now())

	groupIDBytes, err := shared.RandomBytes(4)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_group_id_gen")))
	}
	groupID := fmt.Sprintf("%x", groupIDBytes)

	hostSecret, err := shared.RandomBytes(32)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_secret_gen")))
	}

	// The host's connection to its OWN local server (loopback), no real
	// contact involved, pure self-authentication: an ad-hoc ephemeral
	// pair, never persisted, used both to sign ClientHello.Sig
	// (mySigningKey in client.New) and to verify it (peerKey in addRoom).
	selfKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_secret_gen")))
	}
	selfPub, _, selfMLDSAPub, err := shared.RelSigningKeyPublicParts(selfKey)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_secret_gen")))
	}
	m.addRoom(groupID, hostSecret, m.myUsername, m.myIdentityPub, m.myDevicePub, selfRelKeysResolver(ed25519.PublicKey(selfPub), selfMLDSAPub, selfKey))
	client.Dbg("cmdInvite: host addRoom done at %s", shared.Now())

	// ratchetDH (Diffie-Hellman mix on every message, PCS beyond mere
	// forward secrecy) activates only for rooms with exactly two
	// members, host + one invitee. For N>2 it stays pure SenderKey:
	// pairwise DH makes no sense beyond 2 parties.
	cli := client.New(m.localHost, m.localPort, m.myUsername, hostSecret, len(members) == 2, m.myDevicePub, m.signDeviceSig, m.signPQCSig, selfKey, shared.RelPeerKey{Pub: ed25519.PublicKey(selfPub), MLDSAPub: selfMLDSAPub})
	cli.SetPendingLimits(m.pendingSlotLimit, m.messageRetryDelay, m.pendingEscalationAge, m.messageTTL)
	client.Dbg("cmdInvite: client New() done at %s", shared.Now())

	// List of recipients to invite (excluding myself), with an
	// individual secret for EACH device of each contact, never shared
	// between different devices (fan-out): whoever invites doesn't pick
	// a specific device, the invite extends to all ready ones
	// (ReadyDevices()). Each secret must be registered right away on
	// our own server (m.addRoom), not just sent in the knock, otherwise
	// that device could never authenticate. netAddr is the address
	// declared by the device itself (dev.Address), not the contact's
	// root address, an additional device never listens on the latter.
	type target struct {
		netAddr     string
		identityPub ed25519.PublicKey
		mlkemPub    []byte
		username    string
		secret      []byte
	}
	targets := make([]target, 0, len(names))
	secretsByMember := map[string]map[string][]byte{m.myKey(): {"": hostSecret}}
	for _, c := range invited {
		devs := c.ReadyDevices()
		if len(devs) == 0 {
			continue // already excluded above (pending), defense in depth
		}
		perDevice := make(map[string][]byte, len(devs))
		for devKey, dev := range devs {
			tSecret, err := shared.RandomBytes(32)
			if err != nil {
				return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_secret_gen_for"), c.Username)))
			}
			// peerKey = the per-relationship IdentityKey this device
			// declared toward us (verifies ClientHello.Sig when it
			// connects); mySigningKey = OUR own toward it (signs
			// ServerHello.Sig), both already established by the
			// rel_init/rel_init_ack cycle, never exchanged here.
			m.addRoom(groupID, tSecret, c.Username, c.IdentityPub, []byte(devKey), m.relKeysResolver(c.IdentityPub, []byte(devKey)))
			perDevice[devKey] = tSecret
			targets = append(targets, target{dev.Address, c.IdentityPub, c.MLKEMPub, c.Username, tSecret})
		}
		secretsByMember[client.MemberKeyOf(c.IdentityPub)] = perDevice
	}
	client.Dbg("cmdInvite: targets ready (%d) at %s", len(targets), shared.Now())

	invitedKeys := make([]string, 0, len(members)-1)
	for _, mb := range members[1:] {
		invitedKeys = append(invitedKeys, memberKey(mb))
	}

	ctx, cancel := context.WithCancel(context.Background())
	newTab := &roomTab{
		name:            groupID,
		cli:             cli,
		ctx:             ctx,
		cancel:          cancel,
		lines:           []chatLine{{isSystem: true, text: fmt.Sprintf(i18n.T("tui.creating_group"), groupID)}},
		groupID:         groupID,
		groupMembers:    members,
		roomSecret:      hostSecret,
		hostKey:         m.myKey(),
		secretsByMember: secretsByMember,
		invitedKeys:     invitedKeys,
	}
	newTab.setGroupLabels()
	idx := len(m.tabs)
	m.tabs = append(m.tabs, newTab)
	m.active = idx
	m.refreshViewport()
	client.Dbg("cmdInvite: tab created and refreshViewport done at %s", shared.Now())

	// Builds MemberInfo for the payload
	memberInfos := make([]shared.MemberInfo, len(members))
	for i, mb := range members {
		memberInfos[i] = shared.MemberInfo{Username: mb.Username, IdentityPub: mb.IdentityPub}
	}

	myAddr := m.myAddr
	myUsername := m.myUsername
	myIdentityPub := m.myIdentityPub
	dhTagFn := m.dhTagFn
	dialTor := m.dialTor
	gid := groupID
	inviteTO := m.inviteTimeout

	// connectCmd ONLY does the local cli.Connect(ctx) and immediately
	// returns roomConnectedMsg, which starts waitForRoom, THIS
	// connection's read loop. Sending knocks to the invitees (knocksCmd
	// below) is deliberately a SEPARATE tea.Cmd, run in parallel via
	// tea.Batch, not chained before the return: the websocket library
	// (coder/websocket, conn.go: Ping's doc) is explicit: "Ping must be
	// called concurrently with Reader [...] it [...] waits for a Reader
	// call to read the pong", the server's periodic ping toward THIS
	// same connection (ws.go, every pingInterval=30s, timeout
	// pingInterval/2=15s) never gets a response until someone calls
	// Read client-side; the server cancels the connection's context at
	// expiry and (conn.go: setupReadTimeout/context.AfterFunc) closes
	// the socket, the host's connection would die BEFORE
	// roomConnectedMsg/waitForRoom even start, for a reason that has
	// nothing to do with failed knocks or network issues: simply nobody
	// was reading it yet.
	connectCmd := func() tea.Msg {
		if err := cli.Connect(ctx); err != nil {
			return roomErrMsg{idx: idx, err: fmt.Errorf(i18n.T("tui.err_local_connection"), err)}
		}
		return roomConnectedMsg{idx: idx}
	}
	knocksCmd := func() tea.Msg {
		if dialTor != nil {
			var wg sync.WaitGroup
			for _, t := range targets {
				payload, err := encryptKnockTagged(dhTagFn, t.identityPub, t.mlkemPub, shared.KnockPayload{
					FromUsername:    myUsername,
					FromIdentityPub: myIdentityPub,
					RoomSecret:      t.secret,
					FromAddr:        myAddr,
					GroupID:         gid,
					Members:         memberInfos,
				})
				if err != nil {
					continue
				}
				wg.Add(1)
				go func(netAddr, payload string) {
					defer wg.Done()
					httpCli := &http.Client{
						Transport: &http.Transport{DialContext: dialTor},
						Timeout:   inviteTO,
					}
					resp, err := m.postKnockWithRetry(ctx, httpCli, "http://"+netAddr+"/knock", payload)
					if err == nil {
						io.Copy(io.Discard, resp.Body) //nolint:errcheck
						resp.Body.Close()
					}
				}(t.netAddr, payload)
			}
			wg.Wait()
		}
		return nil
	}
	// groupNoJoinTimeout: if by then no invitee has joined yet, prompts
	// the host, see groupNoJoinTimeoutMsg/queueGroupNoJoinPrompt.
	return tea.Batch(connectCmd, knocksCmd, tea.Tick(groupNoJoinTimeout, func(time.Time) tea.Msg {
		return groupNoJoinTimeoutMsg{idx: idx, groupID: gid}
	}))
}

// cmdRecall reopens a saved group: a new ephemeral secret, a new invite to all members.
func (m *model) cmdRecall(nameOrID string) tea.Cmd {
	var found *GroupInfo
	for i := range m.savedGroups {
		if m.savedGroups[i].LocalName == nameOrID || m.savedGroups[i].GroupID == nameOrID {
			found = &m.savedGroups[i]
			break
		}
	}
	if found == nil {
		return m.openPicker(client.CmdRecall, nameOrID)
	}

	hostSecret, err := shared.RandomBytes(32)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_secret_gen")))
	}

	gid := found.GroupID
	members := found.Members

	// Same as cmdInvite: no saved member can be recalled if the
	// relationship key exchange isn't (no longer) complete toward them.
	// ReadyDevices(): AT LEAST one ready device is enough, the invite
	// then extends to all known ones (fan-out).
	var missing [][]byte
	for _, mb := range members {
		if memberKey(mb) == m.myKey() {
			continue
		}
		c := m.resolveContactByPub(mb.IdentityPub)
		if c == nil || len(c.ReadyDevices()) == 0 {
			missing = append(missing, mb.IdentityPub)
		}
	}
	if len(missing) > 0 {
		// Same logic as cmdInvite, queues instead of failing outright.
		origNameOrID := nameOrID
		return m.queuePendingInvite(i18n.CommandName(client.CmdRecall), missing, func(m *model) tea.Cmd { return m.cmdRecall(origNameOrID) })
	}

	selfKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_secret_gen")))
	}
	selfPub, _, selfMLDSAPub, err := shared.RelSigningKeyPublicParts(selfKey)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_secret_gen")))
	}
	m.addRoom(gid, hostSecret, m.myUsername, m.myIdentityPub, m.myDevicePub, selfRelKeysResolver(ed25519.PublicKey(selfPub), selfMLDSAPub, selfKey))

	// A new secret for each DEVICE of each saved member, never shared
	// (fan-out, like cmdInvite), whoever stayed connected with an old
	// secret (from a previous, not-yet-ended session) still stays on
	// the same roomID, hence the same hub. richTarget carries the
	// DEVICE's address (dev.Address), not the contact's root one, see
	// cmdInvite for why.
	type richTarget struct {
		netAddr     string
		identityPub ed25519.PublicKey
		mlkemPub    []byte
		username    string
		secret      []byte
	}
	var targets []richTarget
	secretsByMember := map[string]map[string][]byte{m.myKey(): {"": hostSecret}}
	for _, mb := range members {
		if memberKey(mb) == m.myKey() {
			continue
		}
		c := m.resolveContactByPub(mb.IdentityPub)
		devs := c.ReadyDevices()
		if len(devs) == 0 {
			continue // already excluded above (missing), defense in depth
		}
		perDevice := make(map[string][]byte, len(devs))
		for devKey, dev := range devs {
			s, err := shared.RandomBytes(32)
			if err != nil {
				return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_secret_gen_for"), mb.Username)))
			}
			m.addRoom(gid, s, mb.Username, mb.IdentityPub, []byte(devKey), m.relKeysResolver(mb.IdentityPub, []byte(devKey)))
			perDevice[devKey] = s
			targets = append(targets, richTarget{dev.Address, mb.IdentityPub, c.MLKEMPub, mb.Username, s})
		}
		secretsByMember[memberKey(mb)] = perDevice
	}

	// ratchetDH: see note in cmdInvite, active only for saved groups with exactly two members.
	cli := client.New(m.localHost, m.localPort, m.myUsername, hostSecret, len(members) == 2, m.myDevicePub, m.signDeviceSig, m.signPQCSig, selfKey, shared.RelPeerKey{Pub: ed25519.PublicKey(selfPub), MLDSAPub: selfMLDSAPub})
	cli.SetPendingLimits(m.pendingSlotLimit, m.messageRetryDelay, m.pendingEscalationAge, m.messageTTL)

	invitedKeys := make([]string, 0, len(members))
	for _, mb := range members {
		if memberKey(mb) != m.myKey() {
			invitedKeys = append(invitedKeys, memberKey(mb))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	newTab := &roomTab{
		name:            found.LocalName,
		cli:             cli,
		ctx:             ctx,
		cancel:          cancel,
		lines:           []chatLine{{isSystem: true, text: fmt.Sprintf(i18n.T("tui.reopening_group"), found.LocalName)}},
		groupID:         gid,
		groupMembers:    members,
		roomSecret:      hostSecret,
		hostKey:         m.myKey(),
		secretsByMember: secretsByMember,
		invitedKeys:     invitedKeys,
	}
	newTab.setGroupLabels()
	idx := len(m.tabs)
	m.tabs = append(m.tabs, newTab)
	m.active = idx
	m.refreshViewport()

	memberInfos := make([]shared.MemberInfo, len(members))
	for i, mb := range members {
		memberInfos[i] = shared.MemberInfo{Username: mb.Username, IdentityPub: mb.IdentityPub}
	}

	myAddr := m.myAddr
	myUsername := m.myUsername
	myIdentityPub := m.myIdentityPub
	dhTagFn := m.dhTagFn
	dialTor := m.dialTor
	inviteTO2 := m.inviteTimeout

	// connectCmd/knocksCmd separate: see the extended note in cmdInvite
	// combining them into one function (with roomConnectedMsg
	// returned only after sending ALL knocks) would leave the host's
	// read loop stalled long enough for the server to kill it over an
	// unanswered ping, before it had ever started reading. knocksCmd
	// sends in parallel (same scheme as cmdInvite), a slow/unreachable
	// device must not delay the fan-out's other knocks.
	connectCmd := func() tea.Msg {
		if err := cli.Connect(ctx); err != nil {
			return roomErrMsg{idx: idx, err: fmt.Errorf(i18n.T("tui.err_local_connection"), err)}
		}
		return roomConnectedMsg{idx: idx}
	}
	knocksCmd := func() tea.Msg {
		if dialTor != nil {
			var wg sync.WaitGroup
			for _, t := range targets {
				payload, err := encryptKnockTagged(dhTagFn, t.identityPub, t.mlkemPub, shared.KnockPayload{
					FromUsername:    myUsername,
					FromIdentityPub: myIdentityPub,
					RoomSecret:      t.secret,
					FromAddr:        myAddr,
					GroupID:         gid,
					Members:         memberInfos,
				})
				if err != nil {
					continue
				}
				wg.Add(1)
				go func(netAddr, payload string) {
					defer wg.Done()
					httpCli := &http.Client{
						Transport: &http.Transport{DialContext: dialTor},
						Timeout:   inviteTO2,
					}
					resp, err := m.postKnockWithRetry(ctx, httpCli, "http://"+netAddr+"/knock", payload)
					if err == nil {
						io.Copy(io.Discard, resp.Body) //nolint:errcheck
						resp.Body.Close()
					}
				}(t.netAddr, payload)
			}
			wg.Wait()
		}
		return nil
	}
	// groupNoJoinTimeout: see note in cmdInvite.
	return tea.Batch(connectCmd, knocksCmd, tea.Tick(groupNoJoinTimeout, func(time.Time) tea.Msg {
		return groupNoJoinTimeoutMsg{idx: idx, groupID: gid}
	}))
}

// cmdJoin accepts a pending group invite (looked up by GroupID).
func (m *model) cmdJoin(groupID string) tea.Cmd {
	client.Dbg("cmdJoin: called for groupID=%s (pendingKnocks=%d)", groupID, len(m.pendingKnocks))
	var knock *pendingKnock
	for i := range m.pendingKnocks {
		if m.pendingKnocks[i].GroupID == groupID {
			k := m.pendingKnocks[i]
			knock = &k
			m.pendingKnocks = append(m.pendingKnocks[:i], m.pendingKnocks[i+1:]...)
			break
		}
	}
	if knock == nil {
		client.Dbg("cmdJoin: no pendingKnock for groupID=%s, opening the picker", groupID)
		return m.openPicker(client.CmdJoin, groupID)
	}
	client.Dbg("cmdJoin: pendingKnock found, host=%s", knock.FromUsername)
	return m.joinKnock(*knock)
}

// hostReadyForJoin reports the relationship keys toward the contact with
// identity key hostPub (the host of an incoming invite) if they're already enough to build the
// connection, a WEAKER condition than ReadyDevices() (the one used by
// cmdInvite for the opposite direction): here OUR OWN RelIdentityPriv
// (generated right away by AddContact) and THEIR PeerRelIdentityPub,
// known as soon as even a single rel_init/rel_init_ack arrives, are
// enough, regardless of RelIdentityConfirmedByPeer, which only says
// whether THEY already have ours, irrelevant to our ability to connect.
func (m *model) hostReadyForJoin(hostPub []byte) (*keystore.DeviceRelation, bool) {
	c := m.resolveContactByPub(hostPub)
	if c == nil {
		client.Dbg("hostReadyForJoin: contact %s not in the address book", keyFingerprint(client.MemberKeyOf(hostPub)))
		return nil, false
	}
	username := c.Username
	if len(c.Devices) == 0 {
		client.Dbg("hostReadyForJoin: %s has no device", username)
		return nil, false
	}
	// A contact can legitimately have more than one device (phone +
	// laptop, or several processes with the same identity): requiring
	// SoleDevice() here would block the join forever as soon as a
	// contact had a second one, regardless of which device actually
	// invited. Deterministic ordering on the keys (like sortedDeviceKeys
	// in the keystore) for a stable choice across successive runs.
	keys := make([]string, 0, len(c.Devices))
	for k := range c.Devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dev := c.Devices[k]
		if dev != nil && len(dev.RelIdentityPriv) > 0 && len(dev.PeerRelIdentityPub) > 0 {
			return dev, true
		}
	}
	client.Dbg("hostReadyForJoin: %s has %d devices, none with ready keys", username, len(c.Devices))
	return nil, false
}

// joinKnock builds the connection toward the room described by knock,
// if hostReadyForJoin already allows it, otherwise queues the
// acceptance in m.pendingJoins (queuePendingJoin), exactly like
// queuePendingInvite does for the opposite direction in cmdInvite.
func (m *model) joinKnock(knock pendingKnock) tea.Cmd {
	groupID := knock.GroupID
	hostDev, ok := m.hostReadyForJoin(knock.FromIdentityPub)
	if !ok {
		client.Dbg("joinKnock: host=%s not ready, queued in pendingJoins", knock.FromUsername)
		return m.queuePendingJoin(knock)
	}
	client.Dbg("joinKnock: host=%s ready, connecting to %s groupID=%s", knock.FromUsername, knock.FromAddr, groupID)

	members := make([]GroupMember, len(knock.Members))
	for i, mi := range knock.Members {
		members[i] = GroupMember{Username: mi.Username, IdentityPub: mi.IdentityPub}
	}

	// Uses the saved local name if it exists, otherwise shows the GroupID
	tabName := groupID
	for _, sg := range m.savedGroups {
		if sg.GroupID == groupID {
			tabName = sg.LocalName
			break
		}
	}

	mySigningKey := shared.RelSigningKey{Priv: hostDev.RelIdentityPriv, MLKEMSeed: hostDev.RelIdentityMLKEMPriv, MLDSASeed: hostDev.RelIdentityMLDSAPriv}
	hostKey := shared.RelPeerKey{Pub: ed25519.PublicKey(hostDev.PeerRelIdentityPub), MLDSAPub: hostDev.PeerRelIdentityMLDSAPub}
	// ratchetDH: see note in cmdInvite, active only if the invite is for exactly two members.
	cli := client.New(knock.FromAddr, 80, m.myUsername, knock.RoomSecret, len(members) == 2, m.myDevicePub, m.signDeviceSig, m.signPQCSig, mySigningKey, hostKey)
	cli.SetPendingLimits(m.pendingSlotLimit, m.messageRetryDelay, m.pendingEscalationAge, m.messageTTL)
	// ctx/cancel created here because isolatedDialer needs a ctx for
	// its own construction, see TUIParams.IsolatedDialer.
	ctx, cancel := context.WithCancel(context.Background())
	dialFn := m.dialTor
	if m.isolatedDialer != nil {
		dialFn = m.isolatedDialer(ctx, groupID) // dedicated circuit for this group
	}
	if dialFn != nil {
		cli.SetDialer(dialFn)
	}

	newTab := &roomTab{
		name:         tabName,
		cli:          cli,
		ctx:          ctx,
		cancel:       cancel,
		lines:        []chatLine{{isSystem: true, text: fmt.Sprintf(i18n.T("tui.connecting_group_tor"), groupID)}},
		groupID:      groupID,
		groupMembers: members,
		hostKey:      client.MemberKeyOf(knock.FromIdentityPub),
		awaitingJoin: true,
	}
	newTab.setGroupLabels()
	idx := len(m.tabs)
	m.tabs = append(m.tabs, newTab)
	m.active = idx
	m.refreshViewport()

	// The first connection over Tor/I2P can take several seconds (I2P
	// especially), an "in progress" popup prevents the TUI from
	// looking stuck right after pressing Enter. Closes itself on
	// roomConnectedMsg/roomErrMsg (see awaitingJoin); any key dismisses
	// it earlier too, but the connection still continues in the background.
	m.textPopupMode = true
	m.textPopupContent = i18n.T("tui.group_join_connecting_popup")

	return func() tea.Msg {
		if err := cli.ConnectWithRetry(ctx, 3, nil); err != nil {
			return roomErrMsg{idx: idx, err: fmt.Errorf(i18n.T("tui.err_group_connection"), err)}
		}
		return roomConnectedMsg{idx: idx}
	}
}

// queuePendingJoin queues a received invite that isn't yet acceptable
// (see joinKnock), same scheme as queuePendingInvite: announces the
// wait in Console, immediately triggers a probe cycle (never a blind
// wait until the next tick), and leaves it to retryPendingJoins to
// retry as soon as hostReadyForJoin(knock.FromIdentityPub) turns true.
func (m *model) queuePendingJoin(knock pendingKnock) tea.Cmd {
	m.pendingJoins = append(m.pendingJoins, &pendingJoin{knock: knock, deadline: time.Now().Add(m.inviteTimeout)})
	notice := styleMeta.Render(fmt.Sprintf(i18n.T("tui.err_contact_rel_keys_pending"), knock.FromUsername))
	return tea.Batch(localTab(m.consoleIdx, notice), m.cmdActiveSilent())
}

// retryPendingJoins checks whether the contact with identity key
// hostPub (the host of one or more queued invites) is now ready
// (hostReadyForJoin) and, for each one, retries joinKnock, called from
// applyRelInit, like retryPendingInvites for the opposite direction.
func (m *model) retryPendingJoins(hostPub []byte) tea.Cmd {
	if len(m.pendingJoins) == 0 {
		return nil
	}
	if _, ok := m.hostReadyForJoin(hostPub); !ok {
		return nil
	}
	client.Dbg("retryPendingJoins: host=%s ready, %d pendingJoins queued", keyFingerprint(client.MemberKeyOf(hostPub)), len(m.pendingJoins))
	var cmds []tea.Cmd
	remaining := m.pendingJoins[:0]
	for _, pj := range m.pendingJoins {
		if bytes.Equal(pj.knock.FromIdentityPub, hostPub) {
			cmds = append(cmds, m.joinKnock(pj.knock))
			continue
		}
		remaining = append(remaining, pj)
	}
	m.pendingJoins = remaining
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

// blockingModalActive reports true if any exclusive mode occupying the
// keyboard is currently active, the same list of `if m.xMode {...}`
// flags checked at the top of Update()'s tea.KeyMsg case. Used only by
// showNextInviteModal to avoid stealing subsequent keys from an
// operation already in progress (e.g. entering a password, a safety
// confirmation): an invite arriving at that moment stays queued until
// the user finishes it. showPalette/debugMode aren't part of it:
// showPalette doesn't consume free text (only arrows/Enter/Esc, no real
// conflict) and debugMode is a simple state toggle, not a popup that
// intercepts keys.
func (m *model) blockingModalActive() bool {
	return m.quitMode || m.pwdMode != 0 || m.addContactMode ||
		m.addContactConfirmMode ||
		m.editContactMode || m.sendContactHintMode || m.backupMode || m.textPopupMode ||
		m.verifySafetyConfirmMode ||
		m.helpMode || m.sendFileMode || m.sendFileRecipientsMode ||
		m.invitePickerMode || m.pingPickerMode || m.sendFilePresetMode || m.fileOfferMode || m.showQRFormatMode ||
		m.saveRenameMode || m.saveDirMode || m.contactPickerMode ||
		m.qrChooseMode || m.qrFileMode || m.qrCameraPreviewMode || m.qrShowActive || m.groupNoJoinConfirmMode ||
		m.remoteNukePickerMode || m.remoteNukeConfirmMode || m.clearAllConfirmMode ||
		m.msgAcksPickerMode || m.msgAcksDetailMode
}

// showNextInviteModal promotes the first still-queued group invite
// (m.pendingKnocks, GroupID != "", knocks with GroupID=="" don't get
// a popup, they stay just an informational log in Console) to
// a modal popup, if no other popup is already open, see
// blockingModalActive. Must be called both when a new invite arrives
// (case knockMsg) and on every KeyMsg as long as nothing is blocking
// (the "self-healing" gate at the top of the tea.KeyMsg case): that way
// an invite arriving while the user was doing something else appears
// on its own as soon as that other operation ends, with no need to
// touch the ~20 exit points of the flags above one by one.
func (m *model) showNextInviteModal() {
	if m.inviteModalMode || m.blockingModalActive() {
		return
	}
	for i := range m.pendingKnocks {
		if m.pendingKnocks[i].GroupID != "" {
			k := m.pendingKnocks[i]
			m.inviteModalMode = true
			m.inviteModalKnock = &k
			client.Dbg("showNextInviteModal: popup shown for groupID=%s from=%s", k.GroupID, k.FromUsername)
			return
		}
	}
}

// showNextFileOfferModal promotes the first queued file_offer
// (m.pendingFileOffers) to a popup, if no other popup is already open
// same pattern as showNextInviteModal above, same reason: never write
// the fileOffer* fields directly from fileOfferMetaDecryptedMsg, always
// and only from here. Called both when new metadata finishes decrypting
// (case fileOfferMetaDecryptedMsg) and on every tea.Msg as long as
// nothing is blocking (the "self-healing" gate) and right after
// responding to an offer (accept/reject, in the same block): that way
// an offer arriving while the user was responding to another one (or
// doing anything else) appears on its own as soon as it's free.
func (m *model) showNextFileOfferModal() {
	if m.fileOfferMode || m.blockingModalActive() {
		return
	}
	for len(m.pendingFileOffers) > 0 {
		transferID := m.pendingFileOffers[0]
		m.pendingFileOffers = m.pendingFileOffers[1:]
		it := m.incomingTransfers[transferID]
		if it == nil {
			continue // expired/removed in the meantime (e.g. timeout), skip to the next one
		}
		m.fileOfferMode = true
		m.fileOfferTransferID = it.transferID
		m.fileOfferFromUserID = it.fromUserID
		m.fileOfferFromKey = it.fromKey
		m.fileOfferFileName = it.fileName
		m.fileOfferFileSize = it.fileSize
		m.fileOfferContentKeyKnown = m.contentRelEstablished(m.tabs[it.tabIdx], it.fromKey)
		m.fileOfferTabIdx = it.tabIdx
		return
	}
}

// ignoreInvite discards a group invite from the queue without accepting it.
func (m *model) ignoreInvite(groupID string) {
	for i := range m.pendingKnocks {
		if m.pendingKnocks[i].GroupID == groupID {
			m.pendingKnocks = append(m.pendingKnocks[:i], m.pendingKnocks[i+1:]...)
			return
		}
	}
}

// declineInvite notifies the host that the invite was rejected, fire-
// and-forget via /knock (same scheme as sendProbeAck
// below), encrypted toward the host's identity key already known from
// the received knock (k.FromIdentityPub/k.FromAddr). Without this, an
// Esc on the invite popup (ignoreInvite) would vanish silently: the
// host would have no way to distinguish "not seen yet" from "rejected",
// other than a silent timeout.
func (m *model) declineInvite(k *pendingKnock) tea.Cmd {
	if k == nil || k.FromAddr == "" || len(k.FromIdentityPub) == 0 {
		return nil
	}
	toAddr := k.FromAddr
	toPub := k.FromIdentityPub
	toMLKEMPub := m.mlkemPubForContact(toPub)
	groupID := k.GroupID
	myUsername := m.myUsername
	myPub := m.myIdentityPub
	dhTagFn := m.dhTagFn
	dialTor := m.dialTor
	retryDelay := m.knockRetryDelay
	timeout := m.inviteTimeout
	return func() tea.Msg {
		payload, err := encryptKnockTagged(dhTagFn, toPub, toMLKEMPub, shared.KnockPayload{
			Type:            "invite_declined",
			FromUsername:    myUsername,
			FromIdentityPub: myPub,
			GroupID:         groupID,
		})
		if err != nil {
			return nil
		}
		httpCli := &http.Client{Transport: &http.Transport{DialContext: dialTor}, Timeout: timeout}
		resp, err := postWithRetry(context.Background(), httpCli, "http://"+toAddr+"/knock", payload, retryDelay)
		if err != nil {
			return nil
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		return nil
	}
}

// queueGroupNoJoinPrompt queues (deduplicated) tab idx for the "nobody
// has accepted the invite yet, close the room?" popup, called both
// from a groupNoJoinTimeoutMsg and from an explicit decline that
// exhausts all invitees (case "invite_declined"). No effect if someone
// has already joined in the meantime (len(tab.online) > 1, including
// ourselves) or if it isn't a host tab (tab.invitedKeys empty for
// invited members' tabs).
func (m *model) queueGroupNoJoinPrompt(idx int) {
	if idx < 0 || idx >= len(m.tabs) {
		return
	}
	tab := m.tabs[idx]
	if tab.groupID == "" || len(tab.invitedKeys) == 0 || len(tab.online) > 1 {
		return
	}
	for _, p := range m.pendingNoJoinPrompts {
		if p == idx {
			return
		}
	}
	m.pendingNoJoinPrompts = append(m.pendingNoJoinPrompts, idx)
	m.showNextGroupNoJoinModal()
}

// showNextGroupNoJoinModal promotes the first queued tab
// (m.pendingNoJoinPrompts) to a confirmation popup, if no other popup
// is already open, same pattern as showNextInviteModal/
// showNextFileOfferModal. Called from the "self-healing" gate in the
// tea.KeyMsg case until the queue empties.
func (m *model) showNextGroupNoJoinModal() {
	if m.groupNoJoinConfirmMode || m.blockingModalActive() {
		return
	}
	for len(m.pendingNoJoinPrompts) > 0 {
		idx := m.pendingNoJoinPrompts[0]
		m.pendingNoJoinPrompts = m.pendingNoJoinPrompts[1:]
		if idx >= len(m.tabs) {
			continue
		}
		tab := m.tabs[idx]
		if tab.groupID == "" || len(tab.online) > 1 {
			continue // already resolved in the meantime (someone joined, or tab closed)
		}
		m.groupNoJoinConfirmMode = true
		m.groupNoJoinConfirmTabIdx = idx
		return
	}
}

// cmdReinvite resends the group invite to an offline member, using the current secret.
// Available only to the host (tab connected locally, not remotely).
func (m *model) cmdReinvite(name string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.groupID == "" || tab.cli == nil || tab.cli.IsRemote() {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_reinvite_host_only")))
	}
	if len(tab.roomSecret) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_room_secret_unavailable")))
	}
	if name == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_reinvite")))
	}

	// Finds the member in the group list, by key; a typed name that
	// matches no member, or more than one, opens the picker.
	found, n := m.resolveMemberArg(tab, name, func(gm GroupMember) bool { return memberKey(gm) != m.myKey() })
	if n != 1 {
		return m.openPicker(client.CmdReinvite, name)
	}
	target := &found

	// Prepares data for the knock
	memberInfos := make([]shared.MemberInfo, len(tab.groupMembers))
	for i, mb := range tab.groupMembers {
		memberInfos[i] = shared.MemberInfo{Username: mb.Username, IdentityPub: mb.IdentityPub}
	}

	myAddr := m.myAddr
	myUsername := m.myUsername
	myIdentityPub := m.myIdentityPub
	dhTagFn := m.dhTagFn
	dialTor := m.dialTor
	gid := tab.groupID
	targetMLKEMPub := m.mlkemPubForContact(target.IdentityPub)
	consoleIdx := m.consoleIdx
	displayName := m.memberName(tab, memberKey(*target))
	if c := m.resolveContactByPub(target.IdentityPub); c != nil {
		displayName = c.NameWithUsername()
	}
	inviteTO := m.inviteTimeout

	// ReadyDevices(): re-invites ALL of this member's ready devices, a
	// new secret for each one, never just one. The previous secret
	// stops authenticating, if the member had been invited before and
	// never connected, the old secret becomes unusable from that moment on.
	targetContact := m.resolveContactByPub(target.IdentityPub)
	var devs map[string]*keystore.DeviceRelation
	if targetContact != nil {
		devs = targetContact.ReadyDevices()
	}
	if targetContact == nil || len(devs) == 0 {
		// Same logic as cmdInvite, queues instead of failing flat. The
		// retry must rerun cmdReinvite on the SAME originating room
		// (tabIdx), not on m.active at retry time (the user may have
		// switched tabs in the meantime).
		origArg := memberPickerKey(*target)
		savedTabIdx := tabIdx
		return m.queuePendingInvite(i18n.CommandName(client.CmdReinvite), [][]byte{target.IdentityPub}, func(m *model) tea.Cmd {
			if savedTabIdx >= len(m.tabs) {
				return nil
			}
			prevActive := m.active
			m.active = savedTabIdx
			cmd := m.cmdReinvite(origArg)
			m.active = prevActive
			return cmd
		})
	}

	type reinviteTarget struct {
		netAddr string
		secret  []byte
	}
	var targets []reinviteTarget
	targetKey := memberKey(*target)
	oldSecrets := tab.secretsByMember[targetKey]
	if tab.secretsByMember == nil {
		tab.secretsByMember = make(map[string]map[string][]byte)
	}
	newSecrets := make(map[string][]byte, len(devs))
	for devKey, dev := range devs {
		newSecret, err := shared.RandomBytes(32)
		if err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_secret_gen_for"), displayName)))
		}
		m.replaceRoomSecret(gid, oldSecrets[devKey], newSecret, target.Username, target.IdentityPub, []byte(devKey), m.relKeysResolver(target.IdentityPub, []byte(devKey)))
		newSecrets[devKey] = newSecret
		targets = append(targets, reinviteTarget{dev.Address, newSecret})
	}
	tab.secretsByMember[targetKey] = newSecrets

	return func() tea.Msg {
		var lastErr error
		lastErrWasEncrypt := false
		sent := 0
		for _, t := range targets {
			client.Dbg("reinvite: to %s (%s), gid=%s, timeout=%s", displayName, t.netAddr, gid, inviteTO)
			payload, err := encryptKnockTagged(dhTagFn, target.IdentityPub, targetMLKEMPub, shared.KnockPayload{
				FromUsername:    myUsername,
				FromIdentityPub: myIdentityPub,
				RoomSecret:      t.secret,
				FromAddr:        myAddr,
				GroupID:         gid,
				Members:         memberInfos,
			})
			if err != nil {
				client.Dbg("reinvite: knock encryption failed: %v", err)
				lastErr, lastErrWasEncrypt = err, true
				continue
			}
			httpCli := &http.Client{
				Transport: &http.Transport{DialContext: dialTor},
				Timeout:   inviteTO,
			}
			resp, err := httpCli.Post("http://"+t.netAddr+"/knock", "application/octet-stream", strings.NewReader(payload))
			if err != nil {
				client.Dbg("reinvite: POST to %s failed: %v", t.netAddr, err)
				lastErr, lastErrWasEncrypt = err, false
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			client.Dbg("reinvite: POST to %s succeeded, status=%s", t.netAddr, resp.Status)
			sent++
		}
		if sent == 0 && lastErr != nil {
			if lastErrWasEncrypt {
				return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_reinvite_encrypt"), lastErr.Error())), isError: true}
			}
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_reinvite_failed"), displayName, lastErr.Error())), isError: true}
		}
		return localDisplayMsg{tabIdx: tabIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.invite_sent"), displayName))}
	}
}

// cmdBan (behind /grp-ban, host only) permanently removes a member from
// the current room: removes their secret from the RoomRegistry (they
// can no longer authenticate, unlike /grp-reinvite which generates a
// new one) and disconnects them if currently connected (m.banMember →
// RoomRegistry.RemoveSecret + KickMember, both in-process and
// synchronous: the same process as the host's server, no network call
// here, unlike cmdReinvite above). Stays in the room's roster, like a
// member who left/declined (memberBanned, gray), doesn't disappear: a
// ban is an event other members must be able to see happened, not a
// silent erasure.
func (m *model) cmdBan(name string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.groupID == "" || tab.cli == nil || tab.cli.IsRemote() {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ban_host_only")))
	}
	if name == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_ban")))
	}

	if pub, ok := decodePickerContactKey(name); ok && bytes.Equal(pub, m.myIdentityPub) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ban_self")))
	}
	target, n := m.resolveMemberArg(tab, name, func(gm GroupMember) bool { return memberKey(gm) != m.myKey() })
	if n != 1 {
		if n == 0 && strings.EqualFold(name, m.myUsername) {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ban_self")))
		}
		return m.openPicker(client.CmdBan, name)
	}
	targetKey := memberKey(target)
	secrets := tab.secretsByMember[targetKey]
	if len(secrets) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_room_secret_unavailable")))
	}

	displayName := m.memberName(tab, targetKey)
	if c := m.resolveContactByPub(target.IdentityPub); c != nil {
		displayName = c.NameWithUsername()
	}
	_, wasConnected := m.revokeMemberSecrets(tabIdx, targetKey)

	key := "tui.ban_done"
	if !wasConnected {
		key = "tui.ban_done_offline"
	}
	return localTab(tabIdx, styleMeta.Render(fmt.Sprintf(i18n.T(key), displayName)))
}

// revokeMemberSecrets revokes ALL secrets registered for the member
// with key memberKey in room tabIdx (one per device) and kicks its
// connected session, the core shared by /grp-ban (interactive, above)
// and the silent revocation triggered by /cnt-del (a contact deletion
// implies a ban from all chats). No effect if that member has no active
// secrets in that room (secretsByMember only lives in the host tab, so a
// non-host tab or one without that member returns removed=false with
// no mutation).
func (m *model) revokeMemberSecrets(tabIdx int, memberKey string) (removed bool, wasConnected bool) {
	tab := m.tabs[tabIdx]
	secrets := tab.secretsByMember[memberKey]
	if len(secrets) == 0 {
		return false, false
	}
	var userID string
	if tab.cli != nil {
		userID = tab.cli.LookupUserID(memberKey)
	}
	for _, secret := range secrets {
		if m.banMember != nil && m.banMember(tab.groupID, secret, userID) {
			wasConnected = true
		}
	}
	delete(tab.secretsByMember, memberKey)
	tab.removeOnline(memberKey)
	if tab.departures == nil {
		tab.departures = make(map[string]memberState)
	}
	tab.departures[memberKey] = memberBanned
	return true, wasConnected
}

// cmdAddMember (behind /grp-add-member) adds a new contact to an
// already-open SenderKey group: registers an individual secret host-
// side, sends the knock to the new contact with the full updated member
// list, and broadcast-notifies (normal SenderKey channel, not the
// contactCard file pipeline) all already-connected members to update
// their own tab.groupMembers.
// Available only to the host (tab connected locally, not remotely,
// same constraint as cmdReinvite) and only on groups born with 3+
// members (ratchetDH == false): a two-member chat stays two forever, no
// ratchet→SenderKey downgrade.
func (m *model) cmdAddMember(name string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.groupID == "" || tab.cli == nil || tab.cli.IsRemote() {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_add_member_host_only")))
	}
	if tab.cli.RatchetDH() {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_add_member_ratchet_dh")))
	}
	if len(tab.roomSecret) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_room_secret_unavailable")))
	}
	if name == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_add_member")))
	}

	c, n := m.resolveContactArg(name)
	if n != 1 {
		return m.openPicker(client.CmdAddMember, name)
	}
	for _, mem := range tab.groupMembers {
		if bytes.Equal(mem.IdentityPub, c.IdentityPub) {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_already_group_member"), c.NameWithUsername())))
		}
	}
	devs := c.ReadyDevices()
	if len(devs) == 0 {
		// Same logic as cmdInvite, queues instead of failing flat. Same
		// constraint as cmdReinvite: the retry must rerun on tabIdx, not
		// on m.active at retry time.
		origArg := contactPickerKey(*c)
		savedTabIdx := tabIdx
		return m.queuePendingInvite(i18n.CommandName(client.CmdAddMember), [][]byte{c.IdentityPub}, func(m *model) tea.Cmd {
			if savedTabIdx >= len(m.tabs) {
				return nil
			}
			prevActive := m.active
			m.active = savedTabIdx
			cmd := m.cmdAddMember(origArg)
			m.active = prevActive
			return cmd
		})
	}

	// Fan-out: a secret for each ready device, same principle as cmdInvite.
	type addMemberTarget struct {
		netAddr string
		secret  []byte
	}
	var targets []addMemberTarget
	perDevice := make(map[string][]byte, len(devs))
	for devKey, dev := range devs {
		newSecret, err := shared.RandomBytes(32)
		if err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_secret_gen_for"), c.Username)))
		}
		m.addRoom(tab.groupID, newSecret, c.Username, c.IdentityPub, []byte(devKey), m.relKeysResolver(c.IdentityPub, []byte(devKey)))
		perDevice[devKey] = newSecret
		targets = append(targets, addMemberTarget{dev.Address, newSecret})
	}
	if tab.secretsByMember == nil {
		tab.secretsByMember = make(map[string]map[string][]byte)
	}
	tab.secretsByMember[client.MemberKeyOf(c.IdentityPub)] = perDevice

	newMember := GroupMember{Username: c.Username, IdentityPub: c.IdentityPub}
	tab.groupMembers = append(tab.groupMembers, newMember)
	tab.setMemberLabel(memberKey(newMember), newMember.Username)

	memberInfos := make([]shared.MemberInfo, len(tab.groupMembers))
	for i, mb := range tab.groupMembers {
		memberInfos[i] = shared.MemberInfo{Username: mb.Username, IdentityPub: mb.IdentityPub}
	}

	myAddr := m.myAddr
	myUsername := m.myUsername
	myIdentityPub := m.myIdentityPub
	dhTagFn := m.dhTagFn
	dialTor := m.dialTor
	gid := tab.groupID
	targetPub := c.IdentityPub
	targetMLKEMPub := c.MLKEMPub
	displayName := c.NameWithUsername()
	inviteTO := m.inviteTimeout
	cli, ctx := tab.cli, tab.ctx
	consoleIdx := m.consoleIdx
	contentKeys := m.buildContentSigningKeys(tab)

	return func() tea.Msg {
		sent := 0
		var lastErr error
		lastErrWasEncrypt := false
		for _, t := range targets {
			payload, err := encryptKnockTagged(dhTagFn, targetPub, targetMLKEMPub, shared.KnockPayload{
				FromUsername:    myUsername,
				FromIdentityPub: myIdentityPub,
				RoomSecret:      t.secret,
				FromAddr:        myAddr,
				GroupID:         gid,
				Members:         memberInfos,
			})
			if err != nil {
				lastErr, lastErrWasEncrypt = err, true
				continue
			}
			httpCli := &http.Client{
				Transport: &http.Transport{DialContext: dialTor},
				Timeout:   inviteTO,
			}
			resp, err := httpCli.Post("http://"+t.netAddr+"/knock", "application/octet-stream", strings.NewReader(payload))
			if err != nil {
				lastErr, lastErrWasEncrypt = err, false
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			sent++
		}
		if sent == 0 {
			if lastErrWasEncrypt {
				return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_add_member_encrypt"), lastErr.Error())), isError: true}
			}
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_add_member_knock_failed"), displayName, lastErr.Error())), isError: true}
		}

		// Broadcast notification to already-connected members (best-
		// effort: doesn't affect the command's outcome). The new member
		// still receives the SenderKeys on join (user_joined), regardless of this notice.
		if raw, jerr := json.Marshal(groupMemberAddedPayload{Member: shared.MemberInfo{
			Username: newMember.Username, IdentityPub: newMember.IdentityPub,
		}}); jerr == nil {
			_, _ = cli.Send(ctx, groupMemberAddedPrefix+string(raw), contentKeys)
		}
		return localDisplayMsg{tabIdx: tabIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.member_added"), displayName))}
	}
}

// cmdSaveGroup saves the current group's composition under a local name.
func (m *model) cmdSaveGroup(nome string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.groupID == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_not_a_group")))
	}
	if nome == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_save_group")))
	}

	g := GroupInfo{
		LocalName: nome,
		GroupID:   tab.groupID,
		Members:   tab.groupMembers,
	}

	if m.saveGroup != nil {
		if err := m.saveGroup(g); err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_save_error"), err.Error())))
		}
	}

	// Updates local memory and tab name
	updated := false
	for i := range m.savedGroups {
		if m.savedGroups[i].GroupID == g.GroupID {
			m.savedGroups[i] = g
			updated = true
			break
		}
	}
	if !updated {
		m.savedGroups = append(m.savedGroups, g)
	}
	tab.name = nome

	return localTab(m.defaultTabIdx(), fmt.Sprintf(i18n.T("tui.group_saved"), nome, tab.groupID))
}

// cmdAddContact adds a contact from the TUI.
// Syntax: nu://username/pubkeyB64 [localname]
//
//	or:  <username> <pubkeyB64> [localname]
//	or:  <path-to-file-with-the-URI>
func (m *model) cmdAddContact(args string) tea.Cmd {
	tabIdx := m.active
	if args == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_add_contact")))
	}

	// If the whole argument is the path of an existing file, reads it
	// and uses its (trimmed) content as the URI, the same text file
	// written by "neutrino show-qr" (dedicated save, see
	// printAndSaveQR): lets identity be exchanged as an attachment
	// (Telegram, email...) instead of having to retype the URI by hand.
	// Checked against the WHOLE argument, not the first field: the
	// manual format "<username> <pubkeyB64> [localname]" always has an
	// internal space, which already makes it an almost-impossible path
	// to find by accident on the filesystem, a nonexistent path simply
	// falls through to the normal parsing below, never a "file not
	// found" error for something that was actually text/URI.
	if info, err := os.Stat(args); err == nil && !info.IsDir() {
		data, rerr := os.ReadFile(args)
		if rerr != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(rerr.Error()))
		}
		args = strings.TrimSpace(string(data))
	}

	var username string
	var pubBytes, mlkemPubBytes, mldsaPubBytes []byte

	if strings.HasPrefix(args, "nu://") {
		// ignores any localname passed after a space (asked interactively)
		uri := strings.SplitN(args, " ", 2)[0]
		var err error
		username, pubBytes, mlkemPubBytes, mldsaPubBytes, err = parseNuURI(uri)
		if err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(err.Error()))
		}
	} else {
		// manual format: username pubkeyB64 [localname], no ML-KEM
		// segment possible in this format: the contact stays on
		// classic knocks until the QR is re-exchanged.
		fields := strings.Fields(args)
		if len(fields) < 2 {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_add_contact_manual")))
		}
		username = fields[0]
		var err error
		pubBytes, err = base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(pubBytes) != 32 {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_pubkey_invalid")))
		}
	}

	return m.startAddContact(tabIdx, username, pubBytes, mlkemPubBytes, mldsaPubBytes)
}

// nuURIKeyB64Len/nuURIMLKEMB64Len/nuURIMLDSAB64Len are the fixed
// standard-base64 lengths of the three known-length segments of the
// nu:// format, 32-byte Ed25519, 1184-byte ML-KEM-768 (encapsulation
// key), and 1952-byte ML-DSA-65 (signing key, packed), respectively.
// Shared by parseNuURI and whoever builds the URI (identityQRContent).
const (
	nuURIKeyB64Len   = 44   // base64(32 bytes) with padding
	nuURIMLKEMB64Len = 1580 // base64(1184 bytes) with padding
	nuURIMLDSAB64Len = 2604 // base64(1952 bytes) with padding
)

// parseNuURI parses a URI nu://username/ed25519B64[/mlkemB64][/mldsaB64]
// the identity QR format (identityQRContent/cmdShowQR), into
// (username, 32-byte Ed25519 pubBytes, optional 1184-byte ML-KEM-768
// mlkemPubBytes, optional 1952-byte ML-DSA-65 mldsaPubBytes). Shared by
// cmdAddContact and startAddContactFromURI ("read QR code" flow, which
// always and only produces this format, never the manual "username
// pubkey" one). The keys are always
// fixed-length in standard base64 and can contain "/", so the URI
// can't be naively split on "/".
//
// The ML-KEM/ML-DSA segments are optional: when absent they return
// nil, not an error, the caller
// (startAddContact→keystore.Contact.MLKEMPub/MLDSAPub empty) falls back
// operations toward that contact to the classic form until the QR is
// re-exchanged. A fourth segment isn't tolerated: any data beyond the
// recognized segments is an invalid URI.
func parseNuURI(uri string) (username string, pubBytes []byte, mlkemPubBytes []byte, mldsaPubBytes []byte, err error) {
	if !strings.HasPrefix(uri, "nu://") {
		return "", nil, nil, nil, errors.New(i18n.T("tui.err_qr_invalid_format"))
	}
	path := strings.TrimPrefix(uri, "nu://")
	slashIdx := strings.IndexByte(path, '/')
	if slashIdx < 0 {
		return "", nil, nil, nil, errors.New(i18n.T("tui.err_qr_invalid_format"))
	}
	username = path[:slashIdx]
	remaining := path[slashIdx+1:]
	if len(remaining) < nuURIKeyB64Len {
		return "", nil, nil, nil, errors.New(i18n.T("tui.err_qr_key_too_short"))
	}
	pubBytes, err = base64.StdEncoding.DecodeString(remaining[:nuURIKeyB64Len])
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return "", nil, nil, nil, errors.New(i18n.T("tui.err_qr_key_invalid"))
	}
	tail := remaining[nuURIKeyB64Len:]

	if len(tail) >= 1+nuURIMLKEMB64Len && tail[0] == '/' {
		candidate := tail[1 : 1+nuURIMLKEMB64Len]
		if dec, decErr := base64.StdEncoding.DecodeString(candidate); decErr == nil && len(dec) == mlkem.EncapsulationKeySize768 {
			mlkemPubBytes = dec
			tail = tail[1+nuURIMLKEMB64Len:]
		}
	}

	if len(tail) >= 1+nuURIMLDSAB64Len && tail[0] == '/' {
		candidate := tail[1 : 1+nuURIMLDSAB64Len]
		if dec, decErr := base64.StdEncoding.DecodeString(candidate); decErr == nil && len(dec) == mldsa65.PublicKeySize {
			mldsaPubBytes = dec
			tail = tail[1+nuURIMLDSAB64Len:]
		}
	}

	if len(tail) > 0 {
		return "", nil, nil, nil, errors.New(i18n.T("tui.err_qr_invalid_format"))
	}
	return username, pubBytes, mlkemPubBytes, mldsaPubBytes, nil
}

// startAddContact validates (not already present) and opens a summary
// of the data read (username/key) with a yes/no confirmation
// (addContactConfirmMode), only after a yes does it move on to the
// local-name prompt (addContactMode/addContactBuf, keys handled in
// Update). The last leg common to every source of a new contact (pasted
// URI, manual form, decoded QR).
func (m *model) startAddContact(tabIdx int, username string, pubBytes, mlkemPubBytes, mldsaPubBytes []byte) tea.Cmd {
	if bytes.Equal(pubBytes, m.myIdentityPub) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_cannot_add_self")))
	}
	if m.contactExists(pubBytes) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_already_in_book"), username)))
	}

	m.pendingContact.username = username
	m.pendingContact.pubBytes = pubBytes
	m.pendingContact.mlkemPub = mlkemPubBytes
	m.pendingContact.mldsaPub = mldsaPubBytes
	m.pendingContact.tabIdx = tabIdx
	m.pendingContact.cardFrom = "" // direct addition, not from a third party's card
	m.addContactConfirmMode = true
	return nil
}

// handleQRDecoded receives the text of a single, just-decoded QR frame
// (file or camera, see qrDecodedMsg) and distinguishes two cases: a
// complete single-frame nu:// URI (proceeds immediately), or an NTR3
// chunk of a multi-QR identity URI (the URI with
// all three PQC segments exceeds a single frame's capacity). In the
// second case it accumulates in m.qrMultiChunks and asks the user to
// scan the next part until all have arrived, then reassembles with
// keystore.AssembleQRMulti and proceeds as for a single-frame URI.
func (m *model) handleQRDecoded(text string) tea.Cmd {
	if !keystore.IsMultiQRChunk([]byte(text)) {
		return m.startAddContactFromURI(text)
	}
	part, total, ok := keystore.QRMultiPartTotal([]byte(text))
	if !ok || total <= 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_qr_multi_chunk")))
	}
	// A total different from the one already in progress is a different
	// session (e.g. the user restarted /cnt-read-qrcode from scratch, or
	// is scanning a different contact's identity partway through the
	// first), restarts from zero instead of mixing two sessions
	// (AssembleQRMulti would reject it later anyway, but this avoids
	// accumulating uselessly until then).
	if m.qrMultiTotal != 0 && m.qrMultiTotal != total {
		m.qrMultiChunks = nil
	}
	if m.qrMultiChunks == nil {
		m.qrMultiChunks = make(map[int][]byte)
	}
	m.qrMultiTotal = total
	m.qrMultiChunks[part] = []byte(text)

	if len(m.qrMultiChunks) < total {
		m.qrChooseMode = true // immediately asks for the next scan (same f/c picker)
		return consoleErrTab(m.consoleIdx, styleMeta.Render(fmt.Sprintf(i18n.T("tui.qr_multi_progress"), len(m.qrMultiChunks), total)))
	}

	ordered := make([][]byte, 0, total)
	for i := range total {
		ordered = append(ordered, m.qrMultiChunks[i])
	}
	m.qrMultiChunks = nil
	m.qrMultiTotal = 0
	reassembled, err := keystore.AssembleQRMulti(ordered)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_qr_multi_assemble"), err.Error())))
	}
	return m.startAddContactFromURI(string(reassembled))
}

// startAddContactFromURI parses a nu://... URI (typically from a
// decoded QR, see cmdReadQR) and opens the same interactive prompt as
// /cnt-add for the local name.
func (m *model) startAddContactFromURI(uri string) tea.Cmd {
	username, pubBytes, mlkemPubBytes, mldsaPubBytes, err := parseNuURI(uri)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(err.Error()))
	}
	return m.startAddContact(m.active, username, pubBytes, mlkemPubBytes, mldsaPubBytes)
}

// cmdDelContact removes a contact from the keystore and from the in-memory list.
func (m *model) cmdDelContact(name string) tea.Cmd {
	if name == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_del_contact")))
	}
	contact := m.resolveNameOrPickerKey(name)
	if contact == nil {
		return m.openPicker(client.CmdDelContact, name)
	}
	removed := *contact

	// Deleting a contact from the address book must not leave them with
	// access to an already-open room where they were a member, the
	// deletion implies a ban from all chats first, silently, with no
	// separate confirmation, and only then is the contact actually
	// deleted. Iterates every group tab we host and revokes this
	// contact's secrets before removing it from the address book, same
	// core as /grp-ban.
	var cmds []tea.Cmd
	for i, tab := range m.tabs {
		if tab.groupID == "" {
			continue
		}
		revokedAny, wasConnected := m.revokeMemberSecrets(i, client.MemberKeyOf(removed.IdentityPub))
		if !revokedAny {
			continue
		}
		key := "tui.ban_done"
		if !wasConnected {
			key = "tui.ban_done_offline"
		}
		cmds = append(cmds, localTab(i, styleMeta.Render(fmt.Sprintf(i18n.T(key), removed.NameWithUsername()))))
	}

	idx := -1
	for i := range m.contacts {
		if bytes.Equal(m.contacts[i].IdentityPub, removed.IdentityPub) {
			idx = i
			break
		}
	}
	if idx >= 0 {
		m.contacts = append(m.contacts[:idx], m.contacts[idx+1:]...)
	}
	if m.deleteContact != nil {
		if err := m.deleteContact(removed.IdentityPub); err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_removal_error"), err.Error())))
		}
	}
	cmds = append(cmds, localTab(m.defaultTabIdx(), fmt.Sprintf(i18n.T("tui.contact_removed"), removed.NameWithUsername())))
	return tea.Batch(cmds...)
}

// cmdDelGroup removes a saved group from the keystore and from the in-memory list.
func (m *model) cmdDelGroup(nameOrID string) tea.Cmd {
	if nameOrID == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_del_group")))
	}
	idx := -1
	for i, g := range m.savedGroups {
		if g.LocalName == nameOrID || g.GroupID == nameOrID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return m.openPicker(client.CmdDelGroup, nameOrID)
	}
	removed := m.savedGroups[idx]
	m.savedGroups = append(m.savedGroups[:idx], m.savedGroups[idx+1:]...)
	if m.deleteGroup != nil {
		key := removed.GroupID
		if key == "" {
			key = removed.LocalName
		}
		if err := m.deleteGroup(key); err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_removal_error"), err.Error())))
		}
	}
	label := removed.LocalName
	if label == "" {
		label = removed.GroupID
	}
	return localTab(m.defaultTabIdx(), fmt.Sprintf(i18n.T("tui.group_removed"), label))
}

// cmdEdit allows setting, changing, or clearing a contact's local name.
// Syntax: /cnt-edit <contact> (resolves by LocalName or Username)
// Opens an interactive prompt; empty string = removes the local name.
func (m *model) cmdEdit(name string) tea.Cmd {
	if name == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_edit")))
	}
	c := m.resolveNameOrPickerKey(name)
	if c == nil {
		return m.openPicker(client.CmdEdit, name)
	}
	m.pendingEditUsername = c.Username
	m.pendingEditContactPub = c.IdentityPub
	m.pendingEditTabIdx = m.active
	m.editContactMode = true
	m.editContactBuf = ""
	return nil
}

// myIdentityURI builds this identity's self-description nu:// URI, the
// canonical builder shared by cmdInfo("self") and cmdShowQR, so the two
// never drift out of sync on which key segments they include
// (same format as cmd/main.go's identityQRContent: pub, then MLKEM if
// present, then MLDSA if present).
func (m *model) myIdentityURI() string {
	uri := "nu://" + m.myUsername + "/" + base64.StdEncoding.EncodeToString(m.myIdentityPub)
	if len(m.myMLKEMPub) > 0 {
		uri += "/" + base64.StdEncoding.EncodeToString(m.myMLKEMPub)
	}
	if len(m.myMLDSAPub) > 0 {
		uri += "/" + base64.StdEncoding.EncodeToString(m.myMLDSAPub)
	}
	return uri
}

// cmdInfo shows the stored data for a contact: nu:// URI, derived network address.
// Accepts "self" to show one's own information.
func (m *model) cmdInfo(name string) tea.Cmd {
	// Own information
	if name == "self" {
		uri := m.myIdentityURI()
		lines := []string{
			fmt.Sprintf(i18n.T("tui.my_info_header"), m.myUsername),
			"  uri:   " + uri,
		}
		if m.myAddr != "" {
			lines = append(lines, "  addr:  "+m.myAddr)
		}
		m.textPopupContent = strings.Join(lines, "\n")
		m.textPopupMode = true
		m.textPopupCopyURI = uri
		return nil
	}

	c := m.resolveNameOrPickerKey(name)
	if c == nil {
		return m.openPicker(client.CmdInfo, name)
	}
	uri := "nu://" + c.Username + "/" + base64.StdEncoding.EncodeToString(c.IdentityPub)
	if len(c.MLKEMPub) > 0 {
		uri += "/" + base64.StdEncoding.EncodeToString(c.MLKEMPub)
	}
	if len(c.MLDSAPub) > 0 {
		uri += "/" + base64.StdEncoding.EncodeToString(c.MLDSAPub)
	}
	lines := []string{
		fmt.Sprintf(i18n.T("tui.contact_info_header"), c.DisplayName(), c.Username),
		"  uri:   " + uri,
		"  addr:  " + c.NetAddr,
	}
	if c.LocalName != "" {
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_local_name"), c.LocalName))
	}
	if c.IntroducedBy != "" || len(c.IntroducedByPub) > 0 {
		introducer := c.IntroducedBy
		if ic := m.resolveContactByPub(c.IntroducedByPub); ic != nil {
			introducer = ic.DisplayName()
		}
		if len(c.IntroducedByPub) > 0 {
			introducer += " ·" + keyFingerprint(client.MemberKeyOf(c.IntroducedByPub))
		}
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_introduced_by"), introducer))
	}
	if len(c.IdentityPub) == 32 && len(m.myIdentityPub) == 32 {
		code := shared.SafetyCode(m.myIdentityPub, c.IdentityPub)
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_safety_code"), code))
	}
	if c.Verified {
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_trust_status"), styleOwnMsg.Render(c.TrustTag())))
	} else {
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_trust_status"), styleErr.Render(c.TrustTag())))
	}
	if c.LastSeenAt.IsZero() {
		lines = append(lines, i18n.T("tui.info_last_seen_never"))
	} else if d := daysSince(c.LastSeenAt); d > 0 {
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_last_seen"), d, formatLocalTimestamp(c.LastSeenAt)))
	} else {
		lines = append(lines, fmt.Sprintf(i18n.T("tui.info_last_seen_today"), formatLocalTimestamp(c.LastSeenAt)))
	}
	// "sees me", independent of "I see" (dot1/dot2 in the Contacts tab, see
	// contactState.seenByPeer): shows WHEN the last confirmation
	// arrived instead of a static dot that never decays, and NEVER
	// assumes a specific cause for the absence of confirmation (see the
	// comment on the field).
	if st, ok := m.contactStates[string(c.IdentityPub)]; ok && st.seenByPeer != nil {
		if *st.seenByPeer {
			if d := daysSince(st.seenByPeerAt); d > 0 {
				lines = append(lines, fmt.Sprintf(i18n.T("tui.info_seen_by_peer_at"), d, formatLocalTimestamp(st.seenByPeerAt)))
			} else {
				lines = append(lines, fmt.Sprintf(i18n.T("tui.info_seen_by_peer_today"), formatLocalTimestamp(st.seenByPeerAt)))
			}
		} else {
			lines = append(lines, i18n.T("tui.info_seen_by_peer_no_confirmation"))
		}
	} else {
		lines = append(lines, i18n.T("tui.info_seen_by_peer_never"))
	}
	m.textPopupContent = strings.Join(lines, "\n")
	m.textPopupMode = true
	m.textPopupCopyURI = uri
	return nil
}

// copyPopupURIToClipboard copies m.textPopupCopyURI to the clipboard
// ("c" key in the /cnt-info popup, see Update) and appends a
// confirmation or error line to the content already shown, the popup
// stays open; clears textPopupCopyURI only on success, so a transient
// failure remains retryable with another press of "c".
func (m *model) copyPopupURIToClipboard() {
	if err := clipboard.WriteAll(m.textPopupCopyURI); err != nil {
		m.textPopupContent += "\n\n" + styleErr.Render(i18n.T("tui.info_copy_uri_failed"))
		return
	}
	m.textPopupContent += "\n\n" + styleOwnMsg.Render(i18n.T("tui.info_copy_uri_done"))
	m.textPopupCopyURI = ""
}

// qrShowFrameDelay is the interval between one frame and the next in
// the animated /show-qr popup, same value as qrOpticalFrameDelay
// (cmd/main.go, "qr send"), duplicated here because it's a different package.
const qrShowFrameDelay = 350 * time.Millisecond

// cmdShowQRSaveImage is /show-qr's "save as image" choice (idx 0,
// default), writes the same multi-part PNG + plain .txt as `neutrino
// show-qr`'s own "image" choice, via the SaveIdentityQR closure
// (cmd/main.go does the actual file I/O, see TUIParams.SaveIdentityQR's
// doc comment for why). Reports the saved paths in a text popup instead
// of printing them straight to the terminal.
func (m *model) cmdShowQRSaveImage() tea.Cmd {
	if m.saveIdentityQR == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_show_qr_save_unavailable")))
	}
	paths, err := m.saveIdentityQR()
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_show_qr_save_failed"), err)))
	}
	var sb strings.Builder
	sb.WriteString(i18n.T("tui.show_qr_saved_header"))
	for _, p := range paths {
		sb.WriteString("\n  " + p)
	}
	m.textPopupContent = sb.String()
	m.textPopupMode = true
	return nil
}

// cmdShowQR shows the QR code of one's own identity in a popup,
// TUI equivalent of `neutrino show-qr` (cmd/main.go), reachable without
// leaving the session. Same nu://username/base64pubkey[/mlkempub]
// URI already shown in text form by cmdInfo "self".
//
// Animated via fountain code (internal/qroptical, same mechanism as "qr
// send"), not a single static QR: a QR with the full identity (ML-KEM
// included, ~1650 characters) requires a large QR version, nearly
// unreadable in a terminal; compressing the ASCII rendering (2x2
// quadrants) doesn't solve it because it distorts the aspect ratio (a
// terminal cell is ~2 times taller than wide: compressing horizontally
// too breaks the compensation ToSmallString applies on purpose). A
// fountain frame (120-byte payload, DefaultBlockSize) instead produces
// a small QR by construction, always readable with normal rendering,
// no password (identity isn't a secret, unlike "qr send").
func (m *model) cmdShowQR() tea.Cmd {
	uri := m.myIdentityURI()
	lines := []string{fmt.Sprintf(i18n.T("tui.my_info_header"), m.myUsername), "  uri:   " + uri}
	if m.myAddr != "" {
		lines = append(lines, "  addr:  "+m.myAddr)
	}
	m.qrShowInfo = strings.Join(lines, "\n")

	sender, err := qroptical.NewSender([]byte(uri), 0)
	if err != nil {
		// Fallback: no drawable QR, just the text already in qrShowInfo,
		// same handling as an error in printAndSaveQR (cmd/main.go).
		m.textPopupContent = m.qrShowInfo
		m.textPopupMode = true
		return nil
	}
	m.qrShowSender = sender
	m.qrShowGen++
	m.qrShowActive = true
	m.qrShowNextFrame()
	return m.qrShowTick(m.qrShowGen)
}

// qrShowNextFrame advances the Sender by one frame and renders it as
// ASCII, ToSmallString (not the quadrants): a fountain frame is
// already small (~180 characters of text, moderate QR version), no
// need to compress further, and ToSmallString stays correctly square on screen.
func (m *model) qrShowNextFrame() {
	if m.qrShowSender == nil {
		return
	}
	text := m.qrShowSender.NextFrame()
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return
	}
	m.qrShowFrame = strings.TrimRight(q.ToSmallString(false), "\n")
}

// qrShowTick schedules the next frame, gen is the current one at
// scheduling time, compared in Update (case qrShowTickMsg) against
// model.qrShowGen to discard ticks from an already-closed session.
func (m *model) qrShowTick(gen int) tea.Cmd {
	return tea.Tick(qrShowFrameDelay, func(time.Time) tea.Msg { return qrShowTickMsg{gen: gen} })
}

// cmdInfoApp (/info-app) shows only the version number, meant to
// distinguish at a glance whether this binary is really the latest
// build compiled or an earlier one.
func (m *model) cmdInfoApp() tea.Cmd {
	m.textPopupContent = fmt.Sprintf(i18n.T("tui.info_app_body"), version.Full())
	m.textPopupMode = true
	return nil
}

// cmdReadQR (/cnt-read-qrcode) opens the source choice (file or
// camera), the real action starts from qrChooseMode/qrFileMode
// (handled in Update) and from cmdReadQRFiles/cmdReadQRCamera below.
func (m *model) cmdReadQR() tea.Cmd {
	m.qrChooseMode = true
	return nil
}

// qrFilesDecodedMsg carries the decoded text of every image file
// selected in qrFileMode, in selection order, or the first decode error
// hit along the way. Decoding is pure file I/O (no model access), so it
// runs in the background inside cmdReadQRFiles; handleQRDecoded (which
// needs *model to accumulate multi-part chunks) then runs once per text
// from Update, see case qrFilesDecodedMsg.
type qrFilesDecodedMsg struct {
	texts []string
	err   error
}

// cmdReadQRFiles decodes every file chosen in qrFileMode (a single file,
// or several at once via Space, an identity QR is often split across
// several numbered PNGs) and reports them for handleQRDecoded to process
// in the same order, see qrFilesDecodedMsg.
func (m *model) cmdReadQRFiles(paths []string) tea.Cmd {
	return func() tea.Msg {
		texts := make([]string, 0, len(paths))
		for _, p := range paths {
			text, err := qrscan.DecodeQRFile(p)
			if err != nil {
				return qrFilesDecodedMsg{err: fmt.Errorf("%s: %w", filepath.Base(p), err)}
			}
			texts = append(texts, text)
		}
		return qrFilesDecodedMsg{texts: texts}
	}
}

// qrCameraFrameMsg carries the last frame already rendered as ANSI art
// (see renderCameraPreview), a discarded frame (not yet consumed when
// a new one arrives) never blocks capture, see cmdReadQRCamera.
type qrCameraFrameMsg struct{ frame string }

// qrCameraDoneMsg carries the FINAL scan message (qrDecodedMsg on
// success, localDisplayMsg on error/timeout/cancellation), wrapped
// instead of being the direct type so waitForQRCameraFrame can
// distinguish "new frame, keep waiting" from "scan finished, stop
// waiting" with a single select.
type qrCameraDoneMsg struct{ msg tea.Msg }

// cmdReadQRCamera reads a QR from the webcam via qrscan.ScanCamera,
// direct V4L2, pure Go (github.com/blackjack/webcam), no external
// process (no system zbar/zbarcam binary).
//
// Live preview in the terminal, but NO separate graphical window: each
// frame is reduced to a small grid and rendered as ANSI art (half-
// height Unicode blocks, grayscale) directly in the terminal popup, so it
// also works over SSH/without an X server (a real X11/Wayland window
// couldn't). cmdReadQRCamera reads from the webcam both a normal
// single-frame QR (direct URI or NTR3 chunk) and an
// animated fountain-coded stream (internal/qroptical, same protocol as
// "qr send"/cmdShowQR), auto-recognized by checking whether the FIRST
// decoded frame starts a fountain transfer (Receiver.Started()): if
// not, it's a normal QR and a single frame is enough; if so, the scan
// continues until Receiver.Done() is true. Both cases go through the
// same "c" choice in the f/c menu.
func (m *model) cmdReadQRCamera() tea.Cmd {
	consoleIdx := m.consoleIdx
	termW, termH := m.lastTermW, m.lastTermH

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	previewCh := make(chan string, 1)
	resultCh := make(chan tea.Msg, 1)
	m.qrCameraCancel = cancel
	m.qrCameraPreviewCh = previewCh
	m.qrCameraResultCh = resultCh
	m.qrCameraPreviewMode = true
	m.qrCameraPreviewContent = ""

	go func() {
		defer cancel()
		sendPreview := func(frame string) {
			select {
			case previewCh <- frame:
			default:
				// The previous frame hasn't been consumed by the Update
				// loop yet, discards and replaces it, NEVER blocks
				// capture (channel buffered to 1, the most recent always wins).
				select {
				case <-previewCh:
				default:
				}
				previewCh <- frame
			}
		}
		var progress string
		recv := qroptical.NewReceiver()
		done := false
		var doneURI string
		err := qrscan.ScanCameraContinuous(ctx, func(img image.Image) {
			frame := renderCameraPreview(img, termW, termH)
			if progress != "" {
				frame += "\n" + progress
			}
			sendPreview(frame)
		}, func(text string) bool {
			recv.AddFrameText(text)
			if !recv.Started() {
				// Not a fountain frame, normal QR, a single frame is enough.
				done = true
				doneURI = text
				return true
			}
			if known, total := recv.Progress(); total > 0 {
				progress = styleMeta.Render(fmt.Sprintf(i18n.T("tui.qr_camera_fountain_progress"), known, total))
			}
			if recv.Done() {
				done = true
				doneURI = string(recv.Bytes())
				return true
			}
			return false
		})
		var msg tea.Msg
		switch {
		case errors.Is(err, context.Canceled):
			return // canceled with Esc: already handled there, no message to send
		case done:
			msg = qrDecodedMsg{uri: doneURI}
		case err != nil:
			msg = localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_qr_decode_failed"), err.Error())), isError: true}
		default:
			msg = localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(i18n.T("tui.err_qr_camera_no_result")), isError: true}
		}
		resultCh <- msg
	}()

	return m.waitForQRCameraFrame()
}

// waitForQRCameraFrame waits for either the next frame (rearms itself)
// or the scan's final message (doesn't rearm, capture is over).
func (m model) waitForQRCameraFrame() tea.Cmd {
	previewCh := m.qrCameraPreviewCh
	resultCh := m.qrCameraResultCh
	if previewCh == nil || resultCh == nil {
		return nil
	}
	return func() tea.Msg {
		select {
		case frame := <-previewCh:
			return qrCameraFrameMsg{frame: frame}
		case msg := <-resultCh:
			return qrCameraDoneMsg{msg: msg}
		}
	}
}

// qrCameraPreviewCols/Rows compute the preview grid from the terminal's
// size at scan-start time (captured once in cmdReadQRCamera, not
// recomputed on every frame: resizing the terminal mid-scan leaves the
// preview at the size it started with, an acceptable minor limitation).
// rows*2 is the actual number of vertical samples extracted from the
// image, see the Unicode "▀" character trick in renderCameraPreview,
// which encodes TWO pixels per character (upper/lower half) instead of just one.
func qrCameraPreviewSize(termW, termH int) (cols, rows int) {
	if termW <= 0 {
		termW = 80
	}
	if termH <= 0 {
		termH = 24
	}
	cols = (termW - 8) / 2 // popup border (4) + padding (2) + margin
	if cols > 44 {
		cols = 44 // beyond this adds nothing useful to reading the QR
	}
	if cols < 16 {
		cols = 16
	}
	rows = (termH - 10) / 2 // popup border + blank line + Esc hint below
	if rows > cols/2 {
		rows = cols / 2 // no "wider" than reasonable relative to the available characters
	}
	if rows < 8 {
		rows = 8
	}
	return cols, rows
}

// renderCameraPreview reduces img to a small grid and draws it as
// grayscale ANSI art, a "▀" character (upper half block) per pair of
// vertical pixels, foreground color = top pixel, background color =
// bottom pixel (truecolor, "\x1b[38;2;r;g;bm"/"\x1b[48;2;r;g;bm"):
// standard technique to double the vertical resolution available in a
// character terminal, the same principle used by terminal image
// viewers like chafa/viu. Nearest-neighbor downsampling: enough to
// recognize a QR code's shape, nothing more is needed.
func renderCameraPreview(img image.Image, termW, termH int) string {
	cols, rows := qrCameraPreviewSize(termW, termH)
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w == 0 || h == 0 {
		return ""
	}
	grayAt := func(x, y int) uint8 {
		g := color.GrayModel.Convert(img.At(x, y)).(color.Gray)
		return g.Y
	}
	var b strings.Builder
	for ry := 0; ry < rows; ry++ {
		topY := bounds.Min.Y + (ry*2)*h/(rows*2)
		botY := bounds.Min.Y + (ry*2+1)*h/(rows*2)
		for cx := 0; cx < cols; cx++ {
			x := bounds.Min.X + cx*w/cols
			top := grayAt(x, topY)
			bot := grayAt(x, botY)
			fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm▀", top, top, top, bot, bot, bot)
		}
		b.WriteString("\x1b[0m")
		if ry < rows-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// cmdRoomInfo shows, for each member of the current room (self
// excluded): connection dot, name colored by ContentKey relationship,
// trust tag if it's a contact, and the safety code. The safety code is
// computed from the IdentityPub already
// known via the invite/knock (tab.groupMembers), not only if the
// member is already a saved contact: their network identity is known
// regardless, whether they're "in the address book" or not only
// concerns whether an out-of-band verification was done, not whether
// the code is computable.
func (m *model) cmdRoomInfo() tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	others := make([]GroupMember, 0, len(tab.groupMembers))
	for _, mem := range tab.groupMembers {
		if memberKey(mem) != m.myKey() {
			others = append(others, mem)
		}
	}
	if len(others) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_whois_no_room")))
	}
	header := fmt.Sprintf(i18n.T("tui.room_info_header"), tab.name)
	if tab.hostKey == m.myKey() {
		header += "  " + styleMeta.Render(i18n.T("tui.room_info_host_tag"))
	} else {
		hostName := m.memberName(tab, tab.hostKey)
		if hostContact := m.resolveContactByPub(memberKeyPub(tab.hostKey)); hostContact != nil {
			hostName = hostContact.DisplayName()
		}
		header += "  " + styleMeta.Render(fmt.Sprintf(i18n.T("tui.room_info_host_tag_named"), hostName))
	}
	lines := []string{header}
	for _, mem := range others {
		key := memberKey(mem)
		name := m.memberName(tab, key)
		contact := m.resolveContactByPub(mem.IdentityPub)
		if contact != nil {
			name = contact.DisplayName()
		}
		var dot string
		if tab.isOnline(key) {
			dot = styleOwnMsg.Render("●")
		} else {
			dot = styleErr.Render("●")
		}
		relOK := m.contentRelEstablished(tab, key)
		var nameS string
		if relOK {
			nameS = styleOwnMsg.Render(name)
		} else {
			nameS = styleWarnName.Render(name)
		}
		// Fixed convention for the whole line: status tag in brackets
		// (color per status), any actionable hint right after in
		// parentheses, never mixed in the same pair. An established
		// ContentKey relationship (relOK, below) doesn't replace this
		// line: it only proves you're talking to whoever holds that
		// key, not that it's really the expected person (a saved,
		// verified contact).
		line := dot + " " + nameS
		switch {
		case contact != nil && contact.Verified:
			line += "  " + styleOwnMsg.Render(contact.TrustTag())
		case contact != nil:
			line += "  " + styleErr.Render(contact.TrustTag()) +
				"  " + styleMeta.Render(fmt.Sprintf(i18n.T("tui.safety_tag_unverified_short"), i18n.CommandName(client.CmdSafety)))
		default:
			line += "  " + styleErr.Render(i18n.T("tui.tag_unknown")) +
				"  " + styleMeta.Render(fmt.Sprintf(i18n.T("tui.hint_add_contact"), i18n.CommandName(client.CmdAddContact)))
		}
		lines = append(lines, line)

		// Identity detail: information only (ContentKey tag/code), no
		// hints, those all live on the line above, never here. The
		// ContentKey relationship is either established with the right
		// keys (contentRelEstablished/relOK) or not established at all
		// there's no intermediate state to distinguish.
		var detail string
		switch {
		case relOK:
			pub, _, _, _, _ := m.contentPeerKeysFor(tab, key)
			hex := fmt.Sprintf("%x", pub)
			if len(hex) > 8 {
				hex = hex[len(hex)-8:]
			}
			detail = i18n.T("tui.identity_label") + ": " + styleOwnMsg.Render(i18n.T("tui.rel_established_tag", hex))
		case len(mem.IdentityPub) == 32 && len(m.myIdentityPub) == 32:
			code := shared.SafetyCode(m.myIdentityPub, mem.IdentityPub)
			detail = "safety: " + styleMeta.Render(code)
		default:
			detail = styleMeta.Render(i18n.T("tui.identity_unknown"))
		}
		lines = append(lines, "    "+detail)
	}
	m.textPopupContent = strings.Join(lines, "\n")
	m.textPopupMode = true
	return nil
}

// contactExists reports whether a contact with this exact IdentityPub
// already exists in the address book, a TRUE duplicate, not a mere
// homonym: two contacts can legitimately share the same self-declared
// username (e.g. one of them ran a nuke and reappeared with a new
// identity under the same chosen name), the real identity is the key,
// not the name. Used before adding a contact to avoid silently
// overwriting an already-saved identity, a different key could mean a
// legitimate device change, but also an impersonation attempt.
func (m *model) contactExists(pub []byte) bool {
	for i := range m.contacts {
		if bytes.Equal(m.contacts[i].IdentityPub, pub) {
			return true
		}
	}
	return false
}

// computeAddress computes the reachable network address from an
// Ed25519 public key, with the right algorithm for the active network
// (m.addressFromPub, set by cmd/main.go based on --net). Falls back to
// Tor if unset (e.g. tests that build a model{} by hand).
func (m model) computeAddress(pub ed25519.PublicKey) string {
	if m.addressFromPub == nil {
		return shared.OnionAddressFromPub(pub)
	}
	return m.addressFromPub(pub)
}

// resolveContactByPub looks up a contact by its real IdentityPub, the
// contact's only identifier: never ambiguous, unlike LocalName/Username,
// which are self-declared and can be shared by several contacts (see
// keystore.Keystore.AddContact).
func (m *model) resolveContactByPub(pub []byte) *ContactInfo {
	if len(pub) != ed25519.PublicKeySize {
		return nil
	}
	for i := range m.contacts {
		if bytes.Equal(m.contacts[i].IdentityPub, pub) {
			return &m.contacts[i]
		}
	}
	return nil
}

// pickerContactKeyPrefix marks a picker key that directly encodes a
// contact's IdentityPub, instead of its Username/LocalName, a leading
// NUL byte isn't typeable from a terminal, so it never collides with a
// hand-typed argument. Disambiguates two contacts with the
// same Username (same name, different IdentityPub, e.g. after one of
// them ran /nukex and reappeared with a new identity under the same
// name).
const pickerContactKeyPrefix = "\x00pub:"

func contactPickerKey(c ContactInfo) string {
	return pickerContactKeyPrefix + base64.RawURLEncoding.EncodeToString(c.IdentityPub)
}

func decodePickerContactKey(key string) ([]byte, bool) {
	if !strings.HasPrefix(key, pickerContactKeyPrefix) {
		return nil, false
	}
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, pickerContactKeyPrefix))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, false
	}
	return pub, true
}

// resolveNameOrPickerKey resolves a command's argument, which can come
// from two different sources: (1) a picker key (contactPickerKey above)
// resolves by IdentityPub, never ambiguous; (2) a hand-typed name
// (LocalName, then Username), resolved only when it matches exactly
// one contact. nil when nothing or more than one contact matches: the
// caller opens the picker, where homonyms are listed by key.
func (m *model) resolveNameOrPickerKey(name string) *ContactInfo {
	c, n := m.resolveContactArg(name)
	if n != 1 {
		return nil
	}
	return c
}

// resolveContactArg resolves a command argument to a contact: a picker
// key (contactPickerKey) by identity key; a typed name by LocalName,
// then by Username. Returns the number of contacts the typed name
// matches, more than one means it is ambiguous and the contact
// returned is nil: the caller must let the user pick by key.
func (m *model) resolveContactArg(arg string) (*ContactInfo, int) {
	if pub, ok := decodePickerContactKey(arg); ok {
		if c := m.resolveContactByPub(pub); c != nil {
			return c, 1
		}
		return nil, 0
	}
	if arg == "" {
		return nil, 0
	}
	for _, field := range []func(ContactInfo) string{
		func(c ContactInfo) string { return c.LocalName },
		func(c ContactInfo) string { return c.Username },
	} {
		var found *ContactInfo
		n := 0
		for i := range m.contacts {
			if field(m.contacts[i]) == arg {
				found = &m.contacts[i]
				n++
			}
		}
		if n == 1 {
			return found, 1
		}
		if n > 1 {
			return nil, n
		}
	}
	return nil, 0
}

// resolveMemberArg resolves a command argument to a member of the
// group open in tab, among those accepted by keep: a picker key by
// identity key; a typed name by the contact's LocalName, then by the
// displayed name, case-insensitively. Returns the number of members
// the typed name matches, more than one means it is ambiguous.
func (m *model) resolveMemberArg(tab *roomTab, arg string, keep func(GroupMember) bool) (GroupMember, int) {
	candidates := make([]GroupMember, 0, len(tab.groupMembers))
	for _, gm := range tab.groupMembers {
		if keep == nil || keep(gm) {
			candidates = append(candidates, gm)
		}
	}
	if pub, ok := decodePickerContactKey(arg); ok {
		for _, gm := range candidates {
			if bytes.Equal(gm.IdentityPub, pub) {
				return gm, 1
			}
		}
		return GroupMember{}, 0
	}
	if arg == "" {
		return GroupMember{}, 0
	}
	for _, name := range []func(GroupMember) string{
		func(gm GroupMember) string {
			if c := m.resolveContactByPub(gm.IdentityPub); c != nil {
				return c.LocalName
			}
			return ""
		},
		func(gm GroupMember) string { return m.baseMemberName(tab, memberKey(gm)) },
	} {
		var found GroupMember
		n := 0
		for _, gm := range candidates {
			if v := name(gm); v != "" && strings.EqualFold(v, arg) {
				found = gm
				n++
			}
		}
		if n > 0 {
			return found, n
		}
	}
	return GroupMember{}, 0
}

// memberPickerKey is the picker key of a group member, the same
// encoding as contactPickerKey, decoded by decodePickerContactKey.
func memberPickerKey(gm GroupMember) string {
	return pickerContactKeyPrefix + base64.RawURLEncoding.EncodeToString(gm.IdentityPub)
}

// memberPickerDisplay is how a group member is shown in a picker: as a
// contact when it is one, otherwise by its member name with a key
// fingerprint, so two homonyms never look the same.
func (m *model) memberPickerDisplay(tab *roomTab, gm GroupMember) string {
	if c := m.resolveContactByPub(gm.IdentityPub); c != nil {
		return contactPickerDisplay(*c)
	}
	return m.baseMemberName(tab, memberKey(gm)) + " ·" + keyFingerprint(memberKey(gm))
}

// contactDisplayByPub is the display name of the contact with identity
// key pub, or a key fingerprint when it is not in the address book.
func (m *model) contactDisplayByPub(pub []byte) string {
	if c := m.resolveContactByPub(pub); c != nil {
		return c.DisplayName()
	}
	return keyFingerprint(client.MemberKeyOf(pub))
}

// setGroupLabels records the username label of every group member.
func (t *roomTab) setGroupLabels() {
	for _, gm := range t.groupMembers {
		t.setMemberLabel(memberKey(gm), gm.Username)
	}
}

// contactPickerDisplay builds the text shown for a contact in the
// picker, same rule already established by renderInvitePicker
// (placeholder `"…"` in quotes if LocalName isn't set, never a silent
// fallback to Username), a natural-width variant (truncName, not
// padName) because a picker can appear on a narrow terminal. Necessary
// (not just cosmetic): with a unique key per IdentityPub, two homonym
// contacts must show as DISTINCT rows even when LocalName is empty for
// both, never a Username lookup that collapses them onto the same row.
func contactPickerDisplay(c ContactInfo) string {
	localPart := `"…"`
	if c.LocalName != "" {
		localPart = `"` + truncName(c.LocalName, maxLocalNameLen) + `"`
	}
	return localPart + " (" + truncName(c.Username, maxUsernameDisplayLen) + ")"
}

// probeSelfKnock checks inbound connectivity (our own hidden service/
// destination reachable from outside) with no contacts involved.
// Sends an ECIES-encrypted POST to our own /knock over the active
// transport; the server decrypts it and puts it back on knockCh.
// The "self_probe" type is handled silently by the knockMsg handler,
// which sets torIn=true. Fire-and-forget: returns no msg (the result
// arrives via knockMsg).
func (m model) probeSelfKnock() tea.Cmd {
	if m.dialTor == nil || m.myAddr == "" || len(m.myIdentityPub) != 32 {
		return nil
	}
	dial := m.dialTor
	onion := m.myAddr
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	myMLKEMPub := m.myMLKEMPub
	dhTagFn := m.dhTagFn
	selfTO := m.selfKnockTimeout
	return func() tea.Msg {
		payload, err := encryptKnockTagged(dhTagFn, myPub, myMLKEMPub, shared.KnockPayload{
			Type:            "self_probe",
			FromUsername:    myUsername,
			FromIdentityPub: myPub,
		})
		if err != nil {
			return nil
		}
		httpCli := &http.Client{
			Transport: &http.Transport{DialContext: dial},
			Timeout:   selfTO,
		}
		resp, err := httpCli.Post("http://"+onion+"/knock", "text/plain", strings.NewReader(payload))
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
		return nil
	}
}

// sendWakeKnock sends a lightweight "wake" packet to group member mem,
// encouraging it to retry the connection if its process is alive but
// its WS toward the room is stuck. Carries no RoomSecret: the server
// doesn't touch RoomRegistry, it just forwards it on knockCh like any
// other informational knock (self_probe, probe_ping...). Fire-and-
// forget: the sender doesn't care about the outcome, the receiver (if
// it gets it) reconnects on its own.
func (m model) sendWakeKnock(groupID string, mem GroupMember) tea.Cmd {
	if m.dialTor == nil || len(mem.IdentityPub) != 32 {
		return nil
	}
	dial := m.dialTor
	targetAddr := m.computeAddress(mem.IdentityPub)
	targetPub := mem.IdentityPub
	targetMLKEMPub := m.mlkemPubForContact(targetPub)
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	dhTagFn := m.dhTagFn
	inviteTO := m.inviteTimeout
	return func() tea.Msg {
		payload, err := encryptKnockTagged(dhTagFn, targetPub, targetMLKEMPub, shared.KnockPayload{
			Type:            "wake",
			FromUsername:    myUsername,
			FromIdentityPub: myPub,
			GroupID:         groupID,
		})
		if err != nil {
			return nil
		}
		httpCli := &http.Client{
			Transport: &http.Transport{DialContext: dial},
			Timeout:   inviteTO,
		}
		resp, err := httpCli.Post("http://"+targetAddr+"/knock", "text/plain", strings.NewReader(payload))
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
		return nil
	}
}

// probeTorSelf checks whether Tor has active circuits.
// Uses the control port (via checkCircuits) if available, response in < 1 ms.
// Fallback: TCP connection to our own .onion (requires intro circuits already ready).
func (m model) probeTorSelf() tea.Cmd {
	if m.checkCircuits != nil {
		fn := m.checkCircuits
		return func() tea.Msg { return torProbeResultMsg{ok: fn()} }
	}
	if m.dialTor == nil || m.myAddr == "" {
		return nil
	}
	dial := m.dialTor
	onion := m.myAddr
	timeout := m.warmupTimeout
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err := dial(ctx, "tcp", onion+":80")
		if err == nil {
			conn.Close()
			return torProbeResultMsg{ok: true}
		}
		s := err.Error()
		// If Tor responded (even with a refusal or relay error), the circuits exist.
		if strings.Contains(s, "connection refused") ||
			strings.Contains(s, "general failure") ||
			strings.Contains(s, "host unreachable") {
			return torProbeResultMsg{ok: true}
		}
		return torProbeResultMsg{ok: false}
	}
}

// cmdWarmupCircuits opens a short TCP connection to every known contact
// over the active transport (Tor or I2P) and closes it immediately, in
// parallel. The goal is to force building and caching the circuits/
// tunnels toward those addresses before the user needs them, reducing
// the latency of the first knock or invite. Silent: no TUI output.
func (m model) cmdWarmupCircuits() tea.Cmd {
	if m.dialTor == nil || len(m.contacts) == 0 {
		return nil
	}
	contacts := m.contacts
	dial := m.dialTor
	timeout := m.warmupTimeout
	retryDelay := m.probeRetryDelay
	retryCount := m.probeRetryCount
	return func() tea.Msg {
		client.Dbg("warmup: starting for %d contacts", len(contacts))
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		done := make(chan struct{}, len(contacts))
		for _, c := range contacts {
			go func() {
				client.Dbg("warmup: TCP → %s:80", c.NetAddr)
				conn, err := dialWithRetry(ctx, dial, "tcp", c.NetAddr+":80", retryDelay, retryCount)
				if err == nil {
					conn.Close()
					client.Dbg("warmup: %s circuit OK", c.Username)
				} else {
					client.Dbg("warmup: %s failed: %v", c.Username, err)
				}
				done <- struct{}{}
			}()
		}
		for range contacts {
			<-done
		}
		client.Dbg("warmup: done")
		return nil
	}
}

// cmdRotateSenderKeys rotates the senderKey on every active connected tab.
// Silent: produces no TUI output. Errors ignored, the next rotation will retry.
func (m model) cmdRotateSenderKeys() tea.Cmd {
	var cmds []tea.Cmd
	for tabIdx, tab := range m.tabs {
		if tab.isConsole || tab.cli == nil || tab.reconnecting || tab.serverShutdown {
			continue
		}
		cli := tab.cli
		ctx := tab.ctx
		rotTabIdx := tabIdx
		cmds = append(cmds, func() tea.Msg {
			if err := cli.RotateSenderKey(ctx); err == nil {
				return senderKeyRotatedMsg{tabIdx: rotTabIdx}
			}
			return nil
		})
	}
	return tea.Batch(cmds...)
}

// cmdRetryPending retries delivery of pending messages on every
// connected tab (Client.RetryDue) and shows a soft Console warning when
// the oldest unconfirmed one exceeds pendingEscalationAge, one single
// warning per stall (see roomTab.pendingEscalated), never repeated every round.
func (m *model) cmdRetryPending() tea.Cmd {
	var cmds []tea.Cmd
	for _, tab := range m.tabs {
		if tab.isConsole || tab.cli == nil || tab.reconnecting || tab.serverShutdown {
			continue
		}
		cli := tab.cli
		ctx := tab.ctx
		t := tab
		cmds = append(cmds, func() tea.Msg {
			_ = cli.RetryDue(ctx)
			cli.FlushDeferredKeyDistributions(ctx)
			return nil
		})
		age, has := cli.OldestPendingAge()
		if !has {
			t.pendingEscalated = false
			continue
		}
		if has && age >= m.pendingEscalationAge && !t.pendingEscalated {
			t.pendingEscalated = true
			name := t.name
			consoleIdx := m.consoleIdx
			cmds = append(cmds, func() tea.Msg {
				return consoleErrTab(consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.pending_escalation_notice"), name)))()
			})
		}
	}
	return tea.Batch(cmds...)
}

// cmdRetryEphemeralRelBootstraps retries sending the ephemeral
// rel_bootstrap toward every not-yet-confirmed room member,
// SendRelBootstrap (client.go) is a one-shot frame with no
// retransmission of its own (requires peerSessionPubs/peerMLKEMPubs
// already populated at the exact instant of the first call, from init/
// user_joined): if that data hadn't arrived yet at that precise moment,
// it would otherwise be lost for the entire room session, no second
// chance. The gate is rel.peerAcked (rel_bootstrap_ack received from
// the peer), NEVER rel.established (that only says whether WE received
// THEIR bootstrap, an independent signal, in the opposite direction):
// stopping there could interrupt the retry even when OUR OWN send
// never arrived. maybeSendRelBootstrap is already idempotent (reuses
// the same ephemeral keys), same interval as cmdRetryPending above (5s).
func (m *model) cmdRetryEphemeralRelBootstraps() tea.Cmd {
	var cmds []tea.Cmd
	for tabIdx, tab := range m.tabs {
		if tab.isConsole || tab.cli == nil || tab.reconnecting || tab.serverShutdown {
			continue
		}
		for _, key := range tab.online {
			if key == m.myKey() || m.hasPersistentContentRel(key) {
				continue
			}
			if rel := tab.ephRels[key]; rel != nil && rel.peerAcked {
				continue
			}
			userID := tab.cli.LookupUserID(key)
			if userID == "" {
				continue
			}
			if cmd := m.maybeSendRelBootstrap(tabIdx, userID, key); cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
	}
	return tea.Batch(cmds...)
}

// cmdRetrySenderKeyDistribution retries SendSenderKeyReliable toward
// every room member for which the first send never succeeded, see the
// comment on roomTab.keySentTo for the full explanation (same class
// of issue as cmdRetryEphemeralRelBootstraps above, more serious: what's
// at stake here is the peer's ability to decrypt ANY of our messages,
// not just signature verification). No dedicated ack to wait for: once
// the write succeeds, sendSenderKeyTo already delivers confirmation
// through the generic reliable channel (msg_id/msg_ack/RetryDue).
func (m *model) cmdRetrySenderKeyDistribution() tea.Cmd {
	var cmds []tea.Cmd
	for tabIdx, tab := range m.tabs {
		if tab.isConsole || tab.cli == nil || tab.reconnecting || tab.serverShutdown {
			continue
		}
		for _, key := range tab.online {
			if key == m.myKey() || tab.keySentTo[key] {
				continue
			}
			userID := tab.cli.LookupUserID(key)
			if userID == "" {
				continue
			}
			cli, ctx := tab.cli, tab.ctx
			sentTabIdx, sentKey, display := tabIdx, key, m.memberName(tab, key)
			cmds = append(cmds, func() tea.Msg {
				if err := cli.SendSenderKeyReliable(ctx, userID); err != nil {
					client.Dbg("sender_key: retry to %s FAILED: %v", display, err)
					return nil
				}
				return senderKeySentMsg{tabIdx: sentTabIdx, member: sentKey}
			})
		}
	}
	return tea.Batch(cmds...)
}

// cmdActive probes all known contacts in parallel over the active
// transport (Tor or I2P, TCP attempt on :80). For contacts found
// online, automatically sends a "probe_ping" knock, the dedicated
// reachability ping ("sees me"), to which the receiver replies with
// probe_ack.
func (m model) cmdActive() tea.Cmd {
	n := len(m.contacts)
	locIdx := m.defaultTabIdx()
	if n == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_no_contacts_configured")))
	}
	return tea.Batch(
		localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.probe_activated"))),
		m.probeContacts(locIdx, false),
		m.propagateRootRotationToDevices(),
	)
}

// cmdActiveSilent is the silent version used by the timer: shows
// results only if at least one contact is online, but the probe's
// start is still announced on the Console tab, always and immediately.
func (m model) cmdActiveSilent() tea.Cmd {
	return tea.Batch(
		localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.probe_activated"))),
		m.probeContacts(m.active, true),
		m.propagateRootRotationToDevices(),
	)
}

func (m model) probeContacts(tabIdx int, silent bool) tea.Cmd {
	if m.dialTor == nil || len(m.contacts) == 0 {
		if !silent {
			return localTab(tabIdx, i18n.T("tui.err_no_contacts_configured"))
		}
		// Every caller sets m.probing=true BEFORE knowing whether
		// there'll be anything to probe (typically no contact added yet
		// on the first periodic tick), a nil here, never followed by a
		// probeResultMsg, would leave m.probing=true stuck for the rest
		// of the session: every subsequent tickActiveMsg would find it
		// already "in progress" and just reschedule itself, never
		// probing anyone again even once a contact gets added. An empty
		// probeResultMsg still closes the round (case probeResultMsg:
		// m.probing = false), like a cycle where contacts simply don't
		// respond at all.
		return func() tea.Msg { return probeResultMsg{tabIdx: tabIdx, silent: silent} }
	}
	contacts := m.contacts
	dial := m.dialTor
	myUsername := m.myUsername
	myIdentityPub := ed25519.PublicKey(m.myIdentityPub)
	myMLKEMPub := m.myMLKEMPub
	myMLDSAPub := m.myMLDSAPub
	myAddr := m.myAddr
	dhTagFn := m.dhTagFn
	dhTagFnOld := m.dhTagFnOld
	// rootPendingSet, contacts who haven't confirmed the latest root
	// IdentityKey rotation yet (Keystore.RootRotationPendingContacts).
	rootPendingContacts, _ := m.rootRotationPendingNow()
	rootPendingSet := make(map[string]bool, len(rootPendingContacts))
	for _, p := range rootPendingContacts {
		rootPendingSet[string(p)] = true
	}
	var oldIdentityPub ed25519.PublicKey
	if m.oldIdentityPubForRotation != nil {
		oldIdentityPub = m.oldIdentityPubForRotation()
	}
	// tagFnFor picks the per-recipient DH mutuality tag: the tag is
	// static-static, so it only matches if signed with the key that
	// EXACTLY corresponds to the pubkey the recipient already has in
	// their address book for us. A contact still in rootPendingSet
	// still has the OLD root: a knock tagged with the new key would be
	// dropped by their server BEFORE being decrypted (identical 202
	// response, invisible on the sender's side). EVERY knock toward a
	// still-pending contact (not just root_rotate) must stay tagged
	// with the old root until they've applied the announcement.
	tagFnFor := func(pub []byte) func(ed25519.PublicKey) ([]byte, error) {
		if rootPendingSet[string(pub)] && dhTagFnOld != nil {
			return dhTagFnOld
		}
		return dhTagFn
	}
	// fromPubFor picks the per-recipient IdentityPub declared in the
	// knock envelope (KnockPayload.FromIdentityPub), same reason as
	// tagFnFor: handleKnock's "defense in depth" filter (on the
	// recipient's server side) verifies that FromIdentityPub EXACTLY
	// matches the pubkey whose tag matched, for a contact still in
	// rootPendingSet that match happens on the OLD pubkey (tagFnFor
	// above picks dhTagFnOld for them), so FromIdentityPub must also
	// stay the old one, not the current one, or the knock would be
	// dropped there (silently, identical 202 response), for ANY knock
	// type, not just root_rotate.
	fromPubFor := func(pub []byte) ed25519.PublicKey {
		if rootPendingSet[string(pub)] && len(oldIdentityPub) == ed25519.PublicKeySize {
			return oldIdentityPub
		}
		return myIdentityPub
	}
	// dangerBroadcastPendingByPub/dangerEndPendingByPub: same
	// principle as pendingSet above, but for danger_broadcast/danger_end
	// (remote_nuke), a contact can appear in more than one entry if
	// several target devices are queued at once (rare, but not
	// prevented), so the value is a list of TargetDeviceID, not a
	// simple bool.
	dangerBroadcastPendingByPub := make(map[string][][]byte)
	for _, p := range m.pendingDangerBroadcasts {
		for _, pub := range p.IdentityPubs {
			dangerBroadcastPendingByPub[string(pub)] = append(dangerBroadcastPendingByPub[string(pub)], p.TargetDeviceID)
		}
	}
	dangerEndPendingByPub := make(map[string][][]byte)
	for _, p := range m.pendingDangerEnds {
		for _, pub := range p.IdentityPubs {
			dangerEndPendingByPub[string(pub)] = append(dangerEndPendingByPub[string(pub)], p.TargetDeviceID)
		}
	}
	probeTimeout := m.probeContactsTimeout
	knockHttpTO := m.knockHttpTimeout
	retryDelay := m.probeRetryDelay
	retryCount := m.probeRetryCount
	signRelBootstrapFn := m.signRelBootstrapFn
	signRelBootstrapMLDSAFn := m.signRelBootstrapMLDSAFn
	isNukedFn := m.isDeviceNuked
	return func() tea.Msg {
		type res struct {
			netUsername      string
			netPub           []byte
			displayName      string
			online           bool
			generatedRelKeys *RelKeyUpdate
		}
		ch := make(chan res, len(contacts))
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		for _, c := range contacts {
			go func() {
				client.Dbg("probe: TCP → %s:80", c.NetAddr)
				conn, err := dialWithRetry(ctx, dial, "tcp", c.NetAddr+":80", retryDelay, retryCount)
				online := err == nil
				client.Dbg("probe: %s online=%v", c.Username, online)
				var genUpd *RelKeyUpdate
				if online {
					conn.Close()
					// probe_ping: the dedicated, deliberate reachability
					// ping ("sees me"), sent ALWAYS, to every online
					// contact, on every cycle, regardless of any
					// rotation. See sendProbePing/applyProbePing.
					if len(c.IdentityPub) == 32 {
						go sendProbePing(dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), myMLKEMPub, myAddr, tagFnFor(c.IdentityPub), knockHttpTO)
					}
					// rel_init: resent until the peer confirms having OUR
					// OWN keys (RelInitConfirmedByPeer, not
					// PeerRelIdentityPub, see applyRelInit). Same
					// principle as probe_ping above: only when the TCP
					// check just confirmed the contact is reachable right
					// now, never blindly.
					// generatedRelKeys: if OUR OWN relationship keys
					// toward this contact don't exist yet, generate them
					// HERE, needed for contacts whose RelIdentityPriv/
					// RelContentPriv are empty. applyRelInit already generates ITS OWN
					// missing keys, but ONLY upon RECEIVING a rel_init,
					// if BOTH sides of such a pair have an empty
					// RelIdentityPriv, that branch never fires because
					// neither side ever sends a first rel_init: a
					// permanent mutual stall. Generated here, not there,
					// for the same reason the send is already
					// conditioned on "online in this very cycle", never blindly.
					dev, devOK := c.SoleDeviceOrPlaceholder()
					if devOK && (!dev.RelIdentityConfirmedByPeer || !dev.RelContentConfirmedByPeer) && (len(dev.RelIdentityPriv) == 0 || len(dev.RelContentPriv) == 0) {
						identKey, err1 := shared.GenerateRelSigningKey()
						contentKey, err2 := shared.GenerateRelSigningKey()
						if err1 == nil && err2 == nil {
							dev.RelIdentityPriv = identKey.Priv
							dev.RelIdentityMLKEMPriv = identKey.MLKEMSeed
							dev.RelIdentityMLDSAPriv = identKey.MLDSASeed
							dev.RelContentPriv = contentKey.Priv
							dev.RelContentMLKEMPriv = contentKey.MLKEMSeed
							dev.RelContentMLDSAPriv = contentKey.MLDSASeed
							genUpd = &RelKeyUpdate{
								RelIdentityPriv:      dev.RelIdentityPriv,
								RelIdentityMLKEMPriv: dev.RelIdentityMLKEMPriv,
								RelIdentityMLDSAPriv: dev.RelIdentityMLDSAPriv,
								RelContentPriv:       dev.RelContentPriv,
								RelContentMLKEMPriv:  dev.RelContentMLKEMPriv,
								RelContentMLDSAPriv:  dev.RelContentMLDSAPriv,
							}
							client.Dbg("probe: %s relationship keys missing, generated now", c.Username)
						} else {
							client.Dbg("probe: %s relationship key generation failed: err1=%v err2=%v", c.Username, err1, err2)
						}
					}
					if devOK && len(dev.RelIdentityPriv) > 0 && len(dev.RelContentPriv) > 0 && (!dev.RelIdentityConfirmedByPeer || !dev.RelContentConfirmedByPeer) {
						identKey := shared.RelSigningKey{Priv: dev.RelIdentityPriv, MLKEMSeed: dev.RelIdentityMLKEMPriv, MLDSASeed: dev.RelIdentityMLDSAPriv}
						contentKey := shared.RelSigningKey{Priv: dev.RelContentPriv, MLKEMSeed: dev.RelContentMLKEMPriv, MLDSASeed: dev.RelContentMLDSAPriv}
						identPub, identMLKEM, identMLDSA, err1 := shared.RelSigningKeyPublicParts(identKey)
						contentPub, contentMLKEM, contentMLDSA, err2 := shared.RelSigningKeyPublicParts(contentKey)
						if err1 == nil && err2 == nil {
							bootstrap := shared.RelBootstrapPayload{
								IdentityPub:      identPub,
								IdentityMLKEMPub: identMLKEM,
								IdentityMLDSAPub: identMLDSA,
								ContentPub:       contentPub,
								ContentMLKEMPub:  contentMLKEM,
								ContentMLDSAPub:  contentMLDSA,
								DevicePub:        m.myDevicePub,
							}
							client.Dbg("probe: rel_init → %s (%s)", c.Username, c.NetAddr)
							go func() {
								if err := sendRelInitAndReport(dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), myMLKEMPub, myAddr, bootstrap, "rel_init", tagFnFor(c.IdentityPub), signRelBootstrapFn, signRelBootstrapMLDSAFn, knockHttpTO); err != nil {
									client.Dbg("probe: rel_init → %s FAILED: %v", c.Username, err)
								}
							}()
						} else {
							client.Dbg("probe: rel_init → %s SKIPPED, RelSigningKeyPublicParts failed: err1=%v err2=%v", c.Username, err1, err2)
						}
					}
					// rel_identity_rotate/rel_content_rotate: resent until
					// the contact confirms receiving OUR new key
					// (IdentityKeyPending/ContentKeyPending, cleared only
					// by a real _ack, see applyRelRotate). Same
					// principle as rel_init above, never both pending
					// keys at once (mutual exclusion guaranteed by Start*Rotation).
					if devOK && dev.IdentityKeyPending && len(dev.RelIdentityPriv) == ed25519.PrivateKeySize && len(dev.RelContentPriv) == ed25519.PrivateKeySize {
						newKey := shared.RelSigningKey{Priv: dev.RelIdentityPriv, MLKEMSeed: dev.RelIdentityMLKEMPriv, MLDSASeed: dev.RelIdentityMLDSAPriv}
						if newPub, newMLKEM, newMLDSA, err := shared.RelSigningKeyPublicParts(newKey); err == nil {
							ts := shared.NowTS()
							payload := shared.RelRotatePayload{
								NewPub:      newPub,
								NewMLKEMPub: newMLKEM,
								NewMLDSAPub: newMLDSA,
								Sig:         shared.SignRelKeyRotation(ed25519.PrivateKey(dev.RelContentPriv), newPub, myUsername, ts),
								SigMLDSA:    shared.SignRelKeyRotationMLDSA(dev.RelContentMLDSAPriv, newPub, myUsername, ts),
								Ts:          ts,
								DevicePub:   m.myDevicePub,
							}
							go sendRelRotate(dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), myMLKEMPub, myAddr, payload, "rel_identity_rotate", tagFnFor(c.IdentityPub), knockHttpTO)
						}
					}
					if devOK && dev.ContentKeyPending && len(dev.RelContentPriv) == ed25519.PrivateKeySize && len(dev.RelIdentityPriv) == ed25519.PrivateKeySize {
						newKey := shared.RelSigningKey{Priv: dev.RelContentPriv, MLKEMSeed: dev.RelContentMLKEMPriv, MLDSASeed: dev.RelContentMLDSAPriv}
						if newPub, newMLKEM, newMLDSA, err := shared.RelSigningKeyPublicParts(newKey); err == nil {
							ts := shared.NowTS()
							payload := shared.RelRotatePayload{
								NewPub:      newPub,
								NewMLKEMPub: newMLKEM,
								NewMLDSAPub: newMLDSA,
								Sig:         shared.SignRelKeyRotation(ed25519.PrivateKey(dev.RelIdentityPriv), newPub, myUsername, ts),
								SigMLDSA:    shared.SignRelKeyRotationMLDSA(dev.RelIdentityMLDSAPriv, newPub, myUsername, ts),
								Ts:          ts,
								DevicePub:   m.myDevicePub,
							}
							go sendRelRotate(dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), myMLKEMPub, myAddr, payload, "rel_content_rotate", tagFnFor(c.IdentityPub), knockHttpTO)
						}
					}
					// root_rotate: announcement of a root IdentityKey
					// rotation toward this contact, resent until they
					// confirm (RootRotationPendingContacts/root_rotate_ack).
					// Mutual guard: if the relationship with this device
					// has a Rel-key rotation STILL in progress
					// (IdentityKeyPending/ContentKeyPending), the
					// announcement stays queued until that one closes,
					// never two concurrent transitions on the same
					// relationship. Sent toward SoleDevice() like this
					// function's other sends; starting a rotation covers
					// every ready device instead (see
					// StartRelIdentityRotationByPub).
					if rootPendingSet[string(c.IdentityPub)] && devOK && !dev.IdentityKeyPending && !dev.ContentKeyPending && len(dev.RelIdentityPriv) == ed25519.PrivateKeySize && len(myIdentityPub) == ed25519.PublicKeySize {
						ts := shared.NowTS()
						payload := shared.RootRotatePayload{
							NewIdentityPub: myIdentityPub,
							NewMLKEMPub:    myMLKEMPub,
							NewMLDSAPub:    myMLDSAPub,
							Sig:            shared.SignRootRotation(ed25519.PrivateKey(dev.RelIdentityPriv), myIdentityPub, myUsername, ts),
							SigMLDSA:       shared.SignRootRotationMLDSA(dev.RelIdentityMLDSAPriv, myIdentityPub, myUsername, ts),
							Ts:             ts,
							DevicePub:      m.myDevicePub,
						}
						go sendRootRotate(dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), myMLKEMPub, myAddr, payload, tagFnFor(c.IdentityPub), knockHttpTO)
					}
					if len(c.IdentityPub) == 32 {
						for _, targetDeviceID := range dangerBroadcastPendingByPub[string(c.IdentityPub)] {
							go sendDangerMsgSingle("danger_broadcast", dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), tagFnFor(c.IdentityPub), targetDeviceID, knockHttpTO)
						}
						for _, targetDeviceID := range dangerEndPendingByPub[string(c.IdentityPub)] {
							go sendDangerMsgSingle("danger_end", dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), tagFnFor(c.IdentityPub), targetDeviceID, knockHttpTO)
						}
					}
					// Sibling retry queue for rel_revoke: for every
					// not-yet-acked self-revocation certificate held on
					// behalf of ANY sibling device (this one included,
					// SoleDevice()'s backstop role from either side,
					// see keystore.Contact.SiblingRevocations), resend
					// once that sibling is known nuked (isNukedFn,
					// backed by Keystore.NukedDevicePubs; nil disables
					// the retry).
					if len(c.IdentityPub) == 32 && isNukedFn != nil {
						for _, sr := range c.SiblingRevocations {
							if sr == nil || sr.Acked || len(sr.SiblingDevicePub) == 0 {
								continue
							}
							if len(sr.IdentitySig) == 0 && len(sr.ContentSig) == 0 {
								continue
							}
							if !isNukedFn(sr.SiblingDevicePub) {
								continue
							}
							payload := shared.RelRevokePayload{
								DevicePub:        append([]byte(nil), sr.SiblingDevicePub...),
								IdentitySig:      sr.IdentitySig,
								IdentitySigMLDSA: sr.IdentitySigMLDSA,
								ContentSig:       sr.ContentSig,
								ContentSigMLDSA:  sr.ContentSigMLDSA,
							}
							go sendRelRevoke(dial, c.NetAddr, c.IdentityPub, c.MLKEMPub, myUsername, fromPubFor(c.IdentityPub), myMLKEMPub, myAddr, payload, tagFnFor(c.IdentityPub), knockHttpTO)
						}
					}
				}
				ch <- res{netUsername: c.Username, netPub: c.IdentityPub, displayName: c.NameWithUsername(), online: online, generatedRelKeys: genUpd}
			}()
		}
		// Collects results respecting the timeout: if bine/SOCKS5
		// doesn't propagate context cancellation, goroutines can block
		// indefinitely on the dial. The select on ctx.Done() guarantees
		// the function returns within the timeout even then; any
		// goroutines left detached will send to ch (buffered) without
		// blocking once they complete.
		results := make([]contactProbeResult, 0, len(contacts))
		for collected := 0; collected < len(contacts); {
			select {
			case r := <-ch:
				results = append(results, contactProbeResult{netUsername: r.netUsername, netPub: r.netPub, username: r.displayName, online: r.online, generatedRelKeys: r.generatedRelKeys})
				collected++
			case <-ctx.Done():
				collected = len(contacts) // exit right away; any pending goroutines will end up in the buffer
			}
		}
		// drains the channel: collects goroutines that completed right at the timeout
		for {
			select {
			case r := <-ch:
				results = append(results, contactProbeResult{netUsername: r.netUsername, netPub: r.netPub, username: r.displayName, online: r.online, generatedRelKeys: r.generatedRelKeys})
			default:
				return probeResultMsg{tabIdx: tabIdx, results: results, silent: silent}
			}
		}
	}
}

// decodeMLKEMPubField extracts and decodes the "mlkem_pub" field
// (base64, produced by json.Marshal of a []byte server-side) from a raw
// userInfo/wsUserJoined entry, see HandshakeResult.PeerMLKEMPub.
// Returns nil if absent (Client.RegisterMLKEMPub ignores it anyway, but
// this avoids a spurious base64.DecodeString on an empty string).
func decodeMLKEMPubField(raw map[string]any) []byte {
	s, _ := raw["mlkem_pub"].(string)
	if s == "" {
		return nil
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return dec
}

// ephemeralRel holds the EPHEMERAL relationship (point-to-point
// bootstrap, rel_bootstrap channel) with a room member with no
// preexisting direct contact ("introduced"), never persisted,
// discarded when the room closes along with the rest of roomTab.
type ephemeralRel struct {
	myIdentity   shared.RelSigningKey // our ephemeral per-relationship IdentityKey toward this peer, this room
	peerIdentity shared.RelPeerKey    // theirs, received via rel_bootstrap, zero value until it arrives
	// peerIdentityMLKEMPub/peerContentMLKEMPub, the ML-KEM-768
	// companion of the two keys above, received in the same
	// rel_bootstrap but not carried by RelPeerKey (which only serves to
	// verify Sig, never to encrypt), kept separately only so it isn't
	// lost on promotion (finalizePromotion), where it flows into
	// Contact.PeerRel*MLKEMPub. Never used for anything else here.
	peerIdentityMLKEMPub []byte
	myContent            shared.RelSigningKey // our ephemeral per-relationship ContentKey
	peerContent          shared.RelPeerKey    // theirs
	peerContentMLKEMPub  []byte
	established          bool // true = we also received THEIR rel_bootstrap (bidirectional relationship ready)
	// peerAcked, true = the peer confirmed (rel_bootstrap_ack)
	// receiving AND applying OUR OWN rel_bootstrap, a signal
	// independent from established above (that one only says whether
	// WE received THEIRS, nothing about the opposite direction).
	// SendRelBootstrap is a one-shot frame with no ack of its own from
	// the underlying WS/HTTP protocol, without this field,
	// cmdRetryEphemeralRelBootstraps would never know when to stop
	// retrying, or worse would stop as soon as established becomes true
	// even if OUR OWN send never arrived.
	peerAcked bool

	// peerTransport*, the peer's transport address, received ONLY if
	// they sent a rel_promote (see shared.RelPromotePayload/
	// applyRelPromote): they intend to become a real contact.
	peerTransportPub      ed25519.PublicKey
	peerTransportMLKEMPub []byte
	peerTransportMLDSAPub []byte
	peerPromoted          bool

	// myPromoteSent, true after the user has run /grp-promote on this
	// member (we sent OUR OWN rel_promote). Together with peerPromoted
	// it decides if and when to finalize the promotion into a real
	// keystore.Contact (finalizePromotion), never automatically from
	// just receiving THEIR rel_promote, which alone expresses ONLY
	// THEIR intent, never ours: explicit human action required on both sides.
	myPromoteSent bool
	// peerPromoteAcked, true if the peer confirmed (rel_promote_ack)
	// receiving AND applying OUR OWN rel_promote, same principle as
	// peerAcked above for rel_bootstrap: myPromoteSent only says
	// whether WE sent ours, nothing about whether it ever arrived. No
	// automatic retry here (unlike rel_bootstrap/sender_key): /grp-promote
	// is an explicit human action, manually repeatable by the user,
	// this field only provides visibility (log), it doesn't drive a periodic cycle.
	peerPromoteAcked bool
}

// hasPersistentContentRel reports whether a persistent, USABLE
// ContentKey relationship already exists with the member whose key is
// memberKey, not "is a known contact" (mere presence in the address book),
// but "the contact really has relationship keys exchanged" (at least
// one device with OUR RelContentPriv and at least one device with
// THEIR PeerRelContentPub, not revoked). A contact saved from a URI/QR
// without ever completing a real rel_init handshake is "known" but
// doesn't have this, using address-book presence alone as the gate to skip
// the ephemeral bootstrap would leave that case stuck forever on both
// sides (neither path available).
func (m *model) hasPersistentContentRel(memberKey string) bool {
	c := m.resolveContactByPub(memberKeyPub(memberKey))
	if c == nil {
		return false
	}
	hasMine := false
	for _, dev := range c.Devices {
		if dev != nil && len(dev.RelContentPriv) == ed25519.PrivateKeySize {
			hasMine = true
			break
		}
	}
	if !hasMine {
		return false
	}
	for _, dev := range c.Devices {
		if dev != nil && len(dev.PeerRelContentPub) == ed25519.PublicKeySize && !dev.RevokedContent {
			return true
		}
	}
	return false
}

// maybeSendRelBootstrap generates (if not already done for this peer in
// this room) our ephemeral relationship key pair and sends it to
// toUserID, the session of the member with key memberKey, only if a persistent, USABLE relationship doesn't already
// exist (hasPersistentContentRel, not mere presence in the address
// book): a direct contact with keys already exchanged needs no
// bootstrap at all, but one only "known by name" does. Idempotent:
// called on every init/user_joined (like SendSenderKey), regenerates
// the keys only the first time, then just resends the same ones,
// harmless, same treatment already used for sender_key.
func (m *model) maybeSendRelBootstrap(tabIdx int, toUserID, memberKey string) tea.Cmd {
	if tabIdx < 0 || tabIdx >= len(m.tabs) {
		return nil
	}
	if memberKey == "" || memberKey == m.myKey() || m.hasPersistentContentRel(memberKey) {
		return nil // self, or a persistent relationship already usable: no bootstrap needed
	}
	tab := m.tabs[tabIdx]
	if tab.ephRels == nil {
		tab.ephRels = make(map[string]*ephemeralRel)
	}
	rel := tab.ephRels[memberKey]
	if rel == nil {
		identKey, err := shared.GenerateRelSigningKey()
		if err != nil {
			return nil
		}
		contentKey, err := shared.GenerateRelSigningKey()
		if err != nil {
			return nil
		}
		rel = &ephemeralRel{myIdentity: identKey, myContent: contentKey}
		tab.ephRels[memberKey] = rel
	}
	username := m.memberName(tab, memberKey)
	identPub, identMLKEM, identMLDSA, err := shared.RelSigningKeyPublicParts(rel.myIdentity)
	if err != nil {
		return nil
	}
	contentPub, contentMLKEM, contentMLDSA, err := shared.RelSigningKeyPublicParts(rel.myContent)
	if err != nil {
		return nil
	}
	payload := shared.RelBootstrapPayload{
		IdentityPub:      identPub,
		IdentityMLKEMPub: identMLKEM,
		IdentityMLDSAPub: identMLDSA,
		ContentPub:       contentPub,
		ContentMLKEMPub:  contentMLKEM,
		ContentMLDSAPub:  contentMLDSA,
	}
	cli, ctx := tab.cli, tab.ctx
	return func() tea.Msg {
		// SendRelBootstrap is a one-shot frame, no retransmission: if it
		// fails here (typically peerSessionPubs/peerMLKEMPubs not yet
		// populated for toUserID at this instant), this logs it so the
		// failure isn't silent even with `neutrino debug` active.
		if err := cli.SendRelBootstrap(ctx, toUserID, payload); err != nil {
			client.Dbg("rel_bootstrap: send to %s FAILED: %v", username, err)
		}
		return nil
	}
}

// applyRelBootstrap decrypts and registers an incoming rel_bootstrap
// from an "introduced" member, the counterpart of maybeSendRelBootstrap
// above. Also generates our own half if not already done (can arrive
// before this client has processed the peer's entry in init/user_joined).
// Returns a tea.Cmd that sends rel_bootstrap_ack to the sender ONLY when
// applying it succeeds all the way through, the sender needs it to
// know THEIR send arrived and to stop retrying (see SendRelBootstrapAck).
func (m *model) applyRelBootstrap(tabIdx int, fromUserID, payloadB64 string) tea.Cmd {
	if tabIdx < 0 || tabIdx >= len(m.tabs) {
		return nil
	}
	tab := m.tabs[tabIdx]
	// See the comment in maybeSendRelBootstrap, same case, receiving
	// side. An unknown from_user_id here typically indicates a
	// rel_bootstrap that arrived before this client processed the
	// sender's user_joined/init (RegisterUser not yet called).
	key := tab.cli.LookupMemberKey(fromUserID)
	if key == "" {
		client.Dbg("rel_bootstrap: received from unknown user_id %s, discarded", client.ShortUID(fromUserID))
		return nil
	}
	username := m.memberName(tab, key)
	if m.hasPersistentContentRel(key) {
		return nil // persistent relationship already usable: ephemeral bootstrap not needed, not an error
	}
	p, err := tab.cli.DecryptRelBootstrap(payloadB64)
	if err != nil {
		client.Dbg("rel_bootstrap: decryption from %s FAILED: %v", username, err)
		return nil
	}
	if tab.ephRels == nil {
		tab.ephRels = make(map[string]*ephemeralRel)
	}
	rel := tab.ephRels[key]
	if rel == nil {
		identKey, err := shared.GenerateRelSigningKey()
		if err != nil {
			client.Dbg("rel_bootstrap: ephemeral key generation toward %s FAILED: %v", username, err)
			return nil
		}
		contentKey, err := shared.GenerateRelSigningKey()
		if err != nil {
			client.Dbg("rel_bootstrap: ephemeral key generation toward %s FAILED: %v", username, err)
			return nil
		}
		rel = &ephemeralRel{myIdentity: identKey, myContent: contentKey}
		tab.ephRels[key] = rel
	}
	rel.peerIdentity = shared.RelPeerKey{Pub: p.IdentityPub, MLDSAPub: p.IdentityMLDSAPub}
	rel.peerIdentityMLKEMPub = p.IdentityMLKEMPub
	rel.peerContent = shared.RelPeerKey{Pub: p.ContentPub, MLDSAPub: p.ContentMLDSAPub}
	rel.peerContentMLKEMPub = p.ContentMLKEMPub
	rel.established = true
	client.Dbg("rel_bootstrap: received and applied from %s, sending ack", username)
	cli, ctx := tab.cli, tab.ctx
	return func() tea.Msg {
		if err := cli.SendRelBootstrapAck(ctx, fromUserID); err != nil {
			client.Dbg("rel_bootstrap_ack: send to %s FAILED: %v", username, err)
		}
		return nil
	}
}

// applyRelPromote decrypts and registers an incoming rel_promote, the
// peer intends to become a real contact, and sends us their transport
// address to make it possible. Requires an already-established
// ephemeral relationship (rel_bootstrap completed in both directions),
// a rel_promote with no prior bootstrap is ignored. If WE have ALSO
// already sent our own rel_promote for this peer (myPromoteSent,
// explicit human action via /grp-promote, never triggered from here),
// immediately finalizes the promotion into a real keystore.Contact, if
// instead we're the first to arrive, we just record the received
// intent, waiting for the user to run /grp-promote themselves.
func (m *model) applyRelPromote(tabIdx int, fromUserID, payloadB64 string) tea.Cmd {
	if tabIdx < 0 || tabIdx >= len(m.tabs) {
		return nil
	}
	tab := m.tabs[tabIdx]
	key := tab.cli.LookupMemberKey(fromUserID)
	if key == "" {
		return nil
	}
	// The signed label is the one the sender signs with: its own
	// username, as the server relays it for that session.
	username := tab.cli.LookupUsername(fromUserID)
	rel := tab.ephRels[key]
	if rel == nil || !rel.established {
		return nil
	}
	p, err := tab.cli.DecryptRelPromote(payloadB64)
	if err != nil {
		return nil
	}
	// The transport identity offered must be the member's own identity
	// key, the one it is known by in this room.
	if !bytes.Equal(p.TransportPub, memberKeyPub(key)) {
		client.Dbg("rel_promote: %s offers an identity different from its own member key, discarded", m.memberName(tab, key))
		return nil
	}
	// Signature required against the sender's ephemeral per-relationship
	// IdentityKey, already known from rel.established (see the comment
	// on RelPromotePayload.Ts/Sig/SigMLDSA), without it, a malicious
	// server could inject a fabricated transport address.
	if !shared.VerifyRelPromote(rel.peerIdentity.Pub, p.TransportPub, p.TransportMLKEMPub, p.TransportMLDSAPub, username, p.Ts, p.Sig) {
		client.Dbg("rel_promote: %s invalid signature, discarded", username)
		return nil
	}
	if len(rel.peerIdentity.MLDSAPub) > 0 && len(p.SigMLDSA) > 0 {
		if !shared.VerifyRelPromoteMLDSA(rel.peerIdentity.MLDSAPub, p.TransportPub, p.TransportMLKEMPub, p.TransportMLDSAPub, username, p.Ts, p.SigMLDSA) {
			client.Dbg("rel_promote: %s invalid MLDSA signature, discarded", username)
			return nil
		}
	}
	rel.peerTransportPub = p.TransportPub
	rel.peerTransportMLKEMPub = p.TransportMLKEMPub
	rel.peerTransportMLDSAPub = p.TransportMLDSAPub
	rel.peerPromoted = true
	client.Dbg("rel_promote: received and applied from %s, sending ack", username)
	cli, ctx := tab.cli, tab.ctx
	ackCmd := func() tea.Msg {
		if err := cli.SendRelPromoteAck(ctx, fromUserID); err != nil {
			client.Dbg("rel_promote_ack: send to %s FAILED: %v", username, err)
		}
		return nil
	}
	if rel.myPromoteSent {
		if finCmd := m.finalizePromotion(tabIdx, key); finCmd != nil {
			return tea.Batch(ackCmd, finCmd)
		}
	}
	return ackCmd
}

// cmdPromote (behind /grp-promote) promotes an EPHEMERAL member of the
// current room (no preexisting direct contact, point-to-point bootstrap
// already completed) to a real contact, explicit human action, never
// automatic, required on BOTH sides (the other member must run the
// same command on us). Reuses the four relationship keys already
// exchanged in the ephemeral bootstrap (no new generation): only sends
// the transport address in addition (rel_promote), the one piece of
// data missing to make the contact reachable outside this room.
func (m *model) cmdPromote(name string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.groupID == "" || tab.cli == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_promote_room_only")))
	}
	if name == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_promote")))
	}
	if pub, ok := decodePickerContactKey(name); ok && bytes.Equal(pub, m.myIdentityPub) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_promote_self")))
	}
	member, n := m.resolveMemberArg(tab, name, func(gm GroupMember) bool { return memberKey(gm) != m.myKey() })
	if n != 1 {
		if n == 0 && strings.EqualFold(name, m.myUsername) {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_promote_self")))
		}
		return m.openPicker(client.CmdPromote, name)
	}
	key := memberKey(member)
	target := m.memberName(tab, key)
	if m.resolveContactByPub(member.IdentityPub) != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_promote_already_contact"), target)))
	}
	if tab.ephRels == nil {
		tab.ephRels = make(map[string]*ephemeralRel)
	}
	rel := tab.ephRels[key]
	if rel == nil || !rel.established {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_promote_not_established"), target)))
	}
	rel.myPromoteSent = true

	userID := tab.cli.LookupUserID(key)
	ts := shared.NowTS()
	payload := shared.RelPromotePayload{
		TransportPub:      ed25519.PublicKey(m.myIdentityPub),
		TransportMLKEMPub: m.myMLKEMPub,
		TransportMLDSAPub: m.myMLDSAPub,
		Ts:                ts,
		Sig:               shared.SignRelPromote(rel.myIdentity.Priv, ed25519.PublicKey(m.myIdentityPub), m.myMLKEMPub, m.myMLDSAPub, m.myUsername, ts),
	}
	if len(rel.myIdentity.MLDSASeed) > 0 {
		payload.SigMLDSA = shared.SignRelPromoteMLDSA(rel.myIdentity.MLDSASeed, ed25519.PublicKey(m.myIdentityPub), m.myMLKEMPub, m.myMLDSAPub, m.myUsername, ts)
	}
	cli, ctx := tab.cli, tab.ctx
	sendCmd := func() tea.Msg {
		if err := cli.SendRelPromote(ctx, userID, payload); err != nil {
			client.Dbg("rel_promote: send to %s FAILED: %v", target, err)
		}
		return nil
	}
	if rel.peerPromoted {
		if finCmd := m.finalizePromotion(tabIdx, key); finCmd != nil {
			return tea.Batch(sendCmd, finCmd)
		}
	}
	return tea.Batch(sendCmd, localTab(tabIdx, styleMeta.Render(fmt.Sprintf(i18n.T("tui.promote_request_sent"), target))))
}

// finalizePromotion turns the ephemeral relationship with the member
// whose key is memberKey (already established, with myPromoteSent && peerPromoted, a
// condition checked by its only two callers, cmdPromote and
// applyRelPromote) into a real keystore.Contact: reuses the four
// relationship keys already exchanged in the ephemeral bootstrap, adds
// only the transport address received via rel_promote. From here on
// the relationship is a contact like any other, RelInitConfirmedByPeer
// starts false, confirmed by the usual rel_init/rel_init_ack cycle
// triggered right below (same treatment as a contact added from a QR,
// see case contactAddedMsg).
func (m *model) finalizePromotion(tabIdx int, memberKey string) tea.Cmd {
	if tabIdx < 0 || tabIdx >= len(m.tabs) {
		return nil
	}
	tab := m.tabs[tabIdx]
	rel := tab.ephRels[memberKey]
	if rel == nil || !rel.established || !rel.myPromoteSent || !rel.peerPromoted {
		return nil
	}
	// The contact is saved under the username label the member is known
	// by in this room; its identity is the transport key it offered.
	username := tab.memberLabels[memberKey]
	if username == "" {
		username = m.memberName(tab, memberKey)
	}
	if c := m.resolveContactByPub(rel.peerTransportPub); c != nil {
		// Already promoted via another path (concurrent re-entry), cleanup only.
		client.Dbg("finalizePromotion: %s already a contact (devices=%d %v), discarding and clearing ephRels", username, len(c.Devices), deviceKeyList(c.Devices))
		delete(tab.ephRels, memberKey)
		return nil
	}
	client.Dbg("finalizePromotion: %s promoting the ephemeral relationship to a real contact", username)
	fn := m.promoteEphemeralContact
	if fn == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.add_contact_unavailable")))
	}
	consoleIdx := m.consoleIdx
	transportPub := append([]byte(nil), rel.peerTransportPub...)
	transportMLKEM := append([]byte(nil), rel.peerTransportMLKEMPub...)
	transportMLDSA := append([]byte(nil), rel.peerTransportMLDSAPub...)
	myIdentKey, myContentKey := rel.myIdentity, rel.myContent
	peerIdent, peerContent := rel.peerIdentity, rel.peerContent
	peerIdentMLKEM := append([]byte(nil), rel.peerIdentityMLKEMPub...)
	peerContentMLKEM := append([]byte(nil), rel.peerContentMLKEMPub...)
	addr := m.computeAddress(ed25519.PublicKey(transportPub))
	delete(tab.ephRels, memberKey)

	return func() tea.Msg {
		if err := fn(username, transportPub, transportMLKEM, transportMLDSA, myIdentKey, myContentKey, peerIdent, peerIdentMLKEM, peerContent, peerContentMLKEM); err != nil {
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error_for"), username, err.Error())), isError: true}
		}
		newContact := ContactInfo{
			Username:    username,
			NetAddr:     addr,
			IdentityPub: ed25519.PublicKey(transportPub),
			MLKEMPub:    transportMLKEM,
			MLDSAPub:    transportMLDSA,
			// No DevicePub exchange in this flow (ephemeral in-room
			// bootstrap), placeholder "" entry, promoted by the first
			// real rel_init/rel_init_ack (same treatment as AddContact).
			Devices: map[string]*keystore.DeviceRelation{
				"": {
					RelIdentityPriv:         myIdentKey.Priv,
					RelIdentityMLKEMPriv:    myIdentKey.MLKEMSeed,
					RelIdentityMLDSAPriv:    myIdentKey.MLDSASeed,
					PeerRelIdentityPub:      peerIdent.Pub,
					PeerRelIdentityMLKEMPub: peerIdentMLKEM,
					PeerRelIdentityMLDSAPub: peerIdent.MLDSAPub,
					RelContentPriv:          myContentKey.Priv,
					RelContentMLKEMPriv:     myContentKey.MLKEMSeed,
					RelContentMLDSAPriv:     myContentKey.MLDSASeed,
					PeerRelContentPub:       peerContent.Pub,
					PeerRelContentMLKEMPub:  peerContentMLKEM,
					PeerRelContentMLDSAPub:  peerContent.MLDSAPub,
				},
			},
		}
		return contactAddedMsg{
			tabIdx:      tabIdx,
			displayText: fmt.Sprintf(i18n.T("tui.contact_added"), username),
			identityPub: ed25519.PublicKey(transportPub),
			contact:     newContact,
			isTabPeer:   true,
		}
	}
}

// cmdRotateRelIdentity/cmdRotateRelContent (behind /sec-rotate-rel-identity
// and /sec-rotate-rel-content) start rotating ONE of the two
// relationship keys toward a contact. The mutual guard (never two keys
// rotating at once toward the same contact) lives in the keystore
// (StartRelIdentityRotationByPub/StartRelContentRotationByPub), not
// repeated here: a rejected attempt simply comes back as a generic error.
// cmdRotateKey starts a rotation WITH CONTINUITY of the root
// IdentityKey (network address). A rare, wide-reaching operation:
// changes the address every contact and every one of our own sibling
// devices reaches us at. No picker, no modal popup, explicit text
// confirmation (typing "ROTATE"), same principle already used for
// /nuke ("NUKE"): less UI machinery to maintain for such a rare action.
func (m *model) cmdRotateKey(arg string) tea.Cmd {
	if strings.TrimSpace(arg) != "ROTATE" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_root_rotate_confirm")))
	}
	if m.startRootRotation == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.add_contact_unavailable")))
	}
	fn := m.startRootRotation
	consoleIdx := m.consoleIdx
	return func() tea.Msg {
		newIdentityPub, newMLKEMPub, newMLDSAPub, newAddr, err := fn()
		if err != nil {
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(err.Error()), isError: true}
		}
		return rootRotationAdoptedMsg{newIdentityPub: newIdentityPub, newMLKEMPub: newMLKEMPub, newMLDSAPub: newMLDSAPub, newAddr: newAddr, consoleKey: "tui.root_rotate_started"}
	}
}

// cmdDeviceSyncTrigger starts a remote address-book sync with one of
// our own sibling devices (KnownDevices). name can be the DeviceLabel
// or a hex prefix of the DeviceID; with no argument (or no match) it
// lists known devices instead of opening a dedicated picker, consistent
// with how rare the operation is.
func (m *model) cmdDeviceSyncTrigger(name string) tea.Cmd {
	devices := m.knownDevicesNow()
	if len(devices) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_remote_nuke_no_known_devices")))
	}
	name = strings.TrimSpace(name)
	var target *DeviceRecordInfo
	for i := range devices {
		d := &devices[i]
		if name != "" && (d.Label == name || strings.HasPrefix(hex.EncodeToString(d.DeviceID), strings.ToLower(name))) {
			target = d
			break
		}
	}
	if target == nil {
		var labels []string
		for _, d := range devices {
			label := d.Label
			if label == "" {
				label = hex.EncodeToString(d.DeviceID)
			}
			labels = append(labels, label)
		}
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_device_sync_usage"), strings.Join(labels, ", "))))
	}
	if m.dialTor == nil || m.buildDeviceSyncSyncKnock == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.add_contact_unavailable")))
	}
	dial := m.dialTor
	computeAddr := m.computeAddress
	newPubFor := m.networkIdentityPubFor
	buildKnock := m.buildDeviceSyncSyncKnock
	knockHttpTO := m.knockHttpTimeout
	deviceID := target.DeviceID
	label := target.Label
	if label == "" {
		label = hex.EncodeToString(deviceID)
	}
	consoleIdx := m.consoleIdx
	return func() tea.Msg {
		if newPubFor == nil {
			return nil
		}
		pub := newPubFor(deviceID)
		addr := computeAddr(pub)
		if addr == "" {
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_device_sync_unreachable"), label)), isError: true}
		}
		payload, err := buildKnock(false, deviceID)
		if err != nil {
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(err.Error()), isError: true}
		}
		if err := postDeviceSyncKnock(dial, addr, payload, knockHttpTO); err != nil {
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_device_sync_failed"), label, err)), isError: true}
		}
		return localDisplayMsg{tabIdx: consoleIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.device_sync_requested"), label))}
	}
}

func (m *model) cmdRotateRelIdentity(name string) tea.Cmd {
	return m.cmdStartRelRotation(name, "identity")
}

func (m *model) cmdRotateRelContent(name string) tea.Cmd {
	return m.cmdStartRelRotation(name, "content")
}

func (m *model) cmdStartRelRotation(name string, which string) tea.Cmd {
	cmdID := client.CmdRotateRelIdentity
	if which == "content" {
		cmdID = client.CmdRotateRelContent
	}
	if name == "" {
		return m.openPicker(cmdID, "")
	}
	c := m.resolveNameOrPickerKey(name)
	if c == nil {
		return m.openPicker(cmdID, name)
	}
	// Opposite guard to probeContacts's (rootPendingSet blocks
	// root_rotate announcements while a Rel-rotation toward that
	// contact is in progress): here it blocks starting a NEW
	// Rel-rotation if a root rotation is still pending toward them,
	// never two concurrent transitions on the same relationship.
	rootPendingContacts, _ := m.rootRotationPendingNow()
	for _, p := range rootPendingContacts {
		if bytes.Equal(p, c.IdentityPub) {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_root_rotation_pending_for_contact"), c.Username)))
		}
	}
	var fn func([]byte) (map[string]shared.RelSigningKey, error)
	if which == "identity" {
		fn = m.startRelIdentityRotationByPub
	} else {
		fn = m.startRelContentRotationByPub
	}
	if fn == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.add_contact_unavailable")))
	}
	username := c.Username
	contactPub := c.IdentityPub
	consoleIdx := m.consoleIdx
	return func() tea.Msg {
		newKeys, err := fn(contactPub)
		if err != nil {
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error_for"), username, err.Error())), isError: true}
		}
		return relRotationStartedMsg{username: username, contactPub: contactPub, which: which, newKeys: newKeys}
	}
}

// encryptKnockTagged encrypts a KnockPayload (shared.EncryptKnock) and
// attaches the static-static DH tag (shared.KnockDHTag, via dhTagFn)
// required by the server-side pre-decryption filter, see
// TUIParams.DHTagFn. dhTagFn must never be nil in production (set by
// cmd/main.go); a knock sent without a valid tag would
// be silently dropped by the server anyway (mandatory mutuality), so
// this fails explicitly instead of sending a payload that would be
// ignored regardless.
//
// recipientMLKEMPubBytes is the recipient's durable ML-KEM-768
// encapsulation key (1184 bytes, from Contact.MLKEMPub/
// pendingContact.mlkemPub), nil or empty for a contact with no
// known key: the knock stays encrypted in
// classic form, permanently, not just as a transitional state (see
// shared.EncryptKnock). A present but malformed value is silently
// ignored (falls back to the classic form) instead of failing the
// entire send, a contact with corrupted data in the address book must
// not block otherwise valid knocks.
func encryptKnockTagged(dhTagFn func(ed25519.PublicKey) ([]byte, error), recipientPub ed25519.PublicKey, recipientMLKEMPubBytes []byte, kp shared.KnockPayload) (string, error) {
	if dhTagFn == nil {
		return "", errors.New("dhTagFn not set")
	}
	tag, err := dhTagFn(recipientPub)
	if err != nil {
		return "", err
	}
	var recipientMLKEMPub *mlkem.EncapsulationKey768
	if len(recipientMLKEMPubBytes) > 0 {
		if ek, err := mlkem.NewEncapsulationKey768(recipientMLKEMPubBytes); err == nil {
			recipientMLKEMPub = ek
		}
	}
	return shared.EncryptKnockWithTag(recipientPub, recipientMLKEMPub, kp, tag)
}

// mlkemPubForContact looks in m.contacts for a contact with IdentityPub
// equal to pub and returns its raw MLKEMPub (nil if the contact is
// unknown or doesn't have a known ML-KEM key yet), helper for
// encryptKnockTagged callers that only have an Ed25519 pubkey on hand,
// not already the whole ContactInfo.
func (m *model) mlkemPubForContact(pub ed25519.PublicKey) []byte {
	for i := range m.contacts {
		if ed25519.PublicKey(m.contacts[i].IdentityPub).Equal(pub) {
			return m.contacts[i].MLKEMPub
		}
	}
	return nil
}

// sendRelInitCmd builds (if possible) the tea.Cmd that sends c our
// public relationship keys, one knock per entry of knockTypes, sent in
// order: "rel_init" for the first send (right after AddContact),
// "rel_init_ack" for the symmetric reply (applyRelInit), possibly
// followed by our own "rel_init". Returns nil if prerequisites are missing (own keys
// not yet generated, transport not active), never a blocking error,
// fire-and-forget: the periodic probe cycle will retry.
// sendRelInitCmd sends a rel_init/rel_init_ack toward ONE specific
// device of the contact (dev, already resolved by the caller, never
// internally via SoleDevice(), which would fail as soon as the contact
// has 2+ known devices). netAddr is dev.Address, the address declared
// by THAT device, falling back to c.NetAddr (root) only if still
// empty: the only legitimate case is the very first rel_init ever sent
// to a freshly-added contact, where nothing has been received yet from
// any of its devices (the only address known at that point is the root
// one from the QR/URI).
func (m *model) sendRelInitCmd(c ContactInfo, dev *keystore.DeviceRelation, knockTypes ...string) tea.Cmd {
	if dev == nil || len(dev.RelIdentityPriv) == 0 || len(dev.RelContentPriv) == 0 || m.dialTor == nil {
		return nil
	}
	netAddr := dev.Address
	if netAddr == "" {
		netAddr = c.NetAddr
	}
	if netAddr == "" {
		return nil
	}
	identKey := shared.RelSigningKey{Priv: dev.RelIdentityPriv, MLKEMSeed: dev.RelIdentityMLKEMPriv, MLDSASeed: dev.RelIdentityMLDSAPriv}
	contentKey := shared.RelSigningKey{Priv: dev.RelContentPriv, MLKEMSeed: dev.RelContentMLKEMPriv, MLDSASeed: dev.RelContentMLDSAPriv}
	identPub, identMLKEM, identMLDSA, err := shared.RelSigningKeyPublicParts(identKey)
	if err != nil {
		return nil
	}
	contentPub, contentMLKEM, contentMLDSA, err := shared.RelSigningKeyPublicParts(contentKey)
	if err != nil {
		return nil
	}
	bootstrap := shared.RelBootstrapPayload{
		IdentityPub:      identPub,
		IdentityMLKEMPub: identMLKEM,
		IdentityMLDSAPub: identMLDSA,
		ContentPub:       contentPub,
		ContentMLKEMPub:  contentMLKEM,
		ContentMLDSAPub:  contentMLDSA,
		DevicePub:        m.myDevicePub,
	}
	dial := m.dialTor
	recipientPub := ed25519.PublicKey(c.IdentityPub)
	recipientMLKEMPub := c.MLKEMPub
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	myMLKEMPub := m.myMLKEMPub
	myAddr := m.myAddr
	dhTagFn := m.dhTagFn
	signRelBootstrapFn := m.signRelBootstrapFn
	signRelBootstrapMLDSAFn := m.signRelBootstrapMLDSAFn
	knockTO := m.knockHttpTimeout
	targetUsername := c.Username
	return func() tea.Msg {
		// The outcome is always visible in debug here, same scheme
		// already used by probeContacts for the periodic retry
		// (client.Dbg("probe: rel_init → ... FAILED")): without this,
		// the very first send (right after AddContact, or the
		// rel_init_ack reply from applyRelInit) would be blind by
		// construction, indistinguishable from a success to any caller.
		go func() {
			for _, knockType := range knockTypes {
				if err := sendRelInitAndReport(dial, netAddr, recipientPub, recipientMLKEMPub, myUsername, myPub, myMLKEMPub, myAddr, bootstrap, knockType, dhTagFn, signRelBootstrapFn, signRelBootstrapMLDSAFn, knockTO); err != nil {
					client.Dbg("sendRelInitCmd: %s → %s (%s) FAILED: %v", knockType, targetUsername, netAddr, err)
				} else {
					client.Dbg("sendRelInitCmd: %s → %s (%s) sent", knockType, targetUsername, netAddr)
				}
			}
		}()
		return nil
	}
}

// sendRelInitAndReport is sendRelInit with the outcome visible to the
// caller, a failure here (encryptKnockTagged, or the HTTP POST itself
// e.g. a Tor circuit that fails to build despite the immediately
// preceding TCP check having succeeded) is otherwise indistinguishable
// from a success, for any caller.
func sendRelInitAndReport(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, myMLKEMPub []byte, myAddr string,
	relBootstrap shared.RelBootstrapPayload, knockType string,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	signRelBootstrapFn func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte,
	signRelBootstrapMLDSAFn func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte,
	timeout time.Duration) error {

	// Authenticated against the sender's root IdentityKey (the only
	// anchor already known to the recipient at this point in the
	// exchange, see the comment on RelBootstrapPayload.Ts/Sig/SigMLDSA
	// in relbootstrap.go), never for the ephemeral in-room bootstrap
	// (EncryptRelBootstrap, a different channel, never passed through
	// here). Ts is fresh on every single send/retry, never reused from
	// a previous call, same principle as RelKeyRotationMsg.
	if signRelBootstrapFn != nil {
		relBootstrap.Ts = shared.NowTS()
		relBootstrap.Sig = signRelBootstrapFn(relBootstrap.IdentityPub, relBootstrap.ContentPub, relBootstrap.DevicePub, myUsername, relBootstrap.Ts)
		if signRelBootstrapMLDSAFn != nil {
			relBootstrap.SigMLDSA = signRelBootstrapMLDSAFn(relBootstrap.IdentityPub, relBootstrap.ContentPub, relBootstrap.DevicePub, myUsername, relBootstrap.Ts)
		}
	}

	kp := shared.KnockPayload{
		Type:            knockType,
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		MLKEMPub:        myMLKEMPub,
		FromAddr:        myAddr,
		RelBootstrap:    &relBootstrap,
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return fmt.Errorf("encryptKnockTagged: %w", err)
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// sendRelRotate sends a "rel_identity_rotate"/"rel_content_rotate"
// knock (request) or its "_ack" counterpart (confirmation), same
// scheme as sendRelInit, the payload (already built by the caller: the
// request carries Sig/SigMLDSA, the ack just echoes NewPub) is the only
// difference between the two directions. No distinction here between
// IdentityKey and ContentKey: knockType alone is enough to route
// correctly on the receiving side (applyRelRotate).
func sendRelRotate(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, myMLKEMPub []byte, myAddr string,
	relRotate shared.RelRotatePayload, knockType string,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	timeout time.Duration) {

	kp := shared.KnockPayload{
		Type:            knockType,
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		MLKEMPub:        myMLKEMPub,
		FromAddr:        myAddr,
		RelRotate:       &relRotate,
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// sendRootRotate sends the "root_rotate" knock (root IdentityKey
// rotation announcement) toward ONE contact, the exact same scheme as
// sendRelRotate, myPub/dhTagFn have already been picked by the caller
// based on whether this contact has already applied the latest
// rotation or not (see fromPubFor/tagFnFor in probeContacts).
func sendRootRotate(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, myMLKEMPub []byte, myAddr string,
	rootRotate shared.RootRotatePayload,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	timeout time.Duration) {

	kp := shared.KnockPayload{
		Type:            "root_rotate",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		MLKEMPub:        myMLKEMPub,
		FromAddr:        myAddr,
		RootRotate:      &rootRotate,
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// sendRelRevoke sends the fire-and-forget "rel_revoke" knock toward one
// contact, carrying one sibling device's already-prepared self-
// revocation certificates (relRevoke.DevicePub/IdentitySig/ContentSig,
// never generated here, see keystore.SiblingRevocation), the sender
// may be the device the certificates are FOR, or any sibling acting as
// a backstop on its behalf (keystore.Contact.SiblingRevocations); the
// recipient cannot and need not distinguish the two. MLKEMPub/FromAddr
// are populated (unlike sendRelRevokeAck) so the recipient's
// applyRelRevoke can address its own "rel_revoke_ack" back.
func sendRelRevoke(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, myMLKEMPub []byte, myAddr string,
	relRevoke shared.RelRevokePayload,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	timeout time.Duration) {

	kp := shared.KnockPayload{
		Type:            "rel_revoke",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		MLKEMPub:        myMLKEMPub,
		FromAddr:        myAddr,
		RelRevoke:       &relRevoke,
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// sendRelRevokeAck sends the fire-and-forget "rel_revoke_ack" knock
// toward the device that announced a just-verified revocation,
// RelRevoke only carries DevicePub (echo, no signature: an ack
// certifies nothing new, only confirms receipt, same principle as
// RelRotatePayload in the ack). netAddr is the network address of the
// ACTUAL SENDER of the knock (KnockPayload.FromAddr), never an address
// derived from the shared root: a sibling revoking on behalf of another
// device resides at a different address than the revoked device (the
// network address is per-device, only the root is shared between
// siblings, see NetworkIdentityPrivKeyFor).
func sendRelRevokeAck(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, devicePub []byte,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	timeout time.Duration) {

	kp := shared.KnockPayload{
		Type:            "rel_revoke_ack",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		RelRevoke:       &shared.RelRevokePayload{DevicePub: devicePub},
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// sendRootRotateAck sends the fire-and-forget "root_rotate_ack" knock
// toward the contact who just announced a valid root rotation,
// FromIdentityPub is ALWAYS our stable, current identity (never old: WE
// are the one replying, not sending our own announcement), the tag is
// the current one (dhTagFn, not dhTagFnOld: the announcement's sender
// already has our current key in their address book, they aren't the
// one in transition).
func sendRootRotateAck(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	timeout time.Duration) {

	kp := shared.KnockPayload{
		Type:            "root_rotate_ack",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// postDeviceSyncKnock sends an already-prepared "device_sync"/
// "device_sync_ack"/"contact_tombstone" knock payload (already
// tagged/encrypted by BuildDeviceSyncRotationKnock/
// BuildDeviceSyncSyncKnock/BuildDeviceSyncAckKnock/
// BuildContactTombstoneKnock) toward one of our own devices at netAddr,
// through the device-sync endpoint (the payload can carry the whole
// address book). Returns an error unless that device accepted it.
func postDeviceSyncKnock(dial func(context.Context, string, string) (net.Conn, error), netAddr, payload string, timeout time.Duration) error {
	return client.PostDeviceSync(context.Background(), dial, netAddr, payload, timeout)
}

// rootRotationAdoptedMsg signals that the process just adopted a new
// root (either started locally or received via device_sync from a
// sibling), Update() uses it to refresh the public keys/address kept
// in memory (m.myIdentityPub/myMLKEMPub/myMLDSAPub/myAddr), otherwise
// stale for the process's entire lifetime (no other point in the code
// reassigns them after startup).
type rootRotationAdoptedMsg struct {
	newIdentityPub ed25519.PublicKey
	newMLKEMPub    []byte
	newMLDSAPub    []byte
	newAddr        string
	consoleKey     string
}

// knownDevicesNow returns this identity's known sibling devices, read
// live (nil if unknown).
func (m model) knownDevicesNow() []DeviceRecordInfo {
	if m.knownDevices == nil {
		return nil
	}
	return m.knownDevices()
}

// rootRotationPendingNow returns the contacts and sibling devices still
// pending for the latest root rotation, read live (nil, nil if unknown).
func (m *model) rootRotationPendingNow() ([][]byte, [][]byte) {
	if m.rootRotationPending == nil {
		return nil, nil
	}
	return m.rootRotationPending()
}

// propagateRootRotationToDevices sends "device_sync" (propagation of
// the current root material) to every one of our sibling devices still
// in rootRotationPendingDevices. Tries BOTH candidate addresses
// (derived from the new root and from the old one, via
// networkIdentityPubFor/oldNetworkIdentityPubFor): until the sibling
// has adopted it, its hidden service stays published at the address
// derived from the OLD root, same principle already applied to the
// remote_nuke fan-out. Called from the same probeContacts cycle
// (cmdActive/cmdActiveSilent), not nested inside it: it's per-device, not per-contact.
func (m model) propagateRootRotationToDevices() tea.Cmd {
	_, devices := m.rootRotationPendingNow()
	if m.dialTor == nil || len(devices) == 0 || m.buildDeviceSyncRotationKnock == nil {
		return nil
	}
	dial := m.dialTor
	computeAddr := m.computeAddress
	newPubFor := m.networkIdentityPubFor
	oldPubFor := m.oldNetworkIdentityPubFor
	buildKnock := m.buildDeviceSyncRotationKnock
	knockHttpTO := m.knockHttpTimeout
	return func() tea.Msg {
		var wg sync.WaitGroup
		for _, deviceID := range devices {
			wg.Add(1)
			go func() {
				defer wg.Done()
				type candidate struct {
					addr      string
					useOldKey bool
				}
				var candidates []candidate
				if newPubFor != nil {
					if pub := newPubFor(deviceID); len(pub) == ed25519.PublicKeySize {
						if a := computeAddr(pub); a != "" {
							candidates = append(candidates, candidate{addr: a, useOldKey: false})
						}
					}
				}
				if oldPubFor != nil {
					if pub := oldPubFor(deviceID); len(pub) == ed25519.PublicKeySize {
						if a := computeAddr(pub); a != "" && (len(candidates) == 0 || a != candidates[0].addr) {
							candidates = append(candidates, candidate{addr: a, useOldKey: true})
						}
					}
				}
				if len(candidates) == 0 {
					return
				}
				var awg sync.WaitGroup
				for _, c := range candidates {
					awg.Add(1)
					go func() {
						defer awg.Done()
						payload, err := buildKnock(c.useOldKey, deviceID)
						if err != nil {
							return
						}
						postDeviceSyncKnock(dial, c.addr, payload, knockHttpTO)
					}()
				}
				awg.Wait()
			}()
		}
		wg.Wait()
		return nil
	}
}

// applyDeviceSync handles an incoming "device_sync" knock from one of
// our own sibling devices. Carries EXACTLY one of two things (never
// both, see shared.DeviceSyncPayload): new root material to adopt
// (rotation propagation), or a remote address-book sync.
func (m *model) applyDeviceSync(k shared.KnockPayload) tea.Cmd {
	if k.DeviceSync == nil {
		return nil
	}
	dial := m.dialTor
	myDeviceID := m.myDeviceID
	buildAck := m.buildDeviceSyncAckKnock
	knockHttpTO := m.knockHttpTimeout
	fromAddr := k.FromAddr
	fromUsername := k.FromUsername

	if len(k.DeviceSync.NewIdentityKey) > 0 {
		adopt := m.adoptRootRotation
		newIdentityKey := k.DeviceSync.NewIdentityKey
		newMLKEMKey := k.DeviceSync.NewMLKEMKey
		newMLDSAKey := k.DeviceSync.NewMLDSAKey
		return func() tea.Msg {
			if adopt == nil {
				return nil
			}
			newAddr, err := adopt(newIdentityKey, newMLKEMKey, newMLDSAKey)
			if err != nil {
				return nil
			}
			if dial != nil && buildAck != nil && fromAddr != "" {
				if payload, perr := buildAck(myDeviceID, false); perr == nil {
					go postDeviceSyncKnock(dial, fromAddr, payload, knockHttpTO)
				}
			}
			newIdentityPub, ok := ed25519.PrivateKey(newIdentityKey).Public().(ed25519.PublicKey)
			if !ok {
				return nil
			}
			var newMLKEMPub, newMLDSAPub []byte
			if len(newMLKEMKey) > 0 {
				if dk, derr := mlkem.NewDecapsulationKey768(newMLKEMKey); derr == nil {
					newMLKEMPub = dk.EncapsulationKey().Bytes()
				}
			}
			if len(newMLDSAKey) == mldsa65.SeedSize {
				var seed [mldsa65.SeedSize]byte
				copy(seed[:], newMLDSAKey)
				pub, _ := mldsa65.NewKeyFromSeed(&seed)
				newMLDSAPub = pub.Bytes()
			}
			return rootRotationAdoptedMsg{newIdentityPub: newIdentityPub, newMLKEMPub: newMLKEMPub, newMLDSAPub: newMLDSAPub, newAddr: newAddr, consoleKey: "tui.device_sync_rotation_adopted"}
		}
	}

	if len(k.DeviceSync.SyncData) > 0 {
		merge := m.mergeSyncedContacts
		buildTombstone := m.buildContactTombstoneKnock
		syncData := k.DeviceSync.SyncData
		return func() tea.Msg {
			if merge != nil {
				if rejected, _ := merge(syncData); len(rejected) > 0 && dial != nil && buildTombstone != nil && fromAddr != "" {
					if payload, perr := buildTombstone(rejected); perr == nil {
						go postDeviceSyncKnock(dial, fromAddr, payload, knockHttpTO)
					}
				}
			}
			if dial != nil && buildAck != nil && fromAddr != "" {
				if payload, perr := buildAck(myDeviceID, true); perr == nil {
					go postDeviceSyncKnock(dial, fromAddr, payload, knockHttpTO)
				}
			}
			return contactsSyncedMsg{text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.device_sync_contacts_received"), fromUsername))}
		}
	}
	return nil
}

// applyDeviceSyncAck handles an incoming "device_sync_ack" knock, one
// of our own sibling devices confirms adopting the latest root rotation
// (always, harmless if it wasn't waiting for any) and/or brings back
// ITS OWN address book (bidirectional exchange of a sync we requested).
func (m *model) applyDeviceSyncAck(k shared.KnockPayload) tea.Cmd {
	ackFn := m.ackRootRotationDevice
	finalizeFn := m.maybeFinalizeRootRotation
	merge := m.mergeSyncedContacts
	buildTombstone := m.buildContactTombstoneKnock
	dial := m.dialTor
	knockHttpTO := m.knockHttpTimeout
	fromAddr := k.FromAddr
	targetDeviceID := k.TargetDeviceID
	fromUsername := k.FromUsername
	var syncData []byte
	if k.DeviceSync != nil {
		syncData = k.DeviceSync.SyncData
	}
	return func() tea.Msg {
		if ackFn != nil && len(targetDeviceID) > 0 {
			_ = ackFn(targetDeviceID)
		}
		if finalizeFn != nil {
			finalizeFn()
		}
		if len(syncData) > 0 && merge != nil {
			if rejected, _ := merge(syncData); len(rejected) > 0 && dial != nil && buildTombstone != nil && fromAddr != "" {
				if payload, perr := buildTombstone(rejected); perr == nil {
					go postDeviceSyncKnock(dial, fromAddr, payload, knockHttpTO)
				}
			}
			return contactsSyncedMsg{text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.device_sync_contacts_received"), fromUsername))}
		}
		return nil
	}
}

// adoptSyncedContacts brings into the in-memory address book what a sync
// with one of our own devices merged into the keystore: contacts not
// shown yet are added, and an already-shown contact gets the devices it
// lacks. Devices already in memory are left as they are, they may hold
// changes not saved yet. A placeholder device ("") the keystore has
// already replaced with a real one is dropped.
func (m *model) adoptSyncedContacts() {
	if m.contactsSnapshot == nil {
		return
	}
	for _, fresh := range m.contactsSnapshot() {
		c := m.resolveContactByPub(fresh.IdentityPub)
		if c == nil {
			m.contacts = append(m.contacts, fresh)
			continue
		}
		if c.Devices == nil {
			c.Devices = make(map[string]*keystore.DeviceRelation, len(fresh.Devices))
		}
		for key, dev := range fresh.Devices {
			if _, ok := c.Devices[key]; !ok {
				c.Devices[key] = dev
			}
		}
		if _, stillPlaceholder := fresh.Devices[""]; !stillPlaceholder && len(fresh.Devices) > 0 {
			delete(c.Devices, "")
		}
	}
}

// applyContactTombstone handles an incoming "contact_tombstone" knock
// from a sibling device: adopts the carried rows (deleting any matching
// live contact, merging ConfirmedSiblings, persisting immediately) and
// replies with a "contact_tombstone_ack" carrying what was adopted.
func (m *model) applyContactTombstone(k shared.KnockPayload) tea.Cmd {
	if k.ContactTombstone == nil || len(k.ContactTombstone.Rows) == 0 {
		return nil
	}
	apply := m.applyContactTombstoneReplies
	buildAck := m.buildContactTombstoneAckKnock
	dial := m.dialTor
	knockHttpTO := m.knockHttpTimeout
	fromAddr := k.FromAddr
	rows := k.ContactTombstone.Rows
	return func() tea.Msg {
		if apply == nil {
			return nil
		}
		acked, err := apply(rows)
		if err != nil || len(acked) == 0 {
			return nil
		}
		if dial != nil && buildAck != nil && fromAddr != "" {
			if payload, perr := buildAck(acked); perr == nil {
				go postDeviceSyncKnock(dial, fromAddr, payload, knockHttpTO)
			}
		}
		return nil
	}
}

// applyContactTombstoneAck handles an incoming "contact_tombstone_ack"
// knock: records, on this identity's own tombstone rows, that the
// sender has adopted every IdentityPub it just acked.
func (m *model) applyContactTombstoneAck(k shared.KnockPayload) tea.Cmd {
	if k.ContactTombstone == nil || len(k.ContactTombstone.Acked) == 0 {
		return nil
	}
	confirm := m.confirmContactTombstoneAcked
	acked := k.ContactTombstone.Acked
	peerDeviceID := k.TargetDeviceID
	return func() tea.Msg {
		if confirm != nil {
			confirm(acked, peerDeviceID)
		}
		return nil
	}
}

// sendRelRotateCmd builds the tea.Cmd that sends (in the background,
// fire-and-forget) an already-prepared rotation knock, c is the
// recipient contact (for address/transport keys), payload has already
// been built by the caller (cmdRotateRelIdentity/cmdRotateRelContent
// for the request, applyRelRotate for the ack, the retry cycle in
// probeContacts for resending the request).
// sendRelRotateCmd sends a rotation request/ack toward ONE specific
// device (dev, already resolved by the caller), netAddr is
// dev.Address, falling back to c.NetAddr (root) only if empty, same
// principle as sendRelInitCmd above.
func (m *model) sendRelRotateCmd(c ContactInfo, dev *keystore.DeviceRelation, payload shared.RelRotatePayload, knockType string) tea.Cmd {
	if m.dialTor == nil || len(c.IdentityPub) != 32 {
		return nil
	}
	netAddr := ""
	if dev != nil {
		netAddr = dev.Address
	}
	if netAddr == "" {
		netAddr = c.NetAddr
	}
	if netAddr == "" {
		return nil
	}
	dial := m.dialTor
	recipientPub := ed25519.PublicKey(c.IdentityPub)
	recipientMLKEMPub := c.MLKEMPub
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	myMLKEMPub := m.myMLKEMPub
	myAddr := m.myAddr
	dhTagFn := m.dhTagFn
	knockTO := m.knockHttpTimeout
	return func() tea.Msg {
		go sendRelRotate(dial, netAddr, recipientPub, recipientMLKEMPub, myUsername, myPub, myMLKEMPub, myAddr, payload, knockType, dhTagFn, knockTO)
		return nil
	}
}

// sendProbePing sends a "probe_ping" knock to the contact over the
// active transport (Tor or I2P, fire-and-forget), the dedicated
// reachability ping, sent by probeContacts to every online contact on
// every cycle (~ActiveInterval, configurable) and also by hand via
// /active. No rotation semantics: the receiver only replies with a
// probe_ack (see applyProbePing).
func sendProbePing(dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, myMLKEMPub []byte, myAddr string,
	dhTagFn func(ed25519.PublicKey) ([]byte, error),
	timeout time.Duration) {

	kp := shared.KnockPayload{
		Type:            "probe_ping",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		MLKEMPub:        myMLKEMPub,
		FromAddr:        myAddr,
	}
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, kp)
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// deviceKeyList lists Contact.Devices' keys as readable strings
// (base64, "" rendered as "<placeholder>"), for diagnostics
// (client.Dbg) only, never for logic.
func deviceKeyList(devices map[string]*keystore.DeviceRelation) []string {
	out := make([]string, 0, len(devices))
	for k := range devices {
		if k == "" {
			out = append(out, "<placeholder>")
			continue
		}
		out = append(out, base64.StdEncoding.EncodeToString([]byte(k))[:12]+"…")
	}
	return out
}

// applyRelInit handles an incoming "rel_init"/"rel_init_ack" knock. The
// mutuality of KnockDHTag (already applied before this handler is ever
// reached) guarantees the sender is already one of our known contacts:
// no on-the-fly creation of a Contact is ever needed here.
func (m *model) applyRelInit(k shared.KnockPayload) tea.Cmd {
	if k.RelBootstrap == nil || len(k.FromIdentityPub) != 32 {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil // should never happen given the tag's mutuality, defense in depth
	}
	// Per-device model: the sender's DevicePub identifies WHICH of its
	// devices is speaking, without it, no Contact.Devices entry can be
	// safely resolved.
	devicePub := k.RelBootstrap.DevicePub
	if len(devicePub) != ed25519.PublicKeySize {
		return nil
	}
	// Authentication against the sender's root IdentityKey, ONLY for
	// the persistent channel (here, never the ephemeral in-room
	// bootstrap), see the comment on RelBootstrapPayload.Ts/Sig/SigMLDSA
	// in internal/shared/relbootstrap.go. No compatibility exception: a
	// rel_init/rel_init_ack lacking a valid Ed25519 signature against
	// Contact.IdentityPub (already known, exchanged out-of-band with
	// the URI) is discarded before touching any field, never applied,
	// never placed in Pending (that's for an authenticated proposal
	// that differs from a known one, not for one that's not
	// authenticated at all). SigMLDSA verified only if both sides
	// already have a known root MLDSAPub, never blocking otherwise,
	// same treatment as the project's other hybrid PQC signatures.
	if !shared.VerifyRelBootstrap(ed25519.PublicKey(contact.IdentityPub), k.RelBootstrap.IdentityPub, k.RelBootstrap.ContentPub, devicePub, k.FromUsername, k.RelBootstrap.Ts, k.RelBootstrap.Sig) {
		client.Dbg("applyRelInit: %s invalid root signature, knock discarded", k.FromUsername)
		return nil
	}
	if len(contact.MLDSAPub) > 0 && len(k.RelBootstrap.SigMLDSA) > 0 {
		if !shared.VerifyRelBootstrapMLDSA(contact.MLDSAPub, k.RelBootstrap.IdentityPub, k.RelBootstrap.ContentPub, devicePub, k.FromUsername, k.RelBootstrap.Ts, k.RelBootstrap.SigMLDSA) {
			client.Dbg("applyRelInit: %s invalid root MLDSA signature, knock discarded", k.FromUsername)
			return nil
		}
	}
	devKey := string(devicePub)
	if contact.Devices == nil {
		contact.Devices = map[string]*keystore.DeviceRelation{}
	}
	client.Dbg("applyRelInit: %s type=%s devicePub=%s… devicesBefore=%d (keys=%v)", k.FromUsername, k.Type, base64.StdEncoding.EncodeToString(devicePub)[:12], len(contact.Devices), deviceKeyList(contact.Devices))
	dev, exists := contact.Devices[devKey]
	promote := false
	if !exists {
		if ph, hasPh := contact.Devices[""]; hasPh {
			// The FIRST device replying to our initial bootstrap, the
			// placeholder entry (OUR OWN keys, already generated by
			// AddContact/probeContacts) gets promoted to the real
			// DevicePub, never recreated.
			dev = ph
			delete(contact.Devices, "")
			promote = true
			client.Dbg("applyRelInit: %s promoting placeholder → %s…", k.FromUsername, base64.StdEncoding.EncodeToString(devicePub)[:12])
		} else {
			client.Dbg("applyRelInit: %s no placeholder, creating NEW device %s… (devKeys already present: %v)", k.FromUsername, base64.StdEncoding.EncodeToString(devicePub)[:12], deviceKeyList(contact.Devices))
			// A genuinely NEW device for this contact, never a
			// conflict by construction (no existing entry to
			// contradict). OUR OWN keys toward it must be generated
			// now, regardless of the message's Type.
			identKey, err := shared.GenerateRelSigningKey()
			if err != nil {
				return nil
			}
			contentKey, err := shared.GenerateRelSigningKey()
			if err != nil {
				return nil
			}
			dev = &keystore.DeviceRelation{
				RelIdentityPriv:      identKey.Priv,
				RelIdentityMLKEMPriv: identKey.MLKEMSeed,
				RelIdentityMLDSAPriv: identKey.MLDSASeed,
				RelContentPriv:       contentKey.Priv,
				RelContentMLKEMPriv:  contentKey.MLKEMSeed,
				RelContentMLDSAPriv:  contentKey.MLDSASeed,
			}
		}
		contact.Devices[devKey] = dev
	}
	client.Dbg("applyRelInit: %s devicesAfter=%d (keys=%v)", k.FromUsername, len(contact.Devices), deviceKeyList(contact.Devices))

	// Conflict (TrustDanger): a rel_init/rel_init_ack that proposes a
	// relationship key (identity OR content, even just one) different
	// from a value ALREADY KNOWN for this device is not
	// cryptographically distinguishable from a restore/replacement of
	// its keys, never applied automatically. Can never fire on a `dev`
	// just created/promoted above (PeerRel* still empty, so
	// "differs"==false by construction). The proposed keys stay pending
	// (PendingPeerRel*, on this device's exact entry) until the user
	// explicitly confirms out-of-band with /sec-verify (see
	// cmdVerifySafety/applyVerification).
	//
	// The guard deliberately does NOT depend on
	// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer: those flags
	// are reset by the ErrInvalidServerSig self-heal on a handshake
	// failure, exactly the symptom a real key change produces, which
	// would let the guard be found already disabled and apply new keys
	// without ever passing through TrustDanger, indistinguishable from
	// a real attack at this level. identityDiffers/contentDiffers alone
	// are enough (they already require a known 32-byte value to fire).
	// The two conditions are combined with ||, not &&: a change to only
	// ONE of the two keys (identity and content rotate independently)
	// must still be caught, not silently applied.
	// dev.RevokedIdentity/RevokedContent alone forces the conflict path
	// too, even when the proposed key is byte-identical to the one on
	// file: a holder of an already-revoked private key could otherwise
	// replay it in an outwardly genuine rel_init and bypass TrustDanger
	// entirely, since identityDiffers/contentDiffers below would read
	// false for an unchanged value.
	identityDiffers := dev.RevokedIdentity ||
		(len(dev.PeerRelIdentityPub) == ed25519.PublicKeySize &&
			!bytes.Equal(dev.PeerRelIdentityPub, k.RelBootstrap.IdentityPub))
	contentDiffers := dev.RevokedContent ||
		(len(dev.PeerRelContentPub) == ed25519.PublicKeySize &&
			!bytes.Equal(dev.PeerRelContentPub, k.RelBootstrap.ContentPub))
	if identityDiffers || contentDiffers {
		dev.PendingPeerRelIdentityPub = k.RelBootstrap.IdentityPub
		dev.PendingPeerRelIdentityMLKEMPub = k.RelBootstrap.IdentityMLKEMPub
		dev.PendingPeerRelIdentityMLDSAPub = k.RelBootstrap.IdentityMLDSAPub
		dev.PendingPeerRelContentPub = k.RelBootstrap.ContentPub
		dev.PendingPeerRelContentMLKEMPub = k.RelBootstrap.ContentMLKEMPub
		dev.PendingPeerRelContentMLDSAPub = k.RelBootstrap.ContentMLDSAPub
		pending := PendingRelKeys{
			DevicePub:        devicePub,
			IdentityPub:      k.RelBootstrap.IdentityPub,
			IdentityMLKEMPub: k.RelBootstrap.IdentityMLKEMPub,
			IdentityMLDSAPub: k.RelBootstrap.IdentityMLDSAPub,
			ContentPub:       k.RelBootstrap.ContentPub,
			ContentMLKEMPub:  k.RelBootstrap.ContentMLKEMPub,
			ContentMLDSAPub:  k.RelBootstrap.ContentMLDSAPub,
		}
		setPendingFn := m.setPendingRelKeys
		pendingPub := contact.IdentityPub
		persistPendingCmd := func() tea.Msg {
			if setPendingFn != nil {
				_ = setPendingFn(pendingPub, pending)
			}
			return nil
		}
		// We still reply: the ack uses OUR OWN current keys, independent
		// of the conflict over THEIRS.
		if k.Type == "rel_init" {
			return tea.Batch(persistPendingCmd, m.sendRelInitCmd(*contact, dev, "rel_init_ack"))
		}
		return persistPendingCmd
	}

	upd := RelKeyUpdate{
		DevicePub:               devicePub,
		PromoteFromPlaceholder:  promote,
		Address:                 k.FromAddr,
		RelIdentityPriv:         dev.RelIdentityPriv,
		RelIdentityMLKEMPriv:    dev.RelIdentityMLKEMPriv,
		RelIdentityMLDSAPriv:    dev.RelIdentityMLDSAPriv,
		RelContentPriv:          dev.RelContentPriv,
		RelContentMLKEMPriv:     dev.RelContentMLKEMPriv,
		RelContentMLDSAPriv:     dev.RelContentMLDSAPriv,
		PeerRelIdentityPub:      k.RelBootstrap.IdentityPub,
		PeerRelIdentityMLKEMPub: k.RelBootstrap.IdentityMLKEMPub,
		PeerRelIdentityMLDSAPub: k.RelBootstrap.IdentityMLDSAPub,
		PeerRelContentPub:       k.RelBootstrap.ContentPub,
		PeerRelContentMLKEMPub:  k.RelBootstrap.ContentMLKEMPub,
		PeerRelContentMLDSAPub:  k.RelBootstrap.ContentMLDSAPub,
	}
	// RelInitConfirmedByPeer turns on ONLY on a real rel_init_ack,
	// never on a spontaneous rel_init from the peer, which is a
	// request, not a confirmation that THEY received OUR OWN keys.
	// Distinct from "I have their keys" (upd.PeerRel* above, populated
	// in both cases): these are the only two conditions that govern,
	// respectively, whether the PEER must keep resending their own
	// rel_init and whether WE must keep resending ours.
	if k.Type == "rel_init_ack" {
		upd.RelIdentityConfirmedByPeer = true
		upd.RelContentConfirmedByPeer = true
	}
	// Immediately updates the local mirror (synchronous), cmdInvite
	// and similar read m.contacts, they must not wait for the
	// persistence I/O round trip below (asynchronous).
	dev.PeerRelIdentityPub = upd.PeerRelIdentityPub
	dev.PeerRelIdentityMLKEMPub = upd.PeerRelIdentityMLKEMPub
	dev.PeerRelIdentityMLDSAPub = upd.PeerRelIdentityMLDSAPub
	dev.PeerRelContentPub = upd.PeerRelContentPub
	dev.PeerRelContentMLKEMPub = upd.PeerRelContentMLKEMPub
	dev.PeerRelContentMLDSAPub = upd.PeerRelContentMLDSAPub
	if upd.Address != "" {
		dev.Address = upd.Address
	}
	if upd.RelIdentityConfirmedByPeer {
		dev.RelIdentityConfirmedByPeer = true
	}
	if upd.RelContentConfirmedByPeer {
		dev.RelContentConfirmedByPeer = true
	}
	// The Contacts tab shows [REL:...] by reading m.contacts at render
	// time, but that render lives in m.vp's buffer (SetContent),
	// populated only by refreshViewport(), never recomputed on its own
	// on every Update(). Without this call, a rel_init_ack arriving
	// while the Contacts tab is already active would leave the buffer
	// with the previous state (no REL) until something else forces it
	// (e.g. switching tabs and back), refreshViewport() itself is
	// already a safe no-op if the active tab isn't Contacts.
	m.refreshViewport()
	// This device's PeerRelContentPub may have just changed, re-
	// verifies every file_announce held pending for this contact/device
	// by the self-heal (case "file_announce", Update()), before even
	// persisting/replying below.
	retryCmd := m.retryPendingFileAnnounces(contact.IdentityPub, devicePub)
	// A rel_init_ack may have just made this contact ready
	// (ReadyDevices() no longer empty), starts on its own any invite
	// queued with queuePendingInvite that was waiting on it. No-op if
	// the contact still isn't ready or there are no queued invites for it.
	inviteRetryCmd := m.retryPendingInvites(contact.IdentityPub)
	// Same principle as inviteRetryCmd above, but for the opposite
	// direction: an invite received FROM this contact (cmdJoin/
	// joinKnock) and accepted before its keys were known (host just
	// restarted, rel_init still in transit) stays queued in
	// m.pendingJoins instead of being lost, see joinKnock/queuePendingJoin.
	joinRetryCmd := m.retryPendingJoins(contact.IdentityPub)
	// A rel_init/rel_init_ack can update PeerRelIdentityPub even AFTER
	// a room has already been registered as host with this contact,
	// not just on the first bootstrap: a real case is the peer
	// restoring from backup (root IdentityPub preserved from the
	// BIP-39 seed, but RelIdentityPriv/RelContentPriv NOT recoverable,
	// so regenerated from scratch) and resending us a rel_init with a
	// new relationship key while still being the same contact by
	// IdentityPub. No explicit refresh needed here: the RoomRegistry
	// resolves the live key pair through
	// keystore.Keystore.RelKeysForDevice on every handshake, never a
	// cached copy, as soon as persistCmd below writes the new key to
	// keystore.Contact (asynchronous, an instant later), the next
	// verification already sees it with no additional action here.

	persistFn := m.updateContactRelKeys
	pub := contact.IdentityPub
	persistCmd := func() tea.Msg {
		if persistFn != nil {
			_ = persistFn(pub, upd)
		}
		return nil
	}
	// We ALWAYS reply to an incoming rel_init (never to a rel_init_ack,
	// which is terminal), regardless of whether our keys already
	// existed: if OUR OWN previous reply were lost, the peer would keep
	// resending rel_init indefinitely, and we must keep replying until
	// they too confirm us in turn (their own RelInitConfirmedByPeer
	// toward us).
	if k.Type == "rel_init" {
		// Our keys not yet confirmed by the peer: our own earlier
		// rel_init never reached them (e.g. dropped by their mutuality
		// filter before they added us). Our rel_init follows the ack, in
		// order, so their ack confirms us now instead of at the next
		// probe cycle.
		knockTypes := []string{"rel_init_ack"}
		if !dev.RelIdentityConfirmedByPeer || !dev.RelContentConfirmedByPeer {
			knockTypes = append(knockTypes, "rel_init")
		}
		return tea.Batch(persistCmd, m.sendRelInitCmd(*contact, dev, knockTypes...), retryCmd, inviteRetryCmd, joinRetryCmd)
	}
	return tea.Batch(persistCmd, retryCmd, inviteRetryCmd, joinRetryCmd)
}

// retryPendingFileAnnounces re-verifies every file_announce held
// pending (self-heal, case "file_announce", Update()) for the specific
// device of the contact with identity key contactPub just resynced by a rel_init_ack, see
// model.pendingFileAnnounces and pendingFileAnnounce. Called from
// applyRelInit right after that device's PeerRelContentPub was updated.
// An announcement whose deadline has already expired is silently
// dropped (the sender will discover the timeout on its own, same
// behavior as an offer never accepted) instead of being re-verified.
func (m *model) retryPendingFileAnnounces(contactPub []byte, devKeyBytes []byte) tea.Cmd {
	if len(m.pendingFileAnnounces) == 0 {
		return nil
	}
	contact := m.resolveContactByPub(contactPub)
	if contact == nil {
		return nil
	}
	dev, ok := contact.DeviceByPub(devKeyBytes)
	if !ok || len(dev.PeerRelContentPub) != ed25519.PublicKeySize {
		return nil
	}
	devKey := string(devKeyBytes)
	now := time.Now()
	var cmds []tea.Cmd
	for transferID, pa := range m.pendingFileAnnounces {
		if pa.fromKey != client.MemberKeyOf(contactPub) || pa.devKey != devKey {
			continue
		}
		if now.After(pa.deadline) {
			delete(m.pendingFileAnnounces, transferID)
			continue
		}
		hashHex := hex.EncodeToString(pa.hash)
		valid := shared.VerifyRelMsg(ed25519.PublicKey(dev.PeerRelContentPub), hashHex, pa.sigTS, m.myKey(), pa.sig) &&
			(len(dev.PeerRelContentMLDSAPub) == 0 || len(pa.sigMLDSA) == 0 || shared.VerifyRelMsgMLDSA(dev.PeerRelContentMLDSAPub, hashHex, pa.sigTS, m.myKey(), pa.sigMLDSA))
		if !valid {
			continue
		}
		if m.verifiedFileHashes == nil {
			m.verifiedFileHashes = make(map[string][]byte)
		}
		m.verifiedFileHashes[transferID] = pa.hash
		delete(m.pendingFileAnnounces, transferID)
		if pa.tabIdx >= len(m.tabs) {
			continue // tab closed in the meantime
		}
		cli := m.tabs[pa.tabIdx].cli
		ctx := m.tabs[pa.tabIdx].ctx
		tid := transferID
		uid := pa.fromUserID
		cmds = append(cmds, func() tea.Msg { _ = cli.SendFileAnnounceAck(ctx, uid, tid); return nil })
	}
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

// queuePendingInvite queues an invite toward one or more contacts still
// missing BOTH confirmed relationship keys (ReadyDevices() empty):
// never a flat error, a fresh rel_init starts RIGHT AWAY (immediate
// probe, never a blind wait until the next periodic cycle) and the
// real invite restarts on its own as soon as retryPendingInvites finds
// it fully ready. label is descriptive text (the original command's
// name), retry repeats the exact same command/arguments once every
// contact in pendingPubs (by identity key) is confirmed.
func (m *model) queuePendingInvite(label string, pendingPubs [][]byte, retry func(m *model) tea.Cmd) tea.Cmd {
	pending := make(map[string]bool, len(pendingPubs))
	names := make([]string, 0, len(pendingPubs))
	for _, pub := range pendingPubs {
		pending[client.MemberKeyOf(pub)] = true
		names = append(names, m.contactDisplayByPub(pub))
	}
	m.pendingInvites = append(m.pendingInvites, &pendingInvite{
		label:    label,
		pending:  pending,
		retry:    retry,
		deadline: time.Now().Add(m.inviteTimeout),
	})
	notice := styleMeta.Render(fmt.Sprintf(i18n.T("tui.invite_queue_pending"), label, strings.Join(names, ", ")))
	return tea.Batch(localTab(m.consoleIdx, notice), m.cmdActiveSilent())
}

// retryPendingInvites checks whether the contact with identity key pub
// is now ready (ReadyDevices() not empty) and, for every queued invite
// that was waiting on it, removes it from its own pending set, an
// invite whose set becomes empty is run immediately (retry) and removed
// from the queue. Called from applyRelInit right after a rel_init_ack
// made both flags of one of the contact's devices true.
func (m *model) retryPendingInvites(pub []byte) tea.Cmd {
	if len(m.pendingInvites) == 0 {
		return nil
	}
	c := m.resolveContactByPub(pub)
	if c == nil || len(c.ReadyDevices()) == 0 {
		return nil
	}
	key := client.MemberKeyOf(pub)
	var cmds []tea.Cmd
	remaining := m.pendingInvites[:0]
	for _, pi := range m.pendingInvites {
		delete(pi.pending, key)
		if len(pi.pending) == 0 {
			cmds = append(cmds, pi.retry(m))
			continue
		}
		remaining = append(remaining, pi)
	}
	m.pendingInvites = remaining
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

// applyRelRotate handles an incoming "rel_identity_rotate"/
// "rel_content_rotate" knock (request) or its "_ack" counterpart
// (confirmation). Same reliability principle as rel_init/rel_init_ack
// (applyRelInit): ALWAYS replies to a request, never to an ack
// (terminal), regardless of any local state, if OUR OWN previous
// reply were lost, the peer would keep resending the request and we
// must keep replying.
func (m *model) applyRelRotate(k shared.KnockPayload) tea.Cmd {
	isIdentity := k.Type == "rel_identity_rotate" || k.Type == "rel_identity_rotate_ack"
	isAck := k.Type == "rel_identity_rotate_ack" || k.Type == "rel_content_rotate_ack"
	if k.RelRotate == nil || len(k.RelRotate.NewPub) != ed25519.PublicKeySize || len(k.FromIdentityPub) != 32 {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil // should never happen given the tag's mutuality, defense in depth
	}
	// Resolves the exact device via RelRotatePayload.DevicePub (same
	// principle already used for RelBootstrapPayload.DevicePub in
	// applyRelInit), falls back to SoleDevice() only if the peer
	// doesn't send it or it doesn't match.
	dev, devOK := contact.DeviceByPub(k.RelRotate.DevicePub)
	if !devOK {
		dev, devOK = contact.SoleDevice()
	}
	if !devOK {
		return nil
	}
	// devKeyBytes: the exact key (the PEER's DevicePub) under which
	// `dev` lives in contact.Devices, found by pointer identity, never
	// blindly trusting k.RelRotate.DevicePub (which could be missing or
	// not match any entry).
	var devKeyBytes []byte
	for key, d := range contact.Devices {
		if d == dev {
			devKeyBytes = []byte(key)
			break
		}
	}

	if isAck {
		// Confirmation: NewPub must match the key CURRENTLY rotating
		// for this contact, a late ack referring to a rotation already
		// forced/closed (key now different) is silently discarded,
		// never reapplied to a subsequent rotation (see RelRotatePayload).
		var currentPriv []byte
		var pending bool
		if isIdentity {
			currentPriv, pending = dev.RelIdentityPriv, dev.IdentityKeyPending
		} else {
			currentPriv, pending = dev.RelContentPriv, dev.ContentKeyPending
		}
		if !pending || len(currentPriv) != ed25519.PrivateKeySize {
			return nil
		}
		myCurrentPub, ok := ed25519.PrivateKey(currentPriv).Public().(ed25519.PublicKey)
		if !ok || !bytes.Equal(k.RelRotate.NewPub, myCurrentPub) {
			return nil
		}
		which := "identity"
		if isIdentity {
			dev.IdentityKeyPending = false
		} else {
			which = "content"
			dev.ContentKeyPending = false
		}
		fn := m.markRelRotationConfirmed
		pub := contact.IdentityPub
		ackDevKey := devKeyBytes
		username := k.FromUsername
		consoleIdx := m.consoleIdx
		return func() tea.Msg {
			if fn != nil {
				_ = fn(pub, ackDevKey, which)
			}
			return localDisplayMsg{tabIdx: consoleIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.rel_rotation_confirmed"), which, username))}
		}
	}

	// Incoming request: verifies with the PEER's stable SIBLING key
	// (never our own), never with the old version of the same key
	// that's rotating.
	var certifyingPub ed25519.PublicKey
	var certifyingMLDSAPub []byte
	if isIdentity {
		certifyingPub, certifyingMLDSAPub = ed25519.PublicKey(dev.PeerRelContentPub), dev.PeerRelContentMLDSAPub
	} else {
		certifyingPub, certifyingMLDSAPub = ed25519.PublicKey(dev.PeerRelIdentityPub), dev.PeerRelIdentityMLDSAPub
	}
	if !shared.VerifyRelKeyRotation(certifyingPub, k.RelRotate.NewPub, k.FromUsername, k.RelRotate.Ts, k.RelRotate.Sig) {
		return nil
	}
	// Freshness: without this, an old captured rotation message, whose
	// signature stays valid as long as the signing sibling key doesn't
	// change, could be replayed later to force a silent rollback to a
	// previous version of the rotating key. Verified AFTER the
	// signature (which includes ts in the signed message), never
	// before: an expired ts with an otherwise invalid signature must
	// stay "discarded for signature", not "discarded for freshness",
	// same order already used for every other check in this function.
	if !shared.TsFresh(k.RelRotate.Ts) {
		return nil
	}
	if len(certifyingMLDSAPub) > 0 && len(k.RelRotate.SigMLDSA) > 0 {
		if !shared.VerifyRelKeyRotationMLDSA(certifyingMLDSAPub, k.RelRotate.NewPub, k.FromUsername, k.RelRotate.Ts, k.RelRotate.SigMLDSA) {
			return nil
		}
	}

	upd := RelKeyUpdate{DevicePub: devKeyBytes}
	if isIdentity {
		upd.PeerRelIdentityPub = k.RelRotate.NewPub
		upd.PeerRelIdentityMLKEMPub = k.RelRotate.NewMLKEMPub
		upd.PeerRelIdentityMLDSAPub = k.RelRotate.NewMLDSAPub
		dev.PeerRelIdentityPub = upd.PeerRelIdentityPub
		dev.PeerRelIdentityMLKEMPub = upd.PeerRelIdentityMLKEMPub
		dev.PeerRelIdentityMLDSAPub = upd.PeerRelIdentityMLDSAPub
		// The PEER's key for any room open as host with this contact
		// has just changed, no explicit refresh needed here: the
		// RoomRegistry reads it live from keystore.Contact on every
		// ClientHello.Sig, as soon as it's persisted below.
	} else {
		upd.PeerRelContentPub = k.RelRotate.NewPub
		upd.PeerRelContentMLKEMPub = k.RelRotate.NewMLKEMPub
		upd.PeerRelContentMLDSAPub = k.RelRotate.NewMLDSAPub
		dev.PeerRelContentPub = upd.PeerRelContentPub
		dev.PeerRelContentMLKEMPub = upd.PeerRelContentMLKEMPub
		dev.PeerRelContentMLDSAPub = upd.PeerRelContentMLDSAPub
	}
	persistFn := m.updateContactRelKeys
	pub := contact.IdentityPub
	persistCmd := func() tea.Msg {
		if persistFn != nil {
			_ = persistFn(pub, upd)
		}
		return nil
	}
	ackType := "rel_identity_rotate_ack"
	if !isIdentity {
		ackType = "rel_content_rotate_ack"
	}
	ackPayload := shared.RelRotatePayload{NewPub: k.RelRotate.NewPub, DevicePub: m.myDevicePub}
	return tea.Batch(persistCmd, m.sendRelRotateCmd(*contact, dev, ackPayload, ackType))
}

// applyRootRotate handles an incoming "root_rotate" knock, a
// contact's root IdentityKey rotation announcement. Mirrors
// applyRelRotate: continuity is verified with the sender's per-contact
// RelIdentityKey (dev.PeerRelIdentityPub), never with their old root.
func (m *model) applyRootRotate(k shared.KnockPayload) tea.Cmd {
	if k.RootRotate == nil || len(k.RootRotate.NewIdentityPub) != ed25519.PublicKeySize || len(k.FromIdentityPub) != 32 {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil // should never happen given the tag's mutuality, defense in depth
	}
	dev, devOK := contact.DeviceByPub(k.RootRotate.DevicePub)
	if !devOK {
		dev, devOK = contact.SoleDevice()
	}
	if !devOK || len(dev.PeerRelIdentityPub) != ed25519.PublicKeySize {
		return nil
	}
	if !shared.VerifyRootRotation(ed25519.PublicKey(dev.PeerRelIdentityPub), k.RootRotate.NewIdentityPub, k.FromUsername, k.RootRotate.Ts, k.RootRotate.Sig) {
		return nil
	}
	// Freshness (same reason/order as applyRelRotate): verified AFTER
	// the signature, never before, an expired ts with an otherwise
	// invalid signature stays "discarded for signature", not
	// "discarded for freshness".
	if !shared.TsFresh(k.RootRotate.Ts) {
		return nil
	}
	if len(dev.PeerRelIdentityMLDSAPub) > 0 && len(k.RootRotate.SigMLDSA) > 0 {
		if !shared.VerifyRootRotationMLDSA(dev.PeerRelIdentityMLDSAPub, k.RootRotate.NewIdentityPub, k.FromUsername, k.RootRotate.Ts, k.RootRotate.SigMLDSA) {
			return nil
		}
	}
	// No RoomRegistry refresh here, unlike applyRelRotate: rooms
	// authenticate only with relationship keys (Rel*Key), never with
	// the root, a root rotation touches nothing there.

	newIdentityPub := append(ed25519.PublicKey(nil), k.RootRotate.NewIdentityPub...)
	newMLKEMPub := k.RootRotate.NewMLKEMPub
	newMLDSAPub := k.RootRotate.NewMLDSAPub
	newAddr := m.computeAddress(newIdentityPub)

	fn := m.updateContactRootIdentity
	pub := contact.IdentityPub
	// In-memory copy, same changes as updateContactRootIdentity applies
	// to the keystore: every later knock and invite toward this contact
	// goes to the new root and address, including the device reachable
	// at the old root-derived address.
	for _, d := range contact.Devices {
		if d != nil && d.Address == contact.NetAddr {
			d.Address = newAddr
		}
	}
	contact.IdentityPub = newIdentityPub
	contact.NetAddr = newAddr
	if len(newMLKEMPub) > 0 {
		contact.MLKEMPub = newMLKEMPub
	}
	if len(newMLDSAPub) > 0 {
		contact.MLDSAPub = newMLDSAPub
	}
	contact.Verified = false
	dial := m.dialTor
	dhTagFn := m.dhTagFn
	knockHttpTO := m.knockHttpTimeout
	myUsername := m.myUsername
	myIdentityPub := ed25519.PublicKey(m.myIdentityPub)
	contactMLKEMPub := k.MLKEMPub
	consoleIdx := m.consoleIdx
	username := k.FromUsername
	return func() tea.Msg {
		if fn != nil {
			_ = fn(pub, newIdentityPub, newMLKEMPub, newMLDSAPub)
		}
		if dial != nil && dhTagFn != nil {
			go sendRootRotateAck(dial, newAddr, newIdentityPub, contactMLKEMPub, myUsername, myIdentityPub, dhTagFn, knockHttpTO)
		}
		return localDisplayMsg{tabIdx: consoleIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.root_rotation_applied"), username))}
	}
}

// applyRootRotateAck handles an incoming "root_rotate_ack" knock, a
// contact confirms applying OUR OWN latest root rotation. Fire-and-
// forget, no signature to verify (the knock's mutuality tag is already
// proof they hold the current key).
func (m *model) applyRootRotateAck(k shared.KnockPayload) tea.Cmd {
	if len(k.FromIdentityPub) != ed25519.PublicKeySize {
		return nil
	}
	ackFn := m.ackRootRotationContact
	finalizeFn := m.maybeFinalizeRootRotation
	pub := append([]byte(nil), k.FromIdentityPub...)
	return func() tea.Msg {
		if ackFn != nil {
			_ = ackFn(pub)
		}
		if finalizeFn != nil {
			finalizeFn()
		}
		return nil
	}
}

// applyRelRevoke handles an incoming "rel_revoke" knock, an
// announcement revoking one or both relationship keys of ONE of the
// sender's devices. The sender can be either the device itself or a
// sibling acting as a backstop on its behalf
// (keystore.Contact.SiblingRevocations), indistinguishable here: the
// knock's mutuality is already guaranteed by the shared root, the
// revocation signature always verifies against the already-known
// relationship key, never against the identity of whoever materially
// sent it. The two keys are verified independently (an announcement
// can revoke only one): a failure on one doesn't block applying the other.
func (m *model) applyRelRevoke(k shared.KnockPayload) tea.Cmd {
	if k.RelRevoke == nil || len(k.FromIdentityPub) != ed25519.PublicKeySize {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil // should never happen given the tag's mutuality, defense in depth
	}
	dev, devOK := contact.DeviceByPub(k.RelRevoke.DevicePub)
	if !devOK {
		dev, devOK = contact.SoleDevice()
	}
	if !devOK {
		return nil
	}

	revokeIdentity := len(k.RelRevoke.IdentitySig) > 0 && len(dev.PeerRelIdentityPub) == ed25519.PublicKeySize &&
		shared.VerifyRelRevoke(ed25519.PublicKey(dev.PeerRelIdentityPub), k.FromUsername, k.RelRevoke.IdentitySig)
	if revokeIdentity && len(dev.PeerRelIdentityMLDSAPub) > 0 && len(k.RelRevoke.IdentitySigMLDSA) > 0 {
		revokeIdentity = shared.VerifyRelRevokeMLDSA(dev.PeerRelIdentityMLDSAPub, ed25519.PublicKey(dev.PeerRelIdentityPub), k.FromUsername, k.RelRevoke.IdentitySigMLDSA)
	}
	revokeContent := len(k.RelRevoke.ContentSig) > 0 && len(dev.PeerRelContentPub) == ed25519.PublicKeySize &&
		shared.VerifyRelRevoke(ed25519.PublicKey(dev.PeerRelContentPub), k.FromUsername, k.RelRevoke.ContentSig)
	if revokeContent && len(dev.PeerRelContentMLDSAPub) > 0 && len(k.RelRevoke.ContentSigMLDSA) > 0 {
		revokeContent = shared.VerifyRelRevokeMLDSA(dev.PeerRelContentMLDSAPub, ed25519.PublicKey(dev.PeerRelContentPub), k.FromUsername, k.RelRevoke.ContentSigMLDSA)
	}
	if !revokeIdentity && !revokeContent {
		return nil
	}
	// In-memory copy, same change markDeviceRevoked applies to the
	// keystore: from now on this relationship no longer counts as
	// established for invites, signatures or verification.
	if revokeIdentity {
		dev.RevokedIdentity = true
	}
	if revokeContent {
		dev.RevokedContent = true
	}
	kinds := "identity"
	switch {
	case revokeIdentity && revokeContent:
		kinds = "identity, content"
	case revokeContent:
		kinds = "content"
	}

	fn := m.markDeviceRevoked
	pub := contact.IdentityPub
	devicePub := append([]byte(nil), k.RelRevoke.DevicePub...)
	dial := m.dialTor
	dhTagFn := m.dhTagFn
	knockHttpTO := m.knockHttpTimeout
	myUsername := m.myUsername
	myIdentityPub := ed25519.PublicKey(m.myIdentityPub)
	recipientMLKEMPub := k.MLKEMPub
	netAddr := k.FromAddr
	if netAddr == "" {
		netAddr = dev.Address
	}
	if netAddr == "" {
		netAddr = contact.NetAddr
	}
	consoleIdx := m.consoleIdx
	username := k.FromUsername
	return func() tea.Msg {
		if fn != nil {
			_ = fn(pub, devicePub, revokeIdentity, revokeContent)
		}
		if dial != nil && dhTagFn != nil && netAddr != "" {
			go sendRelRevokeAck(dial, netAddr, ed25519.PublicKey(pub), recipientMLKEMPub, myUsername, myIdentityPub, devicePub, dhTagFn, knockHttpTO)
		}
		return localDisplayMsg{tabIdx: consoleIdx, text: styleMeta.Render(fmt.Sprintf(i18n.T("tui.rel_revoke_applied"), username, kinds))}
	}
}

// applyRelRevokeAck handles an incoming "rel_revoke_ack" knock, a
// contact (or one of its sibling devices, indistinguishable) confirms
// applying one of our revocations. Fire-and-forget, no signature to
// verify (the knock's mutuality tag is already proof they hold a known
// relationship key), best-effort, see TUIParams.AckSiblingRevocation.
func (m *model) applyRelRevokeAck(k shared.KnockPayload) tea.Cmd {
	if k.RelRevoke == nil || len(k.RelRevoke.DevicePub) == 0 || len(k.FromIdentityPub) != ed25519.PublicKeySize {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil
	}
	fn := m.ackSiblingRevocation
	pub := contact.IdentityPub
	peerDevicePub := append([]byte(nil), k.RelRevoke.DevicePub...)
	return func() tea.Msg {
		if fn != nil {
			_ = fn(pub, peerDevicePub)
		}
		return nil
	}
}

// probeAckCmdFor sends a probe_ack knock to the sender of an incoming
// knock, ONLY if the sender is a known contact with matching key and
// address, the bidirectional reachability signal ("sees me") behind
// probe_ping (the dedicated ping, see applyProbePing). Guarantee:
// k.FromAddr must match the expected onion/i2p, never toward unknown addresses.
//
// The mere arrival of this knock, once the guard above is passed, is
// ALREADY proof the sender reached us, i.e. that they see us,
// regardless of whether OUR OWN reply (the ack below) manages to reach
// THEM in turn: the two directions are asymmetric and must be recorded
// independently (see the comment on contactState.seenByPeer). That's
// why it updates local state immediately, synchronously, before
// attempting to reply.
func (m *model) probeAckCmdFor(k shared.KnockPayload) tea.Cmd {
	if len(k.FromIdentityPub) != 32 {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil // unknown contact: never reply
	}
	fromPub := ed25519.PublicKey(k.FromIdentityPub)
	if k.FromAddr != contact.NetAddr || m.dialTor == nil {
		return nil
	}
	pubKey := string(contact.IdentityPub)
	st := m.contactStates[pubKey]
	yes := true
	st.seenByPeer = &yes
	st.seenByPeerAt = time.Now()
	m.contactStates[pubKey] = st
	fromMLKEMPub := contact.MLKEMPub
	dial := m.dialTor
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	dhTagFn := m.dhTagFn
	knockTO := m.knockHttpTimeout
	onion := k.FromAddr
	return func() tea.Msg {
		go sendProbeAck(dial, onion, fromPub, fromMLKEMPub, myUsername, myPub, dhTagFn, knockTO)
		return nil
	}
}

// applyProbePing handles an incoming "probe_ping" knock, the
// dedicated, deliberate reachability ping, sent by probeContacts to
// every online contact on every cycle (~ActiveInterval, configurable)
// and also by hand via /active, regardless of any rotation. No key/
// rotation logic here: only replies with probe_ack.
func (m *model) applyProbePing(k shared.KnockPayload) tea.Cmd {
	return m.probeAckCmdFor(k)
}

// daysSince returns the difference in local calendar days between
// today and t (0 = today, 1 = yesterday, etc., never elapsed hours: an
// event from last night stays "yesterday" even if only a few hours have
// passed, not "today", and conversely an event from early this morning
// stays "today" even if more than 24 clock hours have passed since
// midnight-to-midnight). A future or zero t returns 0.
func daysSince(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	now := time.Now().Local()
	t = t.Local()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, now.Location())
	diff := int(today.Sub(day).Hours() / 24)
	if diff < 0 {
		return 0
	}
	return diff
}

// formatLocalTimestamp expresses a local clock (never a shared/network
// time) in a user-readable format, e.g. "2026-07-16 21:55".
func formatLocalTimestamp(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04")
}

// sendProbeAck sends a bidirectional reachability signal over the
// active transport (Tor or I2P). A lightweight reply to a probe_ping:
// confirms the circuits/tunnels toward the sender are
// active. Sent only toward addresses already present in the address book.
func sendProbeAck(dial func(context.Context, string, string) (net.Conn, error),
	toAddr string, toPub ed25519.PublicKey, toMLKEMPub []byte, myUsername string, myPub ed25519.PublicKey,
	dhTagFn func(ed25519.PublicKey) ([]byte, error), timeout time.Duration) {

	payload, err := encryptKnockTagged(dhTagFn, toPub, toMLKEMPub, shared.KnockPayload{
		Type:            "probe_ack",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
	})
	if err != nil {
		return
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := httpCli.Post("http://"+toAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// ── remote_nuke ─────────────────────────────────────────────────────────
//
// Remote self-destruction for a device outside physical control. No
// separate guardian identity: the AUTHORITY is whoever holds, in their
// own keystore file, the private key of any identity also duplicated
// on the target device (possession = authorization).
//
// The danger_broadcast does NOT depend on the target receiving and
// executing the command, if the stolen device stays off/unreachable
// for days or weeks, none of the contacts would ever know it's
// compromised until (and if) it comes back online. Instead the
// AUTHORITY sends it, immediately upon confirming /sec-remote-nuke,
// toward its OWN copy of the address book of the identity it ran
// /sec-indoor-sync with (already synced with the target, no need to
// wait for it). The target, if and when it actually receives the
// command, redoes it anyway as defense in depth (executeRemoteNuke):
// covers contacts added after the last /sec-indoor-sync, which the
// authority can't know about. The remote_nuke command itself isn't an
// isolated attempt with limited backoff: if the target doesn't respond
// within a session's few retries, it stays queued
// (Keystore.PendingRemoteNukes) and is automatically retried on every
// subsequent authority startup (retryPendingRemoteNukes, Init()) until
// a remote_nuke_ack arrives, even weeks later.
//
// The same reachability problem exists toward the AUTHORITY's own
// CONTACTS: a contact might never be online together with the
// authority in the same session. The authority's danger_broadcast
// therefore registers in Keystore.PendingDangerBroadcasts (identity
// keys not yet confirmed) and gets resent to any still-queued contact found online
// during a normal probeContacts cycle (no new dedicated timer), until
// each one replies with danger_broadcast_ack, see cmdRemoteNuke,
// sendDangerBroadcastSingle, handleDangerBroadcastAck.

// remoteNukeExecutedMsg signals that the TARGET's best-effort sequence
// (danger_broadcast + ack) has ended (success, partial failure, or
// timeout, always regardless): the case in Update() sets nukeOnExit
// and exits the TUI, exactly like cmdNukeX.
type remoteNukeExecutedMsg struct{}

// broadcastDangerMsg sends msgType ("danger_broadcast" or "danger_end"),
// in parallel and with a SINGLE shared time cap, toward the contacts of
// ALL the passed sibling identities (identities), each contact is
// contacted with the signature/tag of the identity IT belongs to (a
// contact of I2 must see a message authenticable as I2, not as I1,
// otherwise its handleIncomingDangerMsg would discard it as an unknown
// sender). Never blocking beyond the overall timeout, regardless of how
// many identities are involved. Used by the TARGET itself right before
// deleting itself (executeRemoteNuke, msgType="danger_end") and by the
// AUTHORITY as an immediate, best-effort complement to its persistent
// per-identity retry queue (cmdRemoteNukeBroadcast, msgType=
// "danger_broadcast"), that queue (Keystore.PendingDangerBroadcasts)
// only ever covers the identity active in THIS session; this call
// reaches every sibling identity's contacts that happen to be online
// right now, with no retry of its own beyond timeout (a contact offline
// at this exact moment, on a non-active sibling identity, is not
// covered by anything).
func broadcastDangerMsg(msgType string, identities []AllIdentityContactsInfo, dial func(context.Context, string, string) (net.Conn, error),
	knockTO, retryDelay time.Duration, targetDeviceID []byte, timeout time.Duration) {
	if dial == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, id := range identities {
		if id.DHTagFn == nil {
			continue
		}
		for _, c := range id.Contacts {
			if len(c.IdentityPub) != 32 || c.NetAddr == "" {
				continue
			}
			wg.Add(1)
			go func(id AllIdentityContactsInfo, c ContactInfo) {
				defer wg.Done()
				payload, err := encryptKnockTagged(id.DHTagFn, c.IdentityPub, c.MLKEMPub, shared.KnockPayload{
					Type:            msgType,
					FromUsername:    id.Username,
					FromIdentityPub: id.IdentityPub,
					TargetDeviceID:  targetDeviceID,
				})
				if err != nil {
					return
				}
				httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: knockTO}
				_, _ = postWithRetry(ctx, httpCli, "http://"+c.NetAddr+"/knock", payload, retryDelay)
			}(id, c)
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// sendDangerMsgSingle sends a single "danger_broadcast" (preliminary,
// queued warning) or "danger_end" (final warning) message to a contact
// msgType selects which. Fire-and-forget with no retry of its own:
// retry-over-time is the CALLER's responsibility (probeContacts, which
// resends on every probe cycle as long as the contact is still in the
// corresponding Keystore.PendingDangerBroadcasts/PendingDangerEnds queue).
func sendDangerMsgSingle(msgType string, dial func(context.Context, string, string) (net.Conn, error),
	netAddr string, recipientPub ed25519.PublicKey, recipientMLKEMPub []byte,
	myUsername string, myPub ed25519.PublicKey, dhTagFn func(ed25519.PublicKey) ([]byte, error),
	targetDeviceID []byte, timeout time.Duration) {
	payload, err := encryptKnockTagged(dhTagFn, recipientPub, recipientMLKEMPub, shared.KnockPayload{
		Type:            msgType,
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		TargetDeviceID:  targetDeviceID,
	})
	if err != nil {
		return
	}
	httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: timeout}
	resp, err := httpCli.Post("http://"+netAddr+"/knock", "text/plain", strings.NewReader(payload))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// handleRemoteNuke verifies an incoming remote_nuke command and, if
// valid, starts the destruction sequence. TargetDeviceID must match our
// own Keystore.DeviceID (otherwise the command isn't for this device,
// discarded with no effect) and NukeSig must verify against any of the
// keys in authorityPubKeys (every identity in this file, current AND
// old during an ongoing rotation), no list of "authorized devices" to
// consult, possession of the private key is proof in itself. A second
// valid command (e.g. from a second address of the same authority
// fan-out) is a silent no-op: the sequence is already in progress.
func (m *model) handleRemoteNuke(k shared.KnockPayload) tea.Cmd {
	if m.nukeOnExit {
		return nil
	}
	if len(m.myDeviceID) == 0 || len(k.TargetDeviceID) == 0 || !bytes.Equal(k.TargetDeviceID, m.myDeviceID) {
		return nil
	}
	if !shared.TsFresh(k.NukeTs) {
		client.Dbg("remote_nuke: ts=%q not fresh, discarded", k.NukeTs)
		return nil
	}
	verified := false
	for _, pub := range m.authorityPubKeys {
		if shared.VerifyRemoteNuke(pub, k.TargetDeviceID, k.NukeTs, k.NukeSig) {
			verified = true
			break
		}
	}
	// Additional, independent verification against
	// authorityPubKeysMLDSA if the Ed25519 proof above hasn't already
	// validated the command, a second, independent chain.
	if !verified && len(k.NukeSigMLDSA) > 0 {
		for _, pub := range m.authorityPubKeysMLDSA {
			if shared.VerifyRemoteNukeMLDSA(pub, k.TargetDeviceID, k.NukeTs, k.NukeSigMLDSA) {
				verified = true
				break
			}
		}
	}
	if !verified {
		client.Dbg("remote_nuke: NukeSig not verified against any local identity, discarded")
		return nil
	}
	client.Dbg("remote_nuke: valid command received from %s, starting the destruction sequence", k.FromUsername)
	m.appendToConsole(fmt.Sprintf(i18n.T("tui.remote_nuke_received"), k.FromUsername), true)
	return m.executeRemoteNuke(k.FromAddr, k.FromIdentityPub, k.TargetDeviceID)
}

// executeRemoteNuke runs the TARGET's best-effort, time-capped sequence
// (danger_end toward the contacts of every identity in the file, see
// TUIParams.AllIdentitiesContacts, then ack): never blocking beyond
// remoteNukeExecuteTimeout, an unreachable authority or contact must
// NEVER prevent the destruction, which proceeds regardless once the
// timeout expires. The primary warning channel remains the AUTHORITY's
// own (cmdRemoteNukeBroadcast, sent immediately upon confirming the
// command, not conditioned on the target being reachable).
const remoteNukeExecuteTimeout = 20 * time.Second

func (m *model) executeRemoteNuke(authorityAddr string, authorityPub ed25519.PublicKey, targetDeviceID []byte) tea.Cmd {
	dial := m.dialTor
	dhTagFn := m.dhTagFn
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	signAck := m.signRemoteNukeAck
	knockTO := m.knockHttpTimeout
	knockRetryDelay := m.knockRetryDelay
	allIdentitiesFn := m.allIdentitiesContacts
	// Fallback if the closure isn't available (test only, in
	// production AllIdentitiesContacts is always populated by
	// cmd/main.go): covers at least the identity active in this session.
	fallbackIdentity := AllIdentityContactsInfo{
		Username:    myUsername,
		IdentityPub: myPub,
		Contacts:    append([]ContactInfo(nil), m.contacts...),
		DHTagFn:     dhTagFn,
	}

	return func() tea.Msg {
		var allIdentities []AllIdentityContactsInfo
		if allIdentitiesFn != nil {
			allIdentities = allIdentitiesFn()
		}
		if len(allIdentities) == 0 {
			allIdentities = []AllIdentityContactsInfo{fallbackIdentity}
		}
		broadcastDangerMsg("danger_end", allIdentities, dial, knockTO, knockRetryDelay, targetDeviceID, remoteNukeExecuteTimeout)

		if dial != nil && dhTagFn != nil && signAck != nil && authorityAddr != "" && len(authorityPub) == 32 {
			sendRemoteNukeAck(dial, authorityAddr, authorityPub, nil, myUsername, myPub, dhTagFn, targetDeviceID, signAck, knockTO, knockRetryDelay)
		}

		return remoteNukeExecutedMsg{}
	}
}

// sendRemoteNukeAck sends the "about to disappear" confirmation to the
// authority that issued the command, same scheme as sendProbeAck but
// signed with the target's DEVICE-level key (signAck),
// not with an identity: it's the device itself confirming.
func sendRemoteNukeAck(dial func(context.Context, string, string) (net.Conn, error),
	toAddr string, toPub ed25519.PublicKey, toMLKEMPub []byte, myUsername string, myPub ed25519.PublicKey,
	dhTagFn func(ed25519.PublicKey) ([]byte, error), targetDeviceID []byte, signAck func([]byte, string) []byte,
	timeout, retryDelay time.Duration) bool {

	ts := shared.NowTS()
	sig := signAck(targetDeviceID, ts)
	payload, err := encryptKnockTagged(dhTagFn, toPub, toMLKEMPub, shared.KnockPayload{
		Type:            "remote_nuke_ack",
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		TargetDeviceID:  targetDeviceID,
		NukeTs:          ts,
		NukeSig:         sig,
	})
	if err != nil {
		client.Dbg("remote_nuke_ack: payload encryption toward %s failed: %v", toAddr, err)
		return false
	}
	httpCli := &http.Client{
		Transport: &http.Transport{DialContext: dial},
		Timeout:   timeout,
	}
	resp, err := postWithRetry(context.Background(), httpCli, "http://"+toAddr+"/knock", payload, retryDelay)
	if err != nil {
		client.Dbg("remote_nuke_ack: send to %s failed after every retry: %v", toAddr, err)
		return false
	}
	client.Dbg("remote_nuke_ack: sent successfully to %s", toAddr)
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	return true
}

// handleRemoteNukeAck receives the "about to disappear" confirmation
// from a target device: stops any other fan-out attempt still in
// progress for the same command (stops at the first genuine ack, no
// need to keep hammering the other addresses, the target is already
// confirmed reached), removes the command from the persistent queue (no
// further retry on the next startup), and reports it in Console.
//
// Verified with shared.VerifyRemoteNukeAck against the device key known
// among the known devices (TargetDeviceID can only appear there if the
// remote_nuke command was issued through the picker on that same list
// see cmdRemoteNukeTrigger, so the key is always already available
// by the time a legitimate ack can arrive). An unverified ack (missing/
// invalid signature, or unknown TargetDeviceID) is discarded with no
// effect, doesn't stop the fan-out nor touch the persistent queue, the
// retry proceeds normally: a forged ack must never be able to silently
// bury a command the real target hasn't received yet.
// The safety of the destruction itself remains whatever the target
// already applied before sending the ack (handleRemoteNuke), this
// check only protects the integrity of the confirm/retry mechanism, it
// doesn't introduce a second gate on the destruction.
func (m *model) handleRemoteNukeAck(k shared.KnockPayload) tea.Cmd {
	if len(k.TargetDeviceID) == 0 {
		return nil
	}
	var devicePub ed25519.PublicKey
	for _, rec := range m.knownDevicesNow() {
		if bytes.Equal(rec.DeviceID, k.TargetDeviceID) {
			devicePub = rec.DevicePub
			break
		}
	}
	if !shared.VerifyRemoteNukeAck(devicePub, k.TargetDeviceID, k.NukeTs, k.NukeSig) {
		client.Dbg("remote_nuke_ack: signature not verified (unknown device or invalid signature) from %s, discarded", k.FromUsername)
		return nil
	}
	// Freshness (same principle already applied to remote_nuke itself
	// and to rel_key_rotate): without this, an old captured ack,
	// authentic, from a past remote_nuke cycle, could be replayed to
	// silently stop the fan-out of a NEW command genuinely in progress,
	// and show "device destroyed" when it actually isn't.
	if !shared.TsFresh(k.NukeTs) {
		client.Dbg("remote_nuke_ack: ts not fresh (possible replay) from %s, discarded", k.FromUsername)
		return nil
	}
	m.stopRemoteNukeFanOut(k.TargetDeviceID)
	if m.clearPendingRemoteNuke != nil {
		_ = m.clearPendingRemoteNuke(k.TargetDeviceID)
	}
	m.appendToConsole(fmt.Sprintf(i18n.T("tui.remote_nuke_ack_received"), k.FromUsername), true)
	// Safety net: now that the destruction is CONFIRMED, the authority
	// re-broadcasts danger_end toward its own contacts, whoever was
	// offline when the target sent its own direct danger_end
	// (broadcastDangerEnd) still receives it from here, later. Same
	// persistent queue/retry as every other warning, see cmdRegisterDangerQueue.
	return m.cmdRemoteNukeEndBroadcast(k.TargetDeviceID)
}

// handleDangerBroadcast receives the PRELIMINARY "my device is
// compromised" announcement from a contact, a thin wrapper over
// handleIncomingDangerMsg (isEnd=false).
func (m *model) handleDangerBroadcast(k shared.KnockPayload) tea.Cmd {
	return m.handleIncomingDangerMsg(k, false)
}

// handleDangerEnd receives the FINAL "my device has been destroyed"
// announcement from a contact (from the target itself before
// disappearing, or from the authority as a safety net), a thin
// wrapper over handleIncomingDangerMsg (isEnd=true).
func (m *model) handleDangerEnd(k shared.KnockPayload) tea.Cmd {
	return m.handleIncomingDangerMsg(k, true)
}

// handleIncomingDangerMsg handles both "danger_broadcast" (preliminary)
// and "danger_end" (final), only a clearly visible Console
// notification, no automatic filtering of future messages per device.
// Authenticated at the same trust level as any other
// knock (the encrypted envelope + FromIdentityPub verified against the
// address book): no additional signature needed, an unknown contact
// produces no notification.
//
// Arrival-order guard: danger_end can arrive BEFORE a danger_broadcast
// for the same device (a single target→contact hop versus the second
// message's double authority→target→ack→authority→contact round trip)
// a preliminary danger_broadcast arriving AFTER the final one for the
// same device has already been seen (dangerEndSeen) doesn't generate a
// second, misleading Console message ("in progress" after "confirmed
// destroyed"), but the ack still goes out, so the sender's queue closes normally.
func (m *model) handleIncomingDangerMsg(k shared.KnockPayload, isEnd bool) tea.Cmd {
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil
	}
	key := hex.EncodeToString(k.TargetDeviceID)
	if isEnd {
		if m.dangerEndSeen == nil {
			m.dangerEndSeen = make(map[string]bool)
		}
		if !m.dangerEndSeen[key] {
			m.dangerEndSeen[key] = true
			m.appendToConsole(fmt.Sprintf(i18n.T("tui.danger_end_received"), contact.NameWithUsername()), true)
		}
	} else if !m.dangerEndSeen[key] {
		m.appendToConsole(fmt.Sprintf(i18n.T("tui.danger_broadcast_received"), contact.NameWithUsername()), true)
	}

	// Confirms receipt (danger_broadcast_ack/danger_end_ack): without
	// this, a sender with a persistent queue (the authority, for both
	// types) would keep resending it on every probe cycle even if
	// already received, indefinitely. If the sender is the target
	// itself shortly before disappearing, the ack simply finds no one
	// listening, harmless, the target doesn't keep a queue to close anyway.
	dial := m.dialTor
	dhTagFn := m.dhTagFn
	if dial == nil || dhTagFn == nil || contact.NetAddr == "" {
		return nil
	}
	ackType := "danger_broadcast_ack"
	if isEnd {
		ackType = "danger_end_ack"
	}
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	toAddr := contact.NetAddr
	toPub := ed25519.PublicKey(contact.IdentityPub)
	toMLKEMPub := contact.MLKEMPub
	targetDeviceID := k.TargetDeviceID
	knockTO := m.knockHttpTimeout
	knockRetryDelay := m.knockRetryDelay
	return func() tea.Msg {
		sendDangerAckMsg(ackType, dial, toAddr, toPub, toMLKEMPub, myUsername, myPub, dhTagFn, targetDeviceID, knockTO, knockRetryDelay)
		return nil
	}
}

// sendDangerAckMsg sends the confirmation of receiving a
// danger_broadcast (ackType="danger_broadcast_ack") or a danger_end
// (ackType="danger_end_ack") back to the sender, same scheme as
// sendRemoteNukeAck (retry+backoff, postWithRetry): a
// single delivery failure must not leave the sender retrying
// indefinitely a warning already received successfully.
func sendDangerAckMsg(ackType string, dial func(context.Context, string, string) (net.Conn, error),
	toAddr string, toPub ed25519.PublicKey, toMLKEMPub []byte, myUsername string, myPub ed25519.PublicKey,
	dhTagFn func(ed25519.PublicKey) ([]byte, error), targetDeviceID []byte, timeout, retryDelay time.Duration) bool {
	payload, err := encryptKnockTagged(dhTagFn, toPub, toMLKEMPub, shared.KnockPayload{
		Type:            ackType,
		FromUsername:    myUsername,
		FromIdentityPub: myPub,
		TargetDeviceID:  targetDeviceID,
	})
	if err != nil {
		client.Dbg("%s: payload encryption toward %s failed: %v", ackType, toAddr, err)
		return false
	}
	httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: timeout}
	resp, err := postWithRetry(context.Background(), httpCli, "http://"+toAddr+"/knock", payload, retryDelay)
	if err != nil {
		client.Dbg("%s: send to %s failed after every retry: %v", ackType, toAddr, err)
		return false
	}
	client.Dbg("%s: sent successfully to %s", ackType, toAddr)
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	return true
}

// handleDangerBroadcastAck receives confirmation that a contact
// received our preliminary danger_broadcast, a thin wrapper over
// handleIncomingDangerAck (isEnd=false).
func (m *model) handleDangerBroadcastAck(k shared.KnockPayload) tea.Cmd {
	return m.handleIncomingDangerAck(k, false)
}

// handleDangerEndAck receives confirmation that a contact received our
// final danger_end, a thin wrapper over handleIncomingDangerAck (isEnd=true).
func (m *model) handleDangerEndAck(k shared.KnockPayload) tea.Cmd {
	return m.handleIncomingDangerAck(k, true)
}

// handleIncomingDangerAck removes the sender (by identity key) from the corresponding
// queue (pendingDangerBroadcasts or pendingDangerEnds, independent
// queues) both in memory (consulted by probeContacts on the next cycle)
// and on disk (confirmDangerBroadcast/confirmDangerEnd), no further
// retry for this contact/device/message type.
func (m *model) handleIncomingDangerAck(k shared.KnockPayload, isEnd bool) tea.Cmd {
	if len(k.TargetDeviceID) == 0 || len(k.FromIdentityPub) != ed25519.PublicKeySize {
		return nil
	}
	queue := &m.pendingDangerBroadcasts
	confirmFn := m.confirmDangerBroadcast
	consoleKey := "tui.danger_broadcast_ack_received"
	if isEnd {
		queue = &m.pendingDangerEnds
		confirmFn = m.confirmDangerEnd
		consoleKey = "tui.danger_end_ack_received"
	}
	for i, p := range *queue {
		if !bytes.Equal(p.TargetDeviceID, k.TargetDeviceID) {
			continue
		}
		for j, pub := range p.IdentityPubs {
			if bytes.Equal(pub, k.FromIdentityPub) {
				(*queue)[i].IdentityPubs = append(p.IdentityPubs[:j], p.IdentityPubs[j+1:]...)
				break
			}
		}
		if len((*queue)[i].IdentityPubs) == 0 {
			*queue = append((*queue)[:i], (*queue)[i+1:]...)
		}
		break
	}
	if confirmFn != nil {
		_ = confirmFn(k.TargetDeviceID, k.FromIdentityPub)
	}
	m.appendToConsole(fmt.Sprintf(i18n.T(consoleKey), k.FromUsername), false)
	return nil
}

// remoteNukeEntry wraps a CancelFunc inside its own pointer because a
// raw CancelFunc isn't comparable in Go (except to nil): the deferred
// cleanup in cmdRemoteNukeFanOut must be able to tell "am I still the
// current entry in remoteNukeCancels" from "a more recent retry for the
// same DeviceID has already replaced me" by comparing pointers, not
// possible by comparing two func values.
type remoteNukeEntry struct {
	cancel context.CancelFunc
}

// stopRemoteNukeFanOut cancels (if present) the context shared by all
// goroutines of the remote_nuke fan-out still in progress for
// targetDeviceID, any retry/attempt still pending on the other
// addresses stops at the next opportunity (postWithRetry watches ctx.Done()).
func (m *model) stopRemoteNukeFanOut(targetDeviceID []byte) {
	key := hex.EncodeToString(targetDeviceID)
	m.remoteNukeMu.Lock()
	entry := m.remoteNukeCancels[key]
	delete(m.remoteNukeCancels, key)
	m.remoteNukeMu.Unlock()
	if entry != nil {
		entry.cancel()
	}
}

// cmdRemoteNuke is invoked on explicit confirmation of
// /sec-remote-nuke: validates the targets, registers the command in the
// persistent queue (Keystore.PendingRemoteNukes, retried on every
// startup until an ack arrives, see retryPendingRemoteNukes) and starts
// in parallel both the AUTHORITY's danger_broadcast (primary channel,
// immediate, not conditioned on the target being reachable) and the
// first fan-out attempt of the actual command.
func (m *model) cmdRemoteNuke(rec DeviceRecordInfo) tea.Cmd {
	if m.signRemoteNuke == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_remote_nuke_unavailable")))
	}
	targetCount := countValidRemoteNukeTargets(rec)
	if targetCount == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_remote_nuke_no_targets")))
	}
	if m.addPendingRemoteNuke != nil {
		_ = m.addPendingRemoteNuke(rec.DeviceID)
	}
	label := rec.Label
	if label == "" {
		label = hex.EncodeToString(rec.DeviceID)
	}
	m.appendToConsole(i18n.T("tui.remote_nuke_danger_broadcast_sent"), true)
	m.appendToConsole(fmt.Sprintf(i18n.T("tui.remote_nuke_sent"), label, targetCount), true)
	return tea.Batch(m.cmdRemoteNukeBroadcast(rec.DeviceID), m.cmdRemoteNukeFanOut(rec))
}

// countValidRemoteNukeTargets counts rec's sibling identities usable as
// fan-out targets (valid IdentityPub), shared by cmdRemoteNuke and
// retryPendingRemoteNukes to avoid duplicating the check.
func countValidRemoteNukeTargets(rec DeviceRecordInfo) int {
	n := 0
	for _, ref := range rec.SiblingIdentities {
		if len(ref.IdentityPub) == 32 {
			n++
		}
	}
	return n
}

// remoteNukeBroadcastTimeout bounds broadcastDangerBroadcastAllIdentities's
// immediate, best-effort danger_broadcast fan-out, same ~20s order of
// magnitude as remoteNukeExecuteTimeout/nukeDeviceSyncTimeout elsewhere
// in this codebase. Never blocks /sec-remote-nuke beyond this, however
// many sibling identities/contacts are involved.
const remoteNukeBroadcastTimeout = 20 * time.Second

// cmdRemoteNukeBroadcast registers the AUTHORITY's PRELIMINARY
// danger_broadcast toward its own address book (cmdRegisterDangerQueue,
// isEnd=false, persistent retry queue, but covers only the identity
// active in THIS session) AND, in the same call, fires an immediate
// best-effort complement across every sibling identity in the file
// (broadcastDangerBroadcastAllIdentities): without this second part, a
// contact of a non-active sibling identity would never be warned at
// all. Primary channel, called
// right upon confirming /sec-remote-nuke (cmdRemoteNuke), independent of
// whether the target itself is reachable.
func (m *model) cmdRemoteNukeBroadcast(targetDeviceID []byte) tea.Cmd {
	return tea.Batch(m.cmdRegisterDangerQueue(targetDeviceID, false), m.broadcastDangerBroadcastAllIdentities(targetDeviceID))
}

// broadcastDangerBroadcastAllIdentities is the immediate-fan-out half
// of cmdRemoteNukeBroadcast, see its doc comment and
// broadcastDangerMsg's. Never retried beyond remoteNukeBroadcastTimeout:
// a contact offline right now, on a non-active sibling identity, is
// not covered by anything.
func (m *model) broadcastDangerBroadcastAllIdentities(targetDeviceID []byte) tea.Cmd {
	if m.dialTor == nil || m.allIdentitiesContacts == nil {
		return nil
	}
	dial := m.dialTor
	allIdentitiesFn := m.allIdentitiesContacts
	knockTO := m.knockHttpTimeout
	retryDelay := m.knockRetryDelay
	return func() tea.Msg {
		broadcastDangerMsg("danger_broadcast", allIdentitiesFn(), dial, knockTO, retryDelay, targetDeviceID, remoteNukeBroadcastTimeout)
		return nil
	}
}

// cmdRemoteNukeEndBroadcast registers the AUTHORITY's FINAL danger_end
// toward its own address book, a thin wrapper over
// cmdRegisterDangerQueue (isEnd=true). A safety net, called upon
// receiving the remote_nuke_ack (handleRemoteNukeAck): covers only the
// contacts of identities the authority actually holds (never ones never
// duplicated/synced), but also reaches whoever was offline when the
// target sent its own direct danger_end (broadcastDangerEnd,
// executeRemoteNuke), a contact receiving it from both sources still
// replies with an ack to each, no duplication issue (see
// handleIncomingDangerMsg).
func (m *model) cmdRemoteNukeEndBroadcast(targetDeviceID []byte) tea.Cmd {
	return m.cmdRegisterDangerQueue(targetDeviceID, true)
}

// cmdRegisterDangerQueue registers a warning (preliminary or final, see
// isEnd) toward the own address book as a persistent queue
// (Keystore.PendingDangerBroadcasts/PendingDangerEnds) and immediately
// triggers a probeContacts cycle:
// whoever is online right now receives the warning immediately,
// whoever isn't stays queued and is retried on the next periodic
// cycles (tickActiveMsg) with no further action needed from the user.
func (m *model) cmdRegisterDangerQueue(targetDeviceID []byte, isEnd bool) tea.Cmd {
	pubs := make([][]byte, 0, len(m.contacts))
	for _, c := range m.contacts {
		if len(c.IdentityPub) == 32 && c.NetAddr != "" {
			pubs = append(pubs, append([]byte(nil), c.IdentityPub...))
		}
	}
	if len(pubs) == 0 {
		return nil
	}
	entry := DangerBroadcastPendingInfo{TargetDeviceID: targetDeviceID, IdentityPubs: pubs}
	if isEnd {
		m.pendingDangerEnds = append(m.pendingDangerEnds, entry)
		if m.setDangerEndPending != nil {
			_ = m.setDangerEndPending(targetDeviceID, pubs)
		}
	} else {
		m.pendingDangerBroadcasts = append(m.pendingDangerBroadcasts, entry)
		if m.setDangerBroadcastPending != nil {
			_ = m.setDangerBroadcastPending(targetDeviceID, pubs)
		}
	}
	return m.probeContacts(m.consoleIdx, true)
}

// cmdRemoteNukeFanOut sends a remote_nuke command (with timestamp and
// signature ALWAYS fresh, generated here, necessary because every
// attempt, including a retry days later, must fall within the ±5
// minute freshness window verified by the target) toward ALL addresses
// of the sibling identities present on device rec (multi-identity fan-
// out: the sender doesn't know which one will be reachable at that
// moment, they're all the same exact target, same keystore file), in
// parallel with retry/backoff, with automatic stop at the first
// remote_nuke_ack received from any of them (see
// handleRemoteNukeAck/stopRemoteNukeFanOut). Reused both by the first
// emission (cmdRemoteNuke) and by every subsequent retry
// (retryPendingRemoteNukes), no queue registration or danger_broadcast
// here, already done once by cmdRemoteNuke.
func (m *model) cmdRemoteNukeFanOut(rec DeviceRecordInfo) tea.Cmd {
	targets := make([]DeviceIdentityRef, 0, len(rec.SiblingIdentities))
	for _, ref := range rec.SiblingIdentities {
		if len(ref.IdentityPub) == 32 {
			targets = append(targets, ref)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	ts := shared.NowTS()
	sig := m.signRemoteNuke(rec.DeviceID, ts)
	var sigMLDSA []byte
	if m.signRemoteNukeMLDSA != nil {
		sigMLDSA = m.signRemoteNukeMLDSA(rec.DeviceID, ts)
	}
	dial := m.dialTor
	dhTagFn := m.dhTagFn
	myUsername := m.myUsername
	myPub := ed25519.PublicKey(m.myIdentityPub)
	myAddr := m.myAddr
	knockTO := m.knockHttpTimeout
	retryDelay := m.knockRetryDelay
	targetDeviceID := rec.DeviceID
	computeAddr := m.computeAddress
	networkIdentityPubFor := m.networkIdentityPubFor

	key := hex.EncodeToString(targetDeviceID)
	ctx, cancel := context.WithCancel(context.Background())
	entry := &remoteNukeEntry{cancel: cancel}
	m.remoteNukeMu.Lock()
	if m.remoteNukeCancels == nil {
		m.remoteNukeCancels = make(map[string]*remoteNukeEntry)
	}
	if old := m.remoteNukeCancels[key]; old != nil {
		old.cancel() // a previous send for the same device was still in progress: replaced, not accumulated
	}
	m.remoteNukeCancels[key] = entry
	m.remoteNukeMu.Unlock()

	return func() tea.Msg {
		defer func() {
			m.remoteNukeMu.Lock()
			// Compared by pointer, not just "!= nil": if in the
			// meantime a more recent retry for the same DeviceID has
			// already replaced this entry, the current entry in the
			// map is no longer ours, deleting it anyway would
			// silently delete the still-in-progress retry's entry,
			// leaving it with no way to be stopped by an ack received
			// later (stopRemoteNukeFanOut would no longer find it).
			if m.remoteNukeCancels[key] == entry {
				delete(m.remoteNukeCancels, key)
			}
			m.remoteNukeMu.Unlock()
			cancel()
		}()
		var wg sync.WaitGroup
		for _, ref := range targets {
			wg.Add(1)
			go func(ref DeviceIdentityRef) {
				defer wg.Done()
				if dial == nil || dhTagFn == nil {
					return
				}
				// addrs can hold more than one candidate for the same
				// ref: the root address (reaches that device ONLY if
				// it hosts ref.IdentityPub as D1) and, when ref is
				// THIS identity (the only one whose additional device
				// address we can derive, since we hold its root
				// private key), also the address derived via
				// NetworkIdentityPrivKeyFor(targetDeviceID). No
				// removal of the existing candidate.
				var addrs []string
				if a := computeAddr(ref.IdentityPub); a != "" {
					addrs = append(addrs, a)
				}
				if networkIdentityPubFor != nil && bytes.Equal(ref.IdentityPub, myPub) {
					if derivedPub := networkIdentityPubFor(targetDeviceID); len(derivedPub) == ed25519.PublicKeySize {
						if a := computeAddr(derivedPub); a != "" && (len(addrs) == 0 || a != addrs[0]) {
							addrs = append(addrs, a)
						}
					}
				}
				if len(addrs) == 0 {
					return
				}
				payload, err := encryptKnockTagged(dhTagFn, ref.IdentityPub, ref.MLKEMPub, shared.KnockPayload{
					Type:            "remote_nuke",
					FromUsername:    myUsername,
					FromIdentityPub: myPub,
					// Where the target sends its remote_nuke_ack.
					FromAddr:       myAddr,
					TargetDeviceID: targetDeviceID,
					NukeTs:         ts,
					NukeSig:        sig,
					NukeSigMLDSA:   sigMLDSA,
				})
				if err != nil {
					return
				}
				httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: knockTO}
				var awg sync.WaitGroup
				for _, addr := range addrs {
					awg.Add(1)
					go func(addr string) {
						defer awg.Done()
						_, _ = postWithRetry(ctx, httpCli, "http://"+addr+"/knock", payload, retryDelay)
					}(addr)
				}
				awg.Wait()
			}(ref)
		}
		wg.Wait()
		return nil
	}
}

// retryPendingRemoteNukes redoes the fan-out (no new danger_broadcast:
// already sent once by cmdRemoteNuke) for every remote_nuke command
// still queued (Keystore.PendingRemoteNukes), called from Init() on
// every startup, with the same initial delay as the circuits warmup. A
// target whose DeviceID no longer resolves against KnownDevices (should
// never happen) or with no valid sibling identities is silently
// skipped, without interrupting the others.
func (m *model) retryPendingRemoteNukes() tea.Cmd {
	if len(m.pendingRemoteNukeTargets) == 0 {
		return nil
	}
	cmds := make([]tea.Cmd, 0, len(m.pendingRemoteNukeTargets))
	sent := 0
	for _, rec := range m.pendingRemoteNukeTargets {
		if countValidRemoteNukeTargets(rec) == 0 {
			continue
		}
		cmds = append(cmds, m.cmdRemoteNukeFanOut(rec))
		sent++
	}
	if sent == 0 {
		return nil
	}
	m.appendToConsole(fmt.Sprintf(i18n.T("tui.remote_nuke_retry_pending"), sent), true)
	return tea.Batch(cmds...)
}

// ── indoor sync ─────────────────────────────────────────────────────────

// indoorSyncDoneMsg signals the end of an "indoor" sync window (success
// or failure/timeout), see cmdIndoorSync.
type indoorSyncDoneMsg struct{ err error }

// cmdIndoorSync starts an "indoor" sync window (LAN) in the
// background, blocking until the first successful exchange or the
// window's expiry (~60s, see indoor.SyncWindow), never on Update()'s
// thread. indoorSyncing prevents two overlapping windows (both would
// bind the same TCP port, the second would fail the bind anyway, clearer
// to say so right away than to let it be discovered from a cryptic network error).
func (m *model) cmdIndoorSync() tea.Cmd {
	if m.runIndoorSync == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_indoor_sync_unavailable")))
	}
	if m.indoorSyncing {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.indoor_sync_in_progress")))
	}
	m.indoorSyncing = true
	m.appendToConsole(i18n.T("tui.indoor_sync_started"), false)
	runFn := m.runIndoorSync
	return func() tea.Msg {
		// Margin beyond indoor.SyncWindow (~60s): the caller must be
		// able to distinguish "no peer found" (RunIndoorSync's clean
		// return) from a real network stall, never a ctx shorter than
		// the window RunIndoorSync itself already respects internally.
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		err := runFn(ctx)
		return indoorSyncDoneMsg{err: err}
	}
}

// cmdDevices shows a read-only popup with the known devices for one's
// own identity (Keystore.KnownDevices, populated by /sec-indoor-sync).
func (m *model) cmdDevices() tea.Cmd {
	if len(m.knownDevicesNow()) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_remote_nuke_no_known_devices")))
	}
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.devices_list_title")))
	sb.WriteString("\n\n")
	for _, rec := range m.knownDevicesNow() {
		label := rec.Label
		if label == "" {
			label = hex.EncodeToString(rec.DeviceID)
		}
		sb.WriteString("  " + label + "\n")
		for _, ref := range rec.SiblingIdentities {
			sb.WriteString("    - " + ref.Username + "\n")
		}
	}
	return localTab(m.defaultTabIdx(), m.renderBoxPopup(strings.TrimSuffix(sb.String(), "\n")))
}

// cmdDeviceLabel shows (with no argument) or changes (with an
// argument) THIS device's name, the only way for another of our own
// devices to distinguish it in the /sec-remote-nuke picker or the
// /sec-devices list, instead of just the raw DeviceID. Visible to other
// devices only at the next /sec-indoor-sync, but the change itself is
// immediate (persisted right away), not a setting requiring a restart,
// which is why it stays a TUI slash-command rather than its own CLI subcommand.
func (m *model) cmdDeviceLabel(arg string) tea.Cmd {
	if m.setDeviceLabel == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_indoor_sync_unavailable")))
	}
	if arg == "" {
		label := m.myDeviceLabel
		if label == "" {
			label = i18n.T("tui.none_label")
		}
		return localTab(m.defaultTabIdx(), styleMeta.Render(fmt.Sprintf(i18n.T("tui.device_label_current"), label)))
	}
	if err := m.setDeviceLabel(arg); err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error"), err)))
	}
	m.myDeviceLabel = arg
	return localTab(m.defaultTabIdx(), styleMeta.Render(fmt.Sprintf(i18n.T("tui.device_label_set"), arg)))
}

// cmdMsg sets the explicit reply reference for the next send in the
// active tab, arg is the number (#N, chatLine.gseq) shown in the
// header of a message already visible in THIS tab; a number that
// doesn't match any currently shown line is rejected (the reference can
// only point to a message already seen, never a future one or one that
// never arrived here).
func (m *model) cmdMsg(arg string) tea.Cmd {
	tab := m.tabs[m.active]
	if tab.isStandardTab() {
		m.textPopupMode = true
		m.textPopupContent = i18n.T("tui.standard_tab_no_freetext_popup")
		return nil
	}
	n, err := strconv.ParseUint(arg, 10, 64)
	if err != nil || n == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_msg_invalid_number"), arg)))
	}
	found := false
	for _, l := range tab.lines {
		if l.gseq == n {
			found = true
			break
		}
	}
	if !found {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_msg_not_shown"), n)))
	}
	tab.pendingReplyTo = n
	return nil
}

// applyProbeAck receives a probe_ack and updates the sending contact's
// "sees me" status. Accepts the message only if the sender is a known
// contact with a matching key.
func (m *model) applyProbeAck(k shared.KnockPayload) tea.Cmd {
	if len(k.FromIdentityPub) != 32 {
		return nil
	}
	contact := m.resolveContactByPub(k.FromIdentityPub)
	if contact == nil {
		return nil // sender not in address book: ignore
	}
	seen := true
	now := time.Now()
	pubKey := string(contact.IdentityPub)
	st := m.contactStates[pubKey]
	st.seenByPeer = &seen
	st.seenByPeerAt = now
	m.contactStates[pubKey] = st
	if m.dirtyLastAck == nil {
		m.dirtyLastAck = make(map[string]time.Time)
	}
	m.dirtyLastAck[pubKey] = now
	contact.LastAckAt = now
	return nil
}

// flushActivityCmd persists in the background the acks accumulated
// since the last flush together with this probe cycle's "present"
// contacts (reached via TCP), in a single Save() instead of one per
// event. Called at the end of every probe cycle (probeResultMsg): at
// most one Save() per cycle.
func (m *model) flushActivityCmd(seenNow map[string]time.Time) tea.Cmd {
	if (len(m.dirtyLastAck) == 0 && len(seenNow) == 0) || m.flushContactsActivity == nil {
		return nil
	}
	acks := m.dirtyLastAck
	m.dirtyLastAck = make(map[string]time.Time)
	fn := m.flushContactsActivity
	return func() tea.Msg {
		_ = fn(acks, seenNow)
		return nil
	}
}

// flushActivitySync is the synchronous variant used on shutdown
// (before tea.Quit): the program is about to exit, so we can't rely on
// a background tea.Cmd that might not finish. Covers only the
// accumulated acks: a probe cycle in progress at shutdown time hasn't
// produced "present" contacts yet.
func (m *model) flushActivitySync() {
	if len(m.dirtyLastAck) == 0 || m.flushContactsActivity == nil {
		return
	}
	_ = m.flushContactsActivity(m.dirtyLastAck, nil)
	m.dirtyLastAck = make(map[string]time.Time)
}

// contentSigTS reads content_sig_ts from a message's raw frame, the
// same timestamp used to build/verify EVERY entry in content_sigs (one
// timestamp per message, not one per recipient).
func contentSigTS(mm map[string]any) string {
	ts, _ := mm["content_sig_ts"].(string)
	return ts
}

// extractContentSigsFor looks inside content_sigs (see
// client.contentSigEntry) for ALL entries with For == forKey (a member key),
// returns every (sig, sigMLDSA) found: with a multi-device sender
// (fan-out), the sender signs ONCE for each of the recipient's devices,
// all with the same For, the verifier (a single local instance, never
// genuinely "multiple devices" on its own side) tries each one until
// one matches its own unique known key for the sender. content_sigs
// arrives as []any of map[string]any after the JSON→map[string]any
// round trip (encoding/json doesn't know the concrete type), Sig/
// SigMLDSA as standard base64 strings (default []byte marshaling).
func extractContentSigsFor(mm map[string]any, forKey string) []struct{ sig, sigMLDSA []byte } {
	entries, _ := mm["content_sigs"].([]any)
	var out []struct{ sig, sigMLDSA []byte }
	for _, e := range entries {
		entry, _ := e.(map[string]any)
		if entry == nil {
			continue
		}
		forField, _ := entry["for"].(string)
		if forField != forKey {
			continue
		}
		var sig, sigMLDSA []byte
		if sigB64, _ := entry["sig"].(string); sigB64 != "" {
			sig, _ = base64.StdEncoding.DecodeString(sigB64)
		}
		if mldsaB64, _ := entry["sig_mldsa"].(string); mldsaB64 != "" {
			sigMLDSA, _ = base64.StdEncoding.DecodeString(mldsaB64)
		}
		if len(sig) > 0 {
			out = append(out, struct{ sig, sigMLDSA []byte }{sig, sigMLDSA})
		}
	}
	return out
}

// contentPeerCandidateKey is ONE candidate for verifying an incoming
// message's content signature, see contentPeerPubCandidatesFor.
type contentPeerCandidateKey struct {
	pub      ed25519.PublicKey
	mldsaPub []byte
	// ephemeral distinguishes a REL relationship born only from being
	// introduced in a room (ephemeral bootstrap, no direct contact)
	// from one with a contact persisted in the address book, used
	// only for coloring the REL tag in chat (yellow for ephemeral),
	// never to decide whether a signature is valid.
	ephemeral bool
}

// contentPeerPubCandidatesFor resolves the candidates for verifying a
// message's content signature from `from` toward US, persistent
// (Contact.Devices) for a real contact, ephemeral
// (ephemeralRel.peerContent) for an unknown "introduced" one with
// bootstrap already completed. dp is the sender's DevicePub, decoded
// from the message's sealed payload, if it matches an exact device of
// `from`, that ONE is the
// only candidate (precise resolution, never ambiguous: dp identifies
// exactly WHICH of `from`'s devices sent this specific message). With
// an empty or non-matching dp it falls back to
// ALL of `from`'s ready devices. No candidate → not yet verifiable
// (never an error: the caller, parseMessage, treats it as "pending",
// not "invalid").
func (m *model) contentPeerPubCandidatesFor(tab *roomTab, from string, dp []byte) []contentPeerCandidateKey {
	if c := m.resolveContactByPub(memberKeyPub(from)); c != nil {
		if dev, ok := c.DeviceByPub(dp); ok {
			// dp identifies exactly WHICH device sent this message
			// (never ambiguous, see the doc comment above), if that
			// exact device isn't verifiable (missing or revoked key)
			// the verdict is final: NEVER fall back and try a
			// different device, which would silently bypass the
			// revocation declared for this specific device.
			if len(dev.PeerRelContentPub) == ed25519.PublicKeySize && !dev.RevokedContent {
				return []contentPeerCandidateKey{{pub: ed25519.PublicKey(dev.PeerRelContentPub), mldsaPub: dev.PeerRelContentMLDSAPub}}
			}
			return nil
		}
		// Fallback onto ALL known devices (only for an empty or
		// unknown dp, never for a known but
		// rejected device above), not just ReadyDevices(), which also
		// requires Address/RelIdentityPriv, irrelevant for verifying a
		// signature: it's enough that PeerRelContentPub is present.
		// RevokedContent always excludes: a revoked ContentKey must
		// never verify a signature again, indistinguishable from "no candidate".
		out := make([]contentPeerCandidateKey, 0, len(c.Devices))
		for _, dev := range c.Devices {
			if dev == nil || len(dev.PeerRelContentPub) != ed25519.PublicKeySize || dev.RevokedContent {
				continue
			}
			out = append(out, contentPeerCandidateKey{pub: ed25519.PublicKey(dev.PeerRelContentPub), mldsaPub: dev.PeerRelContentMLDSAPub})
		}
		if len(out) > 0 {
			return out
		}
		// No device of this contact has a valid PeerRelContentPub yet
		// (contact saved but rel_init handshake never completed),
		// falls back to the ephemeral case below instead of returning
		// "no candidate" forever. Doesn't touch the exact-dp branch
		// above: a PRECISE device rejected (missing/revoked) stays a
		// final verdict, never a fallback, only the TOTAL absence of
		// valid devices falls through here.
	}
	if rel := tab.ephRels[from]; rel != nil && rel.established && len(rel.peerContent.Pub) == ed25519.PublicKeySize {
		return []contentPeerCandidateKey{{pub: rel.peerContent.Pub, mldsaPub: rel.peerContent.MLDSAPub, ephemeral: true}}
	}
	return nil
}

// contentPeerKeysFor resolves the public ContentKey (+ ML-KEM) of ONE
// of `from`'s devices toward US, for encrypting toward them (hybrid
// ECIES, see encryptForContentPeer, file transfer/contact card), also
// used to verify an incoming "file_announce"'s signature; only
// verifying a chat MESSAGE goes
// through contentPeerPubCandidatesFor above (multi-candidate, for the
// indirect signature inside the SenderKey ciphertext). With 2+
// candidate devices it picks ONE deterministically (ordered by
// DevicePub, not AnyReadyDevice: here only PeerRelContentPub being
// present matters, not the "ready for invite" criteria, Address/
// RelIdentityPriv, which are irrelevant) instead of failing: without a
// per-device session userID (one session per identity in a room),
// there's no way to address more than one device here
// anyway. RevokedContent always excludes a device from the candidates,
// same reason as contentPeerPubCandidatesFor.
func (m *model) contentPeerKeysFor(tab *roomTab, from string) (pub ed25519.PublicKey, mldsaPub, mlkemPub []byte, devKey string, known bool) {
	if c := m.resolveContactByPub(memberKeyPub(from)); c != nil {
		keys := make([]string, 0, len(c.Devices))
		for k := range c.Devices {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dev := c.Devices[k]
			if dev == nil || len(dev.PeerRelContentPub) != ed25519.PublicKeySize || dev.RevokedContent {
				continue
			}
			return ed25519.PublicKey(dev.PeerRelContentPub), dev.PeerRelContentMLDSAPub, dev.PeerRelContentMLKEMPub, k, true
		}
		// No valid device, falls back to the ephemeral case below,
		// same reason as contentPeerPubCandidatesFor above (contact
		// saved but rel_init handshake never completed).
	}
	if rel := tab.ephRels[from]; rel != nil && rel.established && len(rel.peerContent.Pub) == ed25519.PublicKeySize {
		return rel.peerContent.Pub, rel.peerContent.MLDSAPub, rel.peerContentMLKEMPub, "", true
	}
	return nil, nil, nil, "", false
}

// myContentPrivFor resolves OUR OWN per-relationship ContentKey toward
// ONE of the devices of the member with key peerKey, persistent (Contact.Devices) for a
// real contact, ephemeral (ephemeralRel.myContent) for an unknown
// "introduced" one with bootstrap already completed. The same pair
// used for signing (buildContentSigningKeys) and, here, for DECRYPTING
// what that member encrypted with our public ContentKey (dual
// Ed25519/X25519 use), same limitation as contentPeerKeysFor above
// (a single device chosen deterministically, never a true fan-out
// without a per-device userID).
func (m *model) myContentPrivFor(tab *roomTab, peerKey string) (shared.RelSigningKey, bool) {
	if c := m.resolveContactByPub(memberKeyPub(peerKey)); c != nil {
		keys := make([]string, 0, len(c.Devices))
		for k := range c.Devices {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dev := c.Devices[k]
			if dev == nil || len(dev.RelContentPriv) != ed25519.PrivateKeySize {
				continue
			}
			return shared.RelSigningKey{Priv: ed25519.PrivateKey(dev.RelContentPriv), MLKEMSeed: dev.RelContentMLKEMPriv, MLDSASeed: dev.RelContentMLDSAPriv}, true
		}
		// No valid device, falls back to the ephemeral case below,
		// same reason as contentPeerPubCandidatesFor above (contact
		// saved but rel_init handshake never completed).
	}
	if rel := tab.ephRels[peerKey]; rel != nil && len(rel.myContent.Priv) == ed25519.PrivateKeySize {
		return rel.myContent, true
	}
	return shared.RelSigningKey{}, false
}

// encryptForContentPeer/decryptFromContentPeer encrypt an arbitrary
// blob (a file_offer's meta_blob: {file_name, file_size, file_key})
// using the per-relationship ContentKey, the same pair used for
// signing, dual Ed25519/X25519 use (shared.EncryptForPeer/
// DecryptFromPeer, classic/hybrid ML-KEM-768 dual-mode already used for
// knocks). Each recipient gets an envelope encrypted specifically for
// them, never a shared value.
func encryptForContentPeer(peerContentPub ed25519.PublicKey, peerContentMLKEMPub, plaintext []byte) (string, error) {
	var mlkemPub *mlkem.EncapsulationKey768
	if len(peerContentMLKEMPub) > 0 {
		if ek, err := mlkem.NewEncapsulationKey768(peerContentMLKEMPub); err == nil {
			mlkemPub = ek
		}
	}
	return shared.EncryptForPeer(peerContentPub, mlkemPub, plaintext)
}

func decryptFromContentPeer(myContentKey shared.RelSigningKey, payloadB64 string) ([]byte, error) {
	var mlkemPriv *mlkem.DecapsulationKey768
	if len(myContentKey.MLKEMSeed) > 0 {
		if dk, err := mlkem.NewDecapsulationKey768(myContentKey.MLKEMSeed); err == nil {
			mlkemPriv = dk
		}
	}
	return shared.DecryptFromPeer(myContentKey.Priv, mlkemPriv, payloadB64)
}

// buildContentSigningKeys rebuilds, for each other member of room tab
// (by member key), OUR OWN per-relationship ContentKey toward them, persistent
// (Contact.RelContentPriv) for a real contact, ephemeral
// (ephemeralRel.myContent) for an unknown "introduced" one with
// bootstrap already completed (established). Recomputed on every send
// (never cached): always reflects the current state (new members,
// rotations) with no need for a dedicated setter. A member with no
// relationship established yet (a contact with an incomplete rel_init,
// or an ephemeral bootstrap not yet established) simply stays absent
// from the map: the message still goes out, without a signature for them.
func (m *model) buildContentSigningKeys(tab *roomTab) map[string][]shared.RelSigningKey {
	keys := make(map[string][]shared.RelSigningKey, len(tab.groupMembers))
	for _, mem := range tab.groupMembers {
		mk := memberKey(mem)
		if mk == m.myKey() {
			continue
		}
		if c := m.resolveContactByPub(mem.IdentityPub); c != nil {
			// Fan-out: ONE signature for EVERY known device of mem with
			// an established content relationship, each has its own
			// independent key pair with us, never shared between
			// devices of the same contact. On the wire it stays a
			// single content_sigs list with multiple "for":
			// member-key entries, the receiving device (a single
			// local instance) tries each one against its own unique
			// known key for us, see contentPeerPubCandidatesFor.
			for _, dev := range c.Devices {
				if dev == nil || len(dev.RelContentPriv) != ed25519.PrivateKeySize {
					continue
				}
				keys[mk] = append(keys[mk], shared.RelSigningKey{Priv: ed25519.PrivateKey(dev.RelContentPriv), MLKEMSeed: dev.RelContentMLKEMPriv, MLDSASeed: dev.RelContentMLDSAPriv})
			}
			continue
		}
		// Unlike verification (contentPeerPubCandidatesFor, which
		// requires established: it needs THEIR half, received only
		// once bootstrap completes), here it's enough that OUR OWN
		// half already exists, always true as soon as
		// maybeSendRelBootstrap has generated rel (fires automatically
		// on init/user_joined, well before the user types a message):
		// they'll be able to verify this signature as soon as they
		// receive OUR OWN rel_bootstrap, independent of whether we've
		// received theirs. No multi-device concept for an ephemeral
		// contact, a single candidate.
		if rel := tab.ephRels[mk]; rel != nil {
			keys[mk] = []shared.RelSigningKey{rel.myContent}
		}
	}
	return keys
}

// sendMessage sends free text, but only inside a real chat room. In
// every "standard" tab (Console, Contacts, Groups, Tor, Files), free
// text is not a valid action: a single popup blocks free text
// anywhere that isn't a chat, instead of per-tab silent redirects.
func (m *model) sendMessage(text string) tea.Cmd {
	tab := m.tabs[m.active]
	if tab.isStandardTab() {
		m.textPopupMode = true
		m.textPopupContent = i18n.T("tui.standard_tab_no_freetext_popup")
		return nil
	}
	if tab.cli == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_no_connection")))
	}
	contentKeys := m.buildContentSigningKeys(tab)
	cli := tab.cli
	ctx := tab.ctx
	consoleIdx := m.consoleIdx
	budget := m.senderKeyMessageBudget
	replyTo := tab.pendingReplyTo // one-shot: captured now, never reread later (see replySentMsg)
	tabIdx := m.active
	return func() tea.Msg {
		var err error
		if replyTo != 0 {
			_, err = cli.SendReply(ctx, text, contentKeys, replyTo)
		} else {
			_, err = cli.Send(ctx, text, contentKeys)
		}
		if err != nil {
			var bp *client.BackpressureError
			if errors.As(err, &bp) {
				return consoleErrTab(consoleIdx, styleErr.Render(i18n.T("tui.err_pending_backpressure")))()
			}
			return sendErrMsg{err}
		}
		// Count-based rotation criterion (K messages per generation,
		// complementary to the rotation timer), checked after every
		// successful send, not on a separate periodic cycle: it's the
		// only moment MessagesSinceRotation can actually change.
		//
		// Unlike RotateSenderKey's other two call sites (init/
		// rekeyOnNextInit, cmdRotateSenderKeys), this one does NOT
		// reset tab.keySentTo, this closure already returns
		// sendErrMsg/replySentMsg/nil depending on the branch, a fourth
		// message type for a rare event (budget-based rotation, not
		// every send) would complicate things unnecessarily: the next
		// periodic round of cmdRotateSenderKeys (at most
		// senderKeyInterval later) will reset the map anyway, a
		// time-limited drift, not a permanent gap.
		if budget > 0 && cli.MessagesSinceRotation() >= uint64(budget) {
			if err := cli.RotateSenderKey(ctx); err != nil {
				client.Dbg("rotate_key: failed (message budget): %v", err)
			}
		}
		if replyTo != 0 {
			return replySentMsg{tabIdx: tabIdx}
		}
		return nil
	}
}

// ── console ───────────────────────────────────────────────────────────────────

// appendToConsole writes an event to the permanent console tab, both
// errors/disconnections and informational events (isError distinguishes
// the two categories on the same channel).
func (m *model) appendToConsole(text string, isError bool) {
	if m.consoleIdx < 0 || m.consoleIdx >= len(m.tabs) {
		return
	}
	line := chatLine{isSystem: true, text: text, timestamp: shared.Now()}
	m.tabs[m.consoleIdx].lines = append(m.tabs[m.consoleIdx].lines, line)
	if isError {
		m.tabs[m.consoleIdx].hasError = true
	}
	if m.active != m.consoleIdx {
		m.tabs[m.consoleIdx].unread++
	}
}

// appendToTor writes a Tor-related event to the "Tor" tab with a
// timestamp. If the Tor tab isn't present (no-Tor mode), falls back to Console.
func (m *model) appendToTor(text string) {
	if m.torTabIdx < 0 || m.torTabIdx >= len(m.tabs) {
		m.appendToConsole(text, false)
		return
	}
	line := chatLine{isSystem: true, text: text, timestamp: shared.Now()}
	m.tabs[m.torTabIdx].lines = append(m.tabs[m.torTabIdx].lines, line)
	if m.active != m.torTabIdx {
		m.tabs[m.torTabIdx].unread++
	}
}

// appendToDebug writes a debug message to the console tab, but only if debug mode is active.
func (m *model) appendToDebug(text string) {
	if !m.debugMode {
		return
	}
	if m.consoleIdx < 0 || m.consoleIdx >= len(m.tabs) {
		return
	}
	line := chatLine{isSystem: true, text: styleMeta.Render("[dbg] " + text), timestamp: shared.Now()}
	m.tabs[m.consoleIdx].lines = append(m.tabs[m.consoleIdx].lines, line)
	if m.active != m.consoleIdx {
		m.tabs[m.consoleIdx].unread++
	}
}

// filteredCommands returns the commands matching the current prefix in the textarea.
// pickerItems returns the list of entries filtered by the typed text.
// /cnt-info, /grp-contact-send: "self" on top + contacts alphabetically.
// /cnt-edit, /cnt-del, /sec-safety, /sec-verify:
// contacts alphabetically (sec-verify excludes already-verified ones).
// /grp-join: only group invites (knocks with GroupID).
// /grp-recall, /grp-del: saved groups.
// /grp-reinvite: current group members not connected.
func (m model) pickerItems() []string {
	filter := strings.ToLower(m.contactPickerFilter)

	// /grp-recall, /grp-del: use savedGroups
	if m.contactPickerCmd == client.CmdRecall || m.contactPickerCmd == client.CmdDelGroup {
		var out []string
		for _, g := range m.savedGroups {
			key := g.LocalName
			if key == "" {
				key = g.GroupID
			}
			if filter == "" ||
				strings.Contains(strings.ToLower(g.LocalName), filter) ||
				strings.Contains(strings.ToLower(g.GroupID), filter) {
				out = append(out, key)
			}
		}
		return out
	}

	// /grp-reinvite: current group members not connected
	if m.contactPickerCmd == client.CmdReinvite {
		tab := m.tabs[m.active]
		var out []string
		for _, mem := range tab.groupMembers {
			if mk := memberKey(mem); mk == m.myKey() || tab.isOnline(mk) {
				continue
			}
			if filter == "" || strings.Contains(strings.ToLower(m.memberPickerDisplay(tab, mem)), filter) {
				out = append(out, memberPickerKey(mem))
			}
		}
		return out
	}

	// /grp-ban: current room members, excluding ourselves
	if m.contactPickerCmd == client.CmdBan {
		tab := m.tabs[m.active]
		var out []string
		for _, mem := range tab.groupMembers {
			if memberKey(mem) == m.myKey() {
				continue
			}
			if filter == "" || strings.Contains(strings.ToLower(m.memberPickerDisplay(tab, mem)), filter) {
				out = append(out, memberPickerKey(mem))
			}
		}
		return out
	}

	// /grp-promote: ephemeral members of the current room (no
	// preexisting direct contact), excluding ourselves
	if m.contactPickerCmd == client.CmdPromote {
		tab := m.tabs[m.active]
		var out []string
		for _, mem := range tab.groupMembers {
			if memberKey(mem) == m.myKey() || m.resolveContactByPub(mem.IdentityPub) != nil {
				continue
			}
			if filter == "" || strings.Contains(strings.ToLower(m.memberPickerDisplay(tab, mem)), filter) {
				out = append(out, memberPickerKey(mem))
			}
		}
		return out
	}

	// /grp-join: uses pendingKnocks with GroupID
	if m.contactPickerCmd == client.CmdJoin {
		var out []string
		for _, k := range m.pendingKnocks {
			if k.GroupID == "" {
				continue
			}
			if filter == "" ||
				strings.Contains(strings.ToLower(k.GroupID), filter) ||
				strings.Contains(strings.ToLower(k.FromUsername), filter) {
				out = append(out, k.GroupID)
			}
		}
		return out
	}

	var out []string
	if m.contactPickerCmd == client.CmdInfo || m.contactPickerCmd == client.CmdSendContact {
		if filter == "" || strings.Contains("self", filter) {
			out = append(out, "self")
		}
	}
	type entry struct {
		display string
		key     string
	}
	entries := make([]entry, 0, len(m.contacts))
	for _, c := range m.contacts {
		// /sec-unverify: only verified contacts.
		if m.contactPickerCmd == client.CmdUnverifySafety && !c.Verified {
			continue
		}
		// /sec-rotate-rel-identity: a contact whose ContentKey (sibling) is
		// already rotating is excluded, starting would fail anyway (mutual
		// guard, keystore.StartRelIdentityRotationByPub).
		if dev, ok := c.SoleDevice(); ok {
			if m.contactPickerCmd == client.CmdRotateRelIdentity && dev.ContentKeyPending {
				continue
			}
			// /sec-rotate-rel-content: symmetric counterpart of the filter above.
			if m.contactPickerCmd == client.CmdRotateRelContent && dev.IdentityKeyPending {
				continue
			}
		}
		// /grp-add-member: a contact already a member of the current group is excluded.
		if m.contactPickerCmd == client.CmdAddMember {
			isMember := false
			for _, mb := range m.tabs[m.active].groupMembers {
				if bytes.Equal(mb.IdentityPub, c.IdentityPub) {
					isMember = true
					break
				}
			}
			if isMember {
				continue
			}
		}
		display := contactPickerDisplay(c)
		if filter == "" ||
			strings.Contains(strings.ToLower(display), filter) ||
			strings.Contains(strings.ToLower(c.Username), filter) {
			entries = append(entries, entry{display: display, key: contactPickerKey(c)})
		}
	}
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && strings.ToLower(entries[j].display) < strings.ToLower(entries[j-1].display); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	for _, e := range entries {
		out = append(out, e.key)
	}
	return out
}

// pickerItemDisplay returns the human-readable string for a picker entry given its key.
func (m model) pickerItemDisplay(key string) string {
	if key == "self" {
		return "self  (" + m.myUsername + ")"
	}
	// Saved groups
	if m.contactPickerCmd == client.CmdRecall || m.contactPickerCmd == client.CmdDelGroup {
		for _, g := range m.savedGroups {
			gKey := g.LocalName
			if gKey == "" {
				gKey = g.GroupID
			}
			if gKey == key {
				if g.LocalName != "" {
					return fmt.Sprintf("%s  [%s]  %d mem.", g.LocalName, g.GroupID, len(g.Members))
				}
				return fmt.Sprintf("%s  %d mem.", g.GroupID, len(g.Members))
			}
		}
		return key
	}
	// Group members (re-invite, ban, promote): the member's display name
	switch m.contactPickerCmd {
	case client.CmdReinvite, client.CmdBan, client.CmdPromote:
		tab := m.tabs[m.active]
		if pub, ok := decodePickerContactKey(key); ok {
			for _, mem := range tab.groupMembers {
				if bytes.Equal(mem.IdentityPub, pub) {
					if m.contactPickerCmd == client.CmdReinvite {
						return m.memberPickerDisplay(tab, mem) + "  (offline)"
					}
					return m.memberPickerDisplay(tab, mem)
				}
			}
		}
		return key
	}
	// Pending group invites
	if m.contactPickerCmd == client.CmdJoin {
		for _, k := range m.pendingKnocks {
			if k.GroupID == key {
				return key + "  (" + k.FromUsername + ", " + k.At.Format(shared.TimeLayout) + ")"
			}
		}
		return key
	}
	if pub, ok := decodePickerContactKey(key); ok {
		if c := m.resolveContactByPub(pub); c != nil {
			return contactPickerDisplay(*c)
		}
	}
	return key
}

// pickerItemDot returns the colored status dot for a picker entry.
func (m model) pickerItemDot(key string) string {
	if key == "self" {
		return styleMeta.Render("●")
	}
	switch m.contactPickerCmd {
	case client.CmdReinvite:
		return styleErr.Render("●")
	case client.CmdJoin:
		return styleOwnMsg.Render("●")
	case client.CmdRecall, client.CmdDelGroup:
		for _, g := range m.savedGroups {
			gKey := g.LocalName
			if gKey == "" {
				gKey = g.GroupID
			}
			if gKey == key {
				for _, tab := range m.tabs {
					if tab.groupID == g.GroupID && !tab.reconnecting {
						return styleOwnMsg.Render("●")
					}
				}
				return styleErr.Render("●")
			}
		}
		return styleErr.Render("●")
	default:
		lookupKey := key
		if pub, ok := decodePickerContactKey(key); ok {
			lookupKey = string(pub)
		}
		if st, ok := m.contactStates[lookupKey]; ok && st.online != nil {
			if *st.online {
				return styleOwnMsg.Render("●")
			}
			return styleErr.Render("●")
		}
		return styleMeta.Render("◌")
	}
}

// renderInterfaceLock draws the full-screen interface lock, no other
// content (tabs, messages, queued popups) is visible until it is
// unlocked, matching the gate in Update() that intercepts every key
// before any other modal.
func (m model) renderInterfaceLock() string {
	stars := strings.Repeat("*", len([]rune(m.lockUnlockBuf)))
	body := i18n.T("tui.interface_lock_prompt") + stars + "▌"
	if m.lockUnlockErr != "" {
		body += "\n\n" + styleErr.Render(m.lockUnlockErr)
	}
	popup := m.renderBoxPopup(body)
	w, h := m.lastTermW, m.lastTermH
	if w == 0 {
		w = 80
	}
	if h == 0 {
		h = 24
	}
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, popup)
}

// renderHelp draws the scrollable help overlay.
// renderBoxPopup applies the same style as the /help popup, border,
// width, and padding, to simple popups (backup, /cnt-info, /grp-info)
// for visual consistency across all popups.
func (m model) renderBoxPopup(content string) string {
	termW := m.lastTermW
	if termW == 0 {
		termW = 80
	}
	popupW := termW - 4
	return lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(popupW).
		Render(content)
}

// helpLayout returns the /help popup's width and its inner width and
// height (rows available for command entries).
func (m model) helpLayout() (popupW, innerW, pageRows int) {
	termW := m.lastTermW
	if termW == 0 {
		termW = 80
	}
	termH := m.lastTermH
	if termH == 0 {
		termH = 24
	}
	// margin: 2 columns per side, 1 row top and bottom
	popupW = termW - 4
	// usable width inside the horizontal padding (0,1) of each side.
	innerW = popupW - 2
	if innerW < 10 {
		innerW = 10
	}
	// inner height: termH - 2 (margins) - 2 (borders) - 1 (header) - 1 (footer)
	pageRows = termH - 6
	if pageRows < 4 {
		pageRows = 4
	}
	return popupW, innerW, pageRows
}

// helpDescIndent is the indent of every line of a command's description
// in the /help popup.
const helpDescIndent = 2

// helpDescBlock renders a command description for the /help popup: the
// indent applies to every line, so a wrapped description stays aligned.
func helpDescBlock(desc string, innerW int) string {
	return lipgloss.NewStyle().Width(innerW).PaddingLeft(helpDescIndent).Render(desc)
}

// helpPageEnd returns the index after the last command shown on a /help
// page starting at start: entries are added while the physical rows
// (command, wrapped description, blank separator) fit in the popup, and
// a page always holds at least one entry.
func (m model) helpPageEnd(start int) int {
	_, innerW, pageRows := m.helpLayout()
	cmds := client.CommandList()
	used := 0
	end := start
	for end < len(cmds) {
		rows := 1 + strings.Count(helpDescBlock(cmds[end].Desc, innerW), "\n") + 1
		if end > start {
			rows++ // blank separator row from the previous description
		}
		if used > 0 && used+rows > pageRows {
			break
		}
		used += rows
		end++
	}
	return end
}

// helpPrevPageStart returns where the /help page before the one starting
// at start begins: the earliest entry from which a page still reaches
// start.
func (m model) helpPrevPageStart(start int) int {
	p := start
	for p > 0 && m.helpPageEnd(p-1) >= start {
		p--
	}
	return p
}

func (m model) renderHelp() string {
	popupW, innerW, _ := m.helpLayout()
	cmds := client.CommandList()
	total := len(cmds)

	start := m.helpScroll
	if start >= total {
		start = total - 1
	}
	if start < 0 {
		start = 0
	}

	// Two lines per command, command (with its argument, if any) on top,
	// description on the following line, indented. The page ends where
	// helpPageEnd says, so the popup never
	// grows taller than the terminal.
	end := m.helpPageEnd(start)
	var sb strings.Builder
	for i := start; i < end; i++ {
		c := cmds[i]
		left := c.Cmd
		if c.Arg != "" {
			left += " " + c.Arg
		}
		if i > start {
			sb.WriteString("\n")
		}
		sb.WriteString(styleOwnMsg.Render(left) + "\n")
		sb.WriteString(helpDescBlock(c.Desc, innerW) + "\n")
	}

	nav := fmt.Sprintf("%d-%d / %d", start+1, end, total)
	if start > 0 {
		nav = "↑ " + nav
	}
	if end < total {
		nav += " ↓"
	}
	footer := styleMeta.Render("  " + nav + "   " + i18n.T("tui.help_footer_hint"))

	content := styleMeta.Render(i18n.T("tui.help_title")) + "\n" +
		sb.String() +
		footer

	return lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(popupW).
		Render(content)
}

// renderContactPicker draws the contact-picker popup over the screen.
func (m model) renderContactPicker() string {
	items := m.pickerItems()
	var title string
	switch m.contactPickerCmd {
	case client.CmdRecall:
		title = i18n.T("tui.picker_title_recall")
	case client.CmdDelGroup:
		title = i18n.T("tui.picker_title_del_group")
	case client.CmdJoin:
		title = i18n.T("tui.picker_title_join")
	case client.CmdSendContact:
		title = i18n.T("tui.picker_title_send_contact")
	case client.CmdReinvite:
		title = i18n.T("tui.picker_title_reinvite")
	case client.CmdAddMember:
		title = i18n.T("tui.picker_title_add_member")
	case client.CmdVerifySafety:
		title = i18n.T("tui.picker_title_unverified")
	case client.CmdUnverifySafety:
		title = i18n.T("tui.picker_title_verified")
	default:
		title = i18n.T("tui.picker_title_default", i18n.CommandName(m.contactPickerCmd))
	}
	const maxVisible = 10
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(title))
	sb.WriteString("\n")
	filterLine := fmt.Sprintf(i18n.T("tui.picker_filter_label"), m.contactPickerFilter)
	sb.WriteString(styleMeta.Render(filterLine))
	sb.WriteString("\n\n")
	if len(items) == 0 {
		sb.WriteString(styleMeta.Render(i18n.T("tui.picker_no_results")))
	} else {
		start := 0
		if m.contactPickerIdx >= maxVisible {
			start = m.contactPickerIdx - maxVisible + 1
		}
		end := start + maxVisible
		if end > len(items) {
			end = len(items)
		}
		for i := start; i < end; i++ {
			dot := m.pickerItemDot(items[i])
			label := m.pickerItemDisplay(items[i])
			if i == m.contactPickerIdx {
				sb.WriteString("  " + dot + " " + stylePaletteSel.Render(label))
			} else {
				sb.WriteString("  " + dot + " " + stylePaletteDesc.Render(label))
			}
			sb.WriteString("\n")
		}
		if len(items) > maxVisible {
			sb.WriteString(styleMeta.Render(fmt.Sprintf("  … %d/%d", m.contactPickerIdx+1, len(items))))
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.picker_nav_hint")))
	return m.renderBoxPopup(sb.String())
}

func (m model) filteredCommands() []client.PaletteItem {
	val := strings.ToLower(strings.TrimSpace(m.ta.Value()))
	if !strings.HasPrefix(val, "/") || strings.ContainsRune(val, ' ') {
		return nil
	}
	var out []client.PaletteItem
	for _, c := range client.CommandList() {
		if strings.HasPrefix(c.Cmd, val) {
			out = append(out, c)
		}
	}
	return out
}

// renderPalette draws the command popup above the textarea.
func (m model) renderPalette() string {
	items := m.filteredCommands()
	if len(items) == 0 {
		return ""
	}
	const maxVisible = 8
	start := 0
	if m.paletteIdx >= maxVisible {
		start = m.paletteIdx - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(items) {
		end = len(items)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		item := items[i]
		if i == m.paletteIdx {
			label := item.Cmd
			if item.Arg != "" {
				label += " " + item.Arg
			}
			label += "  " + item.Desc
			sb.WriteString(stylePaletteSel.Render(label))
		} else {
			sb.WriteString(stylePaletteCmd.Render(item.Cmd))
			if item.Arg != "" {
				sb.WriteString(" " + stylePaletteArg.Render(item.Arg))
			}
			sb.WriteString("  " + stylePaletteDesc.Render(item.Desc))
		}
		sb.WriteString("\n")
	}
	if len(items) > maxVisible {
		sb.WriteString(styleMeta.Render(fmt.Sprintf("  … %d/%d", m.paletteIdx+1, len(items))))
		sb.WriteString("\n")
	}
	return strings.TrimSuffix(sb.String(), "\n")
}

// nukeDeviceSyncTimeout bounds how long cmdNukeX's device-sync fan-out
// waits before giving up and proceeding to the actual nuke regardless,
// same ~20s order of magnitude as remoteNukeExecuteTimeout/podTimeout
// elsewhere in this codebase. An unreachable sibling must never delay
// the wipe itself, only the few seconds needed to best-effort notify it.
const nukeDeviceSyncTimeout = 20 * time.Second

// deviceSyncNukeDoneMsg signals that a device-sync fan-out armed by
// cmdNukeX OR by a duress secret recognized at the lock screen
// (armDuressWipe) has ended (every known sibling reached, or the
// timeout expired, always regardless): the case in Update() sets
// nukeOnExit or duressWipeOnExit accordingly (duress field) and exits
// the TUI, same scheme as remoteNukeExecutedMsg for executeRemoteNuke.
type deviceSyncNukeDoneMsg struct {
	duress bool
}

// cmdNukeX triggers immediate secure erasure without confirmation. Marks
// this device nuked in NukedDevicePubs and fans out a "device_sync" to
// every known sibling (best-effort, bounded by nukeDeviceSyncTimeout)
// before exiting the TUI, a sibling that learns of it starts resending
// the real rel_revoke to this identity's contacts via its own existing
// SiblingRevocations retry queue (see MarkOwnDeviceNuked's doc comment,
// TUIParams). The actual nuke happens after returning from the TUI (via
// RunTUI → main).
func (m *model) cmdNukeX() tea.Cmd {
	if m.markOwnDeviceNuked != nil {
		m.markOwnDeviceNuked()
	}
	return m.broadcastDeviceSyncNuke(false)
}

// cmdClearAll is confirmed by the caller (clearAllConfirmMode in
// Update()) before this ever runs, unlike cmdNukeX, a deliberate
// uninstall/cleanup action, not a panic trigger: no device-sync fan-out,
// no swap to duress. The actual wipe happens after exiting the TUI, in
// main() (see wipeConfigDir).
func (m *model) cmdClearAll() tea.Cmd {
	m.clearAllOnExit = true
	return tea.Quit
}

// armDuressWipe is cmdNukeX's counterpart for a duress secret recognized
// at the interface lock screen (LockCheckDuress or checkDuressPassword,
// see Update()'s tea.KeyMsg/m.interfaceLocked branch), same reason,
// same device-sync fan-out, only the exit flag it ultimately sets
// differs (duressWipeOnExit, not nukeOnExit).
func (m *model) armDuressWipe() tea.Cmd {
	if m.markOwnDeviceNuked != nil {
		m.markOwnDeviceNuked()
	}
	return m.broadcastDeviceSyncNuke(true)
}

// broadcastDeviceSyncNuke sends "device_sync" (carrying NukedDevicePubs,
// now including this device after MarkOwnDeviceNuked) to every entry in
// the known devices, in parallel with a single shared time cap, same
// fire-and-forget-within-a-deadline pattern as broadcastDangerEnd, never
// blocking beyond nukeDeviceSyncTimeout regardless of how many siblings
// are known or reachable. duress is threaded through unchanged into the
// returned message, so Update() knows which exit flag to set once this
// completes.
func (m *model) broadcastDeviceSyncNuke(duress bool) tea.Cmd {
	if m.dialTor == nil || m.buildDeviceSyncSyncKnock == nil || m.networkIdentityPubFor == nil {
		return func() tea.Msg { return deviceSyncNukeDoneMsg{duress: duress} }
	}
	knownDevices := append([]DeviceRecordInfo(nil), m.knownDevicesNow()...)
	dial := m.dialTor
	buildKnock := m.buildDeviceSyncSyncKnock
	newPubFor := m.networkIdentityPubFor
	computeAddr := m.computeAddress
	knockTO := m.knockHttpTimeout
	retryDelay := m.knockRetryDelay

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), nukeDeviceSyncTimeout)
		defer cancel()
		var wg sync.WaitGroup
		for _, d := range knownDevices {
			wg.Add(1)
			go func(d DeviceRecordInfo) {
				defer wg.Done()
				pub := newPubFor(d.DeviceID)
				addr := computeAddr(pub)
				if addr == "" {
					return
				}
				payload, err := buildKnock(false, d.DeviceID)
				if err != nil {
					return
				}
				httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: knockTO}
				_, _ = postWithRetry(ctx, httpCli, "http://"+addr+"/knock", payload, retryDelay)
			}(d)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
		}
		return deviceSyncNukeDoneMsg{duress: duress}
	}
}

// cmdDebug enables or disables debug mode in the console tab.
// Syntax: /debug on | /debug off | /debug (current status)
// Works only when the console tab is active; returns an error in other tabs.
func (m *model) cmdDebug(arg string) tea.Cmd {
	switch arg {
	case "on":
		m.debugMode = true
		client.SetDebug(m.debugLogCh)
		return localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.debug_on")))
	case "off":
		m.debugMode = false
		client.SetDebug(nil)
		return localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.debug_off")))
	case "":
		status := i18n.T("tui.status_off")
		if m.debugMode {
			status = i18n.T("tui.status_on")
		}
		return localTab(m.consoleIdx, styleMeta.Render(fmt.Sprintf(i18n.T("tui.debug_status"), status)))
	default:
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_debug")))
	}
}

// cmdCompact enables or disables compaction of repeated lines in the
// console tab, same structure as cmdDebug above (syntax, restricted to
// the console tab only), but acts only on the VIEW (refreshViewport),
// never on tab.lines: no data is ever discarded, only hidden until
// disabled again.
// Syntax: /compact on | /compact off | /compact (current status)
func (m *model) cmdCompact(arg string) tea.Cmd {
	tab := m.tabs[m.active]
	if !tab.isConsole {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_compact_console_only")))
	}
	switch arg {
	case "on":
		m.compactMode = true
		m.refreshViewport()
		return localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.compact_on")))
	case "off":
		m.compactMode = false
		m.refreshViewport()
		return localTab(m.consoleIdx, styleMeta.Render(i18n.T("tui.compact_off")))
	case "":
		status := i18n.T("tui.status_off")
		if m.compactMode {
			status = i18n.T("tui.status_on")
		}
		return localTab(m.consoleIdx, styleMeta.Render(fmt.Sprintf(i18n.T("tui.compact_status"), status)))
	default:
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_compact")))
	}
}

// cmdConsoleExport writes the ENTIRE Console tab's content (every line
// this session has ever appended, never pruned, see tab.lines, not
// just what currently fits in the viewport) to a plain-text file, ANSI
// styling stripped, using the exact same destination-picking flow
// already used for a received file (filesystem browser for the
// directory, then an editable proposed name), see saveRenameMode/
// saveDirMode. Honors /compact's collapsing of repeated lines if
// currently on, same as what's shown on screen (m.refreshViewport).
func (m *model) cmdConsoleExport() tea.Cmd {
	consoleTab := m.tabs[m.consoleIdx]
	lines := consoleTab.lines
	if m.compactMode {
		lines = compactChatLines(lines)
	}
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(ansi.Strip(l.render(m.myKey(), "")))
		sb.WriteString("\n")
	}

	dir := startDirForFileBrowser()
	all, _ := listDir(dir) // unlikely error, empty list if it happens anyway
	m.saveFileDir = dir
	m.saveFileEntries = filterDirsOnly(all)
	m.saveFileIdx = 0
	m.saveRenameMode = true
	m.saveFileTabIdx = m.consoleIdx
	m.savePendingData = []byte(sb.String())
	m.savePendingName = fmt.Sprintf("console-%s.txt", m.myUsername)
	m.saveTitle = i18n.T("tui.console_export_rename_title")
	return nil
}

// cmdPQCSign enables/disables the optional ML-DSA-65 signature on messages
// sent in the active room, hybrid PQC network identity. Only on an actual
// room (two-member or group, same restriction as cmdReconnect): the toggle
// lives on that room's *Client (tab.cli.SetPQCSign), not a global setting,
// different rooms can have different choices. Confirmation is shown inline
// in the room itself (not an error, a local conversation status), not in
// Console, consistent with the other non-error status notifications
// already shown there.
// Syntax: /sec-pqc-sign on | /sec-pqc-sign off | /sec-pqc-sign (current status)
func (m *model) cmdPQCSign(arg string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.isStandardTab() {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_pqc_sign_room_only")))
	}
	if tab.cli == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_no_client_for_room")))
	}
	switch arg {
	case "on", "off":
		on := arg == "on"
		tab.cli.SetPQCSign(on)
		key := "tui.pqc_sign_off"
		if on {
			key = "tui.pqc_sign_on"
		}
		return tea.Batch(localTab(tabIdx, styleMeta.Render(i18n.T(key))), m.sendPQCToggleAnnounce(tab, on))
	case "":
		status := i18n.T("tui.status_off")
		if tab.cli.PQCSign() {
			status = i18n.T("tui.status_on")
		}
		return localTab(tabIdx, styleMeta.Render(fmt.Sprintf(i18n.T("tui.pqc_sign_status"), status)))
	default:
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_pqc_sign")))
	}
}

// sendPQCToggleAnnounce notifies all room members of the PQC status
// change (/sec-pqc-sign), see pqcToggleAnnouncePrefix. Best-effort,
// fire-and-forget: the local toggle (tab.cli.SetPQCSign, already applied
// by the caller) does not depend in any way on the outcome of this send.
func (m *model) sendPQCToggleAnnounce(tab *roomTab, on bool) tea.Cmd {
	cli, ctx := tab.cli, tab.ctx
	contentKeys := m.buildContentSigningKeys(tab)
	return func() tea.Msg {
		if raw, err := json.Marshal(pqcToggleAnnouncePayload{On: on}); err == nil {
			_, _ = cli.Send(ctx, pqcToggleAnnouncePrefix+string(raw), contentKeys)
		}
		return nil
	}
}

// cmdBackup starts password verification before showing the 24 BIP-39
// words, the words are recomputed only after verification (case 4,
// pwdMode), never kept ready in advance.
func (m *model) cmdBackup() tea.Cmd {
	if m.getBackupMnemonic == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_backup_unavailable")))
	}
	m.pwdMode = 4
	m.pwdBuf = ""
	return nil
}

// cmdPasswd starts the masked password-change flow (3 steps: current → new → confirm).
func (m *model) cmdPasswd() tea.Cmd {
	if m.changePassword == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.pwd_change_unavailable")))
	}
	m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 1, "", "", ""
	return nil
}

// cmdDuress starts the masked flow to change the decoy identity's own
// identity password (2 steps: new password → confirm, no verification
// of the current one, it is an independent secret, not a replacement).
// An empty password is rejected: the decoy identity exists structurally
// and can never be removed, see the pwdMode==5 case in the main Update.
func (m *model) cmdDuress() tea.Cmd {
	if m.setDuress == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.duress_unavailable")))
	}
	m.pwdMode, m.pwdBuf, m.pwdOld, m.pwdFirst = 5, "", "", ""
	return nil
}

// isDigitsOnly reports whether s contains only ASCII digits 0-9 (the
// interface-lock PIN is never alphanumeric).
func isDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cmdLock immediately locks the interface, Tor/I2P, connections, and open
// rooms remain unchanged. Always available: the identity password (kept in
// RAM for the session, m.keystorePassword) always unlocks the lock again,
// whether or not a PIN has also been configured via /sec-lock-pin.
func (m *model) cmdLock() tea.Cmd {
	m.interfaceLocked = true
	m.lockedSinceAt = time.Now()
	m.lockUnlockBuf, m.lockUnlockErr = "", ""
	return nil
}

// cmdLockPIN starts the masked flow to set/replace the numeric
// interface-lock PIN, 3 steps: new PIN → confirm → duress character →
// character position (pwdMode 7→8→9→10, see the corresponding case in the
// main Update). The PIN is an additional, optional unlock path, the
// identity password always unlocks the lock regardless of whether a PIN is
// configured (see cmdLock).
func (m *model) cmdLockPIN() tea.Cmd {
	if m.setLockSecret == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_unavailable")))
	}
	m.lockSetupSecret, m.lockSetupMarker = "", ""
	m.pwdMode, m.pwdBuf = 7, ""
	return nil
}

// cmdLockTimeout sets the inactivity threshold for the automatic lock,
// free-form operator input (e.g. "30s", "1m", "2m"), not a list of preset
// options; "0" or "0s" disables the automatic lock (the manual /sec-lock
// command always remains available regardless).
func (m *model) cmdLockTimeout(arg string) tea.Cmd {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_usage_lock_timeout"), "/sec-lock-timeout")))
	}
	if arg == "0" {
		arg = "0s"
	}
	d, err := time.ParseDuration(arg)
	if err != nil || d < 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_timeout_invalid")))
	}
	m.interfaceLockTimeout = d
	if m.saveInterfaceLockTimeout != nil {
		if err := m.saveInterfaceLockTimeout(d); err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error"), err.Error())))
		}
	}
	if d == 0 {
		return localTab(m.consoleIdx, i18n.T("tui.lock_timeout_disabled"))
	}
	return localTab(m.consoleIdx, fmt.Sprintf(i18n.T("tui.lock_timeout_set"), d))
}

// cmdNukeTimeout sets the "time" nuke trigger threshold, how long the
// interface may stay LOCKED before an automatic nukex-equivalent
// erasure fires. Same free-form input/disable convention as
// cmdLockTimeout above.
func (m *model) cmdNukeTimeout(arg string) tea.Cmd {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_usage_lock_timeout"), "/sec-nuke-timeout")))
	}
	if arg == "0" {
		arg = "0s"
	}
	d, err := time.ParseDuration(arg)
	if err != nil || d < 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_lock_timeout_invalid")))
	}
	m.timeNukeTimeout = d
	if m.saveTimeNukeTimeout != nil {
		if err := m.saveTimeNukeTimeout(d); err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error"), err.Error())))
		}
	}
	if d == 0 {
		return localTab(m.consoleIdx, i18n.T("tui.nuke_timeout_disabled"))
	}
	return localTab(m.consoleIdx, fmt.Sprintf(i18n.T("tui.nuke_timeout_set"), d))
}

// cmdQuit sets the quit flag so the main loop exits the TUI.
func (m *model) cmdQuit() tea.Cmd {
	m.quitMode = true
	return nil
}

func (m *model) cmdExit() tea.Cmd {
	i := m.active
	tab := m.tabs[i]
	if tab.isContacts || tab.isGroups || tab.isTor || tab.isConsole || tab.isFiles {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_tab_cannot_close"), tab.name)))
	}
	m.closeTabAt(i)
	return nil
}

// closeTabAt closes the tab at index i, reusable by groupNoJoinConfirmMode,
// where the tab to close (the host gave up on a group that got no response)
// is not necessarily the one currently active on screen.
func (m *model) closeTabAt(i int) {
	if i < 0 || i >= len(m.tabs) {
		return
	}
	tab := m.tabs[i]
	if tab.cli != nil {
		tab.cli.GracefulClose()
	}
	if tab.cancel != nil {
		tab.cancel()
	}

	// Incoming transfers still active on THIS tab: without this,
	// dropIncomingTransfer would never be called for them when the tab
	// closes, chunkCh would stay open forever, the dedicated writer
	// goroutine (startIncomingChunkWriter) blocked indefinitely waiting for
	// a chunk that will never arrive (goroutine leak), and the already-open
	// temporary file never closed or cleaned up. Collected before iterating
	// so as not to mutate m.incomingTransfers during its own range.
	var deadTransfers []string
	for id, it := range m.incomingTransfers {
		if it.tabIdx == i {
			deadTransfers = append(deadTransfers, id)
		}
	}
	for _, id := range deadTransfers {
		m.dropIncomingTransfer(id)
	}

	// remove the tab from the slice
	m.tabs = append(m.tabs[:i], m.tabs[i+1:]...)

	// adjust indices that point into positions in the slice
	if m.consoleIdx > i {
		m.consoleIdx--
	} else if m.consoleIdx == i {
		m.consoleIdx = -1
	}
	if m.torTabIdx > i {
		m.torTabIdx--
	}
	if m.pingTabIdx > i {
		m.pingTabIdx--
	}
	if m.active > i {
		m.active--
	} else if m.active == i {
		m.active = m.defaultTabIdx()
	}
	m.refreshViewport()
}

// cmdReconnect reconnects the WebSocket transport AND rotates the
// senderKey (new chain, new generation of ephemeral DH keys) as soon as
// the next "init" frame confirms who is present in the room, see
// rekeyOnNextInit. Transport and message encryption are reset together,
// so the user never has to tell which layer is blocked. /grp-reinvite is
// a different action (re-inviting a member to the room, host only).
func (m *model) cmdReconnect() tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	// Only an actual room (two-member or group), never a standard tab
	// (Console/Contacts/Groups/Network/Files).
	if tab.isStandardTab() {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_reconnect_room_only")))
	}
	if tab.cli == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_no_client_for_room")))
	}
	tab.reconnecting = false // cancel any automatic reconnect in progress
	if tab.cancel != nil {
		tab.cancel()
	}
	newCtx, newCancel := context.WithCancel(context.Background())
	tab.ctx = newCtx
	tab.cancel = newCancel
	tab.rekeyOnNextInit = true
	// New generation NOW, not only on success (see roomErrMsg.gen): a
	// ping/read still in flight from the connection just replaced must be
	// recognizable as stale when it arrives late, instead of being mistaken
	// for a fresh failure of THIS attempt.
	tab.pingGen++
	gen := tab.pingGen
	m.appendToConsole(styleMeta.Render(fmt.Sprintf(i18n.T("tui.reconnecting_room"), tab.name)), false)
	m.refreshViewport()

	cli := tab.cli
	return func() tea.Msg {
		if err := cli.Connect(newCtx); err != nil {
			return roomErrMsg{idx: tabIdx, err: fmt.Errorf(i18n.T("tui.err_reconnection"), err), gen: gen}
		}
		return roomConnectedMsg{idx: tabIdx}
	}
}

// reconnectTab performs the silent automatic reconnect for a disconnected
// Tor tab. Called on the first Tor disconnection; if it fails it returns
// roomErrMsg with tab.reconnecting already true so the second handler
// shows the final error without looping.
func (m *model) reconnectTab(idx int) tea.Cmd {
	tab := m.tabs[idx]
	if tab.cancel != nil {
		tab.cancel()
	}
	newCtx, newCancel := context.WithCancel(context.Background())
	tab.ctx = newCtx
	tab.cancel = newCancel
	// Same reason as the bump in cmdReconnect: new generation at the START
	// of the attempt, not only on success, a ping or read started on the
	// connection just replaced (e.g. a pingWatchdog probe triggered by this
	// same error, or a second error from the read loop blocked on the old
	// ctx) must be recognizable as stale.
	tab.pingGen++
	gen := tab.pingGen
	cli := tab.cli
	tabName := tab.name
	// Self-heal: cli.hostKey stays frozen to how it was when this *Client
	// was created, if in the meantime the roomErrMsg case corrected
	// PeerRelIdentityPub in the address book (mismatched relationship key,
	// see ErrInvalidServerSig above), a reconnect reusing that frozen copy
	// would keep failing forever with the same invalid signature. The
	// current copy is re-read here from m.contacts, right before the
	// attempt.
	if tab.hostKey != "" && tab.hostKey != m.myKey() {
		if hc := m.resolveContactByPub(memberKeyPub(tab.hostKey)); hc != nil {
			if dev, ok := hc.SoleDevice(); ok {
				cli.SetHostKey(shared.RelPeerKey{Pub: ed25519.PublicKey(dev.PeerRelIdentityPub), MLDSAPub: dev.PeerRelIdentityMLDSAPub})
			}
		}
	}
	return func() tea.Msg {
		if err := cli.ConnectWithRetry(newCtx, 5, nil); err != nil {
			return roomErrMsg{idx: idx, err: fmt.Errorf(i18n.T("tui.err_auto_reconnect_failed"), tabName, err), gen: gen}
		}
		return roomConnectedMsg{idx: idx}
	}
}

// roomSlotBusyRetryInterval is the FIXED interval (not exponential, unlike
// ConnectWithRetry) between one attempt and the next when
// client.ErrAlreadyConnectedElsewhere prevents joining a room, the only
// event that resolves this failure is the OTHER device disconnecting,
// never a network issue: a growing backoff would not help, a fixed and
// moderate interval avoids hammering the server without needlessly
// delaying reentry.
const roomSlotBusyRetryInterval = 20 * time.Second

// waitAndRetrySlot retries ONE direct connection (never ConnectWithRetry,
// which would give up after a fixed number of attempts) after
// roomSlotBusyRetryInterval, used only for
// client.ErrAlreadyConnectedElsewhere: retries indefinitely until it
// succeeds or the tab is closed (tab.ctx cancelled), never a final error
// as happens for every other failure (see the roomErrMsg case). If an
// attempt fails for a DIFFERENT reason (network, no longer "busy"), it
// falls back to the generic roomErrMsg, ordinary logic (self-heal,
// exponential reconnect, final error) resumes from there.
func (m *model) waitAndRetrySlot(idx int) tea.Cmd {
	tab := m.tabs[idx]
	cli := tab.cli
	ctx := tab.ctx
	gen := tab.pingGen
	return tea.Tick(roomSlotBusyRetryInterval, func(time.Time) tea.Msg {
		if ctx.Err() != nil {
			return nil
		}
		attCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := cli.Connect(attCtx)
		cancel()
		if err != nil {
			return roomErrMsg{idx: idx, err: err, gen: gen}
		}
		return roomConnectedMsg{idx: idx}
	})
}

// cmdHealth queries the local server and shows its status in the current tab.
func (m model) cmdHealth() tea.Cmd {
	host := m.localHost
	port := m.localPort
	locIdx := m.defaultTabIdx()
	return func() tea.Msg {
		httpCli := &http.Client{Timeout: 5 * time.Second}
		resp, err := httpCli.Get(fmt.Sprintf("http://%s:%d/health", host, port))
		if err != nil {
			return localDisplayMsg{tabIdx: locIdx, text: styleErr.Render("health: " + err.Error()), isError: true}
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return localDisplayMsg{tabIdx: locIdx, text: styleMeta.Render("health: " + strings.TrimSpace(string(body)))}
	}
}

// ── message readers ───────────────────────────────────────────────────────────

func (m model) waitForRoom(idx int) tea.Cmd {
	tab := m.tabs[idx]
	if tab.cli == nil {
		return nil // tab without a connection (e.g. contacts tab)
	}
	// gen stamped NOW (the current generation at the moment THIS read
	// starts), not re-read later, see the comment on roomErrMsg.gen: if a
	// reconnect meanwhile replaces tab.ctx/tab.pingGen, a late error from
	// this now-superseded read must remain recognizable as such.
	gen := tab.pingGen
	return func() tea.Msg {
		msg, err := tab.cli.ReadMsg(tab.ctx)
		if err != nil {
			return roomErrMsg{idx: idx, err: err, gen: gen}
		}
		typ, _ := msg["type"].(string)
		toUserID, _ := msg["to_user_id"].(string)
		transferID, _ := msg["transfer_id"].(string)
		client.Dbg("ws_trace: received tab=%d type=%q to=%s… transfer=%s", idx, typ, client.ShortUID(toUserID), transferID)
		return roomServerMsg{idx: idx, raw: msg}
	}
}

func (m model) waitForKnock() tea.Cmd {
	ch := m.knockCh
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		k, ok := <-ch
		if !ok {
			return nil
		}
		return knockMsg(k)
	}
}

func (m model) waitForSysLock() tea.Cmd {
	ch := m.sysLockCh
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		_, ok := <-ch
		if !ok {
			return nil
		}
		return sysLockMsg{}
	}
}

func (m model) waitForTorLog() tea.Cmd {
	ch := m.torLogCh
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return nil
		}
		return torLogMsg{line: line}
	}
}

func (m model) waitForDebugLog() tea.Cmd {
	ch := m.debugLogCh
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		line := <-ch
		return debugLogMsg{line: line}
	}
}

// ── viewport ──────────────────────────────────────────────────────────────────

// calcVpH returns the viewport height in rows, accounting for the extra
// user bar in group tabs (non-empty groupID with at least one connected
// user).
func (m *model) calcVpH() int {
	const headerH = 2 // tab bar + margin
	footerH := m.ta.Height() + 2
	extra := 0
	if m.active < len(m.tabs) {
		tab := m.tabs[m.active]
		if tab.isTor {
			extra = 2 // WS+Tor status row + separator
		} else if tab.groupID != "" && len(tab.groupMembers) > 0 {
			extra = m.groupBarLines(tab, m.vp.Width) + 1 // user rows (may wrap) + separator
		}
	}
	vpH := m.lastTermH - headerH - footerH - extra
	if vpH < 1 {
		vpH = 1
	}
	return vpH
}

// contentRelEstablished reports whether a ContentKey relationship
// established in BOTH directions already exists toward username in the
// given tab, persistent (Contact.RelContentPriv/PeerRelContentPub, a real
// contact) or ephemeral (ephemeralRel.established, an "introduced"
// stranger with a completed peer-to-peer bootstrap). The guarantee is not
// a comparison of two declared values but verifiable mutual possession of
// the keys themselves (see contentPeerKeysFor/buildContentSigningKeys).
func (m *model) contentRelEstablished(tab *roomTab, username string) bool {
	if _, _, _, _, known := m.contentPeerKeysFor(tab, username); !known {
		return false
	}
	_, ok := m.myContentPrivFor(tab, username)
	return ok
}

// cmdSendContact shares a contact's card, or one's own, via
// "self"/"me"/one's own username, the picker's first entry, with one or
// more members of the current room. Reuses the entire /grp-file-send
// pipeline (same multi-select recipient picker, same per-recipient
// encryption with the ContentKey-per-relationship, same socket-level
// routing) instead of the Double Ratchet: a single transport mechanism
// instead of two, and no to_user_id in the clear (existing routing
// delivers without the relay needing to know anything else).
func (m *model) cmdSendContact(arg string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.isConsole || tab.isContacts || tab.isGroups || tab.isTor || tab.isFiles {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_send_file_wrong_tab")))
	}
	if arg == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_usage_send_contact")))
	}
	argLower := strings.ToLower(arg)
	// "self"/"me"/one's own username: shares one's OWN card (the same
	// identity shown by /cnt-info in these cases, cmdInfo above), not an
	// m.contacts entry, one's own identity is never a ContactInfo in the
	// address book. sendContactHintUsername carries "self" as a sentinel
	// through to finishSendContact, which recognizes it before
	// searching m.contacts.
	username := ""
	var contactPub []byte
	if argLower == "self" || argLower == "me" || argLower == "io" || argLower == strings.ToLower(m.myUsername) {
		username = "self"
	} else {
		found, n := m.resolveContactArg(arg)
		if n == 0 {
			// Fallback for case-insensitive DisplayName/Username matching
			// (resolveContactArg is case-sensitive), only for a manually
			// typed argument, never for a picker key; accepted only when
			// exactly one contact matches.
			for i := range m.contacts {
				c := &m.contacts[i]
				if strings.ToLower(c.DisplayName()) == argLower || strings.ToLower(c.Username) == argLower {
					found = c
					n++
				}
			}
		}
		if n != 1 {
			return m.openPicker(client.CmdSendContact, arg)
		}
		username = found.Username
		contactPub = found.IdentityPub
	}
	candidates := m.eligibleFileRecipients(tabIdx)
	if len(candidates) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(m.noContentRecipientsMsg(tabIdx)))
	}

	// The out-of-band contact hint is asked here, not read from a saved
	// field: it must be written fresh on every send, otherwise it would end
	// up persisted somewhere (violating the constraint that nothing on the
	// keystore may trace back to a real person). See finishSendContact
	// for the continuation after confirmation.
	m.sendContactHintMode = true
	m.sendContactHintBuf = ""
	m.sendContactHintTabIdx = tabIdx
	m.sendContactHintUsername = username
	m.sendContactHintContactPub = contactPub
	return nil
}

// finishSendContact completes /grp-contact-send after the host has typed
// the mandatory out-of-band contact hint (see sendContactHintMode).
// Re-resolves the contact and recipients instead of reusing those captured
// in cmdSendContact: an arbitrary amount of time may pass between
// opening the prompt and pressing Enter, during which the room's (or
// address book's) state may have changed.
func (m *model) finishSendContact(hint string) tea.Cmd {
	tabIdx := m.sendContactHintTabIdx
	username := m.sendContactHintUsername
	contactPub := m.sendContactHintContactPub
	if tabIdx >= len(m.tabs) {
		return nil
	}
	var card contactCard
	if username == "self" {
		// One's own card: the same fields (identity pub + PQC companions)
		// shown by /cnt-info in this same case, no ContactInfo involved,
		// never an address-book entry for oneself. No MLDSAPub: the model
		// does not keep a durable transport ML-DSA public key.
		card = contactCard{
			Username:    m.myUsername,
			IdentityPub: base64.StdEncoding.EncodeToString(m.myIdentityPub),
			MLKEMPub:    m.myMLKEMPub,
			OffbandHint: hint,
		}
	} else {
		found := m.resolveContactByPub(contactPub)
		if found == nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_contact_not_found"), username)))
		}
		card = contactCard{
			Username:    found.Username,
			LocalName:   found.LocalName,
			IdentityPub: base64.StdEncoding.EncodeToString(found.IdentityPub),
			MLKEMPub:    found.MLKEMPub,
			MLDSAPub:    found.MLDSAPub,
			OffbandHint: hint,
		}
	}
	candidates := m.eligibleFileRecipients(tabIdx)
	if len(candidates) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(m.noContentRecipientsMsg(tabIdx)))
	}

	cardJSON, _ := json.Marshal(card)

	m.sendFileTabIdx = tabIdx
	m.sendFilePath = ""
	m.sendFileData = []byte(contactCardPrefix + string(cardJSON))
	m.sendFileDisplayName = card.Username + ".contact"
	m.sendFileSize = int64(len(m.sendFileData))

	if len(candidates) == 1 {
		m.sendFileRecipients = candidates
		m.sendFilePresetIdx = 0
		m.sendFileCompressOn = m.strongCompressionEnabled
		m.sendFilePresetMode = true
		return nil
	}
	m.sendFileCandidates = candidates
	m.sendFileSelected = make(map[string]bool, len(candidates))
	for _, u := range candidates {
		m.sendFileSelected[u] = true
	}
	m.sendFileRecipientsIdx = 0
	m.sendFileRecipientsMode = true
	return nil
}

// fileTransferProgress is the only shared state between the chunk
// send/receive goroutine (which runs outside the main Update loop) and
// the "File" tab rendering, mutex-protected because it is written and
// read by different goroutines, unlike the rest of the model which lives
// only on the main bubbletea loop.
type fileTransferProgress struct {
	mu        sync.Mutex
	label     string // file name
	direction string // "↑" send, "↓" receive
	peer      string // recipients (send, comma-joined) or sender (receive)
	total     int64
	done      int64
	failed    bool
	complete  bool
	// chunksDone/chunksPending/chunksTotal, chunk-level detail, shown in
	// the File tab next to the byte percentage (renderFileProgressView).
	// Send side (↑): chunksDone is how many chunks THIS row (a sendGroup)
	// has already sent, chunksPending always stays 0 (nothing to reorder
	// when sending). Receive side (↓): chunksDone is how many chunks have
	// arrived in total (written + buffered awaiting reorder), chunksPending
	// is the subset still buffered, non-contiguous (see
	// startIncomingChunkWriter, NextIndex/Buffered). chunksTotal is always
	// the number declared by the offer (chunk_count), the same for every
	// row of the same file.
	chunksDone    int64
	chunksPending int64
	chunksTotal   int64
}

func (p *fileTransferProgress) addDone(n int64) {
	p.mu.Lock()
	p.done += n
	p.mu.Unlock()
}

func (p *fileTransferProgress) setComplete(failed bool) {
	p.mu.Lock()
	p.complete = true
	p.failed = failed
	p.mu.Unlock()
}

// setChunks updates the chunk-level detail, see the comment on the
// chunksDone/chunksPending/chunksTotal fields above.
func (p *fileTransferProgress) setChunks(done, pending, total int64) {
	p.mu.Lock()
	p.chunksDone, p.chunksPending, p.chunksTotal = done, pending, total
	p.mu.Unlock()
}

func (p *fileTransferProgress) snapshot() (label, direction, peer string, total, done int64, failed, complete bool, chunksDone, chunksPending, chunksTotal int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.label, p.direction, p.peer, p.total, p.done, p.failed, p.complete, p.chunksDone, p.chunksPending, p.chunksTotal
}

// setPeer updates the recipient list shown for this row, used on the
// send side when a group's composition (sendGroup, see
// startSendingChunks) changes: a new member joins, or one leaves.
func (p *fileTransferProgress) setPeer(peer string) {
	p.mu.Lock()
	p.peer = peer
	p.mu.Unlock()
}

// fileProgressRegistry keeps the insertion-ordered list of transfers shown
// in the "File" tab. Entries remain visible even after completion (marked
// complete/failed) until a new one starts, no automatic cleanup.
type fileProgressRegistry struct {
	mu      sync.Mutex
	order   []string
	entries map[string]*fileTransferProgress
}

func newFileProgressRegistry() *fileProgressRegistry {
	return &fileProgressRegistry{entries: make(map[string]*fileTransferProgress)}
}

func (r *fileProgressRegistry) add(id string, p *fileTransferProgress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[id]; !exists {
		r.order = append(r.order, id)
	}
	r.entries[id] = p
}

func (r *fileProgressRegistry) get(id string) *fileTransferProgress {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entries[id]
}

// remove drops a row from the list, used on the send side when a
// dedicated group (a sendGroup with its own row, see startSendingChunks)
// merges back into another: the separate row disappears instead of
// lingering forever as a ghost "100%".
func (r *fileProgressRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, id)
	for i, existing := range r.order {
		if existing == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func (r *fileProgressRegistry) snapshot() []*fileTransferProgress {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*fileTransferProgress, 0, len(r.order))
	for _, id := range r.order {
		if p, ok := r.entries[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

func (r *fileProgressRegistry) hasActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.order {
		p, ok := r.entries[id]
		if !ok {
			continue
		}
		p.mu.Lock()
		active := !p.complete
		p.mu.Unlock()
		if active {
			return true
		}
	}
	return false
}

// outgoingFileTransfer holds the sender-side state of an in-progress
// /grp-file-send (or /grp-contact-send, same pipeline). Sending starts
// toward those who have already accepted at the first of two moments:
// when fileOfferBatchWindow expires after the offer is sent (case
// fileOfferBatchWindowMsg), or immediately if ALL selected recipients have
// already responded even before that (the "all responded" branch in case
// "file_accept"/handleRoomMsg), sending never waits until
// fileTransferOfferTimeout to start; that remains only the fallback
// deadline for "nobody ever responded". Anyone who accepts after sending
// has already started is readmitted into the ongoing window through the
// same resumeCh mechanism already used for reconnections (fromByte: 0,
// everything already sent to the others so far is resent to them), see
// the dedicated ("readmitted") branch in case "file_accept"/handleRoomMsg.
type outgoingFileTransfer struct {
	transferID string
	tabIdx     int
	fileName   string
	ciphertext []byte
	// envelopes, meta_blob envelope per recipient (user_id), already
	// prepared at encryption time but sent (SendFileOffer) ONLY when that
	// recipient's file_announce_ack arrives, case "file_announce_ack", Update().
	envelopes map[string]shared.FileOfferEnvelope
	preset    string          // "slow" or "warp"
	pending   map[string]bool // member key → true until it responds (announce+offer, a single budget)
	accepted  []string        // user_id of those who accepted, arrival order
	progress  *fileTransferProgress
	ackCh     chan fileChunkAckEvent // seq confirmed by recipients, read by the sending goroutine
	resumeCh  chan fileResumeEvent   // resume announcements, read by the sending goroutine (see startSendingChunks)
	// pendingDone/pendingClosed, signal to the sending goroutine that ALL
	// invitees have now responded (accepted or rejected): startSendingChunks'
	// post-send grace window no longer has any reason to wait until
	// fileTransferOfferTimeout, nobody else can accept late anymore. A
	// channel, not a direct read of pending, because pending is mutated only
	// by the Update() goroutine while startSendingChunks runs on a separate
	// goroutine, reading it from there would be a race.
	// pendingClosed avoids a double close (mutated only by Update(), never by
	// the sending goroutine, which only listens on the channel).
	pendingDone   chan struct{}
	pendingClosed bool
}

// signalAllResponded closes ft.pendingDone the FIRST time ft.pending
// becomes empty, must be called from Update() (the only goroutine that
// touches ft.pending), right after every delete(ft.pending, ...), for
// both an acceptance and a rejection.
func (ft *outgoingFileTransfer) signalAllResponded() {
	if len(ft.pending) == 0 && !ft.pendingClosed {
		ft.pendingClosed = true
		close(ft.pendingDone)
	}
}

// fileResumeEvent routes a received file_resume (a recipient announces
// which byte it resumes from, after its own or the sender's reconnection)
// to the sending goroutine that manages that transfer's sliding window.
type fileResumeEvent struct {
	memberKey string // to remove it from the stalled list, stable unlike user_id
	toUserID  string // CURRENT user_id to address recovery chunks to
	fromByte  int64  // how many bytes the recipient already has (offset to resume from)
	// isNewAccept, true ONLY when the event comes from the "readmitted"
	// fallback (the "file_accept" case above, for a genuine first
	// acceptance arriving after sending has already started toward
	// others), never from an actual file_resume on the wire. The sending
	// goroutine uses it to decide whether to unconditionally admit the
	// sender as a new recipient (isNewAccept=true, fromByte always 0: it
	// has nothing yet) or to honor it only for an already-known recipient
	// (isNewAccept=false), a file_resume from someone who has NEVER
	// accepted before is always ignored, otherwise a reconnection before
	// even responding to the offer would be enough to have the entire file
	// sent.
	isNewAccept bool
}

// fileChunkAckEvent routes a received file_chunk_ack to the sending
// goroutine that manages that transfer's sliding window.
type fileChunkAckEvent struct {
	seq        uint64
	fromUserID string
}

// incomingFileTransfer holds the receiver-side state: raw encrypted chunks
// queue up onto a temporary file (never in RAM) as they arrive, decrypted
// and verified only once, when the transfer completes.
//
// The actual write (os.CreateTemp + Write) does not run on the Update()
// loop: synchronous disk I/O inside the "file_chunk" case would block the
// ENTIRE bubbletea event loop (not just that transfer) for the duration of
// each individual write, the same reason encryption on the send side
// runs off the loop (see onFilePresetChosen).
// chunkCh/chunkResultCh decouple the I/O onto a dedicated per-transfer
// goroutine (startIncomingChunkWriter), consumed in Update() via the
// "waiter" pattern already used by waitForRoom/waitForKnock (case
// incomingChunkWrittenMsg), the file handle itself (tmpFile) stays
// private to the writer goroutine, never exposed here: tmpPath (set from
// the first result) is enough for finalizeIncomingTransfer, which
// re-reads from the path with a fresh os.ReadFile.
type incomingFileTransfer struct {
	transferID string
	tabIdx     int
	fromUserID string
	fromKey    string // sender's member key
	fileName   string
	fileSize   int64  // size of the encrypted blob (how much must actually be received)
	fileKey    []byte // symmetric content key, from the decrypted meta_blob (fileOfferMetaDecryptedMsg)
	chunkCount uint64 // total chunk count declared by the sender in the meta_blob, see startIncomingChunkWriter
	// hash, sha256(ciphertext) already verified at announce time (case
	// "file_announce"), consumed by m.verifiedFileHashes at the time of
	// this file_offer. At the end of the transfer, finalizeIncomingTransfer
	// compares this hash against the sha256 of the received ciphertext,
	// no signature to re-verify, already done before a single chunk arrived.
	hash          []byte
	tmpPath       string
	written       int64
	progress      *fileTransferProgress
	chunkCh       chan incomingChunkJob
	chunkResultCh chan incomingChunkResult
	// abortCh: closed by dropIncomingTransfer to signal abandonment to the
	// dedicated writer goroutine (startIncomingChunkWriter), NEVER chunkCh,
	// which the success path (case incomingChunkWrittenMsg) closes on its
	// own when written reaches fileSize; a distinct channel removes any
	// ambiguity for the writer goroutine between "completed" (chunkCh
	// closed, file to keep) and "abandoned" (abortCh closed, temporary file
	// to remove), see the comment on startIncomingChunkWriter.
	abortCh chan struct{}

	// acceptRetryDeadline, the point past which fileAcceptRetryMsg stops
	// resending the file_accept and silently gives up (the sender will
	// meanwhile have isolated this recipient on its side). Zero value until
	// the offer is accepted, see case tea.KeyEnter in the file_offer popup.
	acceptRetryDeadline time.Time
}

// pendingFileAnnounce, a file_announce whose signature did not verify on
// the first attempt, held pending for self-heal instead of being
// discarded, see model.pendingFileAnnounces and retryPendingFileAnnounces.
type pendingFileAnnounce struct {
	tabIdx     int
	fromKey    string // sender's member key
	fromUserID string
	devKey     string // sender device key (Contact.Devices) to re-verify from
	hash       []byte
	sig        []byte
	sigMLDSA   []byte
	sigTS      string
	deadline   time.Time
}

// pendingInvite, an invite held in queue until the relationship-key
// exchange (rel_init/rel_init_ack) completes for ALL involved contacts,
// see model.pendingInvites and retryPendingInvites. label is descriptive
// text (never executed), used only for the Console queuing/expiry message.
type pendingInvite struct {
	label    string
	pending  map[string]bool        // contact's member key → not yet ready (ReadyDevices() empty)
	retry    func(m *model) tea.Cmd // re-runs exactly the same original command/arguments on the current model
	deadline time.Time
}

// pendingJoin, see model.pendingJoins: a RECEIVED invite, accepted before
// hostReadyForJoin(knock.FromIdentityPub) was true, waiting for
// retryPendingJoins to retry it. Unlike pendingInvite it needs no set of
// pending usernames: an incoming invite always has a single host.
type pendingJoin struct {
	knock    pendingKnock
	deadline time.Time
}

// incomingChunkJob is a raw incoming chunk, passed to the dedicated
// writer goroutine of an incomingFileTransfer, seq is the chunk's STABLE
// INDEX (byteOffset/chunkSize on the sender side, see startSendingChunks),
// not a simple send counter: two chunks with the same seq are always the
// same byte range, even when one of the two arrives from a recovery
// retransmission (catchup) numbered at a different time.
type incomingChunkJob struct {
	seq   uint64
	chunk []byte
}

// incomingChunkResult is the outcome of processing ONE incoming chunk,
// reported by the writer goroutine to Update() (case
// incomingChunkWrittenMsg), "processing" means written to disk IN ORDER,
// or buffered awaiting the missing chunks preceding it (see
// startIncomingChunkWriter): in both cases the sender can consider the
// chunk delivered and send another, so every incoming job always produces
// exactly one result, used in Update() only to send the flow ack. written
// is CUMULATIVE over only the bytes actually written to disk so far (not
// the buffered ones), tmpPath the temporary file's path (the same for
// every result of the same transfer, set by the goroutine when it is
// created, on the first chunk written). complete is true on the result
// that brings the written chunk count to reach the chunkCount declared by
// the sender in the offer, the only end-of-transfer signal, never
// derived from written>=fileSize (fileSize is the encrypted blob's size,
// but a buffered chunk is not yet "written" even though it has already
// arrived).
type incomingChunkResult struct {
	transferID string
	seq        uint64
	written    int64
	tmpPath    string
	complete   bool
	err        error
	// nextIndex/buffered, chunk-level detail state at the time of THIS
	// result (see fileTransferProgress.chunksDone/chunksPending): nextIndex
	// is the contiguous frontier already written, buffered how many chunks
	// arrived early are still awaiting placement.
	nextIndex uint64
	buffered  int
}

// incomingChunkWrittenMsg is the tea.Msg returned by waitForIncomingChunkResult.
type incomingChunkWrittenMsg incomingChunkResult

// dropIncomingTransfer removes an incoming transfer from
// m.incomingTransfers, closing abortCh if present, without this explicit
// close the dedicated writer goroutine (startIncomingChunkWriter) would
// stay blocked forever on a channel that nobody will ever write to or
// close (goroutine leak), every time a transfer is abandoned BEFORE its
// last chunk (rejected, timed out, metadata decryption error, closure of
// the tab hosting it, see closeTabAt, or a write error arrived via
// incomingChunkWrittenMsg: the goroutine has already exited on its own in
// that case, closing a channel nobody reads from anymore remains safe
// regardless). abortCh, NEVER chunkCh: the "completed successfully" case
// closes chunkCh separately (case incomingChunkWrittenMsg, when written
// reaches fileSize) and never goes through this function, a distinct
// channel for abandonment lets the writer goroutine know with certainty,
// unambiguously, when it must also remove the temporary file already
// written (see startIncomingChunkWriter) instead of leaving it orphaned
// on disk.
func (m *model) dropIncomingTransfer(transferID string) {
	if it := m.incomingTransfers[transferID]; it != nil && it.abortCh != nil {
		close(it.abortCh)
	}
	delete(m.incomingTransfers, transferID)
}

// scheduleFileAcceptRetry schedules the next check (case fileAcceptRetryMsg
// in Update()): if by then no chunk has yet arrived for transferID,
// resends the file_accept and reschedules itself, until
// incomingFileTransfer.acceptRetryDeadline expires, see the comment on
// fileAcceptRetryMsg.
func (m *model) scheduleFileAcceptRetry(tabIdx int, toUserID, transferID string) tea.Cmd {
	return tea.Tick(m.fileAcceptRetryInterval, func(time.Time) tea.Msg {
		return fileAcceptRetryMsg{transferID: transferID, toUserID: toUserID, tabIdx: tabIdx}
	})
}

// startIncomingChunkWriter starts the dedicated goroutine that writes to
// disk the chunks of ONE transfer, read in order from chunkCh (never
// concurrent: a single writer per transfer, chunks arrive already in seq
// order from the same WS connection), never a tea.Cmd: this runs for the
// entire duration of the transfer, it does not return a single result but
// produces many on resultCh, consumed by waitForIncomingChunkResult. Go's
// os.File does not internally buffer Writes: each chunk is already
// visible to a concurrent read (os.ReadFile in finalizeIncomingTransfer)
// as soon as this function has received the corresponding result,
// Close() below is only file-descriptor cleanup, not a condition for the
// visibility of data already written.
//
// select is explicit on chunkCh/abortCh instead of a plain "for range
// chunkCh", to unambiguously distinguish completion (chunkCh closed: the
// file stays, to be consumed by finalizeIncomingTransfer) from
// abandonment (abortCh closed: the temporary file already written is
// removed immediately, not left on disk).
//
// Chunks do NOT necessarily arrive in seq order: a recovery catchup (see
// startSendingChunks on the sender side) can deliver a higher index
// before a lower one, never retransmitted, is finally recovered, writing
// blindly in arrival order would silently corrupt the file: it would
// reach "100% written" with content in the wrong order, detected only by
// the final signature verification. nextIndex is the contiguous frontier
// already written to disk; buffered holds chunks that arrived early,
// indexed by their own seq, until the frontier reaches them, at that
// point they are written in a chain, in the same order the original bytes
// arrived, never using os.File.WriteAt: writing always stays sequential
// by construction, only deferred when necessary.
func startIncomingChunkWriter(transferID string, chunkCount uint64, chunkCh <-chan incomingChunkJob, abortCh <-chan struct{}, resultCh chan<- incomingChunkResult) {
	go func() {
		var f *os.File
		var path string
		var written int64
		var nextIndex uint64
		buffered := make(map[uint64][]byte)
		aborted := false
	loop:
		for {
			select {
			case job, ok := <-chunkCh:
				if !ok {
					break loop
				}
				switch {
				case job.seq < nextIndex:
					// Duplicate (retransmission after an ack lost on the
					// network), already written, discarded. The ack is
					// still sent: it is a pure flow signal ("I've finished
					// processing this chunk"), never proof of correctness.
					resultCh <- incomingChunkResult{transferID: transferID, seq: job.seq, nextIndex: nextIndex, buffered: len(buffered)}
					continue
				case job.seq > nextIndex:
					// Arrived ahead of the contiguous frontier, buffered,
					// not written, awaiting what is missing before it.
					buffered[job.seq] = job.chunk
					resultCh <- incomingChunkResult{transferID: transferID, seq: job.seq, nextIndex: nextIndex, buffered: len(buffered)}
					continue
				}
				if f == nil {
					var err error
					f, err = os.CreateTemp("", "neutrino-filetransfer-*.part")
					if err != nil {
						resultCh <- incomingChunkResult{transferID: transferID, seq: job.seq, err: err}
						return
					}
					path = f.Name()
				}
				chunk := job.chunk
				for {
					if _, err := f.Write(chunk); err != nil {
						f.Close()
						os.Remove(path)
						resultCh <- incomingChunkResult{transferID: transferID, seq: nextIndex, err: err}
						return
					}
					written += int64(len(chunk))
					nextIndex++
					next, ok := buffered[nextIndex]
					if !ok {
						break
					}
					delete(buffered, nextIndex)
					chunk = next
				}
				resultCh <- incomingChunkResult{transferID: transferID, seq: job.seq, written: written, tmpPath: path, complete: nextIndex >= chunkCount, nextIndex: nextIndex, buffered: len(buffered)}
			case <-abortCh:
				aborted = true
				break loop
			}
		}
		if f != nil {
			f.Close()
			if aborted {
				os.Remove(path)
			}
		}
	}()
}

// waitForIncomingChunkResult waits for the next write outcome for an
// incoming transfer, same "waiter" pattern as waitForRoom/waitForKnock:
// Update() re-arms it after every result until the transfer is complete
// (at that point it closes chunkCh, the writer goroutine exits its
// for-range and this function receives zero-value/false, tea.Msg nil, the
// cycle stops on its own with no need for an explicit flag).
func waitForIncomingChunkResult(resultCh <-chan incomingChunkResult) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-resultCh
		if !ok {
			return nil
		}
		return incomingChunkWrittenMsg(r)
	}
}

// eligibleFileRecipients returns the member keys present in tab tabIdx with
// a ContentKey relationship already established (see
// contentRelEstablished), the only list of valid candidates for
// /grp-file-send: encrypting for a recipient requires their public
// ContentKey, there is no other way.
func (m *model) eligibleFileRecipients(tabIdx int) []string {
	tab := m.tabs[tabIdx]
	out := make([]string, 0, len(tab.online))
	for _, k := range tab.online {
		if m.contentRelEstablished(tab, k) {
			out = append(out, k)
		}
	}
	return out
}

// namesWithoutContentRel lists the display names (local name if a saved
// contact, otherwise the member name) of the CONNECTED members of room
// tabIdx that do not pass contentRelEstablished, the exact complement of
// eligibleFileRecipients, used to tell the USER who is missing instead of
// just "nobody" when /grp-file-send or /grp-contact-send refuse to
// proceed (same pipeline, same check, see both callers).
func (m *model) namesWithoutContentRel(tabIdx int) []string {
	tab := m.tabs[tabIdx]
	names := make([]string, 0, len(tab.online))
	for _, k := range tab.online {
		if k == m.myKey() || m.contentRelEstablished(tab, k) {
			continue
		}
		name := m.memberName(tab, k)
		if c := m.resolveContactByPub(memberKeyPub(k)); c != nil {
			name = c.DisplayName()
		}
		names = append(names, name)
	}
	return names
}

// noContentRecipientsMsg builds the "no recipient with an established
// relationship" error message, naming WHO is missing when possible.
// Used by both callers of eligibleFileRecipients (cmdSendFile,
// cmdSendContact/finishSendContact), never duplicated by hand.
func (m *model) noContentRecipientsMsg(tabIdx int) string {
	names := m.namesWithoutContentRel(tabIdx)
	if len(names) == 0 {
		return i18n.T("tui.err_send_file_no_content_recipients")
	}
	return fmt.Sprintf(i18n.T("tui.err_send_file_no_content_recipients_named"), strings.Join(names, ", "))
}

// cmdSendFile starts the file-send flow: preconditions (at least one
// recipient with an established ContentKey relationship in the current
// room, fail fast, before letting the user pick a file that could not be
// sent anyway), then opens the filesystem browser to choose the file to send.
func (m *model) cmdSendFile() tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.isConsole || tab.isContacts || tab.isGroups || tab.isTor || tab.isFiles {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_send_file_wrong_tab")))
	}
	if len(m.eligibleFileRecipients(tabIdx)) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(m.noContentRecipientsMsg(tabIdx)))
	}

	dir := startDirForFileBrowser()
	entries, err := listDir(dir)
	if err != nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.generic_error"), err.Error())))
	}
	m.sendFileDir = dir
	m.sendFileEntries = entries
	m.sendFileIdx = 0
	m.sendFileFilter = ""
	m.sendFileMode = true
	m.sendFileTabIdx = tabIdx
	return nil
}

// fsEntry is an entry (file or directory) listed by the /grp-file-send
// filesystem browser, see listDir and sendFileFilteredEntries.
type fsEntry struct {
	name  string
	isDir bool
}

// startDirForFileBrowser returns the directory neutrino was launched from
// (the process cwd), starting point both for picking a file to send
// (/grp-file-send) and for choosing where to save a received file.
// Falls back to $HOME then "/" if the cwd is unavailable (rare).
func startDirForFileBrowser() string {
	if dir, err := os.Getwd(); err == nil {
		return dir
	}
	if dir, err := os.UserHomeDir(); err == nil {
		return dir
	}
	return "/"
}

// listDir lists dir, directories first and then alphabetically
// case-insensitive (same criterion within both groups), keeping navigation predictable.
func listDir(dir string) ([]fsEntry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	entries := make([]fsEntry, 0, len(des))
	for _, de := range des {
		isDir := de.IsDir()
		if de.Type()&os.ModeSymlink != 0 {
			// os.DirEntry.IsDir() reflects the symlink entry itself,
			// never what it points to, a symlinked directory (e.g.
			// Termux's ~/storage/pictures, pointing at Android's real
			// storage) would otherwise show up as a plain file, with no
			// way to open it. os.Stat follows the link; left as the
			// symlink's own (false) type on a broken link, same as
			// os.ReadDir would show it anyway.
			if info, statErr := os.Stat(filepath.Join(dir, de.Name())); statErr == nil {
				isDir = info.IsDir()
			}
		}
		entries = append(entries, fsEntry{name: de.Name(), isDir: isDir})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir
		}
		return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
	})
	return entries, nil
}

// sendFileFilteredEntries applies sendFileFilter (case-insensitive
// substring) to sendFileEntries, same criterion as pickerItems for the
// other filtered popups.
func (m model) sendFileFilteredEntries() []fsEntry {
	filter := strings.ToLower(m.sendFileFilter)
	if filter == "" {
		return m.sendFileEntries
	}
	out := make([]fsEntry, 0, len(m.sendFileEntries))
	for _, e := range m.sendFileEntries {
		if strings.Contains(strings.ToLower(e.name), filter) {
			out = append(out, e)
		}
	}
	return out
}

// sendFileGoUp moves up to sendFileDir's parent directory, if not already
// at the filesystem root (filepath.Dir("/") == "/", no movement).
func (m model) sendFileGoUp() model {
	parent := filepath.Dir(m.sendFileDir)
	if parent == m.sendFileDir {
		return m
	}
	entries, err := listDir(parent)
	if err != nil {
		return m
	}
	m.sendFileDir = parent
	m.sendFileEntries = entries
	m.sendFileIdx = 0
	m.sendFileFilter = ""
	return m
}

// sendFileEnter descends into subdirectory full. If it is not readable
// (permissions) it silently stays where it was instead of showing an
// error popup for a common navigation event (e.g. protected system
// directories).
func (m model) sendFileEnter(full string) model {
	entries, err := listDir(full)
	if err != nil {
		return m
	}
	m.sendFileDir = full
	m.sendFileEntries = entries
	m.sendFileIdx = 0
	m.sendFileFilter = ""
	return m
}

// toggleStringInOrder adds s to list if absent, removes it if present,
// used by qrFileMode's multi-select (Space), preserving the order items
// were toggled on (never re-sorted), so "which one was picked first"
// stays meaningful even though AssembleQRMulti itself doesn't need it.
func toggleStringInOrder(list []string, s string) []string {
	for i, v := range list {
		if v == s {
			return append(list[:i], list[i+1:]...)
		}
	}
	return append(list, s)
}

// qrFileFilteredEntries applies qrFileFilter to qrFileEntries, same
// criterion as sendFileFilteredEntries.
func (m model) qrFileFilteredEntries() []fsEntry {
	filter := strings.ToLower(m.qrFileFilter)
	if filter == "" {
		return m.qrFileEntries
	}
	out := make([]fsEntry, 0, len(m.qrFileEntries))
	for _, e := range m.qrFileEntries {
		if strings.Contains(strings.ToLower(e.name), filter) {
			out = append(out, e)
		}
	}
	return out
}

// qrFileGoUp moves up to qrFileDir's parent directory, same logic as
// sendFileGoUp. Selection (qrFileSelected) survives navigation: it holds
// full paths, independent of which directory is currently shown.
func (m model) qrFileGoUp() model {
	parent := filepath.Dir(m.qrFileDir)
	if parent == m.qrFileDir {
		return m
	}
	entries, err := listDir(parent)
	if err != nil {
		return m
	}
	m.qrFileDir = parent
	m.qrFileEntries = entries
	m.qrFileIdx = 0
	m.qrFileFilter = ""
	return m
}

// qrFileEnter descends into subdirectory full, same logic as sendFileEnter.
func (m model) qrFileEnter(full string) model {
	entries, err := listDir(full)
	if err != nil {
		return m
	}
	m.qrFileDir = full
	m.qrFileEntries = entries
	m.qrFileIdx = 0
	m.qrFileFilter = ""
	return m
}

// renderSaveRenamePopup shows the name proposed by the sender for the
// received file, editable before the folder-choice step (saveDirMode).
func (m model) renderSaveRenamePopup() string {
	title := m.saveTitle
	if title == "" {
		title = i18n.T("tui.recv_file_rename_title")
	}
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(title))
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf(i18n.T("tui.recv_file_rename_label"), m.savePendingName))
	sb.WriteString("\n\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.recv_file_rename_hint")))
	return sb.String()
}

// renderSaveDirBrowser draws the folder browser for step 2/2: same
// navigation as renderSendFileBrowser but without a search filter (the
// list here is already reduced to subdirectories only) and with a
// synthetic entry on top (index 0) representing "save in the current
// folder".
func (m model) renderSaveDirBrowser() string {
	const maxVisible = 12
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.recv_file_save_hint"), m.savePendingName, m.saveFileDir)))
	sb.WriteString("\n\n")

	total := len(m.saveFileEntries) + 1
	start := 0
	if m.saveFileIdx >= maxVisible {
		start = m.saveFileIdx - maxVisible + 1
	}
	end := start + maxVisible
	if end > total {
		end = total
	}
	for i := start; i < end; i++ {
		label := i18n.T("tui.recv_file_save_here")
		if i > 0 {
			label = m.saveFileEntries[i-1].name + "/"
		}
		if i == m.saveFileIdx {
			sb.WriteString("  " + stylePaletteSel.Render(label))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(label))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.recv_file_save_footer")))
	return sb.String()
}

// filterDirsOnly drops files from entries, used by saveDirMode's folder
// browser, where selecting or navigating into a file makes no sense (it
// only chooses where to save, never what to save).
func filterDirsOnly(entries []fsEntry) []fsEntry {
	out := make([]fsEntry, 0, len(entries))
	for _, e := range entries {
		if e.isDir {
			out = append(out, e)
		}
	}
	return out
}

// saveDirGoUp moves up to saveFileDir's parent directory, same logic as
// sendFileGoUp, filtered to subdirectories only.
func (m model) saveDirGoUp() model {
	parent := filepath.Dir(m.saveFileDir)
	if parent == m.saveFileDir {
		return m
	}
	all, err := listDir(parent)
	if err != nil {
		return m
	}
	m.saveFileDir = parent
	m.saveFileEntries = filterDirsOnly(all)
	m.saveFileIdx = 0
	return m
}

// saveDirEnter descends into subdirectory name (inside saveFileDir),
// same logic as sendFileEnter, filtered to subdirectories only.
func (m model) saveDirEnter(name string) model {
	full := filepath.Join(m.saveFileDir, name)
	all, err := listDir(full)
	if err != nil {
		return m
	}
	m.saveFileDir = full
	m.saveFileEntries = filterDirsOnly(all)
	m.saveFileIdx = 0
	return m
}

// onFileChosenForSend is the step following file selection (filesystem
// browser closed with a valid path): checks the size against
// FileTransferMaxSizeMiB before doing any expensive work. With a single
// eligible recipient the recipient is implicit (no popup); with more than
// one it opens the recipient popup, preselected with an established relationship.
func (m model) onFileChosenForSend(path string) (tea.Model, tea.Cmd) {
	tabIdx := m.sendFileTabIdx
	info, err := os.Stat(path)
	if err != nil {
		return m, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_send_file_read"), err.Error())))
	}
	limitBytes := int64(m.fileTransferMaxSizeMiB) * 1024 * 1024
	if info.Size() > limitBytes {
		sizeMiB := info.Size() / (1024 * 1024)
		return m, consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_send_file_too_large"), sizeMiB, m.fileTransferMaxSizeMiB)))
	}
	m.sendFilePath = path
	m.sendFileSize = info.Size()
	m.sendFileData = nil
	m.sendFileDisplayName = ""

	candidates := m.eligibleFileRecipients(tabIdx)
	if len(candidates) == 1 {
		return m.onFileRecipientsChosen(candidates)
	}
	m.sendFileCandidates = candidates
	m.sendFileSelected = make(map[string]bool, len(candidates))
	for _, u := range candidates {
		m.sendFileSelected[u] = true // preselected: Space deselects (opt-out)
	}
	m.sendFileRecipientsIdx = 0
	m.sendFileRecipientsMode = true
	return m, nil
}

// onFileRecipientsChosen is the step following recipient confirmation
// (implicit in a two-member room, or chosen in the group popup): opens
// the speed-preset choice. "slow" remains the default here too, the
// cursor starts at idx 0, "warp" must be explicitly chosen by moving the
// cursor before Enter.
func (m model) onFileRecipientsChosen(recipients []string) (tea.Model, tea.Cmd) {
	m.sendFileRecipients = recipients
	m.sendFilePresetIdx = 0
	m.sendFileCompressOn = m.strongCompressionEnabled
	m.sendFilePresetMode = true
	return m, nil
}

// onFilePresetChosen starts encrypting+signing the file in the
// BACKGROUND and only then sends the file_offer to the chosen recipients
// (case fileEncryptedMsg, below, resumes where this function leaves off).
// Encrypt-then-sign, same scheme as chat messages (see
// buildContentSigningKeys): the content is encrypted ONCE with a random
// symmetric key (file_key), then that key, together with name/size, is
// encrypted again separately for each recipient with their ContentKey
// (encryptForContentPeer), and the shared ciphertext is signed once per
// recipient with OUR ContentKey toward them (SignRelMsg/SignRelMsgMLDSA).
//
// The heavy work (os.ReadFile of a file that can be several megabytes,
// plus encryption, potentially several seconds) must NEVER run in here:
// onFilePresetChosen is called synchronously from bubbletea's Update()
// loop, blocking it blocks the ENTIRE TUI (every tab, every connection,
// every command, including reading incoming network frames, which simply
// queue up until Update() returns) for its whole duration, so the
// encryption of the whole file content never runs here: it runs inside
// a tea.Cmd.
func (m model) onFilePresetChosen(preset string) (tea.Model, tea.Cmd) {
	tabIdx := m.sendFileTabIdx
	tab := m.tabs[tabIdx]

	type fileRecipient struct {
		key      string // member key, also the "for" of the content signature
		userID   string
		pub      ed25519.PublicKey
		mldsaPub []byte
		mlkemPub []byte
		myKey    shared.RelSigningKey
	}
	resolved := make([]fileRecipient, 0, len(m.sendFileRecipients))
	for _, u := range m.sendFileRecipients {
		pub, mldsaPub, mlkemPub, _, known := m.contentPeerKeysFor(tab, u)
		if !known {
			continue
		}
		myKey, ok := m.myContentPrivFor(tab, u)
		if !ok {
			continue
		}
		uid := tab.cli.LookupUserID(u)
		if uid == "" {
			continue // disconnected between selection and now
		}
		resolved = append(resolved, fileRecipient{key: u, userID: uid, pub: pub, mldsaPub: mldsaPub, mlkemPub: mlkemPub, myKey: myKey})
	}
	if len(resolved) == 0 {
		return m, consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_send_file_no_content_recipients")))
	}
	toUserIDs := make([]string, 0, len(resolved))
	pending := make(map[string]bool, len(resolved))
	for _, r := range resolved {
		toUserIDs = append(toUserIDs, r.userID)
		pending[r.key] = true
	}

	var idBytes [16]byte
	_, _ = rand.Read(idBytes[:])
	transferID := hex.EncodeToString(idBytes[:])
	fileName := m.sendFileDisplayName
	if fileName == "" {
		fileName = filepath.Base(m.sendFilePath)
	}

	sendFileData := m.sendFileData
	sendFilePath := m.sendFilePath
	recipients := append([]string(nil), m.sendFileRecipients...)
	strongCompression := m.sendFileCompressOn

	// chunkSize decided here, not inside startSendingChunks: it is needed
	// RIGHT AWAY to compute chunkCount (how many chunks the transfer will
	// have), declared in the meta_blob below, the recipient cannot assume
	// it from their own config.json (preset/chunk size are the sender's
	// choice, potentially different from theirs).
	chunkSizeKiB := m.fileWarpChunkSizeKiB
	if preset == "slow" {
		chunkSizeKiB = m.fileSlowChunkSizeKiB
	}
	chunkSize := chunkSizeKiB * 1024
	if chunkSize <= 0 {
		chunkSize = 16 * 1024
	}

	return m, func() tea.Msg {
		data := sendFileData
		if data == nil {
			var err error
			data, err = os.ReadFile(sendFilePath)
			if err != nil {
				return fileEncryptedMsg{err: fmt.Errorf(i18n.T("tui.err_send_file_read"), err.Error())}
			}
		}

		tagged, err := shared.PackData(data, strongCompression)
		if err != nil {
			return fileEncryptedMsg{err: err}
		}
		fileKey, err := shared.RandomBytes(32)
		if err != nil {
			return fileEncryptedMsg{err: err}
		}
		encB64, err := shared.Encrypt(fileKey, tagged, nil)
		if err != nil {
			return fileEncryptedMsg{err: err}
		}
		ciphertext, err := base64.StdEncoding.DecodeString(encB64)
		if err != nil {
			return fileEncryptedMsg{err: err}
		}

		sigTS := shared.NowTS()

		// We sign the HASH of the ciphertext, not the whole ciphertext,
		// the hash is available at zero cost BEFORE a single byte of the
		// file is transferred, letting the recipient verify authenticity
		// at announce time (file_announce), not only at the end of the transfer.
		hashSum := sha256.Sum256(ciphertext)
		hash := hashSum[:]
		hashHex := hex.EncodeToString(hash)

		announceEnvelopes := make(map[string]shared.FileAnnounceEnvelope, len(resolved))
		for _, r := range resolved {
			announceEnvelopes[r.userID] = shared.FileAnnounceEnvelope{
				Sig:      shared.SignRelMsg(r.myKey.Priv, hashHex, sigTS, r.key),
				SigMLDSA: shared.SignRelMsgMLDSA(r.myKey.MLDSASeed, hashHex, sigTS, r.key),
			}
		}

		// Name, size, and file_key do not travel in the clear: encrypted
		// for each content recipient in a separate, small envelope
		// (meta_blob), the relay routes it without being able to read it
		// (the server never needs them, only the recipient's UI and
		// content decryption do). The actual offer (envelopes) is already
		// prepared here but is NOT sent now, only after each recipient's
		// file_announce_ack (case "file_announce_ack", Update()).
		// ChunkCount, how many chunks the transfer will have, computed
		// with the SAME chunkSize the sender will actually use to send
		// (decided above, before encryption). The recipient uses it to
		// know when chunk numbering is complete (see
		// startIncomingChunkWriter), it cannot recompute it on its own:
		// the preset/chunkSize is the sender's choice, their own
		// config.json may have different values.
		chunkCount := int64((len(ciphertext) + chunkSize - 1) / chunkSize)
		metaPlain, _ := json.Marshal(struct {
			FileName   string `json:"file_name"`
			FileSize   int64  `json:"file_size"`
			FileKey    []byte `json:"file_key"`
			ChunkCount int64  `json:"chunk_count"`
		}{fileName, int64(len(ciphertext)), fileKey, chunkCount})

		envelopes := make(map[string]shared.FileOfferEnvelope, len(resolved))
		for _, r := range resolved {
			metaBlob, err := encryptForContentPeer(r.pub, r.mlkemPub, metaPlain)
			if err != nil {
				continue // a recipient with corrupted data must not block the others
			}
			envelopes[r.userID] = shared.FileOfferEnvelope{MetaBlob: metaBlob}
		}
		if len(envelopes) == 0 || len(announceEnvelopes) == 0 {
			return fileEncryptedMsg{err: errors.New(i18n.T("tui.err_send_file_no_content_recipients"))}
		}

		return fileEncryptedMsg{
			tabIdx:            tabIdx,
			transferID:        transferID,
			fileName:          fileName,
			ciphertext:        ciphertext,
			hash:              hash,
			announceEnvelopes: announceEnvelopes,
			envelopes:         envelopes,
			sigTS:             sigTS,
			toUserIDs:         toUserIDs,
			pending:           pending,
			preset:            preset,
			recipients:        recipients,
		}
	}
}

// startSendingChunks splits the ciphertext into chunks according to the
// chosen preset and sends them with a sliding window (up to
// FileWarpMaxInFlightChunks/FileSlowMaxInFlightChunks chunks without an
// ack at once, instead of lockstep chunk-then-ack-then-chunk, a pipeline
// designed not to waste the round-trip over Tor). A recipient who
// confirms no chunk within fileTransferReconnectTimeout is isolated
// (removed from subsequent sends): the others continue independently.
func (m model) startSendingChunks(ft *outgoingFileTransfer) tea.Cmd {
	tab := m.tabs[ft.tabIdx]
	cli := tab.cli
	toUserIDs := ft.accepted
	ciphertext := ft.ciphertext
	transferID := ft.transferID
	tabIdx := ft.tabIdx
	consoleIdx := m.consoleIdx
	fileName := ft.fileName

	chunkSizeKiB := m.fileWarpChunkSizeKiB
	windowSize := m.fileWarpMaxInFlightChunks
	var delay time.Duration
	if ft.preset == "slow" {
		chunkSizeKiB = m.fileSlowChunkSizeKiB
		windowSize = m.fileSlowMaxInFlightChunks
		delay = time.Duration(m.fileSlowDelayMs) * time.Millisecond
	}
	chunkSize := chunkSizeKiB * 1024
	if chunkSize <= 0 {
		chunkSize = 16 * 1024
	}
	if windowSize <= 0 {
		windowSize = 1
	}
	ackTimeout := m.fileTransferReconnectTimeout
	offerTimeout := m.fileTransferOfferTimeout

	ackCh := make(chan fileChunkAckEvent, 64)
	ft.ackCh = ackCh
	resumeCh := make(chan fileResumeEvent, 16)
	ft.resumeCh = resumeCh
	pendingDone := ft.pendingDone
	progress := ft.progress

	// chunkCountTotal, the same computation as the meta_blob declared at
	// offer time, used here only for the "n. chunks sent - total" detail
	// of each progress row, never for sending itself.
	chunkCountTotal := uint64((len(ciphertext) + chunkSize - 1) / chunkSize)

	return func() tea.Msg {
		// groups, recipients grouped by shared position (same next
		// expected chunk index), ordered by INCREASING index: groups[len-1]
		// is always the front (the most advanced, the one generating new
		// data from the ciphertext), groups[0] the furthest behind. A
		// group behind ALWAYS chases the one immediately ahead of it in
		// the ordering (never the front directly), when it catches up
		// they merge (mergeAdjacent) and the chase cascades toward the
		// next, until all are merged into the front and sends go back to
		// a single multicast, a straggler with a large backlog (e.g. a
		// second full recovery round from scratch) never blocks the
		// front's advancement for everyone else.
		// Scheduling weight: the furthest-behind group (groups[0], only if
		// there is more than one) gets weight 7, every other group
		// (including the front) weight 3, see pickGroup.
		type sendGroup struct {
			index   uint64
			members map[string]bool
			sent    uint64 // chunks sent so far by this group, for weighted scheduling (see pickGroup)
			// progress/progressID, dedicated row in the File tab for THIS
			// group. The front always reuses ft.progress (progressID ==
			// transferID, the row already shown from offer time); a group
			// behind, born from a missed merge, gets its own (see
			// addMemberAtIndex), so two straggling recipients appear on
			// separate rows with their own percentage as soon as they
			// split off, and merge back into a single row once they
			// rejoin (see mergeAdjacent/removeMember).
			progress   *fileTransferProgress
			progressID string
		}
		type inFlightChunk struct {
			size    int
			waiting map[string]bool // user_id → true until it confirms this chunk
			group   *sendGroup      // owning group, for isolation/merge, see sendGroup
		}
		// groupPeerNames resolves and sorts the names of a group's current
		// members, for its progress row's peer field.
		groupPeerNames := func(g *sendGroup) string {
			names := make([]string, 0, len(g.members))
			for uid := range g.members {
				name := cli.LookupUsername(uid)
				if name == "" {
					name = client.ShortUID(uid)
				}
				names = append(names, name)
			}
			sort.Strings(names)
			return strings.Join(names, ", ")
		}
		nextGroupSeq := 1
		// groups starts EMPTY if nobody has accepted yet (never a
		// front-placeholder group with no members): len(groups)==0 is the
		// unambiguous "no active recipients" signal, used below to exit
		// right away instead of needlessly waiting out the grace window.
		var groups []*sendGroup
		// everAccepted, who has ACTUALLY accepted the offer at least once
		// (never someone who only sent a file_resume): a genuine
		// file_resume arriving BEFORE a real file_accept (e.g. a
		// recipient's reconnection while the offer is still an unanswered
		// popup) is ignored, see fileResumeEvent.isNewAccept.
		everAccepted := make(map[string]bool, len(toUserIDs))
		if len(toUserIDs) > 0 {
			front := &sendGroup{index: 0, members: make(map[string]bool, len(toUserIDs)), progress: progress, progressID: transferID}
			for _, u := range toUserIDs {
				front.members[u] = true
				everAccepted[u] = true
			}
			if progress != nil {
				progress.setPeer(groupPeerNames(front))
				progress.setChunks(int64(front.index), 0, int64(chunkCountTotal))
			}
			groups = append(groups, front)
		}
		isolated := make(map[string]string) // member key (stable, unlike user_id) → display name
		inFlight := make(map[uint64]*inFlightChunk)
		deadline := time.Now().Add(offerTimeout)

		// removeMember drops userID from whichever group currently
		// contains it, a group left empty is removed from the list (even
		// if it is the front: the next most-advanced group left
		// automatically replaces it, since the list stays ordered, no
		// special case for "the front was isolated"). Its dedicated
		// progress row disappears with it, EXCEPT when it was the very
		// last group left: in that case the transfer has failed entirely,
		// the row stays visible marked failed instead of disappearing
		// without a trace.
		removeMember := func(userID string) {
			for i, g := range groups {
				if g.members[userID] {
					delete(g.members, userID)
					if len(g.members) == 0 {
						groups = append(groups[:i], groups[i+1:]...)
						if g.progress == nil {
							return
						}
						if len(groups) == 0 {
							g.progress.setComplete(true)
						} else if g.progressID != transferID {
							m.fileProgress.remove(g.progressID)
						}
					} else if g.progress != nil {
						g.progress.setPeer(groupPeerNames(g))
					}
					return
				}
			}
		}
		// resetSent zeroes each group's "sent" counter, must be called
		// every time the SET of groups changes (new arrival, merge,
		// isolation): pickGroup chooses based on the sent/weight ratio,
		// and that ratio only makes sense relative to the CURRENT
		// composition of groups. Without this reset, a freshly recreated
		// group (e.g. a straggler readmitted after being isolated) starts
		// from sent=0 while a front with hundreds of sends already
		// accumulated stays at a very low ratio, starving the front for
		// minutes not because of the 7:3 priority itself but because the
		// scheduler would be "catching up" a historical ratio no longer
		// relevant, instead of applying 7:3 from that point onward.
		resetSent := func() {
			for _, g := range groups {
				g.sent = 0
			}
		}
		// addMemberAtIndex adds userID to the already-existing group with
		// exactly this index, or creates a new one keeping the increasing
		// order, never past the current front (see the two callers, which
		// clamp idx to the front before invoking it).
		addMemberAtIndex := func(idx uint64, userID string) {
			for _, g := range groups {
				if g.index == idx {
					g.members[userID] = true
					if g.progress != nil {
						g.progress.setPeer(groupPeerNames(g))
					}
					return
				}
			}
			ng := &sendGroup{index: idx, members: map[string]bool{userID: true}}
			// Dedicated progress row: without this, a group just split
			// off from the front (a new or readmitted straggler) would
			// stay invisible in the File tab until it rejoins, see the
			// comment on sendGroup's progress field above.
			if m.fileProgress != nil {
				ng.progressID = fmt.Sprintf("%s#out#%d", transferID, nextGroupSeq)
				nextGroupSeq++
				ng.progress = &fileTransferProgress{label: fileName, direction: "↑", peer: groupPeerNames(ng), total: int64(len(ciphertext))}
				ng.progress.setChunks(int64(ng.index), 0, int64(chunkCountTotal))
				m.fileProgress.add(ng.progressID, ng.progress)
			}
			i := 0
			for i < len(groups) && groups[i].index < idx {
				i++
			}
			groups = append(groups, nil)
			copy(groups[i+1:], groups[i:])
			groups[i] = ng
		}
		// mergeAdjacent merges every pair of adjacent groups now at the
		// same index (a straggler that just caught up with the one ahead
		// of it), cascading, until none are left to merge. inFlight
		// pointers still in flight toward the absorbed group are
		// reattached to the destination group: their late isolation (ack
		// never arrived) must remove the member from the group that is
		// ACTUALLY in effect now, not from the one that has since disappeared.
		mergeAdjacent := func() {
			anyMerge := false
			for {
				merged := false
				for i := 0; i < len(groups)-1; i++ {
					if groups[i].index != groups[i+1].index {
						continue
					}
					src, dst := groups[i], groups[i+1]
					for u := range src.members {
						dst.members[u] = true
					}
					for _, info := range inFlight {
						if info.group == src {
							info.group = dst
						}
					}
					// The absorbed group's (src) dedicated row disappears,
					// dst's continues to represent everyone, with the
					// updated name. The front (progressID==transferID)
					// never has a dedicated row to remove here: it is
					// always dst itself when it absorbs someone.
					if src.progress != nil && src.progressID != transferID && m.fileProgress != nil {
						m.fileProgress.remove(src.progressID)
					}
					if dst.progress != nil {
						dst.progress.setPeer(groupPeerNames(dst))
					}
					groups = append(groups[:i], groups[i+1:]...)
					merged, anyMerge = true, true
					break
				}
				if !merged {
					break
				}
			}
			if anyMerge {
				resetSent()
			}
		}
		// pickGroup chooses which group to send the next chunk to, among
		// those with pending work at this moment: the front has work if it
		// has not yet exhausted the ciphertext, a group behind if its
		// index has not yet reached that of the group chasing it (never
		// the front directly, see the comment on groups above). Among the
		// eligible ones it picks the one with the lowest sent/weight ratio
		// (weighted fair scheduling, without floats: cross-multiplied
		// comparison), converges to the 7:3 ratio over time regardless of
		// windowSize.
		pickGroup := func() *sendGroup {
			var best *sendGroup
			var bestWeight uint64
			for i, g := range groups {
				var eligible bool
				weight := uint64(3)
				if i == len(groups)-1 {
					eligible = len(g.members) > 0 && g.index*uint64(chunkSize) < uint64(len(ciphertext))
				} else {
					eligible = len(g.members) > 0 && g.index < groups[i+1].index
					if i == 0 {
						weight = 7
					}
				}
				if !eligible {
					continue
				}
				if best == nil || g.sent*bestWeight < best.sent*weight {
					best, bestWeight = g, weight
				}
			}
			return best
		}
		hasWork := func() bool {
			return pickGroup() != nil
		}

	sendLoop:
		for {
			for len(inFlight) < windowSize && hasWork() {
				g := pickGroup()
				isFront := g == groups[len(groups)-1]
				idx := g.index
				start := int(idx) * chunkSize
				end := start + chunkSize
				if end > len(ciphertext) {
					end = len(ciphertext)
				}
				targets := make([]string, 0, len(g.members))
				waiting := make(map[string]bool, len(g.members))
				for u := range g.members {
					targets = append(targets, u)
					waiting[u] = true
				}
				// tab.ctx, not a ctx captured once at startup: if the
				// SENDER itself reconnects (cmdReconnect/reconnectTab
				// replace tab.ctx with a new context and cancel the old
				// one), a ctx fixed here would stay cancelled forever, and
				// every subsequent send would fail, aborting the entire
				// transfer for all recipients on the sender's first reconnection.
				if err := cli.SendFileChunk(tab.ctx, targets, transferID, idx, ciphertext[start:end]); err != nil {
					if isFront {
						// Local transport failure on the sender's side: the
						// entire goroutine exits, every still-active row
						// (front and any separate group behind) must be
						// marked failed, not just the front's.
						for _, gr := range groups {
							if gr.progress != nil {
								gr.progress.setComplete(true)
							}
						}
						return localDisplayMsg{
							tabIdx:     consoleIdx,
							transferID: transferID,
							text:       styleErr.Render(fmt.Sprintf(i18n.T("tui.err_send_file_generic"), err.Error())),
							isError:    true,
						}
					}
					// Group behind: the connection toward these specific
					// members is down for now, not a local transport
					// failure, retried next round (the group stays eligible).
					continue
				}
				client.Dbg("send_file: transfer=%s seq=%d size=%d targets=%d front=%v", transferID, idx, end-start, len(targets), isFront)
				inFlight[idx] = &inFlightChunk{size: end - start, waiting: waiting, group: g}
				g.sent++
				g.index++
				if g.progress != nil {
					g.progress.setChunks(int64(g.index), 0, int64(chunkCountTotal))
				}
				if !isFront {
					mergeAdjacent()
				}
				if delay > 0 {
					time.Sleep(delay)
				}
			}
			if len(groups) == 0 && len(inFlight) == 0 {
				if progress != nil {
					progress.setComplete(true)
				}
				return localDisplayMsg{tabIdx: consoleIdx, transferID: transferID, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.send_file_no_recipients_left"), fileName)), isError: true}
			}
			// Timeout for this round: the normal ackTimeout while work is
			// in flight; otherwise, all ciphertext sent and confirmed to
			// the recipients known so far, the remaining grace window up
			// to the SAME shared deadline as the original offer
			// (fileTransferOfferTimeout), instead of exiting immediately:
			// a late acceptor (second, third…) still finds this goroutine
			// listening on resumeCh below.
			timeout := ackTimeout
			var pendingDoneCh <-chan struct{}
			if len(inFlight) == 0 {
				timeout = time.Until(deadline)
				if timeout <= 0 {
					break sendLoop
				}
				// pendingDoneCh stays nil (never ready in a select) while
				// work is in flight, only during the post-send wait does
				// it make sense to interrupt it as soon as everyone has
				// responded, never while a send is still active.
				pendingDoneCh = pendingDone
			}
			select {
			case <-pendingDoneCh:
				// All invitees have now responded (accepted or rejected,
				// case "file_accept"/"file_reject" in Update()): no
				// latecomer can arrive anymore, no need to wait out the
				// remaining grace window.
				break sendLoop
			case ev := <-ackCh:
				info, ok := inFlight[ev.seq]
				if !ok || !info.waiting[ev.fromUserID] {
					client.Dbg("send_file: transfer=%s ack discarded seq=%d fromUserID=%s… (not expected)", transferID, ev.seq, client.ShortUID(ev.fromUserID))
					continue
				}
				delete(info.waiting, ev.fromUserID)
				client.Dbg("send_file: transfer=%s ack seq=%d fromUserID=%s… remaining=%d", transferID, ev.seq, client.ShortUID(ev.fromUserID), len(info.waiting))
				if len(info.waiting) == 0 {
					if info.group.progress != nil {
						info.group.progress.addDone(int64(info.size))
					}
					delete(inFlight, ev.seq)
				}
			case ev := <-resumeCh:
				// isNewAccept: this recipient's genuine first acceptance,
				// arriving after sending had already started toward
				// others (the "readmitted" fallback), always restarts
				// from 0, it has nothing yet. Otherwise it is a genuine
				// file_resume (reconnection): honored only if the sender
				// already recognizes it as an acceptor, see
				// fileResumeEvent.isNewAccept and the comment on
				// everAccepted above.
				var idx uint64
				if ev.isNewAccept {
					everAccepted[ev.toUserID] = true
					idx = 0
				} else {
					if !everAccepted[ev.toUserID] {
						continue
					}
					if ev.fromByte < 0 || ev.fromByte > int64(len(ciphertext)) {
						continue
					}
					idx = uint64(ev.fromByte) / uint64(chunkSize)
				}
				delete(isolated, ev.memberKey)
				if len(groups) > 0 {
					if front := groups[len(groups)-1]; idx > front.index {
						idx = front.index
					}
				}
				removeMember(ev.toUserID)
				addMemberAtIndex(idx, ev.toUserID)
				resetSent()
				mergeAdjacent()
			case <-time.After(timeout):
				if len(inFlight) == 0 {
					// Post-send grace window expired: no latecomer showed
					// up by the offer's deadline.
					break sendLoop
				}
				// No progress within the timeout: isolate anyone still
				// waiting on any in-flight chunk, the others continue.
				client.Dbg("send_file: transfer=%s ack timeout (%s), %d chunks still in flight", transferID, ackTimeout, len(inFlight))
				isolatedAny := false
				for sq, info := range inFlight {
					for u := range info.waiting {
						name := cli.LookupUsername(u)
						if name == "" {
							name = client.ShortUID(u)
						}
						isoKey := cli.LookupMemberKey(u)
						if isoKey == "" {
							isoKey = u
						}
						isolated[isoKey] = name
						removeMember(u)
						isolatedAny = true
						client.Dbg("send_file: transfer=%s isolating %s (uid=%s…, seq=%d still unconfirmed)", transferID, name, client.ShortUID(u), sq)
						delete(info.waiting, u)
					}
					if len(info.waiting) == 0 {
						if info.group.progress != nil {
							info.group.progress.addDone(int64(info.size))
						}
						delete(inFlight, sq)
					}
				}
				if isolatedAny {
					resetSent()
				}
			}
		}
		for _, g := range groups {
			if g.progress != nil {
				g.progress.setComplete(false)
			}
		}
		activeUIDs := make(map[string]bool)
		for _, g := range groups {
			for u := range g.members {
				activeUIDs[u] = true
			}
		}
		text := fmt.Sprintf(i18n.T("tui.send_file_complete"), fileName, len(activeUIDs))
		if len(activeUIDs) > 0 {
			activeNames := make([]string, 0, len(activeUIDs))
			for uid := range activeUIDs {
				name := cli.LookupUsername(uid)
				if name == "" {
					name = client.ShortUID(uid)
				}
				activeNames = append(activeNames, name)
			}
			sort.Strings(activeNames)
			text += "\n" + fmt.Sprintf(i18n.T("tui.send_file_complete_recipients"), strings.Join(activeNames, ", "))
		}
		if len(isolated) > 0 {
			names := make([]string, 0, len(isolated))
			for _, name := range isolated {
				names = append(names, name)
			}
			sort.Strings(names)
			text += "\n" + fmt.Sprintf(i18n.T("tui.send_file_isolated"), strings.Join(names, ", "))
		}
		return localDisplayMsg{tabIdx: tabIdx, transferID: transferID, text: styleMeta.Render(text), consoleInfo: true}
	}
}

// decryptFileOfferMeta decrypts {file_name, file_size, file_key} of an
// incoming file_offer in the background, runs in a separate goroutine
// (tea.Cmd) so as not to block the Update() loop while processing the
// hybrid ECIES. myContentKey is OUR ContentKey-per-relationship toward
// the sender (zero value if not yet established, decryptFromContentPeer
// fails explicitly in that case, never a panic).
func decryptFileOfferMeta(myContentKey shared.RelSigningKey, transferID, metaBlobB64 string) tea.Cmd {
	return func() tea.Msg {
		plain, err := decryptFromContentPeer(myContentKey, metaBlobB64)
		if err != nil {
			return fileOfferMetaDecryptedMsg{transferID: transferID, err: err}
		}
		var meta struct {
			FileName   string `json:"file_name"`
			FileSize   int64  `json:"file_size"`
			FileKey    []byte `json:"file_key"`
			ChunkCount int64  `json:"chunk_count"`
		}
		if err := json.Unmarshal(plain, &meta); err != nil {
			return fileOfferMetaDecryptedMsg{transferID: transferID, err: err}
		}
		if meta.ChunkCount <= 0 {
			// Offer from a sender not sending chunk_count: no reliable
			// way to know when numbering is complete, treated as an
			// explicit error instead of guessing.
			return fileOfferMetaDecryptedMsg{transferID: transferID, err: errors.New(i18n.T("tui.err_recv_file_no_chunk_count"))}
		}
		return fileOfferMetaDecryptedMsg{transferID: transferID, fileName: meta.FileName, fileSize: meta.FileSize, fileKey: meta.FileKey, chunkCount: uint64(meta.ChunkCount)}
	}
}

// finalizeIncomingTransfer decrypts+verifies the assembled ciphertext only
// once (never streaming) and, only if the signature is valid, offers to
// save it. The signature is verified with the SENDER's ContentKey toward
// us (same scheme as chat messages), the content decrypted with fileKey
// (from the meta_blob, already decrypted earlier, see decryptFileOfferMeta).
func (m model) finalizeIncomingTransfer(it *incomingFileTransfer) tea.Cmd {
	tabIdx := it.tabIdx
	consoleIdx := m.consoleIdx
	tmpPath := it.tmpPath
	fileName := it.fileName
	declaredHash := it.hash
	fileKey := it.fileKey
	fromUser := m.memberName(m.tabAt(it.tabIdx), it.fromKey)
	progress := it.progress
	// sendVerifyResult notifies the original sender of the FINAL outcome
	// (integrity + decryption), after file_chunk_ack has already proven
	// only transport-level delivery, without this, a failure here would
	// stay visible ONLY in the recipient's Console, and the sender would
	// see "delivered" even for a discarded file. Fire-and-forget, harmless if
	// the sender is no longer reachable, same treatment as
	// SendFileChunkAck/SendFileResume.
	cli := m.tabs[tabIdx].cli
	tabCtx := m.tabs[tabIdx].ctx
	fromUserID := it.fromUserID
	transferID := it.transferID
	sendVerifyResult := func(ok bool) {
		go func() { _ = cli.SendFileVerifyResult(tabCtx, fromUserID, transferID, ok) }()
	}
	return func() tea.Msg {
		defer os.Remove(tmpPath)
		ciphertext, err := os.ReadFile(tmpPath)
		if err != nil {
			if progress != nil {
				progress.setComplete(true)
			}
			sendVerifyResult(false)
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_recv_file_read"), fromUser, err.Error())), isError: true}
		}
		// No signature to re-verify here, authenticity was already
		// established at announce time, BEFORE a single chunk arrived
		// (case "file_announce"). What remains here is only an integrity
		// comparison (transport corruption/tampering, never a mismatched
		// key issue, that is filtered upstream).
		actualHash := sha256.Sum256(ciphertext)
		if !bytes.Equal(actualHash[:], declaredHash) {
			if progress != nil {
				progress.setComplete(true)
			}
			sendVerifyResult(false)
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_recv_file_hash_mismatch"), fromUser, fileName)), isError: true}
		}
		encB64 := base64.StdEncoding.EncodeToString(ciphertext)
		tagged, err := shared.Decrypt(fileKey, encB64, nil)
		if err != nil {
			if progress != nil {
				progress.setComplete(true)
			}
			sendVerifyResult(false)
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_recv_file_decrypt"), fromUser, err.Error())), isError: true}
		}
		plaintext, err := shared.UnpackData(tagged)
		if err != nil {
			if progress != nil {
				progress.setComplete(true)
			}
			sendVerifyResult(false)
			return localDisplayMsg{tabIdx: consoleIdx, text: styleErr.Render(fmt.Sprintf(i18n.T("tui.err_recv_file_decrypt"), fromUser, err.Error())), isError: true}
		}
		if progress != nil {
			progress.setComplete(false)
		}
		sendVerifyResult(true)
		return fileReadyToSaveMsg{tabIdx: tabIdx, fileName: fileName, data: plaintext}
	}
}

// uniqueDestPath avoids silently overwriting an existing file: appends a
// numeric suffix instead of asking for confirmation, safe, no data lost,
// one fewer popup.
func uniqueDestPath(dir, name string) string {
	dest := filepath.Join(dir, name)
	if _, err := os.Stat(dest); err != nil {
		return dest
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", base, i, ext))
		if _, err := os.Stat(candidate); err != nil {
			return candidate
		}
	}
}

// renderFilePresetPicker shows the two speed presets ("slow" default,
// "warp" explicit), Up/Down toggles, Enter confirms the highlighted one.
// renderShowQRFormatPicker shows /show-qr's two output choices, "save
// as image" default (idx 0), "animated" (idx 1), same two choices as
// `neutrino show-qr`'s CLI prompt. Up/Down toggles, Enter confirms.
func (m model) renderShowQRFormatPicker() string {
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.show_qr_format_title")))
	sb.WriteString("\n\n")
	labels := []string{
		i18n.T("tui.show_qr_format_image"),
		i18n.T("tui.show_qr_format_video"),
	}
	for i, label := range labels {
		if i == m.showQRFormatIdx {
			sb.WriteString("  " + stylePaletteSel.Render(label))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(label))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.show_qr_format_hint")))
	return m.renderBoxPopup(sb.String())
}

func (m model) renderFilePresetPicker() string {
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.send_file_preset_title")))
	sb.WriteString("\n\n")
	labels := []string{
		i18n.T("tui.send_file_preset_slow"),
		i18n.T("tui.send_file_preset_warp"),
	}
	for i, label := range labels {
		if i == m.sendFilePresetIdx {
			sb.WriteString("  " + stylePaletteSel.Render(label))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(label))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	compressBox := "[ ]"
	if m.sendFileCompressOn {
		compressBox = "[x]"
	}
	sb.WriteString("  " + stylePaletteDesc.Render(compressBox+" "+i18n.T("tui.send_file_compress_label")))
	sb.WriteString("\n\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.send_file_preset_hint")))
	return m.renderBoxPopup(sb.String())
}

// renderFileOfferPopup shows sender/name/size and whether a ContentKey
// relationship is already established with the sender, an immediate
// check, not yet the cryptographic signature verification (which requires
// the full ciphertext, happening only once the transfer is complete,
// before saving).
func (m model) renderFileOfferPopup() string {
	var relLine string
	if m.fileOfferContentKeyKnown {
		pub, _, _, _, _ := m.contentPeerKeysFor(m.tabs[m.fileOfferTabIdx], m.fileOfferFromKey)
		hex := fmt.Sprintf("%x", pub)
		if len(hex) > 8 {
			hex = hex[len(hex)-8:]
		}
		relLine = styleOwnMsg.Render(i18n.T("tui.rel_established_tag", hex))
	} else {
		relLine = styleErr.Render(i18n.T("tui.recv_file_rel_unknown"))
	}
	sizeKiB := m.fileOfferFileSize / 1024
	popupContent := strings.Join([]string{
		i18n.T("tui.recv_file_offer_title"),
		"",
		fmt.Sprintf(i18n.T("tui.recv_file_offer_from"), m.memberName(m.tabAt(m.fileOfferTabIdx), m.fileOfferFromKey)),
		fmt.Sprintf(i18n.T("tui.recv_file_offer_name"), m.fileOfferFileName),
		fmt.Sprintf(i18n.T("tui.recv_file_offer_size"), sizeKiB),
		relLine,
		"",
		i18n.T("tui.recv_file_offer_hint"),
	}, "\n")
	return m.renderBoxPopup(popupContent)
}

// renderFileProgressView draws the "File" tab's content: one row per
// transfer (send ↑ or receive ↓), sftp/scp-style, no colors, only
// numbers, percentage right-aligned after a fixed 3-dot leader, read
// from fileTransferProgress, written by a goroutine outside the Update
// loop (see tickFileProgressMsg for why an explicit tick is needed).
func (m model) renderFileProgressView() string {
	entries := m.fileProgress.snapshot()
	if len(entries) == 0 {
		return styleMeta.Render(i18n.T("tui.files_tab_empty"))
	}
	var sb strings.Builder
	for _, e := range entries {
		label, direction, peer, total, done, failed, complete, chunksDone, chunksPending, chunksTotal := e.snapshot()
		from, to := m.myUsername, peer
		if direction == "↓" {
			from, to = peer, m.myUsername
		}

		var tail string
		switch {
		case complete && failed:
			tail = i18n.T("tui.files_tab_failed")
		case complete:
			tail = "100%"
		default:
			var pct float64
			if total > 0 {
				pct = float64(done) / float64(total)
			}
			if pct > 1 {
				pct = 1
			}
			tail = fmt.Sprintf("%3.0f%%", pct*100)
		}

		// Chunk-level detail (see the comment on the same-named fields on
		// fileTransferProgress), absent until chunksTotal is known
		// (offer/meta_blob not yet decrypted), never a misleading "0/0".
		var chunkDetail string
		if chunksTotal > 0 {
			if direction == "↓" {
				chunkDetail = " - " + fmt.Sprintf(i18n.T("tui.files_tab_chunks_received"), chunksDone, chunksPending, chunksTotal)
			} else {
				chunkDetail = " - " + fmt.Sprintf(i18n.T("tui.files_tab_chunks_sent"), chunksDone, chunksTotal)
			}
		}

		sb.WriteString(fmt.Sprintf("%s %s %s %s ...%s%s\n", direction, from, label, to, tail, chunkDetail))
	}
	return sb.String()
}

// renderSendFileBrowser draws the /grp-file-send filesystem-browser popup,
// same typed-filter scheme as renderContactPicker (tui.picker_filter_label,
// tui.picker_no_results), but with directory navigation instead of a flat list.
func (m model) renderSendFileBrowser() string {
	items := m.sendFileFilteredEntries()
	const maxVisible = 12

	var sb strings.Builder
	sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_browser_title"), m.sendFileDir)))
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.picker_filter_label"), m.sendFileFilter)))
	sb.WriteString("\n\n")

	if len(items) == 0 {
		sb.WriteString(styleMeta.Render(i18n.T("tui.picker_no_results")))
		sb.WriteString("\n")
	} else {
		start := 0
		if m.sendFileIdx >= maxVisible {
			start = m.sendFileIdx - maxVisible + 1
		}
		end := start + maxVisible
		if end > len(items) {
			end = len(items)
		}
		for i := start; i < end; i++ {
			label := items[i].name
			if items[i].isDir {
				label += "/"
			}
			if i == m.sendFileIdx {
				sb.WriteString("  " + stylePaletteSel.Render(label))
			} else {
				sb.WriteString("  " + stylePaletteDesc.Render(label))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.send_file_browser_hint")))
	return sb.String()
}

// renderQRFileBrowser draws the filesystem-browser popup for
// /cnt-read-qrcode's "file" source, same navigation as
// renderSendFileBrowser, plus a "[ ]"/"[x]" checkbox per entry (Space
// toggles it) for picking several numbered QR images at once instead of
// one at a time, mirroring renderFileRecipientsPicker's checkbox style.
func (m model) renderQRFileBrowser() string {
	items := m.qrFileFilteredEntries()
	const maxVisible = 12

	var sb strings.Builder
	sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.send_file_browser_title"), m.qrFileDir)))
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.picker_filter_label"), m.qrFileFilter)))
	sb.WriteString("\n\n")

	if len(items) == 0 {
		sb.WriteString(styleMeta.Render(i18n.T("tui.picker_no_results")))
		sb.WriteString("\n")
	} else {
		selected := make(map[string]bool, len(m.qrFileSelected))
		for _, p := range m.qrFileSelected {
			selected[p] = true
		}
		start := 0
		if m.qrFileIdx >= maxVisible {
			start = m.qrFileIdx - maxVisible + 1
		}
		end := start + maxVisible
		if end > len(items) {
			end = len(items)
		}
		for i := start; i < end; i++ {
			label := items[i].name
			if items[i].isDir {
				label += "/"
			} else {
				box := "[ ]"
				if selected[filepath.Join(m.qrFileDir, items[i].name)] {
					box = "[x]"
				}
				label = box + " " + label
			}
			if i == m.qrFileIdx {
				sb.WriteString("  " + stylePaletteSel.Render(label))
			} else {
				sb.WriteString("  " + stylePaletteDesc.Render(label))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	if len(m.qrFileSelected) > 0 {
		sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.read_qr_file_browser_selected"), len(m.qrFileSelected))))
		sb.WriteString("\n")
	}
	sb.WriteString(styleMeta.Render(i18n.T("tui.read_qr_file_browser_hint")))
	return sb.String()
}

// renderFileRecipientsPicker shows present members with an established
// relationship, preselected; Space deselects, Enter confirms, Esc cancels
// the entire /grp-file-send flow. Style consistent with renderContactPicker.
func (m model) renderFileRecipientsPicker() string {
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.send_file_recipients_title")))
	sb.WriteString("\n\n")
	tab := m.tabAt(m.sendFileTabIdx)
	for i, u := range m.sendFileCandidates {
		box := "[ ]"
		if m.sendFileSelected[u] {
			box = "[x]"
		}
		label := box + " " + m.memberName(tab, u)
		if i == m.sendFileRecipientsIdx {
			sb.WriteString("  " + stylePaletteSel.Render(label))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(label))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.send_file_recipients_hint")))
	return m.renderBoxPopup(sb.String())
}

// inviteFilteredCandidates returns m.inviteCandidates filtered by the
// text typed into m.inviteFilter (local name or username,
// case-insensitive), same matching criterion as pickerItems' generic
// branch. m.inviteSelected stays indexed by picker key and is unaffected by
// the filter: hiding/showing entries does not touch selection already made.
func (m model) inviteFilteredCandidates() []string {
	filter := strings.ToLower(m.inviteFilter)
	if filter == "" {
		return m.inviteCandidates
	}
	out := make([]string, 0, len(m.inviteCandidates))
	for _, u := range m.inviteCandidates {
		display := u
		if c := m.resolveNameOrPickerKey(u); c != nil {
			display = c.LocalName + " " + c.Username
		}
		if strings.Contains(strings.ToLower(display), filter) {
			out = append(out, u)
		}
	}
	return out
}

// renderInvitePicker shows every contact in the address book, none
// preselected; Space selects, Enter confirms (invites only the selected
// ones), Esc cancels, typing filters by name, Space stays dedicated to
// selection, it does not enter the filter text (unlike the single-select
// picker for /cnt-info, /cnt-edit, etc., where Space has no other action
// to perform). Same interaction scheme as renderFileRecipientsPicker, but
// opt-in instead of opt-out.
func (m model) renderInvitePicker() string {
	items := m.inviteFilteredCandidates()
	const maxVisible = 10
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.invite_picker_title")))
	sb.WriteString("\n")
	filterLine := fmt.Sprintf(i18n.T("tui.picker_filter_label"), m.inviteFilter)
	sb.WriteString(styleMeta.Render(filterLine))
	sb.WriteString("\n\n")
	if len(items) == 0 {
		sb.WriteString(styleMeta.Render(i18n.T("tui.picker_no_results")))
		sb.WriteString("\n")
	} else {
		start := 0
		if m.inviteIdx >= maxVisible {
			start = m.inviteIdx - maxVisible + 1
		}
		end := start + maxVisible
		if end > len(items) {
			end = len(items)
		}
		for i := start; i < end; i++ {
			u := items[i]
			box := "[ ]"
			if m.inviteSelected[u] {
				box = "[x]"
			}
			// The already-established ContentKey relationship (if any) is
			// shown here on purpose: before selecting members for a new
			// group it is better to already know who will be able to
			// receive files (/grp-file-send requires an established
			// relationship with each recipient) rather than discovering
			// it only at send time, with the group already created.
			name := u
			relTag := i18n.T("tui.invite_picker_no_rel")
			if c := m.resolveNameOrPickerKey(u); c != nil {
				// Same structure as renderContactLine (Contacts tab): local
				// name in quotes (placeholder if unset) plus the real
				// username in parentheses, not NameWithUsername(), which
				// instead omits the parentheses when the local name is
				// missing and leaves rows misaligned. Unlike the Contacts tab,
				// this does NOT use a fixed-width padName: a popup can end
				// up on a much narrower terminal (Android/Termux), and a
				// forced 14+14 columns would overflow the line and wrap,
				// truncName only sets an upper cap, at natural length.
				localPart := `"…"`
				if c.LocalName != "" {
					localPart = `"` + truncName(c.LocalName, maxLocalNameLen) + `"`
				}
				name = localPart + " (" + truncName(c.Username, maxUsernameDisplayLen) + ")"
				if dev, ok := c.RelEstablishedDevice(); ok {
					hex := fmt.Sprintf("%x", dev.PeerRelContentPub)
					if len(hex) > 8 {
						hex = hex[len(hex)-8:]
					}
					relTag = "[REL:" + hex + "]"
				} else if c.RelRevoked() {
					relTag = "[REVOKED]"
				}
			}
			label := box + " " + name + "  " + relTag
			if i == m.inviteIdx {
				sb.WriteString("  " + stylePaletteSel.Render(label))
			} else {
				sb.WriteString("  " + stylePaletteDesc.Render(label))
			}
			sb.WriteString("\n")
		}
		if len(items) > maxVisible {
			sb.WriteString(styleMeta.Render(fmt.Sprintf("  … %d/%d", m.inviteIdx+1, len(items))))
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.invite_picker_hint")))
	return m.renderBoxPopup(sb.String())
}

// renderPingPicker shows the current room's members (self excluded) to
// choose who to ping, Enter immediately confirms the highlighted one,
// Esc cancels, single selection (no Space/multi-select unlike renderInvitePicker).
func (m model) renderPingPicker() string {
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.ping_picker_title")))
	sb.WriteString("\n\n")
	tab := m.tabs[m.active]
	for i, u := range m.pingCandidates {
		name := m.memberName(tab, u)
		if i == m.pingPickerIdx {
			sb.WriteString("  " + stylePaletteSel.Render(name))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(name))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.ping_picker_hint")))
	return m.renderBoxPopup(sb.String())
}

// renderRemoteNukePicker shows the known devices (Keystore.KnownDevices,
// populated by "indoor" sync) to choose the target of a remote_nuke
// command, Enter moves to explicit confirmation (never a direct send
// from here), Esc cancels, single selection.
func (m model) renderRemoteNukePicker() string {
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.remote_nuke_picker_title")))
	sb.WriteString("\n\n")
	for i, rec := range m.knownDevicesNow() {
		label := rec.Label
		if label == "" {
			label = hex.EncodeToString(rec.DeviceID)
		}
		names := make([]string, 0, len(rec.SiblingIdentities))
		for _, ref := range rec.SiblingIdentities {
			names = append(names, ref.Username)
		}
		line := label
		if len(names) > 0 {
			line += " (" + strings.Join(names, ", ") + ")"
		}
		if i == m.remoteNukePickerIdx {
			sb.WriteString("  " + stylePaletteSel.Render(line))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(line))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.remote_nuke_picker_hint")))
	return m.renderBoxPopup(sb.String())
}

// cmdRemoteNukeTrigger opens the picker over Keystore.KnownDevices, no
// text-argument resolution (a device has no name as convenient to type as
// a contact's), always a picker if there is at least one.
func (m *model) cmdRemoteNukeTrigger() tea.Cmd {
	if len(m.knownDevicesNow()) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_remote_nuke_no_known_devices")))
	}
	m.remoteNukePickerIdx = 0
	m.remoteNukePickerMode = true
	return nil
}

// msgAcksMaxCandidates limits how many of our own recent messages the
// /grp-msg-acks picker offers, only the most recent ones are practical
// to check, a history of thousands of messages must not turn into an
// equally long list to scroll through.
const msgAcksMaxCandidates = 20

// cmdMsgAcksTrigger opens the picker over the most recent messages sent
// BY US in this room (up to msgAcksMaxCandidates, most recent first), no
// text-argument resolution (a message has no convenient name to type),
// always a picker if there is at least one.
func (m *model) cmdMsgAcksTrigger() tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	isChatTab := !tab.isConsole && !tab.isContacts && !tab.isGroups && !tab.isTor && !tab.isFiles
	if !isChatTab {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_msg_acks_usage")))
	}
	var candidates []int
	for i := len(tab.lines) - 1; i >= 0 && len(candidates) < msgAcksMaxCandidates; i-- {
		if tab.lines[i].msgID != 0 {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_msg_acks_none")))
	}
	m.msgAcksCandidates = candidates
	m.msgAcksPickerIdx = 0
	m.msgAcksPickerMode = true
	return nil
}

// msgAcksPreviewLen truncates the message text preview shown in the
// picker, only to recognize which message is which, not to reread it in
// full (already visible by scrolling the room).
const msgAcksPreviewLen = 40

func msgAcksPreview(text string) string {
	r := []rune(text)
	if len(r) <= msgAcksPreviewLen {
		return text
	}
	return string(r[:msgAcksPreviewLen]) + "…"
}

// renderMsgAcksPicker shows this room's most recent own messages
// (m.msgAcksCandidates, indices into tab.lines) to choose which one to see
// the ack detail for, Enter confirms, Esc cancels, single selection.
func (m model) renderMsgAcksPicker() string {
	tab := m.tabs[m.active]
	var sb strings.Builder
	sb.WriteString(styleMeta.Render(i18n.T("tui.msg_acks_picker_title")))
	sb.WriteString("\n\n")
	for i, lineIdx := range m.msgAcksCandidates {
		if lineIdx >= len(tab.lines) {
			continue
		}
		l := tab.lines[lineIdx]
		line := l.timestamp + " " + msgAcksPreview(l.text)
		if i == m.msgAcksPickerIdx {
			sb.WriteString("  " + stylePaletteSel.Render(line))
		} else {
			sb.WriteString("  " + stylePaletteDesc.Render(line))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.msg_acks_picker_hint")))
	return m.renderBoxPopup(sb.String())
}

// renderMsgAcksDetail shows, for the chosen message
// (m.msgAcksDetailLineIdx, an index into tab.lines), which room members
// (self excluded) have confirmed receipt and which have not, a direct
// comparison between chatLine.ackers and tab.groupMembers, read-only.
func (m model) renderMsgAcksDetail() string {
	tab := m.tabs[m.active]
	if m.msgAcksDetailLineIdx >= len(tab.lines) {
		return m.renderBoxPopup(styleErr.Render(i18n.T("tui.err_msg_acks_none")))
	}
	l := tab.lines[m.msgAcksDetailLineIdx]

	var confirmed, pending []string
	for _, mem := range tab.groupMembers {
		mk := memberKey(mem)
		if mk == m.myKey() {
			continue
		}
		if l.ackers[mk] {
			confirmed = append(confirmed, m.memberName(tab, mk))
		} else {
			pending = append(pending, m.memberName(tab, mk))
		}
	}

	var sb strings.Builder
	sb.WriteString(styleMeta.Render(fmt.Sprintf(i18n.T("tui.msg_acks_detail_title"), l.timestamp, msgAcksPreview(l.text))))
	sb.WriteString("\n\n")
	sb.WriteString(styleOwnMsg.Render(i18n.T("tui.msg_acks_confirmed_label")))
	sb.WriteString("\n  ")
	if len(confirmed) == 0 {
		sb.WriteString(styleMeta.Render(i18n.T("tui.none_label")))
	} else {
		sb.WriteString(strings.Join(confirmed, ", "))
	}
	sb.WriteString("\n\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.msg_acks_pending_label")))
	sb.WriteString("\n  ")
	if len(pending) == 0 {
		sb.WriteString(styleMeta.Render(i18n.T("tui.none_label")))
	} else {
		sb.WriteString(strings.Join(pending, ", "))
	}
	sb.WriteString("\n\n")
	sb.WriteString(styleMeta.Render(i18n.T("tui.msg_acks_detail_hint")))
	return m.renderBoxPopup(sb.String())
}

func (m *model) cmdSaveCard() tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.pendingCard == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_no_pending_card")))
	}
	card := tab.pendingCard
	cardFrom := tab.pendingCardFrom
	tab.pendingCard = nil
	tab.pendingCardFrom = ""
	m.tabs[tabIdx] = tab
	pubBytes, err := base64.StdEncoding.DecodeString(card.IdentityPub)
	if err != nil || len(pubBytes) != 32 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_card_invalid_pubkey")))
	}
	if bytes.Equal(pubBytes, m.myIdentityPub) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_cannot_add_self")))
	}
	if m.contactExists(pubBytes) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_already_in_book"), card.Username)))
	}
	m.pendingContact.username = card.Username
	m.pendingContact.pubBytes = pubBytes
	m.pendingContact.mlkemPub = card.MLKEMPub
	m.pendingContact.mldsaPub = card.MLDSAPub
	m.pendingContact.tabIdx = tabIdx
	m.pendingContact.cardFrom = cardFrom
	m.addContactMode = true
	m.addContactBuf = card.LocalName
	return nil
}

func (m *model) cmdIgnoreCard() tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.pendingCard == nil {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_no_pending_card")))
	}
	m.tabs[tabIdx].pendingCard = nil
	m.tabs[tabIdx].pendingCardFrom = ""
	return localTab(tabIdx, styleMeta.Render(i18n.T("tui.card_discarded")))
}

// cmdPing measures the RTT toward a member of the current room. With an
// argument that resolves to a present member it pings that one directly
// (also resolved from a local name); otherwise (no argument, or one that
// matches nobody) it opens the picker to choose among everyone present,
// a room of 100 contacts is pinged one at a time, it is not a bulk operation.
func (m *model) cmdPing(arg string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]

	isChatTab := !tab.isConsole && !tab.isContacts && !tab.isGroups && !tab.isTor && !tab.isFiles
	if !isChatTab {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ping_usage")))
	}

	notSelf := func(gm GroupMember) bool { return memberKey(gm) != m.myKey() }
	candidates := make([]string, 0, len(tab.groupMembers))
	for _, mem := range tab.groupMembers {
		if notSelf(mem) {
			candidates = append(candidates, memberKey(mem))
		}
	}
	if len(candidates) == 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ping_no_members")))
	}

	if arg != "" {
		if mem, n := m.resolveMemberArg(tab, arg, notSelf); n == 1 {
			return m.doPing(tabIdx, memberKey(mem))
		}
		// arg matches no member, or more than one: opens the picker
		// instead of a blunt error, same principle as the other commands
		// with a contact/group parameter (see openPicker).
	}

	m.pingCandidates = candidates
	m.pingPickerIdx = 0
	m.pingPickerMode = true
	return nil
}

// doPing actually sends the probes toward the member with key peerKey
// in room tabIdx, extracted from cmdPing since it is shared with the
// picker selection.
func (m *model) doPing(tabIdx int, peerKey string) tea.Cmd {
	tab := m.tabs[tabIdx]
	locIdx := m.defaultTabIdx()
	peerName := m.memberName(tab, peerKey)

	var peerUID string
	if tab.cli != nil {
		peerUID = tab.cli.LookupUserID(peerKey)
	}
	if peerUID == "" {
		return consoleErrTab(m.consoleIdx, styleErr.Render(fmt.Sprintf(i18n.T("tui.err_peer_not_connected_yet"), peerName)))
	}
	if m.pingTotal > 0 {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_ping_in_progress")))
	}

	const nProbes = 5
	cli := tab.cli
	ctx := tab.ctx

	// Pre-allocate the sequence numbers in the model's window (event loop → no race).
	seqBase := client.PingSeqBase()
	for i := range uint64(nProbes) {
		m.pingPending[seqBase+i] = struct{}{}
	}
	m.pingTotal = nProbes
	m.pingTabIdx = locIdx
	m.pingRTTs = m.pingRTTs[:0]

	m.textPopupContent = fmt.Sprintf(i18n.T("tui.ping_start"), peerName, nProbes)
	m.textPopupMode = true

	return func() tea.Msg {
		for i := range uint64(nProbes) {
			sentAt := time.Now().UnixNano()
			_ = cli.SendPingProbe(ctx, peerUID, seqBase+i, sentAt)
			if i < nProbes-1 {
				time.Sleep(1 * time.Second)
			}
		}
		return nil
	}
}

// cmdSafety shows the safety code of the current tab or of a specified contact.
func (m *model) cmdSafety(arg string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]
	if tab.safetyCode != "" {
		name := tab.name
		if c := m.resolveContactByPub(tab.peerIdentityPub); c != nil {
			name = c.NameWithUsername()
		}
		m.textPopupContent = fmt.Sprintf(i18n.T("tui.safety_code_with"), name, tab.safetyCode)
		m.textPopupMode = true
		return nil
	}
	if arg != "" {
		if len(m.myIdentityPub) != 32 {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_safety_code_unavailable")))
		}
		contact := m.resolveNameOrPickerKey(arg)
		if contact != nil && len(contact.IdentityPub) == 32 {
			code := shared.SafetyCode(m.myIdentityPub, contact.IdentityPub)
			m.textPopupContent = fmt.Sprintf(i18n.T("tui.safety_code_with"), contact.NameWithUsername(), code)
			m.textPopupMode = true
			return nil
		}
		return m.openPicker(client.CmdSafety, arg)
	}
	return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_safety_code_unavailable")))
}

// applyVerification marks target as Verified. contactPub is the
// IdentityPub of the contact chosen in /sec-verify (a snapshot taken
// before this call, see verifySafetyConfirmContactPub), the only
// identifier used; target is a display label.
func (m *model) applyVerification(target string, contactPub []byte) tea.Cmd {
	if len(contactPub) != ed25519.PublicKeySize {
		return nil
	}
	if m.markContactVerifiedByPub != nil {
		if err := m.markContactVerifiedByPub(contactPub); err == nil {
			if c := m.resolveContactByPub(contactPub); c != nil {
				c.Verified = true
			}
		}
	}
	return localTab(m.defaultTabIdx(), styleOwnMsg.Render(fmt.Sprintf(i18n.T("tui.verify_safety_confirmed"), target)))
}

// startRelDangerConfirm prepares the y/n confirmation for a relationship
// key conflict (TrustDanger), called by cmdVerifySafety when the
// resolved contact has pending keys. Unlike the normal Safety Number
// (root identity, unchanged in this scenario), it shows two codes
// computed on the PENDING relationship keys, the exact same
// out-of-band comparison principle, never inside the app.
func (m *model) startRelDangerConfirm(contact *ContactInfo) tea.Cmd {
	display := contact.DisplayName()
	if contact.LocalName != "" {
		display = contact.LocalName + " (" + contact.Username + ")"
	}
	var codeIdentity, codeContent string
	if _, dev, ok := contact.DeviceWithPendingRelKeys(); ok {
		if len(dev.RelIdentityPriv) == ed25519.PrivateKeySize && len(dev.PendingPeerRelIdentityPub) == ed25519.PublicKeySize {
			myPub, _ := ed25519.PrivateKey(dev.RelIdentityPriv).Public().(ed25519.PublicKey)
			codeIdentity = shared.SafetyCode(myPub, ed25519.PublicKey(dev.PendingPeerRelIdentityPub))
		}
		if len(dev.RelContentPriv) == ed25519.PrivateKeySize && len(dev.PendingPeerRelContentPub) == ed25519.PublicKeySize {
			myPub, _ := ed25519.PrivateKey(dev.RelContentPriv).Public().(ed25519.PublicKey)
			codeContent = shared.SafetyCode(myPub, ed25519.PublicKey(dev.PendingPeerRelContentPub))
		}
	}
	intro := fmt.Sprintf(i18n.T("tui.verify_rel_danger_intro"), display, codeIdentity, codeContent, display)
	m.verifySafetyConfirmContactPub = contact.IdentityPub
	m.verifySafetyConfirmRelDanger = true
	m.verifySafetyPopupContent = intro
	m.verifySafetyConfirmMode = true
	m.verifySafetyConfirmTarget = contact.Username
	return nil
}

// applyPendingRelKeysConfirmation closes a relationship key conflict
// (TrustDanger) after the user's explicit y/n confirmation: applies the
// pending keys (keystore.ConfirmPendingRelKeys), clears Verified, the
// previous trust level applied to the old keys, it must be regained with
// a second /sec-verify, and immediately updates the local mirror.
func (m *model) applyPendingRelKeysConfirmation(target string, contactPub []byte) tea.Cmd {
	if len(contactPub) != ed25519.PublicKeySize || m.confirmPendingRelKeys == nil || !m.confirmPendingRelKeys(contactPub) {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_safety_code_unavailable")))
	}
	c := m.resolveContactByPub(contactPub)
	if c == nil {
		return localTab(m.defaultTabIdx(), styleOwnMsg.Render(fmt.Sprintf(i18n.T("tui.verify_rel_danger_confirmed"), target)))
	}
	_, dev, ok := c.DeviceWithPendingRelKeys()
	if !ok {
		return localTab(m.defaultTabIdx(), styleOwnMsg.Render(fmt.Sprintf(i18n.T("tui.verify_rel_danger_confirmed"), target)))
	}
	if len(dev.PendingPeerRelIdentityPub) > 0 {
		dev.PeerRelIdentityPub = dev.PendingPeerRelIdentityPub
		dev.PeerRelIdentityMLKEMPub = dev.PendingPeerRelIdentityMLKEMPub
		dev.PeerRelIdentityMLDSAPub = dev.PendingPeerRelIdentityMLDSAPub
	}
	if len(dev.PendingPeerRelContentPub) > 0 {
		dev.PeerRelContentPub = dev.PendingPeerRelContentPub
		dev.PeerRelContentMLKEMPub = dev.PendingPeerRelContentMLKEMPub
		dev.PeerRelContentMLDSAPub = dev.PendingPeerRelContentMLDSAPub
	}
	dev.PendingPeerRelIdentityPub = nil
	dev.PendingPeerRelIdentityMLKEMPub = nil
	dev.PendingPeerRelIdentityMLDSAPub = nil
	dev.PendingPeerRelContentPub = nil
	dev.PendingPeerRelContentMLKEMPub = nil
	dev.PendingPeerRelContentMLDSAPub = nil
	c.Verified = false
	// No explicit refresh needed here: m.confirmPendingRelKeys above has
	// already persisted the accepted keys in keystore.Contact BEFORE this
	// line, the RoomRegistry of a room already open with this contact
	// resolves them live on the next ClientHello.Sig, never a cached copy.
	return localTab(m.defaultTabIdx(), styleOwnMsg.Render(fmt.Sprintf(i18n.T("tui.verify_rel_danger_confirmed"), target)))
}

// cmdVerifySafety starts the full safety-number verification: shows
// the whole code in the tab (not a popup dismissible with any key,
// because right after it only needs to intercept y/n) with the
// instruction to compare it in full with the contact over a secure
// external channel (phone call, video, in person), never inside the
// app, because whoever controls that same connection would respond
// exactly as the real contact would, without actually being the expected
// person. On the user's explicit y/n confirmation, the contact is marked
// "Verified" in the keystore.
func (m *model) cmdVerifySafety(arg string) tea.Cmd {
	tabIdx := m.active
	tab := m.tabs[tabIdx]

	var username, display, code string
	var contactPub []byte
	if tab.safetyCode != "" && arg == "" {
		username, display, code = tab.name, tab.name, tab.safetyCode
		contactPub = tab.peerIdentityPub
		if c := m.resolveContactByPub(tab.peerIdentityPub); c != nil {
			// Relationship key conflict (TrustDanger): its own
			// confirmation, on the pending relationship keys.
			if c.TrustLevel() == TrustDanger {
				return m.startRelDangerConfirm(c)
			}
			username = c.Username
			display = c.DisplayName()
			if c.LocalName != "" {
				display = c.LocalName + " (" + c.Username + ")"
			}
			contactPub = c.IdentityPub
		}
	} else if arg != "" {
		if len(m.myIdentityPub) != 32 {
			return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_safety_code_unavailable")))
		}
		contact := m.resolveNameOrPickerKey(arg)
		if contact == nil || len(contact.IdentityPub) != 32 {
			return m.openPicker(client.CmdVerifySafety, arg)
		}
		if contact.TrustLevel() == TrustDanger {
			return m.startRelDangerConfirm(contact)
		}
		username = contact.Username
		display = contact.DisplayName()
		if contact.LocalName != "" {
			display = contact.LocalName + " (" + contact.Username + ")"
		}
		contactPub = contact.IdentityPub
		code = shared.SafetyCode(m.myIdentityPub, contactPub)
	} else {
		return consoleErrTab(m.consoleIdx, styleErr.Render(i18n.T("tui.err_safety_code_unavailable")))
	}

	// The code must be shown inside the confirmation popup itself (not as
	// a persistent row in a tab): closing with the y/n answer leaves no
	// trace in any tab's history, consistent with it being data to read
	// over the phone/in person, not to keep in the message history.
	intro := fmt.Sprintf(i18n.T("tui.verify_safety_intro"), display, code, display)
	m.verifySafetyConfirmContactPub = contactPub
	m.verifySafetyPopupContent = intro
	m.verifySafetyConfirmMode = true
	m.verifySafetyConfirmTarget = username
	return nil
}

// cmdUnverify removes the Verified mark from a contact, resolved by
// identity key, the inverse of /sec-verify. With no argument, or one
// that doesn't resolve to exactly one contact, it opens the picker of
// verified contacts.
func (m *model) cmdUnverify(arg string) tea.Cmd {
	contact := m.resolveNameOrPickerKey(arg)
	if contact == nil {
		return m.openPicker(client.CmdUnverifySafety, arg)
	}
	name := contact.NameWithUsername()
	if !contact.Verified {
		return localTab(m.defaultTabIdx(), styleMeta.Render(fmt.Sprintf(i18n.T("tui.unverify_not_verified"), name)))
	}
	if m.markContactUnverifiedByPub != nil {
		if err := m.markContactUnverifiedByPub(contact.IdentityPub); err != nil {
			return consoleErrTab(m.consoleIdx, styleErr.Render(err.Error()))
		}
	}
	contact.Verified = false
	return localTab(m.defaultTabIdx(), styleOwnMsg.Render(fmt.Sprintf(i18n.T("tui.unverify_done"), name)))
}

// renderGroupBar builds the "● user1  ● user2  …" row for group tabs.
// contentRelEstablished (a ContentKey relationship established in both
// directions with that member) decides whether the name is green or
// yellow (connected, but the only available guarantee is the Safety Number).
func (m model) renderGroupBar(tab *roomTab, width int) string {
	if len(tab.groupMembers) == 0 {
		return ""
	}
	// resolves the display name from the local contact, by key
	resolveName := func(mem GroupMember) string {
		if c := m.resolveContactByPub(mem.IdentityPub); c != nil {
			return c.DisplayName()
		}
		return m.memberName(tab, memberKey(mem))
	}
	type entry struct {
		rendered string
		plainLen int // "● " + name, without ANSI escapes
	}
	entries := make([]entry, 0, len(tab.groupMembers))
	for _, mem := range tab.groupMembers {
		key := memberKey(mem)
		name := resolveName(mem)
		isSelf := key == m.myKey()
		isConn := tab.isOnline(key)
		var rendered string
		switch {
		// Our own entry can never pass contentRelEstablished (we are
		// never our own contact): cryptographically verifying our own identity with
		// ourselves makes no sense. Name in a dedicated color (cyan, same
		// as our own "me" in chat messages) instead of the green used for
		// other verified members, still connected, so the dot is green
		// like anyone else online.
		case isConn && isSelf:
			rendered = styleOwnMsg.Render("●") + " " + stylePeerMsg.Render(name)
		case isConn && m.contentRelEstablished(tab, key):
			// connected and with an established ContentKey relationship: green dot + green name
			rendered = styleOwnMsg.Render("●") + " " + styleOwnMsg.Render(name)
		case isConn:
			// connected but without an established ContentKey relationship (only Safety Number available): green dot + yellow name
			rendered = styleOwnMsg.Render("●") + " " + styleWarnName.Render(name)
		default:
			// offline: dot always red; name gray if left/declined/banned, red if crashed
			st := memberCrashed
			if tab.departures != nil {
				st = tab.departures[key]
			}
			if st == memberLeft || st == memberDeclined || st == memberBanned {
				rendered = styleErr.Render("●") + " " + styleMeta.Render(name)
			} else {
				rendered = styleErr.Render("●") + " " + styleErr.Render(name)
			}
		}
		entries = append(entries, entry{rendered: rendered, plainLen: len([]rune(name)) + 2})
	}
	if width <= 0 {
		width = 80
	}
	// wraps instead of truncating: no member should disappear from the bar.
	var lines []string
	var cur strings.Builder
	curLen := 0
	for _, e := range entries {
		add := e.plainLen
		if curLen > 0 {
			add += 2 // "  " separator
		}
		if curLen > 0 && curLen+add > width {
			lines = append(lines, cur.String())
			cur.Reset()
			curLen = 0
			add = e.plainLen
		}
		if curLen > 0 {
			cur.WriteString("  ")
		}
		cur.WriteString(e.rendered)
		curLen += add
	}
	if curLen > 0 || len(lines) == 0 {
		lines = append(lines, cur.String())
	}
	return strings.Join(lines, "\n")
}

// groupBarLines returns the number of rows renderGroupBar will occupy for
// the given tab at the current width, used by calcVpH to reserve exactly
// the space needed when the bar wraps onto multiple rows.
func (m model) groupBarLines(tab *roomTab, width int) int {
	if tab == nil || tab.groupID == "" || len(tab.groupMembers) == 0 {
		return 0
	}
	bar := m.renderGroupBar(tab, width)
	if bar == "" {
		return 0
	}
	return strings.Count(bar, "\n") + 1
}

// defaultTabIdx is the default destination for generic feedback/announcements
// (confirmations, cancellations, summaries) and the tab returned to when
// leaving a room, Console holds this role, kept correctly updated when a
// tab closes (see cmdExit) and never closable by the user (isStandardTab):
// m.consoleIdx always stays valid for the entire session, so no fallback
// is needed.
func (m *model) defaultTabIdx() int {
	return m.consoleIdx
}

func (m *model) refreshViewport() {
	if !m.ready || len(m.tabs) == 0 {
		return
	}
	tab := m.tabs[m.active]
	// recompute the viewport height on tab change (group ↔ non-group)
	m.vp.Height = m.calcVpH()
	if tab.isContacts {
		m.vp.SetContent(m.renderContactList())
		m.vp.GotoTop()
		return
	}
	if tab.isGroups {
		m.vp.SetContent(m.renderGroupsList())
		m.vp.GotoTop()
		return
	}
	lines := tab.lines
	if tab.isConsole && m.compactMode {
		lines = compactChatLines(lines)
	}
	// gseqIndex, resolves the explicit-reply preview: a single pass over
	// the whole tab instead of a linear search for every row with replyTo!=0.
	var gseqIndex map[uint64]chatLine
	for _, l := range lines {
		if l.gseq != 0 {
			if gseqIndex == nil {
				gseqIndex = make(map[uint64]chatLine, len(lines))
			}
			gseqIndex[l.gseq] = l
		}
	}
	var sb strings.Builder
	w := m.vp.Width
	for _, l := range lines {
		var replyPreview string
		if l.replyTo != 0 {
			if orig, ok := gseqIndex[l.replyTo]; ok {
				replyPreview = orig.username + ": " + truncateReplyPreview(orig.text)
			}
		}
		rendered := l.render(m.myKey(), replyPreview)
		if w > 0 {
			rendered = ansi.Wrap(rendered, w, " ")
		}
		sb.WriteString(rendered)
		sb.WriteString("\n")
	}
	m.vp.SetContent(sb.String())
	m.vp.GotoBottom()
}

// compactChatLines collapses consecutive runs of chatLine with the same
// text (ignoring timestamp/other fields: two identical events at
// different times are the same repeated event, e.g. a periodic probe
// activation), leaving only the LAST occurrence of each run, used by
// refreshViewport when m.compactMode is active (/compact on, console tab
// only). Never modifies the input: always returns a new slice, tab.lines
// stays intact.
func compactChatLines(in []chatLine) []chatLine {
	out := make([]chatLine, 0, len(in))
	for i, l := range in {
		if i+1 < len(in) && in[i+1].text == l.text {
			continue
		}
		out = append(out, l)
	}
	return out
}

// ── helpers ───────────────────────────────────────────────────────────────────

// padName truncates/pads s to width characters (runes), to align
// the Contacts tab's columns regardless of how long the local name and the real
// username are.
func padName(s string, width int) string {
	r := []rune(s)
	if len(r) > width {
		r = r[:width]
	}
	return string(r) + strings.Repeat(" ", width-len(r))
}

// truncName truncates s to maxWidth characters (runes) without padding
// with spaces, unlike padName, meant for variable-width popups (e.g.
// renderInvitePicker) where always imposing the same fixed width would
// overflow the line on narrow terminals (Android/Termux has far fewer
// columns than a desktop): here only an upper cap matters, not aligning
// columns across rows.
func truncName(s string, maxWidth int) string {
	r := []rune(s)
	if len(r) > maxWidth {
		return string(r[:maxWidth])
	}
	return s
}

// renderContactLine generates a single row of the Contacts tab for a
// contact: last-probe time, dual reachability indicator, local
// name/username, ContentKey relationship badge, and trust tag. Extracted
// from renderContactList since it is shared by all four trust groups.
func (m *model) renderContactLine(c ContactInfo) string {
	st, known := m.contactStates[string(c.IdentityPub)]

	var dot1 string
	switch {
	case !known || st.online == nil:
		dot1 = styleMeta.Render("◌")
	case *st.online:
		dot1 = styleOwnMsg.Render("●")
	default:
		dot1 = styleErr.Render("✗")
	}

	// dot2 is independent of dot1 (not subordinate to it): proof that
	// they see us can arrive even when we cannot reach them, see the
	// comment on contactState.seenByPeer.
	var dot2 string
	switch {
	case !known || st.seenByPeer == nil:
		dot2 = styleMeta.Render("◌")
	case *st.seenByPeer:
		dot2 = styleOwnMsg.Render("●")
	default:
		dot2 = styleErr.Render("✗")
	}

	var timeStr string
	if known && st.online != nil {
		timeStr = styleMeta.Render(i18n.FormatContactTimestamp(st.probedAt))
	} else {
		timeStr = styleMeta.Render(i18n.ContactTimestampPlaceholder)
	}

	// No local name set: a placeholder in quotes takes the name's place,
	// to visually flag which contacts have not yet been customized
	// (elsewhere, e.g. group chat, the real name is still the fallback,
	// see DisplayName; only here in the Contacts tab is the placeholder
	// preferred). The quotes remain on set local names too, not just on
	// the placeholder: same treatment for everyone, not only those who
	// have not customized yet. Fixed width (content + quotes) keeps the
	// column aligned the same way row by row, instead of shifting
	// differently depending on name length.
	var name string
	if c.LocalName == "" {
		name = styleMeta.Render(`"` + strings.Repeat("_", maxLocalNameLen) + `"`)
	} else {
		name = `"` + padName(c.LocalName, maxLocalNameLen) + `"`
	}
	netName := padName(c.Username, maxUsernameDisplayLen)
	line := timeStr + " " + dot1 + dot2 + " " + name + styleMeta.Render(" ("+netName+")")
	dev, relEstablished := c.RelEstablishedDevice()
	var hex string
	if relEstablished {
		hex = fmt.Sprintf("%x", dev.PeerRelContentPub)
	}
	if len(hex) > 8 {
		hex = hex[len(hex)-8:]
	}
	for len(hex) < 8 {
		hex += " "
	}
	switch {
	case relEstablished:
		line += " " + styleOwnMsg.Render("[REL:"+hex+"]")
	case c.RelRevoked():
		line += " " + styleErr.Render(fmt.Sprintf("%-14s", "[REVOKED]"))
	default:
		line += " " + styleMeta.Render("[REL:"+hex+"]")
	}
	return line
}

// reachabilityRank converts a contact's status into a sortable integer,
// lower = more reliable. dot2 is not subordinate to dot1 (see
// contactState.seenByPeer), so the two columns contribute independently:
// each is worth 0 (●, best), 1 (◌, unknown), or 2 (✗, worst), score =
// dot1*3 + dot2, dot1 weighted as primary because it determines whether
// the contact is concretely usable RIGHT NOW. A contact never probed in
// either direction (or not yet in m.contactStates) scores 4 (dot1=1,
// dot2=1, ◌◌). The 9 possible combinations, best to worst: 0=●●, 1=●◌,
// 2=●✗, 3=◌●, 4=◌◌, 5=◌✗, 6=✗●, 7=✗◌, 8=✗✗.
func (m *model) reachabilityRank(pub []byte) int {
	st, known := m.contactStates[string(pub)]
	dot1 := 1 // ◌: never probed
	if known && st.online != nil {
		if *st.online {
			dot1 = 0 // ●
		} else {
			dot1 = 2 // ✗
		}
	}
	dot2 := 1 // ◌: unknown
	if known && st.seenByPeer != nil {
		if *st.seenByPeer {
			dot2 = 0 // ●
		} else {
			dot2 = 2 // ✗
		}
	}
	return dot1*3 + dot2
}

// groupContactsByTrust groups contacts by TrustLevel (used by
// renderContactList to show them in separate sections, from most to
// least trusted). Within each group, the secondary ordering is: an
// already-established ContentKey relationship first, then better
// reachability, then username as a stable tie-break.
func (m *model) groupContactsByTrust() map[TrustLevel][]ContactInfo {
	groups := make(map[TrustLevel][]ContactInfo, 4)
	for _, c := range m.contacts {
		lvl := c.TrustLevel()
		groups[lvl] = append(groups[lvl], c)
	}
	relEstablished := func(c ContactInfo) bool {
		_, ok := c.RelEstablishedDevice()
		return ok
	}
	for lvl, list := range groups {
		sort.SliceStable(list, func(i, j int) bool {
			ci, cj := list[i], list[j]
			gi, gj := relEstablished(ci), relEstablished(cj)
			if gi != gj {
				return gi
			}
			ri, rj := m.reachabilityRank(ci.IdentityPub), m.reachabilityRank(cj.IdentityPub)
			if ri != rj {
				return ri < rj
			}
			return ci.Username < cj.Username
		})
		groups[lvl] = list
	}
	return groups
}

// renderContactList generates the contacts tab's text content.
// Shows two status dots per contact:
//
//	dot1 (do I see X?):  ◌ never probed  ● reachable  ✗ unreachable
//	dot2 (does X see me?): ◌ unknown  ● probe_ack received
func (m *model) renderContactList() string {
	if len(m.contacts) == 0 {
		return styleMeta.Render(i18n.T("tui.no_contacts_hint"))
	}
	var sb strings.Builder

	groups := m.groupContactsByTrust()
	// Red/yellow/green on the same three colors already used for trust
	// tags, the two "verified" levels share green, the only difference
	// between them is whether they were also introduced by another contact.
	headers := [4]string{
		styleErr.Render(i18n.T("tui.contacts_group_unknown")),
		styleWarnName.Render(i18n.T("tui.contacts_group_introduced")),
		styleOwnMsg.Render(i18n.T("tui.contacts_group_verified")),
		styleOwnMsg.Render(i18n.T("tui.contacts_group_verified_introduced")),
	}
	first := true
	// TrustDanger (key conflict) ALWAYS goes first, as a trust VALUE it
	// is the lowest possible, but as URGENCY for the user it takes
	// precedence over every other group, including "unverified" (a
	// never-verified contact is normal, one in conflict is an anomaly).
	if dangerList := groups[TrustDanger]; len(dangerList) > 0 {
		sb.WriteString(styleErr.Render(i18n.T("tui.contacts_group_danger")) + "\n")
		for _, c := range dangerList {
			sb.WriteString(m.renderContactLine(c) + "\n")
		}
		first = false
	}
	for lvl := TrustVerifiedIntroduced; lvl >= TrustUnknown; lvl-- {
		list := groups[lvl]
		if len(list) == 0 {
			continue
		}
		if !first {
			sb.WriteString("\n")
		}
		first = false
		sb.WriteString(headers[int(lvl)] + "\n")
		for _, c := range list {
			sb.WriteString(m.renderContactLine(c) + "\n")
		}
	}
	return sb.String()
}

// renderGroupsList generates the groups tab's text content. Unlike
// contacts, there is no periodic reachability probe for saved groups
// (probing them would require reopening them with /grp-recall, a heavy
// action, a new secret and re-invites to every member, not something to
// do passively just to show a status): the only data shown is whether the
// group already has an active tab right now (reopened in this session).
func (m *model) renderGroupsList() string {
	if len(m.savedGroups) == 0 {
		return styleMeta.Render(i18n.T("tui.no_saved_groups_hint"))
	}
	openGroups := make(map[string]bool, len(m.tabs))
	for _, t := range m.tabs {
		if t.groupID != "" {
			openGroups[t.groupID] = true
		}
	}
	const maxMembersShown = 8
	var sb strings.Builder
	for _, g := range m.savedGroups {
		dot := styleMeta.Render("○")
		openTag := ""
		if openGroups[g.GroupID] {
			dot = styleOwnMsg.Render("●")
			openTag = "  " + styleOwnMsg.Render(i18n.T("tui.group_open_tag"))
		}
		sb.WriteString(dot + " " + g.LocalName + "  [" + g.GroupID + "]  " +
			fmt.Sprintf(i18n.T("tui.members_count"), len(g.Members)) + openTag + "\n")

		usernames := make([]string, 0, len(g.Members))
		for _, mem := range g.Members {
			usernames = append(usernames, mem.Username)
		}
		shown := usernames
		suffix := ""
		if len(shown) > maxMembersShown {
			shown = shown[:maxMembersShown]
			suffix = ", ..."
		}
		sb.WriteString(styleMeta.Render("    "+fmt.Sprintf(i18n.T("tui.group_members_line"), strings.Join(shown, ", ")+suffix)) + "\n\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

func localTab(tabIdx int, text string) tea.Cmd {
	return func() tea.Msg {
		return localDisplayMsg{tabIdx: tabIdx, text: text}
	}
}

// consoleErrTab sends an error only to the Console tab and lights up the
// red indicator.
func consoleErrTab(consoleIdx int, text string) tea.Cmd {
	return func() tea.Msg {
		return localDisplayMsg{tabIdx: consoleIdx, text: text, isError: true}
	}
}

// tabAt returns the tab at idx, nil when out of range.
func (m *model) tabAt(idx int) *roomTab {
	if idx < 0 || idx >= len(m.tabs) {
		return nil
	}
	return m.tabs[idx]
}

// myKey is our own member key.
func (m *model) myKey() string {
	return client.MemberKeyOf(m.myIdentityPub)
}

// memberName is the display name of a room member: the username label
// it was invited under, or the contact's username when no label is
// known, with a short key fingerprint appended when another member of
// the same room shows the same name, or the same name as ours, so
// homonyms stay distinguishable.
// Display only: never used to identify anyone.
func (m *model) memberName(tab *roomTab, key string) string {
	if key == "" {
		return ""
	}
	if key == m.myKey() {
		return m.myUsername
	}
	name := m.baseMemberName(tab, key)
	if name == m.myUsername {
		return name + " ·" + keyFingerprint(key)
	}
	if tab == nil {
		return name
	}
	for other := range tab.memberLabels {
		if other != key && other != m.myKey() && m.baseMemberName(tab, other) == name {
			return name + " ·" + keyFingerprint(key)
		}
	}
	return name
}

// baseMemberName is memberName without homonym disambiguation.
func (m *model) baseMemberName(tab *roomTab, key string) string {
	if tab != nil {
		if label := tab.memberLabels[key]; label != "" {
			return label
		}
	}
	if c := m.resolveContactByPub(memberKeyPub(key)); c != nil {
		return c.Username
	}
	return keyFingerprint(key)
}

// keyFingerprint is a short hex fingerprint of a member key, for display.
func keyFingerprint(key string) string {
	pub := memberKeyPub(key)
	if pub == nil {
		return "?"
	}
	return hex.EncodeToString(pub[:4])
}

// agentHooks replaces the terminal with a programmatic driver: options
// builds the tea.Program without screen or keyboard, attach starts the
// driver on the program and returns its shutdown.
type agentHooks struct {
	options func() []tea.ProgramOption
	attach  func(p *tea.Program) (stop func(), err error)
}

// agent is populated only by a build-tag-gated file (neutrino_agent)
// not part of the default build, nil here, RunTUI always uses the
// terminal.
var agent *agentHooks

// agentQueryMsg runs fn against the current model from inside the
// bubbletea loop, so the agent driver reads state without racing
// Update. Only ever sent by agent mode.
type agentQueryMsg struct{ fn func(m model) }

// RunTUI starts the multi-room bubbletea loop and blocks until exit.
// Returns nukeOnExit=true if the user launched /nukex, in that case the
// caller must run the express-nuke procedure (terminate the process).
// Returns duressWipeOnExit=true if a duress was recognized by the
// interface lock during an already-active session, in that case the
// caller must tear down Tor/server/keystore and re-enter the first-run
// wizard WITHOUT terminating the process; the two bools are always
// mutually exclusive. Returns clearAllOnExit=true if the user confirmed
// /sec-clear-all, in that case the caller must wipe the whole config
// directory (see wipeConfigDir) and terminate the process; mutually
// exclusive with the other two.
func RunTUI(params TUIParams) (nukeOnExit bool, duressWipeOnExit bool, clearAllOnExit bool, err error) {
	// On Android/Termux, without a wake-lock the system can suspend the
	// process for an unpredictable time as soon as it goes to the
	// background or the screen turns off, see the termuxenv package
	// comment. Outside Termux (or if the command is not installed)
	// AcquireWakeLock is a silent no-op.
	releaseWakeLock := termuxenv.AcquireWakeLock()
	defer releaseWakeLock()

	opts := []tea.ProgramOption{tea.WithAltScreen()}
	if agent != nil {
		opts = agent.options()
	}
	p := tea.NewProgram(newModel(params), opts...)
	if agent != nil {
		stop, err := agent.attach(p)
		if err != nil {
			return false, false, false, err
		}
		defer stop()
	}

	// Intercepts SIGINT (Ctrl-C from shell), SIGTERM (kill/systemd), SIGHUP
	// (hangup) and ignores them: Neutrino must not exit on any external
	// signal. The user must use /quit or /nukex to exit.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for range sigCh {
			// signal received, intentionally ignored
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	finalModel, runErr := p.Run()
	if fm, ok := finalModel.(model); ok {
		nukeOnExit = fm.nukeOnExit
		duressWipeOnExit = fm.duressWipeOnExit
		clearAllOnExit = fm.clearAllOnExit
	}
	return nukeOnExit, duressWipeOnExit, clearAllOnExit, runErr
}
