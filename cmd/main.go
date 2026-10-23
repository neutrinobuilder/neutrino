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
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // Android/Termux often lacks system tzdata: without this, time.Local would silently fall back to UTC, skewing timestamps shown in the TUI by hours

	"github.com/go-pdf/fpdf"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"

	"neutrino/internal/client"
	"neutrino/internal/client/tui"
	"neutrino/internal/config"
	"neutrino/internal/i18n"
	"neutrino/internal/indoor"
	"neutrino/internal/keystore"
	"neutrino/internal/qroptical"
	"neutrino/internal/qrscan"
	"neutrino/internal/server"
	"neutrino/internal/shared"
	"neutrino/internal/syslock"
	"neutrino/internal/termuxenv"
	"neutrino/internal/tornode"
	"neutrino/internal/transport"
	"neutrino/internal/version"
)

// qrPersonalOverlay, when non-nil, renders a QR image with a center
// overlay for one specific identity (matched by username) instead of the
// plain code — populated only by a build-tag-gated file not part of the
// default build (nil here). pixelsPerModule, not a total image size: see
// qrscan.PixelsPerModule for why a fixed total size is unreliable at a
// large QR version.
var qrPersonalOverlay func(username string, content []byte, pixelsPerModule int) (image.Image, bool)

// agentMain runs the "agent" subcommand — populated only by a
// build-tag-gated file (neutrino_agent) not part of the default build
// (nil here, the subcommand doesn't exist).
var agentMain func(args []string, bridgesFile, netFlag string)

// agentSession, when non-nil, replaces the interactive wizard/login in
// runOnce: creates or unlocks the keystore from credentials supplied by
// agent mode instead of the terminal. Set only by agentMain.
var agentSession func(ksPath, cfgPath string) (*keystore.UnlockedSlot, config.Config)

func usage() string {
	cfgPath := "~/.config/neutrino/config.json" // readable fallback
	if ksPath, err := keystore.DefaultPath(); err == nil {
		cfgPath = configPath(ksPath)
	}
	return i18n.T("cli.usage", version.Full(), cfgPath)
}

// loadActiveLang reads the language saved in config (if any) without
// unlocking the encrypted keystore — localizes CLI messages from the very
// first moment, before even knowing which subcommand was invoked.
func loadActiveLang() i18n.Lang {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		return i18n.LangEN
	}
	cfg, err := config.Load(configPath(ksPath))
	if err != nil {
		return i18n.LangEN
	}
	return i18n.ParseLang(cfg.Lang)
}

func main() {
	// Zeroes its own core dump limit: a process crash must never be able
	// to write the RAM image (identityKey, relationship keys, in-transit
	// plaintext) to disk. Best-effort: a process can only ever *lower* its
	// own RLIMIT_CORE, no privilege required; ignored if unsupported.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})

	termuxenv.FixLocalTimezone()
	i18n.SetActive(loadActiveLang())

	// Extracts --bridges-file and --net before parsing the subcommand.
	args := os.Args[1:]
	bridgesFile := ""
	netFlag := ""
	remaining := args[:0]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--bridges-file" && i+1 < len(args):
			bridgesFile = args[i+1]
			i++
		case args[i] == "--net" && i+1 < len(args):
			netFlag = args[i+1]
			i++
		default:
			remaining = append(remaining, args[i])
		}
	}

	if len(remaining) == 0 {
		runMain(bridgesFile, netFlag)
		return
	}

	switch remaining[0] {
	case "__pod":
		// Hidden subcommand, reached only via spawnPod's self-exec —
		// never meant to be typed by a user, not listed in usage().
		runPod()
	case "add-bridges":
		runAddBridges(remaining[1:])
	case "add-identity":
		runAddIdentity()
	case "agent":
		if agentMain == nil {
			fmt.Fprint(os.Stderr, i18n.T("cli.unknown_command", remaining[0], usage()))
			os.Exit(1)
		}
		agentMain(remaining[1:], bridgesFile, netFlag)
	case "backup":
		runBackup()
	case "debug":
		if len(remaining) < 2 {
			fmt.Fprintln(os.Stderr, i18n.T("cli.debug_usage"))
			os.Exit(1)
		}
		runDebug(remaining[1], bridgesFile, netFlag)
	case "get-bridges":
		runGetBridges()
	case "install":
		runInstall()
	case "lang":
		runLang(remaining[1:])
	case "net":
		runNet(remaining[1:])
	case "qr":
		if len(remaining) < 2 {
			fmt.Fprintln(os.Stderr, i18n.T("cli.qr_usage"))
			os.Exit(1)
		}
		switch remaining[1] {
		case "send":
			runQRSend(remaining[2:])
		case "receive":
			runQRReceive(remaining[2:])
		default:
			fmt.Fprintln(os.Stderr, i18n.T("cli.qr_unknown_subcommand", remaining[1]))
			os.Exit(1)
		}
	case "remove-all-bridges":
		runRemoveAllBridges()
	case "reset-config":
		runResetConfig()
	case "restore":
		runRestore()
	case "show-qr":
		runShowQR()
	case "sync":
		if len(remaining) < 2 {
			fmt.Fprintln(os.Stderr, i18n.T("cli.sync_usage"))
			os.Exit(1)
		}
		switch remaining[1] {
		case "export":
			runSyncExport()
		case "import":
			if len(remaining) < 3 {
				fmt.Fprintln(os.Stderr, i18n.T("cli.sync_import_usage"))
				os.Exit(1)
			}
			if remaining[2] == "--camera" {
				runSyncImportQR()
			} else {
				runSyncImport(remaining[2:])
			}
		default:
			fmt.Fprintln(os.Stderr, i18n.T("cli.sync_unknown_subcommand", remaining[1]))
			os.Exit(1)
		}
	case "use-bridges":
		runUseBridges(remaining[1:])
	case "version", "--version", "-v":
		fmt.Print(i18n.T("cli.version", version.Full()))
	case "--help", "-h", "help":
		fmt.Print(usage())
	default:
		fmt.Fprint(os.Stderr, i18n.T("cli.unknown_command", remaining[0], usage()))
		os.Exit(1)
	}
}

// ── main bootstrap ─────────────────────────────────────────────────────────

// addressFromPubForNet computes the network address reachable from an
// Ed25519 public key, using the right algorithm for netKind — Tor
// (OnionAddressFromPub) or I2P (I2PAddressFromPub, requires the
// birational Ed25519↔X25519 map, see internal/shared/i2p.go). Only the
// public key is needed, never the private one: applies equally to one's
// own address and to a contact's.
func addressFromPubForNet(netKind transport.Kind, pub ed25519.PublicKey) string {
	if netKind == transport.KindI2P {
		addr, err := shared.I2PAddressFromPub(pub)
		if err != nil {
			return ""
		}
		return addr
	}
	return shared.OnionAddressFromPub(pub)
}

// loadBridges reads the bridge file through internal/tornode
// (LoadBridgeFile).
func loadBridges(path string) (*tornode.BridgeConfig, error) {
	return tornode.LoadBridgeFile(path)
}

func filterBridgesByTransport(bc *tornode.BridgeConfig, transport string) *tornode.BridgeConfig {
	return tornode.FilterBridgesByTransport(bc, transport)
}

// fmtDuration formats a duration as "Xs" under a minute, "Ym Zs" otherwise
// — used to show how long each individual startup phase takes (Tor/I2P
// bootstrap, hidden service publication), never the cumulative time since
// the start.
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// runMain is the interactive startup entry point. A single call to
// runOnce (below) covers the whole process lifetime: a duress secret
// typed at the interface lock DURING an already-active session, or at
// the login screen itself (unlockKeystoreSession — by construction of
// the N-slot format, indistinguishable from any other identity's
// password at that point), or a nuke trigger (/nukex, the automatic
// "nuke a tempo", remote_nuke on the target side) — none of them ever
// make runOnce return early: its own internal loop promotes to the
// shared duress identity and keeps going, on the same Tor/I2P node,
// never back to a login prompt. runOnce only returns on an ordinary
// quit (or a fatal() error, which exits the process directly).
func runMain(bridgesFile, netFlag string) {
	runOnce(bridgesFile, netFlag)
}

// buildFakeContact builds one fabricated contact for duress's mirrored
// address book: a name via keystore.DecoyContactName (cfg's decoy_*
// parameters), plus relationship key material of the same shape as a
// real contact's Devices[""] entry — generated, never used for any
// actual handshake.
func buildFakeContact(cfg config.Config, existingFirstNames map[string]bool) keystore.Contact {
	genderByte := make([]byte, 1)
	rand.Read(genderByte)
	female := genderByte[0]%2 == 0
	username, localName := keystore.DecoyContactName(cfg.Lang, cfg.DecoySecondaryLangs, cfg.DecoySecondaryLangPct, cfg.DecoyIntlPct, cfg.DecoyInitialPct, female, existingFirstNames)

	identityPub := make([]byte, ed25519.PublicKeySize)
	rand.Read(identityPub)
	contact := keystore.Contact{Username: username, LocalName: localName, IdentityPub: identityPub}

	identKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		return contact
	}
	contentKey, err := shared.GenerateRelSigningKey()
	if err != nil {
		return contact
	}
	contact.Devices = map[string]*keystore.DeviceRelation{
		"": {
			RelIdentityPriv:      identKey.Priv,
			RelIdentityMLKEMPriv: identKey.MLKEMSeed,
			RelIdentityMLDSAPriv: identKey.MLDSASeed,
			RelContentPriv:       contentKey.Priv,
			RelContentMLKEMPriv:  contentKey.MLKEMSeed,
			RelContentMLDSAPriv:  contentKey.MLDSASeed,
		},
	}
	return contact
}

// rejectedTombstoneRows resolves each IdentityPub in rejected (from
// keystore.UnlockedSlot.AddMirroredContacts) to its full tombstone row,
// ready to send back to whoever sent the now-rejected live contact.
func rejectedTombstoneRows(ks *keystore.Keystore, rejected [][]byte) []keystore.DeletedContact {
	var rows []keystore.DeletedContact
	for _, pub := range rejected {
		if row, ok := ks.DeletedContactRow(pub); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

// applyTombstoneReplies adopts each row (deleting any matching live
// contact, merging ConfirmedSiblings, persisting immediately) and
// returns the IdentityPubs to ack — shared by every sync channel's
// reconciliation step (LAN's TombstoneRound, the knock-based
// ApplyContactTombstoneReplies).
func applyTombstoneReplies(session *keystore.UnlockedSlot, ksPath string, rows []keystore.DeletedContact) [][]byte {
	ks := session.Identity
	var acked [][]byte
	for _, row := range rows {
		ks.AdoptDeletedContact(row)
		idx := -1
		for i, c := range ks.ContactsSnapshot() {
			if bytes.Equal(c.IdentityPub, row.IdentityPub) {
				idx = i
				break
			}
		}
		if idx != -1 {
			if ks.IsDuress {
				if session.EmptyPlainContact(idx) == nil {
					_ = session.SaveSlot(ksPath)
				}
			} else {
				duressIdx, duressKi, duressPlain, hadMirror, err := session.EmptyMirroredContact(idx)
				if err == nil {
					if hadMirror {
						_ = session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain)
					} else {
						_ = session.SaveSlot(ksPath)
					}
				}
			}
		} else {
			_ = session.SaveSlot(ksPath)
		}
		acked = append(acked, row.IdentityPub)
	}
	return acked
}

// buildTombstoneRound builds the 3-step deletion-reconciliation
// callbacks (indoor.TombstoneRound) shared by every sync channel
// (LAN session, knock-based device_sync): ComputeReplies answers a
// peer's live contacts with this identity's own tombstone rows for any
// already-deleted IdentityPub among them; ApplyAndAck adopts a peer's
// reply rows, deleting any still-live local copy, persisting the
// change immediately (so a later step in the same sync sees it);
// ConfirmAcked records, on this identity's own rows, that the peer has
// adopted whatever it just acked.
func buildTombstoneRound(session *keystore.UnlockedSlot, ksPath string) indoor.TombstoneRound {
	ks := session.Identity
	return indoor.TombstoneRound{
		ComputeReplies: func(peerContacts []keystore.Contact) []keystore.DeletedContact {
			var out []keystore.DeletedContact
			for _, c := range peerContacts {
				if row, ok := ks.DeletedContactRow(c.IdentityPub); ok {
					out = append(out, row)
				}
			}
			return out
		},
		ApplyAndAck: func(replies []keystore.DeletedContact) [][]byte {
			return applyTombstoneReplies(session, ksPath, replies)
		},
		ConfirmAcked: func(acked [][]byte, peerDeviceID []byte) {
			for _, pub := range acked {
				ks.ConfirmSiblingForDeletion(pub, peerDeviceID)
			}
		},
	}
}

// runOnce runs a single complete session (wizard/unlock → network
// bootstrap → server → TUI) — returns true if the session ended because of
// a duress secret typed at the interface lock while already active (the
// caller, runMain above, must call it again), false for any other exit
// (normal quit, /nukex — which terminates the process itself via os.Exit).
func runOnce(bridgesFile, netFlag string) {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	cfgPath := configPath(ksPath)

	var session *keystore.UnlockedSlot
	var cfg config.Config
	if agentSession != nil {
		session, cfg = agentSession(ksPath, cfgPath)
	} else if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		session, cfg = runWizard(ksPath, cfgPath)
	} else {
		cfg, err = config.Load(cfgPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, i18n.T("cli.warn_invalid_config", err))
		}
		i18n.SetActive(i18n.ParseLang(cfg.Lang))
		// Which identity this password combination opens — real or the
		// shared duress one — is decided purely by which slot answers
		// (see keystore.LoadAndUnlock): there is no separate "duress
		// detected" branch at login. Every identity, duress included,
		// starts the same session; the few places that behave
		// differently check session.Identity.IsDuress.
		session = unlockKeystoreSession(ksPath)
	}

	// Transport network: an explicit --net takes priority over the value
	// saved in config, which in turn takes priority over the "tor" default
	// (the same scheme as --bridges-file vs bridges_enabled, a bit further
	// below).
	netKind := transport.KindTor
	if netFlag != "" {
		k, err := transport.ParseKind(netFlag)
		if err != nil {
			fatal(i18n.T("cli.net_invalid", netFlag))
		}
		netKind = k
	} else if k, err := transport.ParseKind(cfg.Net); err == nil {
		netKind = k
	}

	addressFromPub := func(pub ed25519.PublicKey) string {
		return addressFromPubForNet(netKind, pub)
	}

	srvCfg := server.ServerConfig{
		PingInterval:    cfg.PingDuration(),
		CleanupInterval: cfg.CleanupDuration(),
	}
	senderKeyInterval := cfg.SenderKeyDuration()
	pendingSlotLimit := cfg.PendingSlotLimitOrDefault()
	messageRetryDelay := cfg.MessageRetryDelayDuration()
	pendingEscalationAge := cfg.PendingEscalationAgeDuration()
	messageTTL := cfg.MessageTTLDuration()
	senderKeyMessageBudget := cfg.SenderKeyMessageBudgetOrDefault()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	netName := "Tor"
	switch netKind {
	case transport.KindTor:
	case transport.KindI2P:
		netName = "I2P"
	default:
		netName = string(netKind)
	}

	// Starts the transport network and publishes the hidden
	// service/destination (the two slowest phases). The process is tied
	// to ctx (lifetime = user session), not a fixed timeout. The 3-minute
	// timeout covers only the initial bootstrap: if it doesn't complete,
	// it exits.
	bootstrapDone := make(chan struct{})
	go func() {
		select {
		case <-bootstrapDone:
		case <-time.After(3 * time.Minute):
			fmt.Fprintln(os.Stderr, i18n.T("cli.err_net_timeout", netName))
			// cancel(), not os.Exit(): at this point transport.Start
			// (below) may have already spawned the embedded Tor/I2P
			// subprocess, still blocked on the same goroutine as runMain
			// — a direct os.Exit() here would orphan it (none of
			// runMain's defers ever run). Cancelling ctx propagates to
			// the processCtx derived inside tor.StartTor/i2pnode.StartI2p
			// (both pass it to exec.CommandContext), terminating the
			// process even while still blocked in startup;
			// transport.Start then unblocks and returns an error, handled
			// by the "if err != nil" path further below — the actual
			// exit happens there, after the subprocess is already dead.
			cancel()
		}
	}()

	// Phase 1: network bootstrap — shows real percentage by parsing the
	// logs. Bridges are a Tor-only concept (bypassing censorship of public
	// Tor relays): an explicit --bridges-file always takes priority (a
	// single manually specified file, no fallback concept there);
	// otherwise, if bridges_enabled is active in config, automatically
	// loads the file saved by 'get-bridges' and filters both its
	// bridge_default lines (bridgeCfg) and, for transport.Start's
	// automatic retry, its bridge_fallback lines (bridgeFallbackCfg). No
	// effect for --net i2p.
	var bridgeCfg, bridgeFallbackCfg *tornode.BridgeConfig
	if netKind == transport.KindTor {
		switch {
		case bridgesFile != "":
			bc, err := loadBridges(bridgesFile)
			if err != nil {
				fatal(i18n.T("cli.err_bridge_file", err))
			}
			bridgeCfg = bc
		case cfg.BridgesEnabled:
			bc, err := loadBridges(bridgesPath(ksPath))
			if err != nil {
				fmt.Fprint(os.Stderr, i18n.T("cli.warn_bridges_enabled_no_file", err))
			} else {
				filtered := filterBridgesByTransport(bc, cfg.BridgeDefault)
				if len(filtered.Lines) == 0 {
					fmt.Fprint(os.Stderr, i18n.T("cli.warn_no_bridges_for_transport", cfg.BridgeDefault))
				} else {
					bridgeCfg = filtered
				}
				if fb := filterBridgesByTransport(bc, cfg.BridgeFallback); len(fb.Lines) > 0 {
					bridgeFallbackCfg = fb
				}
			}
		}
	}
	var bootLog []string
	elapsed := shared.Now
	// First line of the boot, always — both on the raw terminal (visible
	// before the TUI takes over the screen) and in Console once it's
	// running: the running version is the first thing visible in any log
	// provided for diagnosis, without having to ask for it separately or
	// rely on /info-app.
	fmt.Print(i18n.T("cli.version", version.Full()))
	bootLog = append(bootLog, strings.TrimSpace(i18n.T("cli.version", version.Full())))
	phase1Start := time.Now()
	if bridgeCfg != nil {
		fmt.Print(i18n.T("cli.tor_bootstrap_bridge_start", elapsed()))
	} else {
		fmt.Print(i18n.T("cli.net_bootstrap_start", elapsed(), netName))
	}
	lastPct := -1
	var bootstrapActive int32 = 1 // zeroed right after Start to block late callbacks
	node, err := transport.Start(ctx, netKind, transport.StartConfig{
		OnProgress: func(pct int) {
			if atomic.LoadInt32(&bootstrapActive) == 0 {
				return
			}
			if pct > lastPct {
				lastPct = pct
				if bridgeCfg != nil {
					fmt.Print(i18n.T("cli.tor_bootstrap_bridge_progress", elapsed(), pct))
				} else {
					fmt.Print(i18n.T("cli.net_bootstrap_progress", elapsed(), netName, pct))
				}
			}
		},
		Bridges:         bridgeCfg,
		BridgesFallback: bridgeFallbackCfg,
		// BridgeBootstrapTimeout left unset: zero → transport.startTor uses
		// tornode.DefaultBridgeBootstrapTimeout, no dedicated config/CLI
		// option.
		OnBridgeFallback: func() {
			// The bridgeCfg (bridge_default) attempt didn't complete the
			// bootstrap in time — restarts from scratch with
			// bridgeFallbackCfg (bridge_fallback), a new Tor process:
			// without this notice the percentage would seem to stall or
			// go backward with no explanation.
			fmt.Println()
			fmt.Print(i18n.T("cli.tor_bridge_fallback_start", elapsed()))
			lastPct = -1
		},
	})
	atomic.StoreInt32(&bootstrapActive, 0)
	close(bootstrapDone)
	if err != nil {
		fmt.Println()
		if ctx.Err() != nil {
			// Exit triggered by the bootstrap watchdog above (cancel()),
			// not a real network error — the timeout message was already
			// printed there, no subprocess to close (node was never
			// assigned: the subprocess is already dead from ctx's
			// cancellation propagated inside transport.Start).
			os.Exit(1)
		}
		if bridgeCfg != nil && errors.Is(err, tornode.ErrBridgeBootstrapTimeout) {
			// Both bridge_default and (if present) bridge_fallback timed
			// out without completing the bootstrap: an explicit
			// suggestion instead of just the generic error below.
			fatal(i18n.T("cli.err_bridge_bootstrap_all_failed", netName))
		}
		fatal(i18n.T("cli.err_net_start", netName, err))
	}
	defer node.Close()
	// netCleanup manually redoes, in order, exactly what the two defers
	// above (cancel/node.Close) would do on runMain's natural return —
	// needed before any exit going through fatal()/os.Exit() further
	// below, since os.Exit() skips this function's entire defer stack,
	// orphaning the already-started Tor/I2P subprocess. Calling it takes
	// nothing away from the success path: the same defers stay
	// registered, but never get to run a second time because every
	// netCleanup() caller terminates right after with os.Exit(), which
	// also skips those now-redundant defers.
	netCleanup := func() {
		cancel()
		node.Close()
	}
	netBootstrapDoneMsg := i18n.T("cli.net_bootstrap_done", elapsed(), netName, fmtDuration(time.Since(phase1Start)))
	fmt.Println(netBootstrapDoneMsg)
	bootLog = append(bootLog, strings.TrimSpace(netBootstrapDoneMsg))

	// sysLockCh is tied to ctx, not to any identity — a single
	// subscription survives every iteration of the loop below (an OS
	// session-lock signal means the same thing regardless of which
	// identity is currently active).
	sysLockCh := syslock.Watch(ctx)

	// Forces exit after 4 seconds if shutdown stalls (Tor or pending
	// connections). Declared ONCE, outside the loop below: this defer
	// only fires on the function's actual return — never on a `continue`
	// (a nuke or duress trigger promoting to the next identity never
	// returns at all, see nukeRequested/duressWipeRequested below), so a
	// single registration here correctly covers however many identities
	// this call ends up cycling through, and only ever matters for the
	// one true exit path left (a normal quit, no trigger involved).
	defer func() {
		go func() {
			time.Sleep(4 * time.Second)
			os.Exit(0)
		}()
	}()

	// From here on, the loop below re-runs this process AS the identity
	// currently held in session/ks — once per identity ever activated in
	// this run: the first pass (the one just unlocked above), then once
	// more per nuke-triggered promotion to duress (see nukeRequested
	// below), for as long as that keeps happening. node/ctx/netCleanup
	// are shared across every pass — Tor/I2P is never restarted, and the
	// PREVIOUS identity's hidden service/server goroutine is never torn
	// down either: it's simply abandoned, left running with its own
	// (by then emptied) contacts — same anti-forensic principle as the
	// client-side session abandonment elsewhere in this design, never a
	// new observable signal like an onion address suddenly going dark.
	for {
		ks := session.Identity

		// Phase 2: hidden service publication (up to 3 attempts — an EOF on
		// the control port can happen if Tor hasn't stabilized the control
		// connection yet).
		phase2Start := time.Now()
		fmt.Print(i18n.T("cli.hs_publishing", elapsed()))
		var ln net.Listener
		var myAddr, localAddr string
		for attempt := 1; ; attempt++ {
			ln, myAddr, localAddr, err = node.AddHiddenService(ctx, ks.NetworkIdentityPrivKey())
			if err == nil {
				break
			}
			if attempt >= 3 {
				fmt.Println()
				netCleanup()
				fatal(i18n.T("cli.err_hidden_service", err))
			}
			fmt.Print(i18n.T("cli.hs_retry", attempt))
			time.Sleep(2 * time.Second)
		}
		hsPublishedDoneMsg := i18n.T("cli.hs_published_done", fmtDuration(time.Since(phase2Start)))
		fmt.Println(hsPublishedDoneMsg)
		bootLog = append(bootLog, strings.TrimSpace(i18n.T("cli.hs_publishing", elapsed()))+hsPublishedDoneMsg)

		// Phase 3: startup complete
		phase3Start := time.Now()
		hsReadyMsg := i18n.T("cli.hs_ready", elapsed(), myAddr, fmtDuration(time.Since(phase3Start)))
		fmt.Print(hsReadyMsg)
		bootLog = append(bootLog, strings.TrimSpace(hsReadyMsg))

		// Mandatory mutuality on /knock: a getter, not a snapshot, because
		// ks.Contacts grows during the session (e.g. /cnt-add, or accepting a
		// contact card) and the server keeps running for the process's whole
		// lifetime. Uses ks.ContactIdentityPubs(), not a direct iteration over
		// ks.Contacts: this getter is invoked by an HTTP goroutine for every
		// incoming knock, concurrent with AddContact/DeleteContactByPub on the TUI
		// goroutine.
		knownContactPubsFn := func() [][]byte {
			return ks.ContactIdentityPubs()
		}

		// Forwards internal/server's internal diagnostics (KnockDHTag mutuality
		// filter, DecryptKnock outcomes — see internal/server/debug.go) to the
		// same sink as client.Dbg, already activatable with `neutrino debug
		// <file>` or `/debug on|off` — a single debug mechanism for the user,
		// not two. client.Dbg is already a no-op when debug isn't active: no
		// cost to wiring it up unconditionally here.
		server.SetDebug(func(msg string) { client.Dbg("%s", msg) })

		// Multi-room server.
		registry := server.NewRoomRegistry()
		knockCh := make(chan shared.KnockPayload, 16)
		go func() {
			if err := server.RunOnListener(ctx, ln, registry, ks.IdentityPrivKey(), ks.MLKEMDecap(), knockCh, knownContactPubsFn, srvCfg); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, i18n.T("cli.err_server", err))
			}
		}()

		// publishRootHiddenService publishes a NEW hidden service under ks's
		// CURRENT root and starts a second server.RunOnListener on it,
		// sharing the same registry/knockCh/cfg as the startup listener above
		// — used by StartRootRotation/AdoptRootRotation. The old listener
		// stays active (no explicit teardown): online contacts migrate
		// immediately, offline ones will on their return — no need to shut it
		// down specifically for them.
		publishRootHiddenService := func() (string, error) {
			newLn, newMyAddr, _, err := node.AddHiddenService(ctx, ks.NetworkIdentityPrivKey())
			if err != nil {
				return "", err
			}
			go func() {
				if err := server.RunOnListener(ctx, newLn, registry, ks.IdentityPrivKey(), ks.MLKEMDecap(), knockCh, knownContactPubsFn, srvCfg); err != nil && ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, i18n.T("cli.err_server", err))
				}
			}()
			return newMyAddr, nil
		}

		// Own local server address — used to connect to every room created/
		// reopened (client.New(lhost, portNum, ...), passed below as
		// LocalHost/LocalPort).
		lhost, lport, err := net.SplitHostPort(localAddr)
		if err != nil {
			netCleanup()
			fatal(i18n.T("cli.err_invalid_local_addr", err))
		}
		portNum, _ := strconv.Atoi(lport)

		// Contact list for /active and for matching incoming knocks
		contacts := convertContacts(ks.ContactsSnapshot(), addressFromPub)

		savedSnapshot := ks.SavedGroupsSnapshot()
		savedGroups := make([]tui.GroupInfo, 0, len(savedSnapshot))
		for _, sg := range savedSnapshot {
			members := make([]tui.GroupMember, len(sg.Members))
			for i, m := range sg.Members {
				members[i] = tui.GroupMember{Username: m.Username, IdentityPub: m.IdentityPub}
			}
			savedGroups = append(savedGroups, tui.GroupInfo{
				LocalName: sg.LocalName,
				GroupID:   sg.GroupID,
				Members:   members,
			})
		}

		// Known devices to route a remote_nuke command to — populated by
		// "indoor" synchronization, empty until it's run at least once.

		// remote_nuke commands issued by this identity and not yet confirmed
		// by an ack — retried on every startup.
		pendingRemoteNukeTargets := convertDeviceRecords(ks.PendingRemoteNukeTargets())

		// The authority's danger_broadcast/danger_end not yet confirmed by
		// each contact — retried on every probeContacts cycle (independent
		// queues, preliminary vs. final).
		dangerBroadcasts, dangerEnds := ks.DangerPendingSnapshot()
		pendingDangerBroadcasts := convertDangerPending(dangerBroadcasts)
		pendingDangerEnds := convertDangerPending(dangerEnds)

		// Just a health check at startup (warns immediately if /sec-backup
		// won't work) — the 24 words themselves aren't kept: GetBackupMnemonic
		// below recomputes them on demand, only after password verification,
		// and the TUI zeroes them as soon as the popup closes.
		if _, err := ks.Mnemonic(); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("cli.warn_mnemonic_failed", err))
			bootLog = append(bootLog, strings.TrimSpace(i18n.T("cli.warn_mnemonic_failed", err)))
		}

		// Nudge for a keystore with no DeviceLabel: without a name chosen
		// by the user, /sec-remote-nuke and /sec-devices would show only
		// this device's raw DeviceID — not a real blocker, but a
		// "nameless" device is hard to recognize if stolen. The wizard
		// asks for it on every new keystore (createIdentity in runWizard).
		if ks.DeviceLabel == "" {
			bootLog = append(bootLog, strings.TrimSpace(i18n.T("cli.hint_device_label_unset")))
		}

		nukeRequested, duressWipeRequested, clearAllRequested, err := tui.RunTUI(tui.TUIParams{
			Username:               ks.Username,
			Contacts:               contacts,
			BootLog:                bootLog,
			DialTor:                node.DialContext,
			CheckCircuits:          node.HasCircuits,
			HSPublished:            true, // AddHiddenService waits for HS_DESC UPLOADED before returning
			SenderKeyInterval:      senderKeyInterval,
			PendingSlotLimit:       pendingSlotLimit,
			MessageRetryDelay:      messageRetryDelay,
			PendingEscalationAge:   pendingEscalationAge,
			MessageTTL:             messageTTL,
			SenderKeyMessageBudget: senderKeyMessageBudget,
			GetBackupMnemonic:      ks.Mnemonic,
			SaveIdentityQR: func() ([]string, error) {
				qrPath := filepath.Join(filepath.Dir(ksPath), fmt.Sprintf("identity-qr-%s.png", ks.Username))
				return saveIdentityQRForTUI(ks.Username, ks.IdentityPubKey(), ks.MLKEMPubBytes(), ks.MLDSAPubBytes(), qrPath)
			},
			ActiveInterval:               cfg.ActiveDuration(),
			ActiveInitialDelay:           cfg.ActiveInitialDelayDuration(),
			ProbeContactsTimeout:         cfg.ProbeContactsTimeoutDuration(),
			ProbeRetryCount:              cfg.ProbeRetryCountOrDefault(),
			ProbeRetryDelay:              cfg.ProbeRetryDelayDuration(),
			TorProbeInterval:             cfg.TorProbeIntervalDuration(),
			TorProbeInitialDelay:         cfg.TorProbeInitialDelayDuration(),
			FileTransferMaxSizeMiB:       cfg.FileTransferMaxSizeMiBOrDefault(),
			FileWarpChunkSizeKiB:         cfg.FileWarpChunkSizeKiBOrDefault(),
			FileSlowChunkSizeKiB:         cfg.FileSlowChunkSizeKiBOrDefault(),
			FileSlowDelayMs:              int(cfg.FileSlowDelayDuration() / time.Millisecond),
			FileTransferOfferTimeout:     cfg.FileTransferOfferTimeoutDuration(),
			FileOfferBatchWindow:         cfg.FileOfferBatchWindowDuration(),
			FileWarpMaxInFlightChunks:    cfg.FileWarpMaxInFlightChunksOrDefault(),
			FileSlowMaxInFlightChunks:    cfg.FileSlowMaxInFlightChunksOrDefault(),
			FileTransferReconnectTimeout: cfg.FileTransferReconnectTimeoutDuration(),
			FileAcceptRetryInterval:      cfg.FileAcceptRetryIntervalDuration(),
			StrongCompressionEnabled:     cfg.StrongCompressionEnabled,
			WarmupInterval:               cfg.WarmupIntervalDuration(),
			WarmupInitialDelay:           cfg.WarmupInitialDelayDuration(),
			WarmupTimeout:                cfg.WarmupTimeoutDuration(),
			SelfKnockTimeout:             cfg.SelfKnockTimeoutDuration(),
			KnockHttpTimeout:             cfg.KnockHttpTimeoutDuration(),
			KnockRetryDelay:              cfg.KnockRetryDelayDuration(),
			InviteTimeout:                cfg.InviteTimeoutDuration(),
			IsolatedDialer: func(ctx context.Context, token string) func(context.Context, string, string) (net.Conn, error) {
				dialFn, err := node.DialerForToken(ctx, token)
				if err != nil {
					return node.DialContext // fallback to the generic dialer
				}
				return dialFn
			},
			KnockCh:        knockCh,
			SysLockCh:      sysLockCh,
			TorLogCh:       node.LogCh(),
			NetworkName:    netName,
			MyAddr:         myAddr,
			AddressFromPub: addressFromPub,
			MyIdentityPub:  ks.IdentityPubKey(),
			MyMLKEMPub:     ks.MLKEMPubBytes(),
			LocalHost:      lhost,
			LocalPort:      portNum,
			// RoomRegistry.AddSecret/ReplaceSecret take a resolver, never an
			// already-resolved key pair — tui.go builds it
			// (model.relKeysResolver) around ResolveRelKeysForDevice below,
			// which just exposes ks.RelKeysForDevice: re-read on every
			// handshake verification, never cached, so a relationship
			// rotation (local or peer's) is reflected immediately with no
			// need for any explicit refresh.
			AddRoom: func(roomID string, secret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
				registry.AddSecret(roomID, secret, label, identityPub, devicePub, resolveKeys)
			},
			ReplaceRoomSecret: func(roomID string, oldSecret, newSecret []byte, label string, identityPub ed25519.PublicKey, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) {
				registry.ReplaceSecret(roomID, oldSecret, newSecret, label, identityPub, devicePub, resolveKeys)
			},
			ResolveRelKeysForDevice: ks.RelKeysForDevice,
			BanMember: func(roomID string, secret []byte, userID string) bool {
				registry.RemoveSecret(roomID, secret)
				return registry.KickMember(roomID, userID)
			},
			SavedGroups: savedGroups,
			SaveGroup: func(g tui.GroupInfo) error {
				members := make([]keystore.SavedGroupMember, len(g.Members))
				for i, m := range g.Members {
					members[i] = keystore.SavedGroupMember{Username: m.Username, IdentityPub: m.IdentityPub}
				}
				ks.AddSavedGroup(keystore.SavedGroup{
					LocalName: g.LocalName,
					GroupID:   g.GroupID,
					Members:   members,
				})
				return session.SaveSlot(ksPath)
			},
			OnContactDevicePub: func(contactPub []byte, devicePub []byte) error {
				old, ok := ks.GetContactByPub(contactPub)
				if !ok {
					return nil
				}
				if bytes.Equal(old.KnownDevicePub, devicePub) {
					return nil // already up to date
				}
				ks.UpdateContactByPub(old.IdentityPub, func(c *keystore.Contact) { c.KnownDevicePub = devicePub })
				return session.SaveSlot(ksPath)
			},
			DeleteContact: func(pub []byte) error {
				idx := -1
				for i, c := range ks.ContactsSnapshot() {
					if bytes.Equal(c.IdentityPub, pub) {
						idx = i
						break
					}
				}
				if idx == -1 {
					return nil // already gone, not an error
				}
				ks.RecordContactDeletion(pub)
				if ks.IsDuress {
					if err := session.EmptyPlainContact(idx); err != nil {
						return err
					}
					return session.SaveSlot(ksPath)
				}
				duressIdx, duressKi, duressPlain, hadMirror, err := session.EmptyMirroredContact(idx)
				if err != nil {
					return err
				}
				if !hadMirror {
					return session.SaveSlot(ksPath)
				}
				return session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain)
			},
			DeleteGroup: func(nameOrID string) error {
				if !ks.DeleteSavedGroup(nameOrID) {
					return nil
				}
				return session.SaveSlot(ksPath)
			},
			AddContact: func(username, localName string, identityPub, mlkemPub, mldsaPub []byte, introducedBy string, introducedByPub []byte) (shared.RelSigningKey, shared.RelSigningKey, error) {
				// Generates the two per-contact relationship keys
				// (IdentityKey/ContentKey) toward this new contact
				// IMMEDIATELY. Their counterparts (PeerRel*) stay empty until
				// they arrive via the rel_init/rel_init_ack cycle (tui.go),
				// not here. No peer device is known yet at this point: the
				// entry lives under the placeholder key "" (see
				// tui.RelKeyUpdate) until applyRelInit promotes it to the
				// real DevicePub of the first device that responds —
				// per-device model.
				identKey, err := shared.GenerateRelSigningKey()
				if err != nil {
					return shared.RelSigningKey{}, shared.RelSigningKey{}, err
				}
				contentKey, err := shared.GenerateRelSigningKey()
				if err != nil {
					return shared.RelSigningKey{}, shared.RelSigningKey{}, err
				}
				real := keystore.Contact{
					Username:        username,
					LocalName:       localName,
					IdentityPub:     identityPub,
					MLKEMPub:        mlkemPub,
					MLDSAPub:        mldsaPub,
					IntroducedBy:    introducedBy,
					IntroducedByPub: introducedByPub,
					Devices: map[string]*keystore.DeviceRelation{
						"": {
							RelIdentityPriv:      identKey.Priv,
							RelIdentityMLKEMPriv: identKey.MLKEMSeed,
							RelIdentityMLDSAPriv: identKey.MLDSASeed,
							RelContentPriv:       contentKey.Priv,
							RelContentMLKEMPriv:  contentKey.MLKEMSeed,
							RelContentMLDSAPriv:  contentKey.MLDSASeed,
						},
					},
				}
				if ks.IsDuress {
					if _, _, _, err := session.AddPlainContacts([]keystore.Contact{real}, nil); err != nil {
						return shared.RelSigningKey{}, shared.RelSigningKey{}, err
					}
					if err := session.SaveSlot(ksPath); err != nil {
						return shared.RelSigningKey{}, shared.RelSigningKey{}, err
					}
					return identKey, contentKey, nil
				}
				_, _, _, duressIdx, duressKi, duressPlain, err := session.AddMirroredContacts([]keystore.Contact{real}, nil, func(existingFirstNames map[string]bool) keystore.Contact {
					return buildFakeContact(cfg, existingFirstNames)
				})
				if err != nil {
					return shared.RelSigningKey{}, shared.RelSigningKey{}, err
				}
				if err := session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain); err != nil {
					return shared.RelSigningKey{}, shared.RelSigningKey{}, err
				}
				return identKey, contentKey, nil
			},
			UpdateContactRelKeys: func(pub []byte, upd tui.RelKeyUpdate) error {
				found := ks.UpdateContactByPub(pub, func(c *keystore.Contact) {
					if c.Devices == nil {
						c.Devices = map[string]*keystore.DeviceRelation{}
					}
					key := string(upd.DevicePub)
					if upd.PromoteFromPlaceholder {
						if ph, ok := c.Devices[""]; ok {
							delete(c.Devices, "")
							c.Devices[key] = ph
						}
					}
					dev, ok := c.Devices[key]
					if !ok {
						dev = &keystore.DeviceRelation{}
						c.Devices[key] = dev
					}
					if len(upd.RelIdentityPriv) > 0 {
						dev.RelIdentityPriv = upd.RelIdentityPriv
					}
					if len(upd.RelIdentityMLKEMPriv) > 0 {
						dev.RelIdentityMLKEMPriv = upd.RelIdentityMLKEMPriv
					}
					if len(upd.RelIdentityMLDSAPriv) > 0 {
						dev.RelIdentityMLDSAPriv = upd.RelIdentityMLDSAPriv
					}
					if len(upd.PeerRelIdentityPub) > 0 {
						dev.PeerRelIdentityPub = upd.PeerRelIdentityPub
					}
					if len(upd.PeerRelIdentityMLKEMPub) > 0 {
						dev.PeerRelIdentityMLKEMPub = upd.PeerRelIdentityMLKEMPub
					}
					if len(upd.PeerRelIdentityMLDSAPub) > 0 {
						dev.PeerRelIdentityMLDSAPub = upd.PeerRelIdentityMLDSAPub
					}
					if len(upd.RelContentPriv) > 0 {
						dev.RelContentPriv = upd.RelContentPriv
					}
					if len(upd.RelContentMLKEMPriv) > 0 {
						dev.RelContentMLKEMPriv = upd.RelContentMLKEMPriv
					}
					if len(upd.RelContentMLDSAPriv) > 0 {
						dev.RelContentMLDSAPriv = upd.RelContentMLDSAPriv
					}
					if len(upd.PeerRelContentPub) > 0 {
						dev.PeerRelContentPub = upd.PeerRelContentPub
					}
					if len(upd.PeerRelContentMLKEMPub) > 0 {
						dev.PeerRelContentMLKEMPub = upd.PeerRelContentMLKEMPub
					}
					if len(upd.PeerRelContentMLDSAPub) > 0 {
						dev.PeerRelContentMLDSAPub = upd.PeerRelContentMLDSAPub
					}
					if upd.Address != "" {
						dev.Address = upd.Address
					}
					if upd.RelIdentityConfirmedByPeer {
						dev.RelIdentityConfirmedByPeer = true
					}
					if upd.RelContentConfirmedByPeer {
						dev.RelContentConfirmedByPeer = true
					}
				})
				if !found {
					return errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				return session.SaveSlot(ksPath)
			},
			// ResetRelInitConfirmed: the only way to bring
			// RelIdentityConfirmedByPeer/RelContentConfirmedByPeer back to
			// false — UpdateContactRelKeys/RelKeyUpdate above only ever turn
			// them on (together), never off, by design. which
			// ("identity"|"content") picks the flag relevant to the observed
			// self-heal case: a handshake that always fails with "invalid
			// signature" against an otherwise reachable host
			// (case roomErrMsg/client.ErrInvalidServerSig, tui.go) is an
			// Identity problem; a CONTENT signature verification that never
			// checks out (messages/files) is a Content problem — resetting
			// only the relevant one avoids also blocking
			// ReadyDevices()/invites over an issue isolated to the other key.
			// devicePub identifies the exact device; empty or non-matching
			// falls back to Contact.SoleDevice().
			ResetRelInitConfirmed: func(pub, devicePub []byte, which string) error {
				var devErr error
				found := ks.UpdateContactByPub(pub, func(c *keystore.Contact) {
					dev, ok := c.DeviceByPub(devicePub)
					if !ok {
						dev, ok = c.SoleDevice()
					}
					if !ok {
						devErr = errors.New(i18n.T("keystore.err_rel_rotation_ambiguous_device"))
						return
					}
					if which == "content" {
						dev.RelContentConfirmedByPeer = false
					} else {
						dev.RelIdentityConfirmedByPeer = false
					}
				})
				if !found {
					return errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				if devErr != nil {
					return devErr
				}
				return session.SaveSlot(ksPath)
			},
			// SetPendingRelKeys records a relationship-key conflict (TrustDanger)
			// — see tui.applyRelInit. pending.DevicePub identifies the exact
			// entry in conflict — never the placeholder "" (a conflict only
			// happens on an already-confirmed device, see RelKeyUpdate).
			SetPendingRelKeys: func(pub []byte, pending tui.PendingRelKeys) error {
				devFound := false
				ks.UpdateContactByPub(pub, func(c *keystore.Contact) {
					dev, ok := c.Devices[string(pending.DevicePub)]
					if !ok {
						return
					}
					devFound = true
					dev.PendingPeerRelIdentityPub = pending.IdentityPub
					dev.PendingPeerRelIdentityMLKEMPub = pending.IdentityMLKEMPub
					dev.PendingPeerRelIdentityMLDSAPub = pending.IdentityMLDSAPub
					dev.PendingPeerRelContentPub = pending.ContentPub
					dev.PendingPeerRelContentMLKEMPub = pending.ContentMLKEMPub
					dev.PendingPeerRelContentMLDSAPub = pending.ContentMLDSAPub
				})
				if !devFound {
					return errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				return session.SaveSlot(ksPath)
			},
			// ConfirmPendingRelKeys closes the conflict above after the user's
			// explicit out-of-band confirmation (/sec-verify) — see
			// keystore.ConfirmPendingRelKeys.
			ConfirmPendingRelKeys: func(pub []byte) bool {
				if !ks.ConfirmPendingRelKeys(pub) {
					return false
				}
				_ = session.SaveSlot(ksPath)
				return true
			},
			// PromoteEphemeralContact persists a real Contact starting from an
			// ephemeral relationship already established and promoted by both
			// sides (see tui.finalizePromotion) — unlike AddContact it
			// generates no new key: myIdentKey/myContentKey and the peer's
			// pubkeys are already the ones exchanged in the room's ephemeral
			// bootstrap, only written to disk here. The peer's device is
			// never known in this flow (room ephemeral bootstrap, no
			// DevicePub exchange) — the entry lives under the placeholder key
			// "" as with AddContact, promoted to the real DevicePub by the
			// first real rel_init/rel_init_ack that follows (the same
			// treatment as a contact added from scratch).
			PromoteEphemeralContact: func(username string, transportPub, transportMLKEMPub, transportMLDSAPub []byte, myIdentKey, myContentKey shared.RelSigningKey, peerIdent shared.RelPeerKey, peerIdentMLKEMPub []byte, peerContent shared.RelPeerKey, peerContentMLKEMPub []byte) error {
				ks.AddContact(keystore.Contact{
					Username:    username,
					IdentityPub: transportPub,
					MLKEMPub:    transportMLKEMPub,
					MLDSAPub:    transportMLDSAPub,
					Devices: map[string]*keystore.DeviceRelation{
						"": {
							RelIdentityPriv:         myIdentKey.Priv,
							RelIdentityMLKEMPriv:    myIdentKey.MLKEMSeed,
							RelIdentityMLDSAPriv:    myIdentKey.MLDSASeed,
							PeerRelIdentityPub:      peerIdent.Pub,
							PeerRelIdentityMLKEMPub: peerIdentMLKEMPub,
							PeerRelIdentityMLDSAPub: peerIdent.MLDSAPub,
							RelContentPriv:          myContentKey.Priv,
							RelContentMLKEMPriv:     myContentKey.MLKEMSeed,
							RelContentMLDSAPriv:     myContentKey.MLDSASeed,
							PeerRelContentPub:       peerContent.Pub,
							PeerRelContentMLKEMPub:  peerContentMLKEMPub,
							PeerRelContentMLDSAPub:  peerContent.MLDSAPub,
						},
					},
				})
				return session.SaveSlot(ksPath)
			},
			StartRelIdentityRotationByPub: func(pub []byte) (map[string]shared.RelSigningKey, error) {
				rotated, err := ks.StartRelIdentityRotationByPub(pub)
				if err != nil {
					return nil, err
				}
				c, ok := ks.GetContactByPub(pub)
				if !ok {
					return nil, errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				keys := make(map[string]shared.RelSigningKey, len(rotated))
				for _, devKey := range rotated {
					dev := c.Devices[devKey]
					if dev == nil {
						continue
					}
					keys[devKey] = shared.RelSigningKey{Priv: dev.RelIdentityPriv, MLKEMSeed: dev.RelIdentityMLKEMPriv, MLDSASeed: dev.RelIdentityMLDSAPriv}
				}
				if err := session.SaveSlot(ksPath); err != nil {
					return nil, err
				}
				return keys, nil
			},
			StartRelContentRotationByPub: func(pub []byte) (map[string]shared.RelSigningKey, error) {
				rotated, err := ks.StartRelContentRotationByPub(pub)
				if err != nil {
					return nil, err
				}
				c, ok := ks.GetContactByPub(pub)
				if !ok {
					return nil, errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				keys := make(map[string]shared.RelSigningKey, len(rotated))
				for _, devKey := range rotated {
					dev := c.Devices[devKey]
					if dev == nil {
						continue
					}
					keys[devKey] = shared.RelSigningKey{Priv: dev.RelContentPriv, MLKEMSeed: dev.RelContentMLKEMPriv, MLDSASeed: dev.RelContentMLDSAPriv}
				}
				if err := session.SaveSlot(ksPath); err != nil {
					return nil, err
				}
				return keys, nil
			},
			MarkRelRotationConfirmed: func(pub, devicePub []byte, which string) bool {
				var ok bool
				if which == "identity" {
					ok = ks.MarkRelIdentityConfirmed(pub, devicePub)
				} else {
					ok = ks.MarkRelContentConfirmed(pub, devicePub)
				}
				if ok {
					_ = session.SaveSlot(ksPath)
				}
				return ok
			},
			MarkDeviceRevoked: func(pub, devicePub []byte, revokeIdentity, revokeContent bool) bool {
				ok := ks.MarkDeviceRevoked(pub, devicePub, revokeIdentity, revokeContent)
				if ok {
					_ = session.SaveSlot(ksPath)
				}
				return ok
			},
			AckSiblingRevocation: func(pub, peerDevicePub []byte) bool {
				ok := ks.AckSiblingRevocation(pub, peerDevicePub)
				if ok {
					_ = session.SaveSlot(ksPath)
				}
				return ok
			},
			IsDeviceNuked: ks.IsDeviceNuked,
			UpdateContactLocalName: func(pub []byte, localName string) error {
				if !ks.UpdateContactByPub(pub, func(c *keystore.Contact) { c.LocalName = localName }) {
					return errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				return session.SaveSlot(ksPath)
			},
			// KeystorePassword exposed as password_identity only — the
			// file-level password (session.PasswordFile) stays constant
			// for the whole session and is never surfaced here; the TUI's
			// lock check compares against password_identity only.
			KeystorePassword: session.PasswordIdentity,
			ChangePassword: func(oldPwd, newPwd string) error {
				// Verifies oldPwd against the ALREADY-unlocked slot (no
				// password is cached separately — see
				// UnlockedSlot.VerifyPasswordIdentity), then re-wraps K_i
				// under the new combination — the content itself is never
				// touched.
				if !session.VerifyPasswordIdentity(oldPwd) {
					return errors.New(i18n.T("cli.err_wrong_current_password"))
				}
				if !session.PasswordIdentityAvailable(newPwd) {
					return errors.New(i18n.T("keystore.err_identity_password_collision"))
				}
				if err := session.RewrapOwnSlot(session.PasswordFile, newPwd); err != nil {
					return err
				}
				return session.SaveSlot(ksPath)
			},
			SetDuress: func(newPwd string) error {
				// The shared duress identity always exists structurally in
				// the N-slot format — it can't be removed, only its own
				// password_identity can change. Reached via K_i_duress
				// (session.Identity.DuressAccess) — never duress's own OLD
				// password, which this session doesn't need to know.
				if newPwd == "" {
					return errors.New(i18n.T("wizard.err_empty_duress_password"))
				}
				if !session.PasswordIdentityAvailable(newPwd) {
					return errors.New(i18n.T("keystore.err_identity_password_collision"))
				}
				duressKi, err := keystore.OpenDuressAccess(session.Ki, ks.DuressAccess)
				if err != nil {
					return err
				}
				duressIdx, ok := keystore.FindSlotByKi(session.Container, duressKi)
				if !ok {
					return errors.New(i18n.T("keystore.err_duress_slot_not_found"))
				}
				if err := keystore.RewrapSlot(session.Container, duressIdx, duressKi, session.PasswordFile, newPwd); err != nil {
					return err
				}
				return session.SaveSlot(ksPath)
			},
			SetLockSecret: func(secret string, isPIN bool, duressMarker string, duressPosition int) error {
				ks.SetLockSecret(secret, isPIN, duressMarker, duressPosition)
				return session.SaveSlot(ksPath)
			},
			CheckLockSecret: func(candidate string) keystore.LockCheckResult {
				return ks.CheckLockSecret(candidate)
			},
			CheckDuressPassword: func(candidate string) bool {
				return session.CandidateIsDuressPassword(candidate)
			},
			InterfaceLockTimeout: cfg.InterfaceLockTimeoutDuration(),
			SaveInterfaceLockTimeout: func(d time.Duration) error {
				cfg.InterfaceLockTimeout = d.String()
				return config.Save(cfgPath, cfg)
			},
			TimeNukeTimeout: cfg.TimeNukeTimeoutDuration(),
			SaveTimeNukeTimeout: func(d time.Duration) error {
				cfg.TimeNukeTimeout = d.String()
				return config.Save(cfgPath, cfg)
			},
			FlushContactsActivity: func(acks, seen map[string]time.Time) error {
				changed := ks.UpdateContactsLastAck(acks)
				changed = ks.UpdateContactsLastSeen(seen) || changed
				if !changed {
					return nil
				}
				return session.SaveSlot(ksPath)
			},
			DHTagFn: func(peerPub ed25519.PublicKey) ([]byte, error) {
				return shared.KnockDHTag(ks.IdentityPrivKey(), peerPub)
			},
			DHTagFnOld: func(peerPub ed25519.PublicKey) ([]byte, error) {
				priv := ks.OldIdentityPrivKeyForRotation()
				if priv == nil {
					priv = ks.IdentityPrivKey()
				}
				return shared.KnockDHTag(priv, peerPub)
			},
			SignRelBootstrap: func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte {
				return shared.SignRelBootstrap(ks.IdentityPrivKey(), identityPub, contentPub, devicePub, username, ts)
			},
			SignRelBootstrapMLDSA: func(identityPub, contentPub, devicePub ed25519.PublicKey, username, ts string) []byte {
				return shared.SignRelBootstrapMLDSA(ks.MLDSAKey, identityPub, contentPub, devicePub, username, ts)
			},
			MyDevicePub: ks.DevicePubKey(),
			SignDeviceSig: func(ciphertext []byte, ts string) []byte {
				return shared.SignDeviceSig(ks.DevicePrivKey(), string(ciphertext), ts)
			},
			SignPQCSig: func(ciphertext []byte, ts string) []byte {
				return shared.SignPQCSig(ks.MLDSAPrivKey(), string(ciphertext), ts)
			},
			MyDeviceID:            ks.DeviceID,
			AuthorityPubKeys:      ks.AllAuthorityPubKeys(),
			AuthorityPubKeysMLDSA: ks.AllAuthorityPubKeysMLDSA(),
			KnownDevices:          func() []tui.DeviceRecordInfo { return convertDeviceRecords(ks.KnownDevicesSnapshot()) },
			SignRemoteNuke: func(targetDeviceID []byte, ts string) []byte {
				return shared.SignRemoteNuke(ks.IdentityPrivKey(), targetDeviceID, ts)
			},
			SignRemoteNukeMLDSA: func(targetDeviceID []byte, ts string) []byte {
				return shared.SignRemoteNukeMLDSA(ks.MLDSAPrivKey(), targetDeviceID, ts)
			},
			SignRemoteNukeAck: func(targetDeviceID []byte, ts string) []byte {
				return shared.SignRemoteNukeAck(ks.DevicePrivKey(), targetDeviceID, ts)
			},
			NetworkIdentityPubFor: func(targetDeviceID []byte) ed25519.PublicKey {
				return ks.NetworkIdentityPrivKeyFor(targetDeviceID).Public().(ed25519.PublicKey)
			},
			OldNetworkIdentityPubFor: func(targetDeviceID []byte) ed25519.PublicKey {
				priv := ks.OldNetworkIdentityPrivKeyForRotation(targetDeviceID)
				if priv == nil {
					return nil
				}
				return priv.Public().(ed25519.PublicKey)
			},
			MyMLDSAPub:          ks.MLDSAPubBytes(),
			RootRotationPending: ks.RootRotationPendingSnapshot,
			OldIdentityPub: func() ed25519.PublicKey {
				priv := ks.OldIdentityPrivKeyForRotation()
				if priv == nil {
					return nil
				}
				return priv.Public().(ed25519.PublicKey)
			},
			AckRootRotationContact: func(pub []byte) bool {
				ok := ks.AckRootRotationContact(pub)
				if ok {
					_ = session.SaveSlot(ksPath)
				}
				return ok
			},
			AckRootRotationDevice: func(deviceID []byte) bool {
				ok := ks.AckRootRotationDevice(deviceID)
				if ok {
					_ = session.SaveSlot(ksPath)
				}
				return ok
			},
			MaybeFinalizeRootRotation: func() {
				ks.MaybeFinalizeRootRotation()
				_ = session.SaveSlot(ksPath)
			},
			UpdateContactRootIdentity: func(pub []byte, newIdentityPub ed25519.PublicKey, newMLKEMPub, newMLDSAPub []byte) error {
				found := ks.UpdateContactByPub(pub, func(c *keystore.Contact) {
					// A device reachable at the old root-derived address
					// moves to the new one.
					oldAddr := addressFromPub(ed25519.PublicKey(c.IdentityPub))
					newAddr := addressFromPub(newIdentityPub)
					for _, dev := range c.Devices {
						if dev != nil && dev.Address == oldAddr {
							dev.Address = newAddr
						}
					}
					c.IdentityPub = []byte(newIdentityPub)
					if len(newMLKEMPub) > 0 {
						c.MLKEMPub = newMLKEMPub
					}
					if len(newMLDSAPub) > 0 {
						c.MLDSAPub = newMLDSAPub
					}
					c.Verified = false // the previous verification was for the old key
				})
				if !found {
					return nil
				}
				return session.SaveSlot(ksPath)
			},
			StartRootRotation: func() (ed25519.PublicKey, []byte, []byte, string, error) {
				if err := ks.StartRootRotation(); err != nil {
					return nil, nil, nil, "", err
				}
				newAddr, err := publishRootHiddenService()
				if err != nil {
					return nil, nil, nil, "", err
				}
				if err := session.SaveSlot(ksPath); err != nil {
					return nil, nil, nil, "", err
				}
				return ks.IdentityPubKey(), ks.MLKEMPubBytes(), ks.MLDSAPubBytes(), newAddr, nil
			},
			AdoptRootRotation: func(newIdentityKey, newMLKEMKey, newMLDSAKey []byte) (string, error) {
				if err := ks.AdoptRootRotation(newIdentityKey, newMLKEMKey, newMLDSAKey); err != nil {
					return "", err
				}
				newAddr, err := publishRootHiddenService()
				if err != nil {
					return "", err
				}
				if err := session.SaveSlot(ksPath); err != nil {
					return "", err
				}
				return newAddr, nil
			},
			BuildDeviceSyncRotationKnock: func(useOldKey bool, targetDeviceID []byte) (string, error) {
				priv := ks.IdentityPrivKey()
				if useOldKey {
					priv = ks.OldIdentityPrivKeyForRotation()
				}
				if priv == nil {
					return "", errors.New(i18n.T("cli.err_root_rotation_none"))
				}
				pub := priv.Public().(ed25519.PublicKey)
				tag, err := shared.KnockDHTag(priv, pub)
				if err != nil {
					return "", err
				}
				kp := shared.KnockPayload{
					Type:            "device_sync",
					FromUsername:    ks.Username,
					FromIdentityPub: pub,
					TargetDeviceID:  targetDeviceID,
					DeviceSync: &shared.DeviceSyncPayload{
						NewIdentityKey: []byte(ks.IdentityKey),
						NewMLKEMKey:    ks.MLKEMKey,
						NewMLDSAKey:    ks.MLDSAKey,
					},
				}
				return shared.EncryptKnockWithTag(pub, nil, kp, tag)
			},
			BuildDeviceSyncSyncKnock: func(useOldKey bool, targetDeviceID []byte) (string, error) {
				priv := ks.IdentityPrivKey()
				if useOldKey {
					priv = ks.OldIdentityPrivKeyForRotation()
				}
				if priv == nil {
					return "", errors.New(i18n.T("cli.err_root_rotation_none"))
				}
				pub := priv.Public().(ed25519.PublicKey)
				tag, err := shared.KnockDHTag(priv, pub)
				if err != nil {
					return "", err
				}
				syncData, err := json.Marshal(indoor.SyncPayload{
					Contacts: ks.ContactsSnapshot(),
					Device: keystore.DeviceRecord{
						DeviceID:          ks.DeviceID,
						DevicePub:         ks.DevicePub,
						Label:             ks.DeviceLabel,
						SiblingIdentities: ks.SiblingIdentityRefs(),
					},
					KnownDevices:    ks.KnownDevicesSnapshot(),
					NukedDevicePubs: ks.NukedDevicePubsSnapshot(),
				})
				if err != nil {
					return "", err
				}
				kp := shared.KnockPayload{
					Type:            "device_sync",
					FromUsername:    ks.Username,
					FromIdentityPub: pub,
					TargetDeviceID:  targetDeviceID,
					DeviceSync:      &shared.DeviceSyncPayload{SyncData: syncData},
				}
				return shared.EncryptKnockWithTag(pub, nil, kp, tag)
			},
			BuildDeviceSyncAckKnock: func(targetDeviceID []byte, includeSync bool) (string, error) {
				priv := ks.IdentityPrivKey()
				pub := priv.Public().(ed25519.PublicKey)
				tag, err := shared.KnockDHTag(priv, pub)
				if err != nil {
					return "", err
				}
				kp := shared.KnockPayload{
					Type:            "device_sync_ack",
					FromUsername:    ks.Username,
					FromIdentityPub: pub,
					TargetDeviceID:  targetDeviceID,
				}
				if includeSync {
					syncData, err := json.Marshal(indoor.SyncPayload{
						Contacts: ks.ContactsSnapshot(),
						Device: keystore.DeviceRecord{
							DeviceID:          ks.DeviceID,
							DevicePub:         ks.DevicePub,
							Label:             ks.DeviceLabel,
							SiblingIdentities: ks.SiblingIdentityRefs(),
						},
						KnownDevices:    ks.KnownDevicesSnapshot(),
						NukedDevicePubs: ks.NukedDevicePubsSnapshot(),
					})
					if err != nil {
						return "", err
					}
					kp.DeviceSync = &shared.DeviceSyncPayload{SyncData: syncData}
				}
				return shared.EncryptKnockWithTag(pub, nil, kp, tag)
			},
			ContactsSnapshot: func() []tui.ContactInfo {
				return convertContacts(ks.ContactsSnapshot(), addressFromPub)
			},
			MergeSyncedContacts: func(data []byte) ([]byte, error) {
				var p indoor.SyncPayload
				if err := json.Unmarshal(data, &p); err != nil {
					return nil, err
				}
				var added int
				var rejected [][]byte
				if ks.IsDuress {
					var aerr error
					added, _, rejected, aerr = session.AddPlainContacts(p.Contacts, p.Device.DevicePub)
					if aerr != nil {
						return nil, aerr
					}
				} else {
					var duressIdx int
					var duressKi, duressPlain []byte
					var aerr error
					added, _, rejected, duressIdx, duressKi, duressPlain, aerr = session.AddMirroredContacts(p.Contacts, p.Device.DevicePub, func(existingFirstNames map[string]bool) keystore.Contact {
						return buildFakeContact(cfg, existingFirstNames)
					})
					if aerr != nil {
						return nil, aerr
					}
					if added > 0 {
						if err := session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain); err != nil {
							return nil, err
						}
					}
				}
				if len(p.Device.DeviceID) > 0 {
					ks.AppendKnownDevice(p.Device)
				}
				ks.MergeKnownDevices(p.KnownDevices)
				ks.MergeNukedDevicePubs(p.NukedDevicePubs)
				if added == 0 || ks.IsDuress {
					if err := session.SaveSlot(ksPath); err != nil {
						return nil, err
					}
				}
				rows := rejectedTombstoneRows(ks, rejected)
				rowsJSON, err := json.Marshal(rows)
				if err != nil {
					return nil, err
				}
				return rowsJSON, nil
			},
			BuildContactTombstoneKnock: func(rows []byte) (string, error) {
				priv := ks.IdentityPrivKey()
				pub := priv.Public().(ed25519.PublicKey)
				tag, err := shared.KnockDHTag(priv, pub)
				if err != nil {
					return "", err
				}
				kp := shared.KnockPayload{
					Type:             "contact_tombstone",
					FromUsername:     ks.Username,
					FromIdentityPub:  pub,
					ContactTombstone: &shared.ContactTombstonePayload{Rows: rows},
				}
				return shared.EncryptKnockWithTag(pub, nil, kp, tag)
			},
			ApplyContactTombstoneReplies: func(rows []byte) ([]byte, error) {
				var parsed []keystore.DeletedContact
				if err := json.Unmarshal(rows, &parsed); err != nil {
					return nil, err
				}
				return json.Marshal(applyTombstoneReplies(session, ksPath, parsed))
			},
			BuildContactTombstoneAckKnock: func(acked []byte) (string, error) {
				priv := ks.IdentityPrivKey()
				pub := priv.Public().(ed25519.PublicKey)
				tag, err := shared.KnockDHTag(priv, pub)
				if err != nil {
					return "", err
				}
				kp := shared.KnockPayload{
					Type:             "contact_tombstone_ack",
					FromUsername:     ks.Username,
					FromIdentityPub:  pub,
					TargetDeviceID:   ks.DeviceID,
					ContactTombstone: &shared.ContactTombstonePayload{Acked: acked},
				}
				return shared.EncryptKnockWithTag(pub, nil, kp, tag)
			},
			ConfirmContactTombstoneAcked: func(acked []byte, peerDeviceID []byte) {
				var parsed [][]byte
				if err := json.Unmarshal(acked, &parsed); err != nil {
					return
				}
				for _, pub := range parsed {
					ks.ConfirmSiblingForDeletion(pub, peerDeviceID)
				}
				_ = session.SaveSlot(ksPath)
			},
			PendingRemoteNukeTargets: pendingRemoteNukeTargets,
			AddPendingRemoteNuke: func(targetDeviceID []byte) error {
				ks.AddPendingRemoteNuke(targetDeviceID)
				return session.SaveSlot(ksPath)
			},
			ClearPendingRemoteNuke: func(targetDeviceID []byte) error {
				if !ks.RemovePendingRemoteNuke(targetDeviceID) {
					return nil
				}
				return session.SaveSlot(ksPath)
			},
			MarkOwnDeviceNuked: func() {
				ks.MarkDeviceNuked(ks.DevicePub)
			},
			PendingDangerBroadcasts: pendingDangerBroadcasts,
			SetDangerBroadcastPending: func(targetDeviceID []byte, pubs [][]byte) error {
				ks.SetDangerBroadcastPending(targetDeviceID, pubs)
				return session.SaveSlot(ksPath)
			},
			ConfirmDangerBroadcast: func(targetDeviceID, pub []byte) error {
				if !ks.ConfirmDangerBroadcast(targetDeviceID, pub) {
					return nil
				}
				return session.SaveSlot(ksPath)
			},
			PendingDangerEnds: pendingDangerEnds,
			SetDangerEndPending: func(targetDeviceID []byte, pubs [][]byte) error {
				ks.SetDangerEndPending(targetDeviceID, pubs)
				return session.SaveSlot(ksPath)
			},
			ConfirmDangerEnd: func(targetDeviceID, pub []byte) error {
				if !ks.ConfirmDangerEnd(targetDeviceID, pub) {
					return nil
				}
				return session.SaveSlot(ksPath)
			},
			AllIdentitiesContacts: func() []tui.AllIdentityContactsInfo {
				sibs := ks.SiblingKeystores()
				out := make([]tui.AllIdentityContactsInfo, 0, len(sibs))
				for _, sib := range sibs {
					sibPriv := sib.IdentityPrivKey()
					out = append(out, tui.AllIdentityContactsInfo{
						Username:    sib.Username,
						IdentityPub: sib.IdentityPubKey(),
						Contacts:    convertContacts(sib.ContactsSnapshot(), addressFromPub),
						DHTagFn: func(peerPub ed25519.PublicKey) ([]byte, error) {
							return shared.KnockDHTag(sibPriv, peerPub)
						},
					})
				}
				return out
			},
			RunIndoorSync: func(ctx context.Context) error {
				myPayload := indoor.SyncPayload{
					Contacts: ks.ContactsSnapshot(),
					Device: keystore.DeviceRecord{
						DeviceID:          ks.DeviceID,
						DevicePub:         ks.DevicePub,
						Label:             ks.DeviceLabel,
						SiblingIdentities: ks.SiblingIdentityRefs(),
					},
					KnownDevices:    ks.KnownDevicesSnapshot(),
					NukedDevicePubs: ks.NukedDevicePubsSnapshot(),
				}
				round := buildTombstoneRound(session, ksPath)
				peer, err := indoor.RunSync(ctx, ks.IdentityPrivKey(), myPayload, round, nil)
				if err != nil {
					return err
				}
				var added int
				if ks.IsDuress {
					var aerr error
					added, _, _, aerr = session.AddPlainContacts(peer.Contacts, peer.Device.DevicePub)
					if aerr != nil {
						return aerr
					}
				} else {
					var duressIdx int
					var duressKi, duressPlain []byte
					var aerr error
					added, _, _, duressIdx, duressKi, duressPlain, aerr = session.AddMirroredContacts(peer.Contacts, peer.Device.DevicePub, func(existingFirstNames map[string]bool) keystore.Contact {
						return buildFakeContact(cfg, existingFirstNames)
					})
					if aerr != nil {
						return aerr
					}
					if added > 0 {
						ks.AppendKnownDevice(peer.Device)
						ks.MergeKnownDevices(peer.KnownDevices)
						ks.MergeNukedDevicePubs(peer.NukedDevicePubs)
						return session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain)
					}
				}
				ks.AppendKnownDevice(peer.Device)
				ks.MergeKnownDevices(peer.KnownDevices)
				ks.MergeNukedDevicePubs(peer.NukedDevicePubs)
				return session.SaveSlot(ksPath)
			},
			MyDeviceLabel: ks.DeviceLabel,
			SetDeviceLabel: func(label string) error {
				ks.SetDeviceLabel(label)
				return session.SaveSlot(ksPath)
			},
			MarkContactVerifiedByPub: func(pub []byte) error {
				if !ks.UpdateContactByPub(pub, func(c *keystore.Contact) { c.Verified = true }) {
					return errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				return session.SaveSlot(ksPath)
			},
			MarkContactUnverifiedByPub: func(pub []byte) error {
				if !ks.UpdateContactByPub(pub, func(c *keystore.Contact) { c.Verified = false }) {
					return errors.New(i18n.T("cli.err_contact_not_found", fmt.Sprintf("%x", pub)))
				}
				return session.SaveSlot(ksPath)
			},
		})
		if err != nil {
			netCleanup()
			fatal(err.Error())
		}
		if clearAllRequested {
			// /sec-clear-all, confirmed in the TUI — unlike
			// nukeRequested/duressWipeRequested below, this terminates the
			// process: the keystore file itself must no longer exist
			// afterward, never just a swap to the duress identity.
			netCleanup()
			wipeConfigDir(ksPath)
			os.Exit(0)
		}
		if nukeRequested || duressWipeRequested {
			// This identity (ks, this iteration's session.Identity) may
			// ALREADY be the
			// shared duress one — a SECOND /nukex (or any other trigger
			// sharing this path: time, lock-screen duress, remote_nuke)
			// fired after an earlier one already promoted this same
			// process. The sequence below ends with
			// ObliterateSlot(session.Container, session.Idx) — at this
			// point session.Idx would be duress's OWN slot, the single
			// structural anchor every real identity in the file reaches
			// via DuressAccess: destroying it would leave the file
			// unopenable by ANY password, real or duress, forever.
			// Nothing is lost by refusing: duress never regenerates a
			// protection scheme of its own (see PromoteDuress's own doc
			// comment), so a repeat trigger has no further state to
			// swap into anyway. No-op, loop back into this same
			// already-duress session completely unchanged — same "never
			// print anything" principle as every other step of this
			// sequence: an observer must see no difference between a
			// trigger that did something and one that had nothing left
			// to do.
			if ks.IsDuress {
				continue
			}
			// Same swap sequence for every trigger — /nukex, the timed
			// nuke, remote_nuke on the TARGET side (nukeRequested), and a
			// duress secret recognized at the interface lock screen while
			// the session was already active (duressWipeRequested: the
			// TUI's own armDuressWipe already runs the same device-sync
			// fan-out as cmdNukeX before setting this flag — see
			// internal/client/tui/tui.go). The file is never deleted.
			//
			// Rescue pod: assembled and spawned WHILE ks is still
			// its pre-overwrite self (its real contacts) — must happen
			// BEFORE OverwriteAllContacts below empties them. node stays
			// alive (never netCleanup() here): the whole point of this
			// loop is that Tor/I2P and this process never stop. Covers
			// only the identity this process ran with: a sibling identity
			// in the same file (if any) isn't included here.
			if exePath, err := os.Executable(); err == nil {
				snap := keystore.BuildPodSnapshot([]*keystore.Keystore{ks}, func(pub []byte) string {
					return addressFromPub(ed25519.PublicKey(pub))
				}, node.ProxyAddr(), netKind)
				if len(snap.Targets) > 0 {
					client.Dbg("rescue pod: starting separate process for %d contact(s)", len(snap.Targets))
					if perr := spawnPod(exePath, []string{"__pod"}, nil, snap); perr != nil {
						client.Dbg("rescue pod: start failed: %v", perr)
					}
				}
			}
			runNukeOverwriteInPlace(session, ksPath)
			promoted, perr := session.PromoteDuress()
			if perr != nil {
				// Should never happen in practice — every real identity's
				// shared duress exists structurally in this slot format.
				// Safe fallback rather than looping with a broken
				// session: tear down and exit. The file itself was never
				// touched beyond the
				// overwrite above, so the next launch's ordinary login
				// still works correctly either way.
				netCleanup()
				os.Exit(0)
			}
			session = promoted
			// This device's hidden service/server goroutine above is now
			// abandoned, not torn down — see the loop's own doc comment
			// above: never a new observable signal like an onion address
			// going dark. The loop republishes a NEW hidden service for
			// the promoted identity and runs the TUI again, on the SAME
			// node/ctx — no password prompt, no network restart.
			continue
		}
		netCleanup()
		return
	}
}

// ── first-run wizard ───────────────────────────────────────────────────────

// chooseLang asks for the interface language. It's the only text in the
// program that must stay literal in every supported language: the
// catalogs can't be consulted yet, since this very answer determines
// which one to use — each language name is written in that language
// itself (never translated).
func chooseLang() i18n.Lang {
	fmt.Println("Language / Lingua / Langue / Sprache / Idioma / Limbă / Язык:")
	fmt.Println("  1. English")
	fmt.Println("  2. Italiano")
	fmt.Println("  3. Français")
	fmt.Println("  4. Deutsch")
	fmt.Println("  5. Español")
	fmt.Println("  6. Română")
	fmt.Println("  7. Русский")
	fmt.Print("Choice / Scelta [1]: ")
	switch strings.TrimSpace(readLine()) {
	case "2":
		return i18n.LangIT
	case "3":
		return i18n.LangFR
	case "4":
		return i18n.LangDE
	case "5":
		return i18n.LangES
	case "6":
		return i18n.LangRO
	case "7":
		return i18n.LangRU
	default:
		return i18n.LangEN
	}
}

// zeroBytes overwrites b with zeros so the raw bytes read by
// term.ReadPassword don't stay in the heap beyond their use — doesn't
// eliminate the immutable copy made by string(b) (a Go limitation:
// strings can't be zeroed), but closes the exposure window of the
// original slice, the only one under direct control.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// promptNewKeystorePassword asks for a new password — promptKey picks
// the label shown (the file password or a specific identity's own
// password: the two are independent in the N-slot format, see
// unlockKeystoreSession) — offering automatic generation of a secure
// passphrase (7 BIP-39 wordlist words, ~77 bits of entropy — see
// shared.GeneratePassphrase) as an alternative to manual typing. With
// manual typing it still shows a strength estimate after entry, purely
// informational: it doesn't block weak passwords, the real defense
// against offline brute-force remains Argon2id. Shared by the initial
// wizard, "neutrino add-identity" and "neutrino restore" — the field
// itself is always the same generic "Password: " prompt, never specific
// to file/identity/duress: the caller prints its own intro line right
// before this is called, so the field never needs to repeat it.
func promptNewKeystorePassword() string {
	fmt.Print(i18n.T("wizard.passphrase_offer_prompt"))
	if strings.ToLower(strings.TrimSpace(readLine())) == i18n.T("common.yes") {
		words, err := shared.GeneratePassphrase(7)
		if err != nil {
			fatal(i18n.T("wizard.err_passphrase_gen", err))
		}
		fmt.Println()
		fmt.Println(i18n.T("wizard.passphrase_generated_header"))
		fmt.Println()
		fmt.Println("  " + words)
		fmt.Println()
		fmt.Print(i18n.T("wizard.passphrase_confirm_written"))
		readLine()
		fmt.Println()
		return words
	}

	for {
		fmt.Print(i18n.T("wizard.password_prompt"))
		pwd1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fatal(i18n.T("common.err_read_password", err))
		}
		if len(pwd1) == 0 {
			printRetryError(i18n.T("wizard.err_empty_password"))
			continue
		}
		fmt.Print(i18n.T("wizard.password_strength", shared.PasswordStrength(string(pwd1)).Label()))

		fmt.Print(i18n.T("common.password_confirm_prompt"))
		pwd2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fatal(i18n.T("common.err_read_password", err))
		}
		mismatch := string(pwd1) != string(pwd2)
		zeroBytes(pwd2)
		if mismatch {
			zeroBytes(pwd1)
			printRetryError(i18n.T("common.err_passwords_mismatch"))
			continue
		}
		result := string(pwd1)
		zeroBytes(pwd1)
		return result
	}
}

// promptDuressSetup sets up the shared decoy identity — mandatory in
// the N-slot keystore format, never optional (a file always has
// exactly one duress identity, structurally). Asks for a username (the
// decoy is in every respect a second real identity, own name included)
// and its own password_identity — which
// must differ from the real one just chosen in this same wizard,
// otherwise the same combination would always open the same identity
// and duress could never be reached.
func promptDuressSetup(realPasswordIdentity string) (duressUsername, duressPasswordIdentity string) {
	fmt.Println()
	fmt.Println(i18n.T("wizard.duress_intro"))

	for duressUsername == "" {
		duressUsername = prompt(i18n.T("wizard.duress_username_prompt"))
		if duressUsername == "" {
			printRetryError(i18n.T("wizard.err_username_required"))
		}
	}

	for {
		fmt.Print(i18n.T("wizard.password_prompt"))
		pwd1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fatal(i18n.T("common.err_read_password", err))
		}
		if len(pwd1) == 0 {
			printRetryError(i18n.T("wizard.err_empty_duress_password"))
			continue
		}
		if string(pwd1) == realPasswordIdentity {
			zeroBytes(pwd1)
			printRetryError(i18n.T("wizard.err_duress_same_as_real"))
			continue
		}
		fmt.Print(i18n.T("wizard.password_strength", shared.PasswordStrength(string(pwd1)).Label()))

		fmt.Print(i18n.T("common.password_confirm_prompt"))
		pwd2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fatal(i18n.T("common.err_read_password", err))
		}
		mismatch := string(pwd1) != string(pwd2)
		zeroBytes(pwd2)
		if mismatch {
			zeroBytes(pwd1)
			printRetryError(i18n.T("common.err_passwords_mismatch"))
			continue
		}
		duressPasswordIdentity = string(pwd1)
		zeroBytes(pwd1)
		return duressUsername, duressPasswordIdentity
	}
}

func runWizard(ksPath, cfgPath string) (*keystore.UnlockedSlot, config.Config) {
	lang := chooseLang()
	i18n.SetActive(lang)

	fmt.Println(i18n.T("wizard.welcome"))
	fmt.Println(i18n.T("wizard.intro"))
	fmt.Println()

	username := prompt(i18n.T("wizard.username_prompt"))
	if username == "" {
		fatal(i18n.T("wizard.err_username_required"))
	}

	fmt.Println()
	fmt.Println(i18n.T("wizard.file_password_intro"))
	passwordFile := promptNewKeystorePassword()

	fmt.Println()
	fmt.Println(i18n.T("wizard.identity_password_intro"))
	passwordIdentity := promptNewKeystorePassword()

	duressUsername, duressPasswordIdentity := promptDuressSetup(passwordIdentity)

	qrPath := filepath.Join(filepath.Dir(ksPath), fmt.Sprintf("identity-qr-%s.png", username))
	ks, err := createIdentity(username, qrPath)
	if err != nil {
		fatal(err.Error())
	}

	// Device name — asked ONLY here, at file creation (never from
	// add-identity, which adds an identity to the SAME device, never a
	// new one). Without a name chosen by the user, a device's only
	// identifier is its DeviceID (16 random bytes): impossible to tell
	// "Galaxy S22" from "work laptop" apart at a glance among known
	// devices — see Keystore.DeviceLabel.
	hostname, _ := os.Hostname()
	defaultLabel := hostname
	if defaultLabel == "" {
		defaultLabel = i18n.T("wizard.device_label_default_fallback")
	}
	deviceLabel := prompt(fmt.Sprintf(i18n.T("wizard.device_label_prompt"), defaultLabel))
	if deviceLabel == "" {
		deviceLabel = defaultLabel
	}
	return createKeystoreFile(ksPath, cfgPath, lang, ks, deviceLabel, duressUsername, passwordFile, passwordIdentity, duressPasswordIdentity)
}

// createKeystoreFile writes a brand-new keystore file holding ks plus
// the mandatory duress identity, and the initial config — the last
// step of the first-run wizard, shared with agent mode (which supplies
// the same inputs without a terminal).
func createKeystoreFile(ksPath, cfgPath string, lang i18n.Lang, ks *keystore.Keystore, deviceLabel, duressUsername, passwordFile, passwordIdentity, duressPasswordIdentity string) (*keystore.UnlockedSlot, config.Config) {
	ks.SetDeviceLabel(deviceLabel)

	// keystore.New directly, not createIdentity: the decoy identity is
	// never meant to publish its own QR/public key during the wizard —
	// it only matters once reached.
	duress, err := keystore.New(duressUsername)
	if err != nil {
		fatal(i18n.T("wizard.err_identity_key", err))
	}
	duress.SetDeviceLabel(deviceLabel)

	session, err := keystore.CreateFile(ksPath, passwordFile, passwordIdentity, duressPasswordIdentity, ks, duress)
	if err != nil {
		fatal(i18n.T("wizard.err_save_keystore", err))
	}
	cfg := config.Default()
	cfg.Lang = string(lang)
	if err := config.Save(cfgPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("wizard.warn_save_config", err))
	} else {
		fmt.Print(i18n.T("wizard.config_saved", cfgPath))
	}
	fmt.Print(i18n.T("wizard.keystore_saved", ksPath))
	return session, cfg
}

// createIdentity performs the steps to create a single identity — Ed25519
// transport key, QR code — shared between the first-run wizard and
// "neutrino add-identity". The caller has already chosen/validated the
// username and the path where to save the QR.
func createIdentity(username, qrPath string) (*keystore.Keystore, error) {
	ks, err := keystore.New(username)
	if err != nil {
		return nil, errors.New(i18n.T("wizard.err_identity_key", err))
	}

	fmt.Println()
	if err := printAndSaveQR(ks.Username, ks.IdentityPubKey(), ks.MLKEMPubBytes(), ks.MLDSAPubBytes(), qrPath, false); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("wizard.warn_qr", err))
		fmt.Print(i18n.T("wizard.public_key_manual", base64.StdEncoding.EncodeToString(ks.IdentityPubKey())))
	}

	return ks, nil
}

// ── unlock keystore ─────────────────────────────────────────────────────────

// unlockKeystoreSession asks for the two-password combination (file +
// identity) and tries
// it against every slot in ksPath's container (keystore.LoadAndUnlock)
// — whichever slot answers IS the identity for this session, real or
// the shared duress one: no separate "wrong password vs. duress
// detected" branch, by design (see slots.go, unwrapKi).
// The moment the matched slot recognizes itself as duress
// (session.Identity.IsDuress), EVERY other slot in the container —
// every real identity, any pre-existing noise, all of it — is
// overwritten in place with fresh random bytes (ObliterateOtherSlots)
// and the container is written back to disk before this function even
// returns: synchronous and immediate, so a kill right after login still
// leaves the destruction already committed. This never needs any other
// slot's password — see slot_obliterate.go. A non-matching combination
// exits via fatal() with the exact same message as any other open
// failure — never distinguishable from "this is the duress password".
func unlockKeystoreSession(ksPath string) *keystore.UnlockedSlot {
	fmt.Print(i18n.T("cli.password_file_prompt"))
	pwdFileBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal(i18n.T("common.err_read_password", err))
	}
	pwdFile := string(pwdFileBytes)
	zeroBytes(pwdFileBytes)

	fmt.Print(i18n.T("cli.password_identity_prompt"))
	pwdIdentityBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal(i18n.T("common.err_read_password", err))
	}
	pwdIdentity := string(pwdIdentityBytes)
	zeroBytes(pwdIdentityBytes)

	return openKeystoreSession(ksPath, pwdFile, pwdIdentity)
}

// openKeystoreSession tries the password combination against ksPath
// and, if the matched slot is the duress identity, obliterates every
// other slot before returning — see unlockKeystoreSession. Shared with
// agent mode, which supplies the passwords without a terminal.
func openKeystoreSession(ksPath, pwdFile, pwdIdentity string) *keystore.UnlockedSlot {
	session, ok, err := keystore.LoadAndUnlock(ksPath, pwdFile, pwdIdentity)
	if err != nil {
		fatal(i18n.T("cli.err_open_keystore", err))
	}
	if !ok {
		fatal(i18n.T("cli.err_open_keystore", errors.New(i18n.T("keystore.err_wrong_password"))))
	}

	if session.Identity.IsDuress {
		if err := keystore.ObliterateOtherSlots(session.Container, session.Idx); err == nil {
			_ = keystore.WriteSlotContainer(ksPath, session.Container)
		}
	}

	return session
}

// ── add-identity ─────────────────────────────────────────────────────────────

// runAddIdentity creates a new real identity in the SAME file, under
// its own new password_identity (same password_file as the session
// used to unlock) — consumes one pending noise slot and lets 2 new
// ones replace it. It never requires knowing any OTHER identity's
// password: each identity is independently encrypted, this call only
// ever touches the session's own
// SlotPendingNoise bookkeeping and the brand-new identity's slot.
func runAddIdentity() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		fatal(i18n.T("cli.err_no_keystore_yet"))
	}

	session := unlockKeystoreSession(ksPath)

	username := prompt(i18n.T("wizard.username_prompt"))
	if username == "" {
		fatal(i18n.T("wizard.err_username_required"))
	}

	qrPath := filepath.Join(filepath.Dir(ksPath), fmt.Sprintf("identity-qr-%s.png", username))
	newKs, err := createIdentity(username, qrPath)
	if err != nil {
		fatal(err.Error())
	}
	newKs.SetDeviceLabel(session.Identity.DeviceLabel)

	fmt.Println()
	fmt.Println(i18n.T("wizard.identity_password_intro"))
	newPasswordIdentity := promptNewKeystorePassword()
	if !session.PasswordIdentityAvailable(newPasswordIdentity) {
		fatal(i18n.T("keystore.err_identity_password_collision"))
	}

	if _, _, err := session.AddRealIdentity(newPasswordIdentity, newKs); err != nil {
		fatal(err.Error())
	}
	if err := session.SaveSlot(ksPath); err != nil {
		fatal(i18n.T("wizard.err_save_keystore", err))
	}
	fmt.Print(i18n.T("cli.identity_added", username))
}

// ── install ──────────────────────────────────────────────────────────────────

func runInstall() {
	binPath, err := os.Executable()
	if err != nil {
		binPath = "/usr/local/bin/neutrino"
	}

	unit := fmt.Sprintf(`[Unit]
Description=neutrino encrypted terminal chat
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
MemorySwapMax=0
KillMode=process

[Install]
WantedBy=multi-user.target`, binPath)

	fmt.Println(i18n.T("install.step1"))
	fmt.Print(i18n.T("install.tee_command", unit))
	fmt.Println()
	fmt.Println(i18n.T("install.step2"))
	fmt.Println("systemctl daemon-reload")
	fmt.Println("systemctl enable neutrino")
	fmt.Println("systemctl start neutrino")
	fmt.Println()
	fmt.Println(i18n.T("install.useful_commands"))
	fmt.Println(i18n.T("install.cmd_status"))
	fmt.Println(i18n.T("install.cmd_logs"))
	fmt.Println(i18n.T("install.cmd_stop"))
	fmt.Println(i18n.T("install.cmd_restart"))
}

// ── helpers ──────────────────────────────────────────────────────────────────

func configPath(ksPath string) string {
	return filepath.Join(filepath.Dir(ksPath), "config.json")
}

func runResetConfig() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	cfgPath := configPath(ksPath)
	if err := config.Save(cfgPath, config.Default()); err != nil {
		fatal(i18n.T("cli.err_write_config", err))
	}
	fmt.Print(i18n.T("cli.config_reset_done", cfgPath))
}

// runLang shows or sets the language saved in config. Run from the shell,
// before or after using neutrino — it's not a TUI command: the language
// never changes live in an already-running session.
func runLang(args []string) {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	cfgPath := configPath(ksPath)
	cfg, err := config.Load(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn_invalid_config", err))
	}
	i18n.SetActive(i18n.ParseLang(cfg.Lang))

	if len(args) == 0 {
		fmt.Print(i18n.T("cli.lang_current", cfg.Lang))
		return
	}

	arg := strings.ToLower(strings.TrimSpace(args[0]))
	switch i18n.Lang(arg) {
	case i18n.LangIT, i18n.LangEN, i18n.LangFR, i18n.LangDE, i18n.LangES, i18n.LangRO, i18n.LangRU:
	default:
		fatal(i18n.T("cli.lang_invalid", args[0]))
	}

	cfg.Lang = arg
	if err := config.Save(cfgPath, cfg); err != nil {
		fatal(i18n.T("cli.err_write_config", err))
	}
	i18n.SetActive(i18n.Lang(arg))
	fmt.Print(i18n.T("cli.lang_set", arg))
}

// runNet shows or sets the transport network saved in config. Like
// runLang, it's not a TUI command: the network is chosen at startup,
// never live in an already-running session.
func runNet(args []string) {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	cfgPath := configPath(ksPath)
	cfg, err := config.Load(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn_invalid_config", err))
	}
	i18n.SetActive(i18n.ParseLang(cfg.Lang))

	if len(args) == 0 {
		fmt.Print(i18n.T("cli.net_current", cfg.Net))
		return
	}

	kind, err := transport.ParseKind(args[0])
	if err != nil {
		fatal(i18n.T("cli.net_invalid", args[0]))
	}

	cfg.Net = string(kind)
	if err := config.Save(cfgPath, cfg); err != nil {
		fatal(i18n.T("cli.err_write_config", err))
	}
	fmt.Print(i18n.T("cli.net_set", cfg.Net))
}

// runDebug starts Neutrino normally (the same path as `neutrino` with no
// arguments: wizard on first run, TUI otherwise) with internal debug
// (dbg(), see internal/client/debug.go) active from the very first
// instant and written directly to a file — not to the Console tab, which
// lives only in RAM and disappears if the process dies in a crash.
// Intended to capture what happens right before a crash that would
// otherwise leave no other output, without having to manually open
// /debug on at every startup.
func runDebug(filename, bridgesFile, netFlag string) {
	stop, err := client.SetDebugFile(filename)
	if err != nil {
		fatal(i18n.T("cli.err_debug_file", filename, err))
	}
	defer stop()
	runMain(bridgesFile, netFlag)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func runUseBridges(args []string) {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	cfgPath := configPath(ksPath)
	cfg, err := config.Load(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn_invalid_config", err))
	}
	i18n.SetActive(i18n.ParseLang(cfg.Lang))

	if len(args) == 0 {
		fmt.Print(i18n.T("cli.use_bridges_current", onOff(cfg.BridgesEnabled)))
		return
	}

	arg := strings.ToLower(strings.TrimSpace(args[0]))
	var enabled bool
	switch arg {
	case "on":
		enabled = true
	case "off":
		enabled = false
	default:
		fatal(i18n.T("cli.use_bridges_invalid", args[0]))
	}

	cfg.BridgesEnabled = enabled
	if err := config.Save(cfgPath, cfg); err != nil {
		fatal(i18n.T("cli.err_write_config", err))
	}
	fmt.Print(i18n.T("cli.use_bridges_set", onOff(enabled)))
}

func bridgesPath(ksPath string) string {
	return filepath.Join(filepath.Dir(ksPath), "tor_bridges")
}

// convertContacts converts a list of keystore.Contact into internal/client's
// mirror type (tui.ContactInfo), recomputing NetAddr from addressFromPub
// (never persisted on Contact) — used both for the active identity's
// contact list and, for each sibling identity, by the danger_end
// broadcast (AllIdentitiesContacts).
func convertContacts(contacts []keystore.Contact, addressFromPub func(ed25519.PublicKey) string) []tui.ContactInfo {
	out := make([]tui.ContactInfo, 0, len(contacts))
	for _, c := range contacts {
		if len(c.IdentityPub) != 32 {
			continue
		}
		out = append(out, tui.ContactInfo{
			Username:        c.Username,
			LocalName:       c.LocalName,
			NetAddr:         addressFromPub(c.IdentityPub),
			IdentityPub:     c.IdentityPub,
			LastAckAt:       c.LastAckAt,
			LastSeenAt:      c.LastSeenAt,
			Verified:        c.Verified,
			IntroducedBy:    c.IntroducedBy,
			IntroducedByPub: c.IntroducedByPub,
			MLKEMPub:        c.MLKEMPub,
			MLDSAPub:        c.MLDSAPub,
			KnownDevicePub:  c.KnownDevicePub,
			// CloneDevices: tui.ContactInfo is an independent mirror of the
			// keystore — Devices is a map, copying the Contact struct
			// doesn't isolate it (see keystore.Contact.CloneDevices).
			// Without this, any mutation of a *DeviceRelation inside
			// tui.go (applyRelInit and similar, which assume a mirror
			// safely mutable outside ks.mu) would silently write into the
			// live keystore too.
			Devices:            c.CloneDevices(),
			SiblingRevocations: c.SiblingRevocations,
		})
	}
	return out
}

// convertDangerPending converts a list of keystore.DangerBroadcastPending
// into internal/client's mirror type — used both for
// PendingDangerBroadcasts (preliminary) and PendingDangerEnds (final).
func convertDangerPending(pending []keystore.DangerBroadcastPending) []tui.DangerBroadcastPendingInfo {
	out := make([]tui.DangerBroadcastPendingInfo, 0, len(pending))
	for _, p := range pending {
		out = append(out, tui.DangerBroadcastPendingInfo{
			TargetDeviceID: p.TargetDeviceID,
			IdentityPubs:   p.IdentityPubs,
		})
	}
	return out
}

// convertDeviceRecords converts a list of keystore.DeviceRecord into
// internal/client's mirror type (tui.DeviceRecordInfo) — the same
// conversion for both KnownDevices (list of known devices) and
// PendingRemoteNukeTargets (remote_nuke queue to retry at startup),
// avoiding duplicating the loop twice.
func convertDeviceRecords(recs []keystore.DeviceRecord) []tui.DeviceRecordInfo {
	out := make([]tui.DeviceRecordInfo, 0, len(recs))
	for _, rec := range recs {
		refs := make([]tui.DeviceIdentityRef, len(rec.SiblingIdentities))
		for i, ref := range rec.SiblingIdentities {
			refs[i] = tui.DeviceIdentityRef{Username: ref.Username, IdentityPub: ref.IdentityPub, MLKEMPub: ref.MLKEMPub}
		}
		out = append(out, tui.DeviceRecordInfo{
			DeviceID:          rec.DeviceID,
			DevicePub:         rec.DevicePub,
			Label:             rec.Label,
			AddedAt:           rec.AddedAt,
			SiblingIdentities: refs,
		})
	}
	return out
}

const bridgesBaseURL = "https://bridges.torproject.org/bridges/en?transport="

var reHTMLTag = regexp.MustCompile(`<[^>]+>`)

func fetchBridges(transport string) ([]string, error) {
	url := bridgesBaseURL + transport
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(i18n.T("cli.err_unexpected_response", resp.Status))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	text := reHTMLTag.ReplaceAllString(string(body), " ")
	text = strings.ReplaceAll(text, "&#10;", "\n")
	text = strings.ReplaceAll(text, "&amp;", "&")

	prefix := transport + " "
	var bridges []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if strings.HasPrefix(line, prefix) {
			bridges = append(bridges, line)
		}
	}
	return bridges, nil
}

func runRemoveAllBridges() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	bPath := bridgesPath(ksPath)
	if _, err := os.Stat(bPath); os.IsNotExist(err) {
		fmt.Println(i18n.T("bridges.none_found"))
		return
	}
	fmt.Print(i18n.T("bridges.remove_all_prompt", bPath))
	answer := strings.TrimSpace(readLine())
	if !strings.EqualFold(answer, i18n.T("common.yes")) {
		fmt.Println(i18n.T("common.cancelled"))
		return
	}
	if err := os.Remove(bPath); err != nil {
		fatal(i18n.T("bridges.err_remove", err))
	}
	fmt.Println(i18n.T("bridges.removed"))
}

func runGetBridges() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	bPath := bridgesPath(ksPath)

	var all []string
	for _, transport := range []string{"obfs4", "webtunnel"} {
		fmt.Print(i18n.T("bridges.downloading", transport))
		bridges, err := fetchBridges(transport)
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("bridges.warn_transport", transport, err))
			continue
		}
		fmt.Print(i18n.T("bridges.found_count", len(bridges)))
		all = append(all, bridges...)
	}

	if len(all) == 0 {
		fatal(i18n.T("bridges.err_none_found"))
	}

	content := strings.Join(all, "\n") + "\n"
	if err := os.WriteFile(bPath, []byte(content), 0600); err != nil {
		fatal(i18n.T("bridges.err_save", err))
	}

	fmt.Print(i18n.T("bridges.saved_count", len(all), bPath))
	for _, b := range all {
		fmt.Printf("  %s\n", b)
	}
}

// runAddBridges acquires bridge lines from a QR code — useful when this
// device has no direct internet access (censored network) but the user
// has a connected phone: the bridges.torproject.org page shown on the
// phone already includes a QR with the bridge lines. Two sources, the
// same `internal/qrscan` already used by `/cnt-read-qrcode` on the TUI
// — no new external dependency:
// `args[0] == "--camera"` reads from the first available V4L2 webcam
// (Linux desktop only, see qrscan.ScanCamera/camera_other.go), otherwise
// args[0] is the path to an image file (a screenshot of the QR, any
// platform). Decoded lines are ADDED to tor_bridges (never overwritten):
// this allows accumulating bridges from multiple successive scans,
// discarding exact duplicates.
func runAddBridges(args []string) {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("cli.add_bridges_usage"))
		os.Exit(1)
	}

	var text string
	if args[0] == "--camera" {
		fmt.Print(i18n.T("bridges.camera_wait"))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		text, err = qrscan.ScanCamera(ctx, nil)
		if err != nil {
			fatal(i18n.T("bridges.err_camera_scan", err))
		}
	} else {
		text, err = qrscan.DecodeQRFile(args[0])
		if err != nil {
			fatal(i18n.T("bridges.err_qr_decode", err))
		}
	}

	var scanned []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			scanned = append(scanned, line)
		}
	}
	if len(scanned) == 0 {
		fatal(i18n.T("bridges.err_qr_no_lines"))
	}

	bPath := bridgesPath(ksPath)
	existing, _ := os.ReadFile(bPath) // ok if it doesn't exist yet (first acquisition)
	seen := make(map[string]bool)
	var merged []string
	for _, line := range strings.Split(string(existing), "\n") {
		if line = strings.TrimSpace(line); line != "" && !seen[line] {
			seen[line] = true
			merged = append(merged, line)
		}
	}
	added := 0
	for _, line := range scanned {
		if !seen[line] {
			seen[line] = true
			merged = append(merged, line)
			added++
		}
	}

	if err := os.WriteFile(bPath, []byte(strings.Join(merged, "\n")+"\n"), 0600); err != nil {
		fatal(i18n.T("bridges.err_save", err))
	}
	fmt.Print(i18n.T("bridges.added_from_qr", added, len(merged), bPath))
}

// ── animated QR optical transfer (fountain coding) ──────────────────────────
//
// Out-of-band file exchange, with no network at all (neither Tor/I2P nor
// BLE) — the only requirement is that sender and receiver can see each
// other (the sender's screen, the receiver's camera). Encrypted with a
// password (Argon2id, same parameters as the keystore — see
// internal/keystore.deriveKey) because the channel is by definition
// visible to anyone watching the screen during transmission, not just
// the intended recipient.

// qrOpticalArgonTime/Memory/Threads/KeyLen — same values as
// internal/keystore (not exported from that package, duplicated here:
// they're Argon2id constants, not shared state, no risk of silent
// divergence).
const (
	qrOpticalArgonTime    = 3
	qrOpticalArgonMemory  = 64 * 1024
	qrOpticalArgonThreads = 4
	qrOpticalKeyLen       = 32
	qrOpticalSaltLen      = 16
	qrOpticalFrameDelay   = 350 * time.Millisecond
	qrOpticalScanTimeout  = 10 * time.Minute
)

func qrOpticalDeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, qrOpticalArgonTime, qrOpticalArgonMemory, qrOpticalArgonThreads, qrOpticalKeyLen)
}

// runQRSend reads a file and displays it as an endless sequence of
// animated QR codes (fountain coding, internal/qroptical) — keeps running
// until the user interrupts with Ctrl-C: the sender has no way of knowing
// when the receiver has finished (no return channel), it must wait for
// their confirmation out of band (by voice, or in any case not on this
// same channel).
func runQRSend(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("cli.qr_send_usage"))
		os.Exit(1)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fatal(i18n.T("cli.err_qr_read_file", err))
	}

	// The compression flag's default reflects strong_compression_enabled
	// in config.json (the same field that governs /grp-file-send): every
	// transfer, including this one, offers the flag with the default
	// already set from config.json.
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_keystore_path", err))
	}
	cfg, cfgErr := config.Load(configPath(ksPath))
	if cfgErr != nil && !errors.Is(cfgErr, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warn_invalid_config", cfgErr))
	}
	promptKey := "cli.qr_send_compress_prompt_default_off"
	if cfg.StrongCompressionEnabled {
		promptKey = "cli.qr_send_compress_prompt_default_on"
	}
	compressAns := strings.ToLower(prompt(i18n.T(promptKey)))
	strongCompression := cfg.StrongCompressionEnabled
	if cfg.StrongCompressionEnabled && compressAns == i18n.T("common.no") {
		strongCompression = false
	}
	if !cfg.StrongCompressionEnabled && compressAns == i18n.T("common.yes") {
		strongCompression = true
	}
	data, err = shared.PackData(data, strongCompression)
	if err != nil {
		fatal(i18n.T("cli.err_qr_encrypt", err))
	}

	fmt.Print(i18n.T("cli.qr_transfer_password_prompt"))
	pwd1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal(i18n.T("common.err_read_password", err))
	}
	fmt.Print(i18n.T("common.password_confirm_prompt"))
	pwd2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal(i18n.T("common.err_read_password", err))
	}
	mismatch := string(pwd1) != string(pwd2)
	zeroBytes(pwd2)
	if mismatch {
		zeroBytes(pwd1)
		fatal(i18n.T("common.err_passwords_mismatch"))
	}
	password := string(pwd1)
	zeroBytes(pwd1)

	salt := make([]byte, qrOpticalSaltLen)
	if _, err := rand.Read(salt); err != nil {
		fatal(i18n.T("cli.err_qr_encrypt", err))
	}
	key := qrOpticalDeriveKey(password, salt)
	encoded, err := shared.Encrypt(key, data, nil)
	if err != nil {
		fatal(i18n.T("cli.err_qr_encrypt", err))
	}
	cipherRaw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		fatal(i18n.T("cli.err_qr_encrypt", err))
	}
	payload := append(append([]byte(nil), salt...), cipherRaw...)

	sendAnimatedQRLoop(payload, "cli.qr_send_intro")
}

// sendAnimatedQRLoop displays a continuous stream of animated QR codes
// (fountain code, internal/qroptical) for payload, already prepared
// (already encrypted by the caller) — core shared by runQRSend (which
// encrypts with the user's password before calling it) and the animated
// backup/sync variants (already encrypted by the keystore/mnemonic, no
// additional password). Infinite loop: the protocol doesn't know when
// the receiver has finished, the user interrupts with Ctrl-C after an
// out-of-band confirmation. introMsgKey receives sender.K() as its only
// argument.
func sendAnimatedQRLoop(payload []byte, introMsgKey string) {
	sender, err := qroptical.NewSender(payload, 0)
	if err != nil {
		fatal(i18n.T("cli.err_qr_encrypt", err))
	}

	fmt.Print(i18n.T(introMsgKey, sender.K()))
	frames := 0
	for {
		text := sender.NextFrame()
		q, err := qrcode.New(text, qrcode.Medium)
		if err != nil {
			fatal(i18n.T("cli.err_qr_optical_gen", err))
		}
		frames++
		fmt.Print("\033[H\033[2J")
		fmt.Println(q.ToSmallString(false))
		fmt.Print(i18n.T("cli.qr_send_status", frames, sender.K()))
		time.Sleep(qrOpticalFrameDelay)
	}
}

// receiveAnimatedQR reads a stream of animated QR codes (fountain code,
// internal/qroptical) from the webcam until it reconstructs the whole
// payload or the timeout expires — core shared by runQRReceive (which
// then decrypts the payload with the user's password) and the animated
// restore/sync-import variants (which instead decrypt with the 24-word
// mnemonic, no additional password).
func receiveAnimatedQR(timeout time.Duration) ([]byte, error) {
	fmt.Print(i18n.T("cli.qr_receive_wait"))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	recv := qroptical.NewReceiver()
	lastPrinted := -1
	scanErr := qrscan.ScanCameraContinuous(ctx, nil, func(text string) bool {
		recv.AddFrameText(text)
		known, total := recv.Progress()
		if total > 0 && known != lastPrinted {
			lastPrinted = known
			fmt.Print(i18n.T("cli.qr_receive_progress", known, total))
		}
		return recv.Done()
	})
	if scanErr != nil && !recv.Done() {
		return nil, errors.New(i18n.T("cli.err_qr_camera_scan", scanErr))
	}
	if !recv.Done() {
		return nil, errors.New(i18n.T("cli.err_qr_incomplete"))
	}
	return recv.Bytes(), nil
}

// runQRReceive reads a transfer started with "qr send" from the webcam,
// until it has reconstructed it whole or qrOpticalScanTimeout expires.
func runQRReceive(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, i18n.T("cli.qr_receive_usage"))
		os.Exit(1)
	}
	outPath := args[0]

	fmt.Print(i18n.T("cli.qr_transfer_password_prompt"))
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal(i18n.T("common.err_read_password", err))
	}
	password := string(pwd)
	zeroBytes(pwd)

	payload, err := receiveAnimatedQR(qrOpticalScanTimeout)
	if err != nil {
		fatal(err.Error())
	}
	if len(payload) < qrOpticalSaltLen {
		fatal(i18n.T("cli.err_qr_decrypt", errors.New("payload too short")))
	}
	salt, cipherRaw := payload[:qrOpticalSaltLen], payload[qrOpticalSaltLen:]
	key := qrOpticalDeriveKey(password, salt)
	plain, err := shared.Decrypt(key, base64.StdEncoding.EncodeToString(cipherRaw), nil)
	if err != nil {
		fatal(i18n.T("cli.err_qr_decrypt", err))
	}
	// The one-byte marker written by shared.PackData makes the pack
	// self-describing: correct regardless of how the sender set
	// compression, no prior coordination needed.
	plain, err = shared.UnpackData(plain)
	if err != nil {
		fatal(i18n.T("cli.err_qr_decrypt", err))
	}
	if err := os.WriteFile(outPath, plain, 0600); err != nil {
		fatal(i18n.T("cli.err_qr_write_file", err))
	}
	fmt.Print(i18n.T("cli.qr_receive_done", outPath, len(plain)))
}

var stdinReader = bufio.NewReader(os.Stdin)

func readLine() string {
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func prompt(label string) string {
	fmt.Print(label)
	return strings.TrimSpace(readLine())
}

// printRetryError prints a wizard validation error without exiting —
// unlike fatal, the caller loops back and asks again instead of losing
// everything already entered earlier in the same wizard run.
func printRetryError(msg string) {
	fmt.Fprintln(os.Stderr, i18n.T("common.error_prefix")+msg)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, i18n.T("common.error_prefix")+msg)
	os.Exit(1)
}

// ── identity QR ──────────────────────────────────────────────────────────────

// identityQRContent returns the QR's content:
//
//	nu://username/base64pubkey                                    (Ed25519 only)
//	nu://username/base64pubkey/base64mlkempub                     (+ ML-KEM)
//	nu://username/base64pubkey/base64mlkempub/base64mldsapub      (+ ML-DSA)
//
// mlkemPub (1184 bytes, ks.MLKEMPubBytes()) is the identity's durable
// ML-KEM-768 encapsulation key, a fixed-length segment (1580 base64
// characters, see internal/client/tui: nuURIMLKEMB64Len). mldsaPub
// (1952 bytes, ks.MLDSAPubBytes()) is the network identity's durable
// ML-DSA-65 signing key, a fixed-length segment (2604 base64 characters,
// see nuURIMLDSAB64Len). With all three segments the content exceeds a
// single QR frame's capacity (~1700 characters with ML-KEM only, +2604
// with ML-DSA) — printAndSaveQR below falls back to multi-QR when
// needed, reusing the same chunking already used in production for
// backup/sync (keystore.ChunkBlob/AssembleQRMulti).
func identityQRContent(username string, pub ed25519.PublicKey, mlkemPub, mldsaPub []byte) string {
	s := "nu://" + username + "/" + base64.StdEncoding.EncodeToString(pub)
	if len(mlkemPub) > 0 {
		s += "/" + base64.StdEncoding.EncodeToString(mlkemPub)
	}
	if len(mldsaPub) > 0 {
		s += "/" + base64.StdEncoding.EncodeToString(mldsaPub)
	}
	return s
}

// qrQuadrantString renders the QR with one Unicode character per 2x2
// block of modules (quadrant glyphs ▘▝▖▗▌▐▀▄ etc.), a factor of two more
// compact than ToSmallString (which uses half a character per module)
// and four compared to ToString — useful for fitting large QR codes,
// such as an identity's with ML-DSA-65, into a terminal.
func qrQuadrantString(q *qrcode.QRCode, inverseColor bool) string {
	bits := q.Bitmap()
	filled := func(y, x int) bool {
		if y < 0 || y >= len(bits) || x < 0 || x >= len(bits[y]) {
			return false
		}
		return bits[y][x] == inverseColor
	}
	quadrant := [16]rune{
		' ', '▘', '▝', '▀',
		'▖', '▌', '▞', '▛',
		'▗', '▚', '▐', '▜',
		'▄', '▙', '▟', '█',
	}
	var buf bytes.Buffer
	for y := 0; y < len(bits); y += 2 {
		for x := 0; x < len(bits[0]); x += 2 {
			idx := 0
			if filled(y, x) {
				idx |= 1
			}
			if filled(y, x+1) {
				idx |= 2
			}
			if filled(y+1, x) {
				idx |= 4
			}
			if filled(y+1, x+1) {
				idx |= 8
			}
			buf.WriteRune(quadrant[idx])
		}
		buf.WriteString("\n")
	}
	return buf.String()
}

// printAndSaveQR saves the PNG(s) to the given path and, only if display
// is true, also prints them to the terminal as ASCII art. display=false
// is used by the first-run wizard and "neutrino add-identity" (via
// createIdentity): the ASCII art of a QR that includes ML-DSA-65 almost
// always exceeds the terminal's size, unreadable even fullscreen — there
// only the PNG files (zoomable) and the plain URI text remain.
// "neutrino show-qr", invoked explicitly to view the QR, passes
// display=true. Every identity's own URI includes the ML-DSA-65 segment
// (every keystore has one, see migrateVersion), so the content always
// exceeds a single QR frame's capacity — this always chunks into
// multi-QR, the same scheme used for backupSaveQR, one numbered PNG file
// per part plus the raw chunk (for reassembly without a QR decoder if
// needed).
func printAndSaveQR(username string, pub ed25519.PublicKey, mlkemPub, mldsaPub []byte, pngPath string, display bool) error {
	content := identityQRContent(username, pub, mlkemPub, mldsaPub)

	if err := os.MkdirAll(filepath.Dir(pngPath), 0700); err != nil {
		return fmt.Errorf(i18n.T("qr.err_save_png")+": %w", err)
	}
	base := strings.TrimSuffix(pngPath, filepath.Ext(pngPath))
	// Plain text (nu://...) alongside the PNG(s), always — the same URI,
	// convenient to attach as-is via Telegram/email instead of having to
	// copy it by hand or read it pixel-by-pixel from a multi-page QR.
	// Rereadable with "/cnt-add <path>" (cmdAddContact, tui.go).
	txtPath := base + ".txt"
	if err := os.WriteFile(txtPath, []byte(content), 0600); err != nil {
		return fmt.Errorf(i18n.T("qr.err_save_png")+": %w", err)
	}
	fmt.Print(i18n.T("qr.saved_at", txtPath))

	chunks, err := keystore.ChunkBlob([]byte(content))
	if err != nil {
		return fmt.Errorf(i18n.T("cli.err_multi_qr")+": %w", err)
	}
	if display {
		fmt.Print(i18n.T("qr.identity_multi_saved_display", len(chunks)))
	} else {
		fmt.Print(i18n.T("qr.identity_multi_saved_intro", len(chunks)))
	}
	var partPaths []string
	for i, chunk := range chunks {
		q, err := qrscan.EncodeVerified(string(chunk), qrcode.Medium)
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr_gen_n", i+1, err))
			continue
		}
		if display {
			fmt.Printf("[Enter for QR %d/%d]", i+1, len(chunks))
			readLine()
			fmt.Print(i18n.T("cli.qr_n_of_total", i+1, len(chunks)))
			fmt.Println(qrQuadrantString(q, false))
		}
		partPath := fmt.Sprintf("%s-part%d.png", base, i+1)
		if err := q.WriteFile(qrscan.PixelsPerModule, partPath); err == nil {
			fmt.Print(i18n.T("qr.saved_at", partPath))
			partPaths = append(partPaths, partPath)
		}
		if qrPersonalOverlay != nil {
			// A larger canvas than the plain file above (8 vs 4
			// px/module): same box/QR-area fraction, more absolute
			// pixels for the label to stay legible — the overlay
			// replaces the plain file entirely when it applies, so the
			// output size difference is harmless.
			if img, ok := qrPersonalOverlay(username, chunk, -qrscan.PixelsPerModule*2); ok {
				if f, err := os.Create(partPath); err == nil {
					_ = png.Encode(f, img)
					f.Close()
				}
			}
		}
	}

	pdfPath := base + ".pdf"
	if err := saveQRPagesAsPDF(username, content, partPaths, pdfPath); err == nil {
		fmt.Print(i18n.T("qr.saved_at", pdfPath))
	}
	return nil
}

// saveQRPagesAsPDF collects the identity into a single PDF: a first page
// with the plain nu:// URI as selectable/printable text (same content as
// the .txt sidecar), then one page per multi-part QR image — for
// printing or for a single file to keep offline instead of loose PNGs
// plus a separate .txt. A no-op (returns nil without writing anything)
// if pngPaths is empty.
func saveQRPagesAsPDF(username, textContent string, pngPaths []string, pdfPath string) error {
	if len(pngPaths) == 0 {
		return nil
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	// Page breaks are placed by hand below (one AddPage per QR part, plus
	// the first for the text) — fpdf's automatic break, left at its
	// default threshold, would otherwise insert a spurious blank page
	// whenever a header/body cell lands close enough to the bottom margin.
	pdf.SetAutoPageBreak(false, 0)
	pageW, _ := pdf.GetPageSize()
	const margin = 15.0
	const imgSize = 150.0 // mm, square
	const githubURL = "https://github.com/neutrinobuilder/neutrino"

	// fpdf's core fonts (Helvetica/Courier here) are single-byte
	// (WinAnsi/cp1252), not UTF-8 — a raw UTF-8 string with any non-ASCII
	// rune (even a plain em dash) renders as mojibake. tr maps what
	// cp1252 can represent and falls back to "?" for the rest (e.g. a
	// non-Latin username) — acceptable here: title text only, never the
	// URI itself (pure base64 ASCII, unaffected).
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	// header prints the project name and its GitHub URL, centered, at the
	// top of every page, so a printed/detached sheet is still identifiable
	// as a Neutrino identity. Returns the Y position right below it.
	header := func() float64 {
		pdf.SetFont("Helvetica", "B", 26)
		pdf.SetXY(0, margin)
		pdf.CellFormat(pageW, 12, "Neutrino", "", 1, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", 12)
		pdf.SetXY(0, margin+13)
		pdf.CellFormat(pageW, 7, githubURL, "", 1, "C", false, 0, "")
		// 2-3 blank lines of breathing room before the identity text below.
		return margin + 38
	}

	pdf.AddPage()
	y := header()
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetXY(0, y)
	pdf.CellFormat(pageW, 12, tr(username), "", 1, "C", false, 0, "")
	// Small monospace + tight leading: the full URI (pub + MLKEM-768 +
	// ML-DSA-65 as base64) runs well over 4000 characters — a larger
	// size overflows onto a near-empty second page instead of fitting
	// on this one.
	pdf.SetFont("Courier", "", 7)
	pdf.SetXY(margin, y+16)
	pdf.MultiCell(pageW-2*margin, 3.6, textContent, "", "L", false)

	x := (pageW - imgSize) / 2
	for i, path := range pngPaths {
		pdf.AddPage()
		y := header()
		pdf.SetFont("Helvetica", "", 20)
		pdf.SetXY(0, y)
		pdf.CellFormat(pageW, 12, tr(fmt.Sprintf("%s - %d/%d", username, i+1, len(pngPaths))), "", 1, "C", false, 0, "")
		pdf.ImageOptions(path, x, y+12, imgSize, imgSize, false, fpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	}
	if pdf.Err() {
		return pdf.Error()
	}
	return pdf.OutputFileAndClose(pdfPath)
}

// saveIdentityQRForTUI writes the same files as printAndSaveQR
// (display=false: plain .txt + multi-part PNG, personal overlay applied
// when it matches), returning every path written instead of printing
// them — printAndSaveQR's fmt.Print calls would corrupt bubbletea's
// alt-screen buffer if run while the TUI is active, so the TUI's own
// /show-qr "save as image" choice (TUIParams.SaveIdentityQR) uses this
// instead, same file-writing logic duplicated rather than threading an
// io.Writer/quiet flag through printAndSaveQR.
func saveIdentityQRForTUI(username string, pub ed25519.PublicKey, mlkemPub, mldsaPub []byte, pngPath string) ([]string, error) {
	content := identityQRContent(username, pub, mlkemPub, mldsaPub)

	if err := os.MkdirAll(filepath.Dir(pngPath), 0700); err != nil {
		return nil, fmt.Errorf(i18n.T("qr.err_save_png")+": %w", err)
	}
	base := strings.TrimSuffix(pngPath, filepath.Ext(pngPath))
	txtPath := base + ".txt"
	if err := os.WriteFile(txtPath, []byte(content), 0600); err != nil {
		return nil, fmt.Errorf(i18n.T("qr.err_save_png")+": %w", err)
	}
	paths := []string{txtPath}

	chunks, err := keystore.ChunkBlob([]byte(content))
	if err != nil {
		return nil, fmt.Errorf(i18n.T("cli.err_multi_qr")+": %w", err)
	}
	var partPaths []string
	for i, chunk := range chunks {
		q, err := qrscan.EncodeVerified(string(chunk), qrcode.Medium)
		if err != nil {
			continue
		}
		partPath := fmt.Sprintf("%s-part%d.png", base, i+1)
		if err := q.WriteFile(qrscan.PixelsPerModule, partPath); err == nil {
			paths = append(paths, partPath)
			partPaths = append(partPaths, partPath)
		}
		if qrPersonalOverlay != nil {
			if img, ok := qrPersonalOverlay(username, chunk, -qrscan.PixelsPerModule*2); ok {
				if f, err := os.Create(partPath); err == nil {
					_ = png.Encode(f, img)
					f.Close()
				}
			}
		}
	}

	pdfPath := base + ".pdf"
	if err := saveQRPagesAsPDF(username, content, partPaths, pdfPath); err == nil {
		paths = append(paths, pdfPath)
	}
	return paths, nil
}

// ── backup / restore ─────────────────────────────────────────────────────────

func runBackup() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		fatal(i18n.T("cli.err_keystore_not_found_run_first"))
	}
	session := unlockKeystoreSession(ksPath)
	ks := session.Identity

	words, err := ks.Mnemonic()
	if err != nil {
		fatal(i18n.T("backup.err_backup", err))
	}

	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println(i18n.T("backup.title"))
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(i18n.T("backup.write_down_hint"))
	fmt.Println(i18n.T("backup.recover_hint"))
	fmt.Println()
	for i, w := range words {
		fmt.Printf("  %2d. %-12s", i+1, w)
		if (i+1)%4 == 0 {
			fmt.Println()
		}
	}
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println()

	// Full backup — asks for the format
	fmt.Println(i18n.T("backup.full_backup_prompt"))
	fmt.Println(i18n.T("backup.option_bin"))
	fmt.Println(i18n.T("backup.option_qr"))
	fmt.Println(i18n.T("backup.option_both"))
	fmt.Println(i18n.T("backup.option_qr_animated"))
	fmt.Print(i18n.T("backup.choice_prompt_skip"))
	choice := strings.TrimSpace(readLine())

	now := time.Now().Format("20060102")
	if choice == "1" || choice == "3" {
		backupSaveBin(ks, now)
	}
	if choice == "2" || choice == "3" {
		backupSaveQR(ks, now)
	}
	if choice == "4" {
		backupSaveQRAnimated(ks)
	}
	fmt.Println()
}

// backupSaveQRAnimated shows the full backup as a stream of animated QR
// codes (fountain code) — an additional mode alongside backupSaveQR
// (static QR), not a replacement for it: same encrypted payload
// (ExportQRAnimated instead of ExportQR/ExportQRMulti), no additional
// password, the receiver scans it with "neutrino restore" (animated QR
// option).
func backupSaveQRAnimated(ks *keystore.Keystore) {
	data, err := ks.ExportQRAnimated()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr", err))
		return
	}
	sendAnimatedQRLoop(data, "cli.qr_animated_backup_intro")
}

func backupSaveBin(ks *keystore.Keystore, now string) {
	data, err := ks.ExportBackupFile()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_export", err))
		return
	}
	outPath := "neutrino-backup-" + now + ".bin"
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_write_file", err))
		return
	}
	fmt.Print(i18n.T("backup.file_saved", outPath))
	fmt.Println(i18n.T("backup.keep_safe_hint"))
	fmt.Println(i18n.T("backup.restore_needs_both_hint"))
}

func backupSaveQR(ks *keystore.Keystore, now string) {
	// Try a single QR
	data, err := ks.ExportQR()
	if err != nil && !errors.Is(err, keystore.ErrQRTooLarge) {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr", err))
		return
	}

	if errors.Is(err, keystore.ErrQRTooLarge) {
		// Multi-QR
		chunks, err := ks.ExportQRMulti()
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("cli.err_multi_qr", err))
			return
		}
		fmt.Print(i18n.T("backup.large_keystore", len(chunks)))
		for i, chunk := range chunks {
			fmt.Printf("[Enter for QR %d/%d]", i+1, len(chunks))
			readLine()
			q, err := qrscan.EncodeVerified(string(chunk), qrcode.Medium)
			if err != nil {
				fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr_gen_n", i+1, err))
				continue
			}
			fmt.Print(i18n.T("cli.qr_n_of_total", i+1, len(chunks)))
			fmt.Println(q.ToSmallString(false))
			base := fmt.Sprintf("neutrino-backup-%s-part%d", now, i+1)
			if err := q.WriteFile(qrscan.PixelsPerModule, base+".png"); err == nil {
				fmt.Printf("  PNG: %s.png\n", base)
			}
			// raw chunk for restore on a PC with no QR decoder
			if err := os.WriteFile(base+".chunk", chunk, 0600); err == nil {
				fmt.Printf("  Chunk: %s.chunk\n", base)
			}
		}
		fmt.Println(i18n.T("backup.keep_chunks_hint"))
		return
	}

	// Single QR
	q, err := qrscan.EncodeVerified(string(data), qrcode.Medium)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr_gen", err))
		return
	}
	fmt.Println()
	fmt.Println(q.ToSmallString(false))
	outPng := "neutrino-backup-" + now + ".png"
	outChunk := "neutrino-backup-" + now + ".chunk"
	if err := q.WriteFile(qrscan.PixelsPerModule, outPng); err == nil {
		fmt.Printf("PNG: %s\n", outPng)
	}
	if err := os.WriteFile(outChunk, data, 0600); err == nil {
		fmt.Print(i18n.T("backup.chunk_saved_pc_hint", outChunk))
	}
}

func runSyncExport() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		fatal(i18n.T("cli.err_keystore_not_found"))
	}
	session := unlockKeystoreSession(ksPath)
	ks := session.Identity

	if len(ks.Contacts) == 0 {
		fmt.Println(i18n.T("sync.empty_contacts"))
		return
	}

	fmt.Print(i18n.T("sync.contacts_count", len(ks.Contacts)))
	fmt.Println(i18n.T("sync.export_format_title"))
	fmt.Println(i18n.T("sync.option_bin"))
	fmt.Println(i18n.T("sync.option_qr"))
	fmt.Println(i18n.T("sync.option_both"))
	fmt.Println(i18n.T("sync.option_qr_animated"))
	fmt.Print(i18n.T("sync.choice_prompt_default1"))
	choice := strings.TrimSpace(readLine())
	if choice == "" {
		choice = "1"
	}

	now := time.Now().Format("20060102-150405")
	if choice == "1" || choice == "3" {
		syncSaveBin(ks, now)
	}
	if choice == "2" || choice == "3" {
		syncSaveQR(ks, now)
	}
	if choice == "4" {
		syncSaveQRAnimated(ks)
	}
}

// syncSaveQRAnimated shows the encrypted contact list as a stream of
// animated QR codes (fountain code) — an additional mode alongside
// syncSaveQR (static QR), not a replacement for it: same payload as
// ExportSync (already without size limits), no additional password.
func syncSaveQRAnimated(ks *keystore.Keystore) {
	data, err := ks.ExportSync()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_export", err))
		return
	}
	sendAnimatedQRLoop(data, "cli.qr_animated_sync_intro")
}

func syncSaveBin(ks *keystore.Keystore, now string) {
	data, err := ks.ExportSync()
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_export", err))
		return
	}
	outPath := "neutrino-sync-" + now + ".bin"
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_write_file", err))
		return
	}
	fmt.Print(i18n.T("sync.file_saved", outPath, len(ks.Contacts)))
	fmt.Println(i18n.T("sync.transfer_hint", outPath))
}

func syncSaveQR(ks *keystore.Keystore, now string) {
	data, err := ks.ExportSyncQR()
	if err != nil && !errors.Is(err, keystore.ErrSyncQRTooLarge) {
		fmt.Fprintln(os.Stderr, i18n.T("sync.err_qr", err))
		return
	}

	if errors.Is(err, keystore.ErrSyncQRTooLarge) {
		// Contact list too large for a single QR — multi-QR
		chunks, err := ks.ExportSyncQRMulti()
		if err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("sync.err_multi_qr", err))
			return
		}
		fmt.Print(i18n.T("sync.large_contacts", len(chunks)))
		for i, chunk := range chunks {
			fmt.Printf("[Enter for QR %d/%d]", i+1, len(chunks))
			readLine()
			q, err := qrscan.EncodeVerified(string(chunk), qrcode.Medium)
			if err != nil {
				fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr_gen_n", i+1, err))
				continue
			}
			fmt.Print(i18n.T("cli.qr_n_of_total", i+1, len(chunks)))
			fmt.Println(q.ToSmallString(false))
			base := fmt.Sprintf("neutrino-sync-%s-part%d", now, i+1)
			if err := q.WriteFile(qrscan.PixelsPerModule, base+".png"); err == nil {
				fmt.Printf("  PNG: %s.png\n", base)
			}
			if err := os.WriteFile(base+".chunk", chunk, 0600); err == nil {
				fmt.Printf("  Chunk: %s.chunk\n", base)
			}
		}
		fmt.Print(i18n.T("sync.import_on_pc_hint", now))
		return
	}

	// Single QR
	q, err := qrscan.EncodeVerified(string(data), qrcode.Medium)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.err_qr_gen", err))
		return
	}
	fmt.Print(i18n.T("sync.contacts_header", len(ks.Contacts)))
	fmt.Println(q.ToSmallString(false))
	outPng := "neutrino-sync-" + now + ".png"
	outBin := "neutrino-sync-" + now + ".bin"
	if err := q.WriteFile(qrscan.PixelsPerModule, outPng); err == nil {
		fmt.Printf("PNG: %s\n", outPng)
	}
	if err := os.WriteFile(outBin, data, 0600); err == nil {
		fmt.Print(i18n.T("sync.bin_saved_pc_hint", outBin))
	}
}

func runSyncImport(files []string) {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		fatal(i18n.T("cli.err_keystore_not_found"))
	}
	session := unlockKeystoreSession(ksPath)

	// Reads and assembles file(s) (a single .bin, or several .chunk)
	var data []byte
	if len(files) == 1 {
		data, err = os.ReadFile(files[0])
		if err != nil {
			fatal(i18n.T("sync.err_read_file", err))
		}
		// If the file is an NTR3 chunk, assemble it as a sequence of one
		if len(data) >= 4 && string(data[:4]) == "NTR3" {
			assembled, aErr := keystore.AssembleQRMulti([][]byte{data})
			if aErr != nil {
				fatal(i18n.T("cli.err_chunk_assembly", aErr))
			}
			data = assembled
		}
	} else {
		chunks := make([][]byte, 0, len(files))
		for _, f := range files {
			b, rErr := os.ReadFile(f)
			if rErr != nil {
				fatal(i18n.T("cli.err_read_chunk", f, rErr))
			}
			chunks = append(chunks, b)
		}
		data, err = keystore.AssembleQRMulti(chunks)
		if err != nil {
			fatal(i18n.T("cli.err_chunk_assembly", err))
		}
	}

	cfg, _ := config.Load(configPath(ksPath))
	finishSyncImport(session, cfg, ksPath, data)
}

// runSyncImportQR imports the contact list by reading a stream of
// animated QR codes (fountain code) from the webcam instead of from a
// file — an additional mode alongside runSyncImport (file/.chunk), not a
// replacement for it.
func runSyncImportQR() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		fatal(i18n.T("cli.err_keystore_not_found"))
	}
	session := unlockKeystoreSession(ksPath)

	data, err := receiveAnimatedQR(qrOpticalScanTimeout)
	if err != nil {
		fatal(err.Error())
	}

	cfg, _ := config.Load(configPath(ksPath))
	finishSyncImport(session, cfg, ksPath, data)
}

// finishSyncImport asks for the 24-word mnemonic, decrypts data (already
// reassembled, regardless of source: file/.chunk or animated QR) and
// merges the resulting contacts into the keystore — core shared by
// runSyncImport and runSyncImportQR.
func finishSyncImport(session *keystore.UnlockedSlot, cfg config.Config, ksPath string, data []byte) {
	fmt.Println(i18n.T("sync.enter_mnemonic"))
	fmt.Print("> ")
	line := readLine()
	words := strings.Fields(line)
	if len(words) != 24 {
		fatal(i18n.T("common.err_need_24_words", len(words)))
	}

	incoming, err := keystore.ImportSync(words, data)
	if err != nil {
		fatal(i18n.T("sync.err_import", err))
	}

	// nil: the manual file/QR sync format (NTRINO03) carries no source
	// device identifier — no sibling revocation is attributed through
	// this path.
	var added, updated int
	if session.Identity.IsDuress {
		added, updated, _, err = session.AddPlainContacts(incoming, nil)
	} else {
		var duressIdx int
		var duressKi, duressPlain []byte
		added, updated, _, duressIdx, duressKi, duressPlain, err = session.AddMirroredContacts(incoming, nil, func(existingFirstNames map[string]bool) keystore.Contact {
			return buildFakeContact(cfg, existingFirstNames)
		})
		if err == nil && added > 0 {
			err = session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain)
		}
	}
	if err != nil {
		fatal(i18n.T("cli.err_save_keystore", err))
	}
	if added == 0 && updated == 0 {
		fmt.Println(i18n.T("sync.already_synced"))
		return
	}

	if session.Identity.IsDuress || added == 0 {
		err = session.SaveSlot(ksPath)
	}
	if err != nil {
		fatal(i18n.T("cli.err_save_keystore", err))
	}
	fmt.Print(i18n.T("sync.done", added, updated))
}

// ── nuke ─────────────────────────────────────────────────────────────────────

// secureWipeDirFiles lists every regular file present directly in dir
// (non-recursive — Neutrino never creates subdirectories inside the
// config dir). Used by wipeConfigDir so it doesn't limit itself to
// keystore+config.json by name: the same directory can also hold
// tor_bridges, identity-qr-*.png (one per identity in the keystore), and
// any keystore backups the user saved there
// (neutrino-backup-*.bin/.png/.chunk, neutrino-sync-*.bin/.png/.chunk) —
// all of them must be overwritten like the keystore itself, never left
// on disk in the clear.
func secureWipeDirFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	return paths, nil
}

// secureDelete overwrites the file with random data for passes rounds,
// then deletes it. Uses a 64 KB buffer to avoid allocating the whole
// file in RAM.
func secureDelete(path string, passes int) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	size := info.Size()

	if size > 0 {
		const chunk = 64 * 1024
		buf := make([]byte, chunk)
		for pass := range passes {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				f.Close()
				return errors.New(i18n.T("nuke.err_seek_pass", pass+1, err))
			}
			remaining := size
			for remaining > 0 {
				n := int64(len(buf))
				if n > remaining {
					n = remaining
				}
				if _, err := rand.Read(buf[:n]); err != nil {
					f.Close()
					return errors.New(i18n.T("nuke.err_rand", err))
				}
				if _, err := f.Write(buf[:n]); err != nil {
					f.Close()
					return errors.New(i18n.T("nuke.err_write", err))
				}
				remaining -= n
			}
			if err := f.Sync(); err != nil {
				f.Close()
				return errors.New(i18n.T("nuke.err_sync_pass", pass+1, err))
			}
		}
	}

	f.Close()
	return os.Remove(path)
}

// runNukeOverwriteInPlace is the nuke mechanism for nukeOnExit (`/nukex`,
// the timed nuke, and remote_nuke on the TARGET side — all three set the
// same flag via cmdNukeX/executeRemoteNuke in
// internal/client/tui/tui.go): overwrites EVERY contact of session's
// identity, in place (OverwriteAllContacts — same treatment as a normal
// contact-deletion, applied to all of them at once), NEVER deletes or
// even touches the keystore file's own existence: no trigger ever
// deletes a file. Never
// prints anything: an anti-forensic wipe visible on the screen/terminal
// (or a persistent scrollback/log) would itself be evidence that it just
// happened. wipeConfigDir below is NOT part of this trigger grid — it
// backs the unrelated, explicitly confirmed /sec-clear-all, which DOES
// delete the file on purpose.
//
// Does NOT exit the process and does NOT promote duress itself — purely
// the data mutation. The caller (runOnce's own loop, see nukeRequested)
// calls session.PromoteDuress() right after and loops, keeping Tor/I2P
// and the process alive — see that loop's own doc comment.
//
// Also guarantees the triggering real identity's own slot never survives
// this trigger: after the contact overwrite above is committed, its
// slot is overwritten with fresh random bytes (keystore.ObliterateSlot)
// and the container written back to disk — unconditionally, regardless
// of whether any contact existed to overwrite: otherwise a cold restart
// after /nukex would still open the real identity with the real
// password (same principle as ObliterateOtherSlots for duress typed at
// login, unlockKeystoreSession above). Deliberately scoped to ONLY
// this one slot, never every other slot in the file (unlike the
// login-time case): another real identity sharing the same keystore
// file is a legitimate identity of its own, not implicated by this
// trigger — same scoping already applied to the sibling device-sync
// fan-out a few lines above this call's own caller.
func runNukeOverwriteInPlace(session *keystore.UnlockedSlot, ksPath string) {
	duressIdx, duressKi, duressPlain, emptied, err := session.OverwriteAllContacts()
	if err == nil && emptied > 0 {
		_ = session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain)
	}
	if err := keystore.ObliterateSlot(session.Container, session.Idx); err == nil {
		_ = keystore.WriteSlotContainer(ksPath, session.Container)
	}
}

// wipeConfigDir overwrites and deletes every file in ksPath's directory
// — keystore, config.json, tor_bridges, any backup/QR file saved there,
// and any future file with the same need — then removes the now-empty
// directory itself. Falls back to just the keystore and its config file
// if enumerating the directory fails. Called only after an
// explicit, confirmed action (/sec-clear-all) — never by a nuke trigger,
// which must never delete the file (see runNukeOverwriteInPlace above).
func wipeConfigDir(ksPath string) {
	configDir := filepath.Dir(ksPath)

	paths, err := secureWipeDirFiles(configDir)
	if err != nil {
		paths = []string{ksPath, configPath(ksPath)}
	}
	for _, path := range paths {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		_ = secureDelete(path, 10)
	}

	os.Remove(configDir)
}

func runRestore() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); err == nil {
		fmt.Print(i18n.T("restore.overwrite_prompt"))
		if r := strings.ToLower(strings.TrimSpace(readLine())); r != i18n.T("common.yes") {
			fmt.Println(i18n.T("common.cancelled"))
			return
		}
	}

	fmt.Println()
	fmt.Println(i18n.T("restore.enter_mnemonic"))
	fmt.Print("> ")
	line := readLine()
	words := strings.Fields(line)
	if len(words) == 0 {
		// one-word-per-line mode
		for i := range 24 {
			fmt.Print(i18n.T("restore.word_prompt", i+1))
			w := strings.TrimSpace(readLine())
			if w == "" {
				fatal(i18n.T("restore.err_interrupted"))
			}
			words = append(words, w)
		}
	}
	if len(words) != 24 {
		fatal(i18n.T("common.err_need_24_words", len(words)))
	}

	// Backup source
	fmt.Println(i18n.T("restore.source_title"))
	fmt.Println(i18n.T("restore.option_bin"))
	fmt.Println(i18n.T("restore.option_chunk"))
	fmt.Println(i18n.T("restore.option_qr_animated"))
	fmt.Print(i18n.T("restore.choice_prompt_identity_only"))
	srcChoice := strings.TrimSpace(readLine())

	var ks *keystore.Keystore
	switch srcChoice {
	case "1":
		fmt.Print(i18n.T("restore.bin_path_prompt"))
		backupPath := strings.TrimSpace(readLine())
		if backupPath == "" {
			fatal(i18n.T("common.err_path_required"))
		}
		data, err := os.ReadFile(backupPath)
		if err != nil {
			fatal(i18n.T("common.err_read_file", err))
		}
		ks, err = keystore.ImportFromBackupFile(words, data)
		if err != nil {
			fatal(i18n.T("restore.err_from_file", err))
		}
		fmt.Print(i18n.T("restore.full_restore_done", len(ks.Contacts)))

	case "2":
		fmt.Println(i18n.T("restore.chunk_paths_prompt"))
		var chunks [][]byte
		for i := 1; ; i++ {
			fmt.Print(i18n.T("restore.chunk_n_prompt", i))
			p := strings.TrimSpace(readLine())
			if p == "" {
				break
			}
			b, err := os.ReadFile(p)
			if err != nil {
				fatal(i18n.T("common.err_read_named_file", p, err))
			}
			chunks = append(chunks, b)
		}
		if len(chunks) == 0 {
			fatal(i18n.T("restore.err_no_chunks"))
		}
		assembled, err := keystore.AssembleQRMulti(chunks)
		if err != nil {
			fatal(i18n.T("cli.err_chunk_assembly", err))
		}
		ks, err = keystore.ImportFromBackupFile(words, assembled)
		if err != nil {
			fatal(i18n.T("restore.err_from_chunk", err))
		}
		fmt.Print(i18n.T("restore.full_restore_done", len(ks.Contacts)))

	case "3":
		payload, err := receiveAnimatedQR(qrOpticalScanTimeout)
		if err != nil {
			fatal(err.Error())
		}
		ks, err = keystore.ImportFromBackupFile(words, payload)
		if err != nil {
			fatal(i18n.T("restore.err_from_file", err))
		}
		fmt.Print(i18n.T("restore.full_restore_done", len(ks.Contacts)))

	default:
		username := prompt(i18n.T("common.username_prompt"))
		if username == "" {
			fatal(i18n.T("common.err_username_required"))
		}
		ks, err = keystore.ImportFromMnemonic(words, username)
		if err != nil {
			fatal(i18n.T("restore.err_from_words", err))
		}
		fmt.Println(i18n.T("restore.identity_recovered"))
	}

	cfg, _ := config.Load(configPath(ksPath))
	netKind, err := transport.ParseKind(cfg.Net)
	if err != nil {
		netKind = transport.KindTor
	}
	addr := addressFromPubForNet(netKind, ks.IdentityPubKey())
	fmt.Print(i18n.T("restore.net_address", addr))

	fmt.Println()
	fmt.Println(i18n.T("wizard.file_password_intro"))
	pwdFile := promptNewKeystorePassword()
	fmt.Println()
	fmt.Println(i18n.T("wizard.identity_password_intro"))
	pwdIdentity := promptNewKeystorePassword()

	duressUsername, duressPasswordIdentity := promptDuressSetup(pwdIdentity)
	// keystore.New directly, not createIdentity: see runWizard's own
	// identical comment — the decoy never publishes a QR here either.
	duress, err := keystore.New(duressUsername)
	if err != nil {
		fatal(i18n.T("wizard.err_identity_key", err))
	}

	if _, err := keystore.CreateFile(ksPath, pwdFile, pwdIdentity, duressPasswordIdentity, ks, duress); err != nil {
		fatal(i18n.T("cli.err_save_keystore", err))
	}
	fmt.Print(i18n.T("restore.keystore_saved", ksPath))
}

// runShowQR displays the current identity's QR code — as a static
// multi-part image (printAndSaveQR, also saved to disk) or as a
// continuous fountain-code stream (sendAnimatedQRLoop, same mechanism
// as "qr send", nothing saved to disk), the user's choice.
func runShowQR() {
	ksPath, err := keystore.DefaultPath()
	if err != nil {
		fatal(i18n.T("cli.err_config_dir", err))
	}
	if _, err := os.Stat(ksPath); errors.Is(err, os.ErrNotExist) {
		fatal(i18n.T("cli.err_keystore_not_found_run_first"))
	}
	session := unlockKeystoreSession(ksPath)
	ks := session.Identity

	fmt.Println(i18n.T("qr.show_format_prompt"))
	fmt.Print(i18n.T("qr.choice_prompt"))
	choice := strings.TrimSpace(readLine())

	if choice == "2" {
		content := identityQRContent(ks.Username, ks.IdentityPubKey(), ks.MLKEMPubBytes(), ks.MLDSAPubBytes())
		sendAnimatedQRLoop([]byte(content), "cli.qr_animated_identity_intro")
		return
	}

	qrPath := filepath.Join(filepath.Dir(ksPath), fmt.Sprintf("identity-qr-%s.png", ks.Username))
	if err := printAndSaveQR(ks.Username, ks.IdentityPubKey(), ks.MLKEMPubBytes(), ks.MLDSAPubBytes(), qrPath, true); err != nil {
		fatal(err.Error())
	}
}
