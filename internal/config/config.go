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

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"neutrino/internal/shared"
)

// Config holds the operational parameters and local preferences readable
// from a file. The file is text with # comments followed by JSON; editable
// with any text editor. All durations use Go's format: "30s", "5m",
// "1m30s", "1h". This is the only unencrypted file: the language (Lang)
// must live here because it's read before the encrypted keystore can be
// unlocked (to localize the password prompt).
type Config struct {
	// ── preferences ────────────────────────────────────────────────────────────
	// Lang is the interface language, set by the first-run wizard and by
	// `neutrino lang`. Not consulted on Android, where the language lives in
	// the app's own preferences.
	Lang string `json:"lang"`

	// ── transport network ─────────────────────────────────────────────────────
	// Net picks the transport network: "tor" (default) or "i2p" (bundled on
	// linux/amd64 and linux/arm64; other platforms need the 'i2pd' daemon on
	// the system).
	// Overridable for a single run with "--net <network>", which takes
	// priority over this value. Not consulted on Android, like Lang.
	Net string `json:"net"`

	// ── server ─────────────────────────────────────────────────────────────────
	// PingInterval — how often the server sends a WS keepalive ping.
	// pingMissThreshold (internal/server/ws.go) tolerates 2 consecutive
	// missed cycles before declaring the connection dead: a single late pong
	// (common on Tor under circuit stress) isn't enough on its own to evict a
	// healthy member — see also pingWatchdogInterval on the client side
	// (internal/client/tui/tui.go), same principle, same value.
	PingInterval    string `json:"ping_interval"`
	CleanupInterval string `json:"cleanup_interval"`

	// ── forward secrecy ────────────────────────────────────────────────────────
	// SenderKeyInterval and SenderKeyMessageBudget are the two sender_key
	// rotation criteria, combined as an OR — whichever fires first:
	// SenderKeyMessageBudget covers bursts (count-based rotation, independent
	// of how long they take to accumulate), SenderKeyInterval is a hygiene
	// backstop for quiet rooms (a chain that never advances has nothing to
	// protect, but shouldn't stay unrotated forever either).
	SenderKeyInterval      string `json:"sender_key_interval"`
	SenderKeyMessageBudget int    `json:"sender_key_message_budget"`

	// ── reliable delivery (multi-user chat) ───────────────────────────────────
	// PendingSlotLimit is how many messages can stay unacknowledged for a
	// single relationship (sender→recipient) before writing new ones blocks —
	// a threshold chosen for human conversational coherence, not a technical
	// constraint: past a handful of messages the thread of a discussion is
	// already lost before any reply arrives.
	PendingSlotLimit int `json:"pending_slot_limit"`

	// PendingEscalationAge is the age of the oldest unacknowledged message
	// beyond which a warning appears in Console — a first, soft signal: at
	// this threshold a legitimate Tor/I2P circuit rebuild may still be in
	// progress.
	PendingEscalationAge string `json:"pending_escalation_age"`

	// MessageRetryDelay is the backoff (doubled on each attempt) between one
	// retransmission and the next for a single unacknowledged message — same
	// starting value already used for Tor/I2P reconnection.
	MessageRetryDelay string `json:"message_retry_delay"`

	// MessageTTL is how long a sent message may stay unacknowledged by a
	// connected recipient before the sender rotates its sender_key and
	// re-encrypts every unacknowledged message under the new generation.
	// Twice this value also bounds how long a retired DH ephemeral is
	// kept in two-member rooms.
	MessageTTL string `json:"message_ttl"`

	// ── contact probing (reachability check over Tor) ─────────────────────────
	ActiveInterval       string `json:"active_interval"`
	ActiveInitialDelay   string `json:"active_initial_delay"`
	ProbeContactsTimeout string `json:"probe_contacts_timeout"`
	ProbeRetryCount      int    `json:"probe_retry_count"`
	ProbeRetryDelay      string `json:"probe_retry_delay"`

	// ── Tor circuit management ────────────────────────────────────────────────
	TorProbeInterval     string `json:"tor_probe_interval"`
	TorProbeInitialDelay string `json:"tor_probe_initial_delay"`
	WarmupInterval       string `json:"warmup_interval"`
	WarmupInitialDelay   string `json:"warmup_initial_delay"`
	WarmupTimeout        string `json:"warmup_timeout"`
	SelfKnockTimeout     string `json:"self_knock_timeout"`

	// ── knock and invites ─────────────────────────────────────────────────────
	KnockHttpTimeout string `json:"knock_http_timeout"`
	KnockRetryDelay  string `json:"knock_retry_delay"`
	InviteTimeout    string `json:"invite_timeout"`

	// ── Tor bridges ────────────────────────────────────────────────────────────
	BridgesEnabled bool   `json:"bridges_enabled"`
	BridgeDefault  string `json:"bridge_default"`
	BridgeFallback string `json:"bridge_fallback"`

	// ── file transfer ──────────────────────────────────────────────────────────
	// "warp" (fast) and "slow" (default) presets — a bundle of chunk size +
	// not-yet-acked chunk window + delay between chunks, chosen by the sender
	// at the moment of sending (/grp-file-send), not a single static value
	// edited here.
	FileWarpChunkSizeKiB      int `json:"file_warp_chunk_size_kib"`
	FileWarpMaxInFlightChunks int `json:"file_warp_max_inflight_chunks"`
	FileSlowChunkSizeKiB      int `json:"file_slow_chunk_size_kib"`
	FileSlowMaxInFlightChunks int `json:"file_slow_max_inflight_chunks"`
	FileSlowDelayMs           int `json:"file_slow_delay_ms"`

	// FileTransferMaxSizeMiB caps the size of a file that can be sent in a
	// single transfer. The real constraint is the SENDER's RAM, not the
	// server's: the encrypted file stays whole in RAM for the entire send,
	// and during encryption the plaintext
	// read from the file also stays in memory alongside the ciphertext — the
	// real peak is close to DOUBLE this value, not 1×. Lower it on devices
	// with little RAM.
	FileTransferMaxSizeMiB int `json:"file_transfer_max_size_mib"`

	// FileTransferReconnectTimeout is how long the sender waits for a
	// disconnected recipient during a file transfer before declaring their
	// transfer failed (only for them, isolated from the other recipients)
	// and freeing its reserved buffer.
	FileTransferReconnectTimeout string `json:"file_transfer_reconnect_timeout"`

	// FileAcceptRetryInterval is, on the RECIPIENT side, how often to resend
	// its own file_accept if the first chunk hasn't arrived yet — every
	// accepted transfer offer must end in either the file arriving or an
	// explicit timeout, never an indefinite wait (file_accept can be lost
	// silently, see internal/server/hub.go Hub.Send: no backlog for a
	// recipient not registered at that instant). Must stay below at least
	// 1/3 of FileTransferReconnectTimeout — the default 30s against the
	// default 2m of FileTransferReconnectTimeout guarantees at least 4
	// file_accept resends before the sender isolates the recipient. Not
	// derived automatically from FileTransferReconnectTimeout: sender and
	// recipient are separate processes, each with its own config.json, and
	// this value is never exchanged over the wire — changing
	// FileTransferReconnectTimeout requires updating this too, on the
	// recipient side.
	FileAcceptRetryInterval string `json:"file_accept_retry_interval"`

	// FileTransferOfferTimeout is how long the sender waits for the response
	// (accept/reject) of ALL selected recipients before proceeding anyway
	// with whoever has already responded — one forgotten or disconnected
	// recipient shouldn't block sending to everyone else.
	FileTransferOfferTimeout string `json:"file_transfer_offer_timeout"`

	// FileOfferBatchWindow is how long the sender waits AFTER sending the
	// offer (not after the first acceptance: the window is anchored to the
	// offer itself, fixed) before actually starting to send toward whoever
	// has accepted by then, to collect in a single pass whoever accepts
	// nearly at the same time (the norm with several recipients: most
	// respond within a few seconds) instead of starting at the very first
	// acceptance and having to chase every other one with a full resend —
	// costly for a large file. If nobody has accepted by the time this
	// window elapses, nothing happens: it simply keeps waiting. If instead
	// ALL recipients have already responded before this window even
	// elapses, sending starts immediately (the "everyone responded" fast
	// path). A recipient who accepts after this window is still covered:
	// during sending, by the existing resume mechanism (concurrent, no
	// extra wait); after sending, by a grace window up to
	// FileTransferOfferTimeout (see startSendingChunks). Must stay well
	// below FileTransferOfferTimeout, of which it's a sub-window — not an
	// independent value.
	FileOfferBatchWindow string `json:"file_offer_batch_window"`

	// ── file compression ───────────────────────────────────────────────────────
	// StrongCompressionEnabled enables strong packing (LZMA2/XZ) as
	// pre-compression of file/contact-card content before encryption
	// (shared.PackData). Always compresses on a trial basis and falls back to raw
	// if the result isn't smaller than the original: disabling it never
	// risks corrupting a transfer, it only skips the compression attempt.
	StrongCompressionEnabled bool `json:"strong_compression_enabled"`

	// ── interface lock ─────────────────────────────────────────────────────────
	// InterfaceLockTimeout is the inactivity threshold (no keystroke/command)
	// after which the interface locks itself again — "0s" disables the
	// automatic lock (never removes the manual lock command, always
	// available regardless of this value). A free-form value chosen by the
	// operator (e.g. "30s", "1m", "2m"), not a list of preset options.
	InterfaceLockTimeout string `json:"interface_lock_timeout"`

	// TimeNukeTimeout is how long the interface may stay LOCKED before a
	// nukex-equivalent secure erasure triggers automatically — "0s"
	// disables it (default: never nuke just from being locked). Distinct
	// from InterfaceLockTimeout above (that one measures INACTIVITY while
	// unlocked; this one measures time spent already LOCKED).
	TimeNukeTimeout string `json:"time_nuke_timeout"`

	// ── duress decoy names ─────────────────────────────────────────────────────
	// DecoySecondaryLangs: comma-separated ISO codes among it/en/fr/de/es/ro/ru.
	// Empty = disabled.
	DecoySecondaryLangs string `json:"decoy_secondary_langs"`

	// DecoySecondaryLangPct: 0-100. Ignored when DecoySecondaryLangs is empty.
	DecoySecondaryLangPct int `json:"decoy_secondary_lang_pct"`

	// DecoyIntlPct: 0-100, rolled independently of DecoySecondaryLangPct,
	// checked first.
	DecoyIntlPct int `json:"decoy_intl_pct"`

	// DecoyInitialPct: 0-100. Applies on top of the mandatory case (two
	// fabricated contacts sharing the same first name).
	DecoyInitialPct int `json:"decoy_initial_pct"`
}

// Default returns the configuration with its default values.
func Default() Config {
	return Config{
		Lang:                 "en",
		Net:                  "tor",
		PingInterval:         "1m",
		CleanupInterval:      "5m",
		SenderKeyInterval:      "5m",
		SenderKeyMessageBudget: 25,
		ActiveInterval:       "1m",
		ActiveInitialDelay:   "1m",
		ProbeContactsTimeout: "90s",
		ProbeRetryCount:      3,
		ProbeRetryDelay:      "20s",
		TorProbeInterval:     "5m",
		TorProbeInitialDelay: "10s",
		WarmupInterval:       "5m",
		WarmupInitialDelay:   "20s",
		WarmupTimeout:        "1m",
		SelfKnockTimeout:     "1m",
		KnockHttpTimeout:     "15s",
		KnockRetryDelay:      "20s",
		InviteTimeout:        "30s",
		BridgesEnabled:       false,
		BridgeDefault:        "obfs4",
		BridgeFallback:       "webtunnel",

		PendingSlotLimit:     5,
		PendingEscalationAge: "90s",
		MessageRetryDelay:    "20s",
		MessageTTL:           "3m",

		FileWarpChunkSizeKiB:         shared.DefaultFileWarpChunkSizeKiB,
		FileWarpMaxInFlightChunks:    8,
		FileSlowChunkSizeKiB:         16,
		FileSlowMaxInFlightChunks:    2,
		FileSlowDelayMs:              250,
		FileTransferMaxSizeMiB:       512,
		FileTransferReconnectTimeout: "2m",
		FileAcceptRetryInterval:      "30s",
		FileTransferOfferTimeout:     "90s",
		FileOfferBatchWindow:         "10s",

		StrongCompressionEnabled: true,

		InterfaceLockTimeout: "0s",
		TimeNukeTimeout:      "0s",

		DecoySecondaryLangs:   "",
		DecoySecondaryLangPct: 8,
		DecoyIntlPct:          4,
		DecoyInitialPct:       20,
	}
}

// Load reads the configuration from the given file.
// Lines starting with # are stripped before JSON parsing.
// Returns the default values if the file doesn't exist or isn't readable.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), err
	}
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	for _, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			kept = append(kept, l)
		}
	}
	cfg := Default()
	if err := json.Unmarshal([]byte(strings.Join(kept, "\n")), &cfg); err != nil {
		return Default(), err
	}
	return cfg, nil
}

// Save writes the configuration to the given file (permissions 0600).
// The file includes comments explaining each parameter.
func Save(path string, cfg Config) error {
	content := fmt.Sprintf(fileTemplate,
		cfg.Lang,
		cfg.Net,
		cfg.PingInterval,
		cfg.CleanupInterval,
		cfg.SenderKeyInterval,
		cfg.SenderKeyMessageBudget,
		cfg.ActiveInterval,
		cfg.ActiveInitialDelay,
		cfg.ProbeContactsTimeout,
		cfg.ProbeRetryCount,
		cfg.ProbeRetryDelay,
		cfg.TorProbeInterval,
		cfg.TorProbeInitialDelay,
		cfg.WarmupInterval,
		cfg.WarmupInitialDelay,
		cfg.WarmupTimeout,
		cfg.SelfKnockTimeout,
		cfg.KnockHttpTimeout,
		cfg.KnockRetryDelay,
		cfg.InviteTimeout,
		cfg.BridgesEnabled,
		cfg.BridgeDefault,
		cfg.BridgeFallback,
		cfg.PendingSlotLimit,
		cfg.PendingEscalationAge,
		cfg.MessageRetryDelay,
		cfg.MessageTTL,
		cfg.FileWarpChunkSizeKiB,
		cfg.FileWarpMaxInFlightChunks,
		cfg.FileSlowChunkSizeKiB,
		cfg.FileSlowMaxInFlightChunks,
		cfg.FileSlowDelayMs,
		cfg.FileTransferMaxSizeMiB,
		cfg.FileTransferReconnectTimeout,
		cfg.FileAcceptRetryInterval,
		cfg.FileTransferOfferTimeout,
		cfg.FileOfferBatchWindow,
		cfg.StrongCompressionEnabled,
		cfg.InterfaceLockTimeout,
		cfg.TimeNukeTimeout,
		cfg.DecoySecondaryLangs,
		cfg.DecoySecondaryLangPct,
		cfg.DecoyIntlPct,
		cfg.DecoyInitialPct,
	)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

const fileTemplate = `{
  # ── PREFERENCES ──────────────────────────────────────────────────────────────────
  #
  # lang — interface language (wizard, TUI, CLI messages).
  # Valid values: "en", "it", "fr", "de", "es", "ro", "ru". Changing it here
  # (or with "neutrino lang <code>") takes effect on the next neutrino startup.
  # Default: "en".
  "lang": %q,

  # net — transport network to use: "tor" (default) or "i2p" (embedded on
  # linux/amd64 and linux/arm64; other platforms need the 'i2pd' daemon on
  # the system).
  # Changing it here (or with "neutrino net <tor|i2p>") takes effect on the
  # next neutrino startup; "--net <network>" overrides it for a single run.
  # Default: "tor".
  "net": %q,

  # ── SERVER ──────────────────────────────────────────────────────────────────────
  #
  # ping_interval — WebSocket keepalive (ping/pong).
  # The server sends a ping every <ping_interval>; if the client doesn't respond
  # within half the interval, that's one missed cycle. Two consecutive missed
  # cycles (not one) close the connection and the client reconnects — a single
  # late pong is common on a Tor circuit under stress and isn't a reliable sign
  # of a truly dead connection. Lowering it reduces zombie-connection detection
  # time; raising it reduces traffic on slow Tor links. Default: "1m".
  "ping_interval": %q,

  # cleanup_interval — how often the in-memory rate limiter is swept.
  # The rate limiter tracks connections per IP over the last 1-minute window.
  # It periodically removes expired entries to free RAM.
  # Default: "5m".
  "cleanup_interval": %q,

  # ── FORWARD SECRECY ─────────────────────────────────────────────────────────────
  #
  # sender_key_interval and sender_key_message_budget — the two rotation
  # criteria for the broadcast encryption key (senderKey), combined as an OR:
  # rotation fires on whichever condition is met first. sender_key_message_budget
  # bounds exposure by message count (the real quantity a compromised chain
  # exposes going forward, not elapsed time) — the primary driver during an
  # active conversation. sender_key_interval is a hygiene backstop for a room
  # that stays open but mostly silent: an idle chain has nothing to protect,
  # but shouldn't go unrotated forever either.
  #
  # sender_key_interval default: "5m".
  "sender_key_interval": %q,

  # sender_key_message_budget — messages encrypted under the current senderKey
  # generation before rotation fires, regardless of elapsed time. Lower values
  # shrink the exposure window if the chain state is ever compromised, at the
  # cost of more frequent key distribution (one ECIES encryption per room
  # member per rotation). Default: 25.
  "sender_key_message_budget": %d,

  # ── CONTACT PROBING ──────────────────────────────────────────────────────────────
  #
  # active_interval — interval between periodic contact probes over Tor.
  # Each cycle attempts a TCP :80 connection to every contact in the address
  # book in parallel. Updates the ●/✗ markers in the Contacts tab and sends
  # probe_ping to whoever is online.
  # If a cycle is still running when the timer fires, the new cycle is skipped
  # automatically (backpressure): pending probes never exceed 1.
  # Default: "1m".
  "active_interval": %q,

  # active_initial_delay — delay from startup to the first contact probe.
  # Lets Tor build circuits and warmup complete before the first full probe
  # runs. Default: "1m".
  "active_initial_delay": %q,

  # probe_contacts_timeout — global timeout for each contact-probing cycle.
  # A contact that doesn't respond within this time is marked offline.
  # New Tor circuits take 20–60s; the margin is necessary.
  # Default: "90s".
  "probe_contacts_timeout": %q,

  # probe_retry_count — how many TCP dial attempts per contact in each probing
  # cycle, before marking it offline. A single attempt can land in the wrong
  # window of Tor circuit construction even if the contact is online; more
  # attempts (with probe_retry_delay backoff) reduce how often /active needs
  # to be relaunched by hand. Bounded by the overall probe_contacts_timeout
  # budget. Default: 3.
  "probe_retry_count": %d,

  # probe_retry_delay — backoff between probe_retry_count attempts.
  # First retry after probe_retry_delay, second after 2×probe_retry_delay, etc.
  # Default: "20s".
  "probe_retry_delay": %q,

  # ── TOR CIRCUIT MANAGEMENT ───────────────────────────────────────────────────────
  #
  # tor_probe_interval — interval between periodic Tor circuit checks.
  # Uses the control port (< 1ms) if available, otherwise TCP to its own .onion.
  # Updates the colored dot in the Tor tab (red/yellow/green). Default: "5m".
  "tor_probe_interval": %q,

  # tor_probe_initial_delay — delay from startup to the first Tor circuit check.
  # Default: "10s".
  "tor_probe_initial_delay": %q,

  # warmup_interval — interval between circuit pre-warming cycles.
  # Connects ahead of time to known contacts to reduce the latency of the
  # first real connection. Doesn't update the status markers. Default: "5m".
  "warmup_interval": %q,

  # warmup_initial_delay — delay from startup to the first warmup.
  # Must be > tor_probe_initial_delay to avoid overloading Tor at startup.
  # Default: "20s".
  "warmup_initial_delay": %q,

  # warmup_timeout — global timeout for each circuit-warmup cycle.
  # Default: "1m".
  "warmup_timeout": %q,

  # self_knock_timeout — timeout for the self-knock inbound-verification check.
  # After every successful tor_probe, if inbound isn't confirmed yet, the TUI
  # sends a POST to its own /knock over Tor to verify that its hidden service
  # is reachable from the outside without needing any contact to be online.
  # The long timeout is necessary: Tor circuits to a new .onion can take up
  # to 60s. Default: "1m".
  "self_knock_timeout": %q,

  # ── KNOCK AND INVITES ────────────────────────────────────────────────────────────
  #
  # knock_http_timeout — HTTP timeout for automatic background knocks.
  # Used by: sendProbePing, sendProbeAck, and the other background knocks.
  # These knocks are fire-and-forget; 15s is enough once circuits are already
  # warm. No consequences if it expires: the next cycle retries automatically.
  # Default: "15s".
  "knock_http_timeout": %q,

  # knock_retry_delay — backoff between knock attempts (postKnockWithRetry).
  # First retry after knock_retry_delay, second after 2×knock_retry_delay.
  # Tor takes 30–90s to build a new circuit to a .onion: the delay lets
  # circuits stabilize before the next attempt. Default: "20s".
  "knock_retry_delay": %q,

  # invite_timeout — HTTP timeout for the invite/group-management knock
  # lifecycle: sending an invite, declining one, re-inviting, adding a
  # member, recalling a saved group, waking an unreachable member. On
  # Android every one of these goes through the single knock.Send helper, so
  # this field controls all of them there too. Default: "30s".
  "invite_timeout": %q,

  # ── TOR BRIDGES ──────────────────────────────────────────────────────────────────
  #
  # bridges_enabled — enables the use of Tor bridges at startup.
  # Set to true if you're in a country with network censorship or your ISP
  # blocks direct connections to Tor relays. Bridges are read from the
  # tor_bridges file in the same directory as the keystore (use
  # "neutrino get-bridges" to download new ones). Default: false.
  "bridges_enabled": %v,

  # bridge_default — transport to use as first choice among those in tor_bridges.
  # Valid values: "obfs4", "webtunnel".
  #
  # obfs4     — obfuscates Tor traffic into random-looking noise, so firewalls
  #             don't recognize the protocol's signature. The most mature type,
  #             available on the largest number of bridges. Recommended as the
  #             first choice in most cases.
  #
  # webtunnel — wraps Tor traffic inside a standard HTTPS connection, disguising
  #             it as normal web traffic to a real site. Harder to block because
  #             it would require blocking all HTTPS to that domain. More
  #             resistant to sophisticated censorship (deep packet inspection),
  #             but available on fewer bridges.
  #
  # Default: "obfs4".
  "bridge_default": %q,

  # bridge_fallback — fallback transport if bridge_default doesn't work.
  # Neutrino retries with this transport if bootstrapping with bridge_default
  # doesn't complete within the timeout. Leave empty ("") to disable the
  # fallback. Default: "webtunnel".
  "bridge_fallback": %q,

  # ── RELIABLE DELIVERY (multi-user chat) ────────────────────────────────────────────
  #
  # pending_slot_limit — how many messages can stay unacknowledged toward a
  # single recipient before writing new ones is blocked. Chosen for human
  # conversational coherence, not a technical constraint: past a handful of
  # unanswered messages, the thread of a discussion is already lost even
  # before any reply arrives. Default: 5.
  "pending_slot_limit": %d,

  # pending_escalation_age — age of the oldest unacknowledged message after
  # which a soft warning appears in Console. A first, non-alarming signal: at
  # this threshold a legitimate Tor/I2P circuit rebuild may still be in
  # progress. Default: "90s".
  "pending_escalation_age": %q,

  # message_retry_delay — backoff (doubled on each attempt) between
  # retransmissions of a single unacknowledged message. Same starting value
  # already used for Tor/I2P reconnection. Default: "20s".
  "message_retry_delay": %q,

  # message_ttl — how long a sent message may stay unacknowledged by a
  # connected recipient before it is re-encrypted under a new sender_key
  # generation and sent again. Twice this value also bounds how long a
  # retired DH ephemeral key is kept in two-member rooms. Default: "3m".
  "message_ttl": %q,

  # ── FILE TRANSFER ────────────────────────────────────────────────────────────────
  #
  # Speed presets chosen by the sender at the moment of sending (/grp-file-send),
  # not a single static value: "slow" is the default unless "warp" is chosen
  # explicitly. Each preset is a bundle of three parameters — chunk size,
  # depth of the not-yet-acked chunk window, and delay between one chunk and
  # the next — meant for field tuning (Tor circuits, typical file sizes), not
  # to be left at their defaults forever.
  #
  # file_warp_chunk_size_kib — chunk size (KiB) for the "warp" preset.
  # Larger chunks proportionally reduce transport overhead (JSON + Base64
  # envelope, ~33%%), at the cost of more bytes lost if the connection drops
  # mid-chunk while in flight. Default: 64.
  "file_warp_chunk_size_kib": %d,

  # file_warp_max_inflight_chunks — how many not-yet-acked chunks can be in
  # flight per recipient in the "warp" preset. Pipelined instead of lockstep
  # chunk-then-ack-then-chunk, to avoid wasting the round-trip over Tor.
  # Default: 8.
  "file_warp_max_inflight_chunks": %d,

  # file_slow_chunk_size_kib — chunk size (KiB) for the "slow" preset.
  # Smaller chunks mean fewer bursts, less lost work per recipient if the
  # connection drops mid-transfer. Default: 16.
  "file_slow_chunk_size_kib": %d,

  # file_slow_max_inflight_chunks — not-yet-acked chunk window for the "slow"
  # preset. Narrower than "warp" to stay deliberately less invasive on the
  # connection. Default: 2.
  "file_slow_max_inflight_chunks": %d,

  # file_slow_delay_ms — fixed delay (milliseconds) between one chunk and the
  # next in the "slow" preset. Chat always keeps absolute priority over queued
  # chunks regardless of this value. Default: 250.
  "file_slow_delay_ms": %d,

  # file_transfer_max_size_mib — maximum size (MiB) of the original
  # (uncompressed) file that can be sent in a single transfer. The real
  # constraint is the SENDER's RAM, not the server's: during sending, the
  # sender keeps both the plaintext read from the file and the resulting
  # ciphertext in memory — the real RAM peak is close to DOUBLE this value,
  # not 1×. Lower it on devices with little RAM (e.g. future mobile ports).
  # Default: 512.
  "file_transfer_max_size_mib": %d,

  # file_transfer_reconnect_timeout — how long the sender waits for a
  # disconnected recipient during a file transfer before declaring their
  # transfer failed (only for them, isolated from the other recipients).
  # Default: "2m".
  "file_transfer_reconnect_timeout": %q,

  # file_accept_retry_interval — on the RECIPIENT side, how often to resend
  # its own file_accept if the first chunk hasn't arrived yet (a file_accept
  # can be silently lost — see internal/server/hub.go Hub.Send: no backlog
  # for a recipient not registered at that exact instant). Must stay below
  # 1/3 of file_transfer_reconnect_timeout — the defaults (30s vs. 2m)
  # guarantee at least 4 file_accept resends before the sender isolates this
  # recipient. Not derived automatically from file_transfer_reconnect_timeout:
  # sender and recipient are separate processes, each with its own
  # config.json, and this value is never exchanged over the wire — if you
  # change file_transfer_reconnect_timeout, update this too on the recipient
  # side. Default: "30s".
  "file_accept_retry_interval": %q,

  # file_transfer_offer_timeout — how long the sender waits for the response
  # (accept/reject) of ALL selected recipients before proceeding anyway with
  # whoever has already responded. One forgotten or disconnected recipient
  # shouldn't block sending to everyone else. Default: "90s".
  "file_transfer_offer_timeout": %q,

  # file_offer_batch_window — how long the sender waits AFTER sending the
  # offer (not after the first acceptance: the window is fixed, anchored to
  # the offer itself) before actually starting to send toward whoever has
  # accepted by then, to collect whoever accepts nearly at the same time
  # (the norm with several recipients) into a single first pass instead of
  # chasing each one with a full resend — costly for a large file. If nobody
  # has accepted by the time this window elapses, nothing happens: the
  # sender simply keeps waiting. If every recipient has already responded
  # before this window even elapses, sending starts immediately (the "all
  # responded" fast path). A recipient who accepts later stays covered:
  # while sending, through the existing resume mechanism (concurrent, no
  # extra wait); after sending, through a grace window up to
  # file_transfer_offer_timeout (see startSendingChunks). Keep well below
  # file_transfer_offer_timeout, of which this is a sub-window, not an
  # independent value. Default: "10s".
  "file_offer_batch_window": %q,

  # ── FILE COMPRESSION ─────────────────────────────────────────────────────────────
  #
  # strong_compression_enabled — pre-compresses file/contact-card content with
  # LZMA2/XZ before encryption. Always compresses on a trial basis and falls
  # back to raw
  # bytes if the result isn't actually smaller — disabling it never risks
  # corrupting a transfer, it only skips the compression attempt (saves CPU on
  # already-compressed content). Default: true.
  "strong_compression_enabled": %v,

  # ── INTERFACE LOCK ───────────────────────────────────────────────────────────────
  #
  # interface_lock_timeout — inactivity threshold after which the interface
  # locks itself again (no key/command, not "screen off" alone). Free-form
  # value chosen by the operator (e.g. "30s", "1m", "2m"), not a fixed list of
  # options. "0s" disables the automatic lock (the manual lock command stays
  # available regardless of this value). Settable at runtime with
  # "/sec-lock-timeout <duration|0>", persisted here immediately.
  # Default: "0s" (disabled).
  "interface_lock_timeout": %q,

  # time_nuke_timeout — how long the interface may stay LOCKED before an
  # automatic nukex-equivalent secure erasure triggers. Distinct from
  # interface_lock_timeout above (that one measures inactivity while
  # UNLOCKED; this one measures time already spent LOCKED). "0s" disables
  # it (default). Free-form duration, same format as interface_lock_timeout.
  "time_nuke_timeout": %q,

  # ── DURESS DECOY NAMES ───────────────────────────────────────────────────────────
  #
  # decoy_secondary_langs — ISO codes among it,en,fr,de,es,ro,ru, comma-separated.
  # Empty ("") disables. Example: "fr,es". Default: "".
  "decoy_secondary_langs": %q,

  # decoy_secondary_lang_pct — 0-100. Default: 8.
  "decoy_secondary_lang_pct": %d,

  # decoy_intl_pct — 0-100. Default: 4.
  "decoy_intl_pct": %d,

  # decoy_initial_pct — 0-100. Default: 20.
  "decoy_initial_pct": %d
}
`

// ── Duration methods ───────────────────────────────────────────────────────────

func parseDur(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func (c Config) PingDuration() time.Duration {
	return parseDur(c.PingInterval, time.Minute)
}
func (c Config) CleanupDuration() time.Duration {
	return parseDur(c.CleanupInterval, 5*time.Minute)
}
func (c Config) SenderKeyDuration() time.Duration {
	return parseDur(c.SenderKeyInterval, 5*time.Minute)
}
func (c Config) SenderKeyMessageBudgetOrDefault() int {
	return clampPositiveInt(c.SenderKeyMessageBudget, 25)
}
func (c Config) PendingSlotLimitOrDefault() int {
	return clampPositiveInt(c.PendingSlotLimit, 5)
}
func (c Config) PendingEscalationAgeDuration() time.Duration {
	return parseDur(c.PendingEscalationAge, 90*time.Second)
}
func (c Config) MessageRetryDelayDuration() time.Duration {
	return parseDur(c.MessageRetryDelay, 20*time.Second)
}
func (c Config) MessageTTLDuration() time.Duration {
	return parseDur(c.MessageTTL, 3*time.Minute)
}
func (c Config) ActiveDuration() time.Duration {
	// Fallback matches Default().ActiveInterval ("1m") — never observed in
	// practice, since Default() always produces a valid string.
	return parseDur(c.ActiveInterval, time.Minute)
}
func (c Config) ActiveInitialDelayDuration() time.Duration {
	return parseDur(c.ActiveInitialDelay, time.Minute)
}

// InterfaceLockTimeoutDuration uses a different rule than parseDur above:
// zero is a valid, intentional value (automatic lock disabled), not an
// "unset" value to replace with a positive default — an unparseable value
// still falls back to zero (disabled), never to an arbitrary threshold that
// would enable the lock without the operator having chosen it.
func (c Config) InterfaceLockTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.InterfaceLockTimeout)
	if err != nil || d < 0 {
		return 0
	}
	return d
}
// TimeNukeTimeoutDuration follows the same "zero is intentional" rule as
// InterfaceLockTimeoutDuration above — never falls back to an enabling
// default the operator didn't choose.
func (c Config) TimeNukeTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.TimeNukeTimeout)
	if err != nil || d < 0 {
		return 0
	}
	return d
}
func (c Config) ProbeContactsTimeoutDuration() time.Duration {
	return parseDur(c.ProbeContactsTimeout, 90*time.Second)
}
func (c Config) ProbeRetryCountOrDefault() int {
	return clampPositiveInt(c.ProbeRetryCount, 3)
}
func (c Config) ProbeRetryDelayDuration() time.Duration {
	return parseDur(c.ProbeRetryDelay, 20*time.Second)
}
func (c Config) TorProbeIntervalDuration() time.Duration {
	return parseDur(c.TorProbeInterval, 5*time.Minute)
}
func (c Config) TorProbeInitialDelayDuration() time.Duration {
	return parseDur(c.TorProbeInitialDelay, 10*time.Second)
}
func (c Config) WarmupIntervalDuration() time.Duration {
	// Fallback matches Default().WarmupInterval ("5m") — never observed in
	// practice, since Default() always produces a valid string.
	return parseDur(c.WarmupInterval, 5*time.Minute)
}
func (c Config) WarmupInitialDelayDuration() time.Duration {
	return parseDur(c.WarmupInitialDelay, 20*time.Second)
}
func (c Config) WarmupTimeoutDuration() time.Duration {
	return parseDur(c.WarmupTimeout, time.Minute)
}
func (c Config) SelfKnockTimeoutDuration() time.Duration {
	return parseDur(c.SelfKnockTimeout, time.Minute)
}
func (c Config) KnockHttpTimeoutDuration() time.Duration {
	return parseDur(c.KnockHttpTimeout, 15*time.Second)
}
func (c Config) KnockRetryDelayDuration() time.Duration {
	return parseDur(c.KnockRetryDelay, 20*time.Second)
}
func (c Config) InviteTimeoutDuration() time.Duration {
	return parseDur(c.InviteTimeout, 30*time.Second)
}
func (c Config) FileTransferReconnectTimeoutDuration() time.Duration {
	return parseDur(c.FileTransferReconnectTimeout, 2*time.Minute)
}
func (c Config) FileAcceptRetryIntervalDuration() time.Duration {
	return parseDur(c.FileAcceptRetryInterval, 30*time.Second)
}
func (c Config) FileTransferOfferTimeoutDuration() time.Duration {
	return parseDur(c.FileTransferOfferTimeout, 90*time.Second)
}
func (c Config) FileOfferBatchWindowDuration() time.Duration {
	return parseDur(c.FileOfferBatchWindow, 10*time.Second)
}

// ── file transfer methods (clamp to a sensible minimum) ──────────────────────────

func clampPositiveInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func (c Config) FileWarpChunkSizeKiBOrDefault() int {
	return clampPositiveInt(c.FileWarpChunkSizeKiB, shared.DefaultFileWarpChunkSizeKiB)
}
func (c Config) FileWarpMaxInFlightChunksOrDefault() int {
	return clampPositiveInt(c.FileWarpMaxInFlightChunks, 8)
}
func (c Config) FileSlowChunkSizeKiBOrDefault() int {
	return clampPositiveInt(c.FileSlowChunkSizeKiB, 16)
}
func (c Config) FileSlowMaxInFlightChunksOrDefault() int {
	return clampPositiveInt(c.FileSlowMaxInFlightChunks, 2)
}
func (c Config) FileSlowDelayDuration() time.Duration {
	if c.FileSlowDelayMs <= 0 {
		return 250 * time.Millisecond
	}
	return time.Duration(c.FileSlowDelayMs) * time.Millisecond
}
func (c Config) FileTransferMaxSizeMiBOrDefault() int {
	return clampPositiveInt(c.FileTransferMaxSizeMiB, 512)
}
