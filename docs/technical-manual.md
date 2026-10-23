# Technical Manual — Neutrino

## General architecture

`neutrino` is a single Go binary that, on every startup, simultaneously performs three roles:

1. **Tor node** — starts an embedded Tor process (`linux/amd64` and `linux/arm64` binaries included via `go:embed`; falls back to the system daemon on other platforms) and publishes a v3 hidden service with the Ed25519 key of the local identity
2. **WebSocket server** — accepts connections from contacts on the hidden service; routes encrypted messages between clients connected to the same room
3. **Client** — connects to its own local server and, at the user's request, to contacts' servers via Tor

No state is written to disk outside the keystore and the config file. Messages live exclusively in RAM; restarting the process permanently erases them.

> **Android app and macOS.** The native Android app (`cmd/androidapp`, Fyne) and the macOS builds are in testing and not distributed yet. Sections and references about them describe those builds; the Android app's source (`cmd/androidapp`) is not part of this repository.

### Topology: star per room, not mesh

Inside each individual room (two people or a larger group — same mechanism for both) there is **only one host**: whoever creates it by launching `/grp-invite` opens it on their own local server. All other participants connect as clients to that host's hidden service. The `Hub` (see §Server) lives there and acts as a relay: in a group of N people, messages don't go directly from one participant to another, they all pass through the host, which redistributes them via broadcast. No participant connects directly to another participant who isn't the host.

It is therefore not a P2P mesh in the strict sense, but it remains decentralized for three reasons:

- **No fixed third-party server** — every `neutrino` binary simultaneously performs the three roles above; the host role is not dedicated infrastructure, it is simply whoever created that room.
- **The host is blind to content, not to routing metadata** — the `Hub` only forwards already-encrypted bytes (senderKey for broadcast, one `FileOfferEnvelope` per recipient for files) and does not hold the keys to read them. For broadcast, the sender is sealed inside the ciphertext (sealed sender): real protection in groups (the host may be unrelated to the conversation between any two members), but with no practical effect in a two-member room, where the host is always the only other party. For a `file_offer` (including a contact card via `/grp-contact-send`, § "Contact card" below) the `to_user_ids` list still travels in the clear — the relay always knows who it's addressed to, and never who the sender is ambiguously in groups thanks to the channel's sealed sender, but without sealed *recipient*; file name and size, on the other hand, remain encrypted (see `cryptography-manual.md` §6-7).
- **The role flips room by room** — in the next room, the host can be any other participant.

---

## Module layout

```
cmd/main.go                      CLI entry point: wizard, Tor startup, server, TUI

internal/shared/
  crypto.go                      Cryptographic primitives (AES-256-GCM, ECIES, HKDF, room proof,
                                 per-relationship message/knock signing and verification)
  handshake.go                   ClientHello / ServerHello / HandshakeResult structs; RelSigningKey/
                                 RelPeerKey (relationship keys); policy constants
  relbootstrap.go                RelBootstrapPayload — point-to-point bootstrap of relationship
                                 keys (persistent when a contact is added, ephemeral between
                                 members introduced in a room)
  relrotate.go                   RelRotatePayload — per-relationship rotation with cross-
                                 certification (SignRelKeyRotation/VerifyRelKeyRotation)
  pack.go                        PackData/UnpackData (strong LZMA2/XZ pack with a raw fallback),
                                 NowTS — compression/timestamp shared by messages, files, and the
                                 optical QR channel

internal/server/
  models.go                      UserSession, Message
  store.go                       SessionStore (sync.RWMutex, RAM only)
  hub.go                         Hub — WebSocket broadcast and routing
  handshake.go                   DoServerHandshake
  handlers.go                    appCtx (dependency container), handleHealth, handleKnock
  ws.go                          handleWS: upgrade → handshake → message loop; wire frame types
  rooms.go                       RoomRegistry — per-member secrets with their associated relationship keys
  ratelimit.go                   RateLimiter (sliding window per IP)
  server.go                      RunOnListener, ServerConfig; shutdown logic

internal/client/
  handshake.go                   DoClientHandshake
  client.go                      Client: Connect, ConnectWithRetry, Send, DecryptMsg,
                                 RotateSenderKey, SendFileOffer, SendPingProbe, SendPongProbe, …
  tui/tui.go                     bubbletea TUI: model, Update, View, slash commands, tabs, palette,
                                 cmdRoomInfo (/grp-info), contacts tab with renderContactList

internal/keystore/
  keystore.go                    Keystore: Argon2id + AES-256-GCM; Contact, Group, SavedGroup
  backup.go                      BIP-39 mnemonic, backup/restore, QR export (single/multi), contact sync and merge

internal/tornode/
  tornode.go                     Node: StartTor(ctx, StartConfig{OnProgress, Bridges}),
                                 AddHiddenService, HasCircuits, DialContext, DialerForToken,
                                 Close

internal/config/
  config.go                      Config: Load/Save with # comments, default values

internal/i18n/
  i18n.go                        Lang, T(key, args...), SetActive/Active — global per-process language
  catalog.go                     Loads Neutrino-i18n-data.json into catalogs[Lang]map[string]string
  commands.go                    CmdID, RegisterCommands, CommandName, ResolveCommand (command names always in English)
  Neutrino-i18n-data.json        Single translation catalog (embedded via go:embed): one entry per key,
                                 with the en/it/fr/de/es/ro/ru texts

internal/qrscan/
  qrscan.go                      DecodeQRFromImage(image.Image) — decode a QR from an already-loaded image
  camera_linux.go                ScanCamera/ScanCameraContinuous via pure-Go V4L2 (build tag linux && !android)
  camera_other.go                Stub (build tag !linux || android)

internal/fountain/
  fountain.go                    Pure-Go LT codes encoder/decoder (peeling decoder, robust soliton
                                 distribution) — own deterministic PRNG (splitmix64, not math/rand)

internal/qroptical/
  qroptical.go                   Sender/Receiver on top of internal/fountain — QR framing (prefix "NQF1:" +
                                 base64), used both by file transfer (neutrino qr send/receive, Android
                                 screens) and by the animated backup/sync variants

internal/version/
  version.go                     AppVersion — single source shared by the TUI (/info-app) and the Android app (Info menu)
```

---

## Keystore

### Data structure

```go
type Keystore struct {
    Version  int    `json:"version"`
    Username string `json:"username"`
    // IdentityKey/MLKEMKey/MLDSAKey are the global-per-identity TRANSPORT
    // key: they derive the network address (Tor hidden service / I2P
    // destination) and still authenticate/encrypt the knock toward a
    // known contact (KnockDHTag mutuality tag, EncryptKnock/DecryptKnock)
    // — but never authenticate the WebSocket handshake
    // (ClientHello/ServerHello.Sig, that role belongs to the relationship
    // keys on each Contact, see below). On rotation (StartRootRotation)
    // the previous ones stay in the OldIdentityKey/OldMLKEMKey/OldMLDSAKey
    // vault until every contact and device has confirmed the new root.
    IdentityKey []byte       `json:"identity_key"` // current Ed25519 private key (64 bytes)
    MLKEMKey    []byte       `json:"mlkem_key,omitempty"`
    MLDSAKey    []byte       `json:"mldsa_key,omitempty"`
    Contacts    []Contact    `json:"contacts"`
    SavedGroups []SavedGroup `json:"saved_groups,omitempty"`
    // Other fields (device/remote_nuke, duress) — see the dedicated sections.
}
```

`Username` is the **first data field** of the JSON (after `version`) — it is the network identity to which `IdentityKey` (and hence the `.onion` address, derived from the pubkey) and all the lists below are bound. The `Keystore` struct itself remains that of a **single identity** — handling multiple identities in the same file (see "Multiple identities" below) happens entirely at the `Load`/`Save` boundary, without touching this type.

```go
type Contact struct {
    Username  string `json:"username"`             // network identity
    LocalName string `json:"local_name,omitempty"` // personal alias, empty = use Username
    // IdentityPub is the contact's TRANSPORT key (Ed25519, 32 bytes) —
    // computes its network address and stays in use for the knock's
    // mutuality tag and encryption toward them (KnockDHTag/EncryptKnock);
    // it never authenticates the WebSocket handshake, that role
    // belongs to the four relationship keys below.
    IdentityPub []byte `json:"identity_pub"`

    // RelIdentityPriv/PeerRelIdentityPub and RelContentPriv/
    // PeerRelContentPub (+ their respective ML-KEM-768/ML-DSA-65
    // companions, not shown here) are the four relationship keys with
    // THIS contact — generated at random and independent for each one, no
    // master secret, exchanged bidirectionally right after the two users
    // become mutual contacts (§"Relationship keys" below).
    // RelIdentityPriv/PeerRelIdentityPub authenticate the handshake and
    // the knock mutuality tag toward this contact; RelContentPriv/
    // PeerRelContentPub sign and
    // encrypt messages, files, and contact cards exchanged with them.
    RelIdentityPriv        []byte `json:"rel_identity_priv,omitempty"`
    PeerRelIdentityPub     []byte `json:"peer_rel_identity_pub,omitempty"`
    RelContentPriv         []byte `json:"rel_content_priv,omitempty"`
    PeerRelContentPub      []byte `json:"peer_rel_content_pub,omitempty"`
    // RelIdentityConfirmedByPeer/RelContentConfirmedByPeer: both true only
    // after a real rel_init_ack received from this contact (they always
    // turn on together, since the bootstrap carries both keys in one
    // exchange) — it is these two flags, not just the presence of the
    // public keys above, that decide whether the contact is ready to be
    // invited into a room. A self-heal (failed handshake, or an invalid
    // content signature) can clear them independently of each other.
    RelIdentityConfirmedByPeer bool `json:"rel_identity_confirmed_by_peer,omitempty"`
    RelContentConfirmedByPeer  bool `json:"rel_content_confirmed_by_peer,omitempty"`

    MLKEMPub  []byte    `json:"mlkem_pub,omitempty"`  // contact's durable ML-KEM-768 encapsulation key (1184 bytes), from QR/URI or root_rotate
    MLDSAPub  []byte    `json:"mldsa_pub,omitempty"`  // contact's durable ML-DSA-65 public key (1952 bytes, packed)
    LastAckAt time.Time `json:"last_ack_at"`          // local clock: last probe_ack received (zero = never)
    LastSeenAt time.Time `json:"last_seen_at"`        // local clock: last time reached via TCP in a probe cycle (zero = never)
    Verified  bool       `json:"verified,omitempty"`  // full safety number comparison done out-of-band and confirmed by the user (see "Explicit contact verification" below)
    // Other fields (relationship rotation in progress, known device, etc.) —
    // see keystore.go and the dedicated sections.
}

type SavedGroup struct {
    LocalName string             `json:"local_name"`
    GroupID   string             `json:"group_id"` // stable identifier shared among members (4 random bytes, hex)
    Members   []SavedGroupMember `json:"members"`
}

type SavedGroupMember struct {
    Username    string `json:"username"`
    IdentityPub []byte `json:"identity_pub"` // Ed25519 pubkey (32 bytes)
}
```

The `SavedGroup` secret is **not** saved — it is regenerated at every session.

Example of a decrypted JSON payload (`[]byte` keys shown as placeholders, in reality they are raw bytes base64-serialized by `encoding/json`). The payload is **always an array**, even with a single identity (see "Multiple identities"):
```json
[
  {
    "version": 6,
    "username": "alice",
    "identity_key": "<64 bytes>",
    "contacts": [
      {"username": "bob", "local_name": "roberto", "identity_pub": "<32 bytes>"}
    ],
    "saved_groups": []
  }
]
```

### Multiple identities

A keystore file can contain **multiple independent identities** (each with its own `Username`, `IdentityKey`/`.onion`, `Contacts`, `SavedGroups`). The `Keystore` struct itself never changes to express this: it remains that of a single identity, and a file's full list is only ever handled at the disk read/write boundary — every place in the code that reads `ks.Contacts`/`ks.Username`/etc. works on a single identity. **Desktop and Android diverge here**: desktop (and Termux, same binary) uses an N-slot container with a per-identity password; Android (`cmd/androidapp`, native app) uses the single-shared-password array format described further down. No migration path exists between the two — they are different files/accounts, not two views of the same data.

#### Desktop/Termux — N-slot container, per-identity password

**On-disk format**: `slotFileOnDisk{Slots []slotEntry}` (`internal/keystore/slot_file.go`) — a container of independently wrapped slots, not a single JSON array decrypted under one shared password. Each `slotEntry` has the same on-disk shape whether it holds a real identity, the structurally-mandatory decoy identity, or pure random "noise" — indistinguishable from outside. `WriteSlotContainer`/`ReadSlotContainer` do pure container I/O; no slot is opened at this stage.

**Unlocking (`UnlockSlot`/`LoadAndUnlock`, `slot_unlock.go`/`slot_save.go`)**: the two passwords entered at launch — `password_file` (shared by the whole file) and `password_identity` (specific to one identity) — are tried together against every slot. Whichever slot the combination opens **is** the identity for that session: there is no separate "choose an identity" step and no way to distinguish "wrong password" from "this opened the decoy" from the outside. A brand-new file (`CreateFile`, `slot_create.go`) always starts with exactly 3 slots: the real identity, the mandatory decoy, and one noise slot.

**Growth, never a flat count**: adding a real identity (`add-identity` → `(*UnlockedSlot).AddRealIdentity`, `slot_add_identity.go`) consumes one pending noise slot and creates two new noise slots in its place — doubling (1→2→4→8 pending noise slots over successive additions), never a linear +1 — so the total slot count by itself never reveals how many real identities a file holds, only an upper bound on activity. `SlotPendingNoise []int` tracks which indices are still noise; on the decoy identity this list is unrelated to the real one's, by construction.

**Saving touches only what changed**: `SaveSlot` re-wraps and persists only the caller's own slot, rewriting the whole container file but leaving every other slot's ciphertext byte-for-byte untouched; `SaveWithDuress` additionally re-seals the decoy's mirrored content. Changing a password (`/sec-passwd`, `ChangePassword` → `VerifyPasswordIdentity`+`RewrapOwnSlot`) only re-wraps that identity's own key under the new password — the slot's encrypted content itself is never re-encrypted.

**The decoy identity "with the hammer already cocked" (`DuressAccess`, `internal/keystore/duress_access.go`)**: every real identity's slot carries a small field sealing the decoy's own symmetric key (`K_i_duress`) directly under the real identity's own key — no password needed to read it once a real identity is already unlocked. This is what lets `/sec-duress` (`SetDuress` closure in `cmd/main.go`) change the decoy's password, and what lets the interface lock (`CandidateIsDuressPassword`, `slot_duress_check.go`) recognize the decoy's password at the unlock prompt, without that session ever having to know the decoy's *old* password. The decoy's own copy of this same field is indistinguishable random bytes — opening it from the decoy side would require the real identity's key, which the decoy, by design, never has.

**No command removes an identity's slot**: slots are never removed under this format, and no identity can touch another's slot without that identity's own password — "deleting someone else's identity" has no safe meaning. The one exception is opening the decoy at login (below), which overwrites every other slot with random bytes. Destroying your own current identity never deletes the whole file either — see "Self-destruction" below.

**The swap into the decoy identity mid-session**, triggered by `/nukex`, the automatic `time` trigger, `remote_nuke` on the target side, and the duress PIN recognized at the interface lock — all four funnel into the same two-step sequence inside `runOnce`'s own loop (`cmd/main.go`):

```go
func (u *UnlockedSlot) OverwriteAllContacts() (duressIdx int, duressKi, duressPlain []byte, emptied int, err error)  // slot_overwrite.go
func (u *UnlockedSlot) PromoteDuress() (*UnlockedSlot, error)                                                        // slot_promote_duress.go
```

`OverwriteAllContacts` empties every one of the identity's contacts in place — batched `EmptyMirroredContact`, never removing a slot, mirroring each emptied entry onto the decoy's own copy exactly like an ordinary single contact deletion already does. `PromoteDuress` then reuses `DuressAccess` (already in RAM, no password) to open the decoy's own content and hands back a new `UnlockedSlot` bundle for it — `runOnce`'s loop adopts it (`session = promoted`) and `continue`s, instead of returning: the function that unlocked a password prompt once never unlocks a second one, and the already-bootstrapped Tor/I2P node is never torn down and rebuilt. The abandoned real identity's own hidden service is left running, unpublished-from-use but not explicitly closed — closing it would itself be a new, observable, correlatable signal ("this onion address went dark at this instant"), see "Self-destruction" below for the full reasoning.

A session already running as the decoy identity manages its own contacts with a dedicated pair that never touches `DuressAccess` at all:

```go
func (u *UnlockedSlot) AddPlainContacts(incoming []Contact, fromDevicePub []byte) (added, updated int, rejected [][]byte, err error)  // slot_mirror_contact.go
func (u *UnlockedSlot) EmptyPlainContact(realContactIdx int) error
```

The decoy's own `DuressAccess` field holds structurally-mandatory random noise, never a real wrapped key (it has no further decoy beneath it to reach) — calling the mirrored pair (`AddMirroredContacts`/`EmptyMirroredContact`) on a decoy session would deterministically fail AES-GCM authentication. `AddPlainContacts`/`EmptyPlainContact` mirror the same merge/recycle logic but operate on `u.Identity` alone, persisted with `SaveSlot`.

After the swap, `runNukeOverwriteInPlace` (`cmd/main.go`) also overwrites the triggering real identity's own slot with random bytes (`ObliterateSlot`, `slot_obliterate.go`) and writes the container back — so a cold restart can no longer open it with the real password. Only that slot: another real identity in the same file is not implicated by the trigger.

Typing the decoy password directly at login takes a different path (`openKeystoreSession`, `cmd/main.go`): the moment the opened slot is the decoy (`Identity.IsDuress`), `ObliterateOtherSlots` overwrites every other slot in the container — every real identity and every noise slot — with fresh random bytes, and the container is written back before the session starts. No other slot's password is needed: the slots are simply replaced, never decrypted. `DuressAccess` stays one-way (real → decoy, never the reverse), so the decoy session itself never holds a key able to reach a real identity.

#### Android (`cmd/androidapp`) — single shared password

Unlike desktop, Android has **not** been migrated to the N-slot format above: it still uses the original array-under-one-password model. The encrypted JSON payload is an array of `Keystore` objects:
```json
[
  {
    "version": 6,
    "username": "alice",
    "identity_key": "<64 bytes>",
    "contacts": [
      {"username": "bob", "local_name": "roberto", "identity_pub": "<32 bytes>"}
    ],
    "saved_groups": []
  }
]
```
`LoadAll(path, password)` (`internal/keystore/keystore.go`) decrypts and tries to `json.Unmarshal` into `[]*Keystore`; a single-object payload (pre-multiple-identities format) is automatically wrapped into a one-element list. `Load` is a convenience wrapper returning the first identity. Each `*Keystore` carries a private `siblings []*Keystore` field (not serialized) pointing to the whole list; `Save()` marshals `ks.siblings` if set, otherwise just itself. `AddIdentity(existing, newKs)` adds and relinks; `RemoveIdentity(list, username)` removes and relinks, refusing to empty the last identity (`keystore.err_cannot_remove_last_identity`) or remove an unknown username (`keystore.err_identity_not_found`) — `Save()` still rewrites the whole (shorter) file, no multi-pass deletion of just the removed identity.

`appstate.State.KSAll []*keystore.Keystore` holds the full list alongside `KS` (the session's active identity); `screens/unlock.go` calls `keystore.LoadAll`. If unlocking finds more than one identity, `screens/identity_picker.go` (`BuildIdentityPicker`) offers one button per identity before proceeding to bootstrap. "Switching identity" mid-session doesn't exist: it's `/quit` (`screens/quit.go`, also clears `KSAll`) followed by a fresh unlock. `screens/add_identity.go` (`BuildAddIdentity`) asks only a username (reuses the file's already-unlocked single password — no second password to set), with a final QR of the new identity. `screens/identities.go` (`BuildIdentities`, Settings → Identities) lists `KSAll` with the active identity marked and a working "Delete" button per row — absent only on the session's currently active identity.

### Encryption on disk

The keystore is serialized to JSON, encrypted with AES-256-GCM, and written atomically via a temporary file + rename. The AES key is derived from the password with Argon2id:

```
parameters: time=3, memory=64 MB, threads=4, keyLen=32
salt: 16 random bytes, prepended to the payload
nonce: 12 random bytes, after the salt
file layout: salt[16] || nonce[12] || ciphertext_with_tag
```

Format version: `6` — every version bump backfills the new fields on load for a keystore predating it (`migrateVersion`, one `case` per version, each falling through to the next): version 3 added `MLKEMKey` (case 2, itself falling through from case 1, which also backfills `IdentityKey` if absent); version 4 added `DeviceID`/`DevicePriv`/`DevicePub` (device-level signing identity for `remote_nuke`, case 3); version 5 added `MLDSAKey`/`OldMLDSAKey` (durable ML-DSA-65 signing key for the hybrid PQC network identity, case 4); version 6 split `RelIdentityConfirmedByPeer`/`RelContentConfirmedByPeer` out of a single combined flag (case 5). The version is part of the encrypted JSON, not in the clear.

### Path

`~/.config/neutrino/keystore` — `os.UserConfigDir()` + `neutrino/keystore`.

---

## Configuration

`~/.config/neutrino/config.json` — a text file with `#` comment lines followed by standard JSON. The parser in `Load` strips lines starting with `#` before `unmarshal`. Generated on first run by the wizard; can be reset with `neutrino reset-config`.

All duration fields use the Go format (`"30s"`, `"5m"`, `"1m30s"`). Missing or invalid values are silently replaced with the default via `parseDur`.

| Field | Default | Meaning |
|---|---|---|
| `net` | `"tor"` | Transport network: `tor` or `i2p`. Changed with `neutrino net [tor\|i2p]` (§CLI), effective on next restart — overridable for a single run with `--net <network>`, without touching the file |
| `ping_interval` | `1m` | WebSocket keepalive (ping/pong) — 2 consecutive missed cycles tolerated before closing, see §Keepalive |
| `cleanup_interval` | `5m` | Periodic cleanup of the in-RAM rate limiter |
| `sender_key_interval` | `5m` | senderKey rotation — time-based hygiene backstop, even in a silent room (OR criterion with `sender_key_message_budget` below, whichever fires first) |
| `sender_key_message_budget` | `25` | senderKey rotation — count-based criterion, messages sent under the current generation (OR criterion with `sender_key_interval` above) |
| `pending_slot_limit` | `5` | How many broadcast messages can stay without the server's take-charge (one's own self-echo, which carries the assigned `gseq`) before the next send is blocked (backpressure) |
| `message_retry_delay` | `20s` | Backoff (doubles on each attempt) between one retransmission and the next for an unconfirmed message — same value reused server-side for the per-contact delivery queue |
| `pending_escalation_age` | `90s` | Age of the oldest unconfirmed message beyond which the UI shows a soft warning in Console |
| `message_ttl` | `3m` | How long a message may stay unconfirmed by a connected recipient before the sender rotates its senderKey and re-encrypts every unconfirmed message under the new generation; twice this value bounds how long a retired DH ephemeral is kept in two-member rooms |
| `active_interval` | `1m` | Interval between periodic contact probes |
| `active_initial_delay` | `1m` | Delay from launch to the first contact probe |
| `probe_contacts_timeout` | `90s` | Global timeout for a contact probe cycle |
| `probe_retry_count` | `3` | Number of attempts per contact in a probe cycle |
| `probe_retry_delay` | `20s` | Wait between one attempt and the next for the same contact |
| `tor_probe_interval` | `5m` | Interval between periodic Tor circuit checks |
| `tor_probe_initial_delay` | `10s` | Delay from launch to the first Tor check |
| `warmup_interval` | `5m` | Interval between circuit pre-warming cycles |
| `warmup_initial_delay` | `20s` | Delay from launch to the first warmup |
| `warmup_timeout` | `1m` | Global timeout for a warmup cycle |
| `self_knock_timeout` | `1m` | Timeout for the inbound-verification self-knock |
| `knock_http_timeout` | `15s` | HTTP timeout for automatic background knocks |
| `knock_retry_delay` | `20s` | Backoff between `postKnockWithRetry` attempts |
| `invite_timeout` | `30s` | HTTP timeout for the invite lifecycle (invite, re-invite, decline, etc.) — on Android this field covers the same role for every knock sent by `knock.Send` |
| `lang` | `"en"` | Interface language (`en`/`it`/`fr`/`de`/`es`/`ro`/`ru`), read before unlocking the keystore so even the password prompt is localized. Changed with `neutrino lang [it\|en\|fr\|de\|es\|ro\|ru]` (§CLI), effective on next restart |
| `bridges_enabled` | `false` | If `true`, automatically loads `tor_bridges` at bootstrap. Changed with `neutrino use-bridges <on\|off>` (§CLI), effective on next restart |
| `bridge_default` | `"obfs4"` | Bridge type used when `bridges_enabled: true` — filters `tor_bridges`, keeping only lines whose first field matches this transport. Not chosen by the user via CLI: changed by editing `config.json` |
| `bridge_fallback` | `"webtunnel"` | Bridge type automatically used if bootstrap with `bridge_default` doesn't complete within `tornode.DefaultBridgeBootstrapTimeout` (90s) — see § "Tor Bridges" for the retry mechanism (`tornode.StartTorBridges`). Not chosen by the user via CLI: change it by editing `config.json`, like `bridge_default` |
| `file_warp_chunk_size_kib` | `64` | Chunk size (KiB), `warp` preset |
| `file_warp_max_inflight_chunks` | `8` | Sliding window (chunks without ack), `warp` preset |
| `file_slow_chunk_size_kib` | `16` | Chunk size (KiB), `slow` preset |
| `file_slow_max_inflight_chunks` | `2` | Sliding window (chunks without ack), `slow` preset |
| `file_slow_delay_ms` | `250` | Fixed delay between chunks, `slow` preset |
| `file_transfer_max_size_mib` | `512` | Maximum size of the original (uncompressed) file for `/grp-file-send` — a constraint on the sender's RAM, not the server's (real peak ~2× because plaintext+ciphertext coexist during encryption) |
| `strong_compression_enabled` | `true` | Enables the strong pack `shared.PackData` (LZMA2/XZ, with automatic raw fallback if it doesn't pay off) before symmetric encryption of file/contact-card content — see the "File transfer" section. Also read by `runQRSend` as the default for its compression prompt, overridable on every send |
| `file_transfer_offer_timeout` | `90s` | How long the sender waits for a FIRST acceptance before cancelling the whole send — the sole fallback deadline for "nobody ever responded", never the moment sending actually begins (see `file_offer_batch_window`) |
| `file_offer_batch_window` | `10s` | How long the sender waits AFTER sending the offer (not after the first acceptance: a fixed window, anchored to the offer itself) before actually starting to send toward whoever has accepted by then — collects whoever accepts nearly at once into a single pass instead of chasing each one with a full resend. If nobody has accepted by the time this window elapses, nothing happens: the sender simply keeps waiting until `file_transfer_offer_timeout`. If every recipient responds even before this window elapses, sending starts immediately (the "all responded" fast path). A recipient who accepts past this window is still covered, re-admitted into the already-running sliding window via the same reconnection resume mechanism |
| `file_transfer_reconnect_timeout` | `2m` | How long the sender waits for a recipient's ack before isolating them (excluding them from subsequent chunks, while the others continue) |
| `file_accept_retry_interval` | `30s` | RECIPIENT side: how often to resend its own `file_accept` if the first chunk hasn't arrived yet — a `file_accept` can be silently lost (`Hub.Send`, no backlog for a recipient not registered at that instant). Must stay under 1/3 of `file_transfer_reconnect_timeout`; the default guarantees at least 4 resends before the sender isolates the recipient. Not derived automatically from the other value — sender and recipient are separate processes, each with its own `config.json`, and this value is never exchanged over the wire |
| `interface_lock_timeout` | `0s` | Inactivity threshold before the interface locks itself (`/sec-lock-timeout`); `0s` disables it |
| `time_nuke_timeout` | `0s` | How long the interface may stay locked before the automatic self-destruction fires (`/sec-nuke-timeout`); `0s` disables it |

### Tor bridges

1. `neutrino get-bridges` downloads obfs4 and webtunnel bridges from bridges.torproject.org and saves them to `~/.config/neutrino/tor_bridges` (`bridgesPath`, `cmd/main.go`)
2. `neutrino use-bridges on` sets `bridges_enabled: true` in `config.json` (`runUseBridges`, `cmd/main.go`). Effective on next restart: `runMain` loads `tor_bridges` with `loadBridges`, filters it twice (once for `bridge_default`, once for `bridge_fallback`) and passes both to `transport.Start` — if the file doesn't exist yet (no `get-bridges` run), it warns and proceeds without bridges instead of blocking startup
3. `neutrino --bridges-file <path>` explicitly always **takes priority** over `bridges_enabled`: it forces a specific file for that single startup, regardless of the config value — no fallback concept for this path (a single manually supplied file)
4. `neutrino remove-all-bridges` deletes the saved file
5. `neutrino use-bridges off` disables automatic loading

When `bridges_enabled: true`, `runMain` filters `tor_bridges` with `filterBridgesByTransport` (`cmd/main.go`) both for `bridge_default` and `bridge_fallback`, keeping only lines whose first field matches. If the `bridge_default` set doesn't complete bootstrap within `tornode.DefaultBridgeBootstrapTimeout` (90s), `tornode.StartTorBridges` closes that attempt and retries with `bridge_fallback` — if that also fails (or isn't configured), an explicit error suggests `neutrino get-bridges`. The retry exists because `tornode.StartTor` returns as soon as the Tor process authenticates the control port, not when bootstrap reaches 100%: `StartTorBridges` adds the wait-with-timeout needed to tell "succeeded" from "stuck forever" before deciding whether to fall back.

**In-process pluggable transports, no separate `lyrebird` binary.** obfs4/webtunnel bridges don't spawn an external executable (unlike the classic Tor model, where `ClientTransportPlugin <name> exec <path>` has Tor itself fork a child process): `internal/tornode/ptclient.go` imports the Go packages `gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/{obfs4,webtunnel}` directly (not the `lyrebird/transports` registry package, which would drag in Snowflake/Meeklite and their heavy dependency tree — AWS SDK v2, pion/webrtc — unneeded by Neutrino) and starts each requested transport as a local SOCKS listener (`goptlib`, same scheme Orbot uses via `github.com/tladesignz/IPtProxy`). Tor connects to that listener in "unmanaged" mode (`ClientTransportPlugin <name> socks5 <addr>`, torrc(5)), encoding the bridge's destination and arguments (`cert=`, `iat-mode=`, ...) into the SOCKS request exactly as it would with `exec` — `ptClient.Start(name)` returns the local address, `ptClient.Close()` stops everything. Identical mechanism on every platform (Linux/macOS/Android/Termux): no cross-compilation, no binary to extract at runtime, no dedicated APK packaging — this also resolves the Android case, where Tor runs `exec.Command`-based (see above) but no lyrebird had ever been published in bundlable form.

---

## Handshake protocol

### Primitives

**`contactSecret`** = 32 random bytes (`shared.RandomBytes(32)`), generated by the host and distributed individually to each invitee via encrypted knock — never a password or a password derivative, never shared between different members of the same room, never sent over the network in this form.

**`room_key`** = `HKDF-SHA256(contactSecret, nil, "room_<period>")` — key derived for the current time period (period = `UnixTimestamp / 43200`, i.e. rotation every 12 hours).

**`room_proof`** = `HMAC-SHA256(room_key, nonce_client)` — proves knowledge of the secret without revealing it.

**`session_key`** = `HKDF-SHA256(ML-KEM-768(mlkem_pub_client) || X25519(priv_eff, pub_eff_peer), transcript, "neutrino-session-x25519-mlkem768-v1")`

where:
```
transcript = nonce_client || nonce_server || session_pub_client || session_pub_server
```

Including both session pubs in the HKDF salt cryptographically binds the key to the connection's specific endpoint pair: a relay that intercepted and reused the handshake toward different endpoints would produce an incompatible `session_key`. `HandshakeVersion = 5` (mandatory hybrid X25519+ML-KEM-768 key exchange since version 4; the ML-KEM secret precedes the X25519 one in the concatenation, details and FIPS/NIST rationale in `cryptography-manual.md` §4.2).

### `Sig`: per-relationship IdentityKey, not a global key

`Sig`/`SigMLDSA` do not prove possession of a global network key: they prove possession of the **per-relationship IdentityKey** — an Ed25519 keypair (+ ML-KEM-768/ML-DSA-65 companions) generated at random and independent for each contact, never shared, never used for a second purpose. Whoever distributes a room secret (the host, `RoomRegistry.AddSecret`) registers alongside it the expected peer's per-relationship IdentityKey (to verify their `Sig`) and its own toward them (to sign its own `Sig`) — no fingerprint to resolve, no cache, no network fetch: the verification key is already in the hands of whoever needs it, by construction, exchanged when the two users became mutual contacts (see § "Relationship keys" below for the exchange mechanism).

### Sequence

```
Client                                          Server
  │                                               │
  │── generates nonce_client (32B random) ───────▶│
  │── generates ephemeral X25519 keypair ──────────│
  │── generates ephemeral ML-KEM-768 keypair ──────│
  │── room_proof = HMAC(room_key, nonce_client) ──│
  │── signs (nonce_client||session_pub) with the per-relationship IdentityKey toward the host │
  │                                               │
  │──── ClientHello ──────────────────────────────▶│
  │   version, nonce_client, session_pub,         │
  │   mlkem_pub, room_proof, username, ecies_pub, │
  │   sig, sig_mldsa                              │
  │                                               │
  │                                        verifies version
  │                                        validates mlkem_pub length (1184B),
  │                                          else reject(missing_hybrid_kem)
  │                                        ML-KEM-768.Encapsulate(mlkem_pub)
  │                                        looks up room_proof among known secrets →
  │                                          peer's per-relationship IdentityKey
  │                                        verifies sig with that key
  │                                        generates nonce_server (32B)
  │                                        generates ephemeral X25519 keypair
  │                                        signs (nc||ns||session_pub) with its
  │                                          OWN per-relationship IdentityKey
  │                                          toward this peer
  │                                               │
  │◀──── ServerHello ─────────────────────────────│
  │   nonce_server, session_pub, mlkem_ciphertext,│
  │   sig, sig_mldsa                              │
  │                                               │
  │── verifies sig with the host's per-relationship IdentityKey ──│
  │── validates mlkem_ciphertext length (1088B) ──│
  │── ML-KEM-768.Decapsulate(mlkem_ciphertext) ───│
  │── X25519 DH + HKDF(transcript) → session_key ──│
  │                                        X25519 DH + HKDF(transcript) → session_key
```

Verification of the `room_proof` accepts the current period and period+1, to cover the rotation window across 00:00 and 12:00 UTC.

`mlkem_pub`/`mlkem_ciphertext` are mandatory since `HandshakeVersion` 4 (current: 5): a ClientHello/ServerHello missing them (or with the wrong length) is explicitly rejected (`missing_hybrid_kem`) — no silent interoperability with a non-updated peer. `HandshakeResult.PeerMLKEMPub` (server side, the `mlkem_pub` declared by the client) is reused to relay to room members (`mlkem_pub` field in `init`/`user_joined`, see § "WebSocket Frames" below); `HandshakeResult.ClientMLKEMDecap` (client side only) is the decapsulation key `Client` retains for the whole connection, reused to decapsulate incoming hybrid `sender_key` payloads (`cryptography-manual.md` §7.3).

---

## Message encryption

### Broadcast — per-message HMAC ratchet

Each client generates a random 32-byte `senderKey` at startup and derives its initial `chainKey` from it:

```
chainKey₀ = HKDF-SHA256(senderKey, nil, "neutrino-chain-v1")
```

For each message sent, the client advances the ratchet by one step:

```
msgKey_n     = HMAC-SHA256(chainKey_n, 0x01)   ← used to encrypt message n
chainKey_n+1 = HMAC-SHA256(chainKey_n, 0x02)   ← replaces chainKey in memory
```

`msgKey_n` is zeroed immediately after encryption. The ratchet is **one-way**: knowing `chainKey_n+1` does not allow recomputing `msgKey_n` or any previous key.

The wire frame includes `idx` (integer message index, in the clear):

```
wireformat = { "text": Base64(nonce[12]||AES-256-GCM(msgKey_n, plaintext, aad=idx_be64)||tag[16]), "idx": n }
```

`idx` is encoded as 8 big-endian bytes (`seqBytes(idx)`) and passed as **AEAD associated data** (AAD) to AES-256-GCM. The authentication tag covers both the plaintext and the index: any attempt to replay or reorder frames produces an invalid tag and decryption fails at the cryptographic level, with no need for application-level checks.

The recipient also uses `idx` to advance its own copy of the ratchet, but **never more than one step at a time**:
- if `idx == expected`: advances one step, decrypts
- if `idx > expected`: not its turn yet — the caller (TUI/Android, not `DecryptMsg` itself) holds it in a local reorder buffer (keyed on `kid`+`idx`, still-encrypted ciphertext) and resubmits it only once `idx` genuinely becomes the next expected — unlocking, in the same pass, any subsequent messages already buffered
- if `idx < expected`: duplicate — no advancement, but an ack is still sent (the original ack, not the message, may have been the one lost)

No fast-forward, no tolerance threshold on the gap: a future `idx` is never "recovered" by skipping intermediate steps: in two-member rooms every step depends on the DH mix of the immediately preceding message (below), so a skipped step can't be recomputed. What makes "wait instead of guessing" safe is the sender's reliable delivery (§ "Reliable delivery and global numbering" below): with that, a packet is never lost for good as long as the channel stays alive.

The `senderKey` is distributed to each peer via `HybridECIESEncrypt` (X25519+ML-KEM-768 — details in `cryptography-manual.md` §7.3) right after connecting (`sender_key` frame). The initial send uses `SendSenderKeyReliable` (also on Android), which reuses the same reliable delivery channel as text (`msg_id`/`msg_ack`, § "Reliable delivery and global numbering" below) instead of a fire-and-forget send: if `peerSessionPubs`/`peerMLKEMPubs` aren't populated yet for that peer at connection time (a real race at room join), the send fails silently but a periodic retry cycle (`cmdRetrySenderKeyDistribution`/`RetrySenderKeyDistribution`) retries it until it's marked as sent (`senderKeySent`, per peer — never a network ack: only "the first write succeeded", reset on every rotation). The recipient uses it **only** to initialize its own `chainKey` via `InitChainKey`; the raw `senderKey` is zeroed immediately after.

**Rotation (intra-session forward secrecy):** fires on the first of two independent criteria (OR) — a count of messages sent under the current generation (`sender_key_message_budget`, default 25) or a fixed time interval as a hygiene backstop even in a silent room (`sender_key_interval`, default 5 minutes) — plus the user's explicit request (`/grp-reconnect`). The client generates a new random `senderKey` and activates it IMMEDIATELY for outgoing traffic (new `chainKey`, `senderMsgIdx` zeroed), but distribution to each peer follows independent paths: if there are no messages still pending toward that peer, the new key goes out right away on the reliable delivery channel (below); if a backlog remains, distribution is deferred until that queue drains — otherwise the peer, upon receiving the new key, would immediately zero the previous generation (`StorePeerSenderKey` replaces, it does not accumulate) right while it still needs the queued steps to decrypt it. Peers, upon actually receiving the `sender_key` frame, reset their `chainKey` from the new senderKey.

**Security properties:**
- **Per-message**: compromising `chainKey_n` exposes only `msgKey_n` (one message), not previously-consumed past keys
- **K=25 messages OR X=5-minute rotation**: limits future exposure if the current `chainKey` is compromised, both for traffic bursts and for silent rooms
- **No post-compromise security** (for N>2 members): whoever obtains `chainKey_n` keeps computing `chainKey_n+1`, `n+2`, ... indefinitely, until an explicit rotation occurs — see the following subsection for the two-member exception

### DH ratchet for rooms with exactly two members (post-compromise security)

Only when `Client.ratchetDH == true`, a DH ratchet is incorporated into the same state as the symmetric ratchet above — the two classic Double Ratchet components, rebuilt on top of SenderKey instead of as a separate subsystem. No new frame: `dh`/`dhr` are two additional fields inside the sealed plaintext (§ Sealed Sender below), so they are encrypted with the same `msgKey` as every other field.

**When `ratchetDH` is true** — decided once, at `Client` creation, based on the number of room members at that moment, never recalculated afterward:
```go
cmdInvite:   ratchetDH = len(members) == 2       // host + a single invitee
cmdJoin:    ratchetDH = len(knock.Members) == 2
cmdRecall: ratchetDH = len(found.Members) == 2 // saved group
```
For N>2 it stays `false`, identical behavior to the previous section.

**Additional state in `Client`** (active only if `ratchetDH`):
```go
outEphPriv  *ecdh.PrivateKey              // ephemeral in use for the next send
outEphPub   *ecdh.PublicKey
outEphRing  map[string]*ecdh.PrivateKey   // EphID → retired ephemerals
outEphOrder []retiredEph                  // retirement order and time, oldest first
peerEphPub  *ecdh.PublicKey               // peer's last known ephemeral
```

**Send step** (`Send`, `client.go`): if `peerEphPub` is known,
```
dhShared      = ECDH(outEphPriv, peerEphPub)
msgKey        = HMAC-SHA256(chainKey_n, 0x01)                 // same as before
chainKey_n+1 = HMAC-SHA256(chainKey_n ‖ dhShared, 0x02)       // DeriveChainStepDH instead of DeriveChainStep
```
otherwise (bootstrap) the plain step remains. The plaintext always carries `dh = base64(outEphPub)` (starts/continues the exchange) and `dhr = EphID(peerEphPub)` only once the mix has happened. After sending, `retireOutEph()` moves `outEphPriv` into `outEphRing` and generates a new one for the next message. A retired ephemeral is dropped as soon as the peer references a newer one (`pruneOutEphBefore`), and in any case twice `message_ttl` after its retirement (`expireOutEph`). A sender_key rotation leaves `outEphRing` untouched.

**Receive step** (`DecryptMsg`): a message whose `dhr` names an ephemeral no longer in `outEphRing` is refused — nothing committed, no line shown, no `msg_ack` — because the sender mixed it into its next chain key. Past `message_ttl` the sender re-encrypts it under a new generation (§ "Reliable delivery and global numbering").

**Receive step** (`DecryptMsg`): after decrypting with `msgKey` (unchanged, does not depend on DH) and reading `dh`/`dhr` from the plaintext, if `dhr` matches an entry still in `outEphRing`:
```
dhShared     = ECDH(outEphRing[dhr], parse(dh))    // = ECDH(outEphPriv, peerEphPub) of the sender, by ECDH identity
chainKey_n+1 = HMAC-SHA256(chainKey_n ‖ dhShared, 0x02)
```
otherwise (entry outside the retention window, e.g. reordering beyond 5 rotations) the plain step remains for that message. In both cases `peerEphPub` is updated to `parse(dh)`, for the next send in the opposite direction.

**Guarantee**: an attacker who steals `chainKey_n` can compute `msgKey_n+1` (one more message, forward-derivable) but not `chainKey_n+1` — that requires the private key of an ephemeral generated *after* the theft. With ordered delivery, healing occurs from message n+2. With reordering beyond the retention window, that specific step remains on plain forward secrecy and healing slips to the first subsequent step with a successful mix. Like every ratchet, the guarantee assumes an instantaneous theft of state, not persistent access to the device. Full details and formulas: `cryptography-manual.md` §5.1.

**Reset**: `RotateSenderKey`/`StorePeerSenderKey` also zero `outEphRing`/`outEphPriv`/`outEphPub`/`peerEphPub` along with the chain key.

### Contact card — a file

`/grp-contact-send` is a special case of file sending — the same pipeline as `/grp-file-send` (§ "File transfer" below), the same socket-level routing (`ToUserIDs`, § File transfer), the same per-recipient encryption/signing with the per-relationship ContentKey. No constraint on member count: a card can be shared with multiple members of a group in one go.

### Sealed Sender

The sender's identity never appears in the frame relayed by the server. Instead, it travels **inside the encrypted text**:

```json
// plaintext before encryption (invisible to the server):
{ "f": "alice", "t": "hello everyone", "rt": 26 }

// client → server frame:
{ "text": "<base64 ciphertext>", "idx": 42, "kid": "a1b2c3d4", "mseq": 17, "msg_id": "...", "content_sigs": [...], "content_sig_ts": "..." }

// server → client frame (relay, received by every member INCLUDING the sender itself — self-echo):
{ "type": "message", "data": { "kid": "a1b2c3d4", "text": "<base64>", "idx": 42, "mseq": 17, "gseq": 28, "timestamp": "...", "from_user_id": "...", "msg_id": "...", "content_sigs": [...], "content_sig_ts": "..." } }
```

The `kid` field (key identifier) is a 4-byte HMAC hash derived from the current `senderKey`:
```
kid = hex(HMAC-SHA256(senderKey, "neutrino-key-id-v1")[:4])
```

`mseq` is the SENDER's own counter (`Client.outMsgSeq`), never reset by a rotation — unlike `idx`, internal to the ratchet and always zeroed at every new generation. `gseq` is the ROOM's counter, assigned by the server on arrival (§ "Reliable delivery and global numbering" below): it is the number shown to the user and the basis for the explicit reply reference `rt` (§ "Explicit reply reference" below).

The server sees `kid`/`idx`/`mseq` but does not know whom they belong to. The receiver uses `kid` as an index into its own ratchet maps (`peerChainKeys[kid]`, `peerMsgIdx[kid]`). When a new `senderKey` arrives from a peer, the new `kid` is computed, the old entry is zeroed and removed, and `peerKeyIDs[userID]` is set to the new key ID, updating the mapping for cleanup at the next rotation.

`content_sigs` covers the ciphertext and does not reveal the sender: each entry (`shared.ContentSigEntry{For, Sig, SigMLDSA}`) is computed with the per-relationship ContentKey toward ONE specific recipient (`For` is their username, in the clear — needed to know which entry to try, but it does not identify the sender), never with a global key or fingerprint (§ "Message signing").

### senderKey distribution

`sender_key` frame:
```json
{ "type": "sender_key", "to_user_id": "...", "payload": "<ECIES(newSenderKey)>" }
```

The server routes the frame only to the specified `to_user_id`. This control frame still carries `from_user_id` (added by the server) because it is needed for routing; it is not a message frame and exposes no content. This frame is never fire-and-forget: it travels on the reliable delivery queue (below), numbered like any other message (`msg_id`), retransmitted verbatim if unconfirmed.

### Reliable delivery and global numbering

**Client side — `internal/client/pending.go`.** Every broadcast message written to the wire stays "pending" until the server takes charge of it — signalled by the sender's own self-echo, which carries the assigned `gseq` (below) — tracked in `pendingState.out[msgID]` with the EXACT frame already written (`frame map[string]any`): within `message_ttl` a retransmission rewrites it verbatim, never a new ratchet step. Four configurable parameters (`config.json`):
- `pending_slot_limit` (default 5) — how many messages can stay without the server's take-charge before `Send`/`SendReply` return `BackpressureError` and the UI blocks writing;
- `message_retry_delay` (default 20s, doubles on each attempt) — backoff between one retransmission and the next (`RetryDue`, called periodically by a `tea.Tick` on the TUI, an equivalent ticker on Android);
- `pending_escalation_age` (default 90s) — age of the oldest unconfirmed message beyond which the UI shows a soft warning in Console (`OldestPendingAge`);
- `message_ttl` (default 3m) — see below.

**Message TTL — `reencryptExpired`, run at the start of every `RetryDue`.** When a chat message has stayed unconfirmed by a connected recipient (`waiting` not empty) longer than `message_ttl`, the recipient may have refused it (DH ratchet, above) and would keep refusing the same ciphertext. The sender:
- rotates its senderKey (`rotateSenderKeyLocked` with no deferral), sending the new key to every peer at once and dropping any older key still pending or deferred toward it (`dropSupersededKeys`);
- re-encrypts EVERY unconfirmed chat message under the new generation, in `mseq` order, with the same `msg_id` and `mseq` (each pending entry keeps its plaintext, reply reference and content-signing keys in `pendingSource`). The re-encrypted messages count toward the new generation's `sender_key_message_budget`.

The receiver shows a `msg_id` only once (`roomTab.seenMsgIDs`/`RoomState.seenMsgIDs`): a copy of a message already shown is acknowledged again and dropped. A message that fails to decrypt is neither shown nor acknowledged. System announcements (`/grp-add-member`, `/sec-pqc-sign`) are acknowledged like chat messages.

A message leaves the pending queue in two independent stages: `HandleServerAck` (recognition of one's own self-echo, `TakeSentText`; only unblocks backpressure) and `HandleAck` (arrival of a real `msg_ack` from a recipient, also updates `chatLine.ackedBy`/`Line.AckedBy` for the checkmark+count in the UI). The same queue also carries the deferred distribution of a new `senderKey` (`deferredKeys`, § "Broadcast — per-message HMAC ratchet" above).

**Server side — `internal/server/delivery.go`, `roomDelivery`.** A ROOM-wide global sequence number (`gseq`, a single increasing counter, independent of who is writing) is assigned once per message, on arrival (`Dispatch`). For each known member of the room — keyed by root identity key, connected or not — `roomDelivery` maintains an independent FIFO queue (`contactQueue`) — server↔contact "pairwise flattening," the same principle already used client-side for direct relationships: no synchronization between different queues, a slow or temporarily isolated contact accumulates messages in its own queue without blocking or delaying anyone else. Same retry schema as the client side (20s doubling), on a separate server ticker every 5 seconds (`RoomRegistry.RetryDelivery`, `server.go`). A contact whose queue reaches `outboundQueueSize` (256 unconfirmed messages) is evicted (`Hub.KickOverloaded`, a dedicated WS close code `4001`, never `StatusPolicyViolation` — that stays reserved for `/grp-ban`, so other members never see a false "banned" reason for a benign, reconnect-friendly kick) and its queue cleared (`Forget`). The queue belongs to the identity, not to a session: a reconnection of the same identity (`roomState.ClaimIdentitySlot` → `SetLive`) points it at the new connection, and the backlog is delivered there instead of being lost.

**Self-echo, tracked in the sender's own queue like any other member.** The sender is a member of the room like any other inside `roomDelivery`'s per-member queues (keyed by stable identityPub, not the ephemeral session userID) — it receives its own broadcast back as a self-echo and confirms it to the server itself with a dedicated frame, `self_relay_ack` (recognized via `Client.TakeSentText`, populated before the write to the wire), rather than being excluded from the queue. This is deliberate, not incidental: without it, a disconnection in the exact instant between `gseq` assignment and delivery of the self-echo would lose that slot forever, never retransmitted, since nothing outside `roomDelivery` would ever retry it. A retransmission of the same `msg_id` (self-echo/`self_relay_ack` not received in time by the sender, who retries from `pending.go`) reuses the already-assigned `gseq` instead of consuming a new one for a message already dispatched (`roomDelivery.dispatched`, a 5-minute dedup window counted from the latest dispatch of that `msg_id`, `internal/server/delivery.go`). The latest frame for a `msg_id` also replaces the copy still queued for any member that hasn't acknowledged it: a message re-encrypted past `message_ttl` keeps its `gseq` and its place in the queue.

### Explicit reply reference (`/msg N`)

A message can carry an optional reference to a previous message — the `rt` field inside `sealedMsg` (§ above), therefore encrypted like any other field, never visible to the server. Always chosen by the user, never inferred from arrival timing: `/msg N` (TUI) sets the reference for the **next** send (one-shot — consumed and cleared after a successful send, never reapplied to the next one), rejected if `N` does not match any line currently shown in that tab (`chatLine.gseq`). On Android the same function is a tappable ↩ icon on each received/sent message, setting the same `pendingReplyTo` shown in a persistent indicator above the text field, with a dedicated button to cancel it before sending.

The value used as a reference is `gseq` (never `mseq` nor the sender's identity): by itself it is already unique within the room, and whoever shows the reply finds it in their own already-seen history, guaranteed by the strict-order reorder buffer (§ above) — the reference can only point to a message already shown, never a future or never-arrived one. In the UI, a message with a non-zero `rt` shows an extra line above the text (`↩ #N <preview>` if the referenced message is still in the visible history, otherwise just `↩ #N`).

---

## Safety Numbers

### Code derivation

```
seed     = SHA-256(sort(myPub, theirPub))           // sorted keys → 32-byte hash
expanded = HKDF-SHA256(seed, salt=nil, info="neutrino-safety-b62-v1")[0:40]
chars[i] = alphabet[expanded[i] % 62]               // alphabet = "0-9A-Za-z" (62 symbols)
code     = chars[0:8] + " " + chars[8:16] + " " + chars[16:24] + " " + chars[24:32] + " " + chars[32:40]
```

The code is **symmetric**: both parties compute it independently and get the same result (the keys are sorted before hashing). The format is 40 characters split into 5 groups of 8, shown by `/sec-safety`, `/sec-verify`, `/cnt-info` (for a single contact), and `/grp-info` (for all members of a room at once).

**Collision probability** (two different keys producing the same code by chance): with 62 symbols and 40 characters, negligible.

### Manual verification only, out-of-band

No verification mechanism runs inside the app itself: a confirmation computed and exchanged entirely inside the connection it would verify proves nothing useful, because an attacker who controls the entire connection (e.g. a spoofed initial QR, see "The security hole" below) would answer exactly as the real contact would — it would only prove that the two apps in that session computed the same code, not that the real person you believe is behind the pseudonym is actually there. This is why the only verification offered is explicit and out-of-band:

- `/sec-safety [contact]` and `/sec-verify [contact]` — show the code for manual comparison (see "Commands" below for `/sec-verify`).
- `/cnt-info [contact]` — also includes the safety code in the contact summary.
- `/grp-info` (`cmdRoomInfo`, `internal/client/tui/tui.go`), inside a room — shows the status of all room members at once (connection dot, name colored by whether the per-relationship ContentKey is established, trust tag, safety code). The code is computed for **anyone in the room**, even if not yet saved as a contact — their `IdentityPub` is known from the invite/knock (`tab.groupMembers`), it does not need to already be in the address book.
- **Mandatory out-of-band contact info in `/grp-contact-send`** (`contactCard.OffbandHint`, non-omitempty field) — when introducing a contact to someone, the sender must write a way to reach them out-of-band (phone, email, Telegram...), making a genuinely independent comparison possible even with contacts introduced by third parties. The field travels inside the same blob already encrypted+signed with the per-relationship ContentKey as `/grp-file-send`, shown once upon receipt, **never persisted** either in `ContactInfo` or in `keystore.Contact`.

### Explicit contact verification

#### The security hole

Neither the per-relationship ContentKey signature nor the safety code (even if compared) protects against forgery of the **first identity exchange** (QR code). Concrete scenario:

1. Alice generates her own QR (`nu://alice/<Ed25519 pub>/<ML-KEM pub>/<ML-DSA pub>`) and distributes it (image, message, website).
2. An attacker intercepts the distribution and creates a forged copy with their own key triple — not Alice's.
3. Bob imports the forged QR with `/cnt-add`, believing it is Alice's.
4. From that moment on, **everything verifies correctly** from Bob's point of view:
   - The Ed25519 handshake matches the saved key (the attacker's) → no mismatch.
   - On the first exchange (`rel_init`/`rel_init_ack`), Bob and the attacker each generate a per-relationship IdentityKey and ContentKey toward each other — both verify correctly, because there is nothing to compare against an external identity: they are new keys, minted specifically for that relationship.
   - If Bob compared the safety code with the attacker (thinking he's talking to Alice), the code would match perfectly — it is correctly computed on the key the attacker actually put in the forged QR. The code only proves "I'm talking to whoever holds this key," not "this key really belongs to Alice."

**Conclusion**: both the relationship keys and the safety code are anchored to "whatever key was in the scanned QR." If that first exchange is compromised, every subsequent verification inherits it, because the attacker is a cryptographically legitimate participant at every step — they simply aren't the expected person. This is the known, structural limit of every TOFU system (Signal, WhatsApp, and every direct-exchange web-of-trust have the same problem): not solvable with an additional protocol internal to the app, only with a human comparison over a channel **independent** of the QR itself (phone call, video call, in person) — which is why the safety code comparison must happen over a channel different from the one the initial QR arrived on, never trusting a second comparison done with the same person over the same compromised channel.

#### The solution: explicit per-contact state

New field on `Contact` (`internal/keystore/keystore.go`):
```go
Verified bool `json:"verified,omitempty"` // full safety number comparison done out-of-band and confirmed by the user
```

Every contact, **however it was added** (`/cnt-add`, contact card via `/grp-contact-send`+`/cnt-save`, `neutrino sync import`), starts with `Verified = false`. It becomes `true` **only** after an explicit user attestation — never automatically. The new state is purely informational, it does not block any functionality (a deliberate choice: identity verification remains the user's responsibility, the app only makes it visible).

**Automatic reset to `Verified = false`** — the verification that was done applied to the old key, so it must be redone if the key changes:
| Point | File | Trigger |
|---|---|---|
| Applying a contact's root IdentityKey rotation | `cmd/main.go`, closure `UpdateContactRootIdentity` | `applyRootRotate` after verifying the `root_rotate` signature against the contact's `PeerRelIdentityPub` |

| Confirming a contact's pending relationship keys | `internal/keystore/keystore.go`, `ConfirmPendingRelKeys` | `/sec-verify` confirmation on a contact in `TrustDanger` |

A simple `LocalName` change (via `/cnt-edit` or merge) **does not** reset verification — it does not concern identity. `MergeContacts` (`internal/keystore/backup.go`, used by `sync import`) merges by `IdentityPub` and only updates a known contact's `LocalName`/`MLKEMPub` — no reset of `Verified` during the merge: a synced address book never touches the verification state already established on this device.

#### Commands

**`/sec-verify [contact]`** (`CmdVerifySafety`, en: `/sec-verify`) — guided flow:
1. Computes the **full** code (40 characters) with `shared.SafetyCode`, same algorithm as the previous section.
2. Writes it as a system line in the tab (not a popup dismissible with any key — right after, only `s`/`n` need to be intercepted) with an explicit instruction to compare it in full with the contact over an **external** channel (phone call, video, in person) — never inside the app.
3. Enters `verifySafetyConfirmMode`, a dedicated modal in `Update()` (same pattern as `quitMode`: Ctrl+C/Esc cancel, a single key compared against `i18n.T("common.yes")`/`i18n.T("common.no")`) that replaces the textarea with the prompt "Do you consider contact X secure? [y/n]".
4. On "yes": `MarkContactVerifiedByPub(pub)` on the contact resolved by identity key + save, and updates `m.contacts` in memory without needing to restart the app.

**Extension for `TrustDanger` (relationship-key conflict).** If the resolved contact has non-empty `PendingPeerRelIdentityPub`/`PendingPeerRelContentPub` (`TrustLevel() == TrustDanger`), `/sec-verify` doesn't compute the usual safety number: it shows two independent codes instead — one for the relationship identity key, one for the content key — both computed with `shared.SafetyCode` on the **new proposed keys** (`Pending*`), never on the `Peer*` ones already in the address book. On "yes", `ks.ConfirmPendingRelKeys(pub)` promotes `Pending*` → `Peer*`, clears the `Pending*` fields, and forces `Verified = false` (the previous trust applied to the old keys) while leaving `IntroducedBy` untouched — the contact leaves `TrustDanger` and falls back to the ordinary level consistent with its residual state (`TrustIntroduced` if it had an `IntroducedBy`, otherwise `TrustUnknown`). A contact in `TrustDanger` is always offered first by the picker when both they and other unverified contacts are present (`/sec-verify` with no argument) — a key conflict always takes priority over an ordinary verification never done.

Without an argument it always opens the address-book popup, listing every contact, verified or not.

**`/sec-unverify [contact]`** (`CmdUnverifySafety`) — removes the mark: `MarkContactUnverifiedByPub(pub)` sets `Verified = false` on the contact resolved by identity key and saves the keystore. Useful when a verification was confirmed by mistake, or when the contact's device may have been compromised. Without an argument, or with one that doesn't resolve to exactly one contact, it opens the address-book popup restricted to verified contacts (`pickerItems()`, filter `if m.contactPickerCmd == CmdUnverifySafety && !c.Verified { continue }`). On a contact not verified it only reports so. Android: **Remove verification** button on the contact detail page (`security.MarkUnverified`).

**`/sec-safety [contact]`** — without an argument, if the current room already has a code computed for its peer (`tab.safetyCode`, populated by `/cnt-save` when the just-saved contact is a room member) it shows it directly; otherwise it opens the address-book popup (all contacts, no filter).

#### Visible label

Always present, regardless of the safety code — in the address book (`renderContactList`), in `/cnt-info` (for a single contact), and in `/grp-info` (for all room members, `cmdRoomInfo`). `ContactInfo.TrustTag()` derives the label from `TrustLevel()` (`Verified bool` + `IntroducedBy string`):

| `TrustLevel` | Condition | Italian label | English label | Style |
|---|---|---|---|---|
| `TrustDanger` (-1) | `len(PendingPeerRelIdentityPub) > 0 \|\| len(PendingPeerRelContentPub) > 0` | `[CONFLITTO DI CHIAVI]` | `[KEY CONFLICT]` | red (`styleErr`) |
| `TrustUnknown` (0) | `!Verified && IntroducedBy == ""` | `[NON VERIFICATO]` | `[UNVERIFIED]` | red (`styleErr`) |
| `TrustIntroduced` (1) | `!Verified && IntroducedBy != ""` | `[INTRODOTTO DA %s — NON VERIFICATO]` | `[INTRODUCED BY %s — UNVERIFIED]` | red (`styleErr`) |
| `TrustVerified` (2) | `Verified && IntroducedBy == ""` | `[VERIFICATO]` | `[VERIFIED]` | green (`styleOwnMsg`) |
| `TrustVerifiedIntroduced` (3) | `Verified && IntroducedBy != ""` | `[VERIFICATO — INTRODOTTO DA %s]` | `[VERIFIED — INTRODUCED BY %s]` | green (`styleOwnMsg`) |

Color follows only `Verified` (red/green), not the full level — `IntroducedBy` is informational, it does not change the style.

The "UNVERIFIED" label is distinct from "unknown": here the contact **is** saved in the address book, you simply have never confirmed their identity over an independent channel (safety code). "Unknown" (`tui.tag_unknown_suffix`, § Signature tag in messages below, and in `/grp-info` for unsaved room members) instead indicates that person is not in the address book at all — neither label implies the *channel* is insecure (encryption is always the same, always active): the doubt concerns only identity.

#### Grouping in the Contacts tab

`renderContactList()` doesn't iterate `m.contacts` linearly: `groupContactsByTrust()` partitions it into a `map[TrustLevel][]ContactInfo`, then `renderContactList` shows the `TrustDanger` group first if non-empty (always at the top, ahead of every other group), then walks the four ordinary levels in descending order (`TrustVerifiedIntroduced` → `TrustUnknown`), printing a header (`tui.contacts_group_*`) only for non-empty groups — no blank line if a group has no contacts.

Within each group, `groupContactsByTrust` sorts with `sort.SliceStable` on three cascading keys:
1. An already-established ContentKey relationship (`len(RelContentPriv) == ed25519.PrivateKeySize && len(PeerRelContentPub) == ed25519.PublicKeySize`) before those without one
2. Ascending `reachabilityRank()` — score `dot1*3+dot2` (each 0=●/best, 1=◌/unknown, 2=✗/worst), covers all 9 possible combinations, since dot2 is independent of dot1: 0=`●●`, 1=`●◌`, 2=`●✗`, 3=`◌●`, 4=`◌◌`, 5=`◌✗`, 6=`✗●`, 7=`✗◌`, 8=`✗✗`
3. Alphabetical username, as the final stable tie-break

`renderContactLine()` does not append `c.TrustTag()` at the end of the line (after the `[REL:...]` badge) — redundant, since the group a contact belongs to already conveys the trust level once, in the header. `TrustTag()` is still used elsewhere (`cmdInfo`/`cmdRoomInfo`, `internal/client/tui/tui.go` — `/cnt-info` and `/grp-info` respectively).

The headers (`tui.contacts_group_*`) are colored by level — the same styles already used for the app's other trust indicators, not new styles: `styleErr` (red, color 9) for `TrustDanger` and `TrustUnknown`, `styleWarnName` (yellow, color 11) for `TrustIntroduced`, `styleOwnMsg` (green, color 10) for `TrustVerified` and `TrustVerifiedIntroduced` — the latter two share green because they differ only in whether there's an introduction, not in verification level.

---

## WebSocket Frames

### Client → Server

| `type` | Additional fields | Purpose |
|---|---|---|
| *(absent)* | `text`, `idx`, `kid`, `mseq`, `sig`, `sig_ts`, `content_sigs[]`, `content_sig_ts`, `device_sig`, `device_ts`, `pqc_sig`, `pqc_ts`, `msg_id` | Broadcast message — sender sealed inside the ciphertext; `mseq` is the sender's own counter, never reset by a rotation; `content_sigs` carries a per-relationship ContentKey signature for each other member with whom an established relationship exists (§ "Message signing"); `device_sig`/`pqc_sig` are optional (remote_nuke device signature, `/sec-pqc-sign` ML-DSA-65 signature), relayed intact with no server-side verification; `msg_id` is a random ID generated by the sender to correlate ACKs and the self-echo that signals the server's take-charge (§ "Reliable delivery") |
| `sender_key` | `to_user_id`, `payload` | senderKey for a peer, `payload` encrypted with `HybridECIESEncrypt` (X25519+ML-KEM-768, § "Handshake Protocol") |
| `rel_bootstrap` | `to_user_id`, `payload` | Ephemeral relationship-key exchange toward an "introduced" member (§ "Relationship keys", Introduced members) |
| `rel_bootstrap_ack` | `to_user_id` | Confirmation that a received `rel_bootstrap` was applied, toward the original sender — no payload, the frame itself is the proof; the recipient stops retrying the `rel_bootstrap` send (§ "Introduced members") |
| `rel_promote` | `to_user_id`, `payload` | Promotion of an ephemeral relationship to a real contact (§ "Relationship keys", Introduced members) — `payload` also carries `Ts`/`Sig`/`SigMLDSA`, signed with the EPHEMERAL per-relationship IdentityKey (§ "Introduced members"; crypto details in `cryptography-manual.md` §8.1) |
| `rel_promote_ack` | `to_user_id` | Confirmation that a received `rel_promote` was applied, toward the original sender — no payload; unlike `rel_bootstrap_ack` this does not trigger an automatic retry (explicit human action on both sides, § "Introduced members") |
| `ping_probe` | `to_user_id`, `seq`, `sent_at` | RTT probe — unique `seq`, `sent_at` Unix nanoseconds (sender's clock) |
| `pong_probe` | `to_user_id`, `seq`, `sent_at` | Probe response — `sent_at` echoed verbatim; RTT = `now - sent_at` |
| `msg_ack` | `to_user_id`, `msg_id` | Acknowledgment of a broadcast message, routed to the original sender |
| `self_relay_ack` | `msg_id` | The sender confirms its own self-echo to the server, which removes the entry from the sender's own delivery queue — never forwarded (§ "Reliable delivery") |
| `file_announce` | `to_user_ids[]`, `transfer_id`, `hash`, `announce_envelopes{}`, `sig_ts` | Lightweight announcement BEFORE any real file_offer (§File transfer) — `hash` is the SHA-256 of the shared ciphertext, `announce_envelopes` carries one `shared.FileAnnounceEnvelope` (signature over `hash` only) per recipient; no file name/size/key |
| `file_announce_ack` | `to_user_id`, `transfer_id` | Confirms the announcement's signature verified — only after this ack does the sender send the real `file_offer` to THAT recipient |
| `file_offer` | `to_user_ids[]`, `transfer_id`, `envelopes{}` | The real offer (or contact card, via `/grp-contact-send`) — `envelopes` carries one `shared.FileOfferEnvelope` (`meta_blob` only, no signature: authenticity was already established by `file_announce`) per recipient; the server routes one envelope each with a single `Send` per recipient, not a multicast |
| `file_accept` / `file_reject` | `to_user_id`, `transfer_id` | Recipient's response to the offer, toward the original sender |
| `file_chunk` | `to_user_ids[]`, `transfer_id`, `seq`, `payload` | Byte-range slice of the ciphertext (encrypted once with a symmetric `fileKey`) — targeted multicast toward those who accepted |
| `file_chunk_ack` | `to_user_id`, `transfer_id`, `seq` | Acknowledgment of a received chunk, toward the sender — drives the sliding window |
| `file_resume` | `to_user_id`, `transfer_id`, `from_byte` | Resume announcement toward the original sender: how many bytes the recipient already has (after its own reconnect or the sender's) |
| `file_verify_result` | `to_user_id`, `transfer_id`, `verify_ok` | Final outcome (integrity+decryption) toward the original sender, after the last chunk — independent of delivery acks, which only confirm transport |

### Server → Client

| `type` | Fields | When |
|---|---|---|
| `init` | `users[]` (each `user_id, username, session_pub?, mlkem_pub?, identity_pub?`) | Right after the handshake: list of connected users |
| `message` | `data.{kid, text, idx, mseq, gseq, timestamp, from_user_id, msg_id?, sig?, sig_ts?, content_sigs?, content_sig_ts?, device_sig?, device_ts?, pqc_sig?, pqc_ts?}` | Every broadcast message (no username — the sender's identity stays sealed inside the ciphertext, §5). `from_user_id` is the session ID, used only by the client to recognize its own self-echo (`msg_id`, never for identity) — never linked to the real identity. `gseq` is assigned by the server on arrival (§ "Reliable delivery and global numbering"), delivered to the sender too (self-echo, always included in the fan-out) |
| `user_joined` | `user_id, username, session_pub?, mlkem_pub?, identity_pub?` | When a new user joins |
| `user_left` | `user_id`, `reason` | When a user disconnects; `reason`: `"left"` = clean `/grp-exit`, `"lost"` = crash/timeout, `"banned"` = `/grp-ban`, `"overloaded"` = kick for an overloaded delivery queue (§ "Reliable delivery", a dedicated WS close code `4001`, never the same as `/grp-ban` — so other members never read a false "banned" reason for a benign, reconnect-friendly kick) |
| `sender_key` | `from_user_id, payload` | Forwarding of a senderKey from a peer |
| `rel_bootstrap` | `from_user_id, payload` | Forwarding an ephemeral relationship-key exchange |
| `rel_bootstrap_ack` | `from_user_id` | Forwarding the application confirmation to the original `rel_bootstrap` sender |
| `rel_promote` | `from_user_id, payload` | Forwarding a promotion to a real contact |
| `rel_promote_ack` | `from_user_id` | Forwarding the application confirmation to the original `rel_promote` sender |
| `ping_probe` | `from_user_id, seq, sent_at` | Forwarding an RTT probe to the recipient |
| `pong_probe` | `from_user_id, seq, sent_at` | Forwarding an RTT response to the original sender |
| `msg_ack` | `from_user_id, msg_id` | Forwarding delivery ACK to the message's original sender |
| `file_announce` | `from_user_id, transfer_id, hash, sig, sig_mldsa?, sig_ts` | Forwarding the lightweight announcement (§File transfer) — verified right away against the sender's per-relationship ContentKey, never against heavy data |
| `file_announce_ack` | `from_user_id, transfer_id` | Forwarding the confirmation to the original sender — only now does it send the real `file_offer` |
| `file_offer` | `from_user_id, transfer_id, meta_blob` | Forwarding ONE envelope (§File transfer) — `meta_blob` must be decrypted client-side (`shared.DecryptFromPeer`, async) before name/size/`fileKey` are known; no signature left to re-verify, already established by `file_announce` |
| `file_accept` / `file_reject` | `from_user_id, transfer_id` | Forwarding the response to the original sender |
| `file_chunk` | `from_user_id, transfer_id, seq, payload` | Forwarding a chunk (multicast) |
| `file_chunk_ack` | `from_user_id, transfer_id, seq` | Forwarding a chunk ack to the original sender |
| `file_resume` | `from_user_id, transfer_id, from_byte` | Forwarding a resume announcement to the original sender |
| `file_verify_result` | `from_user_id, transfer_id, verify_ok` | Forwarding the final outcome to the original sender |
| `server_shutdown` | — | The server is about to shut down |

**`identity_pub` in `init`/`user_joined`.** The member's root IdentityPub (`UserSession.RootIdentityPub`, `MatchedRootIdentityPub` from the handshake) is relayed to every other member: it is the only identifier of a member on the client side. The member key is `client.MemberKeyOf(identityPub)` (standard base64 of the root key); the sender of any relayed frame is resolved from `from_user_id` with `Client.LookupMemberKey`, and matched to an address book contact with `GetContactByPub`. `username` is only a display label: two members sharing a name — or a member sharing our own name — are shown with an 8-hex-digit fingerprint of their key (`name ·xxxxxxxx`, `memberName`). The per-relationship `MatchedIdentityPub` stays for the host's exclusive use, never relayed. A member "introduced" by a common host, with no pre-existing direct relationship, exchanges its own relationship keys point-to-point with whoever else is already in the room via `rel_bootstrap` (§ "Relationship keys", Introduced members).

**`mlkem_pub` in `init`/`user_joined`.** The ML-KEM-768 encapsulation key the member declared in its own `ClientHello.MLKEMPub` (`HandshakeResult.PeerMLKEMPub` server side) is relayed to all other already-connected members. The receiving side registers it with `Client.RegisterMLKEMPub` (`peerMLKEMPubs`, keyed by `user_id`, pruned on the same peer's reconnect like `peerSessionPubs`) and uses it to encrypt its own `senderKey` toward that peer with `HybridECIESEncrypt` — no second keypair generated specially for this, details in `cryptography-manual.md` §7.3.

---

## Server

### `appCtx` — dependency container

```go
type appCtx struct {
    registry            *RoomRegistry
    limiter             *RateLimiter
    identityPriv        ed25519.PrivateKey         // to decrypt incoming knocks
    mlkemDecap          *mlkem.DecapsulationKey768 // durable twin of identityPriv — nil = hybrid knocks not decryptable, falls back to classic knocks only
    knockCh             chan<- shared.KnockPayload // nil if the server doesn't support knocks
    knownContactPubs    func() [][]byte            // Ed25519 pubkeys of known contacts, read on every knock — mutuality filter (§ "Knock")
    pingInterval        time.Duration              // WS keepalive interval
    cleanupInterval     time.Duration              // rate limiter + stale session cleanup interval
    sessionStaleTimeout time.Duration              // threshold for RoomRegistry.CleanupStaleSessions
    silenced            func() bool                // nil = never silenced; if true, every entry point closes immediately with no protocol response
}
```

All HTTP/WebSocket handlers are methods on `appCtx`. No global state. `mlkemDecap`, like `identityPriv`, is a fixed value passed to `RunOnListener` — regenerating the transport key (§ "Relationship keys", Transport key) spawns a new listener with a new hidden service, it does not modify the one already running (see `cryptography-manual.md` §7.4). The handshake signature (`Sig`/`SigMLDSA` in `ServerHello`) does not depend on a global identity loaded into `appCtx`: the `RelSigningKey` used to sign is the one associated with the matched secret, resolved by `RoomRegistry.LookupSecret` on every connection — no getter, nothing to keep in sync.

### `RoomRegistry` — per-member authentication (`internal/server/rooms.go`)

A room's identity (`roomID`) is decoupled from the secret used to authenticate:

```go
// resolveKeys resolves LIVE, on every LookupSecret (never cached), the
// peer's per-relationship IdentityKey (verifies ClientHello.Sig) and the
// OWN one toward that same peer (signs ServerHello.Sig) — never global
// keys, never a value stored at registration time.
type memberSecret struct { secret []byte; label string; identityPub, devicePub []byte; resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool) }
type roomEntry struct { secrets []memberSecret; state *roomState }
type RoomRegistry struct {
    mu    sync.RWMutex
    rooms map[string]*roomEntry // roomID → entry
}

func (r *RoomRegistry) AddSecret(roomID string, secret []byte, label string, identityPub, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool))
func (r *RoomRegistry) ReplaceSecret(roomID string, oldSecret, newSecret []byte, label string, identityPub, devicePub []byte, resolveKeys func() (shared.RelPeerKey, shared.RelSigningKey, bool)) // /grp-reinvite: revokes the old one, adds the new one
func (r *RoomRegistry) RemoveSecret(roomID string, secret []byte) // /grp-ban: revokes without replacing
func (r *RoomRegistry) LookupSecret(nonceClient, proof []byte) (secret []byte, roomID string, label string, identityPub, devicePub []byte, peerKey shared.RelPeerKey, mySigningKey shared.RelSigningKey, ok bool)
func (r *RoomRegistry) GetOrCreateRoom(roomID string) *roomState // keyed by roomID
func (r *RoomRegistry) KickMember(roomID, userID string) bool    // /grp-ban: forced disconnect via Hub.Kick
func (r *RoomRegistry) ReleaseRoomIfEmpty(roomID string)          // releases a room's hub+sessions once it has no active connections
func (r *RoomRegistry) CleanupStaleSessions(timeout time.Duration) int
func (r *RoomRegistry) TotalSessions() int                        // used by /health
```

`LookupSecret` tries the incoming `room_proof` against **all** secrets of **all** rooms registered in the process (a linear scan over the nested list of rooms and their secrets) and returns, along with the matching secret, the `roomID` and the `label` it belongs to. `label` is the username the host assigned when generating that specific secret (§ "WebSocket Frames") — used in `ws.go` to overwrite the self-declared `Username` field in `ClientHello`, which is otherwise never cryptographically verified. `peerKey`/`mySigningKey` are the two halves of the per-relationship IdentityKey toward that specific member, resolved LIVE by the matched secret's `resolveKeys` (never a value cached at invite time — a relationship rotation is reflected immediately) — `DoServerHandshake` uses them respectively to verify `ClientHello.Sig` and to sign `ServerHello.Sig` (§ "Handshake protocol"); `HandshakeResult.MatchedIdentityPub` (just the public half of `peerKey`) then stays for the host's exclusive use, never relayed to other members already connected (§ "WebSocket Frames").

**Cleaning up empty rooms.** `RemoveSecret` is the server-side mechanism behind `/grp-ban`: it revokes a secret without replacing it (unlike `ReplaceSecret`, used for `/grp-reinvite`), and releases the room's runtime state (hub+sessions) as soon as it has no active connections left — if no valid secret remains for any member, it also removes the entire entry from the registry. Without this, a group banned down to its last member would stay in RAM for the rest of the process's life. `KickMember` forcibly disconnects a still-connected member via `Hub.Kick`, independently of removing the secret.

**Stable roomID**: `KnockPayload.GroupID` (`shared.RandomBytes(4)` hex-encoded, generated once by `cmdInvite`/`cmdJoin`, never regenerated) — **always** set, even for a single-person invite: `cmdInvite`/`cmdJoin` never distinguish by member count, every room has a `GroupID`. There is no server-side fallback that derives a room identifier from the two parties' public keys — a knock with an empty `GroupID` is not a supported case on the current wire format (no live client sender produces one; the picker code that lists pending knocks explicitly skips any with an empty `GroupID`, `internal/client/tui/tui.go`).

`/grp-recall` generates a new `roomSecret`, but with the stable `roomID` different secrets for the same `roomID` always end up in the same hub — no fragmentation between members presenting different secrets for the same room.

**`roomState.delivery` — the room's reliable delivery queue.** Every `roomState` (created by `GetOrCreateRoom`) also carries a `*roomDelivery` (`internal/server/delivery.go`, § "Reliable delivery and global numbering") — full details there; here just the hook into the room's lifecycle: `KickMember` also calls `delivery.Forget(userID)` before `Hub.Kick` (no pending queue survives a banned member), and `RoomRegistry.RetryDelivery()` (called by a dedicated server ticker every 5s, `server.go`) iterates `delivery.RetryAndEvict(hub)` over every room with active state.

### `Hub`

Manages active WebSocket connections for a room. Each registered peer (`Register`) gets a dedicated write goroutine (`outConn.writeLoop`) fed by its own FIFO queue (`outCh`, capacity 256) — `Broadcast`/`Multicast`/`Send` (and the `*Bytes` variants) never write directly: they enqueue (`enqueue`, non-blocking — a full queue means a dropped frame, the same treatment as a frame lost on the wire) and return immediately.

**Why writes aren't done inline.** Writing directly inside the sender's message loop (which reads a frame, routes it, then reads the next one) would tie how fast the sender can keep reading to how fast its slowest recipient can receive: a single peer on a congested Tor circuit would block the sender's read goroutine for the duration of that one write — not just for the frame addressed to that peer, but for **every** subsequent frame from the same sender, including a second transfer to a completely different peer or any chat message. The dedicated write goroutine decouples the two: a slow peer only fills its own queue, never another peer's queue nor the goroutine generating the frame.

**Guaranteed per-peer ordering.** Frame order toward the same peer stays guaranteed — required by the SenderKey ratchet, which needs messages from the same sender in order — because each peer has a single FIFO queue and a single writer.

A write error (dead connection or an expired `hubWriteTimeout` of 15s) removes the peer from the hub right away (`Unregister`), without waiting for its own read loop to notice on its own — this also covers the case where that read loop is stuck waiting for a frame that will never arrive from a connection that's already dead only on the write side.

`Hub.Kick(userID)` forcibly closes a peer's connection (used by `/grp-ban`, host only), with a dedicated close code that lets its read loop distinguish "removed" from a normal disconnection. `Hub.KickOverloaded(userID)` is the analogous call for a contact whose delivery queue (§ "Reliable delivery") reached `outboundQueueSize` (256) — same principle, a different close code (`statusQueueOverloaded`, never `StatusPolicyViolation`) because it is not a ban: reconnection always stays free, no secret is revoked. `roomDelivery.Dispatch` receives its recipients explicitly, as root identity keys (every known member of the room, `RoomRegistry.MemberIdentities`, connected or not) — it never reaches into the hub's internal state.

Each peer's write loop (`outConn.writeLoop`) zeroes every frame right after writing it (`zeroBytes`) — and, on a write error, drains and zeroes the frames still queued — so as not to leave ciphertext on the heap longer than necessary.

### Rate limiting

`RateLimiter`: sliding window per IP. Configured at 10 connections/minute per IP. Loopback addresses (`127.0.0.1`, `::1`) are always allowed — all Tor connections arrive from the local daemon.

Periodic cleanup (`cleanupInterval`, default 5 min) removes expired entries.

### Keepalive

A goroutine per connection sends a WebSocket ping every `pingInterval` (default 1m). A single missed pong within `pingInterval/2` (30s) is not enough on its own: a per-connection counter tolerates `pingMissThreshold` (2) consecutive misses, reset by any pong received, before canceling the connection's context and terminating the message loop. A single late pong is common on a Tor circuit under momentary stress and is not a reliable sign of a truly dead connection — a one-strike rule would cause self-inflicted reconnect storms (see the `roomErrMsg` note below). The client-side watchdog (`pingWatchdogTickMsg`, `internal/client/tui/tui.go`) follows the identical scheme and timing. Android's own client-side probe (`room.Cli.Ping`, `cmd/androidapp/screens/roomconnect.go`, every 30s, skipped if a frame arrived in the last 30s) is one-strike: a single failed or timed-out (15s) ping forces a reconnect; the server side, shared by both platforms, stays tolerant.

### Disconnection type detection

When the message loop (`wsjson.Read`) terminates with an error, the server checks the WebSocket close status:

```go
if s := websocket.CloseStatus(err); s == websocket.StatusNormalClosure || s == websocket.StatusGoingAway {
    exitReason = "left"        // clean disconnect via GracefulClose
} else if s == websocket.StatusPolicyViolation {
    exitReason = "banned"      // Hub.Kick — /grp-ban
} else if s == statusQueueOverloaded {
    exitReason = "overloaded"  // Hub.KickOverloaded — overloaded delivery queue (roomDelivery)
}
// none of the above: stays "lost" (default) — crash, ping timeout, network down
```

The reason is included in the `user_left` broadcast via the `reason` field. `"banned"` and `"overloaded"` deliberately use distinct WS close codes (`websocket.StatusPolicyViolation` vs `statusQueueOverloaded`, a dedicated code in RFC 6455's private range): a kick for overload must never look like a ban to the room's other members.

### Graceful shutdown

> **Note:** the TUI intercepts and **ignores** SIGINT, SIGTERM, and SIGHUP while running (see `RunTUI — Blocking OS signals`). The server shutdown therefore only happens when the TUI exits normally (via `/quit`/`/nukex`), which cancels the root context.

On `SIGTERM`/`SIGINT` (or context cancellation for `RunOnListener`), the server:
1. Broadcasts the `server_shutdown` frame to all rooms
2. Calls `http.Server.Shutdown` with a 5-second timeout

The client, upon receiving `server_shutdown`, sets the `tab.serverShutdown = true` flag. When the connection drops, the flag prevents the automatic reconnection attempt.

---

## Client

### `Client`

```go
type Client struct {
    host, port, username string
    contactSecret        []byte
    dialContext          func(ctx, net, addr) (net.Conn, error)  // nil = local loopback; non-nil = via Tor
    sessionPriv          *ecdh.PrivateKey
    mlkemDecap           *mlkem.DecapsulationKey768  // from HandshakeResult.ClientMLKEMDecap

    // Sender side — own ratchet
    senderKey      []byte           // distributed to peers via HybridECIESEncrypt; zeroed on every rotation
    senderKeyID    string           // 8-char hex derived from senderKey; included in the clear in frames
    senderChainKey []byte           // current state of the HMAC ratchet
    senderMsgIdx   uint64           // idx of the next message; reset to 0 on every rotation
    outMsgSeq      uint64           // mseq — sender's external counter, NEVER reset by a rotation
    lastRotationSeq uint64          // value of outMsgSeq at the last rotation — count-based criterion K

    // DH ratchet — only rooms with exactly 2 members, see "DH ratchet for two-member rooms" above
    ratchetDH   bool
    outEphPriv  *ecdh.PrivateKey
    outEphPub   *ecdh.PublicKey
    outEphRing  map[string]*ecdh.PrivateKey // EphID → retired ephemeral
    outEphOrder []retiredEph                // retirement order and time, oldest first
    peerEphPub  *ecdh.PublicKey             // peer's last known ephemeral

    // Receiver side — per-peer ratchet (all protected by peerMu), indexed by keyID.
    // No skip cache: DecryptMsg always advances by exactly one step, never a
    // fast-forward — see "Reliable delivery and global numbering" above.
    peerChainKeys   map[string][]byte           // keyID → current chain key
    peerMsgIdx      map[string]uint64            // keyID → next expected idx
    peerKeyIDs      map[string]string            // userID → current keyID (for cleanup on rotation)
    peerSessionPubs map[string]*ecdh.PublicKey   // userID → X25519 session pub
    peerMLKEMPubs   map[string]*mlkem.EncapsulationKey768 // userID → ML-KEM-768 pub
    peerMu          sync.RWMutex

    // sentTexts/sentOrder — FIFO cache (msgID → plaintext + rt) to recognize
    // our own self-echo without feeding it through the reception ratchet,
    // see "Reliable delivery and global numbering" above.
    sentTexts map[uint64]sentTextEntry
    sentOrder []uint64

    // pending — reliable delivery queue for broadcast messages sent by this
    // client (numbering, acks, retransmission, backpressure), see "Reliable
    // delivery and global numbering" above and pending.go.
    pending pendingState
    // …
}
```

`SetDialer(fn)` — configures the connection via Tor or I2P (`ws://` scheme without application-level TLS, protected by the underlying transport; generic across both transports).

`ConnectWithRetry(ctx, maxAttempts, onRetry)` — `maxAttempts` attempts (decided by the caller), exponential backoff starting at 20s (doubles each attempt), 90s timeout per attempt.

`GracefulClose()` — sends a WebSocket close frame with `StatusNormalClosure` before closing the connection. Called by `/grp-exit` before `tab.cancel()`, allows the server to distinguish a voluntary exit from a crash.

`RotateSenderKey(ctx)` — generates a new `senderKey`, computes the new `senderKeyID`, activates it IMMEDIATELY for outgoing traffic (zeroes `senderMsgIdx`, reinitializes `senderChainKey`, updates `lastRotationSeq`), then distributes it peer by peer: right away via `HybridECIESEncrypt` (on the reliable delivery channel, § "Reliable delivery and global numbering") if `PendingCountFor(peer) == 0`, otherwise deferred (`deferKeyDistribution`) until that queue drains (`FlushDeferredKeyDistributions`, same periodic cycle as `RetryDue`). The old keys are explicitly zeroed in memory. `peerMu`/`sendMu` protect the ratchet state from race conditions between `Send` and rotation. Called both by the periodic ticker (OR K/X criterion, below) and by `/grp-reconnect`.

`RegisterMLKEMPub(userID, pubBytes)` — analogous to `RegisterSessionPub`, but for the peer's ML-KEM-768 encapsulation key (`mlkem_pub` field of `init`/`user_joined`); populates `peerMLKEMPubs`, pruned by `RegisterUser` on the same peer's reconnect like `peerSessionPubs`.

### TUI

bubbletea architecture (Elm): `Init` → `Update` → `View`.

**`TUIParams`** — initial configuration for the bubbletea model. Fields relevant to the Tor node connection:

```go
DialTor       func(ctx, net, addr) (net.Conn, error)
CheckCircuits func() bool   // nil = probe disabled
MyAddr        string        // own network address (.onion or .b32.i2p) for self-probe
```

**Fixed tabs:**

| Index | Name | Flag | Purpose |
|---|---|---|---|
| 0 | `Console` | `isConsole` | Session event log; `/debug on\|off` writes here; pre-populated with `TUIParams.BootLog` (Tor bootstrap, hidden service publication); page open at startup (`active: consoleIdx`) |
| 1* | `Tor` / `I2P` | `isTor` | Own node status (`Tor: ● out ● in`, `H.S.:`) + log of the active network process (Tor or `i2pd`, depending on `--net`) — tab name comes from `TUIParams.NetworkName`, the internal flag stays `isTor` for both networks |
| 2/1 | `Contacts` | `isContacts` | Contact list with reachability status |
| 3/2 | `Groups` | `isGroups` | List of saved groups (`/grp-save`) |
| 4/3 | `File` | `isFiles` | File transfer progress bars, read-only |

\* Present only if a network process was started (`torTabIdx`, −1 otherwise — in that case the following indices shift down by one, "Index" column shows both values). Order built in `newModel` — Console, then Tor if active, then Contacts/Groups/File, always in this sequence on both platforms (see also `cmd/androidapp/screens/shell.go`). Fixed tabs cannot be closed with `/grp-exit`. `waitForRoom` returns `nil` for tabs with `cli == nil` (including `Contacts`), avoiding a nil-pointer on `ReadMsg`.

**Tor status in the Tor tab:** `model.torUp *bool` (nil / true / false) is updated by `torProbeResultMsg`. The check uses `checkCircuits()` — a synchronous call to Tor's control port via `GETINFO circuit-status`, response in < 1 ms. If `checkCircuits` is not configured, it falls back to a TCP connection to its own onion (less reliable, 60s timeout). The probe starts at warmup (20s) and repeats every 5 min; a state change is logged in the Tor tab. Contact probing starts at T+1 min and repeats every minute (`active_interval`, default `1m`, configurable in `config.json`) with backpressure: if a cycle is still in progress, the next tick is skipped (at most 1 probe in flight).

**Contacts tab:** `model.contactStates map[string]contactState` (key: network username) is updated on every `probeResultMsg`, and synchronously on every `probe_ping`/`probe_ack` received (see below). `renderContactList()` reads `m.contacts` + `m.contactStates` and regenerates the viewport; `refreshViewport()` calls `renderContactList()` for `isContacts` tabs. The Tor tab's WS/Tor header does not appear in the contacts tab (no `extra` in `calcVpH`, gated on `tab.isTor`).

```go
type contactState struct {
    online       *bool     // nil=never probed, true=online, false=offline
    seenByPeer   *bool     // nil=unknown, true=confirmed, false=asymmetry — INDEPENDENT of online
    seenByPeerAt time.Time // moment of the last transition to seenByPeer=true
    onlineStreak int       // consecutive online cycles, reset when offline
    probedAt     time.Time
}
```

`seenByPeer` is independent of `online`: it can be `true` even when `online` is `false`/`nil` (direct proof received regardless of our ability to reach them), and it never decays to `nil` on its own. It becomes `false` only when `onlineStreak >= m.probeRetryCount` without ever a confirmation — never while `online` isn't `true`.

**Console tab:** collects system events. It is a permanent tab (`isConsole`, index `consoleIdx`): it is open from startup and cannot be closed.

**Automatic reconnect:** upon receiving a `roomErrMsg`, if a reconnect is not already in progress and the server has not sent `server_shutdown`, `reconnectTab` is launched: creates a new context, calls `ConnectWithRetry(5)`. If it fails, the tab moves to a definitive error state. Applies to ANY connected tab, not just Tor/I2P — including the host's own connection to its local server in loopback (`tab.cli.IsRemote() == false`, `cmdInvite`/`cmdRecall` never call `SetDialer`).

**`roomErrMsg.gen`:** every `roomErrMsg` carries the generation (`roomTab.pingGen`) active when the attempt that produced it started — read by `waitForRoom`/the ping watchdog AT THE MOMENT the read/ping starts, not when the error comes back. `reconnectTab`/`cmdReconnect` increment `pingGen` at the START of the attempt (not just on success, as `roomConnectedMsg` already did). The `roomErrMsg` case silently discards any message whose `gen` no longer matches the tab's current `pingGen`, before any other logic — this prevents a late error from a connection already superseded by a more recent reconnect from being treated as a fresh failure (it would zero out `tab.reconnecting` mid-way through an ongoing reconnect, or trigger a superfluous one on an already-healthy connection).

**Host↔local-server connection: connect and knock-sending decoupled.** In `cmdInvite`/`cmdRecall`, `cli.Connect(ctx)` to the host's own local server and sending the encrypted knocks to invitees over Tor are two **separate** `tea.Cmd`s (`connectCmd`/`knocksCmd`), run in parallel via `tea.Batch` — the host's connection does not wait for every knock to finish before it starts reading. Reason: the WebSocket library in use (`coder/websocket`) requires `Conn.Ping` to be called **concurrently** with an ongoing `Read` to receive the pong (explicitly documented in its own `conn.go`); if `roomConnectedMsg` (and thus the start of `waitForRoom`, that connection's read loop) were delayed until every knock had been sent, the server's periodic ping toward this connection (`internal/server/ws.go`, every `pingInterval`=1m, 30s timeout, 2 missed cycles tolerated) could still go unanswered for long enough during a lengthy knock-sending run (20s/40s backoff, up to 3 attempts per target over Tor — potentially minutes), leading the server to cancel the connection's context and close it (`conn.go`: `setupReadTimeout`/`context.AfterFunc`) before the host had ever started reading. `knocksCmd` produces no message (`return nil`): individual knock-send errors stay silent.

**Circuit pre-warming:** 20 seconds after startup, `cmdWarmupCircuits` opens short TCP connections to port `:80` of each contact to force Tor to build and cache circuits before first real use. Silent, 60s timeout.

**RTT probe (`/grp-ping`):** available in any chat tab (`isChatTab`, not just two-member rooms). Without an argument it always opens a picker to choose whom to ping (`pingPickerMode`). Sends 5 `ping_probe` frames 1 second apart with unique `seq` values (base = `UnixNano() &^ 0xFFFF`) and `sent_at = time.Now().UnixNano()`. The peer responds immediately with `pong_probe`. RTT computed as `now - sent_at` (sender's clock; `sent_at` echoed verbatim). On completion of the 5 pongs: min/avg/max.

**`/grp-exit`:** first calls `tab.cli.GracefulClose()` (sends WebSocket close frame → server receives `StatusNormalClosure` → `reason: "left"`), then `tab.cancel()` and removes the tab from the slice. Adjusts `consoleIdx`, `pingTabIdx`. Rejected for the fixed tabs (`isContacts`, `isGroups`, `isTor`, `isConsole`, `isFiles`).

**senderKey rotation:** ticker at `senderKeyInterval` (default 5 min, hygiene backstop). `cmdRotateSenderKeys` calls `RotateSenderKey` on every connected tab (skips: console tab, contacts tab, disconnected, reconnecting, server shut down) if the ticker fired OR if `Client.MessagesSinceRotation() >= SenderKeyMessageBudget()` (default 25, count-based criterion, checked after every successful send) — whichever comes first.

**Reorder buffer on receive (`roomTab.msgBuffer`):** a `message` frame whose `idx` is higher than the next expected one (`Client.ExpectedIdx`) is held in full (ciphertext, not plaintext) in `bufferMsg(tab, keyID, idx, mm)` — never decrypted until it is genuinely its turn. When the missing message arrives, `handleIncomingMessage` processes it and then checks, in the same pass, whether the next expected `idx` is already buffered, unlocking it (and so on) up to the first remaining gap. `maxBufferedPerKey` (1000) is only a memory ceiling against a malicious/buggy `idx` — it should never be reached under normal conditions, since the sender's reliable delivery (below) guarantees nothing stays lost forever.

**One's own self-echo bypasses this gate entirely, BEFORE any check on `idx`.** `Client.ExpectedIdx` only tracks a PEER's chain-ratchet (populated by `StorePeerSenderKey`/`DecryptMsg`): one's own `senderKeyID` never enters it, because one's own self-echo never goes through the reception ratchet (`TakeSentText`, not `DecryptMsg`). `handleIncomingMessage` recognizes a self-echo BEFORE consulting `ExpectedIdx` (`Client.HasSentText(msgID)`, a non-destructive check) and routes it straight to `parseMessage`, skipping `bufferMsg`/`ExpectedIdx` entirely — routing it through the per-peer gate would buffer it forever, since no condition would ever make it "expected": from the second send onward the sender would stop seeing their own messages.

**Reliable delivery on the client side (`pending.go`):** every message sent with `Send`/`SendReply` stays "pending" (`Client.pending.out`) until the server takes charge of it (its own self-echo). A periodic cycle (`tea.Tick`, same cadence as `RetryDue`) retries every not-yet-taken-charge-of message with backoff (default 20s, doubling), and drains `FlushDeferredKeyDistributions` for any deferred `sender_key`. Beyond `pending_slot_limit` (default 5) messages without take-charge, `Send`/`SendReply` return `BackpressureError` (`errors.Is(err, client.ErrPendingBackpressure)`): the UI blocks writing and shows `tui.err_pending_backpressure` in Console, until the queue frees up. Beyond `pending_escalation_age` (default 90s) of waiting on the oldest unconfirmed message, a separate soft warning appears in Console (`Client.OldestPendingAge`) — non-blocking, purely informational.

**Explicit reply reference (`/msg N`):** sets the reference for the NEXT send in the active tab (`roomTab.pendingReplyTo`), consumed and cleared after a successful send (one-shot) — rejected with a Console error if `N` does not match any line currently shown (`chatLine.gseq`). A persistent indicator above the input field shows the set reference (`renderReplyIndicator`, with a preview of the referenced message if still visible in this tab).

**Group invite popup (`inviteModalMode`/`inviteModalKnock *pendingKnock`):** a knock with `GroupID != ""` immediately opens a foreground popup (`m.showNextInviteModal()`, called both on receiving the knock and from a "self-healing" gate at the top of `case tea.KeyMsg:`, before any other mode check: it promotes the next queued invite as soon as nothing else is blocking, without having to touch every other popup's exit points one by one). `blockingModalActive()` lists every other popup mode that takes precedence (quit, confirmations, backup, etc.) — if one of those is active, the invite stays queued. Keys: `Enter` = accept (`m.cmdJoin(groupID)`), `Esc` = ignore (`m.ignoreInvite(groupID)`, removes the entry from `m.pendingKnocks`). If more than one arrives they're shown one at a time, in arrival order. A knock with an empty `GroupID` produces neither a popup nor a Console line — no sender produces this shape (§ "Knock" below).

**`memberState` / `departures`:** an `int` type with four constants (`memberCrashed`, `memberLeft`, `memberDeclined`, `memberBanned`). Each `roomTab` has a `departures map[string]memberState` field, keyed by member key, tracking how disconnected members left the room (or never reached it). It is updated by the `user_left` handler (extracts `reason` from the JSON frame, `memberLeft` or `memberCrashed`), by the `"invite_declined"` case (`memberDeclined`, § "Knock" below), and reset on `user_joined` (deletes the entry). Absence of a key = never connected, or the host went down without a `user_left` → treated as `memberCrashed`.

**`renderGroupBar(tab *roomTab, width int) string`** (members, connection states and `departures` are read from `tab`): header for **every** chat tab, groups and two-member rooms alike — there is no separate header for the latter. Visual states per member:

| State | Dot | Name |
|---|---|---|
| self, connected | green `●` | cyan (`stylePeerMsg`) |
| connected, ContentKey relationship established | green `●` | green (`styleOwnMsg`) |
| connected, ContentKey relationship not yet established | green `●` | yellow (`styleWarnName`) — only Safety Number available |
| `memberLeft`, `memberDeclined`, or `memberBanned` | red `●` | gray (`styleMeta`) |
| `memberCrashed` or absent | red `●` | red (`styleErr`) |

`m.contentRelEstablished(tab, username)` checks whether the per-relationship ContentKey toward that member is already known, not a global identity. For details that color alone doesn't convey (trust tag, safety code, full relationship key) see `cmdRoomInfo`, hooked to `/grp-info` (§ "Safety Numbers" above).

**Tab bar colors:** chat tabs (`isChatTab`: not Console, Contacts, Groups, Tor, File) use `styleTabChat` (green, inactive) and `styleTabChatActive` (green + purple background, active). The name turns gray (`styleTab`) when `tab.reconnecting == true`, preceded by a red `●`. The yellow `●` dot signals unread messages and is independent of the name: dot and name are rendered separately to preserve their respective colors.

**Identity prefix (`"<username>:"`, `renderTabBar`, `identityPrefix`).** Always the first element of the row, `styleTab` style — a "fake tab": never present in `m.tabs`, navigates nowhere, and unlike real tabs it never enters the sliding window (its width is subtracted from `avail` BEFORE that window is computed), so it stays visible regardless of how many tabs are open or how narrow the terminal is. Introduced because the terminal window title (`tea.SetWindowTitle("Neutrino - <user>")`, set in `Init()`) depends on the terminal/multiplexer to actually be shown — on some setups it never appears; this prefix is text inside the TUI's own content, always visible regardless. `tea.SetWindowTitle` is still set, a bonus for terminals that do show it. Equivalent of the persistent "Neutrino - \<user\>" header already present on every screen of the Android app (`screens/shell.go`).

**Red error dot on the Console tab** (`roomTab.hasError`, `renderTabBar`): lights up when a message flagged as an error lands in the Console tab while it isn't the active one, turns off as soon as the user views it (centralized cleanup at the start of `Update()`, before the message switch — safe because `m.tabs` is a slice of pointers, so the mutation persists even with a value receiver). Propagated via `localDisplayMsg.isError` and the `isError` parameter of `appendToConsole`; `consoleErrTab(consoleIdx, text)` is the helper for errors meant only for the Console (analogous to `localTab(tabIdx, text)` but with `isError: true`). Not everything that ends up in Console is flagged as an error: debug logs, startup lines (`BootLog`), and the "unreachable" outcome of periodic probes (routine status, not a failure) stay `isError: false` to avoid false alarms.

**Convention for general commands (not tied to a specific chat)**: `/cnt-add`, `/cnt-del`, `/grp-add-member`, `/grp-del`, `/cnt-edit`, `/sec-passwd`, `/sec-rotate-rel-identity`, `/sec-rotate-rel-content` — confirmation always goes to Console (`m.defaultTabIdx()`), any error always to Console with `consoleErrTab` (red dot), **never** tied to `m.active`. Commands intrinsically tied to a tab type (`/grp-reinvite`, `/grp-save`: require `tab.groupID`; `/grp-reconnect`, `/grp-ping`: require an actual chat, `isChatTab`) remain tied to `m.active` instead, since they make no sense outside that context. `/grp-contact-send`/`/cnt-save`/`/cnt-ignore` remain tied to `m.active` for the same reason (they act on the current tab) and work in any room, regardless of member count (see "Contact card" below).

**Contact cards:** mechanism for sharing address-book entries — a special case of file sending (§ "File transfer"), usable in any room regardless of member count.

```go
const contactCardPrefix = "\x00CC\x00"  // invisible sentinel, impossible to type

type contactCard struct {
    Username    string `json:"username"`
    LocalName   string `json:"local_name,omitempty"`
    IdentityPub string `json:"identity_pub"`        // standard base64, 32-byte Ed25519 — transport key
    MLKEMPub    []byte `json:"mlkem_pub,omitempty"`  // subject's durable ML-KEM-768 encapsulation key
    MLDSAPub    []byte `json:"mldsa_pub,omitempty"`  // subject's durable ML-DSA-65 public key
    OffbandHint string `json:"offband_hint"` // out-of-band contact info, mandatory (not omitempty)
}
```

`OffbandHint` — free text written by the sender at send time (phone, email, Telegram...), **never** read from a saved field: `cmdSendContact` opens a mandatory prompt (`sendContactHintMode`/`sendContactHintBuf`, Enter blocked until the buffer is non-empty) before building the card, handled in `finishSendContact`. It lets the recipient contact the card's subject out-of-band to compare the safety code — without this channel, verification would be impossible (see § "Safety Numbers"). There is no equivalent field on `ContactInfo`/`keystore.Contact`: the text is seen only once, upon receipt, then it's gone.

Send flow: `/grp-contact-send <name>` → `cmdSendContact` looks up the contact in the address book, checks eligible recipients, then opens the out-of-band contact-info prompt; only after confirmation does `finishSendContact` serialize `contactCard` to JSON with the `contactCardPrefix` prefix and reuse the entire `/grp-file-send` pipeline (`m.sendFileData`/`m.sendFileDisplayName` instead of a disk path — with a single eligible recipient it skips the picker, with more than one it opens it; same per-recipient encryption/signing with the per-relationship ContentKey, one `FileOfferEnvelope` each). No direct client call: the rest of the flow (offer, acceptance, chunks) is indistinguishable from a regular file.

Receive flow: after `finalizeIncomingTransfer` (full decryption + signature verification), the `fileReadyToSaveMsg` handler checks `bytes.HasPrefix(msg.data, []byte(contactCardPrefix))` on the plaintext; if present, it unmarshals it and sets `tab.pendingCard = &card` and `tab.pendingCardFrom = m.fileOfferFromKey` (the real sender's member key, resolved via `Client.LookupMemberKey` — **not** a field of the card itself) instead of opening the "save to disk" prompt; the out-of-band contact info is shown as an extra system line. `/cnt-save` (`cmdSaveCard`) first decodes `card.IdentityPub` and checks with `contactExists(pub []byte)` (by `IdentityPub`, never `Username` — a contact's unique identifier is its key, never the self-declared name) whether a contact with that exact key is already present: if so, it **rejects** the operation with a message suggesting `/cnt-del` first (no silent overwrite); only if the key doesn't exist does it call `ks.AddContact` with the card's data, uses `pendingCardFrom` to determine `IntroducedBy` (empty if the sender coincides with the card's subject — self-introduction), and clears `pendingCard`/`pendingCardFrom`. `/cnt-ignore` clears both without saving anything. The same `IdentityPub` check applies to `/cnt-add` (`startAddContact`/`resolveContactByPub`). `Keystore.AddContact` dedupes on `bytes.Equal(existing.IdentityPub, c.IdentityPub)`, never on `Username`: two contacts sharing a name but with different keys coexist correctly, each resolvable via `Keystore.GetContactByPub`.

---

## Tor

### `Node`

```go
type Node struct {
    t               *tor.Tor
    mu              sync.Mutex
    svcs            []*tor.OnionService
    cleanup         func()    // removes the extracted tor binary from a temp dir (if embedded)
    ptc             *ptClient // in-process pluggable transport (nil if no bridge)
    logCh           chan string             // Tor process log, one line per element (buffered to 2000, LogCh())
    dialer          *tor.Dialer            // shared generic dialer
    isolatedDialers map[string]*tor.Dialer // token → dialer with a dedicated circuit
}
```

`StartTor(ctx, cfg StartConfig)` — starts Tor with full configuration (`StartConfig{OnProgress func(int), Bridges *BridgeConfig}`). If `cfg.OnProgress` is non-nil, it's called on every `"Bootstrapped XX%"` line in the logs; parsing happens in `torWriter`, an `io.Writer` that buffers by lines and redirects the entire Tor process output to `node.LogCh()` instead of stdout/stderr. If `cfg.Bridges` is non-nil, the requested transports (obfs4/webtunnel) start in-process (`ptclient.go`) — see § "Tor Bridges". A single attempt, no retry: returns as soon as the Tor process authenticates the control port, not when bootstrap reaches 100% (see `StartTorBridges` below for the wait-with-timeout and the fallback-bridge retry).

`AddHiddenService(ctx, privKey)` — creates a v3 hidden service on port 80 with the given Ed25519 key. Returns a `net.Listener`, `.onion` address, and local TCP address. In `main.go` it is called in a loop with up to 3 attempts (2s pause between them) to handle the rare case where the control port connection is not yet stable immediately after bootstrap. `privKey` is `Keystore.NetworkIdentityPrivKey()` (below), not necessarily `ks.IdentityPrivKey()` — called from both `cmd/main.go` and `cmd/androidapp/netboot/bootstrap.go`.

**`NetworkIdentityPrivKey()`** (`internal/keystore/keystore.go`) resolves the network-address conflict when multiple endpoints of the same identity are online together: for D1 (`ks.AdditionalDevice == false`, the common case) it returns `ks.IdentityPrivKey()` directly — unchanged address. For an additional device (`ks.AdditionalDevice == true`, born from `ImportFromBackupFile` — see below) it derives a distinct Ed25519 key with HKDF-SHA256 (domain `"neutrino-device-onion-v1"`, IKM = `IdentityPrivKey().Seed()`, salt = `ks.DeviceID`) — deterministic for the same `DeviceID`, but different from D1's and from every other additional device with a different `DeviceID`: two endpoints of the same identity online together never collide on the same `.onion`/I2P address.

**`ImportFromBackupFile`** (`internal/keystore/backup.go`) — a full restore (24 words + file/chunk/animated QR, address book included) is by construction the "birth" of an additional device: after `json.Unmarshal` of the decrypted keystore, it regenerates `ks.DeviceID` (16 random bytes) and the `ks.DevicePriv`/`ks.DevicePub` pair (fresh `ed25519.GenerateKey`), and sets `ks.AdditionalDevice = true` — without this step the device would carry the ORIGIN device's `DeviceID`/`DevicePriv`, never safely duplicable. Restoring from just the 24 words (`ImportFromMnemonic`, address book lost) leaves `DeviceID`/`AdditionalDevice` untouched — it stays the D1 path, meant to rebuild the same device after total disaster, not to create a new one in parallel.

In the same pass, `ImportFromBackupFile` also clears the relationship keys of every imported contact (`RelIdentityPriv`/`PeerRelIdentityPub`/`RelContentPriv`/`PeerRelContentPub` + PQC companions, `RelIdentityConfirmedByPeer`/`RelContentConfirmedByPeer`, `IdentityKeyPending`/`OldRelIdentityPriv`, `ContentKeyPending`/`OldRelContentPriv`, every `Pending*`, `Verified`, `KnownDevicePub`) — never copied from the backup, keeping only the contact's identity (`IdentityPub`/`Username`/`LocalName`/`IntroducedBy`/`MLKEMPub`/`MLDSAPub`/`LastAckAt`/`LastSeenAt`). Without this the additional device would be born cryptographically indistinguishable from D1 toward every already-confirmed contact — whoever possesses only the backup file (legitimate or stolen) would inherit already-established trust silently, never passing through the `TrustDanger` gate (see above). The additional device re-negotiates the relationship with each contact from scratch — the periodic probe cycle (already existing for an unrelated self-heal, "relationship key exchange not yet complete") generates the missing keys on the fly and resends a `rel_init` as soon as the contact is seen online, no extra action required.

`HasCircuits() bool` — queries the control port with `GETINFO circuit-status` and returns true if at least one circuit is in the `BUILT` state. Uses bine's `n.t.Control.GetInfo(...)`; no SOCKS5 connection needed — response in < 1 ms. Exposed as `TUIParams.CheckCircuits`.

`DialContext` — generic shared SOCKS5 dialer, lazily created on first use.

`DialerForToken(token)` — returns a `DialContext` with SOCKS5 credentials `{User: token, Password: token}`. Tor applies `IsolateSOCKSAuth`: different tokens get separate circuits; the same token reuses the circuit. The dialer is created once per token and cached.

### `.onion` address derivation

```
pubkey = Ed25519 pubkey (32 bytes)
checksum = SHA3-256( ".onion checksum" || pubkey || 0x03 )[0:2]
payload = pubkey[32] || checksum[2] || 0x03
onion = base32_lower(payload) + ".onion"
```

### Contact visibility and Tor status — timings and timeouts

#### Tor connectivity status (tab bar and Tor tab's status bar)

Two independent fields in the TUI model:

| Field | Type | Meaning |
|---|---|---|
| `torUp` | `*bool` | **outbound** circuits active (self-probe via control port or TCP) |
| `torIn` | `*bool` | **inbound** connectivity confirmed (knock received from outside) |

| `torUp` | `torIn` | Tor tab dot (tab bar) | Status bar (inside the Tor tab) |
|---|---|---|---|
| nil | nil | 🔴 red | `Tor:` + 🔴 `out` + 🔴 `in` |
| false | nil (reset) | 🔴 red | `Tor:` + 🔴 `out` + 🔴 `in` |
| true | nil/false | 🟡 yellow | `Tor:` + 🟢 `out` + 🔴 `in` |
| true | true | 🟢 green | `Tor:` + 🟢 `out` + 🟢 `in` |

`Tor:` is always in the standard color (styleMeta). The two `out`/`in` dots are independent: 🟢 green if the respective circuit is active, 🔴 red otherwise. The dot in the tab bar can be 🟡 yellow (only out active); in the status bar inside the tab there is no yellow, just green/red for each dot.

#### Startup sequence (one-time)

| Time | Event | Timeout | Updates |
|---|---|---|---|
| T+10s | `probeTorSelf` | 60s TCP / <1ms control port | `torUp` → yellow dot if ok |
| T+10s+Δ | `probeSelfKnock` (started by `torProbeResultMsg{ok:true}`) | **60s** HTTP POST to own `/knock` | `torIn=true` → green dot if `knockMsg{self_probe}` arrives |
| T+20s | `cmdWarmupCircuits` | 60s global context | nothing — pre-builds Tor circuits to contacts |
| T+1m | silent `probeContacts` | 90s global context | `contactStates.online`, `probedAt`; triggers `probe_ping` toward those online |

#### Recurring timers

| Interval | Event | Timeout | Updates |
|---|---|---|---|
| every **5 min** | `probeTorSelf` | 60s TCP / <1ms control port | `torUp` |
| every **5 min** (if `torIn=nil`) | `probeSelfKnock` (after each `probeTorSelf{ok:true}`) | **60s** HTTP POST | `torIn=true`; stops once `torIn=true` |
| every **1 min** | silent `probeContacts` | 90s global context | `contactStates.online`, `probedAt` |
| every **5 min** | `cmdWarmupCircuits` | 60s global context | nothing — warms up circuits |

#### `probeSelfKnock` flow

```
torProbeResultMsg{ok:true} && torIn==nil
  → POST http://<myOnion>/knock  [KnockEnvelope{tag, ECIES payload}, type="self_probe", 60s timeout]
      → server decrypts → knockCh
          → knockMsg{Type:"self_probe"}
              → torIn=true  (green dot)
              → case "self_probe": silent, no TUI notification
```

No dependency on contacts: the POST goes to its own hidden service over a separate Tor circuit.

#### Sub-events for each `probeContacts`

| Order | Event | Timeout | Notes |
|---|---|---|---|
| 1 | TCP connect `A:80` (dot1 contacts) | 90s shared context | parallel goroutine per contact |
| 2 | `sendProbePing` → A | 15s HTTP | fire-and-forget; only if A is online |
| 3a | A receives our `probe_ping`, verifies known sender+address (`probeAckCmdFor`) | — | A marks **immediately, synchronously**, `seenByPeer[us]=true` in `A.contactStates` — direct proof, doesn't wait for its own ack |
| 3b | `sendProbeAck` A → us | 15s HTTP | A still posts to our `/knock`; can fail independently of 3a (A's circuits toward us not ready yet) |
| 4 | `applyProbeAck` (us), if the POST in 3b succeeds | — | `seenByPeer[A]=true`, `seenByPeerAt=now` → dot2 ● in the Contacts tab |
| — | If neither 3b nor a `probe_ping` from A ever arrives, for `onlineStreak >= probeRetryCount` cycles | — | `seenByPeer[A]` expires from `nil` to `false` → dot2 ✗ (never a diagnosis, see below) |

#### Contacts tab indicators (dot1 / dot2)

```
dot1 (I see A):     ◌ never probed   ● reachable (online==true)   ✗ unreachable (online==false)
dot2 (A sees me):   ◌ unknown (seenByPeer==nil)   ● confirmed (seenByPeer==true, round-trip OR direct proof)   ✗ no confirmation after probeRetryCount consecutive online cycles (seenByPeer==false)
```

`dot2` is not subordinate to `dot1`: it can be `●` even with `dot1` at `◌`/`✗` (A reached us even though we don't reach them right now), and once `●` it never reverts to `◌` on its own. It becomes `✗` **only** while `dot1` is `●` with continuity — never while `dot1` isn't `●`, since in that case we never gave A the chance to respond. `✗` doesn't imply a specific cause: the same observation ("no confirmation despite repeated attempts") is indistinguishable from a genuine network asymmetry, from a failure of the application-level POST alone (independent of the TCP dial's success at step 1), or from A having removed us from their address book — the mutuality filter (`KnockDHTag`, § Knock below) always responds 202 whether it matches or not, precisely so whoever sends a knock can't tell if they were recognized.

**Backpressure:** the `model.probing` flag is set when each `probeContacts` starts and reset upon receiving `probeResultMsg`. If `tickActiveMsg` fires while `probing==true`, the cycle is skipped — at most 1 probe in flight. `/active` also respects the gate. The gate's safety is guaranteed by `probe_contacts_timeout` (90s): even if a goroutine hangs, the context expires and `probeResultMsg` arrives within 90s.

**Drain on timeout:** when the context expires, the collection loop exits with `collected = len(contacts)`. A subsequent non-blocking drain recovers goroutines that completed exactly at the timeout boundary but whose result was already in the buffered channel.

| Indicator | Depends on contacts? | Source | Critical timeout |
|---|---|---|---|
| dot1 "I see A" | Yes | `probeContacts` → TCP A:80 | 90s (global context) |
| dot2 "A sees me" | Yes | `probe_ack` from A via `/knock` | 15s (often insufficient over Tor) |
| Tor dot 🟡 | **No** | `probeTorSelf` | 60s TCP / <1ms control port |
| Tor dot 🟢 | **No** | `probeSelfKnock` → self-knock | 60s HTTP |

---

## Traffic correlation resistance — Tor vs I2P

**Why this section exists:** key rotation (§ "Per-relationship rotation", § "Root IdentityKey rotation with continuity") reduces correlation between address books compromised at different points in time, but does not solve — for either transport network — real-time observation of who is talking to whom at that exact moment.

**Tor.** The project states the limit explicitly as a design choice, not a bug: *"The Tor design doesn't try to protect against an attacker who can see or measure both traffic going into the Tor network and also traffic coming out of the network"* — such an observer can decide whether the two sides match using "some simple statistics" on timing and volume. The stated reason is practical: stronger protections would require overhead and delay incompatible with low-latency browsing. Source: [Tor Project blog, "Traffic correlation using netflows"](https://blog.torproject.org/traffic-correlation-using-netflows/). For a hidden service, the rendezvous path joins two three-hop circuits (~6 hops total), always **bidirectional** — request and response share the same path.

**I2P.** The official "threat model" documentation is equally explicit about its own remaining limits: a "global active adversary" (same category as Tor above) "can gain substantial information" absent defenses not yet deployed ("protocol scrubbing", "nontrivial delays and batching strategies"). Source: [I2P threat model](https://i2p.net/en/docs/overview/threat-model/). One real architectural difference from Tor: I2P uses **unidirectional** tunnels (separate inbound and outbound), so each participant only ever sees half of a flow — which, per the official comparison documentation, makes basic timing correlation on a single observed tunnel "significantly harder". Source: [I2P vs Tor comparison](https://i2p.net/en/docs/overview/comparison).

**Conclusion, not a compromise between the two sources:** neither network claims to solve correlation by a global/sophisticated observer — it's the same limit, acknowledged by both projects in their own official documentation, not an omission by Neutrino. I2P has one specific structural advantage (unidirectional tunnels) that Tor lacks, but I2P's own primary source does not present it as an equivalent or superior guarantee against a sophisticated adversary — only as a partial mitigation.

---

## Message signing

Every broadcast chat message carries **one signature per pairwise relationship present in the room** (up to N-1, for a room with N members) — never a single "room" signature verifiable by everyone with the same key. The sender signs once per recipient it has a relationship with (real or ephemeral), using its own **per-relationship ContentKey** toward them; each recipient verifies only the entry addressed to itself, with the sender's ContentKey toward it.

**Signed data** (`shared.RelMsgSigPayload`):
```
"rel_msg:" + recipient + ":" + ciphertext_base64 + ":" + timestamp
```
Binding the signature to the declared recipient too prevents a signature computed for one recipient from being reused as a signature toward another. `shared.SignRelMsg`/`VerifyRelMsg` (Ed25519) sign/verify this payload; `SignRelMsgMLDSA`/`VerifyRelMsgMLDSA` do the same in parallel with ML-DSA-65, never blocking if absent.

**On the wire**, the signatures travel outside the ciphertext (each recipient must be able to read them without first decrypting anyone else's): the frame carries `content_sigs` (an array of `{for, sig, sig_mldsa}`, `shared.ContentSigEntry` — one entry per recipient) and `content_sig_ts` (the timestamp shared by every entry). The server relays these fields untouched, without inspecting them.

**Synchronous verification**, not asynchronous, with no network lookup: the sender's ContentKey toward us is already in local memory as soon as the relationship-key exchange (or the ephemeral bootstrap for an introduced member) has completed — always before a message can arrive, by construction of the protocol. A single attempt, inside `parseMessage`, no retry needed.

**Signed data in the handshake** (with the per-relationship IdentityKey, not the ContentKey — see § "Handshake protocol"):
- Client: `nonce_client || session_pub_client`
- Server: `nonce_client || nonce_server || session_pub_server`

### Signature tag in messages (`chatLine.render`)

Each chat line shows, after the sender's name, a signature tag computed from `sigStatus` (`internal/client/tui/tui.go`, `chatLine.render`), followed by the device tag (`DEV:…`), the `[PQC]` tag and, on one's own messages, the ack marker:

- `sigOwn` — one's own message (no meaningful self-verification: the multi-signature scheme never produces a single "own" ContentKey to show) → `your message` (`tui.tag_own`)
- `sigOK` — valid signature, verified with the sender's already-known ContentKey toward us → `REL:` + last 8 hex digits of that ContentKey. Gray (`styleMeta`) for a persisted contact's key, yellow (`styleWarnName`) for an ephemeral relationship born only from a room introduction (`contentKeyEphemeral`)
- `sigPending` — no relationship key available yet for that sender → `REL:........` (`tui.tag_sig_pending`)
- `sigFailed` — key known but the signature doesn't match → `signature invalid` (`tui.tag_sig_invalid`), red (`styleErr`)
- `sigNone` — the message carries no signature addressed to us → `no signature` (`tui.tag_no_sig`)

Whether the sender is in the address book is not appended to the signature tag: it is conveyed by the color of `REL:` above and, for room members, by `/grp-info`, which shows `[UNKNOWN]` (`tui.tag_unknown`) for anyone not saved as a contact — distinct from "UNVERIFIED," which instead means "they are in the address book but I haven't yet confirmed their identity with the safety code."


---

## File transfer

`/grp-file-send` — sends an encrypted+signed file to one or more explicitly selected recipients: with a single eligible recipient (an already-established ContentKey relationship, `contentRelEstablished`) the recipient is implicit, no popup; with more than one it opens the selection popup (`eligibleFileRecipients`, same criterion regardless of the room's member count — real or ephemeral/introduced). An already-established per-relationship ContentKey is **mandatory**: there is no other way to encrypt for a recipient. The command is always listed in `/help` (no conditional visibility, consistent with the rest of the codebase); if no room member has an established ContentKey relationship, it responds with an explicit error in Console.

### Encryption and signing — multi-recipient scheme with per-relationship ContentKey

There is no native multi-recipient encryption format: the scheme generates a random symmetric key for the content and distributes it encrypted separately for each recipient.

1. **`fileKey`** — 32 random bytes, generated once per transfer.
2. The file content is compressed (strong pack, `shared.PackData`, see below) and encrypted **once** with `fileKey` (`shared.Encrypt`, AES-256-GCM) — the same blob goes to every recipient. `hash := sha256(ciphertext)`.
3. **Announce phase, before any heavy data**: for each recipient, `hash` (hex-encoded) is signed with the per-relationship ContentKey toward them (`shared.SignRelMsg`/`SignRelMsgMLDSA`, same `RelMsgSigPayload` as always), producing a `shared.FileAnnounceEnvelope{Sig, SigMLDSA}` — no file name, size, or `fileKey` at this stage.
4. Only after a given recipient's announce ack, `{file_name, file_size, file_key}` is encrypted for them with their ContentKey (`shared.EncryptForPeer` — hybrid ECIES X25519+ML-KEM-768 if the recipient's ML-KEM companion is known, otherwise plain X25519), producing a `shared.FileOfferEnvelope{MetaBlob}` — only they can decrypt it and derive `fileKey`. No signature here: authenticity is already established by the announce.

`shared.PackData`/`UnpackData` (`internal/shared/pack.go`): strong pack used by file transfer/contact cards. `PackData` always tries compressing `data` with LZMA2/XZ (`github.com/ulikunitz/xz`, pure Go) when `strongCompression` is `true`, compares the resulting size with the original, and uses whichever is smaller — never worse than not compressing. A one-byte marker at the head of the plaintext lets `UnpackData` exactly reverse whichever operation the sender chose, regardless of how it set `strongCompression` — correct even between a sender and a recipient on different platforms or versions. `strongCompression` is driven by `config.json` (`strong_compression_enabled`, default `true`) on desktop; on Android it is always on (no dedicated setting). The same `PackData`/`UnpackData` (with `NowTS`) is also used by the generic animated-QR channel (`neutrino qr send`/`qr receive`), which encrypts symmetrically with a password instead of toward a ContentKey.
### Delivery — targeted multicast

`internal/server/hub.go` has `MulticastBytes` alongside `Broadcast`: same per-peer queue/write/clean-up-dead-connections pattern, but toward an explicit list of `to_user_id` instead of everyone. The encrypted blob travels only to the selected recipients, never in broadcast — even though an excluded recipient couldn't open it anyway, this avoids making even the traffic transit through them. The server never accumulates the entire file in memory: it forwards chunks as they arrive.

### Flow

1. Sender picks the file (hand-rolled filesystem browser — `listDir`/`fsEntry`, not `bubbles/filepicker`: that library exposes no external filtering hook, needed for the type-to-search filter during navigation), checked against `file_transfer_max_size_mib`.
2. Picks the recipients (popup filtered by already-established ContentKey relationship, pre-selected — Space deselects) and the speed preset (`slow` default, `warp` explicit).
3. Generates `fileKey`, encrypts the content once (blob kept in RAM for the whole transfer duration), computes `hash := sha256(ciphertext)`, and signs that hash separately for each recipient with their ContentKey (`file_announce`, §WebSocket Frames) — no file name/size/key at this stage. All of this work (reading the file, encrypting, signing) runs entirely inside the `tea.Cmd` returned by `onFilePresetChosen` (message `fileEncryptedMsg`), never inline in the `Update()` loop — a file of a few MB takes seconds, enough to freeze the entire single-threaded event loop if run synchronously on the main thread. `/grp-contact-send` (contact card) reuses the same pipeline.
4. Each recipient verifies the announce signature (§"Verification moved before the transfer" below) and, if valid, replies immediately with `file_announce_ack` — ONLY THEN does the sender encrypt and send the real metadata envelope (`{file_name, file_size, file_key, chunk_count}`, `file_offer`, §WebSocket Frames) — name, size, and `fileKey` never travel in the clear or shared between recipients; `chunk_count` is the total number of chunks the sender split the ciphertext into (§"Weighted per-group scheduling" below), declared once here and never recomputed by the recipient. Chunk sending starts toward whoever has already accepted at the first of two moments: when `file_offer_batch_window` (10s by default) elapses after the offer is sent, or immediately if EVERY recipient has already responded even before that — never at the very first isolated accept, to avoid chasing whoever accepts just an instant later with a full resend. Whoever accepts past this window is still re-admitted into the already-running sliding window via the same resume mechanism used for reconnections (`fileResumeEvent{isNewAccept: true}`, "Weighted per-group scheduling" section below). If nobody EVER responds within `file_transfer_offer_timeout` (90s by default, the sole fallback budget, reused for the whole announce→ack→offer→accept round trip), the whole send is cancelled.
5. Recipient receives `file_offer` only after already having verified the matching announce, immediately registers the plaintext fields (sender, transfer_id) and starts decrypting its own envelope in the background (`shared.DecryptFromPeer` with its own ContentKey — never inline in the `Update()` loop, so it never blocks the UI, see `fileOfferMetaDecryptedMsg`). Only upon return does it show the popup with sender/name/size. If another offer popup is already open (or another metadata decryption is completing at nearly the same time), the offer is queued instead (`m.pendingFileOffers` + `showNextFileOfferModal`, same queue + "self-healing" gate pattern as `showNextInviteModal`) instead of overwriting the current popup's fields — so two close-together offers (e.g. a file plus a contact card, or two files from the same sender) never clobber each other.
6. If accepted: chunks are sent with a **sliding window** (up to `..._max_inflight_chunks` chunks without ack in flight at once, not lockstep) — see below.
7. Recipient writes the **raw** encrypted chunks (not decrypted) to a temporary file on disk, sending a `file_chunk_ack` for each one — ALWAYS in position order (`idx`, the chunk index declared by the sender, never arrival order): a catch-up burst can make a higher index arrive before a lower one, never retransmitted, is finally recovered. A chunk that arrives ahead of the already-written contiguous frontier is buffered in RAM (indexed by its own `idx`) instead of written right away; as soon as the frontier reaches it, it's written in a chain together with any already-buffered chunk that follows — never an `os.File.WriteAt`, writes stay sequential by construction, only ever deferred when needed. Without this reordering, writing blindly in arrival order would silently corrupt the file: it would reach "100% written" with the content in the wrong order, caught only by the final hash check.
8. Once the full size is reached: decryption (with `fileKey`, derived from its own envelope) and an integrity check `sha256(received ciphertext) == hash already verified at announce time` — cheap, no public-key crypto here: authenticity is already established, a mismatch at this point is always transport corruption/tampering. Only if it matches does a popup open first to rename the file (name proposed by the sender, editable — `saveRenameMode`), followed by the folder browser to choose where to save it (`saveDirMode`, subdirectories only plus a synthetic "save here" entry); otherwise the temp file is discarded and the error is reported — either way a `file_verify_result` (§WebSocket Frames) goes back to the sender with the real outcome, independent of whatever the individual chunk delivery acks already confirmed.
9. If a file with the same name already exists in the chosen folder, an automatic numeric suffix is added instead of overwriting or asking for confirmation.

"File" tab (permanent, like Console/Tor): one row per group of recipients at the same point of progress, sftp/scp-style (`renderFileProgressView`) — direction, sender, file name, recipient(s), three fixed dots, the right-aligned percentage and, whenever `chunksTotal > 0`, a chunk-level detail appended to the row (send side `n. sent - total`; receive side `n. received - n. non-contiguous - total`, where "non-contiguous" means chunks that arrived ahead of the written frontier and are still buffered awaiting placement, §"Weighted per-group scheduling" below) — no colors (no graphical bar, no dependency on `bubbles/progress`), updated by a lightweight tick (300ms, active only while at least one transfer is in progress) that reads a mutex-protected shared state (`fileTransferProgress`) written by the send/receive goroutines. As long as every recipient of a send stays in step, only one row is shown (the one created at offer time); as soon as one or more fall behind or resume from a different point, each separated group gets its own row with its own name subset and its own percentage, merging back into a single row once they catch up — see below.

### Weighted per-group scheduling, isolation, and resume per recipient

**Chunk indexing.** Every chunk is identified by `idx = byteOffset/chunkSize` (a stable position within the file, never a send-order counter) — the total count (`chunkCount`) is declared once in the `file_offer` (step 4 above) and never recomputed. This decouples a chunk's position from the order it's actually sent in, a precondition for the group scheduling below: two recipients at the same `idx` are by definition at the same point in the file, regardless of how many chunks have actually crossed the wire to reach them.

**Groups ordered by index.** `startSendingChunks` (`internal/client/tui/tui.go`) groups current recipients into `sendGroup{index, members, sent, progress}`, kept in a slice sorted by ascending `index`: the last element (`groups[len-1]`) is always the **front** — the most advanced group, the only one that generates new data from the ciphertext via multicast — every other group ALWAYS chases the one immediately ahead of it in the ordering (never the front directly); when it catches up (same `index`) the two merge (`mergeAdjacent`, cascading upward until nothing more can merge), until everyone is back merged into the front and sending returns to a single multicast. A straggler with a large backlog therefore never blocks progress for everyone else.

**7:3 weight.** Among groups with pending work at a given instant (the front if it hasn't exhausted the ciphertext, a trailing group if its index hasn't yet caught up to the one it's chasing), the scheduler picks, for each free slot in the sliding window, the group with the lowest `sent/weight` ratio (float-free cross-multiplied comparison): the single most-behind group (`groups[0]`, only when there's more than one) gets weight 7, every other group — front included — gets weight 3 individually, never a percentage split of a shared pool (with 5 groups it's 7 against 3+3+3+3=12, not 70/30). This converges to a 7:3 ratio over time regardless of the configured sliding-window size — catch-up never gets absolute priority.

**Fairness reset on every topology change.** Each group's `sent` counter is zeroed (`resetSent`) every time the set of groups changes — a merge, a new arrival, an isolation. Without this reset, a freshly (re)created group (`sent=0`) would first have to "pay off" a historical ratio against a front with hundreds of sends already accumulated before the scheduler actually applied 7:3 from that point on, starving the front for as long as that ratio took to even out.

**Per-group progress rows.** The front always reuses the progress row created at offer time; a group that splits off from the front (isolation, or resume from a different point) gets its own, removed once it merges back — except when it's the very last group left: in that case the whole transfer has failed, and the row stays visible marked failed instead of vanishing without a trace.

**`everAccepted`/`isNewAccept`: a real accept, not a premature resume.** A recipient enters the scheduler only after a genuine `file_accept` — a genuine `file_resume` arriving BEFORE one (e.g. the recipient reconnecting for an unrelated reason while the offer is still an unanswered popup) is ignored, never treated as an implicit acceptance — otherwise a recipient who hadn't decided yet, reconnecting for some other reason, would receive the entire never-requested file, then a second full round at the real acceptance. The "re-admitted" branch (a late acceptance, once sending has already started) always sets `isNewAccept: true` — the recipient has nothing yet, so it's inserted at the front's `idx = 0`, never at a byte offset announced by the frame itself (which doesn't exist on this path).

**Isolation and acks.** `startSendingChunks` sends up to `file_warp_max_inflight_chunks`/`file_slow_max_inflight_chunks` chunks without waiting for an ack, tracking for each in-flight chunk the set of recipients that still need to confirm it (a `file_chunk_ack` arriving via `handleRoomMsg` is routed to a per-transfer channel, `model.outgoingTransfersSending` — not `outgoingTransfers`, which is cleared the instant real sending starts). A recipient that confirms **no** in-flight chunk within `file_transfer_reconnect_timeout` is isolated — removed from its group, which is dropped from the list if it becomes empty — while the others continue independently.

**Retry on acceptance (`fileAcceptRetryMsg`/`scheduleFileAcceptRetry`, `tui.go`).** `Hub.Send` (`internal/server/hub.go`) — used to forward `file_accept` to the sender, like any point-to-point frame — silently drops the frame if the recipient isn't registered in the Hub at that exact instant: no error, no backlog. To avoid leaving a lost acceptance unrecovered, `incomingFileTransfer.acceptRetryDeadline` is set at acceptance time (`time.Now().Add(fileTransferReconnectTimeout)` — the same value the sender uses, read locally); a self-rescheduling `tea.Tick` checks every `fileAcceptRetryInterval` whether `it.written` is still zero (no chunk ever arrived) and, if so, resends `file_accept` and reschedules itself, until either the first chunk arrives or the deadline expires. On the sender side, the mirror branch (`case "file_accept"` in `handleRoomMsg`, when `m.outgoingTransfersSending[transferID]` already exists) re-admits a late acceptance into the already-running sliding window instead of silently discarding it.

**Resume after reconnection**: an isolated recipient (or one only briefly disconnected, either their own reconnect or the sender's) announces how far it's gotten with `file_resume` (single-target, same pattern as `file_chunk_ack`) — sent on every `"init"` (own reconnect) and every `"user_joined"` (the other side's reconnect), idempotent. The sender re-admits it as a separate group at position `idx = fromByte/chunkSize` (clamped to the front's current index), which catches up to the group it chases and merges with it per the scheme above instead of blocking everyone else's progress — the full ciphertext stays in RAM for the whole transfer, so any range already sent to others can always be resent with fresh `seq` values.

### Verification moved before the transfer (self-heal)

An incoming `file_announce` is verified right away against the sender's declared per-relationship ContentKey (`contentPeerKeysFor`/`PeerContentKeyFor`, including the sender's exact device). If the signature verifies: immediate `file_announce_ack`, the hash stays in `verifiedFileHashes` awaiting the real `file_offer`. If it doesn't verify (misaligned key, e.g. the peer's ContentKey was regenerated but never propagated): the announce is not discarded — same self-heal mechanism already used for chat messages (`RelContentConfirmedByPeer` reset on the exact device, which re-triggers a `rel_init` resend on the next probe cycle), with one difference: here a probe round is triggered IMMEDIATELY (not waiting for the periodic cycle) to make the best use of the `file_transfer_offer_timeout` window within which the sender waits for a response. The announce stays pending (`pendingFileAnnounces`/`PendingFileAnnounce`) until its own deadline, re-verified as soon as a `rel_init_ack` resyncs the key (`retryPendingFileAnnounces`/`RetryPendingFileAnnounces`) — no retransmission of any file byte is ever needed: only the hash and signature (a few dozen bytes) are held pending, never the ciphertext.

On completion (`finalizeIncomingTransfer`) there is no signature left to re-verify: only a `sha256(received ciphertext) == hash already verified at announce time` comparison — a mismatch here is always transport corruption/tampering, never a key problem.

---

## Knock (room invite)

The knock is the initial P2P invite mechanism — unified for any room, from two people upward, via `/grp-invite`.

**Flow:**
1. Alice runs `/grp-invite Bob` (or multiple users: `/grp-invite Bob Carol …`)
2. Alice's client opens a local group server with a random `groupID`, generates an **individual** access secret for each invitee (never shared among members, §Per-member authentication), computes the DH mutuality tag toward each recipient (`shared.KnockDHTag`, `cryptography-manual.md` §7.2) and sends each of them a `POST /knock` to their permanent `.onion`/`.b32.i2p` address (derived from their identity key, known from the address book) with a `KnockEnvelope{Tag, Payload}` — `Payload` is the `KnockPayload` encrypted with the recipient's Ed25519 key, in hybrid X25519+ML-KEM-768 form if their durable `MLKEMPub` is known (`Contact.MLKEMPub`), otherwise plain X25519 ECIES (`shared.EncryptKnock`, `cryptography-manual.md` §7.4); `Tag` travels alongside in the clear
3. Bob's server (`handleKnock`) first verifies `Tag` against every known contact in the address book and against itself (self-probe) — a tag matching no one is discarded immediately, **before** any attempt at ECIES decryption (§Mutuality filter below). Only after a match does it decrypt `Payload` and deliver it to the TUI via `knockCh`
4. Bob's TUI immediately opens a popup with the invite (`showNextInviteModal`, see "Group invite popup" above), with the `groupID` and any other invitees — Bob decides whether to accept knowing the relationship keys toward Alice (and any already-known invitee) are already established from `/cnt-add`, without first having to connect
5. Bob presses `Enter` on the popup (equivalent to `/grp-join <groupID>`), which opens the WS connection to Alice's hidden service (the room's host) — `Esc` ignores it instead, without connecting

**Mutuality filter (`Tag`, before decryption).** `handleKnock` (`internal/server/handlers.go`) computes its own expected tag — `HMAC-SHA256(ECDH(own_X25519_key, declared_sender's_X25519_key), "neutrino-knock-tag")` — against every contact in its own address book and compares each one in constant time (`hmac.Equal`) with the received `Tag`: a knock whose tag matches no known contact (nor the self-probe case) is discarded without ever attempting `DecryptKnock`. After a match and a successful decryption, a defense-in-depth check verifies that `payload.FromIdentityPub` really matches the contact whose tag matched. In every case — unknown tag, payload inconsistent after decryption, or a successfully processed knock — the server replies with the exact same `202 Accepted`: the mutuality mechanism itself is not externally observable, it cannot be used to enumerate the recipient's address book by trying tags at random.

**`KnockPayload`:**
```go
type KnockPayload struct {
    Type            string       // "" | "probe_ping" | "probe_ack" | "self_probe" | "wake" |
                                  // "invite_declined" | "rel_init" | "rel_init_ack" |
                                  // "rel_identity_rotate"/"_ack" | "rel_content_rotate"/"_ack" |
                                  // "root_rotate"/"_ack" | "device_sync"/"_ack" |
                                  // "remote_nuke" | "remote_nuke_ack" | "danger_broadcast"/"_ack" |
                                  // "rel_revoke"/"_ack" (see §"remote_nuke — remote self-destruction")
    FromUsername    string
    FromIdentityPub []byte       // current Ed25519 transport pubkey
    RoomSecret      []byte       // individual secret for THIS recipient — never shared with other members (§Per-member authentication)
    FromAddr        string       // sender's network address (.onion or .b32.i2p)
    GroupID         string       // always set by /grp-invite — empty never produces a popup or a Console line, no live sender leaves it empty
    Members         []MemberInfo // full list of invited members, including the host
    MLKEMPub        []byte       // sender's current durable ML-KEM-768 encapsulation key

    // RelBootstrap carries the sender's public relationship keys toward the
    // recipient (rel_init/rel_init_ack only) — exchanged once when two
    // users become mutual contacts, see § "Relationship keys" below.
    RelBootstrap *RelBootstrapPayload `json:"rel_bootstrap,omitempty"`
    // RelRotate carries the rotation of ONE of the two relationship keys
    // toward the recipient (rel_identity_rotate/rel_content_rotate, never
    // both in the same knock), see § "Relationship keys" below.
    RelRotate *RelRotatePayload `json:"rel_rotate,omitempty"`

    // DevicePub/DeviceSig co-sign the knock with the sender's device-level
    // key (Keystore.DevicePriv/DevicePub) — verified and shown (TOFU on
    // Contact.KnownDevicePub), never blocking.
    DevicePub []byte `json:"device_pub,omitempty"`
    DeviceSig []byte `json:"device_sig,omitempty"`

    // remote_nuke protocol fields, Type "remote_nuke" /
    // "remote_nuke_ack" / "danger_broadcast". TargetDeviceID means the
    // device TO ERASE for remote_nuke (target's Keystore.DeviceID), or the
    // device THAT IS ANNOUNCING ITSELF compromised for danger_broadcast
    // (informational, no signature required); absent for remote_nuke_ack
    // (implicit — always the one replying). NukeTs/NukeSig are used only by
    // remote_nuke (signed by the AUTHORITY, RemoteNukeMsg/SignRemoteNuke)
    // and remote_nuke_ack (signed by the TARGET device,
    // RemoteNukeAckMsg/SignRemoteNukeAck) — two distinct signature schemes
    // on the same field name, disambiguated by Type.
    TargetDeviceID []byte `json:"target_device_id,omitempty"`
    NukeTs         string `json:"nuke_ts,omitempty"`
    NukeSig        []byte `json:"nuke_sig,omitempty"`
    NukeSigMLDSA   []byte `json:"nuke_sig_mldsa,omitempty"` // parallel ML-DSA-65 signature of NukeSig, remote_nuke only

    // RootRotate carries the root IdentityKey rotation-with-continuity
    // announcement (root_rotate only, nil in the ack — a plain
    // confirmation), see § "Root IdentityKey rotation with continuity".
    RootRotate *RootRotatePayload `json:"root_rotate,omitempty"`
    // DeviceSync carries the own-device-to-own-device channel
    // (device_sync/_ack) — new root material XOR a remote address-book
    // sync, never both.
    DeviceSync *DeviceSyncPayload `json:"device_sync,omitempty"`
    // RelRevoke carries the revocation of one or both relationship keys of
    // ONE device toward the recipient — Type "rel_revoke" (announcement,
    // signatures populated) / "rel_revoke_ack" (confirmation, only
    // DevicePub populated).
    RelRevoke *RelRevokePayload `json:"rel_revoke,omitempty"`
}
```

**Wire format (`KnockEnvelope`):** the `POST /knock` body is never the encrypted `KnockPayload` alone, but always:
```go
type KnockEnvelope struct {
    Tag     []byte `json:"tag"`     // HMAC-SHA256(static-static ECDH, "neutrino-knock-tag") — in the clear, §Mutuality filter above
    Payload string `json:"payload"` // encrypted KnockPayload (Base64), classic X25519 or hybrid X25519+ML-KEM-768 per the "C:"/"H:" prefix — see §7.4
}
```

**Explicit invite decline (`invite_declined`):** when the invitee presses `Esc` on the invite popup (`ignoreInvite`), besides dropping it from their own local queue (`m.pendingKnocks`) it also fires `declineInvite`, a fire-and-forget knock toward the host — same pattern as `probe_ack` (no retries beyond the ones already built into `postWithRetry`, the same underlying function `postKnockWithRetry` wraps, called here directly with `m.knockRetryDelay`; no response expected), encrypted with `k.FromIdentityPub` and sent to `k.FromAddr` (both already known from the original invite knock). Payload: just `Type`, `FromUsername`, `GroupID`. On the host's side, the `"invite_declined"` case in `case knockMsg:` looks up its own tab by `GroupID` (same lookup pattern as `"wake"`), accepts it only if `client.MemberKeyOf(k.FromIdentityPub)` is in `tab.invitedKeys`, then sets `tab.departures[<that key>] = memberDeclined` (the third `memberState` value, rendered the same as `memberLeft` — gray name, not red, in `renderGroupBar`) and shows a message in Console — the host can thus distinguish "invite not seen yet" from "explicitly declined".

**"No one has joined yet" popup (`groupNoJoinConfirmMode`/`groupNoJoinConfirmTabIdx`):** host-side only. Triggered two ways: (a) `groupNoJoinTimeout` (2 minutes, a `tea.Tick` scheduled by `cmdInvite`/`cmdRecall` alongside the connect) expires with no one having joined (`len(tab.users) <= 1`); (b) the `"invite_declined"` case detects that the last still-pending invitee has now responded (`tab.invitedKeys`, all either `memberDeclined` or in `tab.users`) — in this case the host is prompted right away, without waiting for the timeout. Both triggers go through `queueGroupNoJoinPrompt`/`showNextGroupNoJoinModal` (same queue + "self-healing" gate pattern as `showNextInviteModal`/`showNextFileOfferModal`, with the double-popup guard done via the simple `len(tab.users) <= 1` check at the moment of promotion from the queue). `Enter`/`y` closes the room (`closeTabAt`, extracted from `cmdExit` so it can close a tab other than the active one); `Esc`/`n` just dismisses it — a later decline that exhausts the remaining invitees can still bring it back.

---

## QR reading — adding a contact

`/cnt-read-qrcode` (`cmdReadQR`) and `/cnt-add` with a `nu://` URI both funnel into the same entry point, `startAddContact`/`startAddContactFromURI` (`internal/client/tui/tui.go`): after parsing, both first show a confirmation summary (`addContactConfirmMode`, username/key, `[y/n]`) and only after an explicit `y` do they ask for the local name (`addContactMode`), always showing the user what is actually about to be saved before asking for the name — identical behavior on desktop and Android. Saving immediately generates the two relationship-key pairs toward the new contact (§Relationship keys) and starts the automatic exchange.

**Choosing the source (`qrChooseMode`):** `/cnt-read-qrcode` opens an `f`/`c` popup (image file or camera). `f` leads to `qrFileMode` (the same file browser as `/grp-file-send`, with multi-selection for multi-part QR codes, then `qrscan.DecodeQRFromImage`). `c` leads to `cmdReadQRCamera`.

**Linux camera — pure-Go V4L2, no external process:** `internal/qrscan/camera_linux.go` (build tag `linux && !android`) drives `/dev/video*` via `github.com/blackjack/webcam`, verified free of `import "C"` in the vendored source (compiles with `CGO_ENABLED=0`, consistent with `build_neutrino.sh`). Alternative considered and dropped after checking the source: `github.com/vladimirvivien/go4vl`, which despite its own documentation claiming "pure Go, no cgo" actually uses `import "C"` in over 20 files (only for `linux/videodev2.h` kernel header constants, but still requires `CGO_ENABLED=1`). YUYV pixel format is preferred over MJPEG when the webcam supports both (direct luminance, byte at `row[x*2]`) — some UVC webcams omit the standard Huffman tables that the standard library's `image/jpeg` won't synthesize on its own. `internal/qrscan/camera_other.go` (`!linux || android`) is a stub returning an error — on Android the camera goes through the native Fyne/CameraX path (`cmd/androidapp`), not through this package.

**Live in-terminal preview:** `cmdReadQRCamera` launches `qrscan.ScanCamera(ctx, onFrame)` in a goroutine; `onFrame` (called for every captured frame) renders it via `renderCameraPreview` — nearest-neighbor downsampling to the grid computed by `qrCameraPreviewSize(termW, termH)`, then half-block `▀` characters with truecolor ANSI escapes (`\x1b[38;2;r;g;bm` for the top pixel, `\x1b[48;2;r;g;bm` for the bottom one — doubling effective vertical resolution) — and sends it non-blockingly on a channel with a drop-oldest-if-full pattern (`qrCameraPreviewCh`), consumed by `waitForQRCameraFrame` and shown in the popup (`qrCameraPreviewMode`, `Esc` cancels). No separate graphical window: works even over a plain SSH session. Column cap 44 (min 16), row min 8, formula `(termW-8)/2` / `(termH-10)/2`.

---

## Relationship keys

Every contact has **two** dedicated key pairs — generated at random, independent, never shared with any other contact and never derived from a common secret: the **per-relationship IdentityKey** (authenticates the handshake and the knock mutuality tag toward that contact) and the **per-relationship ContentKey** (signs and encrypts messages, files, and contact cards exchanged with them). Both are Ed25519 + an ML-KEM-768 companion (hybrid encryption) + an ML-DSA-65 companion (parallel signature, never blocking if absent).

### Generation and exchange (`rel_init`/`rel_init_ack`)

Right after a contact is saved to the address book, the client generates its own two key pairs toward them and sends a `rel_init` knock with `RelBootstrap` (its own public keys). The knock's mutuality tag (`shared.KnockDHTag`) requires both sides to already have each other as a contact: a `rel_init` that reaches its destination therefore guarantees that the sender's `Contact` already exists on the receiving side, no on-the-fly creation needed. Since each side generates and sends its own `rel_init` independently, either one may arrive first — idempotent handling: on receipt, if the local keys toward that contact don't exist yet, they're generated; the peer's public keys are updated from the received payload and a `rel_init` is always answered with `rel_init_ack`. If the receiver's own keys are not yet confirmed by the peer — its own earlier `rel_init` was dropped by the peer's mutuality filter, because the peer added it as a contact only afterwards — the ack is followed, in order, by the receiver's own `rel_init`, so the peer's ack confirms both sides in one round instead of at the next probe cycle. `Contact.RelIdentityConfirmedByPeer`/`RelContentConfirmedByPeer` only turn on BOTH upon receiving a real `rel_init_ack` (never from a spontaneous `rel_init`) — it is these two flags, not just the presence of the public keys, that decide whether to keep resending one's own `rel_init`; the retry runs off the same periodic probe cycle that already sends `probe_ping`. `Contact.ReadyDevices()` requires both flags to be true.

`cmdInvite`/`/grp-invite` and similar commands (`/grp-recall`, `/grp-reinvite`, `/grp-add-member`) read `Contact.ReadyDevices()`: if even one contact involved isn't ready yet, the invite doesn't fail with a hard error — it's queued (`queuePendingInvite`/`appstate.State.QueuePendingInvite` on Android), a fresh rel_init fires IMMEDIATELY (not a blind wait for the next periodic cycle), and the real invite restarts automatically once the contact becomes ready (`retryPendingInvites`, called from `applyRelInit` right after a `rel_init_ack`). The wait is bound by the same `InviteTimeout` already used for the invite knock (no new dedicated timeout); once it expires, the queued invite is dropped with a Console notice — expired invites are swept by the existing periodic probe cycle, not by a dedicated ticker.

**Conflict detection (`TrustDanger`).** `applyRelInit` never unconditionally applies received keys to `PeerRelIdentityPub`/`PeerRelContentPub`: if the payload proposes an `IdentityPub` or `ContentPub` (`RelBootstrapPayload`, even just one of the two) differing from an already-known value (32 bytes) in the address book, the new keys are written to `PendingPeerRelIdentityPub`/`PendingPeerRelContentPub` (never directly to `Peer*`) — the contact moves to `TrustDanger` until the user confirms with `/sec-verify` (see above, Safety Number section). The `rel_init_ack` is still sent as the protocol response (necessary so the other side isn't left waiting), but without applying the keys in the clear. If the device has no known value yet for that key (first bootstrap) or the proposed value matches what's already in the address book, the keys are applied directly — no conflict possible by construction.

### Introduced members — ephemeral relationship and promotion

A group member who was never a direct contact ("introduced" by a common host) receives an **ephemeral** point-to-point bootstrap: both sides generate a key pair valid only for the current room and exchange them over the same targeted channel already used for `sender_key` (WS frame `rel_bootstrap`, never a broadcast) — `shared.RelBootstrapPayload{IdentityPub, ContentPub, ...}`, pure TOFU, no certification against an external anchor. The ephemeral keys are destroyed when the room closes, leaving no trace.

Sending `rel_bootstrap` is not fire-and-forget: at connection time `peerSessionPubs`/`peerMLKEMPubs` may not be populated yet for that peer (the same race as the initial `sender_key` above), so the recipient, once it has applied the bootstrap, replies with `rel_bootstrap_ack` (no payload); a periodic retry cycle (`cmdRetryEphemeralRelBootstraps`/`RetryEphemeralRelBootstraps`) repeats the send toward every peer not yet `peerAcked`, and whoever already received the ack stops retrying.

`/grp-promote <username>` promotes an ephemeral member to a persistent contact — an explicit human action required on **both** sides (never automatic from just receiving the other side's request): each sends a `rel_promote` (WS frame, `shared.RelPromotePayload{TransportPub, ..., Ts, Sig, SigMLDSA}`) with their own transport key, signed against the EPHEMERAL per-relationship IdentityKey already exchanged in the bootstrap (the only common anchor available in this context — details and threat model in `cryptography-manual.md` §8.1); the recipient verifies the signature before applying the payload — and rejects it if `TransportPub` differs from the sender's member key (the root IdentityPub relayed by the server) — and, if valid, replies with `rel_promote_ack` (no payload, no automatic retry — still a human action). Once both `rel_promote`s have arrived and been verified, the new `Contact` is created reusing the four keys already exchanged in the ephemeral bootstrap (no new generation) plus the transport address just received. On Android, `chat.RoomState.SendRelPromote`/`ApplyRelPromote`/`OnFinalizePromotion` (`chat/roomstate.go`, `screens/room_tab.go`) are the direct port — reachable from the room's "⋮" menu (`screens/groupmembers.go:BuildPromoteMember`), a picker over members who aren't already direct contacts.

### Per-relationship rotation

The two relationship keys toward a contact can rotate independently, but **never at the same time** toward the same contact: the stable sibling key acts as the continuity anchor for the one being rotated. `/sec-rotate-rel-identity <contact>` and `/sec-rotate-rel-content <contact>` start the respective rotation (a picker if the argument is omitted or invalid, excluding a contact whose sibling key is already rotating). The signed payload is resent on every probe cycle until the contact confirms — indefinitely, no forced closure: each key concerns a single contact, so a rotation that never gets confirmed has no effect on anything else.

**Cross-certification**, not continuity over time: the NEW key is certified by the stable SIBLING key (never by the old version of itself) — `shared.SignRelKeyRotation`/`VerifyRelKeyRotation` (Ed25519) + `SignRelKeyRotationMLDSA`/`VerifyRelKeyRotationMLDSA` (ML-DSA-65, never blocking if absent), signing domain `"rel_key_rotate:"`. On the wire: `KnockPayload.RelRotate` (`shared.RelRotatePayload{NewPub, Sig, SigMLDSA}`), Type `rel_identity_rotate`/`rel_content_rotate` for the request, `_ack` for confirmation (the ack reuses the same struct with only `NewPub` populated — the sender compares the echo against the key currently rotating before accepting it, so a late ack referring to an already-closed rotation is never applied to a later one). The retry (same probe cycle as `rel_init`/`probe_ping`) resends the request as long as `Contact.IdentityKeyPending`/`ContentKeyPending` stays true.

### Transport key — two distinct mechanisms

The global transport key (`Keystore.IdentityKey`/`MLKEMKey`/`MLDSAKey`, derives the network address and still authenticates/encrypts the knock toward a known contact — KnockDHTag, EncryptKnock/DecryptKnock, never the WebSocket handshake) can change in two independent ways:

- **Cold regeneration, no continuity** (`Keystore.RotateTransportKey()`) — just regenerates the three keys, no pending list, no vault for the old one. Anyone who already has a relationship with this identity is still notified of an address change via the stable relationship key they already have with it (never the transport key itself); anyone with no relationship has nothing to distinguish the old/new transport key by. It has no UI trigger and no caller.
- **Rotation with continuity** (`Keystore.StartRootRotation()`, `/sec-rotate-key`) — see the "Root IdentityKey rotation with continuity" section below.

### Root IdentityKey rotation with continuity

The new root is certified toward each contact by the per-contact `RelIdentityKey` (a stable key, independent per contact, survives a root compromise — see "Per-relationship rotation" above), never by the old root itself.

`/sec-rotate-key ROTATE` (the literal argument `ROTATE` is required as explicit confirmation — a rare, wide-reaching operation: it changes one's own network address; any other argument, including none, is rejected with an error) calls `Keystore.StartRootRotation()`: generates the new triple, applies it IMMEDIATELY as current, stashes the old one in a temporary vault (`Keystore.OldIdentityKey`/`OldMLKEMKey`/`OldMLDSAKey`) and repopulates two pending lists — `RootRotationPendingContacts` (the identity key of every contact in the address book) and `RootRotationPendingDevices` (every `KnownDevices` entry). Right after, a second hidden service is published in parallel (`publishRootHiddenService`/Android `st.PublishRootHiddenService`, a new listener + a new `server.RunOnListener`, same registry/knockCh) — the old one stays active with no explicit teardown: online contacts migrate right away, offline ones when they come back.

**Announcement to contacts (`root_rotate`/`root_rotate_ack`)** — inside the same probe cycle (`probeContacts`/`Once`), for each contact still in `RootRotationPendingContacts` and online: signs `NewIdentityPub` with `dev.RelIdentityPriv` (`shared.SignRootRotation`/`SignRootRotationMLDSA`), tags the knock with the OLD root (`KnockDHTag` with `Keystore.OldIdentityPrivKeyForRotation()`) — the recipient still recognizes it, because it hasn't applied the announcement yet, no change to the mutuality filter. **Mutual guard**: if a relationship rotation (Identity or Content) is still in flight toward that device, the announcement stays queued until it closes — never two concurrent transitions on the same relationship; conversely, starting a relationship rotation while a root rotation is pending toward that contact is explicitly rejected (`tui.err_root_rotation_pending_for_contact`). On receipt, `applyRootRotate` verifies the signature against the sender's `dev.PeerRelIdentityPub`, then `shared.TsFresh`, updates the contact's `IdentityPub`/`MLKEMPub`/`MLDSAPub` (clearing `Verified`: the previous verification concerned the old key) and replies with `root_rotate_ack`. The sender removes the contact from `RootRotationPendingContacts` (`Keystore.AckRootRotationContact`) and attempts finalization (`MaybeFinalizeRootRotation`, clears the three vaults only once BOTH pending lists are empty — no time-based expiry).

**Own-device-to-own-device channel (`device_sync`/`device_sync_ack`)** — for one's own sibling devices, which share the same root IdentityKey bit-for-bit (only the published network address differs, derived per device via `Keystore.NetworkIdentityPrivKeyFor(deviceID)`): the channel doesn't go through a contact, it addresses the target device's derived address directly, trying both the one from the new root and the one from the old (`Keystore.OldNetworkIdentityPrivKeyForRotation`) — until the sibling adopts, its hidden service stays published at the address derived from the old root, same principle as the `remote_nuke` fan-out below. It carries EXACTLY one of two things (never both, `shared.DeviceSyncPayload`): the new private material in full (propagation — the sibling adopts it with `Keystore.AdoptRootRotation`, idempotent, and republishes its own hidden service in turn, behaving exactly like the device that started the rotation), or an explicit remote address-book sync (`/sec-device-sync <device>` on desktop — identified by label or a hex `DeviceID` prefix, the command lists known labels in Console if the argument is omitted or doesn't match one, no interactive picker there; a real picker dialog on Android — reuses `indoor.SyncPayload`, the same payload used by LAN multicast sync, here over this transport).

**`remote_nuke` fan-out addressing**: the target's root address (`ref.IdentityPub`) is correct only if that identity is hosted as the primary device; for an additional device the real hidden service is at the address derived via `NetworkIdentityPrivKeyFor(rec.DeviceID)`. The fan-out tries both candidates, on both platforms.

Commands, both platforms: `/sec-rotate-key ROTATE` (the literal argument `ROTATE` required as explicit confirmation) and `/sec-device-sync <device>` (see above for the desktop/Android difference — "Rotate network identity"/"Sync address book with a sibling device" buttons in Settings→Security on Android).

---

## remote_nuke — remote self-destruction

Self-destruction of a device outside physical control (stolen/seized/lost but still on and reachable over the network). No separate guardian identity: the AUTHORITY is anyone who possesses, in their own keystore file, the private key of any identity also duplicated on the target device (`neutrino restore`, same 24 words) — possession = authorization, no list of "authorized devices" to consult. Desktop: `/sec-remote-nuke`, `/sec-indoor-sync`, `/sec-devices`, `/sec-device-label`. Android: same logic in `cmd/androidapp/security/{remotenuke,indoorsync}.go`, reached from Settings → Security — the five knock types introduced by this section are handled explicitly on both platforms (`cmd/androidapp/security/knock.go`: dedicated cases for `remote_nuke`/`remote_nuke_ack`/`danger_broadcast(_ack)`/`danger_end(_ack)`, never left to fall into the `default` case, which would treat them as a fake group invite).

### Device: identifier and signing key

A "device" is the keystore FILE, not the hardware — `Keystore.DeviceID`/`DevicePriv`/`DevicePub` are file-level (same treatment as `duress`, not per-identity): generated once in `New()`, shared by every sibling identity in the same file (`AddIdentity` always inherits them from `existing[0]`, discarding whatever was generated for the new identity). They never rotate with `IdentityKey`/`MLKEMKey` — a device survives an identity rotation. `LoadAll` backfills `DeviceID` for a pre-existing keystore (version < 4) and **persists it immediately** (`list[0].Save(...)`, before anything else could exit without saving) — unlike the `IdentityKey`/`MLKEMKey` backfill, a `DeviceID` regenerated on every start would silently break both `remote_nuke` targeting and recognition via indoor sync.

`Keystore.DeviceLabel` (same file-level treatment, propagated to siblings by `SetDeviceLabel`) is the name the user chose to recognize a device among two or three otherwise indistinguishable ones (only `DeviceID`, 16 hex bytes) — asked in the wizard when a new file's first identity is created, always renamable with `/sec-device-label`.

`DevicePriv` co-signs every outgoing chat message (`Client.Send`, `internal/client/client.go`): `sealedMsg` carries a `DP` field (the device pubkey, INSIDE the ciphertext, never in cleartext on the wire — avoids exposing a stable per-device identifier to the relay server), while `device_sig`/`device_ts` travel outside the ciphertext but are verified against the just-decrypted `DP` in the SAME message — no network bootstrap needed, unlike the per-relationship ContentKey (§ "Message signing"), which has to already be established with that contact beforehand to sign/verify:

```go
func DeviceSigMsg(ciphertext, ts string) []byte   // "device_sig:" ‖ ts ‖ ":" ‖ ciphertext
func SignDeviceSig(devicePriv ed25519.PrivateKey, ciphertext, ts string) []byte
func VerifyDeviceSig(devicePub ed25519.PublicKey, ciphertext, ts string, sig []byte) bool
```

Never blocking: only an informational on-screen tag (`[DEV:xx]`/`[DEV:new]`, same treatment as `[REL:xx]`) and a TOFU update of `Contact.KnownDevicePub` (conceptually distinct from `Keystore.KnownDevices` below: that one is for YOUR OWN identity/targeting, this one is for recognizing a CONTACT's device).

### remote_nuke protocol — command and ack

`KnockPayload` (§ Knock above) gains five fields: `DevicePub`/`DeviceSig` (co-signature of the knock, same principle as chat messages — never a bootstrap problem since the whole payload is already inside the knock's encrypted envelope), `TargetDeviceID`, `NukeTs`, `NukeSig`.

```go
const TsFreshnessWindow = 5 * time.Minute  // ±, generic freshness check reused here — not nuke-specific

func RemoteNukeMsg(targetDeviceID []byte, ts string) []byte      // "remote_nuke:" ‖ targetDeviceID ‖ ":" ‖ ts
func SignRemoteNuke(authorityPriv ed25519.PrivateKey, targetDeviceID []byte, ts string) []byte
func VerifyRemoteNuke(authorityPub ed25519.PublicKey, targetDeviceID []byte, ts string, sig []byte) bool

func RemoteNukeAckMsg(targetDeviceID []byte, ts string) []byte   // "remote_nuke_ack:" ‖ targetDeviceID ‖ ":" ‖ ts
func SignRemoteNukeAck(devicePriv ed25519.PrivateKey, targetDeviceID []byte, ts string) []byte
func VerifyRemoteNukeAck(devicePub ed25519.PublicKey, targetDeviceID []byte, ts string, sig []byte) bool
```

`remote_nuke` is signed with the Ed25519 key of an IDENTITY (the authority); `remote_nuke_ack` is signed with the target's DEVICE-level key — two conceptually different keys, never the same closure client-side (`TUIParams.SignRemoteNuke` vs `SignRemoteNukeAck`).

**Verification on the target side** (`handleRemoteNuke`, `internal/client/tui/tui.go`): `TargetDeviceID` must match the local `Keystore.DeviceID`; `NukeTs` must pass `shared.TsFresh` (generic freshness check, ±`TsFreshnessWindow`); `NukeSig` must verify against **any one** of the keys in `Keystore.AllAuthorityPubKeys()` (every identity in the file, current AND old during an ongoing rotation) — no list of "authorized devices" to consult, possession of the private key is itself the proof.

**Multi-identity fan-out** (`cmdRemoteNukeFanOut`): the sender doesn't know which of the identities present on the target device will be reachable at that moment, so the command (with `NukeTs`/`NukeSig` **always fresh**, regenerated on every call — necessary for retries days apart, see below) is sent in parallel to `AddressFromPub(ref.IdentityPub)` for each `DeviceRecordInfo.SiblingIdentities` (populated from `Keystore.KnownDevices`, learned via indoor sync — see below), with retry/backoff (`postWithRetry`, 3 attempts, doubling backoff from `knockRetryDelay`). **Stop at the first ack**: a shared `context.WithCancel` per `hex(TargetDeviceID)` (`model.remoteNukeCancels`/`remoteNukeMu`, a `*sync.Mutex` not a direct value — `model` is copied by value throughout bubbletea, an embedded-by-value mutex would break mutual exclusion) is cancelled by `handleRemoteNukeAck` as soon as the first `remote_nuke_ack` arrives, stopping every other attempt still in flight toward the other addresses.

**Sequence on the target** (`executeRemoteNuke`, time budget `remoteNukeExecuteTimeout = 20s`): `broadcastDangerEnd` (see below) → `sendRemoteNukeAck` → returns `remoteNukeExecutedMsg{}`, which sets `model.nukeOnExit = true` — same flag, same downstream handling as `cmdNukeX`: the overwrite-and-swap sequence (§ "Multiple identities" above), never the deletion of anything, and the process never exits.

### Persistence and retry

The target can stay unreachable for days/weeks, a single attempt isn't enough; making the warning to contacts depend on successful execution on the target would mean that, if the device never reconnects, no one is ever warned. Same pattern already used by the periodic probe cycle for the rest of its routine traffic (`probe_ping`, `rel_init`, § "Relationship keys") — persistent queue + retry via the normal `probeContacts` cycle, not a new dedicated timer.

**Command toward the device** — `Keystore.PendingRemoteNukes []PendingRemoteNuke{TargetDeviceID, RequestedAt}`:
```go
func (ks *Keystore) AddPendingRemoteNuke(targetDeviceID []byte)                    // idempotent, doesn't reset RequestedAt
func (ks *Keystore) RemovePendingRemoteNuke(targetDeviceID []byte) bool            // on the first ack, handleRemoteNukeAck
func (ks *Keystore) PendingRemoteNukeTargets() []DeviceRecord                      // resolved against KnownDevices, for the fan-out
```
`cmdRemoteNuke` (confirming `/sec-remote-nuke`) registers the queue AND immediately starts `cmdRemoteNukeFanOut`; `retryPendingRemoteNukes` (called from `Init()`, with the same initial delay as circuit warmup — otherwise `postWithRetry`'s mere 3 attempts would run out before Tor/I2P even have a circuit ready) redoes the fan-out for every target still queued on every subsequent start, with `NukeTs`/`NukeSig` regenerated fresh each time.

**Warning to contacts — two independent queues, same scheme**:
```go
type DangerBroadcastPending struct { TargetDeviceID []byte; IdentityPubs [][]byte }

Keystore.PendingDangerBroadcasts []DangerBroadcastPending  // preliminary — "danger_broadcast"
Keystore.PendingDangerEnds       []DangerBroadcastPending  // final       — "danger_end"

func (ks *Keystore) SetDangerBroadcastPending/SetDangerEndPending(targetDeviceID []byte, pubs [][]byte)
func (ks *Keystore) ConfirmDangerBroadcast/ConfirmDangerEnd(targetDeviceID, pub []byte) bool
```
`probeContacts` (`internal/client/tui/tui.go`) builds, on every cycle, two maps `dangerBroadcastPendingByPub`/`dangerEndPendingByPub` (contact identity key → `[][]byte` of `TargetDeviceID`, a contact can appear in more than one queue) and — for every contact found ONLINE that cycle — sends `sendDangerMsgSingle(msgType, ...)` (fire-and-forget, single attempt, no retry of its own: the retry-over-time is the probe cycle itself, exactly like `sendProbePing`) for each `TargetDeviceID` still pending for that contact.

The recipient (`handleIncomingDangerMsg(k, isEnd)`, a single handler for both types) shows a Console line and replies with the matching ack (`danger_broadcast_ack`/`danger_end_ack`, `sendDangerAckMsg`, this time with retry+backoff — a failed delivery mustn't leave the sender retrying an already-received warning forever). `handleIncomingDangerAck(k, isEnd)` removes the contact from the matching queue both in memory (`model.pendingDangerBroadcasts`/`pendingDangerEnds`) and on disk (the two closures above).

**Arrival-order guard**: `danger_end` (a single hop, target→contact) can arrive BEFORE `danger_broadcast` for the same device (which makes a double round trip, authority→target→ack→authority→contact). `model.dangerEndSeen map[string]bool` (keyed by `hex(TargetDeviceID)`) records every `danger_end` already seen; a preliminary `danger_broadcast` arriving afterward for the same device doesn't produce a misleading second Console line ("in progress" after "confirmed destroyed"), but the ack is still sent — the sender's queue closes normally.

**Who sends `danger_end`, and with what coverage:**
- **The target itself**, inside `executeRemoteNuke`, right before overwriting its own real contacts and swapping to the decoy identity: `broadcastDangerEnd(identities []AllIdentityContactsInfo, ...)` iterates **every** sibling identity in the file (`AllIdentitiesContacts`, a closure built in `cmd/main.go` via `Keystore.SiblingKeystores()` — the ONLY place that exposes the siblings' full `*Keystore` values, never to `internal/client`), sending to each contact with the signature/tag of its OWN owning identity (a contact of I2 must be able to verify `FromIdentityPub` as I2, not as I1). A single attempt per contact, shared time budget `remoteNukeExecuteTimeout` — no queue, right before the device overwrites its own contacts and swaps to the decoy identity.
- **The authority**, upon receiving `remote_nuke_ack` (`handleRemoteNukeAck` calls `cmdRemoteNukeEndBroadcast` → `cmdRegisterDangerQueue(targetDeviceID, isEnd=true)`), as a safety net toward its OWN address book only (the identities it possesses and has synced via indoor sync — never ones it has never duplicated) — persistent queue, covers whoever was offline at the exact instant the target fired its own direct `danger_end`.

`cmdRegisterDangerQueue(targetDeviceID, isEnd)` is the function shared by both queues (preliminary/final): builds `usernames` from the current valid contacts, registers the queue (memory+disk), and immediately triggers a silent `probeContacts`.

### "Indoor" (LAN) synchronization

Package `internal/indoor/` — two instances that ALREADY possess the same identity (duplicated via `neutrino restore`, offline channel) discover each other on the LAN and exchange address books plus mutual registration as known devices. No ECDH for the session key: both sides LITERALLY hold the same Ed25519 private key — the session is independently derivable on both sides after a challenge/response that proves mutual possession.

**Discovery — proprietary UDP multicast, not mDNS** (consistent with the "pure Go, zero runtime dependencies" style already applied elsewhere, e.g. direct V4L2 instead of `zbarcam`):
```go
const MulticastAddr = "239.255.42.99:42424"  // IANA "organization-local" scope, never routed beyond the LAN
const TCPPort       = 42425                   // the real session, after multicast rendezvous
const SyncWindow      = 60 * time.Second      // duration of one /sec-indoor-sync window
const AnnounceInterval = 2 * time.Second
```
`AnnouncePacket{Version, IdentityHash, InstanceID}` — **never the identity in the clear**, only `IdentityHash = SHA-256(IdentityPub)[:16]` (anyone on the same network can see the announcement, so it must be limited to whoever already knows that specific identity). `InstanceID` (8 random bytes per session) lets a process discard its own announcements (multicast loopback is often enabled by default; two test processes on the same machine still share the same identity).

**Three-step challenge/response** (`runChallengeResponse`, `session.go`) over a TCP connection:
```
A → B: nonce_A
B → A: nonce_B, Sign(identity_priv, nonce_A ‖ nonce_B)
A → B: Sign(identity_priv, nonce_B ‖ nonce_A)
session_key = HKDF-SHA256(identity_priv, salt=nonce_A‖nonce_B, info="neutrino-indoor-v1")
```
The reversed order of the two nonces in the second signature (`nonce_B ‖ nonce_A`, not `nonce_A ‖ nonce_B`) prevents one side's signature from being reusable as the other's, even in the edge case where the two nonces happened to coincide. `initiator` (whoever received the announcement and connected) only distinguishes message order on the wire, no other role asymmetry — `VerifyChallenge` fails with "not the same identity" if the peer doesn't actually hold the same private key.

**Encrypted payload** (`exchangePayload`, AES-256-GCM via `shared.Encrypt`/`Decrypt`, AAD `"neutrino-indoor-payload-v1"`, 4-byte big-endian length-prefixed framing, cap `maxFrameLen = 4 MiB`):
```go
type SyncPayload struct {
    Contacts []keystore.Contact
    Device   keystore.DeviceRecord  // SiblingIdentities: ALL of the sender's identities at that moment, not just the shared one
}
```
Each side sends its OWN `SyncPayload`. The receiver applies `Keystore.MergeContacts` (the same function already used by `sync import`) and `Keystore.AppendKnownDevice(peer.Device)` (upsert by `DeviceID` — a later sync fully overwrites `SiblingIdentities`, never a field-by-field merge: the identities present on a device change over time).

`/sec-indoor-sync` (`cmdIndoorSync`) blocks until the first successful exchange or `SyncWindow` expires; `model.indoorSyncing` prevents two overlapping windows (both would bind the same TCP port). `/sec-devices` (`cmdDevices`) lists `Keystore.KnownDevices` for the current identity, read-only.

---

## Hybrid PQC network identity (ML-DSA-65)

Hybridization of the **network** identity (`Keystore.IdentityKey`, Ed25519 — derives the Tor/I2P address, signs `RemoteNukeMsg`, authenticates the knock's mutuality tag and encryption toward a known contact). The WebSocket handshake, instead, is authenticated by the per-contact relationship keys (§ "Relationship keys"). Covers post-Q-day impersonation/forgery on these operations, not harvest-now-decrypt-later (already covered by the hybrid post-quantum scheme of handshake/`sender_key`/knock — see `cryptography-manual.md` §4.2/§7.3/§7.4). Full cryptographic detail in `cryptography-manual.md` §8bis. The same two primitives (ML-KEM-768/ML-DSA-65) are also used for the per-contact relationship keys (§ "Relationship keys") — this section covers only the global network identity.

### Key (keystore)

`Keystore.MLDSAKey` (32-byte seed, `github.com/cloudflare/circl/sign/mldsa/mldsa65`, promoted to a direct dependency in both Go modules) — generated fresh/random in `New()` (not derived from the BIP-39 seed, the same choice already made for `MLKEMKey`). Transport key: `RotateTransportKey()` regenerates it together with `IdentityKey`/`MLKEMKey`, a simple replacement with no vault for the old one (§ "Relationship keys", Transport key). One-shot migration for pre-existing keystores: `version` 4→5.

```go
func (ks *Keystore) MLDSAPrivKey() *mldsa65.PrivateKey     // nil-safe, reconstructed from MLDSAKey via NewKeyFromSeed
func (ks *Keystore) MLDSAPubKey() *mldsa65.PublicKey
func (ks *Keystore) MLDSAPubBytes() []byte                 // 1952 packed bytes, for URI/QR
func (ks *Keystore) AllAuthorityPubKeysMLDSA() []*mldsa65.PublicKey  // all sibling identities — remote_nuke
```

`Contact.MLDSAPub []byte` (`json:"mldsa_pub,omitempty"`) — learned on the first URI/QR exchange (see below), updated by `root_rotate` on a root IdentityKey rotation.

### Parallel signatures

`SignRemoteNukeMLDSA` (`internal/shared/crypto.go`) reuses the same message already signed in Ed25519 (`RemoteNukeMsg`) — two independent signatures, not an RFC 9980 composite. Carried in the same encrypted `KnockPayload`: `NukeSigMLDSA` (`omitempty`). Relationship keys get the same treatment with their own dedicated functions (`SignRelKeyRotationMLDSA`/`SignRelMsgMLDSA`, § "Relationship keys"/"Message signing"). Never blocking: a missing or failed verification falls back to the existing Ed25519-only check.

### URI/QR propagation + multi-QR

Optional third positional segment: `nu://username/ed25519B64[/mlkemB64][/mldsaB64]`. `parseNuURI` (desktop, `tui.go`) / `parsePeerURI` (Android, `screens/room_picker.go`) dispatch on the **decoded segment's length** (`nuURIMLDSAB64Len`/`peerURIMLDSAB64Len = 2604`, base64 of 1952 bytes), not a fixed position — the same scheme already used for the ML-KEM segment. Both explicitly reject any leftover text after the recognized segments, with an explicit error.

With all three PQC segments present the URI exceeds a single QR frame's capacity (~4300 characters against a practical threshold of 2953 bytes at error-correction level L). Direct reuse of the chunking mechanism already used for backup/sync:

```go
func ChunkBlob(data []byte) ([][]byte, error)
func AssembleQRMulti(chunks [][]byte) ([]byte, error)            // already existed, unchanged
func IsMultiQRChunk(data []byte) bool                            // new — recognizes an NTR3 chunk without reassembling it
func QRMultiPartTotal(data []byte) (part, total int, ok bool)    // new
```

`printAndSaveQR` (desktop, `cmd/main.go`): if `len(content) <= 2953` uses the unchanged single-frame path, otherwise chunks it and saves one `-partN.png` file per part, with the same interactive loop already used by `backupSaveQR`. On the reading side, `handleQRDecoded` (desktop, `tui.go`) accumulates chunks in `model.qrMultiChunks`/`qrMultiTotal`, shows progress (`tui.qr_multi_progress`) and reopens the picker until all parts have arrived, then calls `AssembleQRMulti` and proceeds as a single-frame URI.

Android: `BuildShare`/`BuildAddIdentityDone` (`screens/share.go`/`add_identity.go`) apply the same scheme on the write side (a "Show QR" button that iterates the parts via `showBackupQR`, generalized with a `filePrefix` parameter instead of the previous hardcoded `"neutrino-backup-"`). On the read side, `showQrSourceDialog` (`screens/qrread.go`) accumulates chunks internally (`handleDecoded`/`scanNext` closures, no new field in `appstate.State` — state scoped to the single scan session) and calls the original `onURI` callback only once, once reassembly is complete.

### Optional per-room signing on chat messages

Signing every message would cost ~3.3KB per signature (`mldsa65.SignatureSize`) — not justifiable as a default. A **mutable** per-room toggle, unlike `ratchetDH` (decided once at construction):

```go
func (c *Client) SetPQCSign(on bool)   // internal/client/client.go, guarded by pqcMu
func (c *Client) PQCSign() bool
```

`Client.signMLDSA func(ciphertext []byte, ts string) []byte` is a closure always present after the keystore v5 migration (passed to `New()` as the last parameter, same principle as `signDeviceSig`: `internal/client` never sees the raw private key) — kept separate from the policy of using it (`pqcSign`). When `signMLDSA != nil && c.PQCSign()`, `Client.Send` attaches `pqc_sig`/`pqc_ts` external to the ciphertext, the same scheme as `device_sig`/`device_ts`:

```go
func PQCSigMsg(ciphertext, ts string) []byte   // "pqc_sig:" ‖ ts ‖ ":" ‖ ciphertext
func SignPQCSig(priv *mldsa65.PrivateKey, ciphertext, ts string) []byte
func VerifyPQCSig(pub *mldsa65.PublicKey, ciphertext, ts string, sig []byte) bool
```

Receiver-side verification (`parseMessage`, `tui.go` / `dispatch.go` on Android): against `Contact.MLDSAPub` (contact resolved from the sender's member key, not a field inside the message — unlike `device_sig`, which is self-verifying), never blocking. A `[PQC]` tag is shown next to the sender's name on EVERY message, always present (never omitted): green if this message carries an active ML-DSA-65 signature — for one's own message, simply whether `pqc_sig` was in the frame at send time; for another's message, only if `pqc_sig` verifies against `Contact.MLDSAPub` — red in every other case, including a not-yet-known sender or one without a known key (never a false positive).

Command `/sec-pqc-sign on|off` (`CmdPQCSign`, `internal/client/commands.go`) — room-scoped like `/grp-reconnect` (`tab.isStandardTab()` rejects Console/Contacts/Groups/Network/Files), confirmation shown inline in the room itself (`localTab`, not Console — a local conversation state, not an error). Android: room "⋮" menu entry (`pqcSignMenuLabel`, `screens/room_tab.go`), same dynamic label reflecting the current `room.Cli.PQCSign()` state, action via `room.AppendLine(&chat.Line{System: true, ...})`. On both platforms, toggling it also produces a broadcast announcement (`pqcToggleAnnouncePrefix`, same regular SenderKey channel, same scheme as the `groupMemberAddedPrefix` system prefix — never a new wire frame): every other room member sees a system line informing them of the change, instead of having to infer it by watching later messages' tags.

Each message line (desktop only) is composed of two lines: a header (timestamp, name, all tags, ACK) on top, the message text indented below — `ansi.Wrap` (`github.com/charmbracelet/x/ansi`, already used for viewport wrapping) honors embedded `\n` characters, wrapping each logical line independently. Android does not mirror this format: per-message rendering is already separate widgets (`RichText` segments), not a single string to split.

---

## Backup, sync, and secure deletion

### BIP-39 seed and identity key

The Ed25519 identity seed is the **first 32 bytes** of `IdentityKey` (the Go private key has layout `seed[32] || pubkey[32]`). These 32 bytes are encoded into 24 BIP-39 mnemonic words via `github.com/tyler-smith/go-bip39`:

```
words = bip39.NewMnemonic(IdentityKey[:32])
seed   = bip39.EntropyFromMnemonic(words)   // verifies the built-in BIP-39 checksum
```

The checksum is 8 bits (1/32 of the seed), encoded in the last word. The words do not change unless the key rotates.

### Binary formats

| Magic | Length | Content | Description |
|---|---|---|---|
| `NTRINO01` | 8 B | `magic[8] \| nonce[12] \| AES-256-GCM(json(keystore))` | Backup file (uncompressed) |
| `NTRINO02` | 8 B | `magic[8] \| nonce[12] \| AES-256-GCM(gzip(json(keystore)))` | Single QR export (gzip) |
| `NTR3` | 4 B | `magic[4] \| part[1] \| total[1] \| session_id[4] \| data[≤1500 B]` | Multi-QR chunk (backup or sync) |
| `NTRINO03` | 8 B | `magic[8] \| nonce[12] \| AES-256-GCM(gzip(json([]Contact)))` | Address book sync (contacts only) |

The AES key for `NTRINO01`/`NTRINO02` is derived with:
```
key = HKDF-SHA256(seed, salt=nil, info="neutrino-backup-v1")
```

The key for `NTRINO03`:
```
key = HKDF-SHA256(seed, salt=nil, info="neutrino-sync-v1")
```

Both devices share the same seed (from the same identity), so the sync key is automatically compatible without any additional secret exchange.

### Multi-QR chunking

The maximum capacity of a QR code (level L) is 2953 binary bytes, but `ChunkBlob` (`internal/keystore/backup.go`) targets a much lower ≤1500-byte segment, well below that ceiling. This isn't a safety margin against corruption — the chunks are never damaged in transit — it's margin for `qrscan.EncodeVerified` (`internal/qrscan/encode.go`): encoding a segment near the 2953-byte ceiling selects a QR version right at the format's hard maximum (40), leaving the self-verify-and-retry mechanism almost no room to pick a different version/mask if the one go-qrcode auto-selects happens to be one the decoder struggles with (measured directly: a real, content-dependent gozxing limitation at near-maximum versions, roughly 5-10% of otherwise-valid renders per version). At ≤1500 bytes a full identity's segments land around version 31 instead of 39, leaving enough versions of retry headroom to measure zero failures across hundreds of real round-trips.

Bytes are split EVENLY across however many segments the ≤1500-byte ceiling requires (not greedily filled segment-by-segment) — every segment ends up a similar size, not one pinned at the ceiling and the rest small:

```
session_id = 4 random bytes                 // matches chunks of the same session
total      = ⌈len(data) / 1500⌉
chunkSize  = ⌈len(data) / total⌉             // even split, never exceeds 1500
chunk[i]   = "NTR3" || byte(i) || byte(total) || session_id || data[i*chunkSize:(i+1)*chunkSize]
```

`AssembleQRMulti` checks the magic, uniform session_id, reorders by `part`, and concatenates the payloads.

The `ChunkBlob` function is shared by `ExportQRMulti` (backup) and `ExportSyncQRMulti` (sync).

### Optical transfer via animated QR (`internal/fountain`, `internal/qroptical`)

An alternative to the static QR codes above, for a purely optical channel (screen → camera, no network involved): the sender shows a continuous stream of changing QR codes (~3/s, `qrOpticalFrameDelay`), the recipient captures frames with a camera until it has gathered enough to reconstruct the payload — it tolerates lost, duplicate, or out-of-order frames, with no need to capture every single one or in any particular order.

`internal/fountain` implements **LT codes** (Luby Transform, robust soliton distribution — Luby 2002, c=0.1, δ=0.05) in pure Go: a peeling decoder and its own deterministic PRNG (`splitmix64`, not `math/rand`, whose exact sequence for a given seed isn't guaranteed stable across toolchain versions — a real risk for a wire format meant to stay compatible over time). Typical overhead is ~1.1× the number of blocks for large payloads, higher (1.4-1.9×) for small payloads (few blocks) — a known property of LT codes at low *k*, not a defect.

`internal/qroptical` provides `Sender`/`Receiver` on top of `internal/fountain`: every frame is plain ASCII text (prefix `NQF1:` + base64 of a binary header + symbol) — never raw bytes, because the QR decoding library in use doesn't guarantee preserving bytes beyond 7-bit ASCII.

**Two uses, two different encryption keys** (fountain coding by itself encrypts nothing — it transports payloads already encrypted by the caller):
- **Generic file transfer** (`neutrino qr send/receive`, Android "Send/Receive file via QR" screens) — the payload is encrypted with a password chosen by the sender and shared out of band (Argon2id + AES-256-GCM, same parameters as the keystore), because the optical channel is by definition visible to anyone watching the screen during transmission.
- **Backup/sync via animated QR** (`neutrino backup`/`restore`, `sync export`/`sync import --camera`, Android "animated QR" buttons) — no additional password: the payload is already the blob encrypted with the identity's 24 BIP-39 words (`Keystore.ExportQRAnimated()` for backup — the same `encryptCompressed` as `ExportQR`/`ExportQRMulti`, without the 2953-byte single-QR limit; `Keystore.ExportSync()`, already unbounded, for the address book). On receive, the reconstructed payload goes directly to `ImportFromBackupFile`/`ImportSync`, the same functions used by the static-QR path.

On desktop, `sendAnimatedQRLoop`/`receiveAnimatedQR` (`cmd/main.go`) are the shared core for all four variants (generic file, backup, sync export, sync import); on Android, `runQRSendAnimationRaw`/`startQRReceiveRaw` (`cmd/androidapp/screens/qroptical.go`) play the same role. Reception on Android goes through `camera.ScanContinuous` (dedicated Java Activity, `CameraQrActivity`), with automatic closing when `qroptical.Receiver.Done()` signals it has gathered enough frames.

### MergeContacts — merge algorithm

Deduplication by `IdentityPub` (the contact's Ed25519 key, 32 bytes):

- If the contact **is not present** in the local keystore → it is added
- If the contact **is already present** → only empty or differing fields are updated:
  - `LocalName`: if the imported file has a non-empty, different value → the imported file wins
  - `MLKEMPub`: same rule (non-empty and different → the imported file wins)

No contact is ever deleted, and no other field (including `Verified` and the relationship keys) is touched by the merge. `Username` (network identity) is never overwritten.

### Self-destruction — overwrite and identity swap, never file deletion or process exit

No *trigger* (`/nukex`, the automatic `time` trigger, `remote_nuke` on the target side, the duress PIN at the interface lock) deletes the keystore file or ends the process — Android can't delete its own installed app, and the design generalizes that constraint to every platform. The one deliberate, explicitly-confirmed exception is `/sec-clear-all` (see below), which is not part of this trigger grid at all. `runOnce` (`cmd/main.go`) wraps its own body in a `for {}` loop precisely to make the trigger case possible without a password re-prompt or a network restart:

```go
func RunTUI(params TUIParams) (nukeOnExit bool, duressWipeOnExit bool, clearAllOnExit bool, err error)
```

`/nukex` sets `nukeOnExit`; the duress password recognized at the interface lock on an already-active session sets `duressWipeOnExit` (via `armDuressWipe`, `internal/client/tui/tui.go`); `/sec-clear-all`, confirmed, sets `clearAllOnExit` (via `cmdClearAll`) — all three `tea.Quit` out of the TUI, but from here on only the first two are handled identically:

```go
for {
    // ... unlock, publish hidden service, run the server, run the TUI ...
    nukeOnExit, duressWipeOnExit, clearAllOnExit, err := tui.RunTUI(tui.TUIParams{ ... })
    if clearAllOnExit {
        netCleanup()
        wipeConfigDir(ksPath) // deletes the file — the one case that does
        os.Exit(0)
    }
    if nukeOnExit || duressWipeOnExit {
        // Pod spawn happens here, while ks is still the real identity's own
        // (pre-overwrite) contact list — see "Salvation pod" below.
        runNukeOverwriteInPlace(session, ksPath) // OverwriteAllContacts + SaveWithDuress
        session, err = session.PromoteDuress()
        if err != nil { netCleanup(); os.Exit(0) } // should never happen in practice
        continue // same node/ctx, same TCP/Tor/I2P circuits, no re-authentication
    }
    netCleanup()
    return
}
```

`node`/`ctx`/`netCleanup`/the lock-watcher goroutine are all set up once, OUTSIDE the loop: a `continue` never triggers `defer node.Close()`, so Tor/I2P genuinely never restart across a swap. The loop republishes a new hidden service for the newly-promoted decoy identity and runs the TUI again on the same already-open node. The real identity's own hidden service from before the swap is deliberately left running, abandoned — explicitly tearing it down would itself be a new, observable, correlatable signal ("this onion address went dark at this exact instant"), worse than leaving an abandoned service answering to an empty contact list.

`runNukeOverwriteInPlace` (`cmd/main.go`) is the data-mutation half only — no process control:

```go
func runNukeOverwriteInPlace(session *keystore.UnlockedSlot, ksPath string) {
    duressIdx, duressKi, duressPlain, emptied, err := session.OverwriteAllContacts()
    if err == nil && emptied > 0 {
        _ = session.SaveWithDuress(ksPath, duressIdx, duressKi, duressPlain)
    }
}
```

It never prints anything: an anti-forensic wipe visible on screen or left in scrollback/a log would itself be evidence that it just happened.

**`secureDelete`/`secureWipeDirFiles`** (10-pass random overwrite + `fsync` + `os.Remove`, `secureWipeDirFiles` deciding which files via `os.ReadDir` on the keystore's directory) back `wipeConfigDir(ksPath string)` (`cmd/main.go`). It's wired to exactly one place, since the behavior grid above forbids `nuke`/`nukex`/`remote_nuke`/duress from ever deleting the file: `/sec-clear-all`, confirmed, outside the trigger grid entirely (see `clearAllOnExit` above). Falls back to just the keystore and its config file if enumerating the directory fails, then removes the now-empty directory itself. Mirrors `cmd/androidapp/screens/nuke.go`'s `wipeConfigDir` (same name and signature, no directory-removal step there — the app's private directory is owned by the OS, never removed by the app itself).

```go
func wipeConfigDir(ksPath string)
func secureDelete(path string, passes int) error
```

> **SSD limitation:** hardware wear leveling can map logical writes onto different physical blocks, potentially leaving previous data recoverable even after an overwrite. On a traditional HDD, overwriting is effective.

### Salvation pod — revoking relationship keys toward contacts

The overwrite-and-swap above is local: it says nothing to the device's own contacts, who would otherwise keep trusting the now-abandoned identity's relationship keys indefinitely. A short-lived, self-exec'd child process (the "pod") delivers the already-signed `rel_revoke` certificates to every contact, fire-and-forget, while the parent keeps running as the decoy identity — see `cryptography-manual.md` § "Salvation pod" for why no private key ever crosses into it.

```go
func BuildPodSnapshot(identities []*Keystore, addressFromPub func([]byte) string, proxyAddr string, netKind transport.Kind) PodSnapshot  // internal/keystore/pod_snapshot.go
func spawnPod(exePath string, args, env []string, snap PodSnapshot) error                                                               // cmd/pod_spawn.go
func runPod()                                                                                                                            // cmd/pod.go, entered via the hidden "__pod" argv[1]
```

`BuildPodSnapshot` runs on the parent, BEFORE `OverwriteAllContacts` empties the identity's contacts, and collects — per contact — its resolved address, the pre-signed `rel_revoke` certificates, and the DH mutuality tag the recipient's server checks before decryption (`PodRevokeTarget`). `spawnPod` re-execs the same binary (`exec.Command(exePath, "__pod")`), writes the JSON snapshot to the child's stdin over a pipe — never argv, never an environment variable, both readable by unrelated processes via `/proc` — and never waits for it (reaped in a separate goroutine). The parent proceeds immediately to `OverwriteAllContacts`/`PromoteDuress` without waiting for the pod either.

`runPod` reads the snapshot from stdin and calls `deliverPodRevokes`, which sends every target's `rel_revoke` in parallel over the network inherited from the parent (SOCKS5 for Tor, a dedicated transient SAM session for I2P — `podDialer`, `internal/transport.DialerSAM`) — no ack is ever awaited, since a genuine one would require decrypting a reply with the real private key, which the pod never holds and the parent has by then already overwritten. Bounded retries (`podRetryDelay`, 2s) within `podTimeout` (~20s), then `os.Exit(0)`. If the parent's own session never had a live Tor/I2P circuit to inherit — a direct decoy-password login, with no prior real session in that process run — `podDialer` instead bootstraps its own node cold (`transport.Start`, budget `podColdBootTimeout`, ~90s) rather than giving up.

**Scope, deliberately narrow**: the pod only ever reaches CONTACTS. Sibling devices sharing the same identity file are notified through the pre-existing `device_sync`/`MarkDeviceNuked` channel instead, run by the PARENT itself, never the pod — a genuine `device_sync_ack` does require the real private key, which only the parent (briefly, before the swap) still has.

### Blocking OS signals

`RunTUI` intercepts `os.Interrupt` (SIGINT), `syscall.SIGTERM`, and `syscall.SIGHUP` with `signal.Notify` and **deliberately ignores** them. Neutrino cannot be closed with `Ctrl+C` nor with `kill`. The only normal exit is `/quit` (interactive confirmation) or `/nukex`. When `p.Run()` returns, `signal.Stop` removes the interception.

### Address book popup (`contactPickerMode`)

Sixteen commands open the popup when run without an argument (or with an argument that doesn't resolve to a valid contact/group): `/cnt-edit`, `/cnt-del`, `/cnt-info`, `/grp-add-member`, `/grp-ban`, `/grp-contact-send`, `/grp-del`, `/grp-join`, `/grp-promote`, `/grp-recall`, `/grp-reinvite`, `/sec-safety`, `/sec-unverify`, `/sec-verify`, and (§ "Relationship keys" above) `/sec-rotate-rel-identity`, `/sec-rotate-rel-content`. `/grp-info` is not among them: it takes no argument, it always and only shows the status of every member of the current room (see § "Safety Numbers").

**State in the model:**
```go
contactPickerMode   bool
contactPickerCmd    CmdID  // e.g. CmdInfo or CmdEdit — not a string, the CmdID itself
contactPickerFilter string // typed text used to filter
contactPickerIdx    int    // highlighted row in the filtered list
```

**`pickerItems() []string`** builds the filtered list based on `contactPickerCmd`:
- `CmdRecall`, `CmdDelGroup`: saved groups (`savedGroups`)
- `CmdReinvite`: current group's members not currently connected
- `CmdBan`: current group's members, excluding self
- `CmdPromote`: current group's *ephemeral* members only (no pre-existing direct contact, `resolveContactByPub` returns nil), excluding self
- `CmdJoin`: pending group invites (`pendingKnocks` with `GroupID` set)
- default (`CmdInfo`, `CmdEdit`, `CmdDelContact`, `CmdAddMember`, `CmdSendContact`, `CmdSafety`, `CmdVerifySafety`, `CmdRotateRelIdentity`, `CmdRotateRelContent`): address book contacts, alphabetical order — `CmdInfo`/`CmdSendContact` with `"self"` on top; `CmdVerifySafety` excludes already-verified contacts; `CmdAddMember` excludes contacts already in the current room; `CmdRotateRelIdentity`/`CmdRotateRelContent` exclude a contact whose sibling relationship key is already rotating (mutual guard, § "Relationship keys")

The filter is case-insensitive and searches `Username`/`LocalName` (or `GroupID`/`LocalName` for groups). `/grp-ping` without an argument uses a similar but dedicated popup (`pingPickerMode`), because the source is the current room (`groupMembers`), not the address book. `/grp-info` (`cmdRoomInfo`) always computes the safety code from the member's self-declared `IdentityPub` in the room (`tab.groupMembers`), never from whatever may already be saved in the address book for the same contact — it therefore works even for a member never saved, since their network identity is already known from the invite/knock.

**`/cnt-info self`** always shows output in a popup (`m.textPopupMode`), regardless of the active tab.

**`/help`** opens a scrollable overlay (`helpMode bool`, `helpScroll int`). The width is `termW - 4`; the page height is not a fixed count of commands but a budget of physical lines (`termH - 6`) measured line by line with the same wrap engine as lipgloss — a long description wraps across multiple lines instead of being truncated, and pagination accounts for that (see `renderHelp()`, `internal/client/tui/tui.go`). The `↑`/`↓` keys scroll by one entry, `PgUp`/`PgDn` by an approximate page step, `Esc`/`Enter` closes.

---

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| GET (WS) | `/ws/chat` | WebSocket connection |
| GET | `/health` | `{"status":"ok","users":N}` |
| POST | `/knock` | Receiving a `KnockEnvelope{tag, encrypted payload}` (classic or hybrid, §7.4) — tag checked against the address book before any decryption (§ "Knock (room invite)") |

---

## Main dependencies

| Package | Role |
|---|---|
| `github.com/coder/websocket` | WebSocket server and client |
| `github.com/charmbracelet/bubbletea` | TUI event loop (Elm architecture) |
| `github.com/charmbracelet/bubbles` | `viewport` (scroll) + `textarea` (input) |
| `github.com/charmbracelet/lipgloss` | Terminal styles and colors |
| `github.com/cretz/bine` | Go bindings for the Tor daemon |
| `github.com/google/uuid` | UUIDv4 for session user_id |
| `github.com/skip2/go-qrcode` | Identity, backup, and sync QR generation |
| `github.com/tyler-smith/go-bip39` | BIP-39 mnemonic encode/decode for the identity seed |
| `golang.org/x/crypto` | Argon2id, HKDF, SHA3 |
| `golang.org/x/net/proxy` | SOCKS5 proxy for Tor circuit isolation |
| `filippo.io/edwards25519` | Ed25519↔X25519 birational map for the I2P address (`--net i2p`) |
| `github.com/cloudflare/circl` | ML-KEM-768 / ML-DSA-65 (hybrid PQC network identity, relationship keys) |
| `github.com/ulikunitz/xz` | LZMA2/XZ compression for the file-transfer strong pack (`shared.PackData`) |
| `gitlab.torproject.org/tpo/.../goptlib` + `.../lyrebird` | In-process obfs4/webtunnel pluggable transport (Tor bridges) |
| `github.com/blackjack/webcam` | Pure-Go V4L2 webcam capture (camera QR reading, Linux desktop) |
| `github.com/makiuchi-d/gozxing` | QR code decoding (contacts, backup/sync, optical transfer) |

---

## CLI — available commands

```
neutrino                        Start (first run: wizard; subsequent runs: TUI — if the keystore has more than
                                 one identity, asks which one to use before proceeding)
neutrino add-bridges <file.png> Acquires obfs4/webtunnel bridge lines from a QR code (or --camera on Linux desktop)
neutrino add-identity           Adds a new identity to the same keystore (same password)
neutrino backup                 Shows the 24 BIP-39 words and generates an encrypted file
neutrino debug <file>           Normal startup (wizard/TUI) with internal debug logging active, written to
                                 <file> instead of Console
neutrino get-bridges            Downloads obfs4 and webtunnel bridges from bridges.torproject.org
neutrino install                Prints the systemd unit file for automatic startup
neutrino lang [it|en|fr|de|es|ro|ru]  Shows or sets the interface language (effective on next restart)
neutrino net [tor|i2p]          Shows or sets the transport network (effective on next restart; i2p embedded on linux/amd64, linux/arm64 and Intel macOS, elsewhere 'i2pd' on the system)
neutrino qr send <file>         Sends a file as an animated QR stream (fountain coding), password-encrypted
neutrino qr receive <out>       Receives a file sent with "qr send", reads from the webcam until complete
neutrino remove-all-bridges     Removes tor_bridges (asks for confirmation)
neutrino reset-config           Rewrites config.json with default values and comments
neutrino restore                Restores identity from 24 BIP-39 words (.bin file, QR chunks, or animated QR)
neutrino show-qr                Shows the QR code of your own identity
neutrino sync export            Exports encrypted address book (file, static QR, or animated QR)
neutrino sync import <file...>  Imports and merges the address book from a .bin file or .chunk chunks
neutrino sync import --camera   Same as above, but reads an animated QR stream from the webcam instead of a file
neutrino use-bridges [on|off]   Shows or sets automatic bridge loading (effective on next restart)
neutrino version                Shows the version (also --version, -v)
neutrino --help                 Shows command usage (also -h, help)
neutrino --bridges-file <path>  Forces a specific bridge file for this run (takes priority over use-bridges)
neutrino --net <network>        Forces the transport network (tor|i2p) for this run only (takes priority over neutrino net)
```

`neutrino get-bridges` downloads both bridge types (`obfs4`, `webtunnel`) from `https://bridges.torproject.org/bridges/en?transport=<type>` with no CAPTCHA, extracts lines with a regex after HTML stripping, and saves them to `~/.config/neutrino/tor_bridges` (permissions 0600).

`neutrino remove-all-bridges` calls `os.Remove` on the `tor_bridges` file after interactive confirmation (`[y/n]`). If the file doesn't exist, it does nothing. A restart is required to apply the change (Tor is already running with the previous configuration).

`neutrino use-bridges on|off` (`runUseBridges`, `cmd/main.go`) reads/writes `cfg.BridgesEnabled` in `config.json`, same pattern as `neutrino lang`. Without an argument it shows the current status. Effective on next restart, never live.

`neutrino reset-config` overwrites `~/.config/neutrino/config.json` with the default values and explanatory comments for every field — useful after incorrect manual edits.

`neutrino net [tor|i2p]` (`runNet`, `cmd/main.go`) reads/writes `cfg.Net` in `config.json`, same pattern as `neutrino lang`/`neutrino use-bridges`. Without an argument it shows the current network. `--net <network>` on a normal startup takes priority over the saved value, without touching it (same scheme as `--bridges-file` over `bridges_enabled`, see above). See `internal/transport` for the `Transport` abstraction (`tor.go` wraps `internal/tornode`, `i2p.go` speaks SAM with an `i2pd` process managed by `internal/i2pnode` — embedded via `go:embed` on linux/amd64, linux/arm64 and darwin/amd64, system PATH elsewhere) and `internal/shared/i2p.go` for deriving the `.b32.i2p` address from the identity's Ed25519 key alone (Edwards25519↔X25519 birational map, same property as `OnionAddressFromPub`: a contact computes another contact's address from their public key alone, never their private key).

`neutrino add-identity` (`runAddIdentity`, `cmd/main.go`) — see "Multiple identities" in the Keystore section for implementation details (desktop: consumes a noise slot, asks a new identity password; Android: shares the file's single password). Requires the keystore to already exist (fails with an explicit message otherwise, suggesting to run `neutrino` first for the wizard).

`neutrino add-bridges <file.png>` / `neutrino add-bridges --camera` (`runAddBridges`, `cmd/main.go`) — acquires bridge lines from a QR code, useful when this device has no direct internet access but the user has a connected phone: the `bridges.torproject.org` page shown on the phone already includes a QR with the bridge lines. File mode (`internal/qrscan.DecodeQRFile`) works on any platform; `--camera` (`internal/qrscan.ScanCamera`, direct V4L2) is Linux desktop only. Decoded lines are ADDED to `tor_bridges` (never overwritten, exact duplicates discarded) — lets bridges accumulate across multiple scans. **Android equivalent** (`screens/advanced_settings.go:acquireBridgesFromQR`, "Acquire bridges from QR" button in the Bridges section of Advanced Settings): same non-destructive merge, reuses `showQrSourceDialog` (file via the Storage Access Framework, or camera via `androidapp/camera` — unlike desktop, the camera path works here) to decode the QR and writes to `androidfs.BridgesPath` (same directory as the keystore/config.json).

`neutrino qr send <file>` / `neutrino qr receive <file-out>` (`runQRSend`/`runQRReceive`, `cmd/main.go`) — file transfer via animated QR, see "Optical transfer via animated QR" in the Keystore section for the mechanism shared with backup/sync. Here the payload is encrypted with a password read from the terminal (`qrOpticalDeriveKey`, Argon2id) — never the 24 BIP-39 words, since this isn't an operation tied to a specific identity. `receiveAnimatedQR` times out after `qrOpticalScanTimeout` (10 minutes) if reception doesn't complete.

`neutrino sync import --camera` (`runSyncImportQR`, `cmd/main.go`) — variant of `sync import` that reads from an animated QR stream (`receiveAnimatedQR`) instead of a file; the shared tail `finishSyncImport` (24 words + `keystore.ImportSync` + `MergeContacts`) is identical regardless of where the bytes came from.

---

## Agent mode and end-to-end tests

`neutrino agent` exists only in binaries built with the `neutrino_agent` build tag (`cmd/agent_neutrino_agent.go`, `internal/client/tui/agent_neutrino_agent.go`); a normal build rejects the subcommand. It runs the same `runMain` as an interactive session, with the terminal replaced by a local Unix socket:

```bash
XDG_CONFIG_HOME=<dir> neutrino agent --sock <path> --creds <file> [--net tor|i2p|loopback] [--loopback-dir <dir>]
```

- `--creds`: JSON file, mode `0600`, replacing the wizard's and the login's terminal input (username, passwords, device label, language, optional `restore_from`, optional `config` overrides of `config.json` fields). Never passed on the command line.
- `XDG_CONFIG_HOME` must be set explicitly: an agent instance never touches `~/.config/neutrino`.
- `--net loopback` (`internal/transport/loopback_neutrino_agent.go`): no anonymity network; each "hidden service" is a plain listener on `127.0.0.1`, and its address (the same `.onion` string Tor would publish for that key) resolves through `--loopback-dir`, shared by every instance of a run (one file per published address). Indoor LAN discovery uses the same directory. Never part of a release.
- `--export-backup <dir>` writes the identity's 24 words and backup file and exits, so a second device of the same identity can be born with `restore_from`.

**Protocol:** one JSON request per line, one JSON reply per line (`{"ok":true,...}` / `{"ok":false,"error":"..."}`). Keystrokes are injected into the bubbletea program as a keyboard would deliver them; state is read inside the bubbletea loop, never from a copy.

| `cmd` | Fields | Effect |
|---|---|---|
| `type` | `text` | Types text into the input, no Enter |
| `send` | `text` | Types text, then Enter |
| `key` | `key` | One named key (`enter`, `esc`, `tab`, arrows, `pgup`/`pgdown`, `ctrl+c`, ...) |
| `state` | — | Tabs, active tab, input line, open modes |
| `lines` | `tab`, `from` | Lines of a tab (`""` = active) from index `from` |
| `screen` | — | Rendered screen (160×50), ANSI stripped |
| `contacts` | — | Address book with relationship state |
| `wait` | `tab`, `pattern`, `from`, `timeout` | Waits for a line matching the regexp (`tab` `"*"` = any tab; default timeout 30 s) |

**End-to-end scenarios** (`internal/e2e`, same build tag): `TestMain` builds the agent binary once, each scenario starts several real instances on the loopback transport and drives them through the socket exactly as a person would drive the TUI.

```bash
go test -tags=neutrino_agent ./internal/e2e/
NEUTRINO_E2E_RACE=1 go test -tags=neutrino_agent ./internal/e2e/   # agent binary built with -race
```

`TestCommandCoverage` maps every slash command of `client.CommandList()` to the scenario that exercises it and fails for any command left without one. Without the tag the package is empty and `go test ./...` skips it.

---

## Build

```bash
go build -o neutrino ./cmd/
```

On platforms without an embedded Tor binary (see below), Neutrino simply runs `tor` as a subprocess, looking for it in the system `PATH` — no "silent" fallback: if it's missing, `StartTor` returns an error with a hint (`tornode.hint_install_tor`).

### Why an embedded Tor binary

The project's stated goal is *single binary, no external services*: the user downloads a single executable and doesn't have to install or configure anything. This requires that the `tor` process itself travel inside the Go binary (`go:embed`) and be extracted to a temporary file at startup — connecting to a system daemon isn't enough, because most users don't have (and don't want to install) `tor` separately.

The platforms with an embedded binary in the released builds are **linux/amd64** and **linux/arm64** (including Android/Termux — see `termux-manual.md`); the macOS builds in testing also embed it on **darwin/amd64** and **darwin/arm64**. Other combinations fall back to the system `tor` until someone adds the binary and the corresponding `embed_<GOOS>_<GOARCH>.go` for that platform (see below) — on Linux with `download_build_tor-core.sh`; the macOS script (`download_tor-browser_macos.sh`) belongs to the builds in testing and is not part of this repository.

The two platforms don't share the same embedding strategy, because Tor Project's official binaries don't behave the same way on Linux and macOS — this difference is the reason the macOS builds in testing use a separate script (`download_tor-browser_macos.sh`) instead of `download_build_tor-core.sh`.

### linux/amd64 and linux/arm64 — static build (`download_build_tor-core.sh`)

The official `tor-expert-bundle-linux-x86_64-*.tar.gz` bundle is **dynamically linked** against `libssl.so.3`, `libcrypto.so.3`, `libevent-2.1.so.7`, `libzstd.so.1`, etc., **without** an `RPATH`/`RUNPATH` pointing to `$ORIGIN` (verifiable with `readelf -d`: no `RPATH`/`RUNPATH` entry). In practice, that binary only runs on a machine that already has exactly those libraries, in a compatible version, installed system-wide — not portable across different distributions, exactly the problem *single binary* is meant to eliminate. For `linux/arm64` the problem is even sharper: the official Tor Expert Bundle publishes no `linux-aarch64` build — only `linux-x86_64`/`linux-i686` and separate `android-*` bundles — so for that architecture there isn't even a dynamic bundle to start from.

`download_build_tor-core.sh [amd64|arm64]` solves the problem by recompiling `tor` from source **from scratch**, inside an `alpine:3.21` Docker container (a clean, reproducible musl environment, without touching the local machine's toolchain), with:

```
--enable-static-tor           # static linking of tor itself
LDFLAGS='-static'              # no dynamic linker in the final binary
--with-libevent-dir / openssl-dev / zlib-dev (-static)   # static musl libraries
```

For `arm64` the build runs under `docker run --platform linux/arm64`, emulated via QEMU on an amd64 host (the binfmt handlers must first be registered once: `docker run --privileged --rm tonistiigi/binfmt --install arm64`) — slower than the native amd64 build, but with no difference in the result: Alpine provides native `aarch64` packages inside the emulated container, it isn't cross-compilation in the strict sense.

The result is a `statically linked` ELF (verified with `file`: no `Requesting program interpreter` line in `readelf -l`, `not a dynamic executable` in `ldd`) that depends on **nothing** present on the target system — consistent with `torBinary` being embedded in `embed_linux_amd64.go`/`embed_linux_arm64.go` and used with no other supporting files in `internal/tornode/tornode.go`. A truly static binary also has no dynamic linker to resolve at runtime: it runs identically on Android/Termux too (Bionic libc, not glibc/musl) under the same Linux kernel — see `termux-manual.md`.

This approach **is not reproducible on macOS**: Darwin has no equivalent of musl (no fully static libc), and cross-compiling `tor` from source for macOS would require the Apple SDK inside the Docker container — an SDK Apple does not allow redistributing in a public image. Hence the need for a different strategy on macOS.

### macOS — official bundle + `libevent.dylib` + ad-hoc signing (`download_tor-browser_macos.sh`)

Applies to the macOS builds in testing, not part of the current releases.

Properties of the official `tor-expert-bundle-macos-{x86_64,aarch64}-<version>.tar.gz` bundles (version pinned in `download_tor-browser_macos.sh`) (inspected with `file`, `llvm-otool -L`/`-l`, `strings`):

- **OpenSSL is statically compiled inside the `tor` binary** (the symbols contain `OPENSSL_BUILDING_OPENSSL`): no external dependency for crypto.
- The only two dynamic system dependencies are `/usr/lib/libSystem.B.dylib` and `/usr/lib/libz.1.dylib` — both part of the operating system itself, with an ABI stability guaranteed by Apple across every supported macOS version: no need to bundle them.
- **Only one** non-system external dependency: `@executable_path/libevent-2.1.7.dylib`, present in the `tor` binary's `LC_LOAD_DYLIB` load command. `@executable_path` is the Mach-O equivalent of `$ORIGIN`: dyld looks for the file in the **same directory as the running executable**, whatever its name or path. Identical on amd64 and arm64 (same libevent version in both bundles).
- **The `tor` binary has no `LC_CODE_SIGNATURE`** — it is not signed, not even ad-hoc. On **Apple Silicon (arm64)** the XNU kernel requires that *any* page mapped as executable belong to a Mach-O with at least an ad-hoc signature: a completely unsigned binary receives **SIGKILL** on the first execution attempt. On Intel (amd64) the absence of a signature does not block local execution, but for uniformity the signature is applied on both architectures.

Conclusion: the official bundle is already "almost static" (a single external dependency, nothing to recompile) — a `download_build_tor-core.sh` for macOS is **not needed**, it's enough to complete `download_tor-browser_macos.sh` to also extract the missing dylib, and sign the binary at runtime (not at build time, see below).

`download_tor-browser_macos.sh` (no arguments) downloads both official macOS bundles (x86_64 and aarch64) and extracts two files from each: `tor_darwin_<arch>` (the `tor` binary) and `libevent_darwin_<arch>.dylib` (its dynamic dependency). On Linux, `tor_linux_<arch>` comes only from `download_build_tor-core.sh` (the static build above). obfs4/webtunnel bridges require no extraction from any bundle: they run in-process (see "Tor bridges" above).

Extracting the dylib is required on macOS: without it, `tor` fails to start (`Library not loaded: @executable_path/libevent-2.1.7.dylib`).

### Embedding architecture (`internal/tornode/embed_*.go`)

Every supported GOOS/GOARCH combination has a file with a dedicated build tag that declares the `torBinary`, `dylibBinary` (`[]byte`) variables via `go:embed`; unsupported platforms get a stub with the same variables empty, so the rest of the package compiles everywhere without `#ifdef`s scattered through the code:

| File | Build tag | Variables |
|---|---|---|
| `embed_linux_amd64.go` | `linux && amd64 && !android` | `torBinary` ← `tor_linux_amd64` |
| `embed_linux_arm64.go` | `linux && arm64 && !android` | `torBinary` ← `tor_linux_arm64` |
| `embed_darwin_amd64.go` | `darwin && amd64` | `torBinary` ← `tor_darwin_amd64`, `dylibBinary` ← `libevent_darwin_amd64.dylib` |
| `embed_darwin_arm64.go` | `darwin && arm64` | `torBinary` ← `tor_darwin_arm64`, `dylibBinary` ← `libevent_darwin_arm64.dylib` |
| `embed_android.go` | `android` | `torBinary = nil` — Tor never travels via `go:embed` here: on the native Android app the real binary is `libtor.so` (guardianproject/tor-android), injected into the APK's `jniLibs/<abi>/` by `cmd/androidapp/inject_jnilibs.sh` and resolved at runtime via `internal/androidnative.Resolve()` (see `StartTor`) — not this package's extraction path at all |
| `embed_stub.go` | everything else | `torBinary = nil` |
| `embed_dylib_stub.go` | everything except darwin/amd64 and darwin/arm64 | `dylibBinary = nil` (includes linux/amd64 and linux/arm64: being static, they have no dynamic dependencies) |

No equivalent for pluggable transports: `ptclient.go` is ordinary Go code, always compiled, on every platform — not a binary to embed.

The build tags are written in explicit mutual negation (e.g. `!(linux && amd64) && !(linux && arm64) && !(darwin && amd64) && !(darwin && arm64) && !android` in the stub) because Go doesn't allow two `var torBinary []byte` in the same constraint set — with partially-overlapping tags you get `torBinary redeclared in this block` at compile time on that combination. `GOOS=android` also satisfies the plain `linux` constraint (`go help buildconstraint`), so `embed_linux_amd64.go`/`embed_linux_arm64.go` both add an explicit `&& !android` to stay out of `embed_android.go`'s way — this is a separate concern from Termux (§ below), which builds this same CLI/TUI binary with `GOOS=linux` (not `android`) and therefore does go through the ordinary static-embed path.

### Runtime extraction and ad-hoc signing

`extractBinary()` in `tornode.go` creates a dedicated temporary directory (`os.MkdirTemp`, permissions `0700`) and writes into it:

- `tor`, permissions `0700`;
- on macOS, also `libevent-2.1.7.dylib` **in the same directory** — necessary because `@executable_path` resolves relative to the directory of the executable currently running, not a fixed path.

The dylib filename is fixed in the constant `macDylibRuntimeName = "libevent-2.1.7.dylib"`: it must match **exactly** what Tor Project's compiler wrote in the official binary's load command at the time the bundle was built, and it cannot be derived at runtime without parsing the Mach-O load commands (out of scope for this project). If a future bundle version updates the libevent version, this constant must be updated by hand — `download_tor-browser_macos.sh` prints the original name found in the bundle precisely to flag any discrepancy to whoever regenerates the binaries.

Right after writing, if `runtime.GOOS == "darwin"`, every extracted Mach-O file goes through `adhocSignDarwin`, which invokes `codesign --force --sign - <path>`. Notes:

- `codesign` is part of the macOS base operating system (does not require Xcode or the Command Line Tools), so it's always available on the target machine with no extra dependencies to install.
- The signature is **ad-hoc** (identity `-`): it does not require an Apple Developer certificate, it only serves to satisfy the kernel's minimum requirement for mapping executable pages on Apple Silicon.
- No Gatekeeper quarantine applies to the extracted files: they are written by `os.WriteFile` from within the process, not downloaded by a browser or by `curl` with the `com.apple.quarantine` xattr — so the "unidentified developer" prompt does not trigger on first run.

Cleanup accordingly changes from `os.Remove(file)` to `os.RemoveAll(dir)`: on the Tor node's `Close()`, the entire directory (binary + dylib) is removed, not just the single file.

### `build_neutrino.sh` — build script

```bash
bash build_neutrino.sh ux                # linux/amd64 static, Tor+i2pd embedded (requires tor_linux_amd64/i2pd_linux_amd64 already present)
bash build_neutrino.sh ux pack           # + upx compression
bash build_neutrino.sh ux-arm            # linux/arm64 static, Tor+i2pd embedded (e.g. Termux/Android — requires tor/i2pd arm64 already present)
bash build_neutrino.sh all               # linux/amd64 + linux/arm64 (builds any missing Tor/i2pd binary first)
bash build_neutrino.sh tor               # regenerates tor_linux_amd64 (download_build_tor-core.sh, requires Docker)
bash build_neutrino.sh tor arm64         # regenerates tor_linux_arm64 (download_build_tor-core.sh, requires Docker + QEMU binfmt for arm64)
bash build_neutrino.sh i2p               # regenerates i2pd_linux_amd64 (download_build_i2pd.sh, requires Docker)
bash build_neutrino.sh i2p arm64         # regenerates i2pd_linux_arm64 (download_build_i2pd.sh, requires Docker + QEMU binfmt)
```

The `ux`/`ux-arm` targets refuse to proceed (with an explicit message) if the respective `tor_linux_<arch>`/`i2pd_linux_<arch>` are missing; `all` builds them first in that case. The Tor/i2pd scripts always build exactly the versions pinned for the current release: integrating a newer upstream Tor or i2pd is a step of the project's own release process, never done by this script. For arm64, the QEMU `binfmt` handler is registered automatically (pinned `tonistiigi/binfmt` image, run privileged) when not already present.

#### Build requirements

`requirements.sh` (repository root) lists the host tools each build step needs; `build_neutrino.sh` and every download/build script source it and check them before doing anything, reporting all missing tools at once:

| Step | Host tools |
|---|---|
| `ux`, `ux-arm`, `all` | `go` — exactly the version in `go.mod` (a different Go release produces a different binary); `upx` only with `pack` |
| `tor [arm64]`, `i2p [arm64]` | `docker`, `curl` (build-dependency download), `file`, `sha256sum` |

Everything else the Tor/i2pd builds need (compiler, libraries, `gpg`, `git`, `wget`) runs inside the pinned Alpine container, not on the host. Those Alpine packages, with all their dependencies, come from a build-dependency archive per architecture (`<BUILD_DEPS_TAG>-<arch>.tar`, published as an asset of the GitHub release `<BUILD_DEPS_TAG>`): the build script downloads it once into `build-deps/`, checks it against the sha256 pinned in the script (`BUILD_DEPS_SHA256_AMD64`/`BUILD_DEPS_SHA256_ARM64`) and installs it inside the container with `apk add --no-network` — apk still verifies Alpine's own signature on every package. A missing archive or a sha256 mismatch stops the build; there is no fallback to the Alpine mirror, which only keeps the latest revision of each package.

### Signing release binaries

Motivation: an unsigned `neutrino-*` binary carries nothing proving its provenance — a user who downloads it has no way to know whether it was actually produced by the project or altered along the way. `build_neutrino.sh` only compiles; every published release is signed by the maintainer at release time, after building with this same `build_neutrino.sh`, using two independent, complementary mechanisms:

1. **A GPG signature appended directly to the tail of each individual binary.** An ELF loader never reads past the segments it actually references, so bytes appended after the end of the file are inert — the same technique self-extracting installers use to append a payload after their own stub. This must run **before** the manifest step below, not after: once the signature is appended, the file's SHA-256 changes, so the manifest has to hash the *final* on-disk content, not the pristine pre-signature binary — reversing the order would make `sha256sum -c` fail against the manifest.
2. **A shared manifest** — `neutrino-manifest`, one SHA-256 line per file (already including its appended signature from step 1), signed once with GPG:

```bash
# 1. per-binary, tail-appended signature (repeated for every released binary)
gpg --local-user 0x6BE2C8ABD7701EB4 --detach-sign --armor --output neutrino-ux-amd64-v<version>-b<build>.sig.tmp neutrino-ux-amd64-v<version>-b<build>
cat neutrino-ux-amd64-v<version>-b<build>.sig.tmp >> neutrino-ux-amd64-v<version>-b<build>
rm neutrino-ux-amd64-v<version>-b<build>.sig.tmp

# 2. shared manifest, hashing the now-signed files
sha256sum neutrino-ux-amd64-v<version>-b<build> neutrino-ux-arm64-v<version>-b<build> > neutrino-manifest
gpg --local-user 0x6BE2C8ABD7701EB4 --detach-sign --armor --output neutrino-manifest.asc neutrino-manifest
```

Both use the same key, so this isn't a stronger cryptographic guarantee than the manifest alone (either one proves provenance equally well) — it's a matter of what travels with the file. A binary redistributed on its own, detached from the release's other files, still carries its own proof; the manifest is more convenient when verifying several files at once, or when a redistribution channel does preserve the sibling `neutrino-manifest`/`.asc` alongside each download.

Unlike every signature used by the app's internal protocol (always in-process, never an external process), this release signature deliberately delegates to the local `gpg` binary — a key generated specifically for this purpose (ed25519, UID `Neutrino Build Signing Key <neutrinobuilder@proton.me>` — a dedicated anonymous address, no personal name attached), never managed by the project's own keystore: the system agent handles its passphrase, consistent with using a key that lives outside the app's keystore.

User-side verification, before running a downloaded binary — first fetch the key from a public keyserver and check its identity, then verify either the manifest (all files at once) or a single binary on its own:
```bash
gpg --keyserver hkps://keys.openpgp.org --recv-keys D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4
# alternative: gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4
gpg --list-keys D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4   # confirm UID: "Neutrino Build Signing Key <neutrinobuilder@proton.me>"

# manifest, all files at once
gpg --verify neutrino-manifest.asc neutrino-manifest && sha256sum -c neutrino-manifest

# a single binary on its own, using its own tail-appended signature
off=$(grep -aob -- '-----BEGIN PGP SIGNATURE-----' FILE | head -1 | cut -d: -f1)
head -c "${off}" FILE > FILE.verified
tail -c +$((off+1)) FILE > FILE.asc
gpg --verify FILE.asc FILE.verified
```
The first two commands prove the key you're about to trust really is the one published for this project, under the UID it claims (`Neutrino Build Signing Key <neutrinobuilder@proton.me>`) — a dedicated anonymous address, not a personal identity to check. From there, either path proves the same two things: that a hash was signed by that key (full fingerprint: `D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4`), and that the file in hand matches it. All of this is needed regardless of which path is used: the signature alone doesn't bind the hash to *that* specific file, the hash alone proves nothing about provenance, and skipping the keyserver check means trusting a key you never verified. Neither mechanism protects against a key substitution attack — a tampered binary re-signed with a *different* key produces an equally "valid" signature under that key; the keyserver/UID check above is what stops that, not the presence of a signature by itself.

**macOS (not part of the current releases).** The GPG signature above proves provenance to a human/script that explicitly verifies it; it is never checked by the operating system. On Apple Silicon the kernel instead requires an *Apple code signature* (`LC_CODE_SIGNATURE` in the Mach-O), independent of GPG. A `darwin/arm64` binary cross-compiled from Linux has none, so anyone building it themselves must sign it ad-hoc once, on any Mac (no Apple Developer account needed):
```bash
codesign --sign - neutrino-macos-arm64-v<version>-b<build>
```

### Reproducible builds

Motivation: a GPG signature (above) proves the binary was produced by whoever holds the signing key — it does not prove the binary actually corresponds to the published source. Reproducible builds close that second gap: anyone can rebuild from the same git commit on their own machine and confirm, byte-for-byte, that they get the same binary the project published.

Determinism rests on these pinned inputs:

- **`-trimpath -buildvcs=false`** (`GO_BUILD_FLAGS` in `build_neutrino.sh`) — strips the local filesystem's absolute paths from the binary (only module-relative paths remain, e.g. `neutrino/cmd/main.go`) and omits VCS stamping (commit hash, dirty-tree flag), both of which would otherwise make the binary depend on where and from which checkout state it was built, not just on its content.
- **The same Go toolchain version** — a different Go release produces different machine code from the same source.
- **The embedded Tor/i2pd binaries** — `tor_linux_<arch>`/`i2pd_linux_<arch>` are committed to the repository and embedded as-is, so a rebuild of the same commit embeds exactly the same bytes. Whoever wants to regenerate them too uses `download_build_tor-core.sh`/`download_build_i2pd.sh`, which build against a specific Alpine Docker image referenced by digest (`ALPINE_DIGEST_AMD64`/`ALPINE_DIGEST_ARM64`, not a floating tag), the exact Alpine packages frozen in the build-dependency archive (see "Build requirements"), upstream sources verified against the bundled release keys (`internal/tornode/tor-release-key.asc`, `internal/i2pnode/i2pd-release-key.asc`), and their own fixed `SOURCE_DATE_EPOCH`.

Verifying a published binary against the source:
```bash
# 1. build the release's commit with the same Go version
bash build_neutrino.sh ux                      # or ux-arm for neutrino-ux-arm64-*

# 2. strip the tail-appended signature from the downloaded binary
off=$(grep -aob -- '-----BEGIN PGP SIGNATURE-----' FILE | head -1 | cut -d: -f1)
head -c "${off}" FILE > FILE.unsigned

# 3. compare
sha256sum FILE.unsigned dist/neutrino-ux-amd64-v<version>-b<build>
```
Matching hashes prove the published binary is exactly what the published source produces. The comparison is only meaningful against a build without `pack`: the released binaries are not `upx`-compressed.

### Tests

```bash
go test ./...                 # all packages
go test -race ./...           # with race detector (important — RWMutex used everywhere)
go test ./internal/shared/... # crypto only
```

## Platforms and anonymous networks

Feasibility matrix for embedding Tor and I2P directly in the binary (`go:embed`, same scheme as `internal/tornode`/`internal/i2pnode`) versus relying on an external program installed separately by the user. "Embedded" means there is no technical obstacle — not that it has already been done; implementation status is in the column next to it.

| Platform \ Network | Tor | Tor — status | I2P | I2P — status |
|---|---|---|---|---|
| **Linux amd64** | Embedded | ✅ Done | Embedded | ✅ Done |
| **Linux arm64** | Embedded | ✅ Done | Embedded | ✅ Done |
| **macOS Intel** | Embedded | 🔶 In testing | Embedded | 🔶 In testing |
| **macOS Apple Silicon** | Embedded | 🔶 In testing | Embedded¹ | ⬜ To do |
| **Windows** | Embedded² | ⬜ To do | Embedded² | ⬜ To do |
| **Android APK** | Embedded³ | 🔶 In testing | Embedded³ | 🔶 In testing |
| **Android Termux** | Embedded⁴ | 🔶 Under verification⁷ | Embedded⁴ | 🔶 Under verification⁷ |
| **iOS** | Embedded⁵ | ⬜ To do | **Not available**⁶ | — (no viable path) |

¹ Requires compiling a native arm64 i2pd for macOS (not published by PurpleI2P today, but buildable in-house).
² Official `tor.exe` / `i2pd.exe`, same `go:embed` scheme as Linux/macOS — no technical obstacle.
³ Like Orbot/Tor Browser Android (tor) and "I2P for Android" (Java router): binary/library for the target ABI bundled inside the APK itself.
⁴ Termux is a complete Linux userland: a static binary can be shipped inside one's own package/installer instead of going through `pkg install`.
⁵ Only as a linked library (`Tor.framework`, no `exec` due to sandboxing) — inside the app bundle.
⁶ No existing i2pd/I2P router port for iOS to start from.
⁷ Static arm64 binaries compiled and embedded (`build_neutrino.sh ux-arm`), clean build/vet/test, smoke test of both binaries (tor/i2pd) under QEMU emulation with no crash — not yet verified with a real bootstrap on a physical Termux device. See `termux-manual.md`.

## Android app

The native Android app (`cmd/androidapp`, Fyne) is in testing and not distributed yet; its source is not part of this repository. Its technical documentation will be published together with the app.
