# User Manual — Neutrino

## What it is

`neutrino` is an encrypted P2P communication terminal. Each instance is simultaneously server and client: it publishes a network address (`.onion` on Tor, or the equivalent on I2P) on which it receives connections and connects to the addresses of its contacts. There is no central server; no one other than the parties involved can know that the communication is taking place.

---

## Requirements

- Linux x86-64 (Tor and i2pd bundled)
- Linux arm64, including Android/Termux (Tor and i2pd bundled here too) — see `termux-manual.md` for Termux-specific installation and usage
- To verify the authenticity of the downloaded binary (optional but recommended): `gpg` in the PATH — see "Verifying the authenticity of the downloaded binary" below. This only concerns the signature on published binaries, a mechanism independent of your in-app identity
- macOS (Intel and Apple Silicon): in testing, not yet distributed — see "macOS (in testing)" below
- A terminal with UTF-8 support, for the `●` `✓` `⚠` symbols used in the interface (peer status, delivery confirmations, warnings). Verified on Debian with `terminator` and `xfce4-terminal`.

---

## Verifying the authenticity of the downloaded binary

Every release (`neutrino-ux-amd64-v<version>-b<build>`, `neutrino-ux-arm64-v<version>-b<build>`) is signed with the project's dedicated release-signing key (`0x6BE2C8ABD7701EB4` — a key generated specifically for this purpose, UID `Neutrino Build Signing Key <neutrinobuilder@proton.me>`: a dedicated anonymous address, no personal name attached), in two ways at once: each binary carries its own signature appended directly to the end of the file, and a shared `neutrino-manifest`/`neutrino-manifest.asc` pair (one hash line per file, GPG-signed) ships alongside them. Either is enough to verify a download on its own — the manifest is convenient when checking several files together, the per-binary signature is convenient if you only have the one file and nothing else. Before running a downloaded binary, first fetch the key and confirm its identity:

```bash
gpg --keyserver hkps://keys.openpgp.org --recv-keys D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4
# alternative: gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4
gpg --list-keys D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4   # confirm UID: "Neutrino Build Signing Key <neutrinobuilder@proton.me>"
```

Then verify the file — using the manifest (if you have `neutrino-manifest`/`.asc` alongside it):
```bash
gpg --verify neutrino-manifest.asc neutrino-manifest       # proves the hash list is signed by that key
sha256sum -c neutrino-manifest                             # proves the downloaded file matches the listed hash
```

...or using the signature already appended to the binary itself (if that's all you have):
```bash
off=$(grep -aob -- '-----BEGIN PGP SIGNATURE-----' neutrino-ux-amd64-v<version>-b<build> | head -1 | cut -d: -f1)
head -c "${off}" neutrino-ux-amd64-v<version>-b<build> > verified-binary
tail -c +$((off+1)) neutrino-ux-amd64-v<version>-b<build> > verified-binary.asc
gpg --verify verified-binary.asc verified-binary            # proves that content is signed by that key
```

All the checks in whichever path you use are required: the signature alone doesn't tie the hash to *that specific* file, the hash alone proves nothing about provenance, and skipping the keyserver lookup means trusting a key you never verified. If any check fails (unknown key, invalid signature, mismatched hash), **do not run the binary**.

### macOS (in testing)

macOS builds (Intel and Apple Silicon) are in testing and are not part of the releases yet. The notes below apply to them.

**On macOS Apple Silicon only**, before the first launch you must also run once:
```bash
codesign --sign - neutrino-macos-arm64-v<version>-b<build>
```
This is not an additional security check: it's a requirement of the macOS kernel on Apple Silicon, which refuses to run any program lacking a code signature — independent of, and complementary to, the GPG verification above (one proves provenance, the other is merely a condition for launching). The `codesign` command is available on **any** Mac, Intel included — it's only *necessary* to run it (on the `arm64` binary) if you're going to launch it on Apple Silicon; on Intel the `neutrino-macos-amd64-v<version>-b<build>` binary starts without needing a code signature.

**On macOS (Intel or Apple Silicon), if the binary was downloaded from a browser** (not copied via `scp`/USB drive): macOS automatically adds the extended attribute `com.apple.quarantine` to the file, and on first launch Gatekeeper shows an "unidentified developer" warning — on **both** architectures, and **regardless** of the ad-hoc signature made above (Gatekeeper on quarantined files requires an Apple Developer ID certificate plus notarization, neither of which is done here). To proceed anyway, once authenticity has been verified with `gpg`/`sha256sum` as above:

- right-click the file → **Open** (then confirm in the dialog), or
- from the terminal: `xattr -d com.apple.quarantine neutrino-macos-<arch>`

---

## First launch — configuration wizard

On first launch, with no arguments, the wizard starts:

```
neutrino
```

The wizard asks:

1. **Language** — English, Italian, French, German, Spanish, Romanian or Russian; it's the only prompt shown in every supported language at once (no language is known yet). From this point on, the rest of the wizard and the app use the chosen language. To change it later see `neutrino lang` below — it is **not** a command available inside the TUI, only from the command line
2. **Username** — the name visible to others during chat (cannot be changed afterward)
3. **File password** — common to every identity you will ever keep in this file; protects it at rest. Before asking for it, the wizard offers to generate one automatically (`[y/N]`, recommended) — a 7-word random passphrase from the same BIP-39 wordlist used for the identity backup, shown on screen for you to write down. If you decline, you type your own password: at the end a strength estimate is shown (very weak/weak/acceptable/strong/very strong), for information only
4. **Identity password** — a second, separate password for THIS specific identity: together with the file password, it's what opens it. Same offer to auto-generate a passphrase as above
5. **Decoy identity** — mandatory, cannot be skipped: choose a username and an identity password (must differ from the one just chosen — checked automatically) for a second, separate identity sharing the same file password. Later, unlocking with the file password and the decoy's identity password instead of your real one opens that separate identity instead — a believable, ordinary-looking account, with no visible sign that another identity exists in the same file. Useful under coercion: whoever makes you unlock it never sees a hint that a real identity exists. Opening the decoy at startup is also a wipe: the moment it unlocks, every other identity in the file — your real one included — is overwritten with random bytes and the file saved, before the session even starts; irreversible, and with no visible difference from an ordinary login. The decoy's password is changeable at any later time with `/sec-duress` (the decoy identity itself can never be removed)
6. **Device name** — a label of your choosing (default: the system's hostname) to recognize this device among those known to your identity in the future, once you have more than one paired — see "Remote self-destruction" below. Viewable or changeable at any later time with `/sec-device-label`

At this point the wizard automatically generates your network identity key (Ed25519, entirely in Go, no system keyring involved) — no name, email, or anything else to type for this: that key only serves to compute your network address (`.onion`/I2P), it doesn't carry any declared identity. Every time you add a contact, the app automatically and silently generates, in the background, a key pair dedicated only to that relationship — used to authenticate connections with them and to sign/encrypt whatever you exchange in a room (see "Message signing" below).

> **The username you choose here is your network identifier: seen by everyone, fixed forever.** Unlike WhatsApp, Telegram and similar apps — where using your real first and last name is the norm, because those apps already know your phone number — here it is **not recommended**: Neutrino neither asks for nor verifies any personal data, and is designed specifically to stay that way. Use a pseudonym. Accordingly, expect that you and your contacts will choose short, non-descriptive strings (`xy001`, `zzskd`...) — that's normal. This is why the address book has a **local name** separate from the username (the `/cnt-edit` command, or when accepting a contact): an alias of your own, private, never shared with anyone — use it to recognize contacts at a glance (`the_blond_one`, `shorty`...). If a contact has already chosen a readable pseudonym on their own (e.g. "Lord Death"), you can also leave the local name blank: in the Contacts tab, contacts without a local name show only a placeholder (`"______________"`) as a reminder — setting it stays optional, see "Contacts Tab" below. The local name can be at most 14 characters long (truncated beyond that), to keep the name column always aligned instead of staggered row by row.

> **Why it's worth accepting the generated passphrase.** The file and identity passwords together are what protects identity, address book and groups at rest on disk: the keystore is encrypted with Argon2id + AES-256-GCM, and with Argon2id (memory-hard, resistant to GPU/ASIC) the factor that really matters against an offline attack is the entropy of the passwords themselves, not extra tricks. A 7-word random passphrase has far more entropy than almost any password "made up on the spot," while still being as easy to write down on paper as the 24 words of the identity backup. There is deliberately no OTP/2FA here: without a server able to verify or reset it, a lost second factor would make the keystore unrecoverable forever — a permanent-lockout risk for minimal benefit, given that anyone threatening an offline keystore already has the file in hand.

At the end, the keystore is saved to `~/.config/neutrino/keystore` and the configuration file to `~/.config/neutrino/config.json` (on macOS: `~/Library/Application Support/neutrino/` instead of `~/.config/neutrino/` — see "Local files" below).

The QR code for your own identity is also printed (visible in the terminal and saved as a PNG at `~/.config/neutrino/identity-qr-<username>.png`) — it's the code to share with contacts. If it doesn't fit in a single QR (common, since each key includes the post-quantum ML-KEM-768/ML-DSA-65 components, not just Ed25519), several numbered PNGs are saved instead (`...-part1.png`, `...-part2.png`...) — share all of them, in order; see `/cnt-read-qrcode` below for how the recipient reassembles them. A PDF (`identity-qr-<username>.pdf`) is saved alongside them, with a first page showing the full identity text and one page per QR image — handy for printing a paper copy.

---

## Subsequent launches

```
neutrino
```

Asks for the file password, then the identity password. Whichever identity that combination belongs to is what opens — your real one (whichever one, if you have more than one — see "Multiple identities" below, by typing that one's own identity password), or the decoy's, with no separate selection menu and no visible difference in outcome (opening the decoy also overwrites every other identity in the file — see "First launch" above). It then shows startup progress in three phases:

```
Oct 23 14:02:10.512 [1/3] Starting Tor: 100% ✓ (31s)
Oct 23 14:02:10.513 [2/3] Publishing hidden service… ✓ (12s)
Oct 23 14:02:22.904 [3/3] Ready! Listening on xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion (0s)
```

Each line starts with the local time; the value in brackets is how long that phase took. During phase 1 the percentage is updated in place on the same line until it reaches 100%.

Tor bootstrap typically takes 30-90 seconds.

---

## Interface

The TUI is made up of three areas:

```
[Console] [Tor] [Contacts] [Groups] [File] [Alice] [• group]   ← tab bar (• = unread messages)
─────────────────────────────────────── ← header (connection status or safety)
│                                      │
│  message area (scroll with           │
│  PgUp/PgDn)                         │
│                                      │
─────────────────────────────────────── ← separator
> type here…                            ← input textarea
```

The first five tabs are fixed, always in the same order, and stay open for the whole session: **Console** (the page open at startup), **Tor** (or **I2P**, depending on which transport network is active), **Contacts**, **Groups**, **File**. Every chat room you open (two-member or group) is added after these five, in the order you open them.

**Colors in the tab bar:**

Chat tabs (two-member and groups) use color to communicate connection status:

| Name color | Meaning |
|---|---|
| Green | Connection active, or reconnecting while this is the selected tab |
| Gray | Reconnecting, shown on a tab that isn't currently selected |

A colored dot may precede the tab name:

| Dot | Meaning |
|---|---|
| Yellow `●` | Unread messages |
| Red `●` | Connection lost (reconnect in progress) |

The Console, Contacts, Groups, Tor and File tabs never change color.

The full legend of every color used across the interface — tab bar, address book, room member bar, chat message tags, command palette — is kept in a standalone reference, [`color-map.html`](color-map.html).

**Tab navigation:**
- `Tab` / `Shift+Tab` — next / previous tab
- `→` / `←` — next / previous tab, only while the input line is empty (with text typed, they move the cursor)

**Quitting the application:**
Neutrino does not respond to `Ctrl+C` or any other OS signal (`SIGTERM`, `SIGHUP`). To quit use `/quit` from the TUI (asks for confirmation).

**Command palette:**
Starting to type `/` brings up the palette with the available commands and their descriptions. Navigate with `↑`/`↓`, select with `Enter`; `Esc` or `Tab` close it.

**Incoming room invites:**
A knock can only be decrypted by someone who already holds a private key recognized by the recipient: no one can forge one having only seen a public key (e.g. an intercepted QR code), and an unrecognized attempt produces no response different from a successful one — this keeps the mechanism itself from becoming a way to discover who's in your address book. A received invite (knock) immediately opens a popup in the foreground — the host's name, the room ID, any other members already known — with two choices: `Enter` to accept and join the room, `Esc` to ignore it. If more than one arrives, they're shown one at a time, queued: once the first is closed (accepted or ignored), the next one appears right away. `Esc` also notifies whoever sent the invite, who sees it reported as declined (the member's name turns grey in the room's member grid) instead of being left without any response.

---

## Types of communication

### Console Tab

The first tab, opened automatically at startup — **Console** — collects global system events: connections, disconnections, incoming knocks, senderKey rotations, network errors. Its first lines are already populated with the startup log (Tor bootstrap, hidden service publication) printed to the terminal before the TUI took control of the screen. It doesn't open with a command and cannot be closed with `/grp-exit`.

When a real error arrives (e.g. rejected key rotation, failed message send, failed safety verification) while you're not on the Console tab, a **red dot** lights up on the tab name — it turns off as soon as you open it. Routine log lines (startup lines, debug, "unreachable" status from periodic probes) don't light it up.

### Tor Tab

The second fixed tab — **Tor** (or **I2P**, depending on which transport network is active) — shows your own node's status in real time:

```
Tor: ● out  ● in   H.S.: ●
```

The two `out`/`in` dots indicate outbound and inbound circuits respectively:

| Dot | Meaning |
|---|---|
| 🟢 green | Circuit active |
| 🔴 red | Circuit not active |

`H.S.:` (hidden service) appears once your own `.onion` address is known: grey `◌` while the bootstrap confirmation is still in progress, green `●` once both the circuit and the hidden service are active, red `✗` otherwise.

Tor status is checked via the control port 10 seconds after startup, then every 5 minutes. The Tor tab cannot be closed with `/grp-exit`.

### What Tor and I2P don't protect against

Both Tor and I2P hide **who** you're talking to from anyone observing the traffic from outside, by encrypting and routing messages through several intermediate computers (relays) before they reach their destination. This works very well against an observer who only sees a slice of the network — the most common scenario.

There is, however, a limit that **both projects state openly** — this is not a gap in Neutrino. If someone can observe *at the same time* both the traffic leaving your device and the traffic arriving at its destination, they can compare timing and data volume and infer that the two sides match, without decrypting anything. This is a limit of the underlying network infrastructure, not something an app running on top of it can fix no matter how well designed — an observer capable of watching both sides of a connection at once is a demanding scenario, typically an actor with access to large portions of network infrastructure, not something within reach of just anyone.

I2P has one extra property Tor doesn't: it uses separate paths for inbound and outbound data (instead of the same path in both directions), which makes it harder for someone watching a single hop to tell what corresponds to what. This is not, however, an absolute guarantee against the capable observer described above — the I2P project itself doesn't claim that it is.

The limit described here is about observation **at the exact moment** of the connection, a problem that neither network fully solves (technical detail and official sources in `technical-manual.md` § "Traffic correlation resistance").

### Contacts Tab

The third fixed tab — **Contacts** — shows the full address book with the reachability status of each contact, grouped by trust level — from most to least trusted, with one exception: a contact in key conflict (see below) always comes first, before every other group, because it needs more urgent attention than a contact that's simply never been verified:

```
KEY CONFLICT
  14:35 ●◌ "Lord Death    " (LordDeath9    ) [REL:        ]

VERIFIED & INTRODUCED
  14:32 ●● "the_blond_one " (xy001         ) [REL:AB12CD34]

VERIFIED CONTACTS
  14:20 ●◌ "Lord Death    " (LordDeath9    ) [REL:        ]

INTRODUCED CONTACTS (UNVERIFIED)
  --:-- ✗◌ "______________" (carol77       ) [REL:9F8E7D6C]

UNVERIFIED
  --:-- ◌◌ "______________" (zzskd         ) [REL:        ]
```

A group appears only if it contains at least one contact — if you don't yet have anyone "introduced," that section simply doesn't show up. Within each group, contacts are sorted by secondary trust: first those whose relationship keys are already exchanged in both directions, then by reachability (from best to worst pair, see the table below), and among ties alphabetically by username.

Each group's header is colored according to its trust level:

| Header | Color |
|---|---|
| `KEY CONFLICT` | red |
| `VERIFIED & INTRODUCED` | green |
| `VERIFIED CONTACTS` | green |
| `INTRODUCED CONTACTS (UNVERIFIED)` | yellow |
| `UNVERIFIED` | red |

**"KEY CONFLICT"** appears when an already-confirmed contact announces two relationship keys (identity and content) that differ from the ones already known — indistinguishable from a legitimate restore of the contact or an attempted substitution: the new keys stay pending, never applied automatically, until you explicitly confirm with `/sec-verify <contact>` (see "Verifying identity" below).

The trust tag (`[VERIFIED]`, `[UNVERIFIED]`...) for each individual contact remains available via `/cnt-info <contact>` or, for all members of a room at once, via `/grp-info` while you're inside that room (see "### Group" below) — and, only for those who were introduced, also the name of whoever presented them.

Each row starts with the time of the last probe (`--:--` if not yet probed), followed by two indicators that are independent of one another: the first tells whether **you** can reach the contact (a plain connection test, repeated every cycle), the second whether **the contact** can reach you (an application-level confirmation, which can arrive at a different moment than the first indicator).

| Pair | Meaning |
|---|---|
| `●●` | You see the contact, and they've confirmed seeing you |
| `●◌` | You see the contact, no confirmation has arrived yet |
| `●✗` | You see the contact, but no confirmation has arrived for a while despite reaching them continuously |
| `✗●` | You don't reach them right now, but they've reached you anyway (even just once, at a different moment) |
| `✗◌` | Not reachable, no confirmation |
| `◌◌` | Never probed in either direction |

The second indicator doesn't depend on the first: it can turn green even if you don't reach the contact right now (all it takes is them having reached you, even once), and once green it stays that way until a more recent proof arrives — it never turns gray back on its own. It only turns red if you keep reaching them continuously for a while without ever receiving any confirmation — never while you don't reach them, since in that case you haven't even given them the chance to respond.

**Red never points to a specific cause.** "No confirmation despite repeated attempts" is indistinguishable, from the outside, from at least three different situations: an asymmetric network problem (they reach you but you can't get a response back to them, or vice versa); they removed you from their own address book (the protocol always responds the same way to a contact attempt, matched or not, precisely so no one can tell whether they were recognized or discarded); or a plain delivery hiccup that resolves itself on the next cycle. None of these is distinguishable from the others, by design.

`/cnt-info <contact>` shows, alongside the safety code and trust status, the time of the last "seen by them" confirmation received (or that none has arrived yet) — useful because the green dot alone doesn't say whether the confirmation is recent or days old.

The name shown is the **local name** in quotes if you've set one (`"the_blond_one"`, `"Lord Death"`...), or a placeholder `"______________"` in the same quotes if you haven't yet done so for that contact — identical treatment in both cases, so you can always spot at a glance where the local name is. Then follows the **real network username** in parentheses (without quotes), always visible (see the box about the username in the wizard chapter above). Both columns — local name/placeholder (quotes included) and real username — are always fixed at 16 and 14 characters wide (truncated beyond), to stay aligned the same way row after row instead of shifting. The `[REL:XXXXXXXX]` badge always appears, but it's green only if the relationship keys with that contact are already exchanged in both directions — otherwise it stays gray with the code space left blank (`[REL:        ]`), consistent with the rest of the interface (gray = neutral, informational color). Trust level (whether you've already confirmed the contact's identity over an independent channel — see "Verifying identity" below) is the criterion by which the groups are composed, communicated once by the group's colored header.

The tab refreshes automatically every minute (periodic polling with backpressure: if the previous cycle hasn't finished yet, the new one is skipped). You can force an immediate refresh with `/active`. It cannot be closed with `/grp-exit`.

### Groups Tab

The fourth fixed tab — **Groups** — shows the list of groups saved with `/grp-save`:

```
● catechism      [a1b2c3d4]  4 members  [open]
    members: alice, bob, carol, dave

○ nightclubs     [f9e8d7c6]  7 members
    members: eve, frank, grace, ...
```

Unlike Contacts, there is no reachability probing for saved groups — probing them would require reopening them with `/grp-recall` (a new secret, new invites to all members), too heavy an action just to show a status. The only indicator is `●`/`[open]` if the group already has an active tab in this session, `○` otherwise. The member list shows at most 8 usernames, `...` if there are more. It cannot be closed with `/grp-exit`; from here use `/grp-recall <name|ID>` to reopen a group.

### Two-person chat

This is not a different type of room from a group — it's a group with exactly two members (you and the other person), created with `/grp-invite <name>` exactly like a larger group. Header, colors and `/grp-info` are identical to what's described in "### Group" below: no bar or command dedicated solely to two-person rooms.

Two properties change only because there happen to be two participants, not because the underlying model is different:

- **No intermediary in the conversation.** The room's host is always the other person themself (never an unrelated third party), so every message you receive comes from someone you already know for certain — unlike a larger group, where the host may be unrelated to a conversation between any two given members.
- **Additional Diffie-Hellman ratchet** (post-compromise security beyond mere forward secrecy) kicks in automatically only when the room has exactly two members — see `cryptography-manual.md` §5.1.

For the out-of-band comparison of identity (manual safety number verification) see "Verifying identity" below: it must always be done over an independent channel (phone, video, in person) — a comparison made only inside the app would prove nothing against someone controlling the entire connection.

### Group

A room with more than one participant. Each invitee receives their own individual access secret from the host (see `/grp-invite` below) — no shared password to know in common: whoever holds only their own secret cannot claim to be another member of the room.

The group tab's header shows all invited members with a colored marker from the moment of creation:

| Dot | Name | Meaning |
|---|---|---|
| `●` green | cyan | You |
| `●` green | green | Member connected, relationship keys already established |
| `●` green | yellow | Member connected, relationship not yet established (only Safety Number available) |
| `●` red | gray | Member left with `/grp-exit` |
| `●` red | red | Member crashed, dropped, or never joined |

The color alone tells you "who is online" and "with whom the relationship keys are established," but not the detail: trust tag, full safety code, relationship code. For that, `/grp-info` shows a summary of all members (excluding yourself), two lines each — status on the first, identity detail on the second:

```
▸ room catechism
● alice  [VERIFIED]
    identity: [REL:a1b2c3d4 ✓ relation established]
● bob  [INTRODUCED BY alice — UNVERIFIED]  (/sec-safety to verify)
    safety: a1B2c3D4 e5F6g7H8 i9J0k1L2 m3N4o5P6 q7R8s9T0
● carol  [UNKNOWN]  (/cnt-add)
    safety: Z9y8X7w6 V5u4T3s2 R1q0P9o8 N7m6L5k4 J3i2H1g0
```

The safety code shown here applies to **anyone in the room**, even someone you haven't saved as a contact — their network identity is already known from the invite, adding them as a contact only lets you verify and remember the outcome, not "unlock" the code. `/cnt-info` with no argument opens the picker to choose a specific contact (see "Commands" below), inside or outside a room alike.

---

## Commands

Command names are always in English (`/grp-invite`, `/cnt-edit`...), regardless of the interface language chosen at first launch (or set later with `neutrino lang`, see below): only each command's argument hint and description — shown in `/help` and in the command palette — are translated, never the word itself typed after the slash.

Address book/group/identity management commands (`/cnt-add`, `/cnt-del`, `/grp-del`, `/cnt-edit`, `/grp-save`, `/sec-passwd`, `/sec-rotate-rel-identity`, `/sec-rotate-rel-content`) always show confirmation and any error in the **Console** tab (with the red dot, see above) — regardless of which tab you run them from.

### Contacts

**`/cnt-add <URI|username pubkey>`**
Adds a contact to the keystore, in two forms:
```
/cnt-add nu://username/BASE64PUBKEY[/BASE64MLKEMPUB/BASE64MLDSAPUB]
/cnt-add username BASE64PUBKEY
```
The `BASE64MLKEMPUB`/`BASE64MLDSAPUB` segments (present in QR codes/URIs generated by this version) carry the contact's two durable post-quantum keys — ML-KEM-768 to protect future invites, and ML-DSA-65 to sign key rotation and remote self-destruction — even against a computer powerful enough to break classical cryptography alone; an older URI without those segments is still valid — the contact is added just the same, only without this extra protection until you exchange an updated QR. The second (manual) form never carries these segments. As soon as the contact is saved, the app automatically and silently exchanges with them, in the background, the relationship keys dedicated to this new relationship (see "Message signing" below) — no further action needed.
The first form also accepts a scanned/pasted QR code directly. After parsing, the TUI shows a summary (username, key) with the prompt `Save this contact? [Y/n]`: `y` (or Enter) moves on to the next step, `n`/Esc cancel without saving anything. Once the summary is confirmed, the TUI asks for the local name (default: network username); press Enter to confirm or Esc to cancel. A contact's unique identifier is its key (the full URI), not its name: two contacts can share the same username and coexist fine, as long as the key is different (for example after someone runs `/nukex` and recreates themselves with a new identity but the same name). If the key exactly matches one already in the address book, the operation is rejected (no silent overwrite) — use `/cnt-del` first if you want to replace it.

**`/cnt-read-qrcode`**
Reads an identity QR code and starts the same flow as `/cnt-add` (summary + local name). It first asks for the source:
```
Read QR from:

  f — image file (local)
  c — camera
```
With **f** it opens a filesystem browser (same one as `/grp-file-send`'s, rooted at the directory Neutrino was launched from) to pick a local PNG/JPEG image containing the QR — arrow keys navigate, typing filters by name, **→**/Enter opens a folder or confirms a file. With **c** it opens the system camera and shows a live preview rendered in ANSI characters directly in the terminal (no separate graphical window — useful over an SSH connection) until it recognizes a valid QR or you press Esc to cancel. On Linux the camera is driven directly via V4L2, no external program required (no `apt install` of any kind needed for this feature, consistent with the rest of the app).

> **An identity's QR is often more than one image.** Since a public key includes the post-quantum ML-KEM-768 and ML-DSA-65 components alongside the classical Ed25519 one, the full identity often doesn't fit in a single QR code. When it doesn't, the person sharing it gets **several numbered QR images** instead of one (same mechanism as the backup/address-book export below). From the file browser, **Space** toggles a file into a multi-selection (shown as `[x]`) — select every numbered part (part1, part2...) and confirm once with Enter to read them all in one go, instead of reopening the browser after each one; selecting a single file (or just pressing Enter with nothing toggled) still works exactly as before. The same picker also simply reappears automatically after a camera scan that only resolved one part, so file and camera sources can be mixed freely across parts — a single-part identity works exactly as before either way, with no extra step.

> **Always read the original `.png` file.** These multi-part QR images sit at a very high density (near the maximum QR version) to fit all three keys — barely any margin is left for data loss. Saving or sharing one through a phone's gallery or a messaging/social app frequently re-encodes it as JPEG along the way, even though the file still ends in `.png` or looks unchanged; that compression is lossy and blurs exactly the fine module edges a QR decoder depends on, which can make an otherwise perfectly generated identity QR unreadable. If `/cnt-read-qrcode` fails on a file that came from anywhere other than Neutrino's own save location, try the original `identity-qr-<username>-partN.png` instead of a re-saved or re-shared copy.

> **Best practice — exchanging the QR safely.** Adding a contact from a QR received via message, email or downloaded from a website **does not guarantee** that key really belongs to the person you think it does: anyone intercepting or substituting that file can create one with their own key, and nothing in the app would flag this on its own — not even verifiable possession of the keys would prevent it, because it only proves "I'm talking to whoever has this key," not "this key really is theirs" (see "Verifying identity" below for why). Because of this:
> - **Prefer exchanging in person** (showing/scanning each other's QR face to face) or over a channel you already know to be authenticated (e.g. a call where you recognize the voice).
> - If the QR arrives over a channel you don't fully control (message, email, download), **after** adding it use `/sec-verify <contact>` to compare the full code with the person over an independent channel (phone call, video call) — only after that confirmation does the contact truly count as "verified" in the address book.
> - Until you do, the contact stays labeled `[UNVERIFIED]` — a reminder that this step is still missing.

**`/cnt-del <username|name>`**
Removes a contact from the keystore (by network username or local name).

**`/cnt-edit [<contact>]`**
Edits a contact's local name (personal alias). With no argument opens the address book popup to choose the contact; then asks for the new local name (leave blank to remove the alias).

**`/cnt-info [<contact>]`**
Shows in a popup the `nu://` URI, the `.onion` address, the local name (if set), who (if anyone) introduced the contact (if they arrived via `/grp-contact-send` — see "Contact transfer" below), the safety code, the verification status and (for contacts) the last time seen online, all stored for a contact. Any key closes the popup. If called with no argument, it first opens an address book popup with "self" at the top and contacts in alphabetical order; filter by typing, navigate with `↑`/`↓`, select with `Enter`, cancel with `Esc` — inside or outside a room alike. `/cnt-info self` shows your own data (URI and address only).

**`/grp-info`**
Inside a room, shows in a popup — for every member at once, in one go — connection status, trust tag, and the safety code or, if the relationship keys with that member are already exchanged in both directions, confirmation of the established relationship (see "### Group" above): no need to pick a single member to see their identity in this room.

### Verifying identity

Every contact has a verification status, visible in the address book. It is independent of the automatic relationship-key exchange — see the "Best practice" box above for why: possessing and correctly using a given key only proves you're talking to whoever holds that key, not that this key really belongs to the person you think. Only a comparison you make yourself, over a channel independent of the app, closes this gap.

There are four possible labels, depending on verification and the contact's provenance:

| Label | Color | Meaning |
|---|---|---|
| `[UNVERIFIED]` | red | Not yet verified, added directly (knock, QR, manual) |
| `[INTRODUCED BY <name> — UNVERIFIED]` | red | Received as a card from another contact (see `/grp-contact-send` below), not yet verified in person |
| `[VERIFIED]` | green | Verified in person, added directly |
| `[VERIFIED — INTRODUCED BY <name>]` | green | Verified in person, but originally presented by another contact |

Provenance ("introduced by") is purely informational, to keep track of the trust chain: it does not affect cryptography and does not automatically propagate from the trust placed in the introducer — an introduced contact still needs to be verified in person like any other. `/cnt-info <contact>` always shows who (if anyone) presented them.

These four labels exist only for contacts who **are already** in the address book. Someone who isn't there at all — a room member never added as a contact — doesn't fall on this scale: `/grp-info` and chat show `unknown` instead (see "### Group" above and "Message signing" below, respectively), a deliberately different label so as not to confuse "not yet verified" (I know them, just missing confirmation) with "I have no idea who this is."

**`/sec-safety [<contact>]`**
Shows in a popup the full security code (40 characters) with a contact. With no argument opens the address book popup to choose the contact (inside a room, `/grp-info` instead shows the code for all members at once — see "### Group" above). Doesn't mark anything as verified — it's purely for viewing the code.

**`/sec-verify [<contact>]`**
Walks you step by step through full verification: shows the security code (40 characters) with instructions to compare it in full with the contact over a channel that is **secure and independent of the app** — phone call, video call, in person. Right after, it asks `Do you consider contact X secure? [y/n]`: answer `y` only if the code shown on your screen matches *exactly*, digit for digit, the one shown on your contact's screen. An affirmative answer marks the contact `[VERIFIED]`; `n`, `Esc` or `Ctrl+C` cancel without changing anything. With no argument it opens the address book popup.

**`/sec-unverify [<contact>]`**
Removes the `[VERIFIED]` mark from a contact, who goes back to `[UNVERIFIED]` (or `[INTRODUCED BY …]`). Use it if you confirmed a verification by mistake, or if you suspect the contact's device has been compromised. With no argument it opens a popup listing only your verified contacts.

> **On a contact in `KEY CONFLICT`, `/sec-verify` shows two codes instead of the usual safety number** — one for the relationship identity key, one for the content key, both computed on the **new keys proposed** by the contact, never on the old ones already in the address book (which wouldn't help here: they haven't changed, they're not part of the conflict). Compare them the same way, out of band — if they match and it's really them, answer `y`: the new keys are applied and the contact leaves the conflict, but it does **not** automatically become `[VERIFIED]` (the previous trust applied to the old keys, it needs to be re-earned) — run `/sec-verify` a second time for the usual safety number if you want to get back to `[VERIFIED]`.

> **When the status reverts to `[UNVERIFIED]` on its own.** If the network address of an already-verified contact changes in a way the app can't reconnect to their previous identity, the status automatically reverts to `[UNVERIFIED]` — the verification you did applied to the previous identity, it needs to be redone on the new one. The relationship keys (used to authenticate the handshake and sign/encrypt in a room with them) are independent of this status: they rotate — on the explicit initiative of either side, `/sec-rotate-rel-identity`/`/sec-rotate-rel-content` — without ever requiring a new verification, because the new key is automatically certified by its sibling key already established with them.

### P2P connections

**`/active`**
Probes all contacts in the keystore in parallel via Tor/I2P to see who is online. The result updates the Contacts tab; each contact that can't be reached is also reported in the Console as `✗ unreachable: <name>`. The same cycle also resends a pending root IdentityKey rotation (`/sec-rotate-key`) to your own devices that haven't adopted it yet.


### Groups

**`/grp-invite <user1> [user2…]`**
Creates a new group with the listed users (they must be contacts in your address book), generates a unique `groupID` and sends the invites via encrypted knock. Automatically opens the group room in your own client. Each invitee receives an **individual** access secret, never shared with the other members — knowing only your own doesn't let you claim to be another member of the group. If an invitee explicitly declines (Esc on their own invite popup), their name shows up grey in the room's member grid. If after 2 minutes no one has joined yet — or, sooner, if every invitee has declined — a popup asks whether to close the room: `Enter`/`y` closes it, `Esc`/`n` keeps waiting (you can still close it at any time with `/grp-exit`).

**`/grp-join <groupID>`**
Accepts a received group invite and connects to the room. The groupID is shown in the incoming knock. As soon as you press Enter a "Connecting…" popup appears, staying visible until the connection either succeeds or fails for good — useful because on I2P the first connection can take several seconds.

**`/grp-save <name>`**
Saves the current group's composition (local name + member list) to the keystore, so it can be reopened later with `/grp-recall`.

**`/grp-recall <name|ID>`**
Reopens a group previously saved with `/grp-save`.

**`/grp-del <name|groupID>`**
Removes a saved group from the keystore.

**`/grp-reinvite [<name>]`** *(group host only)*
Resends the encrypted knock to a member of the current group who appears offline, to bring them back into the room. With no argument, re-invites all offline members. Always generates a new access secret for the re-invited member — the previous one stops working from that moment on.

**`/grp-add-member <contact>`** *(group host only)*
Adds a new member to an already-open group, without having to recreate it from scratch. The new member receives an individual access secret via encrypted knock, like any other invite.

**`/grp-ban <user>`** *(group host only)*
Permanently removes a member from the current room.

**`/grp-promote <user>`**
Promotes an "introduced" member of the current room — someone you know only through this room, never added directly as a contact — to a real, persistent contact in your address book. Opens a picker over eligible members if the argument is omitted or invalid. Requires the same explicit action on **both** sides (each of you runs `/grp-promote` toward the other): once both confirmations have arrived, the new contact is created reusing the relationship keys already exchanged for this room, plus the transport address just received — no new verification is implied, the resulting contact starts `[UNVERIFIED]` like any other (see "Verifying identity" below).

### Contact transfer

**`/grp-contact-send <name>`**
Shares the card of a contact from your own address book with one or more members of the current room — any number of members; the argument is only the local name or network username of the contact **to share**, not the recipient. Before sending it asks for a **mandatory out-of-band contact method** (phone, email, Telegram...): a way for whoever receives the card to reach the described person outside the app and compare the safety code — without that channel, verification would be impossible (see "Verifying identity" above). Enter does nothing until you've typed something; Esc cancels the send. The contact method is never saved anywhere, neither in your keystore nor the recipient's — it's only shown once, at the moment of receipt. The rest reuses exactly the same mechanism as `/grp-file-send` below: same recipient-picker popup (with more than one eligible recipient), same encryption, same requirement — the relationship keys already exchanged both on your side and on each recipient's. When the recipient receives the card, a system message appears with the contact's name, the out-of-band contact method, and instructions for saving or discarding it.

**`/cnt-save`** *(after receiving a card)*
Saves the contact received via `/grp-contact-send` to the keystore. As with `/cnt-add`, the existence check is on the key, not the name: if the key exactly matches one already in the address book, the operation is **rejected** (no silent overwrite) — use `/cnt-del` first if you want to replace it; if the name matches but the key is different (a different identity with the same username), it's added as a separate contact. If whoever sent the card was describing themself, the contact ends up added directly (no "introduced" label); if they were describing a third party, the contact ends up "introduced" by whoever presented them (visible in `/cnt-info` and with the `[INTRODUCED BY <name>]` label in the Contacts tab, see "Verifying identity" above) — in either case no automatic verification starts: it needs to be verified in person (using the out-of-band contact method received along with the card) whenever you actually want to trust it.

**`/cnt-ignore`** *(after receiving a card)*
Discards the received contact card without saving it.

### File transfer

**`/grp-file-send`**
Sends a file encrypted and signed to one or more contacts, using the relationship keys dedicated to each. Requires the relationship keys to already be exchanged — both on your side and the recipient's: only members with this relationship already established show up as selectable. It's the only way to encrypt so that *only* the chosen recipients can open the file, even if someone else present in the same group room happened to receive the encrypted traffic by accident.

The command walks you through a few steps:
1. **File selection** — a browser opens to navigate the filesystem: `↑`/`↓` scroll the list, `→`/`Enter` enter a folder or select the file, `←`/`Backspace` go up to the parent folder, `Esc` cancels. Typing any letter filters the names visible in the current folder.
2. **Recipient selection** — a popup lists room members with the relationship already established, all preselected already; `Space` excludes anyone you don't want to include, `Enter` confirms.
3. **Send speed** — `slow` (default, gentler on the connection) or `warp` (maximum speed); `↑`/`↓` to choose, `Enter` to confirm.

Each recipient receives a confirmation request with your name, the file name, and its size — `Enter`/`y` accepts, `n`/`Esc` declines, before a single byte goes out.

Progress is shown in the **"File"** tab, always present in the tab bar: one row per group of recipients at the same point of progress, sftp/scp-style — direction (↑ send, ↓ receive), sender, file name, recipient(s), three fixed dots, the right-aligned percentage and, once available, a chunk count (send side: sent/total; receive side: received/non-contiguous awaiting placement/total) — no colors (only the numbers change as the transfer progresses). As long as every recipient stays in step, only one row is shown; if one or more fall behind (a disconnect, or resuming from a different point) they get their own row with a separate percentage, merging back into a single row once they catch up. Once a transfer is received and the signature verified, a popup opens to rename the file first (name proposed by the sender, editable, `Enter` confirms), followed by the folder browser to choose where to save it — same navigation as step 1 above, plus a "» save in this folder «" entry at the top of the list; if the signature is invalid the file is discarded and the error reported, without opening anything.

> **Sending starts once whoever has already accepted is collected.** There's no need to wait for every recipient to respond: after the offer is sent, the app waits a short window (10 seconds by default) to collect whoever accepts nearly at the same time into a single start, instead of beginning at the very first accept and having to chase everyone else right after — if everyone has already responded before that window even elapses, sending starts immediately. Anyone who accepts later is still folded into that same send already in progress, receiving everything already sent to the others so far — without blocking anyone. If nobody accepts at all within a limited time (90 seconds by default), the whole send is cancelled. A recipient who stops responding partway through a transfer is excluded from the rest of that send until they reconnect: on reconnection (theirs or the sender's), the app automatically announces where to resume from, with no need to resend from scratch — meanwhile the other recipients keep receiving normally, never blocked waiting on them.

### Tools

**`/help`**
Opens a scrollable overlay with the list of all commands. Navigate with `↑`/`↓` (line by line) or `PgUp`/`PgDn` (page); `Esc` or `Enter` to close. The overlay automatically adapts to the terminal's height.

**`/quit`**
Asks for confirmation before exiting the application (`y` to confirm, `n` or `Esc` to cancel). It's the only way to exit Neutrino: `Ctrl+C` and all OS signals are intentionally ignored.

**`/grp-exit`**
Closes the current tab (any tab except Console, Contacts, Groups, Tor and File, which are always permanent). Sends a clean exit notification to the server: other members will see your name turn gray (voluntary exit). If instead the process crashes without `/grp-exit`, others will see the name in red (sudden drop).

**`/grp-ping [<user>]`**
Measures round-trip time via Tor/I2P to a member of the current room. With a name, pings that member directly; with no argument, if there's only one other member it pings them right away, otherwise it opens a popup to choose who to ping among everyone present (a room with many members is pinged one at a time, not all at once). Sends 5 probes 1 second apart and shows the results in a popup, updated in real time as responses arrive, with a min/avg/max summary at the end. Any key closes the popup (if you close it before all 5 probes complete, the remaining results won't be visible):

```
ping alice via Tor/I2P  (5 probes, 1s interval)
ping 1/5  rtt=312.4 ms
ping 2/5  rtt=298.1 ms
…
--- ping: min=287.3ms  avg=304.0ms  max=321.7ms  (5/5 pong received)
```

**`/msg <number>`**
Sets an explicit reply reference ("reply to") for the **next** message you send in this room — one-shot: after sending, the reference clears itself automatically, so it must be repeated for each new reply. `<number>` is the number shown at the end of each line's header (`#N`, assigned by the server as soon as the message is delivered) — you can only reply to a message already shown in THIS tab: a number that doesn't exist, hasn't arrived here yet, or isn't yours to reference is rejected with an error in Console. After `/msg N`, an indicator `↩ replying to #N — <preview>` appears above the text field until you send (or overwrite it with a new `/msg`); the message sent with that reference shows the same line above its own text, visible to whoever receives it too.

**`/grp-health`**
Shows the local server's status: `{"status":"ok","users":N}`.

**`/grp-msg-acks`**
Inside a room, opens a picker over your own last 20 sent messages that still have an ID (`#N`) — pick one to see which room members have confirmed receiving it.

**`/debug <on|off>`**
Turns additional diagnostic output in the Console tab on or off (which is always present from startup, see "Console Tab" above).

**`/compact <on|off>`**
Turns compaction of repeated lines in the Console tab on or off — when active, a line identical to the one immediately before it isn't repeated but increments a counter next to the existing line (`× N`), useful for not scrolling away important messages during a noisy probe cycle. Affects only the Console tab, never chat rooms.

**`/grp-reconnect`**
Manually reconnects the current tab after a disconnection (EOF, timeout) and also forces a rotation of the message encryption key. Normally not needed: every tab (Tor/I2P or the room where you're the host, connected locally) reconnects automatically on its own. Use it if a tab stays stuck longer than expected, or if messages stop decrypting correctly.

**`/show-qr`**
Shows your own identity QR code in a popup, without leaving the TUI — the same data as `neutrino show-qr`/the PNG saved at first launch, useful to share it mid-session.

**`/info-app`**
Shows the application version in a popup — a quick way to check whether you're running the latest compiled build.

**`/sec-passwd`**
Changes your identity's own identity password — never the file password, shared with every other identity in the file and untouched by this command. Asks for the current identity password, then the new one twice — as you type it a strength estimate appears alongside (very weak/weak/acceptable/strong/very strong), purely informational: it does not block weak passwords, the real defense against offline brute-force remains Argon2id (see box below).

**`/sec-backup`**
Shows a popup with the 24 BIP-39 words of the identity, numbered `01`–`24`. Press any key to close. The words represent the Ed25519 seed and should be written down on paper in a safe place — with them you can recover your own `.onion` address.

**`/sec-duress`**
Changes the decoy identity's own identity password, asked interactively — no argument (the decoy always exists, structurally — see "First launch" above — and can never be removed, only changed). Unlocking with the file password and this password instead of your real one opens the decoy identity instead (see "Remote self-destruction" below).

**`/sec-lock`**
Locks the interface immediately — the screen shows only an unlock prompt, no room content is readable until you unlock. Tor/I2P, open rooms and every background cycle (probing, retries, key rotations) keep running unaffected; nothing is torn down. Always available: your identity password (see `/sec-passwd` above) always unlocks the lock again, whether or not a PIN has also been set up.

**`/sec-lock-pin`**
Sets or replaces an *additional*, optional numeric PIN (minimum 4 digits) that also unlocks the interface lock — your identity password always unlocks it regardless, so a PIN is never required for the lock to be usable. Asks for the new PIN, a confirmation, then optionally a **native duress variant** — one extra character at a position you choose within the PIN. Typing the PIN *plus* that character in that exact position at the unlock prompt is recognized as duress — same outcome, and the same self-destruction sequence described under "Self-destruction" below, as typing the decoy identity's password at this same prompt (see `/sec-duress` above). The decoy identity's own password, if you know it, also still works at this same prompt regardless of whether a PIN is configured.

**`/sec-lock-timeout <duration|0>`**
Sets the inactivity threshold (no keypress, no command) after which the interface locks itself automatically — e.g. `30s`, `1m`, `2m`; `0` disables automatic locking (default). The manual `/sec-lock` command stays available regardless of this setting.

**`/sec-nuke-timeout <duration|0>`**
Sets how long the interface may stay **locked** before an automatic secure erasure triggers — distinct from `/sec-lock-timeout` above, which only measures inactivity *before* the lock engages. Same syntax (`30s`, `1m`, `2m`; `0` disables it, the default). Works independently of whether a lock secret is configured — unlike the lock itself, this can't be "useless" just because no secret was ever set.

**`/sec-pqc-sign <on|off>`**
Turns an additional ML-DSA-65 signature on every message sent on, or off, for the current room only — protects individual messages too (not just relationship-key rotation and remote self-destruction, already protected by construction) against a future quantum attacker capable of forging an Ed25519 signature. Increases the size of every message by a few KB: off by default, turn it on when this level of protection matters more than bandwidth. Every message line always shows a `[PQC]` tag — green if that message is protected this way, red if it isn't. Toggling it notifies every other room member of the change.

**`/nukex`**
**NUKE EXPRESS** — wipes every real contact in place, destroys the real identity's slot and silently swaps your session to the decoy identity, with no confirmation. See "Self-destruction" below for the full sequence.

**`/sec-rotate-rel-identity <contact>`** *(advanced)*
Rotates the relationship IdentityKey toward a specific contact — the key that authenticates connections with them. Generates a new key pair and sends it to the contact, certified by the relationship ContentKey already established with them (stable, untouched by this rotation): it doesn't require a new manual verification, cross-certification alone is enough for the other side to accept it automatically. Opens a picker if the contact is omitted or invalid. If a rotation is already in progress toward that contact (identity or content), the command refuses to start a second one until the current one closes. The announcement is resent on every probe cycle until the contact confirms — indefinitely, no deadline.

**`/sec-rotate-rel-content <contact>`** *(advanced)*
Same mechanism as `/sec-rotate-rel-identity`, but for the relationship ContentKey — the key that signs/encrypts what you exchange with them in a room (messages, files, contact cards). Certified by the stable relationship IdentityKey.

**`/sec-rotate-key ROTATE`** *(rare, wide-reaching)*
Rotates your root IdentityKey — the key your network address (`.onion`/`.b32.i2p`) is derived from. Generates a new address and publishes a second hidden service in parallel (the old one stays active, no disconnection): online contacts receive it right away, offline ones when they come back. The announcement toward each contact is certified by the relationship key already established with them — it doesn't require a new manual Safety Number verification. If a relationship-key rotation is already in progress toward a contact, the announcement stays queued until it closes; conversely, starting a relationship rotation while this one is in progress toward the same contact is refused. Type exactly `ROTATE` as the argument to confirm — a rare operation, not needed for everyday use.

**`/sec-device-sync <device>`**
Syncs the address book with one of your own known sibling devices (same identity, another device — identified by device label or a hex prefix of the device ID). If the argument is omitted or doesn't match a known device, the command lists the known device labels in Console instead of syncing (no interactive picker on desktop). Uses the same direct device-to-device channel through which, during a `/sec-rotate-key` rotation, your other devices automatically receive the new key.

---

## Android app (graphical interface)

> **In testing, not distributed yet.** The Android app is not part of the current releases; the notes below apply to the builds in testing.

A separate native app (APK, Fyne interface) with the same networking and cryptography as the TUI described so far, but with touch screens and buttons instead of `/slash` commands — no physical keyboard needed, no commands to memorize. Different from running Neutrino under Termux (which is the exact same TUI as this manual, inside an Android terminal — see `termux-manual.md`): this section is about the actual graphical app.

### "⋮" menu

Two distinct "⋮" menus, not one shared. The header one, before the "Neutrino v<version>" label at the top, contains application commands: **Settings** (see below), **Info** (shows the app version — touch equivalent of `/info-app`), **Backup**, **Sync contacts**, **Share identity** (your own identity QR), **Send file via QR**, **Receive file via QR**, **Secure wipe** and **Quit**. None of them needs the network, so the same menu is already available on the "Before connecting" screen. The "⋮" menu inside Contacts and in the title of every open room is instead the page one: it always contains **Page help** (shows the help text for whichever screen you're looking at), plus — inside a room — that room's specific items (see "Inside a room" below). A received invite is never a menu item: it immediately opens an Accept/Ignore popup (see below).

### Settings

Reached from the header "⋮" menu, it gathers every function that on the TUI is a terminal command (`neutrino <command>`, never a slash command) plus links to otherwise scattered screens: **Security** (see below), **Identities** (multiple-identity management — see "Multiple identities" below), **Theme** — a manual choice between the Standard theme and the Dark theme, applied immediately with no app restart and **independent** of the phone's own light/dark setting: it stays whatever you picked until you change it again — **Language** and **Network** (Tor/I2P, both effective on the app's next launch, not live), **Advanced settings** (the operational parameters of `config.json` on desktop, effective on the next launch) and, at the bottom, **Reset to default settings** (language, network and theme only). Backup, contact sync and secure wipe are in the header "⋮" menu instead (see above).

### Fixed buttons and incoming invites

Just like on the TUI, five fixed buttons stay visible at all times in the navigation row, in order: **Console** (the page open at startup), **Tor**/**I2P** (your node's status — the same `out`/`in`/hidden-service dots as the TUI), **Contacts**, **Groups**, **File**. Every room you open is added after these five, as a permanent button.

The **Console** tab includes, at the bottom, a tappable list of every general command (not tied to an open room) — the touch equivalent of the TUI's `/slash` commands, `/help` always at the top: a tap runs the command immediately, nothing to type; if it needs a parameter (a contact, a group...) it opens the same screen or picker already used for that function elsewhere in the app, never a free-text field to fill in by hand.

A received invite (knock) immediately opens a popup in the foreground with the host's name and the room ID, with two choices: **Accept** to join the room, **Ignore** to discard it. If more than one arrives, they're shown one at a time, queued. **Ignore** also notifies whoever sent the invite (the member's name turns grey in the room's member grid, on the host's side); if after 2 minutes no one has joined yet — or if every invitee has declined sooner — the host sees a popup asking whether to close the room.

### Contacts

The address book shows, for each contact, two tappable dots in place of the TUI's `●●`/`●◌`/`●✗`/... pairs:

| Dot | Meaning |
|---|---|
| First ("I see them") grey | Never probed |
| First ("I see them") green | Reachable right now |
| First ("I see them") red | Probed, not reachable |
| Second ("they see me") grey | No confirmation has arrived yet |
| Second ("they see me") green | The contact confirmed seeing you (stays green until more recent information arrives, even if you stop reaching them in the meantime) |
| Second ("they see me") red | No confirmation despite reaching them continuously for a while — never points to a specific cause (can be a network issue on either side, or a relationship that's no longer mutual) |

The second dot doesn't depend on the first: it can be green even when the first is grey or red — all it takes is the contact having reached you even once. Tapping a dot opens a popup with the status in words plus a legend — doubles as a mini-help. A checkbox per contact plus the **Invite selected** button create a group room with every chosen contact in one step — the touch equivalent of `/grp-invite`.

The **Read QRcode** button (touch equivalent of `/cnt-read-qrcode`) first asks for the source — image file or the phone's native camera — then shows the same summary (username, key) with confirmation before asking for the local name, exactly as on the TUI. If the identity spans several numbered QR images (see note above), it re-asks for the source after each one until all parts are in, same as on the TUI.

Tapping a contact's name opens their detail page — the touch equivalent of `/cnt-info <contact>`: a trust badge, **the full `nu://` URI, network address, the relationship keys already exchanged with them (if any), last connection, and the last "seen by them" confirmation** (the title at the top only shows the last 8 characters of the `[REL:...]` code, as a compact identifier), an **Invite** button to open a room with them right away, the Safety Number always shown with a **Mark verified** button (touch equivalent of `/sec-verify`) or, on a verified contact, a **Remove verification** button (touch equivalent of `/sec-unverify`), a local name field with a **Rename** button (also clears it if the field is emptied — touch equivalent of `/cnt-edit`), and finally **Delete** (touch equivalent of `/cnt-del`).

If the contact is in **KEY CONFLICT** (red badge, shown first in the address book ahead of every other group — same meaning as `KEY CONFLICT` on the TUI), the Safety Number block is replaced with a warning and two codes (identity and content) computed on the new keys proposed by the contact, with a **Confirm new keys** button instead of "Mark verified": compare them out of band like the usual code, and confirm only if they match and it's really them. Once the keys are applied, the contact leaves the conflict but isn't marked verified — tap the Safety Number button again if you want to re-verify it.

### Inside a room

Besides the title and messages, a grid shows **every** known member of the room (not just who's connected right now): a green dot for anyone connected, red for anyone who isn't — an invite that was never accepted still shows, it doesn't disappear. Next to each of your own messages: "○" until no one has confirmed receiving it yet, "✓N" once N members have confirmed it — updates itself. Every message also carries a tappable ↩ icon: tap it to set that message as the explicit reply reference ("reply to") for your next send — an indicator with a preview appears above the text field, with a dedicated button to cancel it before writing, and it clears itself after sending (one-shot, touch equivalent of `/msg N`). The bottom field is for messages only: every room command (no `/slash` text to type) lives in the room's "⋮" menu, which gathers **Room info** (touch equivalent of `/grp-info`, a single popup with the status of every member), **Send file**, **Send contact card**, **Reinvite offline member** (touch equivalent of `/grp-reinvite`), **Add member** (touch equivalent of `/grp-add-member`), **Ping** (touch equivalent of `/grp-ping`), **Reconnect** (touch equivalent of `/grp-reconnect`, forces the room to reconnect), **Remove member** (touch equivalent of `/grp-ban`, opens a list to pick who to remove — host only), **Save as group**, and **Leave room**.

**Send file** opens Android's native file picker, then a recipient-picker popup among the room members the relationship keys are already established with (all preselected, deselect anyone you want to exclude), then the choice between Slow and Fast speed (the touch equivalent of the `slow`/`warp` presets). Whoever receives it sees a confirmation request (accept/reject) and, once the transfer completes, the native "save file" picker. Sending starts once whoever has already accepted is collected, no need to wait for everyone (see "Sending starts once whoever has already accepted is collected" above, same behavior as the TUI).

**Send contact card** (the touch equivalent of `/grp-contact-send`) lets you pick which saved contact to introduce, asks for a mandatory off-band hint, then sends the card to the same eligible recipients as "Send file", with the same start once whoever has already accepted is collected. Whoever receives it sees a popup with an editable local name and accept/reject.

### Security

Reached from Settings → Security: current address (visible even before you connect, it's computed from your identity key alone), **Probe contacts now** (visible only once you're connected — immediately forces a reachability/confirmation cycle instead of waiting for the automatic one), **Change keystore password** (current password + new password twice), and **Decoy identity password** — despite the name, Android's own, simpler mechanism (not the same as desktop's decoy identity, see "Multiple identities" above): a second password that, typed instead of the real one at unlock, immediately and silently wipes identity and address book and proceeds straight into the first-launch screen, as if the app had just been installed and never used. Optional, and removable at any time by setting an empty one. In the Devices section, **Sync address book with a sibling device** (touch equivalent of `/sec-device-sync`, a picker over known devices) and **Rotate network identity** (touch equivalent of `/sec-rotate-key`, explicit confirmation). Per-contact relation key rotation is instead started from Console (`/sec-rotate-rel-identity`/`/sec-rotate-rel-content`, see above).

> **Emergency — immediate wipe, no confirmation.** "Secure wipe" in the header "⋮" menu always asks you to type "NUKE" before proceeding, to guard against an accidental tap. `/nukex` in the Console command list (touch equivalent of the TUI's NUKE EXPRESS command) is instead **immediate: no confirmation, nothing to type** — one tap and the wipe is already underway. Meant for a real emergency (e.g. the device is about to be seized), where speed matters more than protection against a mistaken tap. In the Console command list this entry is colored red to set it apart from every other one, which always asks for confirmation before acting.

> **On Android, "Secure wipe"/`/nukex` overwrites every file in the app's own private storage — keystore, `config.json`, `tor_bridges` — same scope as desktop, but never anything outside that space.** Any file you saved **outside** the app's private storage through the phone's "Save as" dialog — exported identity/backup QR codes, the address-book export `.bin`/`.chunk` files (header "⋮" menu → Sync contacts), files received from a contact and saved to Downloads or elsewhere — **stays intact on the device**, whether it's a secure wipe or a remote self-destruction. If you exported something from the app and want it to actually disappear along with everything else, you need to delete it yourself from the phone's file manager (or the Downloads folder), before or after the secure wipe. Neither wipe ever uninstalls the app itself or touches other apps' data — on Android there's no separate "binary" to delete the way there is on desktop.

**Remote self-destruction** (see the dedicated section further down) is reached from the same Security page: **Device label** (touch equivalent of `/sec-device-label`), **Sync with nearby device** (touch equivalent of `/sec-indoor-sync`, local-network discovery), and a button that opens a picker over known devices to send the command (touch equivalent of `/sec-remote-nuke`/`/sec-devices`).

---

## Tor bridges — terminal commands

### `neutrino get-bridges`

Downloads `obfs4` and `webtunnel` bridges from `bridges.torproject.org` without a CAPTCHA and saves them to `~/.config/neutrino/tor_bridges`. Shows the bridges found at the end:

```
Downloading obfs4 bridges…
  found 3 bridges
Downloading webtunnel bridges…
  found 2 bridges

Saved 5 bridges to /home/user/.config/neutrino/tor_bridges

  obfs4 158.174.147.145:7800 B275… cert=… iat-mode=0
  webtunnel 172.233.130.178:443 D6DB… url=https://… ver=0.0.1
  …
```

After downloading the bridges, you have two ways to use them:

```
neutrino use-bridges on                                 # enables automatic loading, effective on the next restart
neutrino --bridges-file ~/.config/neutrino/tor_bridges   # or force a specific file just for this launch
```

An explicit `--bridges-file` always takes priority over `use-bridges`. Without either, Neutrino starts with a direct Tor connection, no bridge, even if `tor_bridges` already exists on disk.

**If `bridges.torproject.org` is also blocked:** `get-bridges` makes a direct request (not routed through Tor — to download bridges you need to already have bridges), so if the site is blocked by your network the command won't work. In that case you need out-of-band channels:

- **Email**: write to `bridges@torproject.org` from a Gmail or Riseup address; you receive the bridges by automatic reply.
- **Telegram**: the Tor Project's `@GetBridgesBot` distributes bridges — it's a different piece of infrastructure from the website, so it often stays reachable even when the site is blocked.
- **A contact outside the censored network**: anyone can send you the bridge lines via Signal, encrypted email, etc.

In all these cases you don't need `get-bridges`: `~/.config/neutrino/tor_bridges` is a plain text file, one line per bridge (blank lines or lines starting with `#` are ignored). Open it with any editor and paste in the lines you received, then `neutrino use-bridges on` as usual.

### `neutrino use-bridges [on|off]`

With no argument, shows whether automatic bridge loading is enabled. With an argument, enables/disables it, saving `bridges_enabled` in `config.json`. Effective **only on the next restart**: run it from a terminal, before starting the TUI.

### `neutrino add-bridges <file.png>` / `neutrino add-bridges --camera`

Useful when the desktop has no direct internet access but you have a connected phone: the `bridges.torproject.org` page shown on the phone already includes a QR code with bridge lines. Decodes a QR code from an image file or from the first available webcam and adds the lines read to `tor_bridges` (duplicates discarded, never overwritten) — lets you accumulate bridges from several scans over time.

### `neutrino remove-all-bridges`

Removes the `~/.config/neutrino/tor_bridges` file. Asks for confirmation before proceeding. Useful for going back to a direct Tor connection with no bridge. If you had enabled `use-bridges on`, also disable it with `use-bridges off` — removing only the file leaves the flag on, and on the next restart you'll see the "bridges enabled but no file found" warning.

---

## Other CLI commands

### `neutrino reset-config`

Rewrites `~/.config/neutrino/config.json` with default values and explanatory comments for each parameter. Useful for recovering a corrupted configuration or starting over after bad manual edits. The keystore and bridges are not touched.

### `neutrino lang [it|en|fr|de|es|ro|ru]`

With no argument, shows the currently set language. With an argument, changes and saves it in `config.json`. The effect applies **only on the next restart**: run it from a terminal, before starting the TUI.

### `neutrino net [tor|i2p]`

With no argument, shows the currently set transport network. With an argument, changes and saves it in `config.json`, effective only on the next restart (like `lang`). `--net <network>` on a normal startup forces the network for that session only, without touching the saved config — same priority as `--bridges-file` over `use-bridges`.

`tor` is the default and needs nothing extra. `i2p` is embedded in the binary on linux/amd64 and linux/arm64 (including Android/Termux — see `termux-manual.md`), no extra install, same principle as Tor. In the macOS builds in testing it is embedded on Intel too; on Apple Silicon macOS and other platforms it instead requires the `i2pd` daemon installed on the system. An instance always uses a single network at a time: two contacts who want to talk over I2P instead of Tor simply agree on when to do so, the same way they already agree on when to be online.

**Warning — active VPN.** If a VPN is active on the device, `--net i2p` bootstrap can fail to ever complete (error "bootstrap did not complete within 3 minutes"), on any platform, including Android/Termux. Likely cause: I2P relies mostly on UDP to maintain connections with many peers at once, while Tor uses a single TCP connection — many VPNs block or degrade UDP traffic, or filter P2P-like traffic patterns, while letting Tor through without issue. This is not a Neutrino malfunction: if I2P bootstrap doesn't complete, disable the VPN before trying again. If the VPN is a corporate one, or otherwise cannot be disabled, the practical alternative is to stay on `tor` (the default): unlike I2P, Tor bootstrap works normally even with the VPN active.

### `neutrino add-identity`

Adds a new identity (new username, new `.onion` address, its own contacts and groups, its own identity password) to the **same** keystore file — only the file password is shared with every other identity already there, never the identity password. Does not create a separate file. See "Multiple identities" below.

---

## Multiple identities

A keystore can contain several independent identities, each with its own username, `.onion` address, contact address book, groups, and its own identity password — only the file password is shared across all of them. Useful for keeping, say, a personal profile and one for a project separate, without having to manage multiple files.

> **The separation only holds if it stays clean.** Each identity has its own `.onion`, address book and groups precisely to keep one from leading to the other. If you **deliberately** add the same contact (or a shared contact) across multiple identities, that person — or anyone able to piece that information together — gains a correlation point between the two: a pattern that allows at least a rough identification of who's behind both, even without reaching full deanonymization. Example: if you use one identity for the catechism group and another for the nightclub group, a single contact present in both address books is enough for that contact (or whoever reads their phone) to infer that the two identities are the same person. If compartmentalization genuinely matters to you (identities that must not be traceable to each other), keep the address books completely disjoint.

> **Seizing the device still proves common ownership, even with zero shared contacts.** Multiple identities in the same keystore file stay physically together if the device is seized: whoever seizes it finds proof that both belong to the same person, regardless of how disjoint their address books are. Using separate operating-system accounts or profiles for each identity (instead of `add-identity`) only reduces the address-book correlation risk described above, not this one — the seized device can still reveal, at the system level, that more than one account/profile exists on it. If compartmentalization genuinely matters to you, the only separation that survives a seizure is **physically distinct hardware** for each identity that must never be traced back to the others — not a different account on the same device.

**Adding an identity:**
```
neutrino add-identity
```
Asks for your file and identity password (to unlock an existing identity in the file), then a username and a new identity password for the identity being added — must differ from every other identity password already in the file (checked automatically). Existing identities are not touched.

**Identity slots are never removed**: no identity can touch another's slot without that identity's own password, by design — "deleting someone else's identity" has no safe meaning. The one exception is the decoy: opening it at startup overwrites every other slot in the file (see "First launch" above). To destroy your own current identity, use `/nukex` (see "Self-destruction" below) — it overwrites its contacts and its slot with random bytes and swaps your session to the decoy identity; the slot stays in the file, unreadable.

**Choosing which identity to start with:** purely a matter of which identity password you type at the next launch (see "Subsequent launches" above) — there is no selection menu. To switch, close Neutrino and restart it, typing a different identity's password.

**What's shared and what isn't:**

| | Shared across identities | Specific to each identity |
|---|---|---|
| File password | ✅ one for all | |
| Identity password | | ✅ each has its own, including the decoy |
| Contacts, groups | | ✅ each has its own |
| `.onion` address | | ✅ each has its own |
| Identity QR (`identity-qr-<username>.png`) | | ✅ one file per identity |
| Language, Tor bridges (`config.json`) | ✅ installation-level, not identity-level | |

The 24-word BIP-39 backup (`neutrino backup`) and address book sync remain **per identity**: each has its own seed and must be saved/restored separately — there is not (yet) a single backup that covers all identities at once.

**On Android (graphical app):** a simpler, still single-password model — one password protects every identity in the file, there is no separate file/identity password split and no mandatory decoy identity. On unlock, if the keystore contains more than one identity, a picker appears (one button per identity) before proceeding — with only one identity, no extra step, as always. From Settings → Identities: a list of the identities present (the session's active one is marked), an **Add identity** button (username only, then the QR of the new identity to share right away), and a **Delete** button for each identity — except the currently active one: to delete it, first quit (menu "⋮" → **Quit**) and reopen choosing a different identity from the picker.

---

## Message signing

Every broadcast message sent is signed with the relationship ContentKey dedicated to each recipient present in the room — a different signature for each one, never a single "room-wide" signature (files and contact cards have their own signature, see "File transfer"). Incoming messages show an indicator combining two independent pieces of information:

**What that message's signature proves:**
- `no signature` — the message doesn't carry a signature addressed to you (the sender doesn't yet have a relationship key established with you)
- `REL:........` (dots instead of the code) — your relationship key with the sender isn't established at this exact moment, the signature can't be checked yet
- `REL:XXXXXXXX` — signature verified, last 8 hex characters of their ContentKey toward you; shown in yellow if this is an ephemeral, room-only relationship key (someone you know only through this room, not a saved contact — see `/grp-promote` above to turn them into one), gray once it's a persisted contact's own key
- `signature invalid` — a signature is present but doesn't match the expected key

On your own messages (your own echo in the room) `your message` is shown instead: self-verification doesn't make sense, since you sign once per recipient and there's no single "your" key to display.

**If you know that identity:** a valid signature only proves that someone with that key wrote that text, not that it's someone you trust or have ever verified — that's why the color of `REL:XXXXXXXX` also tells whether the sender is a saved contact (gray) or someone you know only through this room (yellow). For room members not saved as contacts, `/grp-info` shows `[UNKNOWN]` (see "### Group" above) — "not in the address book, I know nothing about them." This differs from `[UNVERIFIED]` (see "Verifying identity" above), which instead concerns a contact **already saved** whose identity you haven't yet confirmed with the safety code.

Key verification only ever uses the local cache (populated by the direct exchange with the other side during connection, and by the periodic probe of contacts in the address book — works even offline if the key is already there, including the case of your own identity, never uploaded anywhere). No public keyserver is ever involved, and the check is always synchronous, a single attempt, never retried: if no relationship key candidate is available at all yet for that sender, the message shows `REL:........` instead of `signature invalid` (see above) — that specific message stays tagged that way even after the key later arrives, since it isn't re-checked retroactively; only a `REL:XXXXXXXX`/`signature invalid` result comes from an actual verification attempt against a key that was already available at the moment the message arrived.

---

## Optical transfer via animated QR (no network)

A continuous stream of animated QR codes (~3 per second) lets you transfer a file, an identity backup, or the contact address book between two devices using only the sender's screen and the recipient's camera. The channel is purely optical: it never goes through Tor, I2P, or any local network — useful when the two devices have no network connectivity to each other, or when you'd rather not have them communicate over any network at all (a true air gap). The stream tolerates lost, blurry, or out-of-order frames: reception completes on its own once enough frames have been gathered to reconstruct the content, with no need to capture every single one or in any particular order.

### `neutrino qr send <file>` / `neutrino qr receive <file-out>`

Transfers any file:

```
neutrino qr send document.pdf
neutrino qr receive received_document.pdf
```

The sender sets a password (to be shared with the recipient out of band, e.g. by voice): the file is encrypted with that password before being transmitted, so anyone who happens to be watching the screen during transmission — the optical channel is by definition visible to anyone in the room — can't read the content without knowing the password. Before encrypting it, the sender chooses whether to compress it with LZMA2/XZ (on by default, same as `/grp-file-send`) — it pays off more here than anywhere else: fewer frames to show/scan, so a shorter transfer. The recipient enters the same password, points the camera at the sender's screen, and the file is written to disk as soon as it's fully reconstructed — decompression (if the sender enabled it) happens on its own, nothing to choose on the receiving end. The sender stops the transmission with `Ctrl+C` once the recipient confirms out of band that they have everything; reception stops on its own after 10 minutes if it doesn't complete.

**On Android**: the same two operations are the **Send file via QR** and **Receive file via QR** buttons, reachable even before connecting to the network (the "Before connecting" screen) — same compression checkbox already seen in "Send file" inside a room.

### Backup and address book via animated QR

Identity backup (`neutrino backup`) and address book sync (`neutrino sync export`/`sync import`) offer the same mechanism as an alternative to the static QR codes — see the respective sections below, and the **Backup**/**Sync contacts** buttons on Android. In this case there's no password to set: the content is already encrypted with the identity's 24 BIP-39 words, exactly as for the file or static-QR export — the benefit of the animated QR here is purely practical (no static QR codes to photograph one by one, the recipient just points the camera and waits), not a different level of encryption.

---

## Identity backup and restore

### The 24 BIP-39 words

The Neutrino identity is a 32-byte Ed25519 key, encoded as 24 BIP-39 mnemonic words. Anyone possessing these 24 words can reconstruct your exact `.onion` address. Write them down on paper and keep them in a safe place — without them, if the device breaks, the identity is lost.

> **IMPORTANT — the keystore passwords and the 24 words are two different things.**
>
> **Changing your identity password (`/sec-passwd`) does NOT invalidate existing backups.** The file and identity passwords only protect the `keystore` file on local disk; the 24 words (and any backup/QR/sync already created with them) are derived from the Ed25519 identity key, a completely separate secret. You can change either password as many times as you like: every backup made before remains valid.
>
> The 24 words encode the root IdentityKey, so they change only when that key changes: `/sec-rotate-key` generates a new root key and therefore new words — write them down again after a rotation, since the old ones restore the previous key and address. Without a rotation they remain valid indefinitely; an additional identity (`neutrino add-identity`) has its own, separate words. They're visible at any time with `/sec-backup` from the TUI or with `neutrino backup` from the terminal.

### `neutrino backup`

Shows the 24 words, then asks whether to also save a full backup (identity + contacts + metadata):

```
neutrino backup
```

Save options:
- **1 — Encrypted file (`.bin`)** — suited for USB, cloud or backup on a desktop PC. The file is useless without the 24 words: it contains data encrypted with AES-256-GCM, key derived from the BIP-39 seed.
- **2 — QR code(s) in the terminal** — shows the QR in the terminal output. If the keystore is too large for a single QR, several QRs are shown in sequence (one at a time, press Enter to advance). For each QR, a `.png` file and a `.chunk` file are also saved for restoring on a PC.
- **3 — Both**
- **4 — Animated QR (camera)** — no static QR codes to photograph one by one: shows a continuous stream of animated QR codes, the same mechanism as "Optical transfer via animated QR" above. The recipient receives it with `neutrino restore`, option 3 (see below).

### `neutrino restore`

Restores the identity from 24 BIP-39 words:

```
neutrino restore
```

The wizard asks:
1. The 24 words
2. The data source:
   - **1 — `.bin` file** (full restore)
   - **2 — `.chunk` file(s)** (one or more, from multiple static QR codes)
   - **3 — Animated QR (camera)** — point the camera at the sender's animated QR stream (`neutrino backup`, option 4)
   - **Just Enter** — restores only the identity (contacts lost)

If an existing keystore is found, it asks for confirmation before overwriting. For the new keystore's password, the same box about the generated passphrase seen in the initial wizard above applies.

> **Network address: two different cases.** With **just Enter** (24 words only, contacts lost) you get the exact same network address as before — meant for total disaster, where you want to *rebuild* the same device. With options **1/2/3** (file/chunk/animated QR, full restore with address book) you're instead bringing the same identity onto an **additional device**: it gets its own network address, distinct from the origin device's, so the two don't collide if they're both online together — a contact keeps reaching you at your usual address (the origin device's), the additional device isn't reachable by them yet with this step alone.

---

## Syncing contacts between devices

Neutrino messages don't exist on disk: they disappear when the program closes. The only persistent information is the **contact address book**. The `sync` command lets you export it from one device and import it on another, merging contacts without losing any.

### `neutrino sync export`

```
neutrino sync export
```

Asks for the format:
- **1 — Encrypted file (`.bin`)** — to transfer via USB, cloud or AirDrop
- **2 — QR code(s) in the terminal** — to scan with a phone's camera; for large address books it shows multiple QRs in sequence
- **3 — Both**
- **4 — Animated QR (camera)** — same mechanism as "Optical transfer via animated QR" above, no static QR codes to photograph one by one; the recipient receives it with `neutrino sync import --camera` (see below).

The file is encrypted with AES-256-GCM; the key is derived from the BIP-39 seed with info `"neutrino-sync-v1"`. It's useless without the 24 words.

### `neutrino sync import`

```
neutrino sync import <file.bin>
neutrino sync import <part1.chunk> <part2.chunk> ...
neutrino sync import --camera
```

The last form points the camera at the sender's animated QR stream (`neutrino sync export`, option 4) instead of reading from a file. Either way, it then asks for the 24 BIP-39 words, decrypts the content and merges the contacts into the local keystore:
- Contacts present only in the file are added
- Contacts already present are updated if the file has a more complete `LocalName` or ML-KEM-768 key
- No contact is ever deleted

At the end it reports how many contacts were added and how many updated.

---

## Self-destruction

### `/nukex` — NUKE EXPRESS

No command of this kind ever deletes your keystore file, your `config.json`, or any other file on disk, and none of them ever closes Neutrino or ends the process — not even this one. Android has no equivalent of deleting the file (an app can't delete itself), so every platform behaves the same way:

```
/nukex
```

Typed from the TUI during a chat, with **no confirmation** — no warning to read, no text to type, one single command and it's already underway:

1. Every one of your real contacts is wiped **in place**, immediately — same treatment as deleting one contact by hand, applied to all of them at once. Right after, the real identity itself is destroyed: its slot in the file is overwritten with random bytes, so it can no longer be opened, not even with the right password. Other real identities in the same file are not touched, and the file itself keeps existing.
2. Behind the scenes, your session silently continues as your **decoy identity** (see "First launch" above) — on the same already-open Tor/I2P connection, with no new password prompt and no restart. From this point on, whatever you type goes to the decoy's own chats and contacts, not your real ones.
3. A short-lived helper process reaches out to every one of your (just-wiped) contacts over Tor/I2P to revoke your relationship keys toward them, so they stop trusting your device — and, separately, your own other devices sharing the same account (if you've set any up, see "Multiple identities" and `/sec-device-sync` below) are notified too, so they can do the same.

> **When to use it.** It's designed for a situation of extreme necessity: the risk of being caught with the app open, or with the device about to fall under someone else's control (a search, seizure, someone about to reach you), is so high and immediate that reading any warning is a luxury you can't afford. At that moment it's not only your own identity at stake: your address book also identifies **all your contacts** to anyone who recognizes what they're looking at — the point of this command is to stop trusting them, and have them stop trusting you, as fast as possible. To exit normally instead, `/quit` is enough.

> **What this is not.** Your real identity's own `.onion` address is left running after the swap — untouched, not published-over, not shut down — deliberately: explicitly closing it would itself be a visible, correlatable signal ("this address went dark at this exact moment"), worse than leaving it answering with nothing behind it. `/nukex` never performs an actual, physical secure-wipe of the keystore directory.

An automatic version of the same sequence also fires on its own once the interface has stayed locked past a duration you set with `/sec-nuke-timeout` (see above) — same three steps, no manual command needed.

### `/sec-clear-all` — permanently delete everything

The one deliberate exception to "no command of this kind ever deletes your keystore file": for when you've decided to stop using Neutrino altogether, not just conceal your identity behind the decoy.

```
/sec-clear-all
```

Asks for explicit confirmation (y/n) — never immediate like `/nukex`, there's no emergency to react to here. Once confirmed, it securely overwrites and deletes every file in your config directory — keystore, `config.json`, any backup or QR code you saved there — then exits Neutrino. There is no decoy swap, no relationship-key revocation toward your contacts: this is a local, permanent removal of your own data, not a response to compromise. If you still want your contacts to stop trusting you, run `/nukex` first and `/sec-clear-all` afterward.

---

## Remote self-destruction (remote_nuke)

### The problem it solves

`/nukex` and the decoy identity (see "First launch", "Self-destruction" and `/sec-duress` above) all share the same assumption: **the device is still in your hands**, or at least you're the one typing something on it — a command, a password that isn't your real one. They cover "I'm about to be discovered" or "I'm being forced to unlock", both by overwriting your contacts and your real identity and continuing as the decoy, never by deleting the file — but not the case where the device **has already been taken from you** — stolen, seized, lost — and you have no way left to touch it.

Remote self-destruction covers exactly this case: if the compromised device is still **on, running Neutrino, and reachable over the network** (an active Tor circuit or I2P tunnel), **another device of yours** — one you still hold — can order it to self-destruct, with nothing for whoever currently holds it to do (or be able to stop). Whoever stole it sees no popup, has to type nothing: if the command arrives, that device quietly wipes its own contacts and swaps to its decoy identity on its own — same sequence as `/nukex`, triggered remotely instead of by hand.

### Who can give the order: no "guardian", just key possession

There's no special identity with administrator powers. Authorization to wipe a device is simply **possessing, in your own keystore, the private key of any identity that is also present on that device** — the same identity (the same 24 BIP-39 words) duplicated onto both devices with `neutrino restore`. No third party, no separate recovery key to protect or risk losing: the authorization mechanism is the same possession you already use for everything else in Neutrino.

This means it **only works if you prepared it in advance**: the identity needs to already be duplicated onto a second device before the first one gets stolen, not after.

### What actually gets wiped: the device, not a single identity

A "device" in Neutrino is **the entire keystore file**, not a piece of hardware. If a file contains more than one identity (see "Multiple identities" above — e.g. `alice` and `alice2` under the same login), remote self-destruction overwrites the contacts of **all of them together**, not just the one used to pair the two devices. If several people share the same device with separate logins/files (e.g. `alice`, `bob`, `carol` on the same laptop, three distinct keystores), each has its own separate device: hitting one doesn't touch the others.

### Preparation — must be done BEFOREHAND, it can't be improvised after the theft

1. **Duplicate an identity onto the second device**, with the same 24 BIP-39 words:
   ```
   neutrino restore
   ```
2. **With both devices on the same local network** (same Wi-Fi/LAN — this step doesn't use Tor/I2P), run on **both**:
   ```
   /sec-indoor-sync
   ```
   They discover each other via UDP multicast, authenticate to each other by proving possession of the same key (no exchange of different keys involved: it's literally the same identity on both sides), and exchange contact lists plus mutual registration as a "known device". The discovery window lasts up to 60 seconds.
3. **Give the device a name** you'll be able to recognize later:
   ```
   /sec-device-label Galaxy S22
   ```
   Without a name of your choosing, the only way to tell two or three known devices apart would be their identifier — 16 random bytes in hex, unreadable. The name is already asked for on the very first launch on a new file (wizard); this command shows or changes it at any later point.
4. **Verify it worked**:
   ```
   /sec-devices
   ```
   Lists the known devices for the current identity — if the one you just synced doesn't show up, repeat `/sec-indoor-sync` with both devices on the same network.

> **Without step 2, done at least once while you still had both devices in hand, remote self-destruction has no way to work.** There's no way to "discover" a device after it's already been stolen: the mutual registration has to have already happened beforehand.

### How to run it

```
/sec-remote-nuke
```
Opens a picker over known devices (populated by `/sec-indoor-sync`); once a target is chosen, it asks for explicit confirmation (y/n) — **not** `/nukex`'s immediate no-confirmation behavior: here a typo can't be undone by whoever receives the command, so the confirmation stays.

Once confirmed, two things start immediately in parallel, **neither of which waits for the stolen device to be reachable**:

1. **Preliminary warning to your own contacts** (`danger_broadcast`) — fires right away toward your address book, regardless of whether the compromised device ever responds. If a contact isn't online at that moment, the warning stays queued and is automatically resent the next time they're seen reachable (the exact same mechanism already used to confirm a key rotation) — nothing to redo by hand, and no expiry: it stays queued until that contact confirms receipt.
2. **The command itself** — since it isn't known in advance which of the identities present on the target device will actually be reachable, it's sent in parallel to **all** the network addresses of **all** the identities on that device (fan-out). If the device is unreachable at that moment, the command does **not** expire: it stays queued and is automatically retried on every one of your subsequent app starts — even days or weeks later — until a confirmation arrives. As soon as the first confirmation arrives from any of the addresses tried, every other attempt still in flight is stopped.

When the confirmation arrives, the authority also fires a second, final warning (`danger_end`, "destroyed" rather than just "in progress") toward your own address book — same persistent queue as the first. It acts as a safety net: a contact that hadn't yet received anything direct from the target device (see below) still gets it from you, even if later.

### What happens on the target device

If and when the command actually arrives, in sequence and fully automatic, with no interaction required from whoever physically holds it:

1. Verifies the command is genuine (signed by an identity also possessed on this device) and recent (±5-minute window, against replaying a command intercepted in the past).
2. Directly warns **all** its own contacts — not just those of the identity Neutrino was running as at that moment, but those of **every** sibling identity present on the same file (`danger_end`, the final warning): the device holds every identity's keys, the authority doesn't. It's a single quick attempt with no queue — a contact who isn't online at that exact instant isn't reached by this channel (see limits below).
3. Confirms to the authority that it's carrying out the command.
4. Runs the exact same sequence as typing `/nukex` by hand (see "Self-destruction" above): every real contact and the real identity's slot overwritten in place, the session silently swapped to the decoy identity on the same network connection, relationship keys revoked toward contacts via the salvation pod. Nothing on disk is deleted, and the device keeps running — as the decoy, on the same already-open Tor/I2P circuit — rather than shutting down.

### Real limits — what it does NOT guarantee

- **The device needs to be on, running Neutrino, and reachable over the network** at the instant the command (or one of its automatic retries) arrives. It isn't an OS-level mechanism like "Find My iPhone", which works even with the app closed: the `neutrino` process itself has to be alive here. If the device stays off/offline forever, the command never arrives — no way around this, no matter how long you keep retrying.
- **The automatic retry needs YOU to restart Neutrino from time to time** — both for the command toward the device and for your warnings to contacts (preliminary and final): all of them resume on your next app start or your next contact-probe cycle (`/active` or the periodic one), not on their own in the background while the app is closed.
- **No proof of successful destruction if the confirmation never arrives** — a device that stayed unreachable, a lost command, or one destroyed physically before the app could respond: from your side all that's left is silence, not a distinct explicit error from "no confirmation received".
- **Your two warnings (preliminary and final) only cover contacts already in your address book as of your last `/sec-indoor-sync`** with the identity involved, and never those of any sibling identities you haven't also duplicated and synced yourself — only the target device, if and when it actually receives the command, can directly warn ALL of its own identities (see above). But even that channel has a structural limit that can't be worked around: it only reaches whoever is online at that exact instant, with no queue or retries (it's a single pass, right before the device overwrites its own contacts). An identity you've never duplicated onto a second device, whose contacts weren't online at that precise moment, is simply left unaware — that's not a software shortcoming, it's a consequence of how you organize your identities across devices: if you want solid coverage for an identity, duplicate it too (`neutrino restore` + `/sec-indoor-sync`), so its warning also travels through the authority's persistent channel.
- **Irreversible, with no local warning on the target device** — that's the whole point of the feature: whoever holds it must not notice in time to stop it.

---

## Sharing your identity

```
neutrino show-qr
```

Prints the QR in the terminal and saves it as a PNG. The QR contains the URI:
```
nu://username/BASE64PUBKEY[/BASE64MLKEMPUB/BASE64MLDSAPUB]
```
With both post-quantum segments the content exceeds the capacity of a single QR: `show-qr` automatically shows a sequence of numbered QR codes to scan in order (the same mechanism as the multi-QR backup/sync, see below).

The recipient adds it with `/cnt-add`.

---

## Auto-start (systemd)

```
neutrino install
```

Prints the commands to install and enable the systemd service. Accepts no options.

---

## Local files

Every path below is relative to your OS's standard per-user config directory: `~/.config/neutrino/` on Linux, `~/Library/Application Support/neutrino/` on macOS.

| Path (Linux) | Contents |
|---|---|
| `~/.config/neutrino/keystore` | Identity (one or more — see "Multiple identities"), contacts, groups — encrypted with Argon2id + AES-256-GCM |
| `~/.config/neutrino/config.json` | Operational parameters — editable with any editor |
| `~/.config/neutrino/tor_bridges` | Tor bridge lines downloaded with `neutrino get-bridges` |
| `~/.config/neutrino/identity-qr-<username>.png` (or `-part1.png`, `-part2.png`... if it doesn't fit in one QR, see "First launch" above) | Identity QR, one per identity — recreated on every `show-qr` |
| `~/.config/neutrino/identity-qr-<username>.pdf` | Same identity, as a printable PDF — one page with the full text, one page per QR image |

The keystore never contains messages. All messages live in RAM and disappear on restart.

---

## Configuration file

`~/.config/neutrino/config.json` is generated on first launch with default values and an explanatory comment for each field. It can be edited with any text editor. To reset it:

```
neutrino reset-config
```

Duration fields use Go's format: `"30s"`, `"1m"`, `"1m30s"`, `"2h"`. The main ones:

| Field | Default | Meaning |
|---|---|---|
| `ping_interval` | `1m` | WebSocket keepalive (2 missed cycles tolerated before closing) |
| `sender_key_interval` | `5m` | Broadcast encryption key rotation — time-based backstop, even in a silent room |
| `sender_key_message_budget` | `25` | Broadcast encryption key rotation — count-based criterion, messages sent under the current generation (whichever of this and `sender_key_interval` comes first) |
| `pending_slot_limit` | `5` | How many messages can stay without delivery confirmation from the server before the next send is blocked (see the "too many unconfirmed messages" error in Console) |
| `active_interval` | `1m` | Periodic contact polling |
| `warmup_interval` | `5m` | Tor circuit pre-warming |
| `invite_timeout` | `30s` | HTTP timeout for the invite lifecycle (invite, re-invite, decline, etc.) |
| `self_knock_timeout` | `1m` | Timeout of the self-knock that confirms your own inbound reachability (the `in` dot in the Tor tab, see "Tor Tab" above) — deliberately long because Tor circuits to a new `.onion` can take up to 60s |
| `lang` | `"en"` | Interface language — changed with `neutrino lang [it\|en\|fr\|de\|es\|ro\|ru]`, effective on the next restart |
| `net` | `"tor"` | Transport network (`tor` or `i2p`) — changed with `neutrino net [tor\|i2p]`, effective on the next restart; `--net <network>` forces it for the current run only |
| `bridges_enabled` | `false` | Automatically load saved bridges at bootstrap — changed with `neutrino use-bridges [on\|off]`, effective on the next restart |
| `bridge_default` | `"obfs4"` | Bridge type used when `bridges_enabled` is on — not chosen via a command, changed by editing `config.json` |
| `bridge_fallback` | `"webtunnel"` | Bridge type automatically retried if bootstrap with `bridge_default` doesn't complete in time |
| `file_transfer_max_size_mib` | `512` | Maximum size (MiB) of a file that can be sent with `/grp-file-send` |
| `strong_compression_enabled` | `true` | Pre-compresses file/contact-card content (`/grp-file-send`) with LZMA2/XZ before encryption — always tried first, falls back to no compression if it doesn't pay off. It's also the default shown by `neutrino qr send`'s compression prompt, still changeable on every send |

### Tor bridges

In countries with network censorship, bridges let Tor connect while getting around blocks. There are two types:

- **obfs4** — makes Tor traffic unrecognizable (random noise). More widespread and mature.
- **webtunnel** — disguises traffic as HTTPS to a real website. More resistant to sophisticated censorship.

To download bridges:

```
neutrino get-bridges
```

Downloads both types from `bridges.torproject.org` and saves them to `~/.config/neutrino/tor_bridges`. To enable them permanently: `neutrino use-bridges on` (effective on the next restart). To use them once without changing the config: `neutrino --bridges-file ~/.config/neutrino/tor_bridges`.

With `use-bridges on`, Neutrino first tries the type indicated by `bridge_default` in `config.json` (default `obfs4`); if that bootstrap doesn't complete in time, it automatically retries with `bridge_fallback` (default `webtunnel`), showing a dedicated on-screen warning. With `--bridges-file`, on the other hand, all lines in the file are used, regardless of type, with no dedicated fallback.
