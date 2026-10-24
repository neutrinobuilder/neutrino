# Neutrino

P2P chat over Tor or I2P. No accounts, no phone number, no central server, no message history.

Fully encrypted — not just end-to-end at the chat level — and cryptographically signed, so security covers the sender's identity as well as the content, with resistance to post-quantum attacks.

---

## Who this isn't for

This isn't a tool for planning a night out with friends, booking a table, or sending memes to the family group chat — for that, [other messengers](https://neutrinobuilder.github.io/neutrino/messenger-comparison.html) already exist, with calls, stickers, channels, bots. Neutrino has none of that, and it's not an oversight: every extra feature is one more place where metadata can leak out. If you need an app that does everything, you're not the audience for this project.

It's built for people who have a concrete reason not to trust a middleman company — journalists with sources to protect, people working in contexts where communications are monitored, anyone who simply rejects, as a matter of principle, the idea that a third party should be able to read or store their conversations. Fewer features, smaller attack surface: it's a deliberate tradeoff, not unfinished work.

---

## Why Neutrino

Imagine you want to talk privately, without using third-party services or third-party tools because you don't want anyone to be able to read or store your messages.

With this program, every participant installs the program on their own computer or phone and gets their own identity: a network address — a Tor `.onion` address by default, or an I2P `.b32.i2p` address if you choose that network instead — similar to a web address but one that reveals neither the physical location of the device nor its IP. Two people who want to talk exchange this address once, out of band (in person, via another app, by phone) — the same way you'd exchange a phone number. From then on, either of them can invite the other into a private room by name: the app authenticates that specific person behind the scenes, there's no shared password anyone else could reuse to get in.

From that moment on you can write as in a normal chat, but eight important things happen that set it apart from all the others:

1. **Messages are encrypted on your device before they even leave** — the device acting as the meeting point receives only incomprehensible data it cannot read, even if it wanted to. It holds only the users' public keys, never their private ones.
2. **No one knows where you physically are** — the connection goes through Tor, or I2P if you choose that network instead. Participants don't see anyone else's IP, and anyone observing the network cannot tell who is talking to whom.
3. **No intermediary stores anything** — there is no external server. The room lives on the device of whoever opened it: when it's turned off, everything disappears. No archive, no database, no company to ask for your data.
4. **The encryption keys change with every message** — even if someone managed to record today's encrypted traffic, they could not decrypt past messages: every message uses a unique key derived from an HMAC chain that only moves forward, never back. The entire chain is regenerated from scratch every 25 messages or every 5 minutes, whichever comes first (default settings).
5. **You can verify who you're really talking to** — every contact has a security code (40 base62 characters), computed from both identities involved, available on request. Compare it with the other person over a different channel — phone, video, in person: if it matches, you know for certain the keys haven't been swapped by anyone.
6. **The main client is text-based** — no graphical app is required, you use it like a text command; built for people who work on servers or want an essential, controllable tool. It runs on Android too, via Termux (same binary, no differences). A separate native Android app with a graphical interface, speaking the same protocol, is in testing and not distributed yet.
7. **Built to resist tomorrow's computers, not just today's** — the connection setup and key exchange already combine classical and post-quantum cryptography (X25519 + ML-KEM-768). Even if someone recorded your encrypted traffic today, a future quantum computer couldn't decrypt it retroactively.
8. **If a device gets seized, you have an out** — another device holding your same identity can trigger a signed remote-wipe command that overwrites your contacts and your real identity on the seized device. Every keystore also has a decoy identity with its own password: typed under coercion, it opens an ordinary-looking identity and silently destroys the real one — whoever is forcing you sees a normal login.

In short: it's like organizing a secret meeting in a windowless room, where everyone enters through a different tunnel, the walls record nothing, and no one on the outside can know who's inside, what's said, or what's shared — payments included, once the wallet in the roadmap ships.

### Addressing Tor skepticism

You'll hear this a lot: "Tor doesn't really protect you," "they can identify anyone who uses it." Here's the accurate picture, not the folklore version.

Tor's own threat model is explicit about what it defends against: a *local* observer — a single ISP, a single relay, a single network operator — who sees only one side of your connection. In a normal circuit, no single party ever sees both who you are and what you're connecting to.

What can genuinely happen, under specific and demanding conditions, is a **traffic correlation attack**: an adversary able to observe or control network traffic at *both* ends of a circuit at the same time can statistically match timing patterns and conclude the two are part of the same conversation. That requires visibility most attackers don't have — relays positioned at both ends, or control of internet infrastructure a connection happens to cross twice. It's realistic for a handful of state-level actors, not for a curious ISP, an employer, or an opportunistic attacker.

Even then, it's a **confirmation, not an identification**: it only works against someone the attacker has already singled out and can watch from both sides — it doesn't hand over a name out of an anonymous connection. The real-world cases where Tor users were unmasked almost always trace back to something else entirely: outdated software with a known, patched bug, a mistake made outside Tor (logging into a real account, an application-level leak), or a compromised device — not a break of the Tor network itself.

Two things specific to Neutrino narrow this further. It only uses Tor/I2P **hidden services** — there's no exit node anywhere in the path, so the entire class of exit-node attacks that affects browsing the ordinary web through Tor doesn't apply here at all. And there's nothing to correlate after the fact: no server stores messages, connections, or metadata anywhere — a successful correlation attack only ever tells an attacker "these two addresses are talking right now," never what was said, and only for as long as they're actively watching.

None of this means "unbreakable" — it means the realistic bar is a resourced, targeted adversary who already suspects you specifically, not a dragnet that unmasks random Tor users. Match your operational security to that bar, not to the folklore version.

---

## Quickstart

**Requirements:** Linux x86-64/arm64, or Android via Termux (arm64) — Tor and I2P are both included, nothing separate to install. macOS builds (Intel and Apple Silicon) are in testing, not distributed yet. Windows has no official build yet.

**Prebuilt binaries:** grab the latest release for your platform from the [Releases page](https://github.com/neutrinobuilder/neutrino/releases) — every binary is signed with key `0x6BE2C8ABD7701EB4`, see the [User Manual](docs/user-manual.md#verifying-the-authenticity-of-the-downloaded-binary) for how to verify it before running it.

**Building from source instead** requires [Go](https://go.dev/dl):

```
git clone https://github.com/neutrinobuilder/neutrino.git
cd neutrino
go build -o neutrino ./cmd/
./neutrino
```

The first launch runs a short guided setup (language, username, file and identity passwords, decoy identity, device name) and ends by showing your network address and a QR code — that's your identity on the network. From the second launch on, `./neutrino` just connects and drops you into the interface.

By default it connects over Tor. Run `neutrino net i2p` before first launch (or any time after, to switch) to use I2P instead — see the User Manual for platform-specific notes.

Everything past this point — adding contacts, creating rooms, file transfer, backup and multi-device sync, the full command reference — is in the **[User Manual](docs/user-manual.md)**.

---

## Languages

The interface is available in English, Italian, French, German, Spanish, Romanian and Russian. The translations other than English were produced with automated tools and have not yet been reviewed by native speakers: expect errors and imprecise nuances, especially where a sentence carries technical meaning.

Some words are intentionally left in English in every language:

- protocol and field names (`session_pub`, `msg_id`, `sender_key`, `rel_init`…)
- product and network names (Tor, I2P, Neutrino, OpenPGP, Termux…)
- cryptographic algorithms (ML-KEM, ML-DSA, AES-256-GCM, X25519, Ed25519, HKDF, Argon2id, BIP-39…)
- URI schemes and prefixes (`nu://`, `REL:`)
- slash commands (`/cnt-add`, `/grp-invite`…) — never translated, not even in labels
- computing terms in common use (keystore, handshake, backup, hidden service, WebSocket, QR code, timeout…)
- file names and command-line flags (`config.json`, `--net`, `--bridges-file`…)

Command names are always in English; only their descriptions are translated.

Corrections are welcome: if you're a native speaker and spot a wrong or awkward translation, open an issue with the language, the text as shown and your suggested wording.

---

## Documentation

|                                                       |                                                                                                      |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **[User Manual](docs/user-manual.md)**                     | Day-to-day usage: contacts, rooms, file transfer, backup & restore, multi-device sync, every command |
| **[Termux Manual](docs/termux-manual.md)**                 | Running the same binary on Android via Termux: install, updates, background/battery, autostart       |
| **[Technical Manual](docs/technical-manual.md)**           | Architecture, protocol, module layout, wire format                                                   |
| **[Cryptography Manual](docs/cryptography-manual.md)**     | Threat model, handshake, ratchets, hybrid post-quantum cryptography, key derivation                  |
| **[Messenger Comparison](https://neutrinobuilder.github.io/neutrino/messenger-comparison.html)** | How Neutrino compares to Signal, Session, Briar, SimpleX, and others                                 |

---

## Roadmap

- **Linux** — further capabilities in active development:
  - **Message Box** — store-and-forward delivery for contacts who are offline when you write to them.
  - **Additional self-destruct trigger** — automatic wipe on an unauthorized USB data connection while the interface is locked (usbNuke).
  - **Remote-wipe guarantee on every path** — relationship-key revocation already covers `/nukex`, the lock timeout (timeNuke), remote wipe and in-session duress, including when the wipe doesn't fully complete; still to come: the decoy-password login and sibling identities in the same file.
  - **Auto-update** — built-in signed update mechanism, no manual download needed.
  - **Location sharing** — optional, encrypted, via OpenStreetMap, with explicit expiry.
  - **Reproducible builds** — verify that a published binary matches the published source, byte for byte.
- **Android** — native app with a graphical interface, same protocol as desktop; developed and undergoing live testing on real devices.
- **macOS** — same TUI binary as Linux (Intel and Apple Silicon), already built; live testing still to be done.
- **Windows** — native build, currently under evaluation.
- **Cryptocurrency wallet** — native send/receive for Bitcoin (Silent Payment) and Monero, over the same encrypted channel:
  - **Dice-based seed generation** — optional physical-entropy alternative for wallet key material, for anyone who doesn't want to trust a software RNG.
- **iOS** — client only, same protocol as desktop and Android.
- **Uncharted territory** — further capabilities in active development that, as far as we know, no other project combines with an E2E messenger and a built-in wallet:
  - **Off-grid communication** — Bluetooth mesh for short range, RF for long range, for when there's no internet at all.

---

## Support the project

Neutrino is free and will stay free — no ads, no telemetry, no paid tiers for the core project.

### Donations

If it's useful to you, donations fund the roadmap above.

- **Monero (XMR):** `847SCVXhrY9SKo1F1PmHkGCVefaFBJhNx5hffzyyS94CWVyZZC3ucPQTZifzE6Mp9EGXX7swUUDiWRBmUZNL35gDPd3ZCFq`
- **Bitcoin (Silent Payment):** `sp1qqfklyysv0tjykvvtqmygwfqmeegm2n2qz6w6693he22599p9pz9tsqj3hnhedvyt6eqcekd8ngllt0r2cuhkmv50akqa6t3pnusnkvdawys0mgfa`
- **Bitcoin (regular):** `bc1qm8pqrc4xhj2tyxnymn2v4zkfkkpn8egnu2qmv6`

### Sponsors

Neutrino is developed pseudonymously, and its developers will not be identified. Support is therefore accepted only in forms that don't require it: cryptocurrency, to the addresses above. Organizations that cannot fund the project directly for this reason, but are interested in it, can fund an independent security audit instead: the sponsor commissions and pays the auditing firm directly, and the results are published here (see [Security audits](#security-audits)). Organizations that want to fund a specific item of the [Roadmap](#roadmap) — the off-grid communication work and the Bitcoin/Monero wallet are natural candidates — can get in touch first to agree on it.

Support never buys influence: no sponsor gets a say in the cryptographic design, telemetry, privileged access, or any change that would weaken users' security. Sponsors are acknowledged by name only, if they wish — no logos, no tracking.

Contact: `neutrino-contact.unaligned609@simplelogin.com` — please encrypt with the project's OpenPGP key: [neutrino-key.asc](neutrino-key.asc) in this repository, also published on [keys.openpgp.org](https://keys.openpgp.org/search?q=D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4). Before using it, check that both copies show the same fingerprint, `D5FB B139 9E94 EC33 4D25  A0D5 6BE2 C8AB D770 1EB4` — the one in this file alone isn't proof.

### Security audits

Independent audits and code review are welcome — everything here is meant to be checked, not taken on faith. Audits can also be sponsored (see [Sponsors](#sponsors)). The most valuable scope is the protocol and its implementation: handshake, SenderKey and DH ratchets, hybrid post-quantum key exchange, keystore encryption and the self-destruct paths. Start from the [Cryptography Manual](docs/cryptography-manual.md) and the [Technical Manual](docs/technical-manual.md).

Report vulnerabilities privately through GitHub's **Report a vulnerability** button (Security tab), never in a public issue — see [SECURITY.md](SECURITY.md).

**Audits:** none yet.

---

## License

Neutrino is free software, licensed under the [GNU Affero General Public License v3.0](LICENSE) or (at your option) any later version (AGPL-3.0-or-later). If you run a modified version of Neutrino as a network service, the AGPL requires you to make your modified source available to the people using that service.
