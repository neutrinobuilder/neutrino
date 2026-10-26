# Cryptography Manual, Neutrino

Reference document on **all** cryptographic primitives and protocols used in Neutrino: what they do, why they were chosen, where they are implemented, which attacks they mitigate. For the application flow (commands, TUI, wizard) see `user-manual.md`; for the non-cryptographic internal architecture see `technical-manual.md`.

Reference convention: references name the source file and the function or type involved.


---

## 1. Threat model

**What Neutrino protects:**
- The content of messages in transit (neither of the two endpoints can be read by anyone else)
- **In groups only (N>2)**, the sender's identity relative to the room host (sealed sender, see §5), the host can route a broadcast message without knowing which of the members wrote it
- Traffic metadata against external network observers (via Tor: no one sees who is talking to whom, or from where)
- Data at rest on disk (encrypted keystore)
- Continuity of identity over time, even across key rotations (§9)

**What it does NOT protect (known limits, not bugs):**
- **In a two-member room, the host is one of the two participants, not a third party to hide from.** The sealed sender from the point above is a real property of the broadcast mechanism (§5), but in a two-member room it protects nothing practical: the room's host is always the other party itself (never a stranger, §3), so "who wrote this" is never information they lack, they already know, since they're the one reading it. Sealed sender only becomes real protection when the host can be a stranger to the individual conversation, that is, in groups. Note that this does not apply to `to_user_ids` (file/`/grp-contact-send`, §6): that stays in the clear even in groups, for a different reason, it is multicast routing, not sender identity.
- **The initial identity exchange (QR).** Neither the relationship signature (§8) nor the safety code (not even when compared) protects against falsification of the initial QR, this is the structural limit of every TOFU system (Signal, WhatsApp, and every direct-exchange web-of-trust all have the same problem). Full detail in `technical-manual.md`, section "Explicit contact verification, The security hole". The only defense is a human comparison over a channel independent of the QR itself (`/sec-verify`).
- **A compromised endpoint.** If one of the two parties' devices is compromised (malware, physical access with an unlocked keystore), no transport cryptography helps, this is a limit of every system, not specific to Neutrino.
- **Metadata about "who is talking when" for an observer who controls both Tor endpoints** (timing correlation analysis), a known limit of Tor itself, not solvable at the application layer.

**RAM-only principle:** messages never touch disk (neither client-side nor server/relay-side), they disappear when the room is closed. The only persistent state is the keystore (identity, contacts, groups), encrypted at rest (§11).

---

## 2. Identity: Ed25519 key and `.onion` address

**What.** A Neutrino user's identity is a single Ed25519 keypair (32-byte private, 32-byte public). There is no certificate authority, no central directory: the identity *is* the key.

**Why Ed25519.** Small, fast signatures, no domain parameters to negotiate, a mature standard (RFC 8032), and it is the same scheme natively used by Tor v3 hidden services, it allows deriving the `.onion` address directly from the public key with no intermediate steps.

**Where:** `internal/keystore/keystore.go`, `New()` generates the keypair with `ed25519.GenerateKey(rand.Reader)`.

**`.onion` address derivation** (`internal/shared/crypto.go`, `OnionAddressFromPub`):
```
checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ 0x03)[:2]
payload  = pubkey[32] ‖ checksum[2] ‖ 0x03
address  = base32(payload) lowercase + ".onion"
```
Standard formula from the Tor v3 spec, not a project invention. Anyone who knows a contact's public key can compute their exact `.onion` address without needing a DNS query or a directory.

**`.b32.i2p` address derivation** (`internal/shared/i2p.go`, `I2PAddressFromPub`/`I2PDestinationPub`), used when the active network is I2P (`--net i2p`) instead of Tor. I2P's "destination" format requires, besides the signing key, a separate X25519 **encryption** key, unlike Tor, where the Ed25519 key alone is enough. To avoid introducing a second secret to persist, the X25519 key is derived from the same Ed25519 key via the standard **birational map** between the Edwards25519 and Curve25519 curves (equivalent to `libsodium crypto_sign_ed25519_pk_to_curve25519`/`_sk_to_curve25519`, not a project invention):
```
X25519 public   = birational_map(Ed25519 public)             # filippo.io/edwards25519, Point.BytesMontgomery()
X25519 private  = clamp(SHA-512(Ed25519 seed)[:32])           # same hash+clamp Ed25519 already computes internally
address         = base32(SHA-256(public destination)) lowercase + ".b32.i2p"
```
Key property, identical to Tor's: the map on the public key doesn't need the private one, so a contact computes another contact's I2P address from their Ed25519 public key alone, exactly as for `.onion`. The padding bytes required by the destination's fixed-width binary format (wider than the actual keys) are also derived deterministically from the public key via HKDF, not random: otherwise the address would change on every reconstruction.

**BIP-39 encoding.** The 32-byte seed of the Ed25519 key is encoded as 24 BIP-39 mnemonic words (`internal/keystore/backup.go`, `Mnemonic()`/`SeedFromMnemonic()`), writable on paper, an interoperable standard (the same wordlist used by Bitcoin/crypto hardware wallets). The 24 words *are* the identity: whoever possesses them can reconstruct the private key and the network address, `.onion` or `.b32.i2p` depending on the network chosen at restore.

---

## 3. Transport: Tor + WebSocket, never TLS

Every instance publishes a Tor v3 hidden service and communicates over WebSocket (`/ws/chat`). Tor already provides channel encryption and authentication at the transport layer (3 hops, onion encryption), for this reason **all** connections use plain `ws://`, not `wss://`: adding TLS on top of Tor would not increase real security, only the attack surface (certificates to manage). The server never configures a TLS listener, explicit comment in `internal/server/server.go`: *"Doesn't use TLS: the transport is protected by Tor."*

Two modes, both over `ws://` (`internal/client/client.go`, `Connect()` always uses `const scheme = "ws"`):
- **Toward a contact**: via Tor or I2P (`SetDialer`, generic across both transports), `.onion` or `.b32.i2p` address.
- **Toward your own room host**: `dialContext` stays `nil` (no call to `SetDialer`) → a local loopback connection on the same address that Tor/I2P itself forwards hidden-service/destination traffic to (`node.AddHiddenService`), this is not a local network/LAN fallback for talking to a remote peer, it always stays on the same machine.

---

## 4. Connection handshake (`ClientHello` / `ServerHello`)

**What.** The first two JSON messages exchanged over every WebSocket connection, before any application message. It fully replaces separate HTTP authentication endpoints, the entire auth protocol lives inside these two frames.

**Where:** `internal/shared/handshake.go` (struct), `internal/client/handshake.go` (`DoClientHandshake`), `internal/server/handshake.go` (`DoServerHandshake`).

### 4.1 Room proof, proving knowledge of the password without sending it

```
contactSecret = 32 random bytes, generated by the host and distributed individually
                to each invitee via encrypted knock, never a password, never
                shared between different members of the same room (RandomBytes(32))
period        = unix_time / 43200                  // 12 hours, rotations at 00:00/12:00 UTC
room_key      = HKDF-SHA256(contactSecret, info="room_<period>")
room_proof    = HMAC-SHA256(room_key, nonce_client)
```
(`DeriveContactRoomKey`, `ComputeRoomProof`, see `internal/shared/crypto.go`)

**Why.** The client proves knowledge of the per-member secret assigned by the host without ever transmitting it, not even in direct hashed form, only an HMAC tied to a random nonce generated at every connection, so it is not replayable on a different connection. The server verifies against the current period **and** the next one (`VerifyRoomProof`) to tolerate clock drift between machines, without this window, even a slightly misaligned clock would break authentication exactly at the boundary of every period rotation.

**Note:** the 12-hour rotation applies *only* to this password-proof HMAC, not to the transport key (§2, never automatic) nor to the `.onion` address (fixed, derived from it) nor to the relationship keys (§9, per-contact rotation, independent).

**Per-member secret, not shared.** The formula above is `HMAC-SHA256(HKDF(contactSecret, "room_<period>"), nonce_client)`, but `contactSecret` is never a single secret known to all room members: the host generates one **distinct per invitee**, distributed individually via ECIES knock (§7.1). The server (`RoomRegistry`, `internal/server/rooms.go`) checks the incoming `room_proof` against all known secrets and, on a match, also returns the stable `roomID` that secret belongs to, so N different secrets authenticate into the same shared room, instead of just one. Full implementation details in `technical-manual.md`, section "`RoomRegistry`, per-member authentication".

**Consequence for identity authentication.** `ClientHello.Username` is pure self-declared text, never cryptographically verified on its own, a client could write any value there. With a recipient-specific secret, the host derives the real identity from **which secret** was presented (`MatchedLabel`, assigned at generation time) instead of trusting the self-declared field: whoever knows only their own individual secret cannot impersonate another specific member of the same room.

**Why not a verifier-based PAKE (e.g. SRP).** Unlike SRP, there is no need here for a two-phase registration nor a server-side verifier persisted for each member: the per-member secret itself, generated and distributed by the host via encrypted knock, is already the only material needed on both sides, a member never needs to "register" with their secret before being able to authenticate, they receive it already set up at invite time.

### 4.2 Ephemeral key exchange, session forward secrecy, hybrid X25519+ML-KEM-768

Every connection generates an ephemeral X25519 keypair on both the client and server side (`ecdh.X25519().GenerateKey`), discarded when the connection closes. As of HandshakeVersion 4, the client also generates an ephemeral ML-KEM-768 keypair (`crypto/mlkem`, Go stdlib, FIPS 203), the server encapsulates (`Encapsulate`) against `ClientHello.MLKEMPub`, returning the ciphertext in `ServerHello.MLKEMCiphertext`; the client decapsulates (`Decapsulate`) to obtain the same shared secret:
```
mlkem_ss    = ML-KEM-768(ClientHello.MLKEMPub)          // Encapsulate on the server side, Decapsulate on the client side
combined_ss = mlkem_ss ‖ ECDH(session_priv, remote_session_pub)
session_key = HKDF-SHA256(
    combined_ss,
    salt = nonce_client ‖ nonce_server ‖ session_pub_client ‖ session_pub_server,
    info = "neutrino-session-x25519-mlkem768-v1"
)
```
(`DeriveSessionKey`, `crypto.go`; keypair generation/encapsulation/decapsulation in `internal/client/handshake.go`, `internal/server/handshake.go`)

**Why the entire transcript is in the salt.** Including both session public keys (in addition to the nonces) cryptographically binds the derived key to *that specific* pair of endpoints, it prevents relay/key-confusion attacks in which an attacker routes A's handshake to B, making both believe they are talking directly to each other. **Forward secrecy:** even if the Ed25519 identity key were compromised in the future, the ephemeral X25519 keys of past sessions have already been discarded, they cannot be used to decrypt previously intercepted traffic.

**Why hybrid, and why `mlkem_ss` comes before the X25519 secret in the concatenation.** An adversary intercepting today's traffic encrypted with X25519 alone (secure against any classical computer, but not against a future quantum computer large enough to break the elliptic-curve discrete-log problem) could store it and decrypt it later, a "harvest now, decrypt later" (HNDL) attack. ML-KEM-768 (FIPS 203, lattice-based) is believed secure even against a quantum adversary; combining the two secrets (instead of replacing X25519 with ML-KEM) guarantees the session key stays secure as long as **at least one** of the two underlying mathematical problems remains hard, no security loss relative to the previous pure-X25519 scheme, only a gain. The `mlkem_ss ‖ dh_secret` order (not the reverse) follows the same order as TLS 1.3's `X25519MLKEM768` hybrid group, described in `draft-ietf-tls-ecdhe-mlkem` (datatracker.ietf.org): the draft requires the secret of the **first FIPS-approved algorithm** to precede the non-approved one in the concatenation, an explicit requirement of NIST SP 800-56Cr2 §2, ML-KEM is FIPS 203 (approved), X25519 is not a FIPS-approved algorithm. The same draft notes that other hybrid groups (e.g. `SecP256r1MLKEM768`, where the ECDH algorithm is itself already a NIST primitive) reverse the order, so this is not a universal "ML-KEM always first" rule, but the case-by-case application of the same FIPS rule. Field sizes involved (ML-KEM-768): encapsulation key 1184 bytes (`ClientHello.MLKEMPub`), ciphertext 1088 bytes (`ServerHello.MLKEMCiphertext`), shared secret 32 bytes, identical to those of the TLS hybrid group, reused unchanged in our scheme.

**Mandatory, no permissive fallback.** A peer that does not send `MLKEMPub` (client) or `MLKEMCiphertext` (server) of the correct length is explicitly rejected (`ErrMissingHybridKEM` if the payload is malformed at the same version; `ErrVersionMismatch` if the version itself doesn't match), the same philosophy already applied to handshake authentication (§4.3): no session proceeds with only one key-exchange algorithm. No interoperability path exists with a peer on an earlier `HandshakeVersion` (current: **5**).

### 4.3 Handshake authentication with the per-relationship IdentityKey, always required, on both sides

The client signs `nonce_client ‖ session_pub_client` and the server signs `nonce_client ‖ nonce_server ‖ session_pub_server` (`ClientSigPayload`/`ServerSigPayload`, `internal/shared/crypto.go`), not just any application message, but the handshake itself. This authenticates the *entire session* from the first exchange onward, not only subsequent messages.

A peer on an earlier `HandshakeVersion` is explicitly rejected, never accepted through a permissive fallback.

The signature never uses the transport key (§2): it uses the **per-relationship IdentityKey**: a randomly generated Ed25519 keypair (+ ML-KEM-768/ML-DSA-65 companions) independent for each contact (`shared.RelSigningKey{Priv, MLKEMSeed, MLDSASeed}` for one's own, `shared.RelPeerKey{Pub, MLDSAPub}` for the peer's known one, `internal/shared/handshake.go`, `GenerateRelSigningKey`/`RelSigningKeyPublicParts`). The client signs `ClientHello.Sig`/`SigMLDSA` with its own per-relationship IdentityKey toward the host it is connecting to; the server signs `ServerHello.Sig`/`SigMLDSA` with its own per-relationship IdentityKey toward that specific client (`DoServerHandshake`/`DoClientHandshake`, `internal/server/handshake.go`/`internal/client/handshake.go`). No permissive fallback: a `ClientHello` whose signature does not verify against the per-relationship IdentityKey known for that secret is rejected outright (`ErrInvalidSignature`); a per-relationship IdentityKey not yet known for that peer (`RelPeerKey.Pub` empty) is rejected before verification is even attempted (`ErrUnknownIdentity`), the same symmetric treatment applies client-side for `ServerHello`.

**No bootstrap problem, because the key is already known before connecting.** Unlike a key declared inline in the handshake itself, the per-relationship IdentityKey is exchanged **before** any room connection is ever attempted: as soon as two users become mutual contacts, each side generates its own two relationship keypairs (IdentityKey + ContentKey, §8) and sends them to the other with a dedicated knock (`rel_init`/`rel_init_ack`, §8), encrypted toward the recipient's transport key (§7.4), not toward an in-progress session. Whoever invites to a room, or accepts an invite, explicitly checks, before attempting the connection, that this exchange is already complete for the contact involved (`RelIdentityPriv`/`PeerRelIdentityPub` present); if it isn't, the operation is queued until the exchange completes (§8) instead of proceeding with a handshake doomed to fail. There is therefore never a window in which a just-met peer's signature is not yet verifiable, and no public key ever needs to travel inside the handshake itself: the handshake always happens after the key exchange has already succeeded.

---

## 5. Broadcast message encryption (group room), "Sender Key" pattern

**What.** Each client generates a random 32-byte `senderKey` on connection (`client.go`), distributed **hybrid X25519+ML-KEM-768 ECIES** (§7.3) to each peer in the room individually, never in the clear, never to the server. From that `senderKey` it derives a one-directional symmetric HMAC ratchet:

```
chain_key₀   = HKDF-SHA256(senderKey, info="neutrino-chain-v1")     // InitChainKey
key_id       = HMAC-SHA256(senderKey, "neutrino-key-id-v1")[:4]     // 8 hex chars, DeriveKeyID

// on every message (DeriveChainStep):
msg_key       = HMAC-SHA256(chain_keyₙ, 0x01)   // single-use, encrypts exactly one message
chain_keyₙ₊₁ = HMAC-SHA256(chain_keyₙ, 0x02)   // replaces the state, one-way step
```
(`crypto.go` `DeriveKeyID`, `InitChainKey`, `DeriveChainStep`)

**Sealed sender.** Username and text are packed **inside** the ciphertext (`sealedMsg` struct), never in the WebSocket frame's clear-text metadata. The relay/server only sees `{text: <ciphertext>, idx, kid, mseq, msg_id}` (plus the per-recipient signatures, see below), it never knows who wrote what, even if it can observe all the traffic it routes. `sealedMsg` also carries an optional `rt` field (explicit reply reference, §5bis): the number of the message this one is replying to, always chosen by the user (`/msg N` in the TUI), also inside the ciphertext, the relay never learns which message a reply targets, only that *a* reply reference exists (ciphertext length, same as any other optional field).

**Per-recipient signature, outside the ciphertext.** Every message carries, alongside the ciphertext but not inside it, a list of signatures, one per pairwise relationship present in the room (`content_sigs`, each `{for: <recipient member key>, sig, sig_mldsa}`, with the per-relationship ContentKey, §8): every recipient must be able to find and verify their own entry without first having to decrypt the message. These entries stay outside the ciphertext but do not compromise sealed sender: they only reveal *who* each signature is addressed to (already known: they are members of the same room), never *who wrote* the message.

This is a single mechanism, used both in groups and in two-member rooms (with only two participants in the room, "broadcast to the room" coincides with a private message between the two of you, §6). But the protection it offers only makes sense where there is an ambiguity worth preserving: **in a group with N members, sealed sender hides from the host which member wrote a given message**: a real protection, because the host can be a stranger to the conversation between any two members. **In a two-member room, the host is always the other party itself** (never a third party, §3): there is no ambiguity to protect, because in a two-person room whoever receives a message already knows, by construction, that it was written by the only other person present. The crypto mechanism stays identical, but its practical usefulness depends on the number of participants in the room.

**AES-256-GCM with AAD.** Every message is encrypted with `msg_key` and the sequence number `idx` (big-endian, 8 bytes) as **additional authenticated data** (`seqBytes`, `client.go`), the index is part of the authentication tag, not just the metadata: an attacker cannot get a message accepted under a different `idx` than the one it was actually encrypted with, which blocks replay and silent reordering.

**Why a ratchet and not a static key: forward secrecy.** Whoever obtains the current `chain_key` cannot recompute the `msg_key`s of already-sent messages (the step is one-way, not invertible), compromising the present state does not compromise that key's past history. `RotateSenderKey` (`client.go`) regenerates everything: new `senderKey` activated immediately for outgoing traffic, old state explicitly zeroed in memory (`zeroKey`). It fires on the first of two independent criteria (OR): a count of messages sent under the current generation (`MessagesSinceRotation`, default 25, `config.SenderKeyMessageBudget`) or a fixed time interval as a hygiene backstop even in a silent room (default 5 minutes, `config.SenderKeyInterval`), plus the user's explicit request (`/grp-reconnect`). Distributing the new key to a single peer uses hybrid ECIES (§7.3) and is never fire-and-forget: it travels over the same reliable delivery channel as any other message (§5bis) and, if that peer still has unconfirmed messages from the previous generation, distribution is deferred until that queue drains, otherwise `StorePeerSenderKey` on their side would immediately zero the old chain (immediate replacement, never a timed retention) right while they still need the queued steps to decrypt it. Only messages of the previous generations hold the distribution back: messages already encrypted under the new key cannot be decrypted, and so never acknowledged, before the key arrives. The one rotation that sends the new key to every peer at once is the one triggered by the message TTL (§5bis): there every unconfirmed message is re-encrypted under the new key, so no peer needs the previous one any longer.

**Strict ordering, never a fast-forward.** `DecryptMsg` advances the ratchet by **exactly one step** and rejects any `idx` other than the one expected, a lower `idx` is a duplicate (no advancement, but an ack is still sent: the original ack, not the message, may have been the one lost), a higher `idx` is not yet its turn and must be buffered by the caller (§5bis) until the intervening messages actually arrive. Skipping ahead in the chain is never possible: in two-member rooms every step depends on the DH mix of the immediately preceding message (§5.1), so a skipped step can't be recomputed. With zero-loss delivery while the channel is alive (§5bis) a packet is never lost for good, you wait, period: no computation over an `idx` that never arrived, so no safety threshold is needed on how far to "guess."

### 5.1 DH ratchet for two-member rooms, post-compromise security

**Why.** The ratchet in §5 is **only** a symmetric ratchet (one-directional HMAC chain): it gives forward secrecy but not post-compromise security (PCS), whoever obtains `chain_key` at a given instant reads all subsequent messages until the sender key is manually rotated, because nothing in the `HMAC-SHA256(chain_keyₙ, 0x02)` step depends on material the attacker does not already possess. SenderKey exists, instead of a full Double Ratchet, because of the fan-out to N>2 members: a pairwise DH ratchet (shared state between two parties) does not generalize to a group. But a room with **exactly two members** is precisely the case the Signal Double Ratchet was designed for. For that case alone, a DH ratchet is incorporated into the same state as the already-existing symmetric ratchet, **rebuilding the two classic Double Ratchet components on top of SenderKey** (symmetric ratchet + DH ratchet), not adding a separate subsystem. The DH material travels **in the same already-existing broadcast frame** (no new frame, no targeted `to_user_id`): the server remains structurally blind, it does not distinguish a reinforced two-person room from a normal group.

**When it activates.** `Client.ratchetDH` (`client.go`), decided once when the connection is created, based on the number of members in the room at creation time, never recomputed afterward, because a room's membership does not change once created:
- `cmdInvite`: `len(members) == 2` (host + a single invitee)
- `cmdJoin`: `len(knock.Members) == 2`
- `cmdRecall`: saved group with exactly 2 members

For N>2 it stays pure SenderKey (symmetric ratchet only), unchanged from §5.

**What.** `sealedMsg` (§5) gains two optional fields, populated only when `ratchetDH` is active, and therefore encrypted together with the rest of the message under AES-256-GCM with `msg_key`, never in the clear on the wire:
```
dh   = base64(my_eph.pub)                    // current ephemeral X25519 pubkey, renewed on every send
dhr  = EphID(known_peer_eph.pub)              // 8 hex chars, which of the peer's pubkeys was used in the mix
```
At step n, if a peer pubkey is already known:
```
dh_shared     = ECDH(my_eph.priv, known_peer_eph.pub)
msg_key       = HMAC-SHA256(chain_keyₙ, 0x01)               // identical to §5, does not depend on DH
chain_keyₙ₊₁ = HMAC-SHA256(chain_keyₙ, dh_shared ‖ 0x02)    // reinforced step, DeriveChainStepDH
```
otherwise (bootstrap: no peer pubkey seen yet) it stays on the simple step from §5. After every send, the ephemeral used is retired (`retireOutEph`) and a new one generated for the next message, published but not yet used in one's own next mix step.

**Why retired ephemerals must be kept.** The recipient, to recompute the same `dh_shared` (ECDH identity: `ECDH(a, B) = ECDH(b, A)` when `A = aG`, `B = bG`), must use `ECDH(known_peer_eph.priv, sender_eph.pub)`, that is, the private key of **their own** ephemeral that the sender referenced as the "known point." That same ephemeral serves simultaneously as the key of one's own outgoing ratchet and as the reference for the other party's incoming ratchet, exactly as in the real Double Ratchet, where there are no two independent DH states but one shared one, and it therefore cannot be discarded right after a single use. The `dhr` field tells the recipient which of their retained keys to use, without needing to guess. `outEphRing` (`client.go`) keeps each retired ephemeral until one of two bounds is reached, whichever comes first:
- **proof of receipt:** the peer references a newer one. The peer always references the latest of ours it has seen, and its messages are processed in order, so none of its later messages can reference an older one (`pruneOutEphBefore`);
- **time:** twice the message TTL (`message_ttl`, default 3 minutes, §5bis) after its retirement (`expireOutEph`).

The time bound is decided by us alone: a peer that stays silent, or keeps referencing an old ephemeral, cannot keep our private ephemerals alive beyond it. A sender_key rotation leaves `outEphRing` untouched, because the peer's messages already in flight may still reference ephemerals retired before it.

**Post-compromise security guarantee, with explicit limits.**

- *Normal case (in-order delivery).* An attacker who obtains `chain_keyₙ` at instant T can compute `msg_keyₙ₊₁ = HMAC(chain_keyₙ, 0x01)`, so they read exactly **one** additional message beyond those already intercepted, the first one after the theft. They cannot compute `chain_keyₙ₊₁` (it requires `dh_shared`, which needs a private ephemeral key generated *after* the theft and never exposed), from the next message (n+2) onward the chain is secure again, with no need for manual rotation.
- *Delayed peer messages.* With the strict ordering of §5 a message never overtakes another one: the only window that matters is how long one's own ephemeral stays retained before the peer references it in a `dhr`. If the peer references one no longer retained, the message is **refused** without advancing the chain and without an ack: the sender mixed that ephemeral into its next chain key, so a simple step here would diverge from the sender's for every later message of that generation. Past the TTL the sender re-encrypts it under a new generation (§5bis), and the room recovers on its own. Forward secrecy is unaffected; the exposure of our retired private ephemerals is bounded by twice the TTL.
- *Assumption about the compromise model.* The guarantee concerns the **instantaneous** theft of state (`chain_key`, not ephemeral keys in transit) at a given moment, not persistent access to the device (e.g., active malware that keeps reading newly generated ephemeral keys as they appear). No ratchet scheme, including Signal's Double Ratchet, protects against sustained device compromise: this is a physical limit of the analysis, not specific to this implementation.
- *Authenticity of the DH material.* `dh`/`dhr` are not individually signed, but they travel inside `sealedMsg`, encrypted and authenticated with AES-256-GCM under `msg_key` (§5), an external attacker who does not possess the current chain state cannot inject or alter a fake ephemeral without decryption failing. Whoever already possesses the current state (the compromise scenario analyzed above) still receives the ephemerals genuinely generated by the legitimate other party and simply does not know their private keys, that is why healing works even in that case.

**Reset.** `StorePeerSenderKey` forgets the peer's known ephemeral (`peerEphPub`) together with its old chain key: our next send uses the simple step until a message under the new generation brings a fresh one. `RotateSenderKey` keeps our own ephemerals (`outEphRing`, `outEphPriv`/`outEphPub`), for the reason given above.

### 5bis. Reliable delivery and message numbering

**Why this belongs in this document.** This is not a cryptographic mechanism in itself, but it is the reason the ratchet can afford the strict ordering of §5 (never a fast-forward): without a real guarantee that a message always eventually arrives, "wait instead of guessing" would block the room forever in the face of a genuine loss. Full implementation details (queues, backoff, overload kick) are in `technical-manual.md`.

**Two distinct numbers, never the same `idx` as the ratchet.** Every broadcast message carries, in the clear alongside the ciphertext:
- `mseq`, the SENDER's own counter, never reset by `RotateSenderKey` (unlike `idx`, internal to the ratchet and always zeroed at every new generation, §5). Used by the sender's delivery queue to correlate acks/retransmissions.
- `gseq`, the ROOM's counter, assigned by the server on arrival (independent of who wrote it), unique within the room. It is the number shown to the user (`#N` at the end of each line) and the basis for the explicit reply reference `rt` (§5).

Neither is secret or sensitive: they are ordering metadata, not identity, sealed sender (§5) stays intact.

**Verbatim retransmission within the TTL, re-encryption under a new generation past it.** A message not confirmed within a threshold (default 20s, doubling) is repeated byte-for-byte, the same already-produced ciphertext, never re-encrypted. Re-encrypting it as a further step of the same chain would advance the chain a second time for the same logical content, for a message the recipient might already have, exactly the kind of misalignment strict ordering exists to eliminate.

A message still unconfirmed by a connected recipient past the **message TTL** (`message_ttl`, default 3 minutes) is handled differently, because the recipient may have refused it (§5.1) and would keep refusing the same ciphertext, while its chain cannot skip ahead:
- the sender rotates its sender_key and sends the new key to every peer at once;
- it re-encrypts **every** unconfirmed message under the new generation, in original order, with the same `msg_id` and `mseq`.

A new generation starts its chain from `idx` 0, so this never creates a gap: the old chain is abandoned on both sides. The server keeps the `gseq` first assigned to that `msg_id` and replaces the copy still queued for whoever has not acknowledged it. A recipient that had already decrypted the earlier copy (only its ack was lost) recognizes the `msg_id`, acknowledges it again and never shows it twice. A refused message, like any message that fails to decrypt, is neither shown nor acknowledged: the missing ack is what triggers the re-encryption.

**Self-echo: the sender never decrypts its own message.** The server sends each sender back its own frame right after distributing it (necessary because no other point in the code shows the line for one's own send before then). If this echo were fed through the generic reception ratchet, in two-member rooms (§5.1) it would fail systematically: the `dhr` field we publish when sending identifies an ephemeral key OF THE PEER, never our own, looking it up in our own `outEphRing` (which holds only our own retired ephemerals) would never find it, permanently diverging the self-echo chain from the real `senderChainKey` as soon as the DH mix activates. The `sentTexts` cache (plaintext + `rt`, indexed by `msg_id`, populated *before* the write to the wire to avoid a race on the self-echo of a local connection) avoids the problem at the root: it recognizes its own echo by `msg_id` and reuses the text already known from having written it, never invoking the ratchet.

---

## 6. File transfer and contact sharing, targeted multicast

**What.** `/grp-file-send` and `/grp-contact-send` (sharing a contact card, see §6.1) route a payload to one or more explicitly chosen recipients, without broadcasting to the entire room. The content is encrypted with a symmetric key generated for the occasion, whose metadata is encrypted separately for each recipient with their per-relationship ContentKey (§8), carried inside the normal `file_offer`/`file_chunk` frames.

**Where:** `internal/server/hub.go` (`MulticastBytes`), `internal/server/ws.go` (case `"file_offer"`/`"file_chunk"`), `internal/client/client.go` (`SendFileOffer`), `internal/client/tui/tui.go` (`onFilePresetChosen`).

**Socket-level multicast, not broadcast+filter.** `Hub.MulticastBytes(ctx, userIDs...)` writes **only** to the WebSocket connections whose IDs are in the list, anyone not among the recipients receives no bytes at all, unlike the broadcast in §5 where everyone receives the same frame and self-selects via decryption. This requires the frame to carry `to_user_ids` **in the clear**: the relay must know where to route it.

**No sealed recipient, an explicit trade-off, not a hidden flaw.** The host always sees, without decrypting anything, the complete list of recipients chosen for each `file_offer`/`file_chunk`, even in groups, where it can be a third party unrelated to the individual conversation. This was not hidden for a practical reason: `to_user_ids` is needed by the relay to route efficiently (real multicast to N recipients, not "send to everyone and let only those who can decrypt do so"); hiding it would require either transmitting to the whole room (O(room) bandwidth instead of O(recipients)) or an anonymous recipient-tag protocol, neither justified for the current use case (targeted sends, not a continuous chat channel).

**File name and size encrypted, not just the content.** `file_name`/`file_size` have never needed to be known by the server, the `FileTransferMaxSizeMiB` limit is applied only on the sender side, before sending, never read server-side. The file's content is encrypted **once** with a random symmetric key (`fileKey`, AES-256-GCM); `{file_name, file_size, file_key}` is then encrypted **separately for each recipient** with their per-relationship ContentKey (`shared.EncryptForPeer`/`DecryptFromPeer`, a generalization of the same dual-mode hybrid X25519+ML-KEM-768/pure-X25519 scheme already used for knocks, §7.4), one envelope per recipient (`shared.FileOfferEnvelope{MetaBlob}`) instead of a single multi-recipient shared blob. The recipient decrypts their own envelope in the background (never inline in the event loop, so the decryption work never blocks the UI) before showing the accept/reject prompt, then uses the recovered `file_key` to decrypt the actual content. Authenticity is established BEFORE this exchange, on a separate lightweight frame (`file_announce`, §6.2 below).

**Per-recipient signature on the hash, not the envelope.** Authenticity of the shared ciphertext is proven at announce time, not on the metadata envelope: `shared.SignRelMsg`/`SignRelMsgMLDSA` signs `sha256(ciphertext)` with the sender's per-relationship ContentKey **toward that specific recipient** (same `RelMsgSigPayload` domain as §5, also bound to the declared recipient), not a single shared signature. A file/contact card with N recipients therefore carries N independent signatures over the same hash, one per pairwise relationship; the metadata envelope (`FileOfferEnvelope`) that arrives afterward carries no signature of its own.

### 6.1 Contact sharing

`/grp-contact-send` shares a contact card as a special case of file transfer, no dedicated cryptographic subsystem:
- reuses exactly the same encryption, the same multicast routing, the same metadata encryption from this section;
- can be shared with one or more chosen members in any tab, via the same multi-select picker used by `/grp-file-send`;
- requires that the ContentKey relationship already be established (bidirectionally) between sender and each recipient, same constraint as `/grp-file-send`, a persistent relationship for a saved contact, or an ephemeral one for a stranger "introduced" in the same room (§8.1).

### 6.2 Verification moved before the transfer (self-heal)

**What.** Before any real `file_offer`, a lightweight `file_announce` frame carries only `hash := sha256(ciphertext)` and the per-recipient signature over that hash, no file name/size/key. The recipient verifies right away: valid → immediate `file_announce_ack`, the hash stays pending awaiting the real `file_offer`; invalid (sender's ContentKey misaligned, e.g. a regeneration never propagated) → **self-heal**, the same mechanism already used for chat messages (`RelContentConfirmedByPeer` reset on the exact device, which re-triggers a `rel_init` resend), with a probe round triggered immediately instead of waiting for the periodic cycle, the announce stays pending (only hash+signature, a few dozen bytes) until a `rel_init_ack` resyncs the key or the budget (`file_transfer_offer_timeout`) expires.

**Why.** A signature carried inside `file_offer` and covering the ENTIRE ciphertext would be verifiable only after receiving and reassembling the whole file: a failure due to a misaligned key would discard the file, since the ciphertext is deleted from disk right after verification, and a self-heal triggered at that point would still require a full retransmission. Moving verification to a lightweight hash BEFORE the transfer means a self-heal never needs to retransmit any file byte.

On completion, `finalizeIncomingTransfer` re-verifies no signature: only `sha256(received ciphertext) == hash already verified at announce time`, a mismatch here is always transport corruption/tampering, never a key problem.

**Where:** `internal/client/tui/tui.go` (`handleRoomMsg`, case `"file_announce"`/`"file_announce_ack"`), plus the equivalent handlers in the Android app (in testing, not part of this repository).

### 6.3 Strong pre-compression pack (XZ/LZMA2)

**What.** Before encrypting the content of a file or a contact card, `shared.PackData` always tries compressing first with LZMA2/XZ (pure Go, `github.com/ulikunitz/xz`) and compares the result with the original, using whichever is smaller, never worse than not compressing at all. A one-byte marker at the head of the plaintext (`packRaw`/`packXZ`) lets `shared.UnpackData` reverse exactly the operation chosen, regardless of how the sender configured compression, correct across different versions/platforms with no prior coordination needed. The packed result is then encrypted with AES-256-GCM: compressing already high-entropy data twice would gain nothing.

**Where:** `internal/shared/pack.go`.

**Why before encryption.** Here the compression ratio matters more than speed (it's a one-time pack before a send). The classic "compression oracle" risk (as in CRIME/BREACH, where observing ciphertext size leaks information about a plaintext that is only partially secret and partially known to the attacker) does not apply here: the file is entirely secret, not a plaintext mixed with attacker-controlled data, an outside observer only sees an encrypted blob of known size, regardless of which compression method was chosen.

---

## 7. ECIES, point-to-point encryption for key distribution

**What.** Point-to-point encrypt-then-MAC based on ephemeral X25519: `ECIESEncrypt`/`ECIESDecrypt` (`crypto.go`).
```
eph_priv, eph_pub = X25519.GenerateKey()
shared            = ECDH(eph_priv, recipient_pub)
channel_key       = HKDF-SHA256(shared, info="neutrino-ecies:"‖eph_pub‖recipient_pub)
wire              = eph_pub[32] ‖ AES-256-GCM(channel_key, plaintext)
```

**Where it is used:**
- Encryption of `KnockPayload`s (knocks, group invites, key rotation announcements, relationship-key exchange/rotation), encrypted directly under the recipient's Ed25519 transport key, converted to X25519 (§7.1)
- **Not** used for distributing the `senderKey` (§5): that uses the hybrid variant `HybridECIESEncrypt`/`HybridECIESDecrypt` (§7.3) instead of this function.
- `KnockPayload`s stay on this pure-X25519 form ONLY toward a recipient whose durable ML-KEM-768 key is not yet known, `EncryptKnock`/`DecryptKnock` are dual-mode: see §7.4.

**Why the recipient's key and `eph_pub` are also in the HKDF `info`:** binding the channel key to that specific exchange prevents reuse of the same derived key across different contexts even given the same DH secret (which, with fresh ephemeral keys on every call, is always different anyway, but domain separation remains good defensive practice).

### 7.1 Ed25519 → X25519 conversion

`KnockPayload`s must be encrypted for a contact of whom **only** the Ed25519 identity key is known (no dedicated X25519 key exchange for a simple knock). `Ed25519PubToX25519`/`Ed25519PrivToX25519` (`crypto.go`) apply the standard birational Edwards→Montgomery map (isomorphic curves) to obtain the corresponding X25519 key, the same formula used by libraries like libsodium for the same purpose, not a project invention.

### 7.2 DH mutuality tag, filtering before decryption, not after

**Why.** Decrypting a `KnockPayload` (ECIES, §7) has non-trivial cost, and the mere attempt to decrypt is not enough to establish whether the sender is a legitimate contact: without an additional check, the server would have to try decrypting every incoming knock against every possible sender, or blindly accept any well-formed envelope. The mutuality tag moves the legitimacy check **before** decryption, not after.

```
tag = HMAC-SHA256(ECDH(my_X25519_key, peer_X25519_key), "neutrino-knock-tag")
```
(`KnockDHTag`, `crypto.go`, both sides' Ed25519 identity keys are first converted to X25519, §7.1)

**Symmetric by construction.** `ECDH(a, B) = ECDH(b, A)` when `A = aG`, `B = bG`: sender and recipient each compute the **exact same tag** starting from their own private key and the other's public key, with no dedicated exchange, the same principle as the DH ratchet in §5.1, here applied to two static keys instead of ephemeral ones (no forward secrecy is expected or needed: the tag only proves "I know your public key and you know mine," it protects no content).

**Wire format.** `KnockEnvelope{Tag []byte, Payload string}` (`crypto.go`), the tag travels in the clear alongside the still-ECIES-encrypted `KnockPayload`, never in place of it: the tag alone reveals nothing about the knock's content (invite, key rotation, relationship-key exchange...), it only routes the decision whether to proceed with decryption.

**Server-side filter.** `handleKnock` (`internal/server/handlers.go`) computes its own expected tag against every known contact in its own address book (and against itself, for the self-probe case) and compares each one with `hmac.Equal` (constant-time) **before** ever calling `DecryptKnock`: a tag that matches no known contact is discarded immediately, without ever attempting ECIES decryption. After a match and a successful decryption, an additional defense-in-depth check verifies that `payload.FromIdentityPub` really matches the contact whose tag matched, a sender cannot present A's tag but a payload signed/encrypted to claim to be B.

### 7.3 HybridECIES, sender_key delivery, hybrid X25519+ML-KEM-768

**What.** `HybridECIESEncrypt`/`HybridECIESDecrypt` (`crypto.go`) replace `ECIESEncrypt`/`ECIESDecrypt` for the one point in the protocol where a long-lived symmetric secret travels that is exposed to the HNDL attack described in §4.2, peer-to-peer delivery of the `senderKey` (§5). Same encrypt-then-MAC scheme as §7, with an ML-KEM-768 encapsulation added to the ephemeral X25519 exchange:
```
eph_priv, eph_pub       = X25519.GenerateKey()
dh_secret               = ECDH(eph_priv, recipient_pub)
mlkem_ss, mlkem_ct      = ML-KEM-768.Encapsulate(recipient_MLKEMPub)
combined_ss             = mlkem_ss ‖ dh_secret
channel_key             = HKDF-SHA256(combined_ss, info="neutrino-ecies-x25519-mlkem768-v1:"‖eph_pub‖recipient_pub)
wire                    = eph_pub[32] ‖ mlkem_ct[1088] ‖ AES-256-GCM(channel_key, plaintext)
```
Same `mlkem_ss ‖ dh_secret` order and same NIST/FIPS rationale as `DeriveSessionKey` (§4.2), explicit domain separation in the HKDF label relative to the one used for the handshake's session_key, while sharing the same combinator principle.

**No third keypair.** `recipient_MLKEMPub` is not generated specially for this purpose: it is the same ML-KEM-768 encapsulation key the peer already announced in its own `ClientHello.MLKEMPub` during the handshake with the host (§4.2), relayed to the room's other already-connected members via `wsUserJoined`/`userInfo` (new `mlkem_pub` field, same scheme already used for `PeerECIESPub`/`session_pub` and for `IdentityPub`), and learned by each client via `Client.RegisterMLKEMPub` (`peerMLKEMPubs`, cached per `userID`, pruned on the same peer's reconnect exactly like `peerSessionPubs`). On the receiving side, the decapsulation key used is `Client.mlkemDecap`, the same object returned by `DoClientHandshake` (`HandshakeResult.ClientMLKEMDecap`) and already used to decapsulate one's own `session_key`, safe by construction: an ML-KEM encapsulation key can receive `Encapsulate()` from multiple independent parties (here: the server for the session_key, and each peer in the room for their own `senderKey`) with no loss of security, unlike a Diffie-Hellman nonce.

**Callers.** `Client.SendSenderKey`, `Client.StorePeerSenderKey`, `Client.RotateSenderKey` (`internal/client/client.go`), wire frame `{type: "sender_key", to_user_id, payload}`, with `payload` in the hybrid format above.

**No externally observable difference.** An unknown tag, a known tag whose payload turns out inconsistent after decryption, and a successfully processed knock all produce the **same HTTP 202 response**: the mutuality mechanism itself must not be usable to enumerate the recipient's address book (an attacker trying tags at random cannot distinguish "unknown contact" from "known contact but something else didn't match" by observing only the response).

### 7.4 Hybrid knocks X25519+ML-KEM-768, durable key, permanent dual-mode

**What.** `EncryptKnock`/`DecryptKnock` (`crypto.go`) JSON-marshal a `KnockPayload` and hand it to `EncryptForPeer`/`DecryptFromPeer` (§6's generalization of this same dual-mode scheme), which encrypts it in hybrid form whenever the recipient's **durable** ML-KEM-768 encapsulation key is known (`Keystore.MLKEMKey`, generated once alongside the Ed25519 identity, not a per-connection ephemeral key like in §4.2/§7.3): a third keypair is needed because a knock, unlike a handshake or `senderKey` delivery, can reach an **offline** contact, encrypted against their long-lived identity, not against an in-progress session for which no ephemeral key yet exists.

```
xPub                = Ed25519PubToX25519(recipient_identity_pub)             // §7.1
mlkem_ss, mlkem_ct  = ML-KEM-768.Encapsulate(recipient_MLKEMPub)             // only if known
combined_ss         = mlkem_ss ‖ ECDH(eph_priv, xPub)
channel_key         = HKDF-SHA256(combined_ss, info="neutrino-ecies-x25519-mlkem768-v1:"‖eph_pub‖xPub)
wire                = "H:" ‖ base64(eph_pub[32] ‖ mlkem_ct[1088] ‖ AES-256-GCM(channel_key, plaintext))
```
Same combinator (`mlkem_ss ‖ dh_secret`, same NIST/FIPS rationale as §4.2) and the same `HybridECIESEncrypt`/`HybridECIESDecrypt` function already used by §7.3, no new primitive, just a second call site.

**A wire discriminator, not a transition window.** A two-character prefix (`"H:"` hybrid / `"C:"` classic, `peerEncFormatHybrid`/`peerEncFormatClassic` in `EncryptForPeer`) precedes the base64 payload, `DecryptFromPeer` reads it to decide which branch to run, falling back to classic decryption for a payload without a prefix. **The classic branch is not a transitional state**: a contact whose ML-KEM key was never learned stays permanently on classic knocks (X25519 only) until a QR/URI is re-exchanged, no lockout, no forced downgrade, no expiry. The mutuality filter (§7.2, `KnockDHTag`) is unchanged: the tag is computed on the Ed25519/X25519 keys, independent of whether the payload is then encrypted classically or hybridly.

**Durable key: generation, rotation.** `Keystore.MLKEMKey` is generated alongside `IdentityKey` in `New()` and rotates in **the exact same event** as `StartRootRotation()`, never independently: the ML-KEM key signs or certifies nothing on its own and has no compromise vector distinct from the transport identity it accompanies. A keystore predating this migration (version 1 or 2) receives a backfilled `MLKEMKey` on first load (`migrateVersion`), exactly as `IdentityKey` already did on the v1→v2 migration.

**URI/QR format.** `nu://username/base64(ed25519_pub)[/base64(mlkem_pub)]`, the transport key and its durable ML-KEM companion alone (the third positional segment, the durable ML-DSA-65 companion, is described in §8bis), never a relationship key (which would make no sense in a QR shared with anyone who scans it, see §8). Each PQC segment has a fixed length (1580 base64 characters for the 1184-byte ML-KEM key, 2604 for the 1952-byte ML-DSA key, both with padding); the parser (`parseNuURI`/`parsePeerURI`) recognizes them by length and decode validity, not by a dedicated separator; any leftover text after the recognized segments produces an explicit error. **A single QR frame is sufficient for the transport key alone**: the URI with Ed25519+ML-KEM stays well within the capacity of a Medium error-correction QR even in byte mode, with the ML-DSA segment as well (§8bis), multi-QR chunking is needed instead, see there.

**Callers.** `encryptKnockTagged`/every call site that sends a `KnockPayload` (`internal/client/tui/tui.go`, and the equivalent code of the Android app, in testing and not part of this repository) resolves the recipient's `MLKEMPub` from the address book (`Contact.MLKEMPub`) before encrypting, `nil`/empty if unknown, automatic fallback to the classic branch. Server-side, `handleKnock` (`internal/server/handlers.go`) uses its own `mlkemDecap` (durable twin of `identityPriv`, passed to `RunOnListener` as a fixed value, a rotation spawns a new listener with a new hidden service, it does not modify the one already running, same scheme as `identityPriv`).

---

## 8. Per-relationship ContentKey: certification and content encryption, not transport hardening

**Design intent.** Every contact has, besides the per-relationship IdentityKey of §4.3 (authenticates the handshake), a second, independent, randomly generated keypair: the **per-relationship ContentKey**. Neither is ever shared across more than two parties, and neither is the transport key (§2, which only generates the network address and routes knocks, §7.4). Message and file content is already protected by §5/§6 and vanishes by RAM-only design regardless: the ContentKey's purpose isn't to make messages "more encrypted," but to provide a verifiable, non-repudiable signature per relationship, whoever wrote a message or sent a file proves it with a key they share exclusively with the recipient.

**Where:** `internal/shared/crypto.go`, `internal/keystore/keystore.go` (`Contact.RelContentPriv`/`PeerRelContentPub` fields + PQC companions).

**Generation and signing.** Ed25519 keypair + ML-KEM-768/ML-DSA-65 companions (same trio as §4.3), generated in-process the moment two users become mutual contacts, never derived from a master secret, never shared with any other relationship. Native Ed25519 signature (`SignRelMsg`/`VerifyRelMsg`) + an optional parallel ML-DSA-65 signature (`SignRelMsgMLDSA`/`VerifyRelMsgMLDSA`, never blocking if the companion isn't known yet), encryption via X25519 conversion of the same Ed25519 key (`Ed25519PrivToX25519`/`Ed25519PubToX25519`, §7.1), no third keypair dedicated solely to encryption.

**Automatic exchange when a contact is added.** As soon as two users become mutual contacts, each side generates, in the background, its own per-relationship IdentityKey and ContentKey toward the other and sends a `rel_init` knock (its four public keys, `shared.KnockPayload.RelBootstrap`, reusing the same payload as the ephemeral bootstrap of §8.1), encrypted toward the recipient's durable transport key (§7.4), routed only if the knock's mutuality tag (§7.2, computed on the transport keys) already matches a contact on both sides. Whoever receives a `rel_init` generates their own keys if they don't already have them and always replies with `rel_init_ack`; if their own keys are not yet confirmed by the sender (their earlier `rel_init` was dropped by the sender's mutuality filter, before the sender added them), the ack is followed by their own `rel_init`, so the exchange completes on both sides in one round, once confirmed, no further `rel_init` is sent, so there is no endless ping-pong; whoever receives a `rel_init_ack` marks the exchange as confirmed (`Contact.RelIdentityConfirmedByPeer`/`RelContentConfirmedByPeer`, turned on together) and stops resending. The periodic probe cycle automatically resends an unconfirmed `rel_init` until the contact confirms, no attempt limit. Inviting a contact to a room (or accepting their invite) requires this exchange to already be complete on both sides: a contact whose relationship keys are not yet known produces no hard error, the invite is queued and runs automatically as soon as the exchange completes (bound by the invite's own timeout), instead of proceeding toward a handshake doomed to fail.

**Payload authentication against the transport key, persistent channel ONLY.** Unlike the ephemeral bootstrap of §8.1 (pure TOFU, no shared anchor between two strangers), here both sides already know and trust each other's transport key (§2, exchanged out of band via URI/QR): the `rel_init`/`rel_init_ack` payload therefore carries `Ts`+`Sig` (+ a parallel `SigMLDSA`, never blocking if absent), an Ed25519 signature by the sender over the proposed fields (`IdentityPub`, `ContentPub`, `DevicePub`) with their own durable `IdentityPrivKey`, verified by the recipient against the already-known `Contact.IdentityPub`, BEFORE touching any field or `Contact.Devices` entry:

```
RelBootstrapMsg = "rel_bootstrap:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ identityPub ‖ contentPub ‖ devicePub
Sig      = Ed25519.Sign(myIdentityPrivKey, RelBootstrapMsg)
SigMLDSA = MLDSA65.Sign(myMLDSAKey, RelBootstrapMsg)        // optional, never blocking
```

A `rel_init`/`rel_init_ack` without `Sig`, or with a signature that doesn't verify against `Contact.IdentityPub`, is silently discarded, never applied, never placed in `Pending`/`TrustDanger` (that's reserved for an authenticated proposal that differs from an already-known one, not for one that isn't authenticated at all). `ts` is included in the signed message, not just the payload, same reason as `RelKeyRotationMsg` (§9): it prevents rewriting the timestamp on a captured payload without invalidating the signature. No compatibility exception: without this signature, an application bug, or a payload tampered in transit by an intermediary capable of encrypting toward the same recipient transport key, would be accepted silently on the very first exchange, with no way for the recipient to tell it apart from a genuine proposal.

**Use, inside rooms only.** The per-relationship ContentKey signs chat messages (`RelMsgSigPayload(ciphertext, ts, forMember) = "rel_msg:" ‖ forMember ‖ ":" ‖ ciphertext ‖ ":" ‖ ts`, `SignRelMsg`/`VerifyRelMsg`(+MLDSA)) and file/contact-card transfers (§6) toward a specific recipient, the signature is always also bound to the declared recipient (`forMember`, the base64 of the recipient's root IdentityPub, never a username, which is only a display label), not reusable as a signature addressed to someone else. **No key is ever shared by more than two parties**: a broadcast message in a room with N members carries up to N-1 distinct signatures (one per pairwise relationship present, §5), never a single signature verifiable by everyone, every recipient verifies only their own, with the ContentKey they specifically share with the sender.

**Synchronous verification, no network bootstrap.** Unlike a certification that depended on an external fetch, the sender's per-relationship ContentKey is already in local memory (persistent for a real contact, ephemeral for an introduced stranger, §8.1) at the very moment a message or file offer can arrive, by construction of the protocol: the exchange (`rel_init`/`rel_init_ack` above, or the peer-to-peer bootstrap of §8.1) is always complete before a shared room is ever reachable. A single, synchronous verification attempt is therefore enough, no retry needed.

**Rotation, see §9.**

### 8.1 Members introduced in a group (3+ people), ephemeral peer-to-peer bootstrap

**The problem it solves.** In a room with three or more members, each member handshakes only with the host, never directly with the other members (§3, §4). Two "introduced" members (no prior direct relationship, never directly invited by one another) therefore never have an occasion to exchange relationship keys through the mechanism of §8, that one assumes the two add each other as contacts, which never happened.

**Peer-to-peer bootstrap.** Each of the two generates an **ephemeral** IdentityKey+ContentKey pair, valid only for the current room, and sends its public half to the other over the same targeted delivery channel already used for `sender_key` (`to_user_id`+`payload`, never a broadcast to the whole room), encrypted toward the recipient's ephemeral WebSocket session (`SessionPub`/`MLKEMPub` known from the `init`/`user_joined` relay, per-session values never correlatable across different rooms), the same hybrid X25519+ML-KEM-768 scheme already used for the `senderKey` (§7.3). Symmetric: each receives the other's public pair the same way.

```
RelBootstrapPayload = {IdentityPub, IdentityMLKEMPub, IdentityMLDSAPub,
                        ContentPub, ContentMLKEMPub, ContentMLDSAPub}
wire = HybridECIESEncrypt(recipient_sessionPub, recipient_mlkemPub, RelBootstrapPayload)
```

**Pure TOFU, contained by construction.** No certification against an external anchor: whoever receives the other's public pair trusts it directly, with no proof it really belongs to whoever claims it, a lower trust tier than a real contact, explicitly accepted for this case. The ephemeral relationship (keys included) lives only for the room's duration: on room close it is destroyed without a trace, no backup, no keystore, no survival beyond the session. A member encountered only in one room therefore never leaves behind a "trusted" key usable in a different context.

**Promotion to a real contact (`/grp-promote`).** If two ephemeral members know each other and decide, an explicit human action on BOTH sides, never automatic from the mere arrival of the other's request, to become persistent contacts, the promotion reuses the four relationship keys already exchanged in the ephemeral bootstrap above (no regeneration: they are already mutually authenticated directly, the same trust level as a direct QR exchange) and additionally exchanges the one thing the ephemeral bootstrap never carries: the proposer's transport public key (needed to compute their network address and reach them outside this room).

```
RelPromotePayload = {TransportPub, TransportMLKEMPub, TransportMLDSAPub}
```

**Payload authentication against the EPHEMERAL per-relationship IdentityKey, the only anchor available here.** Unlike `rel_init`/`rel_init_ack` (§8, durable transport key already known out-of-band), the two "introduced" members share no common root IdentityKey, the only thing they share is the ephemeral pair just exchanged by the bootstrap above. `RelPromotePayload` therefore carries `Ts`+`Sig` (+ a parallel `SigMLDSA`, never blocking), an Ed25519 signature by the sender over the proposed fields with their own **ephemeral** per-relationship IdentityKey (`ephemeralRel.myIdentity.Priv`), verified by the recipient with `ephemeralRel.peerIdentity.Pub`, their half, already received and applied from the earlier `rel_bootstrap` (no extra network bootstrap: the anchor key is already in memory from the moment `rel.Established` is true, the same precondition already required to send/apply a `rel_promote`):

```
RelPromoteMsg = "rel_promote:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ transportPub ‖ transportMLKEMPub ‖ transportMLDSAPub
Sig      = Ed25519.Sign(myEphemeralIdentityPrivKey, RelPromoteMsg)
SigMLDSA = MLDSA65.Sign(myEphemeralIdentityMLDSASeed, RelPromoteMsg)        // optional, never blocking
```

A `rel_promote` missing `Sig`, or with a signature that doesn't verify against `ephemeralRel.peerIdentity.Pub`, is silently discarded, never applied. Without this signature, a malicious server, which already knows the recipient's public `session_pub`, since it distributes it itself via `init`/`user_joined`, could encrypt a fabricated `RelPromotePayload` and inject it posing as a legitimate member's `rel_promote`, redirecting the promotion toward a transport address the attacker controls, with neither sender nor recipient any the wiser.

From that point on the relationship stops being ephemeral: the keys (already existing) and the new transport address flow into a normally persisted `Contact`, indistinguishable from a contact born from a direct QR/invite.

---

## 8bis. Hybrid network identity (Ed25519 + ML-DSA-65)

**Concerns the transport key (§2), not the relationship keys.** `Keystore.IdentityKey` (Ed25519) derives the Tor/I2P address, authenticates the knock's mutuality tag and the durable encryption toward a contact (§7.2/§7.4), signs `SignRemoteNuke` (§13.1), with no interoperability constraint with external software. Every operation signed with this key is also signed, in parallel, with an ML-DSA-65 key (FIPS 204, `github.com/cloudflare/circl/sign/mldsa/mldsa65`). The relationship keys (§4.3, §8) have their own independent ML-DSA-65 companions, generated and rotated separately per contact, the same hybrid principle, applied per-relationship instead of only to the transport identity.

**What it covers and what it does not.** This is not harvest-now-decrypt-later (already covered by the hybrid post-quantum scheme of §4.2/§7.3/§7.4), it is **post-Q-day** impersonation/forgery: an attacker with a quantum computer operational at the moment of the attack forges a signature under someone else's identity (e.g. swapping a payment address in a request with a forged signature).

**Key** (`Keystore.MLDSAKey`, `internal/keystore/keystore.go`): a 32-byte seed (`mldsa65.SeedSize`, same size as the Ed25519 seed), generated with `crypto/rand` in `New()`, **not** derived from the BIP-39 seed, the same design choice already made for `MLKEMKey` (§4.2): no compromise vector independent of the keystore file's own, no reason for a separate lifecycle. It always rotates in the same event as `IdentityKey`/`MLKEMKey` (`StartRootRotation`), never independently; a one-shot migration backfills it for pre-existing keystores (`version` 4→5). `mldsa65.NewKeyFromSeed` reconstructs the keypair from the seed (deterministic, as required by FIPS 204) on every access, never persisted in expanded form.

**Parallel signature on `remote_nuke`'s authority** (`SignRemoteNukeMLDSA`, `internal/shared/crypto.go`): reuses exactly the same message already signed in Ed25519 (`RemoteNukeMsg`, unchanged, §13.1), two independent signatures over the same message, not an RFC 9980 composite (not needed: no interoperability with external software is involved here). Carried in the same encrypted protocol payload (`NukeSigMLDSA`, `omitempty`). **Never blocking**, same philosophy as the rest of the project: a missing MLDSA signature (peer not yet migrated) or a failed verification falls back to the existing Ed25519-only check, never an additional rejection. The parallel ML-DSA-65 signatures on relationship keys (cross-certification on rotation, §9; message/file signing, §5/§6/§8) instead use the **per-relationship** ML-DSA-65 companions, not this key.

**URI/QR propagation.** The ML-DSA-65 public key (1952 bytes, packed) travels as a fourth positional segment in the identity URI: `nu://username/ed25519B64/mlkemB64/mldsaB64`. Parsing (`parseNuURI`/`parsePeerURI`) dispatches on the **decoded segment's length**, not a fixed position, the same scheme already used for the ML-KEM segment (§4.2), backward-compatible with shorter URIs. `Contact.MLDSAPub` is learned on the first URI/QR exchange.

**Multi-QR.** With all three PQC segments present (Ed25519 + ML-KEM + ML-DSA) the URI exceeds a single QR frame's capacity (~4300 characters against a practical threshold of ~2950 bytes at error-correction level L), unlike Ed25519+ML-KEM alone (§7.4, ~1700 characters, a single frame is enough). Direct reuse of the chunking mechanism already used for backup/sync (`keystore.ChunkBlob`/`AssembleQRMulti`, `internal/keystore/backup.go`, format-agnostic over raw bytes), with two new helpers (`IsMultiQRChunk`/`QRMultiPartTotal`) letting the reader recognize an NTR3 chunk before the full sequence has been received, same multi-part scanning UI on desktop (`handleQRDecoded`, `tui.go`) and in the Android app in testing.

**Optional per-room ML-DSA-65 signing on chat messages.** Signing every message would cost ~3.3KB per signature (`mldsa65.SignatureSize`), acceptable for occasional operations (rotation, remote_nuke) but not justifiable as a default on every message. `Client.SetPQCSign(bool)`/`PQCSign() bool` (`internal/client/client.go`) is a **mutable** toggle, unlike `ratchetDH` (decided once at construction based on member count, §5.1): the choice to sign is the user's, per-room, never automatic. Turned on via `/sec-pqc-sign on|off` on the TUI (a room-scoped command) or from the room's "⋮" menu entry on Android. When active, `Client.Send` attaches `pqc_sig`/`pqc_ts` external to the ciphertext, the same scheme as `device_sig`/`device_ts` (§13.1): `shared.PQCSigMsg(ciphertext, ts) = "pqc_sig:" ‖ ts ‖ ":" ‖ ciphertext`, `SignPQCSig`/`VerifyPQCSig`. The receiver verifies against `Contact.MLDSAPub` (never against a field inside the message itself, unlike `device_sig`, which is self-verifying) and shows a `[PQC]` tag next to the sender's name on EVERY message, always present: green if active (for one's own message, `pqc_sig` was in the frame at send time; for another's message, `pqc_sig` verifies against `Contact.MLDSAPub`), red otherwise, never a rejection of the message itself. Toggling it also produces a broadcast announcement (`pqcToggleAnnouncePrefix`) to every room member, over the same SenderKey channel used for regular messages.

---

## 9. Relationship key rotation, cross-certification, per contact

**What.** The two relationship keys toward a given contact (per-relationship IdentityKey, §4.3; per-relationship ContentKey, §8) rotate independently but **never at the same time**: rotating one is only started if the other isn't already rotating toward that same contact, the stable key always serves as the continuity anchor for the one that's changing. Commands: `/sec-rotate-rel-identity <contact>`, `/sec-rotate-rel-content <contact>` (start the respective rotation). The signed payload is resent on every probe cycle until the contact confirms, indefinitely: being a pairwise relationship, a rotation that never gets confirmed has no effect on any other contact, so there is no (and no need for a) forced closure.

**Cross-certification, not continuity over time.** Unlike a scheme where the old version of a key would sign its own new version, here the **new** key is certified by the stable **sister** key, the per-relationship ContentKey if the IdentityKey is rotating, and vice versa:

```
msg          = "rel_key_rotate:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ new_pubkey
sig_ed25519  = Ed25519.Sign(stable_sister_priv, msg)
sig_mldsa    = ML-DSA-65.Sign(stable_sister_priv_mldsa, msg)   // optional, never blocking
```
(`RelKeyRotationMsg`/`SignRelKeyRotation`/`VerifyRelKeyRotation`(+MLDSA), `internal/shared/crypto.go`), `ts` is signed together with the rest for the same anti-replay reason as `RootRotationMsg` (§9bis) and `RelBootstrapMsg` (§8): rewriting the timestamp on a captured payload would invalidate the signature.

**Why this scheme and not a signature from the key's own old version.** A per-relationship rotation always concerns exactly ONE of the two keys at a time (never both together toward the same contact), the sister key is therefore always available, intact, as the continuity anchor. No "out-of-band" channel is ever needed for a voluntary rotation: the out-of-band step (`/sec-verify`, safety number comparison) remains reserved only for the distinct, already-existing case, total loss of both keys, no old one available.

**Wire.** `KnockPayload.RelRotate *RelRotatePayload{NewPub, NewMLKEMPub, NewMLDSAPub, Sig, SigMLDSA}`, knock `rel_identity_rotate`/`rel_identity_rotate_ack` or `rel_content_rotate`/`rel_content_rotate_ack` (never both in the same knock). The ack reuses the same struct but with only `NewPub` set (echo, no signature), whoever started the rotation compares the echo against the key currently being rotated before accepting it as confirmation, so a late ack referring to an already-closed rotation is never applied to a subsequent one.

**Old key retained** (`Contact.OldRelIdentityPriv`/`OldRelContentPriv`, encrypted at rest like the rest of the keystore) until the contact confirms (`IdentityKeyPending`/`ContentKeyPending` clear).

**Note well:** rotating a relationship key does not touch the BIP-39 seed and does not invalidate any backup, it is the transport key (§2), not a relationship key, that determines the 24 words.

### 9.1 Self-signed revocation certificates, pre-generated, never on demand

**What.** Besides rotation (above), each per-relationship key also carries its own revocation certificate, the same principle as a PGP revocation certificate: the private key signs its own public key, once, at the moment the key is generated (bootstrap, §8, or rotation, above) rather than when revocation is actually needed:

```
msg = "rel_revoke:" ‖ username ‖ ":" ‖ pub
sig_ed25519 = Ed25519.Sign(priv, msg)                  // priv is the key's OWN current private half
sig_mldsa   = ML-DSA-65.Sign(priv_mldsa, msg)           // optional, never blocking
```
(`RelRevokeMsg`/`SignRelRevoke`/`VerifyRelRevoke`(+MLDSA), `internal/shared/relrevoke.go`)

**Why pre-generated, not generated at the moment of need.** A revocation is most useful precisely when the private key is about to become unrecoverable (a self-destruct trigger, §11.1/§13), generating it only then would require the key to still be usable at that instant, which is exactly the scenario a self-destruct trigger is racing against. `ensureRelRevocations` (`internal/keystore/keystore.go`) instead backfills a certificate for every device key that doesn't have one yet on every `Save`, by the time a trigger fires, the certificate has already existed for as long as the key itself, stored alongside it (`DeviceRelation.RevokeIdentitySig`/`RevokeContentSig` + MLDSA companions, encrypted at rest like the rest of the keystore, §11).

**No timestamp, unlike rotation (above) or root rotation (§9bis).** A replayed revocation is never a trust escalation, at most it forces a reconfirmation (`TrustDanger`, §10), never downgrades an already-revoked state back to trusted, and never grants anything an attacker didn't already have. The anti-replay freshness check that protects `RelKeyRotationMsg`/`RootRotationMsg` (and the HNDL-adjacent `remote_nuke`, §13.1) has nothing to protect here.

**Verification, and the sibling backstop.** `VerifyRelRevoke` checks the certificate against the relationship key *already known* to the verifier (`PeerRelIdentityPub`/`PeerRelContentPub`), if that key has since rotated, the certificate simply fails to verify and is inert, never dangerous. `Contact.SiblingRevocations` (`keystore.go`) lets a device's sibling (same identity file) resend that device's own pre-generated certificate on its behalf after a self-destruct trigger, the recipient verifies the same signature regardless of which device physically delivered it, never the identity of the sender itself.

**Wire.** `KnockPayload.RelRevoke *RelRevokePayload{DevicePub, IdentitySig, IdentitySigMLDSA, ContentSig, ContentSigMLDSA}`, knock `rel_revoke` (announcement) / `rel_revoke_ack` (confirmation, echo of `DevicePub` only, no signature). At least one of `IdentitySig`/`ContentSig` is always present in a valid announcement, never both absent. Delivery mechanism (the "salvation pod", fan-out, sibling retry over time): §13.2.

---

## 9bis. Root IdentityKey rotation with continuity

**What.** Unlike the per-relationship rotation above, here it's the transport key itself (§2) that rotates, the one the network address (`.onion`/`.b32.i2p`) is derived from. Command: `/sec-rotate-key ROTATE` (explicit confirmation, a rare operation). Continuity is anchored to the per-contact `RelIdentityKey` (§4.3), stable and independent per relationship, never to the old root itself, which may be compromised or already eliminated.

```
msg          = "root_rotate:" ‖ username ‖ ":" ‖ ts ‖ ":" ‖ new_root_pub
sig_ed25519  = Ed25519.Sign(RelIdentityKey_priv_toward_the_contact, msg)
sig_mldsa    = ML-DSA-65.Sign(RelIdentityKey_priv_mldsa, msg)   // optional, never blocking
```
(`RootRotationMsg`/`SignRootRotation`/`VerifyRootRotation`(+MLDSA), `internal/shared/crypto.go`)

**A new hidden service in parallel.** `Keystore.StartRootRotation()` generates the new `IdentityKey`/`MLKEMKey`/`MLDSAKey` triple, applies it IMMEDIATELY as current, and stashes the old one in a temporary vault (`OldIdentityKey`/`OldMLKEMKey`/`OldMLDSAKey`). Right after, a SECOND hidden service is published, sharing the same `RoomRegistry`/knock channel as the first, the old one stays active, no teardown: online contacts migrate as soon as they receive the announcement, offline ones when they come back.

**Mutuality tag with the OLD key.** The `root_rotate` knock stays tagged (`KnockDHTag`, §7.2) with the PREVIOUS root (retained in the vault) until the recipient has applied the announcement, the server-side mutuality filter is never modified: the recipient still recognizes that key, because for them it's still the current one. Only once the announcement is applied (`applyRootRotate`) does the contact switch to tagging/declaring with the new one.

**Mutual lock with relationship rotations.** A relationship rotation (§9) still in progress toward a device suspends the `root_rotate` announcement toward it, never two concurrent transitions on the same relationship; conversely, starting a relationship rotation while a root rotation is pending toward that contact is explicitly refused. No forced closure in either direction: the announcement stays queued (`Keystore.RootRotationPendingContacts`) and is resent on every probe cycle until the contact confirms with `root_rotate_ack`.

**Own-device-to-own-device channel (`device_sync`).** One's own sibling devices share the same root IdentityKey bit-for-bit (§2, D1/additional-device derivation), no announcement is needed, the private material needs to be transferred in full. The channel doesn't go through a contact: it addresses the target device's derived network address directly (`Keystore.NetworkIdentityPrivKeyFor(deviceID)`), trying both the one from the new root and the one from the old, until the sibling adopts, its hidden service stays published at the address derived from the old root. No extra ECIES encryption on the transferred material beyond the knock's own: both sides literally hold the same private key, the mutuality of the tag is already the proof of authenticity. The same channel also carries an explicit address-book sync (`/sec-device-sync <device>`), reusing `indoor.SyncPayload` (§12) over this transport instead of just LAN multicast.

**Note well:** the 24 BIP-39 words encode the current root `IdentityKey` (§2, `Mnemonic()`), so a root rotation replaces them: after it, `/sec-backup` shows new words. Words and backups taken before the rotation restore the previous key and its address.

---

## 10. Safety Numbers, manual identity verification

**What.** A 40-character code calculated from the two transport keys (§2) involved, for an explicit out-of-band verification.

```
seed = SHA-256(min(pubA,pubB) ‖ max(pubA,pubB))      // ordered: both sides compute the same value
code = HKDF-SHA256(seed, info="neutrino-safety-b62-v1") expanded to 40 bytes
       → 40 base62 characters (0-9, A-Z, a-z), 5 groups of 8
```
(`SafetyCode`, `crypto.go`)

**Why no automatic verification.** Any confirmation computed and exchanged entirely inside the very connection it would verify proves nothing useful: an attacker who fully controls that connection (e.g., after an initially falsified QR, §1) would answer exactly as the real contact would, because they still possess the keys involved in the derivation from that point onward. It would only prove "I am talking to whoever knows this connection's code," never "this is really the person I think it is", a verification internal to the app can never close this gap, whatever form it takes. This is why the only verification Neutrino offers is the explicit one described below, over an independent channel.

**Explicit verification** (`/sec-verify`, or `/sec-safety`/`/cnt-info` for display only): the full code must be compared *in person, by phone, or by video call*, a channel independent of the app. It is the only real defense against the TOFU limit of the initial exchange (§1) (see `technical-manual.md` for the full attack scenario). To make this comparison practical even with contacts introduced by third parties (who do not already know each other in person), `/grp-contact-send` requires a mandatory out-of-band contact detail (phone, email, Telegram...) written by the introducer, never persisted, shown only on receipt (see `technical-manual.md`, § "Contact card, a file").

**Relationship-key conflict (`TrustDanger`).** If a contact announces, via a new `rel_init`/`rel_init_ack`, a relationship key (identity or content, even just one of the two) that differs from an already-known value, the new keys stay pending (`PendingPeerRelIdentityPub`/`PendingPeerRelContentPub`) instead of silently replacing the current ones. `/sec-verify` on a contact in this state computes **two** independent `SafetyCode`s, same algorithm as above, same `SafetyCode` function, one on the pair (own relationship IdentityKey, `PendingPeerRelIdentityPub`), one on the pair (own relationship ContentKey, `PendingPeerRelContentPub`): never on the `Peer*` keys already in the address book, which in this scenario haven't changed and aren't part of the conflict. Explicit confirmation (out of band, same principle as the ordinary safety number) promotes the pending keys to current; a refusal leaves them pending, the contact stays in `TrustDanger`.

---

## 11. Encryption at rest of the keystore

**What.** The `keystore` file (`~/.config/neutrino/keystore`), identity, contacts, groups, is encrypted with **Argon2id + AES-256-GCM**.

```
salt  = 16 random bytes (new on every Save)
nonce = 12 random bytes (new on every Save)
key   = Argon2id(password, salt, time=3, memory=64 MiB, parallelism=4, keyLen=32)
file  = salt ‖ nonce ‖ AES-256-GCM(key, nonce, json(identity))
```
(`internal/keystore/keystore.go` params, `Save`, `Load`)

**Why Argon2id.** Memory-hard: an attacker who obtains the file (stolen disk, exposed backup) and attempts offline brute-force cannot effectively parallelize on GPU/ASIC the way they could with a fast hash (SHA-256, low-cost bcrypt), every attempt requires 64 MiB of RAM, which, multiplied by thousands of parallel attempts, becomes prohibitive. With Argon2id, the factor that really matters against an offline attack is the **entropy of the password itself**, not additional cryptographic tricks, hence the choice to propose, by default, a 7-word BIP-39 passphrase (~77 bits, see `GeneratePassphrase`, `internal/shared/password.go`) instead of leaving only a free-text password field.

**Atomic write:** temporary file in the same directory, `fsync`, then `rename`, no window in which the file at the final path is partially written or corrupted by a crash mid-save.

**Not a post-quantum scheme, deliberately, not an oversight.** Every layer here (Argon2id, AES-256-GCM) is classical, unlike the hybrid ML-KEM-768/ML-DSA-65 used for the network identity and relationship keys (§4.2/§7.3/§7.4/§8bis/§9). The two protect against different threats: the network-facing keys guard against harvest-now-decrypt-later (an adversary records today's traffic, decrypts it once a quantum computer breaks the classical math later) and against post-Q-day forgery of a signature, both inherent to exposing an **asymmetric** operation over a network an observer can record. The keystore's at-rest encryption faces neither: it is **symmetric and password-derived**, with no asymmetric trapdoor for Shor's algorithm to target, and AES-256 itself keeps a 128-bit effective security margin against Grover's algorithm, still computationally infeasible. The only lever that matters against an attacker who has obtained the file is the password's own entropy (see above), which a quantum computer does nothing to weaken beyond that same Grover-halved margin. The N-slot wrapping of each identity's own key (`technical-manual.md`, "Multiple identities") reuses this exact same classical pair (`deriveSlotWrapKey`+AES-256-GCM, `internal/keystore/slots.go`) for the same reason.

**Note on "password change" vs "key rotation":** these are two independent secrets by design, never touching the Ed25519 key or any already-exported backup (§12), but the mechanics differ by platform. Desktop/Termux (`/sec-passwd`, N-slot format, see `technical-manual.md`, "Multiple identities"): only that identity's own key-wrap around its symmetric key is redone under the new password; the encrypted content itself is never re-encrypted. Android (not migrated to that format, single shared password): changing it re-encrypts the whole payload with a new salt/nonce/Argon2id key.

### 11.1 Decoy identity / automatic NUKE password (duress)

**Desktop/Termux, a decoy identity, not a separate verifier.** No plaintext verifier exists for this platform: the decoy is a full identity slot inside the same N-slot container as the real one or ones (§ `technical-manual.md`, "Multiple identities"), opened by the ordinary `password_file ‖ password_identity` combination like any other slot, there is nothing to check "before decryption" because there is no separate check: whichever slot the typed combination happens to open **is** the result, structurally indistinguishable from opening a real identity. Each real identity's slot additionally carries `DuressAccess` (`internal/keystore/duress_access.go`): the decoy's own symmetric content key (`K_i_duress`), sealed with plain AES-256-GCM directly under that real identity's own key, no password, no KDF, since whoever already holds a real identity's key is, by definition, authorized to read this ("the decoy with the hammer already cocked"). `/sec-duress` uses this field to locate and re-wrap the decoy's own slot under a new password, without the session ever needing to know the decoy's *old* one. The decoy's own copy of this same field holds indistinguishable random bytes of the same size, opening it would require a REAL identity's key, which the decoy side never has, by construction: the decoy never has a further decoy beneath it to swap into.

**The swap into the decoy identity mid-session.** Every trigger that reaches an already-unlocked real session (`/nukex`, the automatic `time` trigger, `remote_nuke` on the target side, and the duress PIN recognized at the interface lock) runs the same sequence, never deleting the keystore file or ending the process: `UnlockedSlot.OverwriteAllContacts()` (`internal/keystore/slot_overwrite.go`) empties every one of the real identity's contacts in place, the exact same treatment as deleting one contact, batched, then `UnlockedSlot.PromoteDuress()` (`internal/keystore/slot_promote_duress.go`) reuses `K_i_duress` from `DuressAccess` (already in RAM, no password) to return a session bundle for the decoy slot, which the caller adopts in place of the real one. The process keeps running as the decoy identity, on the same already-bootstrapped Tor/I2P circuits, no re-authentication, no restart, and the real identity's own hidden service is left running abandoned rather than torn down (see `technical-manual.md`, "remote_nuke, remote self-destruction" for the anti-forensic reasoning). The decoy session that results manages its own contacts afterward with `AddPlainContacts`/`EmptyPlainContact` (same file as `AddMirroredContacts`/`EmptyMirroredContact`), a decoy has no decoy of its own to mirror into, so it never calls `openDuressContent()` at all. After the swap, the triggering real identity's own slot is overwritten with random bytes (`ObliterateSlot`) and the container written back, so a cold restart can no longer open it with the real password; other real identities in the same file are not touched by these triggers. Typing the decoy password directly at login is handled separately (`openKeystoreSession`, `cmd/main.go`): the moment the opened slot is the decoy, every other slot in the container is overwritten with random bytes (`ObliterateOtherSlots`) and written back before the session starts.

**Android, a separate plaintext verifier (original mechanism, not migrated).**

**What.** A second Argon2id verifier (same parameters as above: time=3, memory=64 MiB, parallelism=4), a 32-byte `Salt`+`Hash`, written **in the clear** in a dedicated file header (magic `NTRK`), outside the encrypted payload.

**Where:** `internal/keystore/duress.go`.

**Why outside the encrypted payload.** The verifier must be checkable **before** (and without) decrypting anything, to distinguish a wrong password from a self-destruct password without ever revealing which one was typed, if it lived inside the encrypted payload, checking it would already require decrypting with one of the two passwords, which would leak which branch was taken before the check even finished. The comparison (`subtle.ConstantTimeCompare`) is constant-time for the same reason: a variable-time comparison would leak via timing how many characters of the typed password match the verifier. This is an intrinsic limit, not specific to this implementation: an attacker who obtains the file and suspects the mechanism exists can still try a known password and observe whether the unlock is "silent" (no contact warned, no visible trace), no duress scheme eliminates this residual risk.

---

## 12. Backup, restore, sync, keys derived from the BIP-39 seed

**What.** Three export formats, all encrypted with keys **derived from the identity seed** (the 24 words), **never** from the keystore password:

| Format | Magic | Content | HKDF info |
|---|---|---|---|
| Full backup (`.bin`) | `NTRINO01` | identity + contacts + groups | `"neutrino-backup-v1"` |
| Single QR export | `NTRINO02` | same as above, gzip | `"neutrino-backup-v1"` |
| Address book sync | `NTRINO03` | contacts only | `"neutrino-sync-v1"` |

```
seed = ks.IdentityKey[:32]                          // same seed as the 24 BIP-39 words
key  = HKDF-SHA256(seed, info=<see table>)
file = magic ‖ nonce[12] ‖ AES-256-GCM(key, nonce, gzip(json(data)))
```
(`internal/keystore/backup.go` `ExportBackupFile`, `ImportFromBackupFile`)

**Why separate HKDF domains** (`"neutrino-backup-v1"` vs `"neutrino-sync-v1"`) even with the same source seed: a sync file (contacts only) and a full backup file (identity too) are encrypted with different keys despite deriving from the same seed, a compromise of one derived key does not help decrypt the other.

**Why from the seed rather than the keystore password:** it allows restoring identity on a device that never knew the original password (only the *new* password to set at restore time is needed, see `promptNewKeystorePassword`), and, symmetrically, it allows changing the keystore password as many times as desired without invalidating backups already made. The two secrets (keystore password, seed/24 words) protect different things and do not affect each other.

### 12.1 Optical transfer via animated QR, same encrypted payload, different channel

A full backup and address book sync can also be transmitted as a stream of animated QR codes (fountain coding, `internal/qroptical`, see `technical-manual.md` for the mechanism) instead of as a file or a static QR. Fountain coding encrypts and decrypts nothing: it carries the exact same blob produced by `encryptCompressed`/`ExportSync`, magic, nonce, AES-256-GCM ciphertext included, bit-for-bit identical to what would end up in a `.bin` file or a static QR. The key remains the one derived from the BIP-39 seed (table above); the recipient decrypts it exactly as it would a file, with no additional password or new cryptographic material needed.

The case of generic file transfer via `neutrino qr send`/`neutrino qr receive` is different (it has no tie to a specific identity): there, the payload is encrypted with AES-256-GCM and an Argon2id-derived key from a password chosen by the sender and shared out of band, necessary because the optical channel is by definition visible to anyone watching the screen during transmission, and in that case there's no shared BIP-39 seed to derive a key from.

**Practical consequence:** rotating the root identity key (§9bis) generates a new seed → the 24 words change → every previous backup/QR export remains valid only for the **old** identity, not the current one. A new backup must be made after every rotation.

---

## 13. Self-destruction (`nuke`), in-place overwrite, never file deletion

**What runs.** No trigger, `/nukex`, the automatic `time` trigger, `remote_nuke` on the target side, or the duress PIN at the interface lock, ever deletes the keystore file or ends the process: Android cannot delete its own installed app, and the design generalizes that constraint to every platform. All four instead run the overwrite-and-swap sequence described in §11.1: every real contact is overwritten in place (`OverwriteAllContacts`), then the session is promoted to the decoy identity (`PromoteDuress`), on the same already-open network circuits. `secureDelete`/`secureWipeDirFiles` (`cmd/main.go`, 10-pass random overwrite + `fsync` + `os.Remove`, decides WHICH files via `os.ReadDir` on the keystore's directory) are wired to no self-destruct trigger: they are used only by the explicit, confirmed `/sec-clear-all` command, which physically wipes the configuration directory.

**Why multiple passes and not just `rm`,** for `/sec-clear-all`: a single `os.Remove` leaves the data recoverable until the physical block is overwritten by something else, multiple overwrites drastically reduce this window on traditional magnetic hard disks. **Known and documented limit:** on SSDs and other flash memories, the controller hardware's *wear leveling* can preserve "old" physical blocks even after the logical overwrite of the file, the guarantee of irreversible deletion is weaker on SSD than on HDD, an intrinsic limit of flash technology, not solvable at the application level.

**Revoking the device's relationship keys toward its contacts** is a separate step from the overwrite above, delivered by the "salvation pod", see §13.2.

### 13.1 remote_nuke, remote self-destruction

Extends the self-destruction above to a device outside physical control: whoever possesses, in their own keystore, the Ed25519 private key of any identity also duplicated on the target device (the AUTHORITY, no separate role, possession is the authorization) can trigger its remote self-destruction. On a verified command, the target runs the exact same overwrite-and-swap sequence as `/nukex`, not a deletion of its own. Full implementation details (fan-out, persistent queues, indoor sync) are in `technical-manual.md` § "remote_nuke, remote self-destruction"; only the cryptographic scheme is covered here.

**Device-level signature (not identity-level).** Every `Keystore` generates, once per FILE (not per identity, shared by every sibling identity), an Ed25519 key pair independent of `IdentityKey`: `DeviceID` (16 random bytes, identifier only) and `DevicePriv`/`DevicePub`. It co-signs every outgoing chat message (`sealedMsg.DP` carries the pubkey INSIDE the ciphertext, never in the clear, avoids a stable identifier observable by the relay):
```
DeviceSigMsg(ciphertext, ts) = "device_sig:" ‖ ts ‖ ":" ‖ ciphertext
device_sig = Sign_Ed25519(DevicePriv, DeviceSigMsg(ciphertext, ts))
```
Verified against the just-decrypted `DP` in the same message, no bootstrap round trip. Never blocking: only an informational tag + TOFU on `Contact.KnownDevicePub`.

**`remote_nuke` command, signed with an IDENTITY, not the device:**
```
RemoteNukeMsg(targetDeviceID, ts) = "remote_nuke:" ‖ targetDeviceID ‖ ":" ‖ ts
NukeSig = Sign_Ed25519(authorityPriv, RemoteNukeMsg(targetDeviceID, ts))
```
Verified by the target against **any** key in `Keystore.AllAuthorityPubKeys()` (every identity in its own file, current and old during an ongoing rotation), no separate PKI, no authorization list: the trust model is "whoever possesses the private key of an identity present on this file can wipe it", identical in spirit to possessing the keystore password. Anti-replay window `TsFresh`/`TsFreshnessWindow = ±5 minutes` (`internal/shared/crypto.go`, a generic timestamp-freshness check, not nuke-specific) on the timestamp, checked by the recipient.

**`remote_nuke_ack` ack, signed with the DEVICE, not an identity:**
```
RemoteNukeAckMsg(targetDeviceID, ts) = "remote_nuke_ack:" ‖ targetDeviceID ‖ ":" ‖ ts
ack_sig = Sign_Ed25519(DevicePriv, RemoteNukeAckMsg(targetDeviceID, ts))
```
A different key from the command by construction: it's the DEVICE confirming "I'm about to overwrite my contacts and swap to the decoy identity", not the identity it was running as, consistent with `DeviceID` being file-level, not per-identity.

**`danger_broadcast`/`danger_end`, no dedicated signature, authenticated by the knock envelope.** Both are `KnockPayload`s encrypted with the recipient's public key (§7.3/§7.4, same scheme as every other knock), `FromIdentityPub` is already verified against the recipient's address book (`handleIncomingDangerMsg`), no extra signature needed beyond the implicit one of being able to decrypt/being a known contact. `danger_end` is signed per-identity when sent by the target toward each sibling identity's own contacts (`AllIdentitiesContacts`, `cmd/main.go`, the only place holding every sibling's private key): a contact of I2 sees `FromIdentityPub` = I2's key, not the identity the device happened to be connected as at that moment.

**"Indoor" synchronization, no ECDH, the session derives from the already-shared key.** Two instances with the SAME duplicated identity (`neutrino restore`) authenticate each other with a three-step challenge/response (`internal/indoor`, details in `technical-manual.md`):
```
A → B: nonce_A
B → A: nonce_B, Sign_Ed25519(identity_priv, nonce_A ‖ nonce_B)
A → B: Sign_Ed25519(identity_priv, nonce_B ‖ nonce_A)
session_key = HKDF-SHA256(identity_priv, salt = nonce_A ‖ nonce_B, info = "neutrino-indoor-v1")
```
Since both sides literally hold the same private key (not two different keys in dialogue), no Diffie-Hellman exchange is needed: the session is independently derivable on both sides after proof of mutual possession. Payload encrypted with AES-256-GCM (`session_key`, dedicated AAD `"neutrino-indoor-payload-v1"`), the same primitive used everywhere in the project. UDP multicast discovery announces only `SHA-256(IdentityPub)[:16]`, never the identity in the clear (anyone on the same local network can see the announcement).

### 13.2 Salvation pod, relationship-key revocation to contacts, never a private key in transit

The overwrite-and-swap sequence (§11.1/§13) is local and instantaneous but says nothing to the device's own contacts: without a separate step, each contact keeps trusting the now-abandoned device's relationship keys indefinitely. A self-exec'd child process (the "pod", `__pod` hidden entry point) delivers the already-existing `rel_revoke` certificates (`DeviceRelation.RevokeIdentitySig`/`RevokeContentSig`, §9.1) to every contact, fire-and-forget, while the parent process continues running as the decoy identity.

**Never a private key crosses into the pod.** The parent builds a snapshot (`PodSnapshot`/`PodRevokeTarget`, `internal/keystore/pod_snapshot.go`) containing, per contact: the pre-computed `rel_revoke` certificates (already signed by the parent, which still held the real private keys at that instant, the same ones `applyRelRevoke`/`AckSiblingRevocation` on the receiving side already verify, §9.1), the contact's resolved address, and the DH mutuality tag (`KnockDHTag`, §7.2) the recipient's server checks before decryption, all data, no key material. The snapshot crosses the process boundary over stdin/a pipe, never argv or an environment variable (both readable by other processes on the same machine via `/proc`). The pod then dials each contact (SOCKS5 over Tor or a dedicated SAM session over I2P, `internal/transport.DialerSAM`, inherited from the parent's already-open circuits, or bootstrapped cold on its own, `podColdBootTimeout`, if the parent's own login never had a live network, e.g. a direct decoy-password login) and sends each `rel_revoke`, bounded retries within `podTimeout` (~20s), then exits, no ack is ever awaited: an authenticated ack would require the real private key, which by this point the parent has already overwritten past recovery and the pod never possessed to begin with.

**Reliability beyond the pod's one-shot delivery window** falls back to the pre-existing sibling-retry mechanism (`SiblingRevocations`/`isNukedFn`, checked on every periodic contact probe, §9.1): a contact unreachable during the pod's ~20s window is not lost, only delayed until it's next seen online, same guarantee already relied on for an ordinary relationship-key rotation. **Siblings of the same identity file** are notified by an entirely different, already-existing channel instead (`device_sync`/`MarkDeviceNuked`, §9bis's own propagation mechanism), the pod's scope is contacts only, never other devices sharing the same account.

---

## 14. Rate limiting (DoS mitigation)

**What.** `RateLimiter` (`internal/server/ratelimit.go`), a sliding window per IP, with loopback addresses always allowed (necessary because in Tor mode the local daemon connects via loopback; rate-limiting `127.0.0.1` would indiscriminately block all Tor clients).

Not cryptography in the strict sense, but part of the overall threat model: it mitigates repeated attempts to guess `room_proof` (§4.1) or to overload the handshake with repeated connections from the same address.

**Per-contact delivery queue overload** (§5bis, `technical-manual.md`) is the analogous mitigation on the already-established broadcast side: a contact that never confirms (isolated or malicious) accumulates up to 256 messages in its own server-side queue before a kick, never a ban, never propagating an error to the other members, just a per-relationship memory bound.

---

## 15. Summary table, active HKDF/HMAC domains

Useful for verifying that two different derivations never share the same `info`/context (domain separation):

| Info / context | Function | Use |
|---|---|---|
| `"room_<period>"` | `DeriveContactRoomKey` | room_proof key, rotates every 12h |
| `"neutrino-session-x25519-mlkem768-v1"` | `DeriveSessionKey` | handshake session_key (hybrid X25519+ML-KEM-768, §4.2) |
| `"neutrino-ecies:"+ephPub+destPub` | `eciesChannelKey` | point-to-point ECIES channel (knock toward a recipient with no known ML-KEM key) |
| `"neutrino-ecies-x25519-mlkem768-v1:"+ephPub+destPub` | `hybridECIESChannelKey` | hybrid point-to-point ECIES channel (`senderKey` delivery §7.3, hybrid knocks §7.4) |
| `"neutrino-chain-v1"` | `InitChainKey` | Sender Key ratchet root (broadcast) |
| `"neutrino-key-id-v1"` (HMAC, not HKDF) | `DeriveKeyID` | public identifier of a senderKey |
| `"neutrino-knock-tag"` (HMAC, not HKDF) | `KnockDHTag` | pre-decryption mutuality tag for a knock (§7.2) |
| `"neutrino-safety-b62-v1"` | `SafetyCode` | safety number code |
| `"neutrino-backup-v1"` | `ExportBackupFile`/`ImportFromBackupFile` | full identity backup |
| `"neutrino-sync-v1"` | `ExportSync`/sync import | address book sync |
| `"neutrino-indoor-v1"` | `indoor.DeriveSessionKey` | "indoor" sync session_key (§13.1, no ECDH, identity private key already shared) |
| `"neutrino-device-onion-v1"` | `Keystore.NetworkIdentityPrivKey` | Ed25519 key for an additional device's network address (IKM = IdentityKey seed, salt = `DeviceID`, see `technical-manual.md`, § "Relationship keys"/`AddHiddenService`) |

Every derivation listed here has at least one real caller in production.

The room identifier itself (`groupID`, generated client-side at invite time, `shared.RandomBytes(4)` hex-encoded, `internal/client/tui/tui.go`) does not appear in this table because it isn't derived from any key material at all, 4 random bytes, not a hash of anything.

---

## 16. Cryptographic primitives, summary by library

| Primitive | Library | Use |
|---|---|---|
| Ed25519 (signature) | `crypto/ed25519` (stdlib) | transport key, relationship keys (handshake, rotation certification, message/file signing) |
| X25519 (ECDH) | `crypto/ecdh` (stdlib) | handshake, ECIES |
| AES-256-GCM | `crypto/aes`+`crypto/cipher` (stdlib) | all authenticated symmetric encryption |
| HKDF-SHA256 | `golang.org/x/crypto/hkdf` | every key derivation from a secret |
| HMAC-SHA256 | `crypto/hmac` (stdlib) | room_proof, key_id, symmetric ratchet |
| SHA-256 | `crypto/sha256` (stdlib) | safety code |
| SHA3-256 | `golang.org/x/crypto/sha3` | `.onion` v3 address checksum |
| Edwards25519 | `filippo.io/edwards25519` | Ed25519↔X25519 birational map for the I2P destination's encryption key |
| Argon2id | `golang.org/x/crypto/argon2` | keystore encryption at rest |
| BIP-39 | `github.com/tyler-smith/go-bip39` | identity seed ↔ 24 words, 7-word passphrase |
| LZMA2/XZ | `github.com/ulikunitz/xz` | strong pre-encryption pack for files/contact cards (§6.3) |
| ML-KEM-768 (KEM) | `crypto/mlkem` (stdlib) | post-quantum hybrid handshake (§4.2), hybrid encryption for knocks/sender_key/files (§7.3/§7.4) |
| ML-DSA-65 (signature) | `github.com/cloudflare/circl/sign/mldsa/mldsa65` | hybrid post-quantum parallel signature, transport key (§8bis) and relationship keys |

**Nonce always random, never a counter.** Every AES-256-GCM encryption in the project uses a randomly generated 96-bit nonce, never a persistent counter, many of the keys involved are ephemeral or rotated frequently, with no shared, synchronized counter state across processes/devices to hang uniqueness on; at 96 random bits, collision probability stays negligible for realistic message volumes per key. AAD is used only where an external piece of data needs to be explicitly bound to the ciphertext (the sequence index `idx` in the SenderKey ratchet, §5), elsewhere the context is already implicitly bound by the protocol's structure (e.g. the ephemeral ECIES key in the HKDF info, §7).

---

## Cross-references

- TOFU limit of the initial exchange, full attack scenario: `technical-manual.md`, "Explicit contact verification"
- Practical behavior of backup/rotation/password: `user-manual.md`, "The 24 BIP-39 words"
- Wire format of application WebSocket frames: `technical-manual.md`, "WebSocket Frames"
- Full implementation of the per-member `RoomRegistry` (struct, signatures, the 4 client points that generate/distribute the secrets): `technical-manual.md`, "`RoomRegistry`, per-member authentication"
