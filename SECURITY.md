# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately, never in a public issue:

1. **Preferred:** GitHub's private vulnerability reporting — the **Report a vulnerability** button in this repository's Security tab.
2. **Alternative:** email `neutrino-contact.unaligned609@simplelogin.com`, encrypted with the project's OpenPGP key ([neutrino-key.asc](neutrino-key.asc), fingerprint `D5FB B139 9E94 EC33 4D25  A0D5 6BE2 C8AB D770 1EB4` — check it against [keys.openpgp.org](https://keys.openpgp.org/search?q=D5FBB1399E94EC334D25A0D56BE2C8ABD7701EB4)).

Include the affected version (`/info-app` or the release tag), the platform, and the steps or code needed to reproduce the issue.

Reports are read and answered as soon as possible, but at this stage of the project no response time is guaranteed.

## Supported versions

At this stage of the project, only the latest release is supported. Fixes are not backported.

## Scope

In scope: everything in this repository — the protocol, the cryptography described in the [Cryptography Manual](docs/cryptography-manual.md), the keystore, the self-destruct paths, the Linux binaries and the build from source.

Out of scope: the Android app and the macOS builds, which are still in testing and not distributed; vulnerabilities in Tor, I2P or other upstream projects, which should be reported to them directly.

## Disclosure

Reports are handled through coordinated disclosure: the fix is published first, then the advisory. Reporters are credited by name or pseudonym, if they wish. There is no bug bounty.
