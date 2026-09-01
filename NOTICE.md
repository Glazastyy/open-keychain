# Notices

## This is a modified version

Glazastov Keychain is a fork of [OpenKeychain](https://github.com/open-keychain/open-keychain),
modified by André Glazastov <andre@glazastov.com>. It is not the OpenKeychain
project, is not endorsed by it, and should not be reported to it.

Changes made in this fork, most recent first:

- Renamed to Glazastov Keychain; application ID changed to `com.glazastov.keychain`,
  with the account type and content provider authority moved to match.
- A key's passphrase can optionally be kept encrypted under an Android Keystore
  key and unlocked with a fingerprint or the device screen lock.
- Fixed reading AEAD encrypted messages (SEIPD v2 and the v5 style AEAD packet).
- Updated the OpenPGP stack to Bouncy Castle 1.85 and the Android build to
  AGP 8.13 / SDK 36 / SQLDelight 2, replacing dependencies orphaned by the
  JCenter shutdown.

## Licensing

**The application as a whole is licensed under the GNU General Public License,
version 3 or later** — see [`LICENSE`](LICENSE). This is inherited from
OpenKeychain and cannot be changed by this fork: the copyright in the bulk of
the source belongs to Schürmann & Breitmoser GbR and the OpenKeychain
contributors, and only they can relicense it.

New files written for this fork are additionally offered by their author under
the MIT License — see [`LICENSE.MIT`](LICENSE.MIT). They carry an
`SPDX-License-Identifier: MIT` header. MIT is GPL-compatible, so this changes
nothing about how the combined application may be distributed; it only means
those individual files may also be reused on their own under MIT terms.

Files taken from OpenKeychain keep their original copyright headers, as the
GPL requires and as accuracy requires. Where such a file was modified here, the
modification is recorded in the git history rather than by rewriting the header.

### Third-party components

| Component | License |
| --- | --- |
| Bouncy Castle (`extern/bouncycastle-pg`, `bcprov`, `bcutil`) | MIT |
| nordpol (`extern/nordpol`) | MIT |
| html-textview (`extern/html-textview`) | Apache-2.0 |
| openpgp-api-lib, sshauthentication-api | Apache-2.0 |
| AndroidX, Material Components, flexbox | Apache-2.0 |
| OkHttp, ZXing, mime4j, Timber, AutoValue, SQLDelight | Apache-2.0 |

### Unresolved

The icon sets under `graphics/drawables/originals/` do not state their license
in this repository. `modernpgp-icons` carries no license file, and the Material
Design Icons entries record only the icon author. This should be resolved, or
the artwork replaced, before publishing under a new brand. See
[`docs/BRANDING.md`](docs/BRANDING.md).
