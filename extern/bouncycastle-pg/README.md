# bouncycastle-pg (vendored)

Source copy of Bouncy Castle's OpenPGP module (`bcpg-jdk18on`) version 1.85,
under the MIT license (see `LICENSE`).

OpenKeychain needs a handful of changes to this library that upstream does not
carry, so it is built from source rather than consumed as a binary artifact.
It replaces the former `extern/bouncycastle` submodule, which pinned a fork of
Bouncy Castle 1.77.

## Local changes

`org/bouncycastle/bcpg/OpaquePublicBCPGKey.java` is new. Everything else below
is a modification of the upstream file of the same name.

 - `bcpg/PublicKeyPacket` — parse key material OpenKeychain cannot interpret
   (unknown algorithm, or an ECDH/ECDSA curve that is not in the named-curve
   table) into an `OpaquePublicBCPGKey` instead of failing. This keeps a key
   ring readable and re-encodable byte for byte when only one subkey is exotic.
 - `bcpg/OpaquePublicBCPGKey` — the opaque key type used above.
 - `bcpg/SecretKeyPacket` — a GNU divert-to-card key stores the card's serial
   number in the IV field, prefixed by its length. Read and write that.
 - `bcpg/S2K` — `createDummyS2K()`, to build GNU dummy S2K specifiers.
 - `openpgp/PGPSecretKey` — `constructGnuDummyKey()`, `getIV()`. Stripped
   secret keys are how a key backed by a security token is represented.
 - `openpgp/PGPSecretKeyRing` — `constructDummyFromPublic()`, same purpose.
 - `openpgp/PGPPublicKey` — `addSubkeyBindingCertification()`, and `isMasterKey()`
   decided by the absence of subkey signatures rather than by packet type and
   algorithm, so a key demoted to a subkey reports as one.
 - `bcpg/SignaturePacket` — an unknown signature version throws `IOException`
   rather than the unchecked `UnsupportedPacketVersionException`, so it is
   handled as the parse failure it is.
 - `bcpg/BCPGInputStream`, `bcpg/LiteralDataPacket`, `openpgp/PGPLiteralData` —
   expose the length of a literal data packet, for progress reporting.
 - `bcpg/ArmoredInputStream` — tolerate the CRCRLF line endings gpg4usb emits.
 - `bcpg/ArmoredOutputStream` — do not write a `Version` header by default.
 - `bcpg/EdDSAPublicBCPGKey` — `getEdDSAEncodedPoint()`.
 - `bcpg/UserAttributeSubpacket` — public `create()` factory.
 - `openpgp/PGPUserAttributeSubpacketVector` — `toSubpacketArray()` made public.
 - `openpgp/PGPPublicKeyEncryptedData` — `getSessionKey()`, exposing the
   encrypted session key for the security token code path.
 - `openpgp/PGPSignatureGenerator` — tolerate a null private key in `init()`.
   A key held on a security token has no private key material here; the content
   signer builder is what signals that the token must be asked, and upstream's
   key-version check would dereference the null first.

## Updating

Unpack the `bcpg-jdk18on` sources jar of the new version over `src/main/java`,
then re-apply the changes above.
