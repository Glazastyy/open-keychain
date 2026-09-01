# Branding

What identifies this app, where each piece lives, and what to change when you
want to replace the artwork.

## Already changed

| What | Value | Where |
| --- | --- | --- |
| Application ID | `com.glazastov.keychain` | `OpenKeychain/build.gradle` |
| Display name | Glazastov Keychain | `app_name` in `OpenKeychain/src/main/res/values/strings.xml` |
| Account type | `com.glazastov.keychain.account` | `OpenKeychain/build.gradle`, both build types |
| Provider authority | `com.glazastov.keychain.provider` | `OpenKeychain/build.gradle`, both build types |
| Shortcut target | `com.glazastov.keychain` | `OpenKeychain/src/main/res/xml/shortcuts.xml` |

The debug build appends `.debug` to all of these, so it installs alongside the
release build.

### What deliberately did not change

The Java package (`namespace` in `OpenKeychain/build.gradle`) is still
`org.sufficientlysecure.keychain`. It is invisible to users, and renaming it
means touching every one of the ~400 source files for no functional gain. The
application ID is what Android and the app stores actually key on, and that is
now yours.

The intent actions — `org.sufficientlysecure.keychain.action.ENCRYPT_TEXT` and
friends, declared in `AndroidManifest.xml` and built from `Constants.PACKAGE_NAME`
— are also unchanged **on purpose**. Other apps launch the app by those names,
so they are an interface, not branding. Renaming them breaks every caller.

Mail apps find this app through the action `org.openintents.openpgp.IOpenPgpService2`,
not by package name, so K-9 and Thunderbird still list it after the rename. The
user picks it in the mail app's OpenPGP provider setting.

## Changing the logo

The launcher icon exists in two forms, and both need replacing.

**Adaptive icon** (Android 8+, what almost every device shows):

- `OpenKeychain/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` — points at the
  two layers below
- `OpenKeychain/src/main/res/drawable/ic_launcher_background.xml` — background layer
- `OpenKeychain/src/main/res/drawable-v24/ic_launcher_foreground.xml` — foreground layer

Both layers are vector drawables. The foreground must keep its art inside the
central safe zone: the outer ~18% on each side is cropped by whatever mask the
launcher applies, so anything near the edge disappears on round-icon devices.

**Legacy raster icon** (Android 7 and below):

- `OpenKeychain/src/main/res/mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/ic_launcher.png`
  at 48, 72, 96, 144 and 192 px square respectively.

The quickest correct route is Android Studio's Image Asset wizard
(*right-click `res` → New → Image Asset*), which writes both forms from one
source image at the right sizes.

**In-app artwork** is separate from the launcher icon: `graphics/drawables/`
holds the SVG sources and `OpenKeychain/src/main/res/drawable*/` the compiled
vectors. `graphics/update-drawables.sh` regenerates the latter from the former.
Most of these are generic UI icons — key, lock, shield — and carry no branding,
so they need no attention unless you want a different visual language.

The store listing images under `fastlane/` and the badges in `graphics/`
(`get-it-on-f-droid.png`, `get-it-on-google-play.png`) are publishing assets,
not part of the app. The Google Play badge is Google's trademark and its use is
governed by their brand guidelines.

## Before publishing under the new brand

1. **Resolve the icon licensing.** The sets under
   `graphics/drawables/originals/` do not state their license here:
   `modernpgp-icons` has no license file, and the Material Design Icons entries
   record only the author's name. Confirm the terms or replace the artwork.
2. **Do not ship OpenKeychain's identity.** Their name and logo are theirs;
   the rename above is what keeps this clean, and it is also what the GPL
   expects of a fork — see `NOTICE.md`.
3. **Sign the release build.** Put `signingStoreLocation`, `signingStorePassword`,
   `signingKeyAlias` and `signingKeyPassword` in `~/.gradle/gradle.properties`
   and the build picks them up. The signing key is what ties the app to your
   store listing permanently — losing it means never updating that listing again.
4. **Keep the source available.** The app is GPLv3 as a whole, so anyone you
   distribute a binary to is entitled to the corresponding source. Publishing
   the repository satisfies this; F-Droid builds from it directly.
