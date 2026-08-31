# nordpol (vendored)

Source copy of [fidesmo/nordpol](https://github.com/fidesmo/nordpol) at tag `v0.1.23`,
licensed under the MIT License (see `LICENSE`).

The upstream project is archived and only ever published binaries to JCenter, which
has been shut down. The sources are therefore built as a local Gradle module. The
upstream `core` (package `nordpol`) and `android` (package `nordpol.android`) sbt
modules are merged here into one Android library; the Java sources were moved into
directories matching their package declarations.
