# Cinder mobile packaging

The launcher/app icon source of truth is
`../assets/Cinder-Logo.png`. The asset is JPEG-encoded despite its historical
`.png` filename, so native wrappers must decode it and generate their platform
icon sizes during the build; do not download or duplicate a second logo.

The native archive engine is ready to be reused on Android and iOS, but the
desktop GUI is intentionally not shipped as a phone app. Desktop code assumes
free filesystem paths and desktop file dialogs; mobile systems expose files
through document providers, security-scoped URLs, share sheets, and explicit
permissions.

## Android target

The Android shell is now under `mobile/android/`. It uses `ACTION_OPEN_DOCUMENT`
and `ACTION_CREATE_DOCUMENT`, persisted provider grants when available, share
intents, a single bounded background job, and a JNI bridge in
`mobile/native/`. It requests no broad storage permission. Build the native
library with `cargo ndk -t arm64-v8a build --release --manifest-path
mobile/native/Cargo.toml` and place the resulting library under the app's
`jniLibs` directory before running Gradle.

The first mobile shell should provide:

- Android Storage Access Framework input/output;
- share-intent import/export;
- a foreground service or bounded worker for long compression jobs;
- scoped storage-safe temporary files;
- touch-first progress, cancellation, and passphrase entry.

The Rust core can be cross-compiled with:

```bash
rustup target add aarch64-linux-android
cargo check -p cinder-core --target aarch64-linux-android
```

The wrapper, manifest, launcher icon sync task, SDK/NDK version, and Gradle
release configuration now live here. A signed APK still requires the Android
keystore and CI secrets; the repository does not contain private signing
material.

## iOS target

The SwiftUI shell is under `mobile/ios/CinderMobile/`. It uses Files document
import/export, security-scoped URL lifetimes, background work, and a UIKit
share sheet. The Xcode project/library link and Apple signing identity remain
machine-specific, so the source shell is checked in instead of an unsigned
or misleading IPA.

The iOS shell should provide:

- `UIDocumentPickerViewController` import/export;
- security-scoped URL lifetime management;
- Files app and share-sheet integration;
- a background-friendly progress model;
- an Xcode app target that embeds the Rust library.

The core can be checked on macOS with:

```bash
rustup target add aarch64-apple-ios
cargo check -p cinder-core --target aarch64-apple-ios
```

An IPA requires the Xcode wrapper, Apple signing identity, provisioning
profile, and usually a macOS runner. The release workflow has a dedicated
mobile packaging job that activates only when those credentials are present.

## Non-negotiable mobile tests

- cancel a large job without corrupting the source or temporary output;
- kill and restart during an archive write, then reject incomplete output;
- round-trip files through SAF / Files providers;
- verify encryption and wrong-passphrase behavior;
- keep memory bounded on low-RAM devices;
- test background/foreground transitions and share-sheet failures.
