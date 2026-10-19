# Cinder iOS shell

This SwiftUI shell uses `fileImporter`/`fileExporter` (backed by the Files
document provider), security-scoped URL lifetime management, background
compression, and a UIKit share sheet. Add the Rust `cinder-mobile` static
library to an Xcode target and link `CinderNative.swift` through a bridging
header or module map.

Build requirements:

1. macOS with Xcode and the requested iOS SDK;
2. `rustup target add aarch64-apple-ios`;
3. `cargo build --manifest-path mobile/native/Cargo.toml --release --target aarch64-apple-ios`;
4. `brew install xcodegen`, then `xcodegen generate --spec mobile/ios/project.yml`;
5. an Xcode signing identity/provisioning profile for a distributable IPA.

The checked-in `project.yml` is the reproducible Xcode project definition.
The CI workflow can generate an unsigned archive without secrets; protected
release jobs should import the certificate/profile from encrypted secrets and
run `xcodebuild -exportArchive` with a repository-specific export options
file.

The launcher icon must be generated from `assets/Cinder-Logo.png` by the
mobile asset sync step; it is the same source used by the desktop shell.
