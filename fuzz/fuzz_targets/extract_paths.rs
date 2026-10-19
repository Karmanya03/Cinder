//! Fuzz the path-safety layer directly.
//!
//! Contract: `safe_destination` and `validate_link_target` never panic, and
//! any path they ACCEPT is provably confined to the root.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cinder_core::extract::{safe_destination, validate_link_target};

fuzz_target!(|data: (String, String)| {
    let (rel, target) = data;
    let root = std::path::Path::new("/tmp/fuzz-root");
    match safe_destination(root, &rel) {
        Ok(dest) => {
            // Property: accepted paths are relative, stay under root, and
            // contain no parent components.
            assert!(dest.starts_with(root), "accepted path escaped root: {dest:?}");
            let rel_check = dest.strip_prefix(root).expect("strip");
            for comp in rel_check.components() {
                assert!(
                    matches!(comp, std::path::Component::Normal(_)),
                    "accepted path contained non-normal component {comp:?} from {rel:?}"
                );
            }
        }
        Err(_) => {}
    }

    // Link targets: never panic; rejection paths are fine.
    let link_dest = root.join("dir").join("link");
    let _ = validate_link_target(root, &link_dest, std::path::Path::new(&target));
});
