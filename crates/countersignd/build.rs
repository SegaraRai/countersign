//! Embed the web UI build (`web/build`, from `vp run build`) when it
//! exists; without it countersignd serves no pages.

use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(countersign_web_ui)");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/build/fetchlet.json");
    // fetchlet.json is written last, after the rest of the build.
    println!("cargo::rerun-if-changed={}", manifest.display());
    if manifest.is_file() {
        println!("cargo::rustc-cfg=countersign_web_ui");
    } else {
        println!("cargo::warning=web/build is missing: this countersignd serves no pages (run `vp run build` first)");
    }
}
