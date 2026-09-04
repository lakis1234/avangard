use std::env;
use std::fs;
use std::path::PathBuf;

mod perf021_builder {
    include!("../perf021/build.rs");
    pub fn run() {
        main();
    }
}

fn main() {
    println!("cargo:rerun-if-changed=../perf021/build.rs");
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    // First generate the proven PERF-021 SHA-256 certified-batch engine in this crate's OUT_DIR.
    // Then transform only the content-digest primitive to BLAKE3. This gives a clean A/B test:
    // same SPSC monetary core, same Ed25519 certificate gate, same batching; only the digest changes.
    perf021_builder::run();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let generated = out_dir.join("generated.rs");
    let mut src = fs::read_to_string(&generated).expect("read PERF-021-generated source");

    src = src.replace("PERF-021", "PERF-022");
    src = src.replace("_0021", "_0022");
    src = src.replace("v2.1.0", "v2.2.0");

    let import_old = "use sha2::{Digest, Sha256};";
    assert_eq!(src.matches(import_old).count(), 1, "PERF-022 expected one SHA-256 import");
    src = src.replace(import_old, "use blake3::Hasher as Blake3Hasher;");

    src = src.replace("Sha256::new()", "Blake3Hasher::new()");

    let p1 = "let digest: [u8; 32] = hasher.finalize().into();";
    assert!(src.contains(p1), "PERF-022 missing precomputed batch digest pattern");
    src = src.replace(p1, "let digest = *hasher.finalize().as_bytes();");

    let p2 = "let digest: [u8; 32] = std::mem::take(&mut batch_hasher).finalize().into();";
    assert!(src.contains(p2), "PERF-022 missing receiver batch digest pattern");
    src = src.replace(
        p2,
        "let digest = *std::mem::replace(&mut batch_hasher, Blake3Hasher::new()).finalize().as_bytes();",
    );

    let p3 = "let digest: [u8; 32] = h.finalize().into();";
    assert!(src.contains(p3), "PERF-022 missing test digest pattern");
    src = src.replace(p3, "let digest = *h.finalize().as_bytes();");

    src = src.replace(
        "VERIFIED AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE",
        "BLAKE3 VERIFIED AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE",
    );
    src = src.replace(
        "Change vs PERF-015: verify one Ed25519 authorization certificate per stream-batch over a SHA-256 content digest",
        "Change vs PERF-021: replace SHA-256 stream-batch content digest with BLAKE3 while retaining the same Ed25519 certificate gate",
    );
    src = src.replace("SHA256 STREAM-BATCH CONTENT DIGEST INCLUDED: YES", "BLAKE3 STREAM-BATCH CONTENT DIGEST INCLUDED: YES");
    src = src.replace("SHA-256", "BLAKE3");

    assert!(!src.contains("Sha256"), "PERF-022 generated source still contains Sha256");
    assert!(!src.contains("sha2::"), "PERF-022 generated source still contains sha2 import");

    fs::write(&generated, src).expect("write PERF-022 generated source");
}
