use std::env;
use std::fs;
use std::path::PathBuf;

mod perf022_builder {
    include!("../perf022/build.rs");
    pub fn run() {
        main();
    }
}

fn replace_once(src: &mut String, from: &str, to: &str, label: &str) {
    let n = src.matches(from).count();
    assert_eq!(n, 1, "PERF-024 transform expected exactly one {label}, found {n}");
    *src = src.replacen(from, to, 1);
}

fn main() {
    println!("cargo:rerun-if-changed=../perf022/build.rs");
    println!("cargo:rerun-if-changed=../perf021/build.rs");
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    // Generate the proven PERF-022 BLAKE3-certified engine, then change only HOW the exact
    // stream-batch bytes are fed to BLAKE3. PERF-022 called Hasher::update once per transaction.
    // PERF-024 appends the same canonical 96 bytes to a preallocated batch buffer and hashes the
    // whole contiguous buffer once at batch flush. Exact-content binding and certificate semantics
    // are unchanged. This isolates per-record BLAKE3 update overhead from cryptographic hashing.
    perf022_builder::run();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let generated = out_dir.join("generated.rs");
    let mut src = fs::read_to_string(&generated).expect("read PERF-022-generated source");

    src = src.replace("PERF-022", "PERF-024");
    src = src.replace("_0022", "_0024");
    src = src.replace("v2.2.0", "v2.4.0");

    replace_once(
        &mut src,
        "                let mut current_batch: Option<usize> = None;\n                let mut batch_hasher = Blake3Hasher::new();\n                let mut cursors = vec![0usize; workers];",
        "                let mut current_batch: Option<usize> = None;\n                // PERF-024: preallocate one contiguous canonical-byte buffer per TCP receiver.\n                // Capacity covers one logical batch plus rounding across stream partitioning.\n                let mut batch_commit_bytes: Vec<u8> = Vec::with_capacity(((batch_size + streams - 1) / streams + 2) * 96);\n                let mut cursors = vec![0usize; workers];",
        "receiver buffered commitment storage",
    );

    let digest_old = "let digest = *std::mem::replace(&mut batch_hasher, Blake3Hasher::new()).finalize().as_bytes();";
    let digest_new = "let digest = *blake3::hash(&batch_commit_bytes).as_bytes(); batch_commit_bytes.clear();";
    let digest_sites = src.matches(digest_old).count();
    assert!(digest_sites >= 2, "PERF-024 expected at least two receiver digest sites, found {digest_sites}");
    src = src.replace(digest_old, digest_new);

    replace_once(
        &mut src,
        "                    batch_hasher.update(&record[..96]);",
        "                    batch_commit_bytes.extend_from_slice(&record[..96]);",
        "per-record canonical-byte buffering",
    );

    src = src.replace(
        "BLAKE3 VERIFIED AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE",
        "BUFFERED BLAKE3 AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE",
    );
    src = src.replace(
        "Change vs PERF-021: replace BLAKE3 stream-batch content digest with BLAKE3 while retaining the same Ed25519 certificate gate",
        "Change vs PERF-022: replace one BLAKE3 update per transaction with one contiguous BLAKE3 hash per stream-batch",
    );
    src = src.replace(
        "Target: preserve the ~5M PERF-015 core while cryptographically gating each stream-batch before execution",
        "Target: recover the PERF-022 hashing loss without weakening exact-content certificate binding",
    );
    src = src.replace(
        "BLAKE3 STREAM-BATCH CONTENT DIGEST INCLUDED: YES",
        "BUFFERED ONE-SHOT BLAKE3 STREAM-BATCH CONTENT DIGEST INCLUDED: YES",
    );

    assert!(!src.contains("batch_hasher.update(&record[..96])"), "PERF-024 still has per-record BLAKE3 update");
    assert!(!src.contains("let mut batch_hasher = Blake3Hasher::new();"), "PERF-024 still has receiver streaming hasher");

    fs::write(&generated, src).expect("write PERF-024 generated source");
}
