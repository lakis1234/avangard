use std::env;
use std::fs;
use std::path::PathBuf;

fn replace_once(src: &mut String, from: &str, to: &str, label: &str) {
    let n = src.matches(from).count();
    assert_eq!(n, 1, "PERF-015 build transform expected exactly one {label}, found {n}");
    *src = src.replacen(from, to, 1);
}

fn replace_some(src: &mut String, from: &str, to: &str, min: usize, label: &str) {
    let n = src.matches(from).count();
    assert!(n >= min, "PERF-015 build transform expected at least {min} {label}, found {n}");
    *src = src.replace(from, to);
}

fn main() {
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source_path = manifest.join("../perf014/src/main.rs");
    let mut src = fs::read_to_string(&source_path).expect("read PERF-014 source");

    // Keep PERF-014's network, SPSC route lanes, state maps, atomicity and timing structure.
    // PERF-015 isolates one hot-path change: pack PREPARE count + value sum into one AtomicU64.
    replace_once(
        &mut src,
        "use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};",
        "use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};",
        "atomic import",
    );

    replace_some(&mut src, "_0014", "_0015", 3, "PERF magic/domain constants");
    replace_some(&mut src, "PERF-014", "PERF-015", 5, "PERF labels");
    replace_once(&mut src, "v1.4.0", "v1.5.0", "version label");

    replace_once(
        &mut src,
        "    let prepared_counts: Arc<Vec<AtomicU8>> =\n        Arc::new((0..txs).map(|_| AtomicU8::new(0)).collect());\n    let prepared_values: Arc<Vec<AtomicU64>> =\n        Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());",
        "    // PERF-015: one packed accumulator per transaction. Low 8 bits = prepared-input count;\n    // upper 56 bits = prepared monetary value sum. One input now performs ONE atomic RMW, not two.\n    let prepared_accum: Arc<Vec<AtomicU64>> =\n        Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());",
        "prepare accumulator allocation",
    );

    replace_once(
        &mut src,
        "        let prepared_counts = Arc::clone(&prepared_counts);\n        let prepared_values = Arc::clone(&prepared_values);",
        "        let prepared_accum = Arc::clone(&prepared_accum);",
        "worker accumulator clone",
    );

    replace_some(
        &mut src,
        "                            prepared_counts[item.tx as usize].fetch_add(1, Ordering::Relaxed);\n                            prepared_values[item.tx as usize].fetch_add(cell.value, Ordering::Relaxed);",
        "                            // Pack count and value into one atomic addition. Count occupies the low byte.\n                            // VALUE is tiny in this benchmark; production encoding would reserve an explicit width.\n                            prepared_accum[item.tx as usize]\n                                .fetch_add((cell.value << 8) | 1, Ordering::Relaxed);",
        1,
        "packed prepare update",
    );

    replace_some(
        &mut src,
        "                    let eligible =\n                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;",
        "                    let packed = prepared_accum[tx as usize].load(Ordering::Relaxed);\n                    let eligible = (packed & 0xff) as usize == arity;",
        2,
        "packed eligibility loads",
    );

    replace_once(
        &mut src,
        "                        let value = prepared_values[tx as usize].load(Ordering::Relaxed);",
        "                        let value = packed >> 8;",
        "packed value extraction",
    );

    replace_once(
        &mut src,
        "    println!(\"PREALLOCATED SPSC ROUTE-LANES -> OWNER-LOCAL ATOMIC ENGINE\");",
        "    println!(\"PACKED PREPARE ACCUMULATOR + SPSC ROUTE-LANES ATOMIC ENGINE\");",
        "benchmark title",
    );
    replace_once(
        &mut src,
        "    println!(\"Change vs PERF-013: remove heavy routed WorkItem MPSC chunks and per-batch Vec transfer\");",
        "    println!(\"Change vs PERF-014: collapse PREPARE count+value accounting from two atomic RMWs to one packed AtomicU64\");",
        "change description",
    );
    replace_once(
        &mut src,
        "            \"PERF-013 LOW-LATENCY REFERENCE SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us\",",
        "            \"PERF-014 COMPARISON SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us\",",
        "reference label",
    );
    replace_once(
        &mut src,
        "    println!(\"PREALLOCATED SPSC ROUTE LANES ACTIVE: YES\");",
        "    println!(\"PACKED PREPARE ACCUMULATOR ACTIVE: YES\");\n    println!(\"PREALLOCATED SPSC ROUTE LANES ACTIVE: YES\");",
        "decision packed label",
    );

    // Add a direct unit test for the packed representation.
    replace_once(
        &mut src,
        "    #[test]\n    fn stream_partition_and_lane_capacity() {",
        "    #[test]\n    fn packed_prepare_accumulator_round_trip() {\n        let a = AtomicU64::new(0);\n        for v in [100u64, 200, 300] {\n            a.fetch_add((v << 8) | 1, Ordering::Relaxed);\n        }\n        let packed = a.load(Ordering::Relaxed);\n        assert_eq!((packed & 0xff) as usize, 3);\n        assert_eq!(packed >> 8, 600);\n    }\n\n    #[test]\n    fn stream_partition_and_lane_capacity() {",
        "packed accumulator unit test insertion",
    );

    assert!(!src.contains("prepared_counts"), "PERF-015 generated source still contains prepared_counts");
    assert!(!src.contains("prepared_values"), "PERF-015 generated source still contains prepared_values");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("generated.rs");
    fs::write(out, src).expect("write PERF-015 generated source");
}
